import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
import httpx

from agentgate.client.pep import (
    PolicyEnforcementPoint,
    AgentGateEnforcer,
    PermissionDeniedError,
    ApprovalRequiredError,
    ApprovalRejectedError,
    ApprovalExpiredError,
    ContextChangedError,
)
from agentgate.core.pdp import PolicyDecisionPoint
from agentgate.hitl.notifier import send_approval_request, TelegramNotifier
from agentgate.hitl.queue import ApprovalQueue, ApprovalStatus, ApprovalRequest
from agentgate.models.decision import DecisionResult, DecisionType
from agentgate.models.manifest import AgentManifest, ToolPermission


@pytest.fixture
def hitl_pdp(tmp_path):
    queue = ApprovalQueue()
    point = PolicyDecisionPoint(approval_queue=queue)
    manifest = AgentManifest(
        agent="hitl_agent",
        tools_allowed=[ToolPermission(name="safe_tool")],
        requires_approval=["sensitive_tool", "block_ip"],
        tools_denied=["danger_tool"],
    )
    point.register_manifest(manifest)
    return point, queue


@pytest.mark.asyncio
async def test_hitl_approve_flow_executes_tool(hitl_pdp):
    pdp, queue = hitl_pdp
    pep = PolicyEnforcementPoint(pdp=pdp)
    tool_mock = AsyncMock(return_value={"executed": True, "target": "10.0.0.1"})

    async def simulate_human_approval():
        await asyncio.sleep(0.05)
        pending = queue.list_pending()
        assert len(pending) == 1
        queue.approve(pending[0].id, approver="admin_alice", notes="Looks legitimate")

    asyncio.create_task(simulate_human_approval())

    with patch("agentgate.client.pep.get_default_approval_queue", return_value=queue):
        result = await pep.check_and_execute(
            tool_mock,
            agent="hitl_agent",
            tool="sensitive_tool",
            arguments={"target": "10.0.0.1"},
            fn_kwargs={"target": "10.0.0.1"},
            wait=True,
        )

    tool_mock.assert_awaited_once_with(target="10.0.0.1")
    assert result["executed"] is True


@pytest.mark.asyncio
async def test_hitl_reject_flow_raises_error(hitl_pdp):
    pdp, queue = hitl_pdp
    pep = PolicyEnforcementPoint(pdp=pdp)
    tool_mock = AsyncMock(return_value={"executed": True})

    async def simulate_human_rejection():
        await asyncio.sleep(0.05)
        pending = queue.list_pending()
        assert len(pending) == 1
        queue.reject(pending[0].id, approver="sec_ops", notes="Potential false positive")

    asyncio.create_task(simulate_human_rejection())

    with patch("agentgate.client.pep.get_default_approval_queue", return_value=queue):
        with pytest.raises(ApprovalRejectedError) as exc_info:
            await pep.check_and_execute(
                tool_mock,
                agent="hitl_agent",
                tool="sensitive_tool",
                arguments={"target": "10.0.0.1"},
                fn_kwargs={"target": "10.0.0.1"},
                wait=True,
            )

    tool_mock.assert_not_called()
    assert exc_info.value.request.status == ApprovalStatus.REJECTED
    assert exc_info.value.request.approver == "sec_ops"


@pytest.mark.asyncio
async def test_hitl_timeout_raises_expired_error(hitl_pdp):
    pdp, queue = hitl_pdp
    pep = PolicyEnforcementPoint(pdp=pdp)
    tool_mock = AsyncMock(return_value={"executed": True})

    with patch("agentgate.client.pep.get_default_approval_queue", return_value=queue):
        with patch("app.config.settings.AGENTGATE_APPROVAL_WAIT_SECONDS", 0.1):
            with pytest.raises(ApprovalExpiredError) as exc_info:
                await pep.check_and_execute(
                    tool_mock,
                    agent="hitl_agent",
                    tool="sensitive_tool",
                    arguments={"target": "10.0.0.1"},
                    fn_kwargs={"target": "10.0.0.1"},
                    wait=True,
                )

    tool_mock.assert_not_called()
    assert exc_info.value.request.status == ApprovalStatus.EXPIRED


@pytest.mark.asyncio
async def test_hitl_context_revalidation_failure(hitl_pdp):
    pdp, queue = hitl_pdp
    pep = PolicyEnforcementPoint(pdp=pdp)
    tool_mock = AsyncMock(return_value={"executed": True})

    context = {"auth_token": "original-secret-token"}

    async def simulate_human_approval_with_token_tampering():
        await asyncio.sleep(0.05)
        pending = queue.list_pending()
        assert len(pending) == 1
        queue.approve(pending[0].id, approver="operator")
        context["auth_token"] = "rotated-token-during-wait"

    asyncio.create_task(simulate_human_approval_with_token_tampering())

    with patch("agentgate.client.pep.get_default_approval_queue", return_value=queue):
        with pytest.raises(ContextChangedError) as exc_info:
            await pep.check_and_execute(
                tool_mock,
                agent="hitl_agent",
                tool="sensitive_tool",
                arguments={"target": "10.0.0.1"},
                context=context,
                fn_kwargs={"target": "10.0.0.1"},
                wait=True,
            )

    tool_mock.assert_not_called()
    assert "Credential mismatch" in exc_info.value.reason


@pytest.mark.asyncio
async def test_agentgate_enforcer_context_manager(hitl_pdp):
    pdp, queue = hitl_pdp
    pep = PolicyEnforcementPoint(pdp=pdp)

    async with AgentGateEnforcer("hitl_agent", "safe_tool", {"arg": "val"}, pep=pep) as decision:
        assert decision.decision == DecisionType.ALLOW

    with pytest.raises(PermissionDeniedError):
        async with AgentGateEnforcer("hitl_agent", "danger_tool", {}, pep=pep):
            pass

    with pytest.raises(ApprovalRequiredError):
        async with AgentGateEnforcer("hitl_agent", "sensitive_tool", {}, pep=pep, wait=False):
            pass


@pytest.mark.asyncio
async def test_hitl_task_cancellation_propagates(hitl_pdp):
    pdp, queue = hitl_pdp
    pep = PolicyEnforcementPoint(pdp=pdp)

    with patch("agentgate.client.pep.get_default_approval_queue", return_value=queue):
        task = asyncio.create_task(
            pep.authorize(
                agent="hitl_agent",
                tool="sensitive_tool",
                arguments={"arg": "x"},
                wait=True,
            )
        )
        await asyncio.sleep(0.05)
        assert len(queue.list_pending()) == 1
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        req = list(queue._memory_store.values())[0]
        assert req.status == ApprovalStatus.EXPIRED


@pytest.mark.asyncio
async def test_telegram_send_approval_request_mocked():
    req = ApprovalRequest(
        id="a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.2.3.4"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)) as mock_post:
        success = await send_approval_request(
            req,
            token="123456:FAKE_TOKEN",
            allowlist_ids=[987654321],
        )

        assert success is True
        mock_post.assert_awaited_once()
        call_kwargs = mock_post.call_args.kwargs
        json_data = call_kwargs["json"]
        assert json_data["chat_id"] == 987654321
        assert "AGENTGATE HUMAN APPROVAL REQUIRED" in json_data["text"]
        assert json_data["reply_markup"]["inline_keyboard"][0][0]["callback_data"] == f"ag_appr_{req.id}"
        assert json_data["reply_markup"]["inline_keyboard"][0][1]["callback_data"] == f"ag_rej_{req.id}"


@pytest.mark.asyncio
async def test_telegram_send_approval_request_network_failure_resilient():
    req = ApprovalRequest(
        id="a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.2.3.4"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectError("Network down"))):
        success = await send_approval_request(
            req,
            token="123456:FAKE_TOKEN",
            allowlist_ids=[987654321],
        )
        assert success is False


def test_approval_queue_idempotency_and_state_guards():
    queue = ApprovalQueue()
    req = queue.create_request("agent", "tool", {})

    queue.approve(req.id, approver="alice")
    assert req.status == ApprovalStatus.APPROVED

    with pytest.raises(ValueError):
        queue.reject(req.id, approver="bob")
