import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select

from agentgate.audit.models import AgentGateBase, AgentGateAuditLog
from agentgate.audit.service import AuditLogService, redact_arguments
from agentgate.client.pep import PolicyEnforcementPoint
from agentgate.core.pdp import PolicyDecisionPoint
from agentgate.hitl.queue import ApprovalQueue
from agentgate.models.decision import DecisionType
from agentgate.models.manifest import AgentManifest, ToolPermission


def test_redact_arguments_rfc1918():
    args = {
        "public_ip": "8.8.8.8",
        "private_ip": "192.168.1.1",
        "nested": {"loopback": "127.0.0.1", "domain": "evil.com"},
        "ip_list": ["10.0.0.5", "1.1.1.1"],
    }
    redacted = redact_arguments(args)
    assert redacted["public_ip"] == "8.8.8.8"
    assert redacted["private_ip"] == "[REDACTED_INTERNAL_IP]"
    assert redacted["nested"]["loopback"] == "[REDACTED_INTERNAL_IP]"
    assert redacted["nested"]["domain"] == "evil.com"
    assert redacted["ip_list"] == ["[REDACTED_INTERNAL_IP]", "1.1.1.1"]


def test_audit_service_no_update_or_delete_methods():
    service = AuditLogService()
    assert not hasattr(service, "update")
    assert not hasattr(service, "delete")
    assert not hasattr(service, "update_event")
    assert not hasattr(service, "delete_event")
    assert not hasattr(service, "modify")


@pytest.mark.asyncio
async def test_full_hitl_cycle_leaves_three_linked_audit_rows():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(AgentGateBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    audit = AuditLogService(session_factory=session_factory)
    queue = ApprovalQueue()

    pdp = PolicyDecisionPoint(audit_service=audit, approval_queue=queue)
    manifest = AgentManifest(
        agent="sec_agent",
        tools_allowed=[],
        requires_approval=["quarantine_host"],
    )
    pdp.register_manifest(manifest)
    pep = PolicyEnforcementPoint(pdp=pdp)

    mock_tool = AsyncMock(return_value={"status": "quarantined"})

    async def simulate_approval():
        await asyncio.sleep(0.05)
        pending = queue.list_pending()
        assert len(pending) == 1
        queue.approve(pending[0].id, approver="alice_soc", notes="Confirmed active breach")

    task = asyncio.create_task(simulate_approval())

    result = await pep.check_and_execute(
        mock_tool,
        agent="sec_agent",
        tool="quarantine_host",
        arguments={"ip": "10.50.1.20", "hostname": "srv-finance"},
        fn_kwargs={"ip": "10.50.1.20"},
        context={"investigation_id": "inv-999"},
        wait=True,
    )
    await task
    await audit.flush()

    assert result["status"] == "quarantined"

    async with session_factory() as session:
        stmt = select(AgentGateAuditLog).order_by(AgentGateAuditLog.created_at.asc())
        rows = list((await session.execute(stmt)).scalars().all())

    # Verify exactly 3 linked rows: DECISION -> APPROVAL_RESOLVED -> EXECUTION
    assert len(rows) == 3

    r1, r2, r3 = rows[0], rows[1], rows[2]

    # Shared linkage
    assert r1.approval_id is not None
    assert r1.approval_id == r2.approval_id == r3.approval_id

    # 1. DECISION event
    assert r1.event_type == "DECISION"
    assert r1.decision == "REQUIRE_APPROVAL"
    assert r1.agent_id == "sec_agent"
    assert r1.tool_name == "quarantine_host"
    assert r1.arguments["ip"] == "[REDACTED_INTERNAL_IP]"

    # 2. APPROVAL_RESOLVED event
    assert r2.event_type == "APPROVAL_RESOLVED"
    assert r2.decision == "ALLOW"
    assert r2.approver == "alice_soc"
    assert r2.decided_at is not None
    assert r2.investigation_id == "inv-999"

    # 3. EXECUTION event
    assert r3.event_type == "EXECUTION"
    assert r3.execution_result == "success"
    assert r3.investigation_id == "inv-999"

    await engine.dispose()


@pytest.mark.asyncio
async def test_audit_execution_error_recorded():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(AgentGateBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    audit = AuditLogService(session_factory=session_factory)
    queue = ApprovalQueue()

    pdp = PolicyDecisionPoint(audit_service=audit, approval_queue=queue)
    manifest = AgentManifest(
        agent="sec_agent",
        tools_allowed=[],
        requires_approval=["quarantine_host"],
    )
    pdp.register_manifest(manifest)
    pep = PolicyEnforcementPoint(pdp=pdp)

    mock_failing_tool = AsyncMock(side_effect=ConnectionResetError("Socket reset"))

    async def simulate_approval():
        await asyncio.sleep(0.05)
        pending = queue.list_pending()
        queue.approve(pending[0].id, approver="alice_soc")

    asyncio.create_task(simulate_approval())

    with pytest.raises(ConnectionResetError):
        await pep.check_and_execute(
            mock_failing_tool,
            agent="sec_agent",
            tool="quarantine_host",
            arguments={"ip": "8.8.8.8"},
            wait=True,
        )

    await audit.flush()

    async with session_factory() as session:
        stmt = select(AgentGateAuditLog).order_by(AgentGateAuditLog.created_at.asc())
        rows = list((await session.execute(stmt)).scalars().all())

    assert len(rows) == 3
    r3 = rows[2]
    assert r3.event_type == "EXECUTION"
    assert r3.execution_result == "error:ConnectionResetError"

    await engine.dispose()
