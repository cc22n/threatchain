import pytest
from pathlib import Path
from agentgate.core.pdp import PolicyDecisionPoint
from agentgate.client.pep import (
    PolicyEnforcementPoint,
    protect,
    PermissionDeniedError,
    ApprovalRequiredError,
)


@pytest.fixture
def pdp():
    point = PolicyDecisionPoint()
    point.load_manifest_file(Path("agentgate/examples/sample_recon.json"))
    return point


@pytest.mark.asyncio
async def test_pep_allow_execution(pdp):
    pep = PolicyEnforcementPoint(pdp=pdp)

    async def dummy_scan(ip: str):
        return {"status": "scanned", "target": ip}

    result = await pep.check_and_execute(
        dummy_scan,
        agent="recon_agent",
        tool="virustotal",
        arguments={"ip": "8.8.8.8"},
        fn_kwargs={"ip": "8.8.8.8"},
    )
    assert result["status"] == "scanned"
    assert result["target"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_pep_deny_raises_exception(pdp):
    pep = PolicyEnforcementPoint(pdp=pdp)

    async def wipe_action():
        return "wiped"

    with pytest.raises(PermissionDeniedError) as exc_info:
        await pep.check_and_execute(
            wipe_action,
            agent="recon_agent",
            tool="isolate_host",
            arguments={},
        )
    assert "explicitly denied" in str(exc_info.value)


@pytest.mark.asyncio
async def test_pep_require_approval_raises_exception(pdp):
    pep = PolicyEnforcementPoint(pdp=pdp)

    async def block_ip_action(ip: str):
        return f"blocked {ip}"

    with pytest.raises(ApprovalRequiredError) as exc_info:
        await pep.check_and_execute(
            block_ip_action,
            agent="recon_agent",
            tool="block_ip",
            arguments={"ip": "1.2.3.4"},
            fn_kwargs={"ip": "1.2.3.4"},
            wait=False,
        )
    assert exc_info.value.decision.requires_human is True


@pytest.mark.asyncio
async def test_pep_mask_applies_redacted_args(pdp):
    pep = PolicyEnforcementPoint(pdp=pdp)

    async def query_feed(ip: str):
        return {"queried_ip": ip}

    result = await pep.check_and_execute(
        query_feed,
        agent="recon_agent",
        tool="abuseipdb",
        arguments={"ip": "10.0.0.1"},
        fn_kwargs={"ip": "10.0.0.1"},
    )
    assert result["queried_ip"] == "[REDACTED_INTERNAL_IP]"


@pytest.mark.asyncio
async def test_protect_decorator_async(pdp):
    class FakeReconAgent:
        agent_name = "recon_agent"

        @protect(tool_name="virustotal", pdp=pdp)
        async def run_lookup(self, ioc_value: str):
            return {"result": f"lookup_{ioc_value}"}

        @protect(tool_name="wipe_disk", pdp=pdp)
        async def dangerous_action(self):
            return "danger"

    agent = FakeReconAgent()
    res = await agent.run_lookup(ioc_value="8.8.8.8")
    assert res["result"] == "lookup_8.8.8.8"

    with pytest.raises(PermissionDeniedError):
        await agent.dangerous_action()
