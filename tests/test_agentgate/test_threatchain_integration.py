import pytest
from unittest.mock import AsyncMock, patch
from pathlib import Path

from agentgate.core.pdp import get_default_pdp
from agentgate.models.decision import DecisionType
from agentgate.client.pep import PermissionDeniedError, ApprovalRequiredError
from agentgate.audit import get_default_audit_service
from app.tools.virustotal import VirusTotalTool
from app.tools.abuseipdb import AbuseIPDBTool


@pytest.fixture
def pdp():
    point = get_default_pdp()
    point.load_manifests_dir(Path("agentgate/manifests"))
    return point


@pytest.mark.asyncio
async def test_recon_agent_allowed_tool_call(pdp, vt_response):
    tool = VirusTotalTool()
    audit = get_default_audit_service()
    initial_log_count = len(audit.get_in_memory_logs())

    with patch.object(tool, "_call_api", new=AsyncMock(return_value=vt_response)):
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_key"}):
            result = await tool._arun("8.8.8.8", ioc_type="ip", agent_name="recon_agent")

    assert result["source"] == "virustotal"
    assert result["malicious"] == 3

    logs = audit.get_in_memory_logs()
    assert len(logs) > initial_log_count
    latest = logs[-1]
    assert latest.agent == "recon_agent"
    assert latest.tool == "virustotal"
    assert latest.decision == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_recon_agent_denied_tool_call(pdp):
    tool = VirusTotalTool()
    tool.api_name = "isolate_host"  # In recon_agent.json tools_denied

    with pytest.raises(PermissionDeniedError) as exc_info:
        await tool._arun("srv-01", agent_name="recon_agent")

    assert "explicitly denied" in str(exc_info.value)
    decision = exc_info.value.decision
    assert decision.decision == DecisionType.DENY
    assert decision.tool == "isolate_host"


@pytest.mark.asyncio
async def test_recon_agent_masking_rfc1918(pdp, abuseipdb_response):
    tool = AbuseIPDBTool()
    mock_call = AsyncMock(return_value=abuseipdb_response)

    with patch.object(tool, "_call_api", new=mock_call):
        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_key"}):
            # Private RFC 1918 IP
            res = await tool._arun("192.168.1.100", agent_name="recon_agent")

    # An internal IOC must never reach (or be cached for) a third-party API
    mock_call.assert_not_called()
    assert res["skipped"] is True
    assert res["source"] == "abuseipdb"

    audit = get_default_audit_service()
    latest = audit.get_in_memory_logs()[-1]
    assert latest.decision == DecisionType.MASK
    assert "ioc_value" in latest.masked_fields


@pytest.mark.asyncio
async def test_recon_agent_approval_required(pdp):
    tool = VirusTotalTool()
    tool.api_name = "block_ip"  # In recon_agent.json requires_approval

    with pytest.raises(ApprovalRequiredError) as exc_info:
        await tool._arun("1.2.3.4", agent_name="recon_agent", wait=False)

    decision = exc_info.value.decision
    assert decision.decision == DecisionType.REQUIRE_APPROVAL
    assert decision.requires_human is True
    assert decision.approval_id is not None
