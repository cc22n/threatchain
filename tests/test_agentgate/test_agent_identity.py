import pytest
from unittest.mock import AsyncMock, patch
from pathlib import Path

from agentgate.audit import get_default_audit_service
from agentgate.client.pep import PermissionDeniedError
from agentgate.core.pdp import get_default_pdp
from agentgate.models.decision import DecisionType
from app.tools.virustotal import VirusTotalTool


@pytest.fixture
def clean_audit_service():
    audit = get_default_audit_service()
    audit._in_memory_buffer.clear()
    return audit


@pytest.fixture
def pdp():
    point = get_default_pdp()
    point.load_manifests_dir(Path("agentgate/manifests"))
    return point


@pytest.mark.asyncio
async def test_strict_mode_without_agent_name_raises_permission_denied(clean_audit_service):
    tool = VirusTotalTool()

    with patch("app.config.settings.AGENTGATE_STRICT", True):
        with pytest.raises(PermissionDeniedError) as exc_info:
            await tool._arun("8.8.8.8", ioc_type="ip")

    err = exc_info.value
    assert "missing agent identity" in str(err)
    assert err.decision.agent == "unknown"
    assert err.decision.decision == DecisionType.DENY
    assert err.decision.reason == "missing agent identity"

    # Verify audit record was created
    logs = clean_audit_service.get_in_memory_logs()
    assert len(logs) == 1
    record = logs[0]
    assert record.agent == "unknown"
    assert record.tool == "virustotal"
    assert record.decision == DecisionType.DENY
    assert record.reason == "missing agent identity"


@pytest.mark.asyncio
async def test_production_env_without_agent_name_raises_permission_denied(clean_audit_service):
    tool = VirusTotalTool()

    with patch("app.config.settings.AGENTGATE_STRICT", False):
        with patch("app.config.settings.APP_ENV", "production"):
            with pytest.raises(PermissionDeniedError) as exc_info:
                await tool._arun("8.8.8.8", ioc_type="ip")

    err = exc_info.value
    assert err.decision.decision == DecisionType.DENY
    assert err.decision.reason == "missing agent identity"

    logs = clean_audit_service.get_in_memory_logs()
    assert len(logs) == 1
    assert logs[0].decision == DecisionType.DENY
    assert logs[0].agent == "unknown"


@pytest.mark.asyncio
async def test_strict_mode_propagates_investigation_id(clean_audit_service):
    tool = VirusTotalTool()

    with patch("app.config.settings.AGENTGATE_STRICT", True):
        with pytest.raises(PermissionDeniedError):
            await tool._arun("8.8.8.8", ioc_type="ip", context={"investigation_id": "inv-strict-999"})

    logs = clean_audit_service.get_in_memory_logs()
    assert len(logs) == 1
    assert logs[0].investigation_id == "inv-strict-999"


@pytest.mark.asyncio
async def test_non_strict_mode_without_agent_name_allows_and_records_unknown(clean_audit_service):
    tool = VirusTotalTool()
    fake_vt = {"source": "virustotal", "malicious": 0}

    with patch("app.config.settings.AGENTGATE_STRICT", False):
        with patch("app.config.settings.APP_ENV", "development"):
            with patch.object(tool, "_call_api", new=AsyncMock(return_value=fake_vt)):
                result = await tool._arun("1.1.1.1", ioc_type="ip", context={"investigation_id": "inv-dev-123"})

    assert result["source"] == "virustotal"

    # Audit record exists with agent="unknown"
    logs = clean_audit_service.get_in_memory_logs()
    assert len(logs) == 1
    record = logs[0]
    assert record.agent == "unknown"
    assert record.tool == "virustotal"
    assert record.decision == DecisionType.ALLOW
    assert "without agent identity" in record.reason
    assert record.investigation_id == "inv-dev-123"


@pytest.mark.asyncio
async def test_with_agent_name_records_proper_agent_identity(clean_audit_service, pdp):
    tool = VirusTotalTool()
    fake_vt = {"source": "virustotal", "malicious": 1}

    with patch("app.config.settings.AGENTGATE_STRICT", True):
        with patch.object(tool, "_call_api", new=AsyncMock(return_value=fake_vt)):
            result = await tool._arun("8.8.8.8", ioc_type="ip", agent_name="recon_agent")

    assert result["source"] == "virustotal"

    logs = clean_audit_service.get_in_memory_logs()
    assert len(logs) >= 1
    latest = logs[-1]
    assert latest.agent == "recon_agent"
    assert latest.decision == DecisionType.ALLOW
