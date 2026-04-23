import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.agents.coordinator import Coordinator, IOC_AGENT_MAP


def test_ioc_agent_map_coverage():
    assert "recon" in IOC_AGENT_MAP["ip"]
    assert "osint" in IOC_AGENT_MAP["ip"]
    assert "mitre" in IOC_AGENT_MAP["ip"]
    assert "malware" in IOC_AGENT_MAP["hash"]
    assert "mitre" in IOC_AGENT_MAP["hash"]
    assert "vuln" in IOC_AGENT_MAP["cve"]
    assert "mitre" in IOC_AGENT_MAP["cve"]


@pytest.mark.asyncio
async def test_coordinator_ip_investigation(db_session):
    inv_id = uuid.uuid4()
    mock_findings = {"reputation": "malicious", "risk_score": 9.0, "key_indicators": ["tor"], "summary": "Malicious."}

    mock_recon = MagicMock()
    mock_recon.run = AsyncMock(return_value=mock_findings)
    mock_osint = MagicMock()
    mock_osint.run = AsyncMock(return_value={"risk_level": "critical", "related_iocs": []})
    mock_mitre = MagicMock()
    mock_mitre.run = AsyncMock(return_value={"techniques": [{"technique_id": "T1090", "technique_name": "Proxy", "tactic": "defense-evasion", "confidence": "high", "evidence": "Tor usage"}], "count": 1})

    with patch("app.agents.coordinator.ReconAgent", return_value=mock_recon), \
         patch("app.agents.coordinator.OsintAgent", return_value=mock_osint), \
         patch("app.agents.coordinator.MitreAgent", return_value=mock_mitre):

        coordinator = Coordinator(db=db_session)
        result = await coordinator.investigate("185.220.101.34", "ip", inv_id)

    assert "agent_findings" in result
    assert "correlation" in result
    assert result["correlation"]["verdict"] in ("malicious", "suspicious", "benign", "unknown")


@pytest.mark.asyncio
async def test_coordinator_handles_agent_failure(db_session):
    inv_id = uuid.uuid4()

    mock_recon = MagicMock()
    mock_recon.run = AsyncMock(side_effect=Exception("API down"))
    mock_osint = MagicMock()
    mock_osint.run = AsyncMock(return_value={"risk_level": "low", "related_iocs": []})
    mock_mitre = MagicMock()
    mock_mitre.run = AsyncMock(return_value={"techniques": [], "count": 0})

    with patch("app.agents.coordinator.ReconAgent", return_value=mock_recon), \
         patch("app.agents.coordinator.OsintAgent", return_value=mock_osint), \
         patch("app.agents.coordinator.MitreAgent", return_value=mock_mitre):

        coordinator = Coordinator(db=db_session)
        result = await coordinator.investigate("8.8.8.8", "ip", inv_id)

    assert result is not None
    assert "correlation" in result
