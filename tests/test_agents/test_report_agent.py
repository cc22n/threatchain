import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.agents.report_agent import ReportAgent


@pytest.mark.asyncio
async def test_report_agent_generates_report(db_session):
    investigation_id = uuid.uuid4()
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.content = """{
        "executive_summary": "The investigated IP is a known Tor exit node associated with Cobalt Strike C2 activity.",
        "verdict": "malicious",
        "severity": "critical",
        "severity_score": 9.2,
        "key_findings": ["Tor exit node detected", "847 abuse reports on AbuseIPDB"],
        "recommendations": "Block IP at perimeter firewall. Review logs for connections to this IP.",
        "timeline": []
    }"""
    mock_response.usage_metadata = {"total_tokens": 350}
    mock_llm.ainvoke = AsyncMock(return_value=mock_response)
    mock_llm.model_name = "claude-sonnet-4-6"

    with patch("app.agents.report_agent.get_llm_for_agent", return_value=mock_llm):
        agent = ReportAgent.__new__(ReportAgent)
        agent.db = db_session
        agent.agent_name = "report"
        agent.llm = mock_llm

        result = await agent.run("185.220.101.34", "ip", investigation_id)

    assert result["verdict"] == "malicious"
    assert result["severity"] == "critical"
    assert result["severity_score"] == 9.2
    assert "executive_summary" in result
    assert "recommendations" in result


@pytest.mark.asyncio
async def test_report_agent_fallback_on_llm_error(db_session):
    investigation_id = uuid.uuid4()
    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(side_effect=Exception("LLM timeout"))
    mock_llm.model_name = "claude-sonnet-4-6"

    with patch("app.agents.report_agent.get_llm_for_agent", return_value=mock_llm):
        agent = ReportAgent.__new__(ReportAgent)
        agent.db = db_session
        agent.agent_name = "report"
        agent.llm = mock_llm

        result = await agent.run("1.2.3.4", "ip", investigation_id)

    assert result is not None
    assert "verdict" in result
