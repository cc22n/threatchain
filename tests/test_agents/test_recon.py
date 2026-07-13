import uuid
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from app.agents.recon_agent import ReconAgent


@pytest.mark.asyncio
async def test_recon_agent_success(db_session, mock_redis):
    investigation_id = uuid.uuid4()

    mock_llm = MagicMock()
    mock_llm.model_name = "mock-model"
    mock_response = MagicMock()
    mock_response.content = '{"reputation": "malicious", "risk_score": 9.2, "key_indicators": ["tor_exit_node"], "summary": "Malicious."}'
    mock_response.usage_metadata = {"total_tokens": 150}
    mock_llm.ainvoke = AsyncMock(return_value=mock_response)

    with patch("app.agents.recon_agent.get_llm_for_agent", return_value=mock_llm):
        with patch.object(ReconAgent, "__init__", lambda self, db, redis_client=None: None):
            agent = ReconAgent.__new__(ReconAgent)
            agent.db = db_session
            agent.agent_name = "recon"
            agent.llm = mock_llm
            agent.vt = MagicMock(_arun=AsyncMock(return_value={"source": "virustotal", "malicious": 15}))
            agent.abuseipdb = MagicMock(_arun=AsyncMock(return_value={"source": "abuseipdb", "abuse_confidence_score": 100}))
            agent.shodan = MagicMock(_arun=AsyncMock(return_value={"source": "shodan", "ports": [22, 9001]}))
            agent.threatfox = MagicMock(_arun=AsyncMock(return_value={"source": "threatfox", "found": True, "malware": "CobaltStrike"}))

            result = await agent.run("185.220.101.34", "ip", investigation_id)

    assert "reputation" in result
    assert "summary" in result


@pytest.mark.asyncio
async def test_recon_agent_partial_failure(db_session, mock_redis):
    investigation_id = uuid.uuid4()
    mock_llm = MagicMock()
    mock_llm.model_name = "mock-model"
    mock_response = MagicMock()
    mock_response.content = '{"reputation": "suspicious", "risk_score": 5.0, "key_indicators": [], "summary": "Partial data."}'
    mock_response.usage_metadata = {"total_tokens": 80}
    mock_llm.ainvoke = AsyncMock(return_value=mock_response)

    with patch("app.agents.recon_agent.get_llm_for_agent", return_value=mock_llm):
        agent = ReconAgent.__new__(ReconAgent)
        agent.db = db_session
        agent.agent_name = "recon"
        agent.llm = mock_llm
        agent.vt = MagicMock(_arun=AsyncMock(return_value={"source": "virustotal", "malicious": 2}))
        agent.abuseipdb = MagicMock(_arun=AsyncMock(side_effect=Exception("rate limit")))
        agent.shodan = MagicMock(_arun=AsyncMock(return_value={"source": "shodan", "ports": [80]}))
        agent.threatfox = MagicMock(_arun=AsyncMock(return_value={"source": "threatfox", "found": False}))

        result = await agent.run("1.2.3.4", "ip", investigation_id)

    assert result is not None
