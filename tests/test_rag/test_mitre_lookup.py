import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from langchain_core.documents import Document


@pytest.mark.asyncio
async def test_mitre_lookup_returns_techniques():
    mock_docs = [
        Document(
            page_content="Technique: T1090.003 - Multi-hop Proxy\nTactics: defense-evasion\n\nAdversaries use Tor for anonymization.",
            metadata={"technique_id": "T1090.003", "technique_name": "Multi-hop Proxy", "tactics": "defense-evasion"},
        ),
        Document(
            page_content="Technique: T1071.001 - Web Protocols\nTactics: command-and-control\n\nHTTPS C2 traffic.",
            metadata={"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactics": "command-and-control"},
        ),
    ]
    mock_llm_response = MagicMock()
    mock_llm_response.content = '[{"technique_id": "T1090.003", "technique_name": "Multi-hop Proxy", "tactic": "defense-evasion", "confidence": "high", "evidence": "Tor exit node detected"}]'

    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(return_value=mock_llm_response)

    with patch("app.chains.mitre_lookup_chain.mitre_similarity_search", return_value=mock_docs), \
         patch("app.chains.mitre_lookup_chain.get_llm_for_agent", return_value=mock_llm):

        from app.chains.mitre_lookup_chain import mitre_lookup
        result = await mitre_lookup("Tor exit node C2 traffic")

    assert isinstance(result, list)
    assert len(result) > 0
    assert result[0]["technique_id"] == "T1090.003"
    assert result[0]["confidence"] == "high"


@pytest.mark.asyncio
async def test_mitre_lookup_fallback_on_llm_error():
    mock_docs = [
        Document(
            page_content="Technique: T1059 - Command and Scripting\nTactics: execution\n\nPowerShell usage.",
            metadata={"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactics": "execution"},
        ),
    ]
    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(side_effect=Exception("LLM timeout"))

    with patch("app.chains.mitre_lookup_chain.mitre_similarity_search", return_value=mock_docs), \
         patch("app.chains.mitre_lookup_chain.get_llm_for_agent", return_value=mock_llm):

        from app.chains.mitre_lookup_chain import mitre_lookup
        result = await mitre_lookup("PowerShell execution")

    assert isinstance(result, list)
    assert len(result) > 0
    assert result[0]["technique_id"] == "T1059"
    assert result[0]["confidence"] == "low"


@pytest.mark.asyncio
async def test_mitre_lookup_empty_when_no_docs():
    with patch("app.chains.mitre_lookup_chain.mitre_similarity_search", return_value=[]):
        from app.chains.mitre_lookup_chain import mitre_lookup
        result = await mitre_lookup("unknown query")

    assert result == []
