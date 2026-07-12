import pytest
from unittest.mock import patch, AsyncMock
from app.tools.threatfox import ThreatFoxTool


@pytest.fixture
def tool(mock_redis):
    return ThreatFoxTool(redis_client=mock_redis)


@pytest.mark.asyncio
async def test_normalize_response(tool, threatfox_response):
    with patch.object(tool, "_call_api", new=AsyncMock(return_value=threatfox_response)):
        with patch.dict("os.environ", {"ABUSECH_AUTH_KEY": "test_auth_key"}):
            result = await tool._arun("malicious.example.com", ioc_type="domain")

    assert result["source"] == "threatfox"
    assert result["found"] is True
    assert result["ioc_type"] == "domain"
    assert result["malware"] == "Emotet"
    assert result["confidence_level"] == 95
    assert result["cached"] is False


@pytest.mark.asyncio
async def test_cache_hit(tool, threatfox_response, mock_redis):
    import json
    normalized = tool._normalize(threatfox_response)
    mock_redis.get.return_value = json.dumps(normalized)

    result = await tool._arun("malicious.example.com", ioc_type="domain")

    assert result["cached"] is True
    mock_redis.get.assert_called_once_with("threatfox:malicious.example.com")


@pytest.mark.asyncio
async def test_normalize_no_data():
    tool = ThreatFoxTool(redis_client=None)
    response = {"query_status": "ok", "data": []}
    result = tool._normalize(response)
    assert result["source"] == "threatfox"
    assert result["found"] is False


@pytest.mark.asyncio
async def test_normalize_failed_query():
    tool = ThreatFoxTool(redis_client=None)
    response = {"query_status": "failed"}
    result = tool._normalize(response)
    assert result["source"] == "threatfox"
    assert result["found"] is False


@pytest.mark.asyncio
async def test_missing_api_key(tool):
    import os
    env = {k: v for k, v in os.environ.items() if k != "ABUSECH_AUTH_KEY"}
    with patch.dict("os.environ", env, clear=True):
        with pytest.raises(ValueError, match="ABUSECH_AUTH_KEY"):
            tool._get_api_key()
