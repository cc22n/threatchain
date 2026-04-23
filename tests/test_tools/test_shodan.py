import pytest
from unittest.mock import patch, AsyncMock
from app.tools.shodan import ShodanTool


@pytest.fixture
def tool(mock_redis):
    return ShodanTool(redis_client=mock_redis)


@pytest.mark.asyncio
async def test_normalize_response(tool, shodan_response):
    with patch.object(tool, "_call_api", new=AsyncMock(return_value=shodan_response)):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test_key"}):
            result = await tool._arun("185.220.101.34")

    assert result["source"] == "shodan"
    assert result["ip"] == "185.220.101.34"
    assert 9001 in result["ports"]
    assert result["org"] == "Tor Project"
    assert result["cached"] is False


@pytest.mark.asyncio
async def test_cache_hit(tool, shodan_response, mock_redis):
    import json
    normalized = tool._normalize(shodan_response)
    mock_redis.get.return_value = json.dumps(normalized)

    result = await tool._arun("185.220.101.34")
    assert result["cached"] is True


@pytest.mark.asyncio
async def test_missing_api_key(tool):
    import os
    env = {k: v for k, v in os.environ.items() if k != "SHODAN_API_KEY"}
    with patch.dict("os.environ", env, clear=True):
        with pytest.raises(ValueError, match="SHODAN_API_KEY"):
            tool._get_api_key()
