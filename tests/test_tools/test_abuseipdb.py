import pytest
from unittest.mock import patch, AsyncMock
from app.tools.abuseipdb import AbuseIPDBTool


@pytest.fixture
def tool(mock_redis):
    return AbuseIPDBTool(redis_client=mock_redis)


@pytest.mark.asyncio
async def test_normalize_response(tool, abuseipdb_response):
    with patch.object(tool, "_call_api", new=AsyncMock(return_value=abuseipdb_response)):
        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_key"}):
            result = await tool._arun("185.220.101.34")

    assert result["source"] == "abuseipdb"
    assert result["abuse_confidence_score"] == 100
    assert result["total_reports"] == 847
    assert result["is_tor"] is True
    assert result["cached"] is False


@pytest.mark.asyncio
async def test_cache_hit(tool, abuseipdb_response, mock_redis):
    import json
    normalized = tool._normalize(abuseipdb_response)
    mock_redis.get.return_value = json.dumps(normalized)

    result = await tool._arun("185.220.101.34")
    assert result["cached"] is True


@pytest.mark.asyncio
async def test_missing_api_key(tool):
    import os
    env = {k: v for k, v in os.environ.items() if k != "ABUSEIPDB_API_KEY"}
    with patch.dict("os.environ", env, clear=True):
        with pytest.raises(ValueError, match="ABUSEIPDB_API_KEY"):
            tool._get_api_key()
