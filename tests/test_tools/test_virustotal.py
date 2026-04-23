import pytest
from unittest.mock import patch, AsyncMock
from app.tools.virustotal import VirusTotalTool


@pytest.fixture
def tool(mock_redis):
    return VirusTotalTool(redis_client=mock_redis)


@pytest.mark.asyncio
async def test_normalize_response(tool, vt_response):
    with patch.object(tool, "_call_api", new=AsyncMock(return_value=vt_response)):
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_key"}):
            result = await tool._arun("8.8.8.8", ioc_type="ip")

    assert result["source"] == "virustotal"
    assert result["malicious"] == 3
    assert result["suspicious"] == 1
    assert result["harmless"] == 70
    assert result["cached"] is False


@pytest.mark.asyncio
async def test_cache_hit(tool, vt_response, mock_redis):
    import json
    normalized = tool._normalize(vt_response)
    mock_redis.get.return_value = json.dumps(normalized)

    result = await tool._arun("8.8.8.8", ioc_type="ip")

    assert result["cached"] is True
    mock_redis.get.assert_called_once_with("virustotal:8.8.8.8")


@pytest.mark.asyncio
async def test_missing_api_key(tool):
    import os
    env = {k: v for k, v in os.environ.items() if k != "VIRUSTOTAL_API_KEY"}
    with patch.dict("os.environ", env, clear=True):
        with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY"):
            tool._get_api_key()
