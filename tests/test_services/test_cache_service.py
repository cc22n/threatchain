import pytest
from unittest.mock import MagicMock
from app.services.cache_service import CacheService


@pytest.fixture
def mock_redis():
    r = MagicMock()
    r.ping.return_value = True
    r.get.return_value = None
    r.setex.return_value = True
    return r


@pytest.fixture
def cache(mock_redis):
    return CacheService(redis_client=mock_redis)


def test_get_cache_miss(cache, mock_redis):
    mock_redis.get.return_value = None
    assert cache.get("virustotal:1.2.3.4") is None


def test_get_cache_hit(cache, mock_redis):
    import json
    mock_redis.get.return_value = json.dumps({"malicious": 5})
    result = cache.get("virustotal:1.2.3.4")
    assert result == {"malicious": 5}


def test_set_calls_setex(cache, mock_redis):
    cache.set("virustotal:1.2.3.4", {"malicious": 3}, ttl_seconds=3600)
    mock_redis.setex.assert_called_once()
    args = mock_redis.setex.call_args[0]
    assert args[0] == "virustotal:1.2.3.4"
    assert args[1] == 3600


def test_make_key(cache):
    assert cache.make_key("shodan", "8.8.8.8") == "shodan:8.8.8.8"


def test_no_redis_returns_none():
    cache = CacheService(redis_client=None)
    assert cache.get("any:key") is None
    assert cache.set("any:key", {"x": 1}) is False
    assert cache.available is False


def test_available_with_redis(cache):
    assert cache.available is True
