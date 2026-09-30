import json
import logging
from typing import Any
from app.config import settings

logger = logging.getLogger(__name__)


class CacheService:
    def __init__(self, redis_client=None):
        self.redis = redis_client

    def get(self, key: str) -> Any | None:
        if not self.redis:
            return None
        try:
            raw = self.redis.get(key)
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.warning("Cache GET failed for %s: %s", key, e)
            return None

    def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> bool:
        if not self.redis:
            return False
        if ttl_seconds is None:
            ttl_seconds = getattr(settings, "CACHE_TTL_HOURS", 24) * 3600
        try:
            self.redis.setex(key, ttl_seconds, json.dumps(value, default=str))
            return True
        except Exception as e:
            logger.warning("Cache SET failed for %s: %s", key, e)
            return False

    def delete(self, key: str) -> bool:
        if not self.redis:
            return False
        try:
            self.redis.delete(key)
            return True
        except Exception as e:
            logger.warning("Cache DELETE failed for %s: %s", key, e)
            return False

    def make_key(self, api_name: str, ioc_value: str) -> str:
        return f"{api_name}:{ioc_value}"

    @property
    def available(self) -> bool:
        if not self.redis:
            return False
        try:
            self.redis.ping()
            return True
        except Exception:
            return False


_redis_client = None


def get_redis_client():
    """
    Return a module-level Redis client singleton.
    Retries connecting if previous attempts failed.
    Returns None if Redis is unavailable so callers can operate in cache-disabled mode.
    """
    global _redis_client
    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_client = None

    try:
        import redis
        client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
        )
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as e:
        logger.warning("Redis not available: %s", e)
        return None
