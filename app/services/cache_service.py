import json
import logging
from typing import Any

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

    def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> bool:
        if not self.redis:
            return False
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


def get_redis_client():
    try:
        import redis
        from app.config import settings
        client = redis.from_url(settings.REDIS_URL, decode_responses=True)
        client.ping()
        return client
    except Exception as e:
        logger.warning("Redis not available: %s", e)
        return None
