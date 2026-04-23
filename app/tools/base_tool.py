import asyncio
import json
import logging
import os
import time
from abc import abstractmethod
from typing import Any

from langchain_core.tools import BaseTool

logger = logging.getLogger(__name__)


class ThreatIntelTool(BaseTool):
    api_name: str
    api_key_env: str = ""
    base_url: str
    rate_limit_per_day: int = 500
    rate_limit_per_minute: int = 60
    redis_client: Any = None
    # Optional AsyncSession; when provided, rate limit counters are enforced via DB.
    db: Any = None

    class Config:
        arbitrary_types_allowed = True

    @abstractmethod
    async def _call_api(self, ioc_value: str, **kwargs) -> dict: ...

    @abstractmethod
    def _normalize(self, raw: dict) -> dict: ...

    def _get_api_key(self) -> str:
        if not self.api_key_env:
            return ""
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise ValueError(f"Missing env var: {self.api_key_env}")
        return key

    def _cache_get(self, key: str) -> dict | None:
        if self.redis_client is None:
            return None
        try:
            raw = self.redis_client.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def _cache_set(self, key: str, value: dict, ttl: int = 86400) -> None:
        if self.redis_client is None:
            return
        try:
            self.redis_client.setex(key, ttl, json.dumps(value))
        except Exception as e:
            logger.warning("Cache write failed for %s: %s", key, e)

    async def _arun(self, ioc_value: str, **kwargs) -> dict:
        cache_key = f"{self.api_name}:{ioc_value}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return {**cached, "cached": True}

        if self.db is not None:
            from app.services.rate_limiter import RateLimiter
            allowed = await RateLimiter(self.db).check_and_increment(self.api_name)
            if not allowed:
                raise RuntimeError(f"Rate limit reached for {self.api_name}")

        start = time.monotonic()
        raw = await self._call_api(ioc_value, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        normalized = self._normalize(raw)
        normalized["response_time_ms"] = elapsed_ms
        normalized["cached"] = False

        self._cache_set(cache_key, normalized)
        return normalized

    def _run(self, ioc_value: str, **kwargs) -> dict:
        # asyncio.run() raises RuntimeError when called from inside a running
        # event loop (i.e. from within FastAPI / uvicorn).  All production
        # callers use _arun; this sync shim is only safe in scripts/tests that
        # have no running loop.  We keep it for LangChain BaseTool compatibility
        # but document the constraint clearly.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            raise RuntimeError(
                f"{self.__class__.__name__}._run() called inside a running event loop. "
                "Use await tool._arun() instead."
            )
        return asyncio.run(self._arun(ioc_value, **kwargs))
