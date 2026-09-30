import asyncio
import json
import logging
import os
import time
from abc import abstractmethod
from typing import Any

import httpx
from langchain_core.tools import BaseTool
from pydantic import ConfigDict

logger = logging.getLogger(__name__)

_shared_client: httpx.AsyncClient | None = None


def get_shared_client() -> httpx.AsyncClient:
    """Returns a shared httpx.AsyncClient with connection pooling."""
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
            timeout=15.0,
        )
    return _shared_client


async def close_shared_client() -> None:
    """Closes the shared httpx.AsyncClient during application shutdown."""
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
        _shared_client = None


class ThreatIntelTool(BaseTool):
    api_name: str
    api_key_env: str = ""
    base_url: str
    rate_limit_per_day: int = 500
    rate_limit_per_minute: int = 60
    redis_client: Any = None
    # Optional AsyncSession; when provided, rate limit counters are enforced via DB.
    db: Any = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def client(self) -> httpx.AsyncClient:
        return get_shared_client()

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

    def _redact_secrets(self, text: str) -> str:
        """Strip the API key from error text: some upstream errors (e.g.
        httpx status errors) embed the full request URL, and agents persist
        the error string in the database."""
        key = os.environ.get(self.api_key_env, "") if self.api_key_env else ""
        if key:
            text = text.replace(key, "***")
        return text

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
        agent_name = kwargs.pop("agent_name", None)
        context = kwargs.pop("context", None)
        wait = kwargs.pop("wait", True)
        decision = None
        eval_args = None
        if not agent_name:
            from app.config import settings
            from agentgate.audit.service import get_default_audit_service
            from agentgate.client.pep import PermissionDeniedError
            from agentgate.models.decision import DecisionResult, DecisionType

            is_strict = getattr(settings, "AGENTGATE_STRICT", False) or getattr(settings, "APP_ENV", "development") == "production"
            eval_args = {"ioc_value": ioc_value, **kwargs}
            inv_id = str(context["investigation_id"]) if context and "investigation_id" in context else None

            if is_strict:
                reason = "missing agent identity"
                denied_decision = DecisionResult(
                    decision=DecisionType.DENY,
                    reason=reason,
                    agent="unknown",
                    tool=self.api_name,
                    arguments=eval_args,
                    requires_human=False,
                    event_type="DECISION",
                    investigation_id=inv_id,
                )
                try:
                    get_default_audit_service().record(denied_decision)
                except Exception as audit_err:
                    logger.warning("Failed to record AgentGate audit for missing agent: %s", audit_err)

                logger.error("AgentGate strict mode DENY: tool %s called without agent_name", self.api_name)
                raise PermissionDeniedError(denied_decision)
            else:
                logger.warning("AgentGate non-strict warning: tool %s called without agent_name (treating as agent=unknown)", self.api_name)
                try:
                    bypass_decision = DecisionResult(
                        decision=DecisionType.ALLOW,
                        reason="tool called without agent identity in non-strict mode",
                        agent="unknown",
                        tool=self.api_name,
                        arguments=eval_args,
                        requires_human=False,
                        event_type="DECISION",
                        investigation_id=inv_id,
                    )
                    get_default_audit_service().record(bypass_decision)
                except Exception as audit_err:
                    logger.warning("Failed to record AgentGate audit for missing agent: %s", audit_err)
        else:
            from agentgate.client.pep import PolicyEnforcementPoint
            from agentgate.models.decision import DecisionType

            pep = PolicyEnforcementPoint()
            eval_args = {"ioc_value": ioc_value, **kwargs}
            decision = await pep.authorize(
                agent=agent_name,
                tool=self.api_name,
                arguments=eval_args,
                context=context,
                wait=wait,
            )

            if decision.decision == DecisionType.MASK and decision.masked_arguments:
                if decision.masked_arguments.get("ioc_value", ioc_value) != ioc_value:
                    # The IOC itself is sensitive (e.g. RFC 1918 address): sending a
                    # redacted placeholder to a third party is useless and would poison
                    # the cache, so skip the lookup entirely. The decision is audited.
                    return {
                        "source": self.api_name,
                        "skipped": True,
                        "reason": "IOC masked by AgentGate policy; not sent to third-party API",
                        "cached": False,
                    }
                for k, v in decision.masked_arguments.items():
                    if k in kwargs:
                        kwargs[k] = v

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
        try:
            raw = await self._call_api(ioc_value, **kwargs)
        except Exception as e:
            if decision and getattr(decision, "approval_id", None):
                try:
                    from agentgate.audit.service import get_default_audit_service
                    inv_id = str(context["investigation_id"]) if context and "investigation_id" in context else None
                    get_default_audit_service().record_event(
                        event_type="EXECUTION",
                        agent=agent_name,
                        tool=self.api_name,
                        decision="ALLOW",
                        reason=f"Tool execution failed: {e}",
                        execution_result=f"error:{type(e).__name__}",
                        approval_id=decision.approval_id,
                        investigation_id=inv_id,
                        arguments=eval_args,
                    )
                except Exception:
                    pass
            raise RuntimeError(
                f"{self.api_name} call failed: {self._redact_secrets(str(e))}"
            ) from None
        elapsed_ms = int((time.monotonic() - start) * 1000)

        if decision and getattr(decision, "approval_id", None):
            try:
                from agentgate.audit.service import get_default_audit_service
                inv_id = str(context["investigation_id"]) if context and "investigation_id" in context else None
                get_default_audit_service().record_event(
                    event_type="EXECUTION",
                    agent=agent_name,
                    tool=self.api_name,
                    decision="ALLOW",
                    reason="Tool execution completed",
                    execution_result="success",
                    approval_id=decision.approval_id,
                    investigation_id=inv_id,
                    arguments=eval_args,
                )
            except Exception:
                pass

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
