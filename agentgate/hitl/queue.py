import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    approver: str | None = None
    notes: str | None = None
    resolved_at: datetime | None = None
    context_snapshot: dict[str, Any] = Field(default_factory=dict)


def _is_expired(expires_at: datetime) -> bool:
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return now > expires_at


class ApprovalQueue:
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._memory_store: dict[str, ApprovalRequest] = {}
        self._events: dict[str, asyncio.Event] = {}

    def configure(self, redis_client=None) -> None:
        """Inject or update Redis client for cross-process synchronization."""
        self.redis = redis_client

    def _persist_to_redis(self, req: ApprovalRequest) -> None:
        if self.redis is None:
            return
        try:
            now = datetime.now(timezone.utc)
            expires_at = req.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            ttl = int((expires_at - now).total_seconds())
            if ttl <= 0 or req.status != ApprovalStatus.PENDING:
                ttl = max(ttl, 60)
            self.redis.setex(f"agentgate:approval:{req.id}", ttl, req.model_dump_json())
        except Exception as e:
            logger.warning("Redis persist failed for approval request %s: %s", req.id, e)

    def _get_from_redis(self, approval_id: str) -> ApprovalRequest | None:
        if self.redis is None:
            return None
        try:
            raw = self.redis.get(f"agentgate:approval:{approval_id}")
            if raw:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                return ApprovalRequest.model_validate_json(raw)
        except Exception as e:
            logger.warning("Redis get failed for approval request %s: %s", approval_id, e)
        return None

    def create_request(
        self,
        agent: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 300,
        context: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        now = datetime.now(timezone.utc)
        req = ApprovalRequest(
            agent=agent,
            tool=tool,
            arguments=arguments,
            expires_at=now + timedelta(seconds=ttl_seconds),
            context_snapshot=context or {},
        )
        self._memory_store[req.id] = req
        self._events[req.id] = asyncio.Event()

        self._persist_to_redis(req)
        return req

    def get_request(self, approval_id: str) -> ApprovalRequest | None:
        req = self._memory_store.get(approval_id)
        if self.redis is not None:
            if req is None or req.status == ApprovalStatus.PENDING:
                remote_req = self._get_from_redis(approval_id)
                if remote_req:
                    req = remote_req
                    self._memory_store[approval_id] = req
                    if req.status != ApprovalStatus.PENDING and approval_id in self._events:
                        self._events[approval_id].set()

        if req and req.status == ApprovalStatus.PENDING:
            if _is_expired(req.expires_at):
                req.status = ApprovalStatus.EXPIRED
                self._persist_to_redis(req)
                if approval_id in self._events:
                    self._events[approval_id].set()
        return req

    def set_ttl(self, approval_id: str, ttl_seconds: float) -> ApprovalRequest | None:
        """
        Re-anchor a pending request's expiry to now + ttl_seconds, but never extend it.
        The PDP creates requests with the queue default (300 s); the PEP calls this so the
        expiry shown to the human matches the time the caller actually waits.
        """
        req = self.get_request(approval_id)
        if req is None or req.status != ApprovalStatus.PENDING:
            return req
        new_expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        current = req.expires_at if req.expires_at.tzinfo else req.expires_at.replace(tzinfo=timezone.utc)
        if new_expiry < current:
            req.expires_at = new_expiry
            self._persist_to_redis(req)
        return req

    def approve(self, approval_id: str, approver: str = "operator", notes: str = "") -> ApprovalRequest:
        req = self.get_request(approval_id)
        if not req:
            raise KeyError(f"Approval request {approval_id} not found")
        if req.status == ApprovalStatus.EXPIRED:
            raise ValueError(f"Approval request {approval_id} has expired")
        if req.status == ApprovalStatus.APPROVED:
            return req
        if req.status == ApprovalStatus.REJECTED:
            raise ValueError(f"Approval request {approval_id} was already rejected")

        req.status = ApprovalStatus.APPROVED
        req.approver = approver
        req.notes = notes
        req.resolved_at = datetime.now(timezone.utc)

        self._memory_store[approval_id] = req
        self._persist_to_redis(req)

        # Signal waiting coroutine
        if approval_id in self._events:
            self._events[approval_id].set()

        return req

    def reject(self, approval_id: str, approver: str = "operator", notes: str = "") -> ApprovalRequest:
        req = self.get_request(approval_id)
        if not req:
            raise KeyError(f"Approval request {approval_id} not found")
        if req.status == ApprovalStatus.EXPIRED:
            raise ValueError(f"Approval request {approval_id} has expired")
        if req.status == ApprovalStatus.REJECTED:
            return req
        if req.status == ApprovalStatus.APPROVED:
            raise ValueError(f"Approval request {approval_id} was already approved")

        req.status = ApprovalStatus.REJECTED
        req.approver = approver
        req.notes = notes
        req.resolved_at = datetime.now(timezone.utc)

        self._memory_store[approval_id] = req
        self._persist_to_redis(req)

        if approval_id in self._events:
            self._events[approval_id].set()

        return req

    async def wait_for_decision(
        self,
        approval_id: str,
        timeout: float | None = None,
        poll_interval: float = 0.5,
    ) -> ApprovalRequest:
        req = self.get_request(approval_id)
        if not req:
            raise KeyError(f"Approval request {approval_id} not found")

        if req.status != ApprovalStatus.PENDING:
            return req

        event = self._events.get(approval_id)
        if event is None:
            event = asyncio.Event()
            self._events[approval_id] = event

        loop = asyncio.get_running_loop()
        start_time = loop.time()

        try:
            while not event.is_set():
                if _is_expired(req.expires_at):
                    req.status = ApprovalStatus.EXPIRED
                    self._persist_to_redis(req)
                    event.set()
                    break

                elapsed = loop.time() - start_time
                if timeout is not None and elapsed >= timeout:
                    req.status = ApprovalStatus.EXPIRED
                    self._persist_to_redis(req)
                    event.set()
                    break

                step = poll_interval
                if timeout is not None:
                    remaining = timeout - elapsed
                    if remaining <= 0:
                        req.status = ApprovalStatus.EXPIRED
                        self._persist_to_redis(req)
                        event.set()
                        break
                    step = min(step, remaining)

                try:
                    await asyncio.wait_for(event.wait(), timeout=step)
                    break
                except asyncio.TimeoutError:
                    if self.redis is not None:
                        remote_req = self._get_from_redis(approval_id)
                        if remote_req and remote_req.status != ApprovalStatus.PENDING:
                            self._memory_store[approval_id] = remote_req
                            req = remote_req
                            event.set()
                            break

        except asyncio.CancelledError:
            req.status = ApprovalStatus.EXPIRED
            self._persist_to_redis(req)
            event.set()
            raise

        return self.get_request(approval_id) or req

    def list_pending(self) -> list[ApprovalRequest]:
        now = datetime.now(timezone.utc)
        if self.redis is not None:
            try:
                keys = []
                if hasattr(self.redis, "scan_iter"):
                    keys = list(self.redis.scan_iter("agentgate:approval:*"))
                elif hasattr(self.redis, "keys"):
                    keys = self.redis.keys("agentgate:approval:*")
                for k in keys:
                    key_str = k if isinstance(k, str) else k.decode("utf-8")
                    approval_id = key_str.split(":")[-1]
                    if approval_id not in self._memory_store or self._memory_store[approval_id].status == ApprovalStatus.PENDING:
                        self.get_request(approval_id)
            except Exception as e:
                logger.warning("Redis discovery failed in list_pending: %s", e)

        pending = []
        for req in list(self._memory_store.values()):
            if req.status == ApprovalStatus.PENDING:
                if _is_expired(req.expires_at):
                    req.status = ApprovalStatus.EXPIRED
                    self._persist_to_redis(req)
                else:
                    pending.append(req)
        return pending


_global_queue: ApprovalQueue | None = None


def get_default_approval_queue(redis_client=None) -> ApprovalQueue:
    global _global_queue
    if _global_queue is None:
        _global_queue = ApprovalQueue(redis_client=redis_client)
    elif redis_client is not None:
        _global_queue.configure(redis_client)
    return _global_queue


def set_default_approval_queue(queue: ApprovalQueue | None) -> None:
    """Set or reset the global queue instance."""
    global _global_queue
    _global_queue = queue
