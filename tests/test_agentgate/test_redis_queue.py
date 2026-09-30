import asyncio
import fnmatch
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch
import pytest

from agentgate.client.pep import PolicyEnforcementPoint
from agentgate.core.pdp import PolicyDecisionPoint
from agentgate.hitl.queue import (
    ApprovalQueue,
    ApprovalRequest,
    ApprovalStatus,
    get_default_approval_queue,
    set_default_approval_queue,
)
from agentgate.models.manifest import AgentManifest, ToolPermission


class FakeRedis:
    """In-memory Redis fake for testing ApprovalQueue synchronization."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._expiry: dict[str, float] = {}
        self.fail_setex = False
        self.fail_get = False
        self.fail_keys = False

    def setex(self, name: str, time_seconds: int, value: str) -> bool:
        if self.fail_setex:
            raise ConnectionError("Simulated Redis connection error on setex")
        self._store[name] = str(value)
        self._expiry[name] = time.time() + time_seconds
        return True

    def get(self, name: str) -> str | None:
        if self.fail_get:
            raise ConnectionError("Simulated Redis connection error on get")
        if name in self._expiry and time.time() > self._expiry[name]:
            self._store.pop(name, None)
            self._expiry.pop(name, None)
            return None
        return self._store.get(name)

    def scan_iter(self, match: str | None = None):
        if self.fail_keys:
            raise ConnectionError("Simulated Redis connection error on scan_iter")
        self._purge_expired()
        for k in list(self._store.keys()):
            if match is None or fnmatch.fnmatch(k, match):
                yield k

    def keys(self, pattern: str = "*") -> list[str]:
        if self.fail_keys:
            raise ConnectionError("Simulated Redis connection error on keys")
        self._purge_expired()
        return [k for k in self._store.keys() if fnmatch.fnmatch(k, pattern)]

    def _purge_expired(self):
        now = time.time()
        for k in list(self._expiry.keys()):
            if now > self._expiry[k]:
                self._store.pop(k, None)
                self._expiry.pop(k, None)


@pytest.fixture
def fake_redis():
    return FakeRedis()


def test_redis_queue_persist_and_read(fake_redis):
    queue1 = ApprovalQueue(redis_client=fake_redis)

    req = queue1.create_request(
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.2.3.4"},
        ttl_seconds=300,
        context={"investigation_id": "inv-123"},
    )

    redis_key = f"agentgate:approval:{req.id}"
    assert redis_key in fake_redis._store
    assert "recon_agent" in fake_redis._store[redis_key]
    assert "block_ip" in fake_redis._store[redis_key]

    # Second queue instance simulating another process with empty memory
    queue2 = ApprovalQueue(redis_client=fake_redis)
    assert req.id not in queue2._memory_store

    fetched = queue2.get_request(req.id)
    assert fetched is not None
    assert fetched.id == req.id
    assert fetched.agent == "recon_agent"
    assert fetched.tool == "block_ip"
    assert fetched.arguments == {"ip": "1.2.3.4"}
    assert fetched.status == ApprovalStatus.PENDING
    assert fetched.context_snapshot == {"investigation_id": "inv-123"}


def test_redis_queue_approve_updates_redis(fake_redis):
    queue1 = ApprovalQueue(redis_client=fake_redis)
    req = queue1.create_request(
        agent="vuln_agent",
        tool="nmap_scan",
        arguments={"target": "10.0.0.1"},
    )

    approved = queue1.approve(req.id, approver="soc_lead", notes="Authorized internal test")
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.approver == "soc_lead"

    # Verify Redis key has updated state
    raw = fake_redis.get(f"agentgate:approval:{req.id}")
    assert raw is not None
    synced = ApprovalRequest.model_validate_json(raw)
    assert synced.status == ApprovalStatus.APPROVED
    assert synced.approver == "soc_lead"
    assert synced.notes == "Authorized internal test"

    # Second queue sees approved status directly
    queue2 = ApprovalQueue(redis_client=fake_redis)
    fetched = queue2.get_request(req.id)
    assert fetched.status == ApprovalStatus.APPROVED
    assert fetched.approver == "soc_lead"


def test_redis_queue_reject_updates_redis(fake_redis):
    queue1 = ApprovalQueue(redis_client=fake_redis)
    req = queue1.create_request(
        agent="osint_agent",
        tool="shodan_query",
        arguments={"query": "sensitive_org"},
    )

    rejected = queue1.reject(req.id, approver="compliance_officer", notes="Scope violation")
    assert rejected.status == ApprovalStatus.REJECTED

    queue2 = ApprovalQueue(redis_client=fake_redis)
    fetched = queue2.get_request(req.id)
    assert fetched.status == ApprovalStatus.REJECTED
    assert fetched.approver == "compliance_officer"
    assert fetched.notes == "Scope violation"


@pytest.mark.asyncio
async def test_redis_queue_cross_process_approve_wait(fake_redis):
    queue1 = ApprovalQueue(redis_client=fake_redis)
    queue2 = ApprovalQueue(redis_client=fake_redis)

    req = queue1.create_request(
        agent="recon_agent",
        tool="deep_scan",
        arguments={"target": "192.168.1.1"},
        ttl_seconds=10,
    )

    async def remote_worker_approve():
        await asyncio.sleep(0.05)
        # queue2 operates in its own memory space and writes to Redis
        queue2.approve(req.id, approver="remote_operator", notes="Approved remotely")

    task = asyncio.create_task(remote_worker_approve())
    result = await queue1.wait_for_decision(req.id, timeout=2.0, poll_interval=0.02)
    await task

    assert result.status == ApprovalStatus.APPROVED
    assert result.approver == "remote_operator"
    assert result.notes == "Approved remotely"


@pytest.mark.asyncio
async def test_redis_queue_cross_process_reject_wait(fake_redis):
    queue1 = ApprovalQueue(redis_client=fake_redis)
    queue2 = ApprovalQueue(redis_client=fake_redis)

    req = queue1.create_request(
        agent="recon_agent",
        tool="deep_scan",
        arguments={"target": "192.168.1.1"},
        ttl_seconds=10,
    )

    async def remote_worker_reject():
        await asyncio.sleep(0.05)
        queue2.reject(req.id, approver="remote_admin", notes="Blocked remotely")

    task = asyncio.create_task(remote_worker_reject())
    result = await queue1.wait_for_decision(req.id, timeout=2.0, poll_interval=0.02)
    await task

    assert result.status == ApprovalStatus.REJECTED
    assert result.approver == "remote_admin"


def test_redis_queue_ttl_expiration(fake_redis):
    queue = ApprovalQueue(redis_client=fake_redis)
    req = queue.create_request(
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.1.1.1"},
        ttl_seconds=1,
    )

    # Force expiration in past in both memory and redis
    req.expires_at = datetime.now(timezone.utc) - timedelta(seconds=2)
    queue._memory_store[req.id] = req
    queue._persist_to_redis(req)

    fetched = queue.get_request(req.id)
    assert fetched.status == ApprovalStatus.EXPIRED

    with pytest.raises(ValueError, match="expired"):
        queue.approve(req.id)

    # Also verify that when Redis TTL key is purged, queue safely handles absence
    fake_redis._expiry[f"agentgate:approval:{req.id}"] = time.time() - 10
    assert fake_redis.get(f"agentgate:approval:{req.id}") is None
    fetched2 = queue.get_request(req.id)
    assert fetched2.status == ApprovalStatus.EXPIRED


def test_redis_queue_failure_resilience_memory_fallback(fake_redis):
    fake_redis.fail_setex = True
    fake_redis.fail_get = True
    fake_redis.fail_keys = True

    queue = ApprovalQueue(redis_client=fake_redis)

    # create_request degrades to memory without raising
    req = queue.create_request(
        agent="fallback_agent",
        tool="safe_tool",
        arguments={"param": "value"},
    )
    assert req.id is not None
    assert req.status == ApprovalStatus.PENDING

    # get_request degrades to memory without raising
    fetched = queue.get_request(req.id)
    assert fetched is not None
    assert fetched.id == req.id

    # approve degrades to memory without raising
    approved = queue.approve(req.id, approver="local_admin")
    assert approved.status == ApprovalStatus.APPROVED

    # list_pending degrades to memory without raising
    pending = queue.list_pending()
    assert isinstance(pending, list)


def test_redis_queue_list_pending_discovers_remote_requests(fake_redis):
    queue1 = ApprovalQueue(redis_client=fake_redis)
    queue2 = ApprovalQueue(redis_client=fake_redis)

    req1 = queue1.create_request(agent="agent_a", tool="tool_a", arguments={}, ttl_seconds=300)
    req2 = queue1.create_request(agent="agent_b", tool="tool_b", arguments={}, ttl_seconds=300)

    # queue2 has empty memory store initially
    assert len(queue2._memory_store) == 0

    pending = queue2.list_pending()
    assert len(pending) == 2
    pending_ids = {r.id for r in pending}
    assert req1.id in pending_ids
    assert req2.id in pending_ids


@pytest.mark.asyncio
async def test_m1_hitl_flow_with_redis_backed_queue(fake_redis):
    """Verify DoD M4: M1 pause & resume flow functions seamlessly with Redis-backed queue."""
    queue = ApprovalQueue(redis_client=fake_redis)
    manifest = AgentManifest(
        agent="redis_hitl_agent",
        tools_allowed=[ToolPermission(name="guarded_tool")],
        requires_approval=["guarded_tool"],
    )
    pdp = PolicyDecisionPoint(approval_queue=queue)
    pdp.register_manifest(manifest)
    pep = PolicyEnforcementPoint(pdp=pdp)

    tool_mock = AsyncMock(return_value={"executed_with_redis": True})

    async def auto_approve():
        await asyncio.sleep(0.05)
        # Simulate approval arriving via another worker or callback
        pending = queue.list_pending()
        assert len(pending) == 1
        queue.approve(pending[0].id, approver="redis_operator")

    task = asyncio.create_task(auto_approve())
    result = await pep.check_and_execute(
        tool_mock,
        agent="redis_hitl_agent",
        tool="guarded_tool",
        arguments={"key": "val"},
        fn_kwargs={"key": "val"},
        wait=True,
    )
    await task

    assert result == {"executed_with_redis": True}
    tool_mock.assert_awaited_once_with(key="val")


def test_approval_queue_configure_lifecycle(fake_redis):
    queue = get_default_approval_queue()
    assert queue is not None

    queue.configure(fake_redis)
    assert queue.redis is fake_redis

    queue.configure(None)
    assert queue.redis is None
