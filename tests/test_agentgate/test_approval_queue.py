import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from agentgate.hitl.queue import ApprovalQueue, ApprovalStatus


def test_approval_queue_lifecycle():
    queue = ApprovalQueue()

    req = queue.create_request(
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.2.3.4"},
        ttl_seconds=10,
    )
    assert req.id is not None
    assert req.status == ApprovalStatus.PENDING

    # Approve
    approved = queue.approve(req.id, approver="soc_analyst_1", notes="Verified malicious C2")
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.approver == "soc_analyst_1"


def test_approval_queue_rejection():
    queue = ApprovalQueue()

    req = queue.create_request(
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "8.8.8.8"},
    )
    rejected = queue.reject(req.id, approver="admin", notes="Do not block DNS")
    assert rejected.status == ApprovalStatus.REJECTED
    assert rejected.notes == "Do not block DNS"


def test_approval_queue_expiration():
    queue = ApprovalQueue()

    req = queue.create_request(
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.1.1.1"},
        ttl_seconds=0,
    )
    # Fast forward expiration
    req.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    fetched = queue.get_request(req.id)
    assert fetched.status == ApprovalStatus.EXPIRED

    with pytest.raises(ValueError, match="expired"):
        queue.approve(req.id)


@pytest.mark.asyncio
async def test_wait_for_decision_async():
    queue = ApprovalQueue()

    req = queue.create_request(
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "9.9.9.9"},
        ttl_seconds=5,
    )

    async def background_approver():
        await asyncio.sleep(0.05)
        queue.approve(req.id, approver="async_operator")

    task = asyncio.create_task(background_approver())
    result = await queue.wait_for_decision(req.id, timeout=2.0)
    await task

    assert result.status == ApprovalStatus.APPROVED
    assert result.approver == "async_operator"
