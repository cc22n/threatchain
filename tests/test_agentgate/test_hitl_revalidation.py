import pytest
from datetime import datetime, timezone, timedelta
from agentgate.hitl.queue import ApprovalRequest, ApprovalStatus
from agentgate.hitl.revalidator import ContextRevalidator


def test_revalidate_matching_context():
    revalidator = ContextRevalidator()
    req = ApprovalRequest(
        agent="recon_agent",
        tool="quarantine_host",
        arguments={"host": "node-1"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        context_snapshot={"api_key": "active_token_123", "session_id": "sess_abc"},
    )

    current_context = {"api_key": "active_token_123", "session_id": "sess_abc"}
    ok, msg = revalidator.revalidate(req, current_context)
    assert ok is True
    assert "successfully revalidated" in msg


def test_revalidate_rotated_credential_rejected():
    revalidator = ContextRevalidator()
    req = ApprovalRequest(
        agent="recon_agent",
        tool="quarantine_host",
        arguments={"host": "node-1"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        context_snapshot={"api_key": "original_key_123"},
    )

    # Key rotated while human was reviewing
    rotated_context = {"api_key": "newly_rotated_key_999"}
    ok, msg = revalidator.revalidate(req, rotated_context)
    assert ok is False
    assert "Credential mismatch" in msg


def test_revalidate_missing_required_key():
    revalidator = ContextRevalidator()
    req = ApprovalRequest(
        agent="recon_agent",
        tool="quarantine_host",
        arguments={"host": "node-1"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        context_snapshot={},
    )

    ok, msg = revalidator.revalidate(req, {}, required_keys=["tenant_id"])
    assert ok is False
    assert "Missing required context key" in msg
