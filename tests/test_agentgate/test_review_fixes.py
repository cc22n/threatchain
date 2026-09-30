"""Regression tests for the supervisor review of the AgentGate completion work."""
import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from agentgate.audit import AuditLogService
from agentgate.client.pep import PolicyEnforcementPoint
from agentgate.core.pdp import PolicyDecisionPoint, get_default_pdp
from agentgate.hitl.queue import ApprovalQueue, ApprovalStatus
from agentgate.models.manifest import AgentManifest, ToolPermission
from app.config import Settings, settings
from app.main import app


def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def auth_headers(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "review-key")
    return {"X-API-Key": "review-key"}


# --- 1. approval TTL must match the real wait --------------------------------

def test_set_ttl_shortens_but_never_extends():
    q = ApprovalQueue()
    req = q.create_request("a", "t", {}, ttl_seconds=300)
    q.set_ttl(req.id, 30)
    assert (req.expires_at - datetime.now(timezone.utc)).total_seconds() <= 30

    short = q.create_request("a", "t", {}, ttl_seconds=5)
    before = short.expires_at
    q.set_ttl(short.id, 100)
    assert short.expires_at == before


def test_set_ttl_ignores_resolved_requests():
    q = ApprovalQueue()
    req = q.create_request("a", "t", {}, ttl_seconds=300)
    q.approve(req.id, approver="alice")
    before = req.expires_at
    q.set_ttl(req.id, 1)
    assert req.expires_at == before
    assert req.status == ApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_authorize_aligns_request_expiry_with_wait_seconds():
    queue = ApprovalQueue()
    pdp = PolicyDecisionPoint(audit_service=AuditLogService(), approval_queue=queue)
    pdp.register_manifest(
        AgentManifest(agent="ttl_agent", tools_allowed=[ToolPermission(name="t")], requires_approval=["risky"])
    )
    pep = PolicyEnforcementPoint(pdp=pdp)

    with patch("agentgate.client.pep.get_default_approval_queue", return_value=queue), \
         patch("app.config.settings.AGENTGATE_APPROVAL_WAIT_SECONDS", 30), \
         patch("app.config.settings.AGENTGATE_TELEGRAM_NOTIFY", False):
        task = asyncio.create_task(pep.authorize("ttl_agent", "risky", {"x": 1}, wait=True))
        await asyncio.sleep(0.05)
        pending = queue.list_pending()
        assert len(pending) == 1
        # Was 300 s before the fix (queue default), which made the Telegram "Expires at" a lie.
        assert (pending[0].expires_at - pending[0].requested_at).total_seconds() <= 31
        queue.approve(pending[0].id, approver="alice")
        result = await task

    assert result.approval_id == pending[0].id


def test_config_warns_when_approval_wait_exceeds_investigation_timeout(caplog):
    with caplog.at_level(logging.WARNING, logger="app.config"):
        Settings(AGENTGATE_APPROVAL_WAIT_SECONDS=200, INVESTIGATION_TIMEOUT_SECONDS=120)
    assert any("AGENTGATE_APPROVAL_WAIT_SECONDS" in r.message for r in caplog.records)


def test_config_silent_with_sane_values(caplog):
    with caplog.at_level(logging.WARNING, logger="app.config"):
        Settings(AGENTGATE_APPROVAL_WAIT_SECONDS=90, INVESTIGATION_TIMEOUT_SECONDS=120)
    assert not any("AGENTGATE_APPROVAL_WAIT_SECONDS" in r.message for r in caplog.records)


# --- 4a. trailing newline must not pass identifier validation ----------------

@pytest.mark.asyncio
async def test_trailing_newline_rejected_in_identifiers(auth_headers):
    async with _client() as c:
        assert (await c.get("/agentgate/api/manifests/recon_agent%0A", headers=auth_headers)).status_code == 422
        assert (await c.put(
            "/agentgate/api/manifests/recon_agent%0A",
            headers=auth_headers,
            json={"agent": "recon_agent\n"},
        )).status_code == 422
        assert (await c.get("/agentgate/api/decisions?agent=recon_agent%0A", headers=auth_headers)).status_code == 422
        assert (await c.get("/agentgate/api/decisions?tool=virustotal%0A", headers=auth_headers)).status_code == 422
        assert (await c.post(
            "/agentgate/api/approve/does-not-matter?approver=alice%0A", headers=auth_headers
        )).status_code == 422
        assert (await c.post(
            "/agentgate/api/reject/does-not-matter?approver=alice%0A", headers=auth_headers
        )).status_code == 422


# --- 4b. manifest editor writes where the PDP loaded from, not the cwd -------

@pytest.mark.asyncio
async def test_manifest_put_writes_to_pdp_directory_not_cwd(auth_headers, tmp_path, monkeypatch):
    manifests_dir = tmp_path / "manifests"
    manifests_dir.mkdir()
    (manifests_dir / "edit_agent.json").write_text(
        json.dumps({"agent": "edit_agent", "tools_allowed": [{"name": "t"}]}), encoding="utf-8"
    )
    pdp = PolicyDecisionPoint(audit_service=AuditLogService(), approval_queue=ApprovalQueue())
    assert pdp.load_manifests_dir(manifests_dir) == 1
    assert pdp.manifests_dir == manifests_dir.resolve()

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)  # a different cwd must not change where the file is written

    body = {"agent": "edit_agent", "tools_allowed": [{"name": "t"}, {"name": "t2"}]}
    with patch("agentgate.dashboard.routes.get_default_pdp", return_value=pdp), \
         patch("agentgate.dashboard.routes.get_default_audit_service", return_value=pdp.audit_service):
        async with _client() as c:
            res = await c.put("/agentgate/api/manifests/edit_agent", headers=auth_headers, json=body)

    assert res.status_code == 200, res.text
    written = json.loads((manifests_dir / "edit_agent.json").read_text(encoding="utf-8"))
    assert [t["name"] for t in written["tools_allowed"]] == ["t", "t2"]
    assert written["version"] == "1.0.1"
    assert not (elsewhere / "agentgate").exists()
    assert list(manifests_dir.glob("tmp*")) == []  # no leftover temp files


# --- 4c. diagnostic script works in strict/production mode -------------------

@pytest.mark.asyncio
async def test_check_apis_goes_through_agentgate_in_production(monkeypatch, vt_response):
    from app.tools.virustotal import VirusTotalTool
    from scripts import check_apis

    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_key")
    check_apis.register_healthcheck_manifest()
    try:
        with patch.object(VirusTotalTool, "_call_api", new=AsyncMock(return_value=vt_response)):
            res = await check_apis.test_tool("VirusTotal", VirusTotalTool, "8.8.8.8", ioc_type="ip")
    finally:
        get_default_pdp().manifests.pop(check_apis.HEALTHCHECK_AGENT, None)

    assert res["status"] == "ok", res
