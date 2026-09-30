import json
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch
import httpx
import pytest

from agentgate.audit import get_default_audit_service
from agentgate.core.pdp import get_default_pdp
from agentgate.hitl.queue import ApprovalStatus, get_default_approval_queue
from agentgate.models.decision import DecisionType
from app.config import settings
from app.main import app


def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def auth_headers(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "m6-test-key")
    return {"X-API-Key": "m6-test-key"}


@pytest.mark.asyncio
async def test_decisions_filter_valid_and_severity(auth_headers):
    pdp = get_default_pdp()
    pdp.decide("recon_agent", "virustotal", {"ip": "8.8.8.8"})
    pdp.decide("vuln_agent", "cve_search", {"cve": "CVE-2024-1234"})
    pdp.decide("recon_agent", "isolate_host", {})  # DENY

    async with _client() as c:
        # Filter by agent
        r1 = await c.get("/agentgate/api/decisions?agent=recon_agent", headers=auth_headers)
        assert r1.status_code == 200
        data1 = r1.json()
        assert len(data1) >= 2
        assert all(d["agent"] == "recon_agent" for d in data1)
        assert all("severity" in d for d in data1)

        # Filter by decision
        r2 = await c.get("/agentgate/api/decisions?decision=DENY", headers=auth_headers)
        assert r2.status_code == 200
        data2 = r2.json()
        assert any(d["tool"] == "isolate_host" for d in data2)
        assert all(d["decision"] == "DENY" for d in data2)

        # Filter by tool
        r3 = await c.get("/agentgate/api/decisions?tool=cve_search", headers=auth_headers)
        assert r3.status_code == 200
        data3 = r3.json()
        assert len(data3) >= 1
        assert all(d["tool"] == "cve_search" for d in data3)

        # Combined filter
        r4 = await c.get("/agentgate/api/decisions?agent=recon_agent&tool=virustotal&decision=ALLOW", headers=auth_headers)
        assert r4.status_code == 200
        data4 = r4.json()
        assert len(data4) >= 1
        assert all(d["agent"] == "recon_agent" and d["tool"] == "virustotal" and d["decision"] == "ALLOW" for d in data4)


@pytest.mark.asyncio
async def test_decisions_filter_invalid_parameters_return_422(auth_headers):
    async with _client() as c:
        # Invalid decision
        r_dec = await c.get("/agentgate/api/decisions?decision=INVALID_CHOICE", headers=auth_headers)
        assert r_dec.status_code == 422

        # Invalid agent (path traversal or special chars)
        r_agent = await c.get("/agentgate/api/decisions?agent=../../bad_agent", headers=auth_headers)
        assert r_agent.status_code == 422

        # Invalid tool
        r_tool = await c.get("/agentgate/api/decisions?tool=<script>", headers=auth_headers)
        assert r_tool.status_code == 422

        # Invalid limit
        r_limit = await c.get("/agentgate/api/decisions?limit=0", headers=auth_headers)
        assert r_limit.status_code == 422

        # HTML endpoint with invalid parameters
        r_html_inv = await c.get("/agentgate/api/decisions-html?decision=NOT_REAL", headers=auth_headers)
        assert r_html_inv.status_code == 422


@pytest.mark.asyncio
async def test_decisions_html_filter_rendering(auth_headers):
    pdp = get_default_pdp()
    pdp.decide("recon_agent", "virustotal", {"ip": "8.8.8.8"})

    async with _client() as c:
        r = await c.get("/agentgate/api/decisions-html?agent=recon_agent&limit=10", headers=auth_headers)
        assert r.status_code == 200
        assert "Severity" in r.text
        assert "recon_agent" in r.text
        assert "virustotal" in r.text

        # Empty match
        r_empty = await c.get("/agentgate/api/decisions-html?agent=non_existent_agent_999", headers=auth_headers)
        assert r_empty.status_code == 200
        assert "No invocations matching filter criteria" in r_empty.text


@pytest.mark.asyncio
async def test_get_manifest_by_agent(auth_headers):
    async with _client() as c:
        # Existing manifest
        res = await c.get("/agentgate/api/manifests/recon_agent", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["agent"] == "recon_agent"
        assert "tools_allowed" in data

        # Non-existent manifest
        res_404 = await c.get("/agentgate/api/manifests/unknown_bot_99", headers=auth_headers)
        assert res_404.status_code == 404

        # Path traversal attack
        res_trav = await c.get("/agentgate/api/manifests/../etc/passwd", headers=auth_headers)
        assert res_trav.status_code == 404 or res_trav.status_code == 422


@pytest.mark.asyncio
async def test_manifest_editor_put_validation_and_path_mismatch(auth_headers):
    async with _client() as c:
        # Path agent does not match body agent
        mismatch_payload = {
            "agent": "recon_agent",
            "project": "threatchain",
            "tools_allowed": [{"name": "virustotal"}],
        }
        res_mismatch = await c.put(
            "/agentgate/api/manifests/osint_agent",
            headers=auth_headers,
            json=mismatch_payload,
        )
        assert res_mismatch.status_code == 422
        assert "does not match" in res_mismatch.text

        # Invalid Pydantic schema
        invalid_schema = {
            "agent": "recon_agent",
            "tools_allowed": "not-a-list",
        }
        res_inv = await c.put(
            "/agentgate/api/manifests/recon_agent",
            headers=auth_headers,
            json=invalid_schema,
        )
        assert res_inv.status_code == 422

        # Non-JSON body
        res_nonjson = await c.put(
            "/agentgate/api/manifests/recon_agent",
            headers={**auth_headers, "Content-Type": "application/json"},
            content="corrupt string",
        )
        assert res_nonjson.status_code == 422


@pytest.mark.asyncio
async def test_manifest_put_updates_pdp_dynamically_and_audits(auth_headers, tmp_path):
    pdp = get_default_pdp()
    audit = get_default_audit_service()

    # Verify initial decision for osint_agent calling nmap_scan is DENY
    initial_decision = pdp.decide("osint_agent", "nmap_scan", {})
    assert initial_decision.decision == DecisionType.DENY

    manifest_file = Path("agentgate/manifests/osint_agent.json")
    backup_content = manifest_file.read_text(encoding="utf-8")

    try:
        current_data = json.loads(backup_content)
        current_data["tools_allowed"].append({"name": "nmap_scan", "scope": "read_only"})

        async with _client() as c:
            put_res = await c.put(
                "/agentgate/api/manifests/osint_agent",
                headers={**auth_headers, "X-Operator": "security_admin"},
                json=current_data,
            )
            assert put_res.status_code == 200
            resp_json = put_res.json()
            assert resp_json["status"] == "success"
            new_version = resp_json["version"]

        # DoD M6 check: without restarting, PDP decision is now ALLOW!
        updated_decision = pdp.decide("osint_agent", "nmap_scan", {})
        assert updated_decision.decision == DecisionType.ALLOW

        # Verify audit record for MANIFEST_CHANGED
        logs = audit.get_in_memory_logs()
        manifest_events = [l for l in logs if getattr(l, "event_type", None) == "MANIFEST_CHANGED"]
        assert len(manifest_events) >= 1
        last_event = manifest_events[-1]
        assert last_event.agent == "osint_agent"
        assert last_event.approver == "security_admin"
        assert new_version in last_event.reason

    finally:
        # Restore original manifest and reload PDP
        manifest_file.write_text(backup_content, encoding="utf-8")
        pdp.load_manifest_file(manifest_file)


@pytest.mark.asyncio
async def test_metrics_api_expanded_fields(auth_headers):
    audit = get_default_audit_service()
    queue = get_default_approval_queue()

    # Seed data
    pdp = get_default_pdp()
    pdp.decide("recon_agent", "virustotal", {"ip": "8.8.8.8"})
    pdp.decide("osint_agent", "shodan", {"ip": "1.1.1.1"})

    # Seed an approved request with response time
    req = queue.create_request("vuln_agent", "block_ip", {"ip": "9.9.9.9"}, ttl_seconds=60)
    req.requested_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    queue.approve(req.id, approver="fast_analyst")

    async with _client() as c:
        resp = await c.get("/agentgate/api/metrics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()

        assert "calls_by_agent" in data
        assert isinstance(data["calls_by_agent"], dict)
        assert "recon_agent" in data["calls_by_agent"]

        assert "top_tools" in data
        assert isinstance(data["top_tools"], list)

        assert "avg_human_response_time_seconds" in data
        assert data["avg_human_response_time_seconds"] is not None
        assert data["avg_human_response_time_seconds"] >= 0.0

        assert data["approved_count"] >= 1
        assert "rejected_count" in data
        assert "expired_count" in data

        # Test metrics cards HTML reflects response time and status
        cards_resp = await c.get("/agentgate/api/metrics-cards", headers=auth_headers)
        assert cards_resp.status_code == 200
        assert "Avg Human Response Time" in cards_resp.text
        assert "Approvals (Pend / Appr / Rej)" in cards_resp.text
