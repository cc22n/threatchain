import pytest
import httpx
from app.main import app
from agentgate.core.pdp import get_default_pdp
from agentgate.hitl.queue import ApprovalStatus, get_default_approval_queue
from agentgate.audit import get_default_audit_service


@pytest.mark.asyncio
async def test_dashboard_html_page():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/agentgate/")
        assert resp.status_code == 200
        assert "AgentGate" in resp.text
        assert "Human Approvals Queue" in resp.text


@pytest.mark.asyncio
async def test_dashboard_metrics_api():
    pdp = get_default_pdp()
    # Generate decisions
    pdp.decide("recon_agent", "virustotal", {"ip": "8.8.8.8"})
    pdp.decide("recon_agent", "isolate_host", {})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/agentgate/api/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_invocations"] >= 2
        assert "denial_rate_pct" in data


@pytest.mark.asyncio
async def test_dashboard_metrics_cards_html():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/agentgate/api/metrics-cards")
        assert resp.status_code == 200
        assert "Total Invocations" in resp.text


@pytest.mark.asyncio
async def test_dashboard_decisions_feed():
    pdp = get_default_pdp()
    pdp.decide("recon_agent", "shodan", {"ip": "1.1.1.1"})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        r_json = await client.get("/agentgate/api/decisions")
        assert r_json.status_code == 200
        assert len(r_json.json()) >= 1

        r_html = await client.get("/agentgate/api/decisions-html")
        assert r_html.status_code == 200
        assert "virustotal" in r_html.text or "shodan" in r_html.text


@pytest.mark.asyncio
async def test_dashboard_approve_action():
    queue = get_default_approval_queue()
    req = queue.create_request("recon_agent", "block_ip", {"ip": "1.2.3.4"})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Check pending list
        p_res = await client.get("/agentgate/api/pending")
        assert p_res.status_code == 200
        ids = [p["id"] for p in p_res.json()]
        assert req.id in ids

        # Approve via UI endpoint
        action_res = await client.post(f"/agentgate/api/approve/{req.id}")
        assert action_res.status_code == 200
        assert "Approved!" in action_res.text

    assert queue.get_request(req.id).status == ApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_dashboard_reject_action():
    queue = get_default_approval_queue()
    req = queue.create_request("recon_agent", "block_ip", {"ip": "5.6.7.8"})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        action_res = await client.post(f"/agentgate/api/reject/{req.id}")
        assert action_res.status_code == 200
        assert "Rejected" in action_res.text

    assert queue.get_request(req.id).status == ApprovalStatus.REJECTED


@pytest.mark.asyncio
async def test_dashboard_manifests():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/agentgate/api/manifests")
        assert res.status_code == 200
        data = res.json()
        assert "recon_agent" in data

        html_res = await client.get("/agentgate/api/manifests-html")
        assert html_res.status_code == 200
        assert "recon_agent" in html_res.text
