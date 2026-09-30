import json
import shutil

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentgate.audit import AgentGateAuditLog, AgentGateBase, AuditLogService
from agentgate.core.evaluator import PolicyEvaluator
from agentgate.core.pdp import PolicyDecisionPoint, get_default_pdp
from agentgate.hitl.queue import get_default_approval_queue
from agentgate.models.decision import DecisionType
from agentgate.models.manifest import AgentManifest, ToolPermission
from app.config import settings
from app.main import app


# --- manifests ---------------------------------------------------------------

def test_default_recon_manifest_allows_all_six_tools():
    """Regression: sample_recon.json used to overwrite recon_agent.json."""
    allowed = {t.name for t in get_default_pdp().manifests["recon_agent"].tools_allowed}
    assert {"urlscan", "securitytrails", "threatfox"} <= allowed
    assert len(allowed) == 6


def test_duplicate_manifest_for_same_agent_fails_loudly(tmp_path):
    shutil.copy("agentgate/manifests/recon_agent.json", tmp_path / "a.json")
    shutil.copy("agentgate/examples/sample_recon.json", tmp_path / "b.json")
    pdp = PolicyDecisionPoint(audit_service=AuditLogService())
    with pytest.raises(ValueError, match="Duplicate manifest"):
        pdp.load_manifests_dir(tmp_path)


def test_reloading_same_directory_is_not_a_duplicate():
    pdp = PolicyDecisionPoint(audit_service=AuditLogService())
    assert pdp.load_manifests_dir("agentgate/manifests") == 4
    assert pdp.load_manifests_dir("agentgate/manifests") == 4


# --- rate limiting -----------------------------------------------------------

def _manifest(limit: int) -> AgentManifest:
    return AgentManifest(
        agent="a", tools_allowed=[ToolPermission(name="vt", rate_limit_per_min=limit)]
    )


def test_call_over_rate_limit_escalates_to_approval():
    now = [0.0]
    ev = PolicyEvaluator(clock=lambda: now[0])
    m = _manifest(3)
    for _ in range(3):
        assert ev.evaluate(m, "vt", {"ioc_value": "8.8.8.8"}).decision == DecisionType.ALLOW
    over = ev.evaluate(m, "vt", {"ioc_value": "8.8.8.8"})
    assert over.decision == DecisionType.REQUIRE_APPROVAL
    assert "Rate escalation" in over.reason


def test_rate_limit_window_slides():
    now = [0.0]
    ev = PolicyEvaluator(clock=lambda: now[0])
    m = _manifest(1)
    assert ev.evaluate(m, "vt", {}).decision == DecisionType.ALLOW
    assert ev.evaluate(m, "vt", {}).decision == DecisionType.REQUIRE_APPROVAL
    now[0] = 61.0
    assert ev.evaluate(m, "vt", {}).decision == DecisionType.ALLOW


def test_rate_limit_is_per_agent_and_tool():
    ev = PolicyEvaluator(clock=lambda: 0.0)
    m = _manifest(1)
    assert ev.evaluate(m, "vt", {}).decision == DecisionType.ALLOW
    other = AgentManifest(agent="b", tools_allowed=[ToolPermission(name="vt", rate_limit_per_min=1)])
    assert ev.evaluate(other, "vt", {}).decision == DecisionType.ALLOW


def test_rate_escalation_creates_approval_request():
    pdp = PolicyDecisionPoint(audit_service=AuditLogService())
    pdp.register_manifest(_manifest(1))
    pdp.decide("a", "vt", {})
    d = pdp.decide("a", "vt", {})
    assert d.decision == DecisionType.REQUIRE_APPROVAL
    assert d.approval_id is not None


# --- durable audit -----------------------------------------------------------

@pytest.mark.asyncio
async def test_pdp_decisions_are_persisted_to_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(AgentGateBase.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    audit = AuditLogService(session_factory=factory)
    pdp = PolicyDecisionPoint(audit_service=audit)
    pdp.register_manifest(_manifest(10))
    pdp.decide("a", "vt", {"ioc_value": "8.8.8.8"})
    pdp.decide("a", "isolate_host", {})  # DENY (not in allowed list) is audited too
    pdp.decide("ghost", "vt", {})        # fail-closed path is audited too
    await audit.flush()

    async with factory() as session:
        rows = (await session.execute(select(AgentGateAuditLog))).scalars().all()
    assert sorted(r.decision for r in rows) == ["ALLOW", "DENY", "DENY"]
    # persisted rows must not double-count in memory
    assert len(audit.get_in_memory_logs()) == 3
    await engine.dispose()


@pytest.mark.asyncio
async def test_audit_db_failure_never_breaks_the_decision():
    class Boom:
        def __call__(self):
            raise RuntimeError("db down")

    audit = AuditLogService(session_factory=Boom())
    pdp = PolicyDecisionPoint(audit_service=audit)
    pdp.register_manifest(_manifest(10))
    d = pdp.decide("a", "vt", {})
    await audit.flush()
    assert d.decision == DecisionType.ALLOW


def test_sync_caller_without_event_loop_records_memory_only():
    audit = AuditLogService(session_factory=lambda: None)
    pdp = PolicyDecisionPoint(audit_service=audit)
    pdp.register_manifest(_manifest(10))
    pdp.decide("a", "vt", {})
    assert len(audit.get_in_memory_logs()) == 1


# --- dashboard auth + XSS ----------------------------------------------------

@pytest.fixture
def api_key(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "s3cret-key")
    return "s3cret-key"


def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_dashboard_actions_require_api_key(api_key):
    req = get_default_approval_queue().create_request("recon_agent", "block_ip", {"ip": "1.2.3.4"})
    async with _client() as c:
        assert (await c.post(f"/agentgate/api/approve/{req.id}")).status_code == 401
        assert (await c.post(f"/agentgate/api/reject/{req.id}")).status_code == 401
        assert (await c.get("/agentgate/api/pending")).status_code == 401
        assert (await c.get("/agentgate/api/decisions")).status_code == 401
        assert (await c.get("/agentgate/api/manifests")).status_code == 401
        # Static shell stays public
        assert (await c.get("/agentgate/")).status_code == 200
        ok = await c.post(f"/agentgate/api/approve/{req.id}", headers={"X-API-Key": api_key})
        assert ok.status_code == 200 and "Approved!" in ok.text


@pytest.mark.asyncio
async def test_dashboard_escapes_untrusted_html():
    payload = "<script>alert(1)</script>"
    queue = get_default_approval_queue()
    queue.create_request("recon_agent", "block_ip", {"url": payload})
    pdp = get_default_pdp()
    pdp.decide("recon_agent", "virustotal", {"ioc_value": payload})

    async with _client() as c:
        pending = (await c.get("/agentgate/api/pending-html")).text
        decisions = (await c.get("/agentgate/api/decisions-html")).text
        # no "/" here: a slash would split the URL path and 404 before reaching the handler
        err = (await c.post("/agentgate/api/approve/<img onerror=alert(1)>")).text

    for body in (pending, decisions):
        assert "<script>alert(1)</script>" not in body
        assert "&lt;script&gt;" in body
    assert "<img onerror" not in err
    assert "&lt;img onerror" in err
