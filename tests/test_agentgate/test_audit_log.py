import pytest
from pathlib import Path
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from agentgate.audit import AgentGateBase, AuditLogService
from agentgate.core.pdp import PolicyDecisionPoint
from agentgate.models.decision import DecisionType


@pytest.fixture
def audit_service():
    return AuditLogService()


@pytest.fixture
def pdp(audit_service):
    point = PolicyDecisionPoint(audit_service=audit_service)
    point.load_manifest_file(Path("agentgate/examples/sample_recon.json"))
    return point


def test_pdp_automatically_records_to_audit_log(pdp, audit_service):
    # 1. ALLOW decision
    pdp.decide("recon_agent", "virustotal", {"ip": "8.8.8.8"})

    # 2. DENY decision
    pdp.decide("recon_agent", "isolate_host", {})

    # 3. MASK decision
    pdp.decide("recon_agent", "abuseipdb", {"ip": "192.168.1.1"})

    logs = audit_service.get_in_memory_logs()
    assert len(logs) == 3
    assert logs[0].decision == DecisionType.ALLOW
    assert logs[1].decision == DecisionType.DENY
    assert logs[2].decision == DecisionType.MASK
    assert logs[2].masked_arguments["ip"] == "[REDACTED_INTERNAL_IP]"


@pytest.mark.asyncio
async def test_audit_log_database_persistence():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(AgentGateBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    audit = AuditLogService()

    async with session_factory() as session:
        point = PolicyDecisionPoint(audit_service=audit)
        point.load_manifest_file(Path("agentgate/examples/sample_recon.json"))
        decision = point.decide("recon_agent", "virustotal", {"target": "google.com"})

        # Persist to DB
        entry = await audit.record_to_db(session, decision, project="threatchain_test")
        assert entry.id is not None
        assert entry.decision == "ALLOW"
        assert entry.tool_name == "virustotal"

        # List back
        listed = await audit.list_recent_db_logs(session, agent_id="recon_agent")
        assert len(listed) == 1
        assert listed[0].id == entry.id
        assert listed[0].project == "threatchain_test"

    await engine.dispose()
