import pytest
from pathlib import Path
from agentgate.core.pdp import PolicyDecisionPoint
from agentgate.models.decision import DecisionType


@pytest.fixture
def pdp():
    point = PolicyDecisionPoint()
    point.load_manifest_file(Path("agentgate/examples/sample_recon.json"))
    return point


def test_evaluator_allow(pdp):
    res = pdp.decide(
        agent="recon_agent",
        tool="virustotal",
        arguments={"ioc_value": "8.8.8.8"},
    )
    assert res.decision == DecisionType.ALLOW
    assert "allowed" in res.reason.lower()


def test_evaluator_explicit_deny(pdp):
    res = pdp.decide(
        agent="recon_agent",
        tool="isolate_host",
        arguments={"hostname": "srv-prod-01"},
    )
    assert res.decision == DecisionType.DENY
    assert "explicitly denied" in res.reason


def test_evaluator_not_allowed_deny(pdp):
    res = pdp.decide(
        agent="recon_agent",
        tool="unregistered_tool",
        arguments={},
    )
    assert res.decision == DecisionType.DENY
    assert "not in allowed tools list" in res.reason


def test_evaluator_require_approval(pdp):
    res = pdp.decide(
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.2.3.4"},
    )
    assert res.decision == DecisionType.REQUIRE_APPROVAL
    assert res.requires_human is True


def test_evaluator_mask_private_ip(pdp):
    res = pdp.decide(
        agent="recon_agent",
        tool="abuseipdb",
        arguments={"ip": "192.168.1.50"},
    )
    assert res.decision == DecisionType.MASK
    assert res.masked_arguments["ip"] == "[REDACTED_INTERNAL_IP]"
    assert "ip" in res.masked_fields


def test_evaluator_no_mask_public_ip(pdp):
    res = pdp.decide(
        agent="recon_agent",
        tool="abuseipdb",
        arguments={"ip": "8.8.8.8"},
    )
    assert res.decision == DecisionType.ALLOW
    assert res.masked_arguments is None


def test_evaluator_fail_closed_unknown_agent(pdp):
    res = pdp.decide(
        agent="rogue_agent",
        tool="virustotal",
        arguments={"ioc_value": "8.8.8.8"},
    )
    assert res.decision == DecisionType.DENY
    assert "fail-closed" in res.reason.lower()
