import pytest
from pathlib import Path
from agentgate.models.manifest import AgentManifest, ToolPermission, MaskRule
from agentgate.core.pdp import PolicyDecisionPoint


def test_agent_manifest_creation():
    manifest = AgentManifest(
        agent="test_agent",
        tools_allowed=[ToolPermission(name="shodan", rate_limit_per_min=5)],
        tools_denied=["block_ip"],
        requires_approval=["isolate_host"],
        mask_rules=[MaskRule(fields=["ip"], condition="rfc1918_ip")],
    )
    assert manifest.agent == "test_agent"
    assert manifest.project == "threatchain"
    assert len(manifest.tools_allowed) == 1
    assert manifest.tools_allowed[0].name == "shodan"


def test_load_manifest_file():
    pdp = PolicyDecisionPoint()
    sample_path = Path("agentgate/examples/sample_recon.json")
    manifest = pdp.load_manifest_file(sample_path)
    assert manifest.agent == "recon_agent"
    assert "isolate_host" in manifest.tools_denied
    assert "block_ip" in manifest.requires_approval
    assert "virustotal" in [t.name for t in manifest.tools_allowed]
