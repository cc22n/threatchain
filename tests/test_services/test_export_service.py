import pytest
from app.services.export_service import export_markdown, export_stix


def test_export_markdown_returns_bytes():
    content = "# Report\n\nTest content."
    result = export_markdown(content)
    assert isinstance(result, bytes)
    assert b"# Report" in result


def test_export_stix_returns_valid_json():
    import json
    result = export_stix(
        ioc_value="185.220.101.34",
        ioc_type="ip",
        investigation_id="test-id-123",
        verdict="malicious",
        mitre_techniques=[
            {"technique_id": "T1090.003", "technique_name": "Multi-hop Proxy",
             "tactic": "defense-evasion", "confidence": "high", "evidence": "Tor detected"},
        ],
        related_iocs=[],
    )
    assert isinstance(result, bytes)
    data = json.loads(result.decode("utf-8"))
    assert data.get("type") == "bundle"
    assert len(data.get("objects", [])) > 0


def test_export_stix_contains_indicator():
    import json
    result = export_stix(
        ioc_value="evil.example.com",
        ioc_type="domain",
        investigation_id="test-id-456",
        verdict="suspicious",
        mitre_techniques=[],
        related_iocs=[],
    )
    data = json.loads(result.decode("utf-8"))
    types = [o.get("type") for o in data.get("objects", [])]
    assert "indicator" in types


def test_export_stix_malware_technique_creates_relationship():
    import json
    result = export_stix(
        ioc_value="abc123" * 8 + "abcd",
        ioc_type="hash",
        investigation_id="test-id-789",
        verdict="malicious",
        mitre_techniques=[
            {"technique_id": "T1059", "technique_name": "Command and Scripting",
             "tactic": "execution", "confidence": "high", "evidence": "PowerShell usage"},
        ],
        related_iocs=[],
    )
    data = json.loads(result.decode("utf-8"))
    types = [o.get("type") for o in data.get("objects", [])]
    assert "relationship" in types
    assert "attack-pattern" in types
