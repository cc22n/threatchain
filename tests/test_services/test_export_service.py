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


@pytest.mark.parametrize("hash_value,expected_algo", [
    ("d41d8cd98f00b204e9800998ecf8427e", "MD5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA-1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256"),
])
def test_export_stix_detects_hash_algorithm(hash_value, expected_algo):
    import json
    result = export_stix(
        ioc_value=hash_value,
        ioc_type="hash",
        investigation_id="test-id-hash",
        verdict="malicious",
        mitre_techniques=[],
        related_iocs=[],
    )
    data = json.loads(result.decode("utf-8"))
    indicator = next(o for o in data["objects"] if o["type"] == "indicator")
    assert f"file:hashes.'{expected_algo}'" in indicator["pattern"]


def test_export_stix_unknown_hash_falls_back_to_file_name():
    import json
    result = export_stix(
        ioc_value="not-a-real-hash-value",
        ioc_type="hash",
        investigation_id="test-id-badhash",
        verdict="suspicious",
        mitre_techniques=[],
        related_iocs=[],
    )
    data = json.loads(result.decode("utf-8"))
    indicator = next(o for o in data["objects"] if o["type"] == "indicator")
    assert "file:name" in indicator["pattern"]
