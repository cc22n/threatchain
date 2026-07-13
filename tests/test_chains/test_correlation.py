from app.chains.correlation_chain import correlate_findings


def test_correlate_malicious_findings():
    findings = {
        "recon": {"reputation": "malicious", "related_iocs": ["evil.com"]},
        "osint": {"risk_level": "critical", "related_iocs": ["1.2.3.4"]},
        "mitre": {"techniques": [{"id": "T1090"}, {"id": "T1071"}]},
    }
    result = correlate_findings(findings)
    assert result["verdict"] == "malicious"
    assert result["severity"] == "critical"
    assert result["severity_score"] >= 8.0
    assert "evil.com" in result["related_iocs"]
    assert "1.2.3.4" in result["related_iocs"]


def test_correlate_deduplicates_iocs():
    findings = {
        "recon": {"related_iocs": ["1.2.3.4", "evil.com"]},
        "osint": {"related_iocs": ["1.2.3.4", "other.com"]},
    }
    result = correlate_findings(findings)
    assert len(result["related_iocs"]) == len(set(result["related_iocs"]))


def test_correlate_empty_findings():
    result = correlate_findings({})
    assert result["verdict"] in ("benign", "unknown")
    assert result["severity_score"] == 0.0
    assert result["related_iocs"] == []


def test_correlate_agents_completed():
    findings = {"recon": {}, "osint": {}}
    result = correlate_findings(findings)
    assert "recon" in result["agents_completed"]
    assert "osint" in result["agents_completed"]


def test_correlate_technique_count():
    findings = {
        "mitre": {"techniques": [{"id": "T1090"}, {"id": "T1071"}, {"id": "T1059"}]},
    }
    result = correlate_findings(findings)
    assert result["technique_count"] == 3
