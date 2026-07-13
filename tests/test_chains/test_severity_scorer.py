from app.chains.severity_scorer import calculate_severity_score, determine_verdict


def test_malicious_ip_scores_critical():
    findings = {
        "recon": {"reputation": "malicious"},
        "osint": {"risk_level": "critical"},
        "mitre": {"techniques": [{"id": "T1090"}, {"id": "T1071"}, {"id": "T1059"}]},
    }
    score, severity = calculate_severity_score(findings)
    assert score >= 8.0
    assert severity == "critical"


def test_benign_scores_low():
    findings = {
        "recon": {"reputation": "benign"},
        "osint": {"risk_level": "low"},
        "mitre": {"techniques": []},
    }
    score, severity = calculate_severity_score(findings)
    assert score < 4.0
    assert severity in ("info", "low")


def test_exploited_cve_adds_score():
    base_findings = {"vuln": {"cvss_score": 7.5, "is_exploited": False}}
    exploited_findings = {"vuln": {"cvss_score": 7.5, "is_exploited": True}}
    score_base, _ = calculate_severity_score(base_findings)
    score_exploited, _ = calculate_severity_score(exploited_findings)
    assert score_exploited > score_base


def test_score_capped_at_ten():
    findings = {
        "recon": {"reputation": "malicious"},
        "malware": {"verdict": "malicious", "threat_score": 10},
        "vuln": {"cvss_score": 10.0, "is_exploited": True},
        "osint": {"risk_level": "critical"},
        "mitre": {"techniques": [1, 2, 3, 4, 5]},
    }
    score, _ = calculate_severity_score(findings)
    assert score <= 10.0


def test_severity_thresholds():
    assert calculate_severity_score({"vuln": {"cvss_score": 9.5}})[1] == "critical"
    assert calculate_severity_score({"vuln": {"cvss_score": 7.0}})[1] in ("high", "medium")
    assert calculate_severity_score({})[1] == "info"


def test_determine_verdict_malicious():
    findings = {"recon": {"reputation": "malicious"}}
    assert determine_verdict(findings, "critical") == "malicious"


def test_determine_verdict_benign():
    findings = {"recon": {"reputation": "benign"}}
    assert determine_verdict(findings, "info") == "benign"


def test_determine_verdict_unknown():
    findings = {}
    assert determine_verdict(findings, "medium") == "unknown"


def test_mitre_alone_does_not_score():
    # Similarity search always returns matches, so MITRE-only findings
    # (all primary agents failed or absent) must not drive the score.
    findings = {
        "recon": {"error": "all tools failed"},
        "mitre": {"techniques": [{"id": "T1090"}, {"id": "T1071"}, {"id": "T1059"}]},
    }
    score, severity = calculate_severity_score(findings)
    assert score == 0.0
    assert severity == "info"
