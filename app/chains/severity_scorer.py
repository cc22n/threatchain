def calculate_severity_score(findings: dict) -> tuple[float, str]:
    score = 0.0

    recon = findings.get("recon", {})
    malware = findings.get("malware", {})
    vuln = findings.get("vuln", {})
    osint = findings.get("osint", {})
    mitre = findings.get("mitre", {})

    # Recon signals (max 3.0)
    rep = str(recon.get("reputation", "")).lower()
    if rep == "malicious":
        score += 3.0
    elif rep == "suspicious":
        score += 1.5

    # Malware signals (max 3.0)
    verdict = str(malware.get("verdict", "")).lower()
    if verdict == "malicious":
        score += 3.0
    elif verdict == "suspicious":
        score += 1.5
    threat_score = float(malware.get("threat_score", 0))
    score += min(threat_score / 10 * 2.0, 2.0)

    # Vuln signals (max 2.0)
    cvss = float(vuln.get("cvss_score", 0))
    if cvss >= 9.0:
        score += 2.0
    elif cvss >= 7.0:
        score += 1.5
    elif cvss >= 4.0:
        score += 0.5
    if vuln.get("is_exploited"):
        score += 1.0

    # OSINT signals (max 2.0)
    risk = str(osint.get("risk_level", "")).lower()
    risk_map = {"critical": 2.0, "high": 1.5, "medium": 0.5, "low": 0.0}
    score += risk_map.get(risk, 0.0)

    # MITRE signals (max 1.0)
    technique_count = len(mitre.get("techniques", []))
    if technique_count >= 3:
        score += 1.0
    elif technique_count >= 1:
        score += 0.5

    score = round(min(score, 10.0), 1)

    if score >= 8.0:
        severity = "critical"
    elif score >= 6.0:
        severity = "high"
    elif score >= 4.0:
        severity = "medium"
    elif score >= 2.0:
        severity = "low"
    else:
        severity = "info"

    return score, severity


def determine_verdict(findings: dict, severity: str) -> str:
    recon_rep = str(findings.get("recon", {}).get("reputation", "")).lower()
    malware_verdict = str(findings.get("malware", {}).get("verdict", "")).lower()

    if recon_rep == "malicious" or malware_verdict == "malicious" or severity == "critical":
        return "malicious"
    if recon_rep == "suspicious" or malware_verdict == "suspicious" or severity == "high":
        return "suspicious"
    if severity in ("info", "low"):
        return "benign"
    return "unknown"
