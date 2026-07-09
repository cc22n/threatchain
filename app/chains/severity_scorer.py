def _safe_float(value, default: float = 0.0) -> float:
    """Convert a value to float, returning default on any conversion error."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# Relative weight of each agent in the final score. The score is a weighted
# average over the agents that actually ran (IOC routing means only a subset
# runs per investigation), so a single high-signal agent can reach "critical"
# on its own -- e.g. a CVE investigation only runs VULN + MITRE.
AGENT_WEIGHTS = {
    "recon": 1.0,
    "malware": 1.5,
    "vuln": 1.5,
    "osint": 1.0,
    "mitre": 0.5,
}


def _recon_score(recon: dict) -> float:
    rep_map = {"malicious": 10.0, "suspicious": 5.0}
    rep = str(recon.get("reputation", "")).lower()
    risk = min(_safe_float(recon.get("risk_score", 0)), 10.0)
    return max(rep_map.get(rep, 0.0), risk)


def _malware_score(malware: dict) -> float:
    verdict_map = {"malicious": 10.0, "suspicious": 5.0}
    verdict = str(malware.get("verdict", "")).lower()
    threat = min(_safe_float(malware.get("threat_score", 0)), 10.0)
    return max(verdict_map.get(verdict, 0.0), threat)


def _vuln_score(vuln: dict) -> float:
    score = min(_safe_float(vuln.get("cvss_score", 0)), 10.0)
    if vuln.get("is_exploited"):
        score = min(score + 2.0, 10.0)
    return score


def _osint_score(osint: dict) -> float:
    risk_map = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.0}
    return risk_map.get(str(osint.get("risk_level", "")).lower(), 0.0)


def _mitre_score(mitre: dict) -> float:
    techniques = mitre.get("techniques", [])
    count = len(techniques) if isinstance(techniques, list) else 0
    if count >= 3:
        return 10.0
    if count == 2:
        return 7.0
    if count == 1:
        return 4.0
    return 0.0


AGENT_SCORERS = {
    "recon": _recon_score,
    "malware": _malware_score,
    "vuln": _vuln_score,
    "osint": _osint_score,
    "mitre": _mitre_score,
}


def calculate_severity_score(findings: dict) -> tuple[float, str]:
    weighted_sum = 0.0
    total_weight = 0.0

    for agent_name, scorer in AGENT_SCORERS.items():
        agent_findings = findings.get(agent_name)
        # Skip agents that did not run or that failed: they must not
        # dilute the average of the agents that produced real signal.
        if not isinstance(agent_findings, dict) or "error" in agent_findings:
            continue
        weight = AGENT_WEIGHTS[agent_name]
        weighted_sum += scorer(agent_findings) * weight
        total_weight += weight

    score = round(weighted_sum / total_weight, 1) if total_weight else 0.0

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
