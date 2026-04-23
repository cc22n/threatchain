from app.chains.severity_scorer import calculate_severity_score, determine_verdict


def correlate_findings(agent_findings: dict) -> dict:
    severity_score, severity = calculate_severity_score(agent_findings)
    verdict = determine_verdict(agent_findings, severity)

    related_iocs = []
    for agent_name, findings in agent_findings.items():
        if isinstance(findings, dict):
            related_iocs.extend(findings.get("related_iocs", []))

    return {
        "verdict": verdict,
        "severity": severity,
        "severity_score": severity_score,
        "related_iocs": list(set(related_iocs)),
        "agents_completed": list(agent_findings.keys()),
        "technique_count": len(agent_findings.get("mitre", {}).get("techniques", [])),
    }
