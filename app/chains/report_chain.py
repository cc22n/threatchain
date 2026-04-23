import json
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.language_models import BaseChatModel
from app.utils import parse_llm_json

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"

SYSTEM_PROMPT = """You are a senior SOC analyst writing a professional threat intelligence report.
Given investigation findings from multiple specialized agents, produce a structured analysis.

Return a JSON object with these exact fields:
- executive_summary: string (3-5 sentences)
- verdict: string (malicious/suspicious/benign/unknown)
- severity: string (critical/high/medium/low/info)
- severity_score: float (0.0-10.0)
- key_findings: list of strings (one per agent finding)
- recommendations: string (actionable mitigation steps)
- timeline: list of strings (chronological events if available, else empty list)

Return ONLY valid JSON."""


async def generate_report_content(
    ioc_value: str,
    ioc_type: str,
    agent_findings: dict,
    mitre_techniques: list,
    correlation: dict,
    llm: BaseChatModel,
) -> dict:
    findings_text = json.dumps(agent_findings, indent=2)
    mitre_text = json.dumps(mitre_techniques, indent=2)

    user_content = (
        f"IOC: {ioc_value} (type: {ioc_type})\n\n"
        f"Correlation Summary:\n{json.dumps(correlation, indent=2)}\n\n"
        f"Agent Findings:\n{findings_text}\n\n"
        f"MITRE ATT&CK Techniques:\n{mitre_text}"
    )

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=user_content)]
    response = await llm.ainvoke(messages)

    parsed = parse_llm_json(response.content)
    tokens = 0
    if hasattr(response, "usage_metadata") and response.usage_metadata:
        tokens = response.usage_metadata.get("total_tokens", 0)
    parsed["_tokens_used"] = tokens
    parsed["_model"] = getattr(llm, "model_name", "")
    return parsed


def render_markdown_report(
    ioc_value: str,
    ioc_type: str,
    investigation_id: str,
    report_data: dict,
    agent_findings: dict,
    mitre_techniques: list,
) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    env.filters["tojson"] = lambda v, indent=2: json.dumps(v, indent=indent, default=str)
    template = env.get_template("report.md.j2")
    return template.render(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        investigation_id=investigation_id,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        verdict=report_data.get("verdict", "unknown"),
        severity=report_data.get("severity", "info"),
        severity_score=report_data.get("severity_score", 0.0),
        summary=report_data.get("executive_summary", ""),
        recommendations=report_data.get("recommendations", ""),
        agent_findings=agent_findings,
        mitre_techniques=mitre_techniques,
        related_iocs=report_data.get("related_iocs", []),
    )
