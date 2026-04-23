import json
import logging
from langchain_core.messages import HumanMessage, SystemMessage
from app.rag.knowledge_base import mitre_similarity_search
from app.llm.router import get_llm_for_agent
from app.utils import parse_llm_json

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a MITRE ATT&CK expert. Given threat intelligence findings and relevant ATT&CK techniques, "
    "identify which techniques apply. Return a JSON array where each element has: "
    "technique_id, technique_name, tactic, confidence (high/medium/low), evidence (one sentence). "
    "Return ONLY valid JSON array, no markdown."
)


async def mitre_lookup(query: str, context_findings: dict | None = None) -> list[dict]:
    docs = mitre_similarity_search(query, k=6)
    if not docs:
        return []

    context_text = "\n\n".join([
        f"[{d.metadata.get('technique_id', '')}] {d.metadata.get('technique_name', '')}\n{d.page_content[:400]}"
        for d in docs
    ])

    findings_text = json.dumps(context_findings, indent=2) if context_findings else ""
    user_content = (
        f"Query: {query}\n\n"
        f"Agent Findings:\n{findings_text}\n\n"
        f"Relevant ATT&CK Techniques:\n{context_text}"
    )

    llm = get_llm_for_agent("mitre")
    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=user_content)]

    try:
        response = await llm.ainvoke(messages)
        return parse_llm_json(response.content)
    except Exception as e:
        logger.error("MITRE lookup chain failed: %s", e)
        return [
            {
                "technique_id": d.metadata.get("technique_id", ""),
                "technique_name": d.metadata.get("technique_name", ""),
                "tactic": d.metadata.get("tactics", "unknown").split(",")[0].strip(),
                "confidence": "low",
                "evidence": "Identified via similarity search",
            }
            for d in docs[:3]
        ]
