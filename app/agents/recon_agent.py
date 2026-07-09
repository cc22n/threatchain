import time
import uuid
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base_agent import BaseAgent
from app.tools.virustotal import VirusTotalTool
from app.tools.abuseipdb import AbuseIPDBTool
from app.tools.shodan import ShodanTool
from app.tools.urlscan import URLScanTool
from app.tools.securitytrails import SecurityTrailsTool
from app.tools.threatfox import ThreatFoxTool
from app.llm.router import get_llm_for_agent
from app.utils import parse_llm_json

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a SOC Level 1 analyst specializing in network reconnaissance. "
    "Given threat intelligence data from multiple sources, extract the key findings "
    "and produce a concise JSON summary with these fields: "
    "reputation (exactly one of, lowercase: malicious, suspicious, benign, unknown), "
    "risk_score (0-10), "
    "key_indicators (list of strings), "
    "summary (one paragraph). "
    "Return ONLY valid JSON."
)


class ReconAgent(BaseAgent):
    agent_name: str = "recon"

    def __init__(self, db: AsyncSession, redis_client=None):
        super().__init__(db)
        self.vt = VirusTotalTool(redis_client=redis_client, db=db)
        self.abuseipdb = AbuseIPDBTool(redis_client=redis_client, db=db)
        self.shodan = ShodanTool(redis_client=redis_client, db=db)
        self.urlscan = URLScanTool(redis_client=redis_client, db=db)
        self.securitytrails = SecurityTrailsTool(redis_client=redis_client, db=db)
        self.threatfox = ThreatFoxTool(redis_client=redis_client, db=db)
        self.llm = get_llm_for_agent("recon")

    async def run(self, ioc_value: str, ioc_type: str, investigation_id: uuid.UUID) -> dict:
        start = time.monotonic()
        raw_results = {}
        errors = {}
        api_calls = 0

        tools_to_run = [("virustotal", self.vt, {"ioc_type": ioc_type})]

        if ioc_type == "ip":
            tools_to_run += [
                ("abuseipdb", self.abuseipdb, {}),
                ("shodan", self.shodan, {}),
            ]
        elif ioc_type in ("url", "domain"):
            tools_to_run.append(("urlscan", self.urlscan, {}))

        if ioc_type == "domain":
            tools_to_run.append(("securitytrails", self.securitytrails, {}))

        tools_to_run.append(("threatfox", self.threatfox, {}))

        for tool_name, tool, kwargs in tools_to_run:
            try:
                raw_results[tool_name] = await tool._arun(ioc_value, **kwargs)
                api_calls += 1
            except Exception as e:
                logger.warning("Tool %s failed: %s", tool_name, e)
                errors[tool_name] = str(e)

        prompt = f"IOC: {ioc_value} (type: {ioc_type})\n\nThreat Intelligence Data:\n{raw_results}"
        messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)]

        llm_model = ""
        findings = {}
        tokens_used = 0
        try:
            response = await self.llm.ainvoke(messages)
            llm_model = getattr(self.llm, "model_name", "")
            findings = parse_llm_json(response.content)
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                tokens_used = response.usage_metadata.get("total_tokens", 0)
        except Exception as e:
            logger.error("LLM parsing failed: %s", e)
            findings = {"error": str(e), "raw_data": str(raw_results)[:500]}

        elapsed_ms = int((time.monotonic() - start) * 1000)
        status = "partial" if errors else "success"

        await self._persist_result(
            investigation_id=investigation_id,
            findings=findings,
            raw_results=raw_results,
            tokens_used=tokens_used,
            api_calls_made=api_calls,
            execution_time_ms=elapsed_ms,
            llm_model_used=llm_model,
            errors=errors if errors else None,
            status=status,
        )
        return findings
