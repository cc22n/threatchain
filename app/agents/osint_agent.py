import time
import uuid
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base_agent import BaseAgent
from app.tools.alienvault_otx import AlienVaultOTXTool
from app.tools.greynoise import GreyNoiseTool
from app.tools.pulsedive import PulsediveTool
from app.tools.threatcrowd import ThreatCrowdTool
from app.tools.phishtank import PhishTankTool
from app.tools.haveibeenpwned import HaveIBeenPwnedTool
from app.llm.router import get_llm_for_agent
from app.utils import parse_llm_json

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are an OSINT analyst. Given open-source threat intelligence data, summarize the findings. "
    "Return JSON with: risk_level (critical/high/medium/low/info), "
    "threat_types (list of strings), "
    "related_iocs (list of strings discovered in the data), "
    "context (string describing geopolitical/campaign context), "
    "summary (one paragraph). "
    "Return ONLY valid JSON."
)


class OsintAgent(BaseAgent):
    agent_name: str = "osint"

    def __init__(self, db: AsyncSession, redis_client=None, ioc_type: str = "ip"):
        super().__init__(db)
        self.greynoise = GreyNoiseTool(redis_client=redis_client, db=db)
        self.otx = AlienVaultOTXTool(redis_client=redis_client, db=db)
        self.pulsedive = PulsediveTool(redis_client=redis_client, db=db)
        self.threatcrowd = ThreatCrowdTool(redis_client=redis_client, db=db)
        self.phishtank = PhishTankTool(redis_client=redis_client, db=db)
        self.hibp = HaveIBeenPwnedTool(redis_client=redis_client, db=db)
        self.llm = get_llm_for_agent("osint")

    async def run(self, ioc_value: str, ioc_type: str, investigation_id: uuid.UUID) -> dict:
        start = time.monotonic()
        raw_results = {}
        errors = {}
        api_calls = 0

        tool_map = {
            "ip": [
                ("greynoise", self.greynoise, {}),
                ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
                ("pulsedive", self.pulsedive, {}),
                ("threatcrowd", self.threatcrowd, {"ioc_type": ioc_type}),
            ],
            "domain": [
                ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
                ("pulsedive", self.pulsedive, {}),
                ("threatcrowd", self.threatcrowd, {"ioc_type": ioc_type}),
            ],
            "url": [
                ("phishtank", self.phishtank, {}),
                ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
            ],
            "hash": [
                ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
                ("threatcrowd", self.threatcrowd, {"ioc_type": ioc_type}),
            ],
            "email": [
                ("haveibeenpwned", self.hibp, {}),
            ],
        }
        tools_to_run = tool_map.get(ioc_type, [("alienvault_otx", self.otx, {"ioc_type": ioc_type})])

        for tool_name, tool, kwargs in tools_to_run:
            try:
                raw_results[tool_name] = await tool._arun(ioc_value, **kwargs)
                api_calls += 1
            except Exception as e:
                logger.warning("Tool %s failed: %s", tool_name, e)
                errors[tool_name] = str(e)

        prompt = f"IOC: {ioc_value} (type: {ioc_type})\n\nOSINT Data:\n{raw_results}"
        messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)]
        findings = {}
        tokens_used = 0
        llm_model = ""
        try:
            response = await self.llm.ainvoke(messages)
            llm_model = getattr(self.llm, "model_name", "")
            findings = parse_llm_json(response.content)
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                tokens_used = response.usage_metadata.get("total_tokens", 0)
        except Exception as e:
            logger.error("LLM parsing failed: %s", e)
            findings = {"error": str(e)}

        elapsed_ms = int((time.monotonic() - start) * 1000)
        await self._persist_result(
            investigation_id=investigation_id,
            findings=findings,
            raw_results=raw_results,
            tokens_used=tokens_used,
            api_calls_made=api_calls,
            execution_time_ms=elapsed_ms,
            llm_model_used=llm_model,
            errors=errors if errors else None,
            status="partial" if errors else "success",
        )
        return findings
