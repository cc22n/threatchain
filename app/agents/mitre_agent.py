import time
import uuid
import logging
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base_agent import BaseAgent
from app.chains.mitre_lookup_chain import mitre_lookup
from app.models.mitre_mapping import MitreMapping

logger = logging.getLogger(__name__)


class MitreAgent(BaseAgent):
    agent_name: str = "mitre"

    def __init__(self, db: AsyncSession):
        super().__init__(db)

    async def run(self, ioc_value: str, ioc_type: str, investigation_id: uuid.UUID, context_findings: dict | None = None) -> dict:
        start = time.monotonic()
        query = f"{ioc_type} IOC: {ioc_value}"
        if context_findings:
            summary = context_findings.get("summary", "")
            indicators = context_findings.get("key_indicators", [])
            query += f". Findings: {summary}. Indicators: {', '.join(indicators)}"

        techniques = await mitre_lookup(query, context_findings)

        # Add all MitreMapping rows to the session without committing yet;
        # _persist_result adds the AgentResult and does a single commit for all.
        for tech in techniques:
            mapping = MitreMapping(
                investigation_id=investigation_id,
                technique_id=tech.get("technique_id", ""),
                technique_name=tech.get("technique_name", ""),
                tactic=tech.get("tactic", ""),
                confidence=tech.get("confidence", "medium"),
                evidence=tech.get("evidence", ""),
            )
            self.db.add(mapping)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        findings = {"techniques": techniques, "count": len(techniques)}

        await self._persist_result(
            investigation_id=investigation_id,
            findings=findings,
            raw_results={"query": query},
            execution_time_ms=elapsed_ms,
            status="success" if techniques else "partial",
        )
        return findings
