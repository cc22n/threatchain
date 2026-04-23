import uuid
import time
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.agents.base_agent import BaseAgent
from app.models.agent_result import AgentResult
from app.models.mitre_mapping import MitreMapping
from app.models.report import Report
from app.chains.report_chain import generate_report_content, render_markdown_report
from app.llm.router import get_llm_for_agent

logger = logging.getLogger(__name__)


class ReportAgent(BaseAgent):
    agent_name: str = "report"

    def __init__(self, db: AsyncSession):
        super().__init__(db)
        self.llm = get_llm_for_agent("report")

    async def run(self, ioc_value: str, ioc_type: str, investigation_id: uuid.UUID) -> dict:
        start = time.monotonic()

        result = await self.db.execute(
            select(AgentResult).where(AgentResult.investigation_id == investigation_id)
        )
        agent_rows = result.scalars().all()
        agent_findings = {row.agent_name: row.findings or {} for row in agent_rows if row.agent_name != "report"}

        mitre_result = await self.db.execute(
            select(MitreMapping).where(MitreMapping.investigation_id == investigation_id)
        )
        mitre_rows = mitre_result.scalars().all()
        mitre_techniques = [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "evidence": m.evidence or "",
            }
            for m in mitre_rows
        ]

        from app.chains.correlation_chain import correlate_findings
        correlation = correlate_findings(agent_findings)

        try:
            report_data = await generate_report_content(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                agent_findings=agent_findings,
                mitre_techniques=mitre_techniques,
                correlation=correlation,
                llm=self.llm,
            )
        except Exception as e:
            logger.error("Report generation failed: %s", e)
            report_data = {
                "executive_summary": f"Investigation of {ioc_value} completed with {len(agent_findings)} agents.",
                "verdict": correlation.get("verdict", "unknown"),
                "severity": correlation.get("severity", "info"),
                "severity_score": correlation.get("severity_score", 0.0),
                "key_findings": [],
                "recommendations": "Review raw agent findings for details.",
                "timeline": [],
                "_tokens_used": 0,
                "_model": "",
            }

        md_content = render_markdown_report(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            investigation_id=str(investigation_id),
            report_data=report_data,
            agent_findings=agent_findings,
            mitre_techniques=mitre_techniques,
        )

        report = Report(
            investigation_id=investigation_id,
            report_format="markdown",
            content=md_content,
            llm_model=report_data.get("_model", ""),
        )
        self.db.add(report)
        await self.db.commit()

        elapsed_ms = int((time.monotonic() - start) * 1000)
        findings = {
            "verdict": report_data.get("verdict"),
            "severity": report_data.get("severity"),
            "severity_score": report_data.get("severity_score"),
            "executive_summary": report_data.get("executive_summary"),
            "recommendations": report_data.get("recommendations"),
            "key_findings": report_data.get("key_findings", []),
        }

        await self._persist_result(
            investigation_id=investigation_id,
            findings=findings,
            raw_results={"report_data": report_data},
            tokens_used=report_data.get("_tokens_used", 0),
            execution_time_ms=elapsed_ms,
            llm_model_used=report_data.get("_model", ""),
            status="success",
        )
        return findings
