import asyncio
import uuid
import logging
from typing import TypedDict
from sqlalchemy.ext.asyncio import AsyncSession
from langgraph.graph import StateGraph, END

from app.agents.recon_agent import ReconAgent
from app.agents.malware_agent import MalwareAgent
from app.agents.vuln_agent import VulnAgent
from app.agents.osint_agent import OsintAgent
from app.agents.mitre_agent import MitreAgent
from app.agents.report_agent import ReportAgent
from app.chains.correlation_chain import correlate_findings
from app.services import progress

logger = logging.getLogger(__name__)


class InvestigationState(TypedDict):
    ioc_value: str
    ioc_type: str
    investigation_id: str
    agent_findings: dict
    correlation: dict
    error: str


IOC_AGENT_MAP = {
    "ip":     ["recon", "osint", "mitre"],
    "domain": ["recon", "osint", "mitre"],
    "hash":   ["malware", "mitre"],
    "url":    ["recon", "malware", "osint"],
    "cve":    ["vuln", "mitre"],
    "email":  ["osint"],
}


class Coordinator:
    def __init__(self, db: AsyncSession, redis_client=None):
        self.db = db
        self.redis_client = redis_client
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(InvestigationState)
        graph.add_node("run_agents", self._run_agents_node)
        graph.add_node("correlate", self._correlate_node)
        graph.set_entry_point("run_agents")
        graph.add_edge("run_agents", "correlate")
        graph.add_edge("correlate", END)
        return graph.compile()

    async def _run_agents_node(self, state: InvestigationState) -> InvestigationState:
        ioc_value = state["ioc_value"]
        ioc_type = state["ioc_type"]
        inv_id = uuid.UUID(state["investigation_id"])
        agents_to_run = IOC_AGENT_MAP.get(ioc_type, ["recon"])

        agent_map = {
            "recon": lambda: ReconAgent(self.db, self.redis_client),
            "malware": lambda: MalwareAgent(self.db, self.redis_client),
            "vuln": lambda: VulnAgent(self.db, self.redis_client),
            "osint": lambda: OsintAgent(self.db, self.redis_client),
        }

        def _notify_agent_done(name: str, result: dict) -> None:
            progress.publish(state["investigation_id"], {
                "event": "agent_completed",
                "investigation_id": state["investigation_id"],
                "agent": name,
                "agent_status": "error" if "error" in result else "success",
            })

        async def _run_one(name: str) -> tuple[str, dict]:
            agent = agent_map[name]()
            try:
                result = await agent.run(ioc_value, ioc_type, inv_id)
            except Exception as e:
                logger.error("Agent %s failed: %s", name, e)
                result = {"error": str(e)}
            _notify_agent_done(name, result)
            return name, result

        non_mitre = [n for n in agents_to_run if n != "mitre"]
        tasks = [_run_one(name) for name in non_mitre]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings = {}
        for item in results:
            if isinstance(item, Exception):
                logger.error("Agent task raised exception: %s", item)
                continue
            name, result = item
            findings[name] = result

        if "mitre" in agents_to_run:
            merged_context = {}
            for v in findings.values():
                if isinstance(v, dict) and "error" not in v:
                    merged_context.update(v)
            mitre_agent = MitreAgent(self.db)
            try:
                findings["mitre"] = await mitre_agent.run(
                    ioc_value, ioc_type, inv_id,
                    context_findings=merged_context or None,
                )
            except Exception as e:
                logger.error("Agent mitre failed: %s", e)
                findings["mitre"] = {"error": str(e)}
            _notify_agent_done("mitre", findings["mitre"])

        return {**state, "agent_findings": findings}

    async def _correlate_node(self, state: InvestigationState) -> InvestigationState:
        correlation = correlate_findings(state["agent_findings"])
        return {**state, "correlation": correlation}

    async def investigate(self, ioc_value: str, ioc_type: str, investigation_id: uuid.UUID, generate_report: bool = True) -> dict:
        initial_state: InvestigationState = {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "investigation_id": str(investigation_id),
            "agent_findings": {},
            "correlation": {},
            "error": "",
        }
        final_state = await self.graph.ainvoke(initial_state)

        report_findings: dict = {}
        if generate_report:
            try:
                report_agent = ReportAgent(db=self.db)
                report_findings = await report_agent.run(ioc_value, ioc_type, investigation_id)
                progress.publish(str(investigation_id), {
                    "event": "report_generated",
                    "investigation_id": str(investigation_id),
                })
            except Exception as e:
                logger.error("ReportAgent failed: %s", e)

        return {
            "agent_findings": final_state["agent_findings"],
            "correlation": final_state["correlation"],
            "report": report_findings,
        }
