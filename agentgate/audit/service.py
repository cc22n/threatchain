import asyncio
import ipaddress
import logging
from collections import deque
from datetime import datetime
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from agentgate.audit.models import AgentGateAuditLog
from agentgate.models.decision import DecisionResult, DecisionType

logger = logging.getLogger(__name__)


def _is_private_ip(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    try:
        ip = ipaddress.ip_address(val.strip())
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def redact_arguments(args: Any) -> Any:
    """Recursively redact RFC 1918 private IPs from argument structures."""
    if isinstance(args, dict):
        return {k: redact_arguments(v) for k, v in args.items()}
    if isinstance(args, list):
        return [redact_arguments(x) for x in args]
    if isinstance(args, str) and _is_private_ip(args):
        return "[REDACTED_INTERNAL_IP]"
    return args


class AuditLogService:
    def __init__(self, max_in_memory: int = 1000, session_factory=None, project: str = "threatchain"):
        self._in_memory_buffer: deque[DecisionResult] = deque(maxlen=max_in_memory)
        self._session_factory = session_factory
        self._project = project
        # Strong references so fire-and-forget persistence tasks are not GC'd mid-flight.
        self._pending_tasks: set[asyncio.Task] = set()

    def configure(self, session_factory, project: str = "threatchain") -> None:
        """Enable durable persistence. session_factory is an async_sessionmaker."""
        self._session_factory = session_factory
        self._project = project

    def record_in_memory(self, decision: DecisionResult) -> None:
        self._in_memory_buffer.append(decision)
        logger.debug("Recorded AgentGate decision in memory: %s -> %s", decision.tool, decision.decision)

    def record_event(
        self,
        event_type: str,
        agent: str,
        tool: str,
        decision: DecisionType | str = DecisionType.ALLOW,
        reason: str = "",
        arguments: dict[str, Any] | None = None,
        masked_arguments: dict[str, Any] | None = None,
        masked_fields: list[str] | None = None,
        approver: str | None = None,
        decided_at: datetime | None = None,
        execution_result: str | None = None,
        approval_id: str | None = None,
        investigation_id: str | None = None,
    ) -> DecisionResult:
        """Record an append-only lifecycle event (APPROVAL_RESOLVED, EXECUTION, MANIFEST_CHANGED)."""
        dec_type = decision if isinstance(decision, DecisionType) else DecisionType(decision)
        safe_arguments = redact_arguments(arguments) or {}
        res = DecisionResult(
            decision=dec_type,
            reason=reason,
            agent=agent,
            tool=tool,
            arguments=safe_arguments,
            masked_arguments=masked_arguments,
            masked_fields=masked_fields or [],
            requires_human=(dec_type == DecisionType.REQUIRE_APPROVAL),
            approval_id=approval_id,
            event_type=event_type,
            approver=approver,
            decided_at=decided_at,
            execution_result=execution_result,
            investigation_id=investigation_id,
        )
        self.record(res)
        return res

    def record(self, decision: DecisionResult) -> None:
        """
        Record a decision in memory and, when a session factory is configured and
        an event loop is running, schedule a durable DB write. Persistence failures
        are logged and never propagate to the tool call being authorized.
        """
        self.record_in_memory(decision)
        if self._session_factory is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # sync caller (scripts/tests): memory only
        task = loop.create_task(self._persist(decision))
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)

    async def _persist(self, decision: DecisionResult) -> None:
        try:
            async with self._session_factory() as session:
                await self.record_to_db(session, decision, project=self._project, also_memory=False)
        except Exception as e:
            logger.error("AgentGate audit DB write failed: %s", e)

    async def flush(self) -> None:
        """Wait for in-flight persistence tasks (used at shutdown and in tests)."""
        if self._pending_tasks:
            await asyncio.gather(*list(self._pending_tasks), return_exceptions=True)

    def get_in_memory_logs(self, limit: int = 50) -> list[DecisionResult]:
        return list(self._in_memory_buffer)[-limit:]

    async def record_to_db(
        self,
        session: AsyncSession,
        decision: DecisionResult,
        project: str = "threatchain",
        decided_by: str = "system",
        also_memory: bool = True,
    ) -> AgentGateAuditLog:
        if also_memory:
            self.record_in_memory(decision)

        safe_args = redact_arguments(decision.arguments)
        safe_masked_args = redact_arguments(decision.masked_arguments) if decision.masked_arguments else None

        entry = AgentGateAuditLog(
            agent_id=decision.agent,
            project=project,
            tool_name=decision.tool,
            decision=str(decision.decision.value),
            reason=decision.reason,
            arguments=safe_args,
            masked_arguments=safe_masked_args,
            masked_fields=decision.masked_fields,
            decided_by=decided_by,
            requires_human=decision.requires_human,
            approval_id=decision.approval_id,
            event_type=getattr(decision, "event_type", "DECISION") or "DECISION",
            approver=getattr(decision, "approver", None),
            decided_at=getattr(decision, "decided_at", None),
            execution_result=getattr(decision, "execution_result", None),
            investigation_id=getattr(decision, "investigation_id", None),
        )
        session.add(entry)
        await session.commit()
        await session.refresh(entry)
        return entry

    async def list_recent_db_logs(
        self,
        session: AsyncSession,
        agent_id: str | None = None,
        limit: int = 50,
    ) -> list[AgentGateAuditLog]:
        stmt = select(AgentGateAuditLog).order_by(desc(AgentGateAuditLog.created_at)).limit(limit)
        if agent_id:
            stmt = stmt.where(AgentGateAuditLog.agent_id == agent_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())


_global_audit_service: AuditLogService | None = None


def get_default_audit_service() -> AuditLogService:
    global _global_audit_service
    if _global_audit_service is None:
        _global_audit_service = AuditLogService()
    return _global_audit_service
