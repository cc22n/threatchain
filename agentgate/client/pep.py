import asyncio
from datetime import datetime, timezone
import functools
import inspect
import logging
from typing import Any, Callable

from agentgate.core.pdp import PolicyDecisionPoint, get_default_pdp
from agentgate.hitl.queue import ApprovalRequest, ApprovalStatus, get_default_approval_queue
from agentgate.models.decision import DecisionResult, DecisionType

logger = logging.getLogger(__name__)


class AgentGateError(Exception):
    """Base error for AgentGate."""
    pass


class PermissionDeniedError(AgentGateError):
    def __init__(self, decision: DecisionResult):
        super().__init__(f"AgentGate Permission Denied: {decision.reason}")
        self.decision = decision


class ApprovalRequiredError(AgentGateError):
    def __init__(self, decision: DecisionResult, request: ApprovalRequest | None = None):
        super().__init__(f"AgentGate Human Approval Required: {decision.reason}")
        self.decision = decision
        self.request = request


class ApprovalRejectedError(AgentGateError):
    def __init__(self, decision: DecisionResult, request: ApprovalRequest | None = None):
        super().__init__(f"AgentGate Human Approval Rejected: {decision.reason}")
        self.decision = decision
        self.request = request


class ApprovalExpiredError(AgentGateError):
    def __init__(self, decision: DecisionResult, request: ApprovalRequest | None = None):
        super().__init__(f"AgentGate Human Approval Expired: {decision.reason}")
        self.decision = decision
        self.request = request


class ContextChangedError(AgentGateError):
    def __init__(self, decision: DecisionResult, request: ApprovalRequest | None = None, reason: str = ""):
        super().__init__(f"AgentGate Context Changed: {reason or decision.reason}")
        self.decision = decision
        self.request = request
        self.reason = reason


class PolicyEnforcementPoint:
    def __init__(self, pdp: PolicyDecisionPoint | None = None):
        self.pdp = pdp or get_default_pdp()

    async def authorize(
        self,
        agent: str,
        tool: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
        wait: bool = True,
    ) -> DecisionResult:
        """
        Evaluate policy for (agent, tool, arguments, context).
        If ALLOW or MASK: returns DecisionResult.
        If DENY: raises PermissionDeniedError.
        If REQUIRE_APPROVAL:
          - If wait=False: raises ApprovalRequiredError immediately.
          - If wait=True: enqueues request, sends notification, waits for decision.
            On APPROVE: revalidates context and returns approved DecisionResult.
            On REJECT: raises ApprovalRejectedError.
            On TIMEOUT/EXPIRE: raises ApprovalExpiredError.
        """
        decision = self.pdp.decide(agent=agent, tool=tool, arguments=arguments, context=context)

        if decision.decision == DecisionType.DENY:
            logger.warning("AgentGate DENIED tool '%s' for agent '%s': %s", tool, agent, decision.reason)
            raise PermissionDeniedError(decision)

        if decision.decision == DecisionType.MASK:
            if decision.masked_fields:
                logger.info("AgentGate applied MASK to tool '%s' arguments: %s", tool, decision.masked_fields)
            return decision

        if decision.decision == DecisionType.REQUIRE_APPROVAL:
            if not wait:
                logger.info("AgentGate requires approval (non-blocking) for tool '%s' by agent '%s'", tool, agent)
                raise ApprovalRequiredError(decision)

            wait_seconds = 90
            notify_telegram = True
            try:
                from app.config import settings
                wait_seconds = getattr(settings, "AGENTGATE_APPROVAL_WAIT_SECONDS", 90)
                notify_telegram = getattr(settings, "AGENTGATE_TELEGRAM_NOTIFY", True)
            except Exception:
                pass

            queue = getattr(self.pdp, "approval_queue", None) or get_default_approval_queue()
            req = queue.get_request(decision.approval_id) if decision.approval_id else None
            if not req:
                req = queue.create_request(
                    agent=agent,
                    tool=tool,
                    arguments=arguments,
                    ttl_seconds=wait_seconds,
                    context=context,
                )
                decision.approval_id = req.id
            else:
                # The PDP created this request with the queue default TTL; align it with
                # the real wait so the expiry shown in Telegram/dashboard is truthful.
                req = queue.set_ttl(req.id, wait_seconds) or req

            try:
                if notify_telegram:
                    try:
                        from agentgate.hitl.notifier import send_approval_request
                        await send_approval_request(req)
                    except Exception as exc:
                        logger.warning("Telegram notification failed for approval %s: %s", req.id, exc)

                if context and "investigation_id" in context:
                    try:
                        from app.services.progress import publish
                        publish(str(context["investigation_id"]), {
                            "type": "agentgate_approval_required",
                            "approval_id": req.id,
                            "agent": agent,
                            "tool": tool,
                            "arguments": arguments,
                        })
                    except Exception:
                        pass

                resolved_req = await queue.wait_for_decision(req.id, timeout=float(wait_seconds))
            except asyncio.CancelledError:
                if req:
                    req.status = ApprovalStatus.EXPIRED
                if decision.approval_id and decision.approval_id in queue._memory_store:
                    queue._memory_store[decision.approval_id].status = ApprovalStatus.EXPIRED
                try:
                    audit = getattr(self.pdp, "audit_service", None) or get_default_audit_service()
                    inv_id = str(context["investigation_id"]) if context and "investigation_id" in context else None
                    audit.record_event(
                        event_type="APPROVAL_RESOLVED",
                        agent=agent,
                        tool=tool,
                        decision=DecisionType.REQUIRE_APPROVAL,
                        reason="Approval request cancelled",
                        approver="cancelled",
                        decided_at=datetime.now(timezone.utc),
                        approval_id=decision.approval_id,
                        investigation_id=inv_id,
                        arguments=arguments,
                    )
                except Exception:
                    pass
                raise

            audit = getattr(self.pdp, "audit_service", None) or get_default_audit_service()
            inv_id = str(context["investigation_id"]) if context and "investigation_id" in context else None

            if resolved_req.status == ApprovalStatus.APPROVED:
                audit.record_event(
                    event_type="APPROVAL_RESOLVED",
                    agent=agent,
                    tool=tool,
                    decision=DecisionType.ALLOW,
                    reason=f"Approved by {resolved_req.approver or 'operator'}",
                    approver=resolved_req.approver or "operator",
                    decided_at=datetime.now(timezone.utc),
                    approval_id=resolved_req.id,
                    investigation_id=inv_id,
                    arguments=arguments,
                )

                from agentgate.hitl.revalidator import ContextRevalidator
                valid, reason = ContextRevalidator().revalidate(resolved_req, current_context=context)
                if not valid:
                    logger.error("AgentGate context revalidation failed for %s: %s", req.id, reason)
                    raise ContextChangedError(decision, request=resolved_req, reason=reason)

                return DecisionResult(
                    decision=DecisionType.ALLOW,
                    reason=f"Approved by {resolved_req.approver or 'operator'}",
                    agent=agent,
                    tool=tool,
                    arguments=arguments,
                    approval_id=resolved_req.id,
                    event_type="DECISION",
                    approver=resolved_req.approver,
                    investigation_id=inv_id,
                )
            elif resolved_req.status == ApprovalStatus.REJECTED:
                audit.record_event(
                    event_type="APPROVAL_RESOLVED",
                    agent=agent,
                    tool=tool,
                    decision=DecisionType.DENY,
                    reason=f"Rejected by {resolved_req.approver or 'operator'}: {resolved_req.notes or ''}",
                    approver=resolved_req.approver or "operator",
                    decided_at=datetime.now(timezone.utc),
                    approval_id=resolved_req.id,
                    investigation_id=inv_id,
                    arguments=arguments,
                )
                logger.warning("AgentGate approval rejected for %s by %s: %s", req.id, resolved_req.approver, resolved_req.notes)
                raise ApprovalRejectedError(decision, request=resolved_req)
            else:
                audit.record_event(
                    event_type="APPROVAL_RESOLVED",
                    agent=agent,
                    tool=tool,
                    decision=DecisionType.DENY,
                    reason="Approval request expired",
                    decided_at=datetime.now(timezone.utc),
                    approval_id=resolved_req.id,
                    investigation_id=inv_id,
                    arguments=arguments,
                )
                logger.warning("AgentGate approval expired for %s", req.id)
                raise ApprovalExpiredError(decision, request=resolved_req)

        return decision

    async def check_and_execute(
        self,
        func: Callable,
        agent: str,
        tool: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
        fn_args: tuple = (),
        fn_kwargs: dict | None = None,
        wait: bool = True,
    ) -> Any:
        fn_kwargs = fn_kwargs or {}
        decision = await self.authorize(
            agent=agent,
            tool=tool,
            arguments=arguments,
            context=context,
            wait=wait,
        )

        effective_kwargs = fn_kwargs.copy()
        if decision.decision == DecisionType.MASK and decision.masked_arguments:
            effective_kwargs.update(decision.masked_arguments)

        audit = getattr(self.pdp, "audit_service", None) or get_default_audit_service()
        inv_id = str(context["investigation_id"]) if context and "investigation_id" in context else None

        try:
            if inspect.iscoroutinefunction(func):
                result = await func(*fn_args, **effective_kwargs)
            else:
                result = func(*fn_args, **effective_kwargs)

            audit.record_event(
                event_type="EXECUTION",
                agent=agent,
                tool=tool,
                decision=DecisionType.ALLOW,
                reason="Execution completed successfully",
                execution_result="success",
                approval_id=decision.approval_id,
                investigation_id=inv_id,
                arguments=arguments,
            )
            return result
        except Exception as exc:
            audit.record_event(
                event_type="EXECUTION",
                agent=agent,
                tool=tool,
                decision=DecisionType.ALLOW,
                reason=f"Execution failed: {exc}",
                execution_result=f"error:{type(exc).__name__}",
                approval_id=decision.approval_id,
                investigation_id=inv_id,
                arguments=arguments,
            )
            raise


class AgentGateEnforcer:
    """Async context manager for AgentGate policy enforcement."""

    def __init__(
        self,
        agent: str,
        tool: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
        pep: PolicyEnforcementPoint | None = None,
        wait: bool = True,
    ):
        self.agent = agent
        self.tool = tool
        self.arguments = arguments
        self.context = context
        self.pep = pep or PolicyEnforcementPoint()
        self.wait = wait
        self.decision: DecisionResult | None = None

    async def __aenter__(self) -> DecisionResult:
        self.decision = await self.pep.authorize(
            agent=self.agent,
            tool=self.tool,
            arguments=self.arguments,
            context=self.context,
            wait=self.wait,
        )
        return self.decision

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False


def protect(
    tool_name: str | None = None,
    agent_attr: str = "agent_name",
    pdp: PolicyDecisionPoint | None = None,
    pep: PolicyEnforcementPoint | None = None,
    agent: str | None = None,
    tool: str | None = None,
    wait: bool = True,
):
    if pep is None:
        pep = PolicyEnforcementPoint(pdp=pdp)

    target_attr = agent or agent_attr
    actual_tool = tool or tool_name or ""

    def decorator(fn: Callable):
        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            first_arg = args[0] if args else None
            agent_name = getattr(first_arg, target_attr, "unknown_agent") if hasattr(first_arg, target_attr) else target_attr
            context = kwargs.pop("context", None)
            eval_args = kwargs.copy()
            return await pep.check_and_execute(
                fn,
                agent=str(agent_name),
                tool=actual_tool,
                arguments=eval_args,
                context=context,
                fn_args=args,
                fn_kwargs=kwargs,
                wait=wait,
            )

        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            # Sync wrapper cannot wait for asynchronous human approval.
            # If PDP returns REQUIRE_APPROVAL, it immediately raises ApprovalRequiredError.
            first_arg = args[0] if args else None
            agent_name = getattr(first_arg, target_attr, "unknown_agent") if hasattr(first_arg, target_attr) else target_attr
            eval_args = kwargs.copy()
            decision = pep.pdp.decide(str(agent_name), actual_tool, eval_args)
            if decision.decision == DecisionType.DENY:
                raise PermissionDeniedError(decision)
            if decision.decision == DecisionType.REQUIRE_APPROVAL:
                raise ApprovalRequiredError(decision)
            effective_kwargs = kwargs.copy()
            if decision.decision == DecisionType.MASK and decision.masked_arguments:
                effective_kwargs.update(decision.masked_arguments)
            return fn(*args, **effective_kwargs)

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator
