import copy
import ipaddress
import time
from collections import deque
from typing import Any, Callable

from agentgate.models.decision import DecisionResult, DecisionType
from agentgate.models.manifest import AgentManifest


def is_private_ip(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    try:
        ip = ipaddress.ip_address(val.strip())
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


RATE_WINDOW_SECONDS = 60.0


class PolicyEvaluator:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        # Sliding window of allowed-call timestamps per (agent, tool).
        self._calls: dict[tuple[str, str], deque[float]] = {}

    def _rate_limit_for(self, manifest: AgentManifest, tool_name: str) -> int | None:
        wildcard = None
        for perm in manifest.tools_allowed:
            if perm.name == tool_name:
                return perm.rate_limit_per_min
            if perm.name == "*":
                wildcard = perm.rate_limit_per_min
        return wildcard

    def _over_rate_limit(self, manifest: AgentManifest, tool_name: str) -> bool:
        """Dynamic authorization check: True if this call would exceed rate_limit_per_min.
        A call that is within the limit is counted; an escalated call is not."""
        limit = self._rate_limit_for(manifest, tool_name)
        if not limit or limit <= 0:
            return False
        now = self._clock()
        window = self._calls.setdefault((manifest.agent, tool_name), deque())
        while window and now - window[0] >= RATE_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
        return False

    def evaluate(
        self,
        manifest: AgentManifest,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> DecisionResult:
        context = context or {}

        # 1. Check explicit tools_denied
        if tool_name in manifest.tools_denied:
            return DecisionResult(
                decision=DecisionType.DENY,
                reason=f"Tool '{tool_name}' is explicitly denied in agent manifest",
                agent=manifest.agent,
                tool=tool_name,
                arguments=arguments,
            )

        # 2. Check requires_approval
        if tool_name in manifest.requires_approval:
            return DecisionResult(
                decision=DecisionType.REQUIRE_APPROVAL,
                reason=f"Tool '{tool_name}' requires human-in-the-loop approval",
                agent=manifest.agent,
                tool=tool_name,
                arguments=arguments,
                requires_human=True,
            )

        # 3. Check allowed tools
        allowed_names = [t.name for t in manifest.tools_allowed]
        is_allowed = (tool_name in allowed_names) or ("*" in allowed_names)
        if not is_allowed:
            return DecisionResult(
                decision=DecisionType.DENY,
                reason=f"Tool '{tool_name}' is not in allowed tools list for agent '{manifest.agent}'",
                agent=manifest.agent,
                tool=tool_name,
                arguments=arguments,
            )

        # 3b. Rate-based escalation: within the limit calls are auto-approved,
        # the next one needs a human (authorization at invocation level).
        if self._over_rate_limit(manifest, tool_name):
            return DecisionResult(
                decision=DecisionType.REQUIRE_APPROVAL,
                reason=f"Rate escalation: '{tool_name}' exceeded its per-minute limit for agent '{manifest.agent}'",
                agent=manifest.agent,
                tool=tool_name,
                arguments=arguments,
                requires_human=True,
            )

        # 4. Check mask rules
        masked_args = copy.deepcopy(arguments)
        masked_fields = []
        needs_mask = False

        for rule in manifest.mask_rules:
            if rule.tool not in ("*", tool_name):
                continue

            for field in rule.fields:
                if field in masked_args:
                    val = masked_args[field]
                    if rule.condition == "rfc1918_ip":
                        if is_private_ip(val):
                            masked_args[field] = "[REDACTED_INTERNAL_IP]"
                            masked_fields.append(field)
                            needs_mask = True
                    else:
                        masked_args[field] = "[REDACTED]"
                        masked_fields.append(field)
                        needs_mask = True

        if needs_mask:
            return DecisionResult(
                decision=DecisionType.MASK,
                reason="Sensitive data in arguments was masked per policy",
                agent=manifest.agent,
                tool=tool_name,
                arguments=arguments,
                masked_arguments=masked_args,
                masked_fields=masked_fields,
            )

        # 5. Default ALLOW
        return DecisionResult(
            decision=DecisionType.ALLOW,
            reason="Tool invocation allowed by policy manifest",
            agent=manifest.agent,
            tool=tool_name,
            arguments=arguments,
        )
