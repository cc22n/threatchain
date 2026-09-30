import logging
from typing import Any
from agentgate.hitl.queue import ApprovalRequest

logger = logging.getLogger(__name__)


class ContextRevalidator:
    """
    Solves the GOTCHA of stale credentials/context when an agent resumes
    execution after an asynchronous human-in-the-loop pause.
    """

    def revalidate(
        self,
        request: ApprovalRequest,
        current_context: dict[str, Any] | None = None,
        required_keys: list[str] | None = None,
    ) -> tuple[bool, str]:
        current_context = current_context or {}
        snapshot = request.context_snapshot or {}

        # 1. Verify required keys are still present
        if required_keys:
            for key in required_keys:
                if key not in current_context:
                    return False, f"Missing required context key after pause: {key}"

        # 2. Verify token/credential match if present in snapshot
        for token_field in ("token", "api_key", "session_id", "auth_token"):
            if token_field in snapshot:
                expected = snapshot[token_field]
                actual = current_context.get(token_field)
                if actual != expected:
                    return (
                        False,
                        f"Credential mismatch after pause for '{token_field}': context was rotated while waiting for human approval.",
                    )

        # 3. Check for stale target modification flag
        if snapshot.get("target_hash") and current_context.get("target_hash"):
            if snapshot["target_hash"] != current_context["target_hash"]:
                return (
                    False,
                    "Target resource state changed while waiting for human approval.",
                )

        return True, "Context successfully revalidated."
