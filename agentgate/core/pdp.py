import json
import logging
from pathlib import Path
from typing import Any

from agentgate.audit.service import AuditLogService, get_default_audit_service
from agentgate.core.evaluator import PolicyEvaluator
from agentgate.hitl.queue import ApprovalQueue, get_default_approval_queue
from agentgate.models.decision import DecisionResult, DecisionType
from agentgate.models.manifest import AgentManifest

logger = logging.getLogger(__name__)

# Absolute, independent of the process working directory.
DEFAULT_MANIFESTS_DIR = Path(__file__).resolve().parent.parent / "manifests"


class PolicyDecisionPoint:
    def __init__(
        self,
        manifests_dir: str | Path | None = None,
        audit_service: AuditLogService | None = None,
        approval_queue: ApprovalQueue | None = None,
    ):
        self.manifests: dict[str, AgentManifest] = {}
        # Directory the manifests were loaded from; the dashboard editor writes back here.
        self.manifests_dir: Path | None = None
        self.evaluator = PolicyEvaluator()
        self.audit_service = audit_service or get_default_audit_service()
        self.approval_queue = approval_queue or get_default_approval_queue()

        if manifests_dir:
            self.load_manifests_dir(manifests_dir)

    def register_manifest(self, manifest: AgentManifest) -> None:
        self.manifests[manifest.agent] = manifest
        logger.info("Registered AgentGate manifest for agent: %s", manifest.agent)

    def load_manifest_file(self, filepath: str | Path) -> AgentManifest:
        p = Path(filepath)
        with open(p, "r", encoding="utf-8") as f:
            if p.suffix.lower() in (".yaml", ".yml"):
                import yaml
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        manifest = AgentManifest.model_validate(data)
        self.register_manifest(manifest)
        return manifest

    def load_manifests_dir(self, directory: str | Path) -> int:
        d = Path(directory)
        count = 0
        if not d.exists():
            return 0
        self.manifests_dir = d.resolve()
        seen: dict[str, Path] = {}
        files = sorted([f for f in d.iterdir() if f.is_file() and f.suffix.lower() in (".json", ".yaml", ".yml")])
        for f in files:
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    if f.suffix.lower() in (".yaml", ".yml"):
                        import yaml
                        raw_data = yaml.safe_load(fh)
                    else:
                        raw_data = json.load(fh)
                    manifest = AgentManifest.model_validate(raw_data)
            except Exception as e:
                logger.error("Failed to load manifest %s: %s", f, e)
                continue
            # Two files for the same agent would silently overwrite each other
            # (the last one wins), so fail loudly instead.
            if manifest.agent in seen:
                raise ValueError(
                    f"Duplicate manifest for agent '{manifest.agent}': "
                    f"{seen[manifest.agent].name} and {f.name}"
                )
            seen[manifest.agent] = f
            self.register_manifest(manifest)
            count += 1
        return count

    def decide(
        self,
        agent: str,
        tool: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> DecisionResult:
        manifest = self.manifests.get(agent)
        if not manifest:
            # Fail-closed: if agent has no registered manifest, DENY by default
            decision = DecisionResult(
                decision=DecisionType.DENY,
                reason=f"No permission manifest registered for agent '{agent}'. Fail-closed.",
                agent=agent,
                tool=tool,
                arguments=arguments,
            )
            self.audit_service.record(decision)
            return decision

        decision = self.evaluator.evaluate(manifest, tool, arguments, context)

        # If approval required, register in queue
        if decision.decision == DecisionType.REQUIRE_APPROVAL:
            req = self.approval_queue.create_request(
                agent=agent,
                tool=tool,
                arguments=arguments,
                context=context,
            )
            decision.approval_id = req.id

        # Record in audit log
        self.audit_service.record(decision)
        return decision


_global_pdp: PolicyDecisionPoint | None = None


def get_default_pdp() -> PolicyDecisionPoint:
    global _global_pdp
    if _global_pdp is None:
        default_dir = DEFAULT_MANIFESTS_DIR
        manifests_path = default_dir if default_dir.exists() else None
        _global_pdp = PolicyDecisionPoint(manifests_dir=manifests_path)
    return _global_pdp
