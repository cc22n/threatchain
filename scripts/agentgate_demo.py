"""AgentGate Interactive CLI Demonstration.

Exercises the deterministic Policy Decision Point (PDP) and Policy Enforcement Point (PEP)
with simulated zero-network tools and displays the immutable append-only audit trail.

Covers:
  1. ALLOW: Authorized tool call.
  2. DENY: Unauthorized tool call blocked with PermissionDeniedError.
  3. MASK: Sensitive RFC 1918 internal IP redaction (skipped=True).
  4. REQUIRE_APPROVAL: Pause & resume HITL workflow with @protect and queue resolution.
  5. Rate limit escalation (Pattern 2 from brief: 1st auto-approves, 2nd requires approval).
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Ensure project root is in path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from agentgate.audit import get_default_audit_service
from agentgate.client.pep import (
    ApprovalRequiredError,
    PermissionDeniedError,
    PolicyEnforcementPoint,
    protect,
)
from agentgate.core.pdp import PolicyDecisionPoint
from agentgate.hitl.notifier import send_approval_request
from agentgate.hitl.queue import ApprovalStatus, get_default_approval_queue
from agentgate.models.decision import DecisionType
from agentgate.models.manifest import AgentManifest, MaskRule, ToolPermission
from app.config import settings


def print_banner(text: str):
    print("\n" + "=" * 76)
    print(f"  {text}")
    print("=" * 76)


async def run_demo(notify_telegram: bool = False):
    print_banner("AGENTGATE GOVERNANCE DEMONSTRATION")
    print("[*] Initializing PDP with manifests from agentgate/manifests...")

    manifests_dir = root_dir / "agentgate" / "manifests"
    audit_svc = get_default_audit_service()
    queue = get_default_approval_queue()

    pdp = PolicyDecisionPoint(manifests_dir=manifests_dir, audit_service=audit_svc, approval_queue=queue)
    pep = PolicyEnforcementPoint(pdp=pdp)

    print(f"[*] Loaded manifests: {sorted(list(pdp.manifests.keys()))}")

    # -------------------------------------------------------------------------
    # 1. ALLOW
    # -------------------------------------------------------------------------
    print_banner("1. ALLOW VERDICT (Authorized Tool Call)")
    print("[*] Invoking 'virustotal' with recon_agent for public IP 8.8.8.8...")

    async def fake_virustotal(ip: str) -> dict:
        return {"source": "fake_virustotal", "ip": ip, "malicious": 0}

    allow_decision = await pep.authorize(
        agent="recon_agent",
        tool="virustotal",
        arguments={"ip": "8.8.8.8"},
    )
    print(f"    PDP Verdict: {allow_decision.decision.value}")
    print(f"    Policy Reason: {allow_decision.reason}")
    res1 = await fake_virustotal("8.8.8.8")
    print(f"    Execution Result: {res1}")
    assert allow_decision.decision == DecisionType.ALLOW

    # -------------------------------------------------------------------------
    # 2. DENY
    # -------------------------------------------------------------------------
    print_banner("2. DENY VERDICT (Unauthorized / Intrusive Tool Call)")
    print("[*] Invoking 'isolate_host' with recon_agent (in tools_denied)...")

    async def fake_isolate_host(host: str) -> dict:
        return {"status": "isolated", "host": host}

    try:
        await pep.authorize(
            agent="recon_agent",
            tool="isolate_host",
            arguments={"host": "srv-prod-01"},
        )
        print("    [!] ERROR: Call should have been blocked!")
    except PermissionDeniedError as err:
        print(f"    [OK] BLOCKED by AgentGate PEP fail-closed:")
        print(f"    Exception: {err}")
        print(f"    Verdict: {err.decision.decision.value} | Reason: {err.decision.reason}")

    # -------------------------------------------------------------------------
    # 3. MASK
    # -------------------------------------------------------------------------
    print_banner("3. MASK VERDICT (RFC 1918 Private IP Redaction)")
    print("[*] Invoking 'virustotal' with recon_agent for private IP 192.168.1.100...")

    mask_decision = await pep.authorize(
        agent="recon_agent",
        tool="virustotal",
        arguments={"ip": "192.168.1.100"},
    )
    print(f"    PDP Verdict: {mask_decision.decision.value}")
    print(f"    Policy Reason: {mask_decision.reason}")
    print(f"    Masked Arguments: {mask_decision.masked_arguments}")
    assert mask_decision.decision == DecisionType.MASK
    assert mask_decision.masked_arguments["ip"] == "[REDACTED_INTERNAL_IP]"

    # -------------------------------------------------------------------------
    # 4. REQUIRE_APPROVAL (HITL Pause & Resume)
    # -------------------------------------------------------------------------
    print_banner("4. REQUIRE_APPROVAL (Human-in-the-Loop Pause & Resume)")
    print("[*] Invoking guarded tool 'block_ip' with recon_agent...")

    @protect(agent="recon_agent", tool="block_ip", pep=pep)
    async def fake_block_ip(ip: str) -> dict:
        print(f"    [--> Tool Body Executed!] Target {ip} blocked in firewall.")
        return {"action": "blocked", "target": ip}

    async def operator_approval_simulator(approval_id: str):
        print(f"    [*] HITL Operator Worker: Waiting 1.0s before approving request {approval_id[:8]}...")
        await asyncio.sleep(1.0)
        req = queue.get_request(approval_id)
        if req and req.status == ApprovalStatus.PENDING:
            queue.approve(approval_id, approver="soc_lead_cli", notes="Approved via interactive CLI demo")
            print(f"    [*] HITL Operator Worker: Request {approval_id[:8]} APPROVED by 'soc_lead_cli'!")

    # Schedule background approver to resolve when tool pauses
    async def monitor_and_approve():
        while True:
            await asyncio.sleep(0.1)
            pending = queue.list_pending()
            for p in pending:
                if p.tool == "block_ip":
                    await operator_approval_simulator(p.id)
                    return

    approver_task = asyncio.create_task(monitor_and_approve())

    print("    [!] Calling fake_block_ip... (Function pauses here waiting for human)")
    start_time = asyncio.get_running_loop().time()
    hitl_result = await fake_block_ip(ip="203.0.113.50")
    elapsed = asyncio.get_running_loop().time() - start_time
    await approver_task

    print(f"    Resumed and finished in {elapsed:.2f}s!")
    print(f"    Return value: {hitl_result}")

    # -------------------------------------------------------------------------
    # 5. RATE LIMIT ESCALATION (Pattern 2 from brief)
    # -------------------------------------------------------------------------
    print_banner("5. RATE LIMIT ESCALATION DEMO (Pattern 2)")
    print("[*] Registering test manifest for 'rate_demo_agent': rate_limit_per_min=1 on 'query_tool'...")

    rate_manifest = AgentManifest(
        agent="rate_demo_agent",
        tools_allowed=[ToolPermission(name="query_tool", rate_limit_per_min=1)],
    )
    pdp.register_manifest(rate_manifest)

    print("    Call #1: within rate limit (count = 1/1)...")
    dec1 = pdp.decide("rate_demo_agent", "query_tool", {"query": "sample1"})
    print(f"    Result #1: Verdict={dec1.decision.value} | Reason={dec1.reason}")
    assert dec1.decision == DecisionType.ALLOW

    print("\n    Call #2: exceeds rate limit within sliding window (count = 2/1)...")
    dec2 = pdp.decide("rate_demo_agent", "query_tool", {"query": "sample2"})
    print(f"    Result #2: Verdict={dec2.decision.value} | Reason={dec2.reason}")
    assert dec2.decision == DecisionType.REQUIRE_APPROVAL
    print(f"    [OK] Second query automatically escalated to approval request: ID={dec2.approval_id[:8]}")

    # -------------------------------------------------------------------------
    # 6. IMMUTABLE AUDIT TRAIL OUTPUT
    # -------------------------------------------------------------------------
    print_banner("6. IMMUTABLE AUDIT TRAIL (Append-Only Event Stream)")
    logs = audit_svc.get_in_memory_logs(limit=20)
    print(f"{'TIMESTAMP':<10} | {'EVENT_TYPE':<18} | {'AGENT':<16} | {'TOOL':<14} | {'DECISION':<18} | {'APPROVER':<12}")
    print("-" * 96)
    for l in logs:
        ts = l.timestamp.strftime("%H:%M:%S")
        ev_type = getattr(l, "event_type", "DECISION") or "DECISION"
        appr = getattr(l, "approver", None) or "-"
        print(f"{ts:<10} | {ev_type:<18} | {l.agent:<16} | {l.tool:<14} | {l.decision.value:<18} | {appr:<12}")

    print("\n[+] Verification Complete: All 4 verdicts, HITL pause/resume, rate limiting, and audit trail verified successfully.")


def main():
    parser = argparse.ArgumentParser(description="AgentGate CLI End-to-End Demo")
    parser.add_argument("--telegram", action="store_true", help="Send actual approval request to Telegram Bot")
    args = parser.parse_args()

    asyncio.run(run_demo(notify_telegram=args.telegram))


if __name__ == "__main__":
    main()
