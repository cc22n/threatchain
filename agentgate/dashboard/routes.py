import json
import logging
import os
import re
import tempfile
from html import escape
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.auth import require_api_key
from agentgate.audit.service import get_default_audit_service
from agentgate.core.pdp import DEFAULT_MANIFESTS_DIR, get_default_pdp
from agentgate.dashboard.templates import DASHBOARD_HTML
from agentgate.hitl.queue import ApprovalStatus, get_default_approval_queue
from agentgate.models.decision import DecisionType
from agentgate.models.manifest import AgentManifest

logger = logging.getLogger(__name__)

router = APIRouter()

# Every data/action endpoint requires the X-API-Key header. Only the static HTML
# shell is public; it prompts for the key and attaches it to each htmx request.
secured = [Depends(require_api_key)]

IDENTIFIER_REGEX = re.compile(r"^[a-z0-9_]{1,50}$")
APPROVER_REGEX = re.compile(r"^[A-Za-z0-9:_-]{1,64}$")


def _e(value) -> str:
    """HTML-escape any value that originates outside this module (IOCs, args, ids)."""
    return escape(str(value), quote=True)


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def dashboard_page():
    return HTMLResponse(content=DASHBOARD_HTML)


@router.get("/api/metrics", dependencies=secured)
async def get_metrics():
    audit = get_default_audit_service()
    queue = get_default_approval_queue()
    logs = audit.get_in_memory_logs(limit=1000)

    total = len(logs)
    allows = sum(1 for l in logs if l.decision == DecisionType.ALLOW)
    denies = sum(1 for l in logs if l.decision == DecisionType.DENY)
    masks = sum(1 for l in logs if l.decision == DecisionType.MASK)
    requires = sum(1 for l in logs if l.decision == DecisionType.REQUIRE_APPROVAL)
    pending = len(queue.list_pending())

    denial_rate = round((denies / total * 100), 1) if total > 0 else 0.0

    calls_by_agent: dict[str, int] = {}
    for l in logs:
        calls_by_agent[l.agent] = calls_by_agent.get(l.agent, 0) + 1

    tools_count: dict[str, int] = {}
    for l in logs:
        tools_count[l.tool] = tools_count.get(l.tool, 0) + 1
    sorted_tools = sorted(tools_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_tools = [{"tool": t, "count": c} for t, c in sorted_tools]

    approved_count = 0
    rejected_count = 0
    expired_count = 0
    response_times: list[float] = []

    # Count from queue memory store
    for req in queue._memory_store.values():
        if req.status == ApprovalStatus.APPROVED:
            approved_count += 1
            if getattr(req, "resolved_at", None):
                response_times.append((req.resolved_at - req.requested_at).total_seconds())
        elif req.status == ApprovalStatus.REJECTED:
            rejected_count += 1
            if getattr(req, "resolved_at", None):
                response_times.append((req.resolved_at - req.requested_at).total_seconds())
        elif req.status == ApprovalStatus.EXPIRED:
            expired_count += 1

    # Include resolved events from audit logs that may not be in queue memory store
    queue_req_ids = set(queue._memory_store.keys())
    for l in logs:
        if getattr(l, "event_type", None) == "APPROVAL_RESOLVED" and l.approval_id not in queue_req_ids:
            if l.decision == DecisionType.ALLOW:
                approved_count += 1
            elif l.decision == DecisionType.DENY:
                rejected_count += 1
            if getattr(l, "decided_at", None) and getattr(l, "timestamp", None):
                orig = next(
                    (x for x in logs if x.approval_id == l.approval_id and getattr(x, "event_type", "DECISION") == "DECISION"),
                    None,
                )
                req_ts = orig.timestamp if orig else l.timestamp
                diff = (l.decided_at - req_ts).total_seconds()
                if diff >= 0:
                    response_times.append(diff)

    avg_resp = round(sum(response_times) / len(response_times), 2) if response_times else None

    return {
        "total_invocations": total,
        "allow_count": allows,
        "deny_count": denies,
        "mask_count": masks,
        "require_approval_count": requires,
        "denial_rate_pct": denial_rate,
        "pending_approvals_count": pending,
        "approved_count": approved_count,
        "rejected_count": rejected_count,
        "expired_count": expired_count,
        "avg_human_response_time_seconds": avg_resp,
        "calls_by_agent": calls_by_agent,
        "top_tools": top_tools,
    }


@router.get("/api/metrics-cards", response_class=HTMLResponse, dependencies=secured)
async def get_metrics_cards():
    m = await get_metrics()
    resp_text = f"{m['avg_human_response_time_seconds']}s" if m["avg_human_response_time_seconds"] is not None else "--"
    html = f"""
    <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
      <div class="text-xs text-slate-400">Total Invocations</div>
      <div class="text-2xl font-bold text-white mt-1">{m['total_invocations']}</div>
    </div>
    <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
      <div class="text-xs text-slate-400">Denial Rate</div>
      <div class="text-2xl font-bold text-rose-400 mt-1">{m['denial_rate_pct']}%</div>
    </div>
    <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
      <div class="text-xs text-slate-400">Avg Human Response Time</div>
      <div class="text-2xl font-bold text-cyan-400 mt-1">{resp_text}</div>
    </div>
    <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
      <div class="text-xs text-slate-400">Approvals (Pend / Appr / Rej)</div>
      <div class="text-lg font-bold text-slate-200 mt-1">
        <span class="text-amber-400">{m['pending_approvals_count']}</span> /
        <span class="text-emerald-400">{m['approved_count']}</span> /
        <span class="text-rose-400">{m['rejected_count']}</span>
      </div>
    </div>
    """
    return HTMLResponse(html)


@router.get("/api/decisions", dependencies=secured)
async def get_decisions(
    agent: str | None = Query(None),
    decision: str | None = Query(None),
    tool: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    if agent and not IDENTIFIER_REGEX.fullmatch(agent):
        raise HTTPException(status_code=422, detail="Invalid agent identifier filter")
    if tool and not IDENTIFIER_REGEX.fullmatch(tool):
        raise HTTPException(status_code=422, detail="Invalid tool identifier filter")

    valid_decision = None
    if decision:
        try:
            valid_decision = DecisionType(decision.upper())
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid decision filter")

    audit = get_default_audit_service()
    pdp = get_default_pdp()
    logs = audit.get_in_memory_logs(limit=1000)

    filtered = []
    for l in logs:
        if agent and l.agent != agent:
            continue
        if tool and l.tool != tool:
            continue
        if valid_decision and l.decision != valid_decision:
            continue
        filtered.append(l)

    results = []
    for l in reversed(filtered[-limit:]):
        item = l.model_dump()
        manifest = pdp.manifests.get(l.agent)
        item["severity"] = getattr(manifest, "risk_level_default", "low") if manifest else "low"
        results.append(item)
    return results


@router.get("/api/decisions-html", response_class=HTMLResponse, dependencies=secured)
async def get_decisions_html(
    agent: str | None = Query(None),
    decision: str | None = Query(None),
    tool: str | None = Query(None),
    limit: int = Query(25, ge=1, le=500),
):
    if agent and not IDENTIFIER_REGEX.fullmatch(agent):
        raise HTTPException(status_code=422, detail="Invalid agent identifier filter")
    if tool and not IDENTIFIER_REGEX.fullmatch(tool):
        raise HTTPException(status_code=422, detail="Invalid tool identifier filter")

    valid_decision = None
    if decision:
        try:
            valid_decision = DecisionType(decision.upper())
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid decision filter")

    audit = get_default_audit_service()
    pdp = get_default_pdp()
    logs = audit.get_in_memory_logs(limit=1000)

    filtered = []
    for l in logs:
        if agent and l.agent != agent:
            continue
        if tool and l.tool != tool:
            continue
        if valid_decision and l.decision != valid_decision:
            continue
        filtered.append(l)

    sliced = list(reversed(filtered[-limit:]))
    if not sliced:
        return HTMLResponse("<p class='text-xs text-slate-500 py-4'>No invocations matching filter criteria.</p>")

    rows = []
    for l in sliced:
        badge_color = {
            DecisionType.ALLOW: "bg-emerald-950 text-emerald-400 border-emerald-800",
            DecisionType.DENY: "bg-rose-950 text-rose-400 border-rose-800",
            DecisionType.MASK: "bg-amber-950 text-amber-400 border-amber-800",
            DecisionType.REQUIRE_APPROVAL: "bg-cyan-950 text-cyan-400 border-cyan-800",
        }.get(l.decision, "bg-slate-800 text-slate-300 border-slate-700")

        manifest = pdp.manifests.get(l.agent)
        severity = getattr(manifest, "risk_level_default", "low") if manifest else "low"
        sev_color = {
            "critical": "text-rose-400 border-rose-800 bg-rose-950/60",
            "high": "text-orange-400 border-orange-800 bg-orange-950/60",
            "medium": "text-amber-400 border-amber-800 bg-amber-950/60",
            "low": "text-slate-400 border-slate-800 bg-slate-900",
        }.get(severity.lower(), "text-slate-400 border-slate-800 bg-slate-900")

        ts = l.timestamp.strftime("%H:%M:%S")
        args_str = json.dumps(l.masked_arguments or l.arguments, default=str)[:50]

        rows.append(f"""
        <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 text-xs">
          <td class="py-2 px-2 text-slate-400">{_e(ts)}</td>
          <td class="py-2 px-2 text-slate-200 font-semibold">{_e(l.agent)}</td>
          <td class="py-2 px-2 text-cyan-300">{_e(l.tool)}</td>
          <td class="py-2 px-2">
            <span class="px-2 py-0.5 rounded border {badge_color} font-bold text-[10px]">{_e(l.decision.value)}</span>
          </td>
          <td class="py-2 px-2">
            <span class="px-1.5 py-0.5 rounded border {sev_color} text-[10px] uppercase font-bold">{_e(severity)}</span>
          </td>
          <td class="py-2 px-2 text-slate-400 truncate max-w-xs">{_e(l.reason)}</td>
          <td class="py-2 px-2 font-mono text-slate-500 truncate max-w-xs">{_e(args_str)}</td>
        </tr>
        """)

    table = f"""
    <table class="w-full text-left">
      <thead>
        <tr class="text-[11px] uppercase text-slate-400 border-b border-slate-800 pb-1">
          <th class="py-1 px-2">Time</th>
          <th class="py-1 px-2">Agent</th>
          <th class="py-1 px-2">Tool</th>
          <th class="py-1 px-2">Decision</th>
          <th class="py-1 px-2">Severity</th>
          <th class="py-1 px-2">Policy Reason</th>
          <th class="py-1 px-2">Arguments</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows)}
      </tbody>
    </table>
    """
    return HTMLResponse(table)


@router.get("/api/pending", dependencies=secured)
async def get_pending():
    queue = get_default_approval_queue()
    pending = queue.list_pending()
    return [p.model_dump() for p in pending]


@router.get("/api/pending-html", response_class=HTMLResponse, dependencies=secured)
async def get_pending_html():
    queue = get_default_approval_queue()
    pending = queue.list_pending()

    if not pending:
        return HTMLResponse("<p class='text-xs text-slate-500 py-4'>No actions awaiting human review.</p>")

    cards = []
    for req in pending:
        rid = _e(req.id)
        cards.append(f"""
        <div id="approval-{rid}" class="bg-slate-950 border border-slate-800 rounded p-3 text-xs space-y-2 mb-3">
          <div class="flex justify-between items-center">
            <span class="font-bold text-amber-400">{_e(req.agent)}</span>
            <span class="text-[10px] text-slate-500">{_e(req.tool)}</span>
          </div>
          <div class="font-mono text-slate-400 text-[11px] bg-slate-900 p-1.5 rounded truncate">
            {_e(json.dumps(req.arguments, default=str))}
          </div>
          <div class="flex gap-2 pt-1">
            <button hx-post="/agentgate/api/approve/{rid}" hx-target="#approval-{rid}" hx-swap="outerHTML"
                    class="flex-1 bg-emerald-700 hover:bg-emerald-600 text-white font-bold py-1 px-2 rounded text-[11px]">
              &#10003; Approve
            </button>
            <button hx-post="/agentgate/api/reject/{rid}" hx-target="#approval-{rid}" hx-swap="outerHTML"
                    class="flex-1 bg-rose-700 hover:bg-rose-600 text-white font-bold py-1 px-2 rounded text-[11px]">
              &#10007; Reject
            </button>
          </div>
        </div>
        """)

    return HTMLResponse("".join(cards))


@router.post("/api/approve/{approval_id}", dependencies=secured)
async def approve_request(
    approval_id: str,
    approver: str = Query("dashboard_operator"),
    request: Request = None,
):
    if not APPROVER_REGEX.fullmatch(approver):
        raise HTTPException(status_code=422, detail="Invalid approver identifier")

    queue = get_default_approval_queue()
    req = queue.get_request(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail=_e(f"Approval request {approval_id} not found"))

    if req.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=_e(f"Approval request {approval_id} already resolved as {req.status.value}"),
        )

    try:
        resolved = queue.approve(approval_id, approver=approver, notes="Approved via AgentGate API")
    except ValueError as e:
        raise HTTPException(status_code=409, detail=_e(str(e)))

    accept = request.headers.get("accept", "") if request else ""
    if "application/json" in accept:
        return JSONResponse(
            content={
                "status": resolved.status.value,
                "id": resolved.id,
                "approver": resolved.approver,
                "tool": resolved.tool,
                "message": "Approved!",
            }
        )
    return HTMLResponse(f"<div class='p-2 bg-emerald-950/40 border border-emerald-800 text-emerald-400 text-xs rounded mb-2'>Action <b>{_e(resolved.tool)}</b> Approved!</div>")


@router.post("/api/reject/{approval_id}", dependencies=secured)
async def reject_request(
    approval_id: str,
    approver: str = Query("dashboard_operator"),
    request: Request = None,
):
    if not APPROVER_REGEX.fullmatch(approver):
        raise HTTPException(status_code=422, detail="Invalid approver identifier")

    queue = get_default_approval_queue()
    req = queue.get_request(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail=_e(f"Approval request {approval_id} not found"))

    if req.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=_e(f"Approval request {approval_id} already resolved as {req.status.value}"),
        )

    try:
        resolved = queue.reject(approval_id, approver=approver, notes="Rejected via AgentGate API")
    except ValueError as e:
        raise HTTPException(status_code=409, detail=_e(str(e)))

    accept = request.headers.get("accept", "") if request else ""
    if "application/json" in accept:
        return JSONResponse(
            content={
                "status": resolved.status.value,
                "id": resolved.id,
                "approver": resolved.approver,
                "tool": resolved.tool,
                "message": "Rejected.",
            }
        )
    return HTMLResponse(f"<div class='p-2 bg-rose-950/40 border border-rose-800 text-rose-400 text-xs rounded mb-2'>Action <b>{_e(resolved.tool)}</b> Rejected.</div>")


@router.get("/api/manifests", dependencies=secured)
async def get_manifests():
    pdp = get_default_pdp()
    return {k: v.model_dump() for k, v in pdp.manifests.items()}


@router.get("/api/manifests/{agent}", dependencies=secured)
async def get_manifest_by_agent(agent: str):
    if not IDENTIFIER_REGEX.fullmatch(agent):
        raise HTTPException(status_code=422, detail="Invalid agent identifier")
    pdp = get_default_pdp()
    manifest = pdp.manifests.get(agent)
    if not manifest:
        raise HTTPException(status_code=404, detail=_e(f"Manifest for agent '{agent}' not found"))
    return manifest.model_dump()


@router.put("/api/manifests/{agent}", dependencies=secured)
async def update_manifest(agent: str, request: Request):
    if not IDENTIFIER_REGEX.fullmatch(agent):
        raise HTTPException(status_code=422, detail="Invalid agent identifier")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")

    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")

    body_agent = body.get("agent")
    if body_agent != agent:
        raise HTTPException(
            status_code=422,
            detail=f"Path agent '{agent}' does not match body agent '{body_agent}'",
        )

    try:
        new_manifest = AgentManifest.model_validate(body)
    except Exception as val_err:
        raise HTTPException(status_code=422, detail=f"Manifest validation error: {val_err}")

    pdp = get_default_pdp()
    old_manifest = pdp.manifests.get(agent)

    # Increment version
    if old_manifest and new_manifest.version == old_manifest.version:
        parts = old_manifest.version.split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
            new_manifest.version = ".".join(parts)
        except ValueError:
            new_manifest.version = f"{old_manifest.version}.1"

    # Atomic write to agentgate/manifests/{agent}.json
    # Write back to the directory the PDP loaded from (absolute, cwd-independent).
    manifests_dir = pdp.manifests_dir or DEFAULT_MANIFESTS_DIR
    manifests_dir.mkdir(parents=True, exist_ok=True)
    target_file = manifests_dir / f"{agent}.json"

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=str(manifests_dir), delete=False, encoding="utf-8") as tf:
            tf.write(new_manifest.model_dump_json(indent=2))
            temp_path = tf.name
        os.replace(temp_path, str(target_file))
    except Exception as write_err:
        logger.error("Atomic write failed for manifest %s: %s", agent, write_err)
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise HTTPException(status_code=500, detail="Failed to write manifest file")

    # In-memory PDP reload
    pdp.register_manifest(new_manifest)

    # Record MANIFEST_CHANGED audit event
    audit = get_default_audit_service()
    operator = request.headers.get("X-Operator", "dashboard_operator")
    audit.record_event(
        event_type="MANIFEST_CHANGED",
        agent=agent,
        tool="manifest_editor",
        decision=DecisionType.ALLOW,
        reason=f"Manifest '{agent}' updated to version {new_manifest.version}",
        approver=operator,
        arguments={"agent": agent, "version": new_manifest.version},
    )

    return {
        "status": "success",
        "message": f"Manifest '{agent}' updated to version {new_manifest.version}",
        "version": new_manifest.version,
        "manifest": new_manifest.model_dump(),
    }


@router.get("/api/manifests-html", response_class=HTMLResponse, dependencies=secured)
async def get_manifests_html():
    pdp = get_default_pdp()
    manifests = pdp.manifests

    if not manifests:
        return HTMLResponse("<p class='text-xs text-slate-500'>No manifests loaded in PDP.</p>")

    items = []
    for name, man in manifests.items():
        allowed = ", ".join(t.name for t in man.tools_allowed) or "none"
        denied = ", ".join(man.tools_denied) or "none"
        requires = ", ".join(man.requires_approval) or "none"
        items.append(f"""
        <div class="bg-slate-950 border border-slate-800 p-3 rounded text-xs space-y-2">
          <div class="flex items-center justify-between">
            <span class="font-bold text-cyan-400 text-sm">{_e(name)} <span class="text-[10px] text-slate-500">({_e(man.project)})</span></span>
            <span class="text-[10px] bg-slate-900 border border-slate-700 px-1.5 py-0.5 rounded text-slate-400">v{_e(man.version)}</span>
          </div>
          <div><span class="text-slate-400">Allowed Tools:</span> <span class="text-emerald-400">{_e(allowed)}</span></div>
          <div><span class="text-slate-400">Explicitly Denied:</span> <span class="text-rose-400">{_e(denied)}</span></div>
          <div><span class="text-slate-400">Requires Approval:</span> <span class="text-amber-400">{_e(requires)}</span></div>
          <details class="mt-2 pt-2 border-t border-slate-800">
            <summary class="cursor-pointer text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold select-none">
              &#9998; Edit Manifest JSON
            </summary>
            <div class="mt-2 space-y-2">
              <textarea id="editor-{_e(name)}" rows="8"
                class="w-full bg-slate-900 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-300 focus:outline-none focus:border-cyan-600">{_e(man.model_dump_json(indent=2))}</textarea>
              <div class="flex items-center justify-between">
                <button onclick="saveManifest('{_e(name)}')"
                        class="bg-cyan-700 hover:bg-cyan-600 text-white font-bold py-1 px-3 rounded text-xs">
                  Save Changes
                </button>
                <div id="status-{_e(name)}" class="text-xs"></div>
              </div>
            </div>
          </details>
        </div>
        """)

    grid = f"<div class='grid grid-cols-1 md:grid-cols-2 gap-3'>{''.join(items)}</div>"
    return HTMLResponse(grid)
