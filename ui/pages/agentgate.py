import json
import os
import sys
from datetime import datetime
from pathlib import Path

import httpx
import streamlit as st

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from api_utils import API_BASE, get_headers

st.set_page_config(page_title="AgentGate Governance", layout="wide")

# Determine AgentGate API base from THREATCHAIN_API_BASE
BACKEND_HOST = os.getenv("THREATCHAIN_BACKEND_HOST", API_BASE.replace("/api/v1", ""))
AGENTGATE_BASE = f"{BACKEND_HOST}/agentgate"

st.title("AgentGate - Policy Enforcement & Governance")
st.caption(
    "Zero-Trust Policy Decision Point (PDP) and Policy Enforcement Point (PEP) "
    "for autonomous AI agents in ThreatChain."
)

col_actions1, col_actions2 = st.columns([8, 2])
with col_actions2:
    if st.button("Refresh Feed", use_container_width=True):
        st.rerun()

st.divider()

# ---------------------------------------------------------
# 1. METRICS ROW
# ---------------------------------------------------------
metrics = {
    "total_invocations": 0,
    "allow_count": 0,
    "deny_count": 0,
    "mask_count": 0,
    "require_approval_count": 0,
    "denial_rate_pct": 0.0,
    "pending_approvals_count": 0,
}

try:
    resp = httpx.get(f"{AGENTGATE_BASE}/api/metrics", headers=get_headers(), timeout=5)
    if resp.status_code == 200:
        metrics = resp.json()
    else:
        st.warning(f"Could not load AgentGate metrics (HTTP {resp.status_code})")
except Exception as exc:
    st.error(f"Cannot reach AgentGate API at {AGENTGATE_BASE}: {exc}")

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Decisions", metrics.get("total_invocations", 0))
m2.metric("Allowed Actions", metrics.get("allow_count", 0))
m3.metric("Denial Rate", f"{metrics.get('denial_rate_pct', 0.0)}%")
m4.metric("Masked Calls (RFC 1918)", metrics.get("mask_count", 0))
m5.metric("Pending Approvals", metrics.get("pending_approvals_count", 0))

st.divider()

# ---------------------------------------------------------
# 2. HUMAN-IN-THE-LOOP (HITL) PENDING APPROVALS
# ---------------------------------------------------------
st.subheader("Pending Human-in-the-Loop (HITL) Queue")
st.caption("High-risk or intrusive agent actions quarantined waiting for human operator authorization.")

pending_items = []
try:
    p_resp = httpx.get(f"{AGENTGATE_BASE}/api/pending", headers=get_headers(), timeout=5)
    if p_resp.status_code == 200:
        pending_items = p_resp.json()
except Exception as e:
    st.error(f"Error fetching pending approvals: {e}")

if not pending_items:
    st.info("No actions awaiting human review. All agent pipelines running within authorized boundaries.")
else:
    for item in pending_items:
        approval_id = item.get("id")
        agent_name = item.get("agent", "unknown")
        tool_name = item.get("tool", "unknown")
        args_payload = item.get("arguments", {})
        created_at = item.get("created_at", "")
        expires_at = item.get("expires_at", "")

        with st.container(border=True):
            h_col1, h_col2 = st.columns([7, 3])
            with h_col1:
                st.markdown(f"**Agent:** `{agent_name}` | **Tool:** `{tool_name}`")
                st.markdown(f"**Arguments:** `{json.dumps(args_payload)}`")
                st.caption(f"ID: `{approval_id}` | Created: {created_at} | Expires: {expires_at}")

            with h_col2:
                btn_col1, btn_col2 = st.columns(2)
                with btn_col1:
                    if st.button("Approve", key=f"app_{approval_id}", type="primary", use_container_width=True):
                        try:
                            a_res = httpx.post(f"{AGENTGATE_BASE}/api/approve/{approval_id}", headers=get_headers(), timeout=5)
                            if a_res.status_code == 200:
                                st.success("Action Approved successfully!")
                                st.rerun()
                            else:
                                st.error(f"Approval failed: {a_res.text}")
                        except Exception as ex:
                            st.error(f"Approval error: {ex}")

                with btn_col2:
                    if st.button("Reject", key=f"rej_{approval_id}", type="secondary", use_container_width=True):
                        try:
                            r_res = httpx.post(f"{AGENTGATE_BASE}/api/reject/{approval_id}", headers=get_headers(), timeout=5)
                            if r_res.status_code == 200:
                                st.warning("Action Rejected.")
                                st.rerun()
                            else:
                                st.error(f"Rejection failed: {r_res.text}")
                        except Exception as ex:
                            st.error(f"Rejection error: {ex}")

st.divider()

# ---------------------------------------------------------
# 3. REAL-TIME AUDIT LOG FEED
# ---------------------------------------------------------
st.subheader("Audit Log & Decision Feed")

filter_col1, filter_col2 = st.columns([3, 7])
with filter_col1:
    filter_decision = st.selectbox(
        "Filter by Decision",
        options=["ALL", "ALLOW", "DENY", "MASK", "REQUIRE_APPROVAL"],
        index=0,
    )

decisions_data = []
try:
    d_resp = httpx.get(f"{AGENTGATE_BASE}/api/decisions?limit=100", headers=get_headers(), timeout=5)
    if d_resp.status_code == 200:
        decisions_data = d_resp.json()
except Exception as e:
    st.error(f"Error fetching decision log: {e}")

if filter_decision != "ALL":
    decisions_data = [d for d in decisions_data if d.get("decision") == filter_decision]

if not decisions_data:
    st.info("No audit logs matching the current filter.")
else:
    table_rows = []
    for d in decisions_data:
        ts_str = d.get("timestamp", "")
        if ts_str:
            try:
                ts_formatted = ts_str.split("T")[1][:8] if "T" in ts_str else ts_str[:8]
            except Exception:
                ts_formatted = ts_str
        else:
            ts_formatted = "-"

        table_rows.append({
            "Time": ts_formatted,
            "Agent": d.get("agent"),
            "Tool": d.get("tool"),
            "Decision": d.get("decision"),
            "Reason": d.get("reason"),
            "Arguments": json.dumps(d.get("masked_arguments") or d.get("arguments") or {}),
        })

    st.dataframe(table_rows, use_container_width=True, hide_index=True)

st.divider()

# ---------------------------------------------------------
# 4. AGENT MANIFEST EXPLORER
# ---------------------------------------------------------
st.subheader("Agent Security Manifests")
st.caption("Active Zero-Trust principle-of-least-privilege manifests configured in AgentGate PDP.")

manifests_data = {}
try:
    m_resp = httpx.get(f"{AGENTGATE_BASE}/api/manifests", headers=get_headers(), timeout=5)
    if m_resp.status_code == 200:
        manifests_data = m_resp.json()
except Exception as e:
    st.error(f"Error fetching manifests: {e}")

if manifests_data:
    cols = st.columns(len(manifests_data))
    for idx, (agent_key, manifest) in enumerate(manifests_data.items()):
        with cols[idx]:
            with st.container(border=True):
                st.markdown(f"**{agent_key}**")
                st.caption(f"Project: `{manifest.get('project', 'ThreatChain')}`")
                
                allowed_tools = [t.get("name") if isinstance(t, dict) else str(t) for t in manifest.get("tools_allowed", [])]
                st.markdown("**Allowed Tools:**")
                st.write(", ".join(allowed_tools) if allowed_tools else "None")

                denied_tools = manifest.get("tools_denied", [])
                st.markdown("**Explicitly Denied:**")
                st.write(", ".join(denied_tools) if denied_tools else "None")

                req_app = manifest.get("requires_approval", [])
                st.markdown("**Requires HITL Approval:**")
                st.write(", ".join(req_app) if req_app else "None")

st.divider()

# ---------------------------------------------------------
# 5. EXTERNAL DASHBOARD LINK
# ---------------------------------------------------------
st.caption(
    f"Need live auto-refreshing WebSocket / HTMX feeds? "
    f"Open the standalone dashboard at: [AgentGate HTMX Dashboard]({AGENTGATE_BASE})"
)
