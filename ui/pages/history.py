import streamlit as st
import httpx
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from api_utils import API_BASE, get_headers

st.set_page_config(page_title="Investigation History", layout="wide")
st.title("Investigation History")

try:
    resp = httpx.get(f"{API_BASE}/investigations?limit=50", headers=get_headers(), timeout=10)
    if resp.status_code == 200:
        investigations = resp.json()
        if not investigations:
            st.info("No investigations yet.")
        else:
            for inv in investigations:
                verdict = inv.get("verdict") or "pending"
                severity = inv.get("severity") or "info"
                color = {"malicious": "red", "suspicious": "orange", "benign": "green"}.get(verdict, "gray")
                with st.expander(f"`{inv['ioc_value']}` -- {inv['ioc_type'].upper()} -- :{color}[{verdict.upper()}]"):
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Severity", severity.upper())
                    col2.metric("Score", inv.get("severity_score") or "N/A")
                    col3.metric("Status", inv.get("status", ""))
                    col4.metric("Time (s)", inv.get("execution_time_seconds") or "N/A")
                    st.caption(f"ID: {inv['id']} | Created: {inv['created_at']}")
                    if st.button("View Report", key=inv["id"]):
                        st.session_state["selected_investigation"] = inv["id"]
                        st.switch_page("pages/report_viewer.py")
    else:
        st.error(f"API error: {resp.status_code}")
except Exception as e:
    st.error(f"Cannot connect to API: {e}")
