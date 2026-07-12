import streamlit as st
import httpx
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from api_utils import API_BASE, get_headers

st.set_page_config(page_title="Settings", layout="wide")
st.title("ThreatChain Settings")

st.subheader("API Authentication")
st.caption(
    "Only needed if the backend has API_KEY configured. Leave empty in dev mode. "
    "The UI also picks up API_KEY from the project .env automatically."
)
# Widget state is dropped when this page is not rendered, so copy the
# value into a plain session key that survives page switches.
_entered = st.text_input(
    "X-API-Key", type="password", value=st.session_state.get("api_key", "")
)
st.session_state["api_key"] = _entered

st.divider()
st.subheader("Batch Investigation")
ioc_input = st.text_area(
    "IOCs (one per line)",
    placeholder="185.220.101.34\nevil.example.com\nabc123...",
    height=150,
)

if st.button("Run Batch", type="primary"):
    ioc_list = [line.strip() for line in ioc_input.strip().splitlines() if line.strip()]
    if not ioc_list:
        st.warning("Enter at least one IOC.")
    elif len(ioc_list) > 20:
        st.error("Batch limit is 20 IOCs.")
    else:
        try:
            resp = httpx.post(f"{API_BASE}/investigate/batch", json=ioc_list, headers=get_headers(), timeout=15)
            if resp.status_code == 202:
                st.success(f"Batch of {len(ioc_list)} IOCs queued. Check History for results.")
            else:
                st.error(f"Error: {resp.text}")
        except Exception as e:
            st.error(f"Cannot connect: {e}")

st.divider()
st.subheader("Reset Daily API Counters")
st.caption("Resets the requests_today counter for all APIs in the database.")
if st.button("Reset Counters", type="secondary"):
    st.info("To reset counters, run: UPDATE api_configs SET requests_today = 0;")
