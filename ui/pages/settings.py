import streamlit as st
import httpx

API_BASE = "http://localhost:8000/api/v1"

st.set_page_config(page_title="Settings", layout="wide")
st.title("ThreatChain Settings")

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
            resp = httpx.post(f"{API_BASE}/investigate/batch", json=ioc_list, timeout=15)
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
