import streamlit as st
import httpx
import json

API_BASE = "http://localhost:8000/api/v1"

st.set_page_config(page_title="ThreatChain", layout="wide")
st.title("ThreatChain - SOC Investigation Pipeline")
st.caption("Investigate IPs, domains, hashes, URLs, and CVEs using 17+ threat intelligence APIs")

with st.form("investigate_form"):
    ioc_value = st.text_input("Enter IOC", placeholder="e.g. 185.220.101.34 or evil.example.com")
    submitted = st.form_submit_button("Investigate", type="primary")

if submitted and ioc_value.strip():
    with st.spinner("Running investigation..."):
        try:
            resp = httpx.post(f"{API_BASE}/investigate", json={"ioc_value": ioc_value.strip()}, timeout=120)
            if resp.status_code in (200, 201):
                data = resp.json()
                st.success(f"Investigation complete: **{data.get('verdict', 'unknown').upper()}**")

                col1, col2, col3 = st.columns(3)
                col1.metric("Verdict", data.get("verdict", "N/A").upper())
                col2.metric("Severity", data.get("severity", "N/A").upper())
                col3.metric("Score", data.get("severity_score", "N/A"))

                if data.get("summary"):
                    st.subheader("Summary")
                    st.write(data["summary"])

                with st.expander("Full Response"):
                    st.json(data)
            else:
                st.error(f"API error {resp.status_code}: {resp.text}")
        except httpx.ConnectError:
            st.error("Cannot connect to ThreatChain API. Make sure the server is running on port 8000.")
        except Exception as e:
            st.error(f"Error: {e}")
elif submitted:
    st.warning("Please enter an IOC value.")
