import streamlit as st
import httpx

API_BASE = "http://localhost:8000/api/v1"

st.set_page_config(page_title="Report Viewer", layout="wide")
st.title("Investigation Report")

inv_id = st.session_state.get("selected_investigation") or st.query_params.get("id", "")

if not inv_id:
    inv_id = st.text_input("Investigation ID", placeholder="Paste investigation UUID here")

if not inv_id:
    st.info("Enter an investigation ID or navigate from History.")
    st.stop()

try:
    report_resp = httpx.get(f"{API_BASE}/investigations/{inv_id}/report", timeout=15)

    if report_resp.status_code == 404:
        st.warning("Report not generated yet.")
        if st.button("Generate Report Now"):
            regen = httpx.post(f"{API_BASE}/investigations/{inv_id}/report/regenerate", timeout=15)
            if regen.status_code == 202:
                st.success("Report generation started. Refresh in a few seconds.")
            else:
                st.error(f"Error: {regen.text}")
    elif report_resp.status_code == 200:
        report = report_resp.json()
        st.markdown(report["content"])

        st.divider()
        st.subheader("Download")
        col1, col2, col3 = st.columns(3)

        with col1:
            md_resp = httpx.get(f"{API_BASE}/investigations/{inv_id}/report/download?format=md", timeout=15)
            if md_resp.status_code == 200:
                st.download_button("Download Markdown", md_resp.content, file_name=f"report_{inv_id[:8]}.md", mime="text/markdown")

        with col2:
            pdf_resp = httpx.get(f"{API_BASE}/investigations/{inv_id}/report/download?format=pdf", timeout=30)
            if pdf_resp.status_code == 200:
                st.download_button("Download PDF", pdf_resp.content, file_name=f"report_{inv_id[:8]}.pdf", mime="application/pdf")

        with col3:
            stix_resp = httpx.get(f"{API_BASE}/investigations/{inv_id}/report/download?format=stix", timeout=15)
            if stix_resp.status_code == 200:
                st.download_button("Download STIX 2.1", stix_resp.content, file_name=f"report_{inv_id[:8]}.stix.json", mime="application/json")
    else:
        st.error(f"API error {report_resp.status_code}: {report_resp.text}")

except Exception as e:
    st.error(f"Cannot connect to API: {e}")
