import streamlit as st
import httpx
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from api_utils import API_BASE, get_headers

st.set_page_config(page_title="Report Viewer", layout="wide")
st.title("Investigation Report")

inv_id = st.session_state.get("selected_investigation") or st.query_params.get("id", "")

if not inv_id:
    inv_id = st.text_input("Investigation ID", placeholder="Paste investigation UUID here")

if not inv_id:
    st.info("Enter an investigation ID or navigate from History.")
    st.stop()

try:
    report_resp = httpx.get(f"{API_BASE}/investigations/{inv_id}/report", headers=get_headers(), timeout=15)

    if report_resp.status_code == 404:
        st.warning("Report not generated yet.")
        if st.button("Generate Report Now"):
            regen = httpx.post(f"{API_BASE}/investigations/{inv_id}/report/regenerate", headers=get_headers(), timeout=15)
            if regen.status_code == 202:
                st.success("Report generation started. Refresh in a few seconds.")
            else:
                st.error(f"Error: {regen.text}")
    elif report_resp.status_code == 200:
        report = report_resp.json()
        st.markdown(report.get("content", ""), unsafe_allow_html=False)

        st.divider()
        st.subheader("Download")

        @st.cache_data(ttl=300, show_spinner=False)
        def _fetch_file(inv_id_val: str, fmt: str) -> bytes | None:
            try:
                resp = httpx.get(
                    f"{API_BASE}/investigations/{inv_id_val}/report/download?format={fmt}",
                    headers=get_headers(),
                    timeout=30,
                )
                if resp.status_code == 200:
                    return resp.content
            except Exception:
                pass
            return None

        col1, col2, col3 = st.columns(3)

        with col1:
            st.download_button(
                "Download Markdown",
                data=report.get("content", ""),
                file_name=f"report_{inv_id[:8]}.md",
                mime="text/markdown",
            )

        with col2:
            pdf_bytes = _fetch_file(inv_id, "pdf")
            if pdf_bytes:
                st.download_button(
                    "Download PDF",
                    data=pdf_bytes,
                    file_name=f"report_{inv_id[:8]}.pdf",
                    mime="application/pdf",
                )
            else:
                st.button("PDF Unavailable", disabled=True)

        with col3:
            stix_bytes = _fetch_file(inv_id, "stix")
            if stix_bytes:
                st.download_button(
                    "Download STIX 2.1",
                    data=stix_bytes,
                    file_name=f"report_{inv_id[:8]}.stix.json",
                    mime="application/json",
                )
            else:
                st.button("STIX Unavailable", disabled=True)
    else:
        st.error(f"API error {report_resp.status_code}: {report_resp.text}")

except Exception as e:
    st.error(f"Cannot connect to API: {e}")
