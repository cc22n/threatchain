import streamlit as st
import httpx

API_BASE = "http://localhost:8000/api/v1"

st.set_page_config(page_title="API Health", layout="wide")
st.title("API & LLM Health Dashboard")

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Threat Intel APIs")
    try:
        resp = httpx.get(f"{API_BASE}/health/apis", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for api in data.get("apis", []):
                pct = api.get("usage_pct", 0)
                color = "red" if pct >= 90 else "orange" if pct >= 70 else "green"
                status = "DISABLED" if not api["is_active"] else f"{api['requests_today']}/{api['rate_limit_per_day']} ({pct}%)"
                st.metric(
                    label=api["api_name"],
                    value=status,
                    delta=f"{api['remaining_today']} remaining" if api["is_active"] else None,
                )
        else:
            st.error(f"API error: {resp.status_code}")
    except Exception as e:
        st.error(f"Cannot connect: {e}")

with col_right:
    st.subheader("LLM Providers")
    try:
        resp = httpx.get(f"{API_BASE}/health/llms", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for provider in data.get("providers", []):
                icon = "OK" if provider["configured"] else "MISSING KEY"
                st.metric(
                    label=provider["provider"],
                    value=icon,
                    delta=", ".join(provider["models"]),
                )
        else:
            st.error(f"API error: {resp.status_code}")
    except Exception as e:
        st.error(f"Cannot connect: {e}")

st.divider()
st.subheader("Global Statistics")
try:
    resp = httpx.get(f"{API_BASE}/stats", timeout=10)
    if resp.status_code == 200:
        stats = resp.json()
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Investigations", stats.get("total_investigations", 0))
        c2.metric("Completed", stats.get("completed", 0))
        c3.metric("Failed", stats.get("failed", 0))
        c4.metric("Malicious Found", stats.get("malicious_found", 0))
        c5.metric("Avg Time (s)", stats.get("avg_execution_time_seconds", 0))
        st.caption(f"Total tokens used: {stats.get('total_tokens_used', 0):,}")
except Exception as e:
    st.error(f"Cannot connect: {e}")
