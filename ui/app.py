import streamlit as st
import httpx
import json
import asyncio
import websockets
import time

from api_utils import API_BASE, WS_BASE, get_headers

st.set_page_config(page_title="ThreatChain", layout="wide")
st.title("ThreatChain - SOC Investigation Pipeline")
st.caption("Investigate IPs, domains, hashes, URLs, and CVEs using 17+ threat intelligence APIs")

async def connect_websocket(investigation_id, status_placeholder, agents_placeholder, timeout_seconds=180):
    """Connect to WebSocket and process events"""
    ws_url = f"{WS_BASE}/investigation/{investigation_id}"
    start_time = time.time()
    agents_status = {}
    current_verdict = None
    current_severity = None
    current_score = None

    try:
        async with websockets.connect(ws_url, ping_interval=None) as websocket:
            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout_seconds:
                    status_placeholder.warning(f"WebSocket timeout after {timeout_seconds}s")
                    return agents_status, current_verdict, current_severity, current_score

                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    event = json.loads(message)
                    event_type = event.get("event", "unknown")

                    if event_type == "snapshot":
                        current_verdict = event.get("verdict")
                        current_severity = event.get("severity")
                        current_score = event.get("severity_score")
                        status_placeholder.info("Connected to investigation stream...")

                    elif event_type == "investigation_started":
                        status_placeholder.info("Investigation started...")

                    elif event_type == "agent_completed":
                        agent_name = event.get("agent", "unknown")
                        agent_status = event.get("agent_status", "unknown")
                        agents_status[agent_name] = agent_status

                        # Update agents display
                        agent_display = ""
                        for agent, status in agents_status.items():
                            if status == "success":
                                agent_display += f"[OK] {agent}\n"
                            elif status == "error":
                                agent_display += f"[ERR] {agent}\n"
                            else:
                                agent_display += f"[-] {agent}\n"
                        agents_placeholder.text(agent_display if agent_display else "No agents completed yet")

                    elif event_type == "report_generated":
                        status_placeholder.info("Report generated, finalizing...")

                    elif event_type == "investigation_finished":
                        current_verdict = event.get("verdict", current_verdict)
                        current_severity = event.get("severity", current_severity)
                        current_score = event.get("severity_score", current_score)
                        final_status = event.get("status", "completed")

                        if final_status == "completed":
                            status_placeholder.success("Investigation completed!")
                        else:
                            status_placeholder.error(f"Investigation {final_status}")

                        return agents_status, current_verdict, current_severity, current_score

                except asyncio.TimeoutError:
                    # Timeout on recv, just continue polling
                    continue
                except json.JSONDecodeError:
                    # Invalid JSON, skip
                    continue

    except Exception as e:
        status_placeholder.warning(f"WebSocket error: {str(e)}")
        return agents_status, current_verdict, current_severity, current_score

def poll_investigation(investigation_id, status_placeholder, agents_placeholder, timeout_seconds=180):
    """Fallback polling mechanism if WebSocket fails"""
    start_time = time.time()
    agents_status = {}

    while True:
        elapsed = time.time() - start_time
        if elapsed > timeout_seconds:
            status_placeholder.warning(f"Polling timeout after {timeout_seconds}s")
            break

        try:
            resp = httpx.get(f"{API_BASE}/investigations/{investigation_id}", headers=get_headers(), timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "pending")

                if status == "running":
                    status_placeholder.info(f"Investigation running... (elapsed: {int(elapsed)}s)")
                elif status == "completed":
                    status_placeholder.success("Investigation completed!")
                    return data
                elif status == "failed":
                    status_placeholder.error("Investigation failed")
                    return data
                elif status == "cancelled":
                    status_placeholder.warning("Investigation cancelled")
                    return data
                else:
                    status_placeholder.info(f"Status: {status}")

            time.sleep(3)
        except Exception as e:
            status_placeholder.warning(f"Polling error: {str(e)}")
            time.sleep(3)

    # Final attempt to get result
    try:
        resp = httpx.get(f"{API_BASE}/investigations/{investigation_id}", headers=get_headers(), timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass

    return None

def render_investigation_result(data):
    """Render investigation result with metrics and report"""
    if not data:
        st.error("No data to display")
        return

    # Metrics row
    col1, col2, col3 = st.columns(3)
    col1.metric("Verdict", str(data.get("verdict", "N/A")).upper())
    col2.metric("Severity", str(data.get("severity", "N/A")).upper())
    col3.metric("Score", data.get("severity_score", "N/A"))

    # Summary
    if data.get("summary"):
        st.subheader("Summary")
        st.write(data["summary"])

    # Full details
    with st.expander("Full Response"):
        st.json(data)

with st.form("investigate_form"):
    ioc_value = st.text_input("Enter IOC", placeholder="e.g. 185.220.101.34 or evil.example.com")
    submitted = st.form_submit_button("Investigate", type="primary")

if submitted and ioc_value.strip():
    ioc_value = ioc_value.strip()

    try:
        # Start investigation async (wait=false)
        st.info("Starting investigation...")
        resp = httpx.post(
            f"{API_BASE}/investigate",
            json={"ioc_value": ioc_value, "wait": False},
            headers=get_headers(),
            timeout=5
        )

        if resp.status_code in (200, 201):
            start_data = resp.json()
            investigation_id = start_data.get("id")

            if not investigation_id:
                st.error("No investigation ID returned from server")
            else:
                st.success(f"Investigation started with ID: {investigation_id}")

                # Create placeholders for live updates
                status_placeholder = st.empty()
                agents_placeholder = st.empty()
                progress_placeholder = st.empty()

                with status_placeholder.container():
                    status_placeholder.info("Connecting to investigation stream...")

                agents_placeholder.text("Waiting for agents to complete...")

                # Try WebSocket first, with timeout and fallback to polling
                try:
                    agents_status, verdict, severity, score = asyncio.run(
                        connect_websocket(investigation_id, status_placeholder, agents_placeholder, timeout_seconds=180)
                    )

                    # If we got a complete result from WebSocket, fetch final data
                    if verdict:
                        try:
                            resp = httpx.get(
                                f"{API_BASE}/investigations/{investigation_id}",
                                headers=get_headers(),
                                timeout=10
                            )
                            if resp.status_code == 200:
                                final_data = resp.json()
                                st.success(f"Investigation complete: **{str(final_data.get('verdict', 'unknown')).upper()}**")
                                render_investigation_result(final_data)
                        except Exception as e:
                            st.warning(f"Could not fetch final data: {str(e)}")
                    else:
                        # WebSocket didn't get verdict, fallback to polling
                        st.info("WebSocket incomplete, switching to polling...")
                        final_data = poll_investigation(investigation_id, status_placeholder, agents_placeholder, timeout_seconds=180)
                        if final_data:
                            st.success(f"Investigation complete: **{str(final_data.get('verdict', 'unknown')).upper()}**")
                            render_investigation_result(final_data)

                except Exception as e:
                    # WebSocket failed entirely, use polling
                    st.warning(f"WebSocket connection failed: {str(e)}. Switching to polling...")
                    final_data = poll_investigation(investigation_id, status_placeholder, agents_placeholder, timeout_seconds=180)
                    if final_data:
                        st.success(f"Investigation complete: **{str(final_data.get('verdict', 'unknown')).upper()}**")
                        render_investigation_result(final_data)
        else:
            st.error(f"API error {resp.status_code}: {resp.text}")

    except httpx.ConnectError:
        st.error("Cannot connect to ThreatChain API. Make sure the server is running on port 8000.")
    except Exception as e:
        st.error(f"Error: {str(e)}")

elif submitted:
    st.warning("Please enter an IOC value.")
