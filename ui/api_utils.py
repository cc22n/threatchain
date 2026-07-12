"""Shared API utilities for ThreatChain UI"""
import os

import streamlit as st
from dotenv import load_dotenv

# Pick up API_KEY (and anything else) from the project .env; the UI runs
# in its own process so it does not inherit the backend settings.
load_dotenv()

# Overridable so the UI can reach the API across containers, where
# "localhost" would point at the UI container itself (docker-compose
# sets these to the "api" service hostname).
API_BASE = os.getenv("THREATCHAIN_API_BASE", "http://localhost:8000/api/v1")
WS_BASE = os.getenv("THREATCHAIN_WS_BASE", "ws://localhost:8000/ws")


def get_api_key() -> str:
    """API key for mutation endpoints.

    Order: API_KEY env var (.env), then the value entered in the Settings
    page (session state). Empty string means no auth header is sent, which
    matches the backend dev mode where API_KEY is unset and auth is skipped.
    This function must never create widgets: it gets called several times
    per rerun and duplicate widgets crash Streamlit.
    """
    return os.getenv("API_KEY", "") or st.session_state.get("api_key", "")


def get_headers() -> dict:
    """Headers dict with optional X-API-Key"""
    api_key = get_api_key()
    return {"X-API-Key": api_key} if api_key else {}
