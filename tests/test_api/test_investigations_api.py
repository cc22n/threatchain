import pytest
import httpx
from unittest.mock import patch
from app.main import app
from app.config import settings


@pytest.mark.asyncio
async def test_get_investigations_authentication():
    with patch.object(settings, "API_KEY", "secret_api_key"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Missing key -> 401
            r1 = await client.get("/api/v1/investigations")
            assert r1.status_code == 401

            # Wrong key -> 401
            r2 = await client.get("/api/v1/investigations", headers={"x-api-key": "wrong_key"})
            assert r2.status_code == 401


@pytest.mark.asyncio
async def test_investigate_invalid_payload():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Empty body -> 422
        resp = await client.post("/api/v1/investigate", json={})
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_batch_invalid_payload():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Not a group of iocs -> 422
        resp = await client.post("/api/v1/investigate/batch", json={"invalid": "format"})
        assert resp.status_code == 422
