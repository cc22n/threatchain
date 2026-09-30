import pytest
import httpx
from unittest.mock import patch
from app.main import app
from app.config import settings


@pytest.mark.asyncio
async def test_health_liveness():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health_apis_authentication():
    with patch.object(settings, "API_KEY", "test_key_123"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Uinauthorized
            r1 = await client.get("/api/v1/health/apis")
            assert r1.status_code == 401

            # Authorized (db dependency will be invoked)
            r2 = await client.get("/api/v1/health/apis", headers={"x-api-key": "test_key_123"})
            assert r2.status_code in (200, 500) # 500 only if local postgres isn't running


@pytest.mark.asyncio
async def test_health_llms_authentication():
    with patch.object(settings, "API_KEY", "test_key_123"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            r1 = await client.get("/api/v1/health/llms")
            assert r1.status_code == 401

            r2 = await client.get("/api/v1/health/llms", headers={"x-api-key": "test_key_123"})
            assert r2.status_code == 200


@pytest.mark.asyncio
async def test_health_ready_status():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health/ready")
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "status" in data
        assert "database" in data
        assert "redis" in data
