import re
import uuid
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.bot import telegram_bot as bot
from app.config import settings
from app.main import app
from agentgate.hitl.queue import ApprovalQueue, ApprovalStatus, get_default_approval_queue


class _FakeAsyncClient:
    def __init__(self, response):
        self._response = response
        self.last_url = None
        self.last_params = None
        self.last_headers = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, params=None, headers=None, **kwargs):
        self.last_url = url
        self.last_params = params
        self.last_headers = headers
        return self._response

    async def get(self, url, headers=None, **kwargs):
        self.last_url = url
        self.last_headers = headers
        return self._response


def _make_callback_update(chat_id: int, callback_data: str, message_text: str = "Test message"):
    update = MagicMock()
    update.effective_chat.id = chat_id

    query = MagicMock()
    query.data = callback_data
    query.message.text = message_text
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()

    update.callback_query = query
    return update


@pytest.mark.asyncio
async def test_callback_allowlist_blocks_unauthorized_user():
    req_id = str(uuid.uuid4())
    update = _make_callback_update(chat_id=999999, callback_data=f"ag_appr_{req_id}")

    with patch.object(settings, "TELEGRAM_ALLOWLIST", "123456"):
        await bot.on_approval_callback(update, None)

    update.callback_query.answer.assert_awaited_once_with(
        "No autorizado para resolver aprobaciones de AgentGate.", show_alert=True
    )
    update.callback_query.edit_message_text.assert_not_called()


@pytest.mark.asyncio
async def test_callback_approve_success():
    req_id = str(uuid.uuid4())
    update = _make_callback_update(chat_id=123456, callback_data=f"ag_appr_{req_id}", message_text="Approval request")

    resp = MagicMock()
    resp.status_code = 200
    fake_client = _FakeAsyncClient(resp)

    with patch.object(settings, "TELEGRAM_ALLOWLIST", "123456"):
        with patch("httpx.AsyncClient", return_value=fake_client):
            await bot.on_approval_callback(update, None)

    assert f"/agentgate/api/approve/{req_id}" in fake_client.last_url
    assert fake_client.last_params["approver"] == "telegram:123456"

    update.callback_query.edit_message_text.assert_awaited_once()
    called_text = update.callback_query.edit_message_text.call_args.kwargs["text"]
    assert "Aprobado por telegram:123456" in called_text


@pytest.mark.asyncio
async def test_callback_reject_success():
    req_id = str(uuid.uuid4())
    update = _make_callback_update(chat_id=123456, callback_data=f"ag_rej_{req_id}", message_text="Approval request")

    resp = MagicMock()
    resp.status_code = 200
    fake_client = _FakeAsyncClient(resp)

    with patch.object(settings, "TELEGRAM_ALLOWLIST", "123456"):
        with patch("httpx.AsyncClient", return_value=fake_client):
            await bot.on_approval_callback(update, None)

    assert f"/agentgate/api/reject/{req_id}" in fake_client.last_url
    assert fake_client.last_params["approver"] == "telegram:123456"

    update.callback_query.edit_message_text.assert_awaited_once()
    called_text = update.callback_query.edit_message_text.call_args.kwargs["text"]
    assert "Rechazado por telegram:123456" in called_text


@pytest.mark.asyncio
async def test_callback_double_tap_returns_conflict_message():
    req_id = str(uuid.uuid4())
    update = _make_callback_update(chat_id=123456, callback_data=f"ag_appr_{req_id}", message_text="Approval request")

    resp = MagicMock()
    resp.status_code = 409
    resp.json.return_value = {"detail": "Approval request already resolved as APPROVED"}
    fake_client = _FakeAsyncClient(resp)

    with patch.object(settings, "TELEGRAM_ALLOWLIST", "123456"):
        with patch("httpx.AsyncClient", return_value=fake_client):
            await bot.on_approval_callback(update, None)

    update.callback_query.edit_message_text.assert_awaited_once()
    called_text = update.callback_query.edit_message_text.call_args.kwargs["text"]
    assert "[ATENCION] Approval request already resolved" in called_text


def test_api_approve_double_resolution_returns_409():
    queue = get_default_approval_queue()
    req = queue.create_request("agent", "tool", {})

    client = TestClient(app)
    # 1st resolution
    r1 = client.post(f"/agentgate/api/approve/{req.id}?approver=op1", headers={"Accept": "application/json"})
    assert r1.status_code == 200
    assert r1.json()["status"] == "APPROVED"

    # 2nd resolution -> 409 Conflict
    r2 = client.post(f"/agentgate/api/approve/{req.id}?approver=op2")
    assert r2.status_code == 409
    assert "already resolved" in r2.json()["detail"]


def test_api_reject_double_resolution_returns_409():
    queue = get_default_approval_queue()
    req = queue.create_request("agent", "tool", {})

    client = TestClient(app)
    # 1st resolution
    r1 = client.post(f"/agentgate/api/reject/{req.id}?approver=op1", headers={"Accept": "application/json"})
    assert r1.status_code == 200
    assert r1.json()["status"] == "REJECTED"

    # 2nd resolution -> 409 Conflict
    r2 = client.post(f"/agentgate/api/reject/{req.id}?approver=op2")
    assert r2.status_code == 409


def test_api_invalid_approver_regex_returns_422():
    queue = get_default_approval_queue()
    req = queue.create_request("agent", "tool", {})

    client = TestClient(app)
    # Approver with invalid characters (e.g. spaces or quotes)
    bad_approver = "bad approver; DROP TABLE"
    r = client.post(f"/agentgate/api/approve/{req.id}?approver={bad_approver}")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_pendientes_command_lists_requests():
    queue = get_default_approval_queue()
    req = queue.create_request("test_agent", "test_tool", {})

    update = MagicMock()
    update.effective_chat.id = 123456
    update.message.reply_text = AsyncMock()

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = [{"id": req.id, "agent": "test_agent", "tool": "test_tool"}]
    fake_client = _FakeAsyncClient(resp)

    with patch.object(settings, "TELEGRAM_ALLOWLIST", "123456"):
        with patch("httpx.AsyncClient", return_value=fake_client):
            await bot.pendientes(update, None)

    update.message.reply_text.assert_awaited_once()
    text = update.message.reply_text.call_args[0][0]
    assert "test_agent" in text
    assert "test_tool" in text
