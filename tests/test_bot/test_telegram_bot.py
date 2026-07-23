import asyncio
import json

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.bot import telegram_bot as bot


class _FakeWebSocketConnection:
    """Minimal async context manager standing in for a websockets connection.

    Same rationale as _FakeAsyncClient below: a hand-written class satisfies
    `async with websockets.connect(...) as ws` where a bare AsyncMock would
    not, because Python looks up __aenter__/__aexit__ on the type.
    """

    def __init__(self, messages):
        self._messages = list(messages)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def recv(self):
        if not self._messages:
            raise ConnectionError("fake websocket exhausted with no terminal event")
        return self._messages.pop(0)


def _patch_ws(messages):
    def factory(*args, **kwargs):
        return _FakeWebSocketConnection(messages)

    return patch("app.bot.telegram_bot.websockets.connect", side_effect=factory)


class _FakeAsyncClient:
    """Minimal async context manager standing in for httpx.AsyncClient.

    Using a real object instead of MagicMock for __aenter__/__aexit__
    sidesteps the well-known footgun where Python looks up dunder methods
    on the type, not the instance, so a bare AsyncMock never satisfies
    `async with client:` even after setting `.return_value` on it.
    """

    def __init__(self, response, calls):
        self._response = response
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def post(self, path, json=None, headers=None):
        self._calls.append({"method": "POST", "path": path, "json": json, "headers": headers})
        return self._response

    async def get(self, path, params=None, headers=None):
        self._calls.append({"method": "GET", "path": path, "params": params, "headers": headers})
        return self._response


def _patch_client(response):
    calls = []

    def factory(*args, **kwargs):
        return _FakeAsyncClient(response, calls)

    return patch("app.bot.telegram_bot.httpx.AsyncClient", side_effect=factory), calls


def _response(status_code, json_data, url="http://test/investigate"):
    return httpx.Response(status_code, json=json_data, request=httpx.Request("GET", url))


# ---------- split_message ----------

def test_split_message_short_text_unchanged():
    assert bot.split_message("hola") == ["hola"]


def test_split_message_splits_long_text():
    text = "linea\n" * 1000
    chunks = bot.split_message(text, limit=4096)
    assert len(chunks) > 1
    assert all(len(c) <= 4096 for c in chunks)


def test_split_message_respects_limit_boundary():
    text = "a" * 4096
    assert bot.split_message(text) == [text]

    text2 = "a" * 4097
    chunks = bot.split_message(text2)
    assert len(chunks) == 2
    assert all(len(c) <= 4096 for c in chunks)


# ---------- format_investigation ----------

def test_format_investigation_pending():
    msg = bot.format_investigation({"id": "abc", "status": "pending"})
    assert "abc" in msg
    assert "pending" in msg


def test_format_investigation_failed():
    msg = bot.format_investigation({"id": "abc", "status": "failed"})
    assert "fallo" in msg


def test_format_investigation_completed():
    inv = {
        "id": "abc123",
        "status": "completed",
        "ioc_value": "1.2.3.4",
        "verdict": "malicious",
        "severity": "high",
        "severity_score": 8.5,
        "summary": "IP asociada a botnet.",
    }
    msg = bot.format_investigation(inv)
    assert "MALICIOUS" in msg
    assert "8.5/10" in msg
    assert "botnet" in msg


def test_format_investigation_completed_no_summary():
    inv = {
        "id": "abc", "status": "completed", "ioc_value": "x",
        "verdict": None, "severity": None, "severity_score": None,
    }
    msg = bot.format_investigation(inv)
    assert "N/D" in msg
    assert "Sin resumen disponible" in msg


# ---------- allowlist ----------

def test_is_allowed_true(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111,222")
    assert bot.is_allowed(111) is True
    assert bot.is_allowed(222) is True


def test_is_allowed_false(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    assert bot.is_allowed(999) is False


def test_is_allowed_empty_allowlist_blocks_everyone(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "")
    assert bot.is_allowed(111) is False


@pytest.mark.asyncio
async def test_require_allowlist_blocks_unlisted_chat(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    called = False

    @bot.require_allowlist
    async def handler(update, context):
        nonlocal called
        called = True

    update = MagicMock()
    update.effective_chat.id = 999
    update.message.reply_text = AsyncMock()

    await handler(update, None)

    assert called is False
    update.message.reply_text.assert_called_once()
    assert "privado" in update.message.reply_text.call_args[0][0]


@pytest.mark.asyncio
async def test_require_allowlist_allows_listed_chat(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    called = False

    @bot.require_allowlist
    async def handler(update, context):
        nonlocal called
        called = True

    update = MagicMock()
    update.effective_chat.id = 111
    update.message.reply_text = AsyncMock()

    await handler(update, None)

    assert called is True
    update.message.reply_text.assert_not_called()


# ---------- _start_investigation ----------

@pytest.mark.asyncio
async def test_start_investigation_unknown_ioc_returns_error():
    result = await bot._start_investigation("not a valid ioc at all!!")
    assert "error" in result


@pytest.mark.asyncio
async def test_start_investigation_calls_api_with_classified_type():
    fake_response = _response(201, {"id": "inv-1", "ioc_value": "1.2.3.4", "status": "pending"})
    patcher, calls = _patch_client(fake_response)

    with patcher:
        result = await bot._start_investigation("1.2.3.4")

    assert result["id"] == "inv-1"
    assert len(calls) == 1
    assert calls[0]["method"] == "POST"
    assert calls[0]["path"] == "/investigate"
    assert calls[0]["json"]["ioc_type"] == "ip"
    assert calls[0]["json"]["wait"] is False


@pytest.mark.asyncio
async def test_start_investigation_raises_on_http_error():
    fake_response = _response(500, {"detail": "boom"})
    patcher, _ = _patch_client(fake_response)

    with patcher:
        with pytest.raises(httpx.HTTPStatusError):
            await bot._start_investigation("1.2.3.4")


# ---------- _fetch_investigation ----------

@pytest.mark.asyncio
async def test_fetch_investigation_returns_json():
    fake_response = _response(200, {"id": "inv-1", "status": "completed"})
    patcher, calls = _patch_client(fake_response)

    with patcher:
        result = await bot._fetch_investigation("inv-1")

    assert result["status"] == "completed"
    assert calls[0]["path"] == "/investigations/inv-1"


@pytest.mark.asyncio
async def test_fetch_investigation_404():
    fake_response = _response(404, {"detail": "not found"})
    patcher, _ = _patch_client(fake_response)

    with patcher:
        with pytest.raises(httpx.HTTPStatusError):
            await bot._fetch_investigation("does-not-exist")


# ---------- _fetch_report ----------

@pytest.mark.asyncio
async def test_fetch_report_returns_json():
    fake_response = _response(200, {"investigation_id": "inv-1", "format": "markdown", "content": "# Report"})
    patcher, calls = _patch_client(fake_response)

    with patcher:
        result = await bot._fetch_report("inv-1")

    assert result["content"] == "# Report"
    assert calls[0]["path"] == "/investigations/inv-1/report"


@pytest.mark.asyncio
async def test_fetch_report_404():
    fake_response = _response(404, {"detail": "not found"})
    patcher, _ = _patch_client(fake_response)

    with patcher:
        with pytest.raises(httpx.HTTPStatusError):
            await bot._fetch_report("does-not-exist")


# ---------- _fetch_stats ----------

@pytest.mark.asyncio
async def test_fetch_stats_returns_json():
    fake_response = _response(200, {"total_investigations": 5, "completed": 4})
    patcher, calls = _patch_client(fake_response)

    with patcher:
        result = await bot._fetch_stats()

    assert result["total_investigations"] == 5
    assert calls[0]["path"] == "/stats"


# ---------- _find_recent_investigation ----------

def _iso_now(seconds_ago: int = 0) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


@pytest.mark.asyncio
async def test_find_recent_investigation_no_rows():
    fake_response = _response(200, [])
    patcher, calls = _patch_client(fake_response)

    with patcher:
        result = await bot._find_recent_investigation("1.2.3.4")

    assert result is None
    assert calls[0]["params"] == {"ioc_value": "1.2.3.4", "limit": 1}


@pytest.mark.asyncio
async def test_find_recent_investigation_returns_recent_match():
    row = {"id": "inv-1", "status": "running", "ioc_value": "1.2.3.4", "created_at": _iso_now(30)}
    fake_response = _response(200, [row])
    patcher, _ = _patch_client(fake_response)

    with patcher:
        result = await bot._find_recent_investigation("1.2.3.4")

    assert result == row


@pytest.mark.asyncio
async def test_find_recent_investigation_ignores_stale_match():
    row = {"id": "inv-1", "status": "completed", "ioc_value": "1.2.3.4", "created_at": _iso_now(9999)}
    fake_response = _response(200, [row])
    patcher, _ = _patch_client(fake_response)

    with patcher:
        result = await bot._find_recent_investigation("1.2.3.4")

    assert result is None


@pytest.mark.asyncio
async def test_find_recent_investigation_ignores_failed_status():
    row = {"id": "inv-1", "status": "failed", "ioc_value": "1.2.3.4", "created_at": _iso_now(5)}
    fake_response = _response(200, [row])
    patcher, _ = _patch_client(fake_response)

    with patcher:
        result = await bot._find_recent_investigation("1.2.3.4")

    assert result is None


# ---------- _check_user_rate_limit ----------

def test_check_user_rate_limit_allows_then_blocks(monkeypatch):
    monkeypatch.setattr(bot, "TELEGRAM_RATE_LIMIT_PER_DAY", 2)
    bot._user_request_log.pop(90001, None)

    assert bot._check_user_rate_limit(90001) is True
    assert bot._check_user_rate_limit(90001) is True
    assert bot._check_user_rate_limit(90001) is False


def test_check_user_rate_limit_tracks_chats_independently(monkeypatch):
    monkeypatch.setattr(bot, "TELEGRAM_RATE_LIMIT_PER_DAY", 1)
    bot._user_request_log.pop(90002, None)
    bot._user_request_log.pop(90003, None)

    assert bot._check_user_rate_limit(90002) is True
    assert bot._check_user_rate_limit(90003) is True
    assert bot._check_user_rate_limit(90002) is False


# ---------- handlers ----------

def _make_update(text=None, args=None, chat_id=111):
    update = MagicMock()
    update.effective_chat.id = chat_id
    update.message.text = text
    update.message.reply_text = AsyncMock()
    context = MagicMock()
    context.args = args or []
    return update, context


@pytest.mark.asyncio
async def test_investigar_without_args_shows_usage(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    update, context = _make_update(args=[])

    await bot.investigar(update, context)

    update.message.reply_text.assert_called_once()
    assert "Uso:" in update.message.reply_text.call_args[0][0]


@pytest.mark.asyncio
async def test_investigar_happy_path_spawns_watch_task(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    fake_response = _response(201, {"id": "inv-42", "ioc_value": "1.2.3.4", "status": "pending"})
    patcher, _ = _patch_client(fake_response)
    update, context = _make_update(args=["1.2.3.4"])

    with patch("app.bot.telegram_bot._find_recent_investigation", new=AsyncMock(return_value=None)):
        with patch("app.bot.telegram_bot._watch_investigation", new=AsyncMock()) as mock_watch:
            with patcher:
                await bot.investigar(update, context)
            pending = list(bot._background_tasks)
            if pending:
                await asyncio.gather(*pending)

    mock_watch.assert_called_once_with(update, "inv-42", "1.2.3.4")
    # _handle_ioc itself must not reply directly anymore - _watch_investigation
    # owns the first message so it can keep editing it as agents finish.
    update.message.reply_text.assert_not_called()


@pytest.mark.asyncio
async def test_investigar_reuses_in_flight_duplicate(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    existing = {"id": "inv-1", "status": "running", "ioc_value": "1.2.3.4"}
    update, context = _make_update(args=["1.2.3.4"])

    with patch("app.bot.telegram_bot._find_recent_investigation", new=AsyncMock(return_value=existing)):
        with patch("app.bot.telegram_bot._start_investigation", new=AsyncMock()) as mock_start:
            with patch("app.bot.telegram_bot._watch_investigation", new=AsyncMock()) as mock_watch:
                await bot.investigar(update, context)
                pending = list(bot._background_tasks)
                if pending:
                    await asyncio.gather(*pending)

    mock_start.assert_not_called()
    mock_watch.assert_called_once_with(update, "inv-1", "1.2.3.4")
    assert "Ya hay una investigacion reciente" in update.message.reply_text.call_args[0][0]


@pytest.mark.asyncio
async def test_investigar_shows_recent_completed_duplicate(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    existing = {
        "id": "inv-1", "status": "completed", "ioc_value": "1.2.3.4",
        "verdict": "malicious", "severity": "high", "severity_score": 8.0,
    }
    update, context = _make_update(args=["1.2.3.4"])

    with patch("app.bot.telegram_bot._find_recent_investigation", new=AsyncMock(return_value=existing)):
        with patch("app.bot.telegram_bot._start_investigation", new=AsyncMock()) as mock_start:
            await bot.investigar(update, context)

    mock_start.assert_not_called()
    all_msgs = " ".join(c.args[0] for c in update.message.reply_text.call_args_list)
    assert "Ya investigue" in all_msgs
    assert "MALICIOUS" in all_msgs


@pytest.mark.asyncio
async def test_investigar_blocked_by_rate_limit(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    monkeypatch.setattr(bot, "TELEGRAM_RATE_LIMIT_PER_DAY", 0)
    bot._user_request_log.pop(111, None)
    update, context = _make_update(args=["1.2.3.4"])

    with patch("app.bot.telegram_bot._find_recent_investigation", new=AsyncMock(return_value=None)):
        with patch("app.bot.telegram_bot._start_investigation", new=AsyncMock()) as mock_start:
            await bot.investigar(update, context)

    mock_start.assert_not_called()
    assert "limite" in update.message.reply_text.call_args[0][0]


@pytest.mark.asyncio
async def test_estado_not_found(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    fake_response = _response(404, {"detail": "not found"})
    patcher, _ = _patch_client(fake_response)
    update, context = _make_update(args=["missing-id"])

    with patcher:
        await bot.estado(update, context)

    msg = update.message.reply_text.call_args[0][0]
    assert "No encontre" in msg


@pytest.mark.asyncio
async def test_reporte_without_args_shows_usage(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    update, context = _make_update(args=[])

    await bot.reporte(update, context)

    msg = update.message.reply_text.call_args[0][0]
    assert "Uso:" in msg


@pytest.mark.asyncio
async def test_reporte_happy_path(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    fake_response = _response(200, {"investigation_id": "inv-1", "content": "# Reporte completo\nDetalle."})
    patcher, _ = _patch_client(fake_response)
    update, context = _make_update(args=["inv-1"])

    with patcher:
        await bot.reporte(update, context)

    msg = update.message.reply_text.call_args[0][0]
    assert "# Reporte completo" in msg
    assert "Detalle." in msg


@pytest.mark.asyncio
async def test_reporte_not_found(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    fake_response = _response(404, {"detail": "not found"})
    patcher, _ = _patch_client(fake_response)
    update, context = _make_update(args=["missing-id"])

    with patcher:
        await bot.reporte(update, context)

    msg = update.message.reply_text.call_args[0][0]
    assert "Todavia no hay reporte" in msg


@pytest.mark.asyncio
async def test_metricas_happy_path(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    fake_response = _response(200, {
        "total_investigations": 12, "completed": 10, "failed": 2,
        "malicious_found": 3, "avg_execution_time_seconds": 45.2,
        "total_tokens_used": 98765,
    })
    patcher, _ = _patch_client(fake_response)
    update, context = _make_update()

    with patcher:
        await bot.metricas(update, context)

    msg = update.message.reply_text.call_args[0][0]
    assert "Investigaciones totales: 12" in msg
    assert "Maliciosas encontradas: 3" in msg


@pytest.mark.asyncio
async def test_on_direct_message_ignores_blocked_chat(monkeypatch):
    monkeypatch.setattr(bot.settings, "TELEGRAM_ALLOWLIST", "111")
    update, context = _make_update(text="1.2.3.4", chat_id=999)

    await bot.on_direct_message(update, context)

    update.message.reply_text.assert_called_once()
    assert "privado" in update.message.reply_text.call_args[0][0]


# ---------- _format_progress ----------

def test_format_progress_no_agents_yet():
    msg = bot._format_progress("1.2.3.4", "inv-1", {})
    assert "1.2.3.4" in msg
    assert "inv-1" in msg
    assert "Esperando resultados" in msg


def test_format_progress_with_mixed_agent_status():
    msg = bot._format_progress("1.2.3.4", "inv-1", {"recon": "success", "osint": "error"})
    assert "[OK] recon" in msg
    assert "[ERROR] osint" in msg


# ---------- _watch_investigation ----------

def _update_with_editable_message():
    status_message = MagicMock()
    status_message.edit_text = AsyncMock()
    update = MagicMock()
    update.message.reply_text = AsyncMock(return_value=status_message)
    return update, status_message


@pytest.mark.asyncio
async def test_watch_investigation_happy_path():
    messages = [
        json.dumps({"event": "agent_completed", "agent": "recon", "agent_status": "success"}),
        json.dumps({"event": "agent_completed", "agent": "osint", "agent_status": "error"}),
        json.dumps({
            "event": "investigation_finished", "investigation_id": "inv-1",
            "status": "completed", "verdict": "malicious", "severity": "high",
            "severity_score": 8.5,
        }),
    ]
    final_inv = {
        "id": "inv-1", "status": "completed", "ioc_value": "1.2.3.4",
        "verdict": "malicious", "severity": "high", "severity_score": 8.5,
        "summary": "IP asociada a botnet.",
    }
    update, status_message = _update_with_editable_message()

    with _patch_ws(messages):
        with patch("app.bot.telegram_bot._fetch_investigation", new=AsyncMock(return_value=final_inv)):
            await bot._watch_investigation(update, "inv-1", "1.2.3.4")

    update.message.reply_text.assert_called_once()
    assert status_message.edit_text.call_count == 3
    last_edit = status_message.edit_text.call_args[0][0]
    assert "MALICIOUS" in last_edit
    assert "8.5/10" in last_edit
    assert "botnet" in last_edit


@pytest.mark.asyncio
async def test_watch_investigation_not_found_on_server():
    messages = [json.dumps({"investigation_id": "inv-missing", "error": "investigation not found"})]
    update, status_message = _update_with_editable_message()

    with _patch_ws(messages):
        with patch("app.bot.telegram_bot._fetch_investigation", new=AsyncMock()) as mock_fetch:
            await bot._watch_investigation(update, "inv-missing", "1.2.3.4")

    mock_fetch.assert_not_called()
    last_edit = status_message.edit_text.call_args[0][0]
    assert "No encontre la investigacion inv-missing" in last_edit


@pytest.mark.asyncio
async def test_watch_investigation_connection_error_falls_back_to_estado():
    update, status_message = _update_with_editable_message()

    with patch("app.bot.telegram_bot.websockets.connect", side_effect=OSError("connection refused")):
        await bot._watch_investigation(update, "inv-1", "1.2.3.4")

    last_edit = status_message.edit_text.call_args[0][0]
    assert "Se corto la conexion en vivo" in last_edit
    assert "/estado inv-1" in last_edit


@pytest.mark.asyncio
async def test_watch_investigation_skips_duplicate_edits():
    messages = [
        json.dumps({"event": "agent_completed", "agent": "recon", "agent_status": "success"}),
        json.dumps({"event": "agent_completed", "agent": "recon", "agent_status": "success"}),
        json.dumps({"event": "investigation_finished", "status": "failed"}),
    ]
    update, status_message = _update_with_editable_message()

    with _patch_ws(messages):
        with patch(
            "app.bot.telegram_bot._fetch_investigation",
            new=AsyncMock(return_value={"id": "inv-1", "status": "failed"}),
        ):
            await bot._watch_investigation(update, "inv-1", "1.2.3.4")

    # Two identical agent_completed events -> only one edit_text call for
    # that state, plus the final "failed" edit = 2 total, not 3.
    assert status_message.edit_text.call_count == 2
