import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import httpx
import websockets
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from app.chains.ioc_classifier import IocClassifier
from app.config import settings

logger = logging.getLogger(__name__)

# THREATCHAIN_API_BASE/THREATCHAIN_WS_BASE follow the same override pattern
# as ui/api_utils.py: override in docker-compose to reach the "api" service
# by hostname instead of localhost.
API_BASE = os.getenv("THREATCHAIN_API_BASE", "http://localhost:8000/api/v1")
WS_BASE = os.getenv("THREATCHAIN_WS_BASE", "ws://localhost:8000/ws")
MESSAGE_LIMIT = 4096
WS_TIMEOUT_SECONDS = 180

# The 17 external APIs already have their own daily rate limit (RateLimiter
# + api_configs, reset by the APScheduler job in app/main.py). This is a
# separate, per-Telegram-user cap so one allowlisted user can't loop
# /investigar and burn through everyone else's shared quota.
TELEGRAM_RATE_LIMIT_PER_DAY = int(os.getenv("TELEGRAM_RATE_LIMIT_PER_DAY", "20"))
# Window to treat a just-started investigation of the same IOC as "still in
# flight" instead of kicking off a duplicate pipeline run.
DEDUP_WINDOW_SECONDS = 600

_classifier = IocClassifier()

# Strong references to fire-and-forget progress-watch tasks: asyncio only
# holds a weak reference to a task once nothing else refers to it, so an
# unreferenced task can be garbage-collected mid-run. Entries remove
# themselves via add_done_callback once the watch finishes.
_background_tasks: set[asyncio.Task] = set()

# In-memory per-chat daily counters. The bot runs as a single process (no
# horizontal scaling planned), so this doesn't need Redis/Postgres like the
# per-API RateLimiter does; it just resets if the bot restarts, which is an
# acceptable tradeoff for a small allowlist.
_user_request_log: dict[int, list[float]] = {}


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


def _check_user_rate_limit(chat_id: int) -> bool:
    now = time.monotonic()
    window_start = now - 86400
    log = _user_request_log.setdefault(chat_id, [])
    log[:] = [t for t in log if t > window_start]
    if len(log) >= TELEGRAM_RATE_LIMIT_PER_DAY:
        return False
    log.append(now)
    return True


def _headers() -> dict:
    return {"X-API-Key": settings.API_KEY} if settings.API_KEY else {}


def is_allowed(chat_id: int) -> bool:
    return chat_id in settings.telegram_allowlist_ids


def require_allowlist(handler):
    @wraps(handler)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id if update.effective_chat else None
        if chat_id is None or not is_allowed(chat_id):
            logger.warning("Blocked message from chat_id=%s (not in allowlist)", chat_id)
            if update.message:
                await update.message.reply_text("Este bot es privado. No tenes acceso.")
            return
        await handler(update, context)
    return wrapper


def split_message(text: str, limit: int = MESSAGE_LIMIT) -> list[str]:
    if len(text) <= limit:
        return [text]
    chunks = []
    remaining = text
    while len(remaining) > limit:
        cut = remaining.rfind("\n", 0, limit)
        if cut <= 0:
            cut = limit
        chunks.append(remaining[:cut])
        remaining = remaining[cut:].lstrip("\n")
    if remaining:
        chunks.append(remaining)
    return chunks


async def _send(update: Update, text: str) -> None:
    for chunk in split_message(text):
        await update.message.reply_text(chunk)


async def _start_investigation(ioc_value: str) -> dict:
    ioc_type = _classifier.classify(ioc_value)["type"]
    if ioc_type == "unknown":
        return {"error": f"No pude clasificar '{ioc_value}' como IOC valido (ip/domain/hash/url/cve)."}
    async with httpx.AsyncClient(base_url=API_BASE, timeout=30.0) as client:
        resp = await client.post(
            "/investigate",
            json={"ioc_value": ioc_value, "ioc_type": ioc_type, "wait": False},
            headers=_headers(),
        )
        resp.raise_for_status()
        return resp.json()


async def _fetch_investigation(investigation_id: str) -> dict:
    async with httpx.AsyncClient(base_url=API_BASE, timeout=30.0) as client:
        resp = await client.get(f"/investigations/{investigation_id}", headers=_headers())
        resp.raise_for_status()
        return resp.json()


async def _fetch_report(investigation_id: str) -> dict:
    async with httpx.AsyncClient(base_url=API_BASE, timeout=30.0) as client:
        resp = await client.get(f"/investigations/{investigation_id}/report", headers=_headers())
        resp.raise_for_status()
        return resp.json()


async def _fetch_stats() -> dict:
    async with httpx.AsyncClient(base_url=API_BASE, timeout=30.0) as client:
        resp = await client.get("/stats", headers=_headers())
        resp.raise_for_status()
        return resp.json()


async def _find_recent_investigation(ioc_value: str) -> dict | None:
    """Look for an in-flight or just-finished investigation of this exact
    IOC so a burst of /investigar (or several users) doesn't fan out into
    duplicate agent pipeline runs for the same target.
    """
    async with httpx.AsyncClient(base_url=API_BASE, timeout=30.0) as client:
        resp = await client.get(
            "/investigations", params={"ioc_value": ioc_value, "limit": 1}, headers=_headers()
        )
        resp.raise_for_status()
        rows = resp.json()

    if not rows:
        return None
    inv = rows[0]
    if inv.get("status") not in ("pending", "running", "completed"):
        return None

    created_at = inv.get("created_at")
    if not created_at:
        return None
    try:
        created = datetime.fromisoformat(created_at)
    except ValueError:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - created
    if age > timedelta(seconds=DEDUP_WINDOW_SECONDS):
        return None
    return inv


def format_investigation(inv: dict) -> str:
    status = inv.get("status", "unknown")
    inv_id = inv.get("id", "?")

    if status in ("pending", "running"):
        return f"Investigacion {inv_id}: {status}. Todavia no termino, proba de nuevo en unos segundos con /estado {inv_id}"
    if status == "failed":
        return f"Investigacion {inv_id}: fallo durante la ejecucion."
    if status == "cancelled":
        return f"Investigacion {inv_id}: cancelada."

    verdict = (inv.get("verdict") or "desconocido").upper()
    severity = inv.get("severity") or "desconocida"
    score = inv.get("severity_score")
    score_txt = f"{score}/10" if score is not None else "N/D"
    summary = inv.get("summary") or "Sin resumen disponible."

    return "\n".join([
        f"Investigacion completada: {inv.get('ioc_value')}",
        f"Veredicto: {verdict}",
        f"Severidad: {severity} ({score_txt})",
        "",
        summary,
        "",
        f"Reporte completo: /reporte {inv_id}",
    ])


def _format_progress(ioc_value: str, inv_id: str, agent_status: dict) -> str:
    lines = [f"Investigando {ioc_value}", f"ID: {inv_id}", ""]
    if not agent_status:
        lines.append("Esperando resultados de los agentes...")
    else:
        for agent, status in agent_status.items():
            mark = {"success": "OK", "error": "ERROR"}.get(status, "...")
            lines.append(f"[{mark}] {agent}")
    return "\n".join(lines)


async def _watch_investigation(update: Update, inv_id: str, ioc_value: str) -> None:
    """Follow /ws/investigation/{id} and edit one message in place as agents
    finish, falling back to a static "check /estado" message on any
    disconnect/timeout/error rather than leaving the user without feedback.
    """
    status_message = await update.message.reply_text(_format_progress(ioc_value, inv_id, {}))
    agent_status: dict = {}
    last_text = [None]

    async def _edit(text: str) -> None:
        if text == last_text[0]:
            return
        last_text[0] = text
        try:
            await status_message.edit_text(text)
        except Exception as e:
            logger.warning("Could not edit progress message for %s: %s", inv_id, e)

    ws_url = f"{WS_BASE}/investigation/{inv_id}"
    start = time.monotonic()
    try:
        async with websockets.connect(ws_url, ping_interval=None) as ws:
            while True:
                remaining = WS_TIMEOUT_SECONDS - (time.monotonic() - start)
                if remaining <= 0:
                    await _edit(
                        _format_progress(ioc_value, inv_id, agent_status)
                        + f"\n\nSe agoto el tiempo de espera. Consulta /estado {inv_id}"
                    )
                    return
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=min(remaining, 15))
                except asyncio.TimeoutError:
                    continue
                event = json.loads(raw)

                if event.get("error"):
                    await _edit(f"No encontre la investigacion {inv_id} en el servidor.")
                    return
                if event.get("event") == "agent_completed":
                    agent_status[event.get("agent", "?")] = event.get("agent_status", "?")
                    await _edit(_format_progress(ioc_value, inv_id, agent_status))
                elif event.get("status") in ("completed", "failed", "cancelled"):
                    break
    except Exception as e:
        logger.warning("Progress WebSocket failed for %s: %s", inv_id, e)
        await _edit(
            _format_progress(ioc_value, inv_id, agent_status)
            + f"\n\nSe corto la conexion en vivo. Consulta /estado {inv_id}"
        )
        return

    try:
        inv = await _fetch_investigation(inv_id)
        await _edit(format_investigation(inv))
    except httpx.HTTPError as e:
        logger.warning("Could not fetch final result for %s: %s", inv_id, e)
        await _edit(f"Investigacion {inv_id} termino. Consulta /estado {inv_id} para el detalle.")


async def _handle_ioc(update: Update, ioc_value: str) -> None:
    try:
        existing = await _find_recent_investigation(ioc_value)
    except httpx.HTTPError as e:
        logger.warning("Dedup lookup failed for %s: %s", ioc_value, e)
        existing = None

    if existing:
        inv_id = existing["id"]
        if existing["status"] in ("pending", "running"):
            await _send(update, f"Ya hay una investigacion reciente de {ioc_value} en curso (ID: {inv_id}). Sigo esa en vez de arrancar otra.")
            _spawn(_watch_investigation(update, inv_id, ioc_value))
        else:
            await _send(update, f"Ya investigue {ioc_value} hace poco (ID: {inv_id}). Te muestro ese resultado:")
            await _send(update, format_investigation(existing))
        return

    chat_id = update.effective_chat.id if update.effective_chat else None
    if chat_id is not None and not _check_user_rate_limit(chat_id):
        await _send(update, f"Llegaste al limite de {TELEGRAM_RATE_LIMIT_PER_DAY} investigaciones por dia. Proba de nuevo mas tarde.")
        return

    try:
        result = await _start_investigation(ioc_value)
    except httpx.HTTPStatusError as e:
        await _send(update, f"Error al iniciar la investigacion ({e.response.status_code}): {e.response.text[:200]}")
        return
    except httpx.HTTPError as e:
        await _send(update, f"No pude conectar con la API de ThreatChain: {e}")
        return

    if "error" in result:
        await _send(update, result["error"])
        return

    inv_id = result.get("id")
    _spawn(_watch_investigation(update, inv_id, ioc_value))


@require_allowlist
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _send(update, (
        "ThreatChain Bot\n\n"
        "Investigo IOCs (IP, dominio, hash, URL, CVE) usando 7 agentes "
        "y 17+ fuentes de threat intel.\n\n"
        "Comandos:\n"
        "/investigar <IOC> - inicia una investigacion\n"
        "/estado <id> - consulta el progreso de una investigacion\n"
        "/reporte <id> - reporte completo en markdown\n"
        "/metricas - estadisticas globales del sistema\n"
        "/ayuda - ejemplos de uso\n\n"
        "Tambien podes mandar un IOC directo sin comando."
    ))


@require_allowlist
async def ayuda(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _send(update, (
        "Ejemplos:\n"
        "/investigar 185.220.101.34\n"
        "/investigar evil-domain.com\n"
        "/investigar CVE-2024-3400\n"
        "/estado 3fa85f64-5717-4562-b3fc-2c963f66afa6\n"
        "/reporte 3fa85f64-5717-4562-b3fc-2c963f66afa6\n\n"
        "Tipos de IOC soportados: ip, domain, hash, url, email, cve."
    ))


@require_allowlist
async def investigar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await _send(update, "Uso: /investigar <IOC>\nEjemplo: /investigar 185.220.101.34")
        return
    ioc_value = " ".join(context.args).strip()
    await _handle_ioc(update, ioc_value)


@require_allowlist
async def estado(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await _send(update, "Uso: /estado <investigation_id>")
        return
    investigation_id = context.args[0].strip()
    try:
        inv = await _fetch_investigation(investigation_id)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            await _send(update, f"No encontre ninguna investigacion con id {investigation_id}")
        else:
            await _send(update, f"Error consultando el estado ({e.response.status_code})")
        return
    except httpx.HTTPError as e:
        await _send(update, f"No pude conectar con la API de ThreatChain: {e}")
        return
    await _send(update, format_investigation(inv))


@require_allowlist
async def reporte(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await _send(update, "Uso: /reporte <investigation_id>")
        return
    investigation_id = context.args[0].strip()
    try:
        report = await _fetch_report(investigation_id)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            await _send(update, f"Todavia no hay reporte para {investigation_id}. Si la investigacion ya termino, proba /estado {investigation_id} primero.")
        else:
            await _send(update, f"Error consultando el reporte ({e.response.status_code})")
        return
    except httpx.HTTPError as e:
        await _send(update, f"No pude conectar con la API de ThreatChain: {e}")
        return
    await _send(update, report.get("content") or "El reporte esta vacio.")


@require_allowlist
async def metricas(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        stats = await _fetch_stats()
    except httpx.HTTPError as e:
        await _send(update, f"No pude conectar con la API de ThreatChain: {e}")
        return
    await _send(update, "\n".join([
        "Metricas de ThreatChain",
        "",
        f"Investigaciones totales: {stats.get('total_investigations', 0)}",
        f"Completadas: {stats.get('completed', 0)}",
        f"Fallidas: {stats.get('failed', 0)}",
        f"Maliciosas encontradas: {stats.get('malicious_found', 0)}",
        f"Tiempo promedio: {stats.get('avg_execution_time_seconds', 0)}s",
        f"Tokens LLM usados: {stats.get('total_tokens_used', 0)}",
    ]))


@require_allowlist
async def on_direct_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ioc_value = (update.message.text or "").strip()
    if not ioc_value:
        return
    await _handle_ioc(update, ioc_value)


def build_application() -> Application:
    if not settings.TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN no esta configurado en .env")
    if not settings.telegram_allowlist_ids:
        logger.warning("TELEGRAM_ALLOWLIST esta vacia - nadie va a poder usar el bot")

    application = Application.builder().token(settings.TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("ayuda", ayuda))
    application.add_handler(CommandHandler("help", ayuda))
    application.add_handler(CommandHandler("investigar", investigar))
    application.add_handler(CommandHandler("estado", estado))
    application.add_handler(CommandHandler("reporte", reporte))
    application.add_handler(CommandHandler("metricas", metricas))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_direct_message))
    return application


def main() -> None:
    logging.basicConfig(level=settings.LOG_LEVEL)
    application = build_application()
    logger.info("ThreatChain Telegram bot starting (polling mode)")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
