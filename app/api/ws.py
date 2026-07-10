import asyncio
import json
import uuid
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.investigation import Investigation
from app.services import progress

logger = logging.getLogger(__name__)
router = APIRouter()

# Poll fallback interval: covers events lost because the publisher runs in
# another worker process (the progress bus is in-process only).
_POLL_FALLBACK_SECONDS = 10


async def _snapshot(inv_uuid: uuid.UUID) -> dict | None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Investigation).where(Investigation.id == inv_uuid)
        )
        inv = result.scalar_one_or_none()
        if inv is None:
            return None
        return {
            "event": "snapshot",
            "investigation_id": str(inv.id),
            "status": inv.status,
            "verdict": inv.verdict,
            "severity": inv.severity,
            "severity_score": float(inv.severity_score) if inv.severity_score is not None else None,
        }


def _is_terminal(message: dict) -> bool:
    return message.get("status") in ("completed", "failed", "cancelled")


@router.websocket("/ws/investigation/{investigation_id}")
async def investigation_ws(websocket: WebSocket, investigation_id: str):
    # Validate UUID before accepting the connection
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    snapshot = await _snapshot(inv_uuid)
    if snapshot is None:
        await websocket.send_text(json.dumps({
            "investigation_id": investigation_id,
            "error": "investigation not found",
        }))
        await websocket.close()
        return

    await websocket.send_text(json.dumps(snapshot))
    if _is_terminal(snapshot):
        await websocket.close()
        return

    queue = progress.subscribe(investigation_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=_POLL_FALLBACK_SECONDS)
            except asyncio.TimeoutError:
                event = await _snapshot(inv_uuid)
                if event is None:
                    break
            await websocket.send_text(json.dumps(event))
            if _is_terminal(event):
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error for %s: %s", investigation_id, e)
    finally:
        progress.unsubscribe(investigation_id, queue)
