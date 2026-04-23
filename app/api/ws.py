import asyncio
import json
import uuid
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.investigation import Investigation

logger = logging.getLogger(__name__)
router = APIRouter()

_connections: dict[str, list[WebSocket]] = {}


async def broadcast(investigation_id: str, message: dict) -> None:
    sockets = _connections.get(investigation_id, [])
    dead = []
    for ws in sockets:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        sockets.remove(ws)


@router.websocket("/ws/investigation/{investigation_id}")
async def investigation_ws(websocket: WebSocket, investigation_id: str):
    # Validate UUID before accepting the connection
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    _connections.setdefault(investigation_id, []).append(websocket)
    try:
        while True:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    # Use the typed uuid.UUID so the column comparison works correctly
                    select(Investigation).where(Investigation.id == inv_uuid)
                )
                inv = result.scalar_one_or_none()
                if inv:
                    await websocket.send_text(json.dumps({
                        "investigation_id": investigation_id,
                        "status": inv.status,
                        "verdict": inv.verdict,
                        "severity": inv.severity,
                        "severity_score": float(inv.severity_score) if inv.severity_score else None,
                    }))
                    if inv.status in ("completed", "failed"):
                        break
                else:
                    await websocket.send_text(json.dumps({
                        "investigation_id": investigation_id,
                        "error": "investigation not found",
                    }))
                    break
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error for %s: %s", investigation_id, e)
    finally:
        sockets = _connections.get(investigation_id, [])
        if websocket in sockets:
            sockets.remove(websocket)
