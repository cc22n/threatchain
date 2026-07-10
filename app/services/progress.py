"""In-process progress event bus for investigation updates.

The WebSocket endpoint subscribes per investigation and receives events
pushed by the investigation service and the coordinator as agents finish,
instead of only polling the database.

Limitation: the registry lives in process memory, so events only reach
WebSocket clients connected to the same worker. Running multiple uvicorn
workers requires moving this to Redis pub/sub (Phase 4+); the WebSocket
endpoint keeps a polling fallback so clients on other workers still see
terminal states.
"""
import asyncio
import logging

logger = logging.getLogger(__name__)

_subscribers: dict[str, list[asyncio.Queue]] = {}


def subscribe(investigation_id: str) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(investigation_id, []).append(queue)
    return queue


def unsubscribe(investigation_id: str, queue: asyncio.Queue) -> None:
    queues = _subscribers.get(investigation_id, [])
    if queue in queues:
        queues.remove(queue)
    if not queues:
        _subscribers.pop(investigation_id, None)


def publish(investigation_id: str, event: dict) -> None:
    """Push an event to every subscriber of an investigation.

    Never raises: progress delivery must not break the pipeline.
    """
    for queue in list(_subscribers.get(investigation_id, [])):
        try:
            queue.put_nowait(event)
        except Exception as e:
            logger.warning("Progress publish failed for %s: %s", investigation_id, e)
