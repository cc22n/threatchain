import asyncio
import time
import uuid
import logging
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.investigation import Investigation
from app.models.agent_result import AgentResult
from app.chains.ioc_classifier import IocClassifier
from app.agents.coordinator import Coordinator
from app.services import progress

logger = logging.getLogger(__name__)
classifier = IocClassifier()


async def run_investigation(
    ioc_value: str,
    ioc_type: str | None,
    db: AsyncSession,
    redis_client=None,
    investigation_id: uuid.UUID | None = None,
) -> Investigation:
    """Run a full investigation.

    When investigation_id is given, an existing (pending) row is reused so
    callers can hand out the id before the run starts (async mode); the
    row is flipped to "running". Otherwise a new row is created.
    """
    resolved_type = ioc_type or classifier.classify(ioc_value)["type"]

    if investigation_id is not None:
        result = await db.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        investigation = result.scalar_one()
        investigation.status = "running"
    else:
        investigation = Investigation(
            ioc_value=ioc_value,
            ioc_type=resolved_type,
            status="running",
        )
        db.add(investigation)
    await db.commit()
    await db.refresh(investigation)

    progress.publish(str(investigation.id), {
        "event": "investigation_started",
        "investigation_id": str(investigation.id),
        "ioc_value": ioc_value,
        "ioc_type": resolved_type,
        "status": "running",
    })

    start = time.monotonic()
    try:
        coordinator = Coordinator(db=db, redis_client=redis_client)
        result = await coordinator.investigate(ioc_value, resolved_type, investigation.id)
        correlation = result.get("correlation", {})

        investigation.status = "completed"
        investigation.verdict = correlation.get("verdict", "unknown")
        investigation.severity = correlation.get("severity", "info")
        investigation.severity_score = correlation.get("severity_score")
        investigation.agents_used = correlation.get("agents_completed", [])
        investigation.execution_time_seconds = round(time.monotonic() - start, 2)

        totals = await db.execute(
            select(
                func.coalesce(func.sum(AgentResult.tokens_used), 0),
                func.coalesce(func.sum(AgentResult.api_calls_made), 0),
            ).where(AgentResult.investigation_id == investigation.id)
        )
        total_tokens, total_api_calls = totals.one()
        investigation.total_tokens_used = total_tokens
        investigation.total_api_calls = total_api_calls
        # Column is TIMESTAMP without time zone; store naive UTC.
        investigation.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    except Exception as e:
        logger.error("Investigation %s failed: %s", investigation.id, e)
        # Roll back any partial writes from the coordinator/agents so the
        # session is clean before writing the final "failed" status.
        # After rollback the in-memory `investigation` object is no longer
        # attached, so we re-fetch it by primary key before updating it.
        inv_id = investigation.id
        await db.rollback()
        result = await db.execute(select(Investigation).where(Investigation.id == inv_id))
        investigation = result.scalar_one()
        investigation.status = "failed"
        investigation.execution_time_seconds = round(time.monotonic() - start, 2)

    await db.commit()
    await db.refresh(investigation)

    progress.publish(str(investigation.id), {
        "event": "investigation_finished",
        "investigation_id": str(investigation.id),
        "status": investigation.status,
        "verdict": investigation.verdict,
        "severity": investigation.severity,
        "severity_score": float(investigation.severity_score) if investigation.severity_score is not None else None,
    })
    return investigation


async def run_batch(
    ioc_list: list[str],
    redis_client=None,
    max_concurrent: int = 3,
) -> list[Investigation]:
    """
    Each batch item gets its own DB session to avoid concurrent writes
    on a shared AsyncSession, which is not thread-safe.
    """
    from app.database import AsyncSessionLocal

    semaphore = asyncio.Semaphore(max_concurrent)

    async def _one(ioc_value: str) -> Investigation:
        async with semaphore:
            async with AsyncSessionLocal() as session:
                return await run_investigation(ioc_value, None, session, redis_client)

    results = await asyncio.gather(*[_one(ioc) for ioc in ioc_list], return_exceptions=True)
    investigations = []
    for r in results:
        if isinstance(r, Exception):
            logger.error("Batch item failed: %s", r)
        else:
            investigations.append(r)
    return investigations


async def get_stats(db: AsyncSession) -> dict:
    from sqlalchemy import func
    from app.models.agent_result import AgentResult

    inv_result = await db.execute(
        select(
            func.count(Investigation.id).label("total"),
            func.count(Investigation.id).filter(Investigation.status == "completed").label("completed"),
            func.count(Investigation.id).filter(Investigation.status == "failed").label("failed"),
            func.count(Investigation.id).filter(Investigation.verdict == "malicious").label("malicious"),
            func.avg(Investigation.execution_time_seconds).label("avg_time"),
        )
    )
    inv_row = inv_result.one()

    token_result = await db.execute(
        select(func.sum(AgentResult.tokens_used).label("total_tokens"))
    )
    token_row = token_result.one()

    return {
        "total_investigations": inv_row.total or 0,
        "completed": inv_row.completed or 0,
        "failed": inv_row.failed or 0,
        "malicious_found": inv_row.malicious or 0,
        "avg_execution_time_seconds": round(float(inv_row.avg_time or 0), 2),
        "total_tokens_used": token_row.total_tokens or 0,
    }
