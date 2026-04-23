import asyncio
import time
import uuid
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.investigation import Investigation
from app.chains.ioc_classifier import IocClassifier
from app.agents.coordinator import Coordinator

logger = logging.getLogger(__name__)
classifier = IocClassifier()


async def run_investigation(
    ioc_value: str,
    ioc_type: str | None,
    db: AsyncSession,
    redis_client=None,
) -> Investigation:
    resolved_type = ioc_type or classifier.classify(ioc_value)["type"]

    investigation = Investigation(
        ioc_value=ioc_value,
        ioc_type=resolved_type,
        status="running",
    )
    db.add(investigation)
    await db.commit()
    await db.refresh(investigation)

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
    except Exception as e:
        logger.error("Investigation %s failed: %s", investigation.id, e)
        # Roll back any partial writes from the coordinator/agents before
        # writing the final "failed" status, so the session is clean.
        await db.rollback()
        investigation.status = "failed"
        investigation.execution_time_seconds = round(time.monotonic() - start, 2)

    await db.commit()
    await db.refresh(investigation)
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
