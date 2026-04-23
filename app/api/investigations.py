import uuid
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.schemas.investigation import InvestigationCreate, InvestigationResponse
from app.models.investigation import Investigation
from app.models.agent_result import AgentResult
from app.models.mitre_mapping import MitreMapping
from app.models.ioc_relationship import IocRelationship
from app.services.investigation_service import run_investigation, run_batch
from app.services.cache_service import get_redis_client

from app.chains.ioc_classifier import IocClassifier
from app.api.auth import require_api_key

router = APIRouter()
_classifier = IocClassifier()


@router.post("/investigate", response_model=InvestigationResponse, status_code=201,
             dependencies=[Depends(require_api_key)])
async def start_investigation(payload: InvestigationCreate, db: AsyncSession = Depends(get_db)):
    ioc_type = payload.ioc_type or _classifier.classify(payload.ioc_value)["type"]
    if ioc_type == "unknown":
        raise HTTPException(status_code=422, detail="Could not classify IOC type")

    redis = get_redis_client()
    investigation = await run_investigation(payload.ioc_value, ioc_type, db, redis)
    return investigation


@router.post("/investigate/batch", status_code=202,
             dependencies=[Depends(require_api_key)])
async def start_batch(ioc_list: list[str], background_tasks: BackgroundTasks):
    if not ioc_list:
        raise HTTPException(status_code=422, detail="IOC list must not be empty")
    if len(ioc_list) > 20:
        raise HTTPException(status_code=422, detail="Batch limit is 20 IOCs")

    async def _run():
        redis = get_redis_client()
        await run_batch(ioc_list, redis)

    background_tasks.add_task(_run)
    return {"message": f"Batch of {len(ioc_list)} IOCs queued", "ioc_count": len(ioc_list)}


@router.get("/investigations", response_model=list[InvestigationResponse])
async def list_investigations(skip: int = 0, limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Investigation).order_by(Investigation.created_at.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(investigation_id: str, db: AsyncSession = Depends(get_db)):
    uid = _parse_uuid(investigation_id)
    return await _get_or_404(db, uid)


@router.get("/investigations/{investigation_id}/results")
async def get_agent_results(investigation_id: str, db: AsyncSession = Depends(get_db)):
    uid = _parse_uuid(investigation_id)
    await _get_or_404(db, uid)
    result = await db.execute(select(AgentResult).where(AgentResult.investigation_id == uid))
    return [
        {
            "agent_name": a.agent_name,
            "status": a.status,
            "findings": a.findings,
            "tokens_used": a.tokens_used,
            "api_calls_made": a.api_calls_made,
            "execution_time_ms": a.execution_time_ms,
            "errors": a.errors,
        }
        for a in result.scalars().all()
    ]


@router.get("/investigations/{investigation_id}/mitre")
async def get_mitre_mappings(investigation_id: str, db: AsyncSession = Depends(get_db)):
    uid = _parse_uuid(investigation_id)
    await _get_or_404(db, uid)
    result = await db.execute(select(MitreMapping).where(MitreMapping.investigation_id == uid))
    return [
        {"technique_id": m.technique_id, "technique_name": m.technique_name,
         "tactic": m.tactic, "confidence": m.confidence, "evidence": m.evidence}
        for m in result.scalars().all()
    ]


@router.get("/investigations/{investigation_id}/relationships")
async def get_ioc_relationships(investigation_id: str, db: AsyncSession = Depends(get_db)):
    uid = _parse_uuid(investigation_id)
    await _get_or_404(db, uid)
    result = await db.execute(select(IocRelationship).where(IocRelationship.investigation_id == uid))
    return [
        {"source_ioc": r.source_ioc, "source_type": r.source_type,
         "related_ioc": r.related_ioc, "related_type": r.related_type,
         "relationship": r.relationship, "source_api": r.source_api, "confidence": r.confidence}
        for r in result.scalars().all()
    ]


@router.delete("/investigations/{investigation_id}", status_code=204,
               dependencies=[Depends(require_api_key)])
async def delete_investigation(investigation_id: str, db: AsyncSession = Depends(get_db)):
    uid = _parse_uuid(investigation_id)
    inv = await _get_or_404(db, uid)
    # Soft-delete: mark as cancelled rather than removing the row.
    # Hard deletes cascade to agent_results, mitre_mappings, etc. which loses
    # audit history.  Use status="cancelled" to keep the record.
    inv.status = "cancelled"
    await db.commit()


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid UUID")


async def _get_or_404(db: AsyncSession, uid: uuid.UUID) -> Investigation:
    result = await db.execute(select(Investigation).where(Investigation.id == uid))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv
