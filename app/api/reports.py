import uuid
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.report import Report
from app.models.investigation import Investigation
from app.models.mitre_mapping import MitreMapping
from app.agents.report_agent import ReportAgent
from app.services.export_service import export_pdf, export_stix, export_markdown
from app.api.auth import require_api_key

router = APIRouter()


async def _get_investigation(investigation_id: str, db: AsyncSession) -> Investigation:
    try:
        uid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid UUID")
    result = await db.execute(select(Investigation).where(Investigation.id == uid))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


async def _get_report(investigation_id: uuid.UUID, db: AsyncSession) -> Report | None:
    result = await db.execute(
        select(Report).where(
            Report.investigation_id == investigation_id,
            Report.report_format == "markdown",
        ).order_by(Report.generated_at.desc())
    )
    return result.scalar_one_or_none()


@router.get("/investigations/{investigation_id}/report")
async def get_report(investigation_id: str, db: AsyncSession = Depends(get_db)):
    inv = await _get_investigation(investigation_id, db)
    report = await _get_report(inv.id, db)
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated yet. Call POST /report/regenerate first.")
    return {
        "investigation_id": investigation_id,
        "format": report.report_format,
        "content": report.content,
        "llm_model": report.llm_model,
        "generated_at": report.generated_at.isoformat(),
    }


@router.post("/investigations/{investigation_id}/report/regenerate", status_code=202,
             dependencies=[Depends(require_api_key)])
async def regenerate_report(
    investigation_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    inv = await _get_investigation(investigation_id, db)
    if inv.status != "completed":
        raise HTTPException(status_code=422, detail="Investigation must be completed before generating report")

    async def _gen():
        from app.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            agent = ReportAgent(db=session)
            await agent.run(inv.ioc_value, inv.ioc_type, inv.id)

    background_tasks.add_task(_gen)
    return {"message": "Report generation started", "investigation_id": investigation_id}


@router.get("/investigations/{investigation_id}/report/download")
async def download_report(
    investigation_id: str,
    format: str = "md",
    db: AsyncSession = Depends(get_db),
):
    inv = await _get_investigation(investigation_id, db)
    report = await _get_report(inv.id, db)
    if not report:
        raise HTTPException(status_code=404, detail="No report found. Call POST /report/regenerate first.")

    mitre_result = await db.execute(
        select(MitreMapping).where(MitreMapping.investigation_id == inv.id)
    )
    mitre_techniques = [
        {"technique_id": m.technique_id, "technique_name": m.technique_name,
         "tactic": m.tactic, "confidence": m.confidence, "evidence": m.evidence or ""}
        for m in mitre_result.scalars().all()
    ]

    if format == "md":
        content = export_markdown(report.content)
        return Response(content=content, media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="report_{investigation_id[:8]}.md"'})

    if format == "pdf":
        content = export_pdf(report.content, inv.ioc_value)
        return Response(content=content, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="report_{investigation_id[:8]}.pdf"'})

    if format == "stix":
        content = export_stix(
            ioc_value=inv.ioc_value,
            ioc_type=inv.ioc_type,
            investigation_id=investigation_id,
            verdict=inv.verdict or "unknown",
            mitre_techniques=mitre_techniques,
            related_iocs=[],
        )
        return Response(content=content, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="report_{investigation_id[:8]}.stix.json"'})

    raise HTTPException(status_code=422, detail="Invalid format. Use: md, pdf, stix")
