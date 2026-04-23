import os
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.database import get_db
from app.services.rate_limiter import RateLimiter
from app.services.investigation_service import get_stats
# Reuse the already-cached config loader instead of re-reading the file
from app.llm.providers import _load_config as _load_ai_config

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok", "env": settings.APP_ENV, "version": "0.2.0"}


@router.get("/health/apis")
async def api_health(db: AsyncSession = Depends(get_db)):
    limiter = RateLimiter(db)
    statuses = await limiter.get_all_status()
    return {"apis": statuses, "total": len(statuses)}


@router.get("/health/llms")
async def llm_health():
    ai_cfg = _load_ai_config()
    providers = []
    for provider_name, provider_cfg in ai_cfg.get("providers", {}).items():
        key_env = provider_cfg.get("api_key_env", "")
        has_key = bool(os.environ.get(key_env, "")) if key_env else True
        providers.append({
            "provider": provider_name,
            "configured": has_key,
            "models": list(provider_cfg.get("models", {}).keys()),
        })
    return {"providers": providers}


@router.get("/stats")
async def global_stats(db: AsyncSession = Depends(get_db)):
    return await get_stats(db)
