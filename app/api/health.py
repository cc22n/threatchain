import os
import logging
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.config import settings
from app.database import get_db
from app.services.rate_limiter import RateLimiter
from app.services.investigation_service import get_stats
from app.services.cache_service import get_redis_client
from app.api.auth import require_api_key
# Reuse the already-cached config loader instead of re-reading the file
from app.llm.providers import _load_config as _load_ai_config

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/health")
async def health_check():
    """Liveness probe: verifies process is up."""
    return {"status": "ok", "env": settings.APP_ENV, "version": "0.2.0"}


@router.get("/health/ready")
async def readiness_check(response: Response, db: AsyncSession = Depends(get_db)):
    """Readiness probe: verifies database and redis connectivity."""
    db_ok = False
    redis_ok = False

    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        logger.warning("Readiness probe DB check failed: %s", e)

    try:
        redis = get_redis_client()
        if redis is not None and redis.ping():
            redis_ok = True
        elif not getattr(settings, "REDIS_URL", None):
            redis_ok = True
    except Exception as e:
        logger.warning("Readiness probe Redis check failed: %s", e)

    is_ready = db_ok and redis_ok
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "unhealthy",
        "database": "healthy" if db_ok else "unhealthy",
        "redis": "healthy" if redis_ok else "unhealthy",
    }


@router.get("/health/apis", dependencies=[Depends(require_api_key)])
async def api_health(db: AsyncSession = Depends(get_db)):
    limiter = RateLimiter(db)
    statuses = await limiter.get_all_status()
    return {"apis": statuses, "total": len(statuses)}


@router.get("/health/llms", dependencies=[Depends(require_api_key)])
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


@router.get("/stats", dependencies=[Depends(require_api_key)])
async def global_stats(db: AsyncSession = Depends(get_db)):
    return await get_stats(db)
