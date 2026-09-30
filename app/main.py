import sys
import asyncio

# psycopg async cannot run on the ProactorEventLoop, and uvicorn >= 0.34
# hardcodes ProactorEventLoop on Windows (its loop_factory ignores the
# asyncio policy). Launch the API with `python -m app.main`, which drives
# the server through asyncio.run() under this Selector policy; running
# `python -m uvicorn app.main:app` on Windows breaks every DB call.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import AsyncSessionLocal
from app.services.rate_limiter import RateLimiter
from app.api.investigations import router as investigations_router
from app.api.health import router as health_router
from app.api.reports import router as reports_router
from app.api.ws import router as ws_router

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def _reset_rate_limits() -> None:
    async with AsyncSessionLocal() as db:
        limiter = RateLimiter(db)
        n = await limiter.reset_daily_counters()
    logger.info("Daily rate limit reset: %d api_configs rows reset", n)


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(
        _reset_rate_limits,
        trigger=CronTrigger(hour=0, minute=0, timezone="UTC"),
        id="reset_rate_limits",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    scheduler.start()

    # Durable AgentGate audit log: every PDP decision is also written to PostgreSQL.
    from agentgate.audit import get_default_audit_service
    audit_service = get_default_audit_service()
    audit_service.configure(AsyncSessionLocal, project="threatchain")

    # Persistent AgentGate approval queue in Redis (falls back to memory if Redis is unavailable)
    from agentgate.hitl import get_default_approval_queue
    from app.services.cache_service import get_redis_client
    approval_queue = get_default_approval_queue()
    approval_queue.configure(get_redis_client())

    yield
    scheduler.shutdown(wait=False)
    try:
        await audit_service.flush()
    except Exception as e:
        logger.warning("Error flushing AgentGate audit log: %s", e)
    # Graceful connection pool shutdown
    try:
        from app.database import engine
        await engine.dispose()
    except Exception as e:
        logger.warning("Error disposing database engine: %s", e)
    try:
        from app.services.cache_service import _redis_client
        if _redis_client is not None:
            _redis_client.close()
    except Exception as e:
        logger.warning("Error closing redis client: %s", e)
    try:
        from app.tools.base_tool import close_shared_client
        await close_shared_client()
    except Exception as e:
        logger.warning("Error closing shared HTTP client: %s", e)


app = FastAPI(title="ThreatChain", version="0.2.0", lifespan=lifespan)

# Rate Limiter setup
try:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from app.limiter import limiter

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
except Exception as e:
    logger.warning("SlowAPI rate limiter not initialized: %s", e)


from fastapi import Request
from fastapi.responses import JSONResponse


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception at %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected internal server error occurred."}
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(health_router)
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(ws_router)

from agentgate.dashboard import agentgate_router
app.include_router(agentgate_router, prefix="/agentgate", tags=["AgentGate"])


if __name__ == "__main__":
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=8000))
    asyncio.run(server.serve())
