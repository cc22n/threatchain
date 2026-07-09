import sys
import asyncio

# psycopg async cannot run on the ProactorEventLoop, and uvicorn >= 0.34
# hardcodes ProactorEventLoop on Windows (its loop_factory ignores the
# asyncio policy). Launch the API with `python -m app.main`, which drives
# the server through asyncio.run() under this Selector policy; running
# `python -m uvicorn app.main:app` on Windows breaks every DB call.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.investigations import router as investigations_router
from app.api.health import router as health_router
from app.api.reports import router as reports_router
from app.api.ws import router as ws_router

app = FastAPI(title="ThreatChain", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(ws_router)


if __name__ == "__main__":
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=8000))
    asyncio.run(server.serve())
