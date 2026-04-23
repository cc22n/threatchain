import json
import pytest
import pytest_asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.database import Base


FIXTURES = Path(__file__).parent / "fixtures"

pytest_plugins = ["pytest_asyncio"]


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    redis.get.return_value = None
    redis.setex.return_value = True
    return redis


@pytest.fixture
def vt_response():
    with open(FIXTURES / "sample_vt_response.json") as f:
        return json.load(f)


@pytest.fixture
def abuseipdb_response():
    with open(FIXTURES / "sample_abuseipdb_response.json") as f:
        return json.load(f)


@pytest.fixture
def shodan_response():
    with open(FIXTURES / "sample_shodan_response.json") as f:
        return json.load(f)
