import pytest
from app.services.rate_limiter import RateLimiter
from app.models.config import ApiConfig


@pytest.mark.asyncio
async def test_check_increments_counter(db_session):
    api = ApiConfig(
        api_name="test_api",
        base_url="https://test.example.com",
        rate_limit_per_day=100,
        rate_limit_per_minute=10,
        requests_today=0,
        is_active=True,
    )
    db_session.add(api)
    await db_session.commit()

    limiter = RateLimiter(db_session)
    allowed = await limiter.check_and_increment("test_api")
    assert allowed is True

    from sqlalchemy import select
    result = await db_session.execute(select(ApiConfig).where(ApiConfig.api_name == "test_api"))
    updated = result.scalar_one()
    assert updated.requests_today == 1


@pytest.mark.asyncio
async def test_blocks_when_limit_reached(db_session):
    api = ApiConfig(
        api_name="limited_api",
        base_url="https://test.example.com",
        rate_limit_per_day=5,
        rate_limit_per_minute=1,
        requests_today=5,
        is_active=True,
    )
    db_session.add(api)
    await db_session.commit()

    limiter = RateLimiter(db_session)
    allowed = await limiter.check_and_increment("limited_api")
    assert allowed is False


@pytest.mark.asyncio
async def test_unknown_api_allowed(db_session):
    limiter = RateLimiter(db_session)
    allowed = await limiter.check_and_increment("nonexistent_api")
    assert allowed is True


@pytest.mark.asyncio
async def test_disabled_api_blocked(db_session):
    api = ApiConfig(
        api_name="disabled_api",
        base_url="https://test.example.com",
        rate_limit_per_day=100,
        rate_limit_per_minute=10,
        requests_today=0,
        is_active=False,
    )
    db_session.add(api)
    await db_session.commit()

    limiter = RateLimiter(db_session)
    allowed = await limiter.check_and_increment("disabled_api")
    assert allowed is False
