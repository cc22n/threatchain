import logging
from datetime import date
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.models.config import ApiConfig

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_and_increment(self, api_name: str) -> bool:
        result = await self.db.execute(
            select(ApiConfig).where(ApiConfig.api_name == api_name)
        )
        config = result.scalar_one_or_none()
        if not config:
            return True

        if not config.is_active:
            logger.warning("API %s is disabled", api_name)
            return False

        if config.rate_limit_per_day > 0 and config.requests_today >= config.rate_limit_per_day:
            logger.warning("API %s daily rate limit reached (%d)", api_name, config.rate_limit_per_day)
            return False

        await self.db.execute(
            update(ApiConfig)
            .where(ApiConfig.api_name == api_name)
            .values(requests_today=ApiConfig.requests_today + 1)
        )
        await self.db.commit()
        return True

    async def get_all_status(self) -> list[dict]:
        result = await self.db.execute(select(ApiConfig).order_by(ApiConfig.api_name))
        configs = result.scalars().all()
        return [
            {
                "api_name": c.api_name,
                "is_active": c.is_active,
                "rate_limit_per_day": c.rate_limit_per_day,
                "requests_today": c.requests_today,
                "remaining_today": max(0, c.rate_limit_per_day - c.requests_today),
                "usage_pct": round(c.requests_today / c.rate_limit_per_day * 100, 1) if c.rate_limit_per_day else 0,
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in configs
        ]

    async def reset_daily_counters(self) -> int:
        result = await self.db.execute(
            update(ApiConfig).values(requests_today=0)
        )
        await self.db.commit()
        return result.rowcount
