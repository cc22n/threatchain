from datetime import datetime
from sqlalchemy import String, Integer, Boolean, TIMESTAMP, Numeric
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
from app.models.types import JSONBType


class ApiConfig(Base):
    __tablename__ = "api_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    api_name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    api_key_env: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rate_limit_per_day: Mapped[int] = mapped_column(Integer, default=1000)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=60)
    requests_today: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=5)
    last_used_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, nullable=True)


class LlmConfig(Base):
    __tablename__ = "llm_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    api_key_env: Mapped[str] = mapped_column(String(100), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), default="cheap")
    best_for: Mapped[dict | None] = mapped_column(JSONBType, nullable=True)
    cost_input_per_m: Mapped[float] = mapped_column(Numeric(8, 4), default=0)
    cost_output_per_m: Mapped[float] = mapped_column(Numeric(8, 4), default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=2)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=20)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
