import uuid
from datetime import datetime
from sqlalchemy import String, Text, Integer, Numeric, TIMESTAMP, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_value: Mapped[str] = mapped_column(String(500), nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity_score: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    agents_used: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    total_api_calls: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    execution_time_seconds: Mapped[float | None] = mapped_column(Numeric(8, 2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, nullable=True)
