from datetime import datetime
from sqlalchemy import String, Integer, Boolean, TIMESTAMP, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
from app.models.types import JSONBType


class ApiToolResult(Base):
    __tablename__ = "api_tool_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_result_id: Mapped[int] = mapped_column(Integer, ForeignKey("agent_results.id", ondelete="CASCADE"), nullable=False, index=True)
    api_name: Mapped[str] = mapped_column(String(50), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(200), nullable=True)
    request_params: Mapped[dict | None] = mapped_column(JSONBType, nullable=True)
    response_data: Mapped[dict | None] = mapped_column(JSONBType, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_cached: Mapped[bool] = mapped_column(Boolean, default=False)
    response_time_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
