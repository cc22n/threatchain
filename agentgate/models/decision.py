from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    MASK = "MASK"


class DecisionResult(BaseModel):
    decision: DecisionType
    reason: str = ""
    agent: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    masked_arguments: dict[str, Any] | None = None
    masked_fields: list[str] = Field(default_factory=list)
    requires_human: bool = False
    approval_id: str | None = None
    event_type: str = "DECISION"
    approver: str | None = None
    decided_at: datetime | None = None
    execution_result: str | None = None
    investigation_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
