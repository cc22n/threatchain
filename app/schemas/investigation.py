import uuid
from datetime import datetime
from pydantic import BaseModel, field_validator
from typing import Optional

_VALID_IOC_TYPES = {"ip", "domain", "hash", "url", "email", "cve"}


class InvestigationCreate(BaseModel):
    ioc_value: str
    ioc_type: Optional[str] = None

    @field_validator("ioc_value")
    @classmethod
    def validate_ioc_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ioc_value must not be empty")
        if len(v) > 2048:
            raise ValueError("ioc_value exceeds maximum length of 2048 characters")
        return v

    @field_validator("ioc_type")
    @classmethod
    def validate_ioc_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _VALID_IOC_TYPES:
            raise ValueError(f"ioc_type must be one of: {', '.join(sorted(_VALID_IOC_TYPES))}")
        return v


class InvestigationResponse(BaseModel):
    id: uuid.UUID
    ioc_value: str
    ioc_type: str
    status: str
    verdict: Optional[str] = None
    severity: Optional[str] = None
    severity_score: Optional[float] = None
    summary: Optional[str] = None
    total_api_calls: int
    total_tokens_used: int
    execution_time_seconds: Optional[float] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
