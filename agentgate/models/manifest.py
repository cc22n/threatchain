from typing import Any
from pydantic import BaseModel, Field


class ToolPermission(BaseModel):
    name: str
    scope: str = "read_only"
    rate_limit_per_min: int = 60
    rate_limit_per_day: int = 1000
    allowed_params: list[str] = Field(default_factory=list)


class MaskRule(BaseModel):
    tool: str = "*"
    fields: list[str] = Field(default_factory=list)
    condition: str | None = None


class AgentManifest(BaseModel):
    agent: str
    project: str = "threatchain"
    version: str = "1.0.0"
    tools_allowed: list[ToolPermission] = Field(default_factory=list)
    tools_denied: list[str] = Field(default_factory=list)
    requires_approval: list[str] = Field(default_factory=list)
    mask_rules: list[MaskRule] = Field(default_factory=list)
    risk_level_default: str = "low"
