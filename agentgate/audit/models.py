import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Boolean, DateTime, JSON
from sqlalchemy.orm import declarative_base

AgentGateBase = declarative_base()


class AgentGateAuditLog(AgentGateBase):
    __tablename__ = "agentgate_audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(100), nullable=False, index=True)
    project = Column(String(100), nullable=False, default="threatchain", index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    decision = Column(String(50), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    arguments = Column(JSON, nullable=True)
    masked_arguments = Column(JSON, nullable=True)
    masked_fields = Column(JSON, nullable=True)
    decided_by = Column(String(100), default="system")
    requires_human = Column(Boolean, default=False)
    approval_id = Column(String(100), nullable=True, index=True)
    event_type = Column(String(50), nullable=False, default="DECISION", index=True)
    approver = Column(String(100), nullable=True)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    execution_result = Column(String(100), nullable=True)
    investigation_id = Column(String(100), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
