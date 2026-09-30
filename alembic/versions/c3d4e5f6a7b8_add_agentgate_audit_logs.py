"""add agentgate_audit_logs table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-24 00:00:00.000000

The AgentGateAuditLog model lives in its own declarative base (agentgate is a
standalone package), so alembic autogenerate does not see it. Kept in sync by hand
with agentgate/audit/models.py.
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agentgate_audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("project", sa.String(100), nullable=False),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("decision", sa.String(50), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("arguments", sa.JSON(), nullable=True),
        sa.Column("masked_arguments", sa.JSON(), nullable=True),
        sa.Column("masked_fields", sa.JSON(), nullable=True),
        sa.Column("decided_by", sa.String(100), nullable=True),
        sa.Column("requires_human", sa.Boolean(), nullable=True),
        sa.Column("approval_id", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    for col in ("agent_id", "project", "tool_name", "decision", "approval_id", "created_at"):
        op.create_index(f"ix_agentgate_audit_logs_{col}", "agentgate_audit_logs", [col])


def downgrade() -> None:
    for col in ("created_at", "approval_id", "decision", "tool_name", "project", "agent_id"):
        op.drop_index(f"ix_agentgate_audit_logs_{col}", table_name="agentgate_audit_logs")
    op.drop_table("agentgate_audit_logs")
