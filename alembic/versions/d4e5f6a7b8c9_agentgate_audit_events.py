"""add audit event columns and append-only trigger

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-25 00:00:00.000000

Adds event_type, approver, decided_at, execution_result, and investigation_id
to agentgate_audit_logs. On PostgreSQL, enforces immutability via a trigger
preventing UPDATE and DELETE operations.
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "agentgate_audit_logs",
        sa.Column("event_type", sa.String(50), nullable=False, server_default="DECISION"),
    )
    op.add_column(
        "agentgate_audit_logs",
        sa.Column("approver", sa.String(100), nullable=True),
    )
    op.add_column(
        "agentgate_audit_logs",
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "agentgate_audit_logs",
        sa.Column("execution_result", sa.String(100), nullable=True),
    )
    op.add_column(
        "agentgate_audit_logs",
        sa.Column("investigation_id", sa.String(100), nullable=True),
    )

    op.create_index("ix_agentgate_audit_logs_event_type", "agentgate_audit_logs", ["event_type"])
    op.create_index("ix_agentgate_audit_logs_investigation_id", "agentgate_audit_logs", ["investigation_id"])

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("""
            CREATE OR REPLACE FUNCTION trg_agentgate_audit_logs_append_only()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'agentgate_audit_logs is append-only';
            END;
            $$ LANGUAGE plpgsql;
        """)
        op.execute("""
            CREATE TRIGGER trg_agentgate_audit_logs_no_update_delete
            BEFORE UPDATE OR DELETE ON agentgate_audit_logs
            FOR EACH ROW
            EXECUTE FUNCTION trg_agentgate_audit_logs_append_only();
        """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_agentgate_audit_logs_no_update_delete ON agentgate_audit_logs;")
        op.execute("DROP FUNCTION IF EXISTS trg_agentgate_audit_logs_append_only();")

    op.drop_index("ix_agentgate_audit_logs_investigation_id", table_name="agentgate_audit_logs")
    op.drop_index("ix_agentgate_audit_logs_event_type", table_name="agentgate_audit_logs")

    op.drop_column("agentgate_audit_logs", "investigation_id")
    op.drop_column("agentgate_audit_logs", "execution_result")
    op.drop_column("agentgate_audit_logs", "decided_at")
    op.drop_column("agentgate_audit_logs", "approver")
    op.drop_column("agentgate_audit_logs", "event_type")
