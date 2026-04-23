"""add FK indexes for performance

Revision ID: a1b2c3d4e5f6
Revises: 2c54c947ba02
Create Date: 2026-04-22 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "2c54c947ba02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_agent_results_investigation_id", "agent_results", ["investigation_id"])
    op.create_index("ix_mitre_mappings_investigation_id", "mitre_mappings", ["investigation_id"])
    op.create_index("ix_ioc_relationships_investigation_id", "ioc_relationships", ["investigation_id"])
    op.create_index("ix_reports_investigation_id", "reports", ["investigation_id"])
    op.create_index("ix_api_tool_results_agent_result_id", "api_tool_results", ["agent_result_id"])


def downgrade() -> None:
    op.drop_index("ix_agent_results_investigation_id", "agent_results")
    op.drop_index("ix_mitre_mappings_investigation_id", "mitre_mappings")
    op.drop_index("ix_ioc_relationships_investigation_id", "ioc_relationships")
    op.drop_index("ix_reports_investigation_id", "reports")
    op.drop_index("ix_api_tool_results_agent_result_id", "api_tool_results")
