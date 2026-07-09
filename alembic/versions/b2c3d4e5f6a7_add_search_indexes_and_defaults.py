"""add search indexes, server defaults, and llm_configs unique constraint

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-11 00:00:00.000000

"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Indexes para patrones de busqueda frecuentes ---

    # Lookup principal: buscar investigaciones por valor de IOC
    op.create_index("ix_investigations_ioc_value", "investigations", ["ioc_value"])

    # Polling del Coordinator: filtrar por status (pending/running/completed)
    op.create_index("ix_investigations_status", "investigations", ["status"])

    # Report Agent: agregar resultados por agente dentro de una investigacion
    op.create_index(
        "ix_agent_results_inv_agent",
        "agent_results",
        ["investigation_id", "agent_name"],
    )

    # Cache fallback: buscar resultados de API por nombre
    op.create_index("ix_api_tool_results_api_name", "api_tool_results", ["api_name"])

    # --- Server defaults para columnas NOT NULL criticas ---
    # Garantiza que inserts raw fuera de SQLAlchemy no violen la restriccion NOT NULL

    op.alter_column(
        "investigations", "status",
        existing_type=sa.String(20),
        existing_nullable=False,
        server_default="pending",
    )
    op.alter_column(
        "agent_results", "status",
        existing_type=sa.String(20),
        existing_nullable=False,
        server_default="pending",
    )
    op.alter_column(
        "api_tool_results", "is_cached",
        existing_type=sa.Boolean(),
        existing_nullable=False,
        server_default=sa.false(),
    )

    # --- Unique constraint en llm_configs ---
    # Evita configs duplicadas de LLM que romperian el router
    op.create_unique_constraint(
        "uq_llm_configs_provider_model",
        "llm_configs",
        ["provider", "model"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_llm_configs_provider_model", "llm_configs", type_="unique")

    op.alter_column(
        "api_tool_results", "is_cached",
        existing_type=sa.Boolean(),
        existing_nullable=False,
        server_default=None,
    )
    op.alter_column(
        "agent_results", "status",
        existing_type=sa.String(20),
        existing_nullable=False,
        server_default=None,
    )
    op.alter_column(
        "investigations", "status",
        existing_type=sa.String(20),
        existing_nullable=False,
        server_default=None,
    )

    op.drop_index("ix_api_tool_results_api_name", "api_tool_results")
    op.drop_index("ix_agent_results_inv_agent", "agent_results")
    op.drop_index("ix_investigations_status", "investigations")
    op.drop_index("ix_investigations_ioc_value", "investigations")
