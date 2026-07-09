from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

# JSONB on PostgreSQL, plain JSON on SQLite (used by the test suite).
# SQLite has no JSONB compiler, so models must use this variant type
# instead of importing JSONB directly.
JSONBType = JSONB().with_variant(JSON(), "sqlite")
