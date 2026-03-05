"""
Alembic environment configuration for async SQLAlchemy.
Supports SQLite (dev) and PostgreSQL (production).
"""

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context

# Ensure the backend/ directory is on sys.path so `app` can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

# Import ALL models so Alembic detects every table
from app.database import Base
from app.models import *  # noqa: F401, F403
from app.config import settings

# ─── Alembic config ───────────────────────────
config = context.config

# Override the hardcoded URL with the environment-driven one
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


# ─── SQLite render_as_batch helper ────────────
# Required for SQLite — ALTER TABLE is not fully supported;
# Alembic uses batch mode to recreate tables instead.
def _is_sqlite() -> bool:
    return settings.DATABASE_URL.startswith("sqlite")


def do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Enable batch mode for SQLite compatibility
        render_as_batch=_is_sqlite(),
        # Compare server defaults so Alembic detects default value changes
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Offline mode -- generate SQL without a live connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=_is_sqlite(),
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Online mode -- connect and run migrations."""
    connectable = create_async_engine(
        settings.DATABASE_URL,
        poolclass=pool.NullPool,  # NullPool is correct for migration scripts
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
