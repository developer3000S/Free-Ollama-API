"""Окружение Alembic для Free Ollama API Gateway (§14.1, README «Миграции»).

URL берётся из той же цепочки источников, что и у шлюза (§13, §14.2):
``ALEMBIC_DB_URL`` → ``GATEWAY_DB_URL`` → ``settings.storage.database_url``.
Движок — async (aiosqlite/asyncpg), поэтому для автогенерации используется
``run_migrations_async`` c ``connectable.run_sync``; SQLite требует
``render_as_batch`` (ALTER TABLE ограничен).
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from foa.config import load_settings  # noqa: E402
from foa.storage.models import Base  # noqa: E402

config = context.config

# Программный запуск (из foa.storage.migrations) передаёт configure_logger=False:
# fileConfig() перечитал бы настройки журнала внутри живого процесса шлюза.
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def render_item(type_: str, obj: object, autogen_context: object) -> str | bool:
    """UTCDateTime из моделей должен импортироваться в ревизии явно."""
    import foa.storage.models as models_module

    if type_ == "type" and isinstance(obj, models_module.UTCDateTime):
        autogen_context.imports.add("from foa.storage.models import UTCDateTime")
        return "UTCDateTime()"
    return False


def database_url() -> str:
    """URL БД по приоритету: атрибут вызвавшего → ALEMBIC_DB_URL → GATEWAY_DB_URL → настройки шлюза."""
    if url := config.attributes.get("database_url"):
        return str(url)
    if url := os.environ.get("ALEMBIC_DB_URL"):
        return url
    settings = load_settings(env=dict(os.environ))
    return settings.storage.database_url


def _sync_url(url: str) -> str:
    """Async-драйверы нужны только рантайму шлюза; Alembic ходит синхронно."""
    return url.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg")


def run_migrations_offline() -> None:
    """Режим «сгенерировать SQL, не подключаясь к БД» (alembic upgrade --sql)."""
    context.configure(
        url=_sync_url(database_url()),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_item=render_item,
        render_as_batch=_sync_url(database_url()).startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_item=render_item,
        # SQLite не умеет полноценный ALTER TABLE — Alembic пересоздаёт таблицу.
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        url=database_url(),
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
