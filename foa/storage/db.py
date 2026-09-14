"""Движок БД и сессии (§14.1).

По умолчанию — локальный SQLite (aiosqlite), в продакшене Postgres через
``GATEWAY_DB_URL``. Способ наведения схемы выбирается ``storage.migrations``:
``create_all`` (значение по умолчанию) или Alembic (см. README, «Миграции»).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from foa.storage.models import Base

log = logging.getLogger("foa.storage.db")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _prepare_sqlite_path(url: str) -> str:
    if "sqlite" not in url:
        return url
    prefix, sep, rest = url.partition(":///")
    if not sep or not rest or rest == ":memory:":
        return url
    path = Path(rest)
    if not path.is_absolute():
        path = Path.cwd() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"{prefix}:///{path}"


def make_engine(url: str, *, echo: bool = False) -> AsyncEngine:
    url = _prepare_sqlite_path(url)
    kwargs: dict = {"echo": echo, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"timeout": 30, "check_same_thread": False}
    return create_async_engine(url, **kwargs)


def _enable_sqlite_integrity(engine: AsyncEngine) -> None:
    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - зависит от драйвера
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()


async def init_db(engine: AsyncEngine, *, create_schema: bool = True) -> None:
    """Создаёт таблицы, включает WAL/ FK для SQLite.

    ``create_schema=False`` — схема наведена Alembic (``storage.migrations=alembic``),
    нужны только pragma-слушатели.
    """
    if engine.dialect.name == "sqlite":
        _enable_sqlite_integrity(engine)
    if create_schema:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    log.info("storage: схема БД готова (%s, create_all=%s)", engine.dialect.name, create_schema)


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("БД не инициализирована — вызовите init_engine()")
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        raise RuntimeError("БД не инициализирована — вызовите init_engine()")
    return _session_factory


def init_engine(url: str, *, echo: bool = False) -> AsyncEngine:
    global _engine, _session_factory
    if _engine is not None:
        return _engine
    _engine = make_engine(url, echo=echo)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _engine


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


async def session_scope() -> AsyncIterator[AsyncSession]:
    """DI-зависимость для FastAPI."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


__all__ = [
    "Base",
    "dispose_engine",
    "get_engine",
    "get_session_factory",
    "init_db",
    "init_engine",
    "make_engine",
    "session_scope",
]
