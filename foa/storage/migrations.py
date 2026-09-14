"""Программный запуск Alembic-миграций (README «Миграции», §14.1).

Используется в двух режимах:

* ``foa-gateway --migrate`` — отдельный шаг развертывания (``upgrade head`` и выход);
* ``storage.migrations: alembic`` — миграции применяются при старте процесса.

env.py запускается в рабочем потоке: свой asyncio.run внутри, поэтому вызов
безопасен и из запущенного event loop приложения, и из CLI.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

log = logging.getLogger("foa.storage.migrations")

_DEV_ROOT = Path(__file__).resolve().parents[2]


def _project_root() -> Path | None:
    """Корень проекта с alembic.ini и migrations/.

    При editable-установке это родитель пакета; в контейнере пакет лежит в
    site-packages, поэтому дополнительно проверяется рабочая директория.
    Переопределение — FOA_MIGRATIONS_ROOT.
    """
    candidates = []
    if override := os.environ.get("FOA_MIGRATIONS_ROOT"):
        candidates.append(Path(override))
    candidates.extend([Path.cwd(), _DEV_ROOT])
    for root in candidates:
        if (root / "alembic.ini").is_file() and (root / "migrations" / "env.py").is_file():
            return root
    return None


class MigrationError(RuntimeError):
    """Миграции запрошены, но их невозможно выполнить."""


def is_available() -> bool:
    try:
        import alembic  # noqa: F401
    except ImportError:
        return False
    root = _project_root()
    return root is not None and (root / "migrations" / "versions").is_dir()


def _run(url: str, revision: str) -> None:
    from alembic import command
    from alembic.config import Config

    root = _project_root()
    if root is None:
        raise MigrationError("не найден alembic.ini с каталогом migrations/ (передайте FOA_MIGRATIONS_ROOT)")
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    # Не трогать настройки журнала живого процесса и явно передать URL шлюза.
    cfg.attributes["configure_logger"] = False
    cfg.attributes["database_url"] = url
    command.upgrade(cfg, revision)


def _stamp(url: str, revision: str) -> None:
    from alembic import command
    from alembic.config import Config

    root = _project_root()
    if root is None:
        raise MigrationError("не найден alembic.ini с каталогом migrations/ (передайте FOA_MIGRATIONS_ROOT)")
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["configure_logger"] = False
    cfg.attributes["database_url"] = url
    command.stamp(cfg, revision)


async def _schema_state(url: str) -> tuple[bool, bool]:
    """Возвращает ``(есть alembic_version, есть наши таблицы)``."""
    from sqlalchemy import inspect

    from foa.storage.db import make_engine

    engine = make_engine(url)
    try:
        def _check(sync_conn):
            names = set(inspect(sync_conn).get_table_names())
            return ("alembic_version" in names, "nodes" in names)

        async with engine.connect() as conn:
            return await conn.run_sync(_check)
    finally:
        await engine.dispose()


async def stamp_head(database_url: str, *, revision: str = "head") -> None:
    """Отмечает существующую схему как ``revision``, не выполняя DDL.

    Нужен для БД, созданных ``create_all``: без ``alembic_version`` Alembic
    считает её «base» и попытается создать таблицы заново (§17 безопасного
    обновления: явное действие оператора, а не молчаливый догад).
    """
    if not is_available():
        raise MigrationError("Alembic недоступен: установите пакет alembic и проверьте наличие migrations/")
    await asyncio.to_thread(_stamp, database_url, revision)
    log.info("migrations: схема отмечена как %s", revision)


async def apply_migrations(database_url: str, *, revision: str = "head") -> None:
    """Выполняет ``alembic upgrade <revision>`` для ``database_url``.

    Легаси-БД (таблицы есть, ``alembic_version`` нет) не угадывается: upgrade
    на ней создал бы существующие таблицы заново, поэтому требуется явное
    ``foa-gateway --stamp``.
    """
    if not is_available():
        raise MigrationError(
            "Alembic недоступен: установите пакет alembic (pip install alembic) и убедитесь, "
            "что каталоги alembic.ini и migrations/ присутствуют в образе"
        )
    has_version, has_tables = await _schema_state(database_url)
    if has_tables and not has_version:
        raise MigrationError(
            "в БД уже есть таблицы (созданы create_all), но нет alembic_version — миграции не запущены, "
            "чтобы не пересоздавать данные. Подтвердите эквивалентность схемы моделям и выполните: "
            "foa-gateway --stamp   (подробности — README, раздел «Миграции»)"
        )
    log.info("migrations: upgrade %s → %s", database_url.split("@")[-1], revision)
    await asyncio.to_thread(_run, database_url, revision)
    log.info("migrations: схема БД обновлена до %s", revision)


__all__ = ["MigrationError", "apply_migrations", "is_available", "stamp_head"]

