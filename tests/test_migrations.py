"""Тесты Alembic-миграций (README «Миграции», §14.1).

Проверяют: начальная ревизия наводит схему, эквивалентную моделям; легаси-БД от
create_all не может быть «унаследована» молча — upgrade блокируется до явного
--stamp; режим storage.migrations=alembic поднимает приложение целиком.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from foa.app import create_app, shutdown, startup
from foa.config import ConfigError, load_settings
from foa.storage import migrations as mig
from foa.storage.db import init_db, make_engine
from foa.storage.models import Base

pytestmark = pytest.mark.asyncio

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_TABLES = sorted(Base.metadata.tables)


def _alembic_config(url: str) -> AlembicConfig:
    cfg = AlembicConfig(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    cfg.attributes["configure_logger"] = False
    cfg.attributes["database_url"] = url
    return cfg


def _sqlite_url(tmp_path: Path, name: str = "mig.sqlite3") -> str:
    return f"sqlite+aiosqlite:///{tmp_path / name}"


def test_head_revision_creates_every_model_table(tmp_path):
    """`upgrade head` на пустой БД создаёт ровно те таблицы, что описаны в моделях."""
    url = _sqlite_url(tmp_path)
    command.upgrade(_alembic_config(url), "head")
    db = sqlite3.connect(tmp_path / "mig.sqlite3")
    tables = sorted(r[0] for r in db.execute("select name from sqlite_master where type='table'"))
    db.close()
    assert [t for t in tables if t != "alembic_version"] == MODEL_TABLES


def test_migrated_schema_has_no_drift_from_models(tmp_path):
    """`alembic check` после upgrade head: схема и модели эквивалентны (защита CI)."""
    url = _sqlite_url(tmp_path)
    command.upgrade(_alembic_config(url), "head")
    # raiseerr=True → AssertionError при drift; тест падает, если модели поменяли
    # без новой ревизии.
    command.check(_alembic_config(url))


async def test_legacy_create_all_database_blocks_upgrade_until_stamped(tmp_path, caplog):
    """§17.1 безопасности данных: БД от create_all без alembic_version не апгрейдится молча."""
    url = _sqlite_url(tmp_path, "legacy.db")
    engine = make_engine(url)
    await init_db(engine)
    await engine.dispose()
    # Данные легаси-БД должны пережить попытку и блокировку.
    db = sqlite3.connect(tmp_path / "legacy.db")
    db.execute(
        "insert into owners (owner_id, contact, display_name, public_key, public_key_type, consent_method, created_at, updated_at)"
        " values ('o1','','','','ed25519','http_well_known','2026-01-01 00:00:00','2026-01-01 00:00:00')"
    )
    db.commit()
    db.close()

    with pytest.raises(mig.MigrationError, match="--stamp"):
        await mig.apply_migrations(url)

    await mig.stamp_head(url)
    await mig.apply_migrations(url)  # после явного stamp — проходит

    db = sqlite3.connect(tmp_path / "legacy.db")
    assert db.execute("select count(*) from owners").fetchone()[0] == 1
    assert db.execute("select version_num from alembic_version").fetchone()[0] != ""
    db.close()


async def test_startup_with_alembic_mode_builds_schema_and_serves(tmp_path):
    """storage.migrations=alembic: схема наводится миграциями, приложение стартует."""
    db_file = tmp_path / "app.db"
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"""
storage:
  database_url: "sqlite+aiosqlite:///{db_file}"
  migrations: alembic
  data_dir: "{tmp_path / 'data'}"
auth:
  admin_token: "test-admin"
""",
        encoding="utf-8",
    )
    settings = load_settings(path=str(cfg), env={})
    app = create_app(settings)
    state = await startup(app, settings, None)
    try:
        async with state.factory()() as session:
            from sqlalchemy import text

            names = set((await session.execute(text("select name from sqlite_master where type='table'"))).scalars())
            assert {"nodes", "consents", "alembic_version"} <= names
            version = (await session.execute(text("select version_num from alembic_version"))).scalars().one()
            assert version  # head отмечен
    finally:
        await shutdown(app)


def test_unknown_migrations_mode_is_rejected():
    from foa.config import default_settings

    settings = default_settings()
    settings.storage.migrations = "flyway"
    with pytest.raises(ConfigError, match=r"storage\.migrations"):
        settings.validate()


async def test_migrations_unavailable_reports_actionable_error(tmp_path, monkeypatch):
    """Если alembic/файлов нет — ошибка с подсказкой, а не молчаливый create_all."""
    monkeypatch.setattr(mig, "_project_root", lambda: None)
    with pytest.raises(mig.MigrationError, match=r"FOA_MIGRATIONS_ROOT|alembic"):
        await mig.apply_migrations(_sqlite_url(tmp_path))
