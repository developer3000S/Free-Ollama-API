"""Хранилище шлюза (SQLAlchemy async).

Данные Discovery хранятся отдельно от маршрутизируемых узлов (§4.7): таблица
``candidates`` не участвует в выборе цели для балансировщика, а узел попадает в
``nodes`` только через реестр согласий.
"""

from __future__ import annotations

from foa.storage.db import Base, get_session_factory, init_db, make_engine
from foa.storage.repositories import (
    ApiKeyRepository,
    AuditRepository,
    BlacklistRepository,
    CandidateRepository,
    ConsentRepository,
    NodeRepository,
    OwnerRepository,
)

__all__ = [
    "ApiKeyRepository",
    "AuditRepository",
    "Base",
    "BlacklistRepository",
    "CandidateRepository",
    "ConsentRepository",
    "NodeRepository",
    "OwnerRepository",
    "get_session_factory",
    "init_db",
    "make_engine",
]
