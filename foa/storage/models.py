"""Табличные модели (SQLAlchemy 2.0)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Хранит и всегда возвращает aware-UTC.

    SQLite (дефолт разработки, §14.1) не сохраняет смещение, и сравнение с
    ``utcnow()`` дало бы TypeError; Postgres-``TIMESTAMP WITH TIME ZONE``
    приходит уже с tzinfo.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    type_annotation_map = {dict: JSON, list: JSON, datetime: UTCDateTime}


# --------------------------------------------------------------------------- #
# Узлы
# --------------------------------------------------------------------------- #


class NodeRow(Base):
    """Реестр узлов (§3.2.4). Статус управляет допустимостью маршрутизации."""

    __tablename__ = "nodes"
    __table_args__ = (
        UniqueConstraint("endpoint", name="uq_nodes_endpoint"),
        Index("ix_nodes_status", "status"),
    )

    node_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    endpoint: Mapped[str] = mapped_column(String(512))
    scheme: Mapped[str] = mapped_column(String(8), default="https")
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=11434)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    owner_id: Mapped[str] = mapped_column(String(64), ForeignKey("owners.owner_id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="candidate")
    #: Активное согласие узла. Без FK: узел создаётся раньше согласия (цикл
    #: nodes ↔ consents), целостность обеспечивает NodeService/ConsentService.
    consent_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    declared_models: Mapped[list] = mapped_column(JSON, default=list)
    observed_models: Mapped[list] = mapped_column(JSON, default=list)
    allowed_models: Mapped[list] = mapped_column(JSON, default=list)
    ollama_version: Mapped[str] = mapped_column(String(64), default="")
    max_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    max_requests_per_hour: Mapped[int] = mapped_column(Integer, default=1000)
    max_tokens_per_hour: Mapped[int] = mapped_column(Integer, default=0)
    weight: Mapped[int] = mapped_column(Integer, default=1)
    effective_weight: Mapped[int] = mapped_column(Integer, default=1)
    ewma_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    error_rate: Mapped[float] = mapped_column(Float, default=0.0)
    functional_check_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    functional_check_model: Mapped[str] = mapped_column(String(160), default="")
    tls_required: Mapped[bool] = mapped_column(Boolean, default=False)
    challenge_token: Mapped[str] = mapped_column(String(128), default="")
    challenge_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    last_health_check: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    last_consent_check: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    liveness_failures: Mapped[int] = mapped_column(Integer, default=0)
    readiness_failures: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    owner: Mapped[OwnerRow] = relationship(back_populates="nodes")


class OwnerRow(Base):
    """Владелец узла (§5.1)."""

    __tablename__ = "owners"

    owner_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    contact: Mapped[str] = mapped_column(String(255), default="")
    display_name: Mapped[str] = mapped_column(String(120), default="")
    public_key: Mapped[str] = mapped_column(Text, default="")
    public_key_type: Mapped[str] = mapped_column(String(32), default="ed25519")
    consent_method: Mapped[str] = mapped_column(String(32), default="http_well_known")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    nodes: Mapped[list[NodeRow]] = relationship(back_populates="owner")


# --------------------------------------------------------------------------- #
# Согласия
# --------------------------------------------------------------------------- #


class ConsentRow(Base):
    """Запись согласия (§5.2). История изменений — в ``consent_history``."""

    __tablename__ = "consents"
    __table_args__ = (Index("ix_consents_status", "status"),)

    consent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    node_id: Mapped[str] = mapped_column(String(64), ForeignKey("nodes.node_id"), index=True)
    owner_id: Mapped[str] = mapped_column(String(64), ForeignKey("owners.owner_id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    method: Mapped[str] = mapped_column(String(32), default="http_well_known")
    issued_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    allowed_models: Mapped[list] = mapped_column(JSON, default=list)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    max_requests_per_hour: Mapped[int] = mapped_column(Integer, default=1000)
    data_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    signature: Mapped[str] = mapped_column(Text, default="")
    challenge_token: Mapped[str] = mapped_column(String(128), default="")
    proof_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    revoke_reason: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    history: Mapped[list[ConsentHistoryRow]] = relationship(
        back_populates="consent", cascade="all, delete-orphan", order_by="ConsentHistoryRow.id"
    )


class ConsentHistoryRow(Base):
    __tablename__ = "consent_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    consent_id: Mapped[str] = mapped_column(String(64), ForeignKey("consents.consent_id"), index=True)
    event: Mapped[str] = mapped_column(String(48))
    actor: Mapped[str] = mapped_column(String(64), default="system")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    consent: Mapped[ConsentRow] = relationship(back_populates="history")


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


class CandidateRow(Base):
    """Кандидат Discovery (§4.4.1). Никогда не используется для маршрутизации."""

    __tablename__ = "candidates"
    __table_args__ = (
        UniqueConstraint("ip", "port", "protocol", name="uq_candidate_dedup"),
        Index("ix_candidates_status", "status"),
        Index("ix_candidates_observed", "observed_at"),
    )

    candidate_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    sources: Mapped[list] = mapped_column(JSON, default=list)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    ip: Mapped[str] = mapped_column(String(45))
    port: Mapped[int] = mapped_column(Integer, default=11434)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    dns_names: Mapped[list] = mapped_column(JSON, default=list)
    asn: Mapped[str] = mapped_column(String(32), default="")
    country: Mapped[str] = mapped_column(String(8), default="")
    service_hint: Mapped[str] = mapped_column(String(48), default="")
    banner_hash: Mapped[str] = mapped_column(String(128), default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="candidate")
    raw_ref: Mapped[dict] = mapped_column(JSON, default=dict)
    enrolled_node_id: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)  # §4.7 — срок хранения


# --------------------------------------------------------------------------- #
# Блэклист / ключи / аудит
# --------------------------------------------------------------------------- #


class BlacklistRow(Base):
    __tablename__ = "blacklist"
    __table_args__ = (Index("ix_blacklist_active", "expires_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(String(64), index=True)
    endpoint: Mapped[str] = mapped_column(String(512), default="")
    reason: Mapped[str] = mapped_column(String(120))
    detail: Mapped[str] = mapped_column(String(500), default="")
    actor: Mapped[str] = mapped_column(String(64), default="system")
    permanent: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    lifted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)


class ApiKeyRow(Base):
    """API-ключ (§12.4.1): хранится только хэш, никогда сам ключ."""

    __tablename__ = "api_keys"

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True)
    key_prefix: Mapped[str] = mapped_column(String(16), index=True)
    label: Mapped[str] = mapped_column(String(120), default="")
    owner_ref: Mapped[str] = mapped_column(String(64), default="")
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=0)
    concurrent_requests: Mapped[int] = mapped_column(Integer, default=0)
    tokens_per_day: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    rotates_from: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)


class AuditLogRow(Base):
    """Журнал аудита (§11.4, §12.7): только метаданные, без содержимого запросов."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_created", "created_at"), Index("ix_audit_subject", "subject_type", "subject_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64), default="system")
    subject_type: Mapped[str] = mapped_column(String(32), default="")
    subject_id: Mapped[str] = mapped_column(String(64), default="")
    request_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, server_default=func.now())
