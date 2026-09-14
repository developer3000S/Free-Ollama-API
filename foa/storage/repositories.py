"""Репозитории: доступ к данным, специфичный для предметной области.

Все методы принимают ``AsyncSession`` явно — это упрощает транзакции в сервисах
и тестирование (в тестах используется in-memory SQLite).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from foa.storage.models import (
    ApiKeyRow,
    AuditLogRow,
    BlacklistRow,
    CandidateRow,
    ConsentHistoryRow,
    ConsentRow,
    NodeRow,
    OwnerRow,
    utcnow,
)

# --------------------------------------------------------------------------- #
# Узлы
# --------------------------------------------------------------------------- #


class NodeRepository:
    @staticmethod
    async def create(session: AsyncSession, node: NodeRow) -> NodeRow:
        session.add(node)
        await session.flush()
        return node

    @staticmethod
    async def get(session: AsyncSession, node_id: str) -> NodeRow | None:
        return await session.get(NodeRow, node_id)

    @staticmethod
    async def get_with_owner(session: AsyncSession, node_id: str) -> NodeRow | None:
        stmt = select(NodeRow).options(selectinload(NodeRow.owner)).where(NodeRow.node_id == node_id)
        return (await session.execute(stmt)).scalar_one_or_none()

    @staticmethod
    async def by_endpoint(session: AsyncSession, endpoint: str) -> NodeRow | None:
        stmt = select(NodeRow).where(NodeRow.endpoint == endpoint)
        return (await session.execute(stmt)).scalar_one_or_none()

    @staticmethod
    async def list_all(session: AsyncSession, *, states: list[str] | None = None, limit: int = 500) -> list[NodeRow]:
        stmt = select(NodeRow).order_by(NodeRow.created_at).limit(limit)
        if states:
            stmt = stmt.where(NodeRow.status.in_(states))
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def set_status(session: AsyncSession, node_id: str, status: str) -> None:
        await session.execute(update(NodeRow).where(NodeRow.node_id == node_id).values(status=status, updated_at=utcnow()))

    @staticmethod
    async def counts_by_status(session: AsyncSession) -> dict[str, int]:
        stmt = select(NodeRow.status, func.count()).group_by(NodeRow.status)
        return {row[0]: row[1] for row in (await session.execute(stmt)).all()}

    @staticmethod
    async def delete(session: AsyncSession, node_id: str) -> None:
        await session.execute(delete(NodeRow).where(NodeRow.node_id == node_id))

    @staticmethod
    async def delete_cascade(session: AsyncSession, node_id: str) -> int:
        """Удаляет узел вместе с историей и записями согласия (FK-целостность)."""
        from foa.storage.models import ConsentHistoryRow

        consent_ids = [
            row[0]
            for row in (await session.execute(select(ConsentRow.consent_id).where(ConsentRow.node_id == node_id))).all()
        ]
        if consent_ids:
            await session.execute(delete(ConsentHistoryRow).where(ConsentHistoryRow.consent_id.in_(consent_ids)))
            await session.execute(delete(ConsentRow).where(ConsentRow.consent_id.in_(consent_ids)))
        result = await session.execute(delete(NodeRow).where(NodeRow.node_id == node_id))
        return int(result.rowcount or 0)


# --------------------------------------------------------------------------- #
# Владельцы
# --------------------------------------------------------------------------- #


class OwnerRepository:
    @staticmethod
    async def get(session: AsyncSession, owner_id: str) -> OwnerRow | None:
        return await session.get(OwnerRow, owner_id)

    @staticmethod
    async def get_or_create(
        session: AsyncSession, owner_id: str, *, contact: str = "", display_name: str = "", public_key: str = ""
    ) -> OwnerRow:
        owner = await session.get(OwnerRow, owner_id)
        if owner is None:
            owner = OwnerRow(
                owner_id=owner_id, contact=contact, display_name=display_name, public_key=public_key
            )
            session.add(owner)
            await session.flush()
        elif public_key and owner.public_key != public_key:
            owner.public_key = public_key
            await session.flush()
        return owner

    @staticmethod
    async def set_public_key(session: AsyncSession, owner_id: str, public_key: str, key_type: str = "ed25519") -> None:
        await session.execute(
            update(OwnerRow).where(OwnerRow.owner_id == owner_id).values(public_key=public_key, public_key_type=key_type)
        )


# --------------------------------------------------------------------------- #
# Согласия
# --------------------------------------------------------------------------- #


class ConsentRepository:
    @staticmethod
    async def create(session: AsyncSession, consent: ConsentRow) -> ConsentRow:
        session.add(consent)
        await session.flush()
        return consent

    @staticmethod
    async def get(session: AsyncSession, consent_id: str) -> ConsentRow | None:
        return await session.get(ConsentRow, consent_id)

    @staticmethod
    async def get_full(session: AsyncSession, consent_id: str) -> ConsentRow | None:
        stmt = (
            select(ConsentRow)
            .options(selectinload(ConsentRow.history))
            .where(ConsentRow.consent_id == consent_id)
        )
        return (await session.execute(stmt)).scalar_one_or_none()

    @staticmethod
    async def active_for_node(session: AsyncSession, node_id: str) -> ConsentRow | None:
        stmt = (
            select(ConsentRow)
            .where(ConsentRow.node_id == node_id, ConsentRow.status == "verified")
            .order_by(ConsentRow.created_at.desc())
            .limit(1)
        )
        return (await session.execute(stmt)).scalar_one_or_none()

    @staticmethod
    async def latest_for_node(session: AsyncSession, node_id: str) -> ConsentRow | None:
        stmt = select(ConsentRow).where(ConsentRow.node_id == node_id).order_by(ConsentRow.created_at.desc()).limit(1)
        return (await session.execute(stmt)).scalar_one_or_none()

    @staticmethod
    async def list_expired(session: AsyncSession, now: datetime) -> list[ConsentRow]:
        stmt = select(ConsentRow).where(ConsentRow.status == "verified", ConsentRow.expires_at.is_not(None), ConsentRow.expires_at < now)
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def list_expiring(session: AsyncSession, now: datetime, window: timedelta) -> list[ConsentRow]:
        stmt = select(ConsentRow).where(
            ConsentRow.status == "verified",
            ConsentRow.expires_at.is_not(None),
            ConsentRow.expires_at >= now,
            ConsentRow.expires_at < now + window,
        )
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def list_all(session: AsyncSession, *, status: str | None = None, limit: int = 500) -> list[ConsentRow]:
        stmt = select(ConsentRow).order_by(ConsentRow.created_at.desc()).limit(limit)
        if status:
            stmt = stmt.where(ConsentRow.status == status)
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def update(session: AsyncSession, consent: ConsentRow, *, event: str, actor: str = "system", detail: dict | None = None) -> ConsentRow:
        consent.version += 1
        consent.updated_at = utcnow()
        session.add(consent)
        session.add(
            ConsentHistoryRow(consent_id=consent.consent_id, event=event, actor=actor, detail=detail or {})
        )
        await session.flush()
        return consent

    @staticmethod
    async def revoke(session: AsyncSession, consent: ConsentRow, *, reason: str, actor: str) -> ConsentRow:
        consent.status = "revoked"
        consent.revoked_at = utcnow()
        consent.revoke_reason = reason[:120]
        return await ConsentRepository.update(session, consent, event="revoked", actor=actor, detail={"reason": reason})

    @staticmethod
    async def add_history(session: AsyncSession, consent_id: str, event: str, *, actor: str = "system", detail: dict | None = None) -> None:
        session.add(ConsentHistoryRow(consent_id=consent_id, event=event, actor=actor, detail=detail or {}))
        await session.flush()


# --------------------------------------------------------------------------- #
# Кандидаты Discovery
# --------------------------------------------------------------------------- #


class CandidateRepository:
    @staticmethod
    async def upsert(session: AsyncSession, candidate: CandidateRow) -> tuple[CandidateRow, bool]:
        """Дедупликация по (ip, port, protocol) (§4.4.2). Возвращает (запись, создана_ли)."""
        stmt = select(CandidateRow).where(
            CandidateRow.ip == candidate.ip,
            CandidateRow.port == candidate.port,
            CandidateRow.protocol == candidate.protocol,
        )
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing is None:
            session.add(candidate)
            await session.flush()
            return candidate, True
        merged = list(dict.fromkeys([*(existing.sources or []), candidate.source]))
        existing.sources = merged
        # Python-овые default= из CandidateRow применяются только на flush,
        # поэтому незаданные поля читаются через `or` — иначе max(None, …) падает.
        existing.risk_score = max(existing.risk_score or 0, candidate.risk_score or 0)
        existing.risk_factors = list(dict.fromkeys([*(existing.risk_factors or []), *(candidate.risk_factors or [])]))[:20]
        observed = candidate.observed_at or existing.observed_at or utcnow()
        existing.observed_at = max(existing.observed_at or observed, observed)
        if candidate.dns_names:
            existing.dns_names = list(dict.fromkeys([*(existing.dns_names or []), *candidate.dns_names]))[:20]
        existing.updated_at = utcnow()
        await session.flush()
        return existing, False

    @staticmethod
    async def get(session: AsyncSession, candidate_id: str) -> CandidateRow | None:
        return await session.get(CandidateRow, candidate_id)

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        status: str | None = None,
        source: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[CandidateRow]:
        stmt = select(CandidateRow).order_by(CandidateRow.observed_at.desc()).limit(limit).offset(offset)
        if status:
            stmt = stmt.where(CandidateRow.status == status)
        if source:
            stmt = stmt.where(CandidateRow.source == source)
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def count(session: AsyncSession) -> int:
        return int((await session.execute(select(func.count()).select_from(CandidateRow))).scalar_one())

    @staticmethod
    async def set_status(session: AsyncSession, candidate_id: str, status: str, *, node_id: str | None = None) -> None:
        values: dict = {"status": status, "updated_at": utcnow()}
        if node_id:
            values["enrolled_node_id"] = node_id
        await session.execute(update(CandidateRow).where(CandidateRow.candidate_id == candidate_id).values(**values))

    @staticmethod
    async def purge_older_than(session: AsyncSession, cutoff: datetime) -> int:
        result = await session.execute(delete(CandidateRow).where(CandidateRow.observed_at < cutoff))
        return int(result.rowcount or 0)

    @staticmethod
    async def delete(session: AsyncSession, candidate_id: str) -> int:
        result = await session.execute(delete(CandidateRow).where(CandidateRow.candidate_id == candidate_id))
        return int(result.rowcount or 0)


# --------------------------------------------------------------------------- #
# Блэклист
# --------------------------------------------------------------------------- #


class BlacklistRepository:
    @staticmethod
    async def add(
        session: AsyncSession,
        entry: BlacklistRow,
    ) -> BlacklistRow:
        await session.execute(
            delete(BlacklistRow).where(BlacklistRow.node_id == entry.node_id, BlacklistRow.lifted_at.is_(None))
        )
        session.add(entry)
        await session.flush()
        return entry

    @staticmethod
    async def active_for_node(session: AsyncSession, node_id: str) -> BlacklistRow | None:
        now = utcnow()
        stmt = select(BlacklistRow).where(
            BlacklistRow.node_id == node_id,
            BlacklistRow.lifted_at.is_(None),
            (BlacklistRow.permanent.is_(True)) | (BlacklistRow.expires_at.is_(None)) | (BlacklistRow.expires_at > now),
        )
        return (await session.execute(stmt)).scalars().first()

    @staticmethod
    async def is_endpoint_blocked(session: AsyncSession, endpoint: str) -> bool:
        now = utcnow()
        stmt = select(BlacklistRow.id).where(
            BlacklistRow.endpoint == endpoint,
            BlacklistRow.lifted_at.is_(None),
            (BlacklistRow.permanent.is_(True)) | (BlacklistRow.expires_at.is_(None)) | (BlacklistRow.expires_at > now),
        )
        return (await session.execute(stmt)).first() is not None

    @staticmethod
    async def list(session: AsyncSession, *, include_expired: bool = False, limit: int = 500) -> list[BlacklistRow]:
        stmt = select(BlacklistRow).order_by(BlacklistRow.created_at.desc()).limit(limit)
        if not include_expired:
            now = utcnow()
            stmt = stmt.where(
                BlacklistRow.lifted_at.is_(None),
                (BlacklistRow.permanent.is_(True)) | (BlacklistRow.expires_at.is_(None)) | (BlacklistRow.expires_at > now),
            )
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def lift(session: AsyncSession, node_id: str, *, actor: str = "admin") -> int:
        result = await session.execute(
            update(BlacklistRow)
            .where(BlacklistRow.node_id == node_id, BlacklistRow.lifted_at.is_(None))
            .values(lifted_at=utcnow())
        )
        return int(result.rowcount or 0)

    @staticmethod
    async def count_active(session: AsyncSession) -> int:
        now = utcnow()
        stmt = (
            select(func.count())
            .select_from(BlacklistRow)
            .where(
                BlacklistRow.lifted_at.is_(None),
                (BlacklistRow.permanent.is_(True)) | (BlacklistRow.expires_at.is_(None)) | (BlacklistRow.expires_at > now),
            )
        )
        return int((await session.execute(stmt)).scalar_one())


# --------------------------------------------------------------------------- #
# API-ключи
# --------------------------------------------------------------------------- #


class ApiKeyRepository:
    @staticmethod
    async def create(session: AsyncSession, row: ApiKeyRow) -> ApiKeyRow:
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def by_hash(session: AsyncSession, key_hash: bytes) -> ApiKeyRow | None:
        stmt = select(ApiKeyRow).where(ApiKeyRow.key_hash == key_hash)
        return (await session.execute(stmt)).scalar_one_or_none()

    @staticmethod
    async def get(session: AsyncSession, key_id: str) -> ApiKeyRow | None:
        return await session.get(ApiKeyRow, key_id)

    @staticmethod
    async def list(session: AsyncSession, *, include_revoked: bool = False, owner_ref: str | None = None) -> list[ApiKeyRow]:
        stmt = select(ApiKeyRow).order_by(ApiKeyRow.created_at.desc())
        if not include_revoked:
            stmt = stmt.where(ApiKeyRow.revoked.is_(False))
        if owner_ref:
            stmt = stmt.where(ApiKeyRow.owner_ref == owner_ref)
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def revoke(session: AsyncSession, key_id: str) -> None:
        await session.execute(update(ApiKeyRow).where(ApiKeyRow.key_id == key_id).values(revoked=True))

    @staticmethod
    async def touch(session: AsyncSession, key_id: str) -> None:
        await session.execute(update(ApiKeyRow).where(ApiKeyRow.key_id == key_id).values(last_used_at=utcnow()))


# --------------------------------------------------------------------------- #
# Аудит
# --------------------------------------------------------------------------- #


class AuditRepository:
    @staticmethod
    async def write(
        session: AsyncSession,
        event: str,
        *,
        actor: str = "system",
        subject_type: str = "",
        subject_id: str = "",
        request_id: str = "",
        detail: dict | None = None,
    ) -> AuditLogRow:
        row = AuditLogRow(
            event=event,
            actor=actor,
            subject_type=subject_type,
            subject_id=subject_id,
            request_id=request_id,
            detail=detail or {},
        )
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        event: str | None = None,
        subject_id: str | None = None,
        limit: int = 200,
        since: datetime | None = None,
    ) -> list[AuditLogRow]:
        stmt = select(AuditLogRow).order_by(AuditLogRow.id.desc()).limit(limit)
        if event:
            stmt = stmt.where(AuditLogRow.event == event)
        if subject_id:
            stmt = stmt.where(AuditLogRow.subject_id == subject_id)
        if since:
            stmt = stmt.where(AuditLogRow.created_at >= since)
        return list((await session.execute(stmt)).scalars().all())

    @staticmethod
    async def purge_older_than(session: AsyncSession, cutoff: datetime) -> int:
        result = await session.execute(delete(AuditLogRow).where(AuditLogRow.created_at < cutoff))
        return int(result.rowcount or 0)
