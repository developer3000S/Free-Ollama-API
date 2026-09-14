"""Юнит-тесты асинхронных репозиториев (§14.1) на in-memory SQLite.

Используется собственный движок ``sqlite+aiosqlite://`` (StaticPool — одна и та же
БД на все сессии теста) и ``init_db``; глобальный ``init_engine`` не затрагивается,
чтобы тесты репозиториев не зависели от жизненного цикла приложения.

Все колонки дат/времени используют декоратор ``UTCDateTime``, поэтому значения
возвращаются aware-UTC — сравнения выполняются только с tz-aware датмами.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
import pytest_asyncio
from foa.storage.db import init_db
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
from foa.storage.repositories import (
    ApiKeyRepository,
    AuditRepository,
    BlacklistRepository,
    CandidateRepository,
    ConsentRepository,
    NodeRepository,
    OwnerRepository,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

OWNER_ID = "owner_test"


# --------------------------------------------------------------------------- #
# Фикстуры
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite://")
    await init_db(eng)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture()
async def factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture()
async def session(factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    """Сессия с уже созданным владельцем (FK на owners активен — PRAGMA foreign_keys=ON)."""
    async with factory() as s:
        s.add(OwnerRow(owner_id=OWNER_ID, contact="owner@example.invalid", display_name="Тест"))
        await s.commit()
        yield s


def make_node(node_id: str, endpoint: str, *, status: str = "candidate", **kwargs) -> NodeRow:
    return NodeRow(node_id=node_id, endpoint=endpoint, host="h", owner_id=OWNER_ID, status=status, **kwargs)


# --------------------------------------------------------------------------- #
# NodeRepository (§3.2.4)
# --------------------------------------------------------------------------- #


async def test_node_create_get_and_defaults(session: AsyncSession):
    """Создание узла и значения колонок по умолчанию."""
    await NodeRepository.create(session, make_node("n1", "https://a.example:11434"))
    await session.commit()

    fetched = await NodeRepository.get(session, "n1")
    assert fetched is not None
    assert fetched.endpoint == "https://a.example:11434"
    assert fetched.status == "candidate"
    assert fetched.owner_id == OWNER_ID
    assert fetched.declared_models == []
    assert fetched.liveness_failures == 0
    assert fetched.created_at.tzinfo is not None and fetched.created_at.tzinfo == utcnow().tzinfo
    assert await NodeRepository.get(session, "нет-такого") is None


async def test_node_endpoint_uniqueness_constraint(session: AsyncSession):
    """uq_nodes_endpoint: два узла с одним endpoint невозможны (§3.2.4)."""
    await NodeRepository.create(session, make_node("n1", "https://dup.example:11434"))
    await session.commit()

    with pytest.raises(IntegrityError) as excinfo:
        await NodeRepository.create(session, make_node("n2", "https://dup.example:11434"))
    assert "uq_nodes_endpoint" in str(excinfo.value.__cause__) or "nodes.endpoint" in str(excinfo.value)
    await session.rollback()
    assert [n.node_id for n in await NodeRepository.list_all(session)] == ["n1"]


async def test_node_by_endpoint_and_get_with_owner(session: AsyncSession):
    await NodeRepository.create(session, make_node("n1", "https://a.example:11434"))
    await session.commit()

    by_ep = await NodeRepository.by_endpoint(session, "https://a.example:11434")
    assert by_ep is not None and by_ep.node_id == "n1"
    assert await NodeRepository.by_endpoint(session, "https://missing.example") is None

    with_owner = await NodeRepository.get_with_owner(session, "n1")
    assert with_owner is not None
    assert with_owner.owner.owner_id == OWNER_ID
    assert with_owner.owner.contact == "owner@example.invalid"


async def test_node_list_all_filters_by_states_and_orders_by_created_at(session: AsyncSession):
    """list_all: фильтр по статусам и упорядочивание по времени создания."""
    base = utcnow()
    await NodeRepository.create(session, make_node("n1", "https://1.example", status="healthy", created_at=base))
    await NodeRepository.create(
        session, make_node("n2", "https://2.example", status="degraded", created_at=base + timedelta(seconds=1))
    )
    await NodeRepository.create(
        session, make_node("n3", "https://3.example", status="healthy", created_at=base + timedelta(seconds=2))
    )
    await session.commit()

    assert [n.node_id for n in await NodeRepository.list_all(session)] == ["n1", "n2", "n3"]
    assert [n.node_id for n in await NodeRepository.list_all(session, states=["healthy"])] == ["n1", "n3"]
    assert [n.node_id for n in await NodeRepository.list_all(session, states=["suspended"])] == []
    assert [n.node_id for n in await NodeRepository.list_all(session, limit=2)] == ["n1", "n2"]


async def test_node_set_status_and_counts_by_status(session: AsyncSession):
    base = utcnow()
    for index, status in enumerate(("healthy", "healthy", "degraded", "revoked")):
        await NodeRepository.create(
            session, make_node(f"n{index}", f"https://{index}.example", status=status, created_at=base + timedelta(seconds=index))
        )
    await session.commit()
    assert await NodeRepository.counts_by_status(session) == {"healthy": 2, "degraded": 1, "revoked": 1}

    await NodeRepository.set_status(session, "n0", "draining")
    await session.commit()
    assert (await NodeRepository.get(session, "n0")).status == "draining"
    assert await NodeRepository.counts_by_status(session) == {"healthy": 1, "draining": 1, "degraded": 1, "revoked": 1}


async def test_node_set_status_touches_updated_at_with_aware_datetime(session: AsyncSession):
    node = await NodeRepository.create(
        session, make_node("n1", "https://a.example", created_at=utcnow() - timedelta(days=2))
    )
    node.updated_at = utcnow() - timedelta(days=2)
    await session.commit()
    before = (await NodeRepository.get(session, "n1")).updated_at

    await NodeRepository.set_status(session, "n1", "healthy")
    await session.commit()
    after = (await NodeRepository.get(session, "n1")).updated_at
    assert after.tzinfo is not None, "UTCDateTime обязан возвращать aware-UTC"
    assert after > before


async def test_node_delete(session: AsyncSession):
    await NodeRepository.create(session, make_node("n1", "https://a.example"))
    await NodeRepository.create(session, make_node("n2", "https://b.example"))
    await session.commit()

    await NodeRepository.delete(session, "n1")
    await session.commit()
    assert [n.node_id for n in await NodeRepository.list_all(session)] == ["n2"]
    assert await NodeRepository.get(session, "n1") is None
    # удаление несуществующего узла — no-op без исключения
    await NodeRepository.delete(session, "нет-такого")
    await session.commit()


async def test_owner_repository_get_or_create(session: AsyncSession):
    """§5.1: владелец создаётся один раз, публичный ключ обновляется явно."""
    created = await OwnerRepository.get_or_create(session, "owner_new", contact="new@example.invalid")
    assert created.created_at.tzinfo is not None
    again = await OwnerRepository.get_or_create(session, "owner_new", contact="ignored@example.invalid")
    assert again.owner_id == created.owner_id
    await session.commit()
    stored = await OwnerRepository.get(session, "owner_new")
    assert stored.contact == "new@example.invalid"

    await OwnerRepository.set_public_key(session, "owner_new", "pubkey-ed25519", "ed25519")
    await session.commit()
    assert (await OwnerRepository.get(session, "owner_new")).public_key == "pubkey-ed25519"


# --------------------------------------------------------------------------- #
# ConsentRepository (§5.2, §5.4, §5.5)
# --------------------------------------------------------------------------- #


async def _node(session: AsyncSession, node_id: str = "n1") -> NodeRow:
    node = await NodeRepository.create(session, make_node(node_id, f"https://{node_id}.example"))
    await session.commit()
    return node


async def test_consent_create_and_get(session: AsyncSession):
    await _node(session)
    consent = await ConsentRepository.create(
        session, ConsentRow(consent_id="c1", node_id="n1", owner_id=OWNER_ID, status="pending")
    )
    await session.commit()

    fetched = await ConsentRepository.get(session, "c1")
    assert fetched is consent
    assert fetched.status == "pending"
    assert fetched.version == 1
    assert fetched.revoked_at is None
    assert fetched.created_at.tzinfo == utcnow().tzinfo


async def test_consent_latest_and_active_for_node(session: AsyncSession):
    """active_for_node возвращает только status='verified'; latest_for_node — любой."""
    await _node(session)
    base = utcnow()
    await ConsentRepository.create(
        session,
        ConsentRow(consent_id="c-old", node_id="n1", owner_id=OWNER_ID, status="verified", created_at=base),
    )
    await ConsentRepository.create(
        session,
        ConsentRow(consent_id="c-new", node_id="n1", owner_id=OWNER_ID, status="expired", created_at=base + timedelta(hours=1)),
    )
    await session.commit()

    assert (await ConsentRepository.latest_for_node(session, "n1")).consent_id == "c-new"
    assert (await ConsentRepository.active_for_node(session, "n1")).consent_id == "c-old"
    assert await ConsentRepository.active_for_node(session, "нет-узла") is None
    assert await ConsentRepository.latest_for_node(session, "нет-узла") is None


async def test_consent_active_returns_most_recent_verified(session: AsyncSession):
    await _node(session)
    base = utcnow()
    for index, (cid, status) in enumerate((("c1", "verified"), ("c2", "verified"), ("c3", "pending"))):
        await ConsentRepository.create(
            session,
            ConsentRow(
                consent_id=cid, node_id="n1", owner_id=OWNER_ID, status=status, created_at=base + timedelta(seconds=index)
            ),
        )
    await session.commit()
    assert (await ConsentRepository.active_for_node(session, "n1")).consent_id == "c2"


async def test_consent_update_bumps_version_and_appends_history(session: AsyncSession):
    """§5.2: каждое изменение согласия попадает в consent_history."""
    await _node(session)
    consent = await ConsentRepository.create(
        session, ConsentRow(consent_id="c1", node_id="n1", owner_id=OWNER_ID, status="verified")
    )
    await session.commit()

    updated = await ConsentRepository.update(session, consent, event="amended", actor="admin", detail={"ttl_days": 7})
    await session.commit()
    assert updated.version == 2
    assert updated.updated_at.tzinfo is not None

    await ConsentRepository.update(session, updated, event="rechecked", actor="system")
    await session.commit()

    full = await ConsentRepository.get_full(session, "c1")
    assert full.version == 3
    assert [(h.event, h.actor, h.detail) for h in full.history] == [
        ("amended", "admin", {"ttl_days": 7}),
        ("rechecked", "system", {}),
    ]


async def test_consent_revoke_sets_status_reason_and_timestamp(session: AsyncSession):
    """§5.5: отзыв фиксируется в записи и в истории."""
    await _node(session)
    consent = await ConsentRepository.create(
        session, ConsentRow(consent_id="c1", node_id="n1", owner_id=OWNER_ID, status="verified")
    )
    await session.commit()

    revoked = await ConsentRepository.revoke(session, consent, reason="владелец отозвал разрешение", actor="owner")
    await session.commit()

    assert revoked.status == "revoked"
    assert revoked.revoke_reason == "владелец отозвал разрешение"
    assert revoked.revoked_at is not None and revoked.revoked_at.tzinfo == utcnow().tzinfo
    assert revoked.version == 2
    assert await ConsentRepository.active_for_node(session, "n1") is None
    assert (await ConsentRepository.latest_for_node(session, "n1")).status == "revoked"

    full = await ConsentRepository.get_full(session, "c1")
    assert [(h.event, h.actor, h.detail) for h in full.history] == [
        ("revoked", "owner", {"reason": "владелец отозвал разрешение"})
    ]


async def test_consent_revoke_truncates_long_reason(session: AsyncSession):
    await _node(session)
    consent = await ConsentRepository.create(
        session, ConsentRow(consent_id="c1", node_id="n1", owner_id=OWNER_ID, status="verified")
    )
    await session.commit()
    revoked = await ConsentRepository.revoke(session, consent, reason="д" * 300, actor="owner")
    await session.commit()
    assert len(revoked.revoke_reason) == 120


async def test_consent_list_expired_and_expiring_windows(session: AsyncSession):
    """§5.4: просроченные и близкие к истечению согласия."""
    await _node(session)
    now = utcnow()
    cases = {
        "c-expired": now - timedelta(days=2),
        "c-soon": now + timedelta(hours=6),
        "c-later": now + timedelta(days=30),
        "c-no-expiry": None,
    }
    for cid, expires_at in cases.items():
        await ConsentRepository.create(
            session,
            ConsentRow(consent_id=cid, node_id="n1", owner_id=OWNER_ID, status="verified", expires_at=expires_at),
        )
    # верифицированное и просроченное — попадает; неподтверждённое просроченное — нет
    await ConsentRepository.create(
        session,
        ConsentRow(consent_id="c-pending", node_id="n1", owner_id=OWNER_ID, status="pending", expires_at=now - timedelta(days=1)),
    )
    await session.commit()

    assert sorted(c.consent_id for c in await ConsentRepository.list_expired(session, now)) == ["c-expired"]
    window = timedelta(days=7)
    assert sorted(c.consent_id for c in await ConsentRepository.list_expiring(session, now, window)) == ["c-soon"]
    assert sorted(c.consent_id for c in await ConsentRepository.list_expiring(session, now, timedelta(days=60))) == [
        "c-later",
        "c-soon",
    ]
    assert await ConsentRepository.list_expiring(session, now, timedelta(minutes=1)) == []


async def test_consent_list_all_and_add_history(session: AsyncSession):
    await _node(session)
    base = utcnow()
    for index, status in enumerate(("verified", "verified", "revoked")):
        await ConsentRepository.create(
            session,
            ConsentRow(consent_id=f"c{index}", node_id="n1", owner_id=OWNER_ID, status=status, created_at=base + timedelta(seconds=index)),
        )
    await session.commit()

    assert len(await ConsentRepository.list_all(session)) == 3
    assert [c.consent_id for c in await ConsentRepository.list_all(session, status="verified")] == ["c1", "c0"]
    assert [c.consent_id for c in await ConsentRepository.list_all(session, limit=1)] == ["c2"]

    await ConsentRepository.add_history(session, "c0", "consent_recheck", actor="health-checker", detail={"ok": True})
    await session.commit()
    rows = (await session.execute(select(ConsentHistoryRow))).scalars().all()
    assert [(r.event, r.actor, r.detail) for r in rows] == [("consent_recheck", "health-checker", {"ok": True})]


# --------------------------------------------------------------------------- #
# CandidateRepository (§4.4.1–§4.4.2, §4.7)
# --------------------------------------------------------------------------- #


async def test_candidate_upsert_creates_new_row(session: AsyncSession):
    candidate = CandidateRow(
        candidate_id="cand1",
        source="censys",
        sources=["censys"],
        ip="203.0.113.10",
        port=11434,
        protocol="tcp",
        risk_score=30,
        risk_factors=["open_port"],
    )
    stored, created = await CandidateRepository.upsert(session, candidate)
    await session.commit()

    assert created is True
    assert stored.candidate_id == "cand1"
    assert await CandidateRepository.count(session) == 1


async def test_candidate_upsert_dedups_by_ip_port_protocol(session: AsyncSession):
    """§4.4.2: дедупликация по (ip, port, protocol); второй источник не создаёт запись."""
    observed = utcnow()
    _first, created_first = await CandidateRepository.upsert(
        session,
        CandidateRow(
            candidate_id="cand1",
            source="censys",
            sources=["censys"],
            ip="203.0.113.10",
            port=11434,
            protocol="tcp",
            risk_score=30,
            risk_factors=["open_port"],
            observed_at=observed,
            dns_names=["a.example"],
        ),
    )
    await session.commit()
    assert created_first is True

    second, created_second = await CandidateRepository.upsert(
        session,
        CandidateRow(
            candidate_id="cand2",
            source="zoomeye",
            sources=["zoomeye", "duplicates-inside"],
            ip="203.0.113.10",
            port=11434,
            protocol="tcp",
            risk_score=55,
            risk_factors=["asn_risk", "open_port"],
            observed_at=observed + timedelta(hours=1),
            dns_names=["b.example", "a.example"],
        ),
    )
    await session.commit()

    assert created_second is False
    assert second.candidate_id == "cand1", "возвращается существующая запись"
    assert await CandidateRepository.count(session) == 1

    stored = await CandidateRepository.get(session, "cand1")
    # sources дополняется первичным источником новой записи (candidate.source), а не всем её списком
    assert stored.sources == ["censys", "zoomeye"], "sources объединяются без дублей"
    assert stored.risk_score == 55, "сохраняется максимальный risk_score"
    assert stored.risk_factors == ["open_port", "asn_risk"], "risk_factors дедуплицируются с сохранением порядка"
    assert stored.dns_names == ["a.example", "b.example"]
    assert stored.observed_at == observed + timedelta(hours=1)
    assert stored.updated_at.tzinfo is not None
    # первичный источник записи не перезаписывается
    assert stored.source == "censys"


async def test_candidate_upsert_keeps_higher_existing_risk(session: AsyncSession):
    """max() по risk_score: меньшее значение не понижает оценку."""
    observed = utcnow()
    await CandidateRepository.upsert(
        session,
        CandidateRow(
            candidate_id="c1",
            source="censys",
            sources=["censys"],
            ip="203.0.113.11",
            port=11434,
            protocol="tcp",
            risk_score=80,
            risk_factors=["asn_risk"],
            observed_at=observed,
        ),
    )
    await session.commit()
    stored, created = await CandidateRepository.upsert(
        session,
        CandidateRow(
            candidate_id="c2",
            source="natlas",
            sources=["natlas"],
            ip="203.0.113.11",
            port=11434,
            protocol="tcp",
            risk_score=10,
            risk_factors=["open_port"],
            observed_at=observed,
        ),
    )
    await session.commit()
    assert created is False
    assert stored.risk_score == 80
    assert stored.risk_factors == ["asn_risk", "open_port"]
    assert stored.sources == ["censys", "natlas"]


async def test_candidate_upsert_merge_tolerates_model_defaults(session: AsyncSession):
    """Слияние не должно требовать ручной подстановки значений по умолчанию модели."""
    await CandidateRepository.upsert(
        session,
        CandidateRow(candidate_id="c1", source="censys", ip="203.0.113.30", port=11434, protocol="tcp"),
    )
    await session.commit()
    _, created = await CandidateRepository.upsert(
        session,
        CandidateRow(candidate_id="c2", source="zoomeye", ip="203.0.113.30", port=11434, protocol="tcp"),
    )
    await session.commit()
    assert created is False


async def test_candidate_upsert_treats_port_and_protocol_as_distinct(session: AsyncSession):
    observed = utcnow()
    for cid, port, protocol in (("a", 11434, "tcp"), ("b", 8080, "tcp"), ("c", 11434, "udp")):
        _, created = await CandidateRepository.upsert(
            session,
            CandidateRow(candidate_id=f"cand-{cid}", source="censys", ip="203.0.113.12", port=port, protocol=protocol, observed_at=observed),
        )
        assert created is True
    await session.commit()
    assert await CandidateRepository.count(session) == 3


async def test_candidate_list_status_pagination_and_set_status(session: AsyncSession):
    base = utcnow()
    for index, (source, ip) in enumerate((("censys", "203.0.113.1"), ("zoomeye", "203.0.113.2"), ("censys", "203.0.113.3"))):
        await CandidateRepository.upsert(
            session,
            CandidateRow(
                candidate_id=f"cand{index}", source=source, ip=ip, port=11434, protocol="tcp", observed_at=base + timedelta(seconds=index)
            ),
        )
    await session.commit()

    assert [c.candidate_id for c in await CandidateRepository.list(session)] == ["cand2", "cand1", "cand0"]
    assert [c.candidate_id for c in await CandidateRepository.list(session, source="censys")] == ["cand2", "cand0"]
    assert [c.candidate_id for c in await CandidateRepository.list(session, limit=1)] == ["cand2"]
    assert [c.candidate_id for c in await CandidateRepository.list(session, limit=1, offset=1)] == ["cand1"]
    assert await CandidateRepository.list(session, status="manual_review") == []

    await CandidateRepository.set_status(session, "cand0", "manual_review", node_id="n7")
    await session.commit()
    stored = await CandidateRepository.get(session, "cand0")
    assert stored.status == "manual_review"
    assert stored.enrolled_node_id == "n7"
    assert [c.candidate_id for c in await CandidateRepository.list(session, status="manual_review")] == ["cand0"]
    assert (await CandidateRepository.get(session, "cand1")).enrolled_node_id is None


async def test_candidate_purge_older_than_removes_only_stale(session: AsyncSession):
    """§4.7: удаляются только кандидаты старше cutoff по observed_at."""
    base = utcnow()
    rows = (
        ("c-fresh-1", "203.0.113.10", base - timedelta(days=1)),
        ("c-fresh-2", "203.0.113.11", base - timedelta(days=2)),
        ("c-stale-1", "203.0.113.12", base - timedelta(days=120)),
        ("c-stale-2", "203.0.113.13", base - timedelta(days=200)),
    )
    for cid, ip, observed in rows:
        await CandidateRepository.upsert(
            session,
            CandidateRow(
                candidate_id=cid, source="censys", ip=ip, port=11434, protocol="tcp", risk_score=0, risk_factors=[], observed_at=observed
            ),
        )
    await session.commit()
    assert await CandidateRepository.count(session) == 4

    deleted = await CandidateRepository.purge_older_than(session, base - timedelta(days=90))
    await session.commit()

    assert deleted == 2
    remaining = sorted(c.candidate_id for c in await CandidateRepository.list(session, limit=50))
    assert remaining == ["c-fresh-1", "c-fresh-2"]
    # повторная очистка тем же cutoff ничего не находит
    assert await CandidateRepository.purge_older_than(session, base - timedelta(days=90)) == 0


async def test_candidate_delete(session: AsyncSession):
    await CandidateRepository.upsert(
        session, CandidateRow(candidate_id="c1", source="censys", ip="203.0.113.20", port=11434, protocol="tcp")
    )
    await session.commit()
    assert await CandidateRepository.delete(session, "c1") == 1
    await session.commit()
    assert await CandidateRepository.delete(session, "c1") == 0
    assert await CandidateRepository.count(session) == 0


# --------------------------------------------------------------------------- #
# BlacklistRepository (§6.6)
# --------------------------------------------------------------------------- #


async def test_blacklist_add_and_active_for_node(session: AsyncSession):
    entry = await BlacklistRepository.add(
        session, BlacklistRow(node_id="n1", endpoint="https://n1.example", reason="consent_revoked", permanent=True)
    )
    await session.commit()

    assert entry.id is not None
    assert entry.created_at.tzinfo == utcnow().tzinfo
    assert entry.lifted_at is None
    active = await BlacklistRepository.active_for_node(session, "n1")
    assert active.reason == "consent_revoked"
    assert await BlacklistRepository.active_for_node(session, "n-none") is None
    assert await BlacklistRepository.count_active(session) == 1


async def test_blacklist_add_replaces_previous_active_entry(session: AsyncSession):
    """Повторная блокировка того же узла заменяет активную запись (§6.6)."""
    await BlacklistRepository.add(session, BlacklistRow(node_id="n1", endpoint="https://n1.example", reason="первая", permanent=True))
    await session.commit()
    await BlacklistRepository.add(
        session, BlacklistRow(node_id="n1", endpoint="https://n1.example", reason="вторая", permanent=False, expires_at=utcnow() + timedelta(days=1))
    )
    await session.commit()

    rows = (await session.execute(select(BlacklistRow))).scalars().all()
    assert len(rows) == 1, "старая активная запись удаляется, а не копится"
    assert (await BlacklistRepository.active_for_node(session, "n1")).reason == "вторая"
    assert await BlacklistRepository.count_active(session) == 1


async def test_blacklist_active_ignores_lifted_and_expired(session: AsyncSession):
    """Снятая и истёкшая (не постоянная) блокировки не активны."""
    await BlacklistRepository.add(session, BlacklistRow(node_id="n-expired", reason="истёк", permanent=False, expires_at=utcnow() - timedelta(hours=1)))
    await BlacklistRepository.add(session, BlacklistRow(node_id="n-lifted", reason="снята", permanent=True))
    await BlacklistRepository.add(session, BlacklistRow(node_id="n-timed", reason="ещё действует", permanent=False, expires_at=utcnow() + timedelta(hours=1)))
    await BlacklistRepository.add(session, BlacklistRow(node_id="n-null-expiry", reason="без срока", permanent=False, expires_at=None))
    await session.commit()
    assert await BlacklistRepository.lift(session, "n-lifted") == 1
    await session.commit()

    assert await BlacklistRepository.active_for_node(session, "n-expired") is None
    assert await BlacklistRepository.active_for_node(session, "n-lifted") is None
    assert (await BlacklistRepository.active_for_node(session, "n-timed")).reason == "ещё действует"
    assert (await BlacklistRepository.active_for_node(session, "n-null-expiry")).reason == "без срока"
    assert await BlacklistRepository.count_active(session) == 2
    assert await BlacklistRepository.lift(session, "n-никого-такого") == 0


async def test_blacklist_is_endpoint_blocked(session: AsyncSession):
    await BlacklistRepository.add(session, BlacklistRow(node_id="n1", endpoint="https://blocked.example", reason="abuse", permanent=True))
    await BlacklistRepository.add(
        session, BlacklistRow(node_id="n2", endpoint="https://expired.example", reason="abuse", permanent=False, expires_at=utcnow() - timedelta(days=1))
    )
    await session.commit()

    assert await BlacklistRepository.is_endpoint_blocked(session, "https://blocked.example") is True
    assert await BlacklistRepository.is_endpoint_blocked(session, "https://expired.example") is False
    assert await BlacklistRepository.is_endpoint_blocked(session, "https://free.example") is False

    assert await BlacklistRepository.lift(session, "n1") == 1
    await session.commit()
    assert await BlacklistRepository.is_endpoint_blocked(session, "https://blocked.example") is False


async def test_blacklist_list_and_lift(session: AsyncSession):
    await BlacklistRepository.add(session, BlacklistRow(node_id="n1", reason="a", permanent=True, created_at=utcnow() - timedelta(days=2)))
    await BlacklistRepository.add(session, BlacklistRow(node_id="n2", reason="b", permanent=True, created_at=utcnow() - timedelta(days=1)))
    await BlacklistRepository.add(session, BlacklistRow(node_id="n3", reason="c", permanent=False, expires_at=utcnow() - timedelta(days=1), created_at=utcnow()))
    await session.commit()

    assert [b.node_id for b in await BlacklistRepository.list(session)] == ["n2", "n1"]
    assert [b.node_id for b in await BlacklistRepository.list(session, include_expired=True)] == ["n3", "n2", "n1"]
    assert [b.node_id for b in await BlacklistRepository.list(session, limit=1)] == ["n2"]

    assert await BlacklistRepository.lift(session, "n1") == 1
    await session.commit()
    lifted = (await session.execute(select(BlacklistRow).where(BlacklistRow.node_id == "n1"))).scalar_one()
    assert lifted.lifted_at is not None and lifted.lifted_at.tzinfo == utcnow().tzinfo
    assert await BlacklistRepository.count_active(session) == 1


# --------------------------------------------------------------------------- #
# ApiKeyRepository (§12.4.1)
# --------------------------------------------------------------------------- #


def _key_hash(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


async def test_api_key_create_stores_only_hash(session: AsyncSession):
    digest = _key_hash("foa_supersecret_key_material")
    row = await ApiKeyRepository.create(
        session,
        ApiKeyRow(key_id="k1", key_hash=digest, key_prefix="foa_super", label="рабочий", owner_ref="user1", scopes=["ollama:read", "ollama:generate"]),
    )
    await session.commit()

    stored = await ApiKeyRepository.get(session, "k1")
    assert stored is row
    assert isinstance(stored.key_hash, bytes) and stored.key_hash == digest
    assert stored.revoked is False
    assert stored.last_used_at is None
    assert stored.scopes == ["ollama:read", "ollama:generate"]
    assert stored.created_at.tzinfo == utcnow().tzinfo
    assert "supersecret" not in str(stored.key_prefix)


async def test_api_key_by_hash_accepts_bytes(session: AsyncSession):
    digest = _key_hash("foa_lookup_material")
    await ApiKeyRepository.create(session, ApiKeyRow(key_id="k1", key_hash=digest, key_prefix="foa_lookup"))
    await session.commit()

    assert (await ApiKeyRepository.by_hash(session, digest)).key_id == "k1"
    assert await ApiKeyRepository.by_hash(session, _key_hash("другой ключ")) is None
    assert await ApiKeyRepository.by_hash(session, b"\x00" * 64) is None
    assert await ApiKeyRepository.get(session, "нет-такого") is None


async def test_api_key_list_excludes_revoked(session: AsyncSession):
    base = utcnow()
    for index, owner in enumerate(("user1", "user1", "user2")):
        await ApiKeyRepository.create(
            session,
            ApiKeyRow(
                key_id=f"k{index}",
                key_hash=hashlib.sha256(f"secret-{index}".encode()).digest(),
                key_prefix=f"foa_p{index}",
                owner_ref=owner,
                created_at=base + timedelta(seconds=index),
            ),
        )
    await session.commit()

    assert sorted(k.key_id for k in await ApiKeyRepository.list(session)) == ["k0", "k1", "k2"]
    assert sorted(k.key_id for k in await ApiKeyRepository.list(session, owner_ref="user1")) == ["k0", "k1"]
    assert [k.key_id for k in await ApiKeyRepository.list(session)] == ["k2", "k1", "k0"], "список — свежими вперёд"

    await ApiKeyRepository.revoke(session, "k1")
    await session.commit()
    assert sorted(k.key_id for k in await ApiKeyRepository.list(session)) == ["k0", "k2"]
    assert sorted(k.key_id for k in await ApiKeyRepository.list(session, include_revoked=True)) == ["k0", "k1", "k2"]
    assert (await ApiKeyRepository.get(session, "k1")).revoked is True
    # отозванный ключ по-прежнему находится по хэшу — фильтр «не отозван» остаётся за сервисом
    assert (await ApiKeyRepository.by_hash(session, hashlib.sha256(b"secret-1").digest())).key_id == "k1"


async def test_api_key_touch_updates_last_used_at(session: AsyncSession):
    await ApiKeyRepository.create(session, ApiKeyRow(key_id="k1", key_hash=_key_hash("m"), key_prefix="foa_p1"))
    await session.commit()
    assert (await ApiKeyRepository.get(session, "k1")).last_used_at is None

    await ApiKeyRepository.touch(session, "k1")
    await session.commit()
    touched = (await ApiKeyRepository.get(session, "k1")).last_used_at
    assert touched is not None
    assert touched.tzinfo == utcnow().tzinfo
    assert utcnow() - touched < timedelta(minutes=5)

    await ApiKeyRepository.touch(session, "k-несуществующий")
    await session.commit()
    assert (await ApiKeyRepository.by_hash(session, _key_hash("m"))).key_id == "k1"


# --------------------------------------------------------------------------- #
# AuditRepository (§11.4, §12.7)
# --------------------------------------------------------------------------- #


async def test_audit_write_and_list_ordering(session: AsyncSession):
    """Журнал аудита отдаётся свежими записями вперёд (§12.7)."""
    for index in range(3):
        await AuditRepository.write(
            session,
            "node.created",
            actor=f"admin{index}",
            subject_type="node",
            subject_id="n1",
            request_id=f"req_{index}",
            detail={"index": index},
        )
    await AuditRepository.write(session, "key.revoked", subject_type="key", subject_id="k1")
    await session.commit()

    rows = await AuditRepository.list(session)
    assert [r.event for r in rows] == ["key.revoked", "node.created", "node.created", "node.created"]
    assert [r.id for r in rows] == sorted((r.id for r in rows), reverse=True)
    newest = rows[0]
    assert newest.actor == "system" and newest.subject_id == "k1" and newest.detail == {}
    assert all(r.created_at.tzinfo == utcnow().tzinfo for r in rows)
    assert await AuditRepository.list(session, limit=2) == rows[:2]


async def test_audit_list_filters_by_event_and_subject(session: AsyncSession):
    await AuditRepository.write(session, "node.created", subject_type="node", subject_id="n1", detail={"a": 1})
    await AuditRepository.write(session, "node.created", subject_type="node", subject_id="n2", detail={"a": 2})
    await AuditRepository.write(session, "consent.revoked", subject_type="node", subject_id="n1")
    await session.commit()

    assert [r.subject_id for r in await AuditRepository.list(session, event="node.created")] == ["n2", "n1"]
    assert [r.event for r in await AuditRepository.list(session, subject_id="n1")] == ["consent.revoked", "node.created"]
    assert [r.event for r in await AuditRepository.list(session, event="node.created", subject_id="n1")] == ["node.created"]
    assert await AuditRepository.list(session, event="несуществующее") == []


async def test_audit_list_since_filter(session: AsyncSession):
    await AuditRepository.write(session, "node.created", subject_id="n1")
    await session.commit()
    assert len(await AuditRepository.list(session, since=utcnow() - timedelta(minutes=5))) == 1
    assert await AuditRepository.list(session, since=utcnow() + timedelta(days=1)) == []


async def test_audit_purge_older_than(session: AsyncSession):
    """§4.7/§12.7: удаляются только записи старше cutoff."""
    cutoff = utcnow() - timedelta(days=30)
    await session.commit()
    await AuditRepository.write(session, "node.created", subject_id="stale-1")
    await AuditRepository.write(session, "node.created", subject_id="stale-2")
    stale_ids = {row.id for row in await AuditRepository.list(session, event="node.created")}
    await session.execute(
        AuditLogRow.__table__.update().where(AuditLogRow.id.in_(stale_ids)).values(created_at=cutoff - timedelta(days=10))
    )
    await AuditRepository.write(session, "node.updated", subject_id="fresh")
    await session.commit()

    deleted = await AuditRepository.purge_older_than(session, cutoff)
    await session.commit()

    assert deleted == 2
    rows = await AuditRepository.list(session)
    assert [r.subject_id for r in rows] == ["fresh"]
    # повторная очистка тем же порогом не находит ничего
    assert await AuditRepository.purge_older_than(session, cutoff) == 0
    assert await AuditRepository.list(session, event="node.created") == []
    # порог в будущем удаляет остаток
    assert await AuditRepository.purge_older_than(session, utcnow() + timedelta(days=1)) == 1
    await session.commit()
    assert await AuditRepository.list(session) == []
