"""Node Registry service (§3.2.4) — единая точка управления жизненным циклом узла.

Связывает реестр (БД), рантайм-пул (:mod:`foa.services.balancer`), согласие
(:mod:`foa.services.consent`) и health-checker (:mod:`foa.services.health`).

Отзыв согласия (§5.5) применяет исключение из маршрутизации сразу: ``routable``
сбрасывается в рантайме до возврата HTTP-ответа, поэтому целевые ≤5 с выполняются
в пределах одного процесса шлюза.
"""

from __future__ import annotations

import time
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from foa.config import Settings
from foa.domain.enums import BlacklistReason, ConsentStatus, NodeState
from foa.domain.errors import ForbiddenError, InvalidRequestError, NotFoundError
from foa.ids import owner_id
from foa.logging import get_logger
from foa.net.security import assert_endpoint_resolvable, parse_endpoint
from foa.observability import metrics
from foa.services.balancer import NodePool, build_runtime
from foa.services.consent import ConsentService
from foa.services.state import breaker_from_config
from foa.storage.models import BlacklistRow, NodeRow, utcnow
from foa.storage.repositories import (
    AuditRepository,
    BlacklistRepository,
    ConsentRepository,
    NodeRepository,
    OwnerRepository,
)

log = get_logger("nodes")


class NodeService:
    def __init__(
        self,
        settings: Settings,
        pool: NodePool,
        consent: ConsentService,
        transport,
        health_checker=None,
    ) -> None:
        self.settings = settings
        self.pool = pool
        self.consent = consent
        self.transport = transport
        self.health = health_checker

    # ------------------------------------------------------------------ #
    # Реестр
    # ------------------------------------------------------------------ #

    async def list_nodes(self, session: AsyncSession, *, states: list[str] | None = None) -> list[NodeRow]:
        return await NodeRepository.list_all(session, states=states)

    async def get_node(self, session: AsyncSession, node_id: str) -> NodeRow:
        row = await NodeRepository.get_with_owner(session, node_id)
        if row is None:
            raise NotFoundError(f"узел {node_id} не найден")
        return row

    async def detail(self, session: AsyncSession, node_id: str) -> dict:
        row = await self.get_node(session, node_id)
        consent = await ConsentRepository.latest_for_node(session, row.node_id)
        runtime = self.pool.get(row.node_id)
        return {
            "node_id": row.node_id,
            "endpoint": row.endpoint,
            "display_name": row.display_name,
            "owner_id": row.owner_id,
            "status": row.status,
            "consent_status": consent.status if consent else ConsentStatus.NONE.value,
            "consent_id": consent.consent_id if consent else None,
            "consent_expires_at": consent.expires_at.isoformat() if consent and consent.expires_at else None,
            "models": row.observed_models or row.allowed_models or row.declared_models,
            "declared_models": row.declared_models,
            "allowed_models": row.allowed_models,
            "max_concurrency": row.max_concurrency,
            "max_requests_per_hour": row.max_requests_per_hour,
            "weight": row.weight,
            "effective_weight": row.effective_weight,
            "ollama_version": row.ollama_version,
            "routable": bool(runtime.routable) if runtime else False,
            "active_connections": runtime.active if runtime else 0,
            "latency_ms": round((runtime.ewma_latency_ms if runtime else row.ewma_latency_ms), 2),
            "error_rate": round((runtime.error_rate if runtime else row.error_rate), 4),
            "last_health_check": row.last_health_check.isoformat() if row.last_health_check else None,
            "last_consent_check": row.last_consent_check.isoformat() if row.last_consent_check else None,
            "functional_check_enabled": row.functional_check_enabled,
        }

    # ------------------------------------------------------------------ #
    # Регистрация владельцем (§9.6.2)
    # ------------------------------------------------------------------ #

    async def register(
        self,
        session: AsyncSession,
        *,
        endpoint: str,
        owner_ref: str = "",
        display_name: str = "",
        models: list[str] | None = None,
        max_concurrency: int = 2,
        max_requests_per_hour: int = 1000,
        max_tokens_per_hour: int | None = None,
        consent_method: str = "http_well_known",
        data_policy: dict | None = None,
        contact: str = "",
        public_key: str = "",
        weight: int = 1,
        actor: str = "owner",
    ) -> tuple[NodeRow, str, str]:
        """Создаёт узел в ``pending_consent`` и возвращает ``(узел, challenge, consent_url)``."""
        parsed = parse_endpoint(endpoint)
        allowed_networks = self._discovery_allowed_networks()
        assert_endpoint_resolvable(
            parsed,
            allow_loopback=self.settings.security.allow_loopback_nodes,
            allowed_networks=allowed_networks,
            pins=self.transport.pins,
        )
        if await BlacklistRepository.is_endpoint_blocked(session, parsed.origin):
            raise ForbiddenError("адрес узла в блэклисте")
        owner_ref = owner_ref or owner_id()
        node, _consent = await self.consent.enroll(
            session,
            endpoint=parsed.origin,
            owner_ref=owner_ref,
            display_name=display_name,
            models=models,
            max_concurrency=max_concurrency,
            max_requests_per_hour=max_requests_per_hour,
            consent_method=consent_method,
            data_policy=data_policy,
            contact=contact,
            public_key=public_key,
            weight=weight,
        )
        if max_tokens_per_hour:
            node.max_tokens_per_hour = max_tokens_per_hour
            await session.flush()
        await AuditRepository.write(
            session,
            "node.registered",
            actor=actor,
            subject_type="node",
            subject_id=node.node_id,
            detail={"endpoint": node.endpoint, "method": consent_method},
        )
        await self.sync_pool(session)
        consent_url = f"{node.endpoint}/.well-known/free-ollama/v1/consent.json"
        return node, node.challenge_token, consent_url

    async def set_public_key(self, session: AsyncSession, owner_ref: str, public_key: str, *, key_type: str = "ed25519") -> None:
        await OwnerRepository.get_or_create(session, owner_ref)
        await OwnerRepository.set_public_key(session, owner_ref, public_key, key_type)
        await AuditRepository.write(session, "owner.public_key_set", actor="owner", subject_type="owner", subject_id=owner_ref)

    # ------------------------------------------------------------------ #
    # Верификация / согласие
    # ------------------------------------------------------------------ #

    async def verify_ownership(
        self, session: AsyncSession, node_id: str, *, method: str | None = None, signed_token: str | None = None, actor: str = "owner"
    ) -> dict:
        node = await self.get_node(session, node_id)
        consent = await self.consent.verify(session, node_id_=node.node_id, method=method, signed_token=signed_token, actor=actor)
        await AuditRepository.write(
            session,
            "node.verified",
            actor=actor,
            subject_type="node",
            subject_id=node.node_id,
            detail={"consent_id": consent.consent_id, "method": consent.method},
        )
        await self.sync_pool(session)
        if self.health is not None:
            runtime = self.pool.get(node.node_id)
            await self.health.force_check(session, node, runtime)
            await self.sync_pool(session)
        return {
            "node_id": node.node_id,
            "status": node.status,
            "consent_id": consent.consent_id,
            "consent_status": consent.status,
            "expires_at": consent.expires_at.isoformat() if consent.expires_at else None,
            "allowed_models": consent.allowed_models,
        }

    async def revoke_consent(self, session: AsyncSession, node_id: str, *, reason: str = "owner_revoked", actor: str = "owner") -> dict:
        """§5.5 — немедленное исключение из пула (цель ≤5 с)."""
        started = time.monotonic()
        node = await self.get_node(session, node_id)
        consent = await self.consent.revoke(session, node, reason=reason, actor=actor)
        # Мгновенное снятие флага маршрутизации в рантайме — до commit'а БД.
        runtime = self.pool.get(node.node_id)
        if runtime is not None:
            runtime.routable = False
            runtime.state = NodeState.REVOKED
        await AuditRepository.write(
            session, "node.consent_revoked", actor=actor, subject_type="node", subject_id=node.node_id, detail={"reason": reason}
        )
        await self.sync_pool(session)
        lag = time.monotonic() - started
        metrics.CONSENT_REVOCATION_LAG_SECONDS.observe(lag)
        log.info(
            "nodes:revoked",
            extra={"foa": {"event": "node.consent_revoked", "node_id": node.node_id, "lag_seconds": round(lag, 4), "actor": actor}},
        )
        return {"node_id": node.node_id, "status": "revoked", "applied_in_seconds": round(lag, 3), "consent_id": consent.consent_id}

    # ------------------------------------------------------------------ #
    # Блокировки (§6.4, §12.4.4)
    # ------------------------------------------------------------------ #

    async def blacklist(
        self,
        session: AsyncSession,
        node_id: str,
        *,
        reason: str = "admin_manual",
        duration: str = "permanent",
        seconds: int | None = None,
        note: str = "",
        actor: str = "admin",
    ) -> dict:
        node = await self.get_node(session, node_id)
        permanent = duration == "permanent"
        expires = None if permanent else utcnow() + timedelta(seconds=seconds or 3600)
        await BlacklistRepository.add(
            session,
            BlacklistRow(
                node_id=node.node_id,
                endpoint=node.endpoint,
                reason=reason[:120],
                detail=note[:500],
                actor=actor,
                permanent=permanent,
                expires_at=expires,
            ),
        )
        runtime = self.pool.get(node.node_id)
        if runtime is not None:
            runtime.routable = False
            runtime.breaker.force_open()
        await self._transition(session, node, NodeState.BLACKLISTED)
        await AuditRepository.write(
            session, "node.blacklisted", actor=actor, subject_type="node", subject_id=node.node_id, detail={"reason": reason, "permanent": permanent}
        )
        metrics.NODE_BLACKLIST_TOTAL.inc()
        await self.sync_pool(session)
        return {"node_id": node.node_id, "status": NodeState.BLACKLISTED.value, "reason": reason, "expires_at": expires.isoformat() if expires else None}

    async def lift_blacklist(self, session: AsyncSession, node_id: str, *, actor: str = "admin") -> dict:
        node = await self.get_node(session, node_id)
        lifted = await BlacklistRepository.lift(session, node_id)
        if not lifted:
            raise InvalidRequestError("для узла нет активной блокировки")
        await self._transition(session, node, NodeState.PENDING_CONSENT)
        await AuditRepository.write(session, "node.blacklist_lifted", actor=actor, subject_type="node", subject_id=node_id)
        await self.sync_pool(session)
        return {"node_id": node_id, "status": NodeState.PENDING_CONSENT.value, "note": "требуется повторное подтверждение согласия"}

    async def set_draining(self, session: AsyncSession, node_id: str, *, draining: bool, actor: str = "admin") -> dict:
        node = await self.get_node(session, node_id)
        if node.status in {NodeState.CANDIDATE.value, NodeState.PENDING_CONSENT.value}:
            raise InvalidRequestError("узел ещё не готов к обслуживанию")
        await self._transition(session, node, NodeState.DRAINING if draining else NodeState.VERIFIED)
        await AuditRepository.write(
            session, "node.draining" if draining else "node.draining_stopped", actor=actor, subject_type="node", subject_id=node_id
        )
        await self.sync_pool(session)
        return {"node_id": node_id, "status": node.status, "draining": draining}

    async def patch(self, session: AsyncSession, node_id: str, *, actor: str = "admin", **fields) -> dict:
        node = await self.get_node(session, node_id)
        changed: dict = {}
        for key, value in fields.items():
            if value is None:
                continue
            if key == "draining":
                return await self.set_draining(session, node_id, draining=bool(value), actor=actor)
            if not hasattr(node, key):
                raise InvalidRequestError(f"неизвестное поле узла: {key}")
            setattr(node, key, value)
            changed[key] = value
        if "max_concurrency" in changed:
            runtime = self.pool.get(node_id)
            if runtime:
                runtime.max_concurrency = node.max_concurrency
        if "weight" in changed:
            node.effective_weight = node.weight
        await session.flush()
        await AuditRepository.write(session, "node.updated", actor=actor, subject_type="node", subject_id=node_id, detail=changed)
        await self.sync_pool(session)
        return {"node_id": node_id, "updated": sorted(changed)}

    async def delete(self, session: AsyncSession, node_id: str, *, actor: str = "admin") -> dict:
        """Удаление узла по запросу владельца (§4.7, §12.7.7)."""
        node = await self.get_node(session, node_id)
        await AuditRepository.write(session, "node.deleted", actor=actor, subject_type="node", subject_id=node_id, detail={"endpoint_hash": _hash(node.endpoint)})
        runtime = self.pool.get(node_id)
        if runtime is not None:
            runtime.routable = False
        await NodeRepository.delete_cascade(session, node_id)
        self.pool.nodes.pop(node_id, None)
        await self.sync_pool(session)
        return {"node_id": node_id, "status": "deleted"}

    # ------------------------------------------------------------------ #
    # Синхронизация рантайм-пула
    # ------------------------------------------------------------------ #

    async def sync_pool(self, session: AsyncSession) -> dict[str, int]:
        rows = await NodeRepository.list_all(session)
        candidates: list[tuple] = []
        for row in rows:
            consent = await ConsentRepository.latest_for_node(session, row.node_id)
            runtime = self.pool.get(row.node_id)
            if runtime is None:
                runtime = build_runtime(row, ConsentService.consent_is_active(consent))
                runtime.breaker = breaker_from_config(self.settings.circuit_breaker)
                runtime.passive_window_seconds = self.settings.health.passive_window_seconds
                runtime.ewma_alpha = self.settings.load_balancer.ewma_alpha
            runtime.state = NodeState(row.status)
            runtime.max_concurrency = row.max_concurrency
            runtime.max_requests_per_hour = row.max_requests_per_hour
            runtime.max_tokens_per_hour = row.max_tokens_per_hour
            runtime.weight = row.weight
            runtime.effective_weight = row.effective_weight
            runtime.models = tuple(row.observed_models or [])
            runtime.allowed_models = tuple(row.allowed_models or row.declared_models or [])
            runtime.endpoint = row.endpoint
            runtime.routable = runtime.state in {NodeState.VERIFIED, NodeState.HEALTHY, NodeState.DEGRADED} and ConsentService.consent_is_active(
                consent
            )
            candidates.append((runtime, ConsentService.consent_is_active(consent)))
        summary = self.pool.sync(candidates)
        self._update_gauges(summary)
        return summary

    def _update_gauges(self, summary: dict[str, int]) -> None:
        for node_id_, runtime in self.pool.nodes.items():
            metrics.NODE_HEALTH_STATUS.labels(node_id=node_id_, state=runtime.state.value).set(1)
            metrics.NODE_LATENCY_MS.labels(node_id=node_id_).set(runtime.ewma_latency_ms)
            metrics.NODE_ERROR_RATE.labels(node_id=node_id_).set(runtime.error_rate)
            metrics.NODE_WEIGHT.labels(node_id=node_id_).set(runtime.effective_weight)
            metrics.CIRCUIT_BREAKER_STATE.labels(node_id=node_id_).set(runtime.breaker.state)
            metrics.ACTIVE_UPSTREAM_CONNECTIONS.labels(node_id=node_id_).set(runtime.active)

    def _discovery_allowed_networks(self) -> list[str]:
        out: list[str] = []
        for cfg in self.settings.discovery.sources.values():
            out.extend(cfg.allowed_scopes or [])
        return out

    async def _transition(self, session: AsyncSession, row: NodeRow, target: NodeState) -> None:
        old = NodeState(row.status)
        await NodeRepository.set_status(session, row.node_id, target.value)
        row.status = target.value
        metrics.NODE_HEALTH_STATUS.labels(node_id=row.node_id, state=old.value).set(0)
        metrics.NODE_HEALTH_STATUS.labels(node_id=row.node_id, state=target.value).set(1)

    # ------------------------------------------------------------------ #
    # Пассивный учёт результатов запроса (вызывает прокси)
    # ------------------------------------------------------------------ #

    async def observe(
        self,
        session: AsyncSession | None,
        node_id: str,
        *,
        ok: bool,
        latency_ms: float,
        status: int,
        tokens: int = 0,
    ) -> None:
        """Пассивный учёт фактического поведения узла (§6.3) + авто-реакции (§6.4)."""
        node = self.pool.get(node_id)
        if node is None:
            return
        node.observe(ok=ok, latency_ms=latency_ms, status=status, tokens=tokens)
        if not ok:
            metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=node_id, kind="passive").inc()
        if node.auth_error and node.routable:
            node.routable = False
            node.breaker.force_open()
            if session is not None:
                await self.blacklist_auto(session, node_id, status)
        elif node.error_rate > self.settings.health.passive_error_rate_threshold and node.routable:
            node.effective_weight = max(1, node.weight // 2)  # §7.7 — понижение веса
            log.info(
                "nodes:degraded_weight",
                extra={"foa": {"event": "node.degraded_weight", "node_id": node_id, "error_rate": round(node.error_rate, 3)}},
            )

    async def blacklist_auto(self, session: AsyncSession, node_id: str, status: int) -> None:
        """§6.4/FR-H-05 — 401/403 от узла: немедленный блэклист без ручного подтверждения."""
        node = await NodeRepository.get(session, node_id)
        if node is None:
            return
        await BlacklistRepository.add(
            session,
            BlacklistRow(
                node_id=node_id,
                endpoint=node.endpoint,
                reason=BlacklistReason.UPSTREAM_AUTH_ERROR.value,
                detail=f"client request received HTTP {status}",
                actor="gateway",
                permanent=True,
            ),
        )
        await self._transition(session, node, NodeState.BLACKLISTED)
        consent = await ConsentRepository.latest_for_node(session, node_id)
        if consent is not None and consent.status == ConsentStatus.VERIFIED.value:
            consent.status = ConsentStatus.FAILED.value
            await ConsentRepository.update(session, consent, event="failed_auth_error", actor="gateway", detail={"status": status})
        await AuditRepository.write(
            session, "node.auto_blacklisted", actor="gateway", subject_type="node", subject_id=node_id, detail={"http_status": status}
        )
        metrics.NODE_BLACKLIST_TOTAL.inc()
        await self.sync_pool(session)
        # Блокировка фиксируется до выброса ошибки: иначе session_scope откатит
        # транзакцию вместе с 502-ответом и узел останется в пуле (§6.4, FR-H-05).
        await session.commit()
        log.warning("nodes:auto_blacklisted", extra={"foa": {"event": "node.auto_blacklisted", "node_id": node_id, "http_status": status}})


def _hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()[:16]


__all__ = ["NodeService"]
