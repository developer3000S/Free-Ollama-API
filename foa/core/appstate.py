"""Контейнер состояния шлюза: связывает сервисы в одно приложение."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

from foa.config import Settings
from foa.net.client import NodeTransport
from foa.services.auth import AuthService
from foa.services.balancer import NodePool
from foa.services.consent import ConsentService
from foa.services.discovery import DiscoveryService
from foa.services.health import HealthChecker
from foa.services.nodes import NodeService
from foa.services.proxy import ProxyService
from foa.services.ratelimit import RateLimiter
from foa.storage.db import get_session_factory
from foa.storage.repositories import ApiKeyRepository


@dataclass
class AppState:
    settings: Settings
    transport: NodeTransport
    pool: NodePool
    ratelimit: RateLimiter
    auth: AuthService
    consent: ConsentService
    nodes: NodeService
    health: HealthChecker
    discovery: DiscoveryService
    proxy: ProxyService
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    tasks: list[Any] = field(default_factory=list)
    started_at: float = 0.0
    session_factory: Any = None

    def factory(self):
        return self.session_factory or get_session_factory()

    async def start_background(self) -> None:
        """Запускает фоновые циклы согласно роли процесса (§3.2.5, §3.2.6, §14.1).

        Роль ``gateway`` (``server.run_background_loops=true``) ведёт все циклы
        сама. В мультирепликовом развёртывании цикл проверок оставляют одному
        экземпляру (``health-checker``/``discovery-worker``), а проксирующие
        реплики получают только перечитывание реестра: иначе каждая реплика
        утроит нагрузку на узлы (§6.1).
        """
        if self.settings.server.run_background_loops:
            self.tasks.append(asyncio.create_task(self.health.run_forever(self.factory(), self.stop), name="foa-health"))
            if self.settings.discovery.enabled and self.settings.discovery.mode != "disabled":
                self.tasks.append(asyncio.create_task(self._discovery_loop(), name="foa-discovery"))
            self.tasks.append(asyncio.create_task(self._consent_expiry_loop(), name="foa-consent-expiry"))
        else:
            self.tasks.append(asyncio.create_task(self._registry_sync_loop(), name="foa-registry-sync"))

    async def _registry_sync_loop(self) -> None:
        """Проксирующая реплика: периодическое перечитывание реестра из БД (§14.1)."""
        from foa.logging import get_logger

        log = get_logger("app")
        interval = max(1.0, self.settings.server.registry_sync_interval_seconds)
        while not self.stop.is_set():
            try:
                async with self.factory()() as session:
                    await self.nodes.sync_pool(session)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("registry sync: итерация завершилась ошибкой: %s", exc)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=interval)
            except TimeoutError:
                pass

    async def _discovery_loop(self) -> None:
        from foa.storage.repositories import AuditRepository

        interval = max(60, self.settings.discovery.scan_interval_seconds)
        while not self.stop.is_set():
            try:
                if self.discovery.active_sources():
                    async with self.factory()() as session:
                        summary = await self.discovery.run_cycle(session)
                        await AuditRepository.write(session, "discovery.cycle", subject_type="discovery", detail=summary)
                        await session.commit()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                from foa.logging import get_logger

                get_logger("app").warning("discovery: цикл завершился ошибкой: %s", exc)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=interval)
            except TimeoutError:
                pass

    async def _consent_expiry_loop(self) -> None:
        """§5.4 — перепроверка не реже 1 раза в сутки + уведомление о скором истечении."""
        from datetime import timedelta

        from foa.logging import get_logger
        from foa.storage.repositories import AuditRepository, ConsentRepository

        log = get_logger("app")
        interval = min(3600, max(60, self.settings.health.consent_recheck_interval_seconds))
        while not self.stop.is_set():
            try:
                async with self.factory()() as session:
                    expired = await ConsentRepository.list_expired(session, _utcnow())
                    for consent in expired:
                        node = await self.nodes.get_node(session, consent.node_id)
                        await self.consent.revoke(session, node, reason="expired", actor="system")
                        await AuditRepository.write(session, "consent.expired", actor="system", subject_type="node", subject_id=consent.node_id)
                    expiring = await ConsentRepository.list_expiring(session, _utcnow(), timedelta(days=7))
                    for consent in expiring:
                        await AuditRepository.write(
                            session,
                            "consent.expiry_warning",
                            actor="system",
                            subject_type="node",
                            subject_id=consent.node_id,
                            detail={"consent_id": consent.consent_id, "expires_at": consent.expires_at.isoformat()},
                        )
                    if expired:
                        await self.nodes.sync_pool(session)
                    await session.commit()
                    if expired:
                        log.info("consent:expired_revoked", extra={"foa": {"event": "consent.expired_revoked", "count": len(expired)}})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("consent: цикл перепроверки завершился ошибкой: %s", exc)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=interval)
            except TimeoutError:
                pass

    async def shutdown(self) -> None:
        self.stop.set()
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self.tasks.clear()
        await self.transport.aclose()

    # -- вспомогательное для обработки результатов запросов ---------------- #

    async def record_tokens(self, key_id: str, tokens: int) -> None:
        self.ratelimit.add_tokens(key_id, tokens)

    async def issue_key(self, **kwargs):
        async with self.factory()() as session:
            row, raw = await self.auth.issue_key(session, **kwargs)
            await session.commit()
            return row, raw

    async def list_keys(self, *, include_revoked: bool = False):
        async with self.factory()() as session:
            return await ApiKeyRepository.list(session, include_revoked=include_revoked)


def _utcnow():
    from datetime import datetime

    return datetime.now(UTC)


__all__ = ["AppState"]
