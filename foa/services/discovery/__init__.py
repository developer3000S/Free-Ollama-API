"""Discovery-конвейер (§4).

Конвейер: ``Источник → Кандидат → Дедупликация → Оценка риска → Реестр кандидатов``.

Инварианты безопасности:

* ни один кандидат не получает статус, допускающий маршрутизацию (§4.4.4, FR-D-04);
* запись из источника отклоняется, если не попала в ``allowed_scopes`` (§4.6);
* активное сканирование чужих сетей запрещено (§4.3) — источники только
  пассивные (официальные API), и они выключены по умолчанию (FR-D-07);
* кандидаты хранятся отдельно от узлов и автоудаляются по истечении срока (§4.7).
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from foa.config import DiscoveryConfig, Settings, SourceConfig
from foa.domain.enums import CandidateStatus, DiscoveryMode
from foa.ids import candidate_id
from foa.logging import get_logger
from foa.observability import metrics
from foa.services.discovery.cache import ResponseCache
from foa.services.discovery.rate_limit import MinuteRateLimiter
from foa.services.discovery.scopes import ScopeSet
from foa.services.discovery.sources import SourceCandidate, source_for
from foa.storage.models import CandidateRow, utcnow
from foa.storage.repositories import CandidateRepository

log = get_logger("discovery")


@dataclass(slots=True)
class IngestOutcome:
    created: int = 0
    deduped: int = 0
    out_of_scope: int = 0
    manual_review: int = 0
    rejected: int = 0

    def merge(self, other: IngestOutcome) -> IngestOutcome:
        for attr in ("created", "deduped", "out_of_scope", "manual_review", "rejected"):
            setattr(self, attr, getattr(self, attr) + getattr(other, attr))
        return self

    def as_dict(self) -> dict[str, int]:
        return {
            "created": self.created,
            "deduped": self.deduped,
            "out_of_scope": self.out_of_scope,
            "manual_review": self.manual_review,
            "rejected": self.rejected,
        }


@dataclass
class DiscoveryService:
    settings: Settings
    http_client=None  # инъекция транспорта в тестах
    _ratelimits: dict[str, MinuteRateLimiter] = field(default_factory=dict, repr=False)
    _cache: ResponseCache = field(default_factory=ResponseCache, repr=False)

    # ------------------------------------------------------------------ #
    # Конфигурация источников
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> DiscoveryConfig:
        return self.settings.discovery

    def _enabled_sources(self) -> dict[str, SourceConfig]:
        return {name: cfg for name, cfg in self.config.sources.items() if cfg.enabled}

    def active_sources(self) -> list[str]:
        """Источники, реально допущенные к опросу в текущем режиме."""
        if not self.config.enabled or self.config.mode == DiscoveryMode.DISABLED.value:
            return []
        out: list[str] = []
        for name, cfg in self._enabled_sources().items():
            if cfg.purpose not in {"inventory", "research", "risk_enrichment"}:
                continue
            if self.config.mode == DiscoveryMode.INVENTORY_ONLY.value and not cfg.allowed_scopes:
                # Инвентаризация разрешена только по явно заданным областям (§4.3).
                continue
            out.append(name)
        return sorted(out)

    # ------------------------------------------------------------------ #
    # Опрос источников
    # ------------------------------------------------------------------ #

    async def collect(self) -> dict[str, list[SourceCandidate]]:
        """Опрашивает активные источники (кэш + rate limit), ничего не записывая."""
        collected: dict[str, list[SourceCandidate]] = {}
        for name in self.active_sources():
            cfg = self.config.sources[name]
            limiter = self._ratelimits.setdefault(name, MinuteRateLimiter(cfg.max_requests_per_minute))
            cached = self._cache.get(name)
            if cached is not None:
                collected[name] = cached
                continue
            if not limiter.allow():
                log.info("discovery:rate_limited", extra={"foa": {"event": "discovery.rate_limited", "source": name}})
                continue
            source = source_for(name, cfg, http_client=self.http_client)
            try:
                results = await source.fetch()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "discovery:source_error",
                    extra={"foa": {"event": "discovery.source_error", "source": name, "error": str(exc)[:200]}},
                )
                results = []
            self._cache.put(name, results, ttl=cfg.cache_ttl_seconds)
            collected[name] = results
        return collected

    async def ingest(self, session: AsyncSession, candidates: Iterable[SourceCandidate], *, source_name: str = "") -> IngestOutcome:
        """Нормализация → фильтр scope → дедупликация → риск → хранение со статусом ``candidate``."""
        outcome = IngestOutcome()
        for item in candidates:
            source = item.source or source_name
            cfg = self.config.sources.get(source)
            scopes = ScopeSet(cfg.allowed_scopes if cfg else [])
            if not scopes.allows(item.ip, dns_names=item.dns_names, asn=item.asn):
                # §4.6: «Если источник вернул хост вне allowed_scopes — отклонить запись»
                outcome.out_of_scope += 1
                metrics.CANDIDATES_TOTAL.labels(source=source, outcome="out_of_scope").inc()
                log.info(
                    "discovery:out_of_scope",
                    extra={"foa": {"event": "discovery.out_of_scope", "source": source, "candidate_ip": item.ip, "port": item.port}},
                )
                continue
            row = self._to_row(item, source)
            stored, created = await CandidateRepository.upsert(session, row)
            if created:
                outcome.created += 1
                metrics.CANDIDATES_TOTAL.labels(source=source, outcome="created").inc()
            else:
                outcome.deduped += 1
                metrics.CANDIDATES_TOTAL.labels(source=source, outcome="deduped").inc()
            if stored.risk_score >= self.config.risk_manual_review_threshold:
                if stored.status == CandidateStatus.CANDIDATE.value:
                    await CandidateRepository.set_status(session, stored.candidate_id, CandidateStatus.REQUIRES_MANUAL_REVIEW.value)
                outcome.manual_review += 1
        await session.flush()
        metrics.CANDIDATE_QUEUE_SIZE.set(await CandidateRepository.count(session))
        return outcome

    async def run_cycle(self, session: AsyncSession) -> dict[str, object]:
        """Один полный цикл обнаружения."""
        collected = await self.collect()
        outcome = IngestOutcome()
        for name, items in collected.items():
            outcome.merge(await self.ingest(session, items, source_name=name))
        purged = await self.purge_expired(session)
        return {"sources": sorted(collected), **outcome.as_dict(), "purged": purged}

    async def purge_expired(self, session: AsyncSession) -> int:
        cutoff = utcnow() - timedelta(days=max(1, self.config.retain_days))
        deleted = await CandidateRepository.purge_older_than(session, cutoff)
        if deleted:
            metrics.CANDIDATE_QUEUE_SIZE.set(await CandidateRepository.count(session))
            log.info("discovery:purged", extra={"foa": {"event": "discovery.purged", "count": deleted}})
        return deleted

    async def delete_candidate(self, session: AsyncSession, candidate_id_: str) -> int:
        """Право владельца на удаление данных по запросу (§4.7, §12.7.7)."""
        deleted = await CandidateRepository.delete(session, candidate_id_)
        if deleted:
            metrics.CANDIDATE_QUEUE_SIZE.set(await CandidateRepository.count(session))
        return deleted

    # ------------------------------------------------------------------ #
    # Нормализация и оценка риска (§4.4.1, §4.4.3)
    # ------------------------------------------------------------------ #

    def _to_row(self, item: SourceCandidate, source: str) -> CandidateRow:
        score, factors = self.assess_risk(item)
        return CandidateRow(
            candidate_id=candidate_id(),
            source=source,
            sources=[source],
            observed_at=item.observed_at or utcnow(),
            ip=item.ip,
            port=item.port,
            protocol=item.protocol or "tcp",
            dns_names=list(item.dns_names)[:20],
            asn=item.asn or "",
            country=item.country or "",
            service_hint=item.service_hint or "",
            banner_hash=item.banner_hash or "",
            risk_score=score,
            risk_factors=factors,
            status=CandidateStatus.CANDIDATE.value,  # §4.4.4 — только candidate
            raw_ref={"fields": item.extra} if item.extra else {},
            expires_at=utcnow() + timedelta(days=max(1, self.config.retain_days)),
        )

    def assess_risk(self, item: SourceCandidate) -> tuple[int, list[str]]:
        """Оценка риска (§4.4.3). Чем выше балл, тем подозрительнее кандидат."""
        score = 0
        factors: list[str] = []
        try:
            addr = ipaddress.ip_address(item.ip)
        except ValueError:
            return 100, ["invalid_ip"]
        if addr.is_private or addr.is_loopback:
            score += 40
            factors.append("non_public_address")
        if addr.is_reserved or addr.is_multicast or addr.is_link_local:
            score += 30
            factors.append("reserved_address_range")
        if item.service_hint and item.service_hint not in {"ollama", "http", "https", "unknown", ""}:
            score += 10
            factors.append("unexpected_service")
        if item.port != 11434:
            score += 10
            factors.append("non_default_port")
        if item.hosted_on_known_cloud:
            score += 15
            factors.append("cloud_hosting")
        if item.open_proxy_suspected:
            score += 20
            factors.append("open_proxy_signals")
        if item.seen_in_blocklists:
            score += 25
            factors.append("blocklist_match")
        if item.abuse_history:
            score += 20
            factors.append("abuse_history")
        if item.age_seconds > 86_400 * 7:
            score += 5
            factors.append("stale_observation")
        if not item.matches_expected_profile:
            score += 15
            factors.append("profile_mismatch")
        return max(0, min(100, score)), factors


__all__ = ["DiscoveryService", "IngestOutcome", "SourceCandidate"]
