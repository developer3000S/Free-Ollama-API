"""Health Checker (§6).

Активные проверки: liveness (``/api/version``), readiness (``/api/tags``),
capability (наличие заявленных моделей), consent re-check (§5.4), опциональная
функциональная проверка (§6.2.5 — по умолчанию выключена).

Пассивные проверки учитываются в :mod:`foa.services.state` (скользящее окно).

Переходы состояний — таблица §6.4:

==========================================  =====================================
Событие                                     Действие
==========================================  =====================================
3 ошибки liveness подряд                    ``unhealthy``
Ошибка согласия                             ``quarantined``
401/403 от узла                             ``blacklisted`` немедленно
>20% ошибок за 60 с                         ``degraded`` → ``unhealthy``
Отзыв согласия владельцем                   немедленное исключение из пула
Ручная блокировка администратором           ``blacklisted``
==========================================  =====================================
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from foa.config import Settings
from foa.domain.enums import (
    ACTIVE_HEALTH_CHECK_STATES,
    ROUTABLE_STATES,
    BlacklistReason,
    ConsentStatus,
    HealthKind,
    NodeState,
)
from foa.logging import get_logger
from foa.net.client import NodeTransport, UpstreamUnavailable
from foa.net.security import parse_endpoint
from foa.observability import metrics
from foa.services.state import CLOSED, NodeRuntime
from foa.storage.models import BlacklistRow, NodeRow, utcnow
from foa.storage.repositories import BlacklistRepository, ConsentRepository, NodeRepository

log = get_logger("health")

AUTH_ERROR_CODES = {401, 403}
REVOCATION_HEADER = "X-FOA-Consent"

#: Приоритеты разрешения сигналов одного прогона (§6.4): чем выше, тем сильнее
#: и необратимее реакция. Блэклист важнее карантина, карантин — ухудшения.
_PRIORITY_DEGRADED = 10
_PRIORITY_UNHEALTHY = 20
_PRIORITY_QUARANTINE = 30
_PRIORITY_BLACKLIST = 40

#: Строгость состояний. Ослабление состояния (например unhealthy → verified)
#: допускается только как явное восстановление, а не как побочный эффект
#: прогона, в котором проверки не запускались из-за интервалов (§6.4).
_SEVERITY: dict[NodeState, int] = {
    NodeState.PENDING_CONSENT: 0,
    NodeState.CONSENT_CHALLENGE_SENT: 0,
    NodeState.CANDIDATE: 0,
    NodeState.VERIFIED: 1,
    NodeState.HEALTHY: 1,
    NodeState.DRAINING: 2,
    NodeState.DEGRADED: 3,
    NodeState.UNHEALTHY: 4,
    NodeState.QUARANTINED: 5,
    NodeState.REVOKED: 6,
    NodeState.BLACKLISTED: 7,
}


@dataclass(slots=True)
class CheckResult:
    kind: HealthKind
    ok: bool
    status_code: int = 0
    latency_ms: float = 0.0
    detail: dict = field(default_factory=dict)
    error: str = ""

    @property
    def auth_error(self) -> bool:
        return self.status_code in AUTH_ERROR_CODES


class HealthChecker:
    def __init__(
        self,
        settings: Settings,
        transport: NodeTransport,
        consent_service=None,
        on_state_change=None,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self.consent_service = consent_service
        self.on_state_change = on_state_change  # async callable(node_id, old, new, reason)
        self._last_liveness: dict[str, float] = {}
        self._last_readiness: dict[str, float] = {}
        self._last_consent: dict[str, float] = {}
        self._last_functional: dict[str, float] = {}
        self._backoff: dict[str, float] = {}

    # ------------------------------------------------------------------ #
    # Планировщик
    # ------------------------------------------------------------------ #

    async def run_forever(self, session_factory, stop: asyncio.Event) -> None:
        """Фоновый цикл проверок (запускается в lifespan приложения)."""
        log.info("health: цикл проверок запущен (liveness=%ss)", self.settings.health.liveness_interval_seconds)
        while not stop.is_set():
            try:
                async with session_factory() as session:
                    changed = await self.check_all(session)
                    await session.commit()
                if changed:
                    await self._publish(changed)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("health: итерация завершилась ошибкой: %s", exc)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.settings.health.liveness_interval_seconds)
            except TimeoutError:
                pass
        log.info("health: цикл проверок остановлен")

    async def check_all(self, session: AsyncSession) -> list[tuple[str, NodeState, NodeState, str]]:
        changed: list[tuple[str, NodeState, NodeState, str]] = []
        nodes = await NodeRepository.list_all(session)
        now = time.monotonic()
        for row in nodes:
            if row.status in {NodeState.BLACKLISTED.value, NodeState.REVOKED.value}:
                continue
            result = await self.check_node(session, row, now=now)
            if result:
                changed.append(result)
        return changed

    async def _publish(self, changed) -> None:
        if self.on_state_change is None:
            return
        for node_id_, old, new, reason in changed:
            await self.on_state_change(node_id_, old, new, reason)

    # ------------------------------------------------------------------ #
    # Одна итерация по узлу
    # ------------------------------------------------------------------ #

    async def check_node(
        self,
        session: AsyncSession,
        row: NodeRow,
        *,
        now: float | None = None,
        runtime: NodeRuntime | None = None,
        force: bool = False,
    ) -> tuple[str, NodeState, NodeState, str] | None:
        """Один прогон проверок: сигналы собираются и разрешаются ОДИН раз.

        Несколько проверок в одном цикле не должны перекрывать состояние друг
        друга, поэтому каждая порождает сигнал ``(приоритет, цель, причина)``,
        а победитель с наивысшим приоритетом применяется единожды (§6.4).
        """
        now = now or time.monotonic()
        signals: list[tuple[int, NodeState, str]] = []
        # Учёт фактически выполненных проверок: «восстановление» возможно только
        # когда проверки действительно запускались и прошли без замечаний.
        executed = 0
        passed = 0

        def due(buckets: dict[str, float], interval: float, key: str) -> bool:
            if force:
                return True
            return now - buckets.get(key, -1e9) >= interval

        h = self.settings.health
        endpoint = parse_endpoint(row.endpoint)

        # Активные проверки допустимы только для узлов, прошедших согласие
        # (§4.3, §12.3): опрос неподтверждённого хоста был бы генерацией
        # трафика на чужой ресурс без разрешения владельца.
        if not force and NodeState(row.status) not in ACTIVE_HEALTH_CHECK_STATES:
            return None

        # 1) liveness ------------------------------------------------------ #
        if due(self._last_liveness, h.liveness_interval_seconds, row.node_id):
            self._last_liveness[row.node_id] = now
            result = await self.liveness(endpoint, row)
            metrics.HEALTH_CHECK_TOTAL.labels(kind=HealthKind.LIVENESS.value, result="ok" if result.ok else "fail").inc()
            executed += 1
            passed += 1 if result.ok else 0
            if result.ok:
                row.liveness_failures = 0
                row.ollama_version = str(result.detail.get("version") or row.ollama_version)
                self._backoff.pop(row.node_id, None)
            else:
                row.liveness_failures += 1
                self._backoff[row.node_id] = min(300.0, h.liveness_interval_seconds * 2 ** min(5, row.liveness_failures))
                metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=row.node_id, kind=result.kind.value).inc()
                if result.auth_error:
                    # 401/403 от узла → немедленный блэклист независимо от порога (§6.4).
                    signals.append((_PRIORITY_BLACKLIST, NodeState.BLACKLISTED, f"liveness HTTP {result.status_code}"))
                elif row.liveness_failures >= h.liveness_failure_threshold:
                    signals.append((_PRIORITY_UNHEALTHY, NodeState.UNHEALTHY, f"liveness_failures={row.liveness_failures}"))

        # 2) readiness + capability ----------------------------------------- #
        if due(self._last_readiness, h.readiness_interval_seconds, row.node_id):
            self._last_readiness[row.node_id] = now
            result = await self.readiness(endpoint, row)
            metrics.HEALTH_CHECK_TOTAL.labels(kind=HealthKind.READINESS.value, result="ok" if result.ok else "fail").inc()
            executed += 1
            passed += 1 if result.ok else 0
            if result.ok:
                row.readiness_failures = 0
                observed = [str(m.get("name")) for m in result.detail.get("models", []) if isinstance(m, dict) and m.get("name")]
                row.observed_models = observed[:200]
                missing = [m for m in (row.allowed_models or []) if m not in observed]
                metrics.HEALTH_CHECK_TOTAL.labels(kind=HealthKind.CAPABILITY.value, result="fail" if missing else "ok").inc()
                if missing:
                    log.info(
                        "health:capability_missing",
                        extra={"foa": {"event": "health.capability_missing", "node_id": row.node_id, "missing": missing}},
                    )
            else:
                row.readiness_failures += 1
                metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=row.node_id, kind=result.kind.value).inc()
                if result.auth_error:
                    signals.append((_PRIORITY_BLACKLIST, NodeState.BLACKLISTED, f"readiness HTTP {result.status_code}"))
                elif row.readiness_failures >= h.readiness_failure_threshold:
                    signals.append((_PRIORITY_DEGRADED, NodeState.DEGRADED, "readiness_failures"))

        # 3) consent re-check ------------------------------------------------ #
        if due(self._last_consent, h.consent_recheck_interval_seconds, row.node_id):
            self._last_consent[row.node_id] = now
            state_name, reason = await self._consent_status(session, row)
            executed += 1
            passed += 1 if state_name == "active" else 0
            row.last_consent_check = utcnow()
            metrics.HEALTH_CHECK_TOTAL.labels(kind=HealthKind.CONSENT.value, result="ok" if state_name == "active" else "fail").inc()
            metrics.NODE_CONSENT_STATUS.labels(node_id=row.node_id, state=reason).set(1)
            if state_name == "broken":
                # §5.4/§6.4, FR-C-05 — доказанная ошибка согласия: карантин.
                signals.append((_PRIORITY_QUARANTINE, NodeState.QUARANTINED, f"consent:{reason}"))
            elif state_name == "inconclusive":
                # Недоступность узла не является отзывом: решение по liveness.
                log.info("health:consent_inconclusive", extra={"foa": {"event": "health.consent_inconclusive", "node_id": row.node_id, "reason": reason}})

        # 4) функциональная проверка (только по явному согласию владельца) --- #
        if (
            self.settings.health.functional_check_enabled
            and row.functional_check_enabled
            and row.functional_check_model
            and due(self._last_functional, h.functional_check_interval_seconds, row.node_id)
        ):
            self._last_functional[row.node_id] = now
            result = await self.functional(endpoint, row)
            metrics.HEALTH_CHECK_TOTAL.labels(kind=HealthKind.FUNCTIONAL.value, result="ok" if result.ok else "fail").inc()
            executed += 1
            passed += 1 if result.ok else 0
            if not result.ok:
                metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=row.node_id, kind=HealthKind.FUNCTIONAL.value).inc()
                if result.auth_error:
                    signals.append((_PRIORITY_BLACKLIST, NodeState.BLACKLISTED, f"functional HTTP {result.status_code}"))

        # 5) пассивные метрики (§6.3, §6.4, §7.7) ---------------------------- #
        if runtime is not None:
            row.ewma_latency_ms = runtime.ewma_latency_ms
            row.error_rate = runtime.error_rate
            signals.extend(self._passive_signals(row, runtime))

        current = NodeState(row.status)
        recovered = (
            not signals
            and executed > 0
            and passed == executed
            and _SEVERITY.get(current, 0) > _SEVERITY[NodeState.VERIFIED]
            and current is not NodeState.DRAINING
        )
        transition = None
        if signals:
            signals.sort(key=lambda item: (-item[0], item[1].value))
            _, target, reason = signals[0]
            if target is NodeState.BLACKLISTED:
                await self._blacklist(session, row, BlacklistReason.UPSTREAM_AUTH_ERROR, reason)
            else:
                transition = await self._transition(session, row, target, reason=reason)
        elif recovered:
            transition = await self._transition(session, row, NodeState.VERIFIED, reason="checks_recovered")

        row.last_health_check = utcnow()
        await session.flush()
        if runtime is not None:
            runtime.state = NodeState(row.status)
            runtime.routable = NodeState(row.status) in ROUTABLE_STATES and runtime.routable
        metrics.NODE_HEALTH_STATUS.labels(node_id=row.node_id, state=NodeState(row.status).value).set(1)
        return transition

    def _passive_signals(self, row: NodeRow, runtime: NodeRuntime) -> list[tuple[int, NodeState, str]]:
        """Сигналы из пассивного наблюдения: доля ошибок и серии таймаутов (§6.3)."""
        signals: list[tuple[int, NodeState, str]] = []
        threshold = self.settings.health.passive_error_rate_threshold
        rate = runtime.error_rate
        if runtime.auth_error:
            signals.append((_PRIORITY_BLACKLIST, NodeState.BLACKLISTED, "passive 401/403"))
        elif rate > threshold and runtime.state in {NodeState.VERIFIED, NodeState.HEALTHY}:
            row.effective_weight = max(1, runtime.weight // 2)  # §7.7.1
            signals.append((_PRIORITY_DEGRADED, NodeState.DEGRADED, f"passive_error_rate={rate:.2f}"))
        elif rate > threshold and runtime.state is NodeState.DEGRADED:
            signals.append((_PRIORITY_UNHEALTHY, NodeState.UNHEALTHY, f"passive_error_rate={rate:.2f}"))
        elif rate <= threshold / 2 and runtime.state is NodeState.DEGRADED and runtime.breaker.state == CLOSED:
            row.effective_weight = runtime.weight
        if runtime.timeout_streak >= self.settings.health.liveness_failure_threshold and runtime.state in {NodeState.VERIFIED, NodeState.HEALTHY}:
            signals.append((_PRIORITY_DEGRADED, NodeState.DEGRADED, "timeout_streak"))
        return signals

    async def _transition(self, session: AsyncSession, row: NodeRow, target: NodeState, *, reason: str) -> tuple:
        old = NodeState(row.status)
        if old == target:
            return (row.node_id, old, target, reason)
        await NodeRepository.set_status(session, row.node_id, target.value)
        row.status = target.value
        metrics.NODE_HEALTH_STATUS.labels(node_id=row.node_id, state=old.value).set(0)
        metrics.NODE_HEALTH_STATUS.labels(node_id=row.node_id, state=target.value).set(1)
        log.warning(
            "health:transition",
            extra={"foa": {"event": "health.transition", "node_id": row.node_id, "from": old.value, "to": target.value, "reason": reason}},
        )
        if self.on_state_change is not None:
            try:
                await self.on_state_change(row.node_id, old, target, reason)
            except Exception as exc:
                log.warning("health: on_state_change failed: %s", exc)
        return (row.node_id, old, target, reason)

    async def _blacklist(self, session: AsyncSession, row: NodeRow, reason: BlacklistReason, detail: str) -> tuple:
        """§6.4 / §12.4.4 — 401/403 от узла: немедленный блэклист."""
        await BlacklistRepository.add(
            session,
            BlacklistRow(
                node_id=row.node_id,
                endpoint=row.endpoint,
                reason=reason.value,
                detail=detail[:500],
                actor="health-checker",
                permanent=True,
            ),
        )
        metrics.NODE_BLACKLIST_TOTAL.inc()
        changed = await self._transition(session, row, NodeState.BLACKLISTED, reason=f"{reason.value}:{detail}")
        consent = await ConsentRepository.latest_for_node(session, row.node_id)
        if consent is not None and consent.status == ConsentStatus.VERIFIED.value:
            consent.status = ConsentStatus.FAILED.value
            await ConsentRepository.update(session, consent, event="failed_auth_error", actor="health-checker", detail={"detail": detail})
        return changed

    async def _consent_status(self, session: AsyncSession, row: NodeRow) -> tuple[str, str]:
        """Три состояния согласия для прогона: ``active`` / ``broken`` / ``inconclusive``.

        ``broken`` — доказанный отзыв/истечение/несовпадение (→ карантин, §6.4).
        ``inconclusive`` — доказательство не получено из-за недоступности узла:
        это сетевой симптом, решение о выводе принимает liveness, а не реестр
        согласий (§5.4 vs §6.4).
        """
        consent = await ConsentRepository.latest_for_node(session, row.node_id)
        if consent is None:
            return "broken", "missing"
        if consent.status == ConsentStatus.REVOKED.value:
            return "broken", "revoked"
        if consent.status != ConsentStatus.VERIFIED.value:
            return "broken", consent.status
        if consent.expires_at is not None and consent.expires_at <= utcnow():
            consent.status = ConsentStatus.EXPIRED.value
            await ConsentRepository.update(session, consent, event="expired", actor="health-checker")
            return "broken", "expired"
        if self.consent_service is not None:
            proof = await self.consent_service.revalidate(session, row, consent)
            if proof.ok:
                return "active", "active"
            if getattr(proof, "inconclusive", False):
                return "inconclusive", proof.error or "unreachable"
            return "broken", proof.error or "proof_failed"
        return "active", "active"

    # ------------------------------------------------------------------ #
    # Отдельные проверки
    # ------------------------------------------------------------------ #

    async def liveness(self, endpoint, row: NodeRow) -> CheckResult:
        h = self.settings.health
        started = time.monotonic()
        try:
            status, _, body = await self.transport.request(
                endpoint,
                "GET",
                "/api/version",
                timeout=h.liveness_response_timeout_seconds,
                max_concurrency=row.max_concurrency,
            )
        except (TimeoutError, UpstreamUnavailable) as exc:
            return CheckResult(HealthKind.LIVENESS, False, error=str(exc), latency_ms=(time.monotonic() - started) * 1000)
        except Exception as exc:
            return CheckResult(HealthKind.LIVENESS, False, error=str(exc), latency_ms=(time.monotonic() - started) * 1000)
        latency = (time.monotonic() - started) * 1000
        if status != 200:
            return CheckResult(HealthKind.LIVENESS, False, status_code=status, latency_ms=latency, error=f"http_{status}")
        import json

        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return CheckResult(HealthKind.LIVENESS, False, status_code=status, latency_ms=latency, error="bad_version_payload")
        return CheckResult(HealthKind.LIVENESS, True, status_code=status, latency_ms=latency, detail=payload if isinstance(payload, dict) else {})

    async def readiness(self, endpoint, row: NodeRow) -> CheckResult:
        h = self.settings.health
        started = time.monotonic()
        try:
            status, _, body = await self.transport.request(
                endpoint,
                "GET",
                "/api/tags",
                timeout=h.readiness_timeout_seconds,
                max_concurrency=row.max_concurrency,
            )
        except Exception as exc:
            return CheckResult(HealthKind.READINESS, False, error=str(exc), latency_ms=(time.monotonic() - started) * 1000)
        latency = (time.monotonic() - started) * 1000
        if status != 200:
            return CheckResult(HealthKind.READINESS, False, status_code=status, latency_ms=latency, error=f"http_{status}")
        import json

        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return CheckResult(HealthKind.READINESS, False, status_code=status, latency_ms=latency, error="bad_tags_payload")
        models = payload.get("models") if isinstance(payload, dict) else None
        if not isinstance(models, list):
            return CheckResult(
                HealthKind.READINESS, True, status_code=status, latency_ms=latency, detail={"models": []}, error="no_models_field"
            )
        return CheckResult(HealthKind.READINESS, True, status_code=status, latency_ms=latency, detail={"models": models})

    async def functional(self, endpoint, row: NodeRow) -> CheckResult:
        """§6.2.5 — минимальная генерация; только по явному разрешению владельца."""
        body = {
            "model": row.functional_check_model,
            "prompt": "ping",
            "stream": False,
            "options": {"num_predict": 1},
        }
        started = time.monotonic()
        try:
            status, _, _ = await self.transport.request(
                endpoint,
                "POST",
                "/api/generate",
                json_body=body,
                timeout=self.settings.limits.max_generation_seconds,
                max_concurrency=row.max_concurrency,
            )
        except Exception as exc:
            return CheckResult(HealthKind.FUNCTIONAL, False, error=str(exc), latency_ms=(time.monotonic() - started) * 1000)
        latency = (time.monotonic() - started) * 1000
        return CheckResult(HealthKind.FUNCTIONAL, status < 400, status_code=status, latency_ms=latency)

    # ------------------------------------------------------------------ #
    # Принудительные операции для админ-API
    # ------------------------------------------------------------------ #

    async def force_check(self, session: AsyncSession, row: NodeRow, runtime: NodeRuntime | None = None) -> tuple | None:
        return await self.check_node(session, row, runtime=runtime, force=True)

    async def blacklist_node(
        self,
        session: AsyncSession,
        row: NodeRow,
        reason: BlacklistReason,
        *,
        detail: str = "",
        actor: str = "system",
    ) -> None:
        await BlacklistRepository.add(
            session,
            BlacklistRow(node_id=row.node_id, endpoint=row.endpoint, reason=reason.value, detail=detail[:500], actor=actor, permanent=True),
        )
        metrics.NODE_BLACKLIST_TOTAL.inc()
        await self._transition(session, row, NodeState.BLACKLISTED, reason=reason.value)


__all__ = ["REVOCATION_HEADER", "CheckResult", "HealthChecker"]
