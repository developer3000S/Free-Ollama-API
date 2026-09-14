"""Рантайм-состояние узлов, пассивный health-check и circuit breaker (§6.3, §6.5).

Счётчики держатся в памяти процесса шлюза (горизонтально масштабируемо: узлы
и согласия — в БД, состояние нагрузки — локально; см. README, «Масштабирование»).
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field

from foa.config import CircuitBreakerConfig, HealthConfig
from foa.domain.enums import NodeState

CLOSED, HALF_OPEN, OPEN = 0, 1, 2


@dataclass(slots=True)
class CircuitBreaker:
    """§6.5 — разрыватель цепи на узел."""

    window_seconds: float = 30.0
    minimum_requests: int = 10
    error_rate_threshold: float = 0.5
    open_duration_seconds: float = 60.0
    half_open_probes: int = 1

    state: int = CLOSED
    _events: deque[tuple[float, bool]] = field(default_factory=deque, repr=False)
    _opened_at: float = 0.0
    _probes_in_flight: int = 0
    consecutive_failures: int = 0

    def record(self, success: bool, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        self._events.append((now, success))
        self._trim(now)
        if success:
            self.consecutive_failures = 0
            if self.state == HALF_OPEN:
                self.state = CLOSED
                self._probes_in_flight = 0
        else:
            self.consecutive_failures += 1
            if self.state == HALF_OPEN:
                self._trip(now)
        if self.state == CLOSED and self._error_rate(now) >= self.error_rate_threshold:
            self._trip(now)
        return self.state

    def allow(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        self._trim(now)
        if self.state == CLOSED:
            return True
        if self.state == OPEN:
            if now - self._opened_at >= self.open_duration_seconds:
                self.state = HALF_OPEN
                self._probes_in_flight = 0
            else:
                return False
        if self._probes_in_flight >= self.half_open_probes:
            return False
        self._probes_in_flight += 1
        return True

    def _trip(self, now: float) -> None:
        self.state = OPEN
        self._opened_at = now
        self._probes_in_flight = 0

    def _error_rate(self, now: float) -> float:
        self._trim(now)
        total = len(self._events)
        if total < self.minimum_requests:
            return 0.0
        failures = sum(1 for _, ok in self._events if not ok)
        return failures / total

    def _trim(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    @property
    def error_rate(self) -> float:
        return self._error_rate(time.monotonic())

    def force_open(self, now: float | None = None) -> None:
        self._trip(time.monotonic() if now is None else now)

    def reset(self) -> None:
        self.state = CLOSED
        self._events.clear()
        self._probes_in_flight = 0
        self.consecutive_failures = 0


@dataclass(slots=True)
class _Sample:
    at: float
    ok: bool
    latency_ms: float
    status: int


@dataclass
class NodeRuntime:
    """Изменяемое в рантайме состояние узла (не сериализуется в БД)."""

    node_id: str
    endpoint: str
    state: NodeState = NodeState.CANDIDATE
    max_concurrency: int = 2
    weight: int = 1
    effective_weight: int = 1
    active: int = 0
    ewma_latency_ms: float = 0.0
    ewma_alpha: float = 0.3
    samples: deque[_Sample] = field(default_factory=deque, repr=False)
    passive_window_seconds: float = 60.0
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    models: tuple[str, ...] = ()
    allowed_models: tuple[str, ...] = ()
    routable: bool = False
    tokens_this_hour: int = 0
    requests_this_hour: int = 0
    hour_started_at: float = field(default_factory=time.monotonic)
    max_requests_per_hour: int = 1000
    max_tokens_per_hour: int = 0
    requests_this_minute: deque[float] = field(default_factory=deque, repr=False)
    last_error: str = ""
    last_state_change: float = field(default_factory=time.monotonic)
    hourly_requests_total: int = 0

    # -- нагрузка --------------------------------------------------------- #

    def acquire(self) -> bool:
        if self.active >= max(1, self.max_concurrency):
            return False
        self.active += 1
        return True

    def release(self) -> None:
        self.active = max(0, self.active - 1)

    # -- пассивный health-check (§6.3) ------------------------------------ #

    def observe(
        self,
        *,
        ok: bool,
        latency_ms: float,
        status: int = 0,
        now: float | None = None,
        tokens: int = 0,
    ) -> None:
        now = time.monotonic() if now is None else now
        self.ewma_latency_ms = (
            latency_ms if self.ewma_latency_ms == 0 else self.ewma_alpha * latency_ms + (1 - self.ewma_alpha) * self.ewma_latency_ms
        )
        self.samples.append(_Sample(at=now, ok=ok, latency_ms=latency_ms, status=status))
        self._trim_samples(now)
        self.breaker.record(ok, now=now)
        if not ok:
            self.last_error = f"http_{status}" if status else "error"
        if tokens:
            self._roll_hour(now)
            self.tokens_this_hour += tokens

    def _trim_samples(self, now: float) -> None:
        cutoff = now - self.passive_window_seconds
        while self.samples and self.samples[0].at < cutoff:
            self.samples.popleft()

    @property
    def error_rate(self) -> float:
        self._trim_samples(time.monotonic())
        if not self.samples:
            return 0.0
        failures = sum(1 for s in self.samples if not s.ok)
        return failures / len(self.samples)

    @property
    def auth_error(self) -> bool:
        """401/403 от узла → немедленный блэклист (§6.4, FR-H-05)."""
        now = time.monotonic()
        self._trim_samples(now)
        return any(s.status in (401, 403) for s in self.samples)

    @property
    def timeout_streak(self) -> int:
        streak = 0
        for sample in reversed(self.samples):
            if sample.status == 0 and not sample.ok:
                streak += 1
            else:
                break
        return streak

    # -- лимиты узла (§7.5) ----------------------------------------------- #

    def _roll_hour(self, now: float) -> None:
        if now - self.hour_started_at >= 3600:
            self.hour_started_at = now
            self.tokens_this_hour = 0
            self.requests_this_hour = 0

    def note_request(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._roll_hour(now)
        self.requests_this_hour += 1
        self.hourly_requests_total += 1
        self.requests_this_minute.append(now)
        cutoff = now - 60
        while self.requests_this_minute and self.requests_this_minute[0] < cutoff:
            self.requests_this_minute.popleft()

    def rpm(self, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        cutoff = now - 60
        while self.requests_this_minute and self.requests_this_minute[0] < cutoff:
            self.requests_this_minute.popleft()
        return len(self.requests_this_minute)

    def limits_allow(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        self._roll_hour(now)
        if self.max_requests_per_hour and self.requests_this_hour >= self.max_requests_per_hour:
            return False
        return not (self.max_tokens_per_hour and self.tokens_this_hour >= self.max_tokens_per_hour)

    # -- скор для гибридного алгоритма (§7.4) ------------------------------ #

    def score(
        self,
        *,
        capacity_weight: float,
        latency_weight: float,
        latency_reference_ms: float,
        health: HealthConfig | None = None,
    ) -> float:
        capacity = 1.0 - (self.active / max(1, self.max_concurrency))
        normalized = min(1.0, self.ewma_latency_ms / max(1.0, latency_reference_ms)) if self.ewma_latency_ms else 0.0
        error_penalty = min(1.0, self.error_rate)
        value = capacity_weight * capacity + latency_weight * (1.0 - normalized) - error_penalty
        return math.floor(value * 10_000) / 10_000 + (0.0001 * max(0, self.effective_weight - 1))

    def snapshot(self) -> dict:
        return {
            "node_id": self.node_id,
            "endpoint": self.endpoint,
            "state": self.state.value,
            "routable": self.routable,
            "active": self.active,
            "max_concurrency": self.max_concurrency,
            "weight": self.weight,
            "effective_weight": self.effective_weight,
            "ewma_latency_ms": round(self.ewma_latency_ms, 2),
            "error_rate": round(self.error_rate, 4),
            "breaker": self.breaker.state,
            "requests_this_hour": self.requests_this_hour,
            "tokens_this_hour": self.tokens_this_hour,
            "rpm": round(self.rpm(), 2),
            "models": list(self.models),
            "last_error": self.last_error,
        }


def breaker_from_config(cfg: CircuitBreakerConfig) -> CircuitBreaker:
    return CircuitBreaker(
        window_seconds=cfg.window_seconds,
        minimum_requests=cfg.minimum_requests,
        error_rate_threshold=cfg.error_rate_threshold,
        open_duration_seconds=cfg.open_duration_seconds,
        half_open_probes=cfg.half_open_probes,
    )


__all__ = ["CircuitBreaker", "NodeRuntime", "breaker_from_config"]
