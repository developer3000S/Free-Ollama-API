"""Rate limiting, квоты и бюджеты генерации (§12.4.2, §12.4.3).

Три механизма (все — из требований ТЗ):

* **token bucket** — пользователь/модель/глобальный лимит запросов;
* **sliding window** — дневная квота токенов и часы работы;
* **concurrency limit** — одновременные запросы (в т.ч. потоковые).

Уровни лимитов (таблица §12.4.2): глобальный, пользователь, модель, узел
(лимиты узла учитывает балансировщик, см. :mod:`foa.services.balancer`),
владелец узла (суммарный бюджет — ``NodeRuntime``).

Бэкенды: in-process (по умолчанию) и Redis (``storage.redis_url``) для
распределённого режима; интерфейс общий.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from foa.config import LimitsConfig, Settings
from foa.domain.errors import BudgetExceededError, QuotaExceededError, RateLimitedError
from foa.logging import get_logger
from foa.observability import metrics

log = get_logger("ratelimit")


@dataclass(slots=True)
class RateDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_at: float
    retry_after: int = 0


class TokenBucket:
    """Классический token bucket (ёмкость = лимит в минуту)."""

    __slots__ = ("capacity", "tokens", "updated_at")

    def __init__(self, capacity: float) -> None:
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated_at = time.monotonic()

    def _refill(self, now: float) -> None:
        elapsed = now - self.updated_at
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * (self.capacity / 60.0))
            self.updated_at = now

    def consume(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        self._refill(now)
        if self.tokens < amount:
            return False
        self.tokens -= amount
        return True

    def retry_after(self) -> int:
        now = time.monotonic()
        self._refill(now)
        if self.tokens >= 1:
            return 0
        rate = self.capacity / 60.0 or 1 / 60.0
        return max(1, int((1 - self.tokens) / rate) + 1)


@dataclass
class SlidingWindowCounter:
    """Скользящее окно для суточных квот."""

    window_seconds: float = 86_400.0
    events: deque[tuple[float, int]] = field(default_factory=deque)

    def add(self, amount: int, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self.events.append((now, amount))
        self._trim(now)

    def _trim(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def total(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        self._trim(now)
        return sum(amount for _, amount in self.events)

    def reset_at(self, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        self._trim(now)
        if not self.events:
            return now + self.window_seconds
        return self.events[0][0] + self.window_seconds


@dataclass
class ConcurrencyLimiter:
    """Одновременные запросы: семафор на субъект + счётчик потоковых.

    ``limit``/``streams_limit`` — общий политикой заданный потолок; вызывающий
    может передать более строгий или более мягкий индивидуальный потолок ключа
    (§12.4.2: «concurrent_requests» владельцем ключа).
    """

    limit: int
    streams_limit: int = 0
    _active: dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)
    _streams: dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def available(self, subject: str, *, limit: int | None = None) -> bool:
        return self._active[subject] < max(1, self.effective_limit(limit))

    def streams_available(self, subject: str, *, streams_limit: int | None = None) -> bool:
        cap = self.effective_streams_limit(streams_limit)
        if not cap:
            return True
        return self._streams[subject] < cap

    def effective_limit(self, limit: int | None = None) -> int:
        return max(1, int(limit or self.limit))

    def effective_streams_limit(self, streams_limit: int | None = None) -> int:
        return max(0, int(streams_limit if streams_limit is not None else self.streams_limit))

    async def acquire(self, subject: str, *, stream: bool = False, limit: int | None = None, streams_limit: int | None = None) -> bool:
        async with self._lock:
            if not self.available(subject, limit=limit):
                return False
            if stream and not self.streams_available(subject, streams_limit=streams_limit):
                return False
            self._active[subject] += 1
            if stream:
                self._streams[subject] += 1
            return True

    async def release(self, subject: str, *, stream: bool = False) -> None:
        async with self._lock:
            self._active[subject] = max(0, self._active[subject] - 1)
            if self._active[subject] == 0:
                self._active.pop(subject, None)
            if stream:
                self._streams[subject] = max(0, self._streams[subject] - 1)
                if self._streams[subject] == 0:
                    self._streams.pop(subject, None)

    def snapshot(self) -> dict[str, int]:
        return dict(self._active)


@dataclass
class InMemoryLimitBackend:
    """Лимиты в пределах одного реплики шлюза (по умолчанию)."""

    buckets: dict[str, TokenBucket] = field(default_factory=dict, repr=False)
    windows: dict[str, SlidingWindowCounter] = field(default_factory=dict, repr=False)

    def bucket(self, key: str, capacity: int) -> TokenBucket:
        bucket = self.buckets.get(key)
        if bucket is None or bucket.capacity != float(capacity):
            bucket = TokenBucket(capacity)
            self.buckets[key] = bucket
        return bucket

    def window(self, key: str, window_seconds: float = 86_400.0) -> SlidingWindowCounter:
        existing = self.windows.get(key)
        if existing is None:
            existing = SlidingWindowCounter(window_seconds=window_seconds)
            self.windows[key] = existing
        return existing


class RedisLimitBackend:
    """Распределённый бэкенд лимитов (``GATEWAY_REDIS_URL``).

    Реализация — Lua-скрипты token bucket и INCR+EXPIRE для окон. Доступен
    только при настроенном Redis; иначе шлюз работает на in-process.
    """

    def __init__(self, redis_client) -> None:
        self.redis = redis_client

    async def consume(self, key: str, capacity: int, amount: float = 1.0) -> bool:  # pragma: no cover - требует Redis
        now = time.time()
        pipe = self.redis.pipeline()
        pipe.hgetall(f"foa:bucket:{key}")
        await pipe.execute()
        state = await self.redis.hgetall(f"foa:bucket:{key}")
        tokens = float(state.get(b"tokens", capacity))
        updated = float(state.get(b"updated", now))
        tokens = min(capacity, tokens + (now - updated) * (capacity / 60.0))
        if tokens < amount:
            return False
        tokens -= amount
        await self.redis.hset(f"foa:bucket:{key}", mapping={"tokens": tokens, "updated": now})
        await self.redis.expire(f"foa:bucket:{key}", 120)
        return True

    async def count(self, key: str, window_seconds: int, amount: int = 1) -> int:  # pragma: no cover
        target = f"foa:win:{key}:{int(time.time()) // window_seconds}"
        total = await self.redis.incrby(target, amount)
        if total == amount:
            await self.redis.expire(target, window_seconds * 2)
        return int(total)


class RateLimiter:
    """Фасад: применяет лимиты из §12.4.2/§12.4.3 и отдаёт заголовки §8.5.2."""

    def __init__(self, settings: Settings, backend=None, redis_client=None) -> None:
        self.settings = settings
        self.limits: LimitsConfig = settings.limits
        self.backend = backend or InMemoryLimitBackend()
        self.redis = RedisLimitBackend(redis_client) if redis_client else None
        self.user_concurrency = ConcurrencyLimiter(
            limit=self.limits.concurrent_requests_per_user,
            streams_limit=self.limits.concurrent_stream_requests_per_user,
        )
        self.node_concurrency = ConcurrencyLimiter(limit=10_000)

    def refresh(self, settings: Settings) -> None:
        """Горячая перезагрузка нечувствительных параметров (§11.5)."""
        self.limits = settings.limits
        self.user_concurrency.limit = settings.limits.concurrent_requests_per_user
        self.user_concurrency.streams_limit = settings.limits.concurrent_stream_requests_per_user

    # ------------------------------------------------------------------ #
    # Проверки
    # ------------------------------------------------------------------ #

    def _capacity_for(self, principal_limit: int, default: int) -> int:
        return int(principal_limit or default)

    async def _consume(self, key: str, limit: int) -> tuple[bool, int, float]:
        """Списывает 1 токен. Возвращает (разрешено, остаток, unix-время сброса)."""
        bucket = self.backend.bucket(key, limit)
        allowed = await self.redis.consume(key, limit) if self.redis is not None else bucket.consume(1)
        if allowed:
            return True, int(bucket.tokens), time.time() + 60
        return False, int(bucket.tokens), time.time() + max(1, bucket.retry_after())

    async def check_user(self, key_id: str, *, limit_override: int = 0) -> RateDecision:
        limit = self._capacity_for(limit_override, self.limits.requests_per_minute_per_user)
        allowed, remaining, reset_at = await self._consume(f"user:{key_id}", limit)
        if not allowed:
            metrics.RATE_LIMITED_TOTAL.labels(scope="user").inc()
            retry = max(1, int(reset_at - time.time()))
            return RateDecision(False, limit, 0, reset_at, retry)
        return RateDecision(True, limit, remaining, reset_at)

    async def check_model(self, model: str) -> RateDecision:
        limit = self.limits.requests_per_minute_per_model
        allowed, remaining, reset_at = await self._consume(f"model:{model}", limit)
        if not allowed:
            metrics.RATE_LIMITED_TOTAL.labels(scope="model").inc()
            return RateDecision(False, limit, 0, reset_at, max(1, int(reset_at - time.time())))
        return RateDecision(True, limit, remaining, reset_at)

    async def check_global(self) -> RateDecision:
        limit = self.limits.requests_per_minute_global
        allowed, remaining, reset_at = await self._consume("global", limit)
        if not allowed:
            metrics.RATE_LIMITED_TOTAL.labels(scope="global").inc()
            return RateDecision(False, limit, 0, reset_at, max(1, int(reset_at - time.time())))
        return RateDecision(True, limit, remaining, reset_at)

    async def check_daily_tokens(self, key_id: str, budget: int) -> RateDecision:
        if not budget:
            return RateDecision(True, 0, 0, time.time() + 60)
        window = self.backend.window(f"tokens:{key_id}")
        if self.redis is not None:
            total = await self.redis.count(f"tokens:{key_id}", 86_400, 0)
        else:
            total = window.total()
        reset_at = time.time() + max(1.0, window.reset_at() - time.monotonic())
        if total >= budget:
            retry = int(max(1, reset_at - time.time()))
            metrics.RATE_LIMITED_TOTAL.labels(scope="quota").inc()
            return RateDecision(False, budget, 0, reset_at, retry)
        return RateDecision(True, budget, max(0, budget - total), reset_at)

    def add_tokens(self, key_id: str, amount: int) -> None:
        if amount <= 0:
            return
        self.backend.window(f"tokens:{key_id}").add(int(amount))

    def enforce_generation_budget(self, requested_num_predict: int | None, prompt_bytes: int) -> None:
        """§12.4.3 — ограничение стоимости генерации и размера промпта."""
        if prompt_bytes > self.limits.max_prompt_bytes:
            raise BudgetExceededError(
                f"размер промпта {prompt_bytes} Б превышает лимит {self.limits.max_prompt_bytes} Б",
                retry_after=60,
                details={"max_prompt_bytes": self.limits.max_prompt_bytes},
            )
        if requested_num_predict and requested_num_predict > self.limits.max_num_predict:
            raise BudgetExceededError(
                f"num_predict={requested_num_predict} превышает лимит {self.limits.max_num_predict}",
                retry_after=60,
                details={"max_num_predict": self.limits.max_num_predict},
            )

    @asynccontextmanager
    async def user_slot(self, key_id: str, *, stream: bool = False, limit: int = 0):
        """Concurrency limit (§12.4.2).

        ``limit`` — индивидуальный потолок ключа; если он не выдан (0),
        применяется политический ``limits.concurrent_requests_per_user``.
        """
        cap = self.user_concurrency.effective_limit(limit or None)
        streams_cap = self.user_concurrency.streams_limit or None
        acquired = await self.user_concurrency.acquire(key_id or "anonymous", stream=stream, limit=cap, streams_limit=streams_cap)
        if not acquired:
            metrics.RATE_LIMITED_TOTAL.labels(scope="concurrency").inc()
            raise RateLimitedError(
                "превышено число одновременных запросов",
                retry_after=5,
                details={"limit": cap if not stream else (streams_cap or cap)},
            )
        try:
            yield
        finally:
            await self.user_concurrency.release(key_id or "anonymous", stream=stream)

    def headers(self, decision: RateDecision) -> dict[str, str]:
        """Заголовки ответа шлюза (§8.5.2)."""
        out = {
            "X-FOA-RateLimit-Limit": str(int(decision.limit)),
            "X-FOA-RateLimit-Remaining": str(int(decision.remaining)),
            "X-FOA-RateLimit-Reset": str(int(decision.reset_at)),
        }
        return out

    def apply(self, *decisions: RateDecision) -> RateDecision:
        """Возвращает самое строгое решение (для заголовков и ошибок)."""
        worst = decisions[0]
        for decision in decisions[1:]:
            if not decision.allowed:
                raise RateLimitedError("rate limit exceeded", retry_after=decision.retry_after or 30)
            if decision.remaining < worst.remaining:
                worst = decision
        return worst

    def quota_check(self, decision: RateDecision) -> None:
        if not decision.allowed:
            raise QuotaExceededError("квота исчерпана", retry_after=decision.retry_after or 60)

    def snapshot(self) -> dict:
        return {
            "backend": "redis" if self.redis else "in_memory",
            "user_buckets": len(self.backend.buckets),
            "active_user_slots": self.user_concurrency.snapshot(),
        }


__all__ = [
    "ConcurrencyLimiter",
    "InMemoryLimitBackend",
    "RateDecision",
    "RateLimiter",
    "RedisLimitBackend",
    "SlidingWindowCounter",
    "TokenBucket",
]
