"""Ограничение частоты запросов к внешним API (§4.5 max_requests_per_minute)."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field


@dataclass(slots=True)
class MinuteRateLimiter:
    limit_per_minute: int = 10
    _events: deque[float] = field(default_factory=deque, repr=False)

    def allow(self, now: float | None = None) -> bool:
        if self.limit_per_minute <= 0:
            return False
        now = time.monotonic() if now is None else now
        cutoff = now - 60.0
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        if len(self._events) >= self.limit_per_minute:
            return False
        self._events.append(now)
        return True

    def remaining(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        cutoff = now - 60.0
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        return max(0, self.limit_per_minute - len(self._events))


__all__ = ["MinuteRateLimiter"]
