"""Кэш ответов внешних источников (§4.2 п.5, FR-D-06)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ResponseCache:
    _entries: dict[str, tuple[float, Any]] = field(default_factory=dict, repr=False)

    def get(self, key: str) -> Any | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.monotonic() >= expires_at:
            self._entries.pop(key, None)
            return None
        return value

    def put(self, key: str, value: Any, *, ttl: int = 86_400) -> None:
        self._entries[key] = (time.monotonic() + max(1, ttl), value)

    def invalidate(self, key: str | None = None) -> None:
        if key is None:
            self._entries.clear()
        else:
            self._entries.pop(key, None)

    def stats(self) -> dict:
        now = time.monotonic()
        live = sum(1 for exp, _ in self._entries.values() if exp > now)
        return {"entries": len(self._entries), "live": live}


__all__ = ["ResponseCache"]
