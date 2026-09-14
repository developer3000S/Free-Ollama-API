"""Генерация идентификаторов с сортировкой по времени (ULID-совместимый формат).

Формат ``prefix_01J9ZK9Q9VX2`` как в ТЗ: 26 символов всего, из них 12 — base32
(6 бит случайности + 46 бит миллисекундного времени), что даёт монотонность
внутри процесса и достаточную уникальность для одного шлюза.
"""

from __future__ import annotations

import secrets
import threading
import time

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CHAR_TO_VALUE = {char: index for index, char in enumerate(CROCKFORD)}
_TIME_LEN = 10
_RAND_LEN = 12

_lock = threading.Lock()
_last_ms = 0
_last_suffix = ""


def _encode(value: int, length: int) -> str:
    out = [""] * length
    for i in range(length - 1, -1, -1):
        out[i] = CROCKFORD[value & 0x1F]
        value >>= 5
    return "".join(out)


def _decode(text: str) -> int:
    """Обратная кодировка алфавита Крокфорда.

    Стандартный ``int(x, 32)`` не подходит: он не принимает символы W/X/Y/Z,
    которые есть в алфавите Крокфорда.
    """
    value = 0
    for char in text:
        value = value * 32 + _CHAR_TO_VALUE[char]
    return value


def monotonic_id(prefix: str) -> str:
    """Возвращает отсортированный по времени идентификатор с монотонным ростом."""
    global _last_ms, _last_suffix
    with _lock:
        ms = int(time.time() * 1000)
        if ms == _last_ms:
            # Инкремент случайной части гарантирует строгую монотонность.
            nxt = (_decode(_last_suffix) + 1) % (32**_RAND_LEN) if _last_suffix else 0
            suffix = _encode(nxt, _RAND_LEN)
            if suffix == _last_suffix:  # переполнение счётчика внутри миллисекунды
                ms += 1
                suffix = "".join(secrets.choice(CROCKFORD) for _ in range(_RAND_LEN))
        else:
            suffix = "".join(secrets.choice(CROCKFORD) for _ in range(_RAND_LEN))
        _last_ms, _last_suffix = ms, suffix
        return f"{prefix}_{_encode(ms, _TIME_LEN)}{suffix}"


def candidate_id() -> str:
    return monotonic_id("cnd")


def node_id() -> str:
    return monotonic_id("node")


def owner_id() -> str:
    return monotonic_id("owner")


def consent_id() -> str:
    return monotonic_id("consent")


def request_id() -> str:
    return monotonic_id("req")


def key_id() -> str:
    return monotonic_id("key")


def event_id() -> str:
    return monotonic_id("evt")


def challenge_token() -> str:
    """Токен вызова для подтверждения владения узлом (ТЗ §5.3)."""
    return secrets.token_urlsafe(32)


def random_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
