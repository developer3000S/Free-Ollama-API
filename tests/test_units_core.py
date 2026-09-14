"""Юнит-тесты базовых модулей шлюза: идентификаторы, области поиска, лимиты частоты
запросов, кэш ответов, криграфия ключей доступа и SSRF-защита адресации узлов.

Проверяемые разделы ТЗ:

* §3.2.1 — формат идентификаторов (``prefix_01J9ZK9Q9VX2``);
* §4.5–§4.6 — allowed_scopes и max_requests_per_minute интеграций Discovery;
* §4.2 п.5, FR-D-06 — кэш ответов внешних источников;
* §5.3, §5.3.3 — токен вызова и подписанные токены согласия (Ed25519);
* §12.4.1 — хранение и проверка ключей доступа (SHA-256 + pepper);
* §12.4.5, §12.5.1, §12.6 — разбор адреса узла, классификация сетей, пиннинг.

Тесты синхронные, без БД и сети. Время подменяется явной инъекцией аргумента
``now`` там, где модуль его принимает, и подменой модуля ``time`` через
``monkeypatch`` там, где модуль обращается к ``time`` сам.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import string
import threading
import time as real_time

import pytest
from cryptography.hazmat.primitives import serialization
from foa import ids as ids_module
from foa.domain.errors import InvalidRequestError
from foa.ids import (
    CROCKFORD,
    candidate_id,
    challenge_token,
    consent_id,
    event_id,
    key_id,
    monotonic_id,
    node_id,
    owner_id,
    random_secret,
    request_id,
)
from foa.net import security as security_module
from foa.net.security import (
    DEFAULT_OLLAMA_PORT,
    PinStore,
    ResolvedAddress,
    classify_ip,
    ip_is_blocked,
    parse_endpoint,
    validate_endpoint,
)
from foa.services import crypto as crypto_module
from foa.services.crypto import (
    KEY_ALPHABET_RE,
    constant_time_token_equal,
    generate_api_key,
    generate_ed25519_pair,
    hash_api_key,
    key_fingerprint,
    load_ed25519_public_key,
    sign_ed25519,
    verify_api_key,
    verify_ed25519,
)
from foa.services.discovery import cache as cache_module
from foa.services.discovery import rate_limit as rate_limit_module
from foa.services.discovery.cache import ResponseCache
from foa.services.discovery.rate_limit import MinuteRateLimiter
from foa.services.discovery.scopes import ScopeSet

_URL_SAFE = set(string.ascii_letters + string.digits + "-_")
_REAL_TIME = real_time.time
_REAL_MONOTONIC = real_time.monotonic
NOW_MS = 1_700_000_000_000
T0 = 1_000_000.0


class ShiftedClock:
    """Подмена модуля ``time``: «сейчас» = реальное время + ``offset``.

    ``ResponseCache`` и ``MinuteRateLimiter`` вызывают ``time.monotonic()`` через
    глобальное имя модуля, поэтому подмены глобального ``time`` достаточно.
    """

    def __init__(self) -> None:
        self.offset = 0.0

    def time(self) -> float:
        return _REAL_TIME() + self.offset

    def monotonic(self) -> float:
        return _REAL_MONOTONIC() + self.offset


class FixedClock:
    """Подмена модуля ``time`` с абсолютным значением «сейчас» (для ``PinStore``)."""

    def __init__(self, now: float) -> None:
        self.now = now

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.now


class SteppingClock:
    """Часы с шагом в миллисекундах (:func:`monotonic_id` читает ``time.time``)."""

    def __init__(self, ms: int = NOW_MS, step_ms: int = 0) -> None:
        self.ms = ms
        self.step_ms = step_ms

    def time(self) -> float:
        current = self.ms
        self.ms += self.step_ms
        return current / 1000.0

    def monotonic(self) -> float:
        return self.time()


def _decode_crockford(text: str) -> int:
    value = 0
    for char in text:
        value = value * 32 + CROCKFORD.index(char)
    return value


def _time_part(identifier: str) -> int:
    return _decode_crockford(identifier.split("_", 1)[1][:10])


def _suffix_part(identifier: str) -> str:
    return identifier.split("_", 1)[1][10:]


@pytest.fixture()
def ids_env(monkeypatch):
    """Изолированное состояние генератора ``monotonic_id`` + управляемые часы."""
    monkeypatch.setattr(ids_module, "_last_ms", 0)
    monkeypatch.setattr(ids_module, "_last_suffix", "")
    clock = SteppingClock()
    monkeypatch.setattr(ids_module, "time", clock)
    return ids_module, clock


@pytest.fixture()
def shifted_clock(monkeypatch):
    """«Сдвигаемые» часы для модулей, читающих ``time`` без явной инъекции."""
    clock = ShiftedClock()
    monkeypatch.setattr(cache_module, "time", clock)
    monkeypatch.setattr(rate_limit_module, "time", clock)
    return clock


@pytest.fixture()
def pin_clock(monkeypatch):
    """Абсолютные часы ``PinStore``: пины пересоздаются с явным ``pinned_at``."""
    clock = FixedClock(now=_REAL_TIME())
    monkeypatch.setattr(security_module, "time", clock)
    return clock


def _pin(store: PinStore, host: str, ips: list[str], at: float) -> None:
    """Кладёт пин с фиксированной меткой времени (не зависит от default_factory)."""
    store.put(host, ips)
    store._pins[host.lower()] = [ResolvedAddress(ip=ip, pinned_at=at) for ip in ips]


# --------------------------------------------------------------------------- #
# foa/ids.py — монотонные идентификаторы (§3.2.1)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("factory", "prefix"),
    [
        (candidate_id, "cnd"),
        (node_id, "node"),
        (owner_id, "owner"),
        (consent_id, "consent"),
        (request_id, "req"),
        (key_id, "key"),
        (event_id, "evt"),
    ],
)
def test_id_prefixes_match_spec_format(ids_env, factory, prefix):
    """§3.2.1 — вид ``prefix_01J9ZK9Q9VX2``: префикс + 22 символа алфавита Крокфорда."""
    _, clock = ids_env
    clock.step_ms = 1
    value = factory()
    assert value.startswith(f"{prefix}_")
    body = value.split("_", 1)[1]
    assert len(body) == 22, "10 символов времени + 12 символов случайной части"
    assert set(body) <= set(CROCKFORD), "алфавит без I/L/O/U"


def test_monotonic_ids_are_ordered_and_unique(ids_env):
    """§3.2.1 — идентификаторы сортируются по времени и не повторяются."""
    _, clock = ids_env
    clock.step_ms = 10
    generated = [monotonic_id("req") for _ in range(40)]
    assert generated == sorted(generated)
    assert len(set(generated)) == len(generated)


def test_monotonic_id_encodes_current_time(ids_env):
    """Миллисекунды «сейчас» кодируются первыми 10 символами после префикса."""
    assert _time_part(monotonic_id("node")) == NOW_MS


def test_monotonic_id_time_part_advances_with_clock(ids_env):
    _, clock = ids_env
    clock.step_ms = 7
    first = monotonic_id("evt")
    second = monotonic_id("evt")
    assert _time_part(second) - _time_part(first) == 7


def test_same_millisecond_ids_increment_suffix(ids_env):
    """Строгая монотонность внутри миллисекунды — инкремент младшей части."""
    ids_pkg, clock = ids_env
    ids_pkg._last_ms = clock.ms
    ids_pkg._last_suffix = "00000000000A"
    first = ids_pkg.monotonic_id("req")
    second = ids_pkg.monotonic_id("req")
    assert _suffix_part(first) == "00000000000B"
    assert _suffix_part(second) == "00000000000C"
    assert first < second
    assert ids_pkg._last_ms == clock.ms, "время не сдвигается, пока не было переполнения"


def test_suffix_increment_wraps_at_alphabet_end(ids_env):
    """«Z» — символ со значением 31: переполнение младшего разряда даёт carry в старший."""
    ids_pkg, clock = ids_env
    ids_pkg._last_ms = clock.ms
    ids_pkg._last_suffix = "0" * 11 + "Z"
    first = ids_pkg.monotonic_id("req")
    second = ids_pkg.monotonic_id("req")
    assert _suffix_part(first) == "0" * 10 + "10"
    assert _suffix_part(second) == "0" * 10 + "11"
    assert first < second


@pytest.mark.parametrize("letter", ["W", "X", "Y", "Z"])
def test_suffix_increment_handles_crockford_only_letters(ids_env, letter):
    """Инкремент опирается на ``_decode`` (Крокфорд), а не на ``int(x, 32)``: буквы W/X/Y/Z
    стандартным base32 не читаются — без обратной кодировки здесь был бы ValueError."""
    ids_pkg, clock = ids_env
    ids_pkg._last_ms = clock.ms
    ids_pkg._last_suffix = "0" * 11 + letter
    assert CROCKFORD.index(letter) >= 28, letter
    value = _decode_crockford(_suffix_part(ids_pkg.monotonic_id("req")))
    assert value == CROCKFORD.index(letter) + 1


def test_same_millisecond_generation_is_stable(ids_env):
    """§3.2.1 — длинная серия в одной миллисекунде: без исключений, строго возрастает."""
    _, clock = ids_env
    clock.step_ms = 0
    generated = [monotonic_id("req") for _ in range(200)]
    assert len(set(generated)) == 200
    assert generated == sorted(generated)
    assert all(len(value) == len(generated[0]) for value in generated)


def test_suffix_counter_stays_monotonic_after_overflow(ids_env):
    """Даже при переполнении 12-разрядного счётчика идентификаторы остаются в алфавите."""
    ids_pkg, clock = ids_env
    ids_pkg._last_ms = clock.ms
    ids_pkg._last_suffix = "Z" * 12
    value = ids_pkg.monotonic_id("req")
    assert set(_suffix_part(value)) <= set(CROCKFORD)
    assert _suffix_part(value) == "0" * 12, "счётчик замкнут по модулю 32**12"


def test_new_millisecond_resamples_random_suffix(ids_env):
    """Смена миллисекунды — младшая часть снова случайна, порядок даёт старшая."""
    ids_pkg, clock = ids_env
    ids_pkg._last_ms = clock.ms - 1
    ids_pkg._last_suffix = "00000000000A"
    value = ids_pkg.monotonic_id("req")
    assert _time_part(value) == NOW_MS
    assert ids_pkg._last_ms == NOW_MS
    assert set(_suffix_part(value)) <= set(CROCKFORD)
    assert _suffix_part(value) != "00000000000B", "это не инкремент — новая случайная часть"


def test_monotonic_ids_across_threads_are_unique(ids_env):
    """Блокировка модуля защищает общий счётчик (§3.2.1)."""
    _, clock = ids_env
    clock.step_ms = 1
    collected: list[str] = []
    guard = threading.Lock()

    def worker() -> None:
        batch = [monotonic_id("evt") for _ in range(10)]
        with guard:
            collected.extend(batch)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(collected)) == len(collected) == 40, "дублей быть не должно"


def test_same_millisecond_ids_never_repeat_across_the_full_alphabet(ids_env):
    """§3.2.1 — регрессия на ``int(suffix, 32)``: серия из 400 идентификаторов в «стоячих»
    часах обязана быть уникальной, упорядоченной и целиком из алфавита Крокфорда."""
    _, clock = ids_env
    clock.step_ms = 0
    generated = [monotonic_id("req") for _ in range(400)]
    assert len(set(generated)) == 400
    assert generated == sorted(generated)
    assert all(set(_suffix_part(value)) <= set(CROCKFORD) for value in generated)


@pytest.mark.parametrize("nbytes", [8, 16, 24, 32])
def test_random_secret_length_grows_with_nbytes(nbytes):
    value = random_secret(nbytes)
    assert set(value) <= _URL_SAFE
    assert len(value) == len(secrets.token_urlsafe(nbytes))


def test_random_secret_is_random():
    assert len({random_secret(16) for _ in range(50)}) == 50


def test_challenge_token_is_random_and_urlsafe():
    """§5.3 — токен вызова: 32 байта энтропии, безопасен для URL и DNS TXT."""
    tokens = {challenge_token() for _ in range(64)}
    assert len(tokens) == 64
    sample = tokens.pop()
    assert len(sample) == len(secrets.token_urlsafe(32))
    assert set(sample) <= _URL_SAFE
    assert "=" not in sample and "+" not in sample


# --------------------------------------------------------------------------- #
# foa/services/discovery/scopes.py — allowed_scopes (§4.5, §4.6)
# --------------------------------------------------------------------------- #


def test_scope_ip_v4_exact_match():
    scopes = ScopeSet(raw=["203.0.113.10"])
    assert scopes.allows_ip("203.0.113.10") is True
    assert scopes.allows_ip("203.0.113.11") is False


def test_scope_ip_v6_exact_match():
    scopes = ScopeSet(raw=["2001:db8::1"])
    assert scopes.allows_ip("2001:db8::1") is True
    assert scopes.allows_ip("2001:db8::2") is False
    assert [str(n) for n in scopes.networks] == ["2001:db8::1/128"]


@pytest.mark.parametrize(
    ("ip", "expected"),
    [("203.0.113.1", True), ("203.0.113.255", True), ("203.0.112.255", False), ("203.0.114.1", False)],
)
def test_scope_cidr_v4(ip, expected):
    assert ScopeSet(raw=["203.0.113.0/24"]).allows_ip(ip) is expected


def test_scope_cidr_non_strict_is_normalized():
    """Хостовая запись ``203.0.113.7/24`` трактуется как сеть целиком (strict=False)."""
    scopes = ScopeSet(raw=["203.0.113.7/24"])
    assert [str(n) for n in scopes.networks] == ["203.0.113.0/24"]
    assert scopes.allows_ip("203.0.113.1") is True


def test_scope_cidr_v6():
    scopes = ScopeSet(raw=["2001:db8::/32"])
    assert scopes.allows_ip("2001:db8:99::1") is True
    assert scopes.allows_ip("2001:db9::1") is False


@pytest.mark.parametrize("value", ["не-ip", "", "999.999.999.999"])
def test_scope_invalid_ip_is_denied_not_raised(value):
    assert ScopeSet(raw=["203.0.113.0/24"]).allows_ip(value) is False


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("example.com", True),
        ("sub.example.com", True),
        ("a.b.example.com", True),
        ("EXAMPLE.COM.", True),
        ("notexample.com", False),
        ("example.net", False),
        ("example.co", False),
        ("", False),
    ],
)
def test_scope_domain_suffix_matching(name, expected):
    """§4.5 — совпадение с dns_name: точное или по суффиксу домена."""
    assert ScopeSet(raw=["example.com"]).allows_domain(name) is expected


@pytest.mark.parametrize("entry", ["example.com", "*.example.com", ".example.com", "**.example.com"])
def test_scope_wildcard_and_plain_domain_are_equivalent(entry):
    scopes = ScopeSet(raw=[entry])
    assert scopes.domains == ["example.com"]
    assert scopes.allows_domain("ollama.example.com") is True
    assert scopes.allows_domain("example.com") is True
    assert scopes.allows_domain("evilexample.com") is False


def test_scope_wildcard_does_not_open_lookalike_domains():
    """§4.6 — ``*.example.com`` не открывает адрес вида ``examplecom.evil.net``."""
    scopes = ScopeSet(raw=["*.example.com"])
    assert scopes.allows_domain("deep.sub.example.com") is True
    assert scopes.allows_domain("examplecom.evil.net") is False


@pytest.mark.parametrize("asn", ["AS64500", "asn:64500", "as 64500", "ASN64500", "as64500"])
def test_scope_asn_forms_are_normalized_to_digits(asn):
    """§4.5 — формы записи ASN: ``AS64500`` / ``asn:64500``."""
    scopes = ScopeSet(raw=[asn])
    assert scopes.asns == {"64500"}
    assert scopes.allows_asn("AS64500") is True
    assert scopes.allows_asn("64500") is True


def test_scope_bare_number_is_not_an_asn():
    """ASN распознаётся только по префиксу ``as``/``asn:`` — «голое» число уходит в домены (§4.5)."""
    scopes = ScopeSet(raw=["64500"])
    assert scopes.asns == set()
    assert scopes.domains == ["64500"]
    assert scopes.allows("8.8.8.8", asn="AS64500") is False


def test_scope_asn_mismatch_and_absence():
    scopes = ScopeSet(raw=["AS64500"])
    assert scopes.allows_asn("AS64501") is False
    assert scopes.allows_asn(None) is False
    assert scopes.allows_asn("") is False
    assert ScopeSet(raw=["example.com"]).allows_asn("64500") is False, "ASN вне scope — запрет"


def test_scope_asn_prefix_swallows_domains_starting_with_as():
    """Правило разбора: любая запись с префиксом ``as`` считается ASN (§4.5).

    Побочный эффект, который фиксирует тест: домен ``ashland.example.com``
    никогда не попадает в список доменов.
    """
    scopes = ScopeSet(raw=["ashland.example.com"])
    assert scopes.asns == set(), "цифр нет — запись проигнорирована как ASN"
    assert scopes.domains == []
    assert scopes.allows("5.6.7.8", dns_names=["ashland.example.com"]) is False


def test_scope_entries_split_by_kind():
    scopes = ScopeSet(raw=["203.0.113.0/24", "2001:db8::1", "AS64500", "example.com", "", "   "])
    assert [str(n) for n in scopes.networks] == ["203.0.113.0/24", "2001:db8::1/128"]
    assert scopes.domains == ["example.com"]
    assert scopes.asns == {"64500"}


def test_scopes_fail_closed_when_empty():
    """§4.6 — пустой allowed_scopes в inventory_only не разрешает ничего."""
    scopes = ScopeSet(raw=[])
    assert scopes.allows("203.0.113.10") is False
    assert scopes.allows("203.0.113.10", dns_names=["example.com"], asn="AS64500") is False
    assert scopes.allows_ip("203.0.113.10") is False
    assert scopes.allows_domain("example.com") is False
    assert scopes.describe()["empty"] is True


def test_scopes_whitespace_only_still_denies():
    scopes = ScopeSet(raw=["", "   "])
    assert scopes.allows("203.0.113.10", dns_names=["example.com"], asn="AS1") is False


def test_scope_allows_by_any_dimension():
    scopes = ScopeSet(raw=["203.0.113.0/24", "AS64500", "example.com"])
    assert scopes.allows("203.0.113.7") is True
    assert scopes.allows("8.8.8.8", asn="AS64500") is True
    assert scopes.allows("8.8.8.8", dns_names=["ollama.example.com"]) is True
    assert scopes.allows("8.8.8.8") is False
    assert scopes.allows("8.8.8.8", dns_names=["other.test"]) is False
    assert scopes.allows("8.8.8.8", dns_names=["other.test", "example.com"]) is True


def test_scope_allows_ignores_empty_asn():
    scopes = ScopeSet(raw=["AS64500"])
    assert scopes.allows("8.8.8.8", asn=None) is False
    assert scopes.allows("8.8.8.8", dns_names=(), asn="AS1234") is False


def test_scope_describe_shape():
    scopes = ScopeSet(raw=["203.0.113.0/24", "AS64501", "AS64500", "lab.example"])
    assert scopes.describe() == {
        "networks": ["203.0.113.0/24"],
        "domains": ["lab.example"],
        "asns": ["64500", "64501"],
        "empty": False,
    }


# --------------------------------------------------------------------------- #
# foa/services/discovery/rate_limit.py — max_requests_per_minute (§4.5)
# --------------------------------------------------------------------------- #


def test_rate_limiter_enforces_limit_within_window():
    limiter = MinuteRateLimiter(limit_per_minute=3)
    assert [limiter.allow(now=T0 + i) for i in range(5)] == [True, True, True, False, False]


def test_rate_limiter_counts_down_remaining():
    limiter = MinuteRateLimiter(limit_per_minute=4)
    assert limiter.remaining(now=T0) == 4
    limiter.allow(now=T0)
    limiter.allow(now=T0)
    assert limiter.remaining(now=T0) == 2


def test_rate_limiter_remaining_does_not_go_negative():
    limiter = MinuteRateLimiter(limit_per_minute=1)
    for _ in range(3):
        limiter.allow(now=T0)
    assert limiter.remaining(now=T0) == 0


def test_rate_limiter_default_limit_is_ten():
    """§4.5 — значение по умолчанию max_requests_per_minute: 10."""
    limiter = MinuteRateLimiter()
    assert limiter.limit_per_minute == 10
    assert limiter.remaining(now=T0) == 10


def test_rate_limiter_window_expiry_after_sixty_seconds():
    limiter = MinuteRateLimiter(limit_per_minute=2)
    assert limiter.allow(now=T0) and limiter.allow(now=T0 + 1)
    assert limiter.allow(now=T0 + 2) is False
    # Окно «строгое»: событие ровно на границе cutoff ещё учитывается (<, а не <=).
    assert limiter.allow(now=T0 + 60.0) is False
    assert limiter.remaining(now=T0 + 60.0) == 0
    assert limiter.allow(now=T0 + 60.5) is True


def test_rate_limiter_partial_window_release():
    limiter = MinuteRateLimiter(limit_per_minute=3)
    for moment in (T0, T0 + 10, T0 + 20):
        assert limiter.allow(now=moment)
    assert limiter.allow(now=T0 + 30) is False
    assert limiter.allow(now=T0 + 75) is True, "два старых события вышли из окна"
    assert limiter.remaining(now=T0 + 75) == 1


def test_rate_limiter_denied_request_is_not_recorded():
    limiter = MinuteRateLimiter(limit_per_minute=1)
    assert limiter.allow(now=T0) is True
    assert limiter.allow(now=T0 + 10) is False
    assert limiter.allow(now=T0 + 60.5) is True, "отказ не должен продлевать окно"


def test_rate_limiter_remaining_does_not_consume_budget():
    limiter = MinuteRateLimiter(limit_per_minute=2)
    limiter.remaining(now=T0)
    limiter.remaining(now=T0)
    assert limiter.allow(now=T0) is True
    assert limiter.allow(now=T0) is True
    assert limiter.allow(now=T0) is False


def test_rate_limiter_instances_do_not_share_state():
    first = MinuteRateLimiter(limit_per_minute=1)
    second = MinuteRateLimiter(limit_per_minute=1)
    assert first.allow(now=T0) is True
    assert second.allow(now=T0) is True


def test_rate_limiter_non_positive_limit_denies_everything():
    assert MinuteRateLimiter(limit_per_minute=0).allow(now=T0) is False
    assert MinuteRateLimiter(limit_per_minute=0).remaining(now=T0) == 0
    assert MinuteRateLimiter(limit_per_minute=-5).allow(now=T0) is False


def test_rate_limiter_falls_back_to_module_clock(shifted_clock):
    limiter = MinuteRateLimiter(limit_per_minute=2)
    assert limiter.allow() and limiter.allow()
    assert limiter.allow() is False
    assert limiter.remaining() == 0
    shifted_clock.offset = 61.0
    assert limiter.allow() is True


# --------------------------------------------------------------------------- #
# foa/services/discovery/cache.py — кэш ответов источников (§4.2 п.5, FR-D-06)
# --------------------------------------------------------------------------- #


def test_cache_put_get_roundtrip():
    cache = ResponseCache()
    cache.put("source:8.8.8.8", {"hostnames": ["dns.google"]}, ttl=60)
    assert cache.get("source:8.8.8.8") == {"hostnames": ["dns.google"]}
    assert cache.get("unknown") is None


def test_cache_put_overwrites_value():
    cache = ResponseCache()
    cache.put("k", 1)
    cache.put("k", 2, ttl=10)
    assert cache.get("k") == 2
    assert cache.stats()["entries"] == 1


def test_cache_stores_value_by_identity():
    cache = ResponseCache()
    payload = ["a", "b"]
    cache.put("list", payload)
    assert cache.get("list") is payload


def test_cache_distinguishes_absent_from_stored_values():
    cache = ResponseCache()
    cache.put("zero", 0, ttl=30)
    cache.put("empty", "", ttl=30)
    assert cache.get("zero") == 0
    assert cache.get("empty") == ""
    assert cache.get("none") is None, "попадание со значением None неотличимо от промаха (§4.2)"


def test_cache_ttl_expiry(shifted_clock):
    cache = ResponseCache()
    cache.put("k", "v", ttl=100)
    assert cache.get("k") == "v"
    shifted_clock.offset = 99.0
    assert cache.get("k") == "v"
    shifted_clock.offset = 100.0
    assert cache.get("k") is None, "срок истекает ровно в момент expires_at (§4.2)"
    assert cache.stats()["entries"] == 0, "просроченная запись удаляется при чтении"


def test_cache_ttl_is_per_entry(shifted_clock):
    cache = ResponseCache()
    cache.put("short", 1, ttl=10)
    cache.put("long", 2, ttl=100)
    shifted_clock.offset = 50.0
    assert cache.get("short") is None
    assert cache.get("long") == 2


def test_cache_non_positive_ttl_is_clamped_to_one_second(shifted_clock):
    """``max(1, ttl)`` — нулевой/отрицательный TTL не даёт ни вечной, ни мгновенно просроченной записи."""
    cache = ResponseCache()
    cache.put("zero", "v", ttl=0)
    cache.put("negative", "v", ttl=-100)
    assert cache.get("zero") == "v"
    assert cache.get("negative") == "v"
    shifted_clock.offset = 1.0
    assert cache.get("zero") is None
    assert cache.get("negative") is None


def test_cache_default_ttl_is_one_day():
    """§4.5 — ответ источника по умолчанию кэшируется на сутки (cache_ttl_seconds: 86400)."""
    cache = ResponseCache()
    cache.put("k", "v")
    expires_at = next(iter(cache._entries.values()))[0]
    assert expires_at - real_time.monotonic() == pytest.approx(86_400, abs=1.0)


def test_cache_invalidate_single_key_and_all():
    cache = ResponseCache()
    cache.put("a", 1)
    cache.put("b", 2)
    cache.invalidate("a")
    assert cache.get("a") is None
    assert cache.get("b") == 2
    cache.invalidate("нет-такого-ключа")
    cache.invalidate()
    assert cache.stats() == {"entries": 0, "live": 0}


def test_cache_stats_counts_live_and_expired(shifted_clock):
    cache = ResponseCache()
    cache.put("live", 1, ttl=100)
    cache.put("dead", 2, ttl=10)
    shifted_clock.offset = 20.0
    assert cache.stats() == {"entries": 2, "live": 1}


def test_cache_stats_on_empty_cache():
    assert ResponseCache().stats() == {"entries": 0, "live": 0}


def test_cache_instances_are_independent():
    first, second = ResponseCache(), ResponseCache()
    first.put("k", "v")
    assert second.get("k") is None


# --------------------------------------------------------------------------- #
# foa/services/crypto.py — ключи доступа (§12.4.1)
# --------------------------------------------------------------------------- #


def test_hash_api_key_is_sha256_of_peppered_material():
    """§12.4.1 — хранится только SHA-256(pepper + key)."""
    key = "foa_" + "A" * 30
    assert hash_api_key(key) == hashlib.sha256(key.encode("utf-8")).digest()
    assert hash_api_key(key, pepper="pepper") == hashlib.sha256(b"pepper" + key.encode("utf-8")).digest()
    assert len(hash_api_key(key, pepper="pepper")) == 32
    assert isinstance(hash_api_key(key), bytes)


def test_hash_api_key_pepper_changes_result():
    key = "foa_" + "B" * 30
    assert hash_api_key(key, pepper="p1") != hash_api_key(key, pepper="p2")
    assert hash_api_key(key, pepper="") == hash_api_key(key)


def test_hash_api_key_does_not_leak_the_key():
    key = generate_api_key()
    digest = hash_api_key(key, pepper="pepper")
    assert key.encode("utf-8") not in digest
    assert hashlib.sha256(key.encode("utf-8")).digest() != digest, "без пеппера хэш другой (§14.2)"


def test_verify_api_key_accepts_matching_key():
    key = generate_api_key()
    stored = hash_api_key(key, pepper="pepper")
    assert verify_api_key(key, stored, pepper="pepper") is True


def test_verify_api_key_rejects_wrong_key():
    stored = hash_api_key(generate_api_key(), pepper="pepper")
    assert verify_api_key(generate_api_key(), stored, pepper="pepper") is False


def test_verify_api_key_requires_the_same_pepper():
    """§14.2 — пеппер берётся из secret manager; без него хэш не совпадёт."""
    key = generate_api_key()
    stored = hash_api_key(key, pepper="secret-pepper")
    assert verify_api_key(key, stored) is False
    assert verify_api_key(key, stored, pepper="other-pepper") is False


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "short",
        "a" * 23,
        "a" * 201,
        "foa_" + "a" * 20 + " ",
        "foa_" + "a" * 20 + "!@#$",
        "foa_" + "a" * 20 + "_кириллица",
        "foa " + "a" * 30,
    ],
)
def test_verify_api_key_rejects_malformed_keys(candidate):
    """§12.4.1 — формат ключа проверяется до сравнения хэша (даже для «правильного» хэша)."""
    assert verify_api_key(candidate, hash_api_key(candidate)) is False


def test_verify_api_key_regex_ignores_trailing_newline():
    """Зафиксирующая проверка: ``$`` в Python пропускает финальный перевод строки.

    Ключ с завершающим ``\\n`` проходит ``KEY_ALPHABET_RE`` и сверяется по хэшу —
    на разборе HTTP-заголовка это несущественно (значение приходит без переноса),
    но тест помечает исключение из алфавитного правила.
    """
    candidate = "foa_" + "a" * 30 + "\n"
    assert KEY_ALPHABET_RE.match(candidate), "regex не экранирует конец строки как следует"
    assert verify_api_key(candidate, hash_api_key(candidate)) is True


@pytest.mark.parametrize("length", [24, 100, 200])
def test_verify_api_key_accepts_key_length_bounds(length):
    key = "a" * length
    assert verify_api_key(key, hash_api_key(key)) is True


@pytest.mark.parametrize("alphabet", ["_", "-", "0123456789", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLM"])
def test_verify_api_key_accepts_allowed_alphabet(alphabet):
    key = (alphabet + "x" * 24)[:40]
    assert KEY_ALPHABET_RE.match(key), key
    assert verify_api_key(key, hash_api_key(key)) is True


def test_generated_api_key_matches_allowed_alphabet():
    key = generate_api_key()
    assert key.startswith("foa_")
    assert KEY_ALPHABET_RE.match(key), key
    assert verify_api_key(key, hash_api_key(key)) is True


def test_generate_api_key_prefix_is_configurable():
    assert generate_api_key(prefix="custom_").startswith("custom_")


def test_generated_api_keys_are_unique():
    assert len({generate_api_key() for _ in range(200)}) == 200


def test_generated_api_key_passes_length_bounds():
    assert 24 <= len(generate_api_key()) <= 200


def test_key_fingerprint_is_short_and_stable():
    key = generate_api_key()
    fingerprint = key_fingerprint(key)
    assert len(fingerprint) == 12
    assert fingerprint == hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    assert key_fingerprint(key) == fingerprint, "отпечаток детерминирован"
    assert key not in fingerprint, "отпечаток не раскрывает ключ"
    assert key_fingerprint(generate_api_key()) != fingerprint


def test_key_fingerprint_is_lowercase_hex():
    assert set(key_fingerprint("foa_" + "Z" * 30)) <= set("0123456789abcdef")


def test_constant_time_token_equal():
    assert constant_time_token_equal("token", "token") is True
    assert constant_time_token_equal("token", "Token") is False
    assert constant_time_token_equal("token", "tokens") is False
    assert constant_time_token_equal("", "") is True
    assert constant_time_token_equal(None, "") is True  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# foa/services/crypto.py — Ed25519 (§5.3.3)
# --------------------------------------------------------------------------- #


def _raw_public_b64url(private_pem: str) -> str:
    private = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_ed25519_sign_verify_round_trip():
    """§5.3.3 — подпись токена согласия проверяется публичным ключом владельца."""
    private_pem, public_pem = generate_ed25519_pair()
    message = b'{"node_id":"node_01","challenge":"abc"}'
    signature = sign_ed25519(private_pem, message)
    assert set(signature) <= _URL_SAFE and "=" not in signature
    assert verify_ed25519(public_pem, message, signature) is True


def test_ed25519_sign_accepts_bytes_pem():
    private_pem, public_pem = generate_ed25519_pair()
    message = b"consent"
    assert verify_ed25519(public_pem, message, sign_ed25519(private_pem.encode("utf-8"), message)) is True


def test_ed25519_verify_accepts_raw_b64url_public_key():
    private_pem, _ = generate_ed25519_pair()
    message = b"consent"
    signature = sign_ed25519(private_pem, message)
    assert verify_ed25519(_raw_public_b64url(private_pem), message, signature) is True


def test_ed25519_signature_is_64_bytes():
    private_pem, _ = generate_ed25519_pair()
    signature = sign_ed25519(private_pem, b"msg")
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    assert len(raw) == 64


def test_ed25519_different_keys_produce_different_material():
    private_a, public_a = generate_ed25519_pair()
    private_b, public_b = generate_ed25519_pair()
    message = b"consent-token"
    assert sign_ed25519(private_a, message) != sign_ed25519(private_b, message)
    assert public_a != public_b


def test_ed25519_rejects_tampered_message():
    private_pem, public_pem = generate_ed25519_pair()
    signature = sign_ed25519(private_pem, b"original")
    assert verify_ed25519(public_pem, b"tampered", signature) is False
    assert verify_ed25519(public_pem, b"", signature) is False


def test_ed25519_rejects_tampered_signature():
    private_pem, public_pem = generate_ed25519_pair()
    message = b"consent-token"
    signature = sign_ed25519(private_pem, message)
    flipped = ("B" if signature[0] != "B" else "C") + signature[1:]
    assert verify_ed25519(public_pem, message, flipped) is False
    assert verify_ed25519(public_pem, message, "%%%") is False
    assert verify_ed25519(public_pem, message, signature[:20]) is False


def test_ed25519_rejects_foreign_public_key():
    private_pem, _ = generate_ed25519_pair()
    _, other_public = generate_ed25519_pair()
    message = b"consent-token"
    assert verify_ed25519(other_public, message, sign_ed25519(private_pem, message)) is False


@pytest.mark.parametrize("material", ["", "   ", None])
def test_load_ed25519_public_key_requires_value(material):
    with pytest.raises(InvalidRequestError):
        load_ed25519_public_key(material)  # type: ignore[arg-type]


@pytest.mark.parametrize("material", ["это-не-ключ", "!!!!", "aGk"])
def test_load_ed25519_public_key_rejects_garbage(material):
    """Некорректный ключ владельца — ошибка запроса (400), а не «подпись не прошла» (§5.3.3)."""
    with pytest.raises(InvalidRequestError):
        load_ed25519_public_key(material)


def test_verify_ed25519_propagates_invalid_public_key_as_bad_request():
    private_pem, _ = generate_ed25519_pair()
    signature = sign_ed25519(private_pem, b"msg")
    with pytest.raises(InvalidRequestError):
        verify_ed25519("!!!!не-ключ!!!!", b"msg", signature)


def test_ed25519_pair_pems_are_parseable_and_match():
    private_pem, public_pem = generate_ed25519_pair()
    assert private_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")
    private = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    public = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    as_raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert public.public_bytes(*as_raw) == private.public_key().public_bytes(*as_raw)


def test_load_ed25519_public_key_returns_verifying_key():
    private_pem, public_pem = generate_ed25519_pair()
    message = b"consent"
    signature = sign_ed25519(private_pem, message)
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    load_ed25519_public_key(public_pem).verify(raw, message)


def test_crypto_module_reexports_helpers():
    assert set(crypto_module.__all__) >= {
        "hash_api_key",
        "verify_api_key",
        "key_fingerprint",
        "constant_time_token_equal",
        "sign_ed25519",
        "verify_ed25519",
        "generate_ed25519_pair",
    }


# --------------------------------------------------------------------------- #
# foa/net/security.py — разбор адреса узла (§12.4.5, §9.6.2)
# --------------------------------------------------------------------------- #


def test_parse_endpoint_defaults_port_to_ollama():
    """§12.4.5 — стандартный порт Ollama 11434 подставляется, если порт не указан."""
    endpoint = parse_endpoint("http://203.0.113.10")
    assert endpoint.port == DEFAULT_OLLAMA_PORT == 11434
    assert endpoint.scheme == "http" and endpoint.tls is False
    assert endpoint.origin == "http://203.0.113.10:11434"
    assert endpoint.netloc == "203.0.113.10:11434"


def test_parse_endpoint_without_scheme_defaults_to_https():
    endpoint = parse_endpoint("ollama.example.com")
    assert endpoint.scheme == "https" and endpoint.tls is True
    assert endpoint.host == "ollama.example.com"
    assert endpoint.port == DEFAULT_OLLAMA_PORT


def test_parse_endpoint_keeps_explicit_port():
    endpoint = parse_endpoint("http://h:8080")
    assert endpoint.port == 8080
    assert endpoint.origin == "http://h:8080"


def test_parse_endpoint_default_port_is_overridable():
    assert parse_endpoint("http://h", default_port=9999).port == 9999


def test_parse_endpoint_lowercases_host_and_strips_trailing_dot():
    endpoint = parse_endpoint("  HTTPS://Ollama.Example.COM.  ")
    assert endpoint.host == "ollama.example.com"
    assert endpoint.scheme == "https"
    assert endpoint.raw == "HTTPS://Ollama.Example.COM.", "raw — исходная строка без обрамляющих пробелов"


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("http://203.0.113.10:11434", "203.0.113.10"),
        ("http://[2001:db8::1]:11434", "2001:db8::1"),
        ("http://[::1]:11434", "::1"),
    ],
)
def test_parse_endpoint_detects_ip_hosts(url, host):
    endpoint = parse_endpoint(url)
    assert endpoint.host == host
    assert endpoint.is_ip is True


def test_parse_endpoint_ipv6_origin_is_rebracketed():
    endpoint = parse_endpoint("http://[2001:db8::1]:11434")
    assert endpoint.origin == "http://[2001:db8::1]:11434"
    assert endpoint.netloc == "[2001:db8::1]:11434"


def test_parse_endpoint_hostname_is_not_marked_as_ip():
    assert parse_endpoint("http://ollama.example.com:11434").is_ip is False


@pytest.mark.parametrize("bare_ipv6", ["http://2001:db8::1", "http://::1"])
def test_parse_endpoint_rejects_unbracketed_ipv6(bare_ipv6):
    """IPv6 без квадратных скобок однозначно не разбирается (§12.4.5)."""
    with pytest.raises(InvalidRequestError):
        parse_endpoint(bare_ipv6)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://h:11434/api/generate", "путь запрещён"),
        ("http://h:11434?x=1", "query запрещён"),
        ("http://h:11434#frag", "fragment запрещён"),
        ("ftp://h:11434", "схема вне белого списка"),
        ("grpc://h:11434", "схема вне белого списка"),
        ("http://user:pass@h:11434", "учётные данные запрещены"),
        ("http://", "хост обязателен"),
        ("http://h:70000", "порт вне диапазона"),
        ("http://exa_mple.com", "недопустимое имя хоста"),
        ("http://-bad.example.com", "недопустимое имя хоста"),
        ("http://" + "a" * 250 + ".com", "слишком длинное имя хоста"),
    ],
)
def test_parse_endpoint_rejects_invalid_urls(url, reason):
    with pytest.raises(InvalidRequestError) as excinfo:
        parse_endpoint(url)
    assert excinfo.value.code.value == "INVALID_REQUEST", reason
    assert str(excinfo.value)


@pytest.mark.parametrize("url", ["http://h:11434/", "https://h/", "http://h"])
def test_parse_endpoint_allows_empty_or_root_path(url):
    """Корневой путь не считается «путём» — узел адресуется без суффикса."""
    assert parse_endpoint(url).host == "h"


def test_parse_endpoint_port_zero_falls_back_to_default():
    """urlparse трактует ``:0`` как отсутствие порта — остаётся значение по умолчанию."""
    assert parse_endpoint("http://h:0").port == DEFAULT_OLLAMA_PORT


def test_parse_endpoint_max_port_is_accepted():
    assert parse_endpoint("http://h:65535").port == 65535


# --------------------------------------------------------------------------- #
# foa/net/security.py — классификация и запреты сетей (§12.5.1)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("127.0.0.1", "loopback"),
        ("127.5.5.5", "loopback"),
        ("::1", "loopback"),
        ("10.0.0.5", "private"),
        ("172.16.0.1", "private"),
        ("192.168.1.1", "private"),
        ("198.51.100.4", "private"),
        ("2001:db8::1", "private"),
        ("fc00::1", "private"),
        ("169.254.169.254", "metadata"),
        ("fe80::1", "metadata"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
    ],
)
def test_classify_ip_categories(ip, expected):
    assert classify_ip(ip) == expected


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_classify_ip_public_address(ip):
    """§12.5.1 — публичный адрес обязан получать категорию ``public``."""
    assert classify_ip(ip) == "public"


def test_classify_ip_rejects_non_address():
    with pytest.raises(ValueError):
        classify_ip("не-адрес")


@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",
        "169.254.1.1",
        "fe80::1",
        "fe80:ffff::1",
        "0.0.0.0",
        "224.0.0.1",
        "ff02::1",
        "240.0.0.1",
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "192.168.0.1",
        "2001:db8::1",
        "не-ip",
        "",
    ],
)
def test_ip_is_blocked_by_default(ip):
    """§12.5.1, §13 — безопасный режим по умолчанию: разрешены только публичные адреса."""
    assert ip_is_blocked(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_ip_is_not_blocked(ip):
    assert ip_is_blocked(ip) is False


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.0.0.53", "::1"])
def test_loopback_allowed_only_with_flag(ip):
    """§12.5.1 — ``security.allow_loopback_nodes`` для изолированного стенда."""
    assert ip_is_blocked(ip, allow_loopback=False) is True
    assert ip_is_blocked(ip, allow_loopback=True) is False


@pytest.mark.parametrize("ip", ["169.254.169.254", "169.254.10.10", "169.254.0.1"])
def test_metadata_ipv4_is_blocked_always(ip):
    """Метаданные облака запрещены даже при включённом allow_loopback_nodes (§12.5.1)."""
    assert ip_is_blocked(ip, allow_loopback=True) is True
    assert ip_is_blocked(ip, allow_loopback=True, allowed_networks=["169.254.0.0/16"]) is True


@pytest.mark.parametrize("ip", ["fe80::1", "fe80:abcd::5"])
def test_link_local_ipv6_is_blocked_always(ip):
    assert ip_is_blocked(ip, allow_loopback=True) is True
    assert ip_is_blocked(ip, allow_loopback=True, allowed_networks=["fe80::/10"]) is True


def test_unspecified_is_blocked_always():
    assert ip_is_blocked("0.0.0.0", allow_loopback=True, allowed_networks=["0.0.0.0/8"]) is True


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.7.7", "172.16.3.4", "fd12:3456::7"])
def test_private_ip_allowed_via_allowed_networks(ip):
    """§4.5/§12.5.1 — частная сеть разрешается только явной записью allowed_networks."""
    networks = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "fd00::/8"]
    assert ip_is_blocked(ip, allowed_networks=networks) is False
    assert ip_is_blocked(ip, allowed_networks=[]) is True


def test_allowed_networks_does_not_open_unrelated_private_space():
    networks = ["10.0.0.0/8"]
    assert ip_is_blocked("10.1.2.3", allowed_networks=networks) is False
    assert ip_is_blocked("192.168.1.1", allowed_networks=networks) is True


def test_allowed_networks_tolerates_bad_cidr():
    assert ip_is_blocked("10.0.0.5", allowed_networks=["не-cidr", "10.0.0.0/8"]) is False
    assert ip_is_blocked("10.0.0.5", allowed_networks=["не-cidr"]) is True


def test_loopback_flag_does_not_allow_private_networks():
    assert ip_is_blocked("10.0.0.5", allow_loopback=True) is True


def test_allowed_networks_does_not_allow_loopback():
    """Белый список сетей не открывает петлю — для неё нужен отдельный флаг (§12.5.1)."""
    assert ip_is_blocked("127.0.0.1", allowed_networks=["127.0.0.0/8"]) is True


# --------------------------------------------------------------------------- #
# foa/net/security.py — validate_endpoint (§9.6.2, §12.5.1)
# --------------------------------------------------------------------------- #


def test_validate_endpoint_returns_stripped_url():
    assert validate_endpoint("  https://93.184.216.34:11434  ") == "https://93.184.216.34:11434"


def test_validate_endpoint_rejects_blocked_ip():
    with pytest.raises(ValueError, match="недопустимую сеть"):
        validate_endpoint("http://127.0.0.1:11434")


def test_validate_endpoint_allows_loopback_with_flag():
    assert validate_endpoint("http://127.0.0.1:11434", allow_loopback=True) == "http://127.0.0.1:11434"


def test_validate_endpoint_still_blocks_metadata_with_loopback_flag():
    with pytest.raises(ValueError, match="недопустимую сеть"):
        validate_endpoint("http://169.254.169.254", allow_loopback=True)
    with pytest.raises(ValueError, match="недопустимую сеть"):
        validate_endpoint("http://[fe80::1]:11434", allow_loopback=True)


def test_validate_endpoint_checks_only_ip_hosts_not_names():
    """Синтаксический уровень не резолвит имена — сеть проверяется только для IP (§12.6)."""
    assert validate_endpoint("http://localhost:11434") == "http://localhost:11434"
    assert validate_endpoint("http://private.internal:11434") == "http://private.internal:11434"


def test_validate_endpoint_honours_allowed_networks():
    assert validate_endpoint("http://10.0.0.5:11434", allowed_networks=["10.0.0.0/8"]) == "http://10.0.0.5:11434"


def test_validate_endpoint_rejects_private_ip_outside_allowed_networks():
    with pytest.raises(ValueError, match="недопустимую сеть"):
        validate_endpoint("http://10.0.0.5:11434", allowed_networks=["192.168.0.0/16"])


def test_validate_endpoint_accepts_public_ip():
    assert validate_endpoint("http://93.184.216.34:11434") == "http://93.184.216.34:11434"


def test_validate_endpoint_rejects_test_net_address():
    """203.0.113.0/24 (TEST-NET-3) в ``ipaddress`` считается частным — вне белого списка запрещён."""
    with pytest.raises(ValueError, match="недопустимую сеть"):
        validate_endpoint("http://203.0.113.7:11434")


def test_validate_endpoint_propagates_parse_errors():
    with pytest.raises(InvalidRequestError):
        validate_endpoint("http://h:11434/api/generate")


def test_validate_endpoint_respects_default_port_override():
    assert validate_endpoint("http://93.184.216.34", default_port=9999) == "http://93.184.216.34"


# --------------------------------------------------------------------------- #
# foa/net/security.py — PinStore (§12.6)
# --------------------------------------------------------------------------- #


def test_pin_store_put_get_roundtrip(pin_clock):
    store = PinStore(ttl_seconds=300)
    store.put("host.example", ["93.184.216.34", "2606:4700:4700::1111"])
    assert store.get("host.example") == ["93.184.216.34", "2606:4700:4700::1111"]


def test_pin_store_is_case_insensitive(pin_clock):
    store = PinStore()
    store.put("Host.Example.COM", ["1.2.3.4"])
    assert store.get("host.example.com") == ["1.2.3.4"]
    assert store.get("HOST.EXAMPLE.COM") == ["1.2.3.4"]


def test_pin_store_unknown_host_returns_none():
    assert PinStore().get("never-put.example") is None


def test_pin_store_ttl_expiry(pin_clock):
    """§12.6 — по истечении TTL пина обязателен ре-резолв (защита от DNS rebinding)."""
    store = PinStore(ttl_seconds=60)
    _pin(store, "a.example", ["1.2.3.4"], at=pin_clock.now)
    pin_clock.now += 59.0
    assert store.get("a.example") == ["1.2.3.4"]
    pin_clock.now += 2.0
    assert store.get("a.example") is None
    assert "a.example" not in store._pins, "просроченный пин вычищается из памяти"


def test_pin_store_boundary_exactly_at_ttl_is_still_fresh(pin_clock):
    store = PinStore(ttl_seconds=60)
    _pin(store, "a.example", ["1.2.3.4"], at=pin_clock.now)
    pin_clock.now += 60.0
    assert store.get("a.example") == ["1.2.3.4"], "сравнение строгое: ``> ttl``"


def test_pin_store_reput_resets_ttl(pin_clock):
    store = PinStore(ttl_seconds=30)
    _pin(store, "a.example", ["1.2.3.4"], at=pin_clock.now)
    pin_clock.now += 20.0
    _pin(store, "a.example", ["9.9.9.9"], at=pin_clock.now)
    pin_clock.now += 25.0
    assert store.get("a.example") == ["9.9.9.9"]


def test_pin_store_expiry_uses_first_entry_timestamp(pin_clock):
    store = PinStore(ttl_seconds=10)
    _pin(store, "a.example", ["1.2.3.4", "5.6.7.8"], at=pin_clock.now)
    store._pins["a.example"].append(ResolvedAddress(ip="0.0.0.0", pinned_at=0.0))
    assert store.get("a.example") == ["1.2.3.4", "5.6.7.8", "0.0.0.0"], "срок считается по первому адресу"


def test_pin_store_default_ttl_is_five_minutes():
    assert PinStore().ttl_seconds == 300.0


def test_pin_store_drop(pin_clock):
    store = PinStore()
    _pin(store, "a.example", ["1.2.3.4"], at=pin_clock.now)
    store.drop("A.Example")
    assert store.get("a.example") is None
    store.drop("a.example")  # повторное удаление — молча


def test_pin_store_empty_list_reads_as_absent(pin_clock):
    store = PinStore()
    _pin(store, "a.example", [], at=pin_clock.now)
    assert store.get("a.example") is None


def test_pin_store_overwrites_previous_addresses(pin_clock):
    store = PinStore()
    _pin(store, "a.example", ["1.2.3.4"], at=pin_clock.now)
    _pin(store, "a.example", ["5.6.7.8"], at=pin_clock.now)
    assert store.get("a.example") == ["5.6.7.8"]


def test_resolved_address_records_pinning_time():
    before = _REAL_TIME()
    address = ResolvedAddress(ip="1.2.3.4")
    assert before <= address.pinned_at <= _REAL_TIME()


def test_security_module_reexports_are_public():
    assert set(security_module.__all__) >= {
        "parse_endpoint",
        "ip_is_blocked",
        "classify_ip",
        "PinStore",
        "validate_endpoint",
        "assert_endpoint_resolvable",
        "DEFAULT_OLLAMA_PORT",
    }
