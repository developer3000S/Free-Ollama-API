"""Юнит-тесты рантайм-слоя: разрыватель цепи, состояние узла и балансировщик.

Проверяемые разделы ТЗ:

* §6.5 — circuit breaker (окно 30 с, минимум 10 запросов, порог 50 %, open 60 с,
  один полураскрытый зонд);
* §6.3, §6.4 — пассивный health-check: EWMA задержки, доля ошибок, 401/403;
* §7.5 — почасовые лимиты узла (max_requests_per_hour, max_tokens_per_hour);
* §7.3 — алгоритмы балансировки (round robin, взвешенный RR, наименьшее число
  соединений, наименьшая задержка, консистентный хэш);
* §7.4 — гибридный алгоритм по умолчанию и его скоринг;
* §7.5, §4.4.4 — узел обслуживает только модели из согласия, маршрутизируются
  только ``verified``/``healthy``/``degraded`` при активном согласии;
* §9.5 — ``NO_HEALTHY_NODES`` и ``MODEL_NOT_FOUND``.

Тесты синхронные: рантайм-объекты и пул собираются напрямую, без БД.
"""

from __future__ import annotations

import math
import time
from collections import Counter

import pytest
from foa.config import BalancerConfig, CircuitBreakerConfig
from foa.domain.enums import NodeState
from foa.domain.errors import ModelNotFoundError, NoHealthyNodesError
from foa.services.balancer import NodePool, available_models, node_supports_model
from foa.services.state import CLOSED, HALF_OPEN, OPEN, CircuitBreaker, NodeRuntime, breaker_from_config

# Гибридные веса по умолчанию (§7.4, config.BalancerConfig).
CAPACITY_W = 0.5
LATENCY_W = 0.3
REFERENCE_MS = 30_000.0
SCORE_KW = {"capacity_weight": CAPACITY_W, "latency_weight": LATENCY_W, "latency_reference_ms": REFERENCE_MS}


def make_node(node_id: str, **overrides) -> NodeRuntime:
    """Собирает ``NodeRuntime`` напрямую (без реестра) в маршрутизируемом состоянии."""
    fields: dict = {
        "node_id": node_id,
        "endpoint": f"http://{node_id}:11434",
        "state": NodeState.HEALTHY,
        "max_concurrency": 4,
        "weight": 1,
        "effective_weight": 1,
        "routable": True,
    }
    fields.update(overrides)
    return NodeRuntime(**fields)


def make_pool(algorithm: str = "least_connections_with_latency", **config_kw) -> NodePool:
    return NodePool(config=BalancerConfig(algorithm=algorithm, **config_kw))


def route(*runtimes: NodeRuntime) -> NodePool:
    """Пул из уже маршрутизируемых узлов (согласие активно у всех)."""
    pool = make_pool()
    pool.sync([(node, True) for node in runtimes])
    return pool


# --------------------------------------------------------------------------- #
# foa/services/state.py — CircuitBreaker (§6.5)
# --------------------------------------------------------------------------- #


def test_breaker_defaults_follow_spec():
    """§6.5 — окно 30 с, минимум 10 запросов, порог 50 %, open 60 с, 1 зонд."""
    breaker = CircuitBreaker()
    assert breaker.window_seconds == 30.0
    assert breaker.minimum_requests == 10
    assert breaker.error_rate_threshold == 0.5
    assert breaker.open_duration_seconds == 60.0
    assert breaker.half_open_probes == 1
    assert breaker.state == CLOSED


def test_breaker_from_config_copies_circuit_breaker_config():
    cfg = CircuitBreakerConfig(
        window_seconds=15.0, minimum_requests=4, error_rate_threshold=0.25, open_duration_seconds=20.0, half_open_probes=2
    )
    breaker = breaker_from_config(cfg)
    assert (breaker.window_seconds, breaker.minimum_requests) == (15.0, 4)
    assert breaker.error_rate_threshold == 0.25
    assert breaker.open_duration_seconds == 20.0
    assert breaker.half_open_probes == 2


def test_breaker_stays_closed_below_minimum_requests():
    """§6.5 — доля ошибок не учитывается, пока запросов меньше минимума."""
    breaker = CircuitBreaker()
    for index in range(9):
        assert breaker.record(False, now=100.0 + index) == CLOSED
    assert breaker.error_rate == 0.0
    assert breaker.allow(now=108.0) is True


def test_breaker_opens_at_threshold_with_minimum_requests():
    breaker = CircuitBreaker()
    for index in range(10):
        breaker.record(False, now=100.0 + index)
    assert breaker.state == OPEN
    assert breaker._error_rate(109.0) == 1.0
    assert breaker.consecutive_failures == 10


@pytest.mark.parametrize(("failures", "successes", "opens"), [(4, 6, False), (5, 5, True), (6, 4, True)])
def test_breaker_error_rate_threshold_is_inclusive(failures, successes, opens):
    """§6.5 — размыкание при доле ошибок >= 0.5 на полном окне выборки."""
    breaker = CircuitBreaker()
    outcomes = [False] * failures + [True] * successes
    for index, ok in enumerate(outcomes):
        breaker.record(ok, now=100.0 + index)
    assert (breaker.state == OPEN) is opens


def test_breaker_ignores_events_outside_window():
    """§6.5 — за пределы 30-секундного окна события не считаются."""
    breaker = CircuitBreaker()
    breaker.record(False, now=100.0)  # устареет к моменту 148
    for index in range(9):
        breaker.record(False, now=140.0 + index)
    assert breaker.state == CLOSED, "в окне только 9 событий — минимума 10 нет"
    assert breaker._error_rate(148.0) == 0.0


def test_breaker_open_blocks_traffic():
    breaker = CircuitBreaker()
    for index in range(10):
        breaker.record(False, now=100.0 + index)
    assert breaker.state == OPEN
    assert breaker.allow(now=109.0) is False
    assert breaker.allow(now=168.9) is False, "до истечения open_duration — доступ закрыт"


def test_breaker_half_open_after_open_duration():
    breaker = CircuitBreaker()
    for index in range(10):
        breaker.record(False, now=100.0 + index)
    assert breaker.allow(now=169.0) is True
    assert breaker.state == HALF_OPEN


def test_breaker_half_open_admits_exactly_one_probe():
    """§6.5 — полураскрытое состояние пропускает ``half_open_probes`` зондов, не больше."""
    breaker = CircuitBreaker()
    for index in range(10):
        breaker.record(False, now=100.0 + index)
    assert breaker.allow(now=169.0) is True
    assert breaker.allow(now=169.0) is False
    assert breaker.allow(now=170.0) is False


def test_breaker_half_open_admits_configured_probe_count():
    breaker = CircuitBreaker(minimum_requests=2, error_rate_threshold=0.5, half_open_probes=2)
    breaker.record(False, now=100.0)
    breaker.record(False, now=101.0)
    assert breaker.state == OPEN
    assert breaker.allow(now=200.0) is True
    assert breaker.allow(now=200.0) is True
    assert breaker.allow(now=200.0) is False


def test_breaker_failed_probe_reopens():
    breaker = CircuitBreaker()
    for index in range(10):
        breaker.record(False, now=100.0 + index)
    opened_at = breaker._opened_at
    assert breaker.allow(now=169.0) is True
    breaker.record(False, now=169.5)
    assert breaker.state == OPEN
    assert breaker._opened_at == 169.5
    assert opened_at == 109.0
    assert breaker.allow(now=170.0) is False


def test_breaker_successful_probe_closes():
    """§6.5 — удачный зонд закрывает цепь и снимает ограничения доступа."""
    breaker = CircuitBreaker()
    for index in range(10):
        breaker.record(False, now=100.0 + index)
    assert breaker.allow(now=169.0) is True
    breaker.record(True, now=169.5)
    assert breaker.state == CLOSED
    assert breaker.consecutive_failures == 0
    assert breaker.allow(now=170.0) is True
    assert breaker.allow(now=170.0) is True, "закрытая цепь не считает зонды"


def test_breaker_success_in_closed_state_keeps_events_in_window():
    """Успех в закрытом состоянии не затирает окно — доля ошибок считается честно (§6.5)."""
    breaker = CircuitBreaker()
    for index in range(6):
        breaker.record(False, now=100.0 + index)
    breaker.record(True, now=106.0)
    assert breaker.state == CLOSED
    assert len(breaker._events) == 7, "события остаются в 30-секундном окне"
    assert breaker._error_rate(106.0) == 0.0, "7 событий ниже минимума 10 — доля не считается"
    breaker.record(False, now=107.0)
    breaker.record(False, now=108.0)
    breaker.record(False, now=109.0)
    assert breaker.state == OPEN, "10 событий, 9 ошибок — 0.9 >= 0.5"


def test_breaker_force_open_and_reset():
    breaker = CircuitBreaker()
    breaker.force_open(now=50.0)
    assert breaker.state == OPEN
    assert breaker.allow(now=50.5) is False
    breaker.reset()
    assert breaker.state == CLOSED
    assert breaker.consecutive_failures == 0
    assert breaker.allow(now=51.0) is True


def test_breaker_error_rate_property_uses_module_clock(monkeypatch):
    """``error_rate`` читается от реального ``time.monotonic`` — окно должно его переживать."""
    breaker = CircuitBreaker(window_seconds=30.0, minimum_requests=2)
    now = time.monotonic()
    breaker.record(False, now=now)
    breaker.record(False, now=now)
    assert breaker.error_rate == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# foa/services/state.py — NodeRuntime: нагрузка (§7.1)
# --------------------------------------------------------------------------- #


def test_acquire_respects_max_concurrency():
    node = make_node("n1", max_concurrency=2)
    assert node.acquire() is True
    assert node.acquire() is True
    assert node.acquire() is False
    assert node.active == 2


def test_release_decrements_and_is_floored_at_zero():
    node = make_node("n1", max_concurrency=2)
    node.acquire()
    node.release()
    assert node.active == 0
    node.release()
    node.release()
    assert node.active == 0, "активные запросы не могут стать отрицательными"


def test_acquire_allows_at_least_one_slot_for_bad_config():
    """``max(1, max_concurrency)`` — нулевая ёмкость не делает узел мёртвым молча."""
    node = make_node("n1", max_concurrency=0)
    assert node.acquire() is True
    assert node.acquire() is False
    assert node.active == 1


@pytest.mark.parametrize("concurrency", [1, 2, 4, 8])
def test_acquire_fill_then_release(concurrency):
    node = make_node("n1", max_concurrency=concurrency)
    assert all(node.acquire() for _ in range(concurrency))
    assert node.acquire() is False
    assert node.active == concurrency
    for _ in range(concurrency):
        node.release()
    assert node.active == 0
    assert node.acquire() is True, "освобождённый слот снова доступен"


# --------------------------------------------------------------------------- #
# foa/services/state.py — NodeRuntime: пассивный health-check (§6.3)
# --------------------------------------------------------------------------- #


def test_ewma_first_sample_seeds_the_average():
    """Первое наблюдение задаёт базу EWMA (иначе среднее стартовало бы с нуля)."""
    node = make_node("n1")
    node.observe(ok=True, latency_ms=120.0, now=1000.0)
    assert node.ewma_latency_ms == 120.0


def test_ewma_formula_with_alpha():
    """§6.3 — ewma = alpha * latest + (1 - alpha) * prev, alpha = 0.3."""
    node = make_node("n1")
    assert node.ewma_alpha == 0.3
    node.observe(ok=True, latency_ms=100.0, now=1000.0)
    node.observe(ok=True, latency_ms=200.0, now=1001.0)
    assert node.ewma_latency_ms == pytest.approx(0.3 * 200 + 0.7 * 100)
    node.observe(ok=True, latency_ms=300.0, now=1002.0)
    assert node.ewma_latency_ms == pytest.approx(0.3 * 300 + 0.7 * 130.0)


def test_ewma_honours_custom_alpha():
    node = make_node("n1", ewma_alpha=0.5)
    node.observe(ok=True, latency_ms=100.0, now=1000.0)
    node.observe(ok=True, latency_ms=200.0, now=1001.0)
    assert node.ewma_latency_ms == pytest.approx(150.0)
    slow = make_node("n2", ewma_alpha=0.1)
    slow.observe(ok=True, latency_ms=100.0, now=1000.0)
    slow.observe(ok=True, latency_ms=200.0, now=1001.0)
    assert slow.ewma_latency_ms == pytest.approx(110.0)


def test_ewma_smoothing_damps_a_spike():
    """§6.3 — один всплеск не «перевешивает» историю наблюдений."""
    node = make_node("n1")
    for _ in range(5):
        node.observe(ok=True, latency_ms=50.0, now=1000.0)
    node.observe(ok=True, latency_ms=10_000.0, now=1001.0)
    assert node.ewma_latency_ms == pytest.approx(0.3 * 10_000 + 0.7 * 50)
    assert node.ewma_latency_ms < 10_000.0
    node.observe(ok=True, latency_ms=50.0, now=1002.0)
    assert node.ewma_latency_ms < 3_000.0, "быстрые ответы возвращают среднее к реальности"


def test_observe_records_error_without_status():
    node = make_node("n1")
    node.observe(ok=False, latency_ms=5.0, now=1000.0)
    assert node.last_error == "error"


def test_observe_records_http_status_as_error():
    node = make_node("n1")
    node.observe(ok=False, latency_ms=5.0, status=503, now=1000.0)
    assert node.last_error == "http_503"


def test_observe_counts_tokens_into_the_hour():
    node = make_node("n1")
    node.observe(ok=True, latency_ms=5.0, now=1000.0, tokens=42)
    assert node.tokens_this_hour == 42
    node.observe(ok=True, latency_ms=5.0, now=1001.0, tokens=8)
    assert node.tokens_this_hour == 50


def test_observe_does_not_count_zero_tokens():
    node = make_node("n1")
    node.observe(ok=True, latency_ms=5.0, now=1000.0)
    assert node.tokens_this_hour == 0


def test_error_rate_over_sliding_window():
    """§6.3 — доля ошибок по окну пассивных наблюдений (по умолчанию 60 с)."""
    node = make_node("n1")
    now = time.monotonic()
    for index in range(10):
        node.observe(ok=index < 7, latency_ms=10.0, status=200 if index < 7 else 500, now=now + index * 0.01)
    assert node.error_rate == pytest.approx(0.3)


def test_error_rate_is_zero_without_samples():
    assert make_node("n1").error_rate == 0.0


def test_error_rate_drops_samples_outside_window():
    node = make_node("n1", passive_window_seconds=60.0)
    now = time.monotonic()
    node.observe(ok=False, latency_ms=5.0, status=500, now=now - 120.0)
    assert len(node.samples) == 1
    assert node.error_rate == 0.0, "устаревшее наблюдение исключено из окна"
    assert len(node.samples) == 0


@pytest.mark.parametrize("status", [401, 403])
def test_auth_error_after_denied_status(status):
    """§6.4, FR-H-05 — 401/403 от узла признак немедленного блэклиста."""
    node = make_node("n1")
    node.observe(ok=False, latency_ms=5.0, status=status, now=time.monotonic())
    assert node.auth_error is True


def test_no_auth_error_for_other_statuses():
    node = make_node("n1")
    now = time.monotonic()
    node.observe(ok=False, latency_ms=5.0, status=500, now=now)
    node.observe(ok=True, latency_ms=5.0, status=200, now=now + 0.1)
    assert node.auth_error is False


def test_auth_error_clears_when_the_sample_expires_the_window():
    node = make_node("n1", passive_window_seconds=60.0)
    node.observe(ok=False, latency_ms=5.0, status=401, now=time.monotonic() - 120.0)
    assert node.auth_error is False


def test_timeout_streak_counts_connect_failures():
    """Таймаут — неудача без HTTP-статуса (``status == 0``) подряд с конца окна."""
    node = make_node("n1")
    now = time.monotonic()
    node.observe(ok=False, latency_ms=1.0, status=0, now=now)
    node.observe(ok=False, latency_ms=1.0, status=0, now=now + 1.0)
    assert node.timeout_streak == 2
    node.observe(ok=True, latency_ms=1.0, status=200, now=now + 2.0)
    assert node.timeout_streak == 0


def test_timeout_streak_ignores_http_errors():
    node = make_node("n1")
    node.observe(ok=False, latency_ms=1.0, status=502, now=time.monotonic())
    assert node.timeout_streak == 0


def test_observe_feeds_the_breaker():
    """§6.3 → §6.5 — пассивные наблюдения питают разрыватель цепи узла."""
    node = make_node("n1")
    now = time.monotonic()
    for index in range(10):
        node.observe(ok=False, latency_ms=10.0, status=500, now=now + index * 0.01)
    assert node.breaker.state == OPEN


def test_snapshot_reports_runtime_fields():
    node = make_node("n1", active=2, ewma_latency_ms=123.456, models=("llama3.1",), requests_this_hour=5)
    now = time.monotonic()
    node.observe(ok=False, latency_ms=5.0, status=418, now=now)
    snapshot = node.snapshot()
    assert snapshot["node_id"] == "n1"
    assert snapshot["endpoint"] == "http://n1:11434"
    assert snapshot["state"] == "healthy"
    assert snapshot["routable"] is True
    assert snapshot["active"] == 2
    assert snapshot["max_concurrency"] == 4
    assert snapshot["ewma_latency_ms"] == pytest.approx(87.92, abs=0.01)
    assert snapshot["requests_this_hour"] == 5
    assert snapshot["models"] == ["llama3.1"]
    assert snapshot["last_error"] == "http_418"
    assert snapshot["breaker"] == CLOSED
    assert set(snapshot) == {
        "node_id",
        "endpoint",
        "state",
        "routable",
        "active",
        "max_concurrency",
        "weight",
        "effective_weight",
        "ewma_latency_ms",
        "error_rate",
        "breaker",
        "requests_this_hour",
        "tokens_this_hour",
        "rpm",
        "models",
        "last_error",
    }


# --------------------------------------------------------------------------- #
# foa/services/state.py — NodeRuntime: почасовые лимиты (§7.5)
# --------------------------------------------------------------------------- #


def test_limits_allow_by_default():
    """§7.5 — ``max_tokens_per_hour == 0`` означает «без ограничения»."""
    node = make_node("n1", max_requests_per_hour=1000, max_tokens_per_hour=0)
    assert node.limits_allow(now=1000.0) is True


def test_limits_block_after_max_requests_per_hour():
    node = make_node("n1", max_requests_per_hour=3)
    for _ in range(3):
        assert node.limits_allow(now=1000.0) is True
        node.note_request(now=1000.0)
    assert node.requests_this_hour == 3
    assert node.limits_allow(now=1000.0) is False


def test_limits_block_after_max_tokens_per_hour():
    node = make_node("n1", max_tokens_per_hour=100, max_requests_per_hour=0)
    node.observe(ok=True, latency_ms=5.0, now=1000.0, tokens=99)
    assert node.limits_allow(now=1000.0) is True
    node.observe(ok=True, latency_ms=5.0, now=1000.0, tokens=1)
    assert node.limits_allow(now=1000.0) is False


@pytest.mark.parametrize("limit_field", ["max_requests_per_hour", "max_tokens_per_hour"])
def test_zero_limit_means_unlimited(limit_field):
    kw = {"max_requests_per_hour": 0, "max_tokens_per_hour": 0}
    kw[limit_field] = 0
    node = make_node("n1", **kw)
    node.requests_this_hour = 10**6
    node.tokens_this_hour = 10**6
    assert node.limits_allow(now=1000.0) is True


def test_hour_rolls_over_after_3600_seconds():
    """§7.5 — почасовой счётчик перекатывается, когда база окна старше 3600 с."""
    anchor = time.monotonic()
    node = make_node("n1", max_requests_per_hour=2)
    node.note_request(now=anchor)
    node.note_request(now=anchor)
    assert node.requests_this_hour == 2
    assert node.limits_allow(now=anchor) is False
    assert node.limits_allow(now=anchor + 3599.0) is False
    assert node.limits_allow(now=anchor + 3601.0) is True, "окно часа перекатилось"
    assert node.requests_this_hour == 0
    assert node.tokens_this_hour == 0
    assert node.hourly_requests_total == 2


def test_note_request_keeps_lifetime_total_after_roll():
    node = make_node("n1")
    node.note_request(now=1000.0)
    node.requests_this_hour = 0
    assert node.hourly_requests_total == 1, "счётчик за всё время не обнуляется вместе с часом"


def test_rpm_counts_requests_in_last_minute():
    node = make_node("n1")
    for _ in range(3):
        node.note_request(now=1000.0)
    assert node.rpm(now=1000.0) == 3


def test_rpm_drops_events_outside_the_minute():
    node = make_node("n1")
    node.note_request(now=1000.0)
    node.note_request(now=1000.0)
    assert node.rpm(now=1059.0) == 2
    assert node.rpm(now=1061.0) == 0


def test_rpm_is_zero_without_traffic():
    assert make_node("n1").rpm(now=1000.0) == 0


# --------------------------------------------------------------------------- #
# foa/services/state.py — NodeRuntime.score (§7.4)
# --------------------------------------------------------------------------- #


def test_score_formula_free_low_latency_node():
    """§7.4 — w_capacity*(1-active/max) + w_latency*(1-normalized) - error_penalty."""
    node = make_node("n1", active=0, max_concurrency=4, ewma_latency_ms=100.0)
    expected = CAPACITY_W * 1.0 + LATENCY_W * (1.0 - 100.0 / REFERENCE_MS)
    assert node.score(**SCORE_KW) == pytest.approx(math.floor(expected * 10_000) / 10_000)


def test_less_loaded_and_faster_node_outranks_busier_one():
    """§7.4 — загруженный/медленный узел проигрывает свободному и быстрому."""
    free = make_node("free", active=0, max_concurrency=4, ewma_latency_ms=50.0)
    busy = make_node("busy", active=3, max_concurrency=4, ewma_latency_ms=9000.0)
    assert free.score(**SCORE_KW) > busy.score(**SCORE_KW)
    assert free.score(**SCORE_KW) == pytest.approx(0.7995, abs=1e-4)
    assert busy.score(**SCORE_KW) == pytest.approx(0.3349, abs=1e-4)


def test_score_clamps_normalized_latency_at_one():
    """Задержка выше эталона не «уводит» скор в бесконечность (§7.4)."""
    slow = make_node("slow", active=0, max_concurrency=4, ewma_latency_ms=60_000.0)
    assert slow.score(**SCORE_KW) == pytest.approx(CAPACITY_W * 1.0 + LATENCY_W * (1.0 - 1.0))


def test_score_without_latency_data_gives_full_latency_credit():
    node = make_node("n1", active=0, max_concurrency=4, ewma_latency_ms=0.0)
    assert node.score(**SCORE_KW) == pytest.approx(CAPACITY_W + LATENCY_W)


def test_score_error_penalty_reduces_value():
    node = make_node("n1", active=0, max_concurrency=4, ewma_latency_ms=100.0)
    clean = node.score(**SCORE_KW)
    now = time.monotonic()
    for index in range(10):
        node.observe(ok=False, latency_ms=100.0, status=500, now=now + index * 0.01)
    degraded = node.score(**SCORE_KW)
    assert degraded < clean
    assert clean - degraded == pytest.approx(1.0, abs=1e-3), "error_rate=1.0 → штраф 1.0"


def test_score_error_penalty_is_capped_at_one():
    node = make_node("n1", active=0, max_concurrency=4, ewma_latency_ms=100.0)
    now = time.monotonic()
    for index in range(10):
        node.observe(ok=index == 0, latency_ms=100.0, status=200 if index == 0 else 500, now=now + index * 0.01)
    assert node.error_rate == pytest.approx(0.9)
    full = make_node("n2", active=0, max_concurrency=4, ewma_latency_ms=100.0)
    full_now = time.monotonic()
    for index in range(10):
        full.observe(ok=False, latency_ms=100.0, status=500, now=full_now + index * 0.01)
    assert node.score(**SCORE_KW) > full.score(**SCORE_KW)


def test_score_weight_bonus_is_small():
    """§7.4 — избыточный вес даёт лишь микронадбавку, не переопределяя задержку/нагрузку."""
    base = make_node("a", active=0, max_concurrency=4, ewma_latency_ms=100.0, effective_weight=1)
    heavy = make_node("b", active=0, max_concurrency=4, ewma_latency_ms=100.0, effective_weight=5)
    assert heavy.score(**SCORE_KW) - base.score(**SCORE_KW) == pytest.approx(0.0004)
    slow_but_heavy = make_node("c", active=0, max_concurrency=4, ewma_latency_ms=2_000.0, effective_weight=5)
    fast_light = make_node("d", active=0, max_concurrency=4, ewma_latency_ms=100.0, effective_weight=1)
    assert fast_light.score(**SCORE_KW) > slow_but_heavy.score(**SCORE_KW)


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — синхронизация пула (§4.4.4, §6.4)
# --------------------------------------------------------------------------- #


def test_sync_marks_routable_and_counts_states():
    pool = make_pool()
    healthy, degraded, candidate = make_node("h"), make_node("d", state=NodeState.DEGRADED), make_node("c", state=NodeState.CANDIDATE)
    summary = pool.sync([(healthy, True), (degraded, True), (candidate, True)])
    assert summary == {"total": 3, "routable": 2, "healthy": 1, "degraded": 1, "candidate": 1}
    assert healthy.routable is True and degraded.routable is True
    assert candidate.routable is False, "§4.4.4 — кандидаты не маршрутизируются"


def test_sync_requires_active_consent():
    pool = make_pool()
    node = make_node("n1")
    summary = pool.sync([(node, False)])
    assert node.routable is False
    assert summary["routable"] == 0


@pytest.mark.parametrize(
    "state",
    [NodeState.PENDING_CONSENT, NodeState.CONSENT_CHALLENGE_SENT, NodeState.UNHEALTHY, NodeState.DRAINING],
)
def test_sync_keeps_non_routable_states_out(state):
    pool = make_pool()
    node = make_node("n1", state=state)
    pool.sync([(node, True)])
    assert node.routable is False


@pytest.mark.parametrize("state", [NodeState.BLACKLISTED, NodeState.QUARANTINED, NodeState.REVOKED])
def test_sync_excludes_blocked_states_even_with_consent(state):
    """§6.4 — блэклист/карантин/отзыв исключаются немедленно."""
    pool = make_pool()
    node = make_node("n1", state=state)
    pool.sync([(node, True)])
    assert node.routable is False


def test_sync_preserves_accumulated_statistics():
    """Между синхронизациями накопленная статистика не теряется (§6.3)."""
    pool = make_pool()
    first = make_node("n1", ewma_latency_ms=250.0)
    pool.sync([(first, True)])
    replacement = make_node("n1", ewma_latency_ms=0.0)
    pool.sync([(replacement, True)])
    kept = pool.get("n1")
    assert kept is replacement
    assert kept.ewma_latency_ms == 250.0
    assert kept.samples is first.samples
    assert kept.breaker is first.breaker


def test_sync_keeps_active_connections_and_counters():
    pool = make_pool()
    original = make_node("n1")
    pool.sync([(original, True)])
    original.acquire()
    original.note_request(now=1000.0)
    original.tokens_this_hour = 7
    replacement = make_node("n1")
    pool.sync([(replacement, True)])
    assert pool.get("n1").active == 1
    assert pool.get("n1").requests_this_hour == 1
    assert pool.get("n1").tokens_this_hour == 7


def test_sync_drops_stale_nodes():
    pool = make_pool()
    a, b = make_node("a"), make_node("b")
    pool.sync([(a, True), (b, True)])
    assert sorted(pool.nodes) == ["a", "b"]
    pool.sync([(a, True)])
    assert list(pool.nodes) == ["a"]
    assert pool.get("b") is None


def test_pool_version_bumps_on_sync():
    pool = make_pool()
    node = make_node("a")
    version = pool.version
    pool.sync([(node, True)])
    assert pool.version == version + 1
    pool.sync([(node, True)])
    assert pool.version == version + 2


def test_pool_snapshot_lists_all_nodes():
    pool = route(make_node("a"), make_node("b", state=NodeState.CANDIDATE))
    snapshot = {entry["node_id"]: entry for entry in pool.snapshot()}
    assert set(snapshot) == {"a", "b"}
    assert snapshot["a"]["routable"] is True and snapshot["b"]["routable"] is False


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — §7.3.1 round robin
# --------------------------------------------------------------------------- #


def test_round_robin_cycles_over_sorted_ids():
    """§7.3.1 — обход по кругу; порядок задаётся сортировкой идентификаторов."""
    pool = make_pool("round_robin")
    pool.sync([(make_node("node_c"), True), (make_node("node_a"), True), (make_node("node_b"), True)])
    picks = [pool.pick().node_id for _ in range(7)]
    assert picks == ["node_a", "node_b", "node_c", "node_a", "node_b", "node_c", "node_a"]


def test_round_robin_cycles_over_eligible_nodes_only():
    """Пока узел занят, цикл идёт по оставшимся — курсор «привязан» к списку eligible."""
    pool = make_pool("round_robin")
    busy = make_node("node_a", max_concurrency=1, active=1)
    pool.sync([(busy, True), (make_node("node_b"), True)])
    assert [pool.pick().node_id for _ in range(3)] == ["node_b"] * 3
    busy.release()
    picks = [pool.pick().node_id for _ in range(4)]
    assert set(picks) == {"node_a", "node_b"}, "освобождённый узел вернулся в ротацию"


def test_round_robin_is_balanced_over_long_run():
    pool = make_pool("round_robin")
    pool.sync([(make_node(node_id), True) for node_id in ("a", "b", "c", "d")])
    counts = Counter(pool.pick().node_id for _ in range(400))
    assert set(counts) == {"a", "b", "c", "d"}
    assert set(counts.values()) == {100}


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — §7.3.2 weighted round robin
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("weights", "expected"), [((5, 3, 1), {"w1": 5, "w2": 3, "w3": 1}), ((3, 1), {"v1": 3, "v2": 1})])
def test_weighted_round_robin_distribution_follows_effective_weight(weights, expected):
    """§7.3.2 — сглаженный взвешенный RR: за полный цикл каждый получает ровно свой вес."""
    pool = make_pool("weighted_round_robin")
    nodes = [
        make_node(node_id, effective_weight=weight, max_concurrency=100)
        for node_id, weight in zip(sorted(expected), weights, strict=True)
    ]
    pool.sync([(node, True) for node in nodes])
    counts = Counter(pool.pick().node_id for _ in range(sum(weights)))
    assert dict(counts) == expected


def test_weighted_round_robin_interleaves_smoothly():
    """§7.3.2 — веса распределяются равномерно по циклу, а не пачками («5 подряд»)."""
    pool = make_pool("weighted_round_robin")
    pool.sync(
        [
            (make_node("w1", effective_weight=5, max_concurrency=100), True),
            (make_node("w2", effective_weight=3, max_concurrency=100), True),
            (make_node("w3", effective_weight=1, max_concurrency=100), True),
        ]
    )
    picks = [pool.pick().node_id for _ in range(9)]
    assert Counter(picks) == Counter({"w1": 5, "w2": 3, "w3": 1})
    assert picks[:5] != ["w1"] * 5, "нет пакетной отдачи одному узлу"
    assert picks.index("w3") <= 4, "самый лёгкий узел входит в ротацию сразу, а не в конце цикла"


def test_weighted_round_robin_treats_non_positive_weight_as_one():
    pool = make_pool("weighted_round_robin")
    pool.sync([(make_node("a", effective_weight=0), True), (make_node("b", effective_weight=1), True)])
    counts = Counter(pool.pick().node_id for _ in range(2))
    assert counts == Counter({"a": 1, "b": 1})


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — §7.3.3 least connections
# --------------------------------------------------------------------------- #


def test_least_connections_picks_least_loaded():
    """§7.3.3 — выбор узла с наименьшим числом активных соединений."""
    pool = make_pool("least_connections")
    pool.sync([(make_node("busy", active=3), True), (make_node("idle", active=0), True), (make_node("half", active=1), True)])
    assert pool.pick().node_id == "idle"


def test_least_connections_normalizes_by_effective_weight():
    """§7.3.3 — нагрузка сравнивается как active/effective_weight."""
    pool = make_pool("least_connections")
    weighted = make_node("big", effective_weight=4, active=2)  # 0.5
    plain = make_node("small", effective_weight=1, active=1)  # 1.0
    pool.sync([(weighted, True), (plain, True)])
    assert pool.pick().node_id == "big"


def test_least_connections_distributes_as_slots_fill():
    pool = make_pool("least_connections")
    a, b = make_node("a", max_concurrency=2), make_node("b", max_concurrency=2)
    pool.sync([(a, True), (b, True)])
    picked = []
    for _ in range(4):
        node = pool.pick()
        picked.append(node.node_id)
        node.acquire()
    assert sorted(picked) == ["a", "a", "b", "b"]


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — §7.3.4 least latency
# --------------------------------------------------------------------------- #


def test_least_latency_picks_fastest():
    """§7.3.4 — минимальная сглаженная задержка (EWMA)."""
    pool = make_pool("least_latency")
    pool.sync([(make_node("slow", ewma_latency_ms=4000.0), True), (make_node("fast", ewma_latency_ms=120.0), True)])
    assert pool.pick().node_id == "fast"


def test_least_latency_ignores_connection_count():
    pool = make_pool("least_latency")
    fast_busy = make_node("fast", ewma_latency_ms=100.0, active=3, max_concurrency=4)
    slow_idle = make_node("slow", ewma_latency_ms=5000.0, active=0)
    pool.sync([(fast_busy, True), (slow_idle, True)])
    assert pool.pick().node_id == "fast"


def test_least_latency_prefers_measured_node_over_unknown():
    """Узел без наблюдений (ewma == 0) трактуется как «нет данных» — §7.3.4."""
    pool = make_pool("least_latency")
    unknown = make_node("unknown", ewma_latency_ms=0.0)
    measured = make_node("measured", ewma_latency_ms=500.0)
    pool.sync([(unknown, True), (measured, True)])
    assert pool.pick().node_id == "measured"


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — §7.3.5 consistent hash
# --------------------------------------------------------------------------- #


def test_consistent_hash_is_stable_for_same_key():
    """§7.3.5 — один и тот же ключ маршрутизируется на один и тот же узел."""
    pool = make_pool("consistent_hash")
    pool.sync([(make_node(node_id, max_concurrency=100), True) for node_id in ("a", "b", "c")])
    picks = {pool.pick(hash_key="user-42").node_id for _ in range(20)}
    assert len(picks) == 1


def test_consistent_hash_spreads_different_keys():
    pool = make_pool("consistent_hash")
    pool.sync([(make_node(node_id, max_concurrency=100), True) for node_id in ("a", "b", "c")])
    counts = Counter(pool.pick(hash_key=f"key-{index}").node_id for index in range(60))
    assert set(counts) == {"a", "b", "c"}, "ни один узел не должен остаться без трафика"
    assert max(counts.values()) < 2 * min(counts.values()), "перекос колец не должен быть кратным"


def test_consistent_hash_respects_overload():
    """§7.3.5 — при перегрузе «своего» узла ключ уходит на следующее кольцо."""
    pool = make_pool("consistent_hash")
    a, b, c = (make_node(node_id, max_concurrency=1) for node_id in ("a", "b", "c"))
    pool.sync([(a, True), (b, True), (c, True)])
    key = next(k for k in (f"key-{i}" for i in range(200)) if pool.pick(hash_key=k).node_id == "a")
    a.active = 1
    moved = pool.pick(hash_key=key)
    assert moved.node_id != "a"
    assert moved.node_id in {"b", "c"}
    a.active = 0
    assert pool.pick(hash_key=key).node_id == "a", "после освобождения ключ возвращается на своё место"


def test_consistent_hash_falls_back_to_least_loaded_ring():
    """Все кольца перегружены — берётся узел с минимальной загрузкой (fail-open внутри eligible)."""
    pool = make_pool("consistent_hash")
    a, b = make_node("a", max_concurrency=2, active=2), make_node("b", max_concurrency=2, active=1)
    pool.sync([(a, True), (b, True)])
    assert pool.pick(hash_key="user-42").node_id == "b"


def test_consistent_hash_uses_model_as_key_when_hash_key_absent():
    pool = make_pool("consistent_hash")
    pool.sync([(make_node("m", models=("llama3.1",), max_concurrency=100), True)])
    assert pool.pick(model="llama3.1").node_id == "m"
    assert pool.pick(hash_key="llama3.1").node_id == pool.pick(model="llama3.1").node_id


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — §7.4 гибрид по умолчанию
# --------------------------------------------------------------------------- #


def test_default_algorithm_is_hybrid():
    """§7.4 — рекомендуемый алгоритм: least_connections_with_latency."""
    assert BalancerConfig().algorithm == "least_connections_with_latency"
    assert make_pool()._select([make_node("only")]).node_id == "only"


def test_hybrid_picks_best_score():
    """§7.4 — свободный и быстрый узел выигрывает у занятого и медленного."""
    free_fast = make_node("free", active=0, ewma_latency_ms=50.0)
    busy_slow = make_node("busy", active=3, ewma_latency_ms=9000.0)
    pool = make_pool()
    pool.sync([(busy_slow, True), (free_fast, True)])
    assert pool.pick().node_id == "free"
    assert free_fast.score(**SCORE_KW) > busy_slow.score(**SCORE_KW)


def test_hybrid_prefers_node_without_errors():
    clean = make_node("clean", active=1, ewma_latency_ms=200.0)
    failing = make_node("failing", active=1, ewma_latency_ms=200.0)
    now = time.monotonic()
    for index in range(6):
        failing.observe(ok=False, latency_ms=200.0, status=500, now=now + index * 0.01)
    assert failing.breaker.state == CLOSED, "6 событий ниже минимума 10 — цепь ещё закрыта"
    pool = make_pool()
    pool.sync([(clean, True), (failing, True)])
    assert pool.pick().node_id == "clean"


def test_hybrid_matches_manual_score_comparison():
    nodes = [
        make_node("a", active=1, max_concurrency=4, ewma_latency_ms=1000.0),
        make_node("b", active=0, max_concurrency=4, ewma_latency_ms=2000.0),
        make_node("c", active=2, max_concurrency=8, ewma_latency_ms=500.0),
    ]
    pool = make_pool()
    pool.sync([(node, True) for node in nodes])
    best = max(nodes, key=lambda node: node.score(**SCORE_KW))
    assert pool.pick().node_id == best.node_id


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — ошибки выбора (§9.5)
# --------------------------------------------------------------------------- #


def test_pick_without_nodes_raises_no_healthy_nodes():
    pool = make_pool()
    with pytest.raises(NoHealthyNodesError) as excinfo:
        pool.pick()
    assert excinfo.value.status_code == 503
    assert excinfo.value.code.value == "NO_HEALTHY_NODES"


def test_pick_without_routable_nodes_raises_no_healthy_nodes():
    """§4.4.4 — узел вне маршрутного множества не выдаётся наружу: пользователь видит 503."""
    pool = make_pool()
    pool.sync([(make_node("cand", state=NodeState.CANDIDATE), True)])
    with pytest.raises(NoHealthyNodesError):
        pool.pick()


def test_pick_without_consent_raises_no_healthy_nodes():
    """§5.1 — согласия нет — пользователю отдаётся 503, а не 404 (§9.3.2)."""
    pool = make_pool()
    pool.sync([(make_node("n1"), False)])
    with pytest.raises(NoHealthyNodesError):
        pool.pick(model="llama3.1")


def test_pick_unknown_model_raises_model_not_found():
    """§9.5 — 404 MODEL_NOT_FOUND, когда модель есть только на несогласованных узлах — тоже 404."""
    pool = make_pool()
    pool.sync([(make_node("n1", models=("llama3.1",)), True)])
    with pytest.raises(ModelNotFoundError) as excinfo:
        pool.pick(model="qwen2.5")
    assert excinfo.value.status_code == 404
    assert excinfo.value.code.value == "MODEL_NOT_FOUND"
    assert "qwen2.5" in str(excinfo.value)


def test_pick_when_all_slots_busy_returns_node_for_queueing():
    """§7.1 — когда свободных слотов нет, узел всё равно выдаётся: вызывающий встаёт в очередь."""
    pool = make_pool()
    pool.sync([(make_node("n1", max_concurrency=1, active=1), True)])
    assert pool.pick().node_id == "n1"
    assert pool.eligible(None)[0].node_id == "n1"


def test_pick_still_raises_when_no_routable_node_at_all():
    pool = make_pool()
    pool.sync([(make_node("n1", max_concurrency=1, active=1, state=NodeState.UNHEALTHY), True)])
    with pytest.raises(NoHealthyNodesError):
        pool.pick()


def test_pick_skips_node_with_open_breaker():
    """§6.5 — разомкнутая цепь исключает узел из выбора."""
    pool = make_pool("least_connections")
    broken, healthy = make_node("broken"), make_node("healthy")
    broken.breaker.force_open(now=time.monotonic() + 10**6)
    pool.sync([(broken, True), (healthy, True)])
    assert [pool.pick().node_id for _ in range(3)] == ["healthy"] * 3
    assert broken not in pool.eligible(None)


def test_pick_skips_node_beyond_hourly_limits():
    """§7.5 — узел, исчерпавший почасовой лимит, не получает трафика."""
    pool = make_pool("least_connections")
    spent, fresh = make_node("spent", max_requests_per_hour=1), make_node("fresh", max_requests_per_hour=10)
    spent.requests_this_hour = 1
    pool.sync([(spent, True), (fresh, True)])
    assert pool.pick().node_id == "fresh"


def test_eligible_excludes_full_concurrency_and_unroutable():
    pool = make_pool()
    busy = make_node("busy", max_concurrency=1, active=1)
    candidate = make_node("cand", state=NodeState.CANDIDATE)
    ok = make_node("ok")
    pool.sync([(busy, True), (candidate, True), (ok, True)])
    assert [node.node_id for node in pool.eligible(None)] == ["ok"]


def test_eligible_honours_model_filter():
    pool = route(make_node("a", models=("llama3.1:8b",)), make_node("b", models=("mistral:7b",)))
    assert [node.node_id for node in pool.eligible("llama3.1")] == ["a"]
    assert [node.node_id for node in pool.eligible(None)] == ["a", "b"]


def test_pick_exclude_retries_on_another_node():
    """§7.6 — повтор обязан выполняться на узле, ещё не отказавшем в этом запросе."""
    pool = make_pool("least_connections")
    pool.sync([(make_node("a"), True), (make_node("b"), True)])
    assert pool.pick(exclude={"a"}).node_id == "b"
    assert pool.pick(exclude={"b"}).node_id == "a"


def test_pick_exclude_with_nothing_left_raises_no_healthy_nodes():
    pool = make_pool()
    pool.sync([(make_node("only"), True)])
    with pytest.raises(NoHealthyNodesError):
        pool.pick(exclude={"only"})


def test_eligible_exclude_drops_the_listed_nodes():
    pool = route(make_node("a"), make_node("b"), make_node("c"))
    assert sorted(node.node_id for node in pool.eligible(None, exclude={"b"})) == ["a", "c"]
    assert pool.eligible(None, exclude={"a", "b", "c"}) == []


def test_degraded_node_is_last_resort():
    """§7.2/§7.7 — degraded участвует в маршрутизации, только когда здоровых нет."""
    pool = make_pool()
    pool.sync([(make_node("healthy"), True), (make_node("degraded", state=NodeState.DEGRADED), True)])
    assert [node.node_id for node in pool.eligible(None)] == ["healthy"]
    assert pool.pick().node_id == "healthy"


def test_degraded_node_serves_when_no_healthy_node_exists():
    pool = make_pool()
    pool.sync([(make_node("degraded", state=NodeState.DEGRADED), True)])
    assert [node.node_id for node in pool.eligible(None)] == ["degraded"]
    assert pool.pick().node_id == "degraded"


def test_allow_degraded_false_excludes_degraded_nodes():
    """§7.7 — явный запрет для вызывающего: degraded снимается даже как последняя опция.

    Замечание: :meth:`NodePool.pick` флаг не пробрасывает (всегда ``allow_degraded=True``),
    поэтому фильтр доступен только напрямую через ``eligible``.
    """
    pool = make_pool()
    pool.sync([(make_node("degraded", state=NodeState.DEGRADED), True)])
    assert pool.eligible(None, allow_degraded=False) == []
    assert pool.eligible(None)[0].node_id == "degraded"
    assert pool.pick().node_id == "degraded", "pick использует значение по умолчанию"


def test_candidates_for_model_lists_routable_supporters():
    pool = make_pool()
    pool.sync(
        [
            (make_node("a", models=("llama3.1",)), True),
            (make_node("b", models=("mistral",)), True),
            (make_node("c", models=("llama3.1",), state=NodeState.CANDIDATE), True),
        ]
    )
    assert sorted(node.node_id for node in pool.candidates_for_model("llama3.1")) == ["a"]
    assert sorted(node.node_id for node in pool.candidates_for_model(None)) == ["a", "b"]


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — резервирование слота
# --------------------------------------------------------------------------- #


def test_reserve_takes_a_slot_and_counts_the_request():
    pool = route(make_node("n1", max_concurrency=2))
    node = pool.get("n1")
    ticket = pool.reserve(node)
    assert ticket == 1, "билет — это номер занятого слота"
    assert node.active == 1
    assert node.requests_this_hour == 1
    assert node.rpm(now=time.monotonic()) == 1


def test_reserve_until_full_falls_back_to_queueing():
    """§7.1 — после заполнения ёмкости узел остаётся кандидатом (очередь), а не исчезает."""
    node = make_node("n1", max_concurrency=2)
    pool = route(node)
    pool.reserve(node)
    pool.reserve(node)
    assert node.active == 2
    assert [n.node_id for n in pool.eligible(None)] == ["n1"]
    assert pool.eligible(None, allow_degraded=False)[0].node_id == "n1"
    pool.release(node)
    assert node.active == 1
    assert [n.node_id for n in pool.eligible(None)] == ["n1"]


# --------------------------------------------------------------------------- #
# foa/services/balancer.py — §7.5 модели узла и согласованные ограничения
# --------------------------------------------------------------------------- #


def test_available_models_without_consent_restriction_is_observed_set():
    node = make_node("n1", models=("llama3.1:8b", "qwen2.5:7b"), allowed_models=())
    assert available_models(node) == {"llama3.1:8b", "qwen2.5:7b"}


def test_available_models_restricted_by_consent():
    """§7.5 — узел не обслуживает модели, отсутствующие в согласии."""
    node = make_node("n1", models=("llama3.1:8b", "mistral:7b", "qwen2.5:7b"), allowed_models=("llama3.1", "mistral:7b"))
    assert available_models(node) == {"llama3.1:8b", "mistral:7b"}


def test_available_models_with_empty_observed_and_allowed():
    assert available_models(make_node("n1")) == set()


def test_available_models_keeps_nothing_when_consent_excludes_everything():
    node = make_node("n1", models=("llama3.1:8b",), allowed_models=("qwen2.5",))
    assert available_models(node) == set()


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("llama3.1", True),
        ("llama3.1:8b", True),
        ("llama3.1:70b", True),
        ("mistral", False),
        ("mistral:7b", False),
        ("llama3", False),
        ("", False),
    ],
)
def test_node_supports_model_matches_family_and_tag(model, expected):
    """§7.3/§7.5 — соответствие по семейству и по тегу вида ``llama3.1:8b``."""
    node = make_node("n1", models=("llama3.1:8b",), allowed_models=("llama3.1",))
    assert node_supports_model(node, model) is expected


def test_node_supports_model_when_only_bare_name_observed():
    node = make_node("n1", models=("llama3.1",), allowed_models=("llama3.1",))
    assert node_supports_model(node, "llama3.1:8b") is True
    assert node_supports_model(node, "llama3.1") is True


def test_node_supports_model_when_only_tag_requested_from_bare_consent():
    node = make_node("n1", models=("llama3.1:8b", "llama3.2:3b"), allowed_models=("llama3.1", "llama3.2"))
    assert node_supports_model(node, "llama3.2:1b") is True
    assert node_supports_model(node, "llama3.3") is False


def test_pick_by_tagged_model_selects_supporting_node():
    """Запрос ``llama3.1:8b`` не должен попасть на узел с ``llama3.2:3b`` (§7.5)."""
    pool = make_pool()
    pool.sync(
        [
            (make_node("a", models=("llama3.1:8b",), allowed_models=("llama3.1",)), True),
            (make_node("b", models=("llama3.2:3b",), allowed_models=("llama3.2",)), True),
        ]
    )
    assert pool.pick(model="llama3.1:8b").node_id == "a"
    assert pool.pick(model="llama3.2").node_id == "b"


def test_pick_refuses_model_outside_consent():
    """§7.5, §17.1 — модель вне согласия недоступна, хотя узел маршрутизируемый."""
    pool = make_pool()
    pool.sync([(make_node("a", models=("llama3.1:8b", "mistral:7b"), allowed_models=("llama3.1",)), True)])
    assert pool.pick(model="llama3.1:8b").node_id == "a"
    with pytest.raises(ModelNotFoundError):
        pool.pick(model="mistral:7b")


def test_eligible_model_filter_does_not_leak_node_presence():
    """§9.3.2 — каталог формируется только по маршрутизируемым узлам."""
    pool = make_pool()
    pool.sync(
        [
            (make_node("a", models=("llama3.1",), state=NodeState.CANDIDATE), True),
            (make_node("b", models=("llama3.1",)), False),
        ]
    )
    assert pool.candidates_for_model("llama3.1") == []
    with pytest.raises(NoHealthyNodesError):
        pool.pick(model="llama3.1")
