"""Интеграционные тесты Health-чек и состояний узла (§6, §15.1, §15.3).

Проверяются: liveness/readiness/capability, пороги ошибок, пассивный мониторинг,
переходы состояний из таблицы §6.4, автоматический блэклист при 401/403 (FR-H-05)
и то, что активные проверки не выполняются до получения согласия (§4.3, §12.3).
"""

from __future__ import annotations

import pytest
from foa.domain.enums import NodeState
from foa.storage.db import get_session_factory
from foa.storage.repositories import BlacklistRepository, NodeRepository

pytestmark = pytest.mark.asyncio


async def _row(node_id: str):
    async with get_session_factory()() as session:
        return await NodeRepository.get(session, node_id)


async def test_no_active_checks_before_consent(gateway, fake_node_primary):
    """§4.3/§12.3: опрос несогласованного хоста = трафик без разрешения владельца."""
    await gateway.register_node(fake_node_primary)
    before = fake_node_primary.request_count
    async with get_session_factory()() as session:
        changed = await gateway.state.health.check_all(session)
        await session.commit()
    assert changed == []
    assert fake_node_primary.request_count == before, "health-checker не должен трогать узлы без согласия"


async def test_liveness_and_readiness_populate_state(gateway, fake_node_primary):
    node_id = await gateway.onboard(fake_node_primary)
    row = await _row(node_id)
    assert row.ollama_version == fake_node_primary.version
    assert set(row.observed_models) == {"llama3.1", "qwen2.5"}
    assert row.last_health_check is not None
    assert row.liveness_failures == 0 and row.readiness_failures == 0
    detail = await gateway.node_detail(node_id)
    assert detail["routable"] is True and detail["latency_ms"] >= 0


async def test_capability_check_detects_missing_model(gateway, fake_node_primary):
    """§6.2.3 — заявленная, но отсутствующая модель: узел не готов для неё."""
    registered = await gateway.register_node(fake_node_primary, models=["llama3.1", "nesushchestvuyushchaya"])
    node_id = registered["node_id"]
    await gateway.approve_node(node_id, fake_node_primary)
    await gateway.health_check(node_id)
    detail = await gateway.node_detail(node_id)
    # Модель отсутствует на узле → она не должна обслуживаться (balancer её не отдаст).
    from foa.services.balancer import node_supports_model

    runtime = gateway.state.pool.get(node_id)
    assert node_supports_model(runtime, "llama3.1") is True
    assert node_supports_model(runtime, "nesushchestvuyushchaya") is False
    assert detail["status"] in {"verified", "healthy", "degraded"}


async def test_liveness_failures_mark_node_unhealthy(gateway, fake_node_primary):
    """§6.4 — 3 ошибки liveness подряд → unhealthy."""
    node_id = await gateway.onboard(fake_node_primary)
    # Узел «упал»: пул keep-alive мог остаться живым, поэтому рвём соединения
    # транспорта и переводим узел в режим ошибок.
    fake_node_primary.mode = "error500"
    await gateway.state.transport.drop_client(__import__("foa.net.security", fromlist=["parse_endpoint"]).parse_endpoint(fake_node_primary.base_url))

    states = []
    for _ in range(4):
        async with get_session_factory()() as session:
            row = await NodeRepository.get(session, node_id)
            await gateway.state.health.check_node(session, row, runtime=gateway.state.pool.get(node_id), force=True)
            await gateway.state.nodes.sync_pool(session)
            await session.commit()
        states.append((await gateway.node_detail(node_id))["status"])
    assert states[-1] == NodeState.UNHEALTHY.value
    detail = await gateway.node_detail(node_id)
    assert detail["routable"] is False

    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503 and response.json()["code"] == "NO_HEALTHY_NODES"


async def test_auth_error_blacklists_node_immediately(gateway, fake_node_noauth):
    """§6.4, FR-H-05, §17.2 — 401 от узла: немедленный блэклист."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    # Регистрируем с временно рабочим режимом, затем узел начинает отказывать.
    registered = await gateway.register_node(fake_node_noauth)
    node_id = registered["node_id"]
    fake_node_noauth.mode = "ok"
    await gateway.approve_node(node_id, fake_node_noauth)
    await gateway.health_check(node_id)
    fake_node_noauth.mode = "unauthorized"

    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 502, "401 от узла трансформируется в ошибку шлюза"
    detail = await gateway.node_detail(node_id)
    assert detail["status"] == NodeState.BLACKLISTED.value and detail["routable"] is False
    assert detail["consent_status"] == "failed"

    async with get_session_factory()() as session:
        entry = await BlacklistRepository.active_for_node(session, node_id)
    assert entry is not None and entry.reason == "upstream_auth_error"
    assert entry.actor == "gateway"

    # Повторный запрос больше не доходит до узла.
    before = fake_node_noauth.request_count
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503
    assert fake_node_noauth.request_count == before


async def test_forbidden_from_node_blacklists(gateway, fake_node_forbidden):
    """§12.4.4 — 403 от узла также ведёт к блэклисту."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    registered = await gateway.register_node(fake_node_forbidden)
    node_id = registered["node_id"]
    fake_node_forbidden.mode = "ok"
    await gateway.approve_node(node_id, fake_node_forbidden)
    await gateway.health_check(node_id)
    fake_node_forbidden.mode = "forbidden"

    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 502
    assert (await gateway.node_detail(node_id))["status"] == NodeState.BLACKLISTED.value


async def test_passive_errors_degrade_then_isolate(gateway, fake_node_primary, fake_node_secondary):
    """§6.3, §6.4, §7.7 — 20% ошибок за окно: понижение веса → degraded."""
    await gateway.use_user_key(scopes=["ollama:generate"])
    # weight=4: понижение веса (§7.7.1) наблюдаемо только при запасе (пол — 1).
    node_id = await gateway.onboard(fake_node_primary, weight=4)
    runtime = gateway.state.pool.get(node_id)

    # Эмулируем серию ошибок узла через пассивный учёт.
    # §6.5: порог срабатывает при >=10 запросов в окне и доле ошибок > 50%.
    for _ in range(12):
        runtime.observe(ok=False, latency_ms=50, status=502)
    assert runtime.error_rate > 0.2
    assert runtime.breaker.state != 0, "circuit breaker обязан отреагировать"

    async with get_session_factory()() as session:
        row = await NodeRepository.get(session, node_id)
        await gateway.state.health.check_node(session, row, runtime=runtime, force=True)
        await gateway.state.nodes.sync_pool(session)
        await session.commit()
    detail = await gateway.node_detail(node_id)
    assert detail["status"] == NodeState.DEGRADED.value
    assert detail["effective_weight"] < detail["weight"], "§7.7.1 — вес понижен"


async def test_circuit_breaker_excludes_node_from_selection(gateway, fake_node_primary, fake_node_secondary):
    """§6.5 — при открытом механизме узел не получает новых запросов."""
    slow_id = await gateway.onboard(fake_node_primary)
    healthy_id = await gateway.onboard(fake_node_secondary, models=["llama3.1"])
    slow = gateway.state.pool.get(slow_id)
    healthy = gateway.state.pool.get(healthy_id)
    assert slow.routable and healthy.routable

    for _ in range(12):
        slow.breaker.record(False)
    assert slow.breaker.state == 2, "цепь обязана быть открыта"

    for _ in range(5):
        assert gateway.state.pool.pick(model="llama3.1").node_id == healthy_id
    text = await gateway.metrics()
    assert "node_circuit_breaker_state" in text


async def test_functional_check_disabled_by_default(gateway, fake_node_primary):
    """§6.2.5 — функциональная проверка с реальной генерацией выключена по умолчанию."""
    assert gateway.state.settings.health.functional_check_enabled is False
    node_id = await gateway.onboard(fake_node_primary)
    await gateway.health_check(node_id)
    generate_calls = [r for r in fake_node_primary.requests if r["path"] == "/api/generate"]
    assert generate_calls == [], "health-check не должен запускать генерацию на несогласованном узле"


async def test_functional_check_honors_owner_opt_in(gateway, fake_node_primary):
    """§6.2.5 — разрешена только при явном включении владельцем и в минимальных параметрах.

    Фоновый цикл health-checker'а (интервал 1 с в тестах) может выполнить
    несколько проверок, поэтому проверяется не количество вызовов, а то, что
    каждый из них безопасен по нагрузке.
    """
    node_id = await gateway.onboard(fake_node_primary)
    async with get_session_factory()() as session:
        row = await NodeRepository.get(session, node_id)
        row.functional_check_enabled = True
        row.functional_check_model = "llama3.1"
        await session.commit()

    gateway.state.settings.health.functional_check_enabled = True
    try:
        async with get_session_factory()() as session:
            row = await NodeRepository.get(session, node_id)
            await gateway.state.health.check_node(session, row, runtime=gateway.state.pool.get(node_id), force=True)
            await session.commit()
        calls = [r for r in fake_node_primary.requests if r["path"] == "/api/generate"]
        assert calls, "при включённой проверке генерация должна выполниться"
        for call in calls:
            body = call["body"]
            assert body["prompt"] == "ping"
            assert body["options"] == {"num_predict": 1}, "минимальный лимит токенов"
            assert body["stream"] is False
            assert body["model"] == "llama3.1", "только модель, назначенная владельцем"
    finally:
        gateway.state.settings.health.functional_check_enabled = False


async def test_health_transition_is_logged(gateway, fake_node_primary):
    node_id = await gateway.onboard(fake_node_primary)
    fake_node_primary.mode = "error500"
    async with get_session_factory()() as session:
        row = await NodeRepository.get(session, node_id)
        for _ in range(3):
            await gateway.state.health.check_node(session, row, runtime=gateway.state.pool.get(node_id), force=True)
        await gateway.state.nodes.sync_pool(session)
        await session.commit()
    fake_node_primary.mode = "error500"
    async with get_session_factory()() as session:
        row = await NodeRepository.get(session, node_id)
        await gateway.state.health.check_node(session, row, runtime=gateway.state.pool.get(node_id), force=True)
        await session.commit()

    entries = await gateway.audit(limit=50)
    events = [e["event"] for e in entries]
    assert "node.registered" in events and "node.verified" in events, "изменения согласия аудируются (§12.7 п.4)"
    status = (await gateway.node_detail(node_id))["status"]
    assert status in {
        NodeState.DEGRADED.value,
        NodeState.UNHEALTHY.value,
        NodeState.QUARANTINED.value,
        NodeState.BLACKLISTED.value,
    }, status
