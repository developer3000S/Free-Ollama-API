"""Нагрузочные тесты (§15.2).

Проверяют поведение шлюза под параллельной нагрузкой через реальный HTTP-путь:

* пиковая нагрузка и очередь запросов при заполненном узле;
* поведение при недоступности узлов (снятие с маршрутизации и сетевая недоступность);
* отсутствие утечек соединений/слотов после всплеска;
* отмена клиентских потоков под нагрузкой.

Лимиты по умолчанию (§13: 20 запросов/мин на модель, 2 одновременных стрима на
пользователя) занижают потолок ниже проверяемого пика, поэтому «тяжёлые» тесты
поднимают их параметризацией фикстуры ``gateway``. Все тесты помечены ``slow`` —
в быстром прогоне (`-m "not slow"`) они исключаются.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from foa.net.security import parse_endpoint

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]

# Пику и всплеску нужны потолки выше безопасных значений по умолчанию (§13).
# capability в consent.json тестового узла даёт max_concurrency=4, поэтому
# очередь к узлу обязана переждать всплеск, а не отдать 503.
BUSY_LIMITS = {
    "limits.requests_per_minute_per_model": 100_000,
    "limits.requests_per_minute_global": 100_000,
    "limits.requests_per_minute_per_user": 100_000,
    "limits.concurrent_stream_requests_per_user": 64,
    "load_balancer.queue_wait_timeout_seconds": 20.0,
}


async def _active_sum(gateway) -> int:
    return sum(runtime.active for runtime in gateway.state.pool.nodes.values())


@pytest.mark.parametrize("gateway", [BUSY_LIMITS], indirect=True)
async def test_peak_load_served_without_errors(gateway, fake_node_primary):
    """§15.2 «пиковая нагрузка» — N параллельных генераций обслуживаются без ошибок."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=48, rate_limit_per_minute=100_000)
    await gateway.onboard(fake_node_primary, models=["llama3.1"], max_concurrency=48)

    async def one() -> int:
        response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
        return response.status_code

    started = time.perf_counter()
    codes = await asyncio.gather(*(one() for _ in range(48)))
    elapsed = time.perf_counter() - started

    assert set(codes) == {200}, codes
    assert len([r for r in fake_node_primary.requests if r["path"] == "/api/generate"]) == 48
    # Пик отработал: активных соединений и занятых слотов не осталось.
    assert await _active_sum(gateway) == 0
    assert gateway.state.ratelimit.user_concurrency.snapshot() == {}
    assert elapsed < 20.0, f"слишком медленно: {elapsed:.1f}s"


async def test_request_queue_when_node_is_full(gateway, fake_node_primary):
    """§15.2 «очередь запросов» — при занятом узле второй ждёт, затем получает 503."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    await gateway.onboard(fake_node_primary, models=["llama3.1"], max_concurrency=1)
    # Узел «держит» единственный слот дольше queue_wait_timeout → второй не дождётся окна.
    fake_node_primary.latency_seconds = 1.2
    gateway.state.settings.load_balancer.queue_wait_timeout_seconds = 0.3

    async def slow() -> int:
        response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "hold"})
        return response.status_code

    first = asyncio.create_task(slow())
    await asyncio.sleep(0.15)  # гарантируем, что первый занял единственный слот
    second = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "queue"})
    first_code = await first

    assert first_code == 200, first_code
    assert second.status_code == 503, second.text
    assert second.json()["code"] == "NO_HEALTHY_NODES"
    # Узел жив и согласован — он просто занят: в реестре он остаётся маршрутизируемым.
    assert (await gateway.client.get("/readyz")).json()["routable_nodes"] == 1


async def test_no_routable_nodes_returns_503(gateway, fake_node_primary, fake_node_secondary):
    """§15.2 «недоступность узлов» — когда все узлы сняты с маршрутизации, отказ 503."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    first = await gateway.onboard(fake_node_primary, models=["llama3.1"])
    second = await gateway.onboard(fake_node_secondary, models=["llama3.1"])
    # Первый draining (§6.4), второй в блэклисте (§12.4.4) — оба вне ROUTABLE_STATES.
    await gateway.client.patch(f"/admin/nodes/{first}", headers=gateway.admin, json={"draining": True})
    await gateway.client.post(f"/admin/nodes/{second}/blacklist", headers=gateway.admin, json={"reason": "admin_manual"})

    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503, response.text
    assert response.json()["code"] == "NO_HEALTHY_NODES"
    assert (await gateway.client.get("/readyz")).status_code == 503


async def test_unreachable_node_fails_fast_without_hang(gateway, fake_node_primary):
    """§15.2 — сетевая недоступность единственного узла даёт 5xx, а не зависание."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    node_id = await gateway.onboard(fake_node_primary, models=["llama3.1"])
    fake_node_primary.stop()  # узел физически недоступен
    await gateway.state.transport.drop_client(parse_endpoint(fake_node_primary.base_url))
    gateway.state.pool.get(node_id).breaker.reset()

    started = time.perf_counter()
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    elapsed = time.perf_counter() - started

    assert response.status_code in {502, 503, 504}, response.text
    assert response.json()["code"] in {"UPSTREAM_ERROR", "UPSTREAM_TIMEOUT", "NO_HEALTHY_NODES"}
    assert elapsed < 15.0, f"отказ по недоступному узлу не должен зависеть ({elapsed:.1f}s)"
    # Соединение с узлом освобождено: утечки active-счётчика нет.
    await asyncio.sleep(0.2)
    assert gateway.state.pool.get(node_id).active == 0


@pytest.mark.parametrize("gateway", [BUSY_LIMITS], indirect=True)
async def test_no_connection_or_slot_leak_after_burst(gateway, fake_node_primary, fake_node_secondary):
    """§15.2 «утечки соединений» — после всплеска счётчики узлов и слотов обнулены."""
    headers = await gateway.use_user_key(scopes=["ollama:generate", "ollama:embed"], concurrent_requests=64, rate_limit_per_minute=100_000)
    ids = [
        await gateway.onboard(fake_node_primary, models=["llama3.1"], max_concurrency=48),
        await gateway.onboard(fake_node_secondary, models=["llama3.1"], max_concurrency=48),
    ]

    async def mixed(i: int) -> None:
        if i % 3 == 0:
            path, body = "/api/embed", {"model": "llama3.1", "input": "x"}
        else:
            path, body = "/api/generate", {"model": "llama3.1", "prompt": "x"}
        response = await gateway.client.post(path, headers=headers, json=body)
        assert response.status_code == 200, response.text

    await asyncio.gather(*(mixed(i) for i in range(40)))
    await asyncio.sleep(0.4)  # выход зависимостей и освобождение слотов

    assert await _active_sum(gateway) == 0
    assert gateway.state.ratelimit.user_concurrency.snapshot() == {}
    for node_id in ids:
        assert gateway.state.pool.get(node_id).active == 0


@pytest.mark.parametrize("gateway", [BUSY_LIMITS], indirect=True)
async def test_client_stream_cancellation_under_load(gateway, fake_node_primary):
    """§15.2 «отмена клиентских потоков» — обрывы потоков не оставляют висящих слотов."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=32, rate_limit_per_minute=100_000)
    node_id = await gateway.onboard(fake_node_primary, models=["llama3.1"], max_concurrency=48)
    runtime = gateway.state.pool.get(node_id)

    async def abort() -> int:
        async with gateway.client.stream(
            "POST", "/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x", "stream": True}
        ) as response:
            async for line in response.aiter_lines():
                if line.strip():
                    json.loads(line)
                    break  # читаем первый чанк и обрываем поток (§17.6)
            return response.status_code

    statuses = await asyncio.gather(*(abort() for _ in range(16)))
    assert statuses.count(200) == 16, statuses
    await asyncio.sleep(0.6)

    assert runtime.active == 0, f"остались активные соединения: {runtime.active}"
    assert gateway.state.ratelimit.user_concurrency.snapshot() == {}
