"""Интеграционные тесты балансировки, лимитов и потоков (§7, §8.4, §12.4, §15.1).

В отличие от юнит-тестов NodePool, здесь проверяется поведение через реальный
HTTP-путь шлюза: распределение запросов между узлами, лимиты владельца,
корректные ошибки и поведение потоков при отключении клиента.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from foa.domain.enums import NodeState
from foa.net.security import parse_endpoint
from foa.storage.db import get_session_factory
from foa.storage.repositories import NodeRepository
from tests.harness import FakeOllama

pytestmark = pytest.mark.asyncio


def _generate_calls(fake: FakeOllama) -> list[dict]:
    return [r for r in fake.requests if r["path"] == "/api/generate"]


async def test_traffic_is_distributed_between_nodes(gateway, fake_node_primary, fake_node_secondary):
    """§7.4 — гибридный алгоритм распределяет запросы на все здоровые узлы."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    await gateway.onboard(fake_node_primary, models=["llama3.1"])
    await gateway.onboard(fake_node_secondary, models=["llama3.1"])

    for _ in range(8):
        response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
        assert response.status_code == 200, response.text

    a, b = len(_generate_calls(fake_node_primary)), len(_generate_calls(fake_node_secondary))
    assert a > 0 and b > 0, f"трафик не распределился: {a}/{b}"
    assert a + b == 8


async def test_round_robin_algorithm_cycles(gateway, fake_node_primary, fake_node_secondary):
    """§7.3.1 — round robin поочерёдно использует узлы."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    await gateway.onboard(fake_node_primary, models=["llama3.1"])
    await gateway.onboard(fake_node_secondary, models=["llama3.1"])
    gateway.state.settings.load_balancer.algorithm = "round_robin"
    try:
        for _ in range(6):
            assert (await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})).status_code == 200
    finally:
        gateway.state.settings.load_balancer.algorithm = "least_connections_with_latency"
    a, b = len(_generate_calls(fake_node_primary)), len(_generate_calls(fake_node_secondary))
    assert a == b == 3, f"round robin дал {a}/{b}"


async def test_weighted_round_robin_respects_weights(gateway, fake_node_primary, fake_node_secondary):
    """§7.3.2 — веса, заданные владельцем, влияют на распределение."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    await gateway.onboard(fake_node_primary, models=["llama3.1"], weight=3)
    await gateway.onboard(fake_node_secondary, models=["llama3.1"], weight=1)
    gateway.state.settings.load_balancer.algorithm = "weighted_round_robin"
    try:
        for _ in range(8):
            assert (await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})).status_code == 200
    finally:
        gateway.state.settings.load_balancer.algorithm = "least_connections_with_latency"
    a, b = len(_generate_calls(fake_node_primary)), len(_generate_calls(fake_node_secondary))
    assert a > b, f"веса не учтены: {a}/{b}"


async def test_least_latency_prefers_faster_node(gateway, fake_node_primary, fake_node_secondary):
    """§7.3.4 — узел с меньшей EWMA-задержкой получает больше запросов."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    fast = await gateway.onboard(fake_node_primary, models=["llama3.1"])
    slow = await gateway.onboard(fake_node_secondary, models=["llama3.1"])
    gateway.state.pool.get(fast).ewma_latency_ms = 100.0
    gateway.state.pool.get(slow).ewma_latency_ms = 9000.0
    gateway.state.settings.load_balancer.algorithm = "least_latency"
    try:
        for _ in range(8):
            assert (await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})).status_code == 200
    finally:
        gateway.state.settings.load_balancer.algorithm = "least_connections_with_latency"
    a, b = len(_generate_calls(fake_node_primary)), len(_generate_calls(fake_node_secondary))
    assert a >= 6, f"быстрый узел получил {a}, медленный {b}"


async def test_only_nodes_with_model_are_used(gateway, fake_node_primary, fake_node_secondary):
    """§7.3/FR-L-03 — запрос уходит только на узел, где модель доступна."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary, models=["llama3.1", "qwen2.5"])
    await gateway.onboard(fake_node_secondary, models=["mistral"])

    assert (await gateway.client.post("/api/generate", headers=headers, json={"model": "mistral", "prompt": "x"})).status_code == 200
    assert len(_generate_calls(fake_node_secondary)) == 1
    assert _generate_calls(fake_node_primary) == []


async def test_unknown_model_returns_404(gateway, fake_node_primary):
    """§9.5.3 — MODEL_NOT_FOUND в совместимом формате."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "netakoy-model", "prompt": "x"})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == "MODEL_NOT_FOUND" and body["error"] and body["request_id"].startswith("req_")


async def test_consent_limited_models_are_enforced(gateway, fake_node_primary):
    """§7.5 — запрет обслуживания моделей, не указанных в согласии."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    # Владелец согласен только на llama3.1, хотя на узле стоят две модели.
    registered = await gateway.register_node(fake_node_primary, models=["llama3.1"])
    node_id = registered["node_id"]
    document = gateway.consent_doc(node_id, fake_node_primary)
    document["capabilities"]["models"] = ["llama3.1"]
    await gateway.approve_node(node_id, fake_node_primary, document=document)
    await gateway.health_check(node_id)

    assert (await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})).status_code == 200
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "qwen2.5", "prompt": "x"})
    assert response.status_code == 404, "модель вне согласия обслуживаться не должна"


async def test_node_concurrency_limit_is_respected(gateway, fake_node_primary):
    """§7.5 — узлу не отправляется больше одновременных запросов, чем он разрешил."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=10)
    node_id = await gateway.onboard(fake_node_primary, max_concurrency=2)
    fake_node_primary.latency_seconds = 0.3
    runtime = gateway.state.pool.get(node_id)

    observed: list[int] = []

    async def sample():
        for _ in range(40):
            observed.append(runtime.active)
            await asyncio.sleep(0.02)

    sampler = asyncio.create_task(sample())
    responses = await asyncio.gather(
        *[gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"}) for _ in range(6)]
    )
    await sampler
    assert all(r.status_code == 200 for r in responses), [r.status_code for r in responses]
    assert max(observed) <= 2, f"превышена максимальная одновременность узла: peak={max(observed)}"
    assert runtime.active == 0


async def test_node_hourly_request_budget(gateway, fake_node_primary):
    """§7.5 — лимит запросов в час, заданный владельцем узла."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=10)
    node_id = await gateway.onboard(fake_node_primary, max_requests_per_hour=3)
    runtime = gateway.state.pool.get(node_id)
    codes = []
    for _ in range(6):
        response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
        codes.append(response.status_code)
    assert codes[:3] == [200, 200, 200], codes
    assert set(codes[3:]) == {503}, f"после исчерпания бюджета узла ожидается NO_HEALTHY_NODES: {codes}"
    assert runtime.requests_this_hour >= 3


async def test_rate_limit_per_user(gateway, fake_node_primary):
    """§12.4.2, FR-A-05, §9.5.2 — 429 RATE_LIMITED с Retry-After."""
    await gateway.onboard(fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"], rate_limit_per_minute=3, concurrent_requests=8)
    codes = []
    for _ in range(8):
        response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
        codes.append(response.status_code)
        if response.status_code == 429:
            assert int(response.headers.get("retry-after", "0")) >= 1
            body = response.json()
            assert body["code"] == "RATE_LIMITED" and body["error"] and body["retry_after"] >= 1
            break
    assert 429 in codes, f"лимит не сработал: {codes}"
    assert codes.count(200) <= 4
    assert "gateway_rate_limited_total" in await gateway.metrics()


async def test_rate_limit_headers_are_present(gateway, fake_node_primary):
    """§8.5.2 — заголовки X-FOA-RateLimit-*."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 200
    limit = int(response.headers["x-foa-ratelimit-limit"])
    remaining = int(response.headers["x-foa-ratelimit-remaining"])
    reset = int(response.headers["x-foa-ratelimit-reset"])
    assert limit >= 1 and 0 <= remaining < limit and reset > 0


async def test_concurrency_limit_per_user(gateway, fake_node_primary, monkeypatch):
    """§12.4.2/§13 — не более concurrent_requests_per_user одновременных запросов."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)
    fake_node_primary.latency_seconds = 0.6
    monkeypatch.setattr(gateway.state.settings.limits, "concurrent_requests_per_user", 2)
    responses = await asyncio.gather(
        *[gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"}) for _ in range(4)]
    )
    codes = sorted(r.status_code for r in responses)
    assert 429 in codes, f"ограничение одновременности не сработало: {codes}"
    assert codes.count(200) <= 2, codes


async def test_generation_budget_limits(gateway, fake_node_primary):
    """§12.4.3 — num_predict и размер промпта ограничены политикой."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)

    response = await gateway.client.post(
        "/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x", "options": {"num_predict": 999999}}
    )
    assert response.status_code == 429
    body = response.json()
    assert body["code"] == "BUDGET_EXCEEDED" and body["details"]["max_num_predict"] == 2048

    big = "a" * (1024 * 1024 + 10)
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": big})
    assert response.status_code == 413, "тело больше max_request_bytes отклоняется до обработки"


async def test_unknown_option_rejected(gateway, fake_node_primary):
    """§12.4.5 — валидация только по белому списку параметров."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)
    response = await gateway.client.post(
        "/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x", "options": {"evil_flag": True}}
    )
    assert response.status_code == 400
    assert "unsupported option" in response.json()["error"]


async def test_daily_token_quota(gateway, fake_node_primary):
    """§12.4.2 — дневная квота токенов на ключ."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], tokens_per_day=10)
    await gateway.onboard(fake_node_primary)
    # Узел возвращает eval_count=7 за запрос: после двух запросов квота исчерпана.
    codes = []
    for _ in range(4):
        response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
        codes.append(response.status_code)
    assert 429 in codes, codes
    last = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert last.status_code == 429 and last.json()["code"] == "QUOTA_EXCEEDED"


async def test_stream_aborted_when_client_disconnects(gateway, fake_node_primary):
    """§8.4/§17.6, §15.2 — при отключении клиента соединение с узлом освобождается."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    node_id = await gateway.onboard(fake_node_primary)
    runtime = gateway.state.pool.get(node_id)

    async with gateway.client.stream(
        "POST", "/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x", "stream": True}
    ) as response:
        first = None
        async for line in response.aiter_lines():
            if line.strip():
                first = json.loads(line)
                break
        assert first is not None and first["response"] == "Hello"
        await response.aclose()
    await asyncio.sleep(0.3)
    assert runtime.active == 0, "соединение с узлом должно быть освобождено"


async def test_stream_error_after_start_cannot_retry(gateway, fake_node_primary):
    """§7.6/§8.4 — после первого байта повтор запрещён, ошибка отдаётся в потоке."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    node_id = await gateway.onboard(fake_node_primary)
    runtime = gateway.state.pool.get(node_id)
    fake_node_primary.mode = "stream_break"
    before = len(_generate_calls(fake_node_primary))

    lines: list[str] = []
    status = None
    try:
        async with gateway.client.stream(
            "POST", "/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x", "stream": True}
        ) as response:
            status = response.status_code
            async for line in response.aiter_lines():
                if line.strip():
                    lines.append(line)
    except Exception as exc:
        lines.append(f"transport-error:{type(exc).__name__}")

    assert status == 200, "поток начат успешно — статус изменить нельзя"
    assert any("par" in line for line in lines), lines
    assert len(_generate_calls(fake_node_primary)) - before == 1, "повтор потока запрещён (§7.6)"
    assert runtime.active == 0


async def test_retry_on_connection_error_keeps_request_id(gateway, fake_node_primary):
    """§7.6 — повтор при ошибке соединения выполняется с тем же X-FOA-Request-ID."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    first = FakeOllama(name="flaky", models=["llama3.1"]).start()
    second = FakeOllama(name="stable", models=["llama3.1"]).start()
    try:
        bad_id = await gateway.onboard(first, models=["llama3.1"])
        await gateway.onboard(second, models=["llama3.1"])
        rid = "req_retry-same-id-0001"

        # Первый узел становится недоступным: соединение с ним отброшено, а
        # keep-alive-клиент закрыт, чтобы запрос дал ошибку соединения.
        first.stop()
        await gateway.state.transport.drop_client(parse_endpoint(first.base_url))
        gateway.state.pool.get(bad_id).breaker.reset()

        response = await gateway.client.post(
            "/api/generate", headers={**headers, "X-FOA-Request-ID": rid}, json={"model": "llama3.1", "prompt": "x"}
        )
        assert response.status_code == 200, response.text
        assert len(_generate_calls(second)) >= 1, "повтор должен уйти на здоровый узел"
        delivered = [h.get("x-foa-request-id") for h in second.headers_seen]
        assert rid in delivered, f"повтор обязан сохранить request-id: {delivered}"
    finally:
        second.stop()


async def test_no_retry_after_generation_started(gateway, fake_node_primary, fake_node_secondary):
    """§7.6 — после начала обработки узлом повтор запрещён."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    await gateway.onboard(fake_node_primary, models=["llama3.1"])
    await gateway.onboard(fake_node_secondary, models=["llama3.1"])
    gateway.state.settings.load_balancer.max_retries = 1
    fake_node_primary.mode = "error500"

    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    # Узел уже приступил к обработке (5xx вместо ошибки соединения) — повтор
    # запрещён, а клиент получает 502 UPSTREAM_ERROR (§9.5.5).
    assert response.status_code == 502
    assert response.json()["code"] == "UPSTREAM_ERROR"
    assert len(_generate_calls(fake_node_primary)) == 1, "повтор на тот же узел недопустим"
    assert len(_generate_calls(fake_node_secondary)) == 0, "повтор на другой узел недопустим"


async def test_read_timeout_is_not_retried_for_generation(gateway, fake_node_primary, fake_node_secondary):
    """§7.6 — таймаут ожидания ответа означает «обработка могла начаться»: без повтора."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"], concurrent_requests=8)
    # WRR с весом 100 гарантирует, что первым выбирается «медленный» узел.
    await gateway.onboard(fake_node_primary, models=["llama3.1"], weight=100)
    await gateway.onboard(fake_node_secondary, models=["llama3.1"], weight=1)
    gateway.state.settings.load_balancer.max_retries = 1
    gateway.state.settings.limits.max_generation_seconds = 0.4
    fake_node_primary.latency_seconds = 1.5
    gateway.state.settings.load_balancer.algorithm = "weighted_round_robin"
    try:
        response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    finally:
        gateway.state.settings.load_balancer.algorithm = "least_connections_with_latency"
    assert response.status_code == 504, response.status_code
    assert response.json()["code"] == "UPSTREAM_TIMEOUT"
    assert len(_generate_calls(fake_node_secondary)) == 0, "запрос с побочным эффектом не повторяется на другом узле"


async def test_no_healthy_nodes_returns_503(gateway, fake_node_primary):
    """§9.5.4 — все узлы нездоровы."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    node_id = await gateway.onboard(fake_node_primary)
    await gateway.health_check(node_id)

    async with get_session_factory()() as session:
        row = await NodeRepository.get(session, node_id)
        row.status = NodeState.UNHEALTHY.value
        await gateway.state.nodes.sync_pool(session)
        await session.commit()

    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503
    assert response.json()["code"] == "NO_HEALTHY_NODES"


async def test_aggregated_tags_merge_models_from_nodes(gateway, fake_node_primary, fake_node_secondary):
    """§9.3.2 — список моделей агрегируется, адреса узлов не раскрываются."""
    headers = await gateway.use_user_key(scopes=["ollama:read"])
    await gateway.onboard(fake_node_primary, models=["llama3.1", "qwen2.5"])
    await gateway.onboard(fake_node_secondary, models=["llama3.1", "mistral"])
    response = await gateway.client.get("/api/tags", headers=headers)
    assert response.status_code == 200
    names = {m["name"] for m in response.json()["models"]}
    assert names == {"llama3.1", "qwen2.5", "mistral"}
    assert "127.0.0.1" not in response.text and f":{fake_node_primary.port}" not in response.text


async def test_draining_node_stops_receiving_traffic(gateway, fake_node_primary, fake_node_secondary):
    """§3.2.4/§6.4 — draining-узел не получает новых запросов, но остаётся в реестре."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    drain_id = await gateway.onboard(fake_node_primary, models=["llama3.1"])
    await gateway.onboard(fake_node_secondary, models=["llama3.1"])

    response = await gateway.client.patch(f"/admin/nodes/{drain_id}", headers=gateway.admin, json={"draining": True})
    assert response.status_code == 200, response.text
    assert (await gateway.node_detail(drain_id))["status"] == NodeState.DRAINING.value

    calls_before = len(_generate_calls(fake_node_primary))
    for _ in range(4):
        assert (await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})).status_code == 200
    assert len(_generate_calls(fake_node_primary)) == calls_before
    assert len(_generate_calls(fake_node_secondary)) == 4

    response = await gateway.client.patch(f"/admin/nodes/{drain_id}", headers=gateway.admin, json={"draining": False})
    assert response.status_code == 200
    detail = await gateway.node_detail(drain_id)
    assert detail["status"] in {NodeState.VERIFIED.value, NodeState.HEALTHY.value}
