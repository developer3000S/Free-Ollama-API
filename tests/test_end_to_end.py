"""Сквозной тест базового пути (§16 этапы 1–2, §17 критерии 1, 4, 6, 7).

Полный жизненный цикл: выдача ключа → регистрация узла → без согласия трафик не
идёт → подтверждение владения → health-check → проксирование generate/chat/tags →
отзыв согласия (≤5 с).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.asyncio


async def test_user_endpoints_require_authentication(gateway, fake_node_primary):
    """§17.4 — все пользовательские эндпоинты требуют аутентификации."""
    for method, path in (("GET", "/api/version"), ("GET", "/api/tags"), ("POST", "/api/generate")):
        response = await gateway.client.request(method, path, json={} if method == "POST" else None)
        assert response.status_code == 401, path
        body = response.json()
        assert body["error"] == "unauthorized"
        assert body["code"] == "UNAUTHORIZED"
        assert body["request_id"].startswith("req_")


async def test_invalid_credentials_are_rejected(gateway):
    response = await gateway.client.get("/api/version", headers={"Authorization": "Bearer foa_nonexistent_key_123"})
    assert response.status_code == 401
    response = await gateway.client.get("/api/version", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401


async def test_full_lifecycle_consent_then_traffic(gateway, fake_node_primary):
    headers = await gateway.use_user_key(scopes=["ollama:read", "ollama:generate"])

    # 1. Регистрация узла: статус до согласия, маршрутизации нет (§5.1, §17.1).
    registered = await gateway.register_node(fake_node_primary)
    node_id = registered["node_id"]
    assert registered["status"] in {"pending_consent", "consent_challenge_sent"}
    assert registered["challenge"]
    assert registered["consent_url"].endswith("/.well-known/free-ollama/v1/consent.json")

    detail = await gateway.node_detail(node_id)
    assert detail["routable"] is False

    # Пока согласия нет, шлюз не проксирует на узел ничего (§17.1).
    response = await gateway.client.get("/api/tags", headers=headers)
    assert response.status_code == 200 and response.json()["models"] == []
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503
    assert response.json()["code"] == "NO_HEALTHY_NODES"
    assert fake_node_primary.request_count == 0, "запросы к узлу без согласия недопустимы"

    # 2. Владелец размещает consent.json и подтверждает владение (§5.3.1).
    verified = await gateway.approve_node(node_id, fake_node_primary)
    assert verified["status"] in {"verified", "healthy"}
    assert verified["consent_status"] == "verified"
    assert verified["allowed_models"] == ["llama3.1", "qwen2.5"]

    # 3. Health-check собирает модели (liveness + readiness, §6.2).
    status = await gateway.health_check(node_id)
    assert status in {"verified", "healthy"}
    detail = await gateway.node_detail(node_id)
    assert detail["routable"] is True
    assert set(detail["models"]) >= {"llama3.1"}

    # 4. Пользовательские эндпоинты работают через шлюз (§9.3).
    response = await gateway.client.get("/api/version", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["version"].startswith("gateway-") and payload["upstream_ollama_supported"] is True
    assert response.headers["x-foa-request-id"].startswith("req_")

    response = await gateway.client.get("/api/tags", headers=headers)
    assert response.status_code == 200
    names = {m["name"] for m in response.json()["models"]}
    assert {"llama3.1", "qwen2.5"} <= names
    # Адреса узлов не раскрываются (§9.3.2).
    assert "127.0.0.1" not in response.text

    response = await gateway.client.post(
        "/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "Hello", "stream": False}
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["response"] == "Hi from fake node" and data["done"] is True
    assert "x-foa-ratelimit-limit" in response.headers

    response = await gateway.client.post(
        "/api/chat", headers=headers, json={"model": "llama3.1", "messages": [{"role": "user", "content": "Hi"}], "stream": False}
    )
    assert response.status_code == 200, response.text
    assert response.json()["message"]["content"] == "Hello! How can I help you?"

    response = await gateway.client.post("/api/show", headers=headers, json={"name": "llama3.1"})
    assert response.status_code == 200
    assert response.json()["details"]["family"] == "llama"

    response = await gateway.client.post("/api/embeddings", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 200 and len(response.json()["embedding"]) == 3

    response = await gateway.client.post("/api/embed", headers=headers, json={"model": "llama3.1", "input": ["a", "b"]})
    assert response.status_code == 200 and len(response.json()["embeddings"]) == 2

    response = await gateway.client.get("/api/ps", headers=headers)
    assert response.status_code == 200 and "models" in response.json()

    # 5. Узел видел запросы и НЕ получил авторизацию клиента/его IP (§8.5.3).
    assert fake_node_primary.request_count >= 4
    for seen in fake_node_primary.headers_seen:
        assert "authorization" not in seen, "ключ клиента не уходит на узел"
        assert "x-forwarded-for" not in seen, "IP клиента не раскрывается"
        assert seen.get("x-foa-request-id", "").startswith("req_"), "трассировка обязательна (§12.3 п.5)"
    for path in ("/api/generate", "/api/chat", "/api/show"):
        proxy_headers = fake_node_primary.headers_by_path(path)
        assert proxy_headers, path
        assert all("x-foa-client-hash" in h for h in proxy_headers), path

    # 6. Отзыв согласия немедленно исключает узел (≤5 с, §5.5 / §17.3).
    result = await gateway.revoke(node_id, reason="owner_test")
    assert result["status"] == "revoked"
    assert result["applied_in_seconds"] <= 5.0

    detail = await gateway.node_detail(node_id)
    assert detail["routable"] is False and detail["status"] == "revoked"

    before = fake_node_primary.request_count
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503 and response.json()["code"] == "NO_HEALTHY_NODES"
    assert fake_node_primary.request_count == before, "после отзыва узел не должен получать запросы"


async def test_streaming_generate_is_proxied_ndjson(gateway, fake_node_primary):
    """§8.4 / §17.6 — потоковый NDJSON проксируется фрагментами."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)

    lines: list[dict] = []
    async with gateway.client.stream(
        "POST", "/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "Hello", "stream": True}
    ) as response:
        assert response.status_code == 200, await response.aread()
        assert response.headers["content-type"].startswith("application/x-ndjson")
        async for raw in response.aiter_lines():
            if raw.strip():
                lines.append(json.loads(raw))
    assert [chunk.get("response") for chunk in lines] == ["Hello", "!", ""]
    assert lines[-1]["done"] is True


async def test_streaming_chat_and_client_abort(gateway, fake_node_primary):
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)
    async with gateway.client.stream(
        "POST",
        "/api/chat",
        headers=headers,
        json={"model": "llama3.1", "messages": [{"role": "user", "content": "hi"}], "stream": True},
    ) as response:
        assert response.status_code == 200
        chunks = [json.loads(line) async for line in response.aiter_lines() if line.strip()]
    assert "".join((c.get("message") or {}).get("content", "") for c in chunks) == "Hi there"


async def test_forbidden_owner_operations_return_403(gateway):
    """§9.4 — pull/push/copy/delete недоступны конечным пользователям."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    for path in ("/api/pull", "/api/push", "/api/copy"):
        response = await gateway.client.post(path, headers=headers, json={"name": "llama3.1"})
        assert response.status_code == 403, path
        assert response.json()["code"] == "FORBIDDEN"
    response = await gateway.client.request("DELETE", "/api/delete", headers=headers, json={"model": "x"})
    assert response.status_code == 403


async def test_client_supplied_request_id_is_honored(gateway, fake_node_primary):
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await gateway.onboard(fake_node_primary)
    rid = "req_client-supplied-0001"
    response = await gateway.client.post(
        "/api/generate", headers={**headers, "X-FOA-Request-ID": rid}, json={"model": "llama3.1", "prompt": "x"}
    )
    assert response.status_code == 200
    assert response.headers["x-foa-request-id"] == rid
    assert fake_node_primary.headers_for(-1)["x-foa-request-id"] == rid


async def test_operational_endpoints(gateway):
    response = await gateway.client.get("/healthz")
    assert response.status_code == 200 and response.json()["status"] == "ok"
    response = await gateway.client.get("/readyz")
    assert response.status_code == 503 and response.json()["routable_nodes"] == 0
    text = await gateway.metrics()
    assert "gateway_requests_total" in text
    assert "gateway_upstream_errors_total" in text


async def test_shipped_example_config_is_valid(tmp_path):
    """§13/§17 — поставляемый config.example.yaml обязан загружаться без правок.

    Тест защищает от дрейфа: если в Settings переименовывают поле, пример
    конфигурации перестаёт загружаться, и это видно сразу.
    """
    from foa.config import load_settings

    example = Path(__file__).resolve().parent.parent / "config.example.yaml"
    assert example.exists(), "config.example.yaml отсутствует в репозитории"
    settings = load_settings(str(example), env={"FOA_STORAGE__DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path}/x.sqlite3"})
    # Безопасные значения по умолчанию из §13 не должны «уезжать» в примере.
    assert settings.security.require_consent is True
    assert settings.security.allow_unverified_nodes is False
    assert settings.security.route_candidates is False
    assert settings.security.active_scanning == "deny"
    assert settings.discovery.auto_route_candidates is False
    assert settings.discovery.mode == "inventory_only"
    assert settings.load_balancer.algorithm == "least_connections_with_latency"
    assert settings.load_balancer.retry_streaming_requests is False
    # Все источники discovery в примере выключены (§17.10).
    assert [name for name, source in settings.discovery.sources.items() if source.enabled] == []
