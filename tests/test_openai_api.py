"""OpenAI-совместимый API ``/v1/*`` — интеграционные тесты (README «OpenAI-совместимый API»).

Проверяют, что второй контракт использует те же аутентификацию, лимиты и
consent gate, что и Ollama API: конвертация формата не должна открывать обходных
путей к узлам (§17.1) или менять формат ошибок §9.5 у основного контракта.
Чистые конвертеры проверены в tests/test_units_openai.py.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.asyncio


async def _onboard(gateway, fake_node, models=("llama3.1",)):
    await gateway.onboard(fake_node, models=list(models))


def _events(body: str) -> list:
    events = []
    for block in body.split("\n\n"):
        block = block.strip()
        if not block.startswith("data:"):
            continue
        data = block[len("data:") :].strip()
        events.append("[DONE]" if data == "[DONE]" else json.loads(data))
    return events


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #


async def test_chat_completions_non_stream(gateway, fake_node_primary):
    """§9.3.5 → chat.completion: message, finish_reason, usage из eval_count."""
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"])

    response = await gateway.client.post(
        "/v1/chat/completions",
        headers=headers,
        json={"model": "llama3.1", "messages": [{"role": "user", "content": "Привет"}]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["object"] == "chat.completion"
    assert body["model"] == "llama3.1"
    assert body["choices"][0]["message"] == {"role": "assistant", "content": "Hello! How can I help you?"}
    assert body["choices"][0]["finish_reason"] == "stop"
    assert body["usage"] == {"prompt_tokens": 15, "completion_tokens": 7, "total_tokens": 22}
    assert response.headers["X-FOA-Request-ID"]
    # Узел получил Ollama-тело, а не OpenAI-форм.
    sent = fake_node_primary.last_request()["body"]
    assert sent["messages"][0]["role"] == "user" and "prompt" not in sent


async def test_chat_completions_stream_is_sse(gateway, fake_node_primary):
    """§8.4 → SSE: дельта за дельтой, finish_reason, завершающий [DONE]."""
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"])

    async with gateway.client.stream(
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={"model": "llama3.1", "messages": [{"role": "user", "content": "x"}], "stream": True},
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["X-Accel-Buffering"] == "no"
        text = "".join([line async for line in response.aiter_text()])

    events = _events(text)
    assert events[-1] == "[DONE]"
    chunks = [e for e in events if isinstance(e, dict)]
    assert all(c["object"] == "chat.completion.chunk" for c in chunks)
    assert chunks[0]["choices"][0]["delta"]["role"] == "assistant"
    assert "".join(c["choices"][0]["delta"].get("content", "") for c in chunks) == "Hi there"
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    # include_usage не запрошен → usage в потоке нет.
    assert not any("usage" in c for c in chunks)


async def test_chat_completions_stream_with_usage_chunk(gateway, fake_node_primary):
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    await _onboard(gateway, fake_node_primary)
    async with gateway.client.stream(
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={
            "model": "llama3.1",
            "messages": [{"role": "user", "content": "x"}],
            "stream": True,
            "stream_options": {"include_usage": True},
        },
    ) as response:
        text = "".join([line async for line in response.aiter_text()])

    chunks = [e for e in _events(text) if isinstance(e, dict)]
    final = chunks[-1]
    assert final["choices"] == []
    assert final["usage"] == {"prompt_tokens": 0, "completion_tokens": 7, "total_tokens": 7}


async def test_completions_legacy_endpoint(gateway, fake_node_primary):
    """/v1/completions → /api/generate: text_completion (response → choices[].text)."""
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    response = await gateway.client.post("/v1/completions", headers=headers, json={"model": "llama3.1", "prompt": "Привет"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["object"] == "text_completion"
    assert body["choices"][0]["text"] == "Hi from fake node"
    assert body["usage"]["completion_tokens"] == 7
    assert fake_node_primary.last_request()["path"] == "/api/generate"


async def test_embeddings_endpoint(gateway, fake_node_primary):
    """/v1/embeddings → /api/embed: объект list с data[i].embedding."""
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:embed"])
    response = await gateway.client.post("/v1/embeddings", headers=headers, json={"model": "llama3.1", "input": ["a", "b", "c"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["object"] == "list"
    assert [item["index"] for item in body["data"]] == [0, 1, 2]
    assert body["data"][0]["embedding"] == [0.1, 0.2, 0.3]
    assert all(item["object"] == "embedding" for item in body["data"])


async def test_models_list_and_retrieve(gateway, fake_node_primary):
    """/v1/models из /api/tags: без адресов узлов (§9.3.2), + точечное получение."""
    await _onboard(gateway, fake_node_primary, models=("llama3.1", "qwen2.5"))
    headers = await gateway.use_user_key(scopes=["ollama:read"])

    response = await gateway.client.get("/v1/models", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["object"] == "list"
    assert [item["id"] for item in body["data"]] == ["llama3.1", "qwen2.5"]
    assert body["data"][0]["object"] == "model"
    assert body["data"][0]["owned_by"] == "free-ollama-api-gateway"
    # Адрес узла не просачивается ни в одно поле (§12.5.2).
    assert str(fake_node_primary.port) not in response.text

    response = await gateway.client.get("/v1/models/llama3.1", headers=headers)
    assert response.status_code == 200 and response.json()["id"] == "llama3.1"
    response = await gateway.client.get("/v1/models/nosuchmodel", headers=headers)
    assert response.status_code == 404
    assert response.json()["error"]["type"] == "invalid_request_error"


# --------------------------------------------------------------------------- #
# те же гарантии, что у Ollama API
# --------------------------------------------------------------------------- #


async def test_openai_endpoints_require_authentication(gateway):
    """§17.4 — нет ключа → 401 authentication_error в конверте OpenAI."""
    for path in ("/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings"):
        method = "GET" if path == "/v1/models" else "POST"
        response = await gateway.client.request(method, path, json={"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]})
        assert response.status_code == 401, path
        error = response.json()["error"]
        assert error["type"] == "authentication_error"
        assert error["code"] == "unauthorized"


async def test_openai_respects_consent_gate(gateway, fake_node_primary):
    """§17.1 — узел без подтверждённого согласия недоступен и через /v1/*."""
    await gateway.register_node(fake_node_primary)  # регистрация без подтверждения владения
    headers = await gateway.use_user_key(scopes=["ollama:generate"])

    response = await gateway.client.post(
        "/v1/chat/completions", headers=headers, json={"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]}
    )
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "no_healthy_nodes"
    assert fake_node_primary.request_count == 0

    response = await gateway.client.post("/v1/completions", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503
    assert fake_node_primary.request_count == 0


async def test_openai_scope_enforcement(gateway, fake_node_primary):
    """§9.2 — read-ключ не генерирует, embed-ключ считает эмбеддинги но не генерацию."""
    await _onboard(gateway, fake_node_primary)
    read_key = await gateway.use_user_key(scopes=["ollama:read"])
    embed_key = await gateway.use_user_key(scopes=["ollama:embed"])

    response = await gateway.client.post(
        "/v1/chat/completions", headers=read_key, json={"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]}
    )
    assert response.status_code == 403 and response.json()["error"]["type"] == "permission_denied"

    response = await gateway.client.post("/v1/embeddings", headers=embed_key, json={"model": "llama3.1", "input": "a"})
    assert response.status_code == 200
    response = await gateway.client.post("/v1/completions", headers=embed_key, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 403


async def test_openai_limited_models_are_enforced(gateway, fake_node_primary):
    """§7.5 — модель вне capability-документа согласия недоступна и через /v1/*."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    registered = await gateway.register_node(fake_node_primary, models=["llama3.1"])
    node_id = registered["node_id"]
    document = gateway.consent_doc(node_id, fake_node_primary)
    document["capabilities"]["models"] = ["llama3.1"]
    await gateway.approve_node(node_id, fake_node_primary, document=document)
    await gateway.health_check(node_id)

    ok = await gateway.client.post(
        "/v1/chat/completions", headers=headers, json={"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]}
    )
    assert ok.status_code == 200
    response = await gateway.client.post(
        "/v1/chat/completions", headers=headers, json={"model": "qwen2.5", "messages": [{"role": "user", "content": "x"}]}
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "model_not_found"


async def test_openai_rate_limited(gateway, fake_node_primary):
    """§12.4.2 — лимит частоты применяется и к /v1/* (429 rate_limit_error)."""
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"], rate_limit_per_minute=1)
    payload = {"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]}
    first = await gateway.client.post("/v1/chat/completions", headers=headers, json=payload)
    assert first.status_code == 200
    second = await gateway.client.post("/v1/chat/completions", headers=headers, json=payload)
    assert second.status_code == 429
    assert second.json()["error"]["type"] == "rate_limit_error"
    assert second.headers["Retry-After"]


async def test_openai_quota_is_shared_with_ollama_api(gateway, fake_node_primary):
    """§12.4.2 — один бюджет на оба контракта: Ollama-запрос уменьшает остаток /v1/*.

    Проверка по заголовкам X-FOA-RateLimit-Remaining: лимит считается на ключ,
    а не на пространство имён путей, иначе второй контракт удваивал бы пропускную
    способность клиента.
    """
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"], rate_limit_per_minute=6)
    payload = {"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]}

    first = await gateway.client.post("/api/chat", headers=headers, json=payload)
    assert first.status_code == 200
    remaining_after_ollama = int(first.headers["X-FOA-RateLimit-Remaining"])
    second = await gateway.client.post("/v1/chat/completions", headers=headers, json=payload)
    assert second.status_code == 200
    remaining_after_openai = int(second.headers["X-FOA-RateLimit-Remaining"])
    assert remaining_after_openai == remaining_after_ollama - 1


async def test_node_selection_still_blocked_on_v1(gateway, fake_node_primary):
    """§12.4.5 — попытка выбрать узел через заголовок отклоняется и на /v1/*."""
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    headers["X-FOA-Node"] = "node_01ZZZZZZZZZZZZZZZZZZZZZZZZ"
    response = await gateway.client.post(
        "/v1/chat/completions", headers=headers, json={"model": "llama3.1", "messages": [{"role": "user", "content": "x"}]}
    )
    assert response.status_code == 403
    assert response.json()["error"]["type"] == "permission_denied"


async def test_ollama_contract_error_format_unchanged(gateway, fake_node_primary):
    """§9.5 — конверт OpenAI не подменяет Ollama-формат ошибок на /api/*."""
    await _onboard(gateway, fake_node_primary)
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "nosuch", "prompt": "x"})
    assert response.status_code == 404
    body = response.json()
    assert "error" in body and body["code"] == "MODEL_NOT_FOUND"
    assert "request_id" in body


async def test_unknown_v1_route_is_not_405(gateway):
    """Неизвестный путь /v1/* — 404 в конверте OpenAI, а не FastAPI-овский detail."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    response = await gateway.client.post("/v1/audio/speech", headers=headers, json={"model": "x"})
    assert response.status_code == 404
    assert response.json()["error"]["type"] == "invalid_request_error"


async def test_stream_failure_after_first_byte_reports_openai_error(gateway, fake_node_primary):
    """§7.6 — обрыв upstream в середине потока превращается в SSE-объект ошибки.

    Режим stream_break у фейкового узла относится к /api/generate, поэтому
    поток открывается через /v1/completions.
    """
    await _onboard(gateway, fake_node_primary)
    fake_node_primary.mode = "stream_break"
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    async with gateway.client.stream(
        "POST",
        "/v1/completions",
        headers=headers,
        json={"model": "llama3.1", "prompt": "x", "stream": True},
    ) as response:
        text = "".join([line async for line in response.aiter_text()])
    events = _events(text)
    assert any(isinstance(e, dict) and "error" in e for e in events), text
    assert events[-1] == "[DONE]"


async def test_openai_router_can_be_disabled(tmp_path):
    """server.openai_api_enabled=false — контракт выключается, Ollama остаётся."""
    from foa.app import create_app
    from foa.config import default_settings

    settings = default_settings()
    settings.storage.database_url = f"sqlite+aiosqlite:///{tmp_path / 'off.db'}"
    settings.storage.data_dir = ""
    settings.auth.admin_token = "test-admin"
    settings.server.openai_api_enabled = False
    paths = set(create_app(settings).openapi()["paths"])
    assert "/v1/chat/completions" not in paths
    assert "/api/chat" in paths


async def test_openai_contract_is_documented_in_openapi(gateway):
    """§16 — второй контракт описан в OpenAPI-схеме шлюза (/docs)."""
    response = await gateway.client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "/v1/chat/completions" in schema["paths"]
    assert "/v1/models" in schema["paths"]
    assert "openai" in schema["paths"]["/v1/chat/completions"]["post"]["tags"]

