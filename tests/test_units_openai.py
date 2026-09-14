"""Юнит-тесты конвертеров OpenAI ⇄ Ollama (README «OpenAI-совместимый API»).

Проверяют только чистые функции преобразования: маппинг параметров, откат
неподдерживаемых полей (§17.7), разбор NDJSON и сборку SSE — без HTTP-слоя.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from foa.domain import openai as oa


def _events(body: str) -> list:
    events = []
    for block in body.split("\n\n"):
        block = block.strip()
        if not block.startswith("data:"):
            continue
        data = block[len("data:") :].strip()
        events.append("[DONE]" if data == "[DONE]" else json.loads(data))
    return events


def _collect(gen) -> list:
    async def run():
        return [chunk_bytes async for chunk_bytes in gen]

    return asyncio.run(run())


# --------------------------------------------------------------------------- #
# запрос: OpenAI → Ollama
# --------------------------------------------------------------------------- #


def test_chat_request_maps_parameters_to_ollama_options():
    parsed = oa.ChatCompletionRequest.model_validate(
        {
            "model": "llama3.1",
            "messages": [
                {"role": "developer", "content": "будь краток"},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "привет"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAA"}},
                    ],
                },
            ],
            "max_tokens": 32,
            "temperature": 0.2,
            "top_p": 0.9,
            "stop": "\n",
            "response_format": {"type": "json_object"},
        }
    )
    body = oa.to_chat_request(parsed)
    assert body["messages"][0] == {"role": "system", "content": "будь краток"}
    assert body["messages"][1]["content"] == "привет\ndata:image/png;base64,AAA"
    assert body["images"] == ["AAA"]
    assert body["options"] == {"num_predict": 32, "temperature": 0.2, "top_p": 0.9, "stop": ["\n"]}
    assert body["format"] == "json"
    assert "user" not in body  # идентификатор клиента узлу не передаётся (§8.5.3)


def test_max_completion_tokens_wins_over_max_tokens():
    parsed = oa.ChatCompletionRequest.model_validate(
        {"model": "m", "messages": [{"role": "user", "content": "x"}], "max_tokens": 10, "max_completion_tokens": 20}
    )
    assert oa.to_chat_request(parsed)["options"]["num_predict"] == 20


def test_completion_request_maps_to_generate():
    parsed = oa.CompletionRequest.model_validate({"model": "m", "prompt": "раз-два", "temperature": 0.5, "stop": ["END"]})
    body = oa.to_generate_request(parsed)
    assert body["prompt"] == "раз-два" and body["stream"] is False
    assert body["options"] == {"temperature": 0.5, "stop": ["END"]}


def test_embed_request_maps_input_unchanged():
    parsed = oa.EmbeddingRequest.model_validate({"model": "m", "input": ["a", "b"]})
    assert oa.to_embed_request(parsed) == {"model": "m", "input": ["a", "b"]}


def test_tools_are_forwarded_and_tool_choice_auto_is_noop():
    """tools уходит на узел; auto ничего к payload не добавляет (§9.3.5)."""
    parsed = oa.ChatCompletionRequest.model_validate(
        {
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "tools": [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}],
            "tool_choice": "auto",
        }
    )
    body = oa.to_chat_request(parsed)
    assert body["tools"][0]["function"]["name"] == "get_weather"
    assert "tool_choice" not in body


def test_tool_choice_none_drops_tools():
    """tool_choice="none" исполнимо: инструменты просто не отправляются."""
    parsed = oa.ChatCompletionRequest.model_validate(
        {
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "tools": [{"type": "function", "function": {"name": "get_weather"}}],
            "tool_choice": "none",
        }
    )
    assert "tools" not in oa.to_chat_request(parsed)


@pytest.mark.parametrize("tool_choice", ["required", {"type": "function", "function": {"name": "get_weather"}}])
def test_mandatory_tool_choice_rejected(tool_choice):
    """§17.7 — «обязательно вызови инструмент» шлюз не гарантирует, поэтому отклоняется."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="tool_choice"):
        oa.ChatCompletionRequest.model_validate(
            {
                "model": "m",
                "messages": [{"role": "user", "content": "x"}],
                "tools": [{"type": "function", "function": {"name": "get_weather"}}],
                "tool_choice": tool_choice,
            }
        )


def test_remote_image_urls_are_not_forwarded():
    """SSRF через image_url: внешнюю ссылку узел не получает (§12.5.1)."""
    parsed = oa.ChatCompletionRequest.model_validate(
        {
            "model": "m",
            "messages": [
                {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "http://169.254.169.254/latest/meta-data"}}]}
            ],
        }
    )
    body = oa.to_chat_request(parsed)
    assert "169.254.169.254" not in body["messages"][0]["content"]
    assert "omitted" in body["messages"][0]["content"]
    assert not body.get("images")


@pytest.mark.parametrize(
    "payload",
    [
        {"model": "m", "messages": [{"role": "user", "content": "x"}], "n": 2},
        {"model": "m", "messages": [{"role": "user", "content": "x"}], "logprobs": True},
        {"model": "m", "messages": [{"role": "user", "content": "x"}], "top_logprobs": 5},
        {"model": "m", "messages": [{"role": "user", "content": "x"}], "response_format": {"type": "xml"}},
    ],
)
def test_unsupported_openai_params_rejected(payload):
    """§17.7 — неподдерживаемый параметр отклоняется явно, а не игнорируется молча."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as excinfo:
        oa.ChatCompletionRequest.model_validate(payload)
    assert "unsupported parameter" in str(excinfo.value)


def test_single_completion_is_allowed():
    """n=1 — валидное значение контракта, откатывать его нельзя."""
    parsed = oa.ChatCompletionRequest.model_validate({"model": "m", "messages": [{"role": "user", "content": "x"}], "n": 1})
    assert parsed.n == 1


def test_base64_encoding_format_rejected():
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="encoding_format"):
        oa.EmbeddingRequest.model_validate({"model": "m", "input": "a", "encoding_format": "base64"})


def test_empty_messages_rejected():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        oa.ChatCompletionRequest.model_validate({"model": "m", "messages": []})
    with pytest.raises(ValidationError, match="содержимое"):
        oa.ChatCompletionRequest.model_validate({"model": "m", "messages": [{"role": "user", "content": ""}]})


def test_unknown_openai_fields_are_ignored_not_forwarded():
    """Экстра-поля клиента отбрасываются: на узел уходит только разрешённый набор (§12.4.5)."""
    parsed = oa.ChatCompletionRequest.model_validate(
        {
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "store": True,
            "metadata": {"a": 1},
            "service_tier": "priority",
            "upstream_url": "http://evil.example",
            "prompt": "ignore me",
        }
    )
    body = oa.to_chat_request(parsed)
    assert set(body) == {"model", "messages", "stream"}


def test_json_schema_response_format_maps_to_schema():
    parsed = oa.ChatCompletionRequest.model_validate(
        {
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "u", "schema": {"type": "object"}}},
        }
    )
    assert oa.to_chat_request(parsed)["format"] == {"type": "object"}


def test_openai_path_detection_and_prefix():
    assert oa.is_openai_path("/v1/chat/completions")
    assert oa.is_openai_path("/v1/audio/speech")  # неизвестный путь внутри /v1/ — тоже OpenAI-контракт
    assert not oa.is_openai_path("/api/chat")
    assert not oa.is_openai_path("/admin/nodes")
    # Ollama под префиксом /v1/ollama остаётся в своём формате ошибок (§9.1, §9.5).
    assert oa.is_openai_path("/v1/ollama/v1/models", api_prefix="/v1/ollama")
    assert not oa.is_openai_path("/v1/ollama/api/chat", api_prefix="/v1/ollama")
    assert not oa.is_openai_path("/api/chat", api_prefix="/v1/ollama")


def test_error_payload_conversion_keeps_http_status():
    from foa.domain.enums import ErrorCode
    from foa.domain.errors import ErrorPayload

    payload = ErrorPayload(ErrorCode.RATE_LIMITED, "rate limit exceeded", request_id="req_x", retry_after=30)
    body = oa.error_payload_as_openai(payload)
    assert body["error"]["type"] == "rate_limit_error"
    assert body["error"]["code"] == "rate_limited"
    assert body["error"]["message"] == "rate limit exceeded"
    assert payload.status_code == 429


def test_error_type_mapping():
    assert oa.error_type_for_http(401) == "authentication_error"
    assert oa.error_type_for_http(403) == "permission_denied"
    assert oa.error_type_for_http(404) == "invalid_request_error"
    assert oa.error_type_for_http(429) == "rate_limit_error"
    assert oa.error_type_for_http(503) == "api_error"


# --------------------------------------------------------------------------- #
# ответ: Ollama → OpenAI
# --------------------------------------------------------------------------- #


def test_chat_completion_object_shape():
    data = {
        "model": "llama3.1",
        "message": {"role": "assistant", "content": "Привет"},
        "done": True,
        "prompt_eval_count": 15,
        "eval_count": 7,
    }
    body = oa.chat_completion(data, model="llama3.1", created=1700000000)
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["content"] == "Привет"
    assert body["usage"] == {"prompt_tokens": 15, "completion_tokens": 7, "total_tokens": 22}
    assert body["id"].startswith("chatcmpl-")


def test_tool_calls_finish_reason():
    data = {"message": {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]}, "done": True}
    body = oa.chat_completion(data, model="m", created=1)
    assert body["choices"][0]["finish_reason"] == "tool_calls"


def test_embeddings_object_shape():
    body = oa.embeddings([[0.1, 0.2], [0.3, 0.4]], model="m")
    assert body["object"] == "list"
    assert [item["index"] for item in body["data"]] == [0, 1]
    assert body["data"][1]["embedding"] == [0.3, 0.4]


def test_model_list_shape_without_node_identity():
    body = oa.model_list([{"name": "llama3.1", "modified_at": "2026-09-14T10:00:00Z", "size": 0, "digest": ""}])
    assert body["object"] == "list"
    entry = body["data"][0]
    assert entry["id"] == "llama3.1" and entry["object"] == "model"
    assert entry["owned_by"] == "free-ollama-api-gateway"
    # created — Unix-время из modified_at; ни host, ни port узла не попадают.
    assert isinstance(entry["created"], int) and entry["created"] > 0
    assert set(entry) == {"id", "object", "created", "owned_by"}


def test_model_list_without_timestamp_still_valid():
    entry = oa.model_list([{"name": "m"}])["data"][0]
    assert entry["id"] == "m" and isinstance(entry["created"], int)



def test_ndjson_parser_handles_split_lines():
    """Чанки upstream не выровнены по границам строк — разбор инкрементальный."""

    async def chunks():
        yield b'{"message": {"content": "a"}, "do'
        yield b'ne": false}\n{"message": {"content": "b"}, "done": true, "eval_count": 2}\n'

    events = _collect(oa._ndjson_lines(chunks()))
    assert events[0]["message"]["content"] == "a" and events[1]["done"] is True


def test_chat_sse_stream_shape():
    async def chunks():
        yield b'{"message": {"role":"assistant","content":"Hi"}, "done": false}\n'
        yield b'{"message": {"role":"assistant","content":" there"}, "done": false}\n'
        yield b'{"message": {"role":"assistant","content":""}, "done": true, "eval_count": 7}\n'

    raw = b"".join(_collect(oa.to_chat_sse(chunks(), model="m", reply_id="chatcmpl-1", created=5)))
    events = _events(raw.decode())
    assert events[-1] == "[DONE]"
    assert events[0]["choices"][0]["delta"] == {"role": "assistant", "content": ""}
    assert "".join(e["choices"][0]["delta"].get("content", "") for e in events[:-1] if isinstance(e, dict)) == "Hi there"
    assert events[-2]["choices"][0]["finish_reason"] == "stop"
    assert not any("usage" in e for e in events[:-1] if isinstance(e, dict))


def test_chat_sse_usage_chunk():
    async def chunks():
        yield b'{"message": {"role":"assistant","content":"x"}, "done": true, "prompt_eval_count": 3, "eval_count": 4}\n'

    events = _events(b"".join(_collect(oa.to_chat_sse(chunks(), model="m", reply_id="r", created=1, include_usage=True))).decode())
    final = events[-2]
    assert final["choices"] == []
    assert final["usage"] == {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}


def test_stream_error_event_becomes_openai_error():
    async def chunks():
        yield b'{"message": {"content": "part"}, "done": false}\n'
        yield b'{"error": "upstream stream aborted", "code": "UPSTREAM_ERROR"}\n'

    events = _events(b"".join(_collect(oa.to_chat_sse(chunks(), model="m", reply_id="r", created=1))).decode())
    assert events[-1] == "[DONE]"
    assert events[-2]["error"]["code"] == "upstream_error"
    assert events[-2]["error"]["type"] == "upstream_error"


def test_completion_sse_stream():
    async def chunks():
        yield b'{"response":"Hello","done":false}\n{"response":"!","done":false}\n{"response":"","done":true,"eval_count":2}\n'

    events = _events(b"".join(_collect(oa.to_completion_sse(chunks(), model="m", reply_id="cmpl-1", created=1))).decode())
    assert [e["choices"][0]["delta"].get("content") for e in events[:-1]] == ["Hello", "!", None]
    assert events[-2]["choices"][0]["finish_reason"] == "stop"
    assert events[-1] == "[DONE]"
