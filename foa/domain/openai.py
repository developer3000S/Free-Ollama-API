"""OpenAI-совместимый контракт: схемы запросов и конвертеры Ollama ⇄ OpenAI.

Шлюз реализует Ollama API (§9.3) как основной; этот модуль надстраивает над ним
привычный для экосистемы контракт ``/v1/*`` (§18 «Поддержка OpenAI-совместимого
API как второго контракта»). Логика маршрутизации, согласий, лимитов и повторов
не дублируется — конвертер только переводит форму запроса/ответа, поэтому
consent gate (§5) действует и здесь без исключений.

``extra="ignore"`` (в отличие от ``extra="forbid"`` на ``/api/*``): реальные
OpenAI-клиенты регулярно присылают поля, которых нет в контракте (``store``,
``metadata``, ``service_tier``), и отказывали бы им на входе. Неизвестные поля
здесь отбрасываются, а не пересылаются на узел: payload для Ollama собирается
явным списком параметров, поэтому защита от инъекции произвольных параметров
(§12.4.5) сохраняется.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_MODEL_NAME_RE = r"^[A-Za-z0-9._:\-/]{1,160}$"
ChatRole = Literal["system", "developer", "user", "assistant", "tool"]


class OpenAIModel(BaseModel):
    # str_strip_whitespace намеренно не включён: он вырезал бы перенос строки из
    # stop=["\n"] — легитимного значения контракта OpenAI.
    model_config = ConfigDict(extra="ignore")


class ContentPart(OpenAIModel):
    """Элемент ``content`` в формате мультимодальных сообщений OpenAI."""

    type: str = "text"
    text: str | None = None
    image_url: dict[str, Any] | None = None


class ChatCompletionMessage(OpenAIModel):
    role: ChatRole
    content: str | list[ContentPart] | None = None
    name: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None


class ChatCompletionRequest(OpenAIModel):
    """``POST /v1/chat/completions``."""

    model: str = Field(pattern=_MODEL_NAME_RE)
    messages: list[ChatCompletionMessage] = Field(min_length=1, max_length=200)
    stream: bool = False
    stream_options: dict[str, Any] | None = None
    max_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    max_completion_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    top_p: float | None = Field(default=None, gt=0.0, le=1.0)
    # n>1 отклоняется явным валидатором ниже, а не полем: сообщение об
    # unsupported parameter должно быть одинаковым для всех таких параметров.
    n: int | None = Field(default=None, ge=1)
    stop: str | list[str] | None = None
    presence_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    frequency_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    seed: int | None = Field(default=None, ge=0)
    response_format: dict[str, Any] | None = None
    tools: list[dict[str, Any]] | None = None
    tool_choice: Any = None
    user: str | None = Field(default=None, max_length=256)
    logprobs: bool | None = None
    top_logprobs: int | None = None
    keep_alive: str | int | None = None

    @field_validator("messages")
    @classmethod
    def _at_least_one_text_part(cls, value: list[ChatCompletionMessage]) -> list[ChatCompletionMessage]:
        if not any(_content_text(m) or m.tool_calls for m in value):
            raise ValueError("messages: содержимое хотя бы одного сообщения обязательно")
        return value

    @field_validator("response_format")
    @classmethod
    def _check_response_format(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        # §17.7: неподдерживаемый тип отклоняется на входе, а не на конвертации.
        ollama_format(value)
        return value

    @model_validator(mode="after")
    def _reject_unsupported(self) -> ChatCompletionRequest:
        _reject_params(
            {
                "n>1": (self.n or 1) > 1,
                "logprobs": bool(self.logprobs) or self.top_logprobs is not None,
                # tool_choice="required"/именованная функция требуют, чтобы узел
                # вызвал инструмент; повлиять на это шлюз не может, а молча
                # проигнорировать такое требование клиента — значит выдать
                # не то, что запрошено (§17.7). "auto" и отсутствие поля — no-op.
                "tool_choice": _tool_choice_unsupported(self.tool_choice),
            }
        )
        return self



class CompletionRequest(OpenAIModel):
    """``POST /v1/completions`` — legacy-контракт текст-в-текст."""

    model: str = Field(pattern=_MODEL_NAME_RE)
    prompt: str = ""
    stream: bool = False
    stream_options: dict[str, Any] | None = None
    max_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    top_p: float | None = Field(default=None, gt=0.0, le=1.0)
    n: int | None = Field(default=None, ge=1)
    stop: str | list[str] | None = None
    presence_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    frequency_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    seed: int | None = Field(default=None, ge=0)
    user: str | None = Field(default=None, max_length=256)
    keep_alive: str | int | None = None

    @model_validator(mode="after")
    def _reject_unsupported(self) -> CompletionRequest:
        _reject_params({"n>1": (self.n or 1) > 1})
        return self


class EmbeddingRequest(OpenAIModel):
    """``POST /v1/embeddings`` → Ollama ``/api/embed`` (§9.3.6)."""

    model: str = Field(pattern=_MODEL_NAME_RE)
    input: str | list[str] = Field(max_length=200)
    encoding_format: Literal["float", "base64"] | None = None
    user: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def _reject_unsupported(self) -> EmbeddingRequest:
        _reject_params({"encoding_format='base64'": self.encoding_format == "base64"})
        return self


# --------------------------------------------------------------------------- #
# Поддержка
# --------------------------------------------------------------------------- #


class UnsupportedParamError(ValueError):
    """Параметр контракта OpenAI, который шлюз честно не эмулирует (§17.7)."""

    def __init__(self, *names: str) -> None:
        self.params = list(names)
        super().__init__("unsupported parameter(s): " + ", ".join(names) + " — этот контракт Ollama их не предоставляет")


def _reject_params(candidates: dict[str, bool]) -> None:
    used = [name for name, present in candidates.items() if present]
    if used:
        raise UnsupportedParamError(*used)


def _tool_choice_unsupported(tool_choice: Any) -> bool:
    """``tool_choice`` исполним только в значениях «на усмотрение модели» и «не использовать».

    ``"required"`` и явная функция обязывают вызвать инструмент; повлиять на
    это шлюз не может, а молча проигнорировать требование клиента — значит
    выдать не то, что запрошено (§17.7). ``"auto"`` ничего не добавляет к
    payload, ``"none"`` реализуется отсылкой запроса без инструментов.
    """
    if tool_choice is None:
        return False
    if isinstance(tool_choice, str):
        return tool_choice not in {"auto", "none"}
    # Любая объектная форма — «вызвать вот этот инструмент» → не исполнимо.
    return True


def tools_payload(parsed: ChatCompletionRequest) -> list[dict[str, Any]] | None:
    """``tools`` для Ollama с учётом ``tool_choice`` (None — инструменты не шлём)."""
    if parsed.tool_choice == "none":
        return None
    return parsed.tools



def _content_text(message: ChatCompletionMessage) -> str:
    """``content`` — строка или список частей; собираем текст и вытаскиваем изображения."""
    if isinstance(message.content, str):
        return message.content
    if isinstance(message.content, list):
        parts: list[str] = []
        for part in message.content:
            if part.type == "text" and part.text:
                parts.append(part.text)
            elif part.type == "image_url":
                parts.append(_image_reference(part.image_url))
        return "\n".join(parts)
    return ""


def _image_reference(image_url: dict[str, Any] | None) -> str:
    """data: URI узел получает как base64-изображение; http(s)-ссылку не пересылаем.

    Загрузка произвольного URL самим узлом означала бы SSRF из чужого процесса
    (§12.5.1), поэтому внешняя ссылка отдаётся как текст-заполнитель.
    """
    url = str((image_url or {}).get("url") or "")
    if url.startswith("data:"):
        return url
    if url:
        return "[image reference omitted: the gateway does not forward remote image URLs to nodes]"
    return "[image part without url]"


def collect_images(messages: list[ChatCompletionMessage]) -> list[str]:
    """base64-изображения из мультимодальных частей → Ollama ``images`` (§9.3.5)."""
    images: list[str] = []
    for message in messages:
        if not isinstance(message.content, list):
            continue
        for part in message.content:
            if part.type != "image_url":
                continue
            url = str((part.image_url or {}).get("url") or "")
            if url.startswith("data:") and "," in url:
                images.append(url.split(",", 1)[1])
    return images


# --------------------------------------------------------------------------- #
# Запрос: OpenAI → Ollama
# --------------------------------------------------------------------------- #


def ollama_options(
    *,
    temperature: float | None = None,
    top_p: float | None = None,
    max_tokens: int | None = None,
    presence_penalty: float | None = None,
    frequency_penalty: float | None = None,
    seed: int | None = None,
    stop: str | list[str] | None = None,
) -> dict[str, Any]:
    """Параметры сэмплирования OpenAI → Ollama ``options`` (§9.3.4)."""
    options: dict[str, Any] = {}
    if temperature is not None:
        options["temperature"] = temperature
    if top_p is not None:
        options["top_p"] = top_p
    if max_tokens is not None:
        options["num_predict"] = max_tokens
    if presence_penalty is not None:
        options["presence_penalty"] = presence_penalty
    if frequency_penalty is not None:
        options["frequency_penalty"] = frequency_penalty
    if seed is not None:
        options["seed"] = seed
    if stop is not None:
        options["stop"] = [stop] if isinstance(stop, str) else list(stop)
    return options


def ollama_format(response_format: dict[str, Any] | None) -> Any:
    """``response_format`` → Ollama ``format`` (``json`` или JSON-схема)."""
    if not response_format:
        return None
    kind = response_format.get("type")
    if kind in (None, "text"):
        return None
    if kind == "json_object":
        return "json"
    if kind == "json_schema":
        schema = response_format.get("json_schema") or {}
        return schema.get("schema") or "json"
    raise UnsupportedParamError(f"response_format.type={kind!r}")


def to_chat_request(parsed: ChatCompletionRequest) -> dict[str, Any]:
    """``/v1/chat/completions`` → тело ``/api/chat`` (§9.3.5).

    Роль ``developer`` (новое имя ``system`` в контракте OpenAI) отображается в
    ``system``, поля ``name``/``user`` не пересылаются: идентификатор клиента
    узлу не положен (§8.5.3, §12.5.2).
    """
    messages: list[dict[str, Any]] = []
    for message in parsed.messages:
        role = "system" if message.role == "developer" else message.role
        entry: dict[str, Any] = {"role": role, "content": _content_text(message)}
        if message.tool_calls:
            entry["tool_calls"] = message.tool_calls
        if message.tool_call_id:
            entry["tool_call_id"] = message.tool_call_id
        messages.append(entry)
    body: dict[str, Any] = {"model": parsed.model, "messages": messages, "stream": parsed.stream}
    options = ollama_options(
        temperature=parsed.temperature,
        top_p=parsed.top_p,
        max_tokens=parsed.max_completion_tokens or parsed.max_tokens,
        presence_penalty=parsed.presence_penalty,
        frequency_penalty=parsed.frequency_penalty,
        seed=parsed.seed,
        stop=parsed.stop,
    )
    if options:
        body["options"] = options
    if fmt := ollama_format(parsed.response_format):
        body["format"] = fmt
    if tools := tools_payload(parsed):
        body["tools"] = tools
    if images := collect_images(parsed.messages):
        body["images"] = images
    if parsed.keep_alive is not None:
        body["keep_alive"] = parsed.keep_alive
    return body


def to_generate_request(parsed: CompletionRequest) -> dict[str, Any]:
    """``/v1/completions`` → тело ``/api/generate`` (§9.3.4)."""
    body: dict[str, Any] = {"model": parsed.model, "prompt": parsed.prompt, "stream": parsed.stream}
    options = ollama_options(
        temperature=parsed.temperature,
        top_p=parsed.top_p,
        max_tokens=parsed.max_tokens,
        presence_penalty=parsed.presence_penalty,
        frequency_penalty=parsed.frequency_penalty,
        seed=parsed.seed,
        stop=parsed.stop,
    )
    if options:
        body["options"] = options
    if parsed.keep_alive is not None:
        body["keep_alive"] = parsed.keep_alive
    return body


def to_embed_request(parsed: EmbeddingRequest) -> dict[str, Any]:
    """``/v1/embeddings`` → тело ``/api/embed`` (§9.3.6)."""
    return {"model": parsed.model, "input": parsed.input}


# --------------------------------------------------------------------------- #
# Ответ: Ollama → OpenAI
# --------------------------------------------------------------------------- #


def _usage(data: dict[str, Any]) -> dict[str, int]:
    prompt = int(data.get("prompt_eval_count") or 0)
    completion = int(data.get("eval_count") or 0)
    return {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}


def _finish_reason(data: dict[str, Any]) -> str:
    if (data.get("message") or {}).get("tool_calls") or data.get("tool_calls"):
        return "tool_calls"
    return "stop"


def chat_completion(data: dict[str, Any], *, model: str, created: int) -> dict[str, Any]:
    """Тело ``/api/chat`` → объект ``chat.completion``."""
    message = data.get("message") or {"role": "assistant", "content": ""}
    out: dict[str, Any] = {
        "role": message.get("role") or "assistant",
        "content": message.get("content") or "",
    }
    if message.get("tool_calls"):
        out["tool_calls"] = message["tool_calls"]
    return {
        "id": f"chatcmpl-{data.get('response_id') or _new_id()}",
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": out, "finish_reason": _finish_reason(data)}],
        "usage": _usage(data),
    }


def completion(data: dict[str, Any], *, model: str, created: int) -> dict[str, Any]:
    """Тело ``/api/generate`` → объект ``text_completion``."""
    return {
        "id": f"cmpl-{data.get('response_id') or _new_id()}",
        "object": "text_completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "text": data.get("response") or "", "finish_reason": "stop"}],
        "usage": _usage(data),
    }


def embeddings(vectors: list[list[float]], *, model: str) -> dict[str, Any]:
    """Тело ``/api/embed`` → ``/v1/embeddings``."""
    return {
        "object": "list",
        "data": [{"object": "embedding", "index": i, "embedding": vector} for i, vector in enumerate(vectors)],
        "model": model,
        "usage": {"prompt_tokens": 0, "total_tokens": 0},
    }


def model_list(models: list[dict[str, Any]]) -> dict[str, Any]:
    """``/api/tags`` → ``/v1/models`` (§9.3.2: без адресов узлов)."""
    return {
        "object": "list",
        "data": [
            {
                "id": item["name"],
                "object": "model",
                "created": _epoch_of(item.get("modified_at")),
                "owned_by": "free-ollama-api-gateway",
            }
            for item in models
        ],
    }


def _epoch_of(iso: Any) -> int:
    from datetime import datetime

    if isinstance(iso, str) and iso:
        try:
            return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())
        except ValueError:
            pass
    return int(time.time())


def _new_id() -> str:
    import secrets

    return secrets.token_hex(12)


# --------------------------------------------------------------------------- #
# Поток: NDJSON Ollama → SSE OpenAI
# --------------------------------------------------------------------------- #

SSE_CONTENT_TYPE = "text/event-stream"


def sse(obj: dict[str, Any] | None) -> bytes:
    if obj is None:
        return b"data: [DONE]\n\n"
    return b"data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n\n"


def chunk(
    reply_id: str,
    *,
    model: str,
    created: int,
    delta: dict[str, Any],
    finish_reason: str | None = None,
    usage: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Один ``chat.completion.chunk`` / ``text_completion.chunk``."""
    obj: dict[str, Any] = {
        "id": reply_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }
    if usage is not None:
        obj["usage"] = usage
    return obj


def _ndjson_lines(chunks_iter: AsyncIterator[bytes]) -> AsyncIterator[dict[str, Any]]:
    """Инкрементальный разбор NDJSON: upstream-чанки не выровнены по границам строк."""

    async def _gen() -> AsyncIterator[dict[str, Any]]:
        buffer = b""
        async for raw in chunks_iter:
            buffer += raw
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(parsed, dict):
                    yield parsed
        tail = buffer.strip()
        if tail:
            try:
                parsed = json.loads(tail.decode("utf-8"))
                if isinstance(parsed, dict):
                    yield parsed
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass

    return _gen()


async def to_chat_sse(
    chunks_iter: AsyncIterator[bytes],
    *,
    model: str,
    reply_id: str,
    created: int,
    include_usage: bool = False,
) -> AsyncIterator[bytes]:
    """NDJSON ``/api/chat`` → SSE ``chat.completions`` (§8.4: без буферизации).

    Событие ``{"error": …}`` (§7.6 — обрыв после первого байта повтор не
    допускает) переводится в объект ошибки OpenAI и завершается ``[DONE]``,
    чтобы клиент увидел нецелевой ответ, а не молча оборванный поток.
    """
    yield sse(chunk(reply_id, model=model, created=created, delta={"role": "assistant", "content": ""}))
    usage: dict[str, int] | None = None
    async for event in _ndjson_lines(chunks_iter):
        if event.get("error"):
            yield sse(openai_stream_error(event))
            yield sse(None)
            return
        message = event.get("message") or {}
        delta: dict[str, Any] = {}
        if content := message.get("content"):
            delta["content"] = content
        if message.get("tool_calls"):
            delta["tool_calls"] = message["tool_calls"]
        if delta:
            yield sse(chunk(reply_id, model=model, created=created, delta=delta))
        if event.get("done"):
            usage = _usage(event)
            yield sse(chunk(reply_id, model=model, created=created, delta={}, finish_reason=_finish_reason(event)))
    if include_usage and usage is not None:
        # По контракту OpenAI usage — отдельный финальный чанк с пустыми choices.
        final = chunk(reply_id, model=model, created=created, delta={})
        final["choices"] = []
        final["usage"] = usage
        yield sse(final)
    yield sse(None)


async def to_completion_sse(chunks_iter: AsyncIterator[bytes], *, model: str, reply_id: str, created: int) -> AsyncIterator[bytes]:
    """NDJSON ``/api/generate`` → SSE legacy-``completion``."""
    async for event in _ndjson_lines(chunks_iter):
        if event.get("error"):
            yield sse(openai_stream_error(event))
            yield sse(None)
            return
        text = event.get("response") or ""
        done = bool(event.get("done"))
        obj = chunk(reply_id, model=model, created=created, delta={"content": text} if text else {}, finish_reason="stop" if done else None)
        obj["object"] = "text_completion"
        yield sse(obj)
    yield sse(None)


def openai_stream_error(event: dict[str, Any]) -> dict[str, Any]:
    """Внутрипотоковая ошибка upstream → объект ошибки формата OpenAI."""
    code = str(event.get("code") or "UPSTREAM_ERROR")
    return {
        "error": {
            "message": str(event.get("error") or "upstream stream aborted"),
            "type": "upstream_error",
            "code": code.lower(),
            "param": None,
        }
    }


def openai_error(*, message: str, err_type: str, code: str | None = None, param: str | None = None, request_id: str = "") -> dict[str, Any]:
    """Канонический конверт ошибки OpenAI (§9.5 + совместимость)."""
    del request_id  # id передаётся заголовком X-FOA-Request-ID, в теле его нет
    return {"error": {"message": message, "type": err_type, "param": param, "code": code}}


def error_type_for_http(status: int) -> str:
    if status == 401:
        return "authentication_error"
    if status == 403:
        return "permission_denied"
    if status in {404, 400, 422}:
        return "invalid_request_error"
    if status == 429:
        return "rate_limit_error"
    if status in {502, 503, 504}:
        return "api_error"
    return "api_error"


#: Пути второго контракта (с учётом server.api_prefix, §9.1).
OPENAI_ROUTES = ("/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings")

#: Основное пространство имён Ollama — его ошибки всегда в формате §9.5.
_OLLAMA_MARKERS = ("/api/", "/admin/")


def is_openai_path(path: str, api_prefix: str = "") -> bool:
    """Относится ли путь к OpenAI-контракту — по нему выбирают формат ошибок (§9.5).

    Проверяется всё пространство имён ``/v1/``, а не только четыре известных
    маршрута: неизвестный путь внутри него (например ``/v1/audio/speech``) тоже
    должен отвечаться конвертом того клиента, который его запросил. Пути Ollama
    при ``server.api_prefix=/v1/ollama`` исключаются по маркерам ``/api/``,
    ``/admin/`` — их формат ошибок остаётся прежним.
    """
    if any(marker in path for marker in _OLLAMA_MARKERS):
        return False
    prefix = (api_prefix or "").rstrip("/")
    if prefix and not path.startswith(prefix + "/"):
        return False
    rest = path[len(prefix) :] if prefix else path
    return rest.startswith("/v1/")


def error_payload_as_openai(payload: Any) -> dict[str, Any]:
    """ErrorPayload шлюза → конверт ошибки OpenAI (message/type/param/code)."""
    from foa.domain.enums import ErrorCode

    code = getattr(payload.code, "value", str(payload.code))
    return openai_error(
        message=payload.message,
        err_type=error_type_for_http(payload.status_code),
        code=None if code == ErrorCode.SERVER_ERROR.value else code.lower(),
    )


__all__ = [
    "OPENAI_ROUTES",
    "SSE_CONTENT_TYPE",
    "ChatCompletionMessage",
    "ChatCompletionRequest",
    "CompletionRequest",
    "ContentPart",
    "EmbeddingRequest",
    "UnsupportedParamError",
    "chat_completion",
    "chunk",
    "completion",
    "embeddings",
    "error_payload_as_openai",
    "error_type_for_http",
    "is_openai_path",
    "model_list",
    "ollama_format",
    "ollama_options",
    "openai_error",
    "openai_stream_error",
    "sse",
    "to_chat_request",
    "to_chat_sse",
    "to_completion_sse",
    "to_embed_request",
    "to_generate_request",
]
