"""OpenAI-совместимый API ``/v1/*`` (README «OpenAI-совместимый API», §18 п.2).

Второй контракт поверх той же службы, что и Ollama API: аутентификация ключами
``foa_…`` (§9.2), лимиты и бюджеты (§12.4), выбор узла балансировщиком и
consent gate (§5, §17.1) применяются одинаково — этот роутер лишь переводит
форму запроса/ответа и не имеет собственных путей к узлам.

Эндпоинты: ``GET /v1/models``, ``GET /v1/models/{model}``,
``POST /v1/chat/completions``, ``POST /v1/completions``, ``POST /v1/embeddings``.

Ошибки в формате OpenAI (``{"error": {message, type, code}}``) формирует
``gateway_error_handler`` по тегу маршрута (§9.5 — при этом Ollama-контракт не
затрагивается).
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from foa.api.deps import db_session, embedding_slot, generation_slot, get_state, read_json_body, require_read
from foa.api.user import _gate, _num_predict, _parse, _rate_headers, _sanitize_upstream_body
from foa.core.appstate import AppState
from foa.domain import openai as oa
from foa.domain.errors import ModelNotFoundError, NotFoundError
from foa.domain.schemas import ChatRequest, EmbedRequest, GenerateRequest
from foa.logging import get_logger
from foa.services.auth import Principal

router = APIRouter(tags=["openai", "ollama"])
log = get_logger("api.openai")

UPSTREAM_TIMEOUT = 30.0


def _stream_options_include_usage(parsed: Any) -> bool:
    options = getattr(parsed, "stream_options", None) or {}
    return bool(options.get("include_usage"))


@router.get("/v1/models")
async def list_models(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(require_read),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    """``GET /v1/models`` из агрегата ``/api/tags`` (§9.3.2) — без адресов узлов."""
    ctx, decision = await _gate(request, state, principal, session)
    payload = await state.proxy.aggregate_tags(session)
    state.proxy.record(ctx, 200)
    return JSONResponse(oa.model_list(payload.get("models", [])), headers=_rate_headers(decision, ctx.request_id))


@router.get("/v1/models/{model_id:path}")
async def retrieve_model(
    model_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(require_read),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    """``GET /v1/models/{id}`` из реестра узлов (не из ``/api/show``).

    Источником служит то же знание о моделях, которое использует балансировщик
    (§7.5): он не отправит запрос на узел, где модели нет, поэтому и здесь
    достаточно агрегата согласованных моделей.
    """
    ctx, decision = await _gate(request, state, principal, session, model=model_id)
    payload = await state.proxy.aggregate_tags(session)
    for item in payload.get("models", []):
        if item.get("name") == model_id:
            state.proxy.record(ctx, 200)
            return JSONResponse(oa.model_list([item])["data"][0], headers=_rate_headers(decision, ctx.request_id))
    raise ModelNotFoundError(f"модель {model_id!r} недоступна ни на одном согласованном узле")


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(generation_slot),
    session: AsyncSession = Depends(db_session),
):
    """``POST /v1/chat/completions`` → ``POST /api/chat`` (§9.3.5)."""
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(oa.ChatCompletionRequest, body)
    ollama_body = oa.to_chat_request(parsed)
    parsed_chat = _parse(ChatRequest, ollama_body)
    prompt_bytes = sum(len(m.content.encode("utf-8")) for m in parsed_chat.messages)
    state.ratelimit.enforce_generation_budget(_num_predict(parsed_chat.options), prompt_bytes)
    ctx, decision = await _gate(request, state, principal, session, model=parsed.model, stream=parsed.stream)
    created = int(time.time())
    reply_id = f"chatcmpl-{ctx.request_id.replace('-', '')[:24]}"

    if not parsed.stream:
        result = await state.proxy.request_json(
            session, ctx, method="POST", path="/api/chat", body=ollama_body, timeout=state.settings.limits.max_generation_seconds, side_effects=True
        )
        data = _sanitize_upstream_body(result.body, ctx=ctx)
        await state.record_tokens(principal.key_id, int(data.get("eval_count") or 0) + int(data.get("prompt_eval_count") or 0))
        state.proxy.record(ctx, result.status)
        return JSONResponse(oa.chat_completion(data, model=parsed.model, created=created), headers=_rate_headers(decision, ctx.request_id))

    async def gen():
        try:
            async for event in oa.to_chat_sse(
                state.proxy.stream_ndjson(session, ctx, method="POST", path="/api/chat", body=ollama_body),
                model=parsed.model,
                reply_id=reply_id,
                created=created,
                include_usage=_stream_options_include_usage(parsed),
            ):
                yield event
        finally:
            await state.record_tokens(principal.key_id, ctx.tokens)
            state.proxy.record(ctx, 200)

    return StreamingResponse(
        gen(),
        media_type=oa.SSE_CONTENT_TYPE,
        headers={**_rate_headers(decision, ctx.request_id), "X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@router.post("/v1/completions")
async def completions(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(generation_slot),
    session: AsyncSession = Depends(db_session),
):
    """``POST /v1/completions`` (legacy) → ``POST /api/generate`` (§9.3.4)."""
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(oa.CompletionRequest, body)
    ollama_body = oa.to_generate_request(parsed)
    parsed_generate = _parse(GenerateRequest, ollama_body)
    state.ratelimit.enforce_generation_budget(_num_predict(parsed_generate.options), len(parsed.prompt.encode("utf-8")))
    ctx, decision = await _gate(request, state, principal, session, model=parsed.model, stream=parsed.stream)
    created = int(time.time())
    reply_id = f"cmpl-{ctx.request_id.replace('-', '')[:24]}"

    if not parsed.stream:
        result = await state.proxy.request_json(
            session, ctx, method="POST", path="/api/generate", body=ollama_body, timeout=state.settings.limits.max_generation_seconds, side_effects=True
        )
        data = _sanitize_upstream_body(result.body, ctx=ctx)
        await state.record_tokens(principal.key_id, int(data.get("eval_count") or 0) + int(data.get("prompt_eval_count") or 0))
        state.proxy.record(ctx, result.status)
        return JSONResponse(oa.completion(data, model=parsed.model, created=created), headers=_rate_headers(decision, ctx.request_id))

    async def gen():
        try:
            async for event in oa.to_completion_sse(
                state.proxy.stream_ndjson(session, ctx, method="POST", path="/api/generate", body=ollama_body),
                model=parsed.model,
                reply_id=reply_id,
                created=created,
            ):
                yield event
        finally:
            await state.record_tokens(principal.key_id, ctx.tokens)
            state.proxy.record(ctx, 200)

    return StreamingResponse(
        gen(),
        media_type=oa.SSE_CONTENT_TYPE,
        headers={**_rate_headers(decision, ctx.request_id), "X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@router.post("/v1/embeddings")
async def create_embeddings(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(embedding_slot),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    """``POST /v1/embeddings`` → ``POST /api/embed`` (§9.3.6)."""
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(oa.EmbeddingRequest, body)
    ollama_body = oa.to_embed_request(parsed)
    parsed_embed = _parse(EmbedRequest, ollama_body)
    inputs = parsed_embed.input if isinstance(parsed_embed.input, list) else [parsed_embed.input]
    state.ratelimit.enforce_generation_budget(None, sum(len(str(i).encode("utf-8")) for i in inputs))
    ctx, decision = await _gate(request, state, principal, session, model=parsed.model)
    result = await state.proxy.request_json(
        session, ctx, method="POST", path="/api/embed", body=ollama_body, timeout=UPSTREAM_TIMEOUT
    )
    data = _sanitize_upstream_body(result.body, ctx=ctx)
    vectors = data.get("embeddings") or ([data["embedding"]] if isinstance(data.get("embedding"), list) else [])
    state.proxy.record(ctx, result.status)
    return JSONResponse(oa.embeddings(vectors, model=parsed.model), headers=_rate_headers(decision, ctx.request_id))


# --------------------------------------------------------------------------- #
# Неизвестный путь /v1/* — отказ в конверте OpenAI, а не FastAPI-овский detail
# --------------------------------------------------------------------------- #


@router.api_route("/v1/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
async def unknown_openai_route(rest: str, request: Request) -> None:
    """Зарегистрирован последним: срабатывает только когда маршрут не совпал.

    ``NotFoundError`` → 404 (не 405), иначе клиенты OpenAI-SDK увидят ответ,
    которого их транспорт не разбирает (§9.5, §18).
    """
    raise NotFoundError("unknown endpoint", details={"path": request.url.path, "rest": rest})



__all__ = ["router"]
