"""Пользовательский REST API, совместимый с Ollama (§9.1–§9.5).

Эндпоинты: ``/api/version``, ``/api/tags``, ``/api/show``, ``/api/generate``,
``/api/chat``, ``/api/embeddings``, ``/api/embed``, ``/api/ps``.

``POST /api/pull|push|copy`` и ``DELETE /api/delete`` конечным пользователям
**не предоставляются** (§9.4): они могут привести к загрузке произвольных
моделей на чужие вычислительные ресурсы.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from foa import GATEWAY_VERSION
from foa.api.deps import (
    authenticate_user,
    db_session,
    embedding_slot,
    generation_slot,
    get_state,
    read_json_body,
    request_id_of,
    require_read,
)
from foa.core.appstate import AppState
from foa.domain.errors import (
    GatewayError,
    InvalidRequestError,
    ModelNotFoundError,
    QuotaExceededError,
    RateLimitedError,
)
from foa.domain.schemas import ChatRequest, EmbeddingsRequest, EmbedRequest, GenerateRequest, ShowRequest
from foa.logging import get_logger
from foa.services.auth import Principal
from foa.services.proxy import NDJSON_CONTENT_TYPE, ProxyContext
from foa.services.ratelimit import RateDecision

router = APIRouter(tags=["ollama"])
log = get_logger("api.user")

UPSTREAM_TIMEOUT = 30.0


async def _gate(request: Request, state: AppState, principal: Principal, session: AsyncSession, *, model: str = "", stream: bool = False) -> tuple[ProxyContext, RateDecision]:
    """Лимиты и бюджеты (§8.2 п.2–5, §12.4.2).

    Проверки применяются по возрастанию специфичности и прерываются на первом
    отказе, чтобы клиент получил точный код: глобальный лимит → лимит ключа →
    лимит модели → дневная квота токенов (QUOTA_EXCEEDED, а не RATE_LIMITED).
    Заголовки X-FOA-RateLimit-* отражают лимит самого ключа (§8.5.2).
    """
    rid = request_id_of(request)
    ctx = ProxyContext(
        request_id=rid,
        principal=principal,
        route=request.url.path,
        model=model,
        stream=stream,
        bytes_in=int(getattr(request.state, "bytes_in", 0) or 0),
    )
    user_decision = await state.ratelimit.check_user(principal.key_id, limit_override=principal.rate_limit_per_minute)
    checks: list[tuple[RateDecision, type[GatewayError]]] = [
        (await state.ratelimit.check_global(), RateLimitedError),
        (user_decision, RateLimitedError),
    ]
    if model:
        checks.append((await state.ratelimit.check_model(model), RateLimitedError))
    if principal.tokens_per_day:
        checks.append((await state.ratelimit.check_daily_tokens(principal.key_id, principal.tokens_per_day), QuotaExceededError))

    for decision, error_type in checks:
        if not decision.allowed:
            raise error_type(
                "rate limit exceeded" if error_type is RateLimitedError else "daily token quota exceeded",
                retry_after=decision.retry_after or 30,
                request_id=rid,
            )
    request.state.foa_ctx = ctx
    return ctx, user_decision


def _rate_headers(decision: RateDecision, rid: str) -> dict[str, str]:
    headers = {"X-FOA-Request-ID": rid}
    headers.update(_decision_headers(decision))
    return headers


def _decision_headers(decision: RateDecision) -> dict[str, str]:
    return {
        "X-FOA-RateLimit-Limit": str(int(decision.limit)),
        "X-FOA-RateLimit-Remaining": str(int(decision.remaining)),
        "X-FOA-RateLimit-Reset": str(int(decision.reset_at)),
    }


def _parse(model_cls, body: dict[str, Any]):
    try:
        return model_cls.model_validate(body)
    except Exception as exc:
        raise InvalidRequestError(_validation_message(exc)) from exc


def _validation_message(exc: Exception) -> str:
    """Формирует сообщение только из имён полей и причин — без значений (§12.2)."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            items = errors()
        except Exception:
            items = []
        reasons: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            field = ".".join(str(part) for part in (item.get("loc") or ()) if part not in ("body", ""))
            reason = str(item.get("msg") or "invalid value").removeprefix("Value error, ").strip()
            reasons.append(f"{field}: {reason}" if field else reason)
        if reasons:
            return "invalid request body: " + "; ".join(dict.fromkeys(reasons))[:400]
    text = str(exc)
    # Не отдаём клиенту содержимое полей (промпты) — только имена/причины.
    if "field required" in text:
        return "invalid request body: " + ", ".join(sorted({line.split(":")[0].strip() for line in text.splitlines() if "field required" in line})[:5])
    return "invalid request body"


def _sanitize_upstream_body(payload: bytes, *, ctx: ProxyContext) -> dict[str, Any]:
    """Ответ узла проходит через фильтр: не должен раскрывать адрес узла (§9.3.2)."""
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidRequestError(f"upstream returned non-JSON response: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        return {"response": data if data is not None else "", "done": True}
    for key in ("node", "node_id", "endpoint", "host", "upstream"):
        data.pop(key, None)
    return data


# --------------------------------------------------------------------------- #
# GET /api/version
# --------------------------------------------------------------------------- #


@router.get("/api/version")
async def api_version(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(authenticate_user),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    ctx, decision = await _gate(request, state, principal, session)
    rid = ctx.request_id
    routable = [n for n in state.pool.nodes.values() if n.routable]
    upstream_versions: list[str] = []
    for runtime in routable:
        version = await _node_version(session, runtime)
        if version and version not in upstream_versions:
            upstream_versions.append(version)
    body: dict[str, Any] = {"version": GATEWAY_VERSION, "upstream_ollama_supported": True}
    if upstream_versions:
        body["upstream_version"] = upstream_versions[0]
    state.proxy.record(ctx, 200)
    return JSONResponse(body, headers=_rate_headers(decision, rid))


async def _node_version(session: AsyncSession, runtime) -> str:
    from foa.storage.repositories import NodeRepository

    row = await NodeRepository.get(session, runtime.node_id)
    return row.ollama_version if row is not None else ""


# --------------------------------------------------------------------------- #
# GET /api/tags
# --------------------------------------------------------------------------- #


@router.get("/api/tags")
async def api_tags(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(require_read),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    ctx, decision = await _gate(request, state, principal, session)
    payload = await state.proxy.aggregate_tags(session)
    state.proxy.record(ctx, 200)
    return JSONResponse(payload, headers=_rate_headers(decision, ctx.request_id))


# --------------------------------------------------------------------------- #
# POST /api/show
# --------------------------------------------------------------------------- #


@router.post("/api/show")
async def api_show(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(require_read),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(ShowRequest, body)
    ctx, decision = await _gate(request, state, principal, session, model=parsed.name)
    if not state.pool.candidates_for_model(parsed.name):
        raise ModelNotFoundError(f"модель {parsed.name!r} недоступна")
    results = await state.proxy.fanout(
        session, ctx, method="POST", path="/api/show", body={"name": parsed.name}, timeout=UPSTREAM_TIMEOUT, require_model_support=True
    )
    if not results:
        raise ModelNotFoundError(f"модель {parsed.name!r} не ответила ни на одном узле")
    merged = dict(results[0]["data"])
    merged.setdefault("license", "")
    merged.setdefault("modelfile", "")
    merged.setdefault("parameters", "")
    merged.setdefault("template", "")
    merged.setdefault("details", {})
    state.proxy.record(ctx, 200)
    return JSONResponse(merged, headers=_rate_headers(decision, ctx.request_id))


# --------------------------------------------------------------------------- #
# GET /api/ps
# --------------------------------------------------------------------------- #


@router.get("/api/ps")
async def api_ps(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(require_read),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    ctx, decision = await _gate(request, state, principal, session)
    results = await state.proxy.fanout(session, ctx, method="GET", path="/api/ps", body=None, timeout=UPSTREAM_TIMEOUT)
    models: dict[str, dict[str, Any]] = {}
    for item in results:
        for entry in (item["data"].get("models") or []):
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or entry.get("model") or "")
            if not name:
                continue
            entry.pop("node", None)
            entry["size_vram"] = int(entry.get("size_vram") or 0)
            models[name] = entry
    state.proxy.record(ctx, 200)
    return JSONResponse({"models": sorted(models.values(), key=lambda m: str(m.get("name")))}, headers=_rate_headers(decision, ctx.request_id))


# --------------------------------------------------------------------------- #
# POST /api/generate
# --------------------------------------------------------------------------- #


@router.post("/api/generate")
async def api_generate(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(generation_slot),
    session: AsyncSession = Depends(db_session),
):
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(GenerateRequest, body)
    ctx, decision = await _gate(request, state, principal, session, model=parsed.model, stream=parsed.stream)
    prompt_bytes = len((parsed.prompt or "").encode("utf-8")) + len((parsed.system or "").encode("utf-8"))
    state.ratelimit.enforce_generation_budget(_num_predict(parsed.options), prompt_bytes)
    payload = parsed.model_dump(exclude_none=True)
    payload.pop("images", None)  # base64-изображения не проксируем без отдельной политики
    payload.setdefault("stream", parsed.stream)

    if not parsed.stream:
        result = await state.proxy.request_json(
            session,
            ctx,
            method="POST",
            path="/api/generate",
            body=payload,
            timeout=state.settings.limits.max_generation_seconds,
            side_effects=True,
        )
        data = _sanitize_upstream_body(result.body, ctx=ctx)
        await state.record_tokens(principal.key_id, int(data.get("eval_count") or 0) + int(data.get("prompt_eval_count") or 0))
        state.proxy.record(ctx, result.status)
        return JSONResponse(data, status_code=result.status, headers=_rate_headers(decision, ctx.request_id))

    async def gen():
        try:
            async for chunk in state.proxy.stream_ndjson(session, ctx, method="POST", path="/api/generate", body=payload):
                yield chunk
        finally:
            await state.record_tokens(principal.key_id, ctx.tokens)
            state.proxy.record(ctx, 200)

    return StreamingResponse(
        gen(),
        media_type=NDJSON_CONTENT_TYPE,
        headers={**_rate_headers(decision, ctx.request_id), "X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


def _num_predict(options: dict | None) -> int | None:
    if not options:
        return None
    value = options.get("num_predict")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# POST /api/chat
# --------------------------------------------------------------------------- #


@router.post("/api/chat")
async def api_chat(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(generation_slot),
    session: AsyncSession = Depends(db_session),
):
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(ChatRequest, body)
    prompt_bytes = sum(len(m.content.encode("utf-8")) for m in parsed.messages)
    state.ratelimit.enforce_generation_budget(_num_predict(parsed.options), prompt_bytes)
    ctx, decision = await _gate(request, state, principal, session, model=parsed.model, stream=parsed.stream)
    payload = parsed.model_dump(exclude_none=True)
    payload.setdefault("stream", parsed.stream)

    if not parsed.stream:
        result = await state.proxy.request_json(
            session, ctx, method="POST", path="/api/chat", body=payload, timeout=state.settings.limits.max_generation_seconds, side_effects=True
        )
        data = _sanitize_upstream_body(result.body, ctx=ctx)
        await state.record_tokens(principal.key_id, int(data.get("eval_count") or 0) + int(data.get("prompt_eval_count") or 0))
        state.proxy.record(ctx, result.status)
        return JSONResponse(data, status_code=result.status, headers=_rate_headers(decision, ctx.request_id))

    async def gen():
        try:
            async for chunk in state.proxy.stream_ndjson(session, ctx, method="POST", path="/api/chat", body=payload):
                yield chunk
        finally:
            await state.record_tokens(principal.key_id, ctx.tokens)
            state.proxy.record(ctx, 200)

    return StreamingResponse(
        gen(),
        media_type=NDJSON_CONTENT_TYPE,
        headers={**_rate_headers(decision, ctx.request_id), "X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


# --------------------------------------------------------------------------- #
# POST /api/embeddings и /api/embed
# --------------------------------------------------------------------------- #


@router.post("/api/embeddings")
async def api_embeddings(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(embedding_slot),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(EmbeddingsRequest, body)
    ctx, decision = await _gate(request, state, principal, session, model=parsed.model)
    state.ratelimit.enforce_generation_budget(None, len(parsed.prompt.encode("utf-8")))
    result = await state.proxy.request_json(
        session, ctx, method="POST", path="/api/embeddings", body=parsed.model_dump(exclude_none=True), timeout=UPSTREAM_TIMEOUT
    )
    data = _sanitize_upstream_body(result.body, ctx=ctx)
    state.proxy.record(ctx, result.status)
    return JSONResponse(data, status_code=result.status, headers=_rate_headers(decision, ctx.request_id))


@router.post("/api/embed")
async def api_embed(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(embedding_slot),
    session: AsyncSession = Depends(db_session),
) -> JSONResponse:
    body = await read_json_body(request, state.settings.limits.max_request_bytes)
    parsed = _parse(EmbedRequest, body)
    ctx, decision = await _gate(request, state, principal, session, model=parsed.model)
    inputs = parsed.input if isinstance(parsed.input, list) else [parsed.input]
    state.ratelimit.enforce_generation_budget(None, sum(len(str(i).encode("utf-8")) for i in inputs))
    result = await state.proxy.request_json(
        session, ctx, method="POST", path="/api/embed", body=parsed.model_dump(exclude_none=True), timeout=UPSTREAM_TIMEOUT
    )
    data = _sanitize_upstream_body(result.body, ctx=ctx)
    state.proxy.record(ctx, result.status)
    return JSONResponse(data, status_code=result.status, headers=_rate_headers(decision, ctx.request_id))


# --------------------------------------------------------------------------- #
# Запрещённые операции (§9.4) — явный 403 вместо 404 для понятного отказа
# --------------------------------------------------------------------------- #


@router.api_route("/api/{operation:path}", methods=["POST", "DELETE", "PUT", "PATCH"], include_in_schema=False)
async def unsupported_ollama_operation(operation: str, request: Request, state: AppState = Depends(get_state)) -> JSONResponse:
    from foa.domain.enums import FORBIDDEN_USER_OPERATIONS
    from foa.domain.errors import ForbiddenError

    if f"/api/{operation}" in FORBIDDEN_USER_OPERATIONS:
        raise ForbiddenError(
            f"операция /api/{operation} недоступна конечным пользователям (см. §9.4 ТЗ)",
            details={"operation": operation, "allowed_for": "owner/admin contour only"},
        )
    raise ModelNotFoundError("unknown endpoint", details={"path": request.url.path})


__all__ = ["router"]
