"""FastAPI-зависимости: request-id, аутентификация, обработка ошибок (§8.2, §8.5, §8.6)."""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from foa.core.appstate import AppState
from foa.domain.enums import REQUEST_ID_HEADER, ErrorCode, Scope
from foa.domain.errors import ErrorPayload, ForbiddenError, GatewayError, InvalidRequestError, UnauthorizedError
from foa.ids import request_id as new_request_id
from foa.logging import get_logger, set_request_context
from foa.services.auth import Principal
from foa.storage.db import session_scope

log = get_logger("http")

MAX_HEADER_LENGTH = 8192


def get_state(request: Request) -> AppState:
    state = getattr(request.app.state, "foa", None)
    if state is None:  # pragma: no cover - защита от неверной сборки приложения
        raise GatewayError("состояние шлюза не инициализировано")
    return state


async def db_session() -> AsyncSession:
    async for session in session_scope():
        yield session


def request_id_of(request: Request) -> str:
    return getattr(request.state, "request_id", "") or ""


def bind_request_context(request: Request) -> str:
    """Генерирует/принимает ``X-FOA-Request-ID`` (§8.5.1)."""
    incoming = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    if incoming:
        if len(incoming) > 128 or any(ch in incoming for ch in "\r\n\x00"):
            raise InvalidRequestError("некорректный X-FOA-Request-ID")
        rid = incoming if incoming.startswith("req_") else f"req_{incoming[:120]}"
    else:
        rid = new_request_id()
    request.state.request_id = rid
    set_request_context(request_id=rid)
    return rid


async def authenticate_user(request: Request, state: AppState = Depends(get_state), session: AsyncSession = Depends(db_session)) -> Principal:
    """Пользовательский контур: обязателен Bearer-ключ (§9.2, FR-A-04, §17.4)."""
    rid = request_id_of(request)
    try:
        principal = await state.auth.authenticate(session, request.headers.get("authorization"))
        await session.commit()
    except UnauthorizedError as exc:
        exc.request_id = rid
        raise
    request.state.principal = principal
    set_request_context(user_key_hash=principal.key_hash_hex)
    return principal


def require_scope(scope: str):
    async def _dep(principal: Principal = Depends(authenticate_user)) -> Principal:
        if scope not in principal.scopes:
            raise ForbiddenError(f"ключу не выдан скоуп {scope}", details={"scope": scope})
        return principal

    return _dep


require_read = require_scope(Scope.OLLAMA_READ.value)
require_generate = require_scope(Scope.OLLAMA_GENERATE.value)
require_embed = require_scope(Scope.OLLAMA_EMBED.value)


async def _peek_stream_flag(request: Request, limit: int) -> bool:
    """Определяет stream-режим до отправки ответа, с тем же лимитом размера."""
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > limit:
            raise GatewayError("request body too large", code=ErrorCode.PAYLOAD_TOO_LARGE)
    request._body = raw  # кэш для повторного чтения в обработчике
    request.state.bytes_in = len(raw)
    try:
        data = json.loads(raw.decode("utf-8") or "null")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and bool(data.get("stream"))


async def generation_slot(
    request: Request,
    principal: Principal = Depends(require_generate),
    state: AppState = Depends(get_state),
):
    """Concurrency limit для генераций (§12.4.2): слот держится до конца ответа.

    Для StreamingResponse выход зависимости выполняется после последнего байта,
    поэтому длительные потоки тоже попадают под лимит.
    """
    stream = await _peek_stream_flag(request, state.settings.limits.max_request_bytes)
    async with state.ratelimit.user_slot(principal.key_id, stream=stream, limit=principal.concurrent_requests):
        yield principal


async def authenticate_admin(request: Request, state: AppState = Depends(get_state), *, write: bool = False) -> Principal:
    """Отдельная аутентификация админ-контура (§9.6, §17.9)."""
    try:
        return state.auth.authenticate_admin(request.headers.get("authorization"), write=write)
    except GatewayError as exc:
        exc.request_id = request_id_of(request)
        raise


async def admin_read(request: Request, state: AppState = Depends(get_state)) -> Principal:
    return await authenticate_admin(request, state, write=False)


async def admin_write(request: Request, state: AppState = Depends(get_state)) -> Principal:
    principal = await authenticate_admin(request, state, write=True)
    if Scope.ADMIN_WRITE.value not in principal.scopes:
        raise ForbiddenError("требуется право admin:write")
    return principal



def error_response(payload: ErrorPayload, headers: dict[str, str] | None = None) -> JSONResponse:
    headers = dict(headers or {})
    headers.setdefault(REQUEST_ID_HEADER, payload.request_id)
    if payload.retry_after is not None:
        headers.setdefault("Retry-After", str(int(payload.retry_after)))
    return JSONResponse(status_code=payload.status_code, content=payload.to_json(), headers=headers)


async def gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
    rid = request_id_of(request)
    payload = exc.payload(rid)
    log.warning(
        "http:error",
        extra={
            "foa": {
                "event": "http.error",
                "request_id": rid,
                "path": request.url.path,
                "status": payload.status_code,
                "error_code": payload.code.value,
            }
        },
    )
    return error_response(payload)


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Некорректный JSON/схема → совместимая ошибка 400 (§8.6, §12.4.5)."""
    from fastapi.exceptions import RequestValidationError

    rid = request_id_of(request)
    if isinstance(exc, RequestValidationError):
        fields = sorted({str(err.get("loc", ["?"])[-1]) for err in exc.errors()})[:10]
        message = "invalid request body"
        payload = ErrorPayload(ErrorCode.INVALID_REQUEST, message, request_id=rid, details={"fields": fields})
    else:  # pragma: no cover - прочие валидации
        payload = ErrorPayload(ErrorCode.INVALID_REQUEST, "invalid request", request_id=rid)
    return error_response(payload)


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Фолбэк: никогда не отдаём внутренние детали и секреты (§8.6)."""
    rid = request_id_of(request)
    log.error(
        "http:unhandled",
        exc_info=exc,
        extra={"foa": {"event": "http.unhandled", "request_id": rid, "path": request.url.path, "type": type(exc).__name__}},
    )
    payload = ErrorPayload(ErrorCode.SERVER_ERROR, "internal server error", request_id=rid)
    return error_response(payload)


async def read_json_body(request: Request, limit: int) -> dict[str, Any]:
    """Читает тело с жёстким лимитом размера (§8.2 п.4, §12.4.5).

    Размер сохраняется в ``request.state.bytes_in`` — в dict он не попадает,
    чтобы не ломать строгую валидацию схем (``extra="forbid"``).
    """
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > limit:
                raise GatewayError("request body too large", code=ErrorCode.PAYLOAD_TOO_LARGE)
        except ValueError:
            raise InvalidRequestError("некорректный Content-Length") from None
    raw = await request.body()
    request.state.bytes_in = len(raw)
    if len(raw) > limit:
        raise GatewayError("request body too large", code=ErrorCode.PAYLOAD_TOO_LARGE)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidRequestError(f"тело запроса должно быть корректным JSON: {type(exc).__name__}") from exc
    if not isinstance(parsed, dict):
        raise InvalidRequestError("тело запроса должно быть JSON-объектом")
    return parsed


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def perf_now() -> float:
    return time.perf_counter()


__all__ = [
    "admin_read",
    "admin_write",
    "authenticate_admin",
    "authenticate_user",
    "bind_request_context",
    "client_ip",
    "db_session",
    "error_response",
    "gateway_error_handler",
    "get_state",
    "perf_now",
    "read_json_body",
    "request_id_of",
    "require_embed",
    "require_generate",
    "require_read",
    "require_scope",
    "unhandled_error_handler",
    "validation_error_handler",
]
