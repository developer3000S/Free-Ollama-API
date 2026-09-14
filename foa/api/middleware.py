"""Middleware шлюза: request-id, тайминги, заголовки, защита (§8.5, §12.4.5)."""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from foa.api.deps import bind_request_context, error_response, request_id_of
from foa.config import Settings
from foa.domain.enums import REQUEST_ID_HEADER, ErrorCode
from foa.domain.errors import ErrorPayload, GatewayError
from foa.domain.openai import is_openai_path
from foa.logging import get_logger, get_request_id
from foa.observability import metrics

log = get_logger("http.mw")

#: Заголовки, которые шлюз обязан не пропускать наружу/вовнутрь (защита от
#: header injection и утечек — §12.4.5)
MAX_HEADERS = 64
MAX_HEADER_SIZE = 8192


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Генерирует request_id, считает длительность, пишет access-лог (§12.5.3)."""

    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        started = time.monotonic()
        try:
            rid = bind_request_context(request)
        except GatewayError as exc:
            return error_response(exc.payload(""))
        request.state.started_at = started
        response = await call_next(request)
        latency_ms = (time.monotonic() - started) * 1000.0
        response.headers[REQUEST_ID_HEADER] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if self.settings.observability.log_requests:
            log.info("http:access", extra={"foa": access_log_fields(request, response, latency_ms)})
        return response


def access_log_fields(request: Request, response: Response, latency_ms: float) -> dict[str, object]:
    """Минимальный набор полей журнала (§12.5.3).

    Содержимое промптов/ответов сюда не попадает намеренно: только метадата.
    """
    return {
        "event": "http.access",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "request_id": request_id_of(request),
        "user_key_hash": get_user_hash(request),
        "route": _route_of(request),
        "method": request.method,
        "status": response.status_code,
        "latency_ms": round(latency_ms, 2),
        "bytes_in": int(getattr(request.state, "bytes_in", 0) or 0),
        "bytes_out": int(response.headers.get("content-length") or 0),
        "model": str(getattr(request.state, "model", "") or ""),
        "stream": bool(getattr(request.state, "is_stream", False)),
        "node_id": str(getattr(request.state, "node_id", "") or ""),
        "error_code": str(getattr(request.state, "error_code", "") or ""),
    }


class RequestGuardMiddleware(BaseHTTPMiddleware):
    """Ограничения на входе: размер, заголовки, методы, «нельзя выбрать узел» (§12.4.5)."""

    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        headers = request.headers
        # Отказы на входе для /v1/* отдаются в конверте OpenAI (§18).
        openai = is_openai_path(request.url.path, self.settings.server.api_prefix)
        if len(headers) > MAX_HEADERS:
            return _reject(400, "too many request headers", request, openai=openai)
        for name, value in headers.items():
            if len(name) + len(value) > MAX_HEADER_SIZE:
                return _reject(400, "header too large", request, openai=openai)
        if request.method in {"POST", "PUT", "PATCH"}:
            declared = headers.get("content-length")
            if declared:
                try:
                    if int(declared) > self.settings.limits.max_request_bytes:
                        return _reject(413, "request body too large", request, code=ErrorCode.PAYLOAD_TOO_LARGE, openai=openai)
                except ValueError:
                    return _reject(400, "invalid Content-Length", request, openai=openai)
        # Попытка указать произвольный целевой узел — запрещена (§12.4.5, §2.1 п.3).
        for name in ("x-foa-node", "x-foa-target", "x-foa-upstream", "x-upstream-url", "x-node-id"):
            if name in headers:
                return _reject(
                    403, "choice of an arbitrary upstream node is not permitted", request, code=ErrorCode.FORBIDDEN, openai=openai
                )
        for param in ("upstream_url", "node", "node_id", "target", "endpoint"):
            if param in request.query_params:
                return _reject(
                    403, "target node selection via query parameter is not permitted", request, code=ErrorCode.FORBIDDEN, openai=openai
                )
        response = await call_next(request)
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Считает запросы, не дошедшие до прокси (отказы аутентификации, лимиты, валидации).

    Успешные маршруты засчитывает :meth:`ProxyService.record`, чтобы не дублировать.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if response.status_code >= 400 and request.url.path.startswith(("/admin", "/api", "/v1")):
            metrics.REQUESTS_TOTAL.labels(
                route=_route_of(request), status=str(response.status_code), error_code=str(getattr(request.state, "error_code", "") or "http_error")
            ).inc()
        return response


def _route_of(request: Request) -> str:
    path = request.url.path
    for known in (
        "/api/version",
        "/api/tags",
        "/api/show",
        "/api/generate",
        "/api/chat",
        "/api/embeddings",
        "/api/embed",
        "/api/ps",
        "/v1/models",
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/metrics",
        "/healthz",
        "/readyz",
    ):
        if path == known or path.startswith(known + "/"):
            return known
    if path.startswith("/admin/"):
        return "/admin/" + path[len("/admin/") :].split("/")[0]
    if path.startswith("/v1/"):
        # Имена моделей в пути /v1/models/{id} в лейбл не попадают (§11.3 low cardinality).
        return "/v1/models"
    return path[:60] or "/"


def get_user_hash(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return getattr(principal, "key_hash_hex", "") or ""


def _reject(status: int, message: str, request: Request, code: ErrorCode = ErrorCode.INVALID_REQUEST, *, openai: bool = False) -> JSONResponse:
    rid = get_request_id()
    payload = ErrorPayload(code, message, request_id=rid)
    response = error_response(payload, openai=openai)
    log.warning("http:rejected", extra={"foa": {"event": "http.rejected", "status": status, "error_code": code.value, "path": request.url.path}})
    return response


__all__ = ["MetricsMiddleware", "RequestContextMiddleware", "RequestGuardMiddleware"]
