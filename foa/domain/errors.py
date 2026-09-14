"""Иерархия ошибок шлюза и их пользовательское представление (§8.6, §9.5).

Формат совместим с Ollama (поле ``error`` присутствует всегда) и дополнен
диагностикой: ``code``, ``request_id``, ``retry_after``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from foa.domain.enums import ERROR_HTTP_STATUS, ErrorCode


@dataclass(slots=True)
class ErrorPayload:
    code: ErrorCode
    message: str
    request_id: str = ""
    retry_after: int | None = None
    details: dict[str, Any] | None = None

    @property
    def status_code(self) -> int:
        return ERROR_HTTP_STATUS.get(self.code, 500)

    def to_json(self) -> dict[str, Any]:
        body: dict[str, Any] = {"error": self.message, "code": self.code.value}
        if self.request_id:
            body["request_id"] = self.request_id
        if self.retry_after is not None:
            body["retry_after"] = int(self.retry_after)
        if self.details:
            body["details"] = self.details
        return body


class GatewayError(Exception):
    """Базовая ошибка шлюза, конвертируемая в HTTP-ответ."""

    code: ErrorCode = ErrorCode.SERVER_ERROR
    message: str = "internal server error"
    http_status: int | None = None

    def __init__(
        self,
        message: str | None = None,
        *,
        code: ErrorCode | None = None,
        retry_after: int | None = None,
        request_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code or self.code
        self.message = message or self.message
        self.retry_after = retry_after
        self.request_id = request_id
        self.details = details
        super().__init__(self.message)

    @property
    def status_code(self) -> int:
        return self.http_status or ERROR_HTTP_STATUS.get(self.code, 500)

    def payload(self, request_id: str = "") -> ErrorPayload:
        return ErrorPayload(
            code=self.code,
            message=self.message,
            request_id=request_id or self.request_id,
            retry_after=self.retry_after,
            details=self.details,
        )


class UnauthorizedError(GatewayError):
    code = ErrorCode.UNAUTHORIZED
    message = "unauthorized"


class ForbiddenError(GatewayError):
    code = ErrorCode.FORBIDDEN
    message = "forbidden"


class RateLimitedError(GatewayError):
    code = ErrorCode.RATE_LIMITED
    message = "rate limit exceeded"

    def __init__(self, message: str | None = None, *, retry_after: int | None = 30, **kw: Any) -> None:
        super().__init__(message, retry_after=retry_after, **kw)


class QuotaExceededError(GatewayError):
    code = ErrorCode.QUOTA_EXCEEDED
    message = "quota exceeded"

    def __init__(self, message: str | None = None, *, retry_after: int | None = 30, **kw: Any) -> None:
        super().__init__(message, retry_after=retry_after, **kw)


class BudgetExceededError(GatewayError):
    code = ErrorCode.BUDGET_EXCEEDED
    message = "generation budget exceeded"

    def __init__(self, message: str | None = None, *, retry_after: int | None = 30, **kw: Any) -> None:
        super().__init__(message, retry_after=retry_after, **kw)


class InvalidRequestError(GatewayError):
    code = ErrorCode.INVALID_REQUEST
    message = "invalid request"


class PayloadTooLargeError(GatewayError):
    code = ErrorCode.PAYLOAD_TOO_LARGE
    message = "request body too large"


class ModelNotFoundError(GatewayError):
    code = ErrorCode.MODEL_NOT_FOUND
    message = "model not found"


class NotFoundError(GatewayError):
    code = ErrorCode.NOT_FOUND
    message = "not found"


class NoHealthyNodesError(GatewayError):
    code = ErrorCode.NO_HEALTHY_NODES
    message = "no healthy upstream nodes available"


class UpstreamError(GatewayError):
    code = ErrorCode.UPSTREAM_ERROR
    message = "upstream node error"


class UpstreamTimeoutError(GatewayError):
    code = ErrorCode.UPSTREAM_TIMEOUT
    message = "upstream node timeout"


class ConsentRequiredError(GatewayError):
    code = ErrorCode.CONSENT_REQUIRED
    message = "node consent is required before this node can serve traffic"


class BlacklistedError(GatewayError):
    code = ErrorCode.NODE_BLACKLISTED
    message = "node is blacklisted"


__all__ = [
    "BlacklistedError",
    "BudgetExceededError",
    "ConsentRequiredError",
    "ErrorPayload",
    "ForbiddenError",
    "GatewayError",
    "InvalidRequestError",
    "ModelNotFoundError",
    "NoHealthyNodesError",
    "NotFoundError",
    "PayloadTooLargeError",
    "QuotaExceededError",
    "RateLimitedError",
    "UnauthorizedError",
    "UpstreamError",
    "UpstreamTimeoutError",
]
