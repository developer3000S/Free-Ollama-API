"""Доменные перечисления и константы (ТЗ §3.2.4, §6.4, §9.2)."""

from __future__ import annotations

import enum
from typing import Final


class NodeState(str, enum.Enum):
    """Состояния узла (переходы — §6.4)."""

    CANDIDATE = "candidate"
    PENDING_CONSENT = "pending_consent"
    CONSENT_CHALLENGE_SENT = "consent_challenge_sent"
    VERIFIED = "verified"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DRAINING = "draining"
    QUARANTINED = "quarantined"
    BLACKLISTED = "blacklisted"
    REVOKED = "revoked"


#: Состояния, из которых маршрутизация пользовательского трафика допустима (§4.4.4)
ROUTABLE_STATES: Final[frozenset[NodeState]] = frozenset({NodeState.VERIFIED, NodeState.HEALTHY, NodeState.DEGRADED})

#: Состояния, для которых допустимы активные health-проверки (§4.3, §12.3):
#: опрос узла, ещё не прошедшего согласие, был бы трафиком на чужой ресурс
#: без разрешения владельца.
ACTIVE_HEALTH_CHECK_STATES: Final[frozenset[NodeState]] = frozenset(
    {
        NodeState.VERIFIED,
        NodeState.HEALTHY,
        NodeState.DEGRADED,
        NodeState.UNHEALTHY,
        NodeState.DRAINING,
    }
)

#: Состояния, которые балансировщик обязан исключить немедленно (§6.4)
NON_ROUTABLE_STATES: Final[frozenset[NodeState]] = frozenset(
    {
        NodeState.CANDIDATE,
        NodeState.PENDING_CONSENT,
        NodeState.CONSENT_CHALLENGE_SENT,
        NodeState.UNHEALTHY,
        NodeState.DRAINING,
        NodeState.QUARANTINED,
        NodeState.BLACKLISTED,
        NodeState.REVOKED,
    }
)


class ConsentStatus(str, enum.Enum):
    NONE = "none"
    PENDING = "pending"
    CHALLENGE_SENT = "challenge_sent"
    VERIFIED = "verified"
    EXPIRED = "expired"
    REVOKED = "revoked"
    FAILED = "failed"


class DiscoveryMode(str, enum.Enum):
    DISABLED = "disabled"
    INVENTORY_ONLY = "inventory_only"
    CANDIDATE_RESEARCH = "candidate_research"
    AUTHORIZED_ENROLLMENT = "authorized_enrollment"


class CandidateStatus(str, enum.Enum):
    CANDIDATE = "candidate"
    REQUIRES_MANUAL_REVIEW = "requires_manual_review"
    ENROLLED = "enrolled"
    REJECTED = "rejected"
    OUT_OF_SCOPE = "out_of_scope"
    EXPIRED = "expired"
    DELETED = "deleted"


class Scope(str, enum.Enum):
    OLLAMA_READ = "ollama:read"
    OLLAMA_GENERATE = "ollama:generate"
    OLLAMA_EMBED = "ollama:embed"
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"
    #: Self-service владельца: регистрация/верификация/отзыв только своих узлов (§2.2).
    NODE_SELF_SERVICE = "node:self_service"


class ErrorCode(str, enum.Enum):
    """Коды ошибок пользовательского API (§9.5)."""

    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    INVALID_REQUEST = "INVALID_REQUEST"
    MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
    NO_HEALTHY_NODES = "NO_HEALTHY_NODES"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    NOT_FOUND = "NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    SERVER_ERROR = "SERVER_ERROR"
    CLIENT_DISCONNECTED = "CLIENT_DISCONNECTED"
    NODE_BLACKLISTED = "NODE_BLACKLISTED"


ERROR_HTTP_STATUS: Final[dict[ErrorCode, int]] = {
    ErrorCode.UNAUTHORIZED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.QUOTA_EXCEEDED: 429,
    ErrorCode.BUDGET_EXCEEDED: 429,
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.MODEL_NOT_FOUND: 404,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.NO_HEALTHY_NODES: 503,
    ErrorCode.UPSTREAM_ERROR: 502,
    ErrorCode.UPSTREAM_TIMEOUT: 504,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.CONSENT_REQUIRED: 403,
    ErrorCode.METHOD_NOT_ALLOWED: 405,
    ErrorCode.SERVER_ERROR: 500,
    ErrorCode.NODE_BLACKLISTED: 403,
}


class BlacklistReason(str, enum.Enum):
    ACCESS_DENIED = "access_denied"
    UPSTREAM_AUTH_ERROR = "upstream_auth_error"
    CONSENT_ERROR = "consent_error"
    ADMIN_MANUAL = "admin_manual"
    ABUSE_REPORT = "abuse_report"
    POLICY_VIOLATION = "policy_violation"


class HealthKind(str, enum.Enum):
    LIVENESS = "liveness"
    READINESS = "readiness"
    CAPABILITY = "capability"
    CONSENT = "consent"
    FUNCTIONAL = "functional"
    PASSIVE = "passive"


class ConsentMethod(str, enum.Enum):
    HTTP_WELL_KNOWN = "http_well_known"
    DNS_TXT = "dns_txt"
    SIGNED_TOKEN = "signed_token"


#: Пути, запрещённые для конечных пользователей (§9.4)
FORBIDDEN_USER_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"/api/pull", "/api/push", "/api/copy", "/api/delete"}
)

#: Пользовательские Ollama-совместимые эндпоинты (белый список, §12.4.5)
USER_ENDPOINTS: Final[frozenset[str]] = frozenset(
    {
        "/api/version",
        "/api/tags",
        "/api/show",
        "/api/generate",
        "/api/chat",
        "/api/embeddings",
        "/api/embed",
        "/api/ps",
    }
)

REQUEST_ID_HEADER: Final = "X-FOA-Request-ID"
CLIENT_HASH_HEADER: Final = "X-FOA-Client-Hash"
