"""Pydantic-схемы пользовательского и административного API (§8, §9).

``extra="forbid"`` на пользовательских эндпоинтах — часть защиты от инъекций и
SSRF: произвольный ``upstream_url`` или неизвестный параметр отклоняется (§12.4.5).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_MODEL_NAME_RE = r"^[A-Za-z0-9._:\-/]{1,160}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ChatMessage(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(max_length=262_144)
    images: list[str] | None = None


class GenerateRequest(StrictModel):
    """``POST /api/generate`` (§9.3.4)."""

    model: str = Field(pattern=_MODEL_NAME_RE)
    prompt: str = Field(default="", max_length=1_048_576)
    system: str | None = Field(default=None, max_length=65_536)
    template: str | None = Field(default=None, max_length=65_536)
    context: list[int] | None = None
    stream: bool = False
    raw: bool = False
    keep_alive: str | int | None = None
    options: dict[str, Any] | None = None
    images: list[str] | None = None
    format: Any = None

    @field_validator("options")
    @classmethod
    def _check_options(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        for key in value:
            if key not in ALLOWED_OPTIONS:
                raise ValueError(f"unsupported option {key!r}")
        return value


class ChatRequest(StrictModel):
    """``POST /api/chat`` (§9.3.5)."""

    model: str = Field(pattern=_MODEL_NAME_RE)
    messages: list[ChatMessage] = Field(min_length=1, max_length=200)
    tools: list[dict[str, Any]] | None = None
    stream: bool = False
    keep_alive: str | int | None = None
    options: dict[str, Any] | None = None
    format: Any = None

    @field_validator("options")
    @classmethod
    def _check_options(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        for key in value:
            if key not in ALLOWED_OPTIONS:
                raise ValueError(f"unsupported option {key!r}")
        return value


class EmbeddingsRequest(StrictModel):
    """``POST /api/embeddings`` (§9.3.6)."""

    model: str = Field(pattern=_MODEL_NAME_RE)
    prompt: str = Field(max_length=1_048_576)
    options: dict[str, Any] | None = None


class EmbedRequest(StrictModel):
    """``POST /api/embed`` — новый формат Ollama (§9.3.6)."""

    model: str = Field(pattern=_MODEL_NAME_RE)
    input: str | list[str] = Field(max_length=200)
    truncate: bool | None = None
    options: dict[str, Any] | None = None


class ShowRequest(StrictModel):
    """``POST /api/show`` (§9.3.3)."""

    name: str = Field(pattern=_MODEL_NAME_RE)


class NodeRegisterRequest(StrictModel):
    """``POST /admin/nodes`` (§9.6.2)."""

    endpoint: str = Field(min_length=8, max_length=512)
    display_name: str = Field(default="", max_length=120)
    owner_id: str = Field(default="", max_length=64)
    models: list[str] = Field(default_factory=list, max_length=200)
    max_concurrency: int = Field(default=2, ge=1, le=1000)
    max_requests_per_hour: int = Field(default=1000, ge=1, le=1_000_000)
    max_tokens_per_hour: int | None = Field(default=None, ge=1)
    consent_method: Literal["http_well_known", "dns_txt", "signed_token"] = "http_well_known"
    data_policy: dict[str, Any] = Field(default_factory=dict)
    allowed_models: list[str] | None = None
    weight: int = Field(default=1, ge=1, le=100)

    @field_validator("endpoint")
    @classmethod
    def _endpoint_syntax(cls, value: str) -> str:
        # Синтаксис адреса проверяется здесь; сетевая политика (loopback/private/
        # metadata, DNS-резолвинг) — в NodeService.register, которая знает о
        # настройках security (§12.5.1).
        from foa.net.security import parse_endpoint

        return parse_endpoint(value).raw


class BlacklistRequest(StrictModel):
    reason: str = Field(default="admin_manual", max_length=64)
    duration: Literal["temporary", "permanent"] | str = Field(default="permanent")
    seconds: int | None = Field(default=None, ge=1)
    note: str = Field(default="", max_length=500)


class NodePatchRequest(StrictModel):
    display_name: str | None = Field(default=None, max_length=120)
    max_concurrency: int | None = Field(default=None, ge=1, le=1000)
    max_requests_per_hour: int | None = Field(default=None, ge=1)
    weight: int | None = Field(default=None, ge=1, le=100)
    draining: bool | None = None
    functional_check_enabled: bool | None = None
    functional_check_model: str | None = Field(default=None, max_length=160)


class ConsentRequest(StrictModel):
    """Повторная подача согласия / активная регистрация владельцем."""

    owner_id: str = Field(min_length=1, max_length=64)
    node_id: str = Field(min_length=1, max_length=64)
    method: Literal["http_well_known", "dns_txt", "signed_token"] = "http_well_known"
    signed_token: str | None = Field(default=None, max_length=8192)
    allowed_models: list[str] = Field(default_factory=list)
    max_concurrency: int = Field(default=2, ge=1, le=1000)
    max_requests_per_hour: int = Field(default=1000, ge=1)
    data_policy: dict[str, Any] = Field(default_factory=dict)
    ttl_days: int = Field(default=90, ge=1, le=365)


class KeyCreateRequest(StrictModel):
    label: str = Field(default="", max_length=80)
    scopes: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int | None = Field(default=None, ge=1)
    concurrent_requests: int | None = Field(default=None, ge=1)
    tokens_per_day: int | None = Field(default=None, ge=1)
    ttl_seconds: int | None = Field(default=None, ge=60)


class ApiKeyView(BaseModel):
    key_id: str
    label: str
    scopes: list[str]
    created_at: str
    expires_at: str | None = None
    revoked: bool = False
    last_used_at: str | None = None


class NodeView(BaseModel):
    """Публичное/административное представление узла (§9.6.1).

    Имена и адреса узлов не раскрываются конечным пользователям (§9.3.2).
    """

    node_id: str
    status: str
    consent_status: str
    models: list[str] = Field(default_factory=list)
    active_connections: int = 0
    max_concurrency: int = 0
    latency_ms: float = 0.0
    error_rate: float = 0.0
    weight: int = 1
    last_health_check: str | None = None
    routable: bool = False
    endpoint: str | None = None
    display_name: str | None = None
    owner_id: str | None = None


# Белые списки полей для агрегируемых ответов (§9.3)
ALLOWED_OPTIONS: frozenset[str] = frozenset(
    {
        "temperature",
        "top_k",
        "top_p",
        "min_p",
        "num_ctx",
        "num_predict",
        "num_batch",
        "num_gpu",
        "seed",
        "repeat_penalty",
        "repeat_last_n",
        "presence_penalty",
        "frequency_penalty",
        "stop",
        "mirostat",
        "mirostat_eta",
        "mirostat_tau",
        "tfs_z",
        "num_keep",
        "penalize_newline",
        "numa",
        "main_gpu",
        "low_vram",
        "f16_kv",
        "logits_all",
        "vocab_only",
        "use_mmap",
        "use_mlock",
        "embedding_only",
        "rope_freqscale",
    }
)

__all__ = [
    "ALLOWED_OPTIONS",
    "ApiKeyView",
    "BlacklistRequest",
    "CandidateView",
    "ChatMessage",
    "ChatRequest",
    "ConsentRequest",
    "EmbedRequest",
    "EmbeddingsRequest",
    "GenerateRequest",
    "KeyCreateRequest",
    "NodePatchRequest",
    "NodeRegisterRequest",
    "NodeView",
    "ShowRequest",
    "StrictModel",
]


class CandidateView(BaseModel):
    """Представление кандидата Discovery (§4.4.1, доступ — только админ/аудитор)."""

    candidate_id: str
    source: str
    observed_at: str
    ip: str
    port: int
    protocol: str = "tcp"
    dns_names: list[str] = Field(default_factory=list)
    asn: str | None = None
    country: str | None = None
    service_hint: str | None = None
    risk_score: int = 0
    status: str = "candidate"
    sources: list[str] = Field(default_factory=list)
    requires_manual_review: bool = False

    @model_validator(mode="after")
    def _flag_review(self) -> CandidateView:
        return self
