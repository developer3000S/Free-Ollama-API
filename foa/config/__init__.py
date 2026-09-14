"""Конфигурация шлюза (ТЗ §11.5, §13, §14.2).

Приоритет источников значений (от низшего к высшему):

1. встроенные значения по умолчанию — максимально безопасный режим (§13);
2. файл ``config.yaml`` (путь в ``FOA_CONFIG_FILE``);
3. переменные окружения ``FOA_<SECTION>__<KEY>``;
4. отдельные совместимые переменные окружения из §14.2.

Секреты в YAML хранятся только как плейсхолдеры вида ``"{env:VAR}"`` или
``"{vault:path/key}"`` и подставляются в рантайме (:mod:`foa.config.secrets`).
"""

from __future__ import annotations

import copy
import os
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

ENV_PREFIX = "FOA_"
_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f"}


class ConfigError(RuntimeError):
    """Конфигурация некорректна или небезопасна — запуск запрещён."""


# --------------------------------------------------------------------------- #
# Секции
# --------------------------------------------------------------------------- #


@dataclass
class SecurityConfig:
    """§13 — безопасный режим по умолчанию."""

    require_consent: bool = True
    allow_unverified_nodes: bool = False
    active_scanning: str = "deny"  # deny | allowlist_only
    route_candidates: bool = False
    store_prompt_bodies: bool = False
    store_response_bodies: bool = False
    forward_client_ip: bool = False
    require_tls_for_nodes: bool = False
    allow_loopback_nodes: bool = True
    client_hash_salt: str = "change-me-in-production"


@dataclass
class LimitsConfig:
    """§12.4.2, §12.4.3, §13."""

    requests_per_minute_per_user: int = 60
    requests_per_minute_global: int = 1000
    requests_per_minute_per_model: int = 20
    concurrent_requests_per_user: int = 2
    max_prompt_bytes: int = 1_048_576
    max_request_bytes: int = 1_048_576
    max_num_predict: int = 2048
    max_generation_seconds: int = 300
    max_messages: int = 200
    max_message_bytes: int = 262_144
    concurrent_stream_requests_per_user: int = 2


@dataclass
class HealthConfig:
    """§6.2, §13."""

    liveness_interval_seconds: int = 15
    liveness_connect_timeout_seconds: float = 2.0
    liveness_response_timeout_seconds: float = 3.0
    liveness_failure_threshold: int = 3
    readiness_interval_seconds: int = 60
    readiness_timeout_seconds: float = 5.0
    readiness_failure_threshold: int = 2
    timeout_seconds: float = 3.0
    failure_threshold: int = 3
    consent_recheck_interval_seconds: int = 86_400  # §5.4 «не реже чем каждые 24 ч»
    consent_revocation_apply_seconds: int = 5  # §5.5 — целевое время применения отзыва
    passive_window_seconds: int = 60  # §6.3
    passive_error_rate_threshold: float = 0.20  # §6.4 — 20% за окно
    functional_check_enabled: bool = False  # §6.2.5 — по умолчанию выключена
    functional_check_model: str = ""
    functional_check_interval_seconds: int = 3600
    retry_after_failure_seconds: float = 1.0  # экспоненциальная задержка: база


@dataclass
class CircuitBreakerConfig:
    """§6.5."""

    window_seconds: float = 30.0
    minimum_requests: int = 10
    error_rate_threshold: float = 0.5
    open_duration_seconds: float = 60.0
    half_open_probes: int = 1


@dataclass
class PoolConfig:
    """§7.1."""

    max_connections_per_node: int = 10
    max_connections_per_model_per_node: int = 4
    connect_timeout_seconds: float = 2.0
    read_headers_timeout_seconds: float = 10.0
    full_generation_timeout_seconds: float = 300.0
    keep_alive: bool = True
    prefer_tls: bool = True


@dataclass
class BalancerConfig:
    """§7.3–§7.6."""

    algorithm: str = "least_connections_with_latency"
    capacity_weight: float = 0.5
    latency_weight: float = 0.3
    ewma_alpha: float = 0.3
    latency_reference_ms: float = 30_000.0
    queue_wait_timeout_seconds: float = 5.0
    connection_wait_timeout_seconds: float = 2.0
    max_retries: int = 1
    retry_streaming_requests: bool = False
    retry_after_upstream_started: bool = False


@dataclass
class SourceConfig:
    """§4.5 — одна интеграция Discovery."""

    enabled: bool = False  # §10 FR-D-07: все источники выключены по умолчанию
    api_key: str = ""
    api_id: str = ""
    api_secret: str = ""
    api_endpoint: str = ""
    allowed_scopes: list[str] = field(default_factory=list)
    purpose: str = "inventory"  # inventory | research | risk_enrichment
    cache_ttl_seconds: int = 86_400
    max_requests_per_minute: int = 10
    query: str = ""


@dataclass
class DiscoveryConfig:
    """§4.3, §4.5, §13."""

    enabled: bool = True
    mode: str = "inventory_only"  # disabled | inventory_only | candidate_research | authorized_enrollment
    active_scanning: str = "deny"
    auto_route_candidates: bool = False
    retain_days: int = 90  # §4.7
    risk_manual_review_threshold: int = 70  # §4.4.3
    scan_interval_seconds: int = 3600
    sources: dict[str, SourceConfig] = field(default_factory=dict)


@dataclass
class PrivacyConfig:
    """§12.5.2."""

    store_request_body: bool = False
    store_response_body: bool = False
    log_metadata_only: bool = True
    retention_days: int = 0


@dataclass
class AuthConfig:
    """§9.2, §12.4.1."""

    require_api_key: bool = True
    key_prefix: str = "foa_"
    default_scopes: list[str] = field(default_factory=lambda: ["ollama:read", "ollama:generate"])
    key_rotation_grace_seconds: int = 3600
    admin_token: str = ""  # пустой → админ-контур закрыт (fail-closed)
    auditor_token: str = ""
    owner_token: str = ""
    #: Идентичность владельца, которой принадлежит owner_token (§2.2, §5.5).
    #: Для мульти-владельческого развёртывания используйте OIDC/mTLS (§9.6).
    owner_ref: str = ""
    bcrypt_like_pepper: str = ""


@dataclass
class ObservabilityConfig:
    """§11.4."""

    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    log_level: str = "INFO"
    log_format: str = "json"
    log_requests: bool = True
    trace_enabled: bool = False


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    api_prefix: str = ""  # напр. "/v1/ollama" (§9.1)
    graceful_shutdown_seconds: float = 30.0
    #: Роль процесса в топологии §14.1. true (по умолчанию) — этот экземпляр сам
    #: ведёт активные health-check, сканирование discovery и слежение за истечением
    #: согласий. false — только проксирование: фоновые циклы вынесены в отдельный
    #: worker, а реплики периодически перечитывают реестр из БД. Иначе при 2+
    #: репликах нагрузка проверок на узлы умножается на число реплик (§6.1).
    run_background_loops: bool = True
    #: Интервал перечитывания реестра в проксирующем режиме (сек). Гарантирует,
    #: что отзыв согласия дойдёт до всех реплик не позже consent_revocation_apply_seconds.
    registry_sync_interval_seconds: float = 2.0


@dataclass
class StorageConfig:
    """§14.1. По умолчанию — локальный SQLite; Postgres задаётся через GATEWAY_DB_URL."""

    database_url: str = "sqlite+aiosqlite:///data/foagw.sqlite3"
    redis_url: str = ""  # пусто → локальные in-memory лимиты/кэш
    data_dir: str = "data"


@dataclass
class Settings:
    version: int = 1
    gateway_id: str = "gateway_main"
    security: SecurityConfig = field(default_factory=SecurityConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    health: HealthConfig = field(default_factory=HealthConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    pool: PoolConfig = field(default_factory=PoolConfig)
    load_balancer: BalancerConfig = field(default_factory=BalancerConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    source_path: str = ""
    reloadable_keys: tuple[str, ...] = ()

    # -- утилиты ---------------------------------------------------------- #

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def apply_overlay(self, overlay: dict[str, Any]) -> None:
        """Накладывает сырой dict поверх текущих значений (только известные поля)."""
        _merge_into(self, overlay, path=())

    def validate(self) -> None:
        """Проверяет инварианты безопасности; нарушения — ConfigError."""
        s = self.security
        if not s.require_consent:
            raise ConfigError("security.require_consent=false запрещён: маршрутизация без согласия недопустима (§5.1)")
        if s.allow_unverified_nodes:
            raise ConfigError("security.allow_unverified_nodes=true запрещён (§3.2.6, §17.1)")
        if s.route_candidates:
            raise ConfigError("security.route_candidates=true запрещён (§4.4.4, FR-D-04)")
        if self.discovery.auto_route_candidates:
            raise ConfigError("discovery.auto_route_candidates=true запрещён (§4.3, FR-D-04)")
        if self.discovery.mode not in {"disabled", "inventory_only", "candidate_research", "authorized_enrollment"}:
            raise ConfigError(f"неизвестный discovery.mode={self.discovery.mode!r}")
        if self.security.active_scanning not in {"deny", "allowlist_only"}:
            raise ConfigError("security.active_scanning должен быть 'deny' или 'allowlist_only' (§4.3)")
        if self.discovery.mode != "disabled":
            if self.discovery.active_scanning not in {"deny", "allowlist_only"}:
                raise ConfigError("discovery.active_scanning должен быть 'deny' или 'allowlist_only'")
            for name, src in self.discovery.sources.items():
                if src.enabled and not src.allowed_scopes and self.discovery.mode == "inventory_only":
                    raise ConfigError(
                        f"discovery.sources.{name}: enabled=true требует непустого allowed_scopes (§4.6)"
                    )
        lb = self.load_balancer
        if lb.algorithm not in BALANCER_ALGORITHMS:
            raise ConfigError(f"неизвестный load_balancer.algorithm={lb.algorithm!r}")
        if not self.server.run_background_loops and self.server.registry_sync_interval_seconds > self.health.consent_revocation_apply_seconds:
            raise ConfigError(
                f"server.registry_sync_interval_seconds={self.server.registry_sync_interval_seconds} превышает "
                f"health.consent_revocation_apply_seconds={self.health.consent_revocation_apply_seconds}: "
                "проксирующая реплика не успеет применить отзыв согласия (§5.5)"
            )
        if not self.privacy.log_metadata_only and not self.security.store_prompt_bodies:
            raise ConfigError("privacy.log_metadata_only=false требует явного security.store_prompt_bodies (§12.5.2)")
        for name, value in (
            ("limits.max_prompt_bytes", self.limits.max_prompt_bytes),
            ("limits.max_num_predict", self.limits.max_num_predict),
            ("limits.requests_per_minute_per_user", self.limits.requests_per_minute_per_user),
        ):
            if value <= 0:
                raise ConfigError(f"{name} должен быть > 0")


BALANCER_ALGORITHMS = {
    "round_robin",
    "weighted_round_robin",
    "least_connections",
    "least_latency",
    "consistent_hash",
    "least_connections_with_latency",
    "least_connections_with_latency_and_error_penalty",
}

# Секции, которые можно перезагружать на лету без остановки трафика (§11.5).
HOT_RELOAD_SECTIONS = {"limits", "health", "circuit_breaker", "observability", "load_balancer", "privacy"}
COLD_SECTIONS = {"security", "auth", "server", "storage", "discovery", "pool"}


# --------------------------------------------------------------------------- #
# Загрузка
# --------------------------------------------------------------------------- #


def _merge_into(target: Any, overlay: dict[str, Any], path: tuple[str, ...]) -> None:
    for key, value in overlay.items():
        if not hasattr(target, key):
            group = _NESTED_GROUPS.get((type(target), key))
            if group is not None and isinstance(value, dict):
                _merge_group(target, key, value, path, group)
                continue
            raise ConfigError(f"неизвестный параметр конфигурации: {'.'.join((*path, key))}")
        current = getattr(target, key)
        if is_dataclass(current) and isinstance(value, dict):
            _merge_into(current, value, (*path, key))
        elif isinstance(current, dict) and isinstance(value, dict):
            for sub, subval in value.items():
                if sub not in current and not isinstance(current, dict):
                    continue
                if isinstance(current.get(sub), SourceConfig) and isinstance(subval, dict):
                    merged = copy.deepcopy(current.get(sub))
                    _merge_into(merged, subval, (*path, key, sub))
                    current[sub] = merged
                elif sub in current:
                    current[sub] = _coerce(type(current[sub]), subval)
                else:
                    current[sub] = SourceConfig(**{k: v for k, v in subval.items() if k in _SOURCE_FIELDS})
        else:
            try:
                setattr(target, key, _coerce(type(current), value))
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"неверное значение {'.'.join((*path, key))}: {exc}") from exc


def _merge_group(target: Any, key: str, value: dict[str, Any], path: tuple[str, ...], group: tuple[str, ...]) -> None:
    """Разворачивает сгруппированный блок YAML (§13) в плоские поля dataclass.

    ТЗ в §13 пишет `load_balancer.retry_policy.{max_retries,...}` вложенно, а
    §7.6 определяет их как независимые переключатели повтора — поле в поле здесь
    не нужно, поэтому группа отображается на уже существующие атрибуты.
    """
    for sub, subval in value.items():
        if sub not in group:
            raise ConfigError(f"неизвестный параметр конфигурации: {'.'.join((*path, key, sub))}")
        current = getattr(target, sub)
        try:
            setattr(target, sub, _coerce(type(current), subval))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"неверное значение {'.'.join((*path, key, sub))}: {exc}") from exc


_NESTED_GROUPS: dict[tuple[type, str], tuple[str, ...]] = {
    (BalancerConfig, "retry_policy"): (
        "max_retries",
        "retry_streaming_requests",
        "retry_after_upstream_started",
    ),
}


_SOURCE_FIELDS = {f.name for f in fields(SourceConfig)}


def _coerce(target_type: type, value: Any) -> Any:
    if value is None:
        return None
    if target_type is bool:
        if isinstance(value, str):
            low = value.strip().lower()
            if low in _TRUE:
                return True
            if low in _FALSE:
                return False
            raise ValueError(f"не bool: {value!r}")
        return bool(value)
    if target_type is int:
        return int(value)
    if target_type in (float,):
        return float(value)
    if target_type is str:
        return str(value)
    if target_type is list:
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        return list(value)
    if target_type is tuple:
        return tuple(value if not isinstance(value, str) else [v.strip() for v in value.split(",") if v.strip()])
    return value


def _env_overrides(env: dict[str, str]) -> dict[str, Any]:
    """``FOA_LIMITS__MAX_PROMPT_BYTES=2048`` → ``{"limits": {"max_prompt_bytes": "2048"}}``."""
    out: dict[str, Any] = {}
    for raw_key, value in env.items():
        if not raw_key.startswith(ENV_PREFIX):
            continue
        key = raw_key[len(ENV_PREFIX) :]
        if key in {"CONFIG_FILE", "CONFIG"}:
            continue
        parts = [p.lower() for p in key.split("__") if p]
        if len(parts) < 2:
            continue
        node = out
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):  # pragma: no cover - защита от конфликта типов
                raise ConfigError(f"конфликт имён переменных окружения: {raw_key}")
        node[parts[-1]] = value
    return out


def _compat_env(env: dict[str, str]) -> dict[str, Any]:
    """Совместимые имена из §14.2 и специфичные для шлюза переменные."""
    overlay: dict[str, Any] = {}

    def put(path: tuple[str, ...], value: str) -> None:
        node = overlay
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value

    if db := env.get("GATEWAY_DB_URL"):
        put(("storage", "database_url"), _normalize_db_url(db))
    if redis := env.get("GATEWAY_REDIS_URL"):
        put(("storage", "redis_url"), redis)
    if pepper := env.get("GATEWAY_JWT_SECRET"):
        put(("auth", "bcrypt_like_pepper"), pepper)
    if token := env.get("FOA_ADMIN_TOKEN") or env.get("GATEWAY_ADMIN_TOKEN"):
        put(("auth", "admin_token"), token)
    if token := env.get("FOA_AUDITOR_TOKEN") or env.get("GATEWAY_AUDITOR_TOKEN"):
        put(("auth", "auditor_token"), token)
    if token := env.get("FOA_OWNER_TOKEN") or env.get("GATEWAY_OWNER_TOKEN"):
        put(("auth", "owner_token"), token)
    if salt := env.get("FOA_CLIENT_HASH_SALT"):
        put(("security", "client_hash_salt"), salt)
    if gid := env.get("GATEWAY_ID"):
        put(("gateway_id",), gid)

    # Ключи внешних платформ (§14.2) включаются только если явно разрешены
    # FOA_DISCOVERY_ENABLED=true и заданы allowed_scopes — см. validate().
    legacy_keys = {
        "censys": ("CENSYS_API_ID", "CENSYS_API_SECRET"),
        "greynoise": ("GREYNOISE_API_KEY", None),
        "zoomeye": ("ZOOMEYE_API_KEY", None),
        "natlas": ("NATLAS_API_KEY", None),
        "criminal_ip": ("CRIMINAL_IP_API_KEY", None),
    }
    for source, (first, second) in legacy_keys.items():
        value = env.get(first) or (env.get(second) if second else None)
        if value:
            put(("discovery", "sources", source, "api_key"), value)
            if second and env.get(second):
                put(("discovery", "sources", source, "api_secret"), env[second])
            if env.get(first):
                put(("discovery", "sources", source, "api_id"), env[first])
    return overlay


def _normalize_db_url(url: str) -> str:
    """Postgres-URL из §14.2 приводим к async-драйверу SQLAlchemy."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def default_settings() -> Settings:
    """Настройки по умолчанию — раздел §13 ТЗ, максимально безопасный режим."""
    sources = {
        name: SourceConfig(enabled=False, purpose=purpose, api_endpoint=endpoint)
        for name, purpose, endpoint in (
            ("censys", "inventory", ""),
            ("greynoise", "research", ""),
            ("zoomeye", "inventory", ""),
            ("natlas", "inventory", ""),
            ("criminal_ip", "risk_enrichment", ""),
        )
    }
    return Settings(
        discovery=DiscoveryConfig(
            enabled=True,
            mode="inventory_only",
            active_scanning="deny",
            auto_route_candidates=False,
            sources=sources,
        )
    )


def load_settings(
    path: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
    *,
    validate: bool = True,
) -> Settings:
    """Собирает настройки: defaults ← YAML ← окружение."""
    env = dict(os.environ if env is None else env)
    settings = default_settings()
    config_path = Path(path or env.get("FOA_CONFIG_FILE") or "config.yaml")
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ConfigError(f"{config_path}: корень документа должен быть mapping")
        settings.source_path = str(config_path)
        settings.apply_overlay(raw)
    settings.apply_overlay(_compat_env(env))
    settings.apply_overlay(_env_overrides(env))
    from foa.config.secretrefs import resolve_secrets

    resolve_secrets(settings, env)
    if validate:
        settings.validate()
    return settings


__all__ = [
    "BALANCER_ALGORITHMS",
    "COLD_SECTIONS",
    "HOT_RELOAD_SECTIONS",
    "ConfigError",
    "DiscoveryConfig",
    "HealthConfig",
    "LimitsConfig",
    "SecurityConfig",
    "Settings",
    "SourceConfig",
    "default_settings",
    "load_settings",
]
