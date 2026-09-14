"""Юнит-тесты конфигурации (§13, §14.2, §11.5), secret-ссылок (§4.5),
структурированного журнала (§11.4, §12.5.2–§12.5.3) и Prometheus-метрик (§11.4).

Тесты фиксируют фактическое поведение модулей: приоритет источников значений,
перечень небезопасных оверрайдов, отбраковываемых ``Settings.validate()``,
маскирование секретов в журнале и состав ключевых метрик.
"""

from __future__ import annotations

import io
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import foa.logging as foa_logging
import foa.observability.metrics as metrics
import pytest
from foa.config import (
    BALANCER_ALGORITHMS,
    COLD_SECTIONS,
    HOT_RELOAD_SECTIONS,
    ConfigError,
    SecurityConfig,
    Settings,
    SourceConfig,
    default_settings,
    load_settings,
)
from foa.config.secretrefs import SecretResolutionError, resolve_ref, resolve_secrets
from foa.logging import (
    JsonLogFormatter,
    KeySafeFormatter,
    RedactingFilter,
    configure_logging,
    get_logger,
    log_event,
    scrub,
    scrub_text,
)
from prometheus_client import generate_latest

# Заведомо несуществующий файл: тесты с ним проверяют работу только default+env.
ABSENT_YAML = "no-such-config-under-tests.yaml"


# --------------------------------------------------------------------------- #
# §13 — значения по умолчанию
# --------------------------------------------------------------------------- #


def test_security_defaults_are_the_safe_mode():
    """§13: безопасный режим по умолчанию (согласие обязательно, кандидаты не маршрутизируются)."""
    security = default_settings().security
    assert isinstance(security, SecurityConfig)
    assert security.require_consent is True
    assert security.allow_unverified_nodes is False
    assert security.route_candidates is False
    assert security.store_prompt_bodies is False
    assert security.forward_client_ip is False
    assert security.active_scanning == "deny"


def test_limits_defaults_match_spec():
    """§13: лимиты по умолчанию."""
    limits = default_settings().limits
    assert limits.requests_per_minute_per_user == 60
    assert limits.concurrent_requests_per_user == 2
    assert limits.max_prompt_bytes == 1_048_576
    assert limits.max_num_predict == 2048
    assert limits.max_generation_seconds == 300


def test_health_defaults_match_spec():
    """§13: интервалы и пороги health-check по умолчанию."""
    health = default_settings().health
    assert health.liveness_interval_seconds == 15
    assert health.liveness_response_timeout_seconds == 3
    assert health.failure_threshold == 3
    # §13 приводит также обобщённые поля таймаута/порога.
    assert health.timeout_seconds == 3
    assert health.readiness_interval_seconds == 60


def test_load_balancer_default_algorithm():
    """§13 / §7.3: алгоритм балансировки по умолчанию."""
    settings = default_settings()
    assert settings.load_balancer.algorithm == "least_connections_with_latency"
    assert settings.load_balancer.algorithm in BALANCER_ALGORITHMS


def test_all_five_discovery_sources_present_and_disabled():
    """§13 + FR-D-07: все пять источников Discovery присутствуют и выключены."""
    sources = default_settings().discovery.sources
    assert set(sources) == {"censys", "greynoise", "zoomeye", "natlas", "criminal_ip"}
    assert all(isinstance(src, SourceConfig) for src in sources.values())
    assert all(src.enabled is False for src in sources.values())
    # §4.5: назначение источника по умолчанию.
    assert sources["greynoise"].purpose == "research"
    assert sources["criminal_ip"].purpose == "risk_enrichment"
    assert sources["censys"].purpose == "inventory"


def test_discovery_defaults_are_inventory_only_and_passive():
    """§13: discovery по умолчанию — пассивный инвентарь без авто-маршрутизации."""
    discovery = default_settings().discovery
    assert discovery.mode == "inventory_only"
    assert discovery.active_scanning == "deny"
    assert discovery.auto_route_candidates is False


def test_default_settings_instances_are_isolated():
    """Правки одного экземпляра настроек не должны «протекать» в другой."""
    first = default_settings()
    first.limits.max_prompt_bytes = 1
    first.discovery.sources.pop("censys")
    assert default_settings().limits.max_prompt_bytes == 1_048_576
    assert "censys" in default_settings().discovery.sources


SPEC_13_YAML = """
security:
  require_consent: true
  allow_unverified_nodes: false
  active_scanning: deny
  route_candidates: false
  store_prompt_bodies: false
  store_response_bodies: false
  forward_client_ip: false
limits:
  requests_per_minute_per_user: 60
  concurrent_requests_per_user: 2
  max_prompt_bytes: 1048576
  max_num_predict: 2048
  max_generation_seconds: 300
health:
  liveness_interval_seconds: 15
  readiness_interval_seconds: 60
  timeout_seconds: 3
  failure_threshold: 3
discovery:
  mode: inventory_only
  sources:
    censys:
      enabled: false
    greynoise:
      enabled: false
    zoomeye:
      enabled: false
    natlas:
      enabled: false
    criminal_ip:
      enabled: false
"""


def test_defaults_equal_the_spec_13_yaml_block(tmp_path):
    """§13: YAML-блок значений по умолчанию совпадает с built-in defaults поле в поле."""
    import yaml

    raw = yaml.safe_load(SPEC_13_YAML)
    settings = default_settings()
    for section, values in raw.items():
        for key, expected in values.items():
            if key == "sources":
                continue
            assert getattr(settings, section).__dict__[key] == expected, f"{section}.{key}"
    for name, source in raw["discovery"]["sources"].items():
        for key, expected in source.items():
            assert getattr(settings.discovery.sources[name], key) == expected, f"discovery.sources.{name}.{key}"
    # файл с этими значениями проходит загрузку и валидацию
    path = _write_yaml(tmp_path, SPEC_13_YAML)
    assert load_settings(path=path, env={}).limits.max_prompt_bytes == 1_048_576


def test_spec_13_yaml_block_loads_verbatim(tmp_path):
    """§13: пример конфигурации из ТЗ должен загружаться без правок (вложенный retry_policy)."""
    path = _write_yaml(
        tmp_path,
        SPEC_13_YAML
        + """
load_balancer:
  algorithm: least_connections_with_latency
  retry_policy:
    max_retries: 1
    retry_streaming_requests: false
    retry_after_upstream_started: false
""",
    )
    settings = load_settings(path=path, env={})
    assert settings.load_balancer.max_retries == 1


def test_retry_policy_flat_keys_are_configurable():
    """Работающая форма из §13 — плоские ключи load_balancer.* (обходной путь для retry_policy)."""
    settings = load_settings(
        path=ABSENT_YAML,
        env={
            "FOA_LOAD_BALANCER__MAX_RETRIES": "0",
            "FOA_LOAD_BALANCER__RETRY_STREAMING_REQUESTS": "false",
            "FOA_LOAD_BALANCER__RETRY_AFTER_UPSTREAM_STARTED": "false",
        },
    )
    assert settings.load_balancer.max_retries == 0
    assert settings.load_balancer.retry_streaming_requests is False
    assert settings.load_balancer.retry_after_upstream_started is False


# --------------------------------------------------------------------------- #
# §11.5 — YAML, переменные окружения, приоритет
# --------------------------------------------------------------------------- #


def _write_yaml(tmp_path: Path, text: str, name: str = "config.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_yaml_overlay_is_applied_over_defaults(tmp_path):
    """§11.5: файл config.yaml перезаписывает значения по умолчанию."""
    path = _write_yaml(
        tmp_path,
        """
version: 7
gateway_id: gw_edge
security:
  store_prompt_bodies: true
limits:
  max_prompt_bytes: 4096
  concurrent_requests_per_user: 5
discovery:
  mode: candidate_research
  sources:
    censys:
      enabled: true
      allowed_scopes: [inventory]
""",
    )
    settings = load_settings(path=path, env={})
    assert settings.version == 7
    assert settings.gateway_id == "gw_edge"
    assert settings.source_path == str(path)
    assert settings.limits.max_prompt_bytes == 4096
    assert settings.limits.concurrent_requests_per_user == 5
    assert settings.discovery.mode == "candidate_research"
    assert settings.discovery.sources["censys"].enabled is True
    assert settings.discovery.sources["censys"].allowed_scopes == ["inventory"]
    # прочие источники не исчезают и не включаются молча
    assert settings.discovery.sources["greynoise"].enabled is False
    # не указанные поля сохраняют безопасные значения по умолчанию
    assert settings.security.allow_unverified_nodes is False
    assert settings.security.require_consent is True


def test_env_overrides_yaml_and_defaults(tmp_path):
    """§11.5: приоритет defaults < YAML < окружение."""
    path = _write_yaml(
        tmp_path,
        """
limits:
  max_prompt_bytes: 4096
  max_num_predict: 128
discovery:
  mode: candidate_research
""",
    )
    settings = load_settings(
        path=path,
        env={
            "FOA_LIMITS__MAX_PROMPT_BYTES": "2048",
            "FOA_DISCOVERY__MODE": "disabled",
        },
    )
    assert settings.limits.max_prompt_bytes == 2048  # окружение перебивает YAML
    assert settings.limits.max_num_predict == 128  # YAML перебивает default
    assert settings.discovery.mode == "disabled"
    assert settings.security.require_consent is True  # default не тронут


def test_env_variable_form_section_key():
    """§11.5: переменные вида FOA_<SECTION>__<KEY>."""
    settings = load_settings(
        path=ABSENT_YAML,
        env={
            "FOA_LIMITS__MAX_PROMPT_BYTES": "32768",
            "FOA_DISCOVERY__MODE": "candidate_research",
            "FOA_SECURITY__ACTIVE_SCANNING": "allowlist_only",
            "FOA_LOAD_BALANCER__ALGORITHM": "least_connections",
        },
    )
    assert settings.limits.max_prompt_bytes == 32768
    assert settings.discovery.mode == "candidate_research"
    assert settings.security.active_scanning == "allowlist_only"
    assert settings.load_balancer.algorithm == "least_connections"


def test_env_boolean_and_list_coercion():
    """Скалярное приведение: bool из «yes/off», список из запятой строки."""
    settings = load_settings(
        path=ABSENT_YAML,
        env={
            "FOA_PRIVACY__STORE_REQUEST_BODY": "yes",
            "FOA_AUTH__REQUIRE_API_KEY": "off",
            "FOA_DISCOVERY__SOURCES__CENSYS__ALLOWED_SCOPES": "inventory, research ,, ",
        },
    )
    assert settings.privacy.store_request_body is True
    assert settings.auth.require_api_key is False
    assert settings.discovery.sources["censys"].allowed_scopes == ["inventory", "research"]


def test_nested_env_for_discovery_source():
    """FOA_DISCOVERY__SOURCES__<NAME>__<KEY> попадает в конкретный источник."""
    settings = load_settings(
        path=ABSENT_YAML,
        env={
            "FOA_DISCOVERY__MODE": "candidate_research",
            "FOA_DISCOVERY__SOURCES__CENSYS__ENABLED": "true",
            "FOA_DISCOVERY__SOURCES__CENSYS__ALLOWED_SCOPES": "inventory",
        },
    )
    assert settings.discovery.sources["censys"].enabled is True
    assert settings.discovery.sources["censys"].allowed_scopes == ["inventory"]
    assert settings.discovery.sources["natlas"].enabled is False


def test_unprefixed_env_vars_are_ignored():
    """Посторонние переменные не должны влиять на настройки."""
    settings = load_settings(path=ABSENT_YAML, env={"SOME_OTHER_APP__LIMITS__MAX_PROMPT_BYTES": "1"})
    assert settings.limits.max_prompt_bytes == 1_048_576


def test_missing_config_file_is_not_an_error():
    """§11.5: отсутствие файла — штатная ситуация, работают только default+env."""
    settings = load_settings(path=ABSENT_YAML, env={})
    assert settings.source_path == ""
    assert isinstance(settings, Settings)


def test_config_file_path_from_env(tmp_path):
    """Путь к файлу может задаваться переменной FOA_CONFIG_FILE (§11.5)."""
    path = _write_yaml(tmp_path, "limits:\n  max_num_predict: 64\n", name="custom.yaml")
    settings = load_settings(path=None, env={"FOA_CONFIG_FILE": str(path)})
    assert settings.limits.max_num_predict == 64
    assert settings.source_path == str(path)


def test_explicit_path_argument_wins_over_env(tmp_path):
    """Явно переданный path имеет приоритет над FOA_CONFIG_FILE."""
    explicit = _write_yaml(tmp_path, "limits:\n  max_num_predict: 64\n", name="explicit.yaml")
    _write_yaml(tmp_path, "limits:\n  max_num_predict: 32\n", name="from_env.yaml")
    settings = load_settings(path=explicit, env={"FOA_CONFIG_FILE": str(explicit.parent / "from_env.yaml")})
    assert settings.limits.max_num_predict == 64
    assert settings.source_path == str(explicit)


def test_yaml_root_must_be_mapping(tmp_path):
    path = _write_yaml(tmp_path, "- 1\n- 2\n")
    with pytest.raises(ConfigError, match="корень документа должен быть mapping"):
        load_settings(path=path, env={})


# --------------------------------------------------------------------------- #
# §14.2 — совместимые переменные окружения
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw_url", "expected"),
    [
        ("postgresql://gw:secret@db.internal:5432/foa", "postgresql+asyncpg://gw:secret@db.internal:5432/foa"),
        ("postgres://gw:secret@db.internal/foa", "postgresql+asyncpg://gw:secret@db.internal/foa"),
        ("postgresql+asyncpg://gw@db/foa", "postgresql+asyncpg://gw@db/foa"),
        ("sqlite+aiosqlite:///data/foagw.sqlite3", "sqlite+aiosqlite:///data/foagw.sqlite3"),
    ],
)
def test_compat_gateway_db_url_is_normalized_for_asyncpg(raw_url, expected):
    """§14.2: GATEWAY_DB_URL приводится к async-драйверу SQLAlchemy."""
    settings = load_settings(path=ABSENT_YAML, env={"GATEWAY_DB_URL": raw_url})
    assert settings.storage.database_url == expected


def test_compat_gateway_redis_url_and_storage_defaults():
    settings = load_settings(path=ABSENT_YAML, env={"GATEWAY_REDIS_URL": "redis://cache:6379/0"})
    assert settings.storage.redis_url == "redis://cache:6379/0"
    assert default_settings().storage.redis_url == ""  # пусто → локальные лимиты/кэш


def test_compat_gateway_jwt_secret_tokens_and_salt():
    """§14.2: GATEWAY_JWT_SECRET, токены контуров, соль и GATEWAY_ID."""
    settings = load_settings(
        path=ABSENT_YAML,
        env={
            "GATEWAY_JWT_SECRET": "pepper-value",
            "GATEWAY_ADMIN_TOKEN": "adm",
            "FOA_AUDITOR_TOKEN": "aud",
            "GATEWAY_OWNER_TOKEN": "own",
            "FOA_CLIENT_HASH_SALT": "salt-42",
            "GATEWAY_ID": "gw_riga",
        },
    )
    assert settings.auth.bcrypt_like_pepper == "pepper-value"
    assert settings.auth.admin_token == "adm"
    assert settings.auth.auditor_token == "aud"
    assert settings.auth.owner_token == "own"
    assert settings.security.client_hash_salt == "salt-42"
    assert settings.gateway_id == "gw_riga"


@pytest.mark.parametrize(
    ("env", "source", "field", "value"),
    [
        ({"CENSYS_API_ID": "cid"}, "censys", "api_id", "cid"),
        ({"CENSYS_API_SECRET": "csec"}, "censys", "api_secret", "csec"),
        ({"GREYNOISE_API_KEY": "gn"}, "greynoise", "api_key", "gn"),
        ({"ZOOMEYE_API_KEY": "zm"}, "zoomeye", "api_key", "zm"),
        ({"NATLAS_API_KEY": "na"}, "natlas", "api_key", "na"),
        ({"CRIMINAL_IP_API_KEY": "ci"}, "criminal_ip", "api_key", "ci"),
    ],
)
def test_compat_platform_keys_map_to_discovery_source(env, source, field, value):
    """§14.2: ключи внешних платформ попадают в discovery.sources.<name>."""
    settings = load_settings(path=ABSENT_YAML, env=env)
    assert getattr(settings.discovery.sources[source], field) == value


def test_compat_platform_keys_do_not_enable_sources():
    """Наличие ключа само по себе не включает источник (FR-D-07)."""
    settings = load_settings(
        path=ABSENT_YAML,
        env={"CENSYS_API_ID": "cid", "CENSYS_API_SECRET": "csec", "GREYNOISE_API_KEY": "gn"},
    )
    assert settings.discovery.sources["censys"].enabled is False
    assert settings.discovery.sources["censys"].api_key == "cid"
    assert settings.discovery.sources["censys"].api_secret == "csec"
    assert settings.discovery.sources["greynoise"].api_key == "gn"
    assert settings.discovery.sources["greynoise"].api_secret == ""


def test_compat_env_loses_to_foa_prefixed_env():
    """Совместимые имена применяются до FOA_-переменных (§14.2 → §11.5)."""
    settings = load_settings(
        path=ABSENT_YAML,
        env={"GATEWAY_DB_URL": "postgresql://u@h/db", "FOA_STORAGE__DATABASE_URL": "sqlite+aiosqlite:///x.db"},
    )
    assert settings.storage.database_url == "sqlite+aiosqlite:///x.db"


# --------------------------------------------------------------------------- #
# §13 / §17.1 — небезопасные оверрайды и неизвестные параметры
# --------------------------------------------------------------------------- #

UNSAFE_OVERRIDES = [
    pytest.param({"security": {"route_candidates": True}}, "route_candidates", id="route_candidates"),
    pytest.param({"security": {"allow_unverified_nodes": True}}, "allow_unverified_nodes", id="unverified_nodes"),
    pytest.param({"security": {"require_consent": False}}, "require_consent", id="no_consent"),
    pytest.param({"discovery": {"auto_route_candidates": True}}, "auto_route_candidates", id="auto_route"),
    pytest.param({"load_balancer": {"algorithm": "magic"}}, "load_balancer.algorithm", id="unknown_algorithm"),
    pytest.param(
        {"discovery": {"mode": "inventory_only", "sources": {"censys": {"enabled": True, "allowed_scopes": []}}}},
        "allowed_scopes",
        id="source_without_scopes",
    ),
    pytest.param({"limits": {"max_prompt_bytes": 0}}, "max_prompt_bytes", id="zero_max_prompt_bytes"),
    pytest.param({"limits": {"max_num_predict": -5}}, "max_num_predict", id="negative_max_num_predict"),
    pytest.param({"limits": {"requests_per_minute_per_user": 0}}, "requests_per_minute_per_user", id="zero_rpm"),
    pytest.param({"security": {"active_scanning": "permit"}}, "active_scanning", id="bad_active_scanning"),
    pytest.param({"discovery": {"active_scanning": "permit"}}, "discovery.active_scanning", id="bad_discovery_scanning"),
    pytest.param({"discovery": {"mode": "everything"}}, "discovery.mode", id="bad_discovery_mode"),
    pytest.param({"privacy": {"log_metadata_only": False}}, "log_metadata_only", id="bodies_in_log"),
]


@pytest.mark.parametrize(("overlay", "expected_fragment"), UNSAFE_OVERRIDES)
def test_validate_rejects_unsafe_override(overlay, expected_fragment):
    """§17.1: небезопасные значения конфигурации делают запуск невозможным (ConfigError)."""
    settings = default_settings()
    settings.apply_overlay(overlay)
    with pytest.raises(ConfigError, match=expected_fragment):
        settings.validate()


def test_unsafe_override_via_environment_is_rejected_by_load_settings():
    """Даже через окружение небезопасное значение не проходит валидацию."""
    with pytest.raises(ConfigError, match="route_candidates"):
        load_settings(path=ABSENT_YAML, env={"FOA_SECURITY__ROUTE_CANDIDATES": "true"})


def test_validate_can_be_explicitly_skipped():
    """load_settings(validate=False) оставляет сырое значение (для инструментов миграции)."""
    settings = load_settings(path=ABSENT_YAML, env={"FOA_SECURITY__ROUTE_CANDIDATES": "true"}, validate=False)
    assert settings.security.route_candidates is True


def test_source_without_scopes_is_allowed_outside_inventory_mode():
    """Ограничение allowed_scopes (§4.6) действует в режиме inventory_only."""
    settings = default_settings()
    settings.apply_overlay(
        {"discovery": {"mode": "candidate_research", "sources": {"censys": {"enabled": True, "allowed_scopes": []}}}}
    )
    settings.validate()  # без исключения


def test_defaults_pass_validation():
    """Конфигурация по умолчанию заведомо валидна (§13)."""
    default_settings().validate()
    load_settings(path=ABSENT_YAML, env={}).validate()


def test_unknown_key_raises_config_error():
    """Опечатка в имени параметра — ошибка, а не молчаливое игнорирование."""
    with pytest.raises(ConfigError, match=r"неизвестный параметр конфигурации: limits\.no_such_key"):
        default_settings().apply_overlay({"limits": {"no_such_key": 1}})


def test_unknown_section_raises_config_error(tmp_path):
    path = _write_yaml(tmp_path, "not_a_section:\n  a: 1\n")
    with pytest.raises(ConfigError, match="неизвестный параметр конфигурации: not_a_section"):
        load_settings(path=path, env={})


def test_unknown_env_section_raises_config_error():
    with pytest.raises(ConfigError, match="неизвестный параметр конфигурации: whatever"):
        load_settings(path=ABSENT_YAML, env={"FOA_WHATEVER__KEY": "1"})


def test_bad_scalar_type_raises_config_error():
    with pytest.raises(ConfigError, match=r"server\.port"):
        load_settings(path=ABSENT_YAML, env={"FOA_SERVER__PORT": "not-a-number"})


# --------------------------------------------------------------------------- #
# §11.5 — горячая перезагрузка
# --------------------------------------------------------------------------- #


def test_hot_and_cold_section_split():
    """§11.5: нечувствительные секции перезагружаются на лету, чувствительные — нет."""
    assert {"limits", "health", "load_balancer"} <= HOT_RELOAD_SECTIONS
    assert {"security", "auth", "storage"} <= COLD_SECTIONS
    assert not (HOT_RELOAD_SECTIONS & COLD_SECTIONS)


def test_hot_reload_sections_are_real_settings_attributes():
    """Каждая перечисленная секция существует в дереве настроек."""
    settings = default_settings()
    for name in HOT_RELOAD_SECTIONS | COLD_SECTIONS:
        assert hasattr(settings, name), name


# --------------------------------------------------------------------------- #
# §4.5 — secret-ссылки
# --------------------------------------------------------------------------- #


def test_resolve_ref_env():
    assert resolve_ref("{env:MY_SECRET}", {"MY_SECRET": "value"}) == "value"


def test_resolve_ref_file(tmp_path):
    secret = tmp_path / "token.txt"
    secret.write_text("  file-secret-value \n", encoding="utf-8")
    assert resolve_ref(f"{{file:{secret}}}", {}) == "file-secret-value"


def test_resolve_ref_vault(tmp_path):
    cache = tmp_path / "secrets"
    cache.mkdir()
    (cache / "kv-data-path-key").write_text("vault-value", encoding="utf-8")
    assert resolve_ref("{vault:kv/data/path/key}", {"FOA_VAULT_CACHE_DIR": str(cache)}) == "vault-value"


def test_resolve_ref_bare_placeholder_actual_lookup_name():
    """Фикс §14.2: схема опциональна, поэтому всё имя уходит в ``scheme`` (``ref`` пуст).

    Имя переменной выводится из непустого сегмента, поэтому ``{api_key_service}``
    читается из ``FOA_SECRET_API_KEY_SERVICE``, а не из пустого ``FOA_SECRET_``.
    """
    assert resolve_ref("{api_key_service}", {"FOA_SECRET_": "wrong-name-value"}) == ""
    assert resolve_ref("{api_key_service}", {"FOA_SECRET_API_KEY_SERVICE": "svc-key"}) == "svc-key"


def test_resolve_ref_bare_placeholder_should_use_env_by_name():
    """§14.2: плейсхолдер ``{api_key_service}`` должен читаться из FOA_SECRET_API_KEY_SERVICE."""
    assert resolve_ref("{api_key_service}", {"FOA_SECRET_API_KEY_SERVICE": "svc-key"}) == "svc-key"


def test_resolve_ref_unknown_scheme_is_looked_up_by_name():
    """Неизвестная схема (не env/file/vault) разрешается по имени, напр. ``{custom:key}``."""
    assert resolve_ref("{custom:key}", {"FOA_SECRET_KEY": "vv"}) == "vv"
    assert resolve_ref("{custom:key}", {}) == ""



@pytest.mark.parametrize(
    "value",
    ["{env:ABSENT}", "{file:/nope/nope.txt}", "{vault:kv/missing}", "{api_key_service}"],
)
def test_resolve_ref_missing_returns_empty_when_not_strict(value, tmp_path):
    """FR-D-07: отсутствующий внешний секрет — не ошибка; интеграция просто остаётся выключенной."""
    assert resolve_ref(value, {"FOA_VAULT_CACHE_DIR": str(tmp_path)}, strict=False) == ""


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        ("{env:ABSENT}", "переменная окружения ABSENT не задана"),
        ("{file:/nope/nope.txt}", "файл секрета не найден"),
        ("{vault:kv/missing}", "vault-секрет недоступен локально"),
        ("{api_key_service}", "не удалось разрешить ссылку на секрет"),
    ],
)
def test_resolve_ref_missing_raises_when_strict(value, fragment, tmp_path):
    with pytest.raises(SecretResolutionError, match=fragment):
        resolve_ref(value, {"FOA_VAULT_CACHE_DIR": str(tmp_path)}, strict=True)


def test_resolve_ref_passes_through_plain_values():
    assert resolve_ref("plain-token", {}) == "plain-token"
    assert resolve_ref("", {}) == ""
    assert resolve_ref(None, {}) is None
    assert resolve_ref(7, {}) == 7
    assert resolve_ref(["{env:X}"], {"X": "y"}) == ["{env:X}"]  # список не разбирается


def test_resolve_secrets_walks_dataclass_tree_in_place():
    """resolve_secrets подставляет значения рекурсивно, включая dict источников Discovery."""
    settings = default_settings()
    settings.auth.admin_token = "{env:MY_ADMIN}"
    settings.auth.owner_token = "literal"
    settings.discovery.sources["censys"].api_key = "{env:MY_CENSYS}"
    settings.discovery.sources["natlas"].api_key = "{env:ABSENT_KEY}"
    settings.security.client_hash_salt = "{env:MY_SALT}"

    returned = resolve_secrets(settings, {"MY_ADMIN": "A1", "MY_CENSYS": "C1", "MY_SALT": "S1"})

    assert returned is settings
    assert settings.auth.admin_token == "A1"
    assert settings.auth.owner_token == "literal"
    assert settings.discovery.sources["censys"].api_key == "C1"
    assert settings.discovery.sources["natlas"].api_key == ""
    assert settings.security.client_hash_salt == "S1"


def test_load_settings_resolves_yaml_placeholders(tmp_path):
    """Секреты в YAML хранятся плейсхолдерами и разрешаются в рантайме (§11.5)."""
    secret_file = tmp_path / "greynoise.key"
    secret_file.write_text("gn-from-file\n", encoding="utf-8")
    yaml_text = "auth:\n  admin_token: '{env:MY_ADMIN_TOK}'\ndiscovery:\n  sources:\n    greynoise:\n      api_key: '{file:"
    yaml_text += str(secret_file) + "}'\n"
    path = _write_yaml(tmp_path, yaml_text)
    settings = load_settings(path=path, env={"MY_ADMIN_TOK": "tok-123"})
    assert settings.auth.admin_token == "tok-123"
    assert settings.discovery.sources["greynoise"].api_key == "gn-from-file"


# --------------------------------------------------------------------------- #
# §12.5.2–§12.5.3 — маскирование и журнал
# --------------------------------------------------------------------------- #

FORBIDDEN_KEYS = [
    "prompt",
    "response",
    "content",
    "messages",
    "api_key",
    "token",
    "secret",
    "authorization",
    "signature",
    "challenge",
]

ALLOWED_METADATA_KEYS = ["request_id", "node_id", "latency_ms", "model", "status"]


@pytest.mark.parametrize("key", FORBIDDEN_KEYS)
def test_scrub_drops_forbidden_key(key):
    assert scrub({key: "x", "request_id": "r"}) == {"request_id": "r"}


def test_scrub_keeps_allowed_metadata():
    """§12.5.3: разрешённая метадата запроса сохраняется без изменений."""
    payload: dict[str, Any] = {
        "request_id": "req_1",
        "node_id": "n_1",
        "latency_ms": 12,
        "model": "llama3.1",
        "status": 200,
    }
    assert set(payload) == set(ALLOWED_METADATA_KEYS)
    assert scrub(payload) == payload


def test_scrub_handles_nested_structures():
    """Вложенные dict/list тоже чистятся — запрещённое поле не «прячется» на втором уровне."""
    clean = scrub({"ctx": {"prompt": "x", "ok": 1}, "tags": ["Bearer abc", "keep me"], "n": 4})
    assert clean == {"ctx": {"ok": 1}, "tags": ["Bearer ***", "keep me"], "n": 4}


def test_scrub_text_masks_bearer_tokens():
    assert scrub_text("Authorization: Bearer eyJhbGciOi.abc_123/x+y") == "Authorization: Bearer ***"
    assert scrub_text("bearer lowercase-token") == "bearer ***"


def test_scrub_text_masks_gateway_api_keys():
    assert scrub_text("key=foa_abcdef123456 accepted") == "key=*** accepted"


def test_scrub_text_masks_long_hex_strings():
    digest = "ab" * 20
    assert scrub_text(f"sha256:{digest}") == "sha256:***"


def test_scrub_text_keeps_ordinary_text():
    text = "node n_7 model llama3.1 status 200 deadbeef"
    assert scrub_text(text) == text


def _record(msg: str = "hello", level: int = logging.INFO, **extra) -> logging.LogRecord:
    record = logging.LogRecord("foa.unit", level, "tests.py", 1, msg, None, None)
    if extra:
        record.foa = extra
    return record


def test_json_log_formatter_emits_valid_json():
    payload = json.loads(JsonLogFormatter().format(_record("запрос выполнен", request_id="r1", prompt="x")))
    assert {"timestamp", "level", "logger", "message"} <= set(payload)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "foa.unit"
    assert payload["message"] == "запрос выполнен"
    assert datetime.strptime(payload["timestamp"], "%Y-%m-%dT%H:%M:%S%z")
    assert "prompt" not in payload
    assert payload["request_id"] == "r1"


def test_json_log_formatter_adds_request_context():
    token = foa_logging._request_id.set("ctx-req-1")
    try:
        payload = json.loads(JsonLogFormatter().format(_record("m")))
    finally:
        foa_logging._request_id.reset(token)
    assert payload["request_id"] == "ctx-req-1"


def test_json_log_formatter_scrubs_message_and_exception():
    forbidden_key = "foa_secretkey123456"
    try:
        raise ValueError(f"boom {forbidden_key}")
    except ValueError:
        record = _record(f"auth failed {forbidden_key}")
        record.exc_info = sys.exc_info()
        record.foa = {"Authorization": "Bearer abcdef", "node_id": "n1"}
    payload = json.loads(JsonLogFormatter().format(record))
    assert forbidden_key not in payload["message"]
    assert forbidden_key not in payload["exception"]
    assert "authorization" not in payload
    assert payload["node_id"] == "n1"


def test_key_safe_formatter_reports_dropped_keys():
    """Без RedactingFilter форматтер сам вырезает запрещённые поля и перечисляет их."""
    payload = json.loads(KeySafeFormatter().format(_record("m", prompt="секрет", response="r", node_id="n1")))
    assert "prompt" not in payload and "response" not in payload
    assert payload["node_id"] == "n1"
    assert set(payload["dropped_keys"]) == {"prompt", "response"}


@pytest.fixture()
def foa_logger():
    """Изолирует глобальное состояние логгера «foa» и контекст трассировки."""
    root = logging.getLogger("foa")
    rid = foa_logging._request_id.set("")
    ukh = foa_logging._user_key_hash.set("")
    saved_handlers, saved_level, saved_propagate = list(root.handlers), root.level, root.propagate
    root.handlers.clear()
    try:
        yield root
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        root.propagate = saved_propagate
        foa_logging._request_id.reset(rid)
        foa_logging._user_key_hash.reset(ukh)


def test_configure_logging_installs_json_formatter_and_is_idempotent(foa_logger):
    stream = io.StringIO()
    configure_logging("INFO", "json", stream=stream)
    configure_logging("INFO", "json", stream=stream)
    configure_logging("INFO", "json", stream=stream)

    assert len(foa_logger.handlers) == 1
    handler = foa_logger.handlers[0]
    assert isinstance(handler.formatter, KeySafeFormatter)
    assert [type(f).__name__ for f in handler.filters] == ["RedactingFilter"]
    assert foa_logger.propagate is False

    get_logger("unit").info("одна строка")
    assert stream.getvalue().count("\n") == 1, "дубли handler'ов удваивали бы журнал"


def test_configure_logging_text_format(foa_logger):
    stream = io.StringIO()
    configure_logging("warning", "text", stream=stream)
    assert not isinstance(foa_logger.handlers[0].formatter, JsonLogFormatter)
    get_logger("unit").error("plain message")
    assert "plain message" in stream.getvalue()
    assert not stream.getvalue().lstrip().startswith("{")


def test_configure_logging_respects_level(foa_logger):
    stream = io.StringIO()
    configure_logging("WARNING", "json", stream=stream)
    get_logger("unit").info("тихо")
    assert stream.getvalue() == ""
    get_logger("unit").warning("слышно")
    assert json.loads(stream.getvalue())["level"] == "WARNING"


def test_log_event_never_writes_prompt_value(foa_logger):
    """§12.5.2 / §15.3: содержимое промпта не попадает в журнал даже как поле события."""
    stream = io.StringIO()
    configure_logging("INFO", "json", stream=stream)
    secret_prompt = "СЕКРЕТНЫЙ ПРОМПТ НЕ ВЫХОДИТЬ"
    log_event(
        get_logger("unit"),
        "gateway.request",
        request_id="req_1",
        node_id="n_1",
        model="llama3.1",
        status=200,
        latency_ms=7,
        prompt=secret_prompt,
        messages=[{"role": "user", "content": secret_prompt}],
        api_key="foa_supersecret123456",
    )
    line = stream.getvalue()
    assert secret_prompt not in line
    assert "foa_supersecret123456" not in line
    payload = json.loads(line)
    for forbidden in FORBIDDEN_KEYS:
        assert forbidden not in payload
    assert payload["event"] == "gateway.request"
    assert payload["request_id"] == "req_1"
    assert payload["node_id"] == "n_1"
    assert payload["status"] == 200


def test_log_event_masks_secret_inside_allowed_field(foa_logger):
    """Если секрет «зашит» в значение разрешённого поля, он маскируется scrub_text."""
    stream = io.StringIO()
    configure_logging("INFO", "json", stream=stream)
    log_event(get_logger("unit"), "upstream_fail", model="llama3.1", node_id="foa_abcdef123456")
    payload = json.loads(stream.getvalue())
    assert payload["node_id"] == "***"


def test_redacting_filter_scrubs_record_in_place():
    record = _record("m", prompt="x", node_id="n1")
    assert RedactingFilter().filter(record) is True
    assert record.foa == {"node_id": "n1"}


# --------------------------------------------------------------------------- #
# §11.4 — метрики
# --------------------------------------------------------------------------- #

SPEC_METRIC_NAMES = [
    "gateway_requests_total",
    "gateway_request_duration_seconds",
    "gateway_upstream_errors_total",
    "gateway_active_upstream_connections",
    "gateway_rate_limited_total",
    "node_health_status",
    "node_consent_status",
    "node_blacklist_total",
]


@pytest.mark.parametrize("name", SPEC_METRIC_NAMES)
def test_spec_metric_is_registered_and_exposed(name):
    """Импорт модуля регистрирует ключевые метрики §11.4 в глобальном REGISTRY."""
    exposition = generate_latest(metrics.REGISTRY).decode("utf-8")
    assert f"# TYPE {name}" in exposition, f"{name} не экспортируется"


def test_describe_lists_metric_families():
    described = metrics.describe()
    assert described == sorted(set(described))
    # prometheus_client снимает суффикс _total у счётчиков в имени семейства
    for base in ("gateway_requests", "gateway_upstream_errors", "gateway_rate_limited", "node_blacklist_total"):
        assert base in described, base


def test_labeled_counter_delta_is_visible_in_exposition():
    """Счётчик с метками инкрементируется; сверяем дельту, а не абсолютное значение."""
    counter = metrics.REQUESTS_TOTAL.labels(route="/__units__", status="299", error_code="")
    before = counter._value.get()
    counter.inc()
    counter.inc(2)
    assert counter._value.get() - before == pytest.approx(3.0)
    # labels() с теми же значениями возвращает того же самого child
    assert metrics.REQUESTS_TOTAL.labels(route="/__units__", status="299", error_code="") is counter

    exposition = generate_latest(metrics.REGISTRY).decode("utf-8")
    assert 'route="/__units__"' in exposition
    assert "gateway_requests_total{" in exposition


def test_other_labeled_collectors_accept_updates():
    node = "unit-node"
    errors_before = metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=node, kind="timeout")._value.get()
    metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=node, kind="timeout").inc()
    errors_after = metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=node, kind="timeout")._value.get()
    assert errors_after - errors_before == pytest.approx(1.0)

    metrics.NODE_HEALTH_STATUS.labels(node_id=node, state="healthy").set(1)
    metrics.NODE_CONSENT_STATUS.labels(node_id=node, state="verified").set(1)
    metrics.ACTIVE_UPSTREAM_CONNECTIONS.labels(node_id=node).set(4)
    exposition = generate_latest(metrics.REGISTRY).decode("utf-8")
    assert f'node_health_status{{node_id="{node}",state="healthy"}} 1.0' in exposition
    assert f'node_consent_status{{node_id="{node}",state="verified"}} 1.0' in exposition
    assert f'gateway_active_upstream_connections{{node_id="{node}"}} 4.0' in exposition


def test_unlabeled_gauge_can_be_set_and_restored():
    original = metrics.NODE_BLACKLIST_TOTAL._value.get()
    try:
        metrics.NODE_BLACKLIST_TOTAL.set(3)
        assert "node_blacklist_total 3.0" in generate_latest(metrics.REGISTRY).decode("utf-8")
    finally:
        metrics.NODE_BLACKLIST_TOTAL.set(original)
    assert metrics.NODE_BLACKLIST_TOTAL._value.get() == original


def test_histogram_observation_registers_labels():
    histogram = metrics.REQUEST_DURATION.labels(route="/__units__", stream="true")
    before = histogram._sum.get()
    histogram.observe(0.25)
    assert histogram._sum.get() - before == pytest.approx(0.25)
    exposition = generate_latest(metrics.REGISTRY).decode("utf-8")
    assert 'gateway_request_duration_seconds_count{route="/__units__",stream="true"}' in exposition
