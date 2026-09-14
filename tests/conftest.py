"""Общие pytest-фикстуры шлюза и разметка тестов по требованиям §15.

Маркеры ``security`` (§15.3) и ``ethics`` (§15.4) назначаются централизованно —
по базовому имени теста (``originalname``), поэтому параметризованные случаи
попадают под разметку целиком. ``slow`` (§15.2) проставляется самим модулем
``test_load.py``. Быстрый прогон: ``pytest -m "not slow"``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from foa.app import build_services, create_app, shutdown, startup
from foa.storage.db import get_session_factory
from tests.harness import (
    TEST_ADMIN_TOKEN,
    TEST_AUDITOR_TOKEN,
    TEST_OWNER_REF,
    TEST_OWNER_TOKEN,
    FakeOllama,
    make_settings,
)

# §15.3 — SSRF, аутентификация/авторизация, криптография, маскирование секретов.
SECURITY_TESTS: frozenset[str] = frozenset(
    {
        # обход аутентификации и разграничение прав (§17.4, §17.9)
        "test_user_endpoints_require_authentication",
        "test_invalid_credentials_are_rejected",
        "test_forbidden_owner_operations_return_403",
        "test_embed_scope_alone_grants_both_embedding_endpoints",
        "test_embedding_and_generation_scopes_are_separate",
        "test_owner_cannot_touch_foreign_or_admin_operations",
        "test_owner_cannot_touch_foreign_node",
        "test_status_requires_a_token",
        "test_status_as_owner_is_forbidden_but_admin_can_read",
        "test_wrong_challenge_rejected",
        "test_wrong_gateway_and_expired_document_rejected",
        # автоматический блэклист при 401/403 (§17.2)
        "test_auth_error_blacklists_node_immediately",
        "test_forbidden_from_node_blacklists",
        "test_blacklisted_endpoint_cannot_register",
        "test_circuit_breaker_excludes_node_from_selection",
        # инъекции в заголовки/HTML и разбор чужих значений (§12.6)
        "test_render_page_escapes_untrusted_values",
        "test_dns_record_rejected_for_ip_host",
        "test_serve_consent_server_answers_only_the_well_known_path",
        "test_client_supplied_request_id_is_honored",
        "test_parse_endpoint_rejects_unbracketed_ipv6",
        "test_parse_endpoint_rejects_invalid_urls",
        # небезопасная конфигурация отклоняется на старте (§13.2)
        "test_validate_rejects_unsafe_override",
        "test_unsafe_override_via_environment_is_rejected_by_load_settings",
        "test_security_defaults_are_the_safe_mode",
        "test_all_five_discovery_sources_present_and_disabled",
        "test_compat_platform_keys_do_not_enable_sources",
        # логирование секретов и промптов (§12.5, §17.8)
        "test_log_event_never_writes_prompt_value",
        "test_log_event_masks_secret_inside_allowed_field",
        "test_redacting_filter_scrubs_record_in_place",
        "test_json_log_formatter_scrubs_message_and_exception",
        "test_key_safe_formatter_reports_dropped_keys",
        # хранение ключей: только хэш, pepper, константное сравнение (§12.4.1)
        "test_api_key_create_stores_only_hash",
        "test_constant_time_token_equal",
        "test_challenge_token_is_random_and_urlsafe",
        "test_consent_history_is_auditable",
        "test_audit_write_and_list_ordering",
        # второй контракт /v1/*: те же аутентификация, скоупы и защита от
        # выбора узла; конвертация формата не должна открывать обходных путей
        "test_openai_endpoints_require_authentication",
        "test_openai_scope_enforcement",
        "test_node_selection_still_blocked_on_v1",
        "test_remote_image_urls_are_not_forwarded",
        "test_unknown_openai_fields_are_ignored_not_forwarded",
        # легаси-БД не апгрейдится молча: защита данных от потери (§14.1)
        "test_legacy_create_all_database_blocks_upgrade_until_stamped",
    }
)

# Префиксы юнит-тестов, целиком про SSRF/криптографию/маскирование/скоупы.
SECURITY_PREFIXES: tuple[str, ...] = (
    "test_validate_endpoint_",
    "test_ip_is_blocked",
    "test_metadata_ipv4_is_blocked",
    "test_link_local_ipv6_is_blocked",
    "test_unspecified_is_blocked",
    "test_loopback_allowed_only_with_flag",
    "test_loopback_flag_does_not_allow_private",
    "test_private_ip_allowed_via_allowed_networks",
    "test_allowed_networks_does_not_",
    "test_resolved_address_records_pinning",
    "test_pin_store_",
    "test_scrub",
    "test_hash_api_key_",
    "test_verify_api_key_",
    "test_generated_api_key",
    "test_ed25519_rejects",
    "test_ed25519_signature_",
    "test_load_ed25519_public_key_",
    "test_verify_ed25519_",
    "test_scope_",
    "test_scopes_",
)

# §15.4 — согласие как условие маршрутизации, отсутствие сканов, отзыв, удаление.
ETHICS_TESTS: frozenset[str] = frozenset(
    {
        # запрет маршрутизации на candidate / без активного согласия (§4.4.4, §17.1)
        "test_full_lifecycle_consent_then_traffic",
        "test_consent_limited_models_are_enforced",
        "test_sync_marks_routable_and_counts_states",
        "test_sync_requires_active_consent",
        "test_sync_keeps_non_routable_states_out",
        "test_sync_excludes_blocked_states_even_with_consent",
        "test_pick_without_routable_nodes_raises_no_healthy_nodes",
        "test_pick_without_consent_raises_no_healthy_nodes",
        "test_pick_refuses_model_outside_consent",
        "test_eligible_excludes_full_concurrency_and_unroutable",
        "test_available_models_restricted_by_consent",
        "test_available_models_keeps_nothing_when_consent_excludes_everything",
        "test_eligible_model_filter_does_not_leak_node_presence",
        "test_candidate_upsert_creates_new_row",
        "test_candidate_list_status_pagination_and_set_status",
        # запрет активных сканов без разрешения (§4.4.1, §6.2.4)
        "test_no_active_checks_before_consent",
        "test_functional_check_disabled_by_default",
        "test_functional_check_honors_owner_opt_in",
        "test_discovery_defaults_are_inventory_only_and_passive",
        "test_source_without_scopes_is_allowed_outside_inventory_mode",
        # отзыв согласия ≤5 с и отсутствие трафика после истечения (§5.4, §5.5)
        "test_revocation_stops_traffic_within_five_seconds",
        "test_expiry_invalidates_routing",
        "test_consent_list_expired_and_expiring_windows",
        # удаление данных по запросу владельца (§12.7.7)
        "test_revoke_and_delete_as_owner",
        "test_node_delete",
        "test_candidate_purge_older_than_removes_only_stale",
        "test_candidate_delete",
        "test_consent_revoke_sets_status_reason_and_timestamp",
        "test_consent_revoke_truncates_long_reason",
        # второй контракт наследует согласие: без него /v1/* тоже 503, узел
        # не получает запросов (§17.1)
        "test_openai_respects_consent_gate",
        "test_openai_limited_models_are_enforced",
        # без активного согласия узел не получает запросов и под нагрузкой (§15.2)
        "test_no_routable_nodes_returns_503",
    }
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Назначает маркеры security/ethics по тестам §15.3/§15.4."""
    for item in items:
        base = getattr(item, "originalname", item.name) or item.name
        if base in SECURITY_TESTS or base.startswith(SECURITY_PREFIXES):
            item.add_marker(pytest.mark.security)
        if base in ETHICS_TESTS:
            item.add_marker(pytest.mark.ethics)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}



class Gateway:
    """Тестовая обёртка над приложением: хелперы жизненного цикла узлов и ключей."""

    def __init__(self, app, state) -> None:
        self.app = app
        self.state = state
        self.admin = _bearer(TEST_ADMIN_TOKEN)
        self.auditor = _bearer(TEST_AUDITOR_TOKEN)
        self.owner = _bearer(TEST_OWNER_TOKEN)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway", timeout=30.0
        )
        self.user_headers: dict[str, str] = {}
        self.user_key_id: str = ""
        self.challenges: dict[str, str] = {}
        self.owners: dict[str, str] = {}

    async def aclose(self) -> None:
        await self.client.aclose()

    # -- ключи пользователя (§12.4.1) ------------------------------------- #

    async def make_user_key(self, **kwargs) -> tuple[str, dict]:
        payload = {"label": kwargs.pop("label", "test key"), **kwargs}
        response = await self.client.post("/admin/keys", headers=self.admin, json=payload)
        assert response.status_code == 201, response.text
        data = response.json()
        return data["key_id"], _bearer(data["api_key"])

    async def use_user_key(self, **kwargs) -> dict:
        self.user_key_id, self.user_headers = await self.make_user_key(**kwargs)
        return self.user_headers

    # -- узлы (§5, §9.6) --------------------------------------------------- #

    async def register_node(self, fake: FakeOllama, *, models: list[str] | None = None, endpoint: str | None = None, **kwargs) -> dict:
        body: dict[str, Any] = {
            "endpoint": endpoint or fake.base_url,
            "display_name": kwargs.pop("display_name", fake.name),
            "models": models if models is not None else fake.models,
            "max_concurrency": kwargs.pop("max_concurrency", 4),
            "consent_method": kwargs.pop("consent_method", "http_well_known"),
            **kwargs,
        }
        response = await self.client.post("/admin/nodes", headers=self.admin, json=body)
        assert response.status_code == 201, response.text
        data = response.json()
        self.challenges[data["node_id"]] = data["challenge"]
        detail = await self.node_detail(data["node_id"])
        self.owners[data["node_id"]] = detail["owner_id"]
        return data

    def consent_doc(self, node_id: str, fake: FakeOllama, *, ttl_days: int = 7, **overrides) -> dict:
        document = {
            "node_id": node_id,
            "challenge": self.challenges[node_id],
            "gateway_id": self.state.settings.gateway_id,
            "owner_id": self.owners[node_id],
            "expires_at": (datetime.now(UTC) + timedelta(days=ttl_days)).isoformat().replace("+00:00", "Z"),
            "capabilities": {"models": fake.models, "max_concurrency": 4},
        }
        document.update(overrides)
        return document

    async def approve_node(self, node_id: str, fake: FakeOllama, *, document: dict | None = None, verify_body: dict | None = None) -> dict:
        """Владелец размещает consent.json и подтверждает владение (§5.3.1)."""
        fake.set_consent(document if document is not None else self.consent_doc(node_id, fake))
        response = await self.client.post(
            f"/admin/nodes/{node_id}/verify", headers=self.admin, json=verify_body or {}
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def register_node_as_owner(self, fake: FakeOllama, **kwargs) -> dict:
        """Регистрация узла самим владельцем (owner-токен, §9.6.2)."""
        kwargs.setdefault("owner_id", TEST_OWNER_REF)
        response = await self.client.post(
            "/admin/nodes",
            headers=self.owner,
            json={"endpoint": kwargs.pop("endpoint", fake.base_url), "models": kwargs.pop("models", fake.models), **kwargs},
        )
        assert response.status_code == 201, response.text
        data = response.json()
        self.challenges[data["node_id"]] = data["challenge"]
        self.owners[data["node_id"]] = TEST_OWNER_REF
        return data

    async def revoke_as_owner(self, node_id: str, **body) -> dict:
        response = await self.client.post(f"/admin/nodes/{node_id}/revoke", headers=self.owner, json=body)
        assert response.status_code == 200, response.text
        return response.json()

    async def node_detail(self, node_id: str) -> dict:
        response = await self.client.get(f"/admin/nodes/{node_id}", headers=self.admin)
        assert response.status_code == 200, response.text
        return response.json()

    async def health_check(self, node_id: str) -> dict:
        """Принудительная проверка + синхронизация пула (эквивалент одного цикла health-checker'а)."""
        async with get_session_factory()() as session:
            row = await self.state.nodes.get_node(session, node_id)
            runtime = self.state.pool.get(node_id)
            await self.state.health.force_check(session, row, runtime)
            await self.state.nodes.sync_pool(session)
            await session.commit()
        return (await self.node_detail(node_id))["status"]

    async def onboard(self, fake: FakeOllama, *, models: list[str] | None = None, **register_kwargs) -> str:
        """Полный путь узла до состояния «маршрутизируется»: регистрация → согласие → health."""
        registered = await self.register_node(fake, models=models, **register_kwargs)
        node_id = registered["node_id"]
        await self.approve_node(node_id, fake)
        status = await self.health_check(node_id)
        assert status in {"verified", "healthy"}, status
        return node_id

    async def revoke(self, node_id: str, **body) -> dict:
        response = await self.client.post(f"/admin/nodes/{node_id}/revoke", headers=self.admin, json=body)
        assert response.status_code == 200, response.text
        return response.json()

    # -- метрики/журналы --------------------------------------------------- #

    async def metrics(self) -> str:
        response = await self.client.get("/metrics")
        assert response.status_code == 200
        return response.text

    async def audit(self, **params) -> list[dict]:
        response = await self.client.get("/admin/audit", headers=self.admin, params=params)
        assert response.status_code == 200, response.text
        return response.json()["entries"]


def _make_settings(tmp_path, overrides: dict[str, Any] | None = None):
    overrides = dict(overrides or {})
    env = {k: v for k, v in overrides.items() if k.startswith("FOA_") or k.startswith("GATEWAY_")}
    cfg = {k: v for k, v in overrides.items() if k not in env}
    settings = make_settings(tmp_path, **env)
    if cfg:
        raw = settings.as_dict()
        for dotted, value in cfg.items():
            node = raw
            parts = dotted.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = value
        settings.apply_overlay(raw)
    return settings


@pytest.fixture()
async def gateway(request, tmp_path):
    """Приложение шлюза с изолированной БД; параметризуется dict'ом оверрайдов."""
    overrides = getattr(request, "param", None) or {}
    settings = _make_settings(tmp_path, overrides)
    app = create_app(settings)
    state = build_services(settings)
    await startup(app, settings, state)
    gw = Gateway(app, state)
    try:
        yield gw
    finally:
        await gw.aclose()
        await shutdown(app)


def _start(name: str, models: list[str]) -> FakeOllama:
    return FakeOllama(name=name, models=models).start()


@pytest.fixture()
def fake_node_primary() -> FakeOllama:
    node = _start("primary", ["llama3.1", "qwen2.5"])
    yield node
    node.stop()


@pytest.fixture()
def fake_node_secondary() -> FakeOllama:
    node = _start("secondary", ["llama3.1", "mistral"])
    yield node
    node.stop()


@pytest.fixture()
def fake_node_broken() -> FakeOllama:
    node = _start("broken", ["llama3.1"])
    node.mode = "error500"
    yield node
    node.stop()


@pytest.fixture()
def fake_node_noauth() -> FakeOllama:
    node = _start("noauth", ["llama3.1"])
    node.mode = "unauthorized"
    yield node
    node.stop()


@pytest.fixture()
def fake_node_forbidden() -> FakeOllama:
    node = _start("forbidden", ["llama3.1"])
    node.mode = "forbidden"
    yield node
    node.stop()


@pytest.fixture()
def fake_node_down() -> FakeOllama:
    """Узел, который сразу закрывает соединение (имитация недоступного сервиса)."""
    node = _start("down", ["llama3.1"])
    node.stop()
    return node


__all__ = ["Gateway", "json", "timezone"]
