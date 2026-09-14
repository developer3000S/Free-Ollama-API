"""Общие pytest-фикстуры шлюза."""

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
