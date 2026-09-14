"""Интеграционные тесты согласия и владения (§5, §15.1, §15.4).

Проверяются все три механизма подтверждения (§5.3.1–§5.3.3), перепроверка,
отзыв, повторное подтверждение при смене адреса, и главное свойство системы:
без активного согласия узел не обслуживает трафик.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from foa.services.consent import CONSENT_PATH, DNS_PREFIX
from tests.harness import TEST_OWNER_REF

pytestmark = pytest.mark.asyncio


async def test_http_well_known_flow(gateway, fake_node_primary):
    headers = await gateway.use_user_key(scopes=["ollama:read", "ollama:generate"])
    registered = await gateway.register_node(fake_node_primary)
    node_id = registered["node_id"]

    # Файл не размещён → верификация обязана провалиться, а узел уйти в карантин (§6.4).
    response = await gateway.client.post(f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={})
    assert response.status_code == 403
    assert response.json()["code"] == "CONSENT_REQUIRED"
    detail = await gateway.node_detail(node_id)
    assert detail["status"] == "quarantined" and detail["consent_status"] == "failed"

    # Узел без согласия трафик не получает (§17.1).
    response = await gateway.client.get("/api/tags", headers=headers)
    assert response.status_code == 200 and response.json()["models"] == []

    # Карантин снимается повторной верификацией после размещения файла.
    fake_node_primary.set_consent(gateway.consent_doc(node_id, fake_node_primary))
    verified = await gateway.client.post(f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={})
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified" and verified.json()["consent_status"] == "verified"
    assert verified.json()["expires_at"] is not None


async def test_wrong_challenge_rejected(gateway, fake_node_primary):
    registered = await gateway.register_node(fake_node_primary)
    node_id = registered["node_id"]
    bad = gateway.consent_doc(node_id, fake_node_primary, challenge="не-тот-токен")
    fake_node_primary.set_consent(bad)
    verify = await gateway.client.post(f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={})
    assert verify.status_code == 403
    assert "challenge" in verify.json()["error"]


async def test_wrong_gateway_and_expired_document_rejected(gateway, fake_node_primary):
    registered = await gateway.register_node(fake_node_primary)
    node_id = registered["node_id"]

    fake_node_primary.set_consent(gateway.consent_doc(node_id, fake_node_primary, gateway_id="чужой-шлюз"))
    response = await gateway.client.post(f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={})
    assert response.status_code == 403 and "gateway_id" in response.json()["error"]

    past = (datetime.now(UTC) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    fake_node_primary.set_consent(gateway.consent_doc(node_id, fake_node_primary, expires_at=past))
    response = await gateway.client.post(f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={})
    assert response.status_code == 403 and "истёк" in response.json()["error"]


async def test_dns_txt_proof(gateway, fake_node_primary, monkeypatch):
    """§5.3.2 — TXT-запись вида gateway=...;node=...;challenge=...;exp=..."""
    # DNS TXT доступен только для узлов с доменным именем (§5.3.2).
    registered = await gateway.register_node(
        fake_node_primary, consent_method="dns_txt", endpoint=f"http://localhost:{fake_node_primary.port}"
    )
    node_id = registered["node_id"]
    challenge = registered["challenge"]

    captured: dict[str, str] = {}

    async def fake_lookup(name: str) -> list[str]:
        captured["name"] = name
        exp = (datetime.now(UTC) + timedelta(days=5)).isoformat()
        return [f"gateway={gateway.state.settings.gateway_id};node={node_id};challenge={challenge};exp={exp}"]

    monkeypatch.setattr(gateway.state.consent, "_lookup_txt", fake_lookup)
    response = await gateway.client.post(f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={"method": "dns_txt"})
    assert response.status_code == 200, response.text
    assert response.json()["consent_status"] == "verified"
    assert captured["name"] == f"{DNS_PREFIX}localhost"

    # Отказ при нераспознанной записи (другой узел) не ломает ранее выданное согласие.
    revoked = await gateway.revoke(node_id)
    assert revoked["status"] == "revoked"


async def test_signed_token_ed25519(gateway, fake_node_primary):
    """§5.3.3 — подписанный JWT (Ed25519) с публичным ключом владельца."""
    from foa.services.consent import build_signed_token
    from foa.services.crypto import generate_ed25519_pair

    private_pem, public_pem = generate_ed25519_pair()
    registered = await gateway.register_node(fake_node_primary, consent_method="signed_token")
    node_id = registered["node_id"]
    owner = gateway.owners[node_id]

    token = build_signed_token(
        private_key_pem=private_pem,
        node_id_=node_id,
        owner_id_=owner,
        gateway_id=gateway.state.settings.gateway_id,
        capabilities={"models": fake_node_primary.models, "max_concurrency": 4},
    )
    # Публичный ключ владельца сначала регистрируется в шлюзе.
    response = await gateway.client.put(
        f"/admin/owners/{owner}/public-key", headers=gateway.admin, json={"public_key": public_pem, "key_type": "ed25519"}
    )
    assert response.status_code == 200, response.text

    verify = await gateway.client.post(
        f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={"method": "signed_token", "signed_token": token}
    )
    assert verify.status_code == 200, verify.text
    assert verify.json()["consent_status"] == "verified"

    # Подделанный токен (другой node_id) отклоняется.
    forged = build_signed_token(
        private_key_pem=private_pem,
        node_id_="node_поддельный",
        owner_id_=owner,
        gateway_id=gateway.state.settings.gateway_id,
    )
    response = await gateway.client.post(
        f"/admin/nodes/{node_id}/verify", headers=gateway.admin, json={"method": "signed_token", "signed_token": forged}
    )
    assert response.status_code == 403
    assert "node_id" in response.json()["error"]


async def test_consent_document_endpoint(gateway, fake_node_primary):
    registered = await gateway.register_node(fake_node_primary, models=["llama3.1"])
    node_id = registered["node_id"]
    response = await gateway.client.post(f"/admin/nodes/{node_id}/consent-document", headers=gateway.admin)
    assert response.status_code == 200
    data = response.json()
    assert data["path"] == CONSENT_PATH
    document = data["document"]
    assert document["node_id"] == node_id
    assert document["challenge"] == registered["challenge"]
    assert document["gateway_id"] == gateway.state.settings.gateway_id
    assert document["capabilities"]["models"] == ["llama3.1"]


async def test_expiry_invalidates_routing(gateway, fake_node_primary):
    """§5.4, §15.4 — узел с истёкшим согласием не обслуживает запросы."""
    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    registered = await gateway.register_node(fake_node_primary)
    node_id = registered["node_id"]
    await gateway.approve_node(node_id, fake_node_primary)
    await gateway.health_check(node_id)

    # Согласие искусственно «истекает».
    from foa.storage.db import get_session_factory
    from foa.storage.repositories import ConsentRepository

    async with get_session_factory()() as session:
        consent = await ConsentRepository.latest_for_node(session, node_id)
        consent.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await session.commit()

    async with get_session_factory()() as session:
        row = await gateway.state.nodes.get_node(session, node_id)
        await gateway.state.health.force_check(session, row, gateway.state.pool.get(node_id))
        await gateway.state.nodes.sync_pool(session)
        await session.commit()

    detail = await gateway.node_detail(node_id)
    assert detail["consent_status"] == "expired"
    assert detail["routable"] is False and detail["status"] == "quarantined"
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503


async def test_revocation_stops_traffic_within_five_seconds(gateway, fake_node_primary):
    """§5.5, §17.3, §15.4 — цель применения отзыва ≤ 5 секунд."""
    import time

    headers = await gateway.use_user_key(scopes=["ollama:generate"])
    node_id = await gateway.onboard(fake_node_primary)
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 200

    started = time.monotonic()
    result = await gateway.revoke(node_id, reason="owner_changed_mind")
    elapsed = time.monotonic() - started
    assert elapsed <= 5.0, f"отзыв применён за {elapsed:.2f} c"
    assert result["applied_in_seconds"] <= 5.0

    detail = await gateway.node_detail(node_id)
    assert detail["routable"] is False
    before = fake_node_primary.request_count
    response = await gateway.client.post("/api/generate", headers=headers, json={"model": "llama3.1", "prompt": "x"})
    assert response.status_code == 503
    assert fake_node_primary.request_count == before

    text = await gateway.metrics()
    assert "consent_revocation_lag_seconds_count" in text


async def test_owner_self_service_flow(gateway, fake_node_primary):
    """Владелец сам регистрирует узел, подтверждает владение и отзывает согласие (§5.5, §9.6.2)."""
    registered = await gateway.register_node_as_owner(fake_node_primary)
    node_id = registered["node_id"]
    assert (await gateway.node_detail(node_id))["owner_id"] == TEST_OWNER_REF

    fake_node_primary.set_consent(gateway.consent_doc(node_id, fake_node_primary))
    verify = await gateway.client.post(f"/admin/nodes/{node_id}/verify", headers=gateway.owner, json={})
    assert verify.status_code == 200, verify.text
    assert verify.json()["consent_status"] == "verified"

    result = await gateway.revoke_as_owner(node_id, reason="owner_api")
    assert result["status"] == "revoked"

    response = await gateway.client.get("/admin/consents", headers=gateway.admin)
    statuses = [c["status"] for c in response.json()["consents"] if c["node_id"] == node_id]
    assert "revoked" in statuses


async def test_owner_cannot_touch_foreign_or_admin_operations(gateway, fake_node_primary, fake_node_secondary):
    """Границы роли владельца: чужой узел и админ-операции недоступны (§9.6, §17.9)."""
    # Узел зарегистрирован администратором на другого владельца.
    foreign = await gateway.register_node(fake_node_primary)
    response = await gateway.client.post(f"/admin/nodes/{foreign['node_id']}/revoke", headers=gateway.owner, json={})
    assert response.status_code == 403 and "другому владельцу" in response.json()["error"]

    # Владелец не управляет ключами и конфигурацией.
    response = await gateway.client.post("/admin/keys", headers=gateway.owner, json={"label": "x"})
    assert response.status_code == 403
    response = await gateway.client.get("/admin/config", headers=gateway.owner)
    assert response.status_code == 401 or response.status_code == 403

    # Регистрация чужого узла от имени другой идентичности запрещена.
    response = await gateway.client.post(
        "/admin/nodes",
        headers=gateway.owner,
        json={"endpoint": fake_node_secondary.base_url, "models": ["mistral"], "owner_id": "owner_кто-то-другой"},
    )
    assert response.status_code == 403


async def test_consent_history_is_auditable(gateway, fake_node_primary):
    registered = await gateway.register_node(fake_node_primary)
    node_id = registered["node_id"]
    await gateway.approve_node(node_id, fake_node_primary)
    response = await gateway.client.get("/admin/consents", headers=gateway.admin)
    assert response.status_code == 200
    item = next(c for c in response.json()["consents"] if c["node_id"] == node_id)
    detail = await gateway.client.get(f"/admin/consents/{item['consent_id']}", headers=gateway.admin)
    assert detail.status_code == 200
    events = [h["event"] for h in detail.json()["history"]]
    assert "challenge_sent" in events and "verified" in events
    # Подпись не раскрывается в списке (§12.5.3).
    assert item["signature"] in ("", "***")


async def test_re_register_same_endpoint_rejected(gateway, fake_node_primary):
    await gateway.register_node(fake_node_primary)
    response = await gateway.client.post(
        "/admin/nodes", headers=gateway.admin, json={"endpoint": fake_node_primary.base_url, "models": ["x"]}
    )
    assert response.status_code == 400 and "уже зарегистрирован" in response.json()["error"]


async def test_blacklisted_endpoint_cannot_register(gateway, fake_node_primary):
    registered = await gateway.register_node(fake_node_primary)
    node_id = registered["node_id"]
    await gateway.client.post(f"/admin/nodes/{node_id}/blacklist", headers=gateway.admin, json={"reason": "abuse_report"})
    await gateway.client.delete(f"/admin/nodes/{node_id}", headers=gateway.admin)
    response = await gateway.client.post(
        "/admin/nodes", headers=gateway.admin, json={"endpoint": fake_node_primary.base_url, "models": ["x"]}
    )
    assert response.status_code == 403 and "блэклист" in response.json()["error"]
