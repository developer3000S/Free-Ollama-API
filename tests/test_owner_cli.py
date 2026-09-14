"""Тесты владельческого CLI ``foa-owner`` (§5.3, §9.6.2, этап 2 ТЗ).

Юнит-часть работает без сети; сценарии согласия прогоняются через **живой**
uvicorn-сервер шлюза: CLI ходит по настоящему HTTP, а ``publish --serve``
поднимает свой consent-сервер, который шлюз опрашивает как адрес узла.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from foa.app import create_app
from foa.cli.owner import (
    ConsentDoc,
    _ConsentHolder,
    _dns_value,
    _start_consent_server,
    build_parser,
    main,
)
from foa.domain.errors import InvalidRequestError
from foa.services.consent import CONSENT_PATH, DNS_PREFIX, verify_consent_token
from tests.harness import TEST_ADMIN_TOKEN, TEST_OWNER_REF, TEST_OWNER_TOKEN, make_settings

ADMIN_ARGS = ["--admin-token", TEST_ADMIN_TOKEN]
OWNER_ARGS = ["--owner-token", TEST_OWNER_TOKEN]


@pytest.fixture()
def key_paths(tmp_path) -> tuple[Path, Path]:
    return tmp_path / "owner.key", tmp_path / "owner.pub"


# --------------------------------------------------------------------------- #
# Ключи (§5.3.3)
# --------------------------------------------------------------------------- #


def test_keygen_writes_private_key_with_restricted_mode(key_paths, capsys):
    private_path, public_path = key_paths
    assert main(["keygen", "--key", str(private_path), "--public-key", str(public_path)]) == 0
    assert "BEGIN PUBLIC KEY" in public_path.read_text()
    assert oct(private_path.stat().st_mode & 0o777) == "0o600"
    # Приватный ключ не должен «протекать» в stdout (§12.2).
    printed = capsys.readouterr().out
    assert "PRIVATE KEY" not in printed
    assert str(private_path) in printed


def test_keygen_refuses_overwrite_without_force(key_paths, capsys):
    private_path, public_path = key_paths
    main(["keygen", "--key", str(private_path), "--public-key", str(public_path)])
    capsys.readouterr()
    assert main(["keygen", "--key", str(private_path), "--public-key", str(public_path)]) == 2
    assert "уже существует" in capsys.readouterr().err
    assert main(["keygen", "--key", str(private_path), "--public-key", str(public_path), "--force"]) == 0


def test_public_key_derivation_matches_keygen(key_paths, capsys):
    private_path, public_path = key_paths
    main(["keygen", "--key", str(private_path), "--public-key", str(public_path)])
    capsys.readouterr()
    assert main(["public-key", "--key", str(private_path)]) == 0
    assert capsys.readouterr().out.strip() == public_path.read_text().strip()


def test_missing_key_file_reports_usage_error(tmp_path, capsys):
    assert main(["public-key", "--key", str(tmp_path / "absent.key")]) == 2
    assert "не удалось прочитать ключ" in capsys.readouterr().err


def test_token_signs_jwt_the_gateway_accepts(key_paths, capsys):
    """§5.3.3 — токен проходит ту же проверку, что выполняет шлюз."""
    private_path, public_path = key_paths
    main(["keygen", "--key", str(private_path), "--public-key", str(public_path)])
    capsys.readouterr()
    code = main(["token", "--key", str(private_path), "--node-id", "node_test", "--owner-id", "owner_test",
                 "--gateway-id", "gateway_main", "--models", "llama3.1"])
    assert code == 0
    token = capsys.readouterr().out.strip()
    claims = verify_consent_token(token, public_key=public_path.read_text(), gateway_id="gateway_main", node_id_="node_test")
    assert claims["node_id"] == "node_test" and claims["owner_id"] == "owner_test"
    assert claims["capabilities"]["models"] == ["llama3.1"]
    # По умолчанию обучение на данных запрещено (§5.2 п.3) — это policy-клаим токена.
    assert claims["policy"]["no_training"] is True
    with pytest.raises(InvalidRequestError, match="gateway_id"):
        verify_consent_token(token, public_key=public_path.read_text(), gateway_id="other", node_id_="node_test")


# --------------------------------------------------------------------------- #
# Материалы согласия (§5.3.1, §5.3.2)
# --------------------------------------------------------------------------- #


DOC_ARGS = ["--node-id", "node_abc", "--challenge", "chal", "--endpoint", "https://ollama.example:11434",
            "--owner-id", "owner_abc", "--gateway-id", "gateway_main", "--models", "llama3.1,qwen2.5"]


def test_consent_file_contains_spec_fields(capsys):
    assert main(["consent-file", *DOC_ARGS]) == 0
    document = json.loads(capsys.readouterr().out)
    assert set(document) == {"node_id", "challenge", "gateway_id", "owner_id", "expires_at", "capabilities"}
    assert document["capabilities"]["models"] == ["llama3.1", "qwen2.5"]
    assert document["expires_at"].endswith("Z")


def test_dns_record_matches_format_the_gateway_parses(capsys):
    """§5.3.2 — значение разбирается шлюзом: gateway=…;node=…;challenge=…;exp=…"""
    assert main(["dns-record", *DOC_ARGS]) == 0
    line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("значение:"))
    parts = dict(pair.split("=", 1) for pair in line.split(":", 1)[1].strip().split(";"))
    assert parts["gateway"] == "gateway_main" and parts["node"] == "node_abc" and parts["challenge"] == "chal"


def test_dns_record_rejected_for_ip_host(capsys):
    args = ["--node-id", "n", "--challenge", "c", "--endpoint", "http://127.0.0.1:11434", "--owner-id", "o", "--gateway-id", "g"]
    assert main(["dns-record", *args]) == 2
    assert "IP-адресом" in capsys.readouterr().err


def test_render_page_escapes_untrusted_values(capsys):
    args = ["--node-id", "node_abc", "--challenge", 'x"><script>alert(1)</script>',
            "--endpoint", "https://ollama.example:11434", "--owner-id", "o", "--gateway-id", "g"]
    assert main(["render-page", *args]) == 0
    page = capsys.readouterr().out
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_consent_document_helpers_agree_with_gateway_format():
    document = ConsentDoc(
        node_id="node_1", challenge="chal", gateway_id="gw", owner_id="own",
        expires_at="2026-09-21T10:00:00Z", capabilities={"models": ["llama3.1"]},
    )
    assert document.dns_txt() == "gateway=gw;node=node_1;challenge=chal;exp=2026-09-21T10:00:00Z"
    assert _dns_value(json.loads(document.as_json())) == document.dns_txt()


# --------------------------------------------------------------------------- #
# Локальный consent-сервер (§5.3.1)
# --------------------------------------------------------------------------- #


def test_serve_consent_server_answers_only_the_well_known_path():
    holder = _ConsentHolder()
    server, base = _start_consent_server(holder, "127.0.0.1", 0)
    try:
        with httpx.Client(base_url=base, timeout=5.0, trust_env=False) as client:
            assert client.get(CONSENT_PATH).status_code == 404  # документ ещё не опубликован
            holder.set(json.dumps({"node_id": "node_1"}))
            assert client.get(CONSENT_PATH).json() == {"node_id": "node_1"}
            assert client.get("/api/version").status_code == 404
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# Живой шлюз: регистрация, согласие, отзыв (§9.6.2, §5.5)
# --------------------------------------------------------------------------- #


def _reserve_port() -> int:
    """Свободный порт занимаем и сразу освобождаем: uvicorn не отдаёт имя сокета наружу."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


@pytest.fixture()
def live_gateway(tmp_path):
    """Настоящий uvicorn-сервер шлюза: CLI работает по HTTP, как реальный владелец."""
    settings = make_settings(tmp_path)
    port = _reserve_port()
    config = uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_config=None, access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if server.started:
            with socket.socket() as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
        time.sleep(0.05)
    else:
        pytest.fail("шлюз не поднялся")
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=20)
    assert not thread.is_alive(), "шлюз не остановился корректно"


def _gateway_args(gateway: str, *extra: str) -> list[str]:
    return ["--gateway", gateway, *OWNER_ARGS, *extra]


def test_status_requires_a_token(live_gateway, capsys, monkeypatch):
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    monkeypatch.delenv("FOA_ADMIN_TOKEN", raising=False)
    assert main(["status", "--gateway", live_gateway]) == 2
    assert "токен" in capsys.readouterr().err


def test_status_as_owner_is_forbidden_but_admin_can_read(live_gateway, capsys, monkeypatch):
    """§9.6 — общий статус шлюза требует admin:read, которого у владельца нет."""
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    monkeypatch.delenv("FOA_ADMIN_TOKEN", raising=False)
    assert main(["status", *_gateway_args(live_gateway)]) == 2
    assert "403" in capsys.readouterr().err
    capsys.readouterr()
    code = main(["status", "--gateway", live_gateway, *ADMIN_ARGS])
    assert code == 0, capsys.readouterr().err
    payload = json.loads(capsys.readouterr().out)
    assert payload["gateway_id"] == "gateway_main"
    assert payload["security"]["require_consent"] is True and payload["security"]["route_candidates"] is False


def test_register_reports_challenge_and_next_steps(live_gateway, fake_node_primary, capsys, monkeypatch):
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    code = main(["register", *_gateway_args(live_gateway), "--endpoint", fake_node_primary.base_url, "--models", "llama3.1"])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    payload = json.loads(captured.out)
    assert payload["status"] in {"pending_consent", "consent_challenge_sent"}
    assert payload["challenge"]
    assert CONSENT_PATH in payload["consent_url"] and "serve-consent" in captured.err


def test_publish_serve_completes_consent_over_http(live_gateway, capsys, monkeypatch):
    """§5.3.1 — владелец без своего веб-сервера: CLI сам отдаёт consent.json, шлюз читает его."""
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    code = main(["publish", *_gateway_args(live_gateway), "--endpoint", "http://127.0.0.1:9", "--serve"])
    assert code == 0, capsys.readouterr().err
    payload = json.loads(capsys.readouterr().out)
    assert payload["verify"]["consent_status"] == "verified"
    assert payload["register"]["node_id"]
    assert payload["serve"].endswith(CONSENT_PATH)


def test_publish_without_serve_waits_for_owner_to_host_file(live_gateway, tmp_path, fake_node_primary, capsys, monkeypatch):
    """Классический путь: CLI отдаёт файл, но пока узел его не раздаёт — consent не проходит."""
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    output = tmp_path / "consent.json"
    code = main(["publish", *_gateway_args(live_gateway), "--endpoint", fake_node_primary.base_url, "--output", str(output)])
    err = capsys.readouterr().err
    assert code == 2, err
    published = json.loads(output.read_text())
    assert published["gateway_id"] == "gateway_main"
    assert "файл согласия" in err

    # Владелец разместил файл на узле (§5.3.1) — подтверждение проходит postфактум.
    fake_node_primary.set_consent(published)
    capsys.readouterr()
    assert main(["verify", *_gateway_args(live_gateway), "--node-id", published["node_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["consent_status"] == "verified"


def test_revoke_and_delete_as_owner(live_gateway, capsys, monkeypatch):
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    main(["publish", *_gateway_args(live_gateway), "--endpoint", "http://127.0.0.1:9", "--serve"])
    node_id = json.loads(capsys.readouterr().out)["register"]["node_id"]
    capsys.readouterr()
    assert main(["revoke", *_gateway_args(live_gateway), "--node-id", node_id, "--reason", "тест"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "revoked"
    capsys.readouterr()
    assert main(["delete", *_gateway_args(live_gateway), "--node-id", node_id]) == 2
    assert "--yes" in capsys.readouterr().err
    capsys.readouterr()
    assert main(["delete", *_gateway_args(live_gateway), "--node-id", node_id, "--yes"]) == 0


def test_signed_token_flow_end_to_end(live_gateway, key_paths, fake_node_primary, capsys, monkeypatch):
    """§5.3.3 — админ регистрирует публичный ключ, владелец подписывает токен и подтверждает узел."""
    private_path, public_path = key_paths
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    main(["keygen", "--key", str(private_path), "--public-key", str(public_path)])
    capsys.readouterr()
    with httpx.Client(base_url=live_gateway, timeout=10.0, trust_env=False) as client:
        response = client.put(
            f"/admin/owners/{TEST_OWNER_REF}/public-key",
            json={"public_key": public_path.read_text(), "key_type": "ed25519"},
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
        )
        assert response.status_code == 200, response.text
    code = main(["register", *_gateway_args(live_gateway), "--endpoint", fake_node_primary.base_url,
                 "--models", "llama3.1", "--method", "signed_token"])
    assert code == 0, capsys.readouterr().err
    node_id = json.loads(capsys.readouterr().out)["node_id"]
    capsys.readouterr()
    assert main(["token", "--key", str(private_path), "--node-id", node_id, "--owner-id", TEST_OWNER_REF,
                 "--gateway-id", "gateway_main", "--models", "llama3.1"]) == 0
    token = capsys.readouterr().out.strip()
    assert token.count(".") == 2
    capsys.readouterr()
    assert main(["verify", *_gateway_args(live_gateway), "--node-id", node_id, "--method", "signed_token",
                 "--signed-token", token]) == 0
    assert json.loads(capsys.readouterr().out)["consent_status"] == "verified"


def test_owner_cannot_touch_foreign_node(live_gateway, fake_node_secondary, capsys, monkeypatch):
    monkeypatch.delenv("FOA_OWNER_TOKEN", raising=False)
    main(["publish", *_gateway_args(live_gateway), "--endpoint", "http://127.0.0.1:9", "--serve"])
    capsys.readouterr()
    with httpx.Client(base_url=live_gateway, timeout=10.0, trust_env=False) as client:
        other = client.post(
            "/admin/nodes",
            json={"endpoint": fake_node_secondary.base_url, "models": ["llama3.1"], "owner_id": "owner_someone_else"},
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"},
        )
        assert other.status_code == 201, other.text
        other_id = other.json()["node_id"]
    assert main(["revoke", *_gateway_args(live_gateway), "--node-id", other_id]) == 2
    assert "другому владельцу" in capsys.readouterr().err


def test_constants_match_spec_paths():
    assert CONSENT_PATH == "/.well-known/free-ollama/v1/consent.json"
    assert DNS_PREFIX == "_free-ollama-challenge."


def test_parser_exposes_every_documented_command():
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices  
    assert {"keygen", "public-key", "register", "consent-file", "serve-consent", "dns-record", "token",
            "publish", "verify", "status", "revoke", "delete", "render-page"} <= set(commands)
