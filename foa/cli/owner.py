"""Владелецский CLI ``foa-owner`` — ключи Ed25519 и материалы согласия (§5.3, §9.6.2).

Шлюз не может принять узел в маршрутизацию, пока владелец сам не подтвердит
владение (§5.2 п.4). Этот инструмент закрывает владельческую сторону процесса:

.. code-block:: text

    foa-owner keygen            # создать пару ключей (signed_token, §5.3.3)
    foa-owner register          # зарегистрировать узел в шлюзе
    foa-owner consent-file      # сформировать consent.json для размещения на узле
    foa-owner serve-consent     # поднять HTTP-сервер с /.well-known/…/consent.json
    foa-owner dns-record        # сформировать значение TXT-записи (§5.3.2)
    foa-owner token             # подписать JWT-токен согласия (§5.3.3)
    foa-owner verify            |
    foa-owner status            |  запросы к админ-контру (Bearer owner-токен)
    foa-owner revoke            |
    foa-owner delete            |

Приватный ключ на диск не пишется и в stdout не попадает: выводятся только
публичный ключ и отпечаток (§12.2). Файлы ключей создаются с правами 0600.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from foa.services.consent import CONSENT_PATH, DNS_PREFIX
from foa.services.crypto import key_fingerprint

DEFAULT_KEY_PATH = Path.home() / ".config" / "foa-owner" / "owner_ed25519.key"
PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----"


class OwnerCLIError(RuntimeError):
    """Ошибка владельца с человекочитаемым текстом: печать в stderr, код 2."""


# --------------------------------------------------------------------------- #
# Ключи
# --------------------------------------------------------------------------- #


def _write_private(path: Path, material: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(material, encoding="ascii")
    os.chmod(path, 0o600)


def _read_private(path: Path) -> str:
    try:
        material = path.read_text(encoding="ascii")
    except OSError as exc:
        raise OwnerCLIError(f"не удалось прочитать ключ {path}: {exc}") from exc
    if PRIVATE_KEY_HEADER not in material:
        raise OwnerCLIError(f"в {path} нет PEM-приватного ключа (ожидался PKCS#8; создайте его: foa-owner keygen)")
    if path.stat().st_mode & 0o077:
        print(f"foa-owner: предупреждение: права на {path} = {oct(path.stat().st_mode & 0o777)}, рекомендуется chmod 600", file=sys.stderr)
    return material


def cmd_keygen(args: argparse.Namespace) -> int:
    from foa.services.crypto import generate_ed25519_pair

    path = Path(args.key)
    if path.exists() and not args.force:
        raise OwnerCLIError(f"{path} уже существует; передайте --force, чтобы перезаписать")
    private_pem, public_pem = generate_ed25519_pair()
    if args.stdout:
        print(json.dumps({"private_key_pem": private_pem, "public_key_pem": public_pem}, ensure_ascii=False, indent=2))
        print("ПРИМЕЧАНИЕ: приватный ключ выведен в stdout — сохраните его в секретное хранилище.", file=sys.stderr)
        return 0
    _write_private(path, private_pem)
    public_path = Path(args.public_key)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_text(public_pem, encoding="ascii")
    print(f"приватный ключ: {path} (права 0600, не публикуйте его)")
    print(f"публичный ключ: {public_path}")
    print(f"отпечаток: {key_fingerprint(public_pem)}")
    print("передайте публичный ключ администратору шлюза: PUT /admin/owners/{owner_id}/public-key (§5.3.3)")
    return 0


def cmd_public(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key

    private = load_pem_private_key(_read_private(Path(args.key)).encode("ascii"), password=None)
    public_pem = private.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    print(public_pem, end="" if args.raw else "\n")
    if not args.raw:
        print(f"# отпечаток: {key_fingerprint(public_pem)}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# Материалы согласия
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ConsentDoc:
    """Содержимое ``consent.json`` (§5.3.1) — то же, что сверяет шлюз."""

    node_id: str
    challenge: str
    gateway_id: str
    owner_id: str
    expires_at: str
    capabilities: dict[str, Any]

    def as_json(self) -> str:
        return json.dumps(
            {
                "node_id": self.node_id,
                "challenge": self.challenge,
                "gateway_id": self.gateway_id,
                "owner_id": self.owner_id,
                "expires_at": self.expires_at,
                "capabilities": self.capabilities,
            },
            ensure_ascii=False,
            indent=2,
        )

    def dns_txt(self) -> str:
        """Значение TXT-записи (§5.3.2): тот же формат key=value, что разбирает шлюз."""
        return f"gateway={self.gateway_id};node={self.node_id};challenge={self.challenge};exp={self.expires_at}"


def _build_document(args: argparse.Namespace) -> ConsentDoc:
    models = [m for m in (args.models or "").split(",") if m.strip()]
    expires = datetime.now(UTC) + timedelta(days=max(1, args.ttl_days))
    return ConsentDoc(
        node_id=args.node_id,
        challenge=args.challenge,
        gateway_id=args.gateway_id,
        owner_id=args.owner_id,
        expires_at=expires.isoformat().replace("+00:00", "Z"),
        capabilities={"models": models, "max_concurrency": args.max_concurrency},
    )


def cmd_consent_file(args: argparse.Namespace) -> int:
    document = _build_document(args)
    payload = document.as_json()
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload + "\n", encoding="utf-8")
        print(f"файл согласия записан: {path}")
    else:
        print(payload)
    print(f"# разместите по пути {CONSENT_PATH} на узле, затем: foa-owner verify --node-id {args.node_id}", file=sys.stderr)
    return 0


def cmd_dns_record(args: argparse.Namespace) -> int:
    document = _build_document(args)
    host = _host_of(args.endpoint)
    if not host or _is_ip_literal(host):
        raise OwnerCLIError("DNS TXT недоступен для узла с IP-адресом: используйте http_well_known или signed_token (§5.3.2)")
    name = f"{DNS_PREFIX}{host}"
    if args.zone_file:
        print(f"{name}. IN TXT \"{document.dns_txt()}\"")
    else:
        print(f"имя:   {name}")
        print(f"значение: {document.dns_txt()}")
    print(f"# после публикации: foa-owner verify --node-id {args.node_id} --method dns_txt", file=sys.stderr)
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    from foa.services.consent import build_signed_token

    private_pem = _read_private(Path(args.key))
    models = [m for m in (args.models or "").split(",") if m.strip()]
    token = build_signed_token(
        private_key_pem=private_pem,
        node_id_=args.node_id,
        owner_id_=args.owner_id,
        gateway_id=args.gateway_id,
        capabilities={"models": models, "max_concurrency": args.max_concurrency},
        policy={"no_training": not args.allow_training, "log_level": args.log_level},
        ttl_seconds=args.ttl_seconds,
    )
    if args.output:
        Path(args.output).write_text(token + "\n", encoding="ascii")
        print(f"токен записан: {args.output}", file=sys.stderr)
    else:
        print(token)
    return 0


class _ConsentHolder:
    """Документ согласия известен только после ответа шлюза — сервер читает его лениво."""

    document: str | None = None

    def set(self, document: str) -> None:
        self.document = document


def _serve_consent_handler(holder: _ConsentHolder):
    path = CONSENT_PATH.rstrip("/")

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path.split("?", 1)[0].rstrip("/") != path or holder.document is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = holder.document.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *fmt_args: Any) -> None:
            # Только путь и код: заголовки клиента (Authorization, X-Forwarded-For) не журналируем (§12.2).
            code = fmt_args[1] if len(fmt_args) > 1 else "?"
            print(f"consent-server: {self.command} {self.path} -> {code}", file=sys.stderr)

    return _Handler


def _start_consent_server(holder: _ConsentHolder, bind: str, port: int) -> tuple[ThreadingHTTPServer, str]:
    """Поднимает consent-сервер в фоновом потоке; вызывать обязан ``shutdown()`` + ``server_close()``."""
    server = ThreadingHTTPServer((bind, port), _serve_consent_handler(holder))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="foa-consent-server", daemon=True).start()
    host, actual_port = server.server_address[0], server.server_address[1]
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    return server, f"http://{display_host}:{actual_port}"


def cmd_serve_consent(args: argparse.Namespace) -> int:
    holder = _ConsentHolder()
    holder.set(_build_document(args).as_json())
    host, port = args.bind, args.port
    server = ThreadingHTTPServer((host, port), _serve_consent_handler(holder))
    server.daemon_threads = True
    print(f"отдаю {CONSENT_PATH} на http://{host}:{server.server_address[1]}", file=sys.stderr)
    print(
        f"важно: шлюз проверяет файл по адресу узла ({args.endpoint}{CONSENT_PATH}) — проксируйте этот путь на порт "
        f"{args.port} либо используйте dns_txt/signed_token (§5.3.2, §5.3.3)",
        file=sys.stderr,
    )
    print("Ctrl+C — остановить", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлено", file=sys.stderr)
    finally:
        server.server_close()
    return 0


def _dns_value(document: dict[str, Any]) -> str:
    """Значение TXT-записи (§5.3.2) из документа согласия, возвращённого шлюзом."""
    return f"gateway={document.get('gateway_id', '')};node={document['node_id']};challenge={document['challenge']};exp={document['expires_at']}"


def _host_of(endpoint: str) -> str:
    from urllib.parse import urlparse

    return urlparse(endpoint).hostname or ""


def _is_ip_literal(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- #
# Запросы к админ-контру
# --------------------------------------------------------------------------- #


def _client(args: argparse.Namespace, *, read_only: bool = False):
    """HTTP-клиент админ-контура (§9.6: отдельная аутентификация).

    Владелец работает owner-токеном и видит только свои узлы. Команда ``status``
    показывает общее состояние шлюза — это ``admin:read``, которого у владельца
    нет (§9.6), поэтому для read_only-запросов принимается и администраторский
    (или аудиторский) токен.
    """
    import httpx

    owner_token = os.environ.get("FOA_OWNER_TOKEN") or args.owner_token
    admin_token = os.environ.get("FOA_ADMIN_TOKEN") or args.admin_token
    token = (admin_token or owner_token) if read_only else (owner_token or admin_token)
    if not token:
        raise OwnerCLIError(
            "нужен токен админ-контура: --admin-token/FOA_ADMIN_TOKEN"
            if read_only
            else "нужен владелецский токен: --owner-token или FOA_OWNER_TOKEN (§9.6)"
        )
    base = (args.gateway or "").rstrip("/")
    if not base:
        raise OwnerCLIError("нужен адрес шлюза: --gateway https://gw.example.com")
    prefix = (args.prefix or "").strip("/")
    if prefix:
        base = f"{base}/{prefix}"
    return httpx.Client(
        base_url=base,
        headers={"Authorization": f"Bearer {token}"},
        timeout=args.timeout,
        follow_redirects=False,
        trust_env=False,
    )


def _print_json(payload: Any, *, raw: bool = False) -> None:
    if raw:
        print(payload)
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _check(response, *, context: str) -> Any:
    """Разворачивает ответ шлюза; тело ошибки — ``{"error": "…", "code": "…"}`` (§9.5.1)."""
    if response.status_code >= 400:
        detail: Any = response.text[:300]
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            detail = body.get("error") or body.get("detail") or body
        raise OwnerCLIError(f"{context}: HTTP {response.status_code} — {detail}")
    return response.json()


def cmd_register(args: argparse.Namespace) -> int:
    body: dict[str, Any] = {
        "endpoint": args.endpoint,
        "models": [m for m in (args.models or "").split(",") if m.strip()],
        "consent_method": args.method,
        "max_concurrency": args.max_concurrency,
        "max_requests_per_hour": args.max_requests_per_hour,
    }
    if args.owner_id:
        body["owner_id"] = args.owner_id
    if args.display_name:
        body["display_name"] = args.display_name
    with _client(args) as client:
        data = _check(client.post("/admin/nodes", json=body), context="регистрация узла")
    _print_json(data)
    print("\nДальше (§5.3): подтвердите владение — шлюз не отправит на узел ни одного запроса до этого.", file=sys.stderr)
    if data.get("next_step"):
        print(f"  {data['next_step']}", file=sys.stderr)
    common = f"--node-id {data.get('node_id', '')} --challenge {data.get('challenge', '')} --endpoint {args.endpoint}"
    identity = f" --owner-id {args.owner_id}" if args.owner_id else ""
    print(f"  foa-owner serve-consent {common}{identity} --gateway-id {args.gateway_id}", file=sys.stderr)
    print(f"  foa-owner consent-file  {common}{identity} --gateway-id {args.gateway_id}", file=sys.stderr)
    print(f"  foa-owner dns-record    {common}{identity} --gateway-id {args.gateway_id}", file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    body: dict[str, Any] = {}
    if args.method:
        body["method"] = args.method
    if args.token_file or args.signed_token:
        signed = args.signed_token or Path(args.token_file).read_text(encoding="ascii").strip()
        body["signed_token"] = signed
    with _client(args) as client:
        data = _check(client.post(f"/admin/nodes/{args.node_id}/verify", json=body), context="подтверждение владения")
    _print_json(data)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    with _client(args) as client:
        if args.node_id:
            _print_json(_check(client.get(f"/admin/nodes/{args.node_id}"), context="состояние узла"))
            return 0
        _print_json(_check(client.get("/admin/status"), context="состояние шлюза"))
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    with _client(args) as client:
        data = _check(
            client.post(f"/admin/nodes/{args.node_id}/revoke", json={"reason": args.reason}),
            context="отзыв согласия",
        )
    _print_json(data)
    print("согласие отозвано: узел исключён из маршрутизации (§5.5)", file=sys.stderr)
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        raise OwnerCLIError("удаление необратимо: передайте --yes для подтверждения (§12.7.7)")
    with _client(args) as client:
        _print_json(_check(client.delete(f"/admin/nodes/{args.node_id}"), context="удаление узла"))
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    """Полный владельческий путь одним прогоном: регистрация → документ согласия → verify.

    Содержимое ``consent.json`` запрашивается у шлюза
    (``POST /admin/nodes/{id}/consent-document``), а не строится здесь: так
    CLI не дублирует сверку ``challenge``/``gateway_id``/``owner_id`` (§5.3.1).

    С ``--serve`` CLI поднимает локальный HTTP-сервер с файлом согласия и
    регистрирует узел на его адрес — удобно для подготовки узла и для стендов.
    """
    server: ThreadingHTTPServer | None = None
    holder = _ConsentHolder()
    endpoint = args.endpoint
    if args.serve:
        server, base = _start_consent_server(holder, args.bind, args.port)
        endpoint = base
    try:
        with _client(args) as client:
            body: dict[str, Any] = {
                "endpoint": endpoint,
                "models": [m for m in (args.models or "").split(",") if m.strip()],
                "consent_method": args.method,
                "max_concurrency": args.max_concurrency,
                "max_requests_per_hour": args.max_requests_per_hour,
            }
            if args.owner_id:
                body["owner_id"] = args.owner_id
            registered = _check(client.post("/admin/nodes", json=body), context="регистрация узла")
            node_id_ = registered["node_id"]
            if args.method == "dns_txt":
                prepared = _check(client.post(f"/admin/nodes/{node_id_}/consent-document"), context="подготовка TXT")
                text = _dns_value(prepared["document"])
                print(f"# опубликуйте TXT {DNS_PREFIX}{_host_of(endpoint)}: {text}", file=sys.stderr)
                _print_json({"register": registered, "dns_txt": text})
                return 0
            prepared = _check(client.post(f"/admin/nodes/{node_id_}/consent-document"), context="подготовка файла согласия")
            document = json.dumps(prepared["document"], ensure_ascii=False, indent=2)
            if server is not None:
                holder.set(document)
                outcome = {"register": registered, "serve": f"{endpoint}{CONSENT_PATH}"}
            else:
                path = Path(args.output or "consent.json")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(document + "\n", encoding="utf-8")
                print(f"файл согласия: {path} → разместите по {endpoint}{CONSENT_PATH}", file=sys.stderr)
                outcome = {"register": registered, "consent_file": str(path)}
                if args.wait:
                    print(f"жду публикации ({args.wait} с)…", file=sys.stderr)
                    time.sleep(args.wait)
            outcome["verify"] = _check(
                client.post(f"/admin/nodes/{node_id_}/verify", json={"method": args.method}), context="подтверждение"
            )
            _print_json(outcome)
            return 0
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()


def cmd_render(args: argparse.Namespace) -> int:
    """HTML-страница с consent.json для быстрой публикации на узле."""
    document = _build_document(args)
    page = f"""<!doctype html>
<meta charset="utf-8">
<title>Free Ollama — согласие узла {escape(document.node_id)}</title>
<p>Разместите этот JSON по пути <code>{escape(CONSENT_PATH)}</code> на узле
<code>{escape(args.endpoint)}</code> — шлюз не будет отправлять сюда запросы пользователей,
пока файл не появится (§5.3.1).</p>
<pre>{escape(document.as_json())}</pre>
<p>Срок действия: <b>{escape(document.expires_at)}</b></p>
"""
    if args.output:
        Path(args.output).write_text(page, encoding="utf-8")
        print(f"страница записана: {args.output}", file=sys.stderr)
    else:
        print(page)
    return 0


# --------------------------------------------------------------------------- #
# Парсер
# --------------------------------------------------------------------------- #


def _add_document_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--node-id", required=True, help="идентификатор узла из ответа /admin/nodes")
    parser.add_argument("--challenge", required=True, help="challenge_token из ответа /admin/nodes")
    parser.add_argument("--endpoint", required=True, help="публичный адрес узла, напр. https://ollama.example.com:11434")
    parser.add_argument("--owner-id", default="", help="идентичность владельца в этом шлюзе")
    parser.add_argument("--gateway-id", default="gateway_main", help="идентификатор шлюза (FOA_GATEWAY__ID у администратора)")
    parser.add_argument("--models", default="", help="список моделей через запятую (ограничивает согласие, §5.2 п.3)")
    parser.add_argument("--max-concurrency", type=int, default=2, help="сколько запросов узел готов обслуживать одновременно")
    parser.add_argument("--ttl-days", type=int, default=7, help="срок действия подтверждения (перепроверка — каждые 24 ч, §5.4)")


def _add_gateway_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--gateway", default=os.environ.get("FOA_GATEWAY_URL", ""), help="адрес шлюза (FOA_GATEWAY_URL)")
    parser.add_argument("--prefix", default="", help="префикс API, если сервер за nginx (server.api_prefix)")
    parser.add_argument("--owner-token", default="", help="владельческий токен (FOA_OWNER_TOKEN)")
    parser.add_argument("--admin-token", default="", help="токен администратора/аудитора — только для read-команд (FOA_ADMIN_TOKEN)")
    parser.add_argument("--timeout", type=float, default=30.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="foa-owner",
        description="Владелецские утилиты Free Ollama API Gateway: ключи, согласие, отзыв (§5, §9.6)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Пример (§5.3.1, http_well_known):\n"
            "  foa-owner keygen\n"
            "  foa-owner register --gateway https://gw.example --endpoint https://ollama.example:11434 --models llama3.1\n"
            "  foa-owner serve-consent --node-id node_01J... --challenge ... --endpoint https://ollama.example:11434\n"
            "  foa-owner verify --node-id node_01J...\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="создать пару ключей Ed25519 для signed_token (§5.3.3)")
    p_keygen.add_argument("--key", default=str(DEFAULT_KEY_PATH), help="куда записать приватный ключ (0600)")
    p_keygen.add_argument("--public-key", default=str(DEFAULT_KEY_PATH.with_suffix(".pub")), help="куда записать публичный ключ")
    p_keygen.add_argument("--stdout", action="store_true", help="вывести оба ключа в stdout (для секретного хранилища)")
    p_keygen.add_argument("--force", action="store_true", help="перезаписать существующий приватный ключ")
    p_keygen.set_defaults(func=cmd_keygen)

    p_public = sub.add_parser("public-key", help="напечатать публичный ключ из приватного")
    p_public.add_argument("--key", default=str(DEFAULT_KEY_PATH))
    p_public.add_argument("--raw", action="store_true", help="без завершающего перевода строки")
    p_public.set_defaults(func=cmd_public)

    p_register = sub.add_parser("register", help="зарегистрировать узел (POST /admin/nodes, §9.6.2)")
    _add_gateway_arguments(p_register)
    p_register.add_argument("--endpoint", required=True)
    p_register.add_argument("--models", default="")
    p_register.add_argument("--owner-id", default="")
    p_register.add_argument("--display-name", default="")
    p_register.add_argument("--method", default="http_well_known", choices=("http_well_known", "dns_txt", "signed_token"))
    p_register.add_argument("--max-concurrency", type=int, default=2)
    p_register.add_argument("--max-requests-per-hour", type=int, default=1000)
    p_register.add_argument("--gateway-id", default="gateway_main")
    p_register.set_defaults(func=cmd_register)

    p_consent = sub.add_parser("consent-file", help="сформировать consent.json (§5.3.1)")
    _add_document_arguments(p_consent)
    p_consent.add_argument("--output", default="", help="записать в файл вместо stdout")
    p_consent.set_defaults(func=cmd_consent_file)

    p_serve = sub.add_parser("serve-consent", help="отдать /.well-known/…/consent.json локальным HTTP-сервером")
    _add_document_arguments(p_serve)
    p_serve.add_argument("--bind", default="0.0.0.0", help="адрес привязки (в Docker обычно 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8899)
    p_serve.set_defaults(func=cmd_serve_consent)

    p_dns = sub.add_parser("dns-record", help="сформировать значение TXT-записи (§5.3.2)")
    _add_document_arguments(p_dns)
    p_dns.add_argument("--zone-file", action="store_true", help="вывести строку для zone file")
    p_dns.set_defaults(func=cmd_dns_record)

    p_token = sub.add_parser("token", help="подписать JWT согласия ключом из keygen (§5.3.3)")
    p_token.add_argument("--key", default=str(DEFAULT_KEY_PATH))
    p_token.add_argument("--node-id", required=True)
    p_token.add_argument("--owner-id", required=True)
    p_token.add_argument("--gateway-id", default="gateway_main")
    p_token.add_argument("--models", default="")
    p_token.add_argument("--max-concurrency", type=int, default=2)
    p_token.add_argument("--allow-training", action="store_true", help="разрешить обучение на данных (по умолчанию — нет, §5.2 п.3)")
    p_token.add_argument("--log-level", default="metadata_only", choices=("none", "metadata_only", "full"))
    p_token.add_argument("--ttl-seconds", type=int, default=3600)
    p_token.add_argument("--output", default="", help="записать токен в файл вместо stdout")
    p_token.set_defaults(func=cmd_token)

    p_publish = sub.add_parser("publish", help="регистрация + подготовка согласия + verify одним прогоном")
    _add_gateway_arguments(p_publish)
    p_publish.add_argument("--endpoint", required=True, help="публичный адрес узла (с --serve узел регистрируется на локальный сервер)")
    p_publish.add_argument("--models", default="")
    p_publish.add_argument("--owner-id", default="")
    p_publish.add_argument("--method", default="http_well_known", choices=("http_well_known", "dns_txt"))
    p_publish.add_argument("--max-concurrency", type=int, default=2)
    p_publish.add_argument("--max-requests-per-hour", type=int, default=1000)
    p_publish.add_argument("--output", default="consent.json", help="файл для consent.json")
    p_publish.add_argument("--wait", type=float, default=0.0, help="секунд на публикацию файла перед verify")
    p_publish.add_argument("--serve", action="store_true", help="отдать consent.json локальным сервером и зарегистрировать узел на него")
    p_publish.add_argument("--bind", default="127.0.0.1", help="адрес привязки для --serve")
    p_publish.add_argument("--port", type=int, default=0, help="порт для --serve (0 — любой свободный)")
    p_publish.set_defaults(func=cmd_publish)

    for name, help_text, extra in (
        ("verify", "подтвердить владение (POST /admin/nodes/{id}/verify)", True),
        ("status", "состояние узла или шлюза (GET /admin/status)", False),
        ("revoke", "отозвать согласие (POST /admin/nodes/{id}/revoke, §5.5)", False),
        ("delete", "удалить узел и его данные (DELETE /admin/nodes/{id}, §12.7.7)", False),
    ):
        p = sub.add_parser(name, help=help_text)
        _add_gateway_arguments(p)
        p.add_argument("--node-id", default="", help="идентификатор узла")
        if extra:
            p.add_argument("--method", default=None, choices=(None, "http_well_known", "dns_txt", "signed_token"))
            p.add_argument("--signed-token", default="", help="готовый JWT из `foa-owner token`")
            p.add_argument("--token-file", default="", help="прочитать JWT из файла")
        if name == "revoke":
            p.add_argument("--reason", default="owner_revoked")
        if name == "delete":
            p.add_argument("--yes", action="store_true")
        p.set_defaults(func={"verify": cmd_verify, "status": cmd_status, "revoke": cmd_revoke, "delete": cmd_delete}[name])

    p_render = sub.add_parser("render-page", help="HTML-страница с consent.json для публикации")
    _add_document_arguments(p_render)
    p_render.add_argument("--output", default="")
    p_render.set_defaults(func=cmd_render)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except OwnerCLIError as exc:
        print(f"foa-owner: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("\nпрервано", file=sys.stderr)
        return 130


__all__ = ["ConsentDoc", "build_parser", "main"]
