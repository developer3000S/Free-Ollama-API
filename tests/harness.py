"""Тестовый стенд: фейковый узел Ollama + собранное приложение шлюза.

Фейк реализует ``/api/version``, ``/api/tags``, ``/api/show``, ``/api/generate``,
``/api/chat``, ``/api/embeddings``, ``/api/embed``, ``/api/ps`` и файл согласия
``/.well-known/free-ollama/v1/consent.json`` (§9.3, §5.3.1), а также управляемые
режимы отказа: ``401``/``403``/``500``/таймаут/обрыв потока (§6.4, §15.3).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

# --------------------------------------------------------------------------- #
# Фейковый Ollama
# --------------------------------------------------------------------------- #


class FakeOllama:
    """HTTP-сервер, имитирующий узел Ollama, с переключаемыми режимами поведения."""

    def __init__(self, *, models: list[str] | None = None, port: int = 0, name: str = "fake") -> None:
        self.models = models or ["llama3.1", "qwen2.5"]
        self.version = "0.3.14"
        self.name = name
        self.consent_document: dict[str, Any] | None = None
        self.requests: list[dict[str, Any]] = []
        self.headers_seen: list[dict[str, str]] = []
        self.mode = "ok"  # ok | unauthorized | forbidden | error500 | timeout | stream_break | tags_empty
        self.latency_seconds = 0.0
        self.tokens_to_report = 7
        self.show_payload = {
            "modelfile": "FROM llama3.1",
            "parameters": "temperature 0.7",
            "template": "{{ .Prompt }}",
            "details": {"parent_model": "", "format": "gguf", "family": "llama", "families": ["llama"], "parameter_size": "8B", "quantization_level": "Q4_0"},
        }
        ps_reports = self.models
        self._ps_models = ps_reports
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):  # тишина серверного лога
                pass

            # -- утилиты ------------------------------------------------- #
            def _json(self, payload: Any, status: int = 200) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _ndjson(self, lines: list[str]) -> None:
                body = ("\n".join(lines) + "\n").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> dict:
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    return json.loads(raw.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    return {}

            def _record(self, path: str, body: dict) -> None:
                outer.requests.append({"path": path, "body": body, "at": time.time()})
                outer.headers_seen.append({k.lower(): v for k, v in self.headers.items()})
                if outer.latency_seconds:
                    time.sleep(outer.latency_seconds)
                if outer.mode == "unauthorized":
                    self._json({"error": "unauthorized"}, 401)
                    return "handled"
                if outer.mode == "forbidden":
                    self._json({"error": "forbidden"}, 403)
                    return "handled"
                if outer.mode == "error500":
                    self._json({"error": "boom"}, 500)
                    return "handled"
                if outer.mode == "timeout":
                    time.sleep(6)
                    self._json({"error": "late"}, 500)
                    return "handled"
                return None

            # -- маршруты ------------------------------------------------ #
            def do_GET(self):
                path = self.path.split("?")[0]
                handled = self._record(path, {})
                if handled:
                    return
                if path == "/api/version":
                    return self._json({"version": outer.version})
                if path == "/api/tags":
                    if outer.mode == "tags_empty":
                        return self._json({"models": []})
                    return self._json({"models": [{"name": m, "model": m, "size": 4_700_000_000, "digest": "sha256:" + "ab" * 31} for m in outer.models]})
                if path == "/api/ps":
                    return self._json({"models": [{"name": m, "model": m, "size": 4_700_000_000, "digest": "sha256:" + "cd" * 31, "details": {"format": "gguf", "family": "llama", "parameter_size": "8B"}} for m in outer._ps_models]})
                if path == outer.consent_path():
                    if outer.consent_document is None:
                        return self._json({"error": "no consent file"}, 404)
                    return self._json(outer.consent_document)
                return self._json({"error": "not found"}, 404)

            def do_POST(self):
                path = self.path.split("?")[0]
                body = self._body()
                handled = self._record(path, body)
                if handled:
                    return
                model = str(body.get("model") or body.get("name") or "")
                if path == "/api/show":
                    return self._json(outer.show_payload)
                if path == "/api/generate":
                    if body.get("stream"):
                        return outer.stream_generate(self, body, model)
                    return self._json(
                        {
                            "model": model,
                            "created_at": "2026-09-14T10:00:00Z",
                            "response": "Hi from fake node",
                            "done": True,
                            "context": [],
                            "total_duration": 1_200_000_000,
                            "load_duration": 100_000_000,
                            "prompt_eval_count": 10,
                            "eval_count": outer.tokens_to_report,
                            "eval_duration": 900_000_000,
                        }
                    )
                if path == "/api/chat":
                    if body.get("stream"):
                        return outer.stream_chat(self, body, model)
                    return self._json(
                        {
                            "model": model,
                            "created_at": "2026-09-14T10:00:00Z",
                            "message": {"role": "assistant", "content": "Hello! How can I help you?"},
                            "done": True,
                            "total_duration": 1_200_000_000,
                            "load_duration": 100_000_000,
                            "prompt_eval_count": 15,
                            "eval_count": outer.tokens_to_report,
                            "eval_duration": 900_000_000,
                        }
                    )
                if path == "/api/embeddings":
                    return self._json({"embedding": [0.11, 0.22, 0.33]})
                if path == "/api/embed":
                    inputs = body.get("input")
                    count = len(inputs) if isinstance(inputs, list) else 1
                    return self._json({"embeddings": [[0.1, 0.2, 0.3] for _ in range(count)]})
                return self._json({"error": "not found"}, 404)

        self._server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name=f"fake-ollama-{name}")
        self.port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"

    # -- жизненный цикл --------------------------------------------------- #

    def start(self) -> FakeOllama:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> FakeOllama:
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    def consent_path(self) -> str:
        return "/.well-known/free-ollama/v1/consent.json"

    # -- поведение потоков ------------------------------------------------ #

    def stream_generate(self, handler: BaseHTTPRequestHandler, body: dict, model: str) -> None:
        if self.mode == "stream_break":
            # Объявляем больший Content-Length, чем реально пишем, и рвём соединение:
            # клиент обязан увидеть усечение тела как ошибку протокола.
            first = (json.dumps({"model": model, "response": "par", "done": False}) + "\n").encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "application/x-ndjson")
            handler.send_header("Content-Length", str(len(first) * 5))
            handler.end_headers()
            handler.wfile.write(first)
            handler.wfile.flush()
            handler.close_connection = True
            handler.wfile.close()
            return
        lines = [
            json.dumps({"model": model, "created_at": "2026-09-14T10:00:00Z", "response": "Hello", "done": False}),
            json.dumps({"model": model, "created_at": "2026-09-14T10:00:01Z", "response": "!", "done": False}),
            json.dumps(
                {
                    "model": model,
                    "created_at": "2026-09-14T10:00:02Z",
                    "response": "",
                    "done": True,
                    "prompt_eval_count": 4,
                    "eval_count": self.tokens_to_report,
                }
            ),
        ]
        handler._ndjson(lines)

    def stream_chat(self, handler: BaseHTTPRequestHandler, body: dict, model: str) -> None:
        lines = [
            json.dumps({"model": model, "created_at": "2026-09-14T10:00:00Z", "message": {"role": "assistant", "content": "Hi"}, "done": False}),
            json.dumps({"model": model, "created_at": "2026-09-14T10:00:01Z", "message": {"role": "assistant", "content": " there"}, "done": False}),
            json.dumps({"model": model, "created_at": "2026-09-14T10:00:02Z", "message": {"role": "assistant", "content": ""}, "done": True, "eval_count": self.tokens_to_report}),
        ]
        handler._ndjson(lines)

    # -- помощники для тестов --------------------------------------------- #

    @property
    def request_count(self) -> int:
        return len(self.requests)

    def last_request(self) -> dict:
        return self.requests[-1]

    def headers_for(self, index: int = -1) -> dict[str, str]:
        return self.headers_seen[index]

    def headers_by_path(self, path: str) -> list[dict[str, str]]:
        """Заголовки запросов, пришедших на конкретный путь (для точечных проверок)."""
        paired = zip(self.requests, self.headers_seen, strict=True)
        return [headers for req, headers in paired if req["path"] == path]

    def set_consent(self, document: dict[str, Any]) -> None:
        self.consent_document = document

    def clear_consent(self) -> None:
        self.consent_document = None


# --------------------------------------------------------------------------- #
# Фикстуры pytest
# --------------------------------------------------------------------------- #

TEST_ADMIN_TOKEN = "admintoken-test-0123456789"
TEST_AUDITOR_TOKEN = "audittoken-test-0123456789"
TEST_OWNER_TOKEN = "ownertoken-test-0123456789"
TEST_OWNER_REF = "owner_test_main"  # идентичность владельца для owner-токена (§2.2)


def make_settings(tmp_path, *, database_url: str | None = None, **env) -> Any:
    from foa.config import load_settings

    base_env = {
        "FOA_STORAGE__DATABASE_URL": database_url or f"sqlite+aiosqlite:///{tmp_path}/foa-test.sqlite3",
        "FOA_STORAGE__DATA_DIR": str(tmp_path / "data"),
        "FOA_AUTH__ADMIN_TOKEN": TEST_ADMIN_TOKEN,
        "FOA_AUTH__AUDITOR_TOKEN": TEST_AUDITOR_TOKEN,
        "FOA_AUTH__OWNER_TOKEN": TEST_OWNER_TOKEN,
        "FOA_AUTH__OWNER_REF": TEST_OWNER_REF,
        "FOA_SECURITY__CLIENT_HASH_SALT": "test-salt",
        "FOA_HEALTH__LIVENESS_INTERVAL_SECONDS": "1",
        "FOA_HEALTH__READINESS_INTERVAL_SECONDS": "1",
        "FOA_HEALTH__CONSENT_RECHECK_INTERVAL_SECONDS": "5",
        "FOA_DISCOVERY__SCAN_INTERVAL_SECONDS": "3600",
        "FOA_LOG_LEVEL": "WARNING",
        "FOA_OBSERVABILITY__LOG_LEVEL": "WARNING",
        "FOA_OBSERVABILITY__LOG_REQUESTS": "false",
    }
    base_env.update(env)
    return load_settings(str(tmp_path / "absent.yaml"), env=base_env)


@pytest.fixture()
def fake_node() -> Iterator[FakeOllama]:
    node = FakeOllama(name="primary").start()
    try:
        yield node
    finally:
        node.stop()
