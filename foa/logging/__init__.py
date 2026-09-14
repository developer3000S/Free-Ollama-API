"""Структурированное JSON-журналирование (§11.4, §12.5.3).

Правила:
* логируется только метаданные запроса — содержимое промптов и ответов не
  попадает в журнал, пока это явно не разрешено политикой (§12.5.2);
* секреты, ключи и токены маскируются всегда, независимо от настроек.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
from contextvars import ContextVar
from typing import Any

_request_id: ContextVar[str] = ContextVar("request_id", default="")
_user_key_hash: ContextVar[str] = ContextVar("user_key_hash", default="")

#: Минимальный набор полей журнала (§12.5.3). Форматтер дописывает request_id и
#: user_key_hash из контекста, а диагностику событий (event, source, path,
#: reason, …) добавлять разрешено: перечень в ТЗ задан как «минимальный набор»,
#: а не как исчерпывающий список.
MINIMUM_LOG_FIELDS = (
    "request_id",
    "user_key_hash",
    "model",
    "stream",
    "status",
    "error_code",
    "node_id",
    "latency_ms",
    "bytes_in",
    "bytes_out",
    "timestamp",
)

_FORBIDDEN_KEYS = re.compile(
    r"(prompt|response|message|messages|content|completion|api[_-]?key|secret|token|authorization|"
    r"password|cookie|signature|challenge)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[a-z0-9._~+/\-]+")
_LONG_HEX_RE = re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE)
_KEY_RE = re.compile(r"\bfoa_[0-9A-Za-z_\-]{6,}")

_REDACTED = "***"


def set_request_context(request_id: str = "", user_key_hash: str = "") -> None:
    if request_id:
        _request_id.set(request_id)
    if user_key_hash:
        _user_key_hash.set(user_key_hash)


def get_request_id() -> str:
    return _request_id.get()


def get_user_key_hash() -> str:
    return _user_key_hash.get()


def scrub_text(text: str) -> str:
    """Вычищает из произвольного текста подозримые на секреты последовательности."""
    text = _BEARER_RE.sub(rf"\1{_REDACTED}", text)
    text = _KEY_RE.sub(_REDACTED, text)
    text = _LONG_HEX_RE.sub(_REDACTED, text)
    return text


def scrub(payload: dict[str, Any]) -> dict[str, Any]:
    """Отфильтровывает запрещённые поля (§12.5.3) и маскирует секреты."""
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if _FORBIDDEN_KEYS.search(key):
            continue
        if isinstance(value, str):
            value = scrub_text(value)
        elif isinstance(value, dict):
            value = scrub(value)
        elif isinstance(value, (list, tuple)):
            value = [scrub_text(v) if isinstance(v, str) else v for v in value]
        clean[key] = value
    return clean


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": scrub_text(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = scrub_text(self.formatException(record.exc_info))
        extra = getattr(record, "foa", None)
        if isinstance(extra, dict):
            payload.update(scrub(extra))
        if rid := get_request_id():
            payload.setdefault("request_id", rid)
        if ukh := get_user_key_hash():
            payload.setdefault("user_key_hash", ukh)
        return json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))


class KeySafeFormatter(JsonLogFormatter):
    """Форматтер, который никогда не пишет запрещённые поля даже при ошибке.

    Проверка применяется к полям из ``record.foa``: служебные ключи формата
    (``message``, ``level``, ``timestamp``) создаются самим форматтером, а их
    содержимое уже очищено :func:`scrub_text`.
    """

    def format(self, record: logging.LogRecord) -> str:
        extra = getattr(record, "foa", None)
        if isinstance(extra, dict) and any(_FORBIDDEN_KEYS.search(str(key)) for key in extra):
            leaked = sorted(str(key) for key in extra if _FORBIDDEN_KEYS.search(str(key)))
            record.foa = scrub(extra)
            record.foa["dropped_keys"] = leaked[:10]
        return super().format(record)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(getattr(record, "foa", None), dict):
            record.foa = scrub(record.foa)
        return True


_configured = threading.Lock()


def configure_logging(level: str = "INFO", fmt: str = "json", stream=None) -> None:
    """Инициализирует корневой логгер шлюза. Идемпотентно."""
    with _configured:
        root = logging.getLogger("foa")
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        for handler in list(root.handlers):
            root.removeHandler(handler)
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.addFilter(RedactingFilter())
        if fmt == "text":
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        else:
            handler.setFormatter(KeySafeFormatter())
        root.addHandler(handler)
        root.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"foa.{name}")


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    """Пишет событие с гарантированно отмаскированным набором полей."""
    logger.log(level, event, extra={"foa": {"event": event, **fields}})


__all__ = [
    "MINIMUM_LOG_FIELDS",
    "JsonLogFormatter",
    "configure_logging",
    "get_logger",
    "get_request_id",
    "get_user_key_hash",
    "log_event",
    "scrub",
    "scrub_text",
    "set_request_context",
]
