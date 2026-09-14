"""Разрешение secret-плейсхолдеров (§4.5 п.3, §11.5, §14.2).

В репозитории и в ``config.yaml`` секреты не хранятся. Допустимые ссылки:

* ``"{env:VAR_NAME}"``            — переменная окружения;
* ``"{file:/path/to/secret}"``    — файл (монтированный secret manager);
* ``"{vault:kv/data/path/key}"``  — Vault-style path, читается из ``VAULT_TOKEN``
  через локальный кэш ``data/secrets/<slug>`` (заглушка внешнего secret manager);
* ``"{api_key_service}"``         — плейсхолдер ТЗ: трактуется как
  ``"{env:FOA_SECRET_<UPPER>}"`` либо остаётся пустым (источник не активируется).

Незаполненные ссылки на внешние секреты не считаются ошибкой: интеграции
Discovery по умолчанию выключены, и отсутствие ключа просто оставляет их
выключенными (FR-D-07).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

REF_RE = re.compile(r"^\{([a-z_]+):?([^}]*)\}$")


class SecretResolutionError(RuntimeError):
    pass


def resolve_ref(value: Any, env: dict[str, str] | None = None, *, strict: bool = False) -> Any:
    """Возвращает разрешённое значение секрета либо исходную строку без ссылок."""
    if not isinstance(value, str):
        return value
    match = REF_RE.match(value.strip())
    if not match:
        return value
    scheme, ref = match.group(1), match.group(2).strip()
    env = dict(os.environ if env is None else env)

    if scheme == "env":
        name = ref or value.strip("{}").upper()
        got = env.get(name)
        if got is None:
            if strict:
                raise SecretResolutionError(f"переменная окружения {name} не задана")
            return ""
        return got

    if scheme == "file":
        path = Path(ref)
        if not path.is_file():
            if strict:
                raise SecretResolutionError(f"файл секрета не найден: {path}")
            return ""
        return path.read_text(encoding="utf-8").strip()

    if scheme == "vault":
        cache = Path(env.get("FOA_VAULT_CACHE_DIR", "data/secrets")) / _slug(ref)
        if cache.is_file():
            return cache.read_text(encoding="utf-8").strip()
        if strict:
            raise SecretResolutionError(f"vault-секрет недоступен локально: {ref}")
        return ""

    # Плейсхолдер без схемы, напр. "{api_key_service}" (§4.5) — ищем по имени.
    # REGEX оставляет схему пустой как имя, поэтому имя берётся из схемы.
    name = "FOA_SECRET_" + re.sub(r"[^0-9A-Za-z]+", "_", ref or scheme).strip("_").upper()
    got = env.get(name)
    if got is None and strict:
        raise SecretResolutionError(f"не удалось разрешить ссылку на секрет {value!r} (ожидалась {name})")
    return got or ""


def _slug(ref: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "-", ref).strip("-").lower() or "secret"


def resolve_secrets(obj: Any, env: dict[str, str] | None = None, *, path: tuple[str, ...] = ()) -> None:
    """Рекурсивно подставляет секреты в dataclass-дереве настроек на месте."""
    from dataclasses import fields, is_dataclass

    if is_dataclass(obj) and not isinstance(obj, type):
        for f in fields(obj):
            current = getattr(obj, f.name)
            if isinstance(current, str):
                setattr(obj, f.name, resolve_ref(current, env))
            elif is_dataclass(current):
                resolve_secrets(current, env, path=(*path, f.name))
            elif isinstance(current, dict):
                for key, val in current.items():
                    if isinstance(val, str):
                        current[key] = resolve_ref(val, env)
                    elif is_dataclass(val):
                        resolve_secrets(val, env, path=(*path, f.name, str(key)))
    return obj


__all__ = ["REF_RE", "SecretResolutionError", "resolve_ref", "resolve_secrets"]
