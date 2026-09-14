"""Криграфия ключей доступа (§12.4.1).

* API-ключи пользователей хранятся только как SHA-256(pepper + key); сам ключ
  выдаётся одинжды при создании и не может быть восстановлен.
* Для проверки подписей согласия (токены Ed25519/JWT) используется публичный
  ключ владельца из реестра.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from foa.domain.errors import InvalidRequestError
from foa.ids import random_secret

KEY_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_\-]{24,200}$")


def generate_api_key(prefix: str = "foa_") -> str:
    return prefix + random_secret(24)


def key_fingerprint(key: str) -> str:
    """Короткий отпечаток для логов/админ-списка — не секрет, но и не ключ."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def hash_api_key(key: str, *, pepper: str = "") -> bytes:
    """Хэш ключа с пеппером; пеппер берётся из secret manager (§14.2)."""
    material = (pepper + key).encode("utf-8") if pepper else key.encode("utf-8")
    return hashlib.sha256(material).digest()


def verify_api_key(candidate: str, stored_hash: bytes, *, pepper: str = "") -> bool:
    if not candidate or not KEY_ALPHABET_RE.match(candidate):
        return False
    return hmac.compare_digest(hash_api_key(candidate, pepper=pepper), stored_hash)


def constant_time_token_equal(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))


# --------------------------------------------------------------------------- #
# Ed25519 (подтверждение согласия подписанным токеном, §5.3.3)
# --------------------------------------------------------------------------- #


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_ed25519_public_key(pem_or_b64: str) -> Ed25519PublicKey:
    material = (pem_or_b64 or "").strip()
    if not material:
        raise InvalidRequestError("публичный ключ владельца не задан")
    if material.startswith("-----BEGIN"):
        return serialization.load_pem_public_key(material.encode("utf-8"))
    try:
        raw = base64.urlsafe_b64decode(material + "=" * (-len(material) % 4))
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise InvalidRequestError(f"не удалось прочитать публичный ключ: {exc}") from exc


def sign_ed25519(private_pem: str | bytes, message: bytes) -> str:
    if isinstance(private_pem, str):
        private_pem = private_pem.encode("utf-8")
    key = serialization.load_pem_private_key(private_pem, password=None)
    return _b64url(key.sign(message))


def verify_ed25519(public_key_pem_or_b64: str, message: bytes, signature_b64url: str) -> bool:
    try:
        key = load_ed25519_public_key(public_key_pem_or_b64)
        signature = base64.urlsafe_b64decode(signature_b64url + "=" * (-len(signature_b64url) % 4))
        key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def generate_ed25519_pair() -> tuple[str, str]:
    """(private_pem, public_pem) — для тестов и для владельческого CLI."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


__all__ = [
    "constant_time_token_equal",
    "generate_api_key",
    "generate_ed25519_pair",
    "hash_api_key",
    "key_fingerprint",
    "load_ed25519_public_key",
    "sign_ed25519",
    "verify_api_key",
    "verify_ed25519",
]
