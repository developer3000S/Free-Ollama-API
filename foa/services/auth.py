"""Аутентификация и авторизация (§9.2, §12.4.1).

* Пользовательский контур: ``Authorization: Bearer foa_...`` → SHA-256(pepper+key)
  → поиск по хэшу → проверка срока/отзыва → скоупы.
* Административный контур отделён (§9.6, §17.9): отдельные токены из secret
  manager, скоупы ``admin:read``/``admin:write``; при незаданном токене админка
  полностью закрыта (fail-closed).
* Ключи выдаются один раз, хранится только хэш; поддержка ротации и отзыва.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from foa.config import Settings
from foa.domain.enums import Scope
from foa.domain.errors import ForbiddenError, UnauthorizedError
from foa.ids import key_id
from foa.logging import get_logger
from foa.services import crypto
from foa.storage.models import ApiKeyRow, utcnow

log = get_logger("auth")

ROLE_SCOPES: dict[str, set[str]] = {
    "user": {Scope.OLLAMA_READ.value, Scope.OLLAMA_GENERATE.value, Scope.OLLAMA_EMBED.value},
    # Владелец — self-service по СВОИМ узлам (§2.2, §5.5); общие админ-ресурсы
    # (ключи, конфигурация, чужие узлы, discovery) ему недоступны.
    "owner": {Scope.OLLAMA_READ.value, Scope.OLLAMA_GENERATE.value, Scope.NODE_SELF_SERVICE.value},
    "admin": {Scope.ADMIN_READ.value, Scope.ADMIN_WRITE.value, Scope.OLLAMA_READ.value},
    "auditor": {Scope.ADMIN_READ.value},
}


@dataclass(slots=True)
class Principal:
    """Аутентифицированный субъект запроса."""

    kind: str  # api_key | admin | auditor | owner
    key_id: str = ""
    owner_ref: str = ""
    scopes: set[str] = field(default_factory=set)
    label: str = ""
    rate_limit_per_minute: int = 0
    concurrent_requests: int = 0
    tokens_per_day: int = 0
    key_hash_hex: str = ""

    @property
    def is_admin(self) -> bool:
        return Scope.ADMIN_WRITE.value in self.scopes or self.kind == "admin"

    @property
    def is_readonly_admin(self) -> bool:
        return self.kind in {"admin", "auditor", "owner"} or Scope.ADMIN_READ.value in self.scopes

    def can(self, scope: str) -> bool:
        return scope in self.scopes

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            raise ForbiddenError(f"требуется скоуп {scope}", details={"scope": scope})

    def audit_actor(self) -> str:
        return f"{self.kind}:{self.key_id or self.owner_ref or 'anonymous'}"


def _extract_bearer(header_value: str | None) -> str:
    if not header_value:
        raise UnauthorizedError()
    parts = header_value.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("ожидался заголовок Authorization: Bearer <ключ>")
    token = parts[1].strip()
    if not token or len(token) > 200:
        raise UnauthorizedError()
    return token


def _timing_safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class AuthService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # ------------------------------------------------------------------ #
    # Проверка подлинности
    # ------------------------------------------------------------------ #

    async def authenticate(self, session: AsyncSession, authorization: str | None) -> Principal:
        token = _extract_bearer(authorization)
        admin = self.settings.auth
        if admin.admin_token and _timing_safe_equal(token, admin.admin_token):
            return Principal(kind="admin", scopes=set(ROLE_SCOPES["admin"]), label="admin-token", key_hash_hex=crypto.key_fingerprint(token))
        if admin.auditor_token and _timing_safe_equal(token, admin.auditor_token):
            return Principal(kind="auditor", scopes=set(ROLE_SCOPES["auditor"]), label="auditor-token", key_hash_hex=crypto.key_fingerprint(token))
        if admin.owner_token and _timing_safe_equal(token, admin.owner_token):
            return Principal(kind="owner", scopes=set(ROLE_SCOPES["owner"]), label="owner-token", key_hash_hex=crypto.key_fingerprint(token))

        key_hash = crypto.hash_api_key(token, pepper=admin.bcrypt_like_pepper)
        row = await _ApiKeyLookup.by_hash(session, key_hash)
        if row is None:
            await asyncio_sleep(0.0)  # выравниваем время ответа при отсутствии ключа
            raise UnauthorizedError()
        if row.revoked:
            raise UnauthorizedError("ключ отозван")
        if row.expires_at is not None and row.expires_at <= utcnow():
            raise UnauthorizedError("срок действия ключа истёк")
        principal = Principal(
            kind="api_key",
            key_id=row.key_id,
            owner_ref=row.owner_ref,
            scopes=set(row.scopes or []),
            label=row.label,
            rate_limit_per_minute=row.rate_limit_per_minute,
            concurrent_requests=row.concurrent_requests,
            tokens_per_day=row.tokens_per_day,
            key_hash_hex=crypto.key_fingerprint(row.key_prefix + ":" + row.key_id),
        )
        row.last_used_at = utcnow()
        await session.flush()
        return principal

    def authenticate_admin(self, authorization: str | None, *, write: bool = False) -> Principal:
        """Отдельная аутентификация админ-контура (§9.6)."""
        token = _extract_bearer(authorization)
        admin = self.settings.auth
        if admin.admin_token and _timing_safe_equal(token, admin.admin_token):
            principal = Principal(kind="admin", scopes=set(ROLE_SCOPES["admin"]), label="admin-token")
        elif admin.auditor_token and _timing_safe_equal(token, admin.auditor_token):
            principal = Principal(kind="auditor", scopes=set(ROLE_SCOPES["auditor"]), label="auditor-token")
        elif admin.owner_token and _timing_safe_equal(token, admin.owner_token):
            if not admin.owner_ref:
                raise ForbiddenError("owner-токен настроен без auth.owner_ref: невозможно определить владельца")
            principal = Principal(kind="owner", scopes=set(ROLE_SCOPES["owner"]), label="owner-token", owner_ref=admin.owner_ref)
        else:
            raise UnauthorizedError("административный доступ требует отдельного токена")
        if write and Scope.ADMIN_WRITE.value not in principal.scopes:
            raise ForbiddenError("роль только для чтения")
        return principal

    # ------------------------------------------------------------------ #
    # Жизненный цикл ключей
    # ------------------------------------------------------------------ #

    async def issue_key(
        self,
        session: AsyncSession,
        *,
        label: str = "",
        scopes: list[str] | None = None,
        owner_ref: str = "",
        rate_limit_per_minute: int = 0,
        concurrent_requests: int = 0,
        tokens_per_day: int = 0,
        ttl_seconds: int | None = None,
    ) -> tuple[ApiKeyRow, str]:
        allowed = {s.value for s in Scope}
        chosen = [s for s in (scopes or self.settings.auth.default_scopes) if s in allowed]
        if not chosen:
            chosen = list(self.settings.auth.default_scopes)
        for scope in chosen:
            if scope in {Scope.ADMIN_WRITE.value, Scope.ADMIN_READ.value}:
                raise ForbiddenError("административные скоупы выдаёт только администратор (отдельным токеном)")
        raw = crypto.generate_api_key(self.settings.auth.key_prefix)
        row = ApiKeyRow(
            key_id=key_id(),
            key_hash=crypto.hash_api_key(raw, pepper=self.settings.auth.bcrypt_like_pepper),
            key_prefix=raw[:12],
            label=label[:120],
            owner_ref=owner_ref[:64],
            scopes=chosen,
            rate_limit_per_minute=rate_limit_per_minute,
            concurrent_requests=concurrent_requests,
            tokens_per_day=tokens_per_day,
            expires_at=utcnow() + timedelta(seconds=ttl_seconds) if ttl_seconds else None,
        )
        session.add(row)
        await session.flush()
        log.info("auth:key_issued", extra={"foa": {"event": "auth.key_issued", "key_id": row.key_id, "scopes": chosen}})
        return row, raw

    async def rotate_key(self, session: AsyncSession, key_id_: str) -> tuple[ApiKeyRow, str]:
        row = await session.get(ApiKeyRow, key_id_)
        if row is None:
            raise UnauthorizedError("ключ не найден")
        grace = self.settings.auth.key_rotation_grace_seconds
        new_row, raw = await self.issue_key(
            session,
            label=row.label,
            scopes=list(row.scopes or []),
            owner_ref=row.owner_ref,
            rate_limit_per_minute=row.rate_limit_per_minute,
            concurrent_requests=row.concurrent_requests,
            tokens_per_day=row.tokens_per_day,
        )
        new_row.rotates_from = row.key_id
        row.expires_at = utcnow() + timedelta(seconds=grace)
        await session.flush()
        log.info("auth:key_rotated", extra={"foa": {"event": "auth.key_rotated", "key_id": new_row.key_id, "from": key_id_}})
        return new_row, raw

    async def revoke_key(self, session: AsyncSession, key_id_: str) -> None:
        from foa.storage.repositories import ApiKeyRepository

        await ApiKeyRepository.revoke(session, key_id_)
        log.info("auth:key_revoked", extra={"foa": {"event": "auth.key_revoked", "key_id": key_id_}})

    # ------------------------------------------------------------------ #
    # Приватность клиента (§8.5.3)
    # ------------------------------------------------------------------ #

    def client_hash(self, client_ip: str) -> str:
        """Псевдоним клиента вместо реального IP (forward_client_ip=false)."""
        salt = self.settings.security.client_hash_salt
        import hashlib

        return "sha256:" + hashlib.sha256(f"{salt}|{client_ip}".encode()).hexdigest()


class _ApiKeyLookup:
    """Отдельный метод, чтобы не тянуть репозиторий в верхний импорт."""

    @staticmethod
    async def by_hash(session: AsyncSession, key_hash: bytes) -> ApiKeyRow | None:
        from foa.storage.repositories import ApiKeyRepository

        return await ApiKeyRepository.by_hash(session, key_hash)


async def asyncio_sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)


def principal_from_row(row: ApiKeyRow, *, scopes: set[str] | None = None) -> Principal:
    return Principal(
        kind="api_key",
        key_id=row.key_id,
        owner_ref=row.owner_ref,
        scopes=set(scopes or row.scopes or []),
        label=row.label,
        rate_limit_per_minute=row.rate_limit_per_minute,
        concurrent_requests=row.concurrent_requests,
        tokens_per_day=row.tokens_per_day,
    )


def consent_required_scope(scope: str) -> bool:
    return scope in {Scope.OLLAMA_GENERATE.value, Scope.OLLAMA_EMBED.value, Scope.OLLAMA_READ.value}


__all__ = ["ROLE_SCOPES", "AuthService", "Principal", "consent_required_scope", "principal_from_row"]
