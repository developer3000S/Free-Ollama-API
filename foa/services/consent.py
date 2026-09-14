"""Consent Registry — подтверждение владения узлом и согласия (§5).

Без ``verified``-согласия узел физически не может попасть в пул маршрутизации:
проверка выполняется в трёх местах — при выдаче статуса, при выборе узла
балансировщиком и при каждом активном health-check (§5.4, FR-C-01…FR-C-05).

Способы подтверждения (минимум два обязательных + третий, §5.3):

* ``http_well_known`` — файл ``/.well-known/free-ollama/v1/consent.json``;
* ``dns_txt`` — TXT ``_free-ollama-challenge.<host>``;
* ``signed_token`` — JWT/JWS с подписью Ed25519 публичным ключом владельца.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from foa.config import Settings
from foa.domain.enums import ConsentMethod, ConsentStatus, NodeState
from foa.domain.errors import ConsentRequiredError, InvalidRequestError, NotFoundError, UpstreamError
from foa.ids import challenge_token, consent_id, node_id
from foa.logging import get_logger
from foa.net.client import NodeTransport
from foa.net.security import Endpoint, parse_endpoint
from foa.storage.models import ConsentRow, NodeRow, utcnow
from foa.storage.repositories import BlacklistRepository, ConsentRepository, NodeRepository, OwnerRepository

log = get_logger("consent")

CONSENT_PATH = "/.well-known/free-ollama/v1/consent.json"
DNS_PREFIX = "_free-ollama-challenge."
TOKEN_AUDIENCE = "free-ollama-gateway"
#: Имя алгоритма по RFC 8037 для ключей Ed25519 (как его регистрирует PyJWT).
JWT_ALGORITHM = "EdDSA"
EXPIRY_WARN_WINDOW = timedelta(days=7)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def parse_dt(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return _aware(value)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return _aware(datetime.fromisoformat(text))
    except ValueError:
        return None


@dataclass(slots=True)
class ConsentProof:
    """Результат проверки способа подтверждения владения."""

    ok: bool
    method: str
    detail: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    #: True — доказательство получить не удалось из-за недоступности узла
    #: (сеть/таймаут/5xx). Это НЕ признак отзыва согласия: решение о состоянии
    #: принимает health-checker по liveness (§6.4), а не consent-реестр (§5.4).
    inconclusive: bool = False

    @property
    def capabilities(self) -> dict[str, Any]:
        return self.detail.get("capabilities") or {}

    @property
    def allowed_models(self) -> list[str]:
        caps = self.capabilities
        models = caps.get("models")
        return [str(m) for m in models] if isinstance(models, list) else []

    @property
    def max_concurrency(self) -> int | None:
        value = self.capabilities.get("max_concurrency")
        return int(value) if isinstance(value, (int, float)) and value else None


class ConsentService:
    def __init__(self, settings: Settings, transport: NodeTransport, dns_resolver=None) -> None:
        self.settings = settings
        self.transport = transport
        self.dns_resolver = dns_resolver  # инъекция для тестов
        self._clock_skew = timedelta(seconds=60)

    # ------------------------------------------------------------------ #
    # Регистрация
    # ------------------------------------------------------------------ #

    async def enroll(
        self,
        session: AsyncSession,
        *,
        endpoint: str,
        owner_ref: str,
        display_name: str = "",
        models: list[str] | None = None,
        max_concurrency: int = 2,
        max_requests_per_hour: int = 1000,
        consent_method: str = ConsentMethod.HTTP_WELL_KNOWN.value,
        data_policy: dict[str, Any] | None = None,
        contact: str = "",
        public_key: str = "",
        weight: int = 1,
    ) -> tuple[NodeRow, ConsentRow]:
        """Создаёт узел в состоянии ``pending_consent`` и выдаёт вызов владельцу (§9.6.2)."""
        parsed = parse_endpoint(endpoint)
        if self.settings.security.require_tls_for_nodes and parsed.scheme != "https":
            raise InvalidRequestError("политика shлюза требует TLS для узлов (security.require_tls_for_nodes)")
        if await BlacklistRepository.is_endpoint_blocked(session, parsed.origin):
            raise InvalidRequestError("адрес узла находится в блэклисте")

        existing = await NodeRepository.by_endpoint(session, parsed.origin)
        if existing is not None:
            raise InvalidRequestError(f"узел с таким адресом уже зарегистрирован ({existing.node_id})")

        owner = await OwnerRepository.get_or_create(
            session, owner_ref, contact=contact, display_name=display_name, public_key=public_key
        )
        token = challenge_token()
        node = NodeRow(
            node_id=node_id(),
            endpoint=parsed.origin,
            scheme=parsed.scheme,
            host=parsed.host,
            port=parsed.port,
            display_name=display_name,
            owner_id=owner.owner_id,
            status=NodeState.PENDING_CONSENT.value,
            declared_models=list(models or []),
            allowed_models=list(models or []),
            max_concurrency=max_concurrency,
            max_requests_per_hour=max_requests_per_hour,
            weight=weight,
            effective_weight=weight,
            challenge_token=token,
            challenge_expires_at=utcnow() + timedelta(days=7),
        )
        await NodeRepository.create(session, node)
        consent = ConsentRow(
            consent_id=consent_id(),
            node_id=node.node_id,
            owner_id=owner.owner_id,
            status=ConsentStatus.CHALLENGE_SENT.value,
            method=consent_method,
            allowed_models=list(models or []),
            max_concurrency=max_concurrency,
            max_requests_per_hour=max_requests_per_hour,
            data_policy=data_policy or {"store_prompts": False, "store_responses": False},
            challenge_token=token,
        )
        await ConsentRepository.create(session, consent)
        await ConsentRepository.add_history(session, consent.consent_id, "challenge_sent", actor=owner.owner_id)
        node.consent_id = consent.consent_id
        await session.flush()
        await self._set_status(session, node.node_id, NodeState.CONSENT_CHALLENGE_SENT)
        log.info(
            "consent:challenge_sent",
            extra={"foa": {"event": "consent.challenge_sent", "node_id": node.node_id, "owner_id": owner.owner_id, "method": consent_method}},
        )
        return node, consent

    # ------------------------------------------------------------------ #
    # Проверка владения
    # ------------------------------------------------------------------ #

    async def verify(
        self,
        session: AsyncSession,
        *,
        node_id_: str,
        method: str | None = None,
        signed_token: str | None = None,
        actor: str = "owner",
    ) -> ConsentRow:
        """Проверяет владение и, при успехе, выдаёт ``verified``-согласие и ``verified``-статус."""
        node = await NodeRepository.get_with_owner(session, node_id_)
        if node is None:
            raise NotFoundError(f"узел {node_id_} не найден")
        consent = await ConsentRepository.latest_for_node(session, node.node_id)
        if consent is None:
            raise ConsentRequiredError("для узла не запрошено согласие")
        if not self.settings.security.require_consent:  # невозможно по validate(), защита на будущее
            raise InvalidRequestError("отключение require_consent запрещено")

        chosen = (method or consent.method or ConsentMethod.HTTP_WELL_KNOWN.value).strip()
        endpoint = parse_endpoint(node.endpoint)
        owner = await OwnerRepository.get(session, consent.owner_id)
        proof = await self.verify_proof(
            endpoint=endpoint,
            node=node,
            consent=consent,
            method=chosen,
            signed_token=signed_token,
            owner_public_key=owner.public_key if owner else "",
        )
        if not proof.ok and proof.inconclusive:
            # Недоступность узла — не доказательство отсутствия владения (§5.4 vs §6.4):
            # решение о выводе из rotation принимает health-checker по liveness,
            # а согласие остаётся в прежнем статусе, чтобы не терять уже
            # выданное разрешение из-за сетевого сбоя.
            await ConsentRepository.add_history(
                session,
                consent.consent_id,
                "verification_inconclusive",
                actor=actor,
                detail={"method": chosen, "error": proof.error},
            )
            await session.commit()
            log.warning(
                "consent:verification_inconclusive",
                extra={"foa": {"event": "consent.verification_inconclusive", "node_id": node.node_id, "method": chosen, "error": proof.error}},
            )
            raise UpstreamError(f"не удалось проверить подтверждение: {proof.error}", details={"method": chosen, "retry_allowed": True})
        if not proof.ok:
            consent.status = ConsentStatus.FAILED.value
            await ConsentRepository.update(
                session, consent, event="verification_failed", actor=actor, detail={"method": chosen, "error": proof.error}
            )
            # Ошибка согласия → карантин (§6.4, FR-C-05)
            await self._set_status(session, node.node_id, NodeState.QUARANTINED)
            # Переход фиксируется до выброса ошибки: иначе middleware откатит
            # транзакцию и карантин не будет сохранён (§6.4).
            await session.commit()
            log.warning(
                "consent:verification_failed",
                extra={"foa": {"event": "consent.verification_failed", "node_id": node.node_id, "method": chosen, "error": proof.error}},
            )
            raise ConsentRequiredError(f"подтверждение владения не пройдено: {proof.error}", details={"method": chosen})

        ttl_days = max(1, min(365, int(self.settings.health.consent_recheck_interval_seconds * 90 / 86_400) or 90))
        policy = dict(consent.data_policy or {})
        policy.setdefault("store_prompts", False)
        policy.setdefault("store_responses", False)
        consent.status = ConsentStatus.VERIFIED.value
        consent.issued_at = utcnow()
        consent.expires_at = utcnow() + timedelta(days=ttl_days)
        consent.method = chosen
        consent.challenge_token = node.challenge_token
        consent.proof_snapshot = {k: v for k, v in proof.detail.items() if k in {"gateway_id", "owner_id", "capabilities", "expires_at"}}
        if proof.allowed_models:
            consent.allowed_models = proof.allowed_models
            node.allowed_models = proof.allowed_models
        if proof.max_concurrency:
            consent.max_concurrency = min(consent.max_concurrency, proof.max_concurrency)
            node.max_concurrency = min(node.max_concurrency, proof.max_concurrency)
        consent.data_policy = policy
        consent.signature = str(proof.detail.get("signature") or "")
        await ConsentRepository.update(session, consent, event="verified", actor=actor, detail={"method": chosen})
        await self._set_status(session, node.node_id, NodeState.VERIFIED)
        log.info(
            "consent:verified",
            extra={"foa": {"event": "consent.verified", "node_id": node.node_id, "owner_id": consent.owner_id, "method": chosen, "expires_at": consent.expires_at.isoformat()}},
        )
        return consent

    async def verify_proof(
        self,
        *,
        endpoint: Endpoint,
        node: NodeRow,
        consent: ConsentRow,
        method: str,
        signed_token: str | None = None,
        owner_public_key: str = "",
    ) -> ConsentProof:
        if method == ConsentMethod.HTTP_WELL_KNOWN.value:
            return await self._proof_http(endpoint, node, consent)
        if method == ConsentMethod.DNS_TXT.value:
            return await self._proof_dns(endpoint, node, consent)
        if method == ConsentMethod.SIGNED_TOKEN.value:
            return self._proof_signed_token(node, consent, signed_token, owner_public_key)
        return ConsentProof(ok=False, method=method, error=f"неизвестный способ подтверждения {method!r}")

    async def _proof_http(self, endpoint: Endpoint, node: NodeRow, consent: ConsentRow) -> ConsentProof:
        try:
            status, _, body = await self.transport.request(
                endpoint, "GET", CONSENT_PATH, timeout=self.settings.health.readiness_timeout_seconds, max_concurrency=node.max_concurrency
            )
        except Exception as exc:
            return ConsentProof(
                ok=False, method="http_well_known", error=f"не удалось получить файл согласия: {exc}", inconclusive=True
            )
        if status == 404:
            # §5.5 — удаление файла согласия владельцем является способом отзыва.
            return ConsentProof(ok=False, method="http_well_known", error="файл согласия удалён владельцем (404)")
        if status in (401, 403):
            return ConsentProof(ok=False, method="http_well_known", error=f"узел запретил доступ к файлу согласия ({status})")
        if status != 200:
            return ConsentProof(ok=False, method="http_well_known", error=f"файл согласия вернул HTTP {status}", inconclusive=True)
        try:
            doc = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ConsentProof(ok=False, method="http_well_known", error="файл согласия не является корректным JSON")
        if not isinstance(doc, dict):
            return ConsentProof(ok=False, method="http_well_known", error="файл согласия должен быть JSON-объектом")
        errors: list[str] = []
        if doc.get("node_id") != node.node_id:
            errors.append("node_id не совпадает")
        if doc.get("challenge") != node.challenge_token:
            errors.append("challenge не совпадает")
        if doc.get("gateway_id") not in (self.settings.gateway_id, None, ""):
            errors.append(f"gateway_id не совпадает ({doc.get('gateway_id')})")
        if doc.get("owner_id") not in (consent.owner_id, None, ""):
            errors.append("owner_id не совпадает")
        expiry = parse_dt(doc.get("expires_at"))
        if expiry is None:
            errors.append("отсутствует или некорректен expires_at")
        elif expiry < utcnow():
            errors.append("срок действия файла согласия истёк")
        if errors:
            return ConsentProof(ok=False, method="http_well_known", detail=doc, error="; ".join(errors))
        return ConsentProof(ok=True, method="http_well_known", detail=doc)

    async def _proof_dns(self, endpoint: Endpoint, node: NodeRow, consent: ConsentRow) -> ConsentProof:
        if endpoint.is_ip:
            return ConsentProof(ok=False, method="dns_txt", error="для узла с IP-адресом недоступен DNS TXT-метод")
        name = f"{DNS_PREFIX}{endpoint.host}"
        records = await self._lookup_txt(name)
        if records is None:
            return ConsentProof(ok=False, method="dns_txt", error=f"не удалось выполнить DNS-запрос {name}", inconclusive=True)
        if not records:
            return ConsentProof(ok=False, method="dns_txt", error=f"TXT-запись {name} не найдена")
        for text in records:
            parsed = _parse_kv(text)
            if parsed.get("gateway") not in (self.settings.gateway_id, None):
                continue
            if parsed.get("node") != node.node_id:
                continue
            if parsed.get("challenge") != node.challenge_token:
                continue
            expiry = parse_dt(parsed.get("exp"))
            if expiry is None or expiry < utcnow():
                return ConsentProof(ok=False, method="dns_txt", detail=parsed, error="срок действия DNS-подтверждения истёк")
            return ConsentProof(ok=True, method="dns_txt", detail={**parsed, "raw": text})
        return ConsentProof(ok=False, method="dns_txt", error=f"ни одна TXT-запись {name} не подтверждает владение")

    async def _lookup_txt(self, name: str) -> list[str] | None:
        if self.dns_resolver is not None:
            try:
                result = self.dns_resolver(name)
                if asyncio.iscoroutine(result):
                    result = await result
                return [str(r) for r in (result or [])]
            except Exception as exc:
                log.debug("consent: dns lookup failed for %s: %s", name, exc)
                return []
        try:
            import dns.resolver

            answers = await asyncio.to_thread(lambda: list(dns.resolver.resolve(name, "TXT")))
            out: list[str] = []
            for answer in answers:
                for chunk in getattr(answer, "strings", []):
                    out.append(chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk))
            return out
        except Exception as exc:
            log.debug("consent: dns lookup failed for %s: %s", name, exc)
            return []

    def _proof_signed_token(
        self, node: NodeRow, consent: ConsentRow, signed_token: str | None, owner_public_key: str
    ) -> ConsentProof:
        if not signed_token:
            return ConsentProof(ok=False, method="signed_token", error="не передан подписанный токен")
        if not owner_public_key:
            return ConsentProof(ok=False, method="signed_token", error="у владельца не зарегистрирован публичный ключ")
        try:
            claims = verify_consent_token(
                signed_token, public_key=owner_public_key, gateway_id=self.settings.gateway_id, node_id_=node.node_id
            )
        except InvalidRequestError as exc:
            return ConsentProof(ok=False, method="signed_token", error=str(exc))
        if claims.get("owner_id") != consent.owner_id:
            return ConsentProof(ok=False, method="signed_token", detail=claims, error="owner_id в токене не совпадает")
        return ConsentProof(ok=True, method="signed_token", detail={**claims, "signature": signed_token})

    # ------------------------------------------------------------------ #
    # Перепроверка и отзыв
    # ------------------------------------------------------------------ #

    async def revalidate(self, session: AsyncSession, node: NodeRow, consent: ConsentRow) -> ConsentProof:
        """§5.4 — периодическая перепроверка актуальности согласия."""
        if _aware(consent.expires_at) is None or _aware(consent.expires_at) <= utcnow():
            return ConsentProof(ok=False, method=consent.method, error="consent_expired")
        endpoint = parse_endpoint(node.endpoint)
        owner = await OwnerRepository.get(session, consent.owner_id)
        proof = await self.verify_proof(
            endpoint=endpoint, node=node, consent=consent, method=consent.method, owner_public_key=owner.public_key if owner else ""
        )
        if proof.ok and consent.status == ConsentStatus.VERIFIED.value:
            await ConsentRepository.add_history(session, consent.consent_id, "revalidated", detail={"method": consent.method})
        return proof

    async def revoke(
        self,
        session: AsyncSession,
        node: NodeRow,
        *,
        reason: str = "owner_revoked",
        actor: str = "owner",
    ) -> ConsentRow:
        """Отзыв согласия (§5.5). Узел убирается из маршрутизации немедленно (<=5 с)."""
        consent = await ConsentRepository.latest_for_node(session, node.node_id)
        if consent is None:
            raise NotFoundError(f"для узла {node.node_id} нет записи согласия")
        if consent.status != ConsentStatus.REVOKED.value:
            await ConsentRepository.revoke(session, consent, reason=reason, actor=actor)
        await self._set_status(session, node.node_id, NodeState.REVOKED)
        consent.status = ConsentStatus.REVOKED.value
        log.info(
            "consent:revoked",
            extra={"foa": {"event": "consent.revoked", "node_id": node.node_id, "actor": actor, "reason": reason}},
        )
        return consent

    @staticmethod
    async def _set_status(session: AsyncSession, node_id_: str, state: NodeState) -> None:
        await NodeRepository.set_status(session, node_id_, state.value)

    @staticmethod
    def consent_is_active(consent: ConsentRow | None, now: datetime | None = None) -> bool:
        """Единая точка истины для балансировщика и health-checker'а (§7.2)."""
        if consent is None:
            return False
        now = now or utcnow()
        if consent.status != ConsentStatus.VERIFIED.value:
            return False
        expires = _aware(consent.expires_at)
        return bool(expires is None or expires > now)


def _parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in text.split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            out[key.strip()] = value.strip()
    return out


def consent_document(node: NodeRow, consent: ConsentRow, gateway_id: str, ttl_days: int = 7) -> dict[str, Any]:
    """Генерирует содержимое файла согласия для размещения владельцем (§5.3.1)."""
    return {
        "node_id": node.node_id,
        "challenge": node.challenge_token,
        "gateway_id": gateway_id,
        "owner_id": consent.owner_id,
        "expires_at": (utcnow() + timedelta(days=ttl_days)).isoformat().replace("+00:00", "Z"),
        "capabilities": {
            "models": list(node.allowed_models or node.declared_models or []),
            "max_concurrency": node.max_concurrency,
        },
    }


def build_signed_token(
    *,
    private_key_pem: str,
    node_id_: str,
    owner_id_: str,
    gateway_id: str,
    capabilities: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    ttl_seconds: int = 3600,
) -> str:
    """Утилита владельческого CLI: подписанный JWT (Ed25519) для §5.3.3.

    Имя алгоритма в JWT (RFC 8037) — ``EdDSA``; PyJWT выбирает Ed25519 по
    типу ключа.
    """
    import jwt

    now = int(datetime.now(UTC).timestamp())
    claims = {
        "node_id": node_id_,
        "owner_id": owner_id_,
        "gateway_id": gateway_id,
        "aud": TOKEN_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "capabilities": capabilities or {},
        "policy": policy or {},
    }
    return jwt.encode(claims, private_key_pem, algorithm=JWT_ALGORITHM)


def verify_consent_token(token: str, *, public_key: str, gateway_id: str, node_id_: str) -> dict[str, Any]:
    import jwt

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[JWT_ALGORITHM],
            audience=TOKEN_AUDIENCE,
            leeway=60,
            options={"require": ["exp", "iat", "nbf", "node_id", "owner_id", "gateway_id"]},
        )
    except jwt.InvalidTokenError as exc:
        raise InvalidRequestError(f"подписанный токен недействителен: {exc}") from exc
    if claims.get("gateway_id") != gateway_id:
        raise InvalidRequestError("gateway_id в токене не совпадает")
    if claims.get("node_id") != node_id_:
        raise InvalidRequestError("node_id в токене не совпадает")
    return claims


__all__ = [
    "CONSENT_PATH",
    "DNS_PREFIX",
    "ConsentProof",
    "ConsentService",
    "build_signed_token",
    "consent_document",
    "verify_consent_token",
]
