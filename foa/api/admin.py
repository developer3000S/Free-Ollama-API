"""Административный API (§9.6) — отдельный контур и отдельная аутентификация.

Доступ: только токены ``admin``/``auditor``/``owner`` из secret manager
(§9.6, §11.5, §17.9). Обычные пользовательские ключи здесь не работают.

Роли (§2.2):

* **admin** — ``admin:write``: узлы, согласия, блэклист, ключи, конфигурация;
* **auditor** — ``admin:read``: журналы и отчёты без права изменения;
* **owner** — регистрация/отзыв собственных узлов.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from foa.api.deps import (
    admin_read,
    admin_write,
    authenticate_admin,
    db_session,
    get_state,
    read_json_body,
    request_id_of,
)
from foa.core.appstate import AppState
from foa.domain.enums import Scope
from foa.domain.errors import ForbiddenError, InvalidRequestError, NotFoundError
from foa.domain.schemas import (
    BlacklistRequest,
    ConsentRequest,
    KeyCreateRequest,
    NodePatchRequest,
    NodeRegisterRequest,
)
from foa.logging import get_logger
from foa.services.auth import Principal
from foa.services.consent import CONSENT_PATH, consent_document
from foa.storage.models import utcnow
from foa.storage.repositories import (
    ApiKeyRepository,
    AuditRepository,
    BlacklistRepository,
    CandidateRepository,
    ConsentRepository,
    NodeRepository,
)

router = APIRouter(tags=["admin"])
log = get_logger("api.admin")

MAX_ADMIN_BODY = 262_144


async def _require(request: Request, principal: Principal, scope: str) -> Principal:
    """Проверка скоупа + запрет «пользовательский ключ в админке» (§17.9)."""
    if principal.kind == "api_key":
        raise ForbiddenError("административный контур недоступен для пользовательских ключей")
    if scope not in principal.scopes:
        raise ForbiddenError(f"требуется {scope}")
    return principal


async def require_owner_or_admin(
    request: Request, state: AppState = Depends(get_state)
) -> Principal:
    """Допускает администратора и владельца (регистрация узла, §9.6.2)."""
    principal = await authenticate_admin(request, state, write=False)
    if principal.kind == "admin":
        return principal
    if principal.kind == "owner" and Scope.NODE_SELF_SERVICE.value in principal.scopes:
        return principal
    raise ForbiddenError("регистрация узлов доступна администратору и владельцу")


def require_node_write(param: str = "node_id"):
    """Допускает администратора либо владельца узла из пути запроса (§2.2, §5.5).

    Владелец управляет только своими узлами: подтверждение владения, отзыв
    согласия, удаление своих данных. Ключи, блэклист и конфигурация остаются
    прерогативой администратора (§9.6).
    """

    async def _dep(
        request: Request,
        state: AppState = Depends(get_state),
        session: AsyncSession = Depends(db_session),
    ) -> Principal:
        principal = await authenticate_admin(request, state, write=False)
        if principal.kind == "admin":
            return principal
        if principal.kind != "owner" or Scope.NODE_SELF_SERVICE.value not in principal.scopes:
            raise ForbiddenError("операция доступна администратору или владельцу узла")
        target = request.path_params.get(param, "")
        row = await NodeRepository.get(session, target)
        if row is None:
            raise NotFoundError(f"узел {target} не найден")
        if row.owner_id != principal.owner_ref:
            raise ForbiddenError("узел принадлежит другому владельцу")
        return principal

    return _dep


node_writer = require_node_write("node_id")


def resolve_owner_identity(principal: Principal, requested_owner: str = "") -> str:
    """Идентичность владельца узла (§5.1 п.1, §2.2).

    Владелец регистрирует узлы только под своей идентичностью; администратор
    может указать любого владельца либо предоставить шлюзу сгенерировать
    идентификатор.
    """
    if principal.kind == "owner":
        if not principal.owner_ref:
            raise ForbiddenError("owner-токен не связан с идентичностью владельца (auth.owner_ref)")
        if requested_owner and requested_owner != principal.owner_ref:
            raise ForbiddenError("владелец не может зарегистрировать узел на другого владельца")
        return principal.owner_ref
    return requested_owner or principal.audit_actor()


def _ok(payload: dict[str, Any], request_id: str, status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers={"X-FOA-Request-ID": request_id})


# --------------------------------------------------------------------------- #
# Узлы (§9.6.1–§9.6.4)
# --------------------------------------------------------------------------- #


@router.get("/admin/nodes")
async def list_nodes(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
    status: str | None = Query(default=None, max_length=32),
    detailed: bool = Query(default=False),
) -> JSONResponse:
    if status:
        await _require(request, principal, Scope.ADMIN_READ.value)
    rows = await state.nodes.list_nodes(session, states=[status] if status else None)
    nodes: list[dict[str, Any]] = []
    for row in rows:
        runtime = state.pool.get(row.node_id)
        consent = await ConsentRepository.latest_for_node(session, row.node_id)
        entry: dict[str, Any] = {
            "node_id": row.node_id,
            "status": row.status,
            "consent_status": consent.status if consent else "none",
            "models": row.observed_models or row.allowed_models or row.declared_models,
            "active_connections": runtime.active if runtime else 0,
            "max_concurrency": row.max_concurrency,
            "latency_ms": round(runtime.ewma_latency_ms, 2) if runtime else row.ewma_latency_ms,
            "error_rate": round(runtime.error_rate, 4) if runtime else row.error_rate,
            "last_health_check": row.last_health_check.isoformat().replace("+00:00", "Z") if row.last_health_check else None,
            "routable": bool(runtime.routable) if runtime else False,
        }
        # Адрес и владелец раскрываются только привилегированным ролям (§9.3.2).
        if detailed or principal.kind in {"admin", "owner"}:
            entry.update(
                {
                    "endpoint": row.endpoint,
                    "display_name": row.display_name,
                    "owner_id": row.owner_id,
                    "ollama_version": row.ollama_version,
                    "weight": row.weight,
                    "effective_weight": row.effective_weight,
                }
            )
        nodes.append(entry)
    return _ok({"nodes": nodes, "total": len(nodes)}, request_id_of(request))


@router.post("/admin/nodes", status_code=201)
async def register_node(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(require_owner_or_admin),
) -> JSONResponse:
    """``POST /admin/nodes`` — регистрация узла владельцем (§9.6.2)."""
    body = await read_json_body(request, MAX_ADMIN_BODY)
    try:
        parsed = NodeRegisterRequest.model_validate(body)
    except Exception as exc:
        raise InvalidRequestError(_schema_error(exc)) from exc
    owner_ref = resolve_owner_identity(principal, parsed.owner_id)
    actor = _actor_ref(principal)
    node, challenge, consent_url = await state.nodes.register(
        session,
        endpoint=parsed.endpoint,
        owner_ref=owner_ref,
        display_name=parsed.display_name,
        models=parsed.models,
        max_concurrency=parsed.max_concurrency,
        max_requests_per_hour=parsed.max_requests_per_hour,
        consent_method=parsed.consent_method,
        data_policy=parsed.data_policy,
        weight=parsed.weight,
        actor=actor,
    )
    await session.commit()
    return _ok(
        {
            "node_id": node.node_id,
            "status": node.status,
            "challenge": challenge,
            "consent_url": consent_url,
            "consent_method": parsed.consent_method,
            "next_step": (
                f"разместите файл согласия по адресу {node.endpoint}{CONSENT_PATH} "
                "и вызовите POST /admin/nodes/{node_id}/verify"
            ),
        },
        request_id_of(request),
        status=201,
    )


@router.get("/admin/nodes/{node_id}")
async def get_node(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_READ.value)
    return _ok(await state.nodes.detail(session, node_id), request_id_of(request))


@router.patch("/admin/nodes/{node_id}")
async def patch_node(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    body = await read_json_body(request, MAX_ADMIN_BODY)
    parsed = NodePatchRequest.model_validate(body)
    result = await state.nodes.patch(session, node_id, actor=_actor_ref(principal), **parsed.model_dump(exclude_none=True))
    await session.commit()
    return _ok(result, request_id_of(request))


@router.delete("/admin/nodes/{node_id}", status_code=200)
async def delete_node(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(node_writer),
) -> JSONResponse:
    """Удаление узла и связанных данных по запросу владельца (§4.7, §12.7.7)."""
    result = await state.nodes.delete(session, node_id, actor=_actor_ref(principal))
    await session.commit()
    return _ok(result, request_id_of(request))


@router.post("/admin/nodes/{node_id}/verify")
async def verify_node(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(node_writer),
) -> JSONResponse:
    """Подтверждение владения (§5.3). Тело: ``{"method": "...", "signed_token": "..."}``."""
    body = await read_json_body(request, MAX_ADMIN_BODY)
    method = str(body.get("method") or "").strip() or None
    signed_token = str(body.get("signed_token") or "").strip() or None
    result = await state.nodes.verify_ownership(session, node_id, method=method, signed_token=signed_token, actor=_actor_ref(principal))
    await session.commit()
    return _ok(result, request_id_of(request))


@router.post("/admin/nodes/{node_id}/consent-document")
async def node_consent_document(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(node_writer),
) -> JSONResponse:
    """Генерирует содержимое consent.json, которое владельцу нужно разместить на узле (§5.3.1)."""
    node = await state.nodes.get_node(session, node_id)
    consent = await ConsentRepository.latest_for_node(session, node.node_id)
    if consent is None:
        raise NotFoundError(f"для узла {node_id} нет записи согласия")
    document = consent_document(node, consent, state.settings.gateway_id)
    return _ok(
        {
            "path": CONSENT_PATH,
            "document": document,
            "instruction": f"разместите JSON по адресу {node.endpoint}{CONSENT_PATH}, затем вызовите /admin/nodes/{node_id}/verify",
        },
        request_id_of(request),
    )


@router.post("/admin/nodes/{node_id}/revoke")
async def revoke_node(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(node_writer),
) -> JSONResponse:
    """Отзыв согласия (§5.5, §9.6.3). Узел исключается из маршрутизации немедленно."""
    body = await read_json_body(request, MAX_ADMIN_BODY)
    reason = str(body.get("reason") or "owner_revoked")[:120]
    result = await state.nodes.revoke_consent(session, node_id, reason=reason, actor=_actor_ref(principal))
    await session.commit()
    return _ok({"node_id": result["node_id"], "status": "revoked", "applied_in_seconds": result["applied_in_seconds"]}, request_id_of(request))


@router.post("/admin/nodes/{node_id}/blacklist")
async def blacklist_node(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Ручная блокировка узла (§9.6.4, §6.4)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    body = await read_json_body(request, MAX_ADMIN_BODY)
    parsed = BlacklistRequest.model_validate(body) if body else BlacklistRequest()
    result = await state.nodes.blacklist(
        session,
        node_id,
        reason=parsed.reason,
        duration=parsed.duration,
        seconds=parsed.seconds,
        note=parsed.note,
        actor=_actor_ref(principal),
    )
    await session.commit()
    return _ok(result, request_id_of(request))


@router.post("/admin/nodes/{node_id}/unblacklist")
async def unblacklist_node(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    result = await state.nodes.lift_blacklist(session, node_id, actor=_actor_ref(principal))
    await session.commit()
    return _ok(result, request_id_of(request))


@router.post("/admin/nodes/{node_id}/health-check")
async def force_health_check(
    node_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Принудительная внецикловая проверка узла (§6.2)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    row = await state.nodes.get_node(session, node_id)
    runtime = state.pool.get(node_id)
    changed = await state.health.force_check(session, row, runtime)
    await state.nodes.sync_pool(session)
    await session.commit()
    return _ok({"node_id": node_id, "status": row.status, "runtime": runtime.snapshot() if runtime else None, "transition": bool(changed)}, request_id_of(request))


# --------------------------------------------------------------------------- #
# Согласия (§9.6.5, §5.2)
# --------------------------------------------------------------------------- #


@router.put("/admin/owners/{owner_id}/public-key")
async def set_owner_public_key(
    owner_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Регистрация публичного ключа владельца для signed_token-подтверждения (§5.3.3)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    body = await read_json_body(request, MAX_ADMIN_BODY)
    public_key = str(body.get("public_key") or "").strip()
    key_type = str(body.get("key_type") or "ed25519")
    if not public_key or len(public_key) > 4096:
        raise InvalidRequestError("требуется корректный public_key (PEM либо base64 Ed25519)")
    from foa.services.crypto import load_ed25519_public_key

    try:
        load_ed25519_public_key(public_key)
    except Exception as exc:
        raise InvalidRequestError(f"публичный ключ не распознан: {exc}") from exc
    await state.nodes.set_public_key(session, owner_id, public_key, key_type=key_type)
    await session.commit()
    return _ok({"owner_id": owner_id, "key_type": key_type, "status": "registered"}, request_id_of(request))


@router.get("/admin/consents")
async def list_consents(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
    status: str | None = Query(default=None, max_length=32),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_READ.value)
    rows = await ConsentRepository.list_all(session, status=status)
    return _ok(
        {
            "consents": [
                {
                    "consent_id": row.consent_id,
                    "node_id": row.node_id,
                    "owner_id": row.owner_id,
                    "status": row.status,
                    "method": row.method,
                    "issued_at": row.issued_at.isoformat().replace("+00:00", "Z") if row.issued_at else None,
                    "expires_at": row.expires_at.isoformat().replace("+00:00", "Z") if row.expires_at else None,
                    "allowed_models": row.allowed_models,
                    "max_concurrency": row.max_concurrency,
                    "max_requests_per_hour": row.max_requests_per_hour,
                    "data_policy": row.data_policy,
                    "signature": "***" if row.signature else "",
                }
                for row in rows
            ]
        },
        request_id_of(request),
    )


@router.get("/admin/consents/{consent_id}")
async def get_consent(
    consent_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
) -> JSONResponse:
    """``GET /admin/consents/{consent_id}`` (§9.6.5) с историей изменений (§3.2.3)."""
    await _require(request, principal, Scope.ADMIN_READ.value)
    consent = await ConsentRepository.get_full(session, consent_id)
    if consent is None:
        raise NotFoundError(f"согласие {consent_id} не найдено")
    return _ok(
        {
            "consent_id": consent.consent_id,
            "node_id": consent.node_id,
            "owner_id": consent.owner_id,
            "status": consent.status,
            "method": consent.method,
            "issued_at": consent.issued_at.isoformat().replace("+00:00", "Z") if consent.issued_at else None,
            "expires_at": consent.expires_at.isoformat().replace("+00:00", "Z") if consent.expires_at else None,
            "allowed_models": consent.allowed_models,
            "max_concurrency": consent.max_concurrency,
            "max_requests_per_hour": consent.max_requests_per_hour,
            "data_policy": consent.data_policy,
            "signature": consent.signature or "",
            "revoked_at": consent.revoked_at.isoformat().replace("+00:00", "Z") if consent.revoked_at else None,
            "revoke_reason": consent.revoke_reason,
            "version": consent.version,
            "history": [
                {
                    "event": item.event,
                    "actor": item.actor,
                    "created_at": item.created_at.isoformat().replace("+00:00", "Z"),
                    "detail": item.detail,
                }
                for item in consent.history
            ],
        },
        request_id_of(request),
    )


@router.post("/admin/consents")
async def submit_consent(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Явная подача согласия владельцем (§5.1) с указанием метода подтверждения."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    body = await read_json_body(request, MAX_ADMIN_BODY)
    parsed = ConsentRequest.model_validate(body)
    node = await NodeRepository.get(session, parsed.node_id)
    if node is None:
        raise NotFoundError(f"узел {parsed.node_id} не найден")
    consent = await ConsentRepository.latest_for_node(session, node.node_id)
    if consent is None:
        node, consent = await state.consent.enroll(
            session,
            endpoint=node.endpoint,
            owner_ref=parsed.owner_id,
            display_name=node.display_name,
            models=parsed.allowed_models,
            max_concurrency=parsed.max_concurrency,
            max_requests_per_hour=parsed.max_requests_per_hour,
            consent_method=parsed.method,
            data_policy=parsed.data_policy,
        )
    result = await state.nodes.verify_ownership(
        session, node.node_id, method=parsed.method, signed_token=parsed.signed_token, actor=parsed.owner_id
    )
    await session.commit()
    return _ok(result, request_id_of(request), status=201)


# --------------------------------------------------------------------------- #
# Блэклист (§9.6.6, §12.4.4)
# --------------------------------------------------------------------------- #


@router.get("/admin/blacklist")
async def list_blacklist(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
    include_expired: bool = Query(default=False),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_READ.value)
    rows = await BlacklistRepository.list(session, include_expired=include_expired)
    return _ok(
        {
            "blacklist": [
                {
                    "node_id": row.node_id,
                    "endpoint": row.endpoint,
                    "reason": row.reason,
                    "detail": row.detail,
                    "actor": row.actor,
                    "permanent": row.permanent,
                    "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
                    "expires_at": row.expires_at.isoformat().replace("+00:00", "Z") if row.expires_at else None,
                    "lifted_at": row.lifted_at.isoformat().replace("+00:00", "Z") if row.lifted_at else None,
                }
                for row in rows
            ],
            "active_total": await BlacklistRepository.count_active(session),
        },
        request_id_of(request),
    )


# --------------------------------------------------------------------------- #
# Discovery: кандидаты (§4.4, §4.7) — только админ/аудитор
# --------------------------------------------------------------------------- #


@router.get("/admin/candidates")
async def list_candidates(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
    status: str | None = Query(default=None, max_length=32),
    source: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Список кандидатов. Публичный экспорт полных списков запрещён (§4.7)."""
    await _require(request, principal, Scope.ADMIN_READ.value)
    rows = await CandidateRepository.list(session, status=status, source=source, limit=limit, offset=offset)
    return _ok(
        {
            "candidates": [
                {
                    "candidate_id": row.candidate_id,
                    "source": row.source,
                    "sources": row.sources,
                    "observed_at": row.observed_at.isoformat().replace("+00:00", "Z"),
                    "ip": row.ip,
                    "port": row.port,
                    "protocol": row.protocol,
                    "dns_names": row.dns_names,
                    "asn": row.asn,
                    "country": row.country,
                    "service_hint": row.service_hint,
                    "banner_hash": row.banner_hash,
                    "risk_score": row.risk_score,
                    "risk_factors": row.risk_factors,
                    "status": row.status,
                    "requires_manual_review": row.status == "requires_manual_review",
                    "routable": False,
                }
                for row in rows
            ],
            "total": await CandidateRepository.count(session),
            "note": "кандидаты не используются для маршрутизации (§4.4.4, FR-D-04)",
        },
        request_id_of(request),
    )


@router.post("/admin/discovery/run")
async def run_discovery(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Внеплановый цикл Discovery (только при явных разрешённых источниках)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    sources = state.discovery.active_sources()
    if not sources:
        return _ok(
            {"sources": [], "created": 0, "deduped": 0, "out_of_scope": 0, "manual_review": 0, "purged": 0, "note": "источники выключены или не заданы allowed_scopes (FR-D-07, §4.6)"},
            request_id_of(request),
        )
    summary = await state.discovery.run_cycle(session)
    await AuditRepository.write(session, "discovery.manual_cycle", actor=_actor_ref(principal), subject_type="discovery", detail=summary)
    await session.commit()
    return _ok(summary, request_id_of(request))


@router.delete("/admin/candidates/{candidate_id}")
async def delete_candidate(
    candidate_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Удаление данных кандидата по запросу (§4.7, §12.7.7)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    deleted = await state.discovery.delete_candidate(session, candidate_id)
    if not deleted:
        raise NotFoundError(f"кандидат {candidate_id} не найден")
    await AuditRepository.write(session, "candidate.deleted", actor=_actor_ref(principal), subject_type="candidate", subject_id=candidate_id)
    await session.commit()
    return _ok({"candidate_id": candidate_id, "status": "deleted"}, request_id_of(request))


@router.post("/admin/candidates/{candidate_id}/enroll")
async def enroll_candidate(
    candidate_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Ручная конвертация кандидата в узел **с обязательным вызовом согласия** (§4.3 authorized_enrollment, этап 5)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    if state.settings.discovery.mode == "disabled":
        raise ForbiddenError("Discovery отключён")
    candidate = await CandidateRepository.get(session, candidate_id)
    if candidate is None:
        raise NotFoundError(f"кандидат {candidate_id} не найден")
    body = await read_json_body(request, MAX_ADMIN_BODY)
    owner_ref = str(body.get("owner_id") or "").strip()
    if not owner_ref:
        raise InvalidRequestError("Требуется owner_id: узел нельзя добавить без идентификатора владельца (§5.1 п.1)")
    endpoint = f"{'https' if body.get('tls') else 'http'}://{candidate.ip}:{candidate.port}"
    node, challenge, consent_url = await state.nodes.register(
        session,
        endpoint=endpoint,
        owner_ref=owner_ref,
        models=[str(m) for m in (body.get("models") or [])][:200],
        max_concurrency=int(body.get("max_concurrency") or 2),
        consent_method=str(body.get("consent_method") or "http_well_known"),
        actor=_actor_ref(principal),
    )
    await CandidateRepository.set_status(session, candidate_id, "enrolled", node_id=node.node_id)
    await AuditRepository.write(
        session,
        "candidate.enrolled",
        actor=_actor_ref(principal),
        subject_type="candidate",
        subject_id=candidate_id,
        detail={"node_id": node.node_id, "consent_required": True},
    )
    await session.commit()
    return _ok(
        {
            "candidate_id": candidate_id,
            "node_id": node.node_id,
            "status": node.status,
            "challenge": challenge,
            "consent_url": consent_url,
            "note": "маршрутизация включится только после подтверждения владельцем (§5.1)",
        },
        request_id_of(request),
        status=201,
    )


# --------------------------------------------------------------------------- #
# Ключи доступа (§12.4.1)
# --------------------------------------------------------------------------- #


@router.get("/admin/keys")
async def list_keys(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
    include_revoked: bool = Query(default=False),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_READ.value)
    rows = await ApiKeyRepository.list(session, include_revoked=include_revoked)
    return _ok(
        {
            "keys": [
                {
                    "key_id": row.key_id,
                    "label": row.label,
                    "prefix": row.key_prefix,
                    "scopes": row.scopes,
                    "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
                    "expires_at": row.expires_at.isoformat().replace("+00:00", "Z") if row.expires_at else None,
                    "revoked": row.revoked,
                    "last_used_at": row.last_used_at.isoformat().replace("+00:00", "Z") if row.last_used_at else None,
                    "rate_limit_per_minute": row.rate_limit_per_minute,
                    "tokens_per_day": row.tokens_per_day,
                }
                for row in rows
            ],
            "note": "значения ключей не хранятся и не возвращаются — только хэши (§12.4.1)",
        },
        request_id_of(request),
    )


@router.post("/admin/keys", status_code=201)
async def create_key(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Выдача пользовательского ключа. Показывается один раз (§12.4.1)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    body = await read_json_body(request, MAX_ADMIN_BODY)
    parsed = KeyCreateRequest.model_validate(body)
    row, raw = await state.auth.issue_key(
        session,
        label=parsed.label,
        scopes=parsed.scopes or None,
        rate_limit_per_minute=parsed.rate_limit_per_minute or 0,
        concurrent_requests=parsed.concurrent_requests or 0,
        tokens_per_day=parsed.tokens_per_day or 0,
        ttl_seconds=parsed.ttl_seconds,
    )
    await AuditRepository.write(session, "key.created", actor=_actor_ref(principal), subject_type="key", subject_id=row.key_id, detail={"scopes": row.scopes})
    await session.commit()
    return _ok(
        {
            "key_id": row.key_id,
            "api_key": raw,
            "scopes": row.scopes,
            "label": row.label,
            "expires_at": row.expires_at.isoformat().replace("+00:00", "Z") if row.expires_at else None,
            "note": "сохраните ключ сейчас: повторно он не выдаётся",
        },
        request_id_of(request),
        status=201,
    )


@router.post("/admin/keys/{key_id}/revoke")
async def revoke_key(
    key_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    await state.auth.revoke_key(session, key_id)
    await AuditRepository.write(session, "key.revoked", actor=_actor_ref(principal), subject_type="key", subject_id=key_id)
    await session.commit()
    return _ok({"key_id": key_id, "revoked": True}, request_id_of(request))


@router.post("/admin/keys/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    row, raw = await state.auth.rotate_key(session, key_id)
    await AuditRepository.write(session, "key.rotated", actor=_actor_ref(principal), subject_type="key", subject_id=row.key_id)
    await session.commit()
    return _ok({"key_id": row.key_id, "api_key": raw, "grace_seconds": state.settings.auth.key_rotation_grace_seconds}, request_id_of(request), status=201)


# --------------------------------------------------------------------------- #
# Аудит, безопасность, конфигурация (§11.4, §12.7)
# --------------------------------------------------------------------------- #


@router.get("/admin/audit")
async def read_audit(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
    event: str | None = Query(default=None, max_length=64),
    subject_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=1000),
) -> JSONResponse:
    """Журнал аудита: изменения согласий, блокировки, ключи (§12.7 п.4)."""
    await _require(request, principal, Scope.ADMIN_READ.value)
    rows = await AuditRepository.list(session, event=event, subject_id=subject_id, limit=limit)
    return _ok(
        {
            "entries": [
                {
                    "id": row.id,
                    "event": row.event,
                    "actor": row.actor,
                    "subject_type": row.subject_type,
                    "subject_id": row.subject_id,
                    "request_id": row.request_id,
                    "detail": row.detail,
                    "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
                }
                for row in rows
            ]
        },
        request_id_of(request),
    )


@router.get("/admin/status")
async def gateway_status(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
) -> JSONResponse:
    """Сводка состояния для наблюдения (§11.4, этап 6)."""
    await _require(request, principal, Scope.ADMIN_READ.value)
    counts = await NodeRepository.counts_by_status(session)
    return _ok(
        {
            "gateway_id": state.settings.gateway_id,
            "time": utcnow().isoformat().replace("+00:00", "Z"),
            "nodes_by_status": counts,
            "routable_nodes": sum(1 for n in state.pool.nodes.values() if n.routable),
            "nodes": state.pool.snapshot(),
            "blacklisted": await BlacklistRepository.count_active(session),
            "discovery": {
                "mode": state.settings.discovery.mode,
                "active_sources": state.discovery.active_sources(),
                "candidates": await CandidateRepository.count(session),
            },
            "ratelimit": state.ratelimit.snapshot(),
            "security": {
                "require_consent": state.settings.security.require_consent,
                "route_candidates": state.settings.security.route_candidates,
                "store_prompt_bodies": state.settings.security.store_prompt_bodies,
                "forward_client_ip": state.settings.security.forward_client_ip,
                "active_scanning": state.settings.security.active_scanning,
            },
        },
        request_id_of(request),
    )


@router.get("/admin/config")
async def read_config(
    request: Request,
    state: AppState = Depends(get_state),
    principal: Principal = Depends(admin_read),
) -> JSONResponse:
    """Текущая конфигурация; секреты вырезаны (§4.5 п.3)."""
    await _require(request, principal, Scope.ADMIN_READ.value)
    return _ok(_redacted(state.settings.as_dict()), request_id_of(request))


@router.post("/admin/config/reload")
async def reload_config(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_write),
) -> JSONResponse:
    """Горячая перезагрузка нечувствительных параметров (§11.5)."""
    await _require(request, principal, Scope.ADMIN_WRITE.value)
    from foa.config import HOT_RELOAD_SECTIONS, load_settings

    fresh = load_settings(state.settings.source_path or None)
    applied: list[str] = []
    for section in HOT_RELOAD_SECTIONS:
        if hasattr(fresh, section):
            setattr(state.settings, section, getattr(fresh, section))
            applied.append(section)
    state.ratelimit.refresh(state.settings)
    state.pool.config = state.settings.load_balancer
    await AuditRepository.write(session, "config.reloaded", actor=_actor_ref(principal), subject_type="config", detail={"sections": applied})
    await session.commit()
    return _ok(
        {
            "reloaded": applied,
            "requires_restart": sorted(set(HOT_RELOAD_SECTIONS.symmetric_difference({"security", "auth", "server", "storage", "discovery", "pool"}))),
            "version": fresh.version,
        },
        request_id_of(request),
    )


@router.post("/admin/abuse-reports")
async def submit_abuse_report(
    request: Request,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(admin_read),
) -> JSONResponse:
    """Форма жалоб на злоупотребления (§12.3 п.6, §12.7 п.2)."""
    body = await read_json_body(request, MAX_ADMIN_BODY)
    subject = str(body.get("subject") or body.get("node_id") or "")[:64]
    report = str(body.get("report") or "")[:2000]
    if not subject or not report:
        raise InvalidRequestError("требуется subject и текст report")
    await AuditRepository.write(
        session,
        "abuse.report",
        actor=_actor_ref(principal),
        subject_type="abuse",
        subject_id=subject,
        detail={"summary": report[:300]},
    )
    await session.commit()
    return _ok({"status": "accepted", "subject": subject}, request_id_of(request), status=202)


# --------------------------------------------------------------------------- #


def _actor_ref(principal: Principal) -> str:
    return principal.audit_actor()


_SCALAR_SECRET_KEYS = {"api_key", "api_secret", "admin_token", "auditor_token", "owner_token", "client_hash_salt", "bcrypt_like_pepper", "database_url", "redis_url", "jwt_secret", "public_key"}


def _redacted(payload: Any) -> Any:
    """Убирает секреты из конфигурационного дампа (§12.5.3)."""
    if isinstance(payload, dict):
        return {
            key: ("***" if str(key).lower() in _SCALAR_SECRET_KEYS and value else _redacted(value))
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [_redacted(item) for item in payload]
    return payload


def _schema_error(exc: Exception) -> str:
    """Сообщение без содержимого полей (промпты не попадают в ответ/журнал)."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        parts = sorted({str(err.get("loc", ["?"])[-1]) + ": " + str(err.get("msg", "")) for err in errors()})
        return "invalid request: " + "; ".join(parts[:6])
    return "invalid request"


__all__ = ["router"]
