"""Проксирующий слой (§8).

Порядок обработки запроса (§8.2): метод/путь → аутентификация → лимит → размер
тела → валидация модели → выбор узла → таймауты → пересылка → потоковая
передача → метрики.

Дисциплина повторов (§7.6):

* ``GET /api/version``/``GET /api/tags`` — 1 повтор допустим;
* ``POST /api/generate`` — 1 повтор **только** при ошибке соединения, до начала
  обработки узлом;
* потоковые запросы — повтор запрещён после первого байта;
* повтор выполняется с тем же ``X-FOA-Request-ID``.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from foa.config import Settings
from foa.domain.enums import ErrorCode, NodeState
from foa.domain.errors import (
    GatewayError,
    NoHealthyNodesError,
    UpstreamError,
    UpstreamTimeoutError,
)
from foa.logging import get_logger
from foa.net.client import NodeTransport, StreamedResponse, UpstreamUnavailable
from foa.net.security import parse_endpoint
from foa.observability import metrics
from foa.services.auth import Principal
from foa.services.balancer import NodePool
from foa.services.consent import ConsentService
from foa.services.ratelimit import RateLimiter
from foa.services.state import NodeRuntime
from foa.storage.models import NodeRow, utcnow
from foa.storage.repositories import ConsentRepository, NodeRepository

log = get_logger("proxy")

NDJSON_CONTENT_TYPE = "application/x-ndjson"
#: Заголовки, которые шлюз никогда не передаёт узлу (§8.5.3)
STRIPPED_UPSTREAM_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-forwarded-for",
        "x-forwarded-proto",
        "forwarded",
        "host",
        "connection",
        "keep-alive",
        "content-length",
        "upgrade",
        "te",
        "trailer",
        "transfer-encoding",
    }
)


@dataclass(slots=True)
class ProxyContext:
    request_id: str
    principal: Principal
    started_at: float = field(default_factory=time.monotonic)
    route: str = ""
    model: str = ""
    stream: bool = False
    bytes_in: int = 0
    bytes_out: int = 0
    node_id: str = ""
    attempts: int = 0
    tokens: int = 0
    error_code: str = ""

    @property
    def latency_ms(self) -> float:
        return (time.monotonic() - self.started_at) * 1000.0


@dataclass(slots=True)
class UpstreamResult:
    status: int
    headers: dict[str, str]
    body: bytes
    node_id: str
    attempts: int


class ProxyService:
    def __init__(
        self,
        settings: Settings,
        pool: NodePool,
        transport: NodeTransport,
        ratelimit: RateLimiter,
        node_service=None,
    ) -> None:
        self.settings = settings
        self.pool = pool
        self.transport = transport
        self.ratelimit = ratelimit
        self.nodes = node_service
        self._inflight: dict[str, int] = {}

    # ------------------------------------------------------------------ #
    # Резервирование узла (§7.2)
    # ------------------------------------------------------------------ #

    async def _acquire(self, session: AsyncSession, ctx: ProxyContext, *, exclude: set[str]) -> tuple[NodeRuntime, NodeRow]:
        deadline = time.monotonic() + self.settings.load_balancer.queue_wait_timeout_seconds
        while True:
            runtime = self.pool.pick(model=ctx.model or None, hash_key=f"{ctx.principal.key_id}:{ctx.model}", exclude=exclude)
            row = await NodeRepository.get(session, runtime.node_id)
            consent = await ConsentRepository.latest_for_node(session, runtime.node_id)
            # Двойная проверка согласия и статуса в момент выбора (FR-C-01, §7.2).
            healthy = (
                row is not None
                and ConsentService.consent_is_active(consent)
                and NodeState(row.status) in {NodeState.VERIFIED, NodeState.HEALTHY, NodeState.DEGRADED}
            )
            if healthy and runtime.acquire():
                runtime.note_request()
                metrics.ACTIVE_UPSTREAM_CONNECTIONS.labels(node_id=runtime.node_id).set(runtime.active)
                return runtime, row
            if not healthy:
                # Узел выбыл из реестра/согласия — повторный выбор бессмысленен.
                exclude.add(runtime.node_id)
            if time.monotonic() >= deadline:
                raise NoHealthyNodesError()
            await asyncio.sleep(0.05)

    async def _release(self, runtime: NodeRuntime) -> None:
        runtime.release()
        metrics.ACTIVE_UPSTREAM_CONNECTIONS.labels(node_id=runtime.node_id).set(runtime.active)

    # ------------------------------------------------------------------ #
    # Не-потоковые запросы
    # ------------------------------------------------------------------ #

    async def request_json(
        self,
        session: AsyncSession,
        ctx: ProxyContext,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        timeout: float | None = None,
        allow_retry: bool = True,
        side_effects: bool = False,
    ) -> UpstreamResult:
        """Отправляет запрос узлу с ограниченным повтором (§7.6).

        Повтор допустим **только** пока узел не начал обработку:

        * ошибка соединения/протокола — узел запрос не получил, повтор разрешён
          даже для генераций (тот же ``X-FOA-Request-ID``);
        * таймаут ожидания ответа и 5xx — узел мог приступить к обработке,
          поэтому для запросов с побочными эффектами повтор запрещён;
        * ``retry_after_upstream_started`` снимает этот запрет явно.
        """
        lb = self.settings.load_balancer
        attempts_left = 1 + (max(0, lb.max_retries) if allow_retry else 0)
        # Узел мог приступить к обработке (таймаут чтения, 5xx) — для запросов с
        # побочными эффектами повтор на таком основании запрещён (§7.6).
        retry_after_start = (not side_effects) or lb.retry_after_upstream_started
        exclude: set[str] = set()
        last_error: GatewayError | None = None
        attempt = 0
        while attempts_left > 0:
            attempts_left -= 1
            attempt += 1
            ctx.attempts = attempt
            runtime, row = await self._acquire(session, ctx, exclude=exclude)
            ctx.node_id = runtime.node_id
            endpoint = parse_endpoint(row.endpoint)
            started = time.monotonic()
            try:
                status, headers, payload = await self.transport.request(
                    endpoint,
                    method,
                    path,
                    json_body=body,
                    headers=self.upstream_headers(ctx),
                    timeout=timeout,
                    max_concurrency=runtime.max_concurrency,
                )
            except (UpstreamUnavailable, UpstreamError, UpstreamTimeoutError) as exc:
                latency = (time.monotonic() - started) * 1000
                await self._release(runtime)
                await self._observe(session, runtime, ok=False, latency_ms=latency, status=0)
                exclude.add(runtime.node_id)
                last_error = exc if isinstance(exc, GatewayError) else UpstreamError(str(exc))
                # Ошибка соединения (§7.6): узел запрос не получил — повтор можно.
                if not _is_connect_error(last_error):
                    raise last_error
                if attempts_left > 0:
                    log.info(
                        "proxy:retry",
                        extra={"foa": {"event": "proxy.retry", "node_id": runtime.node_id, "attempt": attempt, "request_id": ctx.request_id}},
                    )
                    continue
                raise last_error
            except TimeoutError as exc:
                latency = (time.monotonic() - started) * 1000
                await self._release(runtime)
                await self._observe(session, runtime, ok=False, latency_ms=latency, status=0)
                exclude.add(runtime.node_id)
                last_error = UpstreamTimeoutError("upstream timeout")
                if attempts_left > 0 and retry_after_start:
                    continue
                raise last_error from exc
            latency = (time.monotonic() - started) * 1000
            tokens = _count_tokens(payload)
            await self._release(runtime)
            await self._observe(session, runtime, ok=status < 400, latency_ms=latency, status=status, tokens=tokens)
            ctx.bytes_out += len(payload)
            ctx.tokens += tokens
            if status in (401, 403):
                # §6.4 — отказ узла в доступе: узел уже исключён/заблокирован в observe().
                raise UpstreamError("upstream node refused authorization", details={"http_status": status})
            if status >= 500:
                metrics.UPSTREAM_ERRORS_TOTAL.labels(node_id=runtime.node_id, kind=f"http_{status}").inc()
                last_error = UpstreamError("upstream node error", details={"http_status": status, "kind": "read"})
                if attempts_left > 0 and retry_after_start:
                    exclude.add(runtime.node_id)
                    continue
                # §9.5.5 — ошибка узла отдаётся клиенту как 502 UPSTREAM_ERROR,
                # а не сырым статусом узла: адрес и детали узла не раскрываются.
                raise last_error
            return UpstreamResult(status=status, headers=dict(headers), body=payload, node_id=runtime.node_id, attempts=attempt)
        raise last_error or NoHealthyNodesError()

    # ------------------------------------------------------------------ #
    # Потоковые NDJSON-ответы (§8.4)
    # ------------------------------------------------------------------ #

    async def _open_stream(
        self,
        session: AsyncSession,
        ctx: ProxyContext,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> tuple[NodeRuntime, StreamedResponse, float]:
        """Выбирает узел и открывает поток, повторяя до начала передачи (§7.6).

        Повтор допустим только при ошибке соединения (узел запрос не получил) и
        только когда ``load_balancer.retry_streaming_requests=true`` — по
        умолчанию false, так как стрим не должен начаться дважды.
        """
        lb = self.settings.load_balancer
        attempts_left = 1 + max(0, lb.max_retries if lb.retry_streaming_requests else 0)
        exclude: set[str] = set()
        while True:
            attempts_left -= 1
            ctx.attempts += 1
            runtime, row = await self._acquire(session, ctx, exclude=exclude)
            ctx.node_id = runtime.node_id
            endpoint = parse_endpoint(row.endpoint)
            started = time.monotonic()
            try:
                stream = await self.transport.stream(
                    endpoint,
                    method,
                    path,
                    json_body=body,
                    headers=self.upstream_headers(ctx),
                    max_concurrency=runtime.max_concurrency,
                )
                return runtime, stream, started
            except (TimeoutError, UpstreamUnavailable, UpstreamError, UpstreamTimeoutError) as exc:
                latency = (time.monotonic() - started) * 1000
                await self._release(runtime)
                await self._observe(session, runtime, ok=False, latency_ms=latency, status=0)
                if isinstance(exc, asyncio.TimeoutError):
                    raise UpstreamTimeoutError("upstream timeout before stream start") from exc
                last_error = exc if isinstance(exc, GatewayError) else UpstreamError(str(exc))
                if attempts_left > 0 and _is_connect_error(last_error):
                    exclude.add(runtime.node_id)
                    log.info(
                        "proxy:stream_retry",
                        extra={"foa": {"event": "proxy.stream_retry", "node_id": runtime.node_id, "request_id": ctx.request_id}},
                    )
                    continue
                raise last_error

    async def stream_ndjson(
        self,
        session: AsyncSession,
        ctx: ProxyContext,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> AsyncIterator[bytes]:
        """Генератор: передаёт фрагменты без буферизации, прерывает узел при отключении клиента.

        После первого байта повтор запрещён (§7.6): ошибка отдаётся событием
        ``{"error": …}`` внутри потока, а не сменой узла.
        """
        runtime, stream, started = await self._open_stream(session, ctx, method=method, path=path, body=body)
        ok = True
        status = 0
        first_byte = False
        try:
            status = stream.status_code
            if status >= 400:
                ok = False
                detail = await stream.read(limit=64_000)
                await stream.aclose()
                stream = None
                raise UpstreamError(
                    "upstream returned error before stream start",
                    details={"http_status": status, "detail": _safe_text(detail)},
                )
            async for chunk in stream.aiter:
                first_byte = True
                ctx.bytes_out += len(chunk)
                ctx.tokens += _stream_tokens(chunk)
                yield chunk
        except asyncio.CancelledError:
            # Клиент отключился — обрываем запрос к узлу (§8.2 п.10, §8.4).
            ctx.error_code = ErrorCode.CLIENT_DISCONNECTED.value
            log.info(
                "proxy:client_disconnected",
                extra={"foa": {"event": "proxy.client_disconnected", "node_id": runtime.node_id, "request_id": ctx.request_id}},
            )
            raise
        except Exception as exc:
            ok = False
            if first_byte:
                # Поток уже пошёл клиенту: повторяем не узел, а отдаём событие ошибки.
                ctx.error_code = ErrorCode.UPSTREAM_ERROR.value
                yield _stream_error_event(exc)
            elif isinstance(exc, GatewayError):
                raise
            else:
                raise UpstreamError(f"upstream stream error: {exc}") from exc
        finally:
            if stream is not None:
                try:
                    await stream.aclose()
                except Exception:
                    pass
            await self._release(runtime)
            await self._observe(session, runtime, ok=ok, latency_ms=(time.monotonic() - started) * 1000, status=status, tokens=ctx.tokens)

    # ------------------------------------------------------------------ #
    # Заголовки для узла (§8.5.3)
    # ------------------------------------------------------------------ #

    def upstream_headers(self, ctx: ProxyContext, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"X-FOA-Request-ID": ctx.request_id, "Accept-Encoding": "identity", "User-Agent": "Free-Ollama-API-Gateway/1.0"}
        if self.settings.security.forward_client_ip:
            headers["X-Forwarded-For"] = "restricted"
        else:
            headers["X-FOA-Client-Hash"] = self.ratelimit_client_hash(ctx)
        if extra:
            headers.update({k: v for k, v in extra.items() if k.lower() not in STRIPPED_UPSTREAM_HEADERS})
        return headers

    def ratelimit_client_hash(self, ctx: ProxyContext) -> str:
        return f"sha256:{ctx.principal.key_hash_hex or ctx.principal.key_id}"

    # ------------------------------------------------------------------ #
    # Пассивное наблюдение (§6.3)
    # ------------------------------------------------------------------ #

    async def _observe(
        self,
        session: AsyncSession,
        runtime: NodeRuntime,
        *,
        ok: bool,
        latency_ms: float,
        status: int,
        tokens: int = 0,
    ) -> None:
        try:
            await self.nodes.observe(session, runtime.node_id, ok=ok, latency_ms=latency_ms, status=status, tokens=tokens)
        except Exception as exc:
            log.debug("proxy: observe failed: %s", exc)
            runtime.observe(ok=ok, latency_ms=latency_ms, status=status, tokens=tokens)

    # ------------------------------------------------------------------ #
    # Метрики (§11.4)
    # ------------------------------------------------------------------ #

    def record(self, ctx: ProxyContext, status: int) -> None:
        metrics.REQUESTS_TOTAL.labels(route=ctx.route or "unknown", status=str(status), error_code=ctx.error_code or "none").inc()
        metrics.REQUEST_DURATION.labels(route=ctx.route or "unknown", stream=str(ctx.stream).lower()).observe(ctx.latency_ms / 1000.0)

    # ------------------------------------------------------------------ #
    # Агрегации (§9.3.2)
    # ------------------------------------------------------------------ #

    async def aggregate_tags(self, session: AsyncSession) -> dict[str, Any]:
        """Объединённый список моделей согласованных узлов; адреса узлов не раскрываются."""
        merged: dict[str, dict[str, Any]] = {}
        for runtime in self.pool.nodes.values():
            if not runtime.routable:
                continue
            row = await NodeRepository.get(session, runtime.node_id)
            if row is None:
                continue
            modified = row.updated_at.isoformat().replace("+00:00", "Z") if row.updated_at else utcnow().isoformat().replace("+00:00", "Z")
            for name in runtime.models:
                entry = merged.get(name)
                if entry is None:
                    merged[name] = {"name": name, "model": name, "modified_at": modified, "size": 0, "digest": ""}
                else:
                    entry["modified_at"] = max(entry["modified_at"], modified)
        return {"models": sorted(merged.values(), key=lambda item: item["name"])}

    async def fanout(
        self,
        session: AsyncSession,
        ctx: ProxyContext,
        *,
        method: str,
        path: str,
        body: dict | None,
        timeout: float,
        require_model_support: bool = False,
    ) -> list[dict]:
        """Опрос согласованных узлов (агрегация ``/api/show``, ``/api/ps``)."""
        tasks = []
        for runtime in self.pool.nodes.values():
            if not runtime.routable:
                continue
            if require_model_support and ctx.model and not _supports(runtime, ctx.model):
                continue
            row = await NodeRepository.get(session, runtime.node_id)
            if row is None:
                continue
            tasks.append(self._single(session, ctx, runtime, row, method, path, body, timeout))
        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [item for item in results if isinstance(item, dict)]

    async def _single(self, session, ctx, runtime, row, method, path, body, timeout) -> dict | None:
        endpoint = parse_endpoint(row.endpoint)
        try:
            status, _, payload = await self.transport.request(
                endpoint,
                method,
                path,
                json_body=body,
                headers=self.upstream_headers(ctx),
                timeout=timeout,
                max_concurrency=runtime.max_concurrency,
            )
        except Exception as exc:
            await self._observe(session, runtime, ok=False, latency_ms=0, status=0)
            log.debug("proxy: fanout failed for %s: %s", runtime.node_id, exc)
            return None
        await self._observe(session, runtime, ok=status < 400, latency_ms=0, status=status)
        if status >= 400:
            return None
        try:
            data = json.loads(payload.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return {"node_id": runtime.node_id, "data": data if isinstance(data, dict) else {}}


def _supports(runtime: NodeRuntime, model: str) -> bool:
    from foa.services.balancer import node_supports_model

    return node_supports_model(runtime, model)


def _is_connect_error(exc: Exception) -> bool:
    """True — узел заведомо не получил запрос (§7.6: повтор только при ошибке соединения)."""
    details = getattr(exc, "details", None)
    return isinstance(details, dict) and details.get("kind") == "connect"


def _count_tokens(payload: bytes) -> int:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 0
    if not isinstance(data, dict):
        return 0
    return max(0, int(data.get("eval_count") or 0) + int(data.get("prompt_eval_count") or 0))


def _stream_tokens(chunk: bytes) -> int:
    total = 0
    for line in chunk.split(b"\n"):
        line = line.strip()
        if not line.startswith(b"{"):
            continue
        try:
            data = json.loads(line.decode("utf-8", "replace"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("done"):
            total += int(data.get("eval_count") or 0) + int(data.get("prompt_eval_count") or 0)
    return total


def _safe_text(payload: bytes, limit: int = 300) -> str:
    return payload.decode("utf-8", "replace")[:limit]


def _stream_error_event(exc: Exception) -> bytes:
    payload = {"error": "upstream stream aborted", "code": ErrorCode.UPSTREAM_ERROR.value}
    return (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")


__all__ = ["NDJSON_CONTENT_TYPE", "STRIPPED_UPSTREAM_HEADERS", "ProxyContext", "ProxyService", "UpstreamResult"]
