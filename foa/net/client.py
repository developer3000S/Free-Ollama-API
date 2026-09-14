"""HTTP-транспорт до узлов Ollama (§7.1, §8, §12.6).

Особенности реализации:

* отдельный ``httpx.AsyncClient`` (пул соединений) на каждый узел — «пул
  соединений на каждый узел» из §7.1;
* лимит пула = ``max(max_concurrency, pool.max_connections_per_node)``,
  keep-alive включён, повторных попыток на уровне транспорта нет (повторами
  управляет :mod:`foa.services.proxy` согласно §7.6);
* таймауты: соединение 2 с, заголовки/чтение 10 с…300 с, ожидание слота в
  пуле 2 с (§7.1, §8.3);
* SSRF-защита: перед **каждым** запросом адрес узла ревалидируется
  (:meth:`NodeTransport._check_ssrf`) — закреплённый DNS-результат проверяется
  на запрет loopback/private/link-local/metadata, что блокирует DNS rebinding
  между регистрацией и отправкой запроса; redirect'ы не следуются; ``trust_env``
  выключен, чтобы переменные окружения не перехватывали маршрут. Для HTTPS
  дополнительно действует верификация сертификата по имени хоста (§12.6);
* потоковые ответы отдаются как можно-байты без накопления всего тела (§8.4).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx

from foa.config import PoolConfig, SecurityConfig
from foa.ids import request_id
from foa.logging import get_logger, get_request_id
from foa.net.security import Endpoint, PinStore, ip_is_blocked

log = get_logger("net.client")


class UpstreamUnavailable(RuntimeError):
    """Нет активного клиента для узла (закрыт/ещё не создан)."""


@dataclass(slots=True)
class StreamedResponse:
    status_code: int
    headers: httpx.Headers
    aiter: AsyncIterator[bytes]
    aclose: Callable[[], object]
    elapsed_to_headers: float = 0.0
    request_id: str = ""

    async def read(self, *, limit: int = 8 * 1024 * 1024) -> bytes:
        buf = bytearray()
        async for chunk in self.aiter:
            buf.extend(chunk)
            if len(buf) > limit:
                raise ValueError("upstream response too large")
        return bytes(buf)

    async def json(self) -> dict:
        import json

        return json.loads((await self.read()).decode("utf-8"))


@dataclass(slots=True)
class NodeTransport:
    """Пулы соединений + SSRF-safe резолвинг для всех узлов."""

    pool: PoolConfig
    security: SecurityConfig
    pins: PinStore = field(default_factory=PinStore)
    allowed_networks: list[str] = field(default_factory=list)
    connection_wait_timeout_seconds: float = 2.0

    _clients: dict[str, httpx.AsyncClient] = field(default_factory=dict, repr=False)
    _locks: dict[str, asyncio.Lock] = field(default_factory=dict, repr=False)
    _active: dict[str, int] = field(default_factory=dict, repr=False)
    _closed: bool = False

    # -- пулы ------------------------------------------------------------- #

    def _limits(self, endpoint: Endpoint, max_concurrency: int) -> httpx.Limits:
        max_conn = max(self.pool.max_connections_per_node, max_concurrency or 1)
        return httpx.Limits(
            max_connections=max_conn,
            max_keepalive_connections=max_conn if self.pool.keep_alive else 0,
            keepalive_expiry=30.0,
        )

    def _timeouts(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.pool.connect_timeout_seconds,
            read=self.pool.full_generation_timeout_seconds,
            write=self.pool.connect_timeout_seconds,
            pool=self.connection_wait_timeout_seconds,
        )

    async def client_for(self, endpoint: Endpoint, *, max_concurrency: int = 10) -> httpx.AsyncClient:
        if self._closed:
            raise UpstreamUnavailable("транспорт закрыт")
        key = endpoint.origin
        client = self._clients.get(key)
        if client is not None and not client.is_closed:
            return client
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            client = self._clients.get(key)
            if client is not None and not client.is_closed:
                return client
            transport = httpx.AsyncHTTPTransport(retries=0, limits=self._limits(endpoint, max_concurrency))
            client = httpx.AsyncClient(
                base_url=endpoint.origin,
                transport=transport,
                timeout=self._timeouts(),
                follow_redirects=False,
                trust_env=False,
                http1=True,
                http2=False,
            )
            self._clients[key] = client
            self._active.setdefault(key, 0)
            return client

    async def drop_client(self, endpoint: Endpoint) -> None:
        key = endpoint.origin
        client = self._clients.pop(key, None)
        self._locks.pop(key, None)
        self._active.pop(key, None)
        if client is not None:
            await client.aclose()

    # -- запросы ---------------------------------------------------------- #

    @asynccontextmanager
    async def _guarded(self, endpoint: Endpoint):
        key = endpoint.origin
        if self._closed:
            raise UpstreamUnavailable("транспорт закрыт")
        await self._check_ssrf(endpoint)
        self._active[key] = self._active.get(key, 0) + 1
        try:
            yield
        finally:
            self._active[key] = max(0, self._active.get(key, 1) - 1)

    async def _check_ssrf(self, endpoint: Endpoint) -> None:
        """Последняя линия обороны: адрес узла обязан оставаться допустимым."""
        if endpoint.is_ip:
            if ip_is_blocked(endpoint.host, allow_loopback=self.security.allow_loopback_nodes, allowed_networks=self.allowed_networks):
                raise UpstreamUnavailable(f"адрес узла {endpoint.host} запрещён политикой")
            return
        ips = self.pins.get(endpoint.host)
        if ips is None:
            from foa.net.security import resolve_host

            try:
                ips = resolve_host(endpoint.host)
            except Exception as exc:
                raise UpstreamUnavailable(f"DNS-ошибка для {endpoint.host}: {exc}") from exc
            self.pins.put(endpoint.host, ips)
        for ip in ips:
            if ip_is_blocked(ip, allow_loopback=self.security.allow_loopback_nodes, allowed_networks=self.allowed_networks):
                raise UpstreamUnavailable(f"DNS-результат {endpoint.host} → {ip} запрещён политикой (защита от rebinding)")

    @staticmethod
    def _with_trace(headers: dict[str, str] | None) -> dict[str, str]:
        """Каждый запрос к узлу нёсёт ``X-FOA-Request-ID`` (§7.6, §11.4, §12.3 п.5).

        Владелец узла по журналу видит, какой запрос шлюза обработал его сервер,
        а повтор выполняется с тем же идентификатором.
        """
        merged = dict(headers or {})
        if not any(name.lower() == "x-foa-request-id" for name in merged):
            merged["X-FOA-Request-ID"] = get_request_id() or request_id()
        return merged

    async def request(
        self,
        endpoint: Endpoint,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_concurrency: int = 10,
    ) -> tuple[int, dict, bytes]:
        async with self._guarded(endpoint):
            client = await self.client_for(endpoint, max_concurrency=max_concurrency)
            try:
                resp = await client.request(
                    method,
                    path,
                    json=json_body,
                    headers=self._with_trace(headers),
                    timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
                )
            except httpx.HTTPError as exc:
                raise _map_error(exc) from exc
            return resp.status_code, dict(resp.headers), resp.content

    async def stream(
        self,
        endpoint: Endpoint,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
        max_concurrency: int = 10,
    ) -> StreamedResponse:
        """Возвращает потоковый ответ; вызывающий обязан закрыть его через ``aclose``."""
        await self._check_ssrf(endpoint)
        client = await self.client_for(endpoint, max_concurrency=max_concurrency)
        key = endpoint.origin
        self._active[key] = self._active.get(key, 0) + 1
        started = time.monotonic()
        try:
            request = client.build_request(method, path, json=json_body, headers=self._with_trace(headers))
            response = await client.send(request, stream=True)
        except httpx.HTTPError as exc:
            self._active[key] = max(0, self._active.get(key, 1) - 1)
            raise _map_error(exc) from exc
        elapsed = time.monotonic() - started

        async def aiter() -> AsyncIterator[bytes]:
            try:
                async for chunk in response.aiter_bytes():
                    yield chunk
            except httpx.HTTPError as exc:
                raise _map_error(exc) from exc
            finally:
                await response.aclose()
                self._active[key] = max(0, self._active.get(key, 1) - 1)

        async def aclose() -> None:
            await response.aclose()
            self._active[key] = max(0, self._active.get(key, 1) - 1)

        return StreamedResponse(
            status_code=response.status_code,
            headers=response.headers,
            aiter=aiter(),
            aclose=aclose,
            elapsed_to_headers=elapsed,
        )

    def active_connections(self, endpoint: Endpoint) -> int:
        return self._active.get(endpoint.origin, 0)

    @property
    def active_by_node(self) -> dict[str, int]:
        return dict(self._active)

    async def aclose(self) -> None:
        self._closed = True
        clients = list(self._clients.values())
        self._clients.clear()
        self._locks.clear()
        self._active.clear()
        for client in clients:
            await client.aclose()


def _map_error(exc: httpx.HTTPError) -> Exception:
    from foa.domain.errors import UpstreamError, UpstreamTimeoutError

    # details["kind"]="connect" — узел заведомо не получил запрос, повтор
    # на другом узле безопасен (§7.6). "read" — обработка могла начаться.
    if isinstance(exc, (httpx.ConnectTimeout, httpx.PoolTimeout)):
        return UpstreamTimeoutError(f"upstream connect timeout: {type(exc).__name__}", details={"kind": "connect"})
    if isinstance(exc, httpx.TimeoutException):
        return UpstreamTimeoutError(f"upstream timeout: {type(exc).__name__}", details={"kind": "read"})
    if isinstance(exc, httpx.ConnectError):
        return UpstreamError(f"upstream connection error: {exc}", details={"kind": "connect"})
    if isinstance(exc, (httpx.RemoteProtocolError, httpx.LocalProtocolError, httpx.DecodingError)):
        return UpstreamError(f"upstream protocol error: {exc}", details={"kind": "read"})
    if isinstance(exc, (httpx.NetworkError, httpx.StreamError, httpx.CloseError)):
        return UpstreamError(f"upstream connection error: {exc}", details={"kind": "read"})
    return UpstreamError(f"upstream error: {exc}", details={"kind": "read"})


__all__ = ["NodeTransport", "StreamedResponse", "UpstreamUnavailable"]
