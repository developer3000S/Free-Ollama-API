"""SSRF-защита и контроль адресации узлов (§12.4.5, §12.6, §12.5.1).

Правила:

* пользователь никогда не может задать целевой адрес — шлюз ходит только на
  зарегистрированные узлы (белый список эндпоинтов в реестре);
* при регистрации узла хост резолвится и проверяется: запрещены loopback,
  link-local (в т.ч. метаданные облаков 169.254.169.254 / fd00::/8), multicast,
  reserved и частные сети — если только оператор явно не включил
  ``security.allow_loopback_nodes`` (изолированная сеть/тесты) или сеть не
  попала в ``allowed_scopes``;
* разрешённые адреса запоминаются (IP pinning), чтобы исключить DNS rebinding
  между проверкой и запросом; TTL пина ограничен, по истечении — ре-резолв;
* при подключении используется именно запиненный адрес, а не повторный резолвинг.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from foa.domain.errors import InvalidRequestError

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_OLLAMA_PORT = 11434
_MAX_PORT = 65_535

# Диапазоны, которые нельзя трогать ни при каких условиях (метаданные облаков).
_ALWAYS_DENY_NETS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_IPV6_RE = re.compile(r"^\[[0-9A-Fa-f:.]+\]$")


@dataclass(slots=True)
class Endpoint:
    """Разобранный и проверенный адрес узла."""

    scheme: str
    host: str
    port: int
    raw: str
    is_ip: bool = False
    tls: bool = False

    @property
    def origin(self) -> str:
        host = self.host if not self.is_ip or ":" not in self.host else f"[{self.host}]"
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def netloc(self) -> str:
        host = self.host if not self.is_ip or ":" not in self.host else f"[{self.host}]"
        return f"{host}:{self.port}"


@dataclass(slots=True)
class ResolvedAddress:
    ip: str
    pinned_at: float = field(default_factory=time.time)


class PinStore:
    """Кэш закреплённых DNS-адресов (§12.6 «пиннинг ключей/подмены узла»)."""

    def __init__(self, ttl_seconds: float = 300.0) -> None:
        self.ttl_seconds = ttl_seconds
        self._pins: dict[str, list[ResolvedAddress]] = {}

    def put(self, host: str, ips: list[str]) -> None:
        self._pins[host.lower()] = [ResolvedAddress(ip=ip) for ip in ips]

    def get(self, host: str) -> list[str] | None:
        entry = self._pins.get(host.lower())
        if not entry:
            return None
        if time.time() - entry[0].pinned_at > self.ttl_seconds:
            self._pins.pop(host.lower(), None)
            return None
        return [e.ip for e in entry]

    def drop(self, host: str) -> None:
        self._pins.pop(host.lower(), None)


def classify_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr in _ALWAYS_DENY_NETS[0] or addr in _ALWAYS_DENY_NETS[1]:
        return "metadata"
    if addr.is_unspecified or addr in _ALWAYS_DENY_NETS[2]:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if addr.is_private:
        return "private"
    # В стандартной библиотеке нет ``is_public`` — есть ``is_global`` (обратная
    # классификация к частным/служебным диапазонам).
    if addr.is_global:
        return "public"
    return "other"


def ip_is_blocked(ip: str, *, allow_loopback: bool = False, allowed_networks: list[str] = ()) -> bool:
    """True — адрес запрещён для подключения шлюза."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    for net in _ALWAYS_DENY_NETS:
        if addr in net:
            return True
    if addr.is_unspecified or addr.is_multicast:
        return True
    # Порядок важен: в модуле ipaddress IPv6-петля ``::1`` одновременно и
    # ``is_reserved``, и ``is_private`` — петля проверяется первой, иначе
    # ``allow_loopback_nodes`` не работал бы для ``localhost`` (двойная запись A/AAAA).
    if addr.is_loopback:
        return not allow_loopback
    if addr.is_reserved:
        return True
    return addr.is_private and not _in_allowed_networks(addr, allowed_networks)


def _in_allowed_networks(addr, allowed_networks: list[str]) -> bool:
    for cidr in allowed_networks:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def parse_endpoint(url: str, *, default_port: int = DEFAULT_OLLAMA_PORT) -> Endpoint:
    """Разбирает адрес узла и отклоняет явно недопустимые варианты."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlparse(candidate)
    except ValueError as exc:
        raise InvalidRequestError(f"некорректный адрес узла: {exc}") from exc
    scheme = (parsed.scheme or "https").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidRequestError("разрешены только схемы http и https")
    host = parsed.hostname
    if not host:
        raise InvalidRequestError("адрес узла должен содержать хост")
    host = host.rstrip(".").lower()
    if parsed.path not in ("", "/"):
        raise InvalidRequestError("адрес узла не должен содержать путь")
    if parsed.username or parsed.password:
        raise InvalidRequestError("учётные данные в URL узла запрещены")
    if parsed.query or parsed.fragment:
        raise InvalidRequestError("query/fragment в URL узла запрещены")
    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise InvalidRequestError(f"некорректный порт: {exc}") from exc
    if not 1 <= port <= _MAX_PORT:
        raise InvalidRequestError("порт вне допустимого диапазона")
    is_ip = False
    bare = host[1:-1] if _IPV6_RE.match(host) else host
    try:
        ipaddress.ip_address(bare)
        is_ip = True
        host = bare
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise InvalidRequestError("некорректное имя хоста узла") from None
    return Endpoint(scheme=scheme, host=host, port=port, raw=url.strip(), is_ip=is_ip, tls=scheme == "https")


def validate_endpoint(
    url: str,
    *,
    default_port: int = DEFAULT_OLLAMA_PORT,
    allow_loopback: bool = False,
    allowed_networks: list[str] = (),
) -> str:
    """Синтаксическая проверка адреса узла при разборе схемы (§9.6.2).

    Сетевые правила (loopback/private/metadata) применяются в сервисном слое —
    :func:`assert_endpoint_resolvable`, который знает о настройках шлюза.
    """
    endpoint = parse_endpoint(url, default_port=default_port)
    if endpoint.is_ip and ip_is_blocked(endpoint.host, allow_loopback=allow_loopback, allowed_networks=allowed_networks):
        raise ValueError(
            "адрес узла указывает в недопустимую сеть — см. security.allow_loopback_nodes (§12.5.1)"
        )
    return url.strip()


def resolve_host(host: str, timeout: float = 3.0) -> list[str]:
    """Резолвит хост (без блокирующих surprise: используем socket.getaddrinfo)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise InvalidRequestError(f"хост узла не разрешается: {host} ({exc.strerror or exc})") from exc
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def assert_endpoint_resolvable(
    endpoint: Endpoint,
    *,
    allow_loopback: bool = False,
    allowed_networks: list[str] = (),
    pins: PinStore | None = None,
) -> list[str]:
    """Резолвит и проверяет все адреса узла; кэширует пин. Бросает InvalidRequestError при запрете."""
    if endpoint.is_ip:
        ips = [endpoint.host]
    else:
        pinned = pins.get(endpoint.host) if pins else None
        ips = pinned or resolve_host(endpoint.host)
    blocked = [ip for ip in ips if ip_is_blocked(ip, allow_loopback=allow_loopback, allowed_networks=allowed_networks)]
    if blocked:
        raise InvalidRequestError(
            f"узел {endpoint.host} указывает в запрещённые сети: {', '.join(sorted({classify_ip(ip) for ip in blocked}))}"
        )
    if not ips:
        raise InvalidRequestError(f"не найдено ни одного адреса для {endpoint.host}")
    if pins is not None and not endpoint.is_ip:
        pins.put(endpoint.host, ips)
    return ips


__all__ = [
    "ALLOWED_SCHEMES",
    "DEFAULT_OLLAMA_PORT",
    "Endpoint",
    "PinStore",
    "ResolvedAddress",
    "assert_endpoint_resolvable",
    "classify_ip",
    "ip_is_blocked",
    "parse_endpoint",
    "resolve_host",
    "validate_endpoint",
]
