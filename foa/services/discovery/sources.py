"""Интеграции с внешними источниками (§4.2).

Жёсткие правила для всех источников:

1. Только официальные REST API и только ``GET``/читающие запросы — система ничего
   не сканирует сама (``active_scanning: deny``, §4.3).
2. Запрос **обязан** содержать фильтр, выведенный из ``allowed_scopes`` владельца
   (собственные домены/IP-диапазоны/ASN) — глобальный «мировой» поиск запрещён (§4.6).
   Пустые scope'и → :class:`ScopeRequired` и источник не опрашивается.
3. Секреты не попадают ни в URL запроса целиком (авторизация — в заголовках),
   ни в журналы.
4. Частота ограничена ``max_requests_per_minute``, ответы кэшированы
   (``ResponseCache``, см. :mod:`foa.services.discovery`).
5. Результат нормализуется в :class:`SourceCandidate` — статус ``candidate``
   присваивает конвейер, а не источник.

Реализованы адаптеры: Censys, GreyNoise, ZoomEye, Natlas, Criminal IP.
"""

from __future__ import annotations

import base64
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from foa.config import SourceConfig
from foa.logging import get_logger
from foa.services.discovery.scopes import ScopeSet

log = get_logger("discovery.sources")

DEFAULT_TIMEOUT = 20.0
USER_AGENT = "Free-Ollama-API-Gateway/1.0 (inventory; +https://example.invalid/policy)"


class ScopeRequired(RuntimeError):
    """Источник запрещено опрашивать без явных разрешённых областей (§4.6)."""


class SourceError(RuntimeError):
    """Ошибка внешнего API (не несут угрозы — просто отказ источника)."""


@dataclass(slots=True)
class SourceCandidate:
    """Ненормализованная запись «кандидат», как её вернул источник (§4.4.1)."""

    ip: str
    port: int = 11434
    source: str = ""
    protocol: str = "tcp"
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    dns_names: list[str] = field(default_factory=list)
    asn: str | None = None
    country: str | None = None
    service_hint: str | None = None
    banner_hash: str | None = None
    hosted_on_known_cloud: bool = False
    open_proxy_suspected: bool = False
    seen_in_blocklists: bool = False
    abuse_history: bool = False
    age_seconds: int = 0
    matches_expected_profile: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def raw_keys(self) -> list[str]:
        return sorted(self.extra)[:12]


@dataclass(slots=True)
class BaseSource:
    name: str = ""
    config: SourceConfig = field(default_factory=SourceConfig)
    http_client: Any = None

    SOURCE_NAME = ""
    ENDPOINT = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = type(self).SOURCE_NAME
        if not self.config.allowed_scopes and self.config.enabled:
            log.info("discovery:source_without_scopes", extra={"foa": {"event": "discovery.source_without_scopes", "source": self.name}})
        self.scopes = ScopeSet(list(self.config.allowed_scopes))

    # -- обязательный фильтр из allowed_scopes ---------------------------- #

    def scope_filter(self) -> str:
        if not self.scopes.raw:
            raise ScopeRequired(f"источник {self.name}: запрещён запрос без allowed_scopes (§4.6)")
        parts: list[str] = []
        for net in self.scopes.networks:
            parts.append(str(net))
        for domain in self.scopes.domains:
            parts.append(domain)
        for asn in self.scopes.asns:
            parts.append(f"ASN{asn}")
        return " ".join(parts[:20])

    def scope_networks(self) -> list[str]:
        return [str(n) for n in self.scopes.networks]

    def scope_domains(self) -> list[str]:
        return list(self.scopes.domains)

    # -- интерфейс ------------------------------------------------------- #

    async def fetch(self) -> list[SourceCandidate]:  # pragma: no cover - контракт
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.name,
            "purpose": self.config.purpose,
            "enabled": self.config.enabled,
            "endpoint": self.endpoint,
            "scopes": self.scopes.describe(),
        }

    @property
    def endpoint(self) -> str:
        return self.config.api_endpoint or type(self).ENDPOINT

    # -- helpers --------------------------------------------------------- #

    async def _get_json(self, url: str, *, params: dict[str, Any], headers: dict[str, str] | None = None) -> dict:
        client = self.http_client
        if client is None:
            import httpx

            client = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=False, trust_env=True)
            should_close = True
        else:
            should_close = False
        try:
            merged = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
            try:
                response = await client.get(url, params=params, headers=merged)
            except Exception as exc:
                raise SourceError(f"{self.name}: запрос не выполнен: {type(exc).__name__}") from exc
            if response.status_code == 429:
                raise SourceError(f"{self.name}: источник ограничил частоту (429)")
            if response.status_code in (401, 403):
                # Не раскрываем секрет: только код.
                raise SourceError(f"{self.name}: отказ в доступе к API ({response.status_code})")
            if response.status_code >= 400:
                raise SourceError(f"{self.name}: HTTP {response.status_code}")
            try:
                payload = response.json()
            except ValueError as exc:
                raise SourceError(f"{self.name}: ответ не JSON") from exc
            return payload if isinstance(payload, dict) else {"data": payload}
        finally:
            if should_close:
                await client.aclose()

    @staticmethod
    def _in_scopes(scopes: ScopeSet, ip: str, dns_names: list[str], asn: str | None) -> bool:
        return scopes.allows(ip, dns_names=dns_names, asn=asn)

    @staticmethod
    def _parse_ts(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=UTC)
        text = str(value or "").strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)

    @staticmethod
    def _valid_ip(value: Any) -> str | None:
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            return None


# --------------------------------------------------------------------------- #
# Censys (§4.2) — поиск по сертификатам/хостам через официальный API v1
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class CensysSource(BaseSource):
    SOURCE_NAME = "censys"
    ENDPOINT = "https://search.censys.io/api/v1/search/ipv4"

    async def fetch(self) -> list[SourceCandidate]:
        query = self._build_query()
        api_id, api_secret = self.config.api_id, self.config.api_secret
        if not (api_id and api_secret):
            raise SourceError("censys: не заданы api_id/api_secret")
        token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        payload = await self._get_json(
            self.endpoint,
            params={"q": query, "per_page": min(100, max(1, self.config.max_requests_per_minute * 10))},
            headers={"Authorization": f"Basic {token}"},
        )
        out: list[SourceCandidate] = []
        for item in (payload.get("data") or {}).get("hits", []) if isinstance(payload.get("data"), dict) else []:
            ip = self._valid_ip(item.get("ip") or item.get("_source", {}).get("ip"))
            if not ip:
                continue
            source = item.get("_source", item) if isinstance(item.get("_source"), dict) else item
            dns = [str(d) for d in (source.get("dns_names") or source.get("names") or []) if d]
            out.append(
                SourceCandidate(
                    ip=ip,
                    port=_service_port(source) or 11434,
                    source=self.name,
                    observed_at=self._parse_ts(source.get("observed_at") or source.get("last_update")),
                    dns_names=dns[:10],
                    asn=str(source.get("asn", {}).get("asn") if isinstance(source.get("asn"), dict) else source.get("asn") or "") or None,
                    country=(source.get("location", {}).get("country_code") if isinstance(source.get("location"), dict) else source.get("country")),
                    service_hint=str(source.get("service") or source.get("protocols") or "unknown").split("/")[0] or None,
                    hosted_on_known_cloud=bool(source.get("cloud", {}).get("provider")) if isinstance(source.get("cloud"), dict) else False,
                    matches_expected_profile=_profile_ok(source),
                )
            )
        return [c for c in out if self._in_scopes(self.scopes, c.ip, c.dns_names, c.asn)]

    def _build_query(self) -> str:
        """Censys-запрос, **ограниченный** скоупами владельца + портом Ollama."""
        clauses: list[str] = []
        for net in self.scope_networks():
            clauses.append(f'ip: "{net}"')
        for domain in self.scope_domains():
            clauses.append(f'names: "{domain}"')
        if not clauses:
            raise ScopeRequired("censys: allowed_scopes должны содержать IP/CIDR или домены")
        return f"11434 OR service: ollama AND ( {' OR '.join(clauses)} )"


# --------------------------------------------------------------------------- #
# GreyNoise (§4.2) — исследовательский API (risk enrichment), только по IP из scope
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class GreyNoiseSource(BaseSource):
    SOURCE_NAME = "greynoise"
    ENDPOINT = "https://api.greynoise.io/v3/community"

    async def fetch(self) -> list[SourceCandidate]:
        if not self.config.api_key:
            raise SourceError("greynoise: не задан api_key")
        if not self.scopes.networks:
            raise ScopeRequired("greynoise: enrich возможен только по явно указанным IP/CIDR (§4.6)")
        out: list[SourceCandidate] = []
        for net in self.scopes.networks[: self.config.max_requests_per_minute]:
            # Не делаем массовый перебор диапазона: обогащаем только одиночные адреса.
            if net.num_addresses > 1:
                log.info(
                    "greynoise:skipping_range",
                    extra={"foa": {"event": "discovery.source_skip", "source": self.name, "reason": "multi_address_cidr"}},
                )
                continue
            payload = await self._get_json(f"{self.endpoint}/{net.network_address}", params={}, headers={"key": self.config.api_key})
            classification = str(payload.get("classification") or "").lower()
            out.append(
                SourceCandidate(
                    ip=str(net.network_address),
                    port=11434,
                    source=self.name,
                    observed_at=self._parse_ts(payload.get("last_seen")),
                    service_hint=str(payload.get("bot") or payload.get("name") or "")[:40] or None,
                    seen_in_blocklists=classification in {"malicious", "scanner"},
                    abuse_history=classification == "malicious",
                    age_seconds=int(payload.get("age_seconds") or 0),
                )
            )
        return out


# --------------------------------------------------------------------------- #
# ZoomEye (§4.2)
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ZoomEyeSource(BaseSource):
    SOURCE_NAME = "zoomeye"
    ENDPOINT = "https://api.zoomeye.org/host/search"

    async def fetch(self) -> list[SourceCandidate]:
        if not self.config.api_key:
            raise SourceError("zoomeye: не задан api_key")
        clauses = [f'ip:"{net}"' for net in self.scope_networks()] + [f'hostname:"{d}"' for d in self.scope_domains()]
        if not clauses:
            raise ScopeRequired("zoomeye: пустые allowed_scopes")
        query = f'port:11434 AND ({" OR ".join(clauses[:10])})'
        payload = await self._get_json(
            self.endpoint,
            params={"query": query, "page": 1},
            headers={"APIKEY": self.config.api_key},
        )
        out: list[SourceCandidate] = []
        for item in payload.get("matches", []) or []:
            ip = self._valid_ip(item.get("ip"))
            if not ip:
                continue
            dns = [str(item.get("hostname"))] if item.get("hostname") else []
            out.append(
                SourceCandidate(
                    ip=ip,
                    port=int((item.get("portinfo") or {}).get("port") or 11434),
                    source=self.name,
                    observed_at=self._parse_ts(item.get("lasttime")),
                    dns_names=dns,
                    country=item.get("country_code"),
                    service_hint=str((item.get("portinfo") or {}).get("service") or "") or None,
                    banner_hash=str((item.get("portinfo") or {}).get("hexdigest") or "") or None,
                )
            )
        return [c for c in out if self._in_scopes(self.scopes, c.ip, c.dns_names, c.asn)]


# --------------------------------------------------------------------------- #
# Natlas (§4.2) — собственный инстанс; endpoint обязано задаёт развёртывание
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class NatlasSource(BaseSource):
    SOURCE_NAME = "natlas"
    ENDPOINT = "https://natlas.example.local/api/v1/search/elasticsearch"

    async def fetch(self) -> list[SourceCandidate]:
        if not self.config.api_key:
            raise SourceError("natlas: не задан api_key")
        if not self.config.api_endpoint:
            raise SourceError("natlas: требуется собственный api_endpoint (чужие инстансы не опрашиваются)")
        clauses = [f"ip:{net}" for net in self.scope_networks()] + [f"ptr:{d}" for d in self.scope_domains()]
        if not clauses:
            raise ScopeRequired("natlas: пустые allowed_scopes")
        query = f"port:11434 AND ({' OR '.join(clauses[:10])})"
        payload = await self._get_json(self.endpoint, params={"q": query, "count": 50}, headers={"X-Api-Key": self.config.api_key})
        out: list[SourceCandidate] = []
        for hit in (payload.get("results") or []) if isinstance(payload.get("results"), list) else []:
            doc = hit.get("_source", hit) if isinstance(hit, dict) else {}
            ip = self._valid_ip(doc.get("ip")) or self._valid_ip(doc.get("ptr"))
            if not ip:
                continue
            out.append(
                SourceCandidate(
                    ip=ip,
                    port=int(doc.get("port") or 11434),
                    source=self.name,
                    observed_at=self._parse_ts(doc.get("updated_at")),
                    dns_names=[str(doc.get("ptr"))] if doc.get("ptr") else [],
                    service_hint=str(doc.get("service") or "") or None,
                )
            )
        return [c for c in out if self._in_scopes(self.scopes, c.ip, c.dns_names, c.asn)]


# --------------------------------------------------------------------------- #
# Criminal IP (§4.2) — риск-обогащение по IP из scope
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class CriminalIPSource(BaseSource):
    SOURCE_NAME = "criminal_ip"
    ENDPOINT = "https://api.criminalip.io/v1/asset/search"

    async def fetch(self) -> list[SourceCandidate]:
        if not self.config.api_key:
            raise SourceError("criminal_ip: не задан api_key")
        clauses = self.scope_networks() + self.scope_domains()
        if not clauses:
            raise ScopeRequired("criminal_ip: пустые allowed_scopes")
        query = f"11434 ({' '.join(clauses[:5])})"
        payload = await self._get_json(self.endpoint, params={"query": query, "size": 50}, headers={"X-API-KEY": self.config.api_key})
        out: list[SourceCandidate] = []
        for item in (payload.get("data") or []) if isinstance(payload.get("data"), list) else []:
            ip = self._valid_ip(item.get("ip"))
            if not ip:
                continue
            services = item.get("services") or []
            out.append(
                SourceCandidate(
                    ip=ip,
                    port=int(item.get("port") or 11434),
                    source=self.name,
                    observed_at=self._parse_ts(item.get("update_date")),
                    dns_names=[str(s) for s in (item.get("dns") or [])][:5],
                    country=item.get("country"),
                    service_hint=str(services[0]) if services else None,
                    hosted_on_known_cloud=bool(item.get("organization")),
                )
            )
        return [c for c in out if self._in_scopes(self.scopes, c.ip, c.dns_names, c.asn)]


# --------------------------------------------------------------------------- #


def _service_port(source: dict) -> int | None:
    value = source.get("port") or source.get("service_port")
    try:
        port = int(str(value).split("/")[0])
        return port if 1 <= port <= 65_535 else None
    except (TypeError, ValueError):
        return None


def _profile_ok(source: dict) -> bool:
    """Соответствие ожидаемому профилю сервиса Ollama (§4.4.3)."""
    hint = str(source.get("service") or source.get("protocols") or "").lower()
    banner = str(source.get("banner") or "").lower()
    port = _service_port(source)
    if port and port != 11434:
        return False
    return not hint or "ollama" in hint or "http" in hint or "11434" in banner or "v0." in banner


SOURCES: dict[str, type[BaseSource]] = {
    "censys": CensysSource,
    "greynoise": GreyNoiseSource,
    "zoomeye": ZoomEyeSource,
    "natlas": NatlasSource,
    "criminal_ip": CriminalIPSource,
}


def source_for(name: str, config: SourceConfig, http_client: Any = None) -> BaseSource:
    cls = SOURCES.get(name)
    if cls is None:
        raise SourceError(f"неизвестный источник discovery: {name!r}")
    return cls(config=config, http_client=http_client)


__all__ = [
    "SOURCES",
    "BaseSource",
    "CensysSource",
    "CriminalIPSource",
    "GreyNoiseSource",
    "NatlasSource",
    "ScopeRequired",
    "SourceCandidate",
    "SourceError",
    "ZoomEyeSource",
    "source_for",
]
