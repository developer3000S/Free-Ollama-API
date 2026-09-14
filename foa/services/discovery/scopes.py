"""allowed_scopes — ограничитель областей поиска (§4.5, §4.6).

Поддерживаемые формы записей:

* IPv4/IPv6 адрес — ``203.0.113.10``;
* CIDR — ``203.0.113.0/24``;
* ASN — ``AS64500`` / ``asn:64500``;
* домен — ``example.com`` (совпадение с dns_name: точно или по суффиксу);
* wildcard-домен — ``*.example.com``.

Для режима ``inventory_only`` пустой список scope'ов означает «ничего не
разрешено» (fail-closed).
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field


@dataclass(slots=True)
class ScopeSet:
    raw: list[str]
    networks: list = field(default_factory=list, init=False)
    asns: set[str] = field(default_factory=set, init=False)
    domains: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        for entry in self.raw:
            value = str(entry).strip()
            if not value:
                continue
            lowered = value.lower()
            if lowered.startswith(("as", "asn:")):
                digits = "".join(ch for ch in lowered if ch.isdigit())
                if digits:
                    self.asns.add(digits)
                continue
            try:
                if "/" in value:
                    self.networks.append(ipaddress.ip_network(value, strict=False))
                else:
                    self.networks.append(ipaddress.ip_network(f"{value}/32" if ":" not in value else f"{value}/128", strict=False))
                continue
            except ValueError:
                pass
            self.domains.append(lowered.lstrip("*.").lstrip(".") or lowered)

    def allows_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def allows_domain(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        for domain in self.domains:
            if name == domain or name.endswith("." + domain):
                return True
            if fnmatch.fnmatch(name, f"*.{domain}"):
                return True
        return False

    def allows_asn(self, asn: str | None) -> bool:
        if not asn or not self.asns:
            return False
        digits = "".join(ch for ch in str(asn) if ch.isdigit())
        return bool(digits and digits in self.asns)

    def allows(self, ip: str, *, dns_names: list[str] | tuple[str, ...] = (), asn: str | None = None) -> bool:
        if not self.raw:
            return False  # fail-closed (§4.6)
        if self.allows_ip(ip):
            return True
        if asn and self.allows_asn(asn):
            return True
        return any(self.allows_domain(name) for name in dns_names)

    def describe(self) -> dict:
        return {
            "networks": [str(n) for n in self.networks],
            "domains": list(self.domains),
            "asns": sorted(self.asns),
            "empty": not self.raw,
        }


__all__ = ["ScopeSet"]
