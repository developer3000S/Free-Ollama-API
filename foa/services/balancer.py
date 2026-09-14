"""Балансировщик нагрузки (§7.2–§7.5) и пул маршрутизируемых узлов.

Кандидатная дисциплина (§4.4.4, FR-D-04): в пул попадают только узлы со
статусами ``verified``/``healthy`` (``degraded`` допускается с пониженным
весом) **и** активным согласием **и** с закрытым circuit breaker'ом.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
from collections.abc import Iterable
from dataclasses import dataclass, field

from foa.config import BalancerConfig, Settings
from foa.domain.enums import ROUTABLE_STATES, NodeState
from foa.domain.errors import ModelNotFoundError, NoHealthyNodesError
from foa.logging import get_logger
from foa.services.state import NodeRuntime

log = get_logger("balancer")


@dataclass(slots=True)
class Selection:
    node: NodeRuntime
    ticket: int = 0


@dataclass
class NodePool:
    """Множество узлов в рантайме + выбор цели (потокобезопасно)."""

    config: BalancerConfig
    settings: Settings | None = None
    nodes: dict[str, NodeRuntime] = field(default_factory=dict)
    _rr_cursor: dict[str, int] = field(default_factory=dict, repr=False)
    _wrr_state: dict[str, dict[str, int]] = field(default_factory=dict, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    _version: int = 0

    # -- синхронизация с реестром ----------------------------------------- #

    def sync(
        self,
        candidates: Iterable[tuple[NodeRuntime, bool]],
    ) -> dict[str, int]:
        """Принимает ``(runtime, consent_active)`` и пересобирает маршрутизируемое множество.

        Возвращает сводку по состояниям для метрик.
        """
        now_routable = 0
        counts: dict[str, int] = {}
        seen: set[str] = set()
        for runtime, consent_active in candidates:
            seen.add(runtime.node_id)
            previous = self.nodes.get(runtime.node_id)
            if previous is not None:
                # Сохраняем накопленную статистику между синхронизациями.
                runtime.ewma_latency_ms = previous.ewma_latency_ms or runtime.ewma_latency_ms
                runtime.samples = previous.samples
                runtime.breaker = previous.breaker
                runtime.active = previous.active
                runtime.requests_this_hour = previous.requests_this_hour
                runtime.tokens_this_hour = previous.tokens_this_hour
                runtime.requests_this_minute = previous.requests_this_minute
                runtime.hourly_requests_total = previous.hourly_requests_total
            routable = runtime.state in ROUTABLE_STATES and consent_active
            if runtime.state in {NodeState.BLACKLISTED, NodeState.QUARANTINED, NodeState.REVOKED}:
                routable = False
            runtime.routable = routable
            now_routable += 1 if routable else 0
            counts[runtime.state.value] = counts.get(runtime.state.value, 0) + 1
            self.nodes[runtime.node_id] = runtime
        for stale in set(self.nodes) - seen:
            self.nodes.pop(stale, None)
        self._version += 1
        return {"total": len(self.nodes), "routable": now_routable, **counts}

    def get(self, node_id: str) -> NodeRuntime | None:
        return self.nodes.get(node_id)

    def snapshot(self) -> list[dict]:
        return [node.snapshot() for node in self.nodes.values()]

    # -- выбор узла -------------------------------------------------------- #

    def eligible(
        self,
        model: str | None,
        *,
        exclude: set[str] | None = None,
        allow_degraded: bool = True,
    ) -> list[NodeRuntime]:
        """Кандидаты на обслуживание запроса (§7.2).

        Узлы в ``degraded`` допускается использовать только когда здоровых
        нет вовсе: §7.2 требует выбора «health = healthy», а §7.7 отводит
        degraded роли «временное исключение из маршрутизации» — то есть
        последняя опция, а не равноправный участник.

        Если все кандидаты достигли ``max_concurrency`` возвращаются они же —
        вызывающий встаёт в очередь ожидания (§7.1), а не уходит на узел,
        ограниченный чужим лимитом.
        """
        exclude = exclude or set()
        healthy: list[NodeRuntime] = []
        degraded: list[NodeRuntime] = []
        for node in self.nodes.values():
            if node.node_id in exclude or not node.routable:
                continue
            if not node.breaker.allow():
                continue
            if model and not node_supports_model(node, model):
                continue
            if not node.limits_allow():
                continue
            (degraded if node.state is NodeState.DEGRADED else healthy).append(node)
        if healthy:
            return _with_capacity(healthy)
        if degraded and allow_degraded:
            return _with_capacity(degraded)
        return []

    def candidates_for_model(self, model: str | None) -> list[NodeRuntime]:
        """Узел должен обслуживать только модели, указанные в согласии (§7.5)."""
        return [n for n in self.nodes.values() if n.routable and (not model or node_supports_model(n, model))]

    def pick(self, *, model: str | None = None, hash_key: str = "", exclude: set[str] | None = None) -> NodeRuntime:
        """Выбирает узел; бросает NoHealthyNodesError/ModelNotFoundError (§9.5).

        ``exclude`` — узлы, уже отказавшие в текущем запросе: повтор обязан
        выполняться на другом узле (§7.6).

        Каталог формируется только по маршрутизируемым узлам, поэтому 404 ничего
        не сообщает о нездоровых/несогласованных узлах (§9.3.2), а 503 выдаётся,
        когда согласованных узлов нет вовсе.
        """
        exclude = exclude or set()
        routable = [n for n in self.nodes.values() if n.routable]
        if not routable:
            raise NoHealthyNodesError()
        if model:
            supporting = [n for n in routable if node_supports_model(n, model)]
            if not supporting:
                raise ModelNotFoundError(f"модель {model!r} недоступна ни на одном согласованном узле")
        eligible = self.eligible(model, exclude=exclude)
        if not eligible:
            raise NoHealthyNodesError()
        return self._select(eligible, hash_key=hash_key or model or "")

    def _select(self, eligible: list[NodeRuntime], *, hash_key: str = "") -> NodeRuntime:
        algorithm = self.config.algorithm
        if algorithm == "round_robin":
            return self._round_robin(eligible, key="rr")
        if algorithm == "weighted_round_robin":
            return self._weighted_round_robin(eligible)
        if algorithm == "least_connections":
            return min(eligible, key=lambda n: (n.active / max(1, n.effective_weight), random.random()))
        if algorithm == "least_latency":
            return min(eligible, key=lambda n: (n.ewma_latency_ms or float("inf"), random.random()))
        if algorithm == "consistent_hash":
            return self._consistent_hash(eligible, hash_key)
        return self._hybrid(eligible)

    def _hybrid(self, eligible: list[NodeRuntime]) -> NodeRuntime:
        """§7.4 — least_connections_with_latency_and_error_penalty."""
        best = max(
            eligible,
            key=lambda n: n.score(
                capacity_weight=self.config.capacity_weight,
                latency_weight=self.config.latency_weight,
                latency_reference_ms=self.config.latency_reference_ms,
            ),
        )
        return best

    def _round_robin(self, eligible: list[NodeRuntime], *, key: str) -> NodeRuntime:
        ordered = sorted(eligible, key=lambda n: n.node_id)
        index = self._rr_cursor.get(key, 0) % len(ordered)
        self._rr_cursor[key] = (index + 1) % len(ordered)
        return ordered[index]

    def _weighted_round_robin(self, eligible: list[NodeRuntime]) -> NodeRuntime:
        """§7.3.2 — smooth weighted round robin в духе nginx."""
        ordered = sorted(eligible, key=lambda n: n.node_id)
        weights = {n.node_id: max(1, n.effective_weight) for n in ordered}
        total = sum(weights.values())
        currents = self._wrr_state.get("currents", {})
        if not isinstance(currents, dict) or set(currents) != set(weights):
            currents = dict.fromkeys(weights, 0)
        for node_id, weight in weights.items():
            currents[node_id] += weight
        chosen = max(ordered, key=lambda n: (currents[n.node_id], -n.active, n.node_id))
        currents[chosen.node_id] -= total
        self._wrr_state = {"currents": currents}  # type: ignore[assignment]
        return chosen

    def _consistent_hash(self, eligible: list[NodeRuntime], hash_key: str) -> NodeRuntime:
        """§7.3.5 — ring-хэш с ограничением перегрузки."""
        ring: list[tuple[int, NodeRuntime]] = []
        for node in eligible:
            for replica in range(max(1, node.effective_weight) * 20):
                digest = hashlib.blake2b(f"{hash_key}#{node.node_id}#{replica}".encode(), digest_size=8).digest()
                ring.append((int.from_bytes(digest, "big"), node))
        ring.sort(key=lambda item: item[0])
        target_digest = hashlib.blake2b(hash_key.encode(), digest_size=8).digest()
        target = int.from_bytes(target_digest, "big")
        idx = _bisect_ring([r[0] for r in ring], target)
        for offset in range(len(ring)):
            node = ring[(idx + offset) % len(ring)][1]
            if node.active < max(1, node.max_concurrency):
                return node
        return min(eligible, key=lambda n: n.active / max(1, n.max_concurrency))

    # -- резервирование ---------------------------------------------------- #

    def reserve(self, node: NodeRuntime, *, hash_key: str = "") -> int:
        """Занимает слот; возвращает «билет» для последующего освобождения."""
        node.note_request()
        node.acquire()
        return node.active

    def release(self, node: NodeRuntime) -> None:
        node.release()

    @property
    def version(self) -> int:
        return self._version


def _with_capacity(nodes: list[NodeRuntime]) -> list[NodeRuntime]:
    """Свободные узлы, либо все узлы, если свободных нет (очередь ожидания)."""
    free = [n for n in nodes if n.active < max(1, n.max_concurrency)]
    return free or nodes


def _bisect_ring(values: list[int], target: int) -> int:
    lo, hi = 0, len(values)
    while lo < hi:
        mid = (lo + hi) // 2
        if values[mid] < target:
            lo = mid + 1
        else:
            hi = mid
    return lo % len(values)


def available_models(node: NodeRuntime) -> set[str]:
    """Множество моделей, допустимых к обслуживанию на узле (§7.5)."""
    allowed = set(node.allowed_models or ())
    observed = set(node.models or ())
    if not allowed:
        return observed
    return {m for m in observed if m in allowed or any(m.startswith(f"{a}:") or a in m for a in allowed)}


def node_supports_model(node: NodeRuntime, model: str) -> bool:
    name = model.split(":", 1)[0]
    models = available_models(node)
    if model in models or name in models:
        return True
    return any(m == name or m.startswith(f"{name}:") or m.split(":", 1)[0] == name for m in models)


def build_runtime(node_row, consent_active: bool) -> NodeRuntime:
    """Преобразует строку реестра в рантайм-объект (используется NodeService)."""
    runtime = NodeRuntime(
        node_id=node_row.node_id,
        endpoint=node_row.endpoint,
        state=NodeState(node_row.status),
        max_concurrency=node_row.max_concurrency,
        weight=node_row.weight,
        effective_weight=node_row.effective_weight,
        ewma_latency_ms=node_row.ewma_latency_ms,
        models=tuple(node_row.observed_models or []),
        allowed_models=tuple(node_row.allowed_models or []),
        max_requests_per_hour=node_row.max_requests_per_hour,
        max_tokens_per_hour=node_row.max_tokens_per_hour,
    )
    runtime.routable = consent_active and runtime.state in ROUTABLE_STATES
    return runtime


__all__ = ["NodePool", "Selection", "available_models", "build_runtime", "node_supports_model"]
