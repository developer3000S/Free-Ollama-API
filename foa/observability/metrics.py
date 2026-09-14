"""Prometheus-метрики шлюза (§11.4)."""

from __future__ import annotations

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram, Info

# Ключевые метрики из таблицы §11.4
REQUESTS_TOTAL = Counter(
    "gateway_requests_total",
    "Total user requests handled by the gateway",
    ["route", "status", "error_code"],
)
REQUEST_DURATION = Histogram(
    "gateway_request_duration_seconds",
    "End-to-end request duration",
    ["route", "stream"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
)
GATEWAY_OVERHEAD = Histogram(
    "gateway_overhead_seconds",
    "Gateway overhead excluding upstream generation (§11.1 target <50ms p95)",
    ["route"],
    buckets=(0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1),
)
UPSTREAM_ERRORS_TOTAL = Counter(
    "gateway_upstream_errors_total",
    "Upstream node errors",
    ["node_id", "kind"],
)
ACTIVE_UPSTREAM_CONNECTIONS = Gauge(
    "gateway_active_upstream_connections",
    "Active upstream connections per node",
    ["node_id"],
)
RATE_LIMITED_TOTAL = Counter(
    "gateway_rate_limited_total",
    "Requests rejected by rate limiting / quotas",
    ["scope"],
)
NODE_HEALTH_STATUS = Gauge(
    "node_health_status",
    "Node health state (1 = current state)",
    ["node_id", "state"],
)
NODE_CONSENT_STATUS = Gauge(
    "node_consent_status",
    "Node consent state (1 = current state)",
    ["node_id", "state"],
)
NODE_BLACKLIST_TOTAL = Gauge("node_blacklist_total", "Nodes currently blacklisted")
NODE_LATENCY_MS = Gauge("node_latency_ms", "EWMA latency of a node in milliseconds", ["node_id"])
NODE_ERROR_RATE = Gauge("node_error_rate", "Sliding-window error ratio of a node", ["node_id"])
NODE_WEIGHT = Gauge("node_effective_weight", "Effective balancer weight after degradation", ["node_id"])
CIRCUIT_BREAKER_STATE = Gauge(
    "node_circuit_breaker_state",
    "Circuit breaker state (0 closed, 1 half-open, 2 open)",
    ["node_id"],
)
CANDIDATES_TOTAL = Counter(
    "discovery_candidates_total",
    "Candidates ingested by discovery",
    ["source", "outcome"],
)
CANDIDATE_QUEUE_SIZE = Gauge("discovery_candidate_queue_size", "Stored discovery candidates")
CONSENT_REVOCATION_LAG_SECONDS = Histogram(
    "consent_revocation_lag_seconds",
    "Time from revoke request to routing exclusion (§5.5 target <=5s)",
    buckets=(0.05, 0.25, 0.5, 1, 2, 5, 10, 30),
)
HEALTH_CHECK_TOTAL = Counter("health_checks_total", "Active health checks executed", ["kind", "result"])
POOL_WAIT_SECONDS = Histogram(
    "gateway_pool_wait_seconds",
    "Time spent waiting for a free upstream connection / balancer slot",
    buckets=(0.005, 0.02, 0.05, 0.1, 0.5, 1, 2, 5),
)
BUILD_INFO = Info("gateway_build", "Gateway build information")


def describe(registry: CollectorRegistry = REGISTRY) -> list[str]:
    return sorted({m.name for m in registry.collect()})


__all__ = [
    "ACTIVE_UPSTREAM_CONNECTIONS",
    "BUILD_INFO",
    "CANDIDATES_TOTAL",
    "CANDIDATE_QUEUE_SIZE",
    "CIRCUIT_BREAKER_STATE",
    "CONSENT_REVOCATION_LAG_SECONDS",
    "GATEWAY_OVERHEAD",
    "HEALTH_CHECK_TOTAL",
    "NODE_BLACKLIST_TOTAL",
    "NODE_CONSENT_STATUS",
    "NODE_ERROR_RATE",
    "NODE_HEALTH_STATUS",
    "NODE_LATENCY_MS",
    "NODE_WEIGHT",
    "POOL_WAIT_SECONDS",
    "RATE_LIMITED_TOTAL",
    "REGISTRY",
    "REQUESTS_TOTAL",
    "REQUEST_DURATION",
    "UPSTREAM_ERRORS_TOTAL",
    "CollectorRegistry",
    "describe",
]
