"""Сборка приложения Free Ollama API Gateway.

Использование:

.. code-block:: console

    $ python -m foa.app                # uvicorn по настройкам config.yaml
    $ foa-gateway --host 0.0.0.0       # то же через console script

:func:`create_app` собирает приложение без реального сервера, что позволяет
тестировать его через ``httpx.ASGITransport``.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path

import prometheus_client
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

from foa import __version__
from foa.api import admin, openai, user
from foa.api.deps import (
    gateway_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from foa.api.middleware import MetricsMiddleware, RequestContextMiddleware, RequestGuardMiddleware
from foa.config import ConfigError, Settings, load_settings
from foa.core.appstate import AppState
from foa.domain.enums import REQUEST_ID_HEADER
from foa.domain.errors import GatewayError
from foa.logging import configure_logging, get_logger
from foa.net.client import NodeTransport
from foa.observability import metrics as metrics_module
from foa.observability.metrics import BUILD_INFO
from foa.services.auth import AuthService
from foa.services.balancer import NodePool
from foa.services.consent import ConsentService
from foa.services.discovery import DiscoveryService
from foa.services.health import HealthChecker
from foa.services.nodes import NodeService
from foa.services.proxy import ProxyService
from foa.services.ratelimit import RateLimiter
from foa.storage.db import dispose_engine, get_session_factory, init_db, init_engine

log = get_logger("app")

DESCRIPTION = """
Free Ollama API Gateway — управляемый прокси-шлюз к пулу узлов Ollama.

Маршрутизация пользовательского трафика выполняется только на узлы, прошедшие
подтверждение владения и с активным согласием владельца (см. ТЗ, §5, §12).
""".strip()


def build_services(settings: Settings) -> AppState:
    """Создаёт граф сервисов. Порядок важен: транспорт → пул → сервисы."""
    transport = NodeTransport(
        pool=settings.pool,
        security=settings.security,
        connection_wait_timeout_seconds=settings.load_balancer.connection_wait_timeout_seconds,
    )
    pool = NodePool(config=settings.load_balancer, settings=settings)
    ratelimit = RateLimiter(settings)
    auth = AuthService(settings)
    consent = ConsentService(settings, transport)
    health = HealthChecker(settings, transport, consent_service=consent)
    nodes = NodeService(settings, pool, consent, transport, health_checker=health)
    health.on_state_change = _make_state_hook(nodes)
    proxy = ProxyService(settings, pool, transport, ratelimit, node_service=nodes)
    discovery = DiscoveryService(settings)
    return AppState(
        settings=settings,
        transport=transport,
        pool=pool,
        ratelimit=ratelimit,
        auth=auth,
        consent=consent,
        nodes=nodes,
        health=health,
        discovery=discovery,
        proxy=proxy,
    )


def _make_state_hook(nodes: NodeService):
    async def hook(node_id: str, old, new, reason: str) -> None:
        try:
            async with get_session_factory()() as session:
                await nodes.sync_pool(session)
                await session.commit()
        except Exception as exc:
            log.debug("app: sync_pool after transition failed: %s", exc)

    return hook


def create_app(settings: Settings | None = None, *, state: AppState | None = None) -> FastAPI:
    """Собирает FastAPI-приложение шлюза."""
    settings = settings or load_settings()
    configure_logging(settings.observability.log_level, settings.observability.log_format)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        await startup(app, settings, state)
        try:
            yield
        finally:
            await shutdown(app)

    app = FastAPI(
        title="Free Ollama API Gateway",
        version=__version__,
        description=DESCRIPTION,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    BUILD_INFO.info({"version": __version__, "gateway_id": settings.gateway_id})

    app.add_exception_handler(GatewayError, gateway_error_handler)
    # §8.6 — фолбэк для неклассифицированных исключений: клиент получает
    # обезличенный 500, внутренние детали уходят только в журнал.
    app.add_exception_handler(Exception, unhandled_error_handler)
    try:
        from fastapi.exceptions import RequestValidationError

        app.add_exception_handler(RequestValidationError, validation_error_handler)
    except ImportError:  # pragma: no cover
        pass

    prefix = (settings.server.api_prefix or "").rstrip("/")
    if prefix:
        # Совместимость с Ollama (§9.1): поддерживаем и корневые, и префиксные пути.
        app.include_router(user.router, prefix=prefix)
        app.include_router(admin.router, prefix=prefix)
        if settings.server.openai_api_enabled:
            app.include_router(openai.router, prefix=prefix)
    app.include_router(user.router)
    app.include_router(admin.router)
    if settings.server.openai_api_enabled:
        # Второй контракт (§18): OpenAI-совместимые /v1/* поверх того же consent gate.
        app.include_router(openai.router)

    _register_operational_routes(app, settings)

    # add_middleware вставляет в начало цепочки: внешний — RequestContext.
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(RequestGuardMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware, settings=settings)
    return app


def _register_operational_routes(app: FastAPI, settings: Settings) -> None:
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__}, headers={REQUEST_ID_HEADER: "health"})

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> JSONResponse:
        state = get_state_from_app(app)
        routable = sum(1 for node in state.pool.nodes.values() if node.routable)
        body = {"status": "ready" if routable else "degraded", "routable_nodes": routable, "version": __version__}
        return JSONResponse(body, status_code=200 if routable else 503, headers={REQUEST_ID_HEADER: "ready"})

    if settings.observability.metrics_enabled:

        @app.get(settings.observability.metrics_path, include_in_schema=False)
        async def prometheus() -> PlainTextResponse:
            state = get_state_from_app(app)
            _refresh_runtime_gauges(state)
            payload = prometheus_client.generate_latest().decode("utf-8", "replace")
            return PlainTextResponse(payload, media_type="text/plain; version=0.0.4; charset=utf-8")


def get_state_from_app(app: FastAPI) -> AppState:
    state = getattr(app.state, "foa", None)
    if state is None:  # pragma: no cover - только при неверной сборке
        raise RuntimeError("приложение не инициализировано")
    return state


def _refresh_runtime_gauges(state: AppState) -> None:
    for node_id, runtime in state.pool.nodes.items():
        metrics_module.ACTIVE_UPSTREAM_CONNECTIONS.labels(node_id=node_id).set(runtime.active)
        metrics_module.NODE_LATENCY_MS.labels(node_id=node_id).set(runtime.ewma_latency_ms)
        metrics_module.NODE_ERROR_RATE.labels(node_id=node_id).set(runtime.error_rate)
        metrics_module.NODE_WEIGHT.labels(node_id=node_id).set(runtime.effective_weight)
        metrics_module.CIRCUIT_BREAKER_STATE.labels(node_id=node_id).set(runtime.breaker.state)
        metrics_module.NODE_HEALTH_STATUS.labels(node_id=node_id, state=runtime.state.value).set(1)


async def startup(app: FastAPI, settings: Settings, state: AppState | None = None) -> AppState:
    """Инициализация БД, синхронизация пула, запуск фоновых циклов."""
    if settings.storage.data_dir:
        Path(settings.storage.data_dir).mkdir(parents=True, exist_ok=True)
    mode = settings.storage.migrations
    if mode == "alembic":
        from foa.storage.migrations import apply_migrations

        await apply_migrations(settings.storage.database_url)
    engine = init_engine(settings.storage.database_url)
    await init_db(engine, create_schema=mode != "alembic")
    state = state or build_services(settings)
    state.session_factory = get_session_factory()
    app.state.foa = state
    async with state.factory()() as session:
        summary = await state.nodes.sync_pool(session)
        await session.commit()
    if not settings.auth.admin_token:
        log.warning(
            "app:admin_token_missing",
            extra={"foa": {"event": "app.admin_token_missing", "note": "админ-контур закрыт (fail-closed) до задания токена"}},
        )
    log.info(
        "app:started",
        extra={
            "foa": {
                "event": "app.started",
                "version": __version__,
                "gateway_id": settings.gateway_id,
                "discovery_mode": settings.discovery.mode,
                "nodes": summary,
            }
        },
    )
    await state.start_background()
    return state


async def shutdown(app: FastAPI) -> None:
    state: AppState | None = getattr(app.state, "foa", None)
    if state is not None:
        await state.shutdown()
    await dispose_engine()
    log.info("app:stopped", extra={"foa": {"event": "app.stopped"}})


def serve(settings: Settings | None = None) -> FastAPI:
    """Фабрика приложения для uvicorn (``--reload`` требует её строковое имя)."""
    return create_app(settings or load_settings())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="foa-gateway", description="Free Ollama API Gateway")
    parser.add_argument("--config", default=None, help="путь к config.yaml (или FOA_CONFIG_FILE, или ./config.yaml)")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--log-level", default=None)
    parser.add_argument("--print-config", action="store_true", help="показать действующую конфигурацию и выйти")
    parser.add_argument("--check-config", action="store_true", help="проверить конфигурацию и выйти")
    parser.add_argument("--migrate", action="store_true", help="применить Alembic-миграции (upgrade head) и выйти")
    parser.add_argument("--stamp", action="store_true", help="отметить существующую create_all-схему как head, не выполняя DDL")
    args = parser.parse_args(argv)

    # Приложение строится фабрикой serve(), которая заново вызывает load_settings()
    # и не видит аргументы CLI: пробрасываем их через окружение, иначе --config/
    # --host/--port/--log-level применялись бы только к проверкам ниже, а не к
    # запущенному шлюзу.
    if args.config:
        os.environ["FOA_CONFIG_FILE"] = str(args.config)
    if args.host:
        os.environ["FOA_SERVER__HOST"] = str(args.host)
    if args.port:
        os.environ["FOA_SERVER__PORT"] = str(args.port)
    if args.log_level:
        os.environ["FOA_OBSERVABILITY__LOG_LEVEL"] = str(args.log_level)

    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"ошибка конфигурации: {exc}", file=sys.stderr)
        return 2
    if args.check_config:
        print("конфигурация корректна: безопасный режим по умолчанию (§13)")
        return 0
    if args.migrate or args.stamp:
        import asyncio

        from foa.storage.migrations import apply_migrations, stamp_head

        try:
            if args.stamp:
                asyncio.run(stamp_head(settings.storage.database_url))
            else:
                asyncio.run(apply_migrations(settings.storage.database_url))
        except Exception as exc:
            print(f"миграции не выполнены: {exc}", file=sys.stderr)
            return 2
        print("схема отмечена как head (DDL не выполнялся)" if args.stamp else "миграции применены: схема БД обновлена до head")
        return 0
    if args.print_config:
        import json

        from foa.api.admin import _redacted

        print(json.dumps(_redacted(settings.as_dict()), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.host:
        settings.server.host = args.host
    if args.port:
        settings.server.port = args.port
    if args.log_level:
        settings.observability.log_level = args.log_level

    import uvicorn

    uvicorn.run(
        "foa.app:serve",
        host=settings.server.host,
        port=settings.server.port,
        reload=args.reload,
        log_config=None,
        access_log=False,
        factory=True,
    )
    return 0


__all__ = ["AppState", "build_services", "create_app", "get_state_from_app", "main", "serve", "shutdown", "startup"]


if __name__ == "__main__":
    raise SystemExit(main())
