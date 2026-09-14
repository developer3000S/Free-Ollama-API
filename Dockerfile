# Free Ollama API Gateway (§14.1)
#
# Multi-stage: зависимости ставятся в отдельный слой, в финальный образ попадают
# только установленный пакет и системный CA.
FROM python:3.12-slim AS builder
WORKDIR /src
COPY pyproject.toml README.md ./
COPY foa/__init__.py ./foa/__init__.py
# Отдельный слой для зависимостей: пересобирается только при их изменении.
COPY requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
COPY foa ./foa
RUN pip install --no-cache-dir --prefix=/install --no-deps .

FROM python:3.12-slim AS runtime
# nonroot: владелец узла и администратор не должны иметь возможности писать в ФС контейнера.
RUN groupadd --system --gid 10001 foa && useradd --system --uid 10001 --gid foa --create-home foa \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /install /usr/local
# Alembic-миграции (README «Миграции»): нужны для storage.migrations=alembic
# и для отдельного шага `docker compose run --rm gateway-a --migrate`.
COPY alembic.ini ./
COPY migrations ./migrations
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 FOA_SERVER__HOST=0.0.0.0 FOA_SERVER__PORT=8080 FOA_MIGRATIONS_ROOT=/app
USER foa
EXPOSE 8080
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status==200 else 1)"
ENTRYPOINT ["foa-gateway"]
# Роль worker (health-checker / discovery-worker) выбирается окружением:
# FOA_SERVER__RUN_BACKGROUND_LOOPS=false (см. docker-compose.yml).
CMD []
