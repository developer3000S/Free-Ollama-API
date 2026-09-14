# Free Ollama API Gateway

Управляемый прокси-шлюз с Ollama-совместимым API поверх пула узлов Ollama, **владелец
которых явно подтвердил участие**. Реализация ТЗ [`ТЗ.md`](ТЗ.md) (версия 1.0.0).

> **Ключевое положение (§1.1, §2.1, §19).** Шлюз не является «поисковиком бесплатных
> LLM». Пользовательский трафик уходит только на узлы, прошедшие подтверждение
> владения и активное согласие. Обнаруженные в интернете хосты Ollama становятся
> не узлами, а **кандидатами**: они не получают трафик никогда, пока владелец сам
> не зарегистрирует узел и не подтвердит владение (§4.4.4). Обход этого условия
> блокируется не только кодом, но и проверкой конфигурации на старте.

---

## Содержание

- [Что это и зачем](#что-это-и-зачем)
- [Быстрый старт](#быстрый-старт)
- [Пользовательский API](#пользовательский-api)
- [OpenAI-совместимый API (`/v1/*`)](#openai-совместимый-api-v1)
- [Владелец узла: согласие за 5 минут](#владелец-узла-согласие-за-5-минут)
- [Администратор: реестр, ключи, отзыв](#администратор-реестр-ключи-отзыв)
- [Discovery (§4)](#discovery-4)
- [Конфигурация](#конфигурация)
- [Наблюдаемость](#наблюдаемость)
- [Масштабирование](#масштабирование)
- [Миграции](#миграции)
- [Безопасность и этика](#безопасность-и-этика)
- [Тесты и качество](#тесты-и-качество)
- [Критерии приемки (§17)](#критерии-приемки-17)
- [Структура кода](#структура-кода)
- [Ограничения и что не реализовано](#ограничения-и-что-не-реализовано)

---

## Что это и зачем

Три контура в одном процессе (§3.2):

| Контур | Кто им пользуется | Код |
|---|---|---|
| Пользовательский Ollama-совместимый API | держатели ключей `foa_…` | `foa/api/user.py` |
| Административный API + self-service владельца | администратор, аудитор, владельцы узлов | `foa/api/admin.py`, `foa/cli/owner.py` |
| Служебный (health, discovery, реестр) | фоновые циклы той реплики, которой включена роль | `foa/services/`, `foa/core/appstate.py` |

Пользователь шлюза видит обычный Ollama API и не знает (и не должен знать), какой
именно узел обработал запрос. Владелец узла видит метаданные обращений и в любой
момент отзывает согласие. Администратор управляет реестром, лимитами и блэклистом.

---

## Быстрый старт

Требуется Python ≥ 3.11 (проверено на 3.11.2).

```bash
git clone git@github.com:developer3000S/Free-Ollama-API.git
cd Free-Ollama-API
python3.11 -m venv .venv
.venv/bin/pip install -e .            # зависимости из pyproject.toml
# опционально: .venv/bin/pip install -e '.[dev]'   (pytest, ruff, mypy)
# опционально: .venv/bin/pip install -e '.[postgres,redis]'  для прода
```

Конфигурация для знакомства — стартовый стенд на локальном SQLite, без секретов:

```bash
cp .env.example .env                  # заполните токены и GATEWAY_* (см. ниже)
.venv/bin/foa-gateway --config config.example.yaml --check-config
# → конфигурация корректна: безопасный режим по умолчанию (§13)

.venv/bin/foa-gateway --config config.example.yaml --print-config   # действующие значения, секреты маскируются
.venv/bin/foa-gateway --config config.example.yaml                  # запуск на 127.0.0.1:8080
```

После запуска:

| Адрес | Назначение |
|---|---|
| `GET /healthz` | процесс жив: `{"status":"ok"}` |
| `GET /readyz` | готовность обслуживать: `{"status","routable_nodes","version"}`; `503`, если маршрутизируемых узлов 0 |
| `GET /metrics` | Prometheus (§11.4) — наружу не публиковать |
| `GET /docs` | OpenAPI-интерфейс (`/openapi.json`) |

Флаги `foa-gateway`: `--config`, `--host`, `--port`, `--log-level`, `--reload`,
`--check-config`, `--print-config`. Путь к файлу также задаётся переменной
`FOA_CONFIG_FILE` (по умолчанию `./config.yaml`, его отсутствие — не ошибка).

Контейнеризованная топология (§14.1) — 2 реплики шлюза, отдельный health-checker,
Prometheus и nginx с TLS:

```bash
cp .env.example .env    # обязательно: POSTGRES_PASSWORD, FOA_ADMIN_TOKEN, ...
docker compose up -d --build
docker compose --profile discovery up -d   # + worker инвентаризации (трафик не маршрутизируется)
```

---

## Пользовательский API

Ollama-совместимый контракт (§9.3). Базовый путь — корень (`/api/*`); при размещении
за общим ingress путь задаётся `server.api_prefix` (например `/v1/ollama`), §9.1.
Все эндпоинты требуют `Authorization: Bearer <ключ>` (§9.2) — без ключа `401`, при
валидном ключе узел подбирает балансировщик.

```bash
KEY=$(curl -s -X POST http://127.0.0.1:8080/admin/keys \
  -H "Authorization: Bearer $FOA_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"label":"demo","scopes":["ollama:generate"],"tokens_per_day":20000}' | jq -r .api_key)

curl -s -X POST http://127.0.0.1:8080/api/generate \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"llama3.1","prompt":"Привет","stream":false}'
```

Ключ выдаётся с набором скоупов (§9.2); проверка — `require_scope` /
`generation_slot` в `foa/api/deps.py`:

| Скоуп | Даёт право |
|---|---|
| *(любой валидный ключ)* | `GET /api/version` — только аутентификация |
| `ollama:read` | `tags`, `show`, `ps` |
| `ollama:generate` | `generate`, `chat`, `embed` |
| `ollama:embed` | `embeddings` (допускается и `ollama:generate`) |
| `admin:read` / `admin:write` | админ-контур только для чтения / с изменением (§9.6) |
| `node:self_service` | владельцу — его узлы (согласие, статус, отзыв) |


| Метод / путь | Назначение |
|---|---|
| `GET /api/version` | версия шлюза (`gateway-<version>`) и поддерживаемый upstream-контракт, §9.3.1 |
| `GET /api/tags` | **агрегатный** список моделей по всем маршрутизируемым узлам (§9.3.2) |
| `POST /api/show` | метаданные модели (маршрутизируется на узел, где модель есть) |
| `GET /api/ps` | смоделированные модели с всех маршрутизируемых узлов, дедуп по имени |
| `POST /api/generate` | генерация, `stream: true` → NDJSON |
| `POST /api/chat` | чат, `stream: true` → NDJSON |
| `POST /api/embeddings`, `POST /api/embed` | эмбеддинги |


**Запрещённые операции (§9.4).** `pull`, `push`, `copy`, `delete` управляются
владельцем/администратором, а не пользователем, поэтому возвращают явный `403`
(`FORBIDDEN_USER_OPERATIONS` в `foa/domain/enums.py`), а не `404` — чтобы отказ
был объясним. Остальные неизвестные пути под `/api/*` → `404 MODEL_NOT_FOUND`.

**Заголовки (§8.5).** Клиент может передать `X-FOA-Request-ID`; шлюз отвечает
`X-FOA-Request-ID`, `X-FOA-RateLimit-Limit/Remaining/Reset`, а при `429` —
`Retry-After`. Узлам **не** передаются оригинальный `Authorization` клиента, его IP
(взамен — `X-FOA-Client-Hash: sha256:…`, §8.5.3) и любые `X-FOA-*`-заголовки,
выдающие топологию.

**Ошибки (§9.5).** Совместимый с Ollama формат `{"error": "…"}` дополнен
`code`, `request_id`, `retry_after`, `details`. Коды → HTTP-статусы заданы
в `ERROR_HTTP_STATUS` (`foa/domain/enums.py`): `UNAUTHORIZED` 401, `CONSENT_REQUIRED`
403, `RATE_LIMITED` 429, `QUOTA_EXCEEDED` 429, `MODEL_NOT_FOUND` 404,
`NO_HEALTHY_NODES` 503, ошибки upstream → 502/504.

**Потоки (§8.4).** NDJSON проксируется без буферизации и со `identity`-кодированием;
обрыв клиента отменяет запрос к узлу (`test_stream_aborted_when_client_disconnects`).

**Повторы (§7.6).** Повтор возможен только если узел **не получил** запрос
(`kind == "connect"`). После начала обработки повтор запрещён: для генерации он
не делается вовсе (`retry_after_upstream_started: false`), потоковые ответы
не повторяются после первого байта — ошибка отдаётся в поток как
`{"error":…,"code":"UPSTREAM_ERROR"}`. `X-FOA-Request-ID` сохраняется на всех
попытках.

---

## OpenAI-совместимый API (`/v1/*`)

Второй контракт поверх того же Ollama API (§18 п.1: «OpenAI-совместимый API как
второй контракт»). Это **не** отдельная маршрутизация и не обходной путь: запрос
конвертируется в телеграммы `/api/*`, поэтому к нему применяются те же скоупы,
лимиты, бюджеты, повторная дисциплина и, главное, consent gate — узел без
активного согласия не получит запрос и через `/v1/*` (проверено
`test_openai_respects_consent_gate`).

```bash
curl -s https://gw.example.com/v1/chat/completions \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"llama3.1","messages":[{"role":"user","content":"Привет"}],"stream":true}'
```

| Эндпоинт | Отображается на | Требует скоуп |
|---|---|---|
| `GET /v1/models` | `GET /api/tags` (агрегат, без адресов узлов) | `ollama:read` |
| `GET /v1/models/{id}` | тот же агрегат | `ollama:read` |
| `POST /v1/chat/completions` | `POST /api/chat` | `ollama:generate` |
| `POST /v1/completions` | `POST /api/generate` | `ollama:generate` |
| `POST /v1/embeddings` | `POST /api/embed` | `ollama:embed` или `ollama:generate` |

Отключается одной строкой: `server.openai_api_enabled: false`
(`FOA_SERVER__OPENAI_API_ENABLED=false`) — Ollama API при этом не затрагивается.

**Формат ошибок** выбирается по пути запроса: `/v1/*` отвечаются конвертом
OpenAI (`{"error": {"message","type","param","code"}}`, где `type` —
`authentication_error`, `permission_denied`, `rate_limit_error`,
`invalid_request_error`, `api_error`), а `/api/*` и `/admin/*` сохраняют
совместимый с Ollama формат §9.5 (`error`, `code`, `request_id`). Оба формата
несут один и тот же HTTP-статус, `Retry-After` и `X-FOA-Request-ID`
(проверено `test_ollama_contract_error_format_unchanged`).

**Потоки:** Ollama NDJSON → SSE `chat.completion.chunk` без буферизации:
первый чанк с `delta.role`, дельты контента, финальный чанк с `finish_reason`,
`data: [DONE]`. `stream_options.include_usage: true` добавляет отдельный
финальный чанк с пустыми `choices` и `usage`. Обрыв upstream после первого
байта (§7.6 — повтор уже невозможен) отдаётся объектом ошибки внутри потока,
а не молча оборванным SSE.

**Маппинг параметров:** `max_tokens`/`max_completion_tokens` → `options.num_predict`,
`temperature` → `temperature`, `top_p` → `top_p`, `stop` → `stop`,
`presence_penalty`/`frequency_penalty` → одноимённые, `seed` → `seed`,
`role: developer` → `role: system`, `response_format: json_object` →
`format: "json"`, `response_format: json_schema` → `format: <schema>`,
`tools` → `tools` (Ollama-формат), мультимодальные `image_url` c `data:` URI →
`images`. Поле `user` не пересылается: узлу не передаётся идентификатор клиента
(§8.5.3), как и в Ollama-контракте.

**Что честно не поддерживается** и отклоняется с `unsupported parameter(s)`
(§17.7 — молчаливое игнорирование хуже отказа): `n>1`, `logprobs`, `top_logprobs`,
`encoding_format: base64`, неизвестные `response_format.type`. Неизвестные поля
контракта (`store`, `metadata`, `service_tier`) отбрасываются: payload для узла
собирается явным списком, поэтому произвольный параметр на узел не уходит
(§12.4.5). Внешние `http(s)`-ссылки в `image_url` не пересылаются — их скачивал
бы узел, что было бы SSRF из чужого процесса (§12.5.1).

---

## Владелец узла: согласие за 5 минут

CLI `foa-owner` (§5, §9.6.2) закрывает владельческий self-service: ключи, документ
согласия, три способа подтверждения владения, отзыв и удаление данных.

```bash
export FOA_GATEWAY_URL=https://gw.example.com
export FOA_OWNER_TOKEN=...        # выдал администратор; скоуп node:self_service
```

### Способ 1 — `http_well_known` (файл на узле, §5.3.1)

```bash
# 1. регистрация: шлюз выдаёт node_id + одноразовый challenge
foa-owner register --endpoint https://ollama.example.com:11434 --models llama3.1,qwen2.5

# 2. отдать документ согласия. Быстрая проверка локальным сервером CLI:
foa-owner serve-consent --node-id node_01J… --challenge … --endpoint https://ollama.example.com:11434
# ...или сформировать файл и разместить его самому:
foa-owner consent-file --node-id node_01J… --challenge … --endpoint https://ollama.example.com:11434 \
  --output consent.json
# путь публикации: /.well-known/free-ollama/v1/consent.json

# 3. подтвердить владение
foa-owner verify --node-id node_01J…
```

Все три шага одним прогоном: `foa-owner publish --endpoint … --models … --serve`.

### Способ 2 — `dns_txt` (§5.3.2)

```bash
foa-owner dns-record --node-id node_01J… --challenge … --endpoint ollama.example.com
# → значение TXT для _free-ollama-challenge.example.com
foa-owner dns-record … --zone-file        # строка для zone file
foa-owner verify --node-id node_01J…      # шлюз читает TXT через dnspython
```

IP-адрес вместо домена отклоняется: TXT-подтверждение для него бессмысленно.

### Способ 3 — `signed_token` (Ed25519, §5.3.3)

```bash
foa-owner keygen                                   # приватный ключ — 0600, в stdout не печатается
foa-owner public-key                               # этот ключ передаёт администратору
foa-owner token --node-id node_01J… --owner-id acme --models llama3.1 --output consent.jwt
foa-owner verify --node-id node_01J… --method signed_token --token-file consent.jwt
```

Администратор один раз публикует публичный ключ владельца:
`PUT /admin/owners/{owner_ref}/public-key`.

### Остальные команды

`status` (`/admin/status` или узел), `revoke` (§5.5), `delete --yes` (§12.7.7 —
удаление узла и его данных), `render-page` (HTML-страница с `consent.json`, содержимое
экранируется). Секреты — только из `FOA_OWNER_TOKEN`/`FOA_ADMIN_TOKEN` или флагов
`--owner-token`/`--admin-token`; публичный ключ (`--admin-token`) доступен read-командам,
чужие узлы владельцу не отдаются (`403`).

---

## Администратор: реестр, ключи, отзыв

29 эндпоинтов `/admin/*` (§9.6), три отдельных токена и явный fail-closed:
**пустой `auth.admin_token` полностью закрывает контур** — ни одна операция
не доступна.

```bash
curl -s -H "Authorization: Bearer $FOA_ADMIN_TOKEN" http://127.0.0.1:8080/admin/status | jq
```

| Группа | Эндпоинты |
|---|---|
| Узлы | `GET/POST /admin/nodes`, `GET/PATCH/DELETE /admin/nodes/{id}`, `POST …/verify`, `POST …/consent-document`, `POST …/revoke`, `POST …/health-check` |
| Блэклист | `POST/… /admin/nodes/{id}/blacklist`, `…/unblacklist`, `GET /admin/blacklist` |
| Согласия | `GET/POST /admin/consents`, `GET /admin/consents/{id}` (история — §12.7.4) |
| Ключи | `GET/POST /admin/keys`, `POST /admin/keys/{id}/revoke`, `…/rotate` (grace-период §12.4.1) |
| Discovery | `GET /admin/candidates`, `DELETE /admin/candidates/{id}`, `POST …/enroll` (только с ведома владельца), `POST /admin/discovery/run` |
| Прочее | `PUT /admin/owners/{id}/public-key`, `GET /admin/audit`, `GET /admin/config`, `POST /admin/config/reload`, `POST /admin/abuse-reports` |

Права разведены по скоупам: `admin:read` (аудитор) / `admin:write` (администратор) /
`node:self_service` (владелец, только свои узлы) — §2.2, §17.9. `POST /admin/config/reload`
перезагружает нечувствительные параметры без рестарта (§11.5); секреты в ответах
и в журнале маскируются (`_redacted`).

---

## Discovery (§4)

Единственное назначение модуля — **инвентаризация**, а не поиск бесплатных серверов.

```yaml
discovery:
  enabled: true                 # выключено по умолчанию
  mode: inventory_only          # inventory_only | disabled
  active_scanning: deny         # активного сканирования нет ни в одном режиме (§4.4.1)
  auto_route_candidates: false  # отклоняется валидацией, если попытаться поставить true
  retain_days: 90               # §4.7 — по истечении кандидат удаляется purge'ем
  risk_manual_review_threshold: 70
  sources:
    censys:
      enabled: false            # все пять источников выключены по умолчанию
      api_id: "{env:CENSYS_API_ID}"
      api_secret: "{env:CENSYS_API_SECRET}"
      allowed_scopes: ["asn:AS9009", "192.0.2.0/24", "*.example.com"]
      purpose: inventory
      cache_ttl_seconds: 86400
      max_requests_per_minute: 10
```

Конвейер кандидата (`foa/services/discovery/`):

1. **Источник** (Censys, GreyNoise, ZoomEye, Natlas, Criminal IP) опрашивается только
   через публичный API платформы, с троттлингом `max_requests_per_minute` и кэшем
   `cache_ttl_seconds`. Ключ без `allowed_scopes` не даёт включить источник — запуск
   завершится `ConfigError` (§4.4.3, FR-D-03).
2. **Scope-фильтр**: кандидат остаётся, только если попадает в `allowed_scopes`
   оператора (ASN / CIDR / домен, `foa/domain` — сравнение по всем измерениям,
   пустой список = запрет). Так исключается «случайный чужой хост из выдачи платформы».
3. **SSRF-фильтр**: адреса loopback, приватные, link-local и метаданные отбрасываются,
   как и хосты, которые в них резолвятся.
4. **Дедупликация** по `(ip, port, protocol)` с сохранением большего `risk_score`
   и обогащением от GreyNoise/Criminal IP.
5. **Статус** `candidate` → `requires_manual_review` (при высоком риске) → `enrolled`
   (только после регистрации владельца и подтверждения владения) / `rejected` /
   `out_of_scope` / `expired` / `deleted`.

**Кандидат не получает пользовательский трафик и активные проверки** — это
инвариант (`ROUTABLE_STATES`, `NON_ROUTABLE_STATES` в `foa/domain/enums.py`), а не
настройка. `POST /admin/candidates/{id}/enroll` заводит узел в состоянии
`pending_consent` и отправляет владельцу приглашение с `challenge`; маршрутизируемым
он станет только после §5.3. Все переходы — в аудите; `GET /admin/candidates` и
`POST /admin/discovery/run` (запустить цикл вручную) доступны с `admin:read`/`admin:write`.

---

## Конфигурация

Приоритет источников (§13, §14.2), от меньшего к большему:

1. встроенные безопасные значения по умолчанию;
2. `config.yaml` (`--config` / `FOA_CONFIG_FILE`) — см. [`config.example.yaml`](config.example.yaml);
3. переменные вида `FOA_СЕКЦИЯ__КЛЮЧ` (`FOA_SECURITY__ROUTE_CANDIDATES=true`,
   вложенно — `FOA_DISCOVERY__SOURCES__CENSYS__ENABLED=true`);
4. совместимые переменные ТЗ §14.2 (`GATEWAY_DB_URL`, `GATEWAY_REDIS_URL`,
   `GATEWAY_JWT_SECRET`, `GATEWAY_ID`, `CENSYS_API_ID`, …) — они **ниже** `FOA_*`.

Секреты в файл не пишутся: `{env:VAR}`, `{file:/path}`, `{vault:path}`,
`{api_key_service}` (`foa/config/secretrefs.py`). Поддерживаются Vault, AWS/GCP/Azure
Secrets Manager и Kubernetes Secrets (§14.2).

Безопасный режим по умолчанию (§13): `require_consent: true`,
`allow_unverified_nodes: false`, `active_scanning: deny`, `route_candidates: false`,
`store_prompt_bodies: false`, `store_response_bodies: false`, `forward_client_ip: false`,
60 запросов/мин и 2 одновременных запроса на пользователя, `max_generation_seconds: 300`,
балансировка `least_connections_with_latency` с запретом повторов.

**Небезопасный откат невозможен молча** — `Settings.validate()` (`fail-fast`,
`ConfigError` на старте) отклоняет: `route_candidates: true`,
`allow_unverified_nodes: true`, `require_consent: false`, `auto_route_candidates: true`,
неизвестный алгоритм балансировки, источник discovery с включённым `enabled`, но пустым
`allowed_scopes` (§4.4.3), а также `registry_sync_interval_seconds >
consent_revocation_apply_seconds` (иначе §5.5 невыполним).

---

## Наблюдаемость

Структурированные JSON-логи (`foa/logging`), метрики Prometheus, панель Grafana.

**Ключевые метрики (§11.4):** `gateway_requests_total{route,status,error_code}`,
`gateway_request_duration_seconds{route,stream}`, `gateway_overhead_seconds`,
`gateway_upstream_errors_total{node_id,kind}`, `gateway_active_upstream_connections{node_id}`,
`gateway_pool_wait_seconds`, `gateway_rate_limited_total{scope}`,
`node_health_status{node_id,state}`, `node_consent_status{node_id,state}`,
`node_blacklist_total`, `node_latency_ms`, `node_error_rate`, `node_effective_weight`,
`node_circuit_breaker_state`, `consent_revocation_lag_seconds`,
`health_checks_total{kind,result}`, `discovery_candidates_total{source,outcome}`,
`discovery_candidate_queue_size`, `gateway_build_info`.

- Конфиг Prometheus: [`deploy/prometheus.yml`](deploy/prometheus.yml).
- Дашборд (12 панелей, в т.ч. задержка отзыва согласия с порогом 5 с):
  импортировать [`deploy/grafana-dashboard.json`](deploy/grafana-dashboard.json).
- Ingress с TLS, сегментацией `/admin/` и отключённой буферизацией для `/api/`:
  [`deploy/nginx.conf`](deploy/nginx.conf).
- `/metrics` наружу не публикуется (§11.4).

---

## Масштабирование

Шлюз проксирующий и шлюз с фоновыми циклами — **разные роли**, чтобы 2+ реплики
не умножали нагрузку на узлы владельцев (§14.1, §6.1). Переключатель —
`server.run_background_loops`:

| Роль | `run_background_loops` | Что делает |
|---|---|---|
| `gateway-a`, `gateway-b` | `false` | только проксирует пользовательский трафик + `_registry_sync_loop()` — перечитывает реестр и согласия из БД каждые `server.registry_sync_interval_seconds` (по умолчанию 2 с) |
| `health-checker` | `true` | активные liveness/readiness/consent-проверки, единственный владелец циклов |
| `discovery-worker` | `true` | инвентаризация источников → кандидаты (профиль `discovery`) |

Разделение работает за счёт того, где хранится состояние:

- **в БД** — узлы, согласия и их история, ключи, блэклист, кандидаты, аудит.
  Общий для всех реплик; именно из него реплики узнают об отзыве;
- **в памяти процесса** — счётчики нагрузки, EWMA-задержки, sliding-window доли
  ошибок, состояние circuit breaker, пулы httpx (`foa/services/state.py`).
  Они локальны по замыслу: балансировка смотрит на собственную наблюдаемую
  картину реплики, поэтому добавление реплики не требует консенсуса и не создаёт
  горячих точек.

Требования к горизонтальному масштабированию:

1. **Postgres** (`GATEWAY_DB_URL=postgresql+asyncpg://…`) — при SQLite реплики
   не могут иметь общее состояние; SQLite годится только для одиночного стенда.
2. **Redis** (`GATEWAY_REDIS_URL`) — иначе rate-limit, конкурентность и квоты
   (`foa/services/ratelimit.py`) действуют в масштабе одного процесса, то есть
   фактические лимиты пользователя растут числом реплик.
3. **Отзыв согласия ≤5 с (§5.5, §17.3)** обеспечивается не рестартом, а
   перечитыванием реестра: `registry_sync_interval_seconds` обязан быть меньше
   `health.consent_revocation_apply_seconds` — это проверяется на старте.
   Дополнительно согласие сверяется в трёх точках: при выдаче маршрута, при
   выборе в балансировщике и в контуре перепроверки здоровья.
4. **Вывод узла из эксплуатации** — `PATCH /admin/nodes/{id} {"draining": true}`
   переводит его в `draining`: новые запросы на него не идут, активные
   завершаются (§6.4). `server.graceful_shutdown_seconds` описывает целевое окно
   завершения стримов при рестарте реплики (uvicorn `timeout_graceful_shutdown`
   передаётся аргументом запуска, в коде значения по умолчанию нет).
5. **Рестарт реплики не роняет маршрутизацию** — состояние узлов перечитывается
   из БД при старте, а схема (см. [Миграции](#миграции)) общая для всех реплик.

---

## Миграции

Схема БД описана в `foa/storage/models.py` (SQLAlchemy 2.0, `Base.metadata`),
Alembic подключён: `alembic.ini` + `migrations/` с начальной ревизией
`initial schema`. Способ наведения схемы выбирается параметром
`storage.migrations`:

| Значение | Поведение |
|---|---|
| `create_all` (по умолчанию) | `init_db()` вызывает `Base.metadata.create_all` — совместимо с §14.1 и локальными стендами |
| `alembic` | при старте выполняется `alembic upgrade head`, `create_all` не вызывается |
| `off` | шлюз схему не трогает вообще — наводит оператор отдельным шагом |

Команды:

```bash
.venv/bin/alembic upgrade head                       # через CLI (URL из GATEWAY_DB_URL)
.venv/bin/alembic check                              # схема == модели? (для CI)
.venv/bin/foa-gateway --config config.yaml --migrate # upgrade head из конфигурации шлюза и выход
.venv/bin/foa-gateway --config config.yaml --stamp   # отметить существующую create_all-схему как head
FOA_MIGRATIONS_ROOT=/app alembic upgrade head        # явный корень, если cwd ≠ корень проекта
```

**Переход с `create_all` на `alembic` — отдельное явное действие.** В БД, созданной
`create_all`, таблицы есть, а `alembic_version` нет, поэтому Alembic считает её
«base» и попытается создать таблицы заново. Шлюз такую ситуация не угадывает:
`apply_migrations` блокирует upgrade с сообщением, указывающим на `--stamp`
(проверено `test_legacy_create_all_database_blocks_upgrade_until_stamped`).
Порядок апгрейда: резервная копия → `--migrate` на копии → сверка → `--stamp`/
`--migrate` на рабочей БД.

Новая ревизия после изменения моделей:

```bash
.venv/bin/alembic revision --autogenerate -m "что изменилось"
```

`migrations/env.py` передаёт `compare_type=True` и кастомный `render_item` для
типа `UTCDateTime`, а для SQLite включает `render_as_batch` (полноценного
`ALTER TABLE` у него нет — таблица пересоздаётся). URL берётся из той же цепочки
приоритетов §13/§14.2, что и у шлюза: `ALEMBIC_DB_URL` → `GATEWAY_DB_URL` →
`storage.database_url`.

Для SQLite при подключении включаются `journal_mode=WAL`, `foreign_keys=ON`,
`busy_timeout=30000` — без них конкурентные записи из фоновых циклов упирались
бы в блокировки.


---

## Безопасность и этика

Что гарантируется кодом, а не только документом (§12):

- **Согласие как условие маршрутизации.** Балансировщик физически не видит узлов
  вне `ROUTABLE_STATES` (`verified|healthy|degraded`); `candidate`,
  `pending_consent`, `consent_challenge_sent`, `revoked`, `blacklisted`,
  `quarantined` исключены (§4.4.4, §5, §17.1).
- **Узлы, отвечающие `401`/`403`, немедленно исключаются и попадают в блэклист**
  (`upstream_auth_error`) — признак чужого закрытого сервера (§17.2).
- **Активное сканирование запрещено** (§4.4.1): источники читают только уже
  опубликованные данные платформ; активные health-проверки шлются исключительно
  узлам из `ACTIVE_HEALTH_CHECK_STATES`, то есть уже согласившимся.
- **SSRF и обход приватности**: проверка адресов узлов в `foa/net/security.py`
  (`classify_ip`, `ip_is_blocked`, `assert_endpoint_resolvable` — резолвится и сама
  доменная запись), запрет loopback/RFC1918/link-local и адресов облачных метаданных;
  исключения задаёт только владелец шлюза через `allowed_scopes` включённых источников
  (`security.allow_loopback_nodes` — для стендов), отказ от редиректов
  (`follow_redirects=False`), `trust_env=False` для исходящих пулов — переменные
  прокси окружения не могут перенаправить трафик к узлам.
- **Инъекции в заголовки и пути** отсекаются на разборе endpoint и при сборке
  заголовков; пользовательские строки в журналах экранируются.
- **Промпты и ответы в журнал не пишутся** (§12.2, §12.5, §17.8):
  `security.store_prompt_bodies/store_response_bodies=false`,
  `privacy.log_metadata_only=true`, журнал ограничен `MINIMUM_LOG_FIELDS`
  (минимальный набор §12.5.3), а `log_event()` маскирует значения, похожие на
  секреты, даже в разрешённых полях.
- **Ключи пользователей** хранятся как `SHA-256(pepper + key)`, показываются один
  раз, отзываются и ротируются с grace-периодом (§12.4.1).
- **Лимиты и бюджеты** — rps на пользователя/модель/глобально, одновременные
  запросы и стримы, размер промпта и тела, число сообщений, длительность
  генерации, дневной бюджет токенов, почасовой бюджет узла (§12.4.2–12.4.3, §17.5).
- **Кандидаты хранятся ≤ `discovery.retain_days` (90)** и удаляются purge'ем;
  `risk_score ≥ risk_manual_review_threshold` → ручная проверка (§4.7).
- **Права владельца (§12.7):** отзыв согласия, история согласий, удаление узла и
  его данных, обезличенный псевдоним клиента вместо IP, уведомления через
  `POST /admin/abuse-reports` и форму жалобы, обязательная публикация политики
  допустимого использования.
- **Аудит** (`/admin/audit`) — все административные операции, смены согласий и
  выдача ключей.

---

## Тесты и качество

```bash
.venv/bin/pip install -e '.[dev]'          # pytest, ruff, mypy
.venv/bin/python -m pytest tests/ -q              # 665 тестов
.venv/bin/python -m pytest tests/ -q -m "not slow" # 659: без нагрузочных §15.2
.venv/bin/python -m pytest tests/ -q -m security   # проверки §15.3
.venv/bin/python -m pytest tests/ -q -m ethics     # проверки §15.4
.venv/bin/python -m ruff check .           # All checks passed! (line-length 130)
.venv/bin/python -m mypy foa               # опционально, настройки в pyproject.toml
.venv/bin/python -m alembic check          # схема == models (защита от drift)
```

Распределение тестов по файлам:

| Файл | Тестов | Предмет |
|---|---|---|
| `tests/test_units_core.py` | 242 | ID, скоупы, crypto, схемы, ошибки, утилиты (§12.4.1, §4.6) |
| `tests/test_units_runtime.py` | 131 | runtime-состояние узла, circuit breaker, алгоритмы балансировки (§6.3, §6.5, §7) |
| `tests/test_units_config_logging.py` | 113 | слои конфигурации, `validate()`, secret refs, журнал (§13, §14.2, §12.5) |
| `tests/test_units_storage.py` | 37 | репозитории: согласия (история, отзыв), кандидаты (upsert, purge), ключи, блэклист |
| `tests/test_units_openai.py` | 31 | чистые конвертеры OpenAI ⇄ Ollama, маппинг ошибок, NDJSON→SSE (§18) |
| `tests/test_balancing.py` | 23 | 6 алгоритмов, все лимиты и бюджеты, дисциплина повторов §7.6, обрыв клиента, `draining` |
| `tests/test_owner_cli.py` | 21 | `foa-owner` против **реального uvicorn-шлюза**: ключи, consent-файл, TXT, JWT, локальный consent-сервер, publish/verify/revoke/delete |
| `tests/test_openai_api.py` | 18 | `/v1/*` вживую: скоупы, consent gate, лимиты, SSE, оба формата ошибок |
| `tests/test_consent.py` | 13 | три механизма подтверждения, срок действия, отзыв ≤5 с, self-service, изоляция чужих узлов, аудит |
| `tests/test_end_to_end.py` | 13 | полный жизненный цикл: регистрация → согласие → трафик; потоки; отказ `pull/push/...`; скоупы эмбеддингов; валидность поставляемого `config.example.yaml` |
| `tests/test_health.py` | 11 | отсутствие проверок до согласия, `401`/`403` → блэклист, деградация по пассивным ошибкам, выключенный functional-зонд |
| `tests/test_load.py` | 6 | §15.2 (`slow`): пиковая нагрузка, очередь при занятом узле, недоступность узлов, утечки соединений/слотов, обрывы стримов под нагрузкой |
| `tests/test_migrations.py` | 6 | Alembic: начальная ревизия == модели, `alembic check` без drift, блокировка легаси-БД до `--stamp`, старт с `migrations: alembic` |

Маркеры назначаются централизованно в `tests/conftest.py` (`pytest_collection_modifyitems`
по базовому имени теста, поэтому параметризованные случаи размечаются целиком):

| Маркер | Тестов | Источник разметки |
|---|---|---|
| `security` | 213 | §15.3: SSRF, аутентификация/авторизация, криптография, маскирование секретов, инъекции, небезопасная конфигурация, защита обоих контрактов |
| `ethics` | 37 | §15.4: согласие как условие маршрутизации (включая `/v1/*`), запрет активных сканов, отзыв ≤5 с, удаление данных, ограниченные модели |
| `slow` | 6 | §15.2: нагрузочные тесты (`tests/test_load.py` проставляет сам) |

Быстрый прогон CI: `pytest -m "not slow"`; отдельные срезы —
`pytest -m security`, `pytest -m ethics`.

---

## Критерии приемки (§17)

| # | Критерий | Где проверено |
|---|---|---|
| 1 | Запросы не уходят на узлы без подтверждённого согласия | `ROUTABLE_STATES` + `balancer.eligible()`; `test_full_lifecycle_consent_then_traffic`, `test_no_active_checks_before_consent`, `test_consent_limited_models_are_enforced` |
| 2 | Узлы с `401`/`403` немедленно исключаются и блокируются | `test_auth_error_blacklists_node_immediately`, `test_forbidden_from_node_blacklists`, `test_blacklisted_endpoint_cannot_register` |
| 3 | Отзыв согласия применяется ≤5 с | `consent_revocation_apply_seconds` + `_registry_sync_loop()`; `test_revocation_stops_traffic_within_five_seconds`; метрика `consent_revocation_lag_seconds` |
| 4 | Все пользовательские запросы аутентифицированы | `security.require_api_key`, `deps.authenticate_user` (401 без Bearer-ключа); `test_user_endpoints_require_authentication`, `test_invalid_credentials_are_rejected`, `test_openai_endpoints_require_authentication` |
| 5 | Действуют лимиты частоты, объёма и длительности | `foa/services/ratelimit.py`, `limits.*`; `test_rate_limit_per_user`, `test_concurrency_limit_per_user`, `test_generation_budget_limits`, `test_daily_token_quota`, `test_node_hourly_request_budget` |
| 6 | Потоки корректно проксируются и прерываются | `proxy.stream_ndjson`; `test_streaming_generate_is_proxied_ndjson`, `test_streaming_chat_and_client_abort`, `test_stream_aborted_when_client_disconnects` |
| 7 | Ошибки в совместимом формате | `ErrorPayload.to_json()`; проверки `error`/`code`/`request_id` в e2e-тестах, `test_no_healthy_nodes_returns_503`, `test_unknown_model_returns_404` |
| 8 | Журналы не содержат промптов, ответов и секретов | `MINIMUM_LOG_FIELDS`, маскирование; `test_log_event_never_writes_prompt_value`, `test_log_event_masks_secret_inside_allowed_field`, `test_security_defaults_are_the_safe_mode` |
| 9 | Админ-доступ защищён отдельно от пользовательского | `authenticate_admin` + скоупы + fail-closed; `test_owner_cannot_touch_foreign_or_admin_operations` |
| 10 | Внешние источники выключены по умолчанию и только при явной настройке | `SourceConfig.enabled=False`, `allowed_scopes` в `validate()`; `test_all_five_discovery_sources_present_and_disabled`, `test_source_without_scopes_is_allowed_outside_inventory_mode`, `test_compat_platform_keys_do_not_enable_sources` |

---

## Структура кода

```
foa/
  app.py            FastAPI-фабрика, lifespan, /healthz|/readyz|/metrics, CLI foa-gateway
  api/              user.py (§9.3), openai.py (/v1/*, §18), admin.py (§9.6),
                    deps.py (аутентификация, скоупы, формат ошибок),
                    middleware.py (request-id, access-лог §12.5.3)
  config/           §13 + §14.2: слои значений, fail-fast validate(), secret refs
  core/appstate.py  DI-контейнер служб, фоновые циклы (роль §14.1)
  domain/           enums (состояния, скоупы, коды ошибок), errors (§9.5),
                    schemas (pydantic v2), openai.py (контракт /v1 и конвертеры)
  net/              client.py (пулы httpx на узел, маппинг ошибок), security.py (SSRF, IP)
  services/         nodes (реестр), consent (§5), health (§6), balancer (§7),
                    proxy (§8), ratelimit (§12.4), auth (§9.1, §12.4.1),
                    state (рантайм-нагрузка), crypto (Ed25519, хэши), discovery/ (§4)
  storage/          models.py, repositories.py, db.py (async engine),
                    migrations.py (программный Alembic)
  observability/    metrics.py (§11.4)
  logging/          JSON-журнал с минимальным набором полей (§12.5)
  cli/owner.py      владельческий CLI (foa-owner)
migrations/         alembic: env.py (async + render_item + batch), versions/
deploy/             nginx.conf, prometheus.yml, grafana-dashboard.json
tests/              665 тестов (быстрый прогон: -m "not slow")
```

Файлы проекта:

| Файл | Назначение |
|---|---|
| `ТЗ.md` | техническое задание, на которое ссылаются номера разделов в этом README и в комментариях кода |
| `pyproject.toml` | пакет, зависимости, console-scripts, настройки pytest/ruff/mypy |
| `requirements.txt` | runtime-зависимости (используются слоем builder в `Dockerfile`) |
| `alembic.ini` + `migrations/` | миграции схемы (раздел «Миграции») |
| `config.example.yaml` | пример конфигурации §13, загружается как есть — проверяется тестом |
| `.env.example` | переменные окружения §14.2 (копировать в `.env`, не коммитить) |
| `Dockerfile` | multi-stage, nonroot-пользователь, `HEALTHCHECK` на `/healthz`, миграции в образе |
| `docker-compose.yml` | топология §14.1: 2 реплики шлюза, health-checker, discovery-worker (профиль), postgres, redis, prometheus, nginx |
| `update.sh` | `git add . && git commit && git push origin main` — см. [предупреждение](#ограничения-и-что-не-реализовано) |

Точки входа: `foa-gateway` (`foa.app:main`) и `foa-owner` (`foa.cli.owner:main`).

---

## Ограничения и что не реализовано

- **У OpenAI-контракта нет части полей**: `n>1`, `logprobs`, `tools` с полным
  протоколом tool-calls, `audio`/`images`-генерация, `assistants`, `runs`,
  `realtime`. Неподдерживаемые параметры отклоняются явно (§17.7), а не
  игнорируются молча — см. [OpenAI-совместимый API](#openai-совместимый-api-v1).
- **Точность `usage` для потоков** ограничена тем, что возвращает Ollama в
  финальном NDJSON-событии (`eval_count`); `prompt_tokens` в стриме может быть 0,
  если узел его не сообщил.
- **Распределённые трассировки** выключены по умолчанию (`observability.trace_enabled:
  false`); `/admin/config` показывает действующую конфигурацию, версионирование
  конфигурации сводится к файлу + аудит-событию `config.reloaded`.
- **Владельческие уведомления** о жалобах реализованы как приём
  `POST /admin/abuse-reports` и запись в аудит; канал доставки (e-mail, webhook) —
  открытый вопрос §18.
- **Нагрузочные тесты §15.2** покрывают поведение (пик, очередь, отказы, утечки,
  обрывы), но не целевые абсолютные числа из §15.2 («≥ N RPS», «p95 ≤ M мс»):
  они зависят от железа, поэтому измерять их надо на реальном контуре — набор
  помечен `slow` и excluded из быстрого прогона.
- **Миграция данных** (не схемы) не автоматизирована: `nodes.secret`-полей нет,
  но при изменении формата `capability`-документа потребуется сверка вручную.
- `update.sh` выполняет `git add .` → `git commit` → `git push origin main`. Не
  запускайте его с заполненным `.env`: `git add .` попытается отправить секреты
  в GitHub (`.gitignore` исключает `.env`, но проверяйте `git status` перед коммитом).

