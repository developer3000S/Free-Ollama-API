#!/bin/bash

# Скрипт для запуска Free Ollama API Gateway в Docker (топология §14.1).
#
# Выполняет то, что нужно для подъёма стека на чистой машине: проверяет Docker,
# создаёт .env из .env.example и генерирует в нём недостающие секреты (§14.2),
# выпускает самоподписанный сертификат для nginx (без него ingress не стартует),
# пересобирает образ, поднимает сервисы и ждёт готовности шлюза.
#
# Значения секретов в вывод не печатаются — они только записываются в .env.

set -euo pipefail

cd "$(dirname "$0")"

ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
TLS_DIR="deploy/tls"
TLS_CN="${FOA_TLS_CN:-localhost}"
# Наружу публикуется только nginx с TLS, поэтому пользовательский API адресуется
# через него; самоподписанный сертификат требует -k у curl.
USER_URL="https://127.0.0.1"

step() { echo "[$1/$2] $3"; }
fail() { echo "Ошибка: $1" >&2; exit 1; }
note() { echo "       $1"; }

usage() {
    cat <<'HEREDOC'
Использование: ./docker-start.sh [команда] [опции]

  (без аргументов)         собрать образ и поднять стек
  --no-build              поднять без пересборки образа
  --profile NAME          включить профиль compose (например discovery)
  down                    остановить контейнеры (тома, .env и сертификаты сохраняются)
  -h, --help              эта справка

Примеры:
  ./docker-start.sh
  ./docker-start.sh --profile discovery
  ./docker-start.sh --no-build
  ./docker-start.sh down
HEREDOC
}

# --------------------------------------------------------------------------- #
# Аргументы
# --------------------------------------------------------------------------- #

ACTION="up"
BUILD=1
PROFILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        down|stop) ACTION="down" ;;
        --no-build) BUILD=0 ;;
        --profile)
            [ $# -ge 2 ] || fail "--profile требует имя профиля"
            PROFILES+=("$2"); shift
            ;;
        --profile=*) PROFILES+=("${1#--profile=}") ;;
        *) fail "неизвестный аргумент: $1 (справка: ./docker-start.sh --help)" ;;
    esac
    shift
done

PROFILE_ARGS=()
for p in ${PROFILES[@]+"${PROFILES[@]}"}; do
    PROFILE_ARGS+=(--profile "$p")
done

compose() {
    docker compose ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} "$@"
}

# --------------------------------------------------------------------------- #
# 1. Окружение запуска
# --------------------------------------------------------------------------- #

step 1 5 "Проверяю Docker…"
command -v docker >/dev/null 2>&1 || fail "docker не найден в PATH"
docker compose version >/dev/null 2>&1 || fail "нужен Docker Compose v2 (команда «docker compose»)"
docker info >/dev/null 2>&1 || fail "Docker daemon недоступен — проверьте, что он запущен"
note "$(docker --version)"

# Остановка не должна ничего создавать: достаточно .env для интерполяции
# POSTGRES_PASSWORD в docker-compose.yml.
if [ "$ACTION" = "down" ]; then
    [ -f "$ENV_FILE" ] || fail "нет $ENV_FILE — остановка требует её для интерполяции compose-переменных; выполните docker compose down вручную"
    step 4 5 "Останавливаю стек…"
    compose down
    note "тома (pgdata, redisdata, metricsdata), $ENV_FILE и $TLS_DIR сохранены"
    exit 0
fi

# --------------------------------------------------------------------------- #
# 2. .env и секреты (§14.2)
# --------------------------------------------------------------------------- #

step 2 5 "Проверяю конфигурацию окружения…"
[ -f "$ENV_EXAMPLE" ] || fail "нет файла $ENV_EXAMPLE — клон неполный"
if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    note "создан $ENV_FILE из $ENV_EXAMPLE"
fi
command -v openssl >/dev/null 2>&1 || fail "нужен openssl: генерация секретов и сертификата ingress"

# Записывает в .env случайное значение, если переменная пустая или осталась
# плейсхолдером из примера. Печатается только имя переменной.
ensure_secret() {
    local key="$1" value tmp
    value=$(grep -m1 "^${key}=" "$ENV_FILE" | cut -d= -f2- || true)
    case "$value" in
        "" | CHANGE_ME*) ;;
        *) return 0 ;;
    esac
    grep -q "^${key}=" "$ENV_FILE" || fail "$ENV_FILE: нет строки «${key}=» — восстановите файл из $ENV_EXAMPLE"
    value=$(openssl rand -hex 32)
    tmp="${ENV_FILE}.tmp"
    sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" >"$tmp" && mv "$tmp" "$ENV_FILE"
    note "$key: сгенерировано случайное значение (сохранено в $ENV_FILE)"
}

# POSTGRES_PASSWORD обязателен: compose подставляет его и в DSN шлюза, и в
# пароль контейнера postgres; без него compose откажется запускаться.
ensure_secret POSTGRES_PASSWORD
for key in FOA_ADMIN_TOKEN FOA_AUDITOR_TOKEN FOA_OWNER_TOKEN GATEWAY_JWT_SECRET FOA_SECURITY__CLIENT_HASH_SALT; do
    ensure_secret "$key"
done

# GATEWAY_DB_URL в примере содержит плейсхолдер CHANGE_ME — приводим его к
# реальному паролю, чтобы DSN не расходился с паролем postgres. Значение может
# содержать символы, значимые для замены sed, поэтому оно экранируется.
pgpass=$(grep -m1 "^POSTGRES_PASSWORD=" "$ENV_FILE" | cut -d= -f2-)
pgpass_escaped=$(printf '%s' "$pgpass" | sed -e 's/[\\&|]/\\&/g')
tmp_env="${ENV_FILE}.tmp"
sed "s|:CHANGE_ME@|:${pgpass_escaped}@|g" "$ENV_FILE" >"$tmp_env" && mv "$tmp_env" "$ENV_FILE"

# --------------------------------------------------------------------------- #
# 3. TLS для ingress (§14.1: пользовательский API наружу только под TLS)
# --------------------------------------------------------------------------- #

step 3 5 "Проверяю сертификаты ingress…"
if [ ! -s "$TLS_DIR/fullchain.pem" ] || [ ! -s "$TLS_DIR/privkey.pem" ]; then
    mkdir -p "$TLS_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_DIR/privkey.pem" -out "$TLS_DIR/fullchain.pem" \
        -days 365 -subj "/CN=${TLS_CN}" \
        -addext "subjectAltName=DNS:${TLS_CN},DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
        || fail "не удалось выпустить самоподписанный сертификат"
    chmod 600 "$TLS_DIR/privkey.pem"
    note "выпущен самоподписанный сертификат CN=${TLS_CN} — только для локального стенда"
    note "для продакшена замените файлы в $TLS_DIR сертификатом от CA (LE/внутренний)"
else
    note "использую существующие сертификаты в $TLS_DIR"
fi

# Валидация compose-файла до сборки: опечатки в .env видны раньше, чем через
# минуту ожидания несуществующего сервиса.
compose config --quiet || fail "docker compose config — конфигурация не проходит валидацию"

# Порт ingress публикуется с хоста, а проверка занятости дешевле, чем минута
# сборки перед падением в самом конце: если 443 занят чужим процессом, берём
# 8443 и пишем его в FOA_HTTPS_PORT (docker-compose.yml интерполирует значение).
# Порты этого же (перезапускаемого) стека коллизией не считаются.
ensure_key() {
    grep -q "^$1=" "$ENV_FILE" || printf '\n%s=\n' "$1" >>"$ENV_FILE"
}
port_is_free() {
    local port="$1" ours
    command -v ss >/dev/null 2>&1 || return 0
    ours=$(docker inspect --format '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{(index $b 0).HostPort}}{{println}}{{end}}{{end}}' \
        $(compose ps -q 2>/dev/null || true) 2>/dev/null | sort -u || true)
    printf '%s\n' "$ours" | grep -qx "$port" && return 0
    ! ss -ltn 2>/dev/null | grep -qE ":$port[[:space:]]"
}
ensure_key FOA_HTTPS_PORT
https_port=$(grep -m1 '^FOA_HTTPS_PORT=' "$ENV_FILE" | cut -d= -f2-)
if [ -z "$https_port" ]; then
    tmp="${ENV_FILE}.tmp"
    if port_is_free 443; then
        https_port=443
    elif port_is_free 8443; then
        https_port=8443
        note "порт 443 занят другим сервисом — публикую ingress на 8443 (FOA_HTTPS_PORT в $ENV_FILE)"
    else
        echo "Ошибка: порты 443 и 8443 заняты процессами вне этого compose-стека." >&2
        note "освободите один из них или задайте FOA_HTTPS_PORT в $ENV_FILE явно." >&2
        note "Вариант без ingress (шлюз, health-checker, БД и redis поднимутся):" >&2
        note "  docker compose up -d gateway-a gateway-b health-checker postgres redis" >&2
        exit 1
    fi
    sed "s|^FOA_HTTPS_PORT=.*|FOA_HTTPS_PORT=${https_port}|" "$ENV_FILE" >"$tmp" && mv "$tmp" "$ENV_FILE"
elif ! port_is_free "$https_port"; then
    fail "порт ${https_port} (FOA_HTTPS_PORT в $ENV_FILE) занят процессом вне этого стека"
fi
if [ "$https_port" != "443" ]; then
    USER_URL="https://127.0.0.1:${https_port}"
fi

# --------------------------------------------------------------------------- #
# 4. Сборка и подъём
# --------------------------------------------------------------------------- #

if [ "$BUILD" = "1" ]; then
    step 4 5 "Собираю образ шлюза…"
    compose build
else
    step 4 5 "Поднимаю сервисы без пересборки образа…"
fi
if [ "${#PROFILES[@]}" -gt 0 ]; then
    note "профили: ${PROFILES[*]}"
fi
compose up -d

# --------------------------------------------------------------------------- #
# 5. Ожидание готовности
# --------------------------------------------------------------------------- #

step 5 5 "Жду готовности шлюза…"
# Штатный HEALTHCHECK образа опрашивает /healthz изнутри контейнера: наружу 8080
# не публикуется, а /readyz останется 503, пока в реестре нет ни одного
# маршрутизируемого узла (то есть ни одного узла с активным согласием, §5.1).
container=""
ready=0
for _ in $(seq 1 60); do
    # Команда подстановки в присваивании возвращает статус docker compose: без
    # «|| true» нештатный ответ прервал бы ожидание вместо повторной попытки.
    [ -n "$container" ] || container=$(compose ps -q gateway-a 2>/dev/null || true)
    if [ -n "$container" ] \
        && [ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container" 2>/dev/null || echo none)" = "healthy" ]; then
        ready=1
        break
    fi
    sleep 2
done
if [ "$ready" != "1" ]; then
    compose ps || true
    echo "--- журнал gateway-a (последние 40 строк) ---" >&2
    compose logs --tail 40 gateway-a >&2 || true
    fail "шлюз не стал healthy за 120 с — см. вывод выше"
fi

compose ps
echo "--- Успех: стек поднят ---"
note "Пользовательский API: $USER_URL/api/... и $USER_URL/v1/... (сертификат самоподписанный → curl -k)"
note "Диагностика:          $USER_URL/healthz — через ingress проксируется только он; /readyz и /metrics"
note "                       наружу не публикуются (§11.4), проверить так (readyz = 503 при пустом"
note "                       реестре узлов — норма: маршрутизация только на узлы с согласием, §5.1):"
note "                         docker compose exec -T gateway-a python - <<'PY'"
note "                         import urllib.error, urllib.request"
note "                         try: print(urllib.request.urlopen('http://127.0.0.1:8080/readyz').read().decode())"
note "                         except urllib.error.HTTPError as e: print(e.code, e.read().decode())"
note "                       PY"
note "Админ-контур:         наружу закрыт (§9.6): nginx отдаёт /admin/ только из служебной сети, а"
note "                       Swagger UI (/docs) ingress не публикует вовсе (§14.1)."
note "                       Ключ пользователю выдаётся POSTом /admin/keys изнутри сети (пример —"
note "                       раздел «Пользовательский API» в README):"
note "                         docker compose exec -T gateway-a python - <<'PY'"
note "                         import json, os, urllib.request"
note "                         req = urllib.request.Request('http://127.0.0.1:8080/admin/keys',"
note "                             data=json.dumps({'label': 'demo', 'scopes': ['ollama:generate']}).encode(),"
note "                             headers={'Authorization': 'Bearer ' + os.environ['FOA_ADMIN_TOKEN'],"
note "                                    'Content-Type': 'application/json'})"
note "                         print(urllib.request.urlopen(req).read().decode())"
note "                       PY"
note "Логи:                  docker compose logs -f gateway-a gateway-b health-checker"
note "Остановить:            ./docker-start.sh down (данные остаются в томах)"
