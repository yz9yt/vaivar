#!/usr/bin/env bash
# vAIvar Central — small, guided installer for an operator host.
#
# This script installs only Central. Honeypots are deployed separately on
# remote hosts with scripts/deploy.sh or the Central bootstrap installer.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
ENV_FILE="${VAIVAR_CENTRAL_ENV_FILE:-$REPO_ROOT/.env.central}"
BIND="${VAIVAR_CENTRAL_BIND:-127.0.0.1}"
PORT="${VAIVAR_CENTRAL_PORT:-8080}"
PROJECT_NAME="${VAIVAR_CENTRAL_PROJECT:-vaivar-central}"
SHOW_TOKEN=false
CONFIGURE_ONLY=false
PORT_EXPLICIT=false

die() { printf '\nError: %s\n' "$*" >&2; exit 1; }
info() { printf '\n%s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }

usage() {
  cat <<'EOF'
Uso: ./install.sh [opciones]

Instala vAIvar Central con Docker Compose. Solo despliega Central; los
honeypots se instalan en servidores remotos con su instalador separado.

Opciones:
  --port PORT          Puerto del panel/API (si se omite, se pregunta).
  --bind IPv4          Interfaz de publicación (por defecto: 127.0.0.1).
  --project-name NAME  Proyecto Compose (por defecto: vaivar-central).
  --show-token         Mostrar el token admin solo en una terminal interactiva.
  --configure-only     Validar y escribir .env.central sin arrancar Docker.
  -h, --help           Mostrar esta ayuda.
EOF
}

valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_ipv4() {
  local part
  local -a parts
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -ra parts <<< "$1"
  [[ "${#parts[@]}" == 4 ]] || return 1
  for part in "${parts[@]}"; do
    [[ ${#part} -le 3 && ( "$part" == 0 || "$part" != 0* ) ]] || return 1
    (( 10#$part <= 255 )) || return 1
  done
}
valid_project_name() { [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; }
random_hex() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
read_value() {
  [[ -f "$1" ]] || return 0
  awk -v name="$2" 'index($0, name "=") == 1 { value = substr($0, length(name) + 2) } END { print value }' "$1"
}
is_placeholder() { [[ -z "${1:-}" || "$1" =~ ^replace-me|changeme|your- ]]; }

# Read from /dev/tty so `curl ... | bash` can still ask the operator questions.
prompt_port() {
  local candidate
  local prompt_fd=''
  if [[ -r /dev/tty && -t /dev/tty ]]; then
    prompt_fd='/dev/tty'
  elif [[ -t 0 ]]; then
    prompt_fd='/dev/stdin'
  else
    return 0
  fi

  while :; do
    printf '  Puerto de Central [%s]: ' "$PORT" > /dev/stderr
    IFS= read -r candidate < "$prompt_fd" || die 'Entrada interrumpida.'
    candidate="${candidate:-$PORT}"
    if valid_port "$candidate"; then
      PORT="$candidate"
      return 0
    fi
    printf '  El puerto debe estar entre 1 y 65535.\n' > /dev/stderr
  done
}

# Detect listeners from the host and ports published by Docker. The current
# Central Compose project is allowed to reuse its own port during an update.
port_is_used() {
  local port="$1"
  local endpoint
  if command -v ss >/dev/null 2>&1; then
    if ss -H -ltn 2>/dev/null | awk -v p="$port" '{ endpoint=$4; sub(/^.*:/, "", endpoint); if (endpoint == p) found=1 } END { exit found ? 0 : 1 }'; then
      return 0
    fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      return 0
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -ltn 2>/dev/null | awk -v p="$port" '{ endpoint=$4; sub(/^.*:/, "", endpoint); if (endpoint == p) found=1 } END { exit found ? 0 : 1 }'; then
      return 0
    fi
  fi

  local id
  while read -r id; do
    [[ -n "$id" ]] || continue
    if docker inspect -f '{{range $p, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{println .HostPort}}{{end}}{{end}}' "$id" 2>/dev/null \
      | awk -v p="$port" '$0 == p { found=1 } END { exit found ? 0 : 1 }'; then
      return 0
    fi
  done < <(docker ps -q 2>/dev/null || true)
  return 1
}

project_owns_port() {
  local id
  while read -r id; do
    [[ -n "$id" ]] || continue
    if docker inspect -f '{{range $p, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{println .HostPort}}{{end}}{{end}}' "$id" 2>/dev/null \
      | awk -v p="$PORT" '$0 == p { found=1 } END { exit found ? 0 : 1 }'; then
      return 0
    fi
  done < <(docker ps -q --filter "label=com.docker.compose.project=$PROJECT_NAME" --filter 'label=com.docker.compose.service=vaivar-central' 2>/dev/null || true)
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      [[ $# -ge 2 ]] || die '--port necesita un valor.'
      PORT="$2"; PORT_EXPLICIT=true; shift 2 ;;
    --bind)
      [[ $# -ge 2 ]] || die '--bind necesita un valor.'
      BIND="$2"; shift 2 ;;
    --project-name)
      [[ $# -ge 2 ]] || die '--project-name necesita un valor.'
      PROJECT_NAME="$2"; shift 2 ;;
    --show-token) SHOW_TOKEN=true; shift ;;
    --configure-only) CONFIGURE_ONLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Opción desconocida: $1" ;;
  esac
done

[[ -f "$REPO_ROOT/docker-compose.central.yml" ]] || die 'Ejecuta este instalador dentro del repositorio vAIvar.'
valid_ipv4 "$BIND" || die 'La dirección --bind no es una IPv4 válida.'
valid_port "$PORT" || die 'El puerto debe estar entre 1 y 65535.'
valid_project_name "$PROJECT_NAME" || die 'El nombre del proyecto Compose no es válido.'

if ! "$PORT_EXPLICIT"; then
  prompt_port
fi
valid_port "$PORT" || die 'El puerto debe estar entre 1 y 65535.'

info 'Instalación guiada de vAIvar Central'
printf 'Puerto seleccionado: %s\n' "$PORT"
printf 'Interfaz publicada: %s\n' "$BIND"

printf '[1/4] Comprobando Docker y el repositorio...\n'
command -v docker >/dev/null 2>&1 || die 'No se encuentra Docker.'
ok 'Docker disponible.'

printf '[2/4] Comprobando Docker Compose...\n'
docker compose version >/dev/null 2>&1 || die 'Falta el plugin Docker Compose.'
ok 'Docker Compose disponible.'

printf '[3/4] Comprobando el daemon Docker...\n'
if "$CONFIGURE_ONLY"; then
  ok 'Omitido en --configure-only.'
else
  docker info >/dev/null 2>&1 || die 'No se puede acceder al daemon Docker. Comprueba el servicio y los permisos.'
  ok 'Daemon Docker accesible.'
fi

printf '[4/4] Comprobando el puerto %s...\n' "$PORT"
if port_is_used "$PORT" && ! project_owns_port; then
  die "El puerto $PORT ya está ocupado. Elige otro."
fi
ok 'Puerto disponible para este proyecto.'

ENV_DIR="$(dirname "$ENV_FILE")"
mkdir -p "$ENV_DIR"

# Reuse valid credentials on an update; never source or print the env file.
INGEST_TOKEN="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_INGEST_TOKEN)"
OPERATOR_TOKEN="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_OPERATOR_TOKEN)"
ADMIN_TOKEN="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_ADMIN_TOKEN)"
CENTRAL_KEY="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_KEY)"
SUPERADMIN_TOKEN="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_SUPERADMIN_TOKEN)"
AUTH_MODE="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_AUTH_MODE)"

is_placeholder "$INGEST_TOKEN" && INGEST_TOKEN="$(random_hex)"
is_placeholder "$OPERATOR_TOKEN" && OPERATOR_TOKEN="$(random_hex)"
is_placeholder "$ADMIN_TOKEN" && ADMIN_TOKEN="$(random_hex)"
is_placeholder "$CENTRAL_KEY" && CENTRAL_KEY="$(random_hex)"
is_placeholder "$SUPERADMIN_TOKEN" && SUPERADMIN_TOKEN=''
[[ -n "$AUTH_MODE" ]] || AUTH_MODE='legacy'
case "$AUTH_MODE" in none|legacy|oidc) ;; *) die 'VAIVAR_CENTRAL_AUTH_MODE debe ser none, legacy u oidc.' ;; esac

[[ "$INGEST_TOKEN" =~ ^[A-Za-z0-9_-]{16,}$ ]] || die 'El token de ingesta existente no es válido.'
[[ "$OPERATOR_TOKEN" =~ ^[A-Za-z0-9_-]{16,}$ ]] || die 'El token de operador existente no es válido.'
[[ "$ADMIN_TOKEN" =~ ^[A-Za-z0-9_-]{16,}$ ]] || die 'El token admin existente no es válido.'
[[ "$CENTRAL_KEY" =~ ^[a-fA-F0-9]{64,}$ ]] || die 'La clave central debe ser hexadecimal de al menos 64 caracteres.'

TEMP_ENV="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'if [[ -n "${TEMP_ENV:-}" && -e "$TEMP_ENV" ]]; then rm -f "$TEMP_ENV"; fi' EXIT
{
  printf '%s\n' '# vAIvar Central runtime config. AUTOGENERATED — DO NOT COMMIT.'
  printf '%s\n' "CENTRAL_BIND=$BIND"
  printf '%s\n' "CENTRAL_PORT=$PORT"
  printf '%s\n' "VAIVAR_CENTRAL_PORT=$PORT"
  printf '%s\n' "VAIVAR_CENTRAL_INGEST_TOKEN=$INGEST_TOKEN"
  printf '%s\n' "VAIVAR_CENTRAL_OPERATOR_TOKEN=$OPERATOR_TOKEN"
  printf '%s\n' "VAIVAR_CENTRAL_ADMIN_TOKEN=$ADMIN_TOKEN"
  printf '%s\n' "VAIVAR_CENTRAL_SUPERADMIN_TOKEN=$SUPERADMIN_TOKEN"
  printf '%s\n' "VAIVAR_CENTRAL_AUTH_MODE=$AUTH_MODE"
  printf '%s\n' "VAIVAR_CENTRAL_KEY=$CENTRAL_KEY"
  printf '%s\n' 'DATA_PATH=/data/vaivar-central'
  printf '%s\n' 'VAIVAR_RELEASE_DIR=/data/vaivar-central/releases'
  printf '%s\n' "VAIVAR_RELEASE_HOST_DIR=$REPO_ROOT/releases"
  printf '%s\n' '# Optional integrations (leave empty to disable):'
  printf '%s\n' "VAIVAR_SPLUNK_HEC_URL=$(read_value "$ENV_FILE" VAIVAR_SPLUNK_HEC_URL)"
  printf '%s\n' "VAIVAR_SPLUNK_HEC_TOKEN=$(read_value "$ENV_FILE" VAIVAR_SPLUNK_HEC_TOKEN)"
  printf '%s\n' "VAIVAR_SPLUNK_HEC_INDEX=$(read_value "$ENV_FILE" VAIVAR_SPLUNK_HEC_INDEX)"
  printf '%s\n' "VAIVAR_SPLUNK_HEC_SOURCE=$(read_value "$ENV_FILE" VAIVAR_SPLUNK_HEC_SOURCE)"
  printf '%s\n' "VAIVAR_OPENCTI_URL=$(read_value "$ENV_FILE" VAIVAR_OPENCTI_URL)"
  printf '%s\n' "VAIVAR_OPENCTI_TOKEN=$(read_value "$ENV_FILE" VAIVAR_OPENCTI_TOKEN)"
} > "$TEMP_ENV"
chmod 600 "$TEMP_ENV"

compose() (
  unset CENTRAL_BIND CENTRAL_PORT VAIVAR_CENTRAL_PORT
  unset VAIVAR_CENTRAL_INGEST_TOKEN VAIVAR_CENTRAL_OPERATOR_TOKEN VAIVAR_CENTRAL_ADMIN_TOKEN
  unset VAIVAR_CENTRAL_SUPERADMIN_TOKEN VAIVAR_CENTRAL_AUTH_MODE VAIVAR_CENTRAL_KEY
  docker compose --project-name "$PROJECT_NAME" --env-file "$1" -f "$REPO_ROOT/docker-compose.central.yml" "${@:2}"
)

compose "$TEMP_ENV" config --quiet
mv "$TEMP_ENV" "$ENV_FILE"
TEMP_ENV=''

if "$CONFIGURE_ONLY"; then
  info "Configuración guardada en $ENV_FILE (permisos 600)."
  exit 0
fi

info 'Construyendo y arrancando Central…'
compose "$ENV_FILE" up -d --build --wait --wait-timeout 120

info 'Central instalada y saludable.'
DISPLAY_HOST="$BIND"
[[ "$DISPLAY_HOST" != 0.0.0.0 ]] || DISPLAY_HOST='<IP-o-dominio-del-servidor>'
printf 'Panel: http://%s:%s/overview\n' "$DISPLAY_HOST" "$PORT"
printf 'Proyecto Compose: %s\n' "$PROJECT_NAME"
printf 'Configuración: %s (permisos 600; no versionar)\n' "$ENV_FILE"
if "$SHOW_TOKEN" && [[ -t 1 ]]; then
  printf 'Token admin (mostrar solo una vez): %s\n' "$ADMIN_TOKEN"
else
  printf 'Tokens generados y guardados en el archivo privado indicado arriba.\n'
fi
printf 'Parar: docker compose --project-name %s --env-file %s -f %s/docker-compose.central.yml down\n' "$PROJECT_NAME" "$ENV_FILE" "$REPO_ROOT"
