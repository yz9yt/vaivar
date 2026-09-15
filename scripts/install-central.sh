#!/usr/bin/env bash
#
# vAIvar Central installer (launcher): guided, Docker-first, prompt-driven.
#
# Writes a gitignored env file (deploy/.env.central.<env>) and optionally
# starts the central control plane via docker compose. It is the counterpart
# of scripts/deploy.sh (which guides honeypot installs on remote hosts).
#
# Security rules (non-negotiable):
#   * Secrets are written ONLY under deploy/ (gitignored, mode 600).
#   * Never print a token unless the terminal is a TTY and --show-token is set.
#   * Never accept a committed placeholder (replace-me-*) as a real secret.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV="${VAIVAR_CENTRAL_ENV:-dev}"
ENV_FILE="$REPO_ROOT/deploy/.env.central.$ENV"
BIND="0.0.0.0"
PORT="8080"
ADMIN_EMAIL=""
PROJECT_NAME="vaivar-central"
CONFIGURE_ONLY=false
SHOW_TOKEN=false
FORCE=false

usage() {
  cat >&2 <<'EOF'
Uso: scripts/install-central.sh [opciones]

Instala/despliega la central de vAIvar con Docker Compose, de forma guiada.

Opciones:
  --env <dev|pro>        Entorno de configuración (por defecto: dev).
  --bind <IPv4>          Dirección de escucha (por defecto: 0.0.0.0).
  --port <puerto>        Puerto del panel/API (por defecto: 8080).
  --admin-email <email>  Contacto opcional del operador (guardado como metadato).
  --project-name <n>     Nombre del proyecto Compose (por defecto: vaivar-central).
  --configure-only       Validar y escribir la configuración, sin levantar contenedores.
  --show-token           Imprimir el token admin generado (solo si stdout es TTY).
  --force                Sobrescribir un .env existente aunque tenga valores no-placeholder.
  -h, --help             Mostrar esta ayuda.
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
info() { printf '\n%s\n' "$*"; }

# Prompt with default; read from stderr so stdout stays clean for machine output.
prompt() {
  local value
  printf '  %s [%s]: ' "$1" "$2" >&2
  IFS= read -r value || die 'Entrada interrumpida.'
  printf '%s\n' "${value:-$2}"
}

random_hex() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_ipv4() {
  local part; local -a parts
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -ra parts <<< "$1"
  for part in "${parts[@]}"; do [[ ${#part} -le 3 && ( "$part" == 0 || "$part" != 0* ) ]] || return 1; (( 10#$part <= 255 )) || return 1; done
}
valid_project_name() { [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; }

# True when the value looks like a placeholder from the committed template.
is_placeholder() { [[ "${1:-}" =~ replace-me|-CHANGE|xxxx|your-|changeme ]]; }

# Check TCP listeners before Compose attempts to deploy (like deploy.sh).
port_is_used() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk -v p="$port" '$4 ~ (":" p "$") { found=1 } END { exit found ? 0 : 1 }' && return 0
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p="$port" '$4 ~ (":" p "$") { found=1 } END { exit found ? 0 : 1 }' && return 0
  fi
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) [[ $# -ge 2 ]] || die '--env necesita un valor.'; ENV="$2"; shift 2 ;;
    --bind) [[ $# -ge 2 ]] || die '--bind necesita un valor.'; BIND="$2"; shift 2 ;;
    --port) [[ $# -ge 2 ]] || die '--port necesita un valor.'; PORT="$2"; shift 2 ;;
    --admin-email) [[ $# -ge 2 ]] || die '--admin-email necesita un valor.'; ADMIN_EMAIL="$2"; shift 2 ;;
    --project-name) [[ $# -ge 2 ]] || die '--project-name necesita un valor.'; PROJECT_NAME="$2"; shift 2 ;;
    --configure-only) CONFIGURE_ONLY=true; shift ;;
    --show-token) SHOW_TOKEN=true; shift ;;
    --force) FORCE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Opción desconocida: $1" ;;
  esac
done

case "$ENV" in dev|pro) ;; *) die '--env debe ser dev o pro.' ;; esac
valid_ipv4 "$BIND" || die 'La dirección --bind no es una IPv4 válida.'
valid_port "$PORT" || die 'El puerto --port debe estar entre 1 y 65535.'
valid_project_name "$PROJECT_NAME" || die 'El nombre del proyecto Compose no es válido.'
command -v docker >/dev/null 2>&1 || die 'No se encuentra docker.'
docker compose version >/dev/null 2>&1 || die 'Falta Docker Compose.'
if ! "$CONFIGURE_ONLY"; then docker info >/dev/null 2>&1 || die 'No se puede acceder al daemon Docker.'; fi

[[ -d "$REPO_ROOT/deploy" ]] || mkdir -p "$REPO_ROOT/deploy"
ENV_FILE="$(cd "$REPO_ROOT/deploy" && pwd)/.env.central.$ENV"

# --- Load existing values (never echo them). --------------------------------
read_value() { [[ -f "$1" ]] || return 0; awk -v name="$2" 'index($0, name "=") == 1 { value = substr($0, length(name) + 2) } END { print value }' "$1"; }

EXISTING_INGEST="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_INGEST_TOKEN)"
EXISTING_OPERATOR="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_OPERATOR_TOKEN)"
EXISTING_ADMIN="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_ADMIN_TOKEN)"
EXISTING_KEY="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_KEY)"
EXISTING_AUTH_MODE="$(read_value "$ENV_FILE" VAIVAR_CENTRAL_AUTH_MODE)"

if [[ -f "$ENV_FILE" ]] && ! "$FORCE"; then
  if is_placeholder "$EXISTING_INGEST" || is_placeholder "$EXISTING_OPERATOR" || is_placeholder "$EXISTING_ADMIN" || [[ -z "$EXISTING_KEY" ]]; then
    die "El archivo $ENV_FILE contiene marcadores del ejemplo (replace-me...) o una clave vacía. Usa --force para regenerarlo, o edítalo manualmente (NUNCA lo subas al repo)."
  fi
  info "Usando configuración existente en $ENV_FILE (no tocaré secretos)."
  INGEST_TOKEN="$EXISTING_INGEST"; OPERATOR_TOKEN="$EXISTING_OPERATOR"; ADMIN_TOKEN="$EXISTING_ADMIN"; CENTRAL_KEY="$EXISTING_KEY"
else
  INGEST_TOKEN="$(random_hex)"
  OPERATOR_TOKEN="$(random_hex)"
  ADMIN_TOKEN="$(random_hex)"
  CENTRAL_KEY="$(random_hex)"
fi
AUTH_MODE="${EXISTING_AUTH_MODE:-legacy}"
case "$AUTH_MODE" in none|legacy|oidc) ;; *) die 'VAIVAR_CENTRAL_AUTH_MODE debe ser none, legacy u oidc.' ;; esac

[[ "$INGEST_TOKEN" =~ ^[a-f0-9]{64}$ ]] || [[ ${#INGEST_TOKEN} -ge 16 ]] || die 'Ingest token inválido o demasiado corto.'
[[ "$OPERATOR_TOKEN" =~ ^[a-f0-9]{64}$ ]] || [[ ${#OPERATOR_TOKEN} -ge 16 ]] || die 'Operator token inválido o demasiado corto.'
[[ "$ADMIN_TOKEN" =~ ^[a-f0-9]{64}$ ]] || [[ ${#ADMIN_TOKEN} -ge 16 ]] || die 'Admin token inválido o demasiado corto.'
[[ "$CENTRAL_KEY" =~ ^[a-fA-F0-9]{64,}$ ]] || die 'La clave central debe ser hexadecimal de >=64 caracteres.'

if ! "$CONFIGURE_ONLY"; then
  port_is_used "$PORT" && die "El puerto $PORT ya está ocupado en este host."
fi

TEMP_ENV="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'rm -f "$TEMP_ENV"' EXIT

# Build the runtime env file. Values only; comments explain the optional vars.
{
  printf '%s\n' '# vAIvar Central runtime config. AUTOGENERATED — DO NOT COMMIT. Mode: '"$ENV"''
  printf '%s\n' 'CENTRAL_BIND='"$BIND"
  printf '%s\n' "CENTRAL_PORT=$PORT"
  printf '%s\n' "VAIVAR_CENTRAL_PORT=$PORT"
  printf '%s\n' 'VAIVAR_CENTRAL_INGEST_TOKEN='"$INGEST_TOKEN"
  printf '%s\n' 'VAIVAR_CENTRAL_OPERATOR_TOKEN='"$OPERATOR_TOKEN"
  printf '%s\n' 'VAIVAR_CENTRAL_ADMIN_TOKEN='"$ADMIN_TOKEN"
  printf '%s\n' 'VAIVAR_CENTRAL_KEY='"$CENTRAL_KEY"
  printf '%s\n' 'VAIVAR_CENTRAL_AUTH_MODE='"$AUTH_MODE"
  if [[ -n "$ADMIN_EMAIL" ]]; then printf '%s\n' "VAIVAR_ADMIN_EMAIL=$ADMIN_EMAIL"; fi
  printf '%s\n' 'DATA_PATH=/data/vaivar-central'
  printf '%s\n' 'VAIVAR_RELEASE_DIR=/data/vaivar-central/releases'
  printf '%s\n' 'VAIVAR_RELEASE_HOST_DIR='"$REPO_ROOT"'/releases'
  printf '%s\n' '# Optional Splunk HEC export (leave empty to disable):'
  printf '%s\n' 'VAIVAR_SPLUNK_HEC_URL='
  printf '%s\n' 'VAIVAR_SPLUNK_HEC_TOKEN='
  printf '%s\n' 'VAIVAR_SPLUNK_HEC_INDEX=vaivar'
  printf '%s\n' 'VAIVAR_SPLUNK_HEC_SOURCE=vaivar'
  printf '%s\n' '# Optional OpenCTI (leave empty to disable):'
  printf '%s\n' 'VAIVAR_OPENCTI_URL='
  printf '%s\n' 'VAIVAR_OPENCTI_TOKEN='
  printf '%s\n' '# Polling interval in ms:'
  printf '%s\n' 'VAIVAR_POLL_INTERVAL_MS=30000'
} > "$TEMP_ENV"
chmod 600 "$TEMP_ENV"
mv "$TEMP_ENV" "$ENV_FILE"

info "Configuración generada en $ENV_FILE (permisos 600). No la subas al repositorio."

if "$CONFIGURE_ONLY"; then
  info 'Modo --configure-only: no se levanta nada.'
  exit 0
fi

# Deploy with a clean env so nothing leaks from the host shell.
compose() (
  unset VAIVAR_CENTRAL_PORT VAIVAR_CENTRAL_INGEST_TOKEN VAIVAR_CENTRAL_OPERATOR_TOKEN
  unset VAIVAR_CENTRAL_ADMIN_TOKEN VAIVAR_CENTRAL_KEY CENTRAL_BIND CENTRAL_PORT
  unset VAIVAR_RELEASE_DIR VAIVAR_RELEASE_HOST_DIR VAIVAR_POLL_INTERVAL_MS
  unset VAIVAR_SPLUNK_HEC_URL VAIVAR_SPLUNK_HEC_TOKEN VAIVAR_SPLUNK_HEC_INDEX VAIVAR_SPLUNK_HEC_SOURCE
  unset VAIVAR_OPENCTI_URL VAIVAR_OPENCTI_TOKEN
  docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" -f "$REPO_ROOT/docker-compose.central.yml" "$@"
)

info "Construyendo y arrancando Central ($PROJECT_NAME)…"
compose up -d --build --wait --wait-timeout 120
info 'Central desplegada y saludable.'

PUBLIC_HOST="$BIND"
[[ "$PUBLIC_HOST" != 0.0.0.0 ]] || PUBLIC_HOST='<IP-o-dominio>'
printf '\nPanel: http://%s:%s/overview\n' "$PUBLIC_HOST" "$PORT"
printf '  Login con el token operator o admin.\n'
printf 'Proyecto Compose: %s\n' "$PROJECT_NAME"
printf 'Configuración: %s (permisos 600, NO versionar)\n' "$ENV_FILE"
if [[ -t 1 && "$SHOW_TOKEN" == true && -n "$ADMIN_TOKEN" ]]; then
  printf 'Token admin (máscara de seguridad): …%s\n' "${ADMIN_TOKEN: -4}"
fi
printf '\nActualiza con: docker compose --project-name %s --env-file %s -f %s/docker-compose.central.yml down\n' "$PROJECT_NAME" "$ENV_FILE" "$REPO_ROOT"
