#!/usr/bin/env bash
# Run on each target server (for example over SSH), independently of central.
# One public attacker port and one authenticated API port for central access.
# VAIVAR_DEPLOY_ENV overrides deploy/.env.local; VAIVAR_SHOW_TOKEN=0 hides
# the final token when an automation is capturing terminal output.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${VAIVAR_DEPLOY_ENV:-$REPO_ROOT/deploy/.env.local}"
CONFIGURE_ONLY=false
PROJECT_NAME_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --configure-only) CONFIGURE_ONLY=true; shift ;;
    --project-name)
      [[ $# -ge 2 ]] || { printf 'Falta el valor de --project-name.\n' >&2; exit 1; }
      PROJECT_NAME_OVERRIDE="$2"
      shift 2 ;;
    --help|-h)
      printf 'Uso: ./honeypot-install.sh [--configure-only] [--project-name NOMBRE]\n'
      printf 'Ejecutar en el servidor donde quieres instalar este honeypot (por SSH).\n'
      printf 'Pregunta por puertos, interfaces, proyecto Compose e identificador.\n'
      printf 'Usa un proyecto Compose y un archivo de entorno distintos para cada honeypot del mismo host.\n'
      printf 'Genera/reutiliza credenciales privadas y despliega solo el honeypot.\n'
      exit 0 ;;
    *) printf 'Opción desconocida: %s\n' "$1" >&2; exit 1 ;;
  esac
done

info() { printf '\n%s\n' "$*"; }
die() { printf '\nError: %s\n' "$*" >&2; exit 1; }
prompt() {
  local value
  local prompt_fd
  printf '  %s [%s]: ' "$1" "$2" >&2
  if [[ -r /dev/tty && -t /dev/tty ]]; then
    prompt_fd=/dev/tty
  else
    prompt_fd=/dev/stdin
  fi
  IFS= read -r value < "$prompt_fd" || die 'Entrada interrumpida; no se ha iniciado el despliegue.'
  printf '%s\n' "${value:-$2}"
}
read_value() {
  [[ -f "$1" ]] || return 0
  awk -v name="$2" 'index($0, name "=") == 1 { value = substr($0, length(name) + 2) } END { print value }' "$1"
}
random_hex() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_ipv4() {
  local part
  local -a parts
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -ra parts <<< "$1"
  for part in "${parts[@]}"; do
    [[ ${#part} -le 3 && ( "$part" == 0 || "$part" != 0* ) ]] || return 1
    (( 10#$part <= 255 )) || return 1
  done
}
valid_project_name() { [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; }
valid_private_path() {
  [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
  [[ "$1" != "/" ]] || return 1
  case "$1" in */../*|*/..|*/./*|*/.) return 1 ;; esac
}

# Check TCP listeners before Compose attempts the deployment. A port already
# published by this same Compose project is allowed so an update can reuse
# its existing mapping; every other listener is a real conflict.
port_is_used() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk -v p="$port" '$4 ~ (":" p "$") { found=1 } END { exit found ? 0 : 1 }' && return 0
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p="$port" '$4 ~ (":" p "$") { found=1 } END { exit found ? 0 : 1 }' && return 0
  fi

  # Docker-published ports may not have a userspace listener yet. Inspect the
  # published bindings as a fallback and as a second check.
  local id
  while read -r id; do
    [[ -n "$id" ]] || continue
    if docker inspect -f '{{range $p, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{println .HostPort}}{{end}}{{end}}' "$id" 2>/dev/null | awk -v p="$port" '$0 == p { found=1 } END { exit found ? 0 : 1 }'; then
      return 0
    fi
  done < <(docker ps -q 2>/dev/null)
  return 1
}

project_owns_port() {
  local port="$1"
  local id
  while read -r id; do
    [[ -n "$id" ]] || continue
    if docker inspect -f '{{range $p, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{println .HostPort}}{{end}}{{end}}' "$id" 2>/dev/null | awk -v p="$port" '$0 == p { found=1 } END { exit found ? 0 : 1 }'; then
      return 0
    fi
  done < <(docker ps -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" --filter 'label=com.docker.compose.service=vaivar' 2>/dev/null)
  return 1
}

port_available() {
  local port="$1"
  ! port_is_used "$port" || project_owns_port "$port"
}

cd "$REPO_ROOT"
printf '[1/4] Comprobando Docker y el repositorio...\n'
command -v docker >/dev/null 2>&1 || die 'No se encuentra Docker.'
printf '  ✓ Docker disponible.\n'
printf '[2/4] Comprobando Docker Compose...\n'
docker compose version >/dev/null 2>&1 || die 'Falta Docker Compose.'
printf '  ✓ Docker Compose disponible.\n'
printf '[3/4] Comprobando el daemon Docker...\n'
if "$CONFIGURE_ONLY"; then
  printf '  ✓ Omitido en --configure-only.\n'
else
  docker info >/dev/null 2>&1 || die 'No se puede acceder al daemon Docker. Comprueba el servicio y los permisos del usuario.'
  printf '  ✓ Daemon Docker accesible.\n'
fi

DEFAULTS_FILE="$ENV_FILE"
info 'Despliegue de vAIvar en este servidor'
printf 'Ejecuta este script por SSH en cada servidor destino.\n'
printf 'Después añade el honeypot en la central con dominio/IP, puerto de API, canal cifrado y barriertoken.\n'
printf 'El honeypot no necesita la dirección ni las credenciales de la central.\n'

PUBLIC_PORT_DEFAULT="$(read_value "$DEFAULTS_FILE" HONEYPOT_PORT)"
API_PORT_DEFAULT="$(read_value "$DEFAULTS_FILE" HTTP_PORT)"
HONEYPOT_PORT="$(prompt 'Puerto público del honeypot' "${PUBLIC_PORT_DEFAULT:-}")"
HTTP_PORT="$(prompt 'Puerto único de API para la central' "${API_PORT_DEFAULT:-}")"
valid_port "$HONEYPOT_PORT" || die 'El puerto público debe estar entre 1 y 65535.'
valid_port "$HTTP_PORT" || die 'El puerto de API debe estar entre 1 y 65535.'
[[ "$HONEYPOT_PORT" != "$HTTP_PORT" ]] || die 'El puerto público y el privado deben ser distintos.'

PROFILE_DEFAULT="$(read_value "$DEFAULTS_FILE" VAIVAR_HONEYPOT_PROFILE)"
PROFILE="$(prompt 'Superficie a simular (all/http/wiki/openapi/mcp)' "${PROFILE_DEFAULT:-all}")"
case "$PROFILE" in
  all|http|wiki|openapi|mcp) ;;
  *) die 'Perfil inválido. Usa all, http, wiki, openapi o mcp.' ;;
esac

PUBLIC_BIND_DEFAULT="$(read_value "$DEFAULTS_FILE" HONEYPOT_BIND)"
HONEYPOT_BIND="$(prompt 'IP de escucha pública (IPv4)' "${PUBLIC_BIND_DEFAULT:-0.0.0.0}")"
API_BIND_DEFAULT="$(read_value "$DEFAULTS_FILE" API_BIND)"
API_BIND="$(prompt 'Interfaz de escucha de API (0.0.0.0 = todas)' "${API_BIND_DEFAULT:-0.0.0.0}")"
valid_ipv4 "$HONEYPOT_BIND" || die 'IP pública de escucha inválida.'
valid_ipv4 "$API_BIND" || die 'IP de escucha de API inválida.'
SITE_DEFAULT="$(read_value "$ENV_FILE" VAIVAR_SITE_ID)"
SITE_DEFAULT="${SITE_DEFAULT:-$(hostname | tr -cd '[:alnum:]_.-')}"
SITE_ID="$(prompt 'Identificador del honeypot' "${SITE_DEFAULT:-honeypot-1}")"
[[ "$SITE_ID" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$ ]] || die 'Identificador inválido (1-64 letras, números, puntos, guiones o guiones bajos).'

PROJECT_DEFAULT="$(read_value "$ENV_FILE" VAIVAR_COMPOSE_PROJECT)"
PROJECT_DEFAULT="${PROJECT_NAME_OVERRIDE:-${PROJECT_DEFAULT:-vaivar}}"
COMPOSE_PROJECT="$(prompt 'Nombre del proyecto Compose (único por honeypot en este host)' "$PROJECT_DEFAULT")"
valid_project_name "$COMPOSE_PROJECT" || die 'Nombre de proyecto inválido (usa minúsculas, números, guiones o guiones bajos).'

if ! "$CONFIGURE_ONLY"; then
  printf '[4/4] Comprobando puertos %s y %s...\n' "$HONEYPOT_PORT" "$HTTP_PORT"
  port_available "$HONEYPOT_PORT" || die "El puerto público $HONEYPOT_PORT ya está ocupado en este host. Elige otro o actualiza la misma instancia Compose."
  port_available "$HTTP_PORT" || die "El puerto de control $HTTP_PORT ya está ocupado en este host. Elige otro o actualiza la misma instancia Compose."
  printf '  ✓ Puertos disponibles para este proyecto.\n'
else
  printf '[4/4] Comprobando puertos...\n'
  printf '  ✓ Omitido en --configure-only.\n'
fi

ENV_DIR="$(dirname "$ENV_FILE")"
mkdir -p "$ENV_DIR"
ENV_FILE="$(cd "$ENV_DIR" && pwd)/$(basename "$ENV_FILE")"
# Only reuse credentials from this script's existing private deployment file.
# Never source an env file as shell code or print existing secrets in prompts.
MASTER_SECRET="$(read_value "$ENV_FILE" VAIVAR_MASTER_SECRET)"
API_TOKEN="$(read_value "$ENV_FILE" VAIVAR_API_TOKEN)"
[[ -n "$MASTER_SECRET" ]] || MASTER_SECRET="$(random_hex)"
[[ -n "$API_TOKEN" ]] || API_TOKEN="$(random_hex)"
[[ "$MASTER_SECRET" =~ ^[a-fA-F0-9]{64,}$ ]] || die 'El secreto guardado no es hexadecimal de al menos 64 caracteres.'
[[ "$API_TOKEN" =~ ^[a-zA-Z0-9_-]{32,}$ ]] || die 'El barriertoken guardado no tiene un formato válido.'

TEMP_ENV="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'rm -f "$TEMP_ENV"' EXIT
cat > "$TEMP_ENV" <<EOF
# Configuración privada de vAIvar. No compartir ni versionar.
HONEYPOT_BIND=$HONEYPOT_BIND
HONEYPOT_PORT=$HONEYPOT_PORT
API_BIND=$API_BIND
HTTP_PORT=$HTTP_PORT
VAIVAR_PORT_HONEYPOT=$HONEYPOT_PORT
VAIVAR_PORT_HTTP=$HTTP_PORT
VAIVAR_HONEYPOT_PROFILE=$PROFILE
VAIVAR_SITE_ID=$SITE_ID
VAIVAR_COMPOSE_PROJECT=$COMPOSE_PROJECT
VAIVAR_CONTROL_CHANNEL=encrypted
VAIVAR_MASTER_SECRET=$MASTER_SECRET
VAIVAR_API_TOKEN=$API_TOKEN
EOF
chmod 600 "$TEMP_ENV"

# Make the file authoritative even if old port/secret variables were exported.
compose() (
  unset HONEYPOT_BIND HONEYPOT_PORT API_BIND HTTP_PORT VAIVAR_PORT_HONEYPOT
  unset VAIVAR_PORT_HTTP VAIVAR_HONEYPOT_PROFILE VAIVAR_SITE_ID VAIVAR_MASTER_SECRET VAIVAR_API_TOKEN
  unset VAIVAR_CENTRAL_URL VAIVAR_CENTRAL_INGEST_TOKEN VAIVAR_COMPOSE_PROJECT COMPOSE_PROFILES
  unset VAIVAR_CONTROL_CHANNEL
  docker compose --project-name "$COMPOSE_PROJECT" --env-file "$1" -f "$REPO_ROOT/docker-compose.yml" "${@:2}"
)
compose "$TEMP_ENV" config --quiet
if [[ -f "$ENV_FILE" ]]; then
  BACKUP_FILE="$(mktemp "${ENV_FILE}.backup.XXXXXX")"
  cp "$ENV_FILE" "$BACKUP_FILE"
  chmod 600 "$BACKUP_FILE"
fi
mv "$TEMP_ENV" "$ENV_FILE"
if "$CONFIGURE_ONLY"; then
  info "Configuración validada y guardada en $ENV_FILE (permisos 600)."
  exit 0
fi

info 'Construyendo la imagen del honeypot…'
compose "$ENV_FILE" build vaivar
info 'Arrancando el honeypot y esperando a que ambos puertos estén listos…'
if ! compose "$ENV_FILE" up -d --wait --wait-timeout 120 vaivar; then
  compose "$ENV_FILE" ps
  die 'El honeypot no ha quedado saludable. Consulta sus logs; las credenciales están guardadas.'
fi

info 'Honeypot desplegado y saludable.'
PUBLIC_HOST="$HONEYPOT_BIND"
[[ "$PUBLIC_HOST" != 0.0.0.0 ]] || PUBLIC_HOST='<IP-o-dominio-del-honeypot>'
printf 'Superficie pública: http://%s:%s\n' "$PUBLIC_HOST" "$HONEYPOT_PORT"
printf '\nEn la consola central → Añadir honeypot:\n'
printf '  Dominio/IP: <dirección de este servidor accesible desde la central>\n'
printf '  Puerto de comunicación: %s\n' "$HTTP_PORT"
printf '  Transporte: http\n'
printf '  Canal: cifrado de aplicación (AES-256-GCM)\n'
printf '  Token: valor VAIVAR_API_TOKEN del archivo privado indicado abajo\n'
printf 'API de control escuchando en: http://%s:%s (datos de control cifrados dentro del protocolo)\n' "$API_BIND" "$HTTP_PORT"
printf 'Identificador: %s\n' "$SITE_ID"
printf 'Proyecto Compose: %s\n' "$COMPOSE_PROJECT"
printf 'Canal central: POST /api/secure/rpc con sobres AES-256-GCM\n'
printf 'El barriertoken no viaja en ninguna cabecera HTTP.\n'
if [[ "$API_BIND" == 127.* ]]; then
  printf 'Has elegido loopback: publica la API mediante tu proxy o túnel para que la central pueda alcanzarla.\n'
fi
if [[ -t 1 && "${VAIVAR_SHOW_TOKEN:-1}" == 1 ]]; then
  printf '\nBarriertoken (guárdalo en la central): %s\n' "$API_TOKEN"
fi
printf '\nCredenciales guardadas en %s (permisos 600).\n' "$ENV_FILE"
printf 'Repite el despliegue por SSH en el siguiente servidor y registra allí su propio token.\n'
