#!/usr/bin/env bash
# Install/update one vAIvar honeypot from a central-approved bundle or a
# pinned GitHub release asset. Run this on the honeypot host as root.
set -euo pipefail
umask 077

CENTRAL_URL=""
BOOTSTRAP_TOKEN="${VAIVAR_BOOTSTRAP_TOKEN:-}"
ARTIFACT_URL=""
EXPECTED_SHA256=""
INSTALL_DIR="/opt/vaivar"
PROJECT_NAME_OVERRIDE=""
PUBLIC_PORT=""
API_PORT=""
PROFILE=""
PUBLIC_BIND=""
API_BIND=""
SITE_ID=""
NODE_HOST=""
CONTROL_CHANNEL=""
AUTO_REGISTER=0

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
usage() {
  cat >&2 <<'EOF'
Uso:
  honeypot-install.sh --central URL --bootstrap-token TOKEN [opciones]
  honeypot-install.sh --artifact-url URL --sha256 SHA256 [opciones]

Opciones:
  --central URL             Central aprobadora para descargar el bundle.
  --bootstrap-token TOKEN   Capacidad temporal emitida por la central.
  --register                Registrar automáticamente; requiere una URL HTTPS de Central.
  --artifact-url URL        Asset HTTPS/GitHub alternativo al bundle central.
  --sha256 HASH             SHA-256 del bundle (obligatorio con --artifact-url).
  --install-dir DIR         Directorio de instalación (por defecto /opt/vaivar).
  --project-name NAME       Proyecto Compose único por honeypot en este host.
  --host HOST               Dirección que la central usará para llegar a la API.
  --api-port PORT            Puerto de control elegido para esta instalación.
  --public-port PORT         Puerto expuesto elegido para esta instalación.
  --profile PROFILE          all, http, wiki, openapi o mcp (por defecto all).
  --site-id ID               Identidad estable del honeypot.
  --public-bind IPv4         Interfaz pública (por defecto 0.0.0.0).
  --api-bind IPv4             Interfaz de API (por defecto 0.0.0.0).
  --control-channel MODE      encrypted (por defecto) o legacy para instalaciones antiguas.
  -h, --help                 Mostrar esta ayuda.
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
valid_host() {
  [[ "$1" =~ ^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] \
    || [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}
valid_site() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; }
valid_project_name() { [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; }
valid_install_dir() {
  [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
  [[ "$1" != "/" ]] || return 1
  case "$1" in */../*|*/..|*/./*|*/.) return 1 ;; esac
}
valid_token() { [[ "$1" =~ ^[A-Za-z0-9_-]{32,}$ ]]; }
random_hex() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
read_env_value() {
  [[ -f "$1" ]] || return 0
  awk -v name="$2" 'index($0, name "=") == 1 { value = substr($0, length(name) + 2) } END { print value }' "$1"
}
read_running_env_value() {
  local name="$1"
  [[ -n "${RUNNING_CONTAINER_ID:-}" ]] || return 0
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$RUNNING_CONTAINER_ID" 2>/dev/null \
    | awk -v name="$name" 'index($0, name "=") == 1 { value = substr($0, length(name) + 2) } END { print value }'
}

# Check TCP listeners before downloading or replacing an installation. A port
# already published by this same Compose project is allowed so an update can
# reuse its existing mapping; every other listener is a real conflict.
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --central) [[ $# -ge 2 ]] || die '--central necesita un valor.'; CENTRAL_URL="$2"; shift 2 ;;
    --bootstrap-token) [[ $# -ge 2 ]] || die '--bootstrap-token necesita un valor.'; BOOTSTRAP_TOKEN="$2"; shift 2 ;;
    --register) AUTO_REGISTER=1; shift ;;
    --artifact-url) [[ $# -ge 2 ]] || die '--artifact-url necesita un valor.'; ARTIFACT_URL="$2"; shift 2 ;;
    --sha256) [[ $# -ge 2 ]] || die '--sha256 necesita un valor.'; EXPECTED_SHA256="$2"; shift 2 ;;
    --install-dir) [[ $# -ge 2 ]] || die '--install-dir necesita un valor.'; INSTALL_DIR="$2"; shift 2 ;;
    --project-name) [[ $# -ge 2 ]] || die '--project-name necesita un valor.'; PROJECT_NAME_OVERRIDE="$2"; shift 2 ;;
    --host) [[ $# -ge 2 ]] || die '--host necesita un valor.'; NODE_HOST="$2"; shift 2 ;;
    --api-port) [[ $# -ge 2 ]] || die '--api-port necesita un valor.'; API_PORT="$2"; shift 2 ;;
    --public-port) [[ $# -ge 2 ]] || die '--public-port necesita un valor.'; PUBLIC_PORT="$2"; shift 2 ;;
    --profile) [[ $# -ge 2 ]] || die '--profile necesita un valor.'; PROFILE="$2"; shift 2 ;;
    --site-id) [[ $# -ge 2 ]] || die '--site-id necesita un valor.'; SITE_ID="$2"; shift 2 ;;
    --public-bind) [[ $# -ge 2 ]] || die '--public-bind necesita un valor.'; PUBLIC_BIND="$2"; shift 2 ;;
    --api-bind) [[ $# -ge 2 ]] || die '--api-bind necesita un valor.'; API_BIND="$2"; shift 2 ;;
    --control-channel) [[ $# -ge 2 ]] || die '--control-channel necesita un valor.'; CONTROL_CHANNEL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Opción desconocida: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || die 'Ejecuta el instalador como root, por ejemplo: curl ... | sudo bash -s -- ...'
command -v curl >/dev/null 2>&1 || die 'No se encuentra curl.'
command -v docker >/dev/null 2>&1 || die 'No se encuentra Docker.'
docker compose version >/dev/null 2>&1 || die 'Falta Docker Compose.'
command -v sha256sum >/dev/null 2>&1 || die 'No se encuentra sha256sum.'
command -v tar >/dev/null 2>&1 || die 'No se encuentra tar.'
command -v gzip >/dev/null 2>&1 || die 'No se encuentra gzip.'
docker info >/dev/null 2>&1 || die 'No se puede acceder al daemon Docker. Comprueba el servicio y los permisos del usuario.'

[[ -n "$CENTRAL_URL" || -n "$ARTIFACT_URL" ]] || die 'Indica --central o --artifact-url.'
if [[ -n "$CENTRAL_URL" ]]; then
  [[ "$CENTRAL_URL" =~ ^https?://[^[:space:]]+$ ]] || die '--central debe ser una URL http(s).'
  [[ -n "$BOOTSTRAP_TOKEN" ]] || die '--bootstrap-token es obligatorio cuando se usa --central.'
  [[ "$BOOTSTRAP_TOKEN" =~ ^[A-Za-z0-9_-]{32,}$ ]] || die 'El bootstrap token no tiene un formato válido.'
fi
if (( AUTO_REGISTER )); then
  [[ -n "$CENTRAL_URL" ]] || die '--register necesita --central.'
  [[ "$CENTRAL_URL" =~ ^https:// ]] || die '--register solo se permite con una URL HTTPS de Central; con HTTP usa el alta manual.'
fi
if [[ -n "$ARTIFACT_URL" ]]; then
  [[ "$ARTIFACT_URL" =~ ^https?://[^[:space:]]+$ ]] || die '--artifact-url debe ser una URL http(s).'
  [[ "$EXPECTED_SHA256" =~ ^[a-fA-F0-9]{64}$ ]] || die '--sha256 es obligatorio y debe contener 64 hexadecimales.'
fi

ENV_FILE="$INSTALL_DIR/.env"
valid_install_dir "$INSTALL_DIR" || die 'El directorio de instalación debe ser una ruta absoluta segura (por ejemplo /opt/vaivar-hp2).'
COMPOSE_PROJECT="${PROJECT_NAME_OVERRIDE:-$(read_env_value "$ENV_FILE" VAIVAR_COMPOSE_PROJECT)}"
[[ -n "$COMPOSE_PROJECT" ]] || COMPOSE_PROJECT=vaivar
valid_project_name "$COMPOSE_PROJECT" || die 'El nombre del proyecto Compose no es válido (usa minúsculas, números, guiones o guiones bajos).'
RUNNING_CONTAINER_ID="$(docker ps -aq \
  --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" \
  --filter 'label=com.docker.compose.service=vaivar' | head -n1)"
[[ -n "$CONTROL_CHANNEL" ]] || CONTROL_CHANNEL="$(read_env_value "$ENV_FILE" VAIVAR_CONTROL_CHANNEL)"
[[ -n "$CONTROL_CHANNEL" ]] || CONTROL_CHANNEL=encrypted
[[ -n "$PUBLIC_PORT" ]] || PUBLIC_PORT="$(read_env_value "$ENV_FILE" HONEYPOT_PORT)"
[[ -n "$API_PORT" ]] || API_PORT="$(read_env_value "$ENV_FILE" HTTP_PORT)"
[[ -n "$PROFILE" ]] || PROFILE="$(read_env_value "$ENV_FILE" VAIVAR_HONEYPOT_PROFILE)"
[[ -n "$PUBLIC_BIND" ]] || PUBLIC_BIND="$(read_env_value "$ENV_FILE" HONEYPOT_BIND)"
[[ -n "$API_BIND" ]] || API_BIND="$(read_env_value "$ENV_FILE" API_BIND)"
[[ -n "$SITE_ID" ]] || SITE_ID="$(read_env_value "$ENV_FILE" VAIVAR_SITE_ID)"
[[ -n "$PUBLIC_PORT" ]] || PUBLIC_PORT="$(read_running_env_value VAIVAR_PORT_HONEYPOT)"
[[ -n "$API_PORT" ]] || API_PORT="$(read_running_env_value VAIVAR_PORT_HTTP)"
[[ -n "$PROFILE" ]] || PROFILE="$(read_running_env_value VAIVAR_HONEYPOT_PROFILE)"
[[ -n "$PUBLIC_BIND" ]] || PUBLIC_BIND="$(read_running_env_value HONEYPOT_BIND)"
[[ -n "$API_BIND" ]] || API_BIND="$(read_running_env_value API_BIND)"
[[ -n "$SITE_ID" ]] || SITE_ID="$(read_running_env_value VAIVAR_SITE_ID)"
[[ -n "$PUBLIC_PORT" ]] || die 'Indica --public-port o deja ese valor en el .env de la instalación.'
[[ -n "$API_PORT" ]] || die 'Indica --api-port o deja ese valor en el .env de la instalación.'
[[ -n "$PROFILE" ]] || PROFILE=all
[[ -n "$PUBLIC_BIND" ]] || PUBLIC_BIND=0.0.0.0
[[ -n "$API_BIND" ]] || API_BIND=0.0.0.0
[[ -n "$SITE_ID" ]] || SITE_ID="$(hostname | tr -cd '[:alnum:]_.-')"
[[ -n "$SITE_ID" ]] || SITE_ID=honeypot-1

valid_port "$PUBLIC_PORT" || die 'El puerto público no es válido.'
valid_port "$API_PORT" || die 'El puerto de API no es válido.'
[[ "$PUBLIC_PORT" != "$API_PORT" ]] || die 'El puerto público y el puerto de API deben ser distintos.'
case "$PROFILE" in all|http|wiki|openapi|mcp) ;; *) die 'Perfil inválido.' ;; esac
valid_ipv4 "$PUBLIC_BIND" || die 'La interfaz pública debe ser una IPv4.'
valid_ipv4 "$API_BIND" || die 'La interfaz de API debe ser una IPv4.'
valid_site "$SITE_ID" || die 'El site_id no es válido.'
[[ "$CONTROL_CHANNEL" == encrypted || "$CONTROL_CHANNEL" == legacy ]] || die '--control-channel debe ser encrypted o legacy.'

if [[ "$CONTROL_CHANNEL" == legacy ]]; then
  printf 'Aviso: --control-channel legacy deja el API de control sin cifrado de aplicación; úsalo solo para migraciones.\n' >&2
fi

port_available "$PUBLIC_PORT" || die "El puerto público $PUBLIC_PORT ya está ocupado en este host. Elige otro o actualiza la misma instancia Compose."
port_available "$API_PORT" || die "El puerto de control $API_PORT ya está ocupado en este host. Elige otro o actualiza la misma instancia Compose."

[[ -n "$NODE_HOST" ]] || die 'Indica --host con la dirección que Central usará para llegar al honeypot.'
valid_host "$NODE_HOST" || die 'La dirección --host no es un hostname o IPv4 válido.'

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT
BUNDLE="$WORK_DIR/release.bundle.tar.gz"
HEADERS="$WORK_DIR/headers.txt"

DOWNLOAD_FROM_CENTRAL=0
if [[ -n "$ARTIFACT_URL" ]]; then
  DOWNLOAD_URL="$ARTIFACT_URL"
else
  DOWNLOAD_URL="${CENTRAL_URL%/}/api/v1/bootstrap/releases/current/download"
  DOWNLOAD_FROM_CENTRAL=1
fi

printf 'Descargando el bundle aprobado…\n'
if (( DOWNLOAD_FROM_CENTRAL )); then
  curl --fail --silent --show-error --location --retry 3 --retry-delay 1 \
    -D "$HEADERS" -H "X-Vaivar-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
    "$DOWNLOAD_URL" -o "$BUNDLE"
else
  curl --fail --silent --show-error --location --retry 3 --retry-delay 1 \
    -D "$HEADERS" "$DOWNLOAD_URL" -o "$BUNDLE"
fi
if [[ -z "$EXPECTED_SHA256" ]]; then
  EXPECTED_SHA256="$(awk 'tolower($1) == "x-vaivar-release-sha256:" { gsub(/\r/, "", $2); value=$2 } END { print value }' "$HEADERS")"
fi
[[ "$EXPECTED_SHA256" =~ ^[a-fA-F0-9]{64}$ ]] || die 'La descarga no proporcionó un SHA-256 verificable.'
printf '%s  %s\n' "$EXPECTED_SHA256" "$BUNDLE" | sha256sum --check --status || die 'La verificación SHA-256 del bundle ha fallado.'

EXTRACT_DIR="$WORK_DIR/extracted"
mkdir -p "$EXTRACT_DIR"
tar --no-same-owner -xzf "$BUNDLE" -C "$EXTRACT_DIR"
[[ -s "$EXTRACT_DIR/image.tar.gz" ]] || die 'El bundle no contiene image.tar.gz.'
[[ -s "$EXTRACT_DIR/docker-compose.yml" ]] || die 'El bundle no contiene docker-compose.yml.'

printf 'Cargando la imagen Docker…\n'
gzip -dc "$EXTRACT_DIR/image.tar.gz" | docker load
IMAGE_REF="$(awk '$1 == "image:" { print $2; exit }' "$EXTRACT_DIR/docker-compose.yml")"
[[ "$IMAGE_REF" =~ ^vaivar:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || die 'El compose del bundle no referencia una imagen vAIvar versionada.'

install -d -m 0750 "$INSTALL_DIR"
install -m 0644 "$EXTRACT_DIR/docker-compose.yml" "$INSTALL_DIR/docker-compose.yml.new"
mv "$INSTALL_DIR/docker-compose.yml.new" "$INSTALL_DIR/docker-compose.yml"

MASTER_SECRET="$(read_env_value "$ENV_FILE" VAIVAR_MASTER_SECRET)"
API_TOKEN="$(read_env_value "$ENV_FILE" VAIVAR_API_TOKEN)"
LIVE_MASTER_SECRET="$(read_running_env_value VAIVAR_MASTER_SECRET)"
LIVE_API_TOKEN="$(read_running_env_value VAIVAR_API_TOKEN)"
[[ -z "$LIVE_MASTER_SECRET" ]] || MASTER_SECRET="$LIVE_MASTER_SECRET"
[[ -z "$LIVE_API_TOKEN" ]] || API_TOKEN="$LIVE_API_TOKEN"
[[ -n "$MASTER_SECRET" ]] || MASTER_SECRET="$(random_hex)"
[[ -n "$API_TOKEN" ]] || API_TOKEN="$(random_hex)"
[[ "$MASTER_SECRET" =~ ^[a-fA-F0-9]{64,}$ ]] || die 'El secreto existente no es hexadecimal válido.'
valid_token "$API_TOKEN" || die 'El barriertoken existente no es válido.'

TEMP_ENV="$(mktemp "$INSTALL_DIR/.env.tmp.XXXXXX")"
cat > "$TEMP_ENV" <<EOF
# Configuración privada de vAIvar. No compartir ni versionar.
HONEYPOT_BIND=$PUBLIC_BIND
HONEYPOT_PORT=$PUBLIC_PORT
API_BIND=$API_BIND
HTTP_PORT=$API_PORT
VAIVAR_PORT_HONEYPOT=$PUBLIC_PORT
VAIVAR_PORT_HTTP=$API_PORT
VAIVAR_HONEYPOT_PROFILE=$PROFILE
VAIVAR_SITE_ID=$SITE_ID
VAIVAR_COMPOSE_PROJECT=$COMPOSE_PROJECT
VAIVAR_CONTROL_CHANNEL=$CONTROL_CHANNEL
VAIVAR_MASTER_SECRET=$MASTER_SECRET
VAIVAR_API_TOKEN=$API_TOKEN
EOF
chmod 600 "$TEMP_ENV"
mv "$TEMP_ENV" "$ENV_FILE"

compose() {
  docker compose --project-name "$COMPOSE_PROJECT" --env-file "$ENV_FILE" -f "$INSTALL_DIR/docker-compose.yml" "$@"
}
compose config --quiet
printf 'Arrancando el honeypot…\n'
if ! compose up -d --no-build --wait --wait-timeout 120 vaivar; then
  compose ps || true
  die 'El honeypot no ha quedado saludable; consulta los logs con docker compose logs.'
fi

if (( AUTO_REGISTER )); then
  REGISTRATION_BODY="{\"host\":\"$NODE_HOST\",\"port\":$API_PORT,\"token\":\"$API_TOKEN\",\"tls\":\"http\",\"channel\":\"$CONTROL_CHANNEL\"}"
  printf 'Registrando el honeypot en la central…\n'
  REGISTER_RESPONSE=""
  if ! REGISTER_RESPONSE="$(curl --fail --silent --show-error --location --retry 2 \
    -H "X-Vaivar-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
    -H 'Content-Type: application/json' \
    --data "$REGISTRATION_BODY" \
    "${CENTRAL_URL%/}/api/v1/bootstrap/register")"; then
    printf '%s\n' "$REGISTER_RESPONSE" >&2
    die 'El honeypot arrancó, pero la central no pudo completar el registro.'
  fi
fi

printf '\nHoneypot instalado y saludable.\n'
printf '  Imagen: %s\n' "$IMAGE_REF"
printf '  Superficie pública: http://%s:%s (%s)\n' "$NODE_HOST" "$PUBLIC_PORT" "$PROFILE"
printf '  API de control: http://%s:%s\n' "$NODE_HOST" "$API_PORT"
printf '  Canal: %s (AES-256-GCM dentro de HTTP)\n' "$CONTROL_CHANNEL"
printf '  Instalación: %s\n' "$INSTALL_DIR"
printf '  Proyecto Compose: %s\n' "$COMPOSE_PROJECT"
if (( AUTO_REGISTER )); then
  printf '  Registro central: completado\n'
elif [[ -n "$CENTRAL_URL" ]]; then
  printf '  Registro central: pendiente; no se envió el token por HTTP\n'
  printf '  Alta manual: usa host=%s, puerto=%s, canal=%s y el barriertoken de abajo en Central\n' "$NODE_HOST" "$API_PORT" "$CONTROL_CHANNEL"
fi
printf '  Credenciales: %s (permisos 600)\n' "$ENV_FILE"
if [[ -t 1 && "${VAIVAR_SHOW_TOKEN:-1}" == 1 ]]; then
  printf '  Barriertoken: %s\n' "$API_TOKEN"
fi
