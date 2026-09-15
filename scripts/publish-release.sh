#!/usr/bin/env bash
# Build and publish one immutable, offline-capable honeypot release bundle.
# The resulting artifact and manifest can be copied to the central server's
# VAIVAR_RELEASE_DIR or uploaded as a GitHub release asset.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="${2:-$REPO_ROOT/releases}"
VERSION="${1:-}"
CHANNEL="${VAIVAR_RELEASE_CHANNEL:-stable}"

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

[[ -n "$VERSION" ]] || die 'Uso: scripts/publish-release.sh VERSION [RELEASE_DIR]'
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || die 'VERSION debe ser un tag Docker seguro, por ejemplo 1.2.0.'
[[ "$CHANNEL" == stable || "$CHANNEL" == canary ]] || die 'VAIVAR_RELEASE_CHANNEL debe ser stable o canary.'
command -v docker >/dev/null 2>&1 || die 'No se encuentra docker.'
command -v gzip >/dev/null 2>&1 || die 'No se encuentra gzip.'
command -v tar >/dev/null 2>&1 || die 'No se encuentra tar.'
command -v sha256sum >/dev/null 2>&1 || die 'No se encuentra sha256sum.'
command -v python3 >/dev/null 2>&1 || die 'No se encuentra python3.'

ARTIFACT="vaivar-${VERSION}.bundle.tar.gz"
MANIFEST="release-${VERSION}.manifest.json"
mkdir -p "$RELEASE_DIR"
RELEASE_DIR="$(cd "$RELEASE_DIR" && pwd)"
# The Central container runs as UID 1001 and reads this bind mount. Release
# bundles contain no credentials, so the catalog directory and metadata are
# intentionally world-readable while the publisher's staging directory stays
# private.
chmod 0755 "$RELEASE_DIR"
[[ ! -e "$RELEASE_DIR/$ARTIFACT" ]] || die "Ya existe $RELEASE_DIR/$ARTIFACT; publica una versión nueva."
[[ ! -e "$RELEASE_DIR/$MANIFEST" ]] || die "Ya existe $RELEASE_DIR/$MANIFEST; publica una versión nueva."

STAGE="$(mktemp -d "$RELEASE_DIR/.publish.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

IMAGE="vaivar:${VERSION}"
printf 'Construyendo %s…\n' "$IMAGE"
docker build --tag "$IMAGE" "$REPO_ROOT"

# The compose file in the bundle points at the immutable image tag. The
# build stanza is retained for compatibility, but the installer always uses
# --no-build and therefore never needs source code or an internet registry.
sed "s/^    image: vaivar:latest$/    image: ${IMAGE}/" \
  "$REPO_ROOT/docker-compose.yml" > "$STAGE/docker-compose.yml"
printf 'Exportando la imagen…\n'
docker save "$IMAGE" | gzip -n > "$STAGE/image.tar.gz"
tar -czf "$STAGE/$ARTIFACT" -C "$STAGE" image.tar.gz docker-compose.yml

SIZE_BYTES="$(stat -c '%s' "$STAGE/$ARTIFACT")"
SHA256="$(sha256sum "$STAGE/$ARTIFACT" | awk '{print $1}')"
CREATED_AT_MS="$(date +%s%3N)"

# Publish the artifact first and the manifest last. The catalog ignores a
# manifest whose artifact is absent or has a different size.
install -m 0644 "$STAGE/$ARTIFACT" "$RELEASE_DIR/$ARTIFACT"
VERSION="$VERSION" CHANNEL="$CHANNEL" ARTIFACT="$ARTIFACT" \
  SIZE_BYTES="$SIZE_BYTES" SHA256="$SHA256" CREATED_AT_MS="$CREATED_AT_MS" \
  SIGNATURE="${VAIVAR_RELEASE_SIGNATURE:-}" \
  python3 - "$RELEASE_DIR/$MANIFEST.tmp" <<'PY'
import json
import os
import sys

manifest = {
    "schema": "vaivar.release.v1",
    "version": os.environ["VERSION"],
    "channel": os.environ["CHANNEL"],
    "artifact": os.environ["ARTIFACT"],
    "sha256": os.environ["SHA256"],
    "size_bytes": int(os.environ["SIZE_BYTES"]),
    "created_at_ms": int(os.environ["CREATED_AT_MS"]),
}
if os.environ.get("SIGNATURE"):
    manifest["signature"] = os.environ["SIGNATURE"]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
mv "$RELEASE_DIR/$MANIFEST.tmp" "$RELEASE_DIR/$MANIFEST"
chmod 0644 "$RELEASE_DIR/$MANIFEST"

printf '\nRelease publicado:\n'
printf '  Artefacto: %s\n' "$RELEASE_DIR/$ARTIFACT"
printf '  Manifiesto: %s\n' "$RELEASE_DIR/$MANIFEST"
printf '  Versión: %s (%s)\n' "$VERSION" "$CHANNEL"
printf '  SHA-256: %s\n' "$SHA256"
printf '\nCopia ambos ficheros al VAIVAR_RELEASE_DIR de la central.\n'
