#!/bin/sh
# vAIvar runtime entrypoint.
# When run as root (e.g. the central service, where the entrypoint must fix
# ownership of root-owned named volumes), chown data paths and drop to the
# unprivileged runtime user. When already unprivileged, just exec directly.
set -e

RUNTIME_USER=nodejs
RUNTIME_UID=1001

# Only attempt privileged setup when we are actually root.
if [ "$(id -u)" = "0" ]; then
  if [ -d /data ]; then
    chown -R "${RUNTIME_UID}:1001" /data 2>/dev/null || true
  fi
  exec su-exec "${RUNTIME_USER}" "$@"
else
  exec "$@"
fi
