#!/usr/bin/env bash
# vAIvar honeypot — small entry point for a remote honeypot host.
#
# The actual deployment flow lives in scripts/deploy.sh so the Central
# bootstrap path and the interactive path share the same validations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/scripts/deploy.sh" "$@"
