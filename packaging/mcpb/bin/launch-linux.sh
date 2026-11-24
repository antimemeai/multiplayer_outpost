#!/bin/sh
set -eu

SELF_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    exec "${SELF_DIR}/mp-outpost-linux-x86_64" "$@"
    ;;
  aarch64|arm64)
    exec "${SELF_DIR}/mp-outpost-linux-arm64" "$@"
    ;;
  *)
    printf 'mp-outpost.mcpb: unsupported Linux architecture %s\n' "$ARCH" >&2
    exit 1
    ;;
esac
