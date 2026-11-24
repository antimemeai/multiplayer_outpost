#!/bin/sh
set -eu

SELF_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}:${ARCH}" in
  Darwin:arm64|Darwin:aarch64)
    exec "${SELF_DIR}/mp-outpost-darwin-arm64" "$@"
    ;;
  Linux:x86_64|Linux:amd64)
    exec "${SELF_DIR}/mp-outpost-linux-x86_64" "$@"
    ;;
  Linux:aarch64|Linux:arm64)
    exec "${SELF_DIR}/mp-outpost-linux-arm64" "$@"
    ;;
  *)
    printf 'mp-outpost.mcpb: unsupported platform %s/%s\n' "$OS" "$ARCH" >&2
    exit 1
    ;;
esac
