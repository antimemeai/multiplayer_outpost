#!/usr/bin/env bash
# Build, verify, and package a self-contained mp-outpost release tarball + SHA256SUMS.txt + release-manifest.json.
set -euo pipefail

VERSION=""
TARGET=""
OUT_DIR="dist"
SKIP_BUILD=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/package-release.sh --version <vX.Y.Z> [--target <os-arch>] [--out-dir DIR] [--skip-build]

Packages target/release/mp-outpost into:
  <out-dir>/mp-outpost-<version>-<target>.tar.gz
  <out-dir>/SHA256SUMS.txt
  <out-dir>/release-manifest.json
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?missing --version}"; shift 2 ;;
    --target) TARGET="${2:?missing --target}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:?missing --out-dir}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$VERSION" in
  ''|v|*..*|*/*|v*[!0-9A-Za-z._-]*)
    echo "Invalid --version (expected vX.Y.Z): '$VERSION'" >&2
    exit 2 ;;
  v*) ;;
  *)
    echo "Invalid --version (must start with 'v'): '$VERSION'" >&2
    exit 2 ;;
esac

if [ -z "$TARGET" ]; then
  case "$(uname -s)" in
    Darwin) os_slug="darwin" ;;
    Linux) os_slug="linux" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) arch_slug="arm64" ;;
    x86_64|amd64) arch_slug="x86_64" ;;
    *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
  TARGET="${os_slug}-${arch_slug}"
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$SKIP_BUILD" -eq 0 ]; then
  cargo build --release --locked --bin mp-outpost
fi

BIN_PATH="$ROOT_DIR/target/release/mp-outpost"
if [ ! -x "$BIN_PATH" ]; then
  echo "Release binary missing or not executable: $BIN_PATH" >&2
  exit 1
fi

# Offline smoke check
VER_OUT="$("$BIN_PATH" --version)"
echo "Verified binary: $VER_OUT"

# Self-contained linkage verification
if [ "$(uname -s)" = "Darwin" ]; then
  BAD_DYLIBS="$(otool -L "$BIN_PATH" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/System/Library/|/usr/lib/)' || true)"
  if [ -n "$BAD_DYLIBS" ]; then
    echo "ERROR: non-system dynamic libraries found in mp-outpost:" >&2
    echo "$BAD_DYLIBS" >&2
    exit 1
  fi
elif [ "$(uname -s)" = "Linux" ]; then
  BAD_SOS="$(ldd "$BIN_PATH" | awk '/=>/ {print $3}' | grep -Ev '^(|/lib/|/lib64/|/usr/lib/|/usr/lib64/)' || true)"
  if [ -n "$BAD_SOS" ]; then
    echo "ERROR: unexpected non-system shared libraries found in mp-outpost:" >&2
    echo "$BAD_SOS" >&2
    exit 1
  fi
fi

mkdir -p "$OUT_DIR"
OUT_DIR_ABS="$(cd "$OUT_DIR" && pwd)"

STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/mp-outpost-pkg.XXXXXX")"
trap 'rm -rf "$STAGE_ROOT"' EXIT

PKG_STEM="mp-outpost-${VERSION}-${TARGET}"
PKG_DIR="$STAGE_ROOT/$PKG_STEM"
mkdir -p "$PKG_DIR"
cp "$BIN_PATH" "$PKG_DIR/mp-outpost"
chmod 0755 "$PKG_DIR/mp-outpost"
if [ -f "$ROOT_DIR/README.md" ]; then
  cp "$ROOT_DIR/README.md" "$PKG_DIR/README.md"
fi
if [ -f "$ROOT_DIR/LICENSE" ]; then
  cp "$ROOT_DIR/LICENSE" "$PKG_DIR/LICENSE"
fi

TARBALL_NAME="${PKG_STEM}.tar.gz"
TARBALL_PATH="$OUT_DIR_ABS/$TARBALL_NAME"
tar -C "$STAGE_ROOT" -czf "$TARBALL_PATH" "$PKG_STEM"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print tolower($1)}'
  else
    shasum -a 256 -- "$1" | awk '{print tolower($1)}'
  fi
}

SHA="$(sha256_file "$TARBALL_PATH")"
SIZE_BYTES="$(wc -c < "$TARBALL_PATH" | tr -d ' ')"
COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"

printf '%s  %s\n' "$SHA" "$TARBALL_NAME" > "$OUT_DIR_ABS/SHA256SUMS.txt"

cat > "$OUT_DIR_ABS/release-manifest.json" <<JSON
{
  "version": "${VERSION}",
  "commit": "${COMMIT}",
  "assets": [
    {
      "target": "${TARGET}",
      "filename": "${TARBALL_NAME}",
      "sha256": "${SHA}",
      "size_bytes": ${SIZE_BYTES}
    }
  ]
}
JSON

echo "Packaged: $TARBALL_PATH ($SIZE_BYTES bytes, sha256:$SHA)"
