#!/bin/sh
# Download, SHA-256 verify, smoke-check, and atomically install a prebuilt mp-outpost release.
# Usage: curl -fsSL https://multiplayer.tech/install-outpost.sh | sh
set -eu

outpost_version=${OUTPOST_VERSION:-latest}
outpost_prefix=${OUTPOST_PREFIX:-}
outpost_base_url=${OUTPOST_RELEASE_BASE_URL:-}

outpost_usage() {
  cat <<'USAGE'
Usage:
  install-outpost.sh [--version <vX.Y.Z|latest>] [--prefix DIR] [--base-url URL]
  install-outpost.sh --help

Install a SHA-256 verified prebuilt mp-outpost binary atomically into
<prefix>/bin/mp-outpost (default prefix: $HOME/.local).

Environment overrides:
  OUTPOST_VERSION           Release version tag or 'latest' (default: latest)
  OUTPOST_PREFIX            Install prefix (default: $HOME/.local)
  OUTPOST_RELEASE_BASE_URL  Release asset base URL (https:// or file:// only)
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--prefix|--base-url)
      [ "$#" -ge 2 ] || { printf 'Missing value for %s\n' "$1" >&2; exit 2; }
      case "$1" in
        --version) outpost_version=$2 ;;
        --prefix) outpost_prefix=$2 ;;
        --base-url) outpost_base_url=$2 ;;
      esac
      shift 2 ;;
    --help|-h)
      outpost_usage
      exit 0 ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      exit 2 ;;
  esac
done

case "$outpost_version" in
  latest) ;;
  ''|v|*..*|*/*|v*[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-]*)
    printf 'Unsafe or invalid version (expected latest or v[0-9A-Za-z._-]+): %s\n' "$outpost_version" >&2
    exit 2 ;;
  v*) ;;
  *)
    printf 'Unsafe or invalid version: %s\n' "$outpost_version" >&2
    exit 2 ;;
esac

if [ -z "$outpost_prefix" ]; then
  outpost_prefix=${HOME:?HOME must be set}/.local
fi

if [ -z "$outpost_base_url" ]; then
  if [ "$outpost_version" = latest ]; then
    outpost_base_url='https://github.com/antimeme-ai/outpost/releases/latest/download'
  else
    outpost_base_url="https://github.com/antimeme-ai/outpost/releases/download/$outpost_version"
  fi
fi
outpost_base_url=${outpost_base_url%/}

case "$outpost_base_url" in
  https://?*|file://?*) ;;
  *)
    printf 'Refusing unsupported base URL (https:// or file:// only): %s\n' "$outpost_base_url" >&2
    exit 2 ;;
esac

case "$(uname -s)" in
  Darwin) os_slug=darwin ;;
  Linux) os_slug=linux ;;
  *) printf 'Unsupported OS: %s\n' "$(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  arm64|aarch64) arch_slug=arm64 ;;
  x86_64|amd64) arch_slug=x86_64 ;;
  *) printf 'Unsupported architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac

target="${os_slug}-${arch_slug}"

fetch_file() {
  url=$1
  dest=$2
  case "$url" in
    file://*)
      src=${url#file://}
      [ -f "$src" ] || { printf 'Asset not found: %s\n' "$src" >&2; return 1; }
      cp -- "$src" "$dest"
      ;;
    https://*)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
      elif command -v wget >/dev/null 2>&1; then
        wget --https-only --secure-protocol=TLSv1_2 -qO "$dest" "$url"
      else
        printf 'Neither curl nor wget is available.\n' >&2
        return 1
      fi
      ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" | awk '{print tolower($1)}'
  else
    printf 'Neither sha256sum nor shasum is available for SHA-256 verification.\n' >&2
    return 1
  fi
}

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/mp-outpost-install.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

sums_file="$tmpdir/SHA256SUMS.txt"
if ! fetch_file "$outpost_base_url/SHA256SUMS.txt" "$sums_file"; then
  printf 'Could not fetch SHA256SUMS.txt from %s.\n' "$outpost_base_url" >&2
  printf 'If no prebuilt release is published yet, build from source:\n' >&2
  printf '  git clone https://github.com/antimeme-ai/outpost.git && cd outpost && cargo build --release -p outpost-cli\n' >&2
  exit 1
fi

asset_name=$(awk -v t="$target" '
  {
    f = $2
    sub(/^\*/, "", f)
    if (f ~ ("^mp-outpost-.*" t "\\.tar\\.gz$")) {
      print f
      exit
    }
  }
' "$sums_file")

if [ -z "$asset_name" ]; then
  printf 'No mp-outpost release asset found for target %s in SHA256SUMS.txt.\n' "$target" >&2
  exit 1
fi

expected_sha=$(awk -v name="$asset_name" '
  {
    f = $2
    sub(/^\*/, "", f)
    if (f == name) {
      print tolower($1)
      exit
    }
  }
' "$sums_file")

case "$expected_sha" in
  *[!0123456789abcdef]*|'')
    printf 'Malformed SHA-256 entry for %s\n' "$asset_name" >&2
    exit 1 ;;
esac
if [ "${#expected_sha}" -ne 64 ]; then
  printf 'Invalid SHA-256 length for %s\n' "$asset_name" >&2
  exit 1
fi

tarball="$tmpdir/$asset_name"
fetch_file "$outpost_base_url/$asset_name" "$tarball"
actual_sha=$(sha256_file "$tarball")
if [ "$actual_sha" != "$expected_sha" ]; then
  printf 'SHA-256 mismatch for %s (expected %s, got %s)\n' "$asset_name" "$expected_sha" "$actual_sha" >&2
  exit 1
fi

extract_dir="$tmpdir/extract"
mkdir -p "$extract_dir"
tar -xzf "$tarball" -C "$extract_dir"
bin_src=$(find "$extract_dir" -maxdepth 3 -type f -name mp-outpost | head -n 1)
if [ -z "$bin_src" ]; then
  printf 'Archive %s did not contain mp-outpost binary.\n' "$asset_name" >&2
  exit 1
fi
chmod 0755 "$bin_src"
"$bin_src" --version >/dev/null

mkdir -p "$outpost_prefix/bin"
staged="$outpost_prefix/bin/.mp-outpost.tmp.$$"
cp -- "$bin_src" "$staged"
chmod 0755 "$staged"
mv -f -- "$staged" "$outpost_prefix/bin/mp-outpost"

printf 'Installed mp-outpost (%s, sha256:%s) to %s/bin/mp-outpost\n' "$target" "$actual_sha" "$outpost_prefix"
case ":${PATH:-}:" in
  *":$outpost_prefix/bin:"*) ;;
  *) printf 'Note: add %s/bin to your PATH.\n' "$outpost_prefix" ;;
esac
