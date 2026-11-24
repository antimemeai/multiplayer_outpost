#!/usr/bin/env bash
# Builds a deterministic, multi-arch .mcpb (MCP Bundle v0.4) for mp-outpost
# from live SHA-256-verified GitHub Release tarballs.
set -euo pipefail

VERSION="v0.4.0"
REPO="antimemeai/multiplayer_outpost"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
OUT_DIR="${REPO_ROOT}/dist"
UPDATE_SERVER_JSON=0

# Pinned v0.4.0 release tarball SHA-256 digests (verified against GitHub Releases SHA256SUMS.txt)
PINNED_SHA_DARWIN_ARM64="8c884c44a1d0df70e8c0b994f6b09c73d693ebde8b35f2309c56136b643b0add"
PINNED_SHA_LINUX_X86_64="f04dac5d3ee500a077815b38378288d1c878b218ac3c3a1d301d86eaf3707dab"
PINNED_SHA_LINUX_ARM64="e016872244f8dc93f952861fc6446ba77bbb847e0a4d8e44d21d70bb95c96cb8"

usage() {
  cat <<'USAGE'
Usage:
  packaging/mcpb/build-mcpb.sh [--version v0.4.0] [--out-dir DIR] [--update-server-json]

Downloads the verified mp-outpost release tarballs (darwin-arm64, linux-x86_64,
linux-arm64), verifies every SHA-256 digest against pinned hashes and live
SHA256SUMS.txt, extracts each static binary safely, and packs a reproducible
.mcpb ZIP bundle.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?missing --version}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:?missing --out-dir}"; shift 2 ;;
    --update-server-json) UPDATE_SERVER_JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || [[ "$VERSION" == *..* ]]; then
  echo "Invalid --version (expected strict semver vX.Y.Z): $VERSION" >&2
  exit 2
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print tolower($1)}'
  else
    shasum -a 256 -- "$1" | awk '{print tolower($1)}'
  fi
}

pinned_sha_for() {
  case "$1" in
    darwin-arm64) printf '%s' "$PINNED_SHA_DARWIN_ARM64" ;;
    linux-x86_64) printf '%s' "$PINNED_SHA_LINUX_X86_64" ;;
    linux-arm64)  printf '%s' "$PINNED_SHA_LINUX_ARM64" ;;
    *) echo "Unknown target: $1" >&2; exit 1 ;;
  esac
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mp-outpost-mcpb.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

STAGE_DIR="${WORK_DIR}/stage"
DL_DIR="${WORK_DIR}/downloads"
mkdir -p "${STAGE_DIR}/bin" "${DL_DIR}"

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
SUMS_FILE="${DL_DIR}/SHA256SUMS.txt"
curl -fsSL --proto '=https' --tlsv1.2 "${BASE_URL}/SHA256SUMS.txt" -o "${SUMS_FILE}"

for TARGET in darwin-arm64 linux-x86_64 linux-arm64; do
  TARBALL="mp-outpost-${VERSION}-${TARGET}.tar.gz"
  TAR_PATH="${DL_DIR}/${TARBALL}"
  EXPECTED_LIVE="$(awk -v f="$TARBALL" '$2 == f {print tolower($1)}' "${SUMS_FILE}")"
  if [ -z "${EXPECTED_LIVE}" ]; then
    echo "ERROR: ${TARBALL} missing from live SHA256SUMS.txt" >&2
    exit 1
  fi
  if [ "${VERSION}" = "v0.4.0" ]; then
    EXPECTED_PINNED="$(pinned_sha_for "${TARGET}")"
    if [ "${EXPECTED_LIVE}" != "${EXPECTED_PINNED}" ]; then
      echo "ERROR: live SHA-256 mismatch vs pinned hash for ${TARBALL}" >&2
      echo "  live:   ${EXPECTED_LIVE}" >&2
      echo "  pinned: ${EXPECTED_PINNED}" >&2
      exit 1
    fi
  fi

  echo "Fetching ${TARBALL}..."
  curl -fsSL --proto '=https' --tlsv1.2 "${BASE_URL}/${TARBALL}" -o "${TAR_PATH}"

  ACTUAL_SHA="$(sha256_file "${TAR_PATH}")"
  if [ "${ACTUAL_SHA}" != "${EXPECTED_LIVE}" ]; then
    echo "ERROR: downloaded SHA-256 mismatch for ${TARBALL}" >&2
    echo "  expected: ${EXPECTED_LIVE}" >&2
    echo "  actual:   ${ACTUAL_SHA}" >&2
    exit 1
  fi

  # Extract ONLY the expected binary entry after verifying archive members contain no traversal/symlinks.
  MEMBER="mp-outpost-${VERSION}-${TARGET}/mp-outpost"
  python3 - "${TAR_PATH}" "${MEMBER}" "${STAGE_DIR}/bin/mp-outpost-${TARGET}" <<'PY'
import os
import shutil
import sys
import tarfile

tar_path, expected_member, dest_path = sys.argv[1], sys.argv[2], sys.argv[3]
with tarfile.open(tar_path, "r:gz") as tf:
    members = tf.getmembers()
    found = None
    for m in members:
        if m.name.startswith("/") or ".." in m.name.split("/"):
            raise SystemExit(f"Unsafe archive member path: {m.name}")
        if m.issym() or m.islnk():
            raise SystemExit(f"Unexpected link in archive: {m.name}")
        if m.name == expected_member:
            if not m.isfile():
                raise SystemExit(f"Expected regular file for {m.name}")
            found = m
    if found is None:
        raise SystemExit(f"Missing expected binary member: {expected_member}")
    src = tf.extractfile(found)
    if src is None:
        raise SystemExit(f"Could not extract {expected_member}")
    with src, open(dest_path, "wb") as out:
        shutil.copyfileobj(src, out)
os.chmod(dest_path, 0o755)
PY
done

cp "${SCRIPT_DIR}/manifest.json" "${STAGE_DIR}/manifest.json"
cp "${SCRIPT_DIR}/icon.png" "${STAGE_DIR}/icon.png"
cp "${REPO_ROOT}/LICENSE" "${STAGE_DIR}/LICENSE"
cp "${SCRIPT_DIR}/bin/launch.sh" "${STAGE_DIR}/bin/launch.sh"
cp "${SCRIPT_DIR}/bin/launch-linux.sh" "${STAGE_DIR}/bin/launch-linux.sh"
chmod 0644 "${STAGE_DIR}/manifest.json" "${STAGE_DIR}/icon.png" "${STAGE_DIR}/LICENSE"
chmod 0755 "${STAGE_DIR}/bin/launch.sh" "${STAGE_DIR}/bin/launch-linux.sh"

mkdir -p "${OUT_DIR}"
OUT_ABS="$(cd "${OUT_DIR}" && pwd -P)"
OUT_MCPB="${OUT_ABS}/mp-outpost-${VERSION}-universal.mcpb"

# Create a deterministic ZIP archive (fixed UTC timestamp, sorted entries, preserved exec bits).
python3 - "${STAGE_DIR}" "${OUT_MCPB}" <<'PY'
import os
import stat
import sys
import zipfile

stage_dir, out_zip = sys.argv[1], sys.argv[2]
fixed_date_time = (2026, 11, 23, 0, 0, 0)

entries = []
for root, dirs, files in os.walk(stage_dir):
    dirs.sort()
    for name in sorted(files):
        full = os.path.join(root, name)
        rel = os.path.relpath(full, stage_dir).replace(os.sep, "/")
        entries.append((rel, full))
entries.sort(key=lambda item: item[0])

with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for rel, full in entries:
        mode = stat.S_IMODE(os.lstat(full).st_mode)
        zi = zipfile.ZipInfo(filename=rel, date_time=fixed_date_time)
        zi.create_system = 3  # Unix
        zi.external_attr = (stat.S_IFREG | mode) << 16
        with open(full, "rb") as fh:
            zf.writestr(zi, fh.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
PY

MCPB_SHA="$(sha256_file "${OUT_MCPB}")"
MCPB_SIZE="$(wc -c < "${OUT_MCPB}" | tr -d ' ')"
printf '%s  %s\n' "${MCPB_SHA}" "$(basename "${OUT_MCPB}")" > "${OUT_ABS}/$(basename "${OUT_MCPB}").sha256"

echo "Built: ${OUT_MCPB}"
echo "Size:  ${MCPB_SIZE} bytes"
echo "SHA256: ${MCPB_SHA}"

if [ "${UPDATE_SERVER_JSON}" -eq 1 ]; then
  SERVER_JSON="${SCRIPT_DIR}/../mcp-registry/server.json"
  python3 - "${SERVER_JSON}" "${VERSION}" "${MCPB_SHA}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
version_tag = sys.argv[2]
sha256_hex = sys.argv[3]
version = version_tag.removeprefix("v")

data = json.loads(path.read_text(encoding="utf-8"))
data["version"] = version
for pkg in data.get("packages", []):
    if pkg.get("registryType") == "mcpb":
        pkg["version"] = version
        pkg["identifier"] = (
            f"https://github.com/antimemeai/multiplayer_outpost/releases/download/"
            f"{version_tag}/mp-outpost-{version_tag}-universal.mcpb"
        )
        pkg["fileSha256"] = sha256_hex

path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"Updated {path} with fileSha256={sha256_hex}")
PY
fi
