//! Native self-upgrade (`mp-outpost upgrade`) with dual manifest + `SHA256SUMS.txt`
//! verification, hardened archive audit, offline `--version` smoke check, and atomic
//! `0755` binary swap.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use mp_protocol::sha256;
use outpost_control::ControlClient;
use outpost_core::ipc_wire::{ClientKind, HelloPayload, IPC_SCHEMA_VER, IpcFrame, IpcOpcode};
use outpost_daemon::{
    DrainMode, SOCKET_FILE_NAME, decode_hello_ack, encode_drain_payload, encode_hello, fill_random,
    open_dir_nofollow, read_ipc_frame, read_regular_file_bounded_nofollow, resolve_runtime_dir,
    verify_peer_same_uid, write_ipc_frame,
};
use serde::Deserialize;
use serde_json::json;
use tokio::net::UnixStream;

use crate::build_info::{PKG_VERSION, build_digest, build_order, encode_hex};
use crate::cli::GlobalOpts;
use crate::storage::{
    build_control_client_config, list_enrolled_device_ids, resolve_effective_runtime_override,
    resolve_effective_state_dir,
};

const DEFAULT_RELEASE_LATEST_BASE: &str =
    "https://github.com/antimemeai/multiplayer_outpost/releases/latest/download";
const DEFAULT_RELEASE_TAG_BASE_PREFIX: &str =
    "https://github.com/antimemeai/multiplayer_outpost/releases/download";

const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
    "multiplayer.tech",
];

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_SUMS_BYTES: usize = 64 * 1024;
const MAX_TARBALL_BYTES: usize = 32 * 1024 * 1024;
const MAX_TAR_ENTRIES: usize = 16;
const MAX_VERSION_LEN: usize = 64;
const MAX_FILENAME_LEN: usize = 128;

pub const SELF_UPGRADE_DISABLE_ENV: &str = "OUTPOST_NO_SELF_UPGRADE";

fn env_flag_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn self_upgrade_disabled_reason(env_val: Option<&str>) -> Option<String> {
    if cfg!(feature = "packaged") {
        return Some(
            "in-place self-upgrade is disabled in this package-manager build (--features packaged); \
             upgrade via your package manager (e.g. `brew upgrade mp-outpost`, `yay -Syu mp-outpost-bin`, \
             `pacman -Syu`, or `nix profile upgrade`), or run `mp-outpost upgrade --check` to check for updates read-only."
                .to_string(),
        );
    }
    if env_val.is_some_and(env_flag_truthy) {
        return Some(format!(
            "in-place self-upgrade is disabled by {SELF_UPGRADE_DISABLE_ENV}; \
             upgrade via your package manager (e.g. `brew upgrade mp-outpost`, `yay -Syu mp-outpost-bin`, \
             `pacman -Syu`, or `nix profile upgrade`), or run `mp-outpost upgrade --check` to check for updates read-only."
        ));
    }
    None
}

fn enforce_self_upgrade_policy(check_only: bool, env_val: Option<&str>) -> Result<bool, String> {
    let disabled = self_upgrade_disabled_reason(env_val);
    if !check_only && let Some(reason) = disabled {
        return Err(reason);
    }
    Ok(disabled.is_some())
}

#[derive(Debug, Clone)]
struct UpgradeArgs {
    check: bool,
    yes: bool,
    version: String,
    explicit_version: bool,
    base_url: Option<String>,
    install_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    version: String,
    #[allow(dead_code)]
    commit: Option<String>,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAsset {
    target: String,
    filename: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>,
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let core = (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch));
        if core != std::cmp::Ordering::Equal {
            return core;
        }
        match (&self.pre, &other.pre) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(a), Some(b)) => compare_prerelease(a, b),
        }
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(sa), Some(sb)) => {
                let ord = match (sa.parse::<u64>(), sb.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    (Err(_), Err(_)) => sa.cmp(sb),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Parses a SemVer string with optional leading `v` (e.g. `"0.3.0"`, `"v0.3.1-rc.1"`).
fn parse_semver(raw: &str) -> Result<SemVer, String> {
    let trimmed = raw.strip_prefix('v').unwrap_or(raw);
    if trimmed.is_empty() {
        return Err(format!("invalid semver '{raw}'"));
    }
    let without_build = trimmed.split('+').next().unwrap_or(trimmed);
    let (core, pre) = match without_build.split_once('-') {
        Some((c, p)) if !p.is_empty() => (c, Some(p.to_string())),
        Some(_) => return Err(format!("invalid semver prerelease in '{raw}'")),
        None => (without_build, None),
    };
    let mut parts = core.split('.');
    let major_s = parts
        .next()
        .ok_or_else(|| format!("invalid semver '{raw}'"))?;
    let minor_s = parts
        .next()
        .ok_or_else(|| format!("invalid semver '{raw}'"))?;
    let patch_s = parts
        .next()
        .ok_or_else(|| format!("invalid semver '{raw}'"))?;
    if parts.next().is_some() {
        return Err(format!("invalid semver '{raw}': too many version components"));
    }
    let major = major_s
        .parse::<u64>()
        .map_err(|_| format!("invalid semver major in '{raw}'"))?;
    let minor = minor_s
        .parse::<u64>()
        .map_err(|_| format!("invalid semver minor in '{raw}'"))?;
    let patch = patch_s
        .parse::<u64>()
        .map_err(|_| format!("invalid semver patch in '{raw}'"))?;
    Ok(SemVer {
        major,
        minor,
        patch,
        pre,
    })
}

fn current_target_slug() -> Result<&'static str, String> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok("darwin-arm64")
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok("linux-x86_64")
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Ok("linux-arm64")
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        Err(format!(
            "unsupported OS/architecture for prebuilt mp-outpost upgrades ({}-{})",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    }
}

fn validate_version_arg(raw: &str, allow_latest: bool) -> Result<(), String> {
    if allow_latest && raw == "latest" {
        return Ok(());
    }
    if raw.len() < 2 || raw.len() > MAX_VERSION_LEN {
        return Err(format!(
            "invalid version '{raw}': expected 'latest' or v[0-9A-Za-z._-]+ (<= {MAX_VERSION_LEN} chars)"
        ));
    }
    let Some(rest) = raw.strip_prefix('v') else {
        return Err(format!(
            "invalid version '{raw}': must be 'latest' or start with 'v'"
        ));
    };
    if rest.is_empty()
        || raw.contains("..")
        || raw.contains('/')
        || raw.contains('\\')
        || !rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "unsafe or invalid version '{raw}': expected v[0-9A-Za-z._-]+"
        ));
    }
    Ok(())
}

fn validate_asset_filename(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_FILENAME_LEN {
        return Err(format!("invalid release asset filename '{name}'"));
    }
    if !name.starts_with("mp-outpost-") || !name.ends_with(".tar.gz") {
        return Err(format!(
            "unexpected release asset filename '{name}' (expected mp-outpost-*.tar.gz)"
        ));
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!("unsafe release asset filename '{name}'"));
    }
    Ok(())
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_sha256sums(text: &str) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hash_raw) = parts.next() else {
            return Err(format!("malformed SHA256SUMS.txt line {}", idx + 1));
        };
        let Some(fname_raw) = parts.next() else {
            return Err(format!("malformed SHA256SUMS.txt line {}", idx + 1));
        };
        if parts.next().is_some() {
            return Err(format!(
                "unexpected extra tokens in SHA256SUMS.txt line {}",
                idx + 1
            ));
        }
        let hash = hash_raw.to_ascii_lowercase();
        if !is_valid_sha256_hex(&hash) {
            return Err(format!(
                "invalid SHA-256 digest on SHA256SUMS.txt line {}",
                idx + 1
            ));
        }
        let fname = fname_raw.strip_prefix('*').unwrap_or(fname_raw);
        if fname.is_empty() || fname.contains('/') || fname.contains("..") {
            return Err(format!(
                "unsafe filename '{fname}' in SHA256SUMS.txt line {}",
                idx + 1
            ));
        }
        if let Some(prev) = map.insert(fname.to_string(), hash.clone())
            && prev != hash
        {
            return Err(format!(
                "conflicting duplicate SHA256SUMS.txt entries for '{fname}'"
            ));
        }
    }
    if map.is_empty() {
        return Err("SHA256SUMS.txt contained no entries".to_string());
    }
    Ok(map)
}

fn parse_and_cross_verify_manifest(
    manifest_bytes: &[u8],
    sums_bytes: &[u8],
    target: &str,
    requested_version: Option<&str>,
) -> Result<(String, ReleaseAsset), String> {
    let manifest_str = core::str::from_utf8(manifest_bytes)
        .map_err(|_| "release-manifest.json is not valid UTF-8".to_string())?;
    let manifest: ReleaseManifest = serde_json::from_str(manifest_str)
        .map_err(|e| format!("invalid release-manifest.json: {e}"))?;

    validate_version_arg(&manifest.version, false)?;
    let _ = parse_semver(&manifest.version)?;
    if let Some(req_ver) = requested_version
        && manifest.version != req_ver
    {
        return Err(format!(
            "release-manifest.json version '{}' does not match requested version '{req_ver}'",
            manifest.version
        ));
    }

    let mut matched: Option<ReleaseAsset> = None;
    for asset in manifest.assets {
        if asset.target == target {
            if matched.is_some() {
                return Err(format!(
                    "duplicate asset entries for target '{target}' in release-manifest.json"
                ));
            }
            matched = Some(asset);
        }
    }
    let asset = matched.ok_or_else(|| {
        format!("no release asset found for target '{target}' in release-manifest.json")
    })?;

    validate_asset_filename(&asset.filename)?;
    if !is_valid_sha256_hex(&asset.sha256) {
        return Err(format!(
            "invalid lowercase 64-hex sha256 in release-manifest.json for '{}'",
            asset.filename
        ));
    }
    if asset.size_bytes == 0 || asset.size_bytes > MAX_TARBALL_BYTES as u64 {
        return Err(format!(
            "asset '{}' size_bytes {} out of allowed range 1..={MAX_TARBALL_BYTES}",
            asset.filename, asset.size_bytes
        ));
    }

    let sums_str = core::str::from_utf8(sums_bytes)
        .map_err(|_| "SHA256SUMS.txt is not valid UTF-8".to_string())?;
    let sums = parse_sha256sums(sums_str)?;
    let sums_sha = sums.get(&asset.filename).ok_or_else(|| {
        format!(
            "SHA256SUMS.txt missing entry for manifest asset '{}'",
            asset.filename
        )
    })?;
    if sums_sha != &asset.sha256 {
        return Err(format!(
            "SHA-256 mismatch between release-manifest.json ({}) and SHA256SUMS.txt ({}) for '{}'",
            asset.sha256, sums_sha, asset.filename
        ));
    }

    Ok((manifest.version, asset))
}

fn parse_upgrade_args(args: &[String]) -> Result<UpgradeArgs, String> {
    let mut check = false;
    let mut yes = false;
    let mut version = "latest".to_string();
    let mut explicit_version = false;
    let mut base_url: Option<String> = None;
    let mut install_path: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args.get(i).map(String::as_str).unwrap_or_default();
        match arg {
            "--check" => {
                check = true;
                i += 1;
            }
            "--yes" | "-y" => {
                yes = true;
                i += 1;
            }
            "--version" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| "missing value for --version".to_string())?;
                validate_version_arg(val, true)?;
                version = val.clone();
                explicit_version = val != "latest";
                i += 2;
            }
            "--base-url" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| "missing value for --base-url".to_string())?;
                let trimmed = val.trim_end_matches('/');
                let is_https =
                    trimmed.starts_with("https://") && trimmed.len() > "https://".len();
                let is_file =
                    trimmed.starts_with("file://") && trimmed.len() > "file://".len();
                if !is_https && !is_file {
                    return Err(format!(
                        "unsupported --base-url '{val}' (only https:// and file:// are allowed)"
                    ));
                }
                base_url = Some(trimmed.to_string());
                i += 2;
            }
            "--install-path" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| "missing value for --install-path".to_string())?;
                if val.is_empty() {
                    return Err("--install-path must not be empty".to_string());
                }
                install_path = Some(PathBuf::from(val));
                i += 2;
            }
            other => {
                return Err(format!(
                    "unknown upgrade option '{other}' (supported: --check, --yes/-y, --version <vX.Y.Z|latest>, --base-url <url>, --install-path <path>)"
                ));
            }
        }
    }

    Ok(UpgradeArgs {
        check,
        yes,
        version,
        explicit_version,
        base_url,
        install_path,
    })
}

fn extract_https_authority_and_host(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("URL must start with https://: '{url}'"))?;
    let split = rest
        .bytes()
        .position(|b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let authority = rest.get(..split).unwrap_or("");
    if authority.is_empty() {
        return Err(format!("missing host in URL '{url}'"));
    }
    let host = if let Some(after_open) = authority.strip_prefix('[') {
        after_open
            .split_once(']')
            .map(|(h, _)| h)
            .ok_or_else(|| format!("invalid bracketed host in '{url}'"))?
    } else {
        authority.split_once(':').map_or(authority, |(h, _)| h)
    };
    if host.is_empty() {
        return Err(format!("missing host in URL '{url}'"));
    }
    Ok((authority.to_string(), host.to_ascii_lowercase()))
}

async fn fetch_asset_bytes(
    base_url: &str,
    relative_name: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if relative_name.is_empty()
        || relative_name.contains('/')
        || relative_name.contains('\\')
        || relative_name.contains("..")
    {
        return Err(format!("unsafe asset name '{relative_name}'"));
    }

    if let Some(dir_str) = base_url.strip_prefix("file://") {
        let file_path = Path::new(dir_str).join(relative_name);
        return read_regular_file_bounded_nofollow(&file_path, max_bytes)
            .map_err(|e| format!("failed reading local release asset '{}': {e}", file_path.display()));
    }

    if base_url.starts_with("https://") {
        let full_url = format!("{base_url}/{relative_name}");
        let (authority, custom_host) = extract_https_authority_and_host(base_url)?;
        let cfg = build_control_client_config(&authority)
            .map_err(|e| format!("failed building TLS 1.3 client config for '{authority}': {e}"))?;
        let client = ControlClient::new(cfg);

        let mut allowed: Vec<&str> = DEFAULT_ALLOWED_HOSTS.to_vec();
        if !allowed.iter().any(|h| h.eq_ignore_ascii_case(&custom_host)) {
            allowed.push(custom_host.as_str());
        }

        return client
            .fetch_https_bytes(&full_url, max_bytes, &allowed)
            .await
            .map_err(|e| format!("failed downloading '{full_url}': {e}"));
    }

    Err(format!("unsupported base URL scheme in '{base_url}'"))
}

/// Audits `tar -tzf` entry listing and returns the single validated relative path to `mp-outpost`.
fn validate_tar_entries(listing: &str) -> Result<String, String> {
    let mut count = 0usize;
    let mut binary_entry: Option<String> = None;

    for raw in listing.lines() {
        if raw.is_empty() {
            continue;
        }
        count += 1;
        if count > MAX_TAR_ENTRIES {
            return Err(format!(
                "refusing release archive with more than {MAX_TAR_ENTRIES} entries"
            ));
        }
        if raw.starts_with('/') || raw.starts_with('\\') || raw.contains('\\') {
            return Err(format!("refusing unsafe archive entry '{raw}'"));
        }
        if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err("refusing archive entry containing control characters".to_string());
        }

        let trimmed_dir = raw.trim_end_matches('/');
        if trimmed_dir.is_empty() {
            return Err(format!("refusing unsafe archive entry '{raw}'"));
        }
        for comp in trimmed_dir.split('/') {
            if comp == ".." {
                return Err(format!(
                    "refusing archive entry with path traversal '..': '{raw}'"
                ));
            }
        }

        let is_dir_entry = raw.ends_with('/');
        if !is_dir_entry
            && (trimmed_dir == "mp-outpost" || trimmed_dir.ends_with("/mp-outpost"))
        {
            if binary_entry.is_some() {
                return Err("refusing archive with multiple 'mp-outpost' binary entries".to_string());
            }
            binary_entry = Some(trimmed_dir.to_string());
        }
    }

    if count == 0 {
        return Err("refusing empty release archive".to_string());
    }
    binary_entry.ok_or_else(|| "release archive did not contain 'mp-outpost' binary".to_string())
}

/// RAII staging directory (`0700`) removed unconditionally on drop.
struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    fn create() -> Result<Self, String> {
        let base = std::env::temp_dir();
        let my_uid = unsafe { libc::geteuid() };

        for _ in 0..8 {
            let mut rnd = [0u8; 16];
            fill_random(&mut rnd).map_err(|e| format!("CSPRNG failure creating staging dir: {e}"))?;
            let candidate = base.join(format!("mp-outpost-upgrade-{}", encode_hex(&rnd)));
            let cpath = CString::new(candidate.as_os_str().as_bytes())
                .map_err(|_| "staging dir path contains NUL byte".to_string())?;
            let rc = unsafe { libc::mkdir(cpath.as_ptr(), 0o700) };
            if rc == 0 {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::lstat(cpath.as_ptr(), &mut st) } != 0 {
                    let _ = fs::remove_dir(&candidate);
                    return Err("failed to lstat newly created staging directory".to_string());
                }
                if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR || st.st_uid != my_uid {
                    let _ = fs::remove_dir(&candidate);
                    return Err("staging directory failed ownership/type verification".to_string());
                }
                if (st.st_mode & 0o777) != 0o700 {
                    let _ = unsafe { libc::chmod(cpath.as_ptr(), 0o700) };
                }
                return Ok(Self { path: candidate });
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(format!(
                "failed to create private staging dir '{}': {err}",
                candidate.display()
            ));
        }
        Err("failed to allocate unique staging directory after 8 attempts".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Recursively verifies via `symlink_metadata` (`lstat`) that an extracted directory tree
/// contains ONLY regular files and directories (zero symlinks, FIFOs, devices, or sockets).
fn audit_extracted_tree_no_symlinks(dir: &Path, depth: usize) -> Result<(), String> {
    if depth > 8 {
        return Err("extracted archive directory nesting exceeds safety limit".to_string());
    }
    let rd = fs::read_dir(dir)
        .map_err(|e| format!("failed reading extracted dir '{}': {e}", dir.display()))?;
    for entry_res in rd {
        let entry = entry_res.map_err(|e| format!("failed reading archive entry: {e}"))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("lstat failed on '{}': {e}", path.display()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(format!(
                "refusing extracted archive containing symlink '{}'",
                path.display()
            ));
        }
        if ft.is_dir() {
            audit_extracted_tree_no_symlinks(&path, depth + 1)?;
        } else if !ft.is_file() {
            return Err(format!(
                "refusing extracted archive containing non-regular file '{}'",
                path.display()
            ));
        }
    }
    Ok(())
}

fn confirm_upgrade_tty(
    current_ver: &str,
    new_ver: &str,
    target: &str,
    sha256_hex: &str,
) -> Result<(), String> {
    let is_tty = unsafe {
        libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1
    };
    if !is_tty {
        return Err("non-interactive terminal detected; pass --yes to confirm upgrade".to_string());
    }
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("failed to open /dev/tty for upgrade confirmation: {e}"))?;
    let sha_prefix = sha256_hex.get(..16).unwrap_or(sha256_hex);
    write!(
        tty,
        "Upgrade mp-outpost v{current_ver} -> {new_ver} ({target}, sha256:{sha_prefix}...)? [y/N]: "
    )
    .and_then(|()| tty.flush())
    .map_err(|e| format!("failed writing confirmation prompt to /dev/tty: {e}"))?;

    let mut line = String::new();
    let mut reader = BufReader::new(tty);
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed reading confirmation from /dev/tty: {e}"))?;
    let answer = line.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        Ok(())
    } else {
        Err("upgrade cancelled by user".to_string())
    }
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let rc = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let n = usize::try_from(rc).unwrap_or(0);
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to file descriptor",
            ));
        }
        buf = buf.get(n..).unwrap_or(&[]);
    }
    Ok(())
}

fn fsync_fd(fd: RawFd) -> io::Result<()> {
    loop {
        let rc = unsafe { libc::fsync(fd) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// Atomically installs executable bytes with exact `0755` permissions into `dirfd/target_name`:
/// `openat(O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, 0o755)` -> `fchmod(0o755)` ->
/// `write_all` -> `fsync(file)` -> `close` -> `renameat` -> `fsync(dirfd)`.
fn atomic_write_executable_0755(
    dirfd: RawFd,
    target_name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if target_name.is_empty()
        || target_name == "."
        || target_name == ".."
        || target_name.contains('/')
    {
        return Err(format!("invalid install filename '{target_name}'"));
    }
    let target_c = CString::new(target_name)
        .map_err(|_| "install filename contains NUL byte".to_string())?;

    let mut file_fd: Option<OwnedFd> = None;
    let mut tmp_c: Option<CString> = None;

    for _ in 0..16 {
        let mut rnd = [0u8; 4];
        fill_random(&mut rnd).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let tmp_name = format!(".{target_name}.tmp.{}", encode_hex(&rnd));
        let candidate_c = CString::new(tmp_name.as_str())
            .map_err(|_| "temp filename contains NUL byte".to_string())?;
        let raw_fd = unsafe {
            libc::openat(
                dirfd,
                candidate_c.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o755 as libc::c_uint,
            )
        };
        if raw_fd >= 0 {
            file_fd = Some(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            tmp_c = Some(candidate_c);
            break;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::AlreadyExists {
            continue;
        }
        return Err(format!("openat temp binary failed: {err}"));
    }

    let (Some(fd), Some(tmp_c)) = (file_fd, tmp_c) else {
        return Err("failed to allocate unique temp filename in install directory".to_string());
    };

    let write_res = (|| -> io::Result<()> {
        if unsafe { libc::fchmod(fd.as_raw_fd(), 0o755) } != 0 {
            return Err(io::Error::last_os_error());
        }
        write_all_fd(fd.as_raw_fd(), bytes)?;
        fsync_fd(fd.as_raw_fd())?;
        Ok(())
    })();

    drop(fd);

    if let Err(err) = write_res {
        unsafe {
            let _ = libc::unlinkat(dirfd, tmp_c.as_ptr(), 0);
        }
        return Err(format!("failed writing staged binary: {err}"));
    }

    let rc = unsafe { libc::renameat(dirfd, tmp_c.as_ptr(), dirfd, target_c.as_ptr()) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            let _ = libc::unlinkat(dirfd, tmp_c.as_ptr(), 0);
        }
        return Err(format!("atomic renameat failed: {err}"));
    }

    fsync_fd(dirfd).map_err(|e| format!("fsync install directory failed: {e}"))?;
    Ok(())
}

async fn best_effort_drain_local_daemons(opts: &GlobalOpts) {
    let Ok(state_dir) = resolve_effective_state_dir(opts.state_dir.as_deref()) else {
        return;
    };
    let runtime_override = resolve_effective_runtime_override(opts.runtime_dir.as_deref());
    let device_ids = match opts.device_id {
        Some(id) => vec![id],
        None => list_enrolled_device_ids(&state_dir),
    };

    for device_id in device_ids {
        let Ok(rt_path) = resolve_runtime_dir(device_id, runtime_override.as_deref()) else {
            continue;
        };
        let sock_path = rt_path.join(SOCKET_FILE_NAME);
        if !sock_path.exists() {
            continue;
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            send_graceful_drain(&sock_path, device_id),
        )
        .await;
    }
}

async fn send_graceful_drain(sock_path: &Path, device_id: u64) -> Result<(), ()> {
    let mut stream = UnixStream::connect(sock_path).await.map_err(|_| ())?;
    verify_peer_same_uid(stream.as_raw_fd()).map_err(|_| ())?;

    let hello = HelloPayload {
        ipc_schema_ver: IPC_SCHEMA_VER,
        build_order: build_order(),
        build_digest: build_digest(),
        client_kind: ClientKind::Cli,
        client_pid: std::process::id(),
    };
    write_ipc_frame(
        &mut stream,
        &IpcFrame {
            opcode: IpcOpcode::Hello,
            request_id: 1,
            payload: encode_hello(&hello),
        },
    )
    .await
    .map_err(|_| ())?;

    let Some(ack_frame) = read_ipc_frame(&mut stream).await.map_err(|_| ())? else {
        return Err(());
    };
    if ack_frame.opcode != IpcOpcode::HelloAck {
        return Err(());
    }
    let ack = decode_hello_ack(&ack_frame.payload).map_err(|_| ())?;
    if ack.device_id != device_id {
        return Err(());
    }
    write_ipc_frame(
        &mut stream,
        &IpcFrame {
            opcode: IpcOpcode::DrainAndShutdown,
            request_id: 2,
            payload: encode_drain_payload(DrainMode::RestartKeepParty),
        },
    )
    .await
    .map_err(|_| ())?;
    let _ = read_ipc_frame(&mut stream).await;
    Ok(())
}

/// Runs `mp-outpost upgrade [--check] [--yes|-y] [--version <vX.Y.Z|latest>] [--base-url <url>] [--install-path <path>]`.
pub async fn run_upgrade(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let parsed = parse_upgrade_args(args)?;
    let env_guard = std::env::var(SELF_UPGRADE_DISABLE_ENV).ok();
    let self_upgrade_disabled = enforce_self_upgrade_policy(parsed.check, env_guard.as_deref())?;
    let target = current_target_slug()?;

    let base_url = match parsed.base_url {
        Some(u) => u,
        None if parsed.version == "latest" => DEFAULT_RELEASE_LATEST_BASE.to_string(),
        None => format!("{DEFAULT_RELEASE_TAG_BASE_PREFIX}/{}", parsed.version),
    };

    let manifest_bytes =
        fetch_asset_bytes(&base_url, "release-manifest.json", MAX_MANIFEST_BYTES).await?;
    let sums_bytes = fetch_asset_bytes(&base_url, "SHA256SUMS.txt", MAX_SUMS_BYTES).await?;

    let requested_ver = if parsed.explicit_version {
        Some(parsed.version.as_str())
    } else {
        None
    };
    let (latest_version, asset) =
        parse_and_cross_verify_manifest(&manifest_bytes, &sums_bytes, target, requested_ver)?;

    let current_sv = parse_semver(PKG_VERSION)?;
    let latest_sv = parse_semver(&latest_version)?;
    let update_available = latest_sv > current_sv;

    if parsed.check {
        if opts.json {
            let out = json!({
                "current_version": format!("v{PKG_VERSION}"),
                "latest_version": latest_version,
                "update_available": update_available,
                "self_upgrade_disabled": self_upgrade_disabled,
                "target": target,
                "asset": asset.filename,
                "sha256": asset.sha256,
                "size_bytes": asset.size_bytes,
            });
            println!("{out}");
        } else if update_available {
            println!(
                "Update available: v{PKG_VERSION} -> {latest_version} ({target}, {}, sha256:{})",
                asset.filename, asset.sha256
            );
        } else {
            println!(
                "mp-outpost is up to date (current: v{PKG_VERSION}, latest: {latest_version}, target: {target})"
            );
        }
        return Ok(());
    }

    if !parsed.explicit_version && !update_available {
        if opts.json {
            let out = json!({
                "status": "up_to_date",
                "current_version": format!("v{PKG_VERSION}"),
                "latest_version": latest_version,
                "target": target,
            });
            println!("{out}");
        } else {
            println!(
                "mp-outpost v{PKG_VERSION} is already up to date (latest: {latest_version})."
            );
        }
        return Ok(());
    }

    if !parsed.yes {
        confirm_upgrade_tty(PKG_VERSION, &latest_version, target, &asset.sha256)?;
    }

    let tarball_bytes = fetch_asset_bytes(&base_url, &asset.filename, MAX_TARBALL_BYTES).await?;
    if tarball_bytes.len() as u64 != asset.size_bytes {
        return Err(format!(
            "downloaded size mismatch for '{}' (expected {} bytes, got {})",
            asset.filename,
            asset.size_bytes,
            tarball_bytes.len()
        ));
    }

    let actual_sha = encode_hex(&sha256(&tarball_bytes));
    if actual_sha != asset.sha256 {
        return Err(format!(
            "SHA-256 mismatch for '{}' (expected {}, got {actual_sha})",
            asset.filename, asset.sha256
        ));
    }

    let staging = StagingDir::create()?;
    let tarball_path = staging.path().join(&asset.filename);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tarball_path)
            .map_err(|e| format!("failed creating staged tarball: {e}"))?;
        let _ = fs::set_permissions(&tarball_path, fs::Permissions::from_mode(0o600));
        f.write_all(&tarball_bytes)
            .map_err(|e| format!("failed writing staged tarball: {e}"))?;
    }

    // 1. Audit archive entries BEFORE extraction.
    let list_out = Command::new("tar")
        .arg("-tzf")
        .arg(&tarball_path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed running 'tar -tzf': {e}"))?;
    if !list_out.status.success() {
        let stderr = String::from_utf8_lossy(&list_out.stderr);
        return Err(format!("tar listing failed: {}", stderr.trim()));
    }
    let listing = core::str::from_utf8(&list_out.stdout)
        .map_err(|_| "tar archive listing was not valid UTF-8".to_string())?;
    let bin_rel_path = validate_tar_entries(listing)?;

    // 2. Extract into private `0700` subdirectory without preserving owner/permissions.
    let extract_dir = staging.path().join("extract");
    fs::create_dir(&extract_dir).map_err(|e| format!("failed creating extract dir: {e}"))?;
    fs::set_permissions(&extract_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("failed setting extract dir mode 0700: {e}"))?;

    let extract_out = Command::new("tar")
        .arg("-xzf")
        .arg(&tarball_path)
        .arg("-C")
        .arg(&extract_dir)
        .arg("--no-same-owner")
        .arg("--no-same-permissions")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed running 'tar -xzf': {e}"))?;
    if !extract_out.status.success() {
        let stderr = String::from_utf8_lossy(&extract_out.stderr);
        return Err(format!("tar extraction failed: {}", stderr.trim()));
    }

    // 3. Walk extracted tree with lstat rejecting ANY symlink/FIFO/device/non-regular file.
    audit_extracted_tree_no_symlinks(&extract_dir, 0)?;

    let extracted_bin = extract_dir.join(&bin_rel_path);
    let bin_meta = fs::symlink_metadata(&extracted_bin)
        .map_err(|e| format!("extracted binary missing at '{}': {e}", extracted_bin.display()))?;
    if !bin_meta.file_type().is_file() || bin_meta.len() == 0 {
        return Err("extracted mp-outpost binary is not a non-empty regular file".to_string());
    }
    fs::set_permissions(&extracted_bin, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("failed chmod 0755 on extracted binary: {e}"))?;

    // 4. Offline smoke check: `<extracted> --version` must exit 0 and begin with "mp-outpost ".
    let smoke_out = Command::new(&extracted_bin)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed executing smoke test on upgraded binary: {e}"))?;
    if !smoke_out.status.success() {
        return Err(format!(
            "upgraded binary failed offline '--version' smoke check (exit {:?})",
            smoke_out.status.code()
        ));
    }
    let smoke_stdout = core::str::from_utf8(&smoke_out.stdout)
        .map_err(|_| "upgraded binary '--version' output was not valid UTF-8".to_string())?;
    if !smoke_stdout.starts_with("mp-outpost ") {
        return Err(format!(
            "upgraded binary '--version' output failed verification: '{}'",
            smoke_stdout.trim()
        ));
    }

    // 5. Read verified binary bytes and atomically swap into install_path with 0755.
    let bin_bytes = read_regular_file_bounded_nofollow(&extracted_bin, MAX_TARBALL_BYTES)
        .map_err(|e| format!("failed reading verified binary: {e}"))?;

    let using_custom_install = parsed.install_path.is_some();
    let install_path = match parsed.install_path {
        Some(p) => p,
        None => std::env::current_exe()
            .map_err(|e| format!("failed to locate current executable path: {e}"))?,
    };
    let target_name = install_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid install path '{}'", install_path.display()))?;
    let parent_dir = match install_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir_fd = open_dir_nofollow(parent_dir).map_err(|e| {
        format!(
            "failed to open install directory '{}': {e}",
            parent_dir.display()
        )
    })?;
    atomic_write_executable_0755(dir_fd.as_raw_fd(), target_name, &bin_bytes)?;

    // 6. Best-effort graceful drain of running local daemon(s) after default in-place upgrade.
    if !using_custom_install {
        best_effort_drain_local_daemons(opts).await;
    }

    if opts.json {
        let out = json!({
            "status": "upgraded",
            "previous_version": format!("v{PKG_VERSION}"),
            "version": latest_version,
            "target": target,
            "sha256": actual_sha,
            "install_path": install_path.display().to_string(),
            "smoke_version": smoke_stdout.trim(),
        });
        println!("{out}");
    } else {
        println!(
            "Upgraded mp-outpost to {latest_version} ({target}, sha256:{actual_sha}) at {}",
            install_path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parsing_and_ordering() -> Result<(), String> {
        let v030 = parse_semver("0.3.0")?;
        let v030_v = parse_semver("v0.3.0")?;
        assert_eq!(v030, v030_v);

        let v030_rc1 = parse_semver("v0.3.0-rc.1")?;
        let v030_rc2 = parse_semver("v0.3.0-rc.2")?;
        let v031 = parse_semver("v0.3.1")?;
        let v100 = parse_semver("v1.0.0")?;

        assert!(v030_rc1 < v030_rc2);
        assert!(v030_rc2 < v030);
        assert!(v030 < v031);
        assert!(v031 < v100);

        assert!(parse_semver("").is_err());
        assert!(parse_semver("0.3").is_err());
        assert!(parse_semver("0.3.0.1").is_err());
        assert!(parse_semver("0.3.x").is_err());
        assert!(parse_semver("v0.3.0-").is_err());
        Ok(())
    }

    #[test]
    fn validate_tar_entries_accepts_clean_and_rejects_hostile() -> Result<(), String> {
        let ok = "mp-outpost-v0.3.0-darwin-arm64/\nmp-outpost-v0.3.0-darwin-arm64/mp-outpost\nmp-outpost-v0.3.0-darwin-arm64/README.md\n";
        assert_eq!(
            validate_tar_entries(ok)?,
            "mp-outpost-v0.3.0-darwin-arm64/mp-outpost"
        );

        let flat_ok = "mp-outpost\nREADME.md\n";
        assert_eq!(validate_tar_entries(flat_ok)?, "mp-outpost");

        assert!(validate_tar_entries("").is_err());
        assert!(validate_tar_entries("../evil\nmp-outpost\n").is_err());
        assert!(validate_tar_entries("/etc/passwd\nmp-outpost\n").is_err());
        assert!(validate_tar_entries("a/../b\nmp-outpost\n").is_err());
        assert!(validate_tar_entries("dir/a\ndir/b\n").is_err());
        assert!(validate_tar_entries("a/mp-outpost\nb/mp-outpost\n").is_err());
        assert!(validate_tar_entries("dir\\mp-outpost\n").is_err());

        // > MAX_TAR_ENTRIES rejected
        let mut too_many = String::from("mp-outpost\n");
        for n in 0..MAX_TAR_ENTRIES {
            too_many.push_str(&format!("file-{n}.txt\n"));
        }
        assert!(validate_tar_entries(&too_many).is_err());
        Ok(())
    }

    #[test]
    fn sha256sums_parsing_and_dual_verification_mismatch() -> Result<(), String> {
        let sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let filename = "mp-outpost-v9.9.9-darwin-arm64.tar.gz";

        let sums_ok = format!("{sha_a}  {filename}\n");
        let parsed = parse_sha256sums(&sums_ok)?;
        assert_eq!(parsed.get(filename).map(String::as_str), Some(sha_a));

        let manifest = format!(
            r#"{{"version":"v9.9.9","commit":"abc123","assets":[{{"target":"darwin-arm64","filename":"{filename}","sha256":"{sha_a}","size_bytes":1024}}]}}"#
        );
        let (ver, asset) = parse_and_cross_verify_manifest(
            manifest.as_bytes(),
            sums_ok.as_bytes(),
            "darwin-arm64",
            None,
        )?;
        assert_eq!(ver, "v9.9.9");
        assert_eq!(asset.sha256, sha_a);

        // Mismatch between manifest and SHA256SUMS.txt MUST fail closed!
        let sums_bad = format!("{sha_b}  {filename}\n");
        let err = parse_and_cross_verify_manifest(
            manifest.as_bytes(),
            sums_bad.as_bytes(),
            "darwin-arm64",
            None,
        )
        .err()
        .unwrap_or_default();
        assert!(
            err.contains("SHA-256 mismatch between release-manifest.json and SHA256SUMS.txt")
                || err.contains("SHA-256 mismatch"),
            "unexpected error: {err}"
        );

        // Malformed sums rejected
        assert!(parse_sha256sums("not-a-hash  file.tar.gz\n").is_err());
        assert!(parse_sha256sums("").is_err());
        Ok(())
    }

    #[test]
    fn self_upgrade_guard_enforces_packaged_and_env_while_allowing_check() -> Result<(), String> {
        // Read-only `--check` MUST remain allowed even when OUTPOST_NO_SELF_UPGRADE=1 or --features packaged
        assert!(enforce_self_upgrade_policy(true, Some("1"))?);
        assert!(enforce_self_upgrade_policy(true, Some("true"))?);
        assert!(enforce_self_upgrade_policy(true, Some("YES"))?);

        // Mutating self-upgrade MUST be refused when env is truthy
        let err_env = enforce_self_upgrade_policy(false, Some("1"))
            .err()
            .unwrap_or_default();
        assert!(
            err_env.contains("brew upgrade mp-outpost") && err_env.contains("upgrade --check"),
            "unexpected guard error: {err_env}"
        );
        assert!(enforce_self_upgrade_policy(false, Some("true")).is_err());
        assert!(enforce_self_upgrade_policy(false, Some("yes")).is_err());
        assert!(enforce_self_upgrade_policy(false, Some("on")).is_err());

        #[cfg(feature = "packaged")]
        {
            assert!(enforce_self_upgrade_policy(true, None)?);
            let err_pkg = enforce_self_upgrade_policy(false, None)
                .err()
                .unwrap_or_default();
            assert!(
                err_pkg.contains("packaged") && err_pkg.contains("brew upgrade mp-outpost"),
                "unexpected packaged error: {err_pkg}"
            );
        }

        #[cfg(not(feature = "packaged"))]
        {
            assert!(!enforce_self_upgrade_policy(false, None)?);
            assert!(!enforce_self_upgrade_policy(false, Some("0"))?);
            assert!(!enforce_self_upgrade_policy(false, Some("false"))?);
            assert!(!enforce_self_upgrade_policy(false, Some(""))?);
        }

        Ok(())
    }

    #[tokio::test]
    async fn file_url_upgrade_check_tamper_and_atomic_install() -> Result<(), String> {
        let target = current_target_slug()?;
        let release_dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let pkg_stage = tempfile::tempdir().map_err(|e| format!("stage tempdir: {e}"))?;

        let version = "v9.9.9";
        let stem = format!("mp-outpost-{version}-{target}");
        let pkg_sub = pkg_stage.path().join(&stem);
        fs::create_dir(&pkg_sub).map_err(|e| format!("mkdir: {e}"))?;

        // Build a valid stub executable that prints "mp-outpost 9.9.9".
        let stub_bin = pkg_sub.join("mp-outpost");
        fs::write(&stub_bin, "#!/bin/sh\necho \"mp-outpost 9.9.9 (test-upgrade)\"\n")
            .map_err(|e| format!("write stub: {e}"))?;
        fs::set_permissions(&stub_bin, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod stub: {e}"))?;

        let tarball_name = format!("{stem}.tar.gz");
        let tarball_path = release_dir.path().join(&tarball_name);
        let tar_status = Command::new("tar")
            .arg("-C")
            .arg(pkg_stage.path())
            .arg("-czf")
            .arg(&tarball_path)
            .arg(&stem)
            .status()
            .map_err(|e| format!("tar create: {e}"))?;
        assert!(tar_status.success(), "tar create failed");

        let tb_bytes = fs::read(&tarball_path).map_err(|e| format!("read tarball: {e}"))?;
        let tb_sha = encode_hex(&sha256(&tb_bytes));
        let tb_size = tb_bytes.len() as u64;

        fs::write(
            release_dir.path().join("SHA256SUMS.txt"),
            format!("{tb_sha}  {tarball_name}\n"),
        )
        .map_err(|e| format!("write sums: {e}"))?;

        let manifest = json!({
            "version": version,
            "commit": "deadbeef1234",
            "assets": [{
                "target": target,
                "filename": tarball_name,
                "sha256": tb_sha,
                "size_bytes": tb_size,
            }]
        });
        fs::write(
            release_dir.path().join("release-manifest.json"),
            manifest.to_string(),
        )
        .map_err(|e| format!("write manifest: {e}"))?;

        let base_url = format!("file://{}", release_dir.path().display());
        let opts = GlobalOpts {
            json: true,
            ..GlobalOpts::default()
        };

        // 1. `--check` succeeds without installing anything.
        run_upgrade(
            &opts,
            &[
                "--check".to_string(),
                "--base-url".to_string(),
                base_url.clone(),
            ],
        )
        .await?;

        // 2. Under `--features packaged`, mutating `--yes` MUST be refused while `--check` succeeded above.
        #[cfg(feature = "packaged")]
        {
            let err = run_upgrade(
                &opts,
                &[
                    "--yes".to_string(),
                    "--base-url".to_string(),
                    base_url,
                ],
            )
            .await
            .err()
            .unwrap_or_default();
            assert!(
                err.contains("packaged") && err.contains("brew upgrade mp-outpost"),
                "expected packaged guard error, got: {err}"
            );
            return Ok(());
        }

        // 2. Full atomic install into a temp `--install-path` succeeds with 0755 and passes smoke test.
        #[cfg(not(feature = "packaged"))]
        {
        let install_dir = tempfile::tempdir().map_err(|e| format!("install dir: {e}"))?;
        let install_path = install_dir.path().join("mp-outpost");
        fs::write(&install_path, b"old-binary").map_err(|e| format!("seed old: {e}"))?;

        run_upgrade(
            &opts,
            &[
                "--yes".to_string(),
                "--base-url".to_string(),
                base_url.clone(),
                "--install-path".to_string(),
                install_path.display().to_string(),
            ],
        )
        .await?;

        let meta = fs::metadata(&install_path).map_err(|e| format!("meta: {e}"))?;
        assert_eq!(meta.permissions().mode() & 0o777, 0o755);
        let ver_out = Command::new(&install_path)
            .arg("--version")
            .output()
            .map_err(|e| format!("run installed: {e}"))?;
        assert!(ver_out.status.success());
        assert!(String::from_utf8_lossy(&ver_out.stdout).starts_with("mp-outpost 9.9.9"));

        // 3. Tampered tarball MUST be rejected without modifying the installed binary.
        let mut tampered = tb_bytes.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xff;
        }
        fs::write(&tarball_path, &tampered).map_err(|e| format!("write tamper: {e}"))?;
        let err = run_upgrade(
            &opts,
            &[
                "--yes".to_string(),
                "--base-url".to_string(),
                base_url,
                "--install-path".to_string(),
                install_path.display().to_string(),
            ],
        )
        .await
        .err()
        .unwrap_or_default();
        assert!(
            err.contains("SHA-256 mismatch"),
            "expected SHA-256 tamper rejection, got: {err}"
        );

        Ok(())
        }
    }
}
