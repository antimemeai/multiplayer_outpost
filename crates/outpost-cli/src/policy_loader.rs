//! Verified filesystem loader for unified `/etc/multiplayer/policy.toml` (with backward-compatible
//! legacy `lan.toml` fallback) and `mp-outpost policy status [--json]` CLI handler.
//!
//! Security invariants:
//! - System policy parent `/etc/multiplayer` is verified with `O_DIRECTORY | O_NOFOLLOW`,
//!   `st_uid == 0`, `(st_mode & 0o022) == 0`; leaf files are opened via
//!   `openat(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)` and verified as `S_IFREG`,
//!   `st_uid == 0`, `(st_mode & 0o022) == 0`, `<= 16 KiB`.
//! - User policy parent `$XDG_CONFIG_HOME/mp-outpost` (or `$HOME/.config/mp-outpost`) and leaf
//!   files (`policy.toml` / `lan.toml`) undergo the same `O_NOFOLLOW` / `S_IFREG` / `st_uid == euid`
//!   / `(st_mode & 0o022) == 0` / `<= 16 KiB` checks.
//! - Any tampering, symlink, wrong ownership, permissive mode, oversized file, invalid UTF-8, or
//!   corrupt TOML fails CLOSED.
//! - Environment kill-switches (`MP_DISABLE_LAN` / `BLACKBIRD_DISABLE_LAN`) and brakes overrides
//!   (`MP_BRAKES` / `BLACKBIRD_BRAKES`) are read via `std::env::var_os` and fail closed on
//!   non-UTF-8 or invalid values.

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use outpost_core::lan_protocol::{
    MAX_LAN_POLICY_FILE_BYTES, PartialLanPolicy, parse_partial_lan_policy_toml,
};
use outpost_core::policy::{
    BrakesProfile, EffectiveUnifiedPolicy, MAX_UNIFIED_POLICY_FILE_BYTES, UnifiedPolicyFile,
    merge_unified_policy_floor, parse_unified_policy_toml,
};
use serde_json::json;

use crate::cli::GlobalOpts;

pub const SYSTEM_POLICY_DIR: &str = "/etc/multiplayer";
pub const POLICY_FILE_NAME: &str = "policy.toml";
pub const LEGACY_LAN_FILE_NAME: &str = "lan.toml";

/// Result of loading and monotonically merging system, user, and environment policy layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedUnifiedPolicy {
    pub effective: EffectiveUnifiedPolicy,
    pub system_policy_loaded: bool,
    pub legacy_system_lan_loaded: bool,
    pub user_policy_loaded: bool,
    pub legacy_user_lan_loaded: bool,
}

/// Explicit filesystem/environment source specification for deterministic testing.
#[derive(Debug, Clone)]
pub struct PolicyLoadSources {
    pub system_dir: PathBuf,
    pub user_dir: Option<PathBuf>,
    pub expected_system_uid: u32,
    pub expected_user_uid: Option<u32>,
}

impl Default for PolicyLoadSources {
    fn default() -> Self {
        Self {
            system_dir: PathBuf::from(SYSTEM_POLICY_DIR),
            user_dir: None,
            expected_system_uid: 0,
            expected_user_uid: None,
        }
    }
}

fn process_env_os_lookup(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

fn default_user_policy_dir(lookup: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    if let Some(xdg) = lookup("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Some(PathBuf::from(xdg).join("mp-outpost"));
    }
    if let Some(home) = lookup("HOME")
        && !home.is_empty()
    {
        return Some(PathBuf::from(home).join(".config").join("mp-outpost"));
    }
    None
}

/// Checks a LAN kill-switch env var via `var_os`.
/// Non-UTF-8 values fail closed (treated as `true` = LAN disabled) so an attacker or
/// misconfiguration can never bypass the kill-switch with non-UTF-8 bytes.
fn env_lan_kill_switch_active(
    lookup: &dyn Fn(&str) -> Option<OsString>,
    var_name: &str,
) -> Result<bool, String> {
    let Some(raw) = lookup(var_name) else {
        return Ok(false);
    };
    if raw.is_empty() {
        return Ok(false);
    }
    let Some(text) = raw.to_str() else {
        return Err(format!(
            "environment variable {var_name} contains non-UTF-8 bytes (fail closed)"
        ));
    };
    let lower = text.trim_matches([' ', '\t']).to_ascii_lowercase();
    Ok(!(lower.is_empty() || lower == "0" || lower == "false" || lower == "no"))
}

/// Parses an optional brakes profile override (`MP_BRAKES` / `BLACKBIRD_BRAKES`).
/// Fails closed on non-UTF-8 or unrecognized profile names.
fn parse_env_brakes_var(
    lookup: &dyn Fn(&str) -> Option<OsString>,
    var_name: &str,
) -> Result<Option<BrakesProfile>, String> {
    let Some(raw) = lookup(var_name) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    let Some(text) = raw.to_str() else {
        return Err(format!(
            "environment variable {var_name} contains non-UTF-8 bytes (fail closed)"
        ));
    };
    let trimmed = text.trim_matches([' ', '\t']).to_ascii_lowercase();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let profile = BrakesProfile::parse(&trimmed).ok_or_else(|| {
        format!(
            "invalid {var_name} value '{trimmed}' (expected black-flag|guarded|sandboxed|airgap)"
        )
    })?;
    Ok(Some(profile))
}

fn parse_env_brakes_override(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Option<BrakesProfile>, String> {
    let mp = parse_env_brakes_var(lookup, "MP_BRAKES")?;
    let bb = parse_env_brakes_var(lookup, "BLACKBIRD_BRAKES")?;
    Ok(match (mp, bb) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    })
}

/// Opens a policy directory with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and verifies
/// ownership (`st_uid == expected_uid`) and mode (`(st_mode & 0o022) == 0`).
/// Returns `Ok(None)` only when the directory does not exist (`ENOENT`); all symlinks, wrong
/// owners, group/world-writable modes, or other errors fail closed.
fn open_verified_policy_dir(
    dir_path: &Path,
    expected_uid: u32,
) -> Result<Option<OwnedFd>, String> {
    let raw_bytes = dir_path.as_os_str().as_bytes();
    if raw_bytes.is_empty() {
        return Err("policy directory path must not be empty".to_string());
    }
    let mut trimmed = raw_bytes;
    while trimmed.len() > 1 && trimmed.ends_with(b"/") {
        if let Some(prefix) = trimmed.strip_suffix(b"/") {
            trimmed = prefix;
        } else {
            break;
        }
    }
    let cpath = CString::new(trimmed)
        .map_err(|_| format!("policy directory '{}' contains NUL byte", dir_path.display()))?;

    let raw_fd = loop {
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            let raw_errno = err.raw_os_error();
            if raw_errno == Some(libc::ELOOP) {
                return Err(format!(
                    "refusing symlinked policy directory '{}' (fail closed)",
                    dir_path.display()
                ));
            }
            if raw_errno == Some(libc::ENOTDIR) {
                let mut lst: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::lstat(cpath.as_ptr(), &mut lst) } == 0
                    && (lst.st_mode & libc::S_IFMT) == libc::S_IFLNK
                {
                    return Err(format!(
                        "refusing symlinked policy directory '{}' (fail closed)",
                        dir_path.display()
                    ));
                }
            }
            return Err(format!(
                "failed to open policy directory '{}': {err}",
                dir_path.display()
            ));
        }
        break fd;
    };
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(format!(
            "failed to fstat policy directory '{}': {}",
            dir_path.display(),
            io::Error::last_os_error()
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(format!(
            "refusing non-directory policy path '{}' (fail closed)",
            dir_path.display()
        ));
    }
    if st.st_uid != expected_uid {
        return Err(format!(
            "refusing policy directory '{}': expected owner uid={expected_uid}, got uid={} (fail closed)",
            dir_path.display(),
            st.st_uid
        ));
    }
    if (st.st_mode & 0o022) != 0 {
        return Err(format!(
            "refusing group/world-writable policy directory '{}' (mode {:04o}, fail closed)",
            dir_path.display(),
            st.st_mode & 0o7777
        ));
    }

    Ok(Some(fd))
}

/// Opens a regular leaf file inside an already-verified parent directory fd via
/// `openat(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)` and verifies `S_IFREG`,
/// `st_uid == expected_uid`, `(st_mode & 0o022) == 0`, and `<= max_bytes`.
fn read_verified_policy_leaf(
    parent_fd: &OwnedFd,
    parent_display: &Path,
    leaf_name: &str,
    expected_uid: u32,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    let full_path = parent_display.join(leaf_name);
    let cleaf = CString::new(leaf_name.as_bytes())
        .map_err(|_| format!("policy filename '{leaf_name}' contains NUL byte"))?;

    let raw_fd = loop {
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                cleaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(format!(
                    "refusing symlinked policy file '{}' (fail closed)",
                    full_path.display()
                ));
            }
            return Err(format!(
                "failed to open policy file '{}': {err}",
                full_path.display()
            ));
        }
        break fd;
    };
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(format!(
            "failed to fstat policy file '{}': {}",
            full_path.display(),
            io::Error::last_os_error()
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "refusing non-regular policy file '{}' (fail closed)",
            full_path.display()
        ));
    }
    if st.st_uid != expected_uid {
        return Err(format!(
            "refusing policy file '{}': expected owner uid={expected_uid}, got uid={} (fail closed)",
            full_path.display(),
            st.st_uid
        ));
    }
    if (st.st_mode & 0o022) != 0 {
        return Err(format!(
            "refusing group/world-writable policy file '{}' (mode {:04o}, fail closed)",
            full_path.display(),
            st.st_mode & 0o7777
        ));
    }
    if st.st_size < 0 || (st.st_size as u64) > (max_bytes as u64) {
        return Err(format!(
            "policy file '{}' exceeds max {max_bytes} bytes (fail closed)",
            full_path.display()
        ));
    }

    let file = File::from(fd);
    let mut raw = Vec::new();
    let limit = (max_bytes as u64).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut raw)
        .map_err(|e| format!("failed reading policy file '{}': {e}", full_path.display()))?;
    if raw.len() > max_bytes {
        return Err(format!(
            "policy file '{}' grew beyond max {max_bytes} bytes (fail closed)",
            full_path.display()
        ));
    }
    let text = String::from_utf8(raw)
        .map_err(|_| format!("policy file '{}' is not valid UTF-8 (fail closed)", full_path.display()))?;
    Ok(Some(text))
}

/// Loads and merges policy from explicit sources and an injected environment lookup function.
pub fn load_effective_unified_policy_from(
    sources: &PolicyLoadSources,
    env_lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<LoadedUnifiedPolicy, String> {
    // 1. System layer (`/etc/multiplayer/policy.toml` + legacy `/etc/multiplayer/lan.toml`)
    let mut system_policy: Option<UnifiedPolicyFile> = None;
    let mut legacy_system_lan: Option<PartialLanPolicy> = None;
    if !sources.system_dir.as_os_str().is_empty()
        && let Some(sys_dir_fd) =
            open_verified_policy_dir(&sources.system_dir, sources.expected_system_uid)?
    {
        if let Some(text) = read_verified_policy_leaf(
            &sys_dir_fd,
            &sources.system_dir,
            POLICY_FILE_NAME,
            sources.expected_system_uid,
            MAX_UNIFIED_POLICY_FILE_BYTES,
        )? {
            let parsed = parse_unified_policy_toml(&text).map_err(|e| {
                format!(
                    "malformed system policy '{}' (fail closed): {e}",
                    sources.system_dir.join(POLICY_FILE_NAME).display()
                )
            })?;
            system_policy = Some(parsed);
        }
        if let Some(text) = read_verified_policy_leaf(
            &sys_dir_fd,
            &sources.system_dir,
            LEGACY_LAN_FILE_NAME,
            sources.expected_system_uid,
            MAX_LAN_POLICY_FILE_BYTES,
        )? {
            let parsed = parse_partial_lan_policy_toml(&text).map_err(|e| {
                format!(
                    "malformed legacy system LAN policy '{}' (fail closed): {e}",
                    sources.system_dir.join(LEGACY_LAN_FILE_NAME).display()
                )
            })?;
            legacy_system_lan = Some(parsed);
        }
    }

    // 2. User layer (`$XDG_CONFIG_HOME/mp-outpost/` or `$HOME/.config/mp-outpost/`)
    let resolved_user_dir = sources
        .user_dir
        .clone()
        .or_else(|| default_user_policy_dir(env_lookup));
    let mut user_policy: Option<UnifiedPolicyFile> = None;
    let mut legacy_user_lan: Option<PartialLanPolicy> = None;
    if let Some(ref udir) = resolved_user_dir
        && !udir.as_os_str().is_empty()
    {
        let expected_uid = sources
            .expected_user_uid
            .unwrap_or_else(|| unsafe { libc::geteuid() });
        if let Some(usr_dir_fd) = open_verified_policy_dir(udir, expected_uid)? {
            if let Some(text) = read_verified_policy_leaf(
                &usr_dir_fd,
                udir,
                POLICY_FILE_NAME,
                expected_uid,
                MAX_UNIFIED_POLICY_FILE_BYTES,
            )? {
                let parsed = parse_unified_policy_toml(&text).map_err(|e| {
                    format!(
                        "malformed user policy '{}' (fail closed): {e}",
                        udir.join(POLICY_FILE_NAME).display()
                    )
                })?;
                user_policy = Some(parsed);
            }
            if let Some(text) = read_verified_policy_leaf(
                &usr_dir_fd,
                udir,
                LEGACY_LAN_FILE_NAME,
                expected_uid,
                MAX_LAN_POLICY_FILE_BYTES,
            )? {
                let parsed = parse_partial_lan_policy_toml(&text).map_err(|e| {
                    format!(
                        "malformed legacy user LAN policy '{}' (fail closed): {e}",
                        udir.join(LEGACY_LAN_FILE_NAME).display()
                    )
                })?;
                legacy_user_lan = Some(parsed);
            }
        }
    }

    // 3. Environment overrides (`std::env::var_os`, failing closed on non-UTF-8/invalid values)
    let env_lan_disabled = env_lan_kill_switch_active(env_lookup, "MP_DISABLE_LAN")?
        || env_lan_kill_switch_active(env_lookup, "BLACKBIRD_DISABLE_LAN")?;
    let env_brakes_override = parse_env_brakes_override(env_lookup)?;

    // 4. Monotonic floor merge
    let effective = merge_unified_policy_floor(
        system_policy.as_ref(),
        legacy_system_lan.as_ref(),
        user_policy.as_ref(),
        legacy_user_lan.as_ref(),
        env_lan_disabled,
        env_brakes_override,
    )
    .map_err(|e| format!("unified policy merge rejected (fail closed): {e}"))?;

    Ok(LoadedUnifiedPolicy {
        effective,
        system_policy_loaded: system_policy.is_some(),
        legacy_system_lan_loaded: legacy_system_lan.is_some(),
        user_policy_loaded: user_policy.is_some(),
        legacy_user_lan_loaded: legacy_user_lan.is_some(),
    })
}

/// Loads and monotonically merges `/etc/multiplayer/{policy,lan}.toml`, user
/// `{policy,lan}.toml`, and environment overrides (`MP_DISABLE_LAN` / `BLACKBIRD_DISABLE_LAN`,
/// `MP_BRAKES` / `BLACKBIRD_BRAKES`).
pub fn load_effective_unified_policy() -> Result<LoadedUnifiedPolicy, String> {
    load_effective_unified_policy_from(&PolicyLoadSources::default(), &process_env_os_lookup)
}

/// CLI entrypoint for `mp-outpost policy status [--json]`.
pub fn run_policy_cmd(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost policy status [--json]".to_string());
    };
    if sub != "status" {
        return Err(format!(
            "unknown policy subcommand '{sub}' (expected: status)"
        ));
    }

    let mut json_out = opts.json;
    for arg in args.get(1..).unwrap_or_default() {
        match arg.as_str() {
            "--json" => json_out = true,
            other => {
                return Err(format!(
                    "unknown argument to `policy status`: {other}"
                ));
            }
        }
    }

    let loaded = load_effective_unified_policy()?;
    let eff = &loaded.effective;

    if json_out {
        let payload = json!({
            "sources": {
                "system_policy_loaded": loaded.system_policy_loaded,
                "legacy_system_lan_loaded": loaded.legacy_system_lan_loaded,
                "user_policy_loaded": loaded.user_policy_loaded,
                "legacy_user_lan_loaded": loaded.legacy_user_lan_loaded,
            },
            "brakes": {
                "min_profile": eff.brakes.min_profile.as_str(),
                "default_profile": eff.brakes.default_profile.as_str(),
                "active_profile": eff.brakes.active_profile.as_str(),
                "allow_escalation": eff.brakes.allow_escalation,
                "require_local_auth_for_escalation": eff.brakes.require_local_auth_for_escalation,
                "extra_denied_paths": eff.brakes.extra_denied_paths,
                "fail_closed_on_missing_sandbox": eff.brakes.fail_closed_on_missing_sandbox,
            },
            "party_trust": {
                "max_default_profile": eff.party_trust.max_default_profile.as_str(),
                "max_peer_override": eff.party_trust.max_peer_override.as_str(),
                "max_external_guest_profile": eff.party_trust.max_external_guest_profile.as_str(),
                "max_turns_per_peer": eff.party_trust.max_turns_per_peer,
                "max_cost_usd_per_peer_micros": eff.party_trust.max_cost_usd_per_peer_micros,
                "max_cost_usd_per_peer": eff.party_trust.max_cost_usd_per_peer(),
            },
            "lan": {
                "disabled": eff.lan.config.disabled,
                "require_pin": eff.lan.config.require_pin,
                "require_local_auth": eff.lan.config.require_local_auth,
                "idle_timeout_sec": eff.lan.config.idle_timeout_sec,
                "scan_timeout_sec": eff.lan.config.scan_timeout_sec,
                "max_idle_timeout_sec": eff.lan.max_idle_timeout_sec,
                "max_scan_timeout_sec": eff.lan.max_scan_timeout_sec,
            },
            "online": {
                "disabled": eff.online.disabled,
                "require_force_relays": eff.online.require_force_relays,
                "allowed_authorities": eff.online.allowed_authorities,
                "allowed_org_slugs": eff.online.allowed_org_slugs,
                "allow_personal_parties": eff.online.allow_personal_parties,
            }
        });
        if let Ok(text) = serde_json::to_string_pretty(&payload) {
            println!("{text}");
        }
    } else {
        println!(
            "Unified Policy Status\n\
             Sources:\n  \
               system_policy (/etc/multiplayer/policy.toml): {}\n  \
               legacy_system_lan (/etc/multiplayer/lan.toml): {}\n  \
               user_policy: {}\n  \
               legacy_user_lan: {}\n\
             [brakes]\n  \
               active_profile: {}\n  \
               min_profile: {}\n  \
               default_profile: {}\n  \
               allow_escalation: {}\n  \
               require_local_auth_for_escalation: {}\n  \
               fail_closed_on_missing_sandbox: {}\n\
             [party_trust]\n  \
               max_default_profile: {}\n  \
               max_peer_override: {}\n  \
               max_external_guest_profile: {}\n  \
               max_turns_per_peer: {}\n  \
               max_cost_usd_per_peer: ${:.6}\n\
             [lan]\n  \
               disabled: {}\n  \
               require_pin: {}\n  \
               require_local_auth: {}\n  \
               idle_timeout_sec: {} (ceiling {})\n  \
               scan_timeout_sec: {} (ceiling {})\n\
             [online]\n  \
               disabled: {}\n  \
               require_force_relays: {}\n  \
               allow_personal_parties: {}",
            loaded.system_policy_loaded,
            loaded.legacy_system_lan_loaded,
            loaded.user_policy_loaded,
            loaded.legacy_user_lan_loaded,
            eff.brakes.active_profile.as_str(),
            eff.brakes.min_profile.as_str(),
            eff.brakes.default_profile.as_str(),
            eff.brakes.allow_escalation,
            eff.brakes.require_local_auth_for_escalation,
            eff.brakes.fail_closed_on_missing_sandbox,
            eff.party_trust.max_default_profile.as_str(),
            eff.party_trust.max_peer_override.as_str(),
            eff.party_trust.max_external_guest_profile.as_str(),
            eff.party_trust.max_turns_per_peer,
            eff.party_trust.max_cost_usd_per_peer(),
            eff.lan.config.disabled,
            eff.lan.config.require_pin,
            eff.lan.config.require_local_auth,
            eff.lan.config.idle_timeout_sec,
            eff.lan.max_idle_timeout_sec,
            eff.lan.config.scan_timeout_sec,
            eff.lan.max_scan_timeout_sec,
            eff.online.disabled,
            eff.online.require_force_relays,
            eff.online.allow_personal_parties,
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use outpost_core::policy::PartyTrustProfile;

    use super::*;

    fn empty_env(_: &str) -> Option<OsString> {
        None
    }

    #[test]
    fn merges_system_user_legacy_and_env_monotonically() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let uid = unsafe { libc::geteuid() };
        let sys_dir = tmp.path().join("sys");
        let usr_dir = tmp.path().join("usr");
        fs::create_dir(&sys_dir)?;
        fs::create_dir(&usr_dir)?;
        fs::set_permissions(&sys_dir, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&usr_dir, fs::Permissions::from_mode(0o755))?;

        let sys_policy_path = sys_dir.join("policy.toml");
        fs::write(
            &sys_policy_path,
            "[brakes]\nmin_profile = \"guarded\"\n\n[party_trust]\nmax_default_profile = \"advisory\"\n",
        )?;
        fs::set_permissions(&sys_policy_path, fs::Permissions::from_mode(0o644))?;

        let sys_lan_path = sys_dir.join("lan.toml");
        fs::write(&sys_lan_path, "[lan]\nrequire_pin = true\nidle_timeout_sec = 120\n")?;
        fs::set_permissions(&sys_lan_path, fs::Permissions::from_mode(0o644))?;

        let usr_policy_path = usr_dir.join("policy.toml");
        fs::write(
            &usr_policy_path,
            "[brakes]\nmin_profile = \"black-flag\"\ndefault_profile = \"sandboxed\"\n\n[party_trust]\nmax_default_profile = \"black-flag\"\n",
        )?;
        fs::set_permissions(&usr_policy_path, fs::Permissions::from_mode(0o644))?;

        let sources = PolicyLoadSources {
            system_dir: sys_dir,
            user_dir: Some(usr_dir),
            expected_system_uid: uid,
            expected_user_uid: Some(uid),
        };
        let loaded = load_effective_unified_policy_from(&sources, &empty_env)?;
        assert!(loaded.system_policy_loaded);
        assert!(loaded.legacy_system_lan_loaded);
        assert!(loaded.user_policy_loaded);
        assert!(!loaded.legacy_user_lan_loaded);
        assert_eq!(loaded.effective.brakes.min_profile, BrakesProfile::Guarded);
        assert_eq!(
            loaded.effective.brakes.active_profile,
            BrakesProfile::Sandboxed
        );
        assert_eq!(
            loaded.effective.party_trust.max_default_profile,
            PartyTrustProfile::Advisory
        );
        assert!(loaded.effective.lan.config.require_pin);
        assert_eq!(loaded.effective.lan.config.idle_timeout_sec, 120);

        // Non-UTF-8 MP_DISABLE_LAN MUST fail closed.
        let bad_env = |k: &str| {
            if k == "MP_DISABLE_LAN" {
                Some(OsString::from_vec(vec![0xff, 0xfe]))
            } else {
                None
            }
        };
        assert!(load_effective_unified_policy_from(&sources, &bad_env).is_err());

        // Weakening MP_BRAKES below system min_profile MUST fail closed.
        let weak_brakes = |k: &str| {
            if k == "MP_BRAKES" {
                Some(OsString::from("black-flag"))
            } else {
                None
            }
        };
        assert!(load_effective_unified_policy_from(&sources, &weak_brakes).is_err());
        Ok(())
    }

    #[test]
    fn refuses_symlink_and_world_writable_policy_files() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let uid = unsafe { libc::geteuid() };
        let sys_dir = tmp.path().join("sys");
        fs::create_dir(&sys_dir)?;
        fs::set_permissions(&sys_dir, fs::Permissions::from_mode(0o755))?;

        let real_file = tmp.path().join("target.toml");
        fs::write(&real_file, "[lan]\ndisabled = false\n")?;
        symlink(&real_file, sys_dir.join("policy.toml"))?;

        let sources = PolicyLoadSources {
            system_dir: sys_dir.clone(),
            user_dir: Some(tmp.path().join("absent_usr")),
            expected_system_uid: uid,
            expected_user_uid: Some(uid),
        };
        assert!(load_effective_unified_policy_from(&sources, &empty_env).is_err());

        fs::remove_file(sys_dir.join("policy.toml"))?;
        let writable = sys_dir.join("policy.toml");
        fs::write(&writable, "[lan]\ndisabled = false\n")?;
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o666))?;
        assert!(load_effective_unified_policy_from(&sources, &empty_env).is_err());
        Ok(())
    }
}
