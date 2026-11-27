//! Full LAN Party! (`mp1-lan/1`) runtime, policy loader, local OS presence guard,
//! zero-dep UDP multicast mDNS advertiser/scanner (`_mp1-lan._udp.local.`),
//! and `mp-outpost lan {status|scan|host|join}` CLI surface.
//!
//! 100% wire-interoperable with Blackbird `v0.3.0` (`src/lan_party_runtime.cpp`,
//! `src/lan_party_protocol.cpp`, `src/lan_mdns.cpp`) and enforces all 6 Operator
//! Security Mandates without exception.

use core::fmt;
use std::cell::UnsafeCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::{CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use icu_normalizer::ComposingNormalizerBorrowed;
use mp_protocol::{RelayPolicy, validate_ed25519_pubkey_strict};
use outpost_control::wall_now_ms;
use outpost_core::fence::{fence_peer_text, sanitize_peer_text, scan_outbound_secrets};
use outpost_core::lan_protocol::{
    DEFAULT_SYSTEM_LAN_POLICY_PATH, DNS_CLASS_IN, DNS_TYPE_PTR, EffectiveLanPolicy,
    LAN_BEACON_ALPN, LAN_BEACON_VERSION, LAN_MAX_MEMBERS, LAN_MDNS_DEFAULT_PORT,
    LAN_MDNS_DEFAULT_TTL_SEC, LAN_MDNS_MAX_DIRECT_ADDRS, LAN_MDNS_MAX_PACKET_BYTES,
    LAN_MDNS_MULTICAST_GROUP, LAN_MDNS_SERVICE_TYPE, LAN_PARTY_ID_BYTES, LanBeaconRecord,
    LanHandshakeMessage, LanHelloMessage, LanJoinMessage, LanMdnsAnnouncement, LanMemberInfo,
    LanPinLockoutStatus, LanPinPeerKey, LanPinRateLimitConfig, LanPinRateLimiter, LanPolicyConfig,
    LanRosterMessage, LanWelcomeMessage, MAX_LAN_IDLE_TIMEOUT_SEC, MAX_LAN_POLICY_FILE_BYTES,
    MAX_LAN_SCAN_TIMEOUT_SEC, PartialLanPolicy, compute_lan_pin_proof, compute_lan_safety_number,
    decode_lan_mdns_packet, decode_lan_pubkey_base64url, dns_names_equal_ci,
    encode_lan_announcement, encode_lan_goodbye, encode_lan_ptr_query, encode_lan_pubkey_base64url,
    format_lan_direct_target, format_lan_party_id_hex, is_valid_lan_name, parse_lan_direct_target,
    parse_lan_party_id_hex, parse_partial_lan_policy_toml, resolve_lan_policy,
    sanitize_lan_display_name, validate_lan_pin, verify_lan_pin_proof,
};
use outpost_core::p2p_wire::{
    MAX_CHAT_BODY_BYTES, MAX_CONTROL_NOTICE_BYTES, MAX_EPHEMERAL_STATUS_BYTES,
    MAX_ROOM_SCOPE_BYTES, MAX_TARGET_SELECTOR_BYTES, P2pBridgeEnvelope, P2pChatMessage,
    P2pControlNotice, P2pEphemeralPulse, P2pPartyFrame,
};
use outpost_core::policy::{
    DEFAULT_SYSTEM_POLICY_PATH, UnifiedPolicyFile, merge_unified_policy_floor,
    parse_unified_policy_toml,
};
use outpost_core::storage_codec::{PeersStoreRecord, TrustState, decode_peers_store};
use outpost_core::trust::verify_safety_number;
use outpost_daemon::{
    DaemonError, StateLock, VerifiedDir, atomic_write_in_dir, atomic_write_in_dir_no_replace,
    fill_random, open_dir_nofollow, open_or_create_private_dir,
};
use outpost_p2p::{
    CLOSE_UNAUTHORIZED, LanTransportConfig, P2pEventStream, P2pTransportEvent, PartyP2pConfig,
    PartyP2pHandle, PartyP2pTransport,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use zeroize::{Zeroize as _, Zeroizing};

use crate::build_info::encode_hex;
use crate::cli::GlobalOpts;
use crate::storage::{
    PEERS_FILE, load_device_record, resolve_active_device_id, resolve_effective_state_dir,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LAN_DEFAULT_ROOM_SCOPE: &str = "lan/main";
const LAN_IDENTITY_FILE: &str = "identity.json";
const LAN_PEERS_FILE: &str = "lan_peers.json";
const MAX_LAN_IDENTITY_FILE_BYTES: usize = 16 * 1024;
const MAX_LAN_PEERS_FILE_BYTES: usize = 512 * 1024;
const MAX_PEERS_BIN_BYTES: usize = 2 * 1024 * 1024;
const MAX_LAN_PINNED_PEERS: usize = 1024;
const MAX_PIN_INPUT_BYTES: usize = 256;
const LAN_PENDING_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const LAN_JOIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const LAN_APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_APPROVAL_QUEUE: usize = 8;
const LAN_REJECT_FLUSH_GRACE: Duration = Duration::from_millis(25);
const LAN_MDNS_REANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
const LAN_MDNS_SCAN_QUERY_INTERVAL: Duration = Duration::from_secs(2);
const LAN_MDNS_REPLY_COOLDOWN: Duration = Duration::from_secs(1);
const MAX_MDNS_UNICAST_COOLDOWN_ENTRIES: usize = 256;
const MAX_DISCOVERED_LAN_LOBBIES: usize = 64;
const DNS_TYPE_ANY: u16 = 255;

// ---------------------------------------------------------------------------
// 1. Policy Loader & Hard Kill-Switch (Mandates #1, #2, #3, #6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct LanPolicyPaths {
    pub system_unified_policy_path: Option<PathBuf>,
    pub system_policy_path: PathBuf,
    pub user_unified_policy_path: Option<PathBuf>,
    pub user_policy_path: Option<PathBuf>,
    pub expected_system_uid: u32,
    pub expected_user_uid: Option<u32>,
}

impl Default for LanPolicyPaths {
    fn default() -> Self {
        Self {
            system_unified_policy_path: Some(PathBuf::from(DEFAULT_SYSTEM_POLICY_PATH)),
            system_policy_path: PathBuf::from(DEFAULT_SYSTEM_LAN_POLICY_PATH),
            user_unified_policy_path: None,
            user_policy_path: None,
            expected_system_uid: 0,
            expected_user_uid: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectivePolicyReport {
    pub policy: LanPolicyConfig,
    pub effective: EffectiveLanPolicy,
    pub system_unified_policy_loaded: bool,
    pub system_unified_policy_path: Option<PathBuf>,
    pub system_policy_loaded: bool,
    pub system_policy_path: PathBuf,
    pub user_unified_policy_loaded: bool,
    pub user_unified_policy_path: Option<PathBuf>,
    pub user_policy_loaded: bool,
    pub user_policy_path: Option<PathBuf>,
    pub env_disabled: bool,
}

fn env_kill_switch_active(lookup: &dyn Fn(&str) -> Option<OsString>, var_name: &str) -> bool {
    let Some(raw_os) = lookup(var_name) else {
        return false;
    };
    let Some(raw) = raw_os.to_str() else {
        // Non-UTF-8 value in kill-switch env var MUST fail closed.
        return true;
    };
    let lower = raw.trim_matches([' ', '\t']).to_ascii_lowercase();
    // Honor 1/true/yes and fail closed on any other non-empty value.
    !(lower.is_empty() || lower == "0" || lower == "false" || lower == "no")
}

fn default_user_config_path(
    lookup: &dyn Fn(&str) -> Option<OsString>,
    filename: &str,
) -> Option<PathBuf> {
    if let Some(xdg) = lookup("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Some(PathBuf::from(xdg).join("mp-outpost").join(filename));
    }
    if let Some(home) = lookup("HOME")
        && !home.is_empty()
    {
        return Some(
            PathBuf::from(home)
                .join(".config")
                .join("mp-outpost")
                .join(filename),
        );
    }
    None
}

fn read_verified_policy_file(
    path: &Path,
    expected_uid: u32,
    forbid_group_world_write: bool,
) -> Result<Option<String>, String> {
    let raw_bytes = path.as_os_str().as_bytes();
    if raw_bytes.is_empty() {
        return Err("LAN policy path must not be empty".to_string());
    }
    let Some(parent) = path.parent() else {
        return Err(format!(
            "LAN policy path '{}' has no parent directory",
            path.display()
        ));
    };
    let Some(leaf) = path.file_name() else {
        return Err(format!(
            "LAN policy path '{}' has no filename",
            path.display()
        ));
    };

    let mut parent_bytes = parent.as_os_str().as_bytes();
    if parent_bytes.is_empty() {
        parent_bytes = b".";
    }
    while parent_bytes.len() > 1 && parent_bytes.ends_with(b"/") {
        if let Some(prefix) = parent_bytes.strip_suffix(b"/") {
            parent_bytes = prefix;
        } else {
            break;
        }
    }
    let cparent = CString::new(parent_bytes)
        .map_err(|_| format!("policy parent path '{}' contains NUL byte", parent.display()))?;
    let cleaf = CString::new(leaf.as_bytes())
        .map_err(|_| format!("LAN policy filename '{}' contains NUL byte", path.display()))?;

    // Verify parent directory via O_DIRECTORY | O_NOFOLLOW BEFORE treating ENOENT leaf as absent!
    let parent_raw_fd = loop {
        let fd = unsafe {
            libc::open(
                cparent.as_ptr(),
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
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(format!(
                    "refusing symlinked policy parent directory '{}' (fail closed)",
                    parent.display()
                ));
            }
            if err.raw_os_error() == Some(libc::ENOTDIR) {
                let mut lst: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::lstat(cparent.as_ptr(), &mut lst) } == 0
                    && (lst.st_mode & libc::S_IFMT) == libc::S_IFLNK
                {
                    return Err(format!(
                        "refusing symlinked policy parent directory '{}' (fail closed)",
                        parent.display()
                    ));
                }
            }
            return Err(format!(
                "failed opening policy parent directory '{}': {err}",
                parent.display()
            ));
        }
        break fd;
    };
    let parent_fd = unsafe { OwnedFd::from_raw_fd(parent_raw_fd) };

    let mut pst: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(parent_fd.as_raw_fd(), &mut pst) } != 0 {
        return Err(format!(
            "failed to fstat policy parent directory '{}': {}",
            parent.display(),
            io::Error::last_os_error()
        ));
    }
    if (pst.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(format!(
            "refusing non-directory policy parent '{}' (fail closed)",
            parent.display()
        ));
    }
    if pst.st_uid != expected_uid {
        return Err(format!(
            "refusing policy parent '{}': expected owner uid={expected_uid}, got uid={}",
            parent.display(),
            pst.st_uid
        ));
    }
    if forbid_group_world_write && (pst.st_mode & 0o022) != 0 {
        return Err(format!(
            "refusing group/world-writable policy parent '{}' (mode {:04o})",
            parent.display(),
            pst.st_mode & 0o7777
        ));
    }

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
                    "refusing symlinked LAN policy '{}' (ELOOP)",
                    path.display()
                ));
            }
            return Err(format!(
                "failed to open LAN policy '{}': {err}",
                path.display()
            ));
        }
        break fd;
    };
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut fst) } != 0 {
        return Err(format!(
            "failed to fstat LAN policy '{}': {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    if (fst.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "refusing non-regular LAN policy '{}' (fail closed)",
            path.display()
        ));
    }
    if fst.st_uid != expected_uid {
        return Err(format!(
            "refusing LAN policy '{}': expected owner uid={expected_uid}, got uid={}",
            path.display(),
            fst.st_uid
        ));
    }
    if forbid_group_world_write && (fst.st_mode & 0o022) != 0 {
        return Err(format!(
            "refusing group/world-writable LAN policy '{}' (mode {:04o})",
            path.display(),
            fst.st_mode & 0o7777
        ));
    }
    if fst.st_size < 0 || (fst.st_size as u64) > (MAX_LAN_POLICY_FILE_BYTES as u64) {
        return Err(format!(
            "LAN policy '{}' exceeds max {MAX_LAN_POLICY_FILE_BYTES} bytes",
            path.display()
        ));
    }

    let file = File::from(fd);
    let mut raw = Vec::new();
    let limit = (MAX_LAN_POLICY_FILE_BYTES as u64).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut raw)
        .map_err(|e| format!("failed reading LAN policy '{}': {e}", path.display()))?;
    if raw.len() > MAX_LAN_POLICY_FILE_BYTES {
        return Err(format!(
            "LAN policy '{}' grew beyond max {MAX_LAN_POLICY_FILE_BYTES} bytes",
            path.display()
        ));
    }
    let text = String::from_utf8(raw)
        .map_err(|_| format!("LAN policy '{}' is not valid UTF-8", path.display()))?;
    Ok(Some(text))
}

pub(crate) fn load_effective_lan_policy(
    paths: &LanPolicyPaths,
    env_lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<EffectivePolicyReport, String> {
    let mut sys_unified: Option<UnifiedPolicyFile> = None;
    if let Some(ref upath) = paths.system_unified_policy_path
        && !upath.as_os_str().is_empty()
        && let Some(text) = read_verified_policy_file(upath, paths.expected_system_uid, true)?
    {
        let parsed = parse_unified_policy_toml(&text).map_err(|e| {
            format!(
                "malformed system unified policy '{}' (fail closed): {e}",
                upath.display()
            )
        })?;
        sys_unified = Some(parsed);
    }

    let mut sys_legacy: Option<PartialLanPolicy> = None;
    if !paths.system_policy_path.as_os_str().is_empty()
        && let Some(sys_text) =
            read_verified_policy_file(&paths.system_policy_path, paths.expected_system_uid, true)?
    {
        let parsed = parse_partial_lan_policy_toml(&sys_text).map_err(|e| {
            format!(
                "malformed system LAN policy '{}' (fail closed): {e}",
                paths.system_policy_path.display()
            )
        })?;
        sys_legacy = Some(parsed);
    }

    let expected_user_uid = paths
        .expected_user_uid
        .unwrap_or_else(|| unsafe { libc::geteuid() });

    let resolved_user_unified_path = paths
        .user_unified_policy_path
        .clone()
        .or_else(|| default_user_config_path(env_lookup, "policy.toml"));
    let mut user_unified: Option<UnifiedPolicyFile> = None;
    if let Some(ref upath) = resolved_user_unified_path
        && !upath.as_os_str().is_empty()
        && let Some(text) = read_verified_policy_file(upath, expected_user_uid, true)?
    {
        let parsed = parse_unified_policy_toml(&text).map_err(|e| {
            format!(
                "malformed user unified policy '{}' (fail closed): {e}",
                upath.display()
            )
        })?;
        user_unified = Some(parsed);
    }

    let resolved_user_path = paths
        .user_policy_path
        .clone()
        .or_else(|| default_user_config_path(env_lookup, "lan.toml"));
    let mut user_legacy: Option<PartialLanPolicy> = None;
    if let Some(ref upath) = resolved_user_path
        && !upath.as_os_str().is_empty()
        && let Some(user_text) = read_verified_policy_file(upath, expected_user_uid, true)?
    {
        let parsed = parse_partial_lan_policy_toml(&user_text).map_err(|e| {
            format!(
                "malformed user LAN policy '{}' (fail closed): {e}",
                upath.display()
            )
        })?;
        user_legacy = Some(parsed);
    }

    let env_disabled = env_kill_switch_active(env_lookup, "MP_DISABLE_LAN")
        || env_kill_switch_active(env_lookup, "BLACKBIRD_DISABLE_LAN");

    let effective = if sys_unified.is_some() || user_unified.is_some() {
        merge_unified_policy_floor(
            sys_unified.as_ref(),
            sys_legacy.as_ref(),
            user_unified.as_ref(),
            user_legacy.as_ref(),
            env_disabled,
            None,
        )
        .map_err(|e| format!("failed merging unified policy floor (fail closed): {e}"))?
        .lan
    } else {
        resolve_lan_policy(sys_legacy.as_ref(), user_legacy.as_ref(), env_disabled)
    };

    Ok(EffectivePolicyReport {
        policy: effective.config,
        effective,
        system_unified_policy_loaded: sys_unified.is_some(),
        system_unified_policy_path: paths.system_unified_policy_path.clone(),
        system_policy_loaded: sys_legacy.is_some(),
        system_policy_path: paths.system_policy_path.clone(),
        user_unified_policy_loaded: user_unified.is_some(),
        user_unified_policy_path: resolved_user_unified_path,
        user_policy_loaded: user_legacy.is_some(),
        user_policy_path: resolved_user_path,
        env_disabled,
    })
}

fn process_env_lookup(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

fn enforce_lan_enabled_and_local_auth(
    report: &EffectivePolicyReport,
    auth_reason: &str,
) -> Result<(), String> {
    if report.policy.disabled {
        return Err(
            "LAN Party mode is disabled by policy or environment kill-switch (MP_DISABLE_LAN / BLACKBIRD_DISABLE_LAN / lan.toml)"
                .to_string(),
        );
    }
    if report.policy.require_local_auth {
        verify_local_os_presence(auth_reason)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Local OS Presence Guard (Mandate #6: macOS LAContext dlopen + sudo -k -v)
// ---------------------------------------------------------------------------

fn verify_via_sudo() -> Result<(), String> {
    // Mandate #6: probe non-interactively after invalidating any cached timestamp.
    // If sudo succeeds without prompting (NOPASSWD), fail closed!
    let nopasswd_probe = Command::new("/usr/bin/sudo")
        .args(["-k", "-n", "-v"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| {
            format!("local OS presence guard failed executing /usr/bin/sudo -k -n -v: {e}")
        })?;
    if nopasswd_probe.success() {
        return Err("refusing NOPASSWD sudo for local OS presence check".to_string());
    }

    // Single invocation invalidates cached credentials and immediately prompts interactively,
    // eliminating any two-process `-k` then `-v` race window.
    let v_status = Command::new("/usr/bin/sudo")
        .args(["-k", "-v"])
        .status()
        .map_err(|e| format!("local OS presence guard failed executing /usr/bin/sudo -k -v: {e}"))?;
    if !v_status.success() {
        return Err("local OS presence authentication denied (/usr/bin/sudo -k -v)".to_string());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos_local_auth {
    use std::ffi::{CString, c_char, c_int, c_long, c_void};
    use std::sync::{Arc, Condvar, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    const LA_POLICY_DEVICE_OWNER_AUTHENTICATION: c_long = 2;
    const BLOCK_HAS_COPY_DISPOSE: c_int = 1 << 25;
    const LA_EVAL_TIMEOUT: Duration = Duration::from_secs(60);

    type ObjcGetClassFn = unsafe extern "C" fn(*const c_char) -> *mut c_void;
    type SelRegisterNameFn = unsafe extern "C" fn(*const c_char) -> *mut c_void;
    type MsgSendIdFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type MsgSendVoidFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
    type MsgSendIdCStrFn =
        unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut c_void;
    type MsgSendCanEvalFn =
        unsafe extern "C" fn(*mut c_void, *mut c_void, c_long, *mut *mut c_void) -> i8;
    type MsgSendEvalFn =
        unsafe extern "C" fn(*mut c_void, *mut c_void, c_long, *mut c_void, *mut c_void);
    type ObjcAutoreleasePoolPushFn = unsafe extern "C" fn() -> *mut c_void;
    type ObjcAutoreleasePoolPopFn = unsafe extern "C" fn(*mut c_void);

    struct LaSymbols {
        get_class: ObjcGetClassFn,
        reg_sel: SelRegisterNameFn,
        msg_id: MsgSendIdFn,
        msg_void: MsgSendVoidFn,
        msg_id_cstr: MsgSendIdCStrFn,
        msg_can_eval: MsgSendCanEvalFn,
        msg_eval: MsgSendEvalFn,
        pool_push: ObjcAutoreleasePoolPushFn,
        pool_pop: ObjcAutoreleasePoolPopFn,
        stack_block_isa: *mut c_void,
    }

    // SAFETY: Function pointers and `_NSConcreteStackBlock` class pointer loaded with
    // `RTLD_NODELETE` remain valid and immutable for the entire process lifetime.
    unsafe impl Send for LaSymbols {}
    unsafe impl Sync for LaSymbols {}

    static LA_SYMBOLS: OnceLock<Option<LaSymbols>> = OnceLock::new();

    fn load_la_symbols() -> Option<&'static LaSymbols> {
        LA_SYMBOLS
            .get_or_init(|| {
                let la_path =
                    c"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication";
                let fnd_path = c"/System/Library/Frameworks/Foundation.framework/Foundation";
                let objc_path = c"/usr/lib/libobjc.A.dylib";

                let flags = libc::RTLD_LAZY | libc::RTLD_LOCAL | libc::RTLD_NODELETE;
                let la_fw = unsafe { libc::dlopen(la_path.as_ptr(), flags) };
                let fnd_fw = unsafe { libc::dlopen(fnd_path.as_ptr(), flags) };
                let objc_lib = unsafe { libc::dlopen(objc_path.as_ptr(), flags) };
                if la_fw.is_null() || fnd_fw.is_null() || objc_lib.is_null() {
                    return None;
                }

                let sym_get_class = unsafe { libc::dlsym(objc_lib, c"objc_getClass".as_ptr()) };
                let sym_reg_sel = unsafe { libc::dlsym(objc_lib, c"sel_registerName".as_ptr()) };
                let sym_msg_send = unsafe { libc::dlsym(objc_lib, c"objc_msgSend".as_ptr()) };
                let sym_pool_push =
                    unsafe { libc::dlsym(objc_lib, c"objc_autoreleasePoolPush".as_ptr()) };
                let sym_pool_pop =
                    unsafe { libc::dlsym(objc_lib, c"objc_autoreleasePoolPop".as_ptr()) };
                let stack_block_isa =
                    unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"_NSConcreteStackBlock".as_ptr()) };
                if sym_get_class.is_null()
                    || sym_reg_sel.is_null()
                    || sym_msg_send.is_null()
                    || sym_pool_push.is_null()
                    || sym_pool_pop.is_null()
                    || stack_block_isa.is_null()
                {
                    return None;
                }

                Some(LaSymbols {
                    get_class: unsafe { std::mem::transmute::<*mut c_void, ObjcGetClassFn>(sym_get_class) },
                    reg_sel: unsafe { std::mem::transmute::<*mut c_void, SelRegisterNameFn>(sym_reg_sel) },
                    msg_id: unsafe { std::mem::transmute::<*mut c_void, MsgSendIdFn>(sym_msg_send) },
                    msg_void: unsafe { std::mem::transmute::<*mut c_void, MsgSendVoidFn>(sym_msg_send) },
                    msg_id_cstr: unsafe { std::mem::transmute::<*mut c_void, MsgSendIdCStrFn>(sym_msg_send) },
                    msg_can_eval: unsafe { std::mem::transmute::<*mut c_void, MsgSendCanEvalFn>(sym_msg_send) },
                    msg_eval: unsafe { std::mem::transmute::<*mut c_void, MsgSendEvalFn>(sym_msg_send) },
                    pool_push: unsafe {
                        std::mem::transmute::<*mut c_void, ObjcAutoreleasePoolPushFn>(sym_pool_push)
                    },
                    pool_pop: unsafe {
                        std::mem::transmute::<*mut c_void, ObjcAutoreleasePoolPopFn>(sym_pool_pop)
                    },
                    stack_block_isa,
                })
            })
            .as_ref()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum LocalAuthOutcome {
        Authorized,
        Denied,
        TimedOut,
        Unavailable,
    }

    struct LaWaitState {
        done: bool,
        succeeded: bool,
    }

    type LaWaitPair = (Mutex<LaWaitState>, Condvar);

    #[repr(C)]
    struct LaBlockDescriptor {
        reserved: libc::c_ulong,
        size: libc::c_ulong,
        copy_helper: unsafe extern "C" fn(*mut c_void, *const c_void),
        dispose_helper: unsafe extern "C" fn(*mut c_void),
    }

    #[repr(C)]
    struct LaReplyBlock {
        isa: *mut c_void,
        flags: c_int,
        reserved: c_int,
        invoke: unsafe extern "C" fn(*mut LaReplyBlock, i8, *mut c_void),
        descriptor: *const LaBlockDescriptor,
        pair: *const LaWaitPair,
    }

    unsafe extern "C" fn la_block_copy_helper(dst: *mut c_void, src: *const c_void) {
        if dst.is_null() || src.is_null() {
            return;
        }
        let src_block = unsafe { &*(src.cast::<LaReplyBlock>()) };
        let dst_block = unsafe { &mut *(dst.cast::<LaReplyBlock>()) };
        if !src_block.pair.is_null() {
            unsafe {
                Arc::increment_strong_count(src_block.pair);
            }
            dst_block.pair = src_block.pair;
        }
    }

    unsafe extern "C" fn la_block_dispose_helper(src: *mut c_void) {
        if src.is_null() {
            return;
        }
        let block = unsafe { &mut *(src.cast::<LaReplyBlock>()) };
        if !block.pair.is_null() {
            let ptr = block.pair;
            block.pair = std::ptr::null();
            unsafe {
                drop(Arc::from_raw(ptr));
            }
        }
    }

    unsafe extern "C" fn la_reply_invoke(block: *mut LaReplyBlock, success: i8, _err: *mut c_void) {
        if block.is_null() {
            return;
        }
        let pair_ptr = unsafe { (*block).pair };
        if pair_ptr.is_null() {
            return;
        }
        let (mu, cv) = unsafe { &*pair_ptr };
        let mut guard = match mu.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.succeeded = success != 0;
        guard.done = true;
        cv.notify_one();
    }

    struct AutoreleasePoolGuard {
        pool: *mut c_void,
        pop: ObjcAutoreleasePoolPopFn,
    }

    impl AutoreleasePoolGuard {
        fn new(push: ObjcAutoreleasePoolPushFn, pop: ObjcAutoreleasePoolPopFn) -> Self {
            let pool = unsafe { push() };
            Self { pool, pop }
        }
    }

    impl Drop for AutoreleasePoolGuard {
        fn drop(&mut self) {
            if !self.pool.is_null() {
                unsafe {
                    (self.pop)(self.pool);
                }
            }
        }
    }

    struct ObjcReleaseGuard {
        obj: *mut c_void,
        send_void: MsgSendVoidFn,
        release_sel: *mut c_void,
    }

    impl Drop for ObjcReleaseGuard {
        fn drop(&mut self) {
            if !self.obj.is_null() {
                unsafe {
                    (self.send_void)(self.obj, self.release_sel);
                }
            }
        }
    }

    struct StackBlockArcGuard(*const LaWaitPair);

    impl Drop for StackBlockArcGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    drop(Arc::from_raw(self.0));
                }
            }
        }
    }

    pub(super) fn verify_via_lacontext(reason: &str) -> LocalAuthOutcome {
        let Ok(reason_c) = CString::new(reason) else {
            return LocalAuthOutcome::Unavailable;
        };
        let Some(syms) = load_la_symbols() else {
            return LocalAuthOutcome::Unavailable;
        };

        // Wrap ALL Objective-C calls in an RAII autorelease pool.
        let _pool = AutoreleasePoolGuard::new(syms.pool_push, syms.pool_pop);

        let la_ctx_cls = unsafe { (syms.get_class)(c"LAContext".as_ptr()) };
        let ns_string_cls = unsafe { (syms.get_class)(c"NSString".as_ptr()) };
        if la_ctx_cls.is_null() || ns_string_cls.is_null() {
            return LocalAuthOutcome::Unavailable;
        }

        let sel_alloc = unsafe { (syms.reg_sel)(c"alloc".as_ptr()) };
        let sel_init = unsafe { (syms.reg_sel)(c"init".as_ptr()) };
        let sel_release = unsafe { (syms.reg_sel)(c"release".as_ptr()) };
        let sel_invalidate = unsafe { (syms.reg_sel)(c"invalidate".as_ptr()) };
        let sel_init_utf8 = unsafe { (syms.reg_sel)(c"initWithUTF8String:".as_ptr()) };
        let sel_can_eval = unsafe { (syms.reg_sel)(c"canEvaluatePolicy:error:".as_ptr()) };
        let sel_eval =
            unsafe { (syms.reg_sel)(c"evaluatePolicy:localizedReason:reply:".as_ptr()) };

        let ctx_alloc = unsafe { (syms.msg_id)(la_ctx_cls, sel_alloc) };
        if ctx_alloc.is_null() {
            return LocalAuthOutcome::Unavailable;
        }
        let ctx = unsafe { (syms.msg_id)(ctx_alloc, sel_init) };
        if ctx.is_null() {
            unsafe {
                (syms.msg_void)(ctx_alloc, sel_release);
            }
            return LocalAuthOutcome::Unavailable;
        }
        let _ctx_guard = ObjcReleaseGuard {
            obj: ctx,
            send_void: syms.msg_void,
            release_sel: sel_release,
        };

        // Pass NULL for the nullable `NSError **` out-param so no autoreleased NSError is
        // allocated (zero leak, zero double-release under `_pool`).
        let can_eval = unsafe {
            (syms.msg_can_eval)(
                ctx,
                sel_can_eval,
                LA_POLICY_DEVICE_OWNER_AUTHENTICATION,
                std::ptr::null_mut(),
            )
        };
        if can_eval == 0 {
            return LocalAuthOutcome::Unavailable;
        }

        let str_alloc = unsafe { (syms.msg_id)(ns_string_cls, sel_alloc) };
        if str_alloc.is_null() {
            return LocalAuthOutcome::Unavailable;
        }
        let ns_reason = unsafe { (syms.msg_id_cstr)(str_alloc, sel_init_utf8, reason_c.as_ptr()) };
        if ns_reason.is_null() {
            unsafe {
                (syms.msg_void)(str_alloc, sel_release);
            }
            return LocalAuthOutcome::Unavailable;
        }
        let _reason_guard = ObjcReleaseGuard {
            obj: ns_reason,
            send_void: syms.msg_void,
            release_sel: sel_release,
        };

        static BLOCK_DESC: LaBlockDescriptor = LaBlockDescriptor {
            reserved: 0,
            size: std::mem::size_of::<LaReplyBlock>() as libc::c_ulong,
            copy_helper: la_block_copy_helper,
            dispose_helper: la_block_dispose_helper,
        };

        let wait_pair: Arc<LaWaitPair> = Arc::new((
            Mutex::new(LaWaitState {
                done: false,
                succeeded: false,
            }),
            Condvar::new(),
        ));
        let stack_pair_raw = Arc::into_raw(Arc::clone(&wait_pair));
        let _stack_arc_guard = StackBlockArcGuard(stack_pair_raw);

        let mut reply_block = LaReplyBlock {
            isa: syms.stack_block_isa,
            flags: BLOCK_HAS_COPY_DISPOSE,
            reserved: 0,
            invoke: la_reply_invoke,
            descriptor: &BLOCK_DESC,
            pair: stack_pair_raw,
        };

        unsafe {
            (syms.msg_eval)(
                ctx,
                sel_eval,
                LA_POLICY_DEVICE_OWNER_AUTHENTICATION,
                ns_reason,
                (&mut reply_block as *mut LaReplyBlock).cast::<c_void>(),
            );
        }

        let (mu, cv) = &*wait_pair;
        let deadline = Instant::now() + LA_EVAL_TIMEOUT;
        let mut guard = match mu.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        while !guard.done {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let (next_guard, wait_res) = match cv.wait_timeout(guard, remaining) {
                Ok(pair) => pair,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard = next_guard;
            if wait_res.timed_out() {
                break;
            }
        }
        if !guard.done {
            drop(guard);
            unsafe {
                (syms.msg_void)(ctx, sel_invalidate);
            }
            return LocalAuthOutcome::TimedOut;
        }
        if guard.succeeded {
            LocalAuthOutcome::Authorized
        } else {
            LocalAuthOutcome::Denied
        }
    }
}

fn verify_local_os_presence_paused(
    _pause: &TtyPromptPauseGuard,
    reason: &str,
) -> Result<(), String> {
    if reason.is_empty()
        || reason.len() > 256
        || reason.chars().any(|c| (c as u32) < 0x20 || c == '\x7f')
    {
        return Err("invalid local auth reason string".to_string());
    }

    #[cfg(target_os = "macos")]
    {
        // Attempt LAContext unconditionally first; never skip based on spoofable SSH_* env vars.
        match macos_local_auth::verify_via_lacontext(reason) {
            macos_local_auth::LocalAuthOutcome::Authorized => return Ok(()),
            macos_local_auth::LocalAuthOutcome::Denied => {
                return Err(
                    "local OS presence authentication denied (Touch ID / macOS password)"
                        .to_string(),
                );
            }
            macos_local_auth::LocalAuthOutcome::TimedOut => {
                return Err("local authentication timed out".to_string());
            }
            macos_local_auth::LocalAuthOutcome::Unavailable => {
                // Fall back to sudo -k -n -v probe + sudo -k -v only when LAContext is unavailable.
            }
        }
        verify_via_sudo()
    }

    #[cfg(not(target_os = "macos"))]
    {
        verify_via_sudo()
    }
}

pub(crate) fn verify_local_os_presence(reason: &str) -> Result<(), String> {
    let pause = TtyPromptPauseGuard::acquire();
    verify_local_os_presence_paused(&pause, reason)
}

// ---------------------------------------------------------------------------
// 3. Signal-Safe Masked `/dev/tty` Prompt & `--pin-stdin` (Mandate #4)
// ---------------------------------------------------------------------------

struct LanSyncTermiosCell(UnsafeCell<MaybeUninit<libc::termios>>);
unsafe impl Sync for LanSyncTermiosCell {}

static LAN_SAVED_TTY_FD: AtomicI32 = AtomicI32::new(-1);
static LAN_SAVED_TERMIOS_VALID: AtomicBool = AtomicBool::new(false);
static LAN_SAVED_TERMIOS: LanSyncTermiosCell =
    LanSyncTermiosCell(UnsafeCell::new(MaybeUninit::uninit()));

extern "C" fn lan_restore_termios_on_signal(sig: libc::c_int) {
    let was_valid = LAN_SAVED_TERMIOS_VALID.swap(false, Ordering::AcqRel);
    let fd = LAN_SAVED_TTY_FD.swap(-1, Ordering::AcqRel);
    if was_valid && fd >= 0 {
        unsafe {
            let ptr = (*LAN_SAVED_TERMIOS.0.get()).as_ptr();
            let _ = libc::tcsetattr(fd, libc::TCSAFLUSH, ptr);
        }
    }
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        let _ = libc::sigemptyset(&mut dfl.sa_mask);
        let _ = libc::sigaction(sig, &dfl, std::ptr::null_mut());
        let _ = libc::raise(sig);
    }
}

struct LanTermiosEchoGuard {
    fd: RawFd,
    saved: libc::termios,
    prev_sigint: libc::sigaction,
    prev_sigterm: libc::sigaction,
    signals_installed: bool,
}

impl LanTermiosEchoGuard {
    fn disable_echo(fd: RawFd) -> Result<Self, String> {
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return Err(format!("tcgetattr failed: {}", io::Error::last_os_error()));
        }

        LAN_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
        unsafe {
            (*LAN_SAVED_TERMIOS.0.get()).write(orig);
        }
        LAN_SAVED_TTY_FD.store(fd, Ordering::Release);
        LAN_SAVED_TERMIOS_VALID.store(true, Ordering::Release);

        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = lan_restore_termios_on_signal as *const () as usize;
        let _ = unsafe { libc::sigemptyset(&mut act.sa_mask) };

        let mut prev_sigint: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut prev_sigterm: libc::sigaction = unsafe { std::mem::zeroed() };
        let rc_int = unsafe { libc::sigaction(libc::SIGINT, &act, &mut prev_sigint) };
        let rc_term = unsafe { libc::sigaction(libc::SIGTERM, &act, &mut prev_sigterm) };
        if rc_int != 0 || rc_term != 0 {
            LAN_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
            LAN_SAVED_TTY_FD.store(-1, Ordering::Release);
            if rc_int == 0 {
                let _ = unsafe { libc::sigaction(libc::SIGINT, &prev_sigint, std::ptr::null_mut()) };
            }
            if rc_term == 0 {
                let _ =
                    unsafe { libc::sigaction(libc::SIGTERM, &prev_sigterm, std::ptr::null_mut()) };
            }
            return Err(format!("sigaction failed: {}", io::Error::last_os_error()));
        }

        let mut noecho = orig;
        noecho.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &noecho) } != 0 {
            let err = io::Error::last_os_error();
            LAN_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
            LAN_SAVED_TTY_FD.store(-1, Ordering::Release);
            let _ = unsafe { libc::sigaction(libc::SIGINT, &prev_sigint, std::ptr::null_mut()) };
            let _ = unsafe { libc::sigaction(libc::SIGTERM, &prev_sigterm, std::ptr::null_mut()) };
            return Err(format!("tcsetattr failed: {err}"));
        }

        Ok(Self {
            fd,
            saved: orig,
            prev_sigint,
            prev_sigterm,
            signals_installed: true,
        })
    }
}

impl Drop for LanTermiosEchoGuard {
    fn drop(&mut self) {
        // Restore termios BEFORE clearing the static signal-recovery slot so a late
        // SIGINT/SIGTERM during drop still restores terminal echo.
        unsafe {
            let _ = libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
        }
        LAN_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
        LAN_SAVED_TTY_FD.store(-1, Ordering::Release);
        unsafe {
            if self.signals_installed {
                let _ = libc::sigaction(libc::SIGINT, &self.prev_sigint, std::ptr::null_mut());
                let _ = libc::sigaction(libc::SIGTERM, &self.prev_sigterm, std::ptr::null_mut());
            }
        }
    }
}

fn strip_crlf(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

pub(crate) fn normalize_and_validate_pin(raw: Zeroizing<String>) -> Result<Zeroizing<String>, String> {
    let normalizer = ComposingNormalizerBorrowed::new_nfc();
    let normalized = Zeroizing::new(normalizer.normalize(&raw).into_owned());
    drop(raw);
    validate_lan_pin(&normalized)
        .map_err(|_| "invalid LAN PIN (must be 1..=64 UTF-8 bytes with no control/BiDi chars)".to_string())?;
    Ok(normalized)
}

fn read_line_unbuffered_fd_timeout(
    fd: RawFd,
    max_bytes: usize,
    timeout: Option<Duration>,
) -> Result<Zeroizing<String>, String> {
    // Pre-allocate full capacity so secret bytes are never copied across heap reallocations.
    let mut buf = Zeroizing::new(Vec::with_capacity(max_bytes.saturating_add(1)));
    let mut byte = [0u8; 1];
    let deadline = timeout.map(|d| Instant::now() + d);
    loop {
        if let Some(dl) = deadline {
            let Some(rem) = dl.checked_duration_since(Instant::now()) else {
                byte.zeroize();
                return Err("timed out waiting for /dev/tty input".to_string());
            };
            let poll_ms = i32::try_from(rem.as_millis().min(250)).unwrap_or(250).max(1);
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, poll_ms) };
            if prc == 0 {
                continue;
            }
            if prc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                byte.zeroize();
                return Err(format!("failed polling secret input: {err}"));
            }
        }
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            byte.zeroize();
            return Err(format!("failed reading secret input: {err}"));
        }
        if n == 0 {
            break;
        }
        let b = byte[0];
        byte[0] = 0;
        if b == b'\n' {
            buf.push(b);
            break;
        }
        if buf.len() >= max_bytes {
            byte.zeroize();
            return Err(format!(
                "PIN input exceeded maximum allowed {max_bytes} bytes"
            ));
        }
        buf.push(b);
    }
    byte.zeroize();

    let raw_vec = std::mem::take(&mut *buf);
    let mut s = Zeroizing::new(match String::from_utf8(raw_vec) {
        Ok(text) => text,
        Err(e) => {
            let mut bad = e.into_bytes();
            bad.zeroize();
            return Err("LAN PIN must be valid UTF-8".to_string());
        }
    });
    strip_crlf(&mut s);
    Ok(s)
}

fn read_line_unbuffered_fd(fd: RawFd, max_bytes: usize) -> Result<Zeroizing<String>, String> {
    read_line_unbuffered_fd_timeout(fd, max_bytes, None)
}

fn read_pin_from_stdin() -> Result<Zeroizing<String>, String> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) == 1 } {
        return Err(
            "refusing --pin-stdin on an interactive terminal; omit --pin-stdin for hidden /dev/tty prompt"
                .to_string(),
        );
    }
    let raw = read_line_unbuffered_fd(libc::STDIN_FILENO, MAX_PIN_INPUT_BYTES)?;
    normalize_and_validate_pin(raw)
}

fn read_pin_from_tty(prompt: &str) -> Result<Zeroizing<String>, String> {
    let _pause = TtyPromptPauseGuard::acquire();
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            format!(
                "cannot prompt for LAN PIN without controlling /dev/tty ({e}); pass --pin-stdin when piping"
            )
        })?;
    let guard = LanTermiosEchoGuard::disable_echo(tty.as_raw_fd())?;
    unsafe {
        let _ = libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH);
    }
    tty.write_all(prompt.as_bytes())
        .map_err(|e| format!("failed writing prompt to /dev/tty: {e}"))?;
    tty.flush()
        .map_err(|e| format!("failed flushing /dev/tty: {e}"))?;
    let raw_res = read_line_unbuffered_fd(tty.as_raw_fd(), MAX_PIN_INPUT_BYTES);
    drop(guard);
    let _ = tty.write_all(b"\n");
    let _ = tty.flush();
    normalize_and_validate_pin(raw_res?)
}

// ---------------------------------------------------------------------------
// 4. Local-Only & Online-Reuse LAN Identity (`0600` atomic `identity.json`)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct LanIdentity {
    pub account_id: u64,
    pub is_online_identity: bool,
    pub display_name: String,
    pub public_key: [u8; 32],
    pub signing_seed: Zeroizing<[u8; 32]>,
    pub safety_number: String,
    pub device_cwt: Vec<u8>,
    pub lan_dir: PathBuf,
}

impl fmt::Debug for LanIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanIdentity")
            .field("account_id", &self.account_id)
            .field("is_online_identity", &self.is_online_identity)
            .field("display_name", &self.display_name)
            .field("public_key", &encode_lan_pubkey_base64url(&self.public_key))
            .field("signing_seed", &"[REDACTED]")
            .field("safety_number", &self.safety_number)
            .field(
                "device_cwt",
                &format!("[REDACTED {} bytes]", self.device_cwt.len()),
            )
            .field("lan_dir", &self.lan_dir)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct StoredLanIdentityJson {
    version: u32,
    account_id: u64,
    display_name: String,
    seed_hex: String,
    #[serde(default)]
    public_key_hex: Option<String>,
}

fn resolve_default_lan_dir(override_dir: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(dir) = override_dir {
        if dir.as_os_str().is_empty() {
            return Err("--lan-dir must not be empty".to_string());
        }
        return Ok(dir.to_path_buf());
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("mp-outpost").join("lan"));
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("mp-outpost")
            .join("lan"));
    }
    Err("cannot resolve LAN data directory: neither --lan-dir, XDG_DATA_HOME, nor HOME is set"
        .to_string())
}

fn default_display_name() -> String {
    if let Ok(user) = std::env::var("USER") {
        let clean = sanitize_lan_display_name(&user);
        if !clean.is_empty() {
            return clean;
        }
    }
    "lan-player".to_string()
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err("expected 64 lowercase hex characters".to_string());
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = match bytes.get(i * 2).copied() {
            Some(b @ b'0'..=b'9') => b - b'0',
            Some(b @ b'a'..=b'f') => 10 + (b - b'a'),
            _ => return Err("invalid lowercase hex character".to_string()),
        };
        let lo = match bytes.get(i * 2 + 1).copied() {
            Some(b @ b'0'..=b'9') => b - b'0',
            Some(b @ b'a'..=b'f') => 10 + (b - b'a'),
            _ => return Err("invalid lowercase hex character".to_string()),
        };
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// Opens an existing private directory without following a symlink at the target component
/// (only `ENOENT` maps to `Ok(None)`) and verifies `fstat` ownership (`st_uid == euid`) and
/// strict `0700` permissions (`(st_mode & 0o077) == 0`).
fn open_verified_private_dir_readonly(path: &Path) -> Result<Option<OwnedFd>, String> {
    let fd = match open_dir_nofollow(path) {
        Ok(fd) => fd,
        Err(DaemonError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => {
            return Err(format!(
                "refusing private directory '{}' (fail closed): {e}",
                path.display()
            ));
        }
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(format!(
            "failed fstat on private directory '{}': {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || st.st_uid != euid
        || (st.st_mode & 0o077) != 0
    {
        return Err(format!(
            "refusing insecure private directory '{}' (must be owned by uid={euid} with mode 0700, got uid={} mode {:04o})",
            path.display(),
            st.st_uid,
            st.st_mode & 0o7777
        ));
    }
    Ok(Some(fd))
}

fn read_strict_0600_file_in_dir(
    dir_fd: RawFd,
    name: &str,
    max_bytes: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let cname = CString::new(name).map_err(|_| format!("invalid filename '{name}'"))?;
    let raw_fd = loop {
        let fd = unsafe {
            libc::openat(
                dir_fd,
                cname.as_ptr(),
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
                return Err(format!("refusing symlinked LAN file '{name}'"));
            }
            return Err(format!("failed opening '{name}': {err}"));
        }
        break fd;
    };
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(format!(
            "failed fstat on '{name}': {}",
            io::Error::last_os_error()
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_uid != euid
        || (st.st_mode & 0o077) != 0
    {
        return Err(format!(
            "refusing insecure LAN file '{name}' (must be regular file owned by current user with mode 0600, got mode {:04o})",
            st.st_mode & 0o7777
        ));
    }
    if st.st_size < 0 || (st.st_size as u64) > (max_bytes as u64) {
        return Err(format!("LAN file '{name}' exceeds max {max_bytes} bytes"));
    }

    let initial_cap = usize::try_from(st.st_size).unwrap_or(0).min(max_bytes);
    let mut out = Zeroizing::new(Vec::with_capacity(initial_cap));
    let file = File::from(fd);
    let limit = (max_bytes as u64).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut out)
        .map_err(|e| format!("failed reading '{name}': {e}"))?;
    if out.len() > max_bytes {
        return Err(format!(
            "LAN file '{name}' grew beyond max {max_bytes} bytes"
        ));
    }
    Ok(Some(out))
}

fn try_load_online_lan_identity(
    opts: &GlobalOpts,
    preferred_display_name: Option<&str>,
    lan_dir: &Path,
) -> Result<Option<LanIdentity>, String> {
    let Ok(state_dir_path) = resolve_effective_state_dir(opts.state_dir.as_deref()) else {
        return Ok(None);
    };
    if open_verified_private_dir_readonly(&state_dir_path)?.is_none() {
        return Ok(None);
    }
    let Ok(device_id) = resolve_active_device_id(&state_dir_path, opts.device_id) else {
        return Ok(None);
    };
    let Ok(rec) = load_device_record(&state_dir_path, device_id) else {
        return Ok(None);
    };
    let seed = Zeroizing::new(rec.device_secret);
    let sk = SigningKey::from_bytes(&seed);
    let derived_pk = sk.verifying_key().to_bytes();
    if derived_pk != rec.device_pubkey {
        return Err("enrolled device_secret does not match device_pubkey".to_string());
    }
    let safety_number = compute_lan_safety_number(rec.account_id, &derived_pk)
        .map_err(|e| format!("failed computing Safety Number for online identity: {e}"))?;
    let display_name = preferred_display_name
        .map(sanitize_lan_display_name)
        .unwrap_or_else(|| sanitize_lan_display_name(&rec.device_label));
    Ok(Some(LanIdentity {
        account_id: rec.account_id,
        is_online_identity: true,
        display_name,
        public_key: derived_pk,
        signing_seed: seed,
        safety_number,
        device_cwt: rec.device_cwt,
        lan_dir: lan_dir.to_path_buf(),
    }))
}

fn parse_stored_lan_identity(
    mut raw: Zeroizing<Vec<u8>>,
    preferred_display_name: Option<&str>,
    lan_dir: &Path,
) -> Result<LanIdentity, String> {
    let raw_vec = std::mem::take(&mut *raw);
    let text = Zeroizing::new(match String::from_utf8(raw_vec) {
        Ok(s) => s,
        Err(e) => {
            let mut bad = e.into_bytes();
            bad.zeroize();
            return Err("identity.json is not valid UTF-8".to_string());
        }
    });
    drop(raw);

    let mut stored: StoredLanIdentityJson = serde_json::from_str(&text)
        .map_err(|e| format!("corrupt LAN identity.json: {e}"))?;
    let seed_hex = Zeroizing::new(std::mem::take(&mut stored.seed_hex));
    if stored.version != 1 || stored.account_id != 0 {
        return Err("invalid LAN identity.json version or account_id".to_string());
    }
    if !is_valid_lan_name(&stored.display_name) {
        return Err("invalid display_name in LAN identity.json".to_string());
    }
    let seed = Zeroizing::new(
        decode_hex_32(&seed_hex).map_err(|_| "corrupt seed_hex in LAN identity.json")?,
    );
    drop(seed_hex);

    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    if let Some(ref declared_hex) = stored.public_key_hex {
        let declared_pk = decode_hex_32(declared_hex)
            .map_err(|_| "corrupt public_key_hex in LAN identity.json")?;
        if declared_pk != pk {
            return Err("LAN identity.json public_key_hex mismatch".to_string());
        }
    }
    let safety_number = compute_lan_safety_number(0, &pk)
        .map_err(|e| format!("invalid Ed25519 key in identity.json: {e}"))?;
    let display_name = preferred_display_name
        .map(sanitize_lan_display_name)
        .unwrap_or(stored.display_name);

    Ok(LanIdentity {
        account_id: 0,
        is_online_identity: false,
        display_name,
        public_key: pk,
        signing_seed: seed,
        safety_number,
        device_cwt: Vec::new(),
        lan_dir: lan_dir.to_path_buf(),
    })
}

pub(crate) fn load_or_create_lan_identity(
    opts: &GlobalOpts,
    lan_dir_override: Option<&Path>,
    local_only: bool,
    preferred_display_name: Option<&str>,
) -> Result<LanIdentity, String> {
    let lan_dir = resolve_default_lan_dir(lan_dir_override)?;

    // Prefer already-enrolled online identity unless --lan-dir or --local-only explicitly isolates local identity.
    if lan_dir_override.is_none()
        && !local_only
        && let Some(online) = try_load_online_lan_identity(opts, preferred_display_name, &lan_dir)?
    {
        return Ok(online);
    }

    let dir: VerifiedDir =
        open_or_create_private_dir(&lan_dir).map_err(|e| format!("failed opening LAN dir: {e}"))?;
    if let Some(raw) =
        read_strict_0600_file_in_dir(dir.as_raw_fd(), LAN_IDENTITY_FILE, MAX_LAN_IDENTITY_FILE_BYTES)?
    {
        return parse_stored_lan_identity(raw, preferred_display_name, &lan_dir);
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    fill_random(&mut *seed).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let safety_number = compute_lan_safety_number(0, &pk)
        .map_err(|e| format!("failed computing LAN Safety Number: {e}"))?;
    let display_name = preferred_display_name
        .map(sanitize_lan_display_name)
        .unwrap_or_else(default_display_name);

    let seed_hex = Zeroizing::new(encode_hex(&*seed));
    let pk_hex = encode_hex(&pk);
    let mut stored = StoredLanIdentityJson {
        version: 1,
        account_id: 0,
        display_name: display_name.clone(),
        seed_hex: (*seed_hex).clone(),
        public_key_hex: Some(pk_hex),
    };
    // Serialize directly into a pre-allocated Zeroizing buffer so seed_hex never copies across reallocs.
    let mut serialized = Zeroizing::new(Vec::with_capacity(512));
    serde_json::to_writer(&mut *serialized, &stored)
        .map_err(|e| format!("failed serializing identity.json: {e}"))?;
    serialized.push(b'\n');
    stored.seed_hex.zeroize();
    drop(stored);
    drop(seed_hex);

    match atomic_write_in_dir_no_replace(dir.as_raw_fd(), LAN_IDENTITY_FILE, &serialized, 0o600) {
        Ok(()) => {}
        Err(DaemonError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            // Concurrent writer won the race: reload the winning identity.json atomically.
            let raw = read_strict_0600_file_in_dir(
                dir.as_raw_fd(),
                LAN_IDENTITY_FILE,
                MAX_LAN_IDENTITY_FILE_BYTES,
            )?
            .ok_or_else(|| "LAN identity.json vanished after AlreadyExists".to_string())?;
            return parse_stored_lan_identity(raw, preferred_display_name, &lan_dir);
        }
        Err(e) => return Err(format!("failed writing LAN identity.json: {e}")),
    }

    Ok(LanIdentity {
        account_id: 0,
        is_online_identity: false,
        display_name,
        public_key: pk,
        signing_seed: seed,
        safety_number,
        device_cwt: Vec::new(),
        lan_dir,
    })
}

fn inspect_lan_identity_readonly(
    opts: &GlobalOpts,
    lan_dir_override: Option<&Path>,
) -> Result<(PathBuf, Option<LanIdentity>), String> {
    let lan_dir = resolve_default_lan_dir(lan_dir_override)?;
    if lan_dir_override.is_none()
        && let Some(online) = try_load_online_lan_identity(opts, None, &lan_dir)?
    {
        return Ok((lan_dir, Some(online)));
    }
    let Some(dir_fd) = open_verified_private_dir_readonly(&lan_dir)? else {
        return Ok((lan_dir, None));
    };
    if let Some(raw) = read_strict_0600_file_in_dir(
        dir_fd.as_raw_fd(),
        LAN_IDENTITY_FILE,
        MAX_LAN_IDENTITY_FILE_BYTES,
    )? {
        let id = parse_stored_lan_identity(raw, None, &lan_dir)?;
        return Ok((lan_dir, Some(id)));
    }
    Ok((lan_dir, None))
}

// ---------------------------------------------------------------------------
// 5. Safety Number Pinning & Known Peers Store (Mandate #5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinnedLanPeerEntry {
    pubkey_hex: String,
    account_id: u64,
    display_name: String,
    safety_number: String,
    pinned_at_ms: u64,
    #[serde(default)]
    revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinnedLanPeersFile {
    version: u32,
    peers: Vec<PinnedLanPeerEntry>,
}

impl Default for PinnedLanPeersFile {
    fn default() -> Self {
        Self {
            version: 1,
            peers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerTrustStatus {
    PinnedTrusted,
    RevokedBlocked,
    Unpinned,
}

#[derive(Debug, Clone)]
pub(crate) enum TrustMode {
    InteractiveTty,
    ExpectedSafetyNumber(String),
    #[cfg(test)]
    AlwaysReject,
}

#[derive(Clone)]
struct LanPeerPinStore {
    lan_dir: PathBuf,
    online_state_dir: Option<PathBuf>,
    require_local_auth_on_pin: bool,
    trust_mode: TrustMode,
}

impl LanPeerPinStore {
    fn new(
        lan_dir: PathBuf,
        online_state_dir: Option<PathBuf>,
        require_local_auth_on_pin: bool,
        trust_mode: TrustMode,
    ) -> Self {
        Self {
            lan_dir,
            online_state_dir,
            require_local_auth_on_pin,
            trust_mode,
        }
    }

    fn load_lan_peers_file_from_fd(dir_fd: RawFd) -> Result<PinnedLanPeersFile, String> {
        let Some(raw) =
            read_strict_0600_file_in_dir(dir_fd, LAN_PEERS_FILE, MAX_LAN_PEERS_FILE_BYTES)?
        else {
            return Ok(PinnedLanPeersFile::default());
        };
        let parsed: PinnedLanPeersFile = serde_json::from_slice(&raw)
            .map_err(|e| format!("corrupt {LAN_PEERS_FILE} (fail closed): {e}"))?;
        if parsed.version != 1 {
            return Err(format!("unsupported {LAN_PEERS_FILE} version"));
        }
        Ok(parsed)
    }

    fn load_lan_peers_file(&self) -> Result<PinnedLanPeersFile, String> {
        let Some(dir_fd) = open_verified_private_dir_readonly(&self.lan_dir)? else {
            return Ok(PinnedLanPeersFile::default());
        };
        Self::load_lan_peers_file_from_fd(dir_fd.as_raw_fd())
    }

    fn load_online_peers_readonly(&self) -> Result<Option<PeersStoreRecord>, String> {
        let Some(ref st_path) = self.online_state_dir else {
            return Ok(None);
        };
        let Some(st_fd) = open_verified_private_dir_readonly(st_path)? else {
            return Ok(None);
        };
        let Some(raw) =
            read_strict_0600_file_in_dir(st_fd.as_raw_fd(), PEERS_FILE, MAX_PEERS_BIN_BYTES)?
        else {
            return Ok(None);
        };
        let store = decode_peers_store(&raw)
            .map_err(|e| format!("corrupt {PEERS_FILE} (fail closed): {e}"))?;
        Ok(Some(store))
    }

    fn count_pinned(&self) -> usize {
        self.load_lan_peers_file()
            .map(|f| f.peers.iter().filter(|p| !p.revoked).count())
            .unwrap_or(0)
    }

    fn lookup_peer(&self, account_id: u64, pubkey: &[u8; 32]) -> Result<PeerTrustStatus, String> {
        let expected_sn = compute_lan_safety_number(account_id, pubkey)
            .map_err(|e| format!("invalid peer pubkey: {e}"))?;
        let pk_hex = encode_hex(pubkey);

        let mut revoked = false;
        let mut trusted = false;

        // 1. Check online peers.bin (fail closed on corrupt peers.bin or symlink/insecure state dir).
        if let Some(online_store) = self.load_online_peers_readonly()? {
            for p in &online_store.peers {
                if p.root_pubkey == *pubkey {
                    match p.trust_state {
                        TrustState::RevokedBlocked => revoked = true,
                        TrustState::PinnedTrusted if p.account_id == account_id => trusted = true,
                        TrustState::PinnedTrusted | TrustState::Unpinned => {}
                    }
                }
            }
        }

        // 2. Check dedicated 0600 lan_peers.json.
        let file = self.load_lan_peers_file()?;
        for entry in &file.peers {
            if entry.pubkey_hex == pk_hex {
                if entry.revoked {
                    revoked = true;
                } else if entry.account_id == account_id && entry.safety_number == expected_sn {
                    trusted = true;
                }
            }
        }

        // Revocation in EITHER store ALWAYS dominates PinnedTrusted / Unpinned!
        if revoked {
            return Ok(PeerTrustStatus::RevokedBlocked);
        }
        if trusted {
            return Ok(PeerTrustStatus::PinnedTrusted);
        }
        Ok(PeerTrustStatus::Unpinned)
    }

    fn find_key_change_conflict(
        &self,
        account_id: u64,
        display_name: &str,
        pubkey: &[u8; 32],
    ) -> Result<Option<String>, String> {
        let pk_hex = encode_hex(pubkey);
        let file = self.load_lan_peers_file()?;
        for entry in &file.peers {
            if entry.pubkey_hex != pk_hex {
                if account_id != 0 && entry.account_id == account_id {
                    return Ok(Some(format!(
                        "account_id={account_id} was previously pinned under a DIFFERENT key (SN {})",
                        entry.safety_number
                    )));
                }
                if !display_name.is_empty() && entry.display_name.eq_ignore_ascii_case(display_name)
                {
                    return Ok(Some(format!(
                        "display_name '{}' was previously pinned under a DIFFERENT key (SN {})",
                        entry.display_name, entry.safety_number
                    )));
                }
            }
        }
        if let Some(online_store) = self.load_online_peers_readonly()? {
            for p in &online_store.peers {
                if p.root_pubkey != *pubkey && p.trust_state == TrustState::PinnedTrusted {
                    if account_id != 0 && p.account_id == account_id {
                        return Ok(Some(format!(
                            "online account_id={account_id} is pinned in peers.bin under a DIFFERENT key"
                        )));
                    }
                    if !display_name.is_empty()
                        && !p.handle_prop.is_empty()
                        && p.handle_prop.eq_ignore_ascii_case(display_name)
                    {
                        return Ok(Some(format!(
                            "online peer '{}' is pinned in peers.bin under a DIFFERENT key",
                            sanitize_lan_display_name(&p.handle_prop)
                        )));
                    }
                }
            }
        }
        Ok(None)
    }

    fn pin_peer(
        &self,
        account_id: u64,
        pubkey: &[u8; 32],
        display_name: &str,
        safety_number: &str,
    ) -> Result<(), String> {
        let dir = open_or_create_private_dir(&self.lan_dir)
            .map_err(|e| format!("failed opening LAN dir for pinning: {e}"))?;
        let _lock = StateLock::lock(&dir, Duration::from_secs(5))
            .map_err(|e| format!("failed locking LAN peer store: {e}"))?;
        let mut file = Self::load_lan_peers_file_from_fd(dir.as_raw_fd())?;
        let pk_hex = encode_hex(pubkey);
        let now_ms = wall_now_ms();
        let clean_name = sanitize_lan_display_name(display_name);

        if let Some(existing) = file.peers.iter_mut().find(|p| p.pubkey_hex == pk_hex) {
            if existing.revoked {
                return Err("peer is revoked in lan_peers.json".to_string());
            }
            existing.account_id = account_id;
            existing.display_name = clean_name;
            existing.safety_number = safety_number.to_string();
            existing.pinned_at_ms = now_ms;
        } else {
            if file.peers.len() >= MAX_LAN_PEERS_FILE_BYTES.min(MAX_LAN_PINNED_PEERS) {
                return Err("LAN pinned peers store is full".to_string());
            }
            file.peers.push(PinnedLanPeerEntry {
                pubkey_hex: pk_hex,
                account_id,
                display_name: clean_name,
                safety_number: safety_number.to_string(),
                pinned_at_ms: now_ms,
                revoked: false,
            });
        }

        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| format!("failed serializing {LAN_PEERS_FILE}: {e}"))?;
        atomic_write_in_dir(dir.as_raw_fd(), LAN_PEERS_FILE, &bytes)
            .map_err(|e| format!("failed writing {LAN_PEERS_FILE}: {e}"))
    }

    fn verify_or_pin_peer(
        &self,
        role_label: &str,
        display_name: &str,
        account_id: u64,
        pubkey: &[u8; 32],
        source_addr: &str,
    ) -> Result<String, String> {
        let sn = compute_lan_safety_number(account_id, pubkey)
            .map_err(|e| format!("invalid peer Ed25519 pubkey: {e}"))?;
        match self.lookup_peer(account_id, pubkey)? {
            PeerTrustStatus::PinnedTrusted => return Ok(sn),
            PeerTrustStatus::RevokedBlocked => {
                return Err(format!(
                    "refusing revoked peer '{}' (Safety Number {sn})",
                    sanitize_lan_display_name(display_name)
                ));
            }
            PeerTrustStatus::Unpinned => {}
        }

        let clean_name = sanitize_lan_display_name(display_name);
        let pk_b64u = encode_lan_pubkey_base64url(pubkey);
        let key_change_warning =
            self.find_key_change_conflict(account_id, &clean_name, pubkey)?;

        // G3-L3-1: Hold ONE non-reentrant TtyPromptPauseGuard across the ENTIRE unpinned
        // prompt + local OS presence authentication sequence so spawn_stdin_line_reader can
        // NEVER wake between them and steal a sudo password into LAN chat!
        let needs_tty_guard =
            matches!(self.trust_mode, TrustMode::InteractiveTty) || self.require_local_auth_on_pin;
        let pause_guard = needs_tty_guard.then(TtyPromptPauseGuard::acquire);

        let approved = match &self.trust_mode {
            TrustMode::ExpectedSafetyNumber(candidate) => {
                if !verify_safety_number(account_id, pubkey, candidate) {
                    return Err(format!(
                        "--yes-safety-number mismatch for {role_label} '{clean_name}' (computed {sn})"
                    ));
                }
                true
            }
            #[cfg(test)]
            TrustMode::AlwaysReject => false,
            TrustMode::InteractiveTty => {
                let Some(ref pause) = pause_guard else {
                    return Err("internal error: missing TTY prompt pause guard".to_string());
                };
                prompt_tty_safety_number_confirm_paused(
                    pause,
                    role_label,
                    &clean_name,
                    account_id,
                    &pk_b64u,
                    &sn,
                    source_addr,
                    key_change_warning.as_deref(),
                    Some(LAN_APPROVAL_TIMEOUT),
                )?
            }
        };

        if !approved {
            return Err(format!(
                "unpinned {role_label} '{clean_name}' (Safety Number {sn}) rejected"
            ));
        }

        // Mandate #6: enforce local OS presence guard under the SAME TtyPromptPauseGuard
        // before pinning a new LAN peer when configured.
        if self.require_local_auth_on_pin {
            let Some(ref pause) = pause_guard else {
                return Err("internal error: missing TTY prompt pause guard".to_string());
            };
            verify_local_os_presence_paused(pause, "Authorize pinning new LAN Party peer")?;
        }

        drop(pause_guard);

        self.pin_peer(account_id, pubkey, &clean_name, &sn)?;
        Ok(sn)
    }
}

static TTY_PROMPT_ACTIVE: AtomicBool = AtomicBool::new(false);
static STDIN_READ_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Non-reentrant RAII guard that pauses `spawn_stdin_line_reader` across `/dev/tty` prompts
/// and local OS presence checks (`LAContext` / `sudo -k -v`).
struct TtyPromptPauseGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl TtyPromptPauseGuard {
    fn acquire() -> Self {
        TTY_PROMPT_ACTIVE.store(true, Ordering::Release);
        let guard = STDIN_READ_GATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self { _lock: guard }
    }
}

impl Drop for TtyPromptPauseGuard {
    fn drop(&mut self) {
        TTY_PROMPT_ACTIVE.store(false, Ordering::Release);
    }
}

#[allow(clippy::too_many_arguments)]
fn prompt_tty_safety_number_confirm_paused(
    _pause: &TtyPromptPauseGuard,
    role_label: &str,
    display_name: &str,
    account_id: u64,
    pk_b64u: &str,
    safety_number: &str,
    source_addr: &str,
    key_change_warning: Option<&str>,
    timeout: Option<Duration>,
) -> Result<bool, String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            format!(
                "unpinned {role_label} '{display_name}' (Safety Number {safety_number}) requires interactive /dev/tty confirmation or --yes-safety-number <SN>"
            )
        })?;
    // Flush any pre-typed chat bytes immediately after acquiring TtyPromptPauseGuard and
    // BEFORE writing the trust prompt so queued input cannot accidentally confirm a peer.
    unsafe {
        let _ = libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH);
    }
    let acct_label = if account_id == 0 {
        "local-only".to_string()
    } else {
        account_id.to_string()
    };
    let warning_block = match key_change_warning {
        Some(detail) => format!(
            "\n[WARNING: KEY CHANGED] {detail}\n  Verify this peer's Safety Number out-of-band before trusting!"
        ),
        None => String::new(),
    };
    let banner = format!(
        "{warning_block}\n[LAN Trust Check] Unpinned {role_label} attempting connection:\n  Name:          {display_name}\n  Account ID:    {acct_label}\n  Source:        {source_addr}\n  Host/Peer PK:  {pk_b64u}\n  Safety Number: {safety_number}\nType 'yes' to trust and pin this peer (anything else rejects): "
    );
    tty.write_all(banner.as_bytes())
        .map_err(|e| format!("failed writing trust prompt to /dev/tty: {e}"))?;
    tty.flush()
        .map_err(|e| format!("failed flushing /dev/tty: {e}"))?;

    let raw_line = match read_line_unbuffered_fd_timeout(tty.as_raw_fd(), 64, timeout) {
        Ok(line) => line,
        Err(e) => {
            let _ = tty.write_all(b"\n[LAN Trust Check] confirmation aborted/timed out.\n");
            let _ = tty.flush();
            return Err(format!("failed reading confirmation from /dev/tty: {e}"));
        }
    };
    Ok(raw_line.trim().eq_ignore_ascii_case("yes"))
}

// ---------------------------------------------------------------------------
// 6. Local IPv4 Enumeration & Zero-Dep Opt-In UDP Multicast mDNS
// ---------------------------------------------------------------------------

fn lan_ipv4_priority(ip: Ipv4Addr) -> u8 {
    let [a, b, _, _] = ip.octets();
    if a == 192 && b == 168 {
        return 0;
    }
    if a == 10 {
        return 1;
    }
    if a == 172 && (16..=31).contains(&b) {
        return 2;
    }
    if a == 100 && (64..=127).contains(&b) {
        return 3;
    }
    if a == 169 && b == 254 {
        return 5;
    }
    4
}

fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0 || a == 127 || (a & 0xf0) == 0xe0 || (a == 255 && b == 255 && c == 255 && d == 255))
}

pub(crate) fn enumerate_lan_ipv4_addrs(service_port: u16) -> Vec<SocketAddr> {
    let mut non_link_local: Vec<(u8, Ipv4Addr)> = Vec::new();
    let mut link_local: Vec<Ipv4Addr> = Vec::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) == 0 && !ifap.is_null() {
            let mut cur = ifap;
            while !cur.is_null() {
                let ifa = &*cur;
                let flags = ifa.ifa_flags as i32;
                let is_up = (flags & libc::IFF_UP) != 0;
                let is_loopback = (flags & libc::IFF_LOOPBACK) != 0;
                if is_up && !is_loopback && !ifa.ifa_addr.is_null() {
                    let family = i32::from((*ifa.ifa_addr).sa_family);
                    if family == libc::AF_INET {
                        let sin = &*(ifa.ifa_addr.cast::<libc::sockaddr_in>());
                        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        if is_usable_lan_ipv4(ip) {
                            let prio = lan_ipv4_priority(ip);
                            if prio == 5 {
                                if !link_local.contains(&ip) {
                                    link_local.push(ip);
                                }
                            } else if !non_link_local.iter().any(|(_, existing)| *existing == ip) {
                                non_link_local.push((prio, ip));
                            }
                        }
                    }
                }
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }

    non_link_local.sort_by_key(|(prio, ip)| (*prio, ip.octets()));
    let mut out: Vec<SocketAddr> = Vec::new();
    for (_, ip) in non_link_local {
        if out.len() >= LAN_MDNS_MAX_DIRECT_ADDRS {
            break;
        }
        out.push(SocketAddr::new(IpAddr::V4(ip), service_port));
    }
    if out.is_empty() {
        for ip in link_local {
            if out.len() >= LAN_MDNS_MAX_DIRECT_ADDRS {
                break;
            }
            out.push(SocketAddr::new(IpAddr::V4(ip), service_port));
        }
    }
    out
}

fn open_mdns_udp_socket(
    bind_ip: Ipv4Addr,
    bind_port: u16,
    mcast_group: Ipv4Addr,
    enable_multicast: bool,
) -> Result<UdpSocket, String> {
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw_fd < 0 {
        return Err(format!(
            "failed creating mDNS UDP socket: {}",
            io::Error::last_os_error()
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    unsafe {
        let fd_flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFD, 0);
        if fd_flags < 0
            || libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) < 0
        {
            return Err(format!(
                "failed setting FD_CLOEXEC on mDNS socket: {}",
                io::Error::last_os_error()
            ));
        }
        let fl_flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL, 0);
        if fl_flags < 0
            || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl_flags | libc::O_NONBLOCK) < 0
        {
            return Err(format!(
                "failed setting O_NONBLOCK on mDNS socket: {}",
                io::Error::last_os_error()
            ));
        }

        let one: libc::c_int = 1;
        if libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(format!(
                "setsockopt(SO_REUSEADDR) failed: {}",
                io::Error::last_os_error()
            ));
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        if enable_multicast
            && libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
        {
            return Err(format!(
                "setsockopt(SO_REUSEPORT) failed: {}",
                io::Error::last_os_error()
            ));
        }

        let mut bind_sa: libc::sockaddr_in = std::mem::zeroed();
        bind_sa.sin_family = libc::AF_INET as libc::sa_family_t;
        bind_sa.sin_addr = libc::in_addr {
            s_addr: u32::from(bind_ip).to_be(),
        };
        bind_sa.sin_port = bind_port.to_be();
        if libc::bind(
            fd.as_raw_fd(),
            (&bind_sa as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            return Err(format!(
                "bind({bind_ip}:{bind_port}) failed: {}",
                io::Error::last_os_error()
            ));
        }

        if enable_multicast {
            #[cfg(target_os = "macos")]
            {
                let ttl: u8 = 255;
                let _ = libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_MULTICAST_TTL,
                    (&ttl as *const u8).cast(),
                    std::mem::size_of::<u8>() as libc::socklen_t,
                );
                let loop_on: u8 = 1;
                let _ = libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_MULTICAST_LOOP,
                    (&loop_on as *const u8).cast(),
                    std::mem::size_of::<u8>() as libc::socklen_t,
                );
            }
            #[cfg(not(target_os = "macos"))]
            {
                let ttl: libc::c_int = 255;
                let _ = libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_MULTICAST_TTL,
                    (&ttl as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                let loop_on: libc::c_int = 1;
                let _ = libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_MULTICAST_LOOP,
                    (&loop_on as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            let mreq = libc::ip_mreq {
                imr_multiaddr: libc::in_addr {
                    s_addr: u32::from(mcast_group).to_be(),
                },
                imr_interface: libc::in_addr {
                    s_addr: u32::from(bind_ip).to_be(),
                },
            };
            if libc::setsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                (&mreq as *const libc::ip_mreq).cast(),
                std::mem::size_of::<libc::ip_mreq>() as libc::socklen_t,
            ) != 0
            {
                return Err(format!(
                    "setsockopt(IP_ADD_MEMBERSHIP {mcast_group}) failed: {}",
                    io::Error::last_os_error()
                ));
            }
        }
    }

    let std_sock = std::net::UdpSocket::from(fd);
    UdpSocket::from_std(std_sock).map_err(|e| format!("failed registering mDNS socket: {e}"))
}

fn mdns_multicast_dest() -> SocketAddr {
    let ip = LAN_MDNS_MULTICAST_GROUP
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::new(224, 0, 0, 251));
    SocketAddr::new(IpAddr::V4(ip), LAN_MDNS_DEFAULT_PORT)
}

fn is_valid_mdns_unicast_target(addr: SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip().to_canonical() {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    }
}

struct MdnsAdvertiserHandle {
    stop_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MdnsAdvertiserHandle {
    fn start(
        beacon: LanBeaconRecord,
        service_port: u16,
        addrs: Vec<SocketAddr>,
    ) -> Result<Self, String> {
        let mcast_dest = mdns_multicast_dest();
        let mcast_ip = match mcast_dest.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => Ipv4Addr::new(224, 0, 0, 251),
        };
        let sock = open_mdns_udp_socket(
            Ipv4Addr::UNSPECIFIED,
            LAN_MDNS_DEFAULT_PORT,
            mcast_ip,
            true,
        )?;

        let ann = LanMdnsAnnouncement {
            beacon: beacon.clone(),
            service_port,
            addrs: addrs.clone(),
            ttl_sec: LAN_MDNS_DEFAULT_TTL_SEC,
        };
        let announce_pkt = encode_lan_announcement(&ann)
            .map_err(|e| format!("failed encoding mDNS announcement: {e}"))?;
        let goodbye_pkt = encode_lan_goodbye(&beacon, service_port, &addrs)
            .map_err(|e| format!("failed encoding mDNS goodbye: {e}"))?;

        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = sock.send_to(&announce_pkt, mcast_dest).await;
            let mut interval = tokio::time::interval(LAN_MDNS_REANNOUNCE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // consume immediate first tick

            let mut last_mcast_reply: Option<Instant> = None;
            let mut last_unicast_reply: HashMap<IpAddr, Instant> = HashMap::new();
            let mut recv_buf = vec![0u8; LAN_MDNS_MAX_PACKET_BYTES];
            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        let _ = sock.send_to(&goodbye_pkt, mcast_dest).await;
                        tokio::time::sleep(Duration::from_millis(15)).await;
                        let _ = sock.send_to(&goodbye_pkt, mcast_dest).await;
                        break;
                    }
                    _ = interval.tick() => {
                        let _ = sock.send_to(&announce_pkt, mcast_dest).await;
                    }
                    res = sock.recv_from(&mut recv_buf) => {
                        if let Ok((n, src)) = res
                            && let Some(pkt_bytes) = recv_buf.get(..n)
                            && let Ok(pkt) = decode_lan_mdns_packet(pkt_bytes)
                            && !pkt.is_response
                        {
                            for q in &pkt.questions {
                                if q.qclass == DNS_CLASS_IN
                                    && (q.qtype == DNS_TYPE_PTR || q.qtype == DNS_TYPE_ANY)
                                    && dns_names_equal_ci(&q.qname, LAN_MDNS_SERVICE_TYPE)
                                {
                                    let now = Instant::now();
                                    if q.unicast_response {
                                        if !is_valid_mdns_unicast_target(src) {
                                            break;
                                        }
                                        let src_ip = src.ip().to_canonical();
                                        if last_unicast_reply
                                            .get(&src_ip)
                                            .is_some_and(|t| now.duration_since(*t) < LAN_MDNS_REPLY_COOLDOWN)
                                        {
                                            break;
                                        }
                                        if last_unicast_reply.len() >= MAX_MDNS_UNICAST_COOLDOWN_ENTRIES {
                                            last_unicast_reply.retain(|_, t| {
                                                now.duration_since(*t) < LAN_MDNS_REPLY_COOLDOWN
                                            });
                                        }
                                        if last_unicast_reply.len() >= MAX_MDNS_UNICAST_COOLDOWN_ENTRIES
                                            && !last_unicast_reply.contains_key(&src_ip)
                                        {
                                            break;
                                        }
                                        last_unicast_reply.insert(src_ip, now);
                                        let _ = sock.send_to(&announce_pkt, src).await;
                                    } else {
                                        if last_mcast_reply
                                            .is_some_and(|t| now.duration_since(t) < LAN_MDNS_REPLY_COOLDOWN)
                                        {
                                            break;
                                        }
                                        last_mcast_reply = Some(now);
                                        let _ = sock.send_to(&announce_pkt, mcast_dest).await;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            drop(sock);
        });

        Ok(Self {
            stop_tx: Some(stop_tx),
            task: Some(task),
        })
    }

    async fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;
        }
    }
}

impl Drop for MdnsAdvertiserHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DiscoveredLobby {
    pub beacon: LanBeaconRecord,
    pub service_port: u16,
    pub addrs: Vec<SocketAddr>,
    pub safety_number: String,
    pub last_seen_ms: u64,
}

async fn scan_lan_mdns(
    timeout_sec: u32,
    stop_on_party_id: Option<&str>,
) -> Result<Vec<DiscoveredLobby>, String> {
    let mcast_dest = mdns_multicast_dest();
    let mcast_ip = match mcast_dest.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::new(224, 0, 0, 251),
    };

    let (sock, unicast_query) =
        match open_mdns_udp_socket(Ipv4Addr::UNSPECIFIED, LAN_MDNS_DEFAULT_PORT, mcast_ip, true) {
            Ok(s) => (s, false),
            Err(_) => {
                // Fallback for restricted ports: bind ephemeral port and request QU unicast replies.
                let s = open_mdns_udp_socket(Ipv4Addr::UNSPECIFIED, 0, mcast_ip, true)?;
                (s, true)
            }
        };

    let query_pkt = encode_lan_ptr_query(unicast_query)
        .map_err(|e| format!("failed encoding mDNS PTR query: {e}"))?;
    let _ = sock.send_to(&query_pkt, mcast_dest).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(u64::from(timeout_sec));
    let mut re_query = tokio::time::interval(LAN_MDNS_SCAN_QUERY_INTERVAL);
    re_query.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    re_query.tick().await;

    let mut lobbies: BTreeMap<String, DiscoveredLobby> = BTreeMap::new();
    let mut recv_buf = vec![0u8; LAN_MDNS_MAX_PACKET_BYTES];

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let sleep_rem = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep_rem);

        tokio::select! {
            _ = &mut sleep_rem => {
                break;
            }
            _ = re_query.tick() => {
                let _ = sock.send_to(&query_pkt, mcast_dest).await;
            }
            res = sock.recv_from(&mut recv_buf) => {
                if let Ok((n, src)) = res
                    && let Some(pkt_bytes) = recv_buf.get(..n)
                    && let Ok(pkt) = decode_lan_mdns_packet(pkt_bytes)
                    && pkt.is_response
                {
                    for gid in &pkt.goodbye_party_ids {
                        lobbies.remove(gid);
                    }
                    if let Some(ann) = pkt.announcement {
                        if ann.is_goodbye() {
                            lobbies.remove(&ann.beacon.lan_party_id);
                        } else if let Ok(sn) = compute_lan_safety_number(0, &ann.beacon.host_pubkey) {
                            let id = ann.beacon.lan_party_id.clone();
                            let is_target = stop_on_party_id == Some(id.as_str());
                            if !is_target
                                && !lobbies.contains_key(&id)
                                && lobbies.len() >= MAX_DISCOVERED_LAN_LOBBIES
                            {
                                continue;
                            }
                            let mut addrs = ann.addrs;
                            if addrs.is_empty() && ann.service_port != 0 {
                                let fallback = SocketAddr::new(src.ip(), ann.service_port);
                                if !fallback.ip().is_unspecified() && !fallback.ip().is_multicast() {
                                    addrs.push(fallback);
                                }
                            }
                            lobbies.insert(
                                id.clone(),
                                DiscoveredLobby {
                                    beacon: ann.beacon,
                                    service_port: ann.service_port,
                                    addrs,
                                    safety_number: sn,
                                    last_seen_ms: wall_now_ms(),
                                },
                            );
                            if is_target {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    drop(sock);
    Ok(lobbies.into_values().collect())
}

// ---------------------------------------------------------------------------
// 7. Wire Helpers & Interactive Session Primitives
// ---------------------------------------------------------------------------

fn now_unix_ns() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(dur.as_nanos()).unwrap_or(i64::MAX)
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default().to_string()
}

fn sanitize_bounded(raw: &str, max_bytes: usize) -> String {
    let clean = sanitize_peer_text(raw);
    truncate_utf8(&clean, max_bytes)
}

fn random_nonce_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = fill_random(&mut b);
    u64::from_le_bytes(b)
}

fn emit_jsonl(val: &Value) {
    if let Ok(line) = serde_json::to_string(val) {
        println!("{line}");
        let _ = io::stdout().flush();
    }
}

fn members_to_json(members: &[LanMemberInfo]) -> Value {
    let arr: Vec<Value> = members
        .iter()
        .map(|m| {
            let sn = compute_lan_safety_number(m.account_id, &m.pubkey).unwrap_or_default();
            json!({
                "account_id": m.account_id,
                "display_name": m.display_name,
                "pubkey_b64u": encode_lan_pubkey_base64url(&m.pubkey),
                "safety_number": sn,
                "is_host": m.is_host,
            })
        })
        .collect();
    Value::Array(arr)
}

/// Spawns a blocking thread reading UTF-8 lines from `STDIN_FILENO` (using `poll` +
/// unbuffered byte-by-byte reads coordinated with `TTY_PROMPT_ACTIVE` so interactive
/// `/dev/tty` trust prompts never race with the chat stdin reader).
fn spawn_stdin_line_reader() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut line_bytes = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            if TTY_PROMPT_ACTIVE.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let mut pfd = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, 25) };
            if prc == 0 {
                continue;
            }
            if prc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) == 0
            {
                continue;
            }
            let _gate = STDIN_READ_GATE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if TTY_PROMPT_ACTIVE.load(Ordering::Acquire) {
                continue;
            }
            let n = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
            drop(_gate);
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if n == 0 {
                if !line_bytes.is_empty() {
                    let mut text = String::from_utf8_lossy(&line_bytes).into_owned();
                    strip_crlf(&mut text);
                    let _ = tx.send(text);
                }
                break;
            }
            if byte[0] == b'\n' {
                let mut text = String::from_utf8_lossy(&line_bytes).into_owned();
                strip_crlf(&mut text);
                line_bytes.clear();
                if tx.send(text).is_err() {
                    break;
                }
            } else if line_bytes.len() < MAX_CHAT_BODY_BYTES {
                line_bytes.push(byte[0]);
            }
        }
    });
    rx
}

// ---------------------------------------------------------------------------
// 8. Core In-TLS `mp1-lan/1` Host & Joiner Session Engines
// ---------------------------------------------------------------------------

struct PendingLanPeer {
    host_nonce: [u8; 32],
    connected_at: Instant,
    source_ip: String,
    awaiting_approval: bool,
}

#[derive(Clone)]
struct PendingApprovalRequest {
    peer_pubkey: [u8; 32],
    account_id: u64,
    display_name: String,
    source_ip: String,
    peer_key: LanPinPeerKey,
}

pub(crate) struct CompletedApproval {
    req: PendingApprovalRequest,
    result: Result<String, String>,
}

pub(crate) enum HostInput {
    Transport(P2pTransportEvent),
    Approval(CompletedApproval),
}

#[derive(Debug, Clone)]
pub(crate) enum LanSessionEvent {
    PeerJoined {
        member: LanMemberInfo,
        safety_number: String,
        roster_epoch: u64,
        members: Vec<LanMemberInfo>,
    },
    PeerRejected {
        peer_pubkey: [u8; 32],
        reason: String,
    },
    PeerLeft {
        member: LanMemberInfo,
        reason_code: u32,
        roster_epoch: u64,
        members: Vec<LanMemberInfo>,
    },
    RosterUpdated {
        roster_epoch: u64,
        locked: bool,
        members: Vec<LanMemberInfo>,
    },
    ChatReceived {
        peer_pubkey: [u8; 32],
        chat: P2pChatMessage,
    },
    BridgeReceived {
        peer_pubkey: [u8; 32],
        envelope: P2pBridgeEnvelope,
    },
    PulseReceived {
        peer_pubkey: [u8; 32],
        sender_name: String,
        pulse: P2pEphemeralPulse,
    },
    ControlNoticeReceived {
        peer_pubkey: [u8; 32],
        notice: P2pControlNotice,
    },
    LobbyLocked {
        roster_epoch: u64,
    },
    LobbyClosed {
        reason: String,
    },
}

pub(crate) struct LanHostConfig {
    pub identity: LanIdentity,
    pub lobby_name: String,
    pub require_pin: bool,
    pub pin: Option<Zeroizing<String>>,
    pub idle_timeout_sec: u32,
    pub enable_mdns: bool,
    pub start_locked: bool,
    pub bind_port: Option<u16>,
    pub max_members: u8,
    pub pin_rate_limit: LanPinRateLimitConfig,
    pub online_state_dir: Option<PathBuf>,
    pub require_local_auth_on_pin: bool,
    pub trust_mode: TrustMode,
}

pub(crate) struct LanHostSession {
    identity: LanIdentity,
    lan_party_id: String,
    lobby_name: String,
    require_pin: bool,
    pin: Option<Zeroizing<String>>,
    max_members: usize,
    idle_timeout_sec: u32,
    idle_deadline: Option<Instant>,
    mdns_deadline: Option<Instant>,
    locked: bool,
    lobby_closed: bool,
    service_port: u16,
    direct_addrs: Vec<SocketAddr>,
    handle: Arc<PartyP2pHandle>,
    events: P2pEventStream,
    mdns: Option<MdnsAdvertiserHandle>,
    pin_store: LanPeerPinStore,
    pin_limiter: LanPinRateLimiter,
    pending_peers: HashMap<[u8; 32], PendingLanPeer>,
    approval_queue: VecDeque<PendingApprovalRequest>,
    approval_in_flight: Option<[u8; 32]>,
    approval_tx: mpsc::Sender<CompletedApproval>,
    approval_rx: mpsc::Receiver<CompletedApproval>,
    members: Vec<LanMemberInfo>,
    roster_epoch: u64,
}

impl LanHostSession {
    pub(crate) async fn start(cfg: LanHostConfig) -> Result<Self, String> {
        let lobby_name = sanitize_lan_display_name(&cfg.lobby_name);
        if !is_valid_lan_name(&lobby_name) {
            return Err("invalid LAN lobby name".to_string());
        }
        let max_members = usize::from(cfg.max_members);
        if max_members == 0 || max_members > LAN_MAX_MEMBERS {
            return Err(format!("max_members must be in 1..={LAN_MAX_MEMBERS}"));
        }
        if cfg.require_pin {
            let Some(ref p) = cfg.pin else {
                return Err("LAN PIN is required by policy or --require-pin".to_string());
            };
            validate_lan_pin(p).map_err(|_| "invalid LAN PIN".to_string())?;
        }

        let mut id_bytes = [0u8; LAN_PARTY_ID_BYTES];
        fill_random(&mut id_bytes).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let lan_party_id = format_lan_party_id_hex(&id_bytes);

        let transport = PartyP2pTransport::spawn_with_lan(
            PartyP2pConfig {
                local_device_id: if cfg.identity.account_id == 0 {
                    1
                } else {
                    cfg.identity.account_id
                },
                device_secret: *cfg.identity.signing_seed,
                effective_relay_policy: RelayPolicy::NoRelays,
                pinned_relay_url: None,
            },
            Some(LanTransportConfig {
                no_relays: true,
                lan_open_admission: !cfg.start_locked,
                lan_bind_port: cfg.bind_port,
            }),
        )
        .await
        .map_err(|e| format!("failed starting LAN P2P transport: {e}"))?;

        let (handle, events) = transport.split();
        let bound_direct = handle.local_direct_addrs();
        let service_port = bound_direct
            .iter()
            .find_map(|a| (a.port() != 0).then_some(a.port()))
            .ok_or_else(|| "LAN P2P endpoint bound no UDP port".to_string())?;

        let mut direct_addrs = enumerate_lan_ipv4_addrs(service_port);
        if direct_addrs.is_empty() {
            direct_addrs = bound_direct;
        }
        if direct_addrs.is_empty() {
            direct_addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), service_port));
        }

        let mdns = if cfg.enable_mdns && !cfg.start_locked {
            let beacon = LanBeaconRecord {
                version: LAN_BEACON_VERSION,
                lan_party_id: lan_party_id.clone(),
                lobby_name: lobby_name.clone(),
                host_name: cfg.identity.display_name.clone(),
                host_pubkey: cfg.identity.public_key,
                require_pin: cfg.require_pin,
                alpn: LAN_BEACON_ALPN.to_string(),
            };
            match MdnsAdvertiserHandle::start(beacon, service_port, direct_addrs.clone()) {
                Ok(h) => Some(h),
                Err(e) => {
                    handle.close().await;
                    return Err(format!("failed starting mDNS advertiser: {e}"));
                }
            }
        } else {
            None
        };

        let pin_store = LanPeerPinStore::new(
            cfg.identity.lan_dir.clone(),
            cfg.online_state_dir,
            cfg.require_local_auth_on_pin,
            cfg.trust_mode,
        );

        let host_member = LanMemberInfo {
            account_id: cfg.identity.account_id,
            display_name: cfg.identity.display_name.clone(),
            pubkey: cfg.identity.public_key,
            is_host: true,
        };

        let now = Instant::now();
        let idle_dur = Duration::from_secs(u64::from(cfg.idle_timeout_sec));
        let mdns_deadline = mdns.as_ref().map(|_| now + idle_dur);
        let idle_deadline = Some(now + idle_dur);
        let (approval_tx, approval_rx) = mpsc::channel(4);

        Ok(Self {
            identity: cfg.identity,
            lan_party_id,
            lobby_name,
            require_pin: cfg.require_pin,
            pin: cfg.pin,
            max_members,
            idle_timeout_sec: cfg.idle_timeout_sec,
            idle_deadline,
            mdns_deadline,
            locked: cfg.start_locked,
            lobby_closed: false,
            service_port,
            direct_addrs,
            handle,
            events,
            mdns,
            pin_store,
            pin_limiter: LanPinRateLimiter::new(cfg.pin_rate_limit),
            pending_peers: HashMap::new(),
            approval_queue: VecDeque::new(),
            approval_in_flight: None,
            approval_tx,
            approval_rx,
            members: vec![host_member],
            roster_epoch: 1,
        })
    }

    pub(crate) fn lan_party_id(&self) -> &str {
        &self.lan_party_id
    }

    pub(crate) fn lobby_name(&self) -> &str {
        &self.lobby_name
    }

    pub(crate) fn service_port(&self) -> u16 {
        self.service_port
    }

    pub(crate) fn direct_addrs(&self) -> &[SocketAddr] {
        &self.direct_addrs
    }

    pub(crate) fn loopback_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.service_port)
    }

    pub(crate) fn members(&self) -> &[LanMemberInfo] {
        &self.members
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.lobby_closed
    }

    pub(crate) fn idle_deadline(&self) -> Option<Instant> {
        self.idle_deadline
    }

    pub(crate) fn mdns_deadline(&self) -> Option<Instant> {
        self.mdns_deadline
    }

    pub(crate) async fn stop_mdns(&mut self) {
        if let Some(ref mut mdns) = self.mdns {
            mdns.stop().await;
        }
        self.mdns = None;
        self.mdns_deadline = None;
    }

    fn find_member(&self, pubkey: &[u8; 32]) -> Option<&LanMemberInfo> {
        self.members.iter().find(|m| &m.pubkey == pubkey)
    }

    fn has_display_name_collision(&self, clean_name: &str) -> bool {
        self.members
            .iter()
            .any(|m| m.display_name.eq_ignore_ascii_case(clean_name))
    }

    async fn reject_pending(&mut self, peer_pubkey: [u8; 32], reason: &str) -> LanSessionEvent {
        self.pending_peers.remove(&peer_pubkey);
        self.approval_queue.retain(|r| r.peer_pubkey != peer_pubkey);
        let welcome = LanHandshakeMessage::Welcome(LanWelcomeMessage {
            lan_party_id: self.lan_party_id.clone(),
            accepted: false,
            reason: reason.to_string(),
            roster_epoch: self.roster_epoch,
            members: Vec::new(),
        });
        if self
            .handle
            .send_lan_handshake(peer_pubkey, &welcome)
            .await
            .is_ok()
        {
            tokio::time::sleep(LAN_REJECT_FLUSH_GRACE).await;
        }
        self.handle.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
        LanSessionEvent::PeerRejected {
            peer_pubkey,
            reason: reason.to_string(),
        }
    }

    async fn admit_pending_peer(
        &mut self,
        peer_pubkey: [u8; 32],
        account_id: u64,
        clean_name: String,
        safety_number: String,
        peer_key: &LanPinPeerKey,
    ) -> LanSessionEvent {
        // Promote peer in iroh allowlist (unlocks Lanes 1 & 2) and admit!
        if self.handle.allow_peer(peer_pubkey).await.is_err() {
            return self.reject_pending(peer_pubkey, "rejected").await;
        }

        self.pin_limiter.record_success(peer_key);
        self.pending_peers.remove(&peer_pubkey);
        self.idle_deadline = None;

        let member = LanMemberInfo {
            account_id,
            display_name: clean_name,
            pubkey: peer_pubkey,
            is_host: false,
        };
        self.members.push(member.clone());
        self.roster_epoch = self.roster_epoch.saturating_add(1);

        let welcome = LanHandshakeMessage::Welcome(LanWelcomeMessage {
            lan_party_id: self.lan_party_id.clone(),
            accepted: true,
            reason: String::new(),
            roster_epoch: self.roster_epoch,
            members: self.members.clone(),
        });
        let _ = self.handle.send_lan_handshake(peer_pubkey, &welcome).await;
        self.broadcast_roster(Some(peer_pubkey)).await;

        LanSessionEvent::PeerJoined {
            member,
            safety_number,
            roster_epoch: self.roster_epoch,
            members: self.members.clone(),
        }
    }

    fn maybe_start_next_approval(&mut self) {
        while self.approval_in_flight.is_none() {
            let Some(req) = self.approval_queue.pop_front() else {
                break;
            };
            if self.lobby_closed
                || self.locked
                || !self.pending_peers.contains_key(&req.peer_pubkey)
                || !self.handle.is_peer_connected(&req.peer_pubkey)
            {
                self.pending_peers.remove(&req.peer_pubkey);
                continue;
            }
            self.approval_in_flight = Some(req.peer_pubkey);
            let pin_store = self.pin_store.clone();
            let tx = self.approval_tx.clone();
            tokio::spawn(async move {
                let req_blocking = req.clone();
                let blocking = tokio::task::spawn_blocking(move || {
                    pin_store.verify_or_pin_peer(
                        "LAN joiner",
                        &req_blocking.display_name,
                        req_blocking.account_id,
                        &req_blocking.peer_pubkey,
                        &req_blocking.source_ip,
                    )
                });
                let result = match tokio::time::timeout(LAN_APPROVAL_TIMEOUT, blocking).await {
                    Ok(Ok(res)) => res,
                    Ok(Err(join_err)) => Err(format!("peer approval task failed: {join_err}")),
                    Err(_) => Err("peer approval timed out (30s)".to_string()),
                };
                let _ = tx.send(CompletedApproval { req, result }).await;
            });
        }
    }

    async fn broadcast_roster(&self, exclude_pubkey: Option<[u8; 32]>) {
        let roster = LanHandshakeMessage::Roster(LanRosterMessage {
            lan_party_id: self.lan_party_id.clone(),
            roster_epoch: self.roster_epoch,
            locked: self.locked,
            members: self.members.clone(),
        });
        for m in &self.members {
            if m.is_host || Some(m.pubkey) == exclude_pubkey {
                continue;
            }
            let _ = self.handle.send_lan_handshake(m.pubkey, &roster).await;
        }
    }

    pub(crate) async fn lock_lobby(&mut self) -> LanSessionEvent {
        self.locked = true;
        self.stop_mdns().await;
        self.handle.set_lan_open_admission(false).await;
        self.approval_queue.clear();
        let pending_keys: Vec<[u8; 32]> = self.pending_peers.keys().copied().collect();
        for pk in pending_keys {
            let _ = self.reject_pending(pk, "locked").await;
        }
        if self.members.len() <= 1 && self.idle_deadline.is_none() {
            self.idle_deadline =
                Some(Instant::now() + Duration::from_secs(u64::from(self.idle_timeout_sec)));
        }
        self.roster_epoch = self.roster_epoch.saturating_add(1);
        self.broadcast_roster(None).await;
        LanSessionEvent::LobbyLocked {
            roster_epoch: self.roster_epoch,
        }
    }

    pub(crate) async fn send_chat(&self, body: &str) -> Result<(), String> {
        let clean_body = sanitize_bounded(body, MAX_CHAT_BODY_BYTES);
        if let Some(kind) = scan_outbound_secrets(
            clean_body.as_bytes(),
            &self.identity.signing_seed,
            &self.identity.device_cwt,
        ) {
            return Err(format!(
                "blocked outbound message: detected secret material ({kind:?})"
            ));
        }
        if let Some(ref pin) = self.pin
            && !pin.is_empty()
        {
            let normalizer = ComposingNormalizerBorrowed::new_nfc();
            let normalized_body = normalizer.normalize(&clean_body);
            if clean_body.contains(pin.as_str())
                || body.contains(pin.as_str())
                || normalized_body.contains(pin.as_str())
            {
                return Err(
                    "blocked outbound message: contains active LAN lobby PIN".to_string(),
                );
            }
        }
        let frame = P2pPartyFrame::ChatMessage(P2pChatMessage {
            room_scope: LAN_DEFAULT_ROOM_SCOPE.to_string(),
            target_selector: "@all".to_string(),
            sender_handle: self.identity.display_name.clone(),
            timestamp_ns: now_unix_ns(),
            body: clean_body,
        });
        for m in &self.members {
            if m.is_host {
                continue;
            }
            let _ = self.handle.send_frame(m.pubkey, &frame).await;
        }
        Ok(())
    }

    pub(crate) async fn shutdown(&mut self, reason: &str) -> LanSessionEvent {
        self.lobby_closed = true;
        self.stop_mdns().await;
        self.approval_queue.clear();
        self.pin = None;
        let _ = tokio::time::timeout(Duration::from_millis(500), self.handle.close()).await;
        LanSessionEvent::LobbyClosed {
            reason: reason.to_string(),
        }
    }

    async fn evict_stalled_pending(&mut self) -> Vec<LanSessionEvent> {
        let now = Instant::now();
        let stalled: Vec<[u8; 32]> = self
            .pending_peers
            .iter()
            .filter(|(_, p)| {
                !p.awaiting_approval
                    && now.duration_since(p.connected_at) >= LAN_PENDING_HANDSHAKE_TIMEOUT
            })
            .map(|(pk, _)| *pk)
            .collect();
        let mut out = Vec::with_capacity(stalled.len());
        for pk in stalled {
            out.push(self.reject_pending(pk, "handshake_timeout").await);
        }
        out
    }

    /// Cancel-safe pure channel receive over transport events and completed async approvals.
    pub(crate) async fn recv_next_input(&mut self) -> Option<HostInput> {
        if self.lobby_closed {
            return None;
        }
        tokio::select! {
            ev = self.events.recv_event() => ev.map(HostInput::Transport),
            app = self.approval_rx.recv() => app.map(HostInput::Approval),
        }
    }

    pub(crate) async fn handle_completed_approval(
        &mut self,
        completed: CompletedApproval,
    ) -> Vec<LanSessionEvent> {
        let mut emitted = Vec::new();
        self.approval_in_flight = None;

        let req = completed.req;
        let pk = req.peer_pubkey;

        if self.lobby_closed {
            self.pending_peers.remove(&pk);
            return emitted;
        }
        if !self.pending_peers.contains_key(&pk) || !self.handle.is_peer_connected(&pk) {
            self.pending_peers.remove(&pk);
            self.maybe_start_next_approval();
            return emitted;
        }
        if self.locked {
            emitted.push(self.reject_pending(pk, "locked").await);
            self.maybe_start_next_approval();
            return emitted;
        }
        if self.members.len() >= self.max_members {
            emitted.push(self.reject_pending(pk, "full").await);
            self.maybe_start_next_approval();
            return emitted;
        }
        if self.has_display_name_collision(&req.display_name) {
            emitted.push(self.reject_pending(pk, "display_name_in_use").await);
            self.maybe_start_next_approval();
            return emitted;
        }

        match completed.result {
            Ok(safety_number) => {
                emitted.push(
                    self.admit_pending_peer(
                        pk,
                        req.account_id,
                        req.display_name,
                        safety_number,
                        &req.peer_key,
                    )
                    .await,
                );
            }
            Err(_) => {
                emitted.push(self.reject_pending(pk, "rejected").await);
            }
        }

        self.maybe_start_next_approval();
        emitted
    }

    pub(crate) async fn handle_transport_event(
        &mut self,
        ev: P2pTransportEvent,
    ) -> Vec<LanSessionEvent> {
        let mut emitted = Vec::new();
        match ev {
            P2pTransportEvent::PeerConnected { peer_pubkey } => {
                if peer_pubkey == self.identity.public_key || self.find_member(&peer_pubkey).is_some()
                {
                    return emitted;
                }
                if self.lobby_closed || self.locked || self.pin_limiter.is_lobby_locked() {
                    self.handle.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
                    return emitted;
                }
                let source_ip = self
                    .handle
                    .peer_remote_addr(peer_pubkey)
                    .await
                    .map(|a| a.ip().to_canonical().to_string())
                    .unwrap_or_else(|| "lan-direct".to_string());
                let peer_key = LanPinPeerKey {
                    joiner_pubkey: peer_pubkey,
                    source_ip: source_ip.clone(),
                };
                if self.pin_limiter.is_peer_locked(&peer_key) {
                    emitted.push(self.reject_pending(peer_pubkey, "locked").await);
                    return emitted;
                }

                let mut host_nonce = [0u8; 32];
                if fill_random(&mut host_nonce).is_err() {
                    self.handle.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
                    return emitted;
                }
                self.pending_peers.insert(
                    peer_pubkey,
                    PendingLanPeer {
                        host_nonce,
                        connected_at: Instant::now(),
                        source_ip,
                        awaiting_approval: false,
                    },
                );

                let hello = LanHandshakeMessage::Hello(LanHelloMessage {
                    lan_party_id: self.lan_party_id.clone(),
                    lobby_name: self.lobby_name.clone(),
                    host_name: self.identity.display_name.clone(),
                    host_account_id: self.identity.account_id,
                    host_pubkey: self.identity.public_key,
                    require_pin: self.require_pin,
                    host_nonce,
                    max_members: u8::try_from(self.max_members).unwrap_or(LAN_MAX_MEMBERS as u8),
                });
                if self
                    .handle
                    .send_lan_handshake(peer_pubkey, &hello)
                    .await
                    .is_err()
                {
                    self.pending_peers.remove(&peer_pubkey);
                    self.handle.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
                }
            }
            P2pTransportEvent::LanHandshakeReceived {
                peer_pubkey,
                message,
            } => {
                let Some(pending) = self.pending_peers.get(&peer_pubkey) else {
                    if self.find_member(&peer_pubkey).is_none() {
                        self.handle.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
                    }
                    return emitted;
                };
                if pending.awaiting_approval {
                    // Already queued or in-flight for interactive approval; ignore duplicate join.
                    return emitted;
                }
                let host_nonce = pending.host_nonce;
                let source_ip = pending.source_ip.clone();

                let LanHandshakeMessage::Join(join) = message else {
                    emitted.push(self.reject_pending(peer_pubkey, "protocol_error").await);
                    return emitted;
                };
                if join.lan_party_id != self.lan_party_id {
                    emitted.push(self.reject_pending(peer_pubkey, "party_id_mismatch").await);
                    return emitted;
                }

                let peer_key = LanPinPeerKey {
                    joiner_pubkey: peer_pubkey,
                    source_ip: source_ip.clone(),
                };
                match self.pin_limiter.check(&peer_key) {
                    LanPinLockoutStatus::LobbyLocked => {
                        // G3-L3-2: Commit lobby teardown & close admission BEFORE any best-effort rejection!
                        self.lobby_closed = true;
                        self.pin = None;
                        self.handle.set_lan_open_admission(false).await;
                        emitted.push(self.reject_pending(peer_pubkey, "locked").await);
                        emitted.push(self.shutdown("pin_lobby_locked").await);
                        return emitted;
                    }
                    LanPinLockoutStatus::PeerLocked => {
                        emitted.push(self.reject_pending(peer_pubkey, "locked").await);
                        return emitted;
                    }
                    LanPinLockoutStatus::Allowed => {}
                }

                // 1. Verify PIN proof inside TLS 1.3 (Mandate #4).
                if self.require_pin {
                    let pin_ok = match (&self.pin, join.pin_proof) {
                        (Some(pin), Some(proof)) => verify_lan_pin_proof(
                            pin,
                            &self.lan_party_id,
                            &self.identity.public_key,
                            &peer_pubkey,
                            &host_nonce,
                            &proof,
                        )
                        .unwrap_or(false),
                        _ => false,
                    };
                    if !pin_ok {
                        let post = self.pin_limiter.record_failure(&peer_key);
                        if post == LanPinLockoutStatus::LobbyLocked {
                            // G3-L3-2: Immediately commit lockout & stop open admission BEFORE
                            // any best-effort rejection send!
                            self.lobby_closed = true;
                            self.pin = None;
                            self.handle.set_lan_open_admission(false).await;
                            emitted.push(self.reject_pending(peer_pubkey, "locked").await);
                            emitted.push(self.shutdown("pin_lobby_locked").await);
                            return emitted;
                        }
                        let reason = match post {
                            LanPinLockoutStatus::Allowed => "invalid_pin",
                            LanPinLockoutStatus::PeerLocked | LanPinLockoutStatus::LobbyLocked => {
                                "locked"
                            }
                        };
                        emitted.push(self.reject_pending(peer_pubkey, reason).await);
                        return emitted;
                    }
                }

                // 2. Check lock, lobby capacity, and display-name uniqueness.
                if self.locked {
                    emitted.push(self.reject_pending(peer_pubkey, "locked").await);
                    return emitted;
                }
                if self.members.len() >= self.max_members {
                    emitted.push(self.reject_pending(peer_pubkey, "full").await);
                    return emitted;
                }
                let clean_name = sanitize_lan_display_name(&join.display_name);
                if self.has_display_name_collision(&clean_name) {
                    emitted.push(
                        self.reject_pending(peer_pubkey, "display_name_in_use")
                            .await,
                    );
                    return emitted;
                }

                // 3. Mandatory Safety Number pinning / confirmation (Mandate #5).
                let trust_status = match self.pin_store.lookup_peer(join.account_id, &peer_pubkey) {
                    Ok(status) => status,
                    Err(_) => {
                        emitted.push(self.reject_pending(peer_pubkey, "rejected").await);
                        return emitted;
                    }
                };
                match trust_status {
                    PeerTrustStatus::PinnedTrusted => {
                        let Ok(sn) = compute_lan_safety_number(join.account_id, &peer_pubkey)
                        else {
                            emitted.push(self.reject_pending(peer_pubkey, "rejected").await);
                            return emitted;
                        };
                        emitted.push(
                            self.admit_pending_peer(
                                peer_pubkey,
                                join.account_id,
                                clean_name,
                                sn,
                                &peer_key,
                            )
                            .await,
                        );
                    }
                    PeerTrustStatus::RevokedBlocked => {
                        emitted.push(self.reject_pending(peer_pubkey, "rejected").await);
                    }
                    PeerTrustStatus::Unpinned => {
                        let needs_blocking_prompt =
                            matches!(self.pin_store.trust_mode, TrustMode::InteractiveTty)
                                || self.pin_store.require_local_auth_on_pin;
                        if needs_blocking_prompt {
                            // G3-L3-2: Offload interactive /dev/tty confirmation & OS presence
                            // guard onto spawn_blocking with a bounded 1-at-a-time queue so chat
                            // relay, eviction, timers, and signals NEVER freeze!
                            if self.approval_queue.len() >= MAX_PENDING_APPROVAL_QUEUE {
                                emitted.push(self.reject_pending(peer_pubkey, "busy").await);
                                return emitted;
                            }
                            if let Some(p) = self.pending_peers.get_mut(&peer_pubkey) {
                                p.awaiting_approval = true;
                            }
                            self.approval_queue.push_back(PendingApprovalRequest {
                                peer_pubkey,
                                account_id: join.account_id,
                                display_name: clean_name,
                                source_ip,
                                peer_key,
                            });
                            self.maybe_start_next_approval();
                        } else {
                            let safety_number = match self.pin_store.verify_or_pin_peer(
                                "LAN joiner",
                                &clean_name,
                                join.account_id,
                                &peer_pubkey,
                                &source_ip,
                            ) {
                                Ok(sn) => sn,
                                Err(_) => {
                                    emitted.push(self.reject_pending(peer_pubkey, "rejected").await);
                                    return emitted;
                                }
                            };
                            emitted.push(
                                self.admit_pending_peer(
                                    peer_pubkey,
                                    join.account_id,
                                    clean_name,
                                    safety_number,
                                    &peer_key,
                                )
                                .await,
                            );
                        }
                    }
                }
            }
            P2pTransportEvent::FrameReceived {
                peer_pubkey, frame, ..
            } => {
                let Some(member) = self.find_member(&peer_pubkey).cloned() else {
                    self.handle.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
                    return emitted;
                };
                match frame {
                    P2pPartyFrame::ChatMessage(chat) => {
                        // Strict anti-spoofing: sender_handle ALWAYS comes from authenticated roster.
                        let clean = P2pChatMessage {
                            room_scope: sanitize_bounded(&chat.room_scope, MAX_ROOM_SCOPE_BYTES),
                            target_selector: sanitize_bounded(
                                &chat.target_selector,
                                MAX_TARGET_SELECTOR_BYTES,
                            ),
                            sender_handle: member.display_name.clone(),
                            timestamp_ns: chat.timestamp_ns,
                            body: sanitize_bounded(&chat.body, MAX_CHAT_BODY_BYTES),
                        };
                        let relay_frame = P2pPartyFrame::ChatMessage(clean.clone());
                        for m in &self.members {
                            if m.is_host || m.pubkey == peer_pubkey {
                                continue;
                            }
                            let _ = self.handle.send_frame(m.pubkey, &relay_frame).await;
                        }
                        emitted.push(LanSessionEvent::ChatReceived {
                            peer_pubkey,
                            chat: clean,
                        });
                    }
                    P2pPartyFrame::BridgeEnvelope(env) => {
                        let clean = P2pBridgeEnvelope {
                            room_scope: sanitize_bounded(&env.room_scope, MAX_ROOM_SCOPE_BYTES),
                            payload: env.payload,
                        };
                        let relay_frame = P2pPartyFrame::BridgeEnvelope(clean.clone());
                        for m in &self.members {
                            if m.is_host || m.pubkey == peer_pubkey {
                                continue;
                            }
                            let _ = self.handle.send_frame(m.pubkey, &relay_frame).await;
                        }
                        emitted.push(LanSessionEvent::BridgeReceived {
                            peer_pubkey,
                            envelope: clean,
                        });
                    }
                    P2pPartyFrame::EphemeralPulse(pulse) => {
                        let clean = P2pEphemeralPulse {
                            activity_state: pulse.activity_state,
                            timestamp_ns: pulse.timestamp_ns,
                            status: sanitize_bounded(&pulse.status, MAX_EPHEMERAL_STATUS_BYTES),
                        };
                        let relay_frame = P2pPartyFrame::EphemeralPulse(clean.clone());
                        for m in &self.members {
                            if m.is_host || m.pubkey == peer_pubkey {
                                continue;
                            }
                            let _ = self.handle.send_frame(m.pubkey, &relay_frame).await;
                        }
                        emitted.push(LanSessionEvent::PulseReceived {
                            peer_pubkey,
                            sender_name: member.display_name,
                            pulse: clean,
                        });
                    }
                    P2pPartyFrame::ControlNotice(notice) => {
                        let clean = P2pControlNotice {
                            kind: notice.kind,
                            party_epoch: notice.party_epoch,
                            text: sanitize_bounded(&notice.text, MAX_CONTROL_NOTICE_BYTES),
                        };
                        emitted.push(LanSessionEvent::ControlNoticeReceived {
                            peer_pubkey,
                            notice: clean,
                        });
                    }
                }
            }
            P2pTransportEvent::PeerDisconnected {
                peer_pubkey,
                reason_code,
            } => {
                self.pending_peers.remove(&peer_pubkey);
                self.approval_queue.retain(|r| r.peer_pubkey != peer_pubkey);
                if let Some(pos) = self
                    .members
                    .iter()
                    .position(|m| !m.is_host && m.pubkey == peer_pubkey)
                {
                    let left = self.members.remove(pos);
                    // Revoke peer from transport allowlist so a disconnected member cannot
                    // reconnect directly to party lanes while the lobby is /lock'ed!
                    self.handle.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
                    if self.members.len() <= 1 {
                        self.idle_deadline = Some(
                            Instant::now() + Duration::from_secs(u64::from(self.idle_timeout_sec)),
                        );
                    }
                    self.roster_epoch = self.roster_epoch.saturating_add(1);
                    self.broadcast_roster(None).await;
                    emitted.push(LanSessionEvent::PeerLeft {
                        member: left,
                        reason_code,
                        roster_epoch: self.roster_epoch,
                        members: self.members.clone(),
                    });
                }
            }
        }
        emitted
    }

    #[cfg(test)]
    pub(crate) async fn next_event(&mut self) -> Option<Vec<LanSessionEvent>> {
        match self.recv_next_input().await? {
            HostInput::Transport(ev) => Some(self.handle_transport_event(ev).await),
            HostInput::Approval(app) => Some(self.handle_completed_approval(app).await),
        }
    }
}

pub(crate) struct LanJoinConfig {
    pub identity: LanIdentity,
    pub host_pubkey: [u8; 32],
    pub host_addrs: Vec<SocketAddr>,
    pub expected_lan_party_id: Option<String>,
    pub policy_require_pin: bool,
    pub pin: Option<Zeroizing<String>>,
    pub pin_prompt_if_needed: bool,
    pub online_state_dir: Option<PathBuf>,
    pub require_local_auth_on_pin: bool,
    pub trust_mode: TrustMode,
}

pub(crate) struct LanJoinSession {
    identity: LanIdentity,
    host_pubkey: [u8; 32],
    host_name: String,
    host_safety_number: String,
    lan_party_id: String,
    lobby_name: String,
    roster_epoch: u64,
    locked: bool,
    members: Vec<LanMemberInfo>,
    handle: Arc<PartyP2pHandle>,
    events: P2pEventStream,
    closed: bool,
}

impl LanJoinSession {
    pub(crate) async fn connect_and_handshake(mut cfg: LanJoinConfig) -> Result<Self, String> {
        validate_ed25519_pubkey_strict(&cfg.host_pubkey)
            .map_err(|_| "invalid host Ed25519 pubkey".to_string())?;
        if cfg.host_pubkey == cfg.identity.public_key {
            return Err("cannot join our own LAN lobby".to_string());
        }
        if cfg.host_addrs.is_empty() {
            return Err("no host direct addresses available".to_string());
        }

        let pin_store = LanPeerPinStore::new(
            cfg.identity.lan_dir.clone(),
            cfg.online_state_dir,
            cfg.require_local_auth_on_pin,
            cfg.trust_mode,
        );

        // Pre-check revoked status before opening any socket.
        if pin_store.lookup_peer(0, &cfg.host_pubkey)? == PeerTrustStatus::RevokedBlocked {
            return Err("refusing to connect to revoked host".to_string());
        }

        let source_addr = cfg
            .host_addrs
            .first()
            .map(|a| format_lan_direct_target(*a))
            .unwrap_or_else(|| "lan-direct".to_string());

        let transport = PartyP2pTransport::spawn_with_lan(
            PartyP2pConfig {
                local_device_id: if cfg.identity.account_id == 0 {
                    2
                } else {
                    cfg.identity.account_id
                },
                device_secret: *cfg.identity.signing_seed,
                effective_relay_policy: RelayPolicy::NoRelays,
                pinned_relay_url: None,
            },
            Some(LanTransportConfig {
                no_relays: true,
                lan_open_admission: false,
                lan_bind_port: None,
            }),
        )
        .await
        .map_err(|e| format!("failed starting LAN P2P transport: {e}"))?;

        let (handle, mut events) = transport.split();
        if let Err(e) = handle.allow_peer(cfg.host_pubkey).await {
            handle.close().await;
            return Err(format!("failed allowlisting host: {e}"));
        }
        if let Err(e) = handle.connect_direct(cfg.host_pubkey, &cfg.host_addrs).await {
            handle.close().await;
            return Err(format!("failed connecting to LAN host: {e}"));
        }

        // Step 1: Await LAN_HELLO from host on Lane 0.
        let hello = tokio::time::timeout(LAN_JOIN_HANDSHAKE_TIMEOUT, async {
            while let Some(ev) = events.recv_event().await {
                match ev {
                    P2pTransportEvent::LanHandshakeReceived {
                        peer_pubkey,
                        message: LanHandshakeMessage::Hello(h),
                    } if peer_pubkey == cfg.host_pubkey => return Ok(h),
                    P2pTransportEvent::PeerDisconnected {
                        peer_pubkey,
                        reason_code,
                    } if peer_pubkey == cfg.host_pubkey => {
                        return Err(format!(
                            "host disconnected before LAN_HELLO (code={reason_code})"
                        ));
                    }
                    _ => {}
                }
            }
            Err("LAN transport closed before LAN_HELLO".to_string())
        })
        .await
        .map_err(|_| "timed out waiting for LAN_HELLO from host".to_string())?;

        let hello = match hello {
            Ok(h) => h,
            Err(e) => {
                handle.close().await;
                return Err(e);
            }
        };

        // CRITICAL: Bind hello.host_pubkey to authenticated TLS 1.3 RPK peer_pubkey!
        if hello.host_pubkey != cfg.host_pubkey {
            handle.close().await;
            return Err("LAN_HELLO host_pubkey does not match authenticated TLS RPK".to_string());
        }
        if let Some(ref expected_id) = cfg.expected_lan_party_id
            && &hello.lan_party_id != expected_id
        {
            handle.close().await;
            return Err("LAN_HELLO lan_party_id mismatch".to_string());
        }
        if cfg.policy_require_pin && !hello.require_pin {
            handle.close().await;
            return Err(
                "local policy requires PIN-protected LAN lobbies, but host has no PIN".to_string(),
            );
        }

        let clean_host_name = sanitize_lan_display_name(&hello.host_name);
        let clean_lobby_name = sanitize_lan_display_name(&hello.lobby_name);

        // Mandate #5: Verify host Safety Number BEFORE sending LAN_JOIN or any PIN proof!
        let host_safety_number = match pin_store.verify_or_pin_peer(
            "LAN host",
            &clean_host_name,
            hello.host_account_id,
            &cfg.host_pubkey,
            &source_addr,
        ) {
            Ok(sn) => sn,
            Err(e) => {
                handle.close().await;
                return Err(e);
            }
        };

        // Step 2: Compute BLAKE3 PIN proof if required, then send LAN_JOIN.
        let pin_proof = if hello.require_pin {
            let pin = match cfg.pin.take() {
                Some(p) => p,
                None if cfg.pin_prompt_if_needed => {
                    match read_pin_from_tty("Enter LAN lobby PIN: ") {
                        Ok(p) => p,
                        Err(e) => {
                            handle.close().await;
                            return Err(e);
                        }
                    }
                }
                None => {
                    handle.close().await;
                    return Err("host requires a PIN (pass --pin-stdin or use an interactive terminal)".to_string());
                }
            };
            let proof = match compute_lan_pin_proof(
                &pin,
                &hello.lan_party_id,
                &cfg.host_pubkey,
                &cfg.identity.public_key,
                &hello.host_nonce,
            ) {
                Ok(p) => p,
                Err(e) => {
                    drop(pin);
                    handle.close().await;
                    return Err(format!("failed computing LAN PIN proof: {e}"));
                }
            };
            drop(pin);
            Some(proof)
        } else {
            cfg.pin = None;
            None
        };

        let join_msg = LanHandshakeMessage::Join(LanJoinMessage {
            lan_party_id: hello.lan_party_id.clone(),
            display_name: cfg.identity.display_name.clone(),
            account_id: cfg.identity.account_id,
            pin_proof,
        });
        if let Err(e) = handle.send_lan_handshake(cfg.host_pubkey, &join_msg).await {
            handle.close().await;
            return Err(format!("failed sending LAN_JOIN: {e}"));
        }

        // Step 3: Await LAN_WELCOME from host on Lane 0.
        let welcome = tokio::time::timeout(LAN_JOIN_HANDSHAKE_TIMEOUT, async {
            while let Some(ev) = events.recv_event().await {
                match ev {
                    P2pTransportEvent::LanHandshakeReceived {
                        peer_pubkey,
                        message: LanHandshakeMessage::Welcome(w),
                    } if peer_pubkey == cfg.host_pubkey => return Ok(w),
                    P2pTransportEvent::PeerDisconnected {
                        peer_pubkey,
                        reason_code,
                    } if peer_pubkey == cfg.host_pubkey => {
                        return Err(format!(
                            "host disconnected during handshake (code={reason_code})"
                        ));
                    }
                    _ => {}
                }
            }
            Err("LAN transport closed before LAN_WELCOME".to_string())
        })
        .await
        .map_err(|_| "timed out waiting for LAN_WELCOME from host".to_string())?;

        let welcome = match welcome {
            Ok(w) => w,
            Err(e) => {
                handle.close().await;
                return Err(e);
            }
        };

        if welcome.lan_party_id != hello.lan_party_id {
            handle.close().await;
            return Err("LAN_WELCOME lan_party_id mismatch".to_string());
        }
        if !welcome.accepted {
            let reason = if welcome.reason.is_empty() {
                "rejected".to_string()
            } else {
                sanitize_peer_text(&welcome.reason)
            };
            handle.close().await;
            return Err(format!("LAN join rejected by host: {reason}"));
        }

        Ok(Self {
            identity: cfg.identity,
            host_pubkey: cfg.host_pubkey,
            host_name: clean_host_name,
            host_safety_number,
            lan_party_id: hello.lan_party_id,
            lobby_name: clean_lobby_name,
            roster_epoch: welcome.roster_epoch,
            locked: false,
            members: welcome.members,
            handle,
            events,
            closed: false,
        })
    }

    pub(crate) fn lan_party_id(&self) -> &str {
        &self.lan_party_id
    }

    pub(crate) fn lobby_name(&self) -> &str {
        &self.lobby_name
    }

    pub(crate) fn host_name(&self) -> &str {
        &self.host_name
    }

    pub(crate) fn host_safety_number(&self) -> &str {
        &self.host_safety_number
    }

    pub(crate) fn members(&self) -> &[LanMemberInfo] {
        &self.members
    }

    pub(crate) fn roster_epoch(&self) -> u64 {
        self.roster_epoch
    }

    pub(crate) async fn send_chat(&self, body: &str) -> Result<(), String> {
        let clean_body = sanitize_bounded(body, MAX_CHAT_BODY_BYTES);
        if let Some(kind) = scan_outbound_secrets(
            clean_body.as_bytes(),
            &self.identity.signing_seed,
            &self.identity.device_cwt,
        ) {
            return Err(format!(
                "blocked outbound message: detected secret material ({kind:?})"
            ));
        }
        let frame = P2pPartyFrame::ChatMessage(P2pChatMessage {
            room_scope: LAN_DEFAULT_ROOM_SCOPE.to_string(),
            target_selector: "@all".to_string(),
            sender_handle: self.identity.display_name.clone(),
            timestamp_ns: now_unix_ns(),
            body: clean_body,
        });
        self.handle
            .send_frame(self.host_pubkey, &frame)
            .await
            .map_err(|e| format!("failed sending LAN chat: {e}"))
    }

    pub(crate) async fn close(&mut self) {
        self.closed = true;
        let _ = tokio::time::timeout(Duration::from_millis(500), self.handle.close()).await;
    }

    pub(crate) async fn next_event(&mut self) -> Option<LanSessionEvent> {
        if self.closed {
            return None;
        }
        while let Some(ev) = self.events.recv_event().await {
            match ev {
                P2pTransportEvent::LanHandshakeReceived {
                    peer_pubkey,
                    message: LanHandshakeMessage::Roster(roster),
                } if peer_pubkey == self.host_pubkey => {
                    if roster.lan_party_id == self.lan_party_id
                        && roster.roster_epoch >= self.roster_epoch
                    {
                        self.roster_epoch = roster.roster_epoch;
                        self.locked = roster.locked;
                        self.members = roster.members.clone();
                        return Some(LanSessionEvent::RosterUpdated {
                            roster_epoch: self.roster_epoch,
                            locked: self.locked,
                            members: self.members.clone(),
                        });
                    }
                }
                P2pTransportEvent::FrameReceived {
                    peer_pubkey, frame, ..
                } if peer_pubkey == self.host_pubkey => match frame {
                    P2pPartyFrame::ChatMessage(chat) => {
                        let clean = P2pChatMessage {
                            room_scope: sanitize_bounded(&chat.room_scope, MAX_ROOM_SCOPE_BYTES),
                            target_selector: sanitize_bounded(
                                &chat.target_selector,
                                MAX_TARGET_SELECTOR_BYTES,
                            ),
                            sender_handle: sanitize_lan_display_name(&chat.sender_handle),
                            timestamp_ns: chat.timestamp_ns,
                            body: sanitize_bounded(&chat.body, MAX_CHAT_BODY_BYTES),
                        };
                        return Some(LanSessionEvent::ChatReceived {
                            peer_pubkey,
                            chat: clean,
                        });
                    }
                    P2pPartyFrame::BridgeEnvelope(env) => {
                        let clean = P2pBridgeEnvelope {
                            room_scope: sanitize_bounded(&env.room_scope, MAX_ROOM_SCOPE_BYTES),
                            payload: env.payload,
                        };
                        return Some(LanSessionEvent::BridgeReceived {
                            peer_pubkey,
                            envelope: clean,
                        });
                    }
                    P2pPartyFrame::EphemeralPulse(pulse) => {
                        let clean = P2pEphemeralPulse {
                            activity_state: pulse.activity_state,
                            timestamp_ns: pulse.timestamp_ns,
                            status: sanitize_bounded(&pulse.status, MAX_EPHEMERAL_STATUS_BYTES),
                        };
                        return Some(LanSessionEvent::PulseReceived {
                            peer_pubkey,
                            sender_name: self.host_name.clone(),
                            pulse: clean,
                        });
                    }
                    P2pPartyFrame::ControlNotice(notice) => {
                        let clean = P2pControlNotice {
                            kind: notice.kind,
                            party_epoch: notice.party_epoch,
                            text: sanitize_bounded(&notice.text, MAX_CONTROL_NOTICE_BYTES),
                        };
                        return Some(LanSessionEvent::ControlNoticeReceived {
                            peer_pubkey,
                            notice: clean,
                        });
                    }
                },
                P2pTransportEvent::PeerDisconnected {
                    peer_pubkey,
                    reason_code,
                } if peer_pubkey == self.host_pubkey => {
                    self.closed = true;
                    return Some(LanSessionEvent::LobbyClosed {
                        reason: format!("host_disconnected:{reason_code}"),
                    });
                }
                _ => {}
            }
        }
        self.closed = true;
        None
    }
}

// ---------------------------------------------------------------------------
// 9. CLI Argument Parsing & Subcommand Dispatch (`mp-outpost lan ...`)
// ---------------------------------------------------------------------------

fn reject_pin_on_argv(args: &[String]) -> Result<(), String> {
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower == "--pin" || lower.starts_with("--pin=") {
            return Err(
                "refusing --pin on argv; pass LAN PIN via --pin-stdin or interactive /dev/tty prompt only"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn next_arg<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Result<&'a str, String> {
    let val = args
        .get(*idx + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))?;
    *idx += 2;
    Ok(val)
}

fn print_lan_usage() {
    println!(
        "Usage:\n\
  mp-outpost lan status [--lan-dir <dir>] [--json]\n\
  mp-outpost lan scan [--timeout <1..60>] [--json]\n\
  mp-outpost lan host [--name <name>] [--require-pin] [--pin-stdin] [--timeout <1..1800>] [--no-mdns] [--bind-port <port>] [--lan-dir <dir>] [--local-only] [--display-name <name>] [--yes-safety-number <SN>] [--json]\n\
  mp-outpost lan join <lobby_id|ip:port> [--host-pk <b64url>] [--pin-stdin] [--scan-timeout <1..60>] [--lan-dir <dir>] [--local-only] [--display-name <name>] [--yes-safety-number <SN>] [--json]"
    );
}

pub async fn run_lan(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    reject_pin_on_argv(args)?;

    let Some(subcmd) = args.first().map(String::as_str) else {
        print_lan_usage();
        return Ok(());
    };
    let rest = args.get(1..).unwrap_or_default();

    match subcmd {
        "-h" | "--help" | "help" => {
            print_lan_usage();
            Ok(())
        }
        "status" => cmd_lan_status(opts, rest),
        "scan" => cmd_lan_scan(opts, rest).await,
        "host" => cmd_lan_host(opts, rest).await,
        "join" => cmd_lan_join(opts, rest).await,
        other => Err(format!(
            "unknown `lan` subcommand '{}' (expected status|scan|host|join)",
            sanitize_peer_text(other)
        )),
    }
}

fn cmd_lan_status(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut lan_dir_override: Option<PathBuf> = None;
    let mut json_out = opts.json;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--lan-dir" => {
                lan_dir_override = Some(PathBuf::from(next_arg(args, &mut i, "--lan-dir")?));
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_lan_usage();
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unknown `lan status` argument: {}",
                    sanitize_peer_text(other)
                ));
            }
        }
    }

    // Mandate #1: ZERO sockets opened in `lan status`!
    let report = load_effective_lan_policy(&LanPolicyPaths::default(), &process_env_lookup)?;
    let (lan_dir, identity) = inspect_lan_identity_readonly(opts, lan_dir_override.as_deref())?;
    let online_state_dir = resolve_effective_state_dir(opts.state_dir.as_deref()).ok();
    let pin_store = LanPeerPinStore::new(
        lan_dir.clone(),
        online_state_dir,
        report.policy.require_local_auth,
        TrustMode::InteractiveTty,
    );
    let pinned_count = pin_store.count_pinned();

    if json_out {
        let id_val = match identity {
            Some(id) => json!({
                "initialized": true,
                "is_online_identity": id.is_online_identity,
                "account_id": id.account_id,
                "display_name": id.display_name,
                "pubkey_b64u": encode_lan_pubkey_base64url(&id.public_key),
                "safety_number": id.safety_number,
            }),
            None => json!({
                "initialized": false,
            }),
        };
        let out = json!({
            "policy": {
                "disabled": report.policy.disabled,
                "require_pin": report.policy.require_pin,
                "require_local_auth": report.policy.require_local_auth,
                "idle_timeout_sec": report.policy.idle_timeout_sec,
                "max_idle_timeout_sec": report.effective.max_idle_timeout_sec,
                "scan_timeout_sec": report.policy.scan_timeout_sec,
                "max_scan_timeout_sec": report.effective.max_scan_timeout_sec,
            },
            "sources": {
                "system_unified_policy_path": report.system_unified_policy_path.as_ref().map(|p| p.display().to_string()),
                "system_unified_policy_loaded": report.system_unified_policy_loaded,
                "system_policy_path": report.system_policy_path.display().to_string(),
                "system_policy_loaded": report.system_policy_loaded,
                "user_unified_policy_path": report.user_unified_policy_path.as_ref().map(|p| p.display().to_string()),
                "user_unified_policy_loaded": report.user_unified_policy_loaded,
                "user_policy_path": report.user_policy_path.as_ref().map(|p| p.display().to_string()),
                "user_policy_loaded": report.user_policy_loaded,
                "env_disabled": report.env_disabled,
            },
            "lan_dir": lan_dir.display().to_string(),
            "pinned_lan_peers": pinned_count,
            "identity": id_val,
        });
        if let Ok(pretty) = serde_json::to_string_pretty(&out) {
            println!("{pretty}");
        }
    } else {
        println!("LAN Party! status (mp1-lan/1 — zero sockets opened)");
        println!(
            "  disabled:           {}{}",
            report.policy.disabled,
            if report.env_disabled {
                " (env kill-switch active)"
            } else {
                ""
            }
        );
        println!("  require_pin:        {}", report.policy.require_pin);
        println!("  require_local_auth: {}", report.policy.require_local_auth);
        println!(
            "  idle_timeout_sec:   {} (ceiling {})",
            report.policy.idle_timeout_sec, report.effective.max_idle_timeout_sec
        );
        println!(
            "  scan_timeout_sec:   {} (ceiling {})",
            report.policy.scan_timeout_sec, report.effective.max_scan_timeout_sec
        );
        if let Some(ref sup) = report.system_unified_policy_path {
            println!(
                "  system unified:     {} ({})",
                sup.display(),
                if report.system_unified_policy_loaded {
                    "loaded"
                } else {
                    "not present"
                }
            );
        }
        println!(
            "  system policy:      {} ({})",
            report.system_policy_path.display(),
            if report.system_policy_loaded {
                "loaded"
            } else {
                "not present"
            }
        );
        if let Some(ref uup) = report.user_unified_policy_path
            && report.user_unified_policy_loaded
        {
            println!("  user unified:       {} (loaded)", uup.display());
        }
        if let Some(ref up) = report.user_policy_path {
            println!(
                "  user policy:        {} ({})",
                up.display(),
                if report.user_policy_loaded {
                    "loaded"
                } else {
                    "not present"
                }
            );
        }
        println!("  lan_dir:            {}", lan_dir.display());
        println!("  pinned LAN peers:   {pinned_count}");
        match identity {
            Some(id) => {
                println!(
                    "  identity:           {} ({}, account_id={})",
                    id.display_name,
                    if id.is_online_identity {
                        "online"
                    } else {
                        "local-only"
                    },
                    id.account_id
                );
                println!(
                    "  pubkey:             {}",
                    encode_lan_pubkey_base64url(&id.public_key)
                );
                println!("  safety_number:      {}", id.safety_number);
            }
            None => {
                println!("  identity:           uninitialized (created on first lan host/join)");
            }
        }
    }
    Ok(())
}

async fn cmd_lan_scan(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut timeout_override: Option<u32> = None;
    let mut json_out = opts.json;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--timeout" => {
                let raw = next_arg(args, &mut i, "--timeout")?;
                let val = raw
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --timeout '{raw}'"))?;
                if val == 0 || val > MAX_LAN_SCAN_TIMEOUT_SEC {
                    return Err(format!(
                        "--timeout must be in 1..={MAX_LAN_SCAN_TIMEOUT_SEC}"
                    ));
                }
                timeout_override = Some(val);
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_lan_usage();
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unknown `lan scan` argument: {}",
                    sanitize_peer_text(other)
                ));
            }
        }
    }

    // Mandates #2 & #6 BEFORE opening any socket!
    let report = load_effective_lan_policy(&LanPolicyPaths::default(), &process_env_lookup)?;
    enforce_lan_enabled_and_local_auth(&report, "Authorize mp-outpost LAN Party scan")?;

    let effective_timeout = report.effective.effective_scan_timeout(timeout_override);

    let lobbies = scan_lan_mdns(effective_timeout, None).await?;

    if json_out {
        let items: Vec<Value> = lobbies
            .iter()
            .map(|l| {
                let addrs: Vec<String> = l
                    .addrs
                    .iter()
                    .map(|a| format_lan_direct_target(*a))
                    .collect();
                json!({
                    "lan_party_id": l.beacon.lan_party_id,
                    "lobby_name": l.beacon.lobby_name,
                    "host_name": l.beacon.host_name,
                    "host_pubkey_b64u": encode_lan_pubkey_base64url(&l.beacon.host_pubkey),
                    "lan_sn": l.safety_number,
                    "safety_number": l.safety_number,
                    "require_pin": l.beacon.require_pin,
                    "service_port": l.service_port,
                    "addrs": addrs,
                    "last_seen_ms": l.last_seen_ms,
                })
            })
            .collect();
        let out = json!({
            "timeout_sec": effective_timeout,
            "lobbies": items,
        });
        if let Ok(pretty) = serde_json::to_string_pretty(&out) {
            println!("{pretty}");
        }
    } else if lobbies.is_empty() {
        println!("No LAN Party lobbies discovered within {effective_timeout}s.");
    } else {
        println!(
            "Discovered {} LAN Party lobby(ies) ({effective_timeout}s scan):",
            lobbies.len()
        );
        for l in &lobbies {
            let addrs: Vec<String> = l
                .addrs
                .iter()
                .map(|a| format_lan_direct_target(*a))
                .collect();
            println!(
                "  id={}  name=\"{}\"  host=\"{}\"  pin={}  addrs=[{}]  lan_sn={}",
                l.beacon.lan_party_id,
                l.beacon.lobby_name,
                l.beacon.host_name,
                if l.beacon.require_pin { "yes" } else { "no" },
                addrs.join(", "),
                l.safety_number
            );
        }
        println!(
            "  (Note: lan_sn assumes local-only account_id=0; online-enrolled hosts verify their account Safety Number during TLS LAN_HELLO)"
        );
    }
    Ok(())
}

async fn cmd_lan_host(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut lobby_name: Option<String> = None;
    let mut cli_require_pin = false;
    let mut pin_stdin = false;
    let mut timeout_override: Option<u32> = None;
    let mut no_mdns = false;
    let mut bind_port: Option<u16> = None;
    let mut lan_dir_override: Option<PathBuf> = None;
    let mut local_only = false;
    let mut display_name_override: Option<String> = None;
    let mut yes_safety_number: Option<String> = None;
    let mut start_locked = false;
    let mut json_out = opts.json;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--name" => {
                lobby_name = Some(next_arg(args, &mut i, "--name")?.to_string());
            }
            "--require-pin" => {
                cli_require_pin = true;
                i += 1;
            }
            "--pin-stdin" => {
                pin_stdin = true;
                i += 1;
            }
            "--timeout" => {
                let raw = next_arg(args, &mut i, "--timeout")?;
                let val = raw
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --timeout '{raw}'"))?;
                if val == 0 || val > MAX_LAN_IDLE_TIMEOUT_SEC {
                    return Err(format!(
                        "--timeout must be in 1..={MAX_LAN_IDLE_TIMEOUT_SEC}"
                    ));
                }
                timeout_override = Some(val);
            }
            "--no-mdns" => {
                no_mdns = true;
                i += 1;
            }
            "--lock" => {
                start_locked = true;
                i += 1;
            }
            "--bind-port" => {
                let raw = next_arg(args, &mut i, "--bind-port")?;
                let p = raw
                    .parse::<u16>()
                    .map_err(|_| format!("invalid --bind-port '{raw}'"))?;
                if p == 0 {
                    return Err("--bind-port must be in 1..=65535".to_string());
                }
                bind_port = Some(p);
            }
            "--lan-dir" => {
                lan_dir_override = Some(PathBuf::from(next_arg(args, &mut i, "--lan-dir")?));
            }
            "--local-only" => {
                local_only = true;
                i += 1;
            }
            "--display-name" => {
                display_name_override =
                    Some(next_arg(args, &mut i, "--display-name")?.to_string());
            }
            "--yes-safety-number" => {
                yes_safety_number =
                    Some(next_arg(args, &mut i, "--yes-safety-number")?.to_string());
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_lan_usage();
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unknown `lan host` argument: {}",
                    sanitize_peer_text(other)
                ));
            }
        }
    }

    // Mandates #2 & #6 BEFORE opening any socket!
    let report = load_effective_lan_policy(&LanPolicyPaths::default(), &process_env_lookup)?;
    enforce_lan_enabled_and_local_auth(&report, "Authorize mp-outpost LAN Party host")?;

    let effective_idle = report.effective.effective_idle_timeout(timeout_override);
    let require_pin = report.policy.require_pin || cli_require_pin || pin_stdin;

    let pin = if require_pin {
        if pin_stdin {
            Some(read_pin_from_stdin()?)
        } else {
            Some(read_pin_from_tty("Set LAN lobby PIN: ")?)
        }
    } else {
        None
    };

    let identity = load_or_create_lan_identity(
        opts,
        lan_dir_override.as_deref(),
        local_only,
        display_name_override.as_deref(),
    )?;
    let chosen_lobby_name = lobby_name
        .map(|s| sanitize_lan_display_name(&s))
        .unwrap_or_else(|| sanitize_lan_display_name(&format!("{}-lan", identity.display_name)));
    let trust_mode = match yes_safety_number {
        Some(sn) => TrustMode::ExpectedSafetyNumber(sn),
        None => TrustMode::InteractiveTty,
    };
    let online_state_dir = resolve_effective_state_dir(opts.state_dir.as_deref()).ok();

    let mut host = LanHostSession::start(LanHostConfig {
        identity: identity.clone(),
        lobby_name: chosen_lobby_name,
        require_pin,
        pin,
        idle_timeout_sec: effective_idle,
        enable_mdns: !no_mdns && !start_locked,
        start_locked,
        bind_port,
        max_members: LAN_MAX_MEMBERS as u8,
        pin_rate_limit: LanPinRateLimitConfig::default(),
        online_state_dir,
        require_local_auth_on_pin: report.policy.require_local_auth,
        trust_mode,
    })
    .await?;

    let host_pk_b64u = encode_lan_pubkey_base64url(&identity.public_key);
    let primary_addr = host
        .direct_addrs()
        .first()
        .copied()
        .unwrap_or_else(|| host.loopback_addr());
    let direct_target = format_lan_direct_target(primary_addr);
    let join_cmd = format!("mp-outpost lan join {direct_target} --host-pk {host_pk_b64u}");

    if json_out {
        let all_addrs: Vec<String> = host
            .direct_addrs()
            .iter()
            .map(|a| format_lan_direct_target(*a))
            .collect();
        emit_jsonl(&json!({
            "event": "lobby_ready",
            "lan_party_id": host.lan_party_id(),
            "lobby_name": host.lobby_name(),
            "host_name": identity.display_name,
            "safety_number": identity.safety_number,
            "host_pk_b64u": host_pk_b64u,
            "direct_addr": direct_target,
            "addrs": all_addrs,
            "service_port": host.service_port(),
            "require_pin": require_pin,
            "mdns_enabled": !no_mdns && !start_locked,
            "idle_timeout_sec": effective_idle,
            "join_command": join_cmd,
        }));
    } else {
        println!("LAN Party! host ready (mp1-lan/1)");
        println!("  Lobby ID:      {}", host.lan_party_id());
        println!("  Lobby Name:    {}", host.lobby_name());
        println!("  Host:          {}", identity.display_name);
        println!("  Safety Number: {}", identity.safety_number);
        println!("  Direct Addr:   {direct_target}");
        println!("  Host PK:       {host_pk_b64u}");
        println!(
            "  PIN Required:  {} | mDNS: {} | Idle Timeout: {}s",
            if require_pin { "yes" } else { "no" },
            if !no_mdns && !start_locked {
                "on (_mp1-lan._udp.local.)"
            } else {
                "off"
            },
            effective_idle
        );
        println!("  Join Command:  {join_cmd}");
        println!("Type a message and press Enter to chat, /lock to lock lobby, /members to list, /quit to exit.");
    }

    let mut stdin_rx = spawn_stdin_line_reader();
    let mut stdin_open = true;
    let mut evict_tick = tokio::time::interval(Duration::from_secs(2));
    evict_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();

    let mut exit_err: Option<String> = None;

    while !host.is_closed() {
        let idle_deadline = host.idle_deadline();
        let mdns_deadline = host.mdns_deadline();
        let idle_sleep = async move {
            match idle_deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if dl <= now {
                        return;
                    }
                    tokio::time::sleep(dl - now).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let mdns_sleep = async move {
            match mdns_deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if dl <= now {
                        return;
                    }
                    tokio::time::sleep(dl - now).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let wait_signal = async {
            match (sigterm.as_mut(), sigint.as_mut()) {
                (Some(t), Some(i)) => {
                    tokio::select! {
                        _ = t.recv() => {}
                        _ = i.recv() => {}
                    }
                }
                _ => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        };

        enum HostSelectAction {
            IdleTimeout,
            MdnsTimeout,
            Signal,
            EvictTick,
            Stdin(Option<String>),
            HostInput(Option<HostInput>),
        }

        // G3-L3-2: Select ONLY on cancel-safe primitives (timers, signals, pure channel recv).
        // All multi-step async mutations/rejections/teardown execute outside `select!`.
        let action = tokio::select! {
            _ = idle_sleep => HostSelectAction::IdleTimeout,
            _ = mdns_sleep => HostSelectAction::MdnsTimeout,
            _ = wait_signal => HostSelectAction::Signal,
            _ = evict_tick.tick() => HostSelectAction::EvictTick,
            maybe_line = stdin_rx.recv(), if stdin_open => HostSelectAction::Stdin(maybe_line),
            maybe_input = host.recv_next_input() => HostSelectAction::HostInput(maybe_input),
        };

        match action {
            HostSelectAction::IdleTimeout => {
                let closed_ev = host.shutdown("lan_host_timeout").await;
                print_lan_event(&closed_ev, json_out);
                break;
            }
            HostSelectAction::MdnsTimeout => {
                host.stop_mdns().await;
            }
            HostSelectAction::Signal => {
                let closed_ev = host.shutdown("signal").await;
                print_lan_event(&closed_ev, json_out);
                break;
            }
            HostSelectAction::EvictTick => {
                for ev in host.evict_stalled_pending().await {
                    print_lan_event(&ev, json_out);
                }
            }
            HostSelectAction::Stdin(maybe_line) => match maybe_line {
                Some(line) => {
                    let trimmed = line.trim();
                    if trimmed == "/quit" || trimmed == "/exit" {
                        let closed_ev = host.shutdown("quit").await;
                        print_lan_event(&closed_ev, json_out);
                        break;
                    } else if trimmed == "/lock" {
                        let locked_ev = host.lock_lobby().await;
                        print_lan_event(&locked_ev, json_out);
                    } else if trimmed == "/members" {
                        if json_out {
                            emit_jsonl(&json!({
                                "event": "roster",
                                "members": members_to_json(host.members()),
                            }));
                        } else {
                            println!("Members ({}):", host.members().len());
                            for m in host.members() {
                                println!(
                                    "  - {}{}",
                                    m.display_name,
                                    if m.is_host { " (host)" } else { "" }
                                );
                            }
                        }
                    } else if !trimmed.is_empty()
                        && let Err(err) = host.send_chat(trimmed).await
                    {
                        eprintln!("warning: {err}");
                    }
                }
                None => {
                    // Stdin closed (e.g. after --pin-stdin pipe): keep hosting until timeout/signal.
                    stdin_open = false;
                }
            },
            HostSelectAction::HostInput(maybe_input) => {
                let Some(input) = maybe_input else {
                    break;
                };
                let evs = match input {
                    HostInput::Transport(raw_ev) => host.handle_transport_event(raw_ev).await,
                    HostInput::Approval(approval) => host.handle_completed_approval(approval).await,
                };
                for ev in evs {
                    if matches!(ev, LanSessionEvent::LobbyClosed { ref reason } if reason == "pin_lobby_locked")
                    {
                        exit_err = Some("LAN lobby torn down after 15 failed PIN attempts".to_string());
                    }
                    print_lan_event(&ev, json_out);
                }
            }
        }
    }

    if !host.is_closed() {
        let _ = host.shutdown("stopped").await;
    }

    if let Some(err) = exit_err {
        return Err(err);
    }
    Ok(())
}

async fn cmd_lan_join(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut target_arg: Option<String> = None;
    let mut host_pk_arg: Option<String> = None;
    let mut pin_stdin = false;
    let mut scan_timeout_override: Option<u32> = None;
    let mut lan_dir_override: Option<PathBuf> = None;
    let mut local_only = false;
    let mut display_name_override: Option<String> = None;
    let mut yes_safety_number: Option<String> = None;
    let mut json_out = opts.json;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--host-pk" => {
                host_pk_arg = Some(next_arg(args, &mut i, "--host-pk")?.to_string());
            }
            "--pin-stdin" => {
                pin_stdin = true;
                i += 1;
            }
            "--scan-timeout" => {
                let raw = next_arg(args, &mut i, "--scan-timeout")?;
                let val = raw
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --scan-timeout '{raw}'"))?;
                if val == 0 || val > MAX_LAN_SCAN_TIMEOUT_SEC {
                    return Err(format!(
                        "--scan-timeout must be in 1..={MAX_LAN_SCAN_TIMEOUT_SEC}"
                    ));
                }
                scan_timeout_override = Some(val);
            }
            "--lan-dir" => {
                lan_dir_override = Some(PathBuf::from(next_arg(args, &mut i, "--lan-dir")?));
            }
            "--local-only" => {
                local_only = true;
                i += 1;
            }
            "--display-name" => {
                display_name_override =
                    Some(next_arg(args, &mut i, "--display-name")?.to_string());
            }
            "--yes-safety-number" => {
                yes_safety_number =
                    Some(next_arg(args, &mut i, "--yes-safety-number")?.to_string());
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_lan_usage();
                return Ok(());
            }
            other if !other.starts_with('-') && target_arg.is_none() => {
                target_arg = Some(other.to_string());
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown `lan join` argument: {}",
                    sanitize_peer_text(other)
                ));
            }
        }
    }

    let Some(target) = target_arg else {
        return Err(
            "`lan join` requires <lobby_id|ip:port> (e.g. `mp-outpost lan join 192.168.1.5:4433 --host-pk <b64url>`)"
                .to_string(),
        );
    };

    // Mandates #2 & #6 BEFORE opening any socket!
    let report = load_effective_lan_policy(&LanPolicyPaths::default(), &process_env_lookup)?;
    enforce_lan_enabled_and_local_auth(&report, "Authorize mp-outpost LAN Party join")?;

    let cli_host_pk = match host_pk_arg {
        Some(ref raw) => Some(
            decode_lan_pubkey_base64url(raw)
                .map_err(|_| "invalid --host-pk (expected 43-char unpadded base64url Ed25519 pubkey)".to_string())?,
        ),
        None => None,
    };

    let (host_pubkey, host_addrs, expected_lan_party_id) =
        if let Ok(direct_sock) = parse_lan_direct_target(&target) {
            let pk = cli_host_pk.ok_or_else(|| {
                "direct `ip:port` join requires --host-pk <b64url> to authenticate the host TLS RPK"
                    .to_string()
            })?;
            (pk, vec![direct_sock], None)
        } else if parse_lan_party_id_hex(&target).is_ok() {
            let effective_scan = report.effective.effective_scan_timeout(scan_timeout_override);
            let found = scan_lan_mdns(effective_scan, Some(&target)).await?;
            let lobby = found
                .into_iter()
                .find(|l| l.beacon.lan_party_id == target)
                .ok_or_else(|| {
                    format!("LAN lobby '{target}' not discovered within {effective_scan}s")
                })?;
            if let Some(expected_pk) = cli_host_pk
                && expected_pk != lobby.beacon.host_pubkey
            {
                return Err(
                    "discovered lobby host_pubkey does not match explicit --host-pk".to_string(),
                );
            }
            if lobby.addrs.is_empty() {
                return Err(format!(
                    "discovered LAN lobby '{target}' advertised no usable addresses"
                ));
            }
            (
                lobby.beacon.host_pubkey,
                lobby.addrs,
                Some(lobby.beacon.lan_party_id),
            )
        } else {
            return Err(format!(
                "invalid join target '{}': expected 16-hex lobby_id or ip:port",
                sanitize_peer_text(&target)
            ));
        };

    // Read PIN from stdin BEFORE spawning the stdin chat reader if --pin-stdin was passed.
    let pin = if pin_stdin {
        Some(read_pin_from_stdin()?)
    } else {
        None
    };

    let identity = load_or_create_lan_identity(
        opts,
        lan_dir_override.as_deref(),
        local_only,
        display_name_override.as_deref(),
    )?;
    let trust_mode = match yes_safety_number {
        Some(sn) => TrustMode::ExpectedSafetyNumber(sn),
        None => TrustMode::InteractiveTty,
    };
    let online_state_dir = resolve_effective_state_dir(opts.state_dir.as_deref()).ok();

    let mut client = LanJoinSession::connect_and_handshake(LanJoinConfig {
        identity: identity.clone(),
        host_pubkey,
        host_addrs,
        expected_lan_party_id,
        policy_require_pin: report.policy.require_pin,
        pin,
        pin_prompt_if_needed: !pin_stdin,
        online_state_dir,
        require_local_auth_on_pin: report.policy.require_local_auth,
        trust_mode,
    })
    .await?;

    if json_out {
        emit_jsonl(&json!({
            "event": "peer_joined",
            "lan_party_id": client.lan_party_id(),
            "lobby_name": client.lobby_name(),
            "host_name": client.host_name(),
            "host_safety_number": client.host_safety_number(),
            "roster_epoch": client.roster_epoch(),
            "members": members_to_json(client.members()),
        }));
    } else {
        println!(
            "Joined LAN Party! \"{}\" (id={}, host={}, sn={})",
            client.lobby_name(),
            client.lan_party_id(),
            client.host_name(),
            client.host_safety_number()
        );
        println!(
            "Members ({}): {}",
            client.members().len(),
            client
                .members()
                .iter()
                .map(|m| m.display_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("Type a message and press Enter to chat, /members to list, /quit to exit.");
    }

    let mut stdin_rx = spawn_stdin_line_reader();
    let mut stdin_open = true;

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();

    loop {
        let wait_signal = async {
            match (sigterm.as_mut(), sigint.as_mut()) {
                (Some(t), Some(i)) => {
                    tokio::select! {
                        _ = t.recv() => {}
                        _ = i.recv() => {}
                    }
                }
                _ => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        };

        tokio::select! {
            _ = wait_signal => {
                client.close().await;
                print_lan_event(&LanSessionEvent::LobbyClosed { reason: "signal".to_string() }, json_out);
                break;
            }
            maybe_line = stdin_rx.recv(), if stdin_open => {
                match maybe_line {
                    Some(line) => {
                        let trimmed = line.trim();
                        if trimmed == "/quit" || trimmed == "/exit" {
                            client.close().await;
                            print_lan_event(&LanSessionEvent::LobbyClosed { reason: "quit".to_string() }, json_out);
                            break;
                        } else if trimmed == "/members" {
                            if json_out {
                                emit_jsonl(&json!({
                                    "event": "roster",
                                    "roster_epoch": client.roster_epoch(),
                                    "members": members_to_json(client.members()),
                                }));
                            } else {
                                println!("Members ({}):", client.members().len());
                                for m in client.members() {
                                    println!(
                                        "  - {}{}",
                                        m.display_name,
                                        if m.is_host { " (host)" } else { "" }
                                    );
                                }
                            }
                        } else if !trimmed.is_empty()
                            && let Err(err) = client.send_chat(trimmed).await
                        {
                            eprintln!("warning: {err}");
                        }
                    }
                    None => {
                        stdin_open = false;
                    }
                }
            }
            maybe_ev = client.next_event() => {
                let Some(ev) = maybe_ev else {
                    break;
                };
                let is_closed = matches!(ev, LanSessionEvent::LobbyClosed { .. });
                print_lan_event(&ev, json_out);
                if is_closed {
                    break;
                }
            }
        }
    }

    client.close().await;
    Ok(())
}

fn format_fenced_text_body(body: &str) -> String {
    body.replace('\n', "\n  | ")
}

fn print_lan_event(ev: &LanSessionEvent, json_out: bool) {
    match ev {
        LanSessionEvent::PeerJoined {
            member,
            safety_number,
            roster_epoch,
            members,
        } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "peer_joined",
                    "display_name": member.display_name,
                    "account_id": member.account_id,
                    "pubkey_b64u": encode_lan_pubkey_base64url(&member.pubkey),
                    "safety_number": safety_number,
                    "roster_epoch": roster_epoch,
                    "members": members_to_json(members),
                }));
            } else {
                println!(
                    "[+] {} joined (sn={}, members={})",
                    member.display_name,
                    safety_number,
                    members.len()
                );
            }
        }
        LanSessionEvent::PeerRejected {
            peer_pubkey,
            reason,
        } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "peer_rejected",
                    "pubkey_b64u": encode_lan_pubkey_base64url(peer_pubkey),
                    "reason": reason,
                }));
            } else {
                println!(
                    "[!] rejected peer {} ({reason})",
                    encode_lan_pubkey_base64url(peer_pubkey)
                );
            }
        }
        LanSessionEvent::PeerLeft {
            member,
            reason_code,
            roster_epoch,
            members,
        } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "peer_left",
                    "display_name": member.display_name,
                    "pubkey_b64u": encode_lan_pubkey_base64url(&member.pubkey),
                    "reason_code": reason_code,
                    "roster_epoch": roster_epoch,
                    "members": members_to_json(members),
                }));
            } else {
                println!(
                    "[-] {} left (code={reason_code}, members={})",
                    member.display_name,
                    members.len()
                );
            }
        }
        LanSessionEvent::RosterUpdated {
            roster_epoch,
            locked,
            members,
        } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "roster",
                    "roster_epoch": roster_epoch,
                    "locked": locked,
                    "members": members_to_json(members),
                }));
            } else {
                println!(
                    "[*] roster epoch={roster_epoch} locked={locked} members={}",
                    members.len()
                );
            }
        }
        LanSessionEvent::ChatReceived { peer_pubkey, chat } => {
            let nonce = random_nonce_u64();
            let fenced = fence_peer_text(&chat.body, nonce);
            if json_out {
                emit_jsonl(&json!({
                    "event": "chat",
                    "peer_pubkey_b64u": encode_lan_pubkey_base64url(peer_pubkey),
                    "sender": chat.sender_handle,
                    "room_scope": chat.room_scope,
                    "target_selector": chat.target_selector,
                    "timestamp_ns": chat.timestamp_ns,
                    "body": chat.body,
                    "fenced_body": fenced,
                }));
            } else {
                println!(
                    "[{}] {}",
                    chat.sender_handle,
                    format_fenced_text_body(&chat.body)
                );
            }
        }
        LanSessionEvent::BridgeReceived {
            peer_pubkey,
            envelope,
        } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "bridge",
                    "peer_pubkey_b64u": encode_lan_pubkey_base64url(peer_pubkey),
                    "room_scope": envelope.room_scope,
                    "payload_bytes": envelope.payload.len(),
                }));
            } else {
                println!(
                    "[bridge:{}] {} bytes",
                    envelope.room_scope,
                    envelope.payload.len()
                );
            }
        }
        LanSessionEvent::PulseReceived {
            peer_pubkey,
            sender_name,
            pulse,
        } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "pulse",
                    "peer_pubkey_b64u": encode_lan_pubkey_base64url(peer_pubkey),
                    "sender": sender_name,
                    "activity_state": pulse.activity_state as u8,
                    "status": pulse.status,
                }));
            } else {
                println!(
                    "[pulse:{sender_name}] {}",
                    format_fenced_text_body(&pulse.status)
                );
            }
        }
        LanSessionEvent::ControlNoticeReceived {
            peer_pubkey,
            notice,
        } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "control_notice",
                    "peer_pubkey_b64u": encode_lan_pubkey_base64url(peer_pubkey),
                    "party_epoch": notice.party_epoch,
                    "text": notice.text,
                }));
            } else {
                println!("[notice] {}", format_fenced_text_body(&notice.text));
            }
        }
        LanSessionEvent::LobbyLocked { roster_epoch } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "lobby_locked",
                    "roster_epoch": roster_epoch,
                }));
            } else {
                println!("[*] lobby locked (mDNS stopped, new joins disabled)");
            }
        }
        LanSessionEvent::LobbyClosed { reason } => {
            if json_out {
                emit_jsonl(&json!({
                    "event": "lobby_closed",
                    "reason": reason,
                }));
            } else {
                println!("[*] LAN lobby closed ({reason})");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 10. Unit & Full In-Process Loopback QUIC LAN Party! Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use outpost_core::storage_codec::{PeerRecord, PeersStoreRecord, encode_peers_store};

    use super::*;

    fn test_opts(tmp: &Path) -> GlobalOpts {
        GlobalOpts {
            state_dir: Some(tmp.join("state")),
            runtime_dir: Some(tmp.join("runtime")),
            device_id: None,
            json: false,
            debug: false,
            strict_pins: false,
        }
    }

    #[test]
    fn lan_policy_system_floor_kill_switch_and_symlink_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let sys_path = tmp.path().join("sys_lan.toml");
        let user_path = tmp.path().join("user_lan.toml");
        let my_uid = unsafe { libc::geteuid() };

        fs::write(
            &sys_path,
            "[lan]\ndisabled = false\nrequire_pin = true\nrequire_local_auth = true\nidle_timeout_sec = 120\nscan_timeout_sec = 10\n",
        )?;
        fs::set_permissions(&sys_path, fs::Permissions::from_mode(0o644))?;

        // User tries to weaken every single setting -> system floor MUST hold!
        fs::write(
            &user_path,
            "[lan]\ndisabled = false\nrequire_pin = false\nrequire_local_auth = false\nidle_timeout_sec = 900\nscan_timeout_sec = 60\n",
        )?;
        fs::set_permissions(&user_path, fs::Permissions::from_mode(0o600))?;

        let paths = LanPolicyPaths {
            system_unified_policy_path: None,
            system_policy_path: sys_path.clone(),
            user_unified_policy_path: None,
            user_policy_path: Some(user_path.clone()),
            expected_system_uid: my_uid,
            expected_user_uid: Some(my_uid),
        };

        let report = load_effective_lan_policy(&paths, &|_| None)?;
        assert!(report.system_policy_loaded);
        assert!(report.user_policy_loaded);
        assert!(!report.policy.disabled);
        assert!(report.policy.require_pin);
        assert!(report.policy.require_local_auth);
        assert_eq!(report.policy.idle_timeout_sec, 120);
        assert_eq!(report.policy.scan_timeout_sec, 10);

        // MP_DISABLE_LAN=1 forces fail-closed disabled = true!
        let report_mp = load_effective_lan_policy(&paths, &|k| {
            (k == "MP_DISABLE_LAN").then(|| OsString::from("1"))
        })?;
        assert!(report_mp.policy.disabled);
        assert!(report_mp.env_disabled);

        // BLACKBIRD_DISABLE_LAN=true also forces disabled = true!
        let report_bb = load_effective_lan_policy(&paths, &|k| {
            (k == "BLACKBIRD_DISABLE_LAN").then(|| OsString::from("YES"))
        })?;
        assert!(report_bb.policy.disabled);

        // Symlinked system policy MUST fail closed!
        let sym_path = tmp.path().join("sym_lan.toml");
        symlink(&sys_path, &sym_path)?;
        let sym_paths = LanPolicyPaths {
            system_unified_policy_path: None,
            system_policy_path: sym_path,
            user_unified_policy_path: None,
            user_policy_path: None,
            expected_system_uid: my_uid,
            expected_user_uid: Some(my_uid),
        };
        assert!(load_effective_lan_policy(&sym_paths, &|_| None).is_err());

        // Group/world-writable policy file MUST fail closed!
        fs::set_permissions(&user_path, fs::Permissions::from_mode(0o666))?;
        assert!(load_effective_lan_policy(&paths, &|_| None).is_err());

        // Malformed TOML MUST fail closed!
        fs::set_permissions(&user_path, fs::Permissions::from_mode(0o600))?;
        fs::write(&user_path, "[lan]\nunknown_key = true\n")?;
        assert!(load_effective_lan_policy(&paths, &|_| None).is_err());

        // --pin on argv MUST be refused!
        assert!(reject_pin_on_argv(&["host".into(), "--pin".into(), "1234".into()]).is_err());
        assert!(reject_pin_on_argv(&["host".into(), "--pin=1234".into()]).is_err());

        Ok(())
    }

    #[test]
    fn lan_local_only_identity_0600_and_canonical_safety_number()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let lan_dir = tmp.path().join("lan_id");

        let id1 = load_or_create_lan_identity(&opts, Some(&lan_dir), true, Some("QuakeHost"))?;
        assert_eq!(id1.account_id, 0);
        assert!(!id1.is_online_identity);
        assert_eq!(id1.display_name, "QuakeHost");
        assert_eq!(
            id1.safety_number,
            compute_lan_safety_number(0, &id1.public_key)?
        );

        // Debug output MUST redact signing_seed and device_cwt!
        let dbg = format!("{id1:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&encode_hex(&*id1.signing_seed)));

        let id_file = lan_dir.join(LAN_IDENTITY_FILE);
        let meta = fs::symlink_metadata(&id_file)?;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        // Reload yields identical keypair and Safety Number.
        let id2 = load_or_create_lan_identity(&opts, Some(&lan_dir), true, None)?;
        assert_eq!(id1.public_key, id2.public_key);
        assert_eq!(id1.safety_number, id2.safety_number);
        assert_eq!(id2.display_name, "QuakeHost");

        // Relaxing permissions to 0644 MUST fail closed!
        fs::set_permissions(&id_file, fs::Permissions::from_mode(0o644))?;
        assert!(load_or_create_lan_identity(&opts, Some(&lan_dir), true, None).is_err());

        Ok(())
    }

    #[tokio::test]
    async fn lan_loopback_quic_handshake_nfc_pin_pinning_and_bidirectional_chat()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let host_dir = tmp.path().join("host_lan");
        let join_dir = tmp.path().join("join_lan");

        let host_id = load_or_create_lan_identity(&opts, Some(&host_dir), true, Some("HostOne"))?;
        let join_id = load_or_create_lan_identity(&opts, Some(&join_dir), true, Some("JoinTwo"))?;

        // Host uses NFD PIN ("cafe\u{0301}-42"); joiner uses NFC ("caf\u{00e9}-42")!
        let host_pin = normalize_and_validate_pin(Zeroizing::new("cafe\u{0301}-42".to_string()))?;
        let join_pin = normalize_and_validate_pin(Zeroizing::new("caf\u{00e9}-42".to_string()))?;
        assert_eq!(&*host_pin, &*join_pin);

        let mut host = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "quake-night".to_string(),
            require_pin: true,
            pin: Some(host_pin),
            idle_timeout_sec: 60,
            enable_mdns: false,
            start_locked: false,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig::default(),
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(join_id.safety_number.clone()),
        })
        .await?;

        let host_addr = host.loopback_addr();
        let host_pk = host_id.public_key;
        let host_sn = host_id.safety_number.clone();

        // Spawn joiner connect+handshake concurrently with host event pump.
        let join_task = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: join_id.clone(),
            host_pubkey: host_pk,
            host_addrs: vec![host_addr],
            expected_lan_party_id: Some(host.lan_party_id().to_string()),
            policy_require_pin: true,
            pin: Some(join_pin.clone()),
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_sn),
        }));

        // Pump host until PeerJoined arrives.
        let mut peer_joined = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !peer_joined {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(500), host.next_event()).await
            {
                for ev in evs {
                    if let LanSessionEvent::PeerJoined { member, .. } = ev {
                        assert_eq!(member.pubkey, join_id.public_key);
                        assert_eq!(member.display_name, "JoinTwo");
                        peer_joined = true;
                    }
                }
            }
        }
        assert!(peer_joined, "host must admit verified LAN joiner");

        let mut joiner = tokio::time::timeout(Duration::from_secs(5), join_task).await???;
        assert_eq!(joiner.lan_party_id(), host.lan_party_id());
        assert_eq!(joiner.lobby_name(), "quake-night");
        assert_eq!(joiner.members().len(), 2);

        // Verify lan_peers.json was written with 0600 on both sides!
        let host_peers_meta = fs::symlink_metadata(host_dir.join(LAN_PEERS_FILE))?;
        assert_eq!(host_peers_meta.permissions().mode() & 0o777, 0o600);
        let join_peers_meta = fs::symlink_metadata(join_dir.join(LAN_PEERS_FILE))?;
        assert_eq!(join_peers_meta.permissions().mode() & 0o777, 0o600);

        // Bidirectional ChatMessage exchange over Lane 1!
        joiner.send_chat("hello from joiner!").await?;
        let mut got_at_host = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && got_at_host.is_none() {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(500), host.next_event()).await
            {
                for ev in evs {
                    if let LanSessionEvent::ChatReceived { chat, .. } = ev {
                        got_at_host = Some(chat);
                    }
                }
            }
        }
        let host_chat = got_at_host.ok_or("host did not receive joiner chat")?;
        assert_eq!(host_chat.sender_handle, "JoinTwo");
        assert_eq!(host_chat.body, "hello from joiner!");

        host.send_chat("welcome to quake night!").await?;
        let mut got_at_joiner = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && got_at_joiner.is_none() {
            if let Ok(Some(LanSessionEvent::ChatReceived { chat, .. })) =
                tokio::time::timeout(Duration::from_millis(500), joiner.next_event()).await
            {
                got_at_joiner = Some(chat);
            }
        }
        let join_chat = got_at_joiner.ok_or("joiner did not receive host chat")?;
        assert_eq!(join_chat.sender_handle, "HostOne");
        assert_eq!(join_chat.body, "welcome to quake night!");

        // Outbound secret leak guard blocks own signing seed (even with stripped control-char obfuscation)
        // AND host MUST block sending its own active LAN PIN in chat!
        let leaked_seed_hex = encode_hex(&*join_id.signing_seed);
        assert!(joiner.send_chat(&format!("oops {leaked_seed_hex}")).await.is_err());
        let obfuscated_seed = format!(
            "{}\x00{}",
            leaked_seed_hex.get(..16).unwrap_or(""),
            leaked_seed_hex.get(16..).unwrap_or("")
        );
        assert!(joiner.send_chat(&obfuscated_seed).await.is_err());
        assert!(
            host.send_chat("the pin is caf\u{00e9}-42").await.is_err(),
            "host must refuse sending its own active LAN PIN in chat"
        );

        joiner.close().await;
        let _ = host.shutdown("test_done").await;

        // Verify pinned peer is recognized automatically on reconnect even with AlwaysReject trust mode!
        let mut host2 = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "quake-round-2".to_string(),
            require_pin: true,
            pin: Some(join_pin.clone()),
            idle_timeout_sec: 60,
            enable_mdns: false,
            start_locked: false,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig::default(),
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::AlwaysReject,
        })
        .await?;
        let host2_addr = host2.loopback_addr();
        let join2_task = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: join_id.clone(),
            host_pubkey: host_id.public_key,
            host_addrs: vec![host2_addr],
            expected_lan_party_id: None,
            policy_require_pin: true,
            pin: Some(join_pin),
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::AlwaysReject,
        }));
        let mut rejoined = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !rejoined {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(500), host2.next_event()).await
                && evs
                    .iter()
                    .any(|e| matches!(e, LanSessionEvent::PeerJoined { .. }))
            {
                rejoined = true;
            }
        }
        assert!(rejoined, "already-pinned peer must reconnect automatically");
        let mut joiner2 = tokio::time::timeout(Duration::from_secs(5), join2_task).await???;
        joiner2.close().await;
        let _ = host2.shutdown("test_done").await;

        Ok(())
    }

    #[tokio::test]
    async fn lan_loopback_wrong_pin_rejected_and_lockout_tears_down_lobby()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let host_dir = tmp.path().join("host_pin");
        let bad_dir = tmp.path().join("bad_pin");

        let host_id = load_or_create_lan_identity(&opts, Some(&host_dir), true, Some("PinHost"))?;
        let bad_id = load_or_create_lan_identity(&opts, Some(&bad_dir), true, Some("GuessGuy"))?;

        // Use small rate limits (max_peer_failures=2, max_lobby_failures=3) to test lockout quickly!
        let mut host = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "pin-lock-test".to_string(),
            require_pin: true,
            pin: Some(Zeroizing::new("correct-pin-99".to_string())),
            idle_timeout_sec: 60,
            enable_mdns: false,
            start_locked: false,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig {
                max_peer_failures: 2,
                max_lobby_failures: 3,
            },
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(bad_id.safety_number.clone()),
        })
        .await?;
        let host_addr = host.loopback_addr();

        // Attempt 1: wrong PIN -> rejected with invalid_pin
        let try1 = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: bad_id.clone(),
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: Some(Zeroizing::new("wrong-1".to_string())),
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number.clone()),
        }));
        let mut rej1 = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && rej1.is_none() {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(400), host.next_event()).await
            {
                for ev in evs {
                    if let LanSessionEvent::PeerRejected { reason, .. } = ev {
                        rej1 = Some(reason);
                    }
                }
            }
        }
        assert_eq!(rej1.as_deref(), Some("invalid_pin"));
        let err1 = tokio::time::timeout(Duration::from_secs(5), try1).await??;
        assert!(err1.is_err());

        // Attempt 2: 2nd wrong PIN from same peer -> peer locked ("locked")
        let try2 = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: bad_id.clone(),
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: Some(Zeroizing::new("wrong-2".to_string())),
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number.clone()),
        }));
        let mut rej2 = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && rej2.is_none() {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(400), host.next_event()).await
            {
                for ev in evs {
                    if let LanSessionEvent::PeerRejected { reason, .. } = ev {
                        rej2 = Some(reason);
                    }
                }
            }
        }
        assert_eq!(rej2.as_deref(), Some("locked"));
        assert!(tokio::time::timeout(Duration::from_secs(5), try2).await??.is_err());

        // Attempt 3 from a 2nd joiner hits max_lobby_failures (3) -> tears down lobby!
        let bad2_id = load_or_create_lan_identity(
            &opts,
            Some(&tmp.path().join("bad_pin2")),
            true,
            Some("GuessTwo"),
        )?;
        let try3 = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: bad2_id,
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: Some(Zeroizing::new("wrong-3".to_string())),
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number.clone()),
        }));
        let mut lobby_torn_down = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !lobby_torn_down {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(400), host.next_event()).await
            {
                for ev in evs {
                    if matches!(ev, LanSessionEvent::LobbyClosed { ref reason } if reason == "pin_lobby_locked")
                    {
                        lobby_torn_down = true;
                    }
                }
            }
        }
        assert!(lobby_torn_down, "lobby must tear down when total PIN failures hit cap");
        assert!(host.is_closed());
        assert!(tokio::time::timeout(Duration::from_secs(5), try3).await??.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn lan_loopback_unpinned_safety_number_mismatch_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let host_id = load_or_create_lan_identity(
            &opts,
            Some(&tmp.path().join("sn_host")),
            true,
            Some("SnHost"),
        )?;
        let join_id = load_or_create_lan_identity(
            &opts,
            Some(&tmp.path().join("sn_join")),
            true,
            Some("SnJoin"),
        )?;

        let mut host = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "sn-check".to_string(),
            require_pin: false,
            pin: None,
            idle_timeout_sec: 60,
            enable_mdns: false,
            start_locked: false,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig::default(),
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(join_id.safety_number.clone()),
        })
        .await?;
        let host_addr = host.loopback_addr();

        // Joiner passes a bogus --yes-safety-number -> MUST fail closed BEFORE sending LAN_JOIN!
        let join_task = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: join_id,
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(
                "0000-0000-0000-0000-0000-0000-0000-0000".to_string(),
            ),
        }));

        // Pump host so it sends LAN_HELLO.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline && !join_task.is_finished() {
            let _ = tokio::time::timeout(Duration::from_millis(200), host.next_event()).await;
        }
        let res = tokio::time::timeout(Duration::from_secs(3), join_task).await??;
        assert!(res.is_err(), "wrong Safety Number must fail closed");
        let _ = host.shutdown("test_done").await;
        Ok(())
    }

    #[tokio::test]
    async fn lan_loopback_three_party_star_relay_and_lock_lobby()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let host_dir = tmp.path().join("star_host");
        let a_dir = tmp.path().join("star_a");
        let b_dir = tmp.path().join("star_b");
        let c_dir = tmp.path().join("star_c");

        let host_id = load_or_create_lan_identity(&opts, Some(&host_dir), true, Some("StarHost"))?;
        let a_id = load_or_create_lan_identity(&opts, Some(&a_dir), true, Some("PlayerA"))?;
        let b_id = load_or_create_lan_identity(&opts, Some(&b_dir), true, Some("PlayerB"))?;
        let c_id = load_or_create_lan_identity(&opts, Some(&c_dir), true, Some("PlayerC"))?;

        // Pre-pin PlayerA and PlayerB in host's lan_peers.json, and StarHost in A & B.
        let host_pins = LanPeerPinStore::new(host_dir, None, false, TrustMode::AlwaysReject);
        host_pins.pin_peer(0, &a_id.public_key, "PlayerA", &a_id.safety_number)?;
        host_pins.pin_peer(0, &b_id.public_key, "PlayerB", &b_id.safety_number)?;
        LanPeerPinStore::new(a_dir, None, false, TrustMode::AlwaysReject).pin_peer(
            0,
            &host_id.public_key,
            "StarHost",
            &host_id.safety_number,
        )?;
        LanPeerPinStore::new(b_dir, None, false, TrustMode::AlwaysReject).pin_peer(
            0,
            &host_id.public_key,
            "StarHost",
            &host_id.safety_number,
        )?;

        let mut host = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "star-arena".to_string(),
            require_pin: false,
            pin: None,
            idle_timeout_sec: 60,
            enable_mdns: false,
            start_locked: false,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig::default(),
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::AlwaysReject,
        })
        .await?;
        let host_addr = host.loopback_addr();

        // Connect PlayerA and PlayerB concurrently.
        let join_a = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: a_id.clone(),
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::AlwaysReject,
        }));
        let join_b = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: b_id.clone(),
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::AlwaysReject,
        }));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && host.members().len() < 3 {
            let _ = tokio::time::timeout(Duration::from_millis(300), host.next_event()).await;
        }
        assert_eq!(host.members().len(), 3);
        let mut player_a = tokio::time::timeout(Duration::from_secs(5), join_a).await???;
        let mut player_b = tokio::time::timeout(Duration::from_secs(5), join_b).await???;

        // PlayerA sends chat -> host receives & relays to PlayerB with authenticated sender_handle!
        player_a.send_chat("frag time!").await?;
        let mut host_relayed = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !host_relayed {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(300), host.next_event()).await
                && evs
                    .iter()
                    .any(|e| matches!(e, LanSessionEvent::ChatReceived { chat, .. } if chat.body == "frag time!"))
            {
                host_relayed = true;
            }
        }
        assert!(host_relayed);

        let mut b_got_chat = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && b_got_chat.is_none() {
            if let Ok(Some(LanSessionEvent::ChatReceived { chat, .. })) =
                tokio::time::timeout(Duration::from_millis(300), player_b.next_event()).await
            {
                b_got_chat = Some(chat);
            }
        }
        let relayed = b_got_chat.ok_or("PlayerB did not receive relayed chat from PlayerA")?;
        assert_eq!(relayed.sender_handle, "PlayerA");
        assert_eq!(relayed.body, "frag time!");

        // Lock lobby: PlayerC MUST be rejected at transport layer while PlayerA/B remain live!
        let locked_ev = host.lock_lobby().await;
        assert!(matches!(locked_ev, LanSessionEvent::LobbyLocked { .. }));
        let c_res = LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: c_id,
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number),
        })
        .await;
        assert!(c_res.is_err(), "locked lobby must reject new joiners");

        player_a.close().await;
        player_b.close().await;
        let _ = host.shutdown("test_done").await;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Gate #3 Security Hardening Regression Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn g3_duplicate_display_name_impersonation_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let host_dir = tmp.path().join("dup_host");
        let imp_host_dir = tmp.path().join("dup_imp_host");
        let legit_dir = tmp.path().join("dup_legit");
        let imp_peer_dir = tmp.path().join("dup_imp_peer");

        let host_id =
            load_or_create_lan_identity(&opts, Some(&host_dir), true, Some("HostAlpha"))?;
        // Impersonator 1 claims host's display name with different ASCII casing!
        let imp_host_id =
            load_or_create_lan_identity(&opts, Some(&imp_host_dir), true, Some("hostalpha"))?;
        let legit_id =
            load_or_create_lan_identity(&opts, Some(&legit_dir), true, Some("ScoutOne"))?;
        // Impersonator 2 claims legit member's display name with different ASCII casing!
        let imp_peer_id =
            load_or_create_lan_identity(&opts, Some(&imp_peer_dir), true, Some("SCOUTONE"))?;

        let host_pins = LanPeerPinStore::new(host_dir, None, false, TrustMode::AlwaysReject);
        host_pins.pin_peer(0, &imp_host_id.public_key, "Other1", &imp_host_id.safety_number)?;
        host_pins.pin_peer(0, &legit_id.public_key, "ScoutOne", &legit_id.safety_number)?;
        host_pins.pin_peer(0, &imp_peer_id.public_key, "Other2", &imp_peer_id.safety_number)?;

        let mut host = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "dup-check".to_string(),
            require_pin: false,
            pin: None,
            idle_timeout_sec: 60,
            enable_mdns: false,
            start_locked: false,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig::default(),
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::AlwaysReject,
        })
        .await?;
        let host_addr = host.loopback_addr();

        // 1. Impersonating the host's display_name MUST be rejected with "display_name_in_use"!
        let t1 = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: imp_host_id,
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number.clone()),
        }));
        let mut rej_reason = None;
        let dl = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < dl && rej_reason.is_none() {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(300), host.next_event()).await
            {
                for ev in evs {
                    if let LanSessionEvent::PeerRejected { reason, .. } = ev {
                        rej_reason = Some(reason);
                    }
                }
            }
        }
        assert_eq!(rej_reason.as_deref(), Some("display_name_in_use"));
        assert!(tokio::time::timeout(Duration::from_secs(5), t1).await??.is_err());

        // 2. Legit peer ScoutOne joins cleanly.
        let t2 = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: legit_id,
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number.clone()),
        }));
        let dl = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < dl && host.members().len() < 2 {
            let _ = tokio::time::timeout(Duration::from_millis(300), host.next_event()).await;
        }
        let mut legit_client = tokio::time::timeout(Duration::from_secs(5), t2).await???;

        // 3. Second joiner claiming "SCOUTONE" MUST be rejected with "display_name_in_use"!
        let t3 = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: imp_peer_id,
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number),
        }));
        let mut rej2 = None;
        let dl = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < dl && rej2.is_none() {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(300), host.next_event()).await
            {
                for ev in evs {
                    if let LanSessionEvent::PeerRejected { reason, .. } = ev {
                        rej2 = Some(reason);
                    }
                }
            }
        }
        assert_eq!(rej2.as_deref(), Some("display_name_in_use"));
        assert!(tokio::time::timeout(Duration::from_secs(5), t3).await??.is_err());

        legit_client.close().await;
        let _ = host.shutdown("test_done").await;
        Ok(())
    }

    #[tokio::test]
    async fn g3_disconnect_revokes_peer_blocking_reconnect_while_locked_and_rearms_idle_timer()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let host_dir = tmp.path().join("rev_host");
        let peer_dir = tmp.path().join("rev_peer");

        let host_id = load_or_create_lan_identity(&opts, Some(&host_dir), true, Some("LockHost"))?;
        let peer_id = load_or_create_lan_identity(&opts, Some(&peer_dir), true, Some("LeavingPeer"))?;

        // Start a separate host with start_locked: true to verify idle_deadline is armed even when
        // started locked with 0 remote peers!
        let mut locked_start_host = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "locked-init".to_string(),
            require_pin: false,
            pin: None,
            idle_timeout_sec: 45,
            enable_mdns: false,
            start_locked: true,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig::default(),
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::AlwaysReject,
        })
        .await?;
        assert!(
            locked_start_host.idle_deadline().is_some(),
            "start_locked host with 0 remote peers must still arm idle_deadline"
        );
        let _ = locked_start_host.shutdown("test_done").await;

        let mut host = LanHostSession::start(LanHostConfig {
            identity: host_id.clone(),
            lobby_name: "rev-lock-test".to_string(),
            require_pin: false,
            pin: None,
            idle_timeout_sec: 60,
            enable_mdns: false,
            start_locked: false,
            bind_port: None,
            max_members: 4,
            pin_rate_limit: LanPinRateLimitConfig::default(),
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(peer_id.safety_number.clone()),
        })
        .await?;
        assert!(host.idle_deadline().is_some(), "initial idle_deadline must be armed");
        let host_addr = host.loopback_addr();

        // Peer joins -> idle_deadline clears while lobby has remote members.
        let join_task = tokio::spawn(LanJoinSession::connect_and_handshake(LanJoinConfig {
            identity: peer_id.clone(),
            host_pubkey: host_id.public_key,
            host_addrs: vec![host_addr],
            expected_lan_party_id: None,
            policy_require_pin: false,
            pin: None,
            pin_prompt_if_needed: false,
            online_state_dir: None,
            require_local_auth_on_pin: false,
            trust_mode: TrustMode::ExpectedSafetyNumber(host_id.safety_number.clone()),
        }));
        let dl = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < dl && host.members().len() < 2 {
            let _ = tokio::time::timeout(Duration::from_millis(300), host.next_event()).await;
        }
        assert_eq!(host.members().len(), 2);
        assert!(
            host.idle_deadline().is_none(),
            "idle_deadline must disarm while remote peers are connected"
        );
        let mut peer_client = tokio::time::timeout(Duration::from_secs(5), join_task).await???;

        // Lock lobby while peer is connected, then peer disconnects!
        let _ = host.lock_lobby().await;
        peer_client.close().await;

        let mut saw_left = false;
        let dl = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < dl && !saw_left {
            if let Ok(Some(evs)) =
                tokio::time::timeout(Duration::from_millis(300), host.next_event()).await
                && evs
                    .iter()
                    .any(|e| matches!(e, LanSessionEvent::PeerLeft { .. }))
            {
                saw_left = true;
            }
        }
        assert!(saw_left, "host must observe PeerLeft after client closes");
        assert_eq!(host.members().len(), 1);
        assert!(
            host.idle_deadline().is_some(),
            "idle_deadline MUST re-arm when all remote peers leave"
        );

        // Now the disconnected peer attempts to reconnect directly while the lobby is locked.
        // Because PeerDisconnected called revoke_peer, the transport MUST reject the reconnect!
        let reconnect_res = tokio::time::timeout(
            Duration::from_secs(3),
            LanJoinSession::connect_and_handshake(LanJoinConfig {
                identity: peer_id,
                host_pubkey: host_id.public_key,
                host_addrs: vec![host_addr],
                expected_lan_party_id: None,
                policy_require_pin: false,
                pin: None,
                pin_prompt_if_needed: false,
                online_state_dir: None,
                require_local_auth_on_pin: false,
                trust_mode: TrustMode::AlwaysReject,
            }),
        )
        .await;
        if let Ok(Ok(_)) = reconnect_res {
            return Err("disconnected peer must NOT reconnect while lobby is locked".into());
        }

        let _ = host.shutdown("test_done").await;
        Ok(())
    }

    #[test]
    fn g3_revocation_in_lan_peers_dominates_peers_bin_and_corrupt_peers_bin_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let opts = test_opts(tmp.path());
        let lan_dir = tmp.path().join("lan_rev");
        let state_dir = tmp.path().join("online_state");
        let peer_id = load_or_create_lan_identity(
            &opts,
            Some(&tmp.path().join("peer_id")),
            true,
            Some("RevPeer"),
        )?;
        let other_id = load_or_create_lan_identity(
            &opts,
            Some(&tmp.path().join("other_id")),
            true,
            Some("RevPeer"),
        )?;

        let vdir = open_or_create_private_dir(&state_dir)?;
        let peer_sn_42 = compute_lan_safety_number(42, &peer_id.public_key)?;

        // Write lan_peers.json marking peer_id as revoked: true!
        let lan_vdir = open_or_create_private_dir(&lan_dir)?;
        let revoked_file = PinnedLanPeersFile {
            version: 1,
            peers: vec![PinnedLanPeerEntry {
                pubkey_hex: encode_hex(&peer_id.public_key),
                account_id: 42,
                display_name: "RevPeer".to_string(),
                safety_number: peer_sn_42.clone(),
                pinned_at_ms: 1,
                revoked: true,
            }],
        };
        atomic_write_in_dir(
            lan_vdir.as_raw_fd(),
            LAN_PEERS_FILE,
            &serde_json::to_vec_pretty(&revoked_file)?,
        )?;

        // 1. peers.bin exists with no entry (Unpinned) -> lan_peers.json revoked: true MUST dominate!
        atomic_write_in_dir(
            vdir.as_raw_fd(),
            PEERS_FILE,
            &encode_peers_store(&PeersStoreRecord::default())?,
        )?;
        let store = LanPeerPinStore::new(
            lan_dir.clone(),
            Some(state_dir.clone()),
            false,
            TrustMode::AlwaysReject,
        );
        assert_eq!(
            store.lookup_peer(42, &peer_id.public_key)?,
            PeerTrustStatus::RevokedBlocked
        );

        // 2. Even if peers.bin says PinnedTrusted, revocation in lan_peers.json STILL dominates!
        let online_trusted = PeersStoreRecord {
            peers: vec![PeerRecord {
                api_authority_hash: [0u8; 8],
                account_id: 42,
                root_pubkey: peer_id.public_key,
                trust_state: TrustState::PinnedTrusted,
                pinned_at_ms: 1,
                handle_prop: "RevPeer".to_string(),
                handle_fetched_ms: 1,
            }],
        };
        atomic_write_in_dir(
            vdir.as_raw_fd(),
            PEERS_FILE,
            &encode_peers_store(&online_trusted)?,
        )?;
        assert_eq!(
            store.lookup_peer(42, &peer_id.public_key)?,
            PeerTrustStatus::RevokedBlocked
        );

        // 3. Conversely, RevokedBlocked in peers.bin MUST dominate a pinned entry in lan_peers.json!
        let lan_pinned = PinnedLanPeersFile {
            version: 1,
            peers: vec![PinnedLanPeerEntry {
                pubkey_hex: encode_hex(&peer_id.public_key),
                account_id: 42,
                display_name: "RevPeer".to_string(),
                safety_number: peer_sn_42,
                pinned_at_ms: 1,
                revoked: false,
            }],
        };
        atomic_write_in_dir(
            lan_vdir.as_raw_fd(),
            LAN_PEERS_FILE,
            &serde_json::to_vec_pretty(&lan_pinned)?,
        )?;
        let online_revoked = PeersStoreRecord {
            peers: vec![PeerRecord {
                api_authority_hash: [0u8; 8],
                account_id: 42,
                root_pubkey: peer_id.public_key,
                trust_state: TrustState::RevokedBlocked,
                pinned_at_ms: 1,
                handle_prop: "RevPeer".to_string(),
                handle_fetched_ms: 1,
            }],
        };
        atomic_write_in_dir(
            vdir.as_raw_fd(),
            PEERS_FILE,
            &encode_peers_store(&online_revoked)?,
        )?;
        assert_eq!(
            store.lookup_peer(42, &peer_id.public_key)?,
            PeerTrustStatus::RevokedBlocked
        );

        // 4. Verify account_id binding in peers.bin: restore PinnedTrusted in peers.bin and
        // empty lan_peers.json -> account_id=42 is PinnedTrusted while mismatched account_id=99 is Unpinned!
        atomic_write_in_dir(
            vdir.as_raw_fd(),
            PEERS_FILE,
            &encode_peers_store(&online_trusted)?,
        )?;
        let empty_lan = PinnedLanPeersFile::default();
        atomic_write_in_dir(
            lan_vdir.as_raw_fd(),
            LAN_PEERS_FILE,
            &serde_json::to_vec_pretty(&empty_lan)?,
        )?;
        assert_eq!(
            store.lookup_peer(42, &peer_id.public_key)?,
            PeerTrustStatus::PinnedTrusted
        );
        assert_eq!(
            store.lookup_peer(99, &peer_id.public_key)?,
            PeerTrustStatus::Unpinned
        );

        // 5. Key-changed conflict detection surfaces warning when another key claims same account_id/name!
        let conflict = store.find_key_change_conflict(42, "RevPeer", &other_id.public_key)?;
        assert!(
            conflict.is_some(),
            "different key claiming already-pinned account_id/name must surface key-change warning"
        );

        // 6. Corrupt peers.bin MUST fail closed (Err), never silently ignored!
        atomic_write_in_dir(vdir.as_raw_fd(), PEERS_FILE, b"not-a-valid-peers-bin")?;
        assert!(store.lookup_peer(42, &peer_id.public_key).is_err());

        Ok(())
    }

    #[test]
    fn g3_non_utf8_env_kill_switch_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let non_utf8 = OsStr::from_bytes(&[0xff, 0xfe, b'0']).to_os_string();
        let paths = LanPolicyPaths {
            system_unified_policy_path: None,
            system_policy_path: PathBuf::new(),
            user_unified_policy_path: None,
            user_policy_path: None,
            expected_system_uid: unsafe { libc::geteuid() },
            expected_user_uid: None,
        };
        let report_mp = load_effective_lan_policy(&paths, &|k| {
            (k == "MP_DISABLE_LAN").then(|| non_utf8.clone())
        })?;
        assert!(
            report_mp.policy.disabled && report_mp.env_disabled,
            "non-UTF-8 MP_DISABLE_LAN MUST fail closed"
        );

        let report_bb = load_effective_lan_policy(&paths, &|k| {
            (k == "BLACKBIRD_DISABLE_LAN").then(|| non_utf8.clone())
        })?;
        assert!(
            report_bb.policy.disabled && report_bb.env_disabled,
            "non-UTF-8 BLACKBIRD_DISABLE_LAN MUST fail closed"
        );
        Ok(())
    }

    #[test]
    fn g3_omitted_system_policy_timeout_allows_cli_600_and_merges_unified_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let sys_unified = tmp.path().join("policy.toml");
        let sys_legacy = tmp.path().join("lan.toml");
        let my_uid = unsafe { libc::geteuid() };

        // System policy sets require_pin = true but OMITS idle_timeout_sec and scan_timeout_sec!
        fs::write(&sys_legacy, "[lan]\nrequire_pin = true\n")?;
        fs::set_permissions(&sys_legacy, fs::Permissions::from_mode(0o644))?;

        let paths = LanPolicyPaths {
            system_unified_policy_path: Some(sys_unified.clone()),
            system_policy_path: sys_legacy.clone(),
            user_unified_policy_path: None,
            user_policy_path: None,
            expected_system_uid: my_uid,
            expected_user_uid: Some(my_uid),
        };

        let report = load_effective_lan_policy(&paths, &|_| None)?;
        assert!(report.system_policy_loaded);
        assert!(report.policy.require_pin);
        assert_eq!(report.effective.max_idle_timeout_sec, MAX_LAN_IDLE_TIMEOUT_SEC);
        assert_eq!(report.effective.effective_idle_timeout(Some(600)), 600);
        assert_eq!(report.effective.effective_scan_timeout(Some(30)), 30);

        // Now add unified policy.toml tightening require_local_auth = true and idle_timeout_sec = 450!
        fs::write(
            &sys_unified,
            "[lan]\nrequire_local_auth = true\nidle_timeout_sec = 450\n",
        )?;
        fs::set_permissions(&sys_unified, fs::Permissions::from_mode(0o644))?;

        let merged = load_effective_lan_policy(&paths, &|_| None)?;
        assert!(merged.system_unified_policy_loaded);
        assert!(merged.system_policy_loaded);
        assert!(merged.policy.require_pin);
        assert!(merged.policy.require_local_auth);
        assert_eq!(merged.effective.max_idle_timeout_sec, 450);
        assert_eq!(merged.effective.effective_idle_timeout(Some(600)), 450);

        // Verify multiline text-mode fencing & mDNS unicast target validation helpers.
        assert_eq!(
            format_fenced_text_body("hello\n[+] fake join"),
            "hello\n  | [+] fake join"
        );
        assert!(!is_valid_mdns_unicast_target(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            0
        )));
        assert!(!is_valid_mdns_unicast_target(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            5353
        )));
        assert!(is_valid_mdns_unicast_target(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            5353
        )));

        Ok(())
    }
}
