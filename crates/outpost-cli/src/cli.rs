//! Owned CLI argument parser (zero `clap`) and full Spec v2 command handlers.
//!
//! Security invariants:
//! - Invite secrets (`mpinv1_...`, `mppi1_...`) are NEVER accepted on `argv`.
//! - `peer trust` and `peer revoke` require an interactive controlling TTY (`isatty` + `/dev/tty`)
//!   and NEVER accept `--safety-number` on `argv`.
//! - `whoami --safety-number` works offline from enrolled binary state (`d<13hex>.dev.bin`).

use std::cell::UnsafeCell;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64U};
use ed25519_dalek::SigningKey;
use mp_protocol::{
    AccountId, CwtError, DeviceId, MAX_CWT_TTL_SECS, MAX_SAFE_ID, PartyJoinMode, PartyVisibility,
    RelayPolicy, compute_device_fingerprint, decode_recovery_key, encode_device_cwt,
    encode_recovery_key, sha256, validate_ed25519_pubkey_strict, verify_device_cwt,
};
use outpost_control::{
    AuthSessionPollResponse, AuthSessionStartRequest, ControlClient, ControlError,
    DEFAULT_API_AUTHORITY, DeviceLinkApproveRequest, DeviceLinkInspectResponse,
    DeviceLinkPollResponse, EnrollDeviceRequest, RegisterAccountRequest, RequestSigner,
    wall_now_ms, wall_now_secs,
};
use outpost_core::fence::{
    contains_device_link_token, contains_recovery_file, contains_recovery_key, fence_peer_text,
    sanitize_peer_text,
};
use outpost_core::ipc_wire::{ClientKind, HelloPayload, IPC_SCHEMA_VER, IpcOpcode};
use outpost_core::party_state::DEFAULT_POLL_MAX_BYTES;
use outpost_core::storage_codec::{
    DeviceRecord, PeerRecord, PendingDeviceRecord, PendingRegRecord, TrustState,
};
use outpost_core::trust::{
    api_authority_hash, compute_safety_number, verify_safety_number,
};
use outpost_daemon::{
    ClientConfig, DAEMON_LOCK_NAME, DAEMON_LOG_NAME, DaemonClient, DaemonError, DrainMode,
    FlockGuard, ForceStopOutcome, STARTUP_LOCK_NAME, atomic_write_in_dir_no_replace, fill_random,
    force_stop_daemon, open_dir_nofollow, open_or_create_private_dir, read_file_in_dir,
    read_regular_file_bounded_nofollow, resolve_runtime_dir,
};
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

use crate::build_info::{
    PKG_VERSION, build_digest, build_order, encode_hex, on_disk_exe_matches_local,
};
use crate::ipc_payloads::{
    FriendEdgeResp, FriendsLiveIpcResp, IpcPartyEventKind, PartyControlNoticeReq, PartyCreateReq,
    PartyEpochOpReq, PartyInviteMintReq, PartyInviteRevokeReq, PartyJoinReq, PartyKickReq,
    PartyListResp, PartyMembersResp, PartyPollIpcReq, PartyPostBoardReq, PartyPromoteReq,
    PartyRequestApproveReq, PartyRequestRejectReq, PartyRequestsListReq, PartySendChatReq,
    PartyWaitIpcReq, RoomEnterIpcReq, RoomEnterIpcResp, RoomInviteIpcReq, RoomInviteIpcResp,
    RoomLeaveIpcReq, RoomLeaveIpcResp, StatusResp, decode_bool_resp, decode_friend_edge_resp, decode_friends_list_resp, decode_friends_live_resp,
    decode_party_create_resp, decode_party_epoch_resp, decode_party_invite_mint_resp,
    decode_party_join_resp, decode_party_list_resp, decode_party_members_resp,
    decode_party_poll_resp, decode_party_request_approve_resp, decode_party_requests_list_resp,
    decode_reload_resp, decode_resolve_handle_resp, decode_room_enter_resp,
    decode_room_invite_resp, decode_room_leave_resp, decode_send_result_resp, decode_status_resp,
    encode_control_notice_req, encode_party_create_req, encode_party_epoch_op_req,
    encode_party_invite_mint_req, encode_party_invite_revoke_req, encode_party_join_req,
    encode_party_kick_req, encode_party_poll_req, encode_party_post_board_req,
    encode_party_promote_req, encode_party_request_approve_req, encode_party_request_reject_req,
    encode_party_requests_list_req, encode_party_send_chat_req, encode_party_wait_req,
    encode_resolve_handle_req, encode_room_enter_req, encode_room_invite_req,
    encode_room_leave_req, encode_u64_req, relay_policy_name, trust_state_name,
};
use crate::mcp_bridge::build_spawn_command_with_opts;
use crate::mpkey::{
    MAX_PEM_BYTES, decrypt_mpkey, encrypt_mpkey, write_mpkey_atomic_0600,
    write_mpkey_atomic_0600_with_force,
};
use crate::storage::{
    DEFAULT_RELAY_URL, PENDING_DEV_FILE, PENDING_REG_CWT_FILE, PENDING_REG_FILE,
    build_control_client_config, list_enrolled_device_ids, load_default_device_id,
    load_device_record, load_peers_store, load_pending_device, load_pending_reg,
    load_pending_reg_cwt, lock_state, open_state_dir, pubkey_fingerprint_hex, remove_state_file,
    resolve_active_device_id, resolve_effective_runtime_override, resolve_effective_state_dir,
    save_default_device_id, save_device_record, save_peers_store, save_pending_device,
    save_pending_reg, save_pending_reg_cwt,
};

#[derive(Debug, Clone, Default)]
pub struct GlobalOpts {
    pub state_dir: Option<PathBuf>,
    pub runtime_dir: Option<PathBuf>,
    pub device_id: Option<u64>,
    pub json: bool,
    pub debug: bool,
    pub strict_pins: bool,
}

#[derive(Debug, Clone)]
pub struct DaemonSubcommandArgs {
    pub device_id: u64,
    pub ready_fd: Option<i32>,
    pub runtime_dir: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub idle_timeout_secs: Option<u64>,
    pub foreground: bool,
    pub strict_pins: bool,
}

/// Global fail-closed `argv` secret guard called at the VERY TOP of `main()` BEFORE
/// `__daemon`, `mcp`, or standard CLI dispatch.
pub fn reject_secrets_in_argv(args: &[String]) -> Result<(), String> {
    const SECRET_FLAGS: &[(&str, &str)] = &[
        ("--passphrase", "passphrase"),
        ("--recovery-key", "recovery key"),
        ("--invite-secret", "invite secret"),
    ];

    for a in args.iter().skip(1) {
        let lower = a.to_ascii_lowercase();
        if lower == "--pin" || lower.starts_with("--pin=") {
            return Err(
                "PINs are forbidden on CLI argv (use hidden /dev/tty prompt or --pin-stdin)"
                    .to_string(),
            );
        }
        for &(flag, label) in SECRET_FLAGS {
            if lower == flag || lower.starts_with(&format!("{flag}=")) {
                return Err(format!(
                    "refusing {flag} on argv; pass {label} via stdin or interactive /dev/tty only"
                ));
            }
        }
        if lower.contains("mpinv1_") || lower.contains("mppi1_") {
            return Err(
                "refusing invite secret on argv; pass invite tokens via --invite-stdin only"
                    .to_string(),
            );
        }
        if lower.contains("mpdl1_") || contains_device_link_token(a.as_bytes()) {
            return Err("refusing device-link poll token on argv".to_string());
        }
        if lower.contains("mprk1_") || contains_recovery_key(a.as_bytes()) {
            return Err(
                "refusing recovery key on argv; pass recovery keys via --recovery-key-stdin, --root-key-file, --mpkey, or interactive /dev/tty only"
                    .to_string(),
            );
        }
        if contains_recovery_file(a.as_bytes()) {
            return Err(
                "refusing .mpkey recovery file contents on argv; pass a file path via --mpkey <path>"
                    .to_string(),
            );
        }
        if contains_private_pem_header_local(a.as_bytes()) {
            return Err("refusing private/recovery/secret PEM material on argv".to_string());
        }
    }

    // Also inspect space-joined argv words to catch unprefixed 55-char Crockford recovery keys
    // pasted across multiple whitespace-separated arguments.
    if args.len() > 2 {
        let joined = args.get(1..).unwrap_or_default().join(" ");
        if contains_recovery_key(joined.as_bytes()) {
            return Err(
                "refusing recovery key on argv; pass recovery keys via --recovery-key-stdin, --root-key-file, --mpkey, or interactive /dev/tty only"
                    .to_string(),
            );
        }
    }

    Ok(())
}

pub(crate) fn contains_private_pem_header_local(haystack: &[u8]) -> bool {
    const PREFIX: &[u8] = b"-----BEGIN ";
    const SUFFIXES: [&[u8]; 3] = [
        b"PRIVATE KEY-----",
        b"RECOVERY KEY-----",
        b"SECRET KEY-----",
    ];
    if haystack.len() < PREFIX.len() {
        return false;
    }
    let last_start = haystack.len() - PREFIX.len();
    let Some(search_area) = haystack.get(..=last_start) else {
        return false;
    };
    for (idx, &b) in search_area.iter().enumerate() {
        if b != b'-' {
            continue;
        }
        if !haystack
            .get(idx..idx + PREFIX.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(PREFIX))
        {
            continue;
        }
        let scan_start = idx + PREFIX.len();
        let scan_limit = (scan_start + 64).min(haystack.len());
        let Some(window) = haystack.get(scan_start..scan_limit) else {
            continue;
        };
        for suffix in SUFFIXES {
            if let Some(pos) = window
                .windows(suffix.len())
                .position(|w| w.eq_ignore_ascii_case(suffix))
                && window.get(0..pos).is_some_and(|label| {
                    label
                        .iter()
                        .all(|&c| c.is_ascii_alphanumeric() || c == b' ' || c == b'-')
                        && (label.is_empty() || matches!(label.last(), Some(b' ' | b'-')))
                })
            {
                return true;
            }
        }
    }
    false
}

pub(crate) fn redact_unknown_arg(arg: &str) -> String {
    if let Some((flag, _val)) = arg.split_once('=') {
        let fl = flag.to_ascii_lowercase();
        if fl == "--passphrase"
            || fl == "--recovery-key"
            || fl == "--invite-secret"
            || fl == "--pin"
            || fl == "--token"
            || fl == "--secret"
            || fl == "--key"
            || fl.ends_with("-passphrase")
            || fl.ends_with("-secret")
            || fl.ends_with("-token")
            || fl.ends_with("-key")
            || fl.ends_with("-pin")
        {
            return format!("{}=[REDACTED]", sanitize_cli_meta(flag));
        }
    }
    sanitize_cli_meta(arg)
}

/// Checks if raw argv invokes `__daemon` BEFORE any Tokio runtime is created.
pub fn parse_daemon_subcommand_if_present(
    args: &[String],
) -> Result<Option<DaemonSubcommandArgs>, String> {
    let mut i = 1usize;
    let mut state_dir: Option<PathBuf> = None;
    let mut runtime_dir: Option<PathBuf> = None;
    let mut device_id: Option<u64> = None;
    let mut ready_fd: Option<i32> = None;
    let mut idle_timeout_secs: Option<u64> = None;
    let mut foreground = false;
    let mut strict_pins = false;
    let mut is_daemon = false;

    while i < args.len() {
        let arg = args.get(i).map(String::as_str).unwrap_or_default();
        match arg {
            "__daemon" if !is_daemon => {
                is_daemon = true;
                i += 1;
            }
            "--device-id" => {
                let val = next_val(args, &mut i, "--device-id")?;
                device_id = Some(parse_safe_id(val, "--device-id")?);
            }
            "--ready-fd" => {
                let val = next_val(args, &mut i, "--ready-fd")?;
                let fd = val
                    .parse::<i32>()
                    .map_err(|_| format!("invalid --ready-fd '{val}'"))?;
                ready_fd = Some(fd);
            }
            "--runtime-dir" => {
                let val = next_val(args, &mut i, "--runtime-dir")?;
                runtime_dir = Some(PathBuf::from(val));
            }
            "--state-dir" => {
                let val = next_val(args, &mut i, "--state-dir")?;
                state_dir = Some(PathBuf::from(val));
            }
            "--idle-timeout-secs" => {
                let val = next_val(args, &mut i, "--idle-timeout-secs")?;
                let secs = val
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --idle-timeout-secs '{val}'"))?;
                idle_timeout_secs = Some(secs);
            }
            "--foreground" => {
                foreground = true;
                i += 1;
            }
            "--strict-pins" => {
                strict_pins = true;
                i += 1;
            }
            _ if !is_daemon => {
                // Another subcommand; not `__daemon`.
                return Ok(None);
            }
            other => {
                return Err(format!(
                    "unknown __daemon argument: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    if !is_daemon {
        return Ok(None);
    }

    let device_id = device_id.ok_or_else(|| "__daemon requires --device-id <u64>".to_string())?;
    Ok(Some(DaemonSubcommandArgs {
        device_id,
        ready_fd,
        runtime_dir,
        state_dir,
        idle_timeout_secs,
        foreground,
        strict_pins,
    }))
}

/// Checks if raw argv invokes `mcp` stdio proxy subcommand and extracts its options.
/// `mcp setup ...` is handled as a regular CLI command.
pub fn parse_mcp_subcommand_if_present(args: &[String]) -> Result<Option<GlobalOpts>, String> {
    let (opts, rest) = extract_global_opts(args)?;
    if rest.first().map(String::as_str) != Some("mcp") {
        return Ok(None);
    }
    if rest.get(1).map(String::as_str) == Some("setup") {
        return Ok(None);
    }
    if rest.len() > 1 {
        return Err(format!(
            "unexpected argument to `mcp`: {}",
            redact_unknown_arg(rest.get(1).map(String::as_str).unwrap_or_default())
        ));
    }
    Ok(Some(opts))
}

/// Executes any non-`__daemon`, non-`mcp` CLI command.
pub async fn run_cli_command(args: &[String]) -> Result<(), String> {
    reject_secrets_in_argv(args)?;

    let (opts, rest) = extract_global_opts(args)?;
    let Some(cmd) = rest.first().map(String::as_str) else {
        print_usage();
        return Ok(());
    };

    let sub = rest.get(1..).unwrap_or_default();
    match cmd {
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        "-V" | "--version" | "version" => {
            if opts.json {
                print_json(&json!({
                    "version": PKG_VERSION,
                    "ipc_schema_ver": IPC_SCHEMA_VER,
                    "build_order": build_order(),
                    "build_digest": crate::build_info::BUILD_DIGEST_HEX,
                }));
            } else {
                println!(
                    "mp-outpost {} (schema={} order={} digest={})",
                    PKG_VERSION,
                    IPC_SCHEMA_VER,
                    build_order(),
                    crate::build_info::BUILD_DIGEST_HEX
                );
            }
            Ok(())
        }
        "login" => cmd_login(&opts, sub).await,
        "chat" => crate::chat::cmd_chat(&opts, sub).await,
        "invite" => cmd_invite(&opts, sub).await,
        "join" => cmd_join(&opts, sub).await,
        "leave" => cmd_leave(&opts, sub).await,
        "friends" => cmd_friends_live(&opts, sub).await,
        "add" => cmd_add_friend(&opts, sub).await,
        "account" => cmd_account(&opts, sub).await,
        "whoami" => cmd_whoami(&opts, sub),
        "device" => cmd_device(&opts, sub).await,
        "web" => cmd_web(&opts, sub).await,
        "doctor" => cmd_doctor(&opts, sub).await,
        "relays" => cmd_relays(&opts, sub).await,
        "lan" => crate::lan::run_lan(&opts, sub).await,
        "upgrade" => crate::upgrade::run_upgrade(&opts, sub).await,
        "mcp" => crate::mcp_setup::cmd_mcp(&opts, sub),
        "peer" | "peers" => cmd_peer(&opts, sub).await,
        "friend" => cmd_friend(&opts, sub).await,
        "party" => cmd_party(&opts, sub).await,
        "board" => cmd_board(&opts, sub).await,
        "daemon" => cmd_daemon(&opts, sub).await,
        other => Err(format!(
            "unknown subcommand '{}' (run `mp-outpost --help`)",
            redact_unknown_arg(other)
        )),
    }
}

fn print_usage() {
    println!(
        "mp-outpost {PKG_VERSION} — multiplayer.tech party sidecar & MCP bridge\n\n\
Usage:\n\
  mp-outpost [GLOBAL FLAGS] <command> ...\n\n\
Quick Start:\n\
  login [--no-open]                       Sign in via browser\n\
  chat [@handle|CODE|url]                 Open live second-window party chat\n\
  invite [@handle] [--name <name>]        Invite a friend or get a share link & 4-char code\n\
  join [@handle|CODE|url]                 Join a party (bare `join` accepts latest invite; supports multiplayer.tech, mp.gg, clank.party)\n\
  leave                                   Leave the current party\n\
  friends                                 Live friends roster & pending party invites\n\
  add @handle                             Add a friend or accept their request\n\n\
Global Flags:\n\
  --json                  Emit structured JSON output\n\
  --debug                 Show internal IDs and technical diagnostics\n\
  --strict-pins           Require manual safety-number pinning before sending\n\
  --state-dir <path>      Override state directory (or OUTPOST_STATE_DIR)\n\
  --runtime-dir <path>    Override runtime directory (or OUTPOST_RUNTIME_DIR)\n\
  --device-id <u64>       Select device ID (or OUTPOST_DEVICE_ID)\n\n\
Advanced Commands:\n\
  whoami [--safety-number]\n\
  peers list|verify|trust|revoke\n\
  party status|list|members|say|read|wait|create|join|invite|leave|disband\n\
  board post|read\n\
  friend list|add|accept|deny|decline|remove|block <@handle>\n\
  lan status|scan|host|join\n\
  mcp [setup [--client claude|codex|cursor|antigravity|hermes|gemini|opencode|zed|all] [--write] [--config <path>] [--global]]\n\
  daemon status|start|stop|restart|logs\n\
  account register|rename|recovery-key|export-mpkey|recover\n\
  device init|install-cwt|enroll|renew|revoke|link <create|join|approve>\n\
  web approve <XXXX-XXXX>\n\
  doctor | relays | upgrade"
    );
}

fn extract_global_opts(args: &[String]) -> Result<(GlobalOpts, Vec<String>), String> {
    let mut opts = GlobalOpts::default();
    let mut rest = Vec::new();
    let mut i = 1usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--state-dir" => {
                let v = next_val(args, &mut i, "--state-dir")?;
                opts.state_dir = Some(PathBuf::from(v));
            }
            "--runtime-dir" => {
                let v = next_val(args, &mut i, "--runtime-dir")?;
                opts.runtime_dir = Some(PathBuf::from(v));
            }
            "--device-id" => {
                let v = next_val(args, &mut i, "--device-id")?;
                opts.device_id = Some(parse_safe_id(v, "--device-id")?);
            }
            "--json" => {
                opts.json = true;
                i += 1;
            }
            "--debug" => {
                opts.debug = true;
                i += 1;
            }
            "--strict-pins" => {
                opts.strict_pins = true;
                i += 1;
            }
            _ => {
                rest.push(a.to_string());
                i += 1;
            }
        }
    }
    Ok((opts, rest))
}

pub(crate) fn next_val<'a>(
    args: &'a [String],
    idx: &mut usize,
    flag: &str,
) -> Result<&'a str, String> {
    let val = args
        .get(*idx + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))?;
    *idx += 2;
    Ok(val)
}

pub(crate) fn parse_safe_id(raw: &str, name: &str) -> Result<u64, String> {
    let id = raw
        .parse::<u64>()
        .map_err(|_| format!("invalid integer for {name}: '{raw}'"))?;
    if id == 0 || id > MAX_SAFE_ID {
        return Err(format!("{name} must be in 1..={MAX_SAFE_ID}"));
    }
    Ok(id)
}

fn parse_relay_policy(raw: &str) -> Result<RelayPolicy, String> {
    match raw {
        "allow" | "allow_relays" => Ok(RelayPolicy::AllowRelays),
        "force" | "force_relays" => Ok(RelayPolicy::ForceRelays),
        "no" | "none" | "no_relays" => Ok(RelayPolicy::NoRelays),
        _ => Err(format!(
            "invalid --relay-policy '{raw}' (expected allow|force|no)"
        )),
    }
}

fn validate_device_label(label: &str) -> Result<(), String> {
    if label.is_empty()
        || label.len() > 64
        || !label.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(
            "device_label must be 1..=64 printable ASCII characters (0x20..=0x7e)".to_string(),
        );
    }
    Ok(())
}

fn strip_trailing_line_ending(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

struct SyncTermiosCell(UnsafeCell<MaybeUninit<libc::termios>>);
unsafe impl Sync for SyncTermiosCell {}

static SAVED_TTY_FD: AtomicI32 = AtomicI32::new(-1);
static SAVED_TERMIOS_VALID: AtomicBool = AtomicBool::new(false);
static SAVED_TERMIOS: SyncTermiosCell = SyncTermiosCell(UnsafeCell::new(MaybeUninit::uninit()));

extern "C" fn restore_termios_on_signal(sig: libc::c_int) {
    let was_valid = SAVED_TERMIOS_VALID.swap(false, Ordering::AcqRel);
    let fd = SAVED_TTY_FD.swap(-1, Ordering::AcqRel);
    if was_valid && fd >= 0 {
        unsafe {
            let ptr = (*SAVED_TERMIOS.0.get()).as_ptr();
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

struct TermiosEchoGuard {
    fd: RawFd,
    saved: libc::termios,
    prev_sigint: libc::sigaction,
    prev_sigterm: libc::sigaction,
    signals_installed: bool,
}

impl TermiosEchoGuard {
    fn disable_echo(fd: RawFd) -> Result<Self, String> {
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return Err(format!("tcgetattr failed: {}", io::Error::last_os_error()));
        }

        // Publish saved termios BEFORE installing signal handlers so Ctrl-C / SIGTERM
        // always restores terminal echo async-signal-safely.
        SAVED_TERMIOS_VALID.store(false, Ordering::Release);
        unsafe {
            (*SAVED_TERMIOS.0.get()).write(orig);
        }
        SAVED_TTY_FD.store(fd, Ordering::Release);
        SAVED_TERMIOS_VALID.store(true, Ordering::Release);

        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = restore_termios_on_signal as *const () as usize;
        let _ = unsafe { libc::sigemptyset(&mut act.sa_mask) };

        let mut prev_sigint: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut prev_sigterm: libc::sigaction = unsafe { std::mem::zeroed() };
        let rc_int = unsafe { libc::sigaction(libc::SIGINT, &act, &mut prev_sigint) };
        let rc_term = unsafe { libc::sigaction(libc::SIGTERM, &act, &mut prev_sigterm) };
        if rc_int != 0 || rc_term != 0 {
            SAVED_TERMIOS_VALID.store(false, Ordering::Release);
            SAVED_TTY_FD.store(-1, Ordering::Release);
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
            SAVED_TERMIOS_VALID.store(false, Ordering::Release);
            SAVED_TTY_FD.store(-1, Ordering::Release);
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

impl Drop for TermiosEchoGuard {
    fn drop(&mut self) {
        SAVED_TERMIOS_VALID.store(false, Ordering::Release);
        SAVED_TTY_FD.store(-1, Ordering::Release);
        unsafe {
            let _ = libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
            if self.signals_installed {
                let _ = libc::sigaction(libc::SIGINT, &self.prev_sigint, std::ptr::null_mut());
                let _ = libc::sigaction(libc::SIGTERM, &self.prev_sigterm, std::ptr::null_mut());
            }
        }
    }
}

fn is_interactive_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

fn open_interactive_tty(op: &str) -> Result<File, String> {
    if !is_interactive_tty() {
        return Err(format!(
            "`{op}` requires an interactive terminal (TTY stdin/stdout); headless/piped execution is refused"
        ));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("failed to open controlling /dev/tty: {e}"))
}

const MAX_TTY_SECRET_BYTES: usize = 512;

fn read_secret_from_tty(op: &str, prompt: &str) -> Result<Zeroizing<String>, String> {
    let mut tty = open_interactive_tty(op)?;
    // CRITICAL (G2-L3-7): Disable echo with TCSAFLUSH BEFORE writing the prompt so
    // early keystrokes cannot echo to the terminal.
    let guard = TermiosEchoGuard::disable_echo(tty.as_raw_fd())?;
    tty.write_all(prompt.as_bytes())
        .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;
    tty.flush()
        .map_err(|e| format!("failed flushing /dev/tty: {e}"))?;

    // Unbuffered byte-by-byte read into `Zeroizing<Vec<u8>>` (zero `BufReader` residue!).
    let mut buf = Zeroizing::new(Vec::with_capacity(128));
    let mut byte = [0u8; 1];
    let mut read_err: Option<String> = None;
    loop {
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                let b = byte[0];
                byte[0] = 0;
                if b == b'\n' {
                    buf.push(b);
                    break;
                }
                if buf.len() >= MAX_TTY_SECRET_BYTES {
                    read_err = Some(format!(
                        "secret input exceeded maximum allowed {MAX_TTY_SECRET_BYTES} bytes"
                    ));
                    break;
                }
                buf.push(b);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                read_err = Some(format!("failed reading from /dev/tty: {e}"));
                break;
            }
        }
    }
    byte.zeroize();
    drop(guard);
    let _ = tty.write_all(b"\n");
    let _ = tty.flush();

    if let Some(err) = read_err {
        return Err(err);
    }

    let raw_vec = std::mem::take(&mut *buf);
    let mut s = Zeroizing::new(match String::from_utf8(raw_vec) {
        Ok(text) => text,
        Err(e) => {
            let mut bad = e.into_bytes();
            bad.zeroize();
            return Err("secret input on /dev/tty must be valid UTF-8".to_string());
        }
    });
    strip_trailing_line_ending(&mut s);
    Ok(s)
}

fn read_all_stdin_zeroizing(max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buf = Zeroizing::new(Vec::new());
    let mut handle = io::stdin().take((max_bytes as u64).saturating_add(1));
    handle
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed reading stdin: {e}"))?;
    if buf.len() > max_bytes {
        return Err(format!("stdin exceeded max allowed {max_bytes} bytes"));
    }
    Ok(buf)
}

fn read_passphrase_from_stdin() -> Result<Zeroizing<String>, String> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) == 1 } {
        return Err(
            "refusing --passphrase-stdin on an interactive terminal; omit --passphrase-stdin for masked /dev/tty prompt"
                .to_string(),
        );
    }
    let mut raw = read_all_stdin_zeroizing(1024)?;
    let raw_vec = std::mem::take(&mut *raw);
    let mut s = Zeroizing::new(match String::from_utf8(raw_vec) {
        Ok(text) => text,
        Err(e) => {
            let mut bad = e.into_bytes();
            bad.zeroize();
            return Err("passphrase on stdin must be valid UTF-8".to_string());
        }
    });
    strip_trailing_line_ending(&mut s);
    Ok(s)
}

pub(crate) fn print_json(val: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(val) {
        println!("{s}");
    }
}

fn random_bytes_32_zeroizing() -> Result<Zeroizing<[u8; 32]>, String> {
    let mut b = Zeroizing::new([0u8; 32]);
    fill_random(&mut *b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(b)
}

pub(crate) fn random_safe_id() -> Result<u64, String> {
    let mut b = [0u8; 8];
    fill_random(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok((u64::from_le_bytes(b) % MAX_SAFE_ID).saturating_add(1))
}

fn jitter_ms(max_exclusive: u64) -> u64 {
    if max_exclusive <= 1 {
        return 0;
    }
    let mut b = [0u8; 8];
    if fill_random(&mut b).is_ok() {
        u64::from_le_bytes(b) % max_exclusive
    } else {
        0
    }
}

fn wall_now_ms_adjusted(client: &ControlClient) -> u64 {
    let local = i128::from(wall_now_ms());
    let offset = i128::from(client.clock_offset_ms());
    u64::try_from(local.saturating_add(offset).max(0)).unwrap_or(u64::MAX)
}

fn classify_poll_retry_sleep(
    err: &ControlError,
    transient_attempt: u32,
    remaining: Duration,
) -> Option<Duration> {
    match err {
        ControlError::Api {
            status: 429,
            retry_after_ms,
            ..
        } => {
            let base = retry_after_ms.unwrap_or(3_000).clamp(1_000, 30_000);
            let delay = Duration::from_millis(base.saturating_add(jitter_ms(500)));
            Some(delay.min(remaining))
        }
        ControlError::Api {
            status: 500..=599, ..
        }
        | ControlError::Io(_)
        | ControlError::Timeout => {
            let exp = 1u64 << transient_attempt.min(2);
            let backoff = 2_000u64.saturating_mul(exp).min(8_000);
            let delay = Duration::from_millis(backoff.saturating_add(jitter_ms(500)));
            Some(delay.min(remaining))
        }
        _ => None,
    }
}

fn is_valid_browser_fingerprint(fp: &str) -> bool {
    fp.len() == 8 && fp.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn normalize_device_fingerprint_arg(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    let core = trimmed.strip_prefix("mpdevfp2:").map_or(trimmed, str::trim);
    let bytes = core.as_bytes();
    if bytes.len() != 35 {
        return None;
    }
    for (idx, &b) in bytes.iter().enumerate() {
        if idx == 8 || idx == 17 || idx == 26 {
            if b != b'-' {
                return None;
            }
        } else if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            return None;
        }
    }
    Some(core)
}

fn check_no_colliding_device_record(
    state_dir_path: &Path,
    candidate: &DeviceRecord,
) -> Result<(), String> {
    if let Ok(existing) = load_device_record(state_dir_path, candidate.device_id)
        && (existing.account_id != candidate.account_id
            || existing.api_authority != candidate.api_authority
            || existing.device_pubkey != candidate.device_pubkey)
    {
        return Err(format!(
            "refusing to overwrite existing device record for device_id={} (existing account_id={} authority='{}' differs from new account_id={} authority='{}')",
            candidate.device_id,
            existing.account_id,
            sanitize_cli_meta(&existing.api_authority),
            candidate.account_id,
            sanitize_cli_meta(&candidate.api_authority)
        ));
    }
    Ok(())
}

pub(crate) fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

pub(crate) fn toml_basic_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) <= 0x1F || (c as u32) == 0x7F => {
                use core::fmt::Write as _;
                let _ = write!(&mut out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn sanitize_cli_meta(input: &str) -> String {
    let cleaned = sanitize_peer_text(input);
    let mut out = String::with_capacity(cleaned.len());
    for ch in cleaned.chars() {
        match ch {
            '\n' | '\r' | '\t' | '[' | ']' | '<' | '>' | '=' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

fn read_all_stdin_trimmed(max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut handle = io::stdin().take((max_bytes as u64).saturating_add(1));
    handle
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed reading stdin: {e}"))?;
    if buf.len() > max_bytes {
        return Err(format!("stdin exceeded max allowed {max_bytes} bytes"));
    }
    Ok(buf)
}

fn read_root_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let raw = Zeroizing::new(
        read_regular_file_bounded_nofollow(path, 512)
            .map_err(|e| format!("failed to read root key file '{}': {e}", path.display()))?,
    );
    if raw.len() == 32 {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&raw);
        return Ok(out);
    }
    let text = core::str::from_utf8(&raw).map_err(|_| {
        "root key file must be 32 raw bytes, base64, 64-char hex, or mprk1_ recovery key"
            .to_string()
    })?;
    let trimmed = text.trim();
    if let Ok(seed) = decode_recovery_key(trimmed) {
        return Ok(Zeroizing::new(seed));
    }
    if let Ok(decoded) = B64.decode(trimmed.as_bytes()).map(Zeroizing::new)
        && decoded.len() == 32
    {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&decoded);
        return Ok(out);
    }
    if let Some(arr) = crate::build_info::decode_hex_32(trimmed) {
        return Ok(Zeroizing::new(arr));
    }
    Err(
        "root key file must contain 32-byte Ed25519 seed (raw, base64, 64-char hex, or mprk1_ recovery key)"
            .to_string(),
    )
}

fn write_root_key_file(path: &Path, secret: &[u8; 32]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid root key output path '{}'", path.display()))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir_fd = open_dir_nofollow(parent)
        .map_err(|e| format!("failed to open output directory '{}': {e}", parent.display()))?;
    let content = Zeroizing::new(format!("{}\n", encode_recovery_key(secret)));
    match atomic_write_in_dir_no_replace(dir_fd.as_raw_fd(), file_name, content.as_bytes(), 0o600) {
        Ok(()) => Ok(()),
        Err(DaemonError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            Err(format!(
                "refusing to overwrite existing key file '{}'",
                path.display()
            ))
        }
        Err(e) => Err(format!(
            "failed writing root key file '{}': {e}",
            path.display()
        )),
    }
}

// ---------------------------------------------------------------------------
// Daemon Client Helpers
// ---------------------------------------------------------------------------

pub(crate) async fn connect_daemon_cli(
    opts: &GlobalOpts,
    read_only_cli: bool,
    auto_spawn: bool,
) -> Result<(DaemonClient, u64), String> {
    let state_dir = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let runtime_override = resolve_effective_runtime_override(opts.runtime_dir.as_deref());
    let device_id = resolve_active_device_id(&state_dir, opts.device_id)?;

    let hello = HelloPayload {
        ipc_schema_ver: IPC_SCHEMA_VER,
        build_order: build_order(),
        build_digest: build_digest(),
        client_kind: ClientKind::Cli,
        client_pid: std::process::id(),
    };
    let mut cfg = ClientConfig::new(device_id, hello);
    cfg.runtime_dir_override = runtime_override.clone();
    cfg.read_only_cli = read_only_cli;
    cfg.on_disk_exe_matches_local = on_disk_exe_matches_local();
    if auto_spawn {
        cfg.spawn_command = Some(build_spawn_command_with_opts(
            device_id,
            &state_dir,
            runtime_override.as_deref(),
            opts.strict_pins,
        )?);
    }
    let client = DaemonClient::connect_or_spawn(&cfg)
        .await
        .map_err(|e| e.to_string())?;
    Ok((client, device_id))
}

async fn notify_daemon_reload_if_running(opts: &GlobalOpts, device_id: u64) {
    let runtime_override = resolve_effective_runtime_override(opts.runtime_dir.as_deref());
    let hello = HelloPayload {
        ipc_schema_ver: IPC_SCHEMA_VER,
        build_order: build_order(),
        build_digest: build_digest(),
        client_kind: ClientKind::Cli,
        client_pid: std::process::id(),
    };
    let mut cfg = ClientConfig::new(device_id, hello);
    cfg.runtime_dir_override = runtime_override;
    cfg.read_only_cli = true;
    cfg.spawn_command = None;
    cfg.connect_timeout = Duration::from_millis(400);
    cfg.slow_path_timeout = Duration::from_millis(400);
    cfg.exit_wait_timeout = Duration::from_millis(200);

    if let Ok(mut client) = DaemonClient::connect_or_spawn(&cfg).await
        && let Ok(raw) = client.request(IpcOpcode::ReloadDevice, Vec::new()).await
    {
        let _ = decode_reload_resp(&raw);
    }
}

// ---------------------------------------------------------------------------
// Xbox Live 1-Verb Commands (`login`, `invite`, `join`, `leave`, `friends`, `add`)
// ---------------------------------------------------------------------------

fn default_device_label() -> String {
    let raw = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "outpost".to_string());
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii() && (0x20..=0x7e).contains(&(*c as u32)))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "outpost".to_string()
    } else {
        cleaned
    }
}

fn is_safe_browser_url(url: &str) -> bool {
    url.starts_with("https://")
        && url.len() <= 512
        && url.bytes().all(|b| b > 0x20 && b < 0x7f)
}

fn try_open_browser(url: &str) -> bool {
    if std::env::var("OUTPOST_NO_BROWSER")
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
    {
        return false;
    }
    if !is_safe_browser_url(url) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

async fn cmd_login(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut api_authority = DEFAULT_API_AUTHORITY.to_string();
    let mut device_label = default_device_label();
    let mut no_open = false;
    let mut poll_interval_ms: u64 = 1_500;
    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--api-authority" => {
                api_authority = next_val(args, &mut i, "--api-authority")?.to_string();
            }
            "--device-label" => {
                device_label = next_val(args, &mut i, "--device-label")?.to_string();
            }
            "--no-open" => {
                no_open = true;
                i += 1;
            }
            "--poll-ms" => {
                poll_interval_ms = next_val(args, &mut i, "--poll-ms")?
                    .parse::<u64>()
                    .map_err(|_| "invalid --poll-ms".to_string())?
                    .clamp(50, 10_000);
            }
            other => {
                return Err(format!(
                    "unknown argument to `login`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }
    validate_device_label(&device_label)?;

    let device_secret = random_bytes_32_zeroizing()?;
    let device_pubkey = SigningKey::from_bytes(&device_secret)
        .verifying_key()
        .to_bytes();

    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let start = client
        .auth_session_start(&AuthSessionStartRequest {
            device_pubkey,
            device_label: device_label.clone(),
            client: "outpost".to_string(),
        })
        .await
        .map_err(|e| format!("failed to start login session: {e}"))?;

    let safe_code = sanitize_cli_meta(&start.user_code);
    let safe_url = sanitize_cli_meta(&start.verify_url);
    if !opts.json {
        let opened = if no_open {
            false
        } else {
            try_open_browser(&start.verify_url)
        };
        if opened {
            println!("Opening browser to sign in...");
        } else {
            println!("Open this URL to sign in: {safe_url}");
        }
        println!("Confirmation code: {safe_code}");
        println!("Waiting for approval...");
    }

    let deadline = Instant::now() + Duration::from_secs(300);
    let mut transient_attempt = 0u32;

    loop {
        if Instant::now() >= deadline {
            return Err("login timed out; run `mp-outpost login` to try again".to_string());
        }
        let now_ms = wall_now_ms_adjusted(&client);
        if start.expires_at_ms > 0 && now_ms >= start.expires_at_ms {
            return Err("login session expired; run `mp-outpost login` to try again".to_string());
        }

        match client
            .auth_session_poll(&start.flow_id, &start.poll_token)
            .await
        {
            Ok(AuthSessionPollResponse::Pending { .. }) => {
                transient_attempt = 0;
                tokio::time::sleep(Duration::from_millis(poll_interval_ms)).await;
            }
            Ok(AuthSessionPollResponse::Expired) => {
                return Err(
                    "login session expired; run `mp-outpost login` to try again".to_string()
                );
            }
            Ok(AuthSessionPollResponse::Denied) => {
                return Err("login was cancelled in browser".to_string());
            }
            Ok(AuthSessionPollResponse::Approved {
                account_id,
                handle,
                device_id,
                root_pubkey_b64,
                device_cwt_b64,
                cwt_expires_ms,
                session_token: _,
            }) => {
                let root_raw = B64
                    .decode(root_pubkey_b64.as_bytes())
                    .map_err(|_| "server returned invalid root_pubkey_b64".to_string())?;
                let root_pubkey: [u8; 32] = root_raw
                    .try_into()
                    .map_err(|_| "server returned non-32-byte root_pubkey".to_string())?;
                validate_ed25519_pubkey_strict(&root_pubkey)
                    .map_err(|e| format!("server returned invalid root_pubkey: {e}"))?;

                let device_cwt = B64
                    .decode(device_cwt_b64.as_bytes())
                    .map_err(|_| "server returned invalid device_cwt_b64".to_string())?;
                let adjusted_now_s = i64::try_from(wall_now_ms_adjusted(&client) / 1000)
                    .unwrap_or_else(|_| wall_now_secs());
                verify_device_cwt(
                    &device_cwt,
                    &root_pubkey,
                    Some(&device_pubkey),
                    adjusted_now_s,
                )
                .map_err(|e| format!("server returned invalid device_cwt: {e}"))?;

                let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
                let state_dir = open_state_dir(&state_dir_path)?;
                let lock = lock_state(&state_dir)?;
                let rec = DeviceRecord {
                    account_id,
                    device_id,
                    root_pubkey,
                    device_secret: *device_secret,
                    device_pubkey,
                    device_cwt,
                    local_relay_policy: RelayPolicy::AllowRelays,
                    api_authority: api_authority.clone(),
                    default_relay_url: DEFAULT_RELAY_URL.to_string(),
                    device_label: device_label.clone(),
                };
                save_device_record(&state_dir_path, &lock, &rec)?;
                save_default_device_id(&state_dir, &lock, device_id)?;
                drop(lock);

                notify_daemon_reload_if_running(opts, device_id).await;

                let clean_handle = sanitize_cli_meta(handle.trim_start_matches('@'));
                if opts.json {
                    print_json(&json!({
                        "status": "signed_in",
                        "handle": clean_handle,
                        "account_id": account_id,
                        "device_id": device_id,
                        "cwt_expires_ms": cwt_expires_ms,
                    }));
                } else {
                    println!("Signed in as @{clean_handle}");
                }
                return Ok(());
            }
            Err(err) => {
                let rem = deadline.saturating_duration_since(Instant::now());
                if let Some(delay) = classify_poll_retry_sleep(&err, transient_attempt, rem) {
                    transient_attempt = transient_attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
                } else {
                    return Err(format!("login failed: {err}"));
                }
            }
        }
    }
}

pub(crate) async fn rpc_get_status(client: &mut DaemonClient) -> Result<StatusResp, String> {
    let raw = client
        .request(IpcOpcode::GetStatus, Vec::new())
        .await
        .map_err(|e| e.to_string())?;
    decode_status_resp(&raw).map_err(|e| e.to_string())
}

pub(crate) async fn rpc_party_list(client: &mut DaemonClient) -> Result<PartyListResp, String> {
    let raw = client
        .request(IpcOpcode::PartyList, Vec::new())
        .await
        .map_err(|e| e.to_string())?;
    decode_party_list_resp(&raw).map_err(|e| e.to_string())
}

pub(crate) async fn rpc_party_members(
    client: &mut DaemonClient,
    party_id: u64,
) -> Result<PartyMembersResp, String> {
    let raw = client
        .request(IpcOpcode::PartyMembers, encode_u64_req(party_id))
        .await
        .map_err(|e| e.to_string())?;
    decode_party_members_resp(&raw).map_err(|e| e.to_string())
}

pub(crate) async fn rpc_room_invite(
    client: &mut DaemonClient,
    req: RoomInviteIpcReq,
) -> Result<RoomInviteIpcResp, String> {
    let raw = client
        .request(
            IpcOpcode::RoomInvite,
            encode_room_invite_req(&req).map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    decode_room_invite_resp(&raw).map_err(|e| e.to_string())
}

pub(crate) async fn rpc_room_enter(
    client: &mut DaemonClient,
    req: RoomEnterIpcReq,
) -> Result<RoomEnterIpcResp, String> {
    let raw = client
        .request(
            IpcOpcode::RoomEnter,
            encode_room_enter_req(&req).map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    decode_room_enter_resp(&raw).map_err(|e| e.to_string())
}

pub(crate) async fn rpc_room_leave(
    client: &mut DaemonClient,
    party_id: Option<u64>,
) -> Result<RoomLeaveIpcResp, String> {
    let raw = client
        .request(
            IpcOpcode::RoomLeave,
            encode_room_leave_req(&RoomLeaveIpcReq { party_id }),
        )
        .await
        .map_err(|e| e.to_string())?;
    decode_room_leave_resp(&raw).map_err(|e| e.to_string())
}

pub(crate) async fn rpc_friends_live(
    client: &mut DaemonClient,
) -> Result<FriendsLiveIpcResp, String> {
    let raw = client
        .request(IpcOpcode::FriendsLive, Vec::new())
        .await
        .map_err(|e| e.to_string())?;
    decode_friends_live_resp(&raw).map_err(|e| e.to_string())
}

pub(crate) async fn rpc_add_friend(
    client: &mut DaemonClient,
    target_str: &str,
) -> Result<(String, FriendEdgeResp), String> {
    let clean_display = sanitize_cli_meta(target_str.trim().trim_start_matches('@'));
    let target_id = resolve_account_target(client, target_str).await?;
    let raw = client
        .request(IpcOpcode::FriendRequest, encode_u64_req(target_id))
        .await
        .map_err(|e| e.to_string())?;
    let resp = decode_friend_edge_resp(&raw).map_err(|e| e.to_string())?;
    Ok((clean_display, resp))
}

async fn cmd_invite(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut handle: Option<String> = None;
    let mut name: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--name" => {
                name = Some(next_val(args, &mut i, "--name")?.to_string());
            }
            other if !other.starts_with('-') && handle.is_none() => {
                handle = Some(other.trim().trim_start_matches('@').to_string());
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown argument to `invite`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;
    let resp = rpc_room_invite(
        &mut client,
        RoomInviteIpcReq {
            handle,
            party_id: None,
            name,
        },
    )
    .await?;

    if opts.json {
        print_json(&json!({
            "party_id": resp.party_id,
            "room_code": resp.room_code,
            "share_url": resp.share_url,
            "handle_url": resp.handle_url,
            "ws_path": resp.ws_path,
            "invited_handle": resp.invited_handle,
        }));
    } else {
        let code = sanitize_cli_meta(&resp.room_code);
        let share = sanitize_cli_meta(&resp.share_url);
        if let Some(ref inv) = resp.invited_handle
            && !inv.is_empty()
        {
            println!(
                "Invited @{} — code {code} ({share})",
                sanitize_cli_meta(inv.trim_start_matches('@'))
            );
        } else {
            println!("Party ready — code {code} ({share})");
        }
        if !resp.handle_url.is_empty() {
            println!("Link: {}", sanitize_cli_meta(&resp.handle_url));
        }
        if opts.debug {
            println!("debug: party_id={} ws_path={}", resp.party_id, resp.ws_path);
        }
    }
    Ok(())
}

pub(crate) fn format_member_display(account_id: u64, raw_handle: &str) -> String {
    let trimmed = raw_handle.trim();
    let is_guest = account_id == 0 || trimmed.ends_with(" (guest)");
    let clean = sanitize_cli_meta(
        trimmed
            .trim_start_matches('@')
            .strip_suffix(" (guest)")
            .unwrap_or(trimmed.trim_start_matches('@'))
            .trim(),
    );
    if is_guest {
        if clean.is_empty() {
            "guest".to_string()
        } else {
            format!("{clean} (guest)")
        }
    } else if clean.is_empty() {
        "member".to_string()
    } else {
        format!("@{clean}")
    }
}

async fn cmd_join(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut target = String::new();
    let mut agent_name: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--agent-name" => {
                agent_name = Some(next_val(args, &mut i, "--agent-name")?.to_string());
            }
            other if !other.starts_with('-') && target.is_empty() => {
                target = other.trim().to_string();
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown argument to `join`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;
    let resp = rpc_room_enter(&mut client, RoomEnterIpcReq { target, agent_name }).await?;

    if opts.json {
        let members: Vec<Value> = resp
            .members
            .iter()
            .map(|m| {
                json!({
                    "account_id": m.account_id,
                    "handle": m.handle,
                    "client": m.client,
                    "agent_name": m.agent_name,
                    "status": m.status,
                })
            })
            .collect();
        print_json(&json!({
            "party_id": resp.party_id,
            "room_code": resp.room_code,
            "name": resp.name,
            "share_url": resp.share_url,
            "ws_path": resp.ws_path,
            "members": members,
        }));
    } else {
        let name = if resp.name.is_empty() {
            "party".to_string()
        } else {
            sanitize_cli_meta(&resp.name)
        };
        let code = sanitize_cli_meta(&resp.room_code);
        println!("Joined {name} (code {code}) · {} live", resp.members.len());
        for m in &resp.members {
            let display = format_member_display(m.account_id, &m.handle);
            let badge = if m.status == "live" || m.status.is_empty() {
                "●"
            } else {
                "○"
            };
            let client_tag = if m.client.is_empty() {
                String::new()
            } else {
                format!(" ({})", sanitize_cli_meta(&m.client))
            };
            println!("  {badge} {display}{client_tag}");
        }
        if opts.debug {
            println!("debug: party_id={} ws_path={}", resp.party_id, resp.ws_path);
        }
    }
    Ok(())
}

async fn cmd_leave(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let party_id = match args.first().map(String::as_str) {
        None => None,
        Some(raw) if args.len() == 1 => Some(parse_safe_id(raw, "<party_id>")?),
        Some(other) => {
            return Err(format!(
                "unknown argument to `leave`: {}",
                redact_unknown_arg(other)
            ));
        }
    };
    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;
    let resp = rpc_room_leave(&mut client, party_id).await?;
    if opts.json {
        print_json(&json!({
            "left": resp.left,
            "party_id": resp.party_id,
        }));
    } else {
        println!("Left party.");
    }
    Ok(())
}

async fn cmd_friends_live(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err(format!(
            "unknown argument to `friends`: {}",
            redact_unknown_arg(args.first().map(String::as_str).unwrap_or_default())
        ));
    }
    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;
    let resp = rpc_friends_live(&mut client).await?;

    if opts.json {
        let friends: Vec<Value> = resp
            .friends
            .iter()
            .map(|f| {
                json!({
                    "account_id": f.account_id,
                    "handle": f.handle,
                    "state": f.state,
                    "presence": f.presence,
                    "client": f.client,
                    "party_room_code": f.party_room_code,
                    "joinable": f.joinable,
                })
            })
            .collect();
        let invites: Vec<Value> = resp
            .pending_invites
            .iter()
            .map(|inv| {
                json!({
                    "party_id": inv.party_id,
                    "room_code": inv.room_code,
                    "from_handle": inv.from_handle,
                    "created_at_ms": inv.created_at_ms,
                })
            })
            .collect();
        print_json(&json!({
            "friends": friends,
            "pending_invites": invites,
        }));
    } else {
        if !resp.pending_invites.is_empty() {
            println!("Pending party invites:");
            for inv in &resp.pending_invites {
                println!(
                    "  ● @{} invited you (code {}) — run `mp-outpost join`",
                    sanitize_cli_meta(inv.from_handle.trim_start_matches('@')),
                    sanitize_cli_meta(&inv.room_code)
                );
            }
            if !resp.friends.is_empty() {
                println!();
            }
        }
        if resp.friends.is_empty() {
            if resp.pending_invites.is_empty() {
                println!("No friends yet. Run `mp-outpost add @handle` to add someone.");
            }
        } else {
            for f in &resp.friends {
                let h = sanitize_cli_meta(f.handle.trim_start_matches('@'));
                let icon = match f.presence.as_str() {
                    "online" | "in_party" => "●",
                    _ => "○",
                };
                let status = if f.state == "pending_in" {
                    format!("incoming request — run `mp-outpost add @{h}`")
                } else if f.state == "pending_out" {
                    "request sent".to_string()
                } else if f.presence == "in_party" {
                    match (&f.party_room_code, f.joinable) {
                        (Some(code), true) => {
                            format!("in party ({}) [Join: mp-outpost join @{h}]", sanitize_cli_meta(code))
                        }
                        (Some(code), false) => format!("in party ({})", sanitize_cli_meta(code)),
                        (None, true) => format!("in party [Join: mp-outpost join @{h}]"),
                        (None, false) => "in party".to_string(),
                    }
                } else if f.presence == "online" {
                    "online".to_string()
                } else {
                    "offline".to_string()
                };
                if opts.debug {
                    println!("{icon} @{h} — {status} (account_id={})", f.account_id);
                } else {
                    println!("{icon} @{h} — {status}");
                }
            }
        }
    }
    Ok(())
}

async fn cmd_add_friend(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let target_str = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| "usage: mp-outpost add @handle".to_string())?;
    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;
    let (clean_display, resp) = rpc_add_friend(&mut client, target_str).await?;
    let state_label = friend_state_label(resp.state);
    if opts.json {
        print_json(&json!({
            "handle": clean_display,
            "target_account_id": resp.target_account_id,
            "state": resp.state,
            "state_label": state_label,
        }));
    } else if resp.state == 0 {
        println!("You and @{clean_display} are now friends.");
    } else {
        println!("Sent friend request to @{clean_display}.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `account` Commands
// ---------------------------------------------------------------------------

async fn cmd_account(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(
            "usage: mp-outpost account <register|rename|recovery-key|export-mpkey|recover> ..."
                .to_string(),
        );
    };
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        "register" => cmd_account_register(opts, rest).await,
        "rename" => cmd_account_rename(opts, rest).await,
        "recovery-key" => cmd_account_recovery_key(opts, rest),
        "export-mpkey" => cmd_account_export_mpkey(opts, rest),
        "recover" => cmd_account_recover(opts, rest).await,
        other => Err(format!("unknown account subcommand '{other}'")),
    }
}

async fn cmd_account_register(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut handle: Option<String> = None;
    let mut root_key_out: Option<PathBuf> = None;
    let mut recovery_key_out: Option<PathBuf> = None;
    let mut invite_stdin = false;
    let mut resume = false;
    let mut device_label = "outpost".to_string();
    let mut api_authority = DEFAULT_API_AUTHORITY.to_string();

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--handle" => handle = Some(next_val(args, &mut i, "--handle")?.to_string()),
            "--root-key-out" => {
                root_key_out = Some(PathBuf::from(next_val(args, &mut i, "--root-key-out")?))
            }
            "--recovery-key-out" => {
                recovery_key_out = Some(PathBuf::from(next_val(
                    args,
                    &mut i,
                    "--recovery-key-out",
                )?))
            }
            "--invite-stdin" => {
                invite_stdin = true;
                i += 1;
            }
            "--resume" => {
                resume = true;
                i += 1;
            }
            "--device-label" => {
                device_label = next_val(args, &mut i, "--device-label")?.to_string()
            }
            "--api-authority" => {
                api_authority = next_val(args, &mut i, "--api-authority")?.to_string()
            }
            other => {
                return Err(format!(
                    "unknown argument to `account register`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    validate_device_label(&device_label)?;

    if let Some(rk_path) = recovery_key_out.as_ref()
        && rk_path.exists()
    {
        return Err(format!(
            "refusing to overwrite existing recovery key file '{}'",
            rk_path.display()
        ));
    }

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let state_dir = open_state_dir(&state_dir_path)?;

    let (pending, root_secret, device_cwt) = if resume {
        let lock = lock_state(&state_dir)?;
        let pending = load_pending_reg(&state_dir)?
            .ok_or_else(|| "no pending_reg.bin found to resume".to_string())?;
        let journaled_cwt = load_pending_reg_cwt(&state_dir)?;
        drop(lock);
        let root_path = root_key_out
            .as_ref()
            .ok_or_else(|| {
                "--resume requires --root-key-out <path> pointing to the saved root key".to_string()
            })?;
        let root_secret = read_root_key_file(root_path)?;
        let derived_root_pk = SigningKey::from_bytes(&root_secret)
            .verifying_key()
            .to_bytes();
        if derived_root_pk != pending.root_pubkey {
            return Err("root key file does not match pending_reg.bin root_pubkey".to_string());
        }
        let now_s = wall_now_secs();
        let cwt = match journaled_cwt {
            Some(existing)
                if verify_device_cwt(
                    &existing,
                    &pending.root_pubkey,
                    Some(&pending.device_pubkey),
                    now_s,
                )
                .is_ok() =>
            {
                existing
            }
            _ => {
                let root_sk = SigningKey::from_bytes(&root_secret);
                let fresh = encode_device_cwt(
                    &root_sk,
                    &pending.device_pubkey,
                    now_s,
                    now_s.saturating_add(MAX_CWT_TTL_SECS),
                )
                .map_err(|e| format!("failed signing device CWT: {e}"))?;
                let lock = lock_state(&state_dir)?;
                save_pending_reg_cwt(&state_dir, &lock, &fresh)?;
                drop(lock);
                fresh
            }
        };
        (pending, root_secret, cwt)
    } else {
        let handle = handle.ok_or_else(|| "account register requires --handle <h>".to_string())?;
        let root_path = root_key_out
            .as_ref()
            .ok_or_else(|| "account register requires --root-key-out <path>".to_string())?;
        let root_secret = random_bytes_32_zeroizing()?;
        let root_sk = SigningKey::from_bytes(&root_secret);
        let root_pubkey = root_sk.verifying_key().to_bytes();
        let device_secret = random_bytes_32_zeroizing()?;
        let device_pubkey = SigningKey::from_bytes(&device_secret)
            .verifying_key()
            .to_bytes();
        let idempotency_key = *random_bytes_32_zeroizing()?;

        let now_s = wall_now_secs();
        let device_cwt = encode_device_cwt(
            &root_sk,
            &device_pubkey,
            now_s,
            now_s.saturating_add(MAX_CWT_TTL_SECS),
        )
        .map_err(|e| format!("failed signing device CWT: {e}"))?;

        write_root_key_file(root_path, &root_secret)?;
        eprintln!(
            "WARNING: Root private key written to '{}' (mode 0600, canonical mprk1_). Move it to cold offline storage!",
            root_path.display()
        );

        let rec = PendingRegRecord {
            idempotency_key,
            root_pubkey,
            device_secret: *device_secret,
            device_pubkey,
            handle,
            device_label,
            api_authority,
        };
        let lock = lock_state(&state_dir)?;
        save_pending_reg(&state_dir, &lock, &rec)?;
        save_pending_reg_cwt(&state_dir, &lock, &device_cwt)?;
        drop(lock);
        (rec, root_secret, device_cwt)
    };

    let invite_secret = if invite_stdin {
        let mut raw = read_all_stdin_zeroizing(512)?;
        let raw_vec = std::mem::take(&mut *raw);
        let text = Zeroizing::new(match String::from_utf8(raw_vec) {
            Ok(s) => s,
            Err(e) => {
                let mut bad = e.into_bytes();
                bad.zeroize();
                return Err("invite secret on stdin must be valid UTF-8".to_string());
            }
        });
        Zeroizing::new(text.trim().to_string())
    } else {
        return Err(
            "account register requires --invite-stdin (secrets never accepted on argv)".to_string(),
        );
    };

    let cfg = build_control_client_config(&pending.api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);
    let idem_str = B64U.encode(pending.idempotency_key);
    let resp = client
        .register_account(
            *root_secret,
            &idem_str,
            &RegisterAccountRequest {
                invite_secret: invite_secret.to_string(),
                handle: pending.handle.clone(),
                device_pubkey: pending.device_pubkey,
                device_label: pending.device_label.clone(),
                device_cwt: device_cwt.clone(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    drop(invite_secret);

    let recovery_key = Zeroizing::new(encode_recovery_key(&root_secret));

    if let Some(rk_path) = recovery_key_out.as_ref() {
        write_root_key_file(rk_path, &root_secret)?;
    }
    drop(root_secret);

    let dev_rec = DeviceRecord {
        account_id: resp.account_id,
        device_id: resp.device_id,
        root_pubkey: pending.root_pubkey,
        device_secret: pending.device_secret,
        device_pubkey: pending.device_pubkey,
        device_cwt,
        local_relay_policy: RelayPolicy::AllowRelays,
        api_authority: pending.api_authority,
        default_relay_url: DEFAULT_RELAY_URL.to_string(),
        device_label: pending.device_label,
    };

    let lock = lock_state(&state_dir)?;
    save_device_record(&state_dir_path, &lock, &dev_rec)?;
    save_default_device_id(&state_dir, &lock, resp.device_id)?;
    remove_state_file(&state_dir, &lock, PENDING_REG_FILE);
    remove_state_file(&state_dir, &lock, PENDING_REG_CWT_FILE);
    drop(lock);

    let sn = compute_safety_number(resp.account_id, &pending.root_pubkey);
    let safe_handle = sanitize_cli_meta(&resp.handle);
    let written_path = recovery_key_out
        .as_ref()
        .or(root_key_out.as_ref())
        .map(|p| p.display().to_string());

    // CRITICAL (G2-L3-1): NEVER emit `mprk1_` to `--json` stdout or headless stdout!
    let mut printed_to_tty = false;
    if !opts.json
        && recovery_key_out.is_none()
        && is_interactive_tty()
        && let Ok(mut tty) = OpenOptions::new().write(true).open("/dev/tty")
    {
        let box_msg = format!(
            "\n========================================================================\n\
             IMPORTANT — SAVE YOUR RECOVERY KEY NOW:\n  {}\n\
             Store this Recovery Key in a password manager or offline backup.\n\
             Anyone with this key controls your account; multiplayer.tech cannot\n\
             recover it for you. You can also export a passphrase-protected file\n\
             with `mp-outpost account export-mpkey`.\n\
             ========================================================================\n",
            recovery_key.as_str()
        );
        if tty.write_all(box_msg.as_bytes()).is_ok() && tty.flush().is_ok() {
            printed_to_tty = true;
        }
    }
    drop(recovery_key);

    if opts.json {
        print_json(&json!({
            "account_id": resp.account_id,
            "device_id": resp.device_id,
            "handle": safe_handle,
            "safety_number": sn,
            "recovery_key_written_to": written_path,
            "recovery_key_printed_to_tty": printed_to_tty,
        }));
    } else {
        println!(
            "Registered account_id={} device_id={} handle=@{}\nSafety Number: {}",
            resp.account_id, resp.device_id, safe_handle, sn
        );
        if let Some(rk_path) = recovery_key_out.as_ref() {
            println!(
                "Recovery key written to '{}' (mode 0600).",
                rk_path.display()
            );
        } else if !printed_to_tty {
            eprintln!(
                "NOTE: Recovery key omitted from non-interactive stdout (canonical mprk1_ saved in root key file). To write a separate recovery key file, run: mp-outpost account recovery-key --root-key-file <path> --recovery-key-out <out>"
            );
        }
    }
    Ok(())
}

fn cmd_account_recovery_key(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut root_key_file: Option<PathBuf> = None;
    let mut recovery_key_out: Option<PathBuf> = None;
    let mut account_id_opt: Option<u64> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--recovery-key-out" => {
                recovery_key_out = Some(PathBuf::from(next_val(
                    args,
                    &mut i,
                    "--recovery-key-out",
                )?))
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            other => {
                return Err(format!(
                    "unknown argument to `account recovery-key`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }
    let root_path = root_key_file
        .ok_or_else(|| "account recovery-key requires --root-key-file <path>".to_string())?;
    let root_secret = read_root_key_file(&root_path)?;
    let root_pubkey = SigningKey::from_bytes(&root_secret)
        .verifying_key()
        .to_bytes();
    let root_pubkey_b64 = B64.encode(root_pubkey);

    let safety_number = account_id_opt
        .or_else(|| {
            let st = resolve_effective_state_dir(opts.state_dir.as_deref()).ok()?;
            let did = resolve_active_device_id(&st, opts.device_id).ok()?;
            let dev = load_device_record(&st, did).ok()?;
            (dev.root_pubkey == root_pubkey).then_some(dev.account_id)
        })
        .map(|aid| compute_safety_number(aid, &root_pubkey));

    // CRITICAL (G2-L3-1): NEVER emit `mprk1_` to `--json` stdout or headless stdout!
    if let Some(out_path) = recovery_key_out {
        write_root_key_file(&out_path, &root_secret)?;
        drop(root_secret);
        if opts.json {
            print_json(&json!({
                "recovery_key_written_to": out_path.display().to_string(),
                "root_pubkey_b64": root_pubkey_b64,
                "safety_number": safety_number,
            }));
        } else {
            println!(
                "Wrote canonical mprk1_ recovery key to '{}' (mode 0600).",
                out_path.display()
            );
        }
        return Ok(());
    }

    if opts.json {
        return Err(
            "refusing to emit recovery key in --json stdout; pass --recovery-key-out <path> to write a mode-0600 file"
                .to_string(),
        );
    }

    let mut tty = open_interactive_tty("account recovery-key").map_err(|e| {
        format!("{e}; pass --recovery-key-out <path> to write a mode-0600 recovery key file")
    })?;
    let recovery_key = Zeroizing::new(encode_recovery_key(&root_secret));
    drop(root_secret);
    let line = Zeroizing::new(format!("{}\n", recovery_key.as_str()));
    tty.write_all(line.as_bytes())
        .and_then(|()| tty.flush())
        .map_err(|e| format!("failed writing recovery key to /dev/tty: {e}"))?;
    Ok(())
}

fn cmd_account_export_mpkey(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut root_key_file: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut account_id: Option<u64> = None;
    let mut handle: Option<String> = None;
    let mut passphrase_stdin = false;
    let mut force = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--out" => out_path = Some(PathBuf::from(next_val(args, &mut i, "--out")?)),
            "--account-id" => {
                account_id = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--handle" => handle = Some(next_val(args, &mut i, "--handle")?.to_string()),
            "--passphrase-stdin" => {
                passphrase_stdin = true;
                i += 1;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            "--passphrase" => {
                return Err(
                    "refusing --passphrase on argv; use --passphrase-stdin or interactive /dev/tty"
                        .to_string(),
                );
            }
            other => {
                return Err(format!(
                    "unknown argument to `account export-mpkey`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let root_path = root_key_file
        .ok_or_else(|| "account export-mpkey requires --root-key-file <path>".to_string())?;
    let out_path =
        out_path.ok_or_else(|| "account export-mpkey requires --out <file.mpkey>".to_string())?;
    if !force && out_path.exists() {
        return Err(format!(
            "refusing to overwrite existing .mpkey file '{}' (pass --force to replace)",
            out_path.display()
        ));
    }

    let root_secret = read_root_key_file(&root_path)?;
    let root_pubkey = SigningKey::from_bytes(&root_secret)
        .verifying_key()
        .to_bytes();

    let passphrase = if passphrase_stdin {
        read_passphrase_from_stdin()?
    } else {
        let p1 = read_secret_from_tty("account export-mpkey", "Enter passphrase: ")?;
        let p2 = read_secret_from_tty("account export-mpkey", "Confirm passphrase: ")?;
        if p1.as_str() != p2.as_str() {
            return Err("passphrases do not match".to_string());
        }
        p1
    };

    if passphrase.is_empty() {
        return Err("passphrase must not be empty".to_string());
    }
    if passphrase.chars().count() < 12 {
        eprintln!(
            "WARNING: Passphrase is shorter than 12 characters; consider using a stronger passphrase."
        );
    }

    let pem = encrypt_mpkey(&root_secret, &passphrase, account_id, handle.as_deref())?;
    drop(passphrase);
    drop(root_secret);

    if force {
        write_mpkey_atomic_0600_with_force(&out_path, &pem, true)?;
    } else {
        write_mpkey_atomic_0600(&out_path, &pem)?;
    }

    let root_pubkey_b64 = B64.encode(root_pubkey);
    if opts.json {
        print_json(&json!({
            "exported": true,
            "path": out_path.display().to_string(),
            "account_id": account_id,
            "handle": handle,
            "root_pubkey_b64": root_pubkey_b64,
        }));
    } else {
        println!(
            "Exported encrypted .mpkey recovery file to '{}' (mode 0600).",
            out_path.display()
        );
    }
    Ok(())
}

async fn cmd_account_recover(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut recovery_key_stdin = false;
    let mut mpkey_path: Option<PathBuf> = None;
    let mut passphrase_stdin = false;
    let mut root_key_file: Option<PathBuf> = None;
    let mut device_label: Option<String> = None;
    let mut root_key_out: Option<PathBuf> = None;
    let mut relay_policy = RelayPolicy::AllowRelays;
    let mut api_authority = DEFAULT_API_AUTHORITY.to_string();
    let mut relay_url = DEFAULT_RELAY_URL.to_string();

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--recovery-key-stdin" => {
                recovery_key_stdin = true;
                i += 1;
            }
            "--mpkey" => mpkey_path = Some(PathBuf::from(next_val(args, &mut i, "--mpkey")?)),
            "--passphrase-stdin" => {
                passphrase_stdin = true;
                i += 1;
            }
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--device-label" => {
                device_label = Some(next_val(args, &mut i, "--device-label")?.to_string())
            }
            "--root-key-out" => {
                root_key_out = Some(PathBuf::from(next_val(args, &mut i, "--root-key-out")?))
            }
            "--relay-policy" => {
                relay_policy = parse_relay_policy(next_val(args, &mut i, "--relay-policy")?)?
            }
            "--api-authority" => {
                api_authority = next_val(args, &mut i, "--api-authority")?.to_string()
            }
            "--relay-url" => relay_url = next_val(args, &mut i, "--relay-url")?.to_string(),
            "--recovery-key" | "--passphrase" => {
                return Err(format!(
                    "refusing {a} on argv; use --recovery-key-stdin, --mpkey [--passphrase-stdin], --root-key-file, or interactive /dev/tty"
                ));
            }
            other => {
                return Err(format!(
                    "unknown argument to `account recover`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let device_label = device_label
        .ok_or_else(|| "account recover requires --device-label <name>".to_string())?;
    validate_device_label(&device_label)?;

    let source_count = usize::from(recovery_key_stdin)
        + usize::from(mpkey_path.is_some())
        + usize::from(root_key_file.is_some());
    if source_count > 1 {
        return Err(
            "specify at most one of --recovery-key-stdin, --mpkey, or --root-key-file".to_string(),
        );
    }
    if passphrase_stdin && mpkey_path.is_none() {
        return Err("--passphrase-stdin requires --mpkey <path>".to_string());
    }

    // Validate local state directory and `--root-key-out` no-clobber BEFORE any network call!
    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let state_dir = open_state_dir(&state_dir_path)?;
    if let Some(out_path) = root_key_out.as_ref()
        && out_path.exists()
    {
        return Err(format!(
            "refusing to overwrite existing root key file '{}'",
            out_path.display()
        ));
    }

    let mut mpkey_expected_account_id: Option<u64> = None;
    let root_secret: Zeroizing<[u8; 32]> = if recovery_key_stdin {
        if unsafe { libc::isatty(libc::STDIN_FILENO) == 1 } {
            return Err(
                "refusing --recovery-key-stdin on an interactive terminal; omit --recovery-key-stdin for masked /dev/tty prompt"
                    .to_string(),
            );
        }
        let mut raw = read_all_stdin_zeroizing(256)?;
        let raw_vec = std::mem::take(&mut *raw);
        let mut s = Zeroizing::new(match String::from_utf8(raw_vec) {
            Ok(text) => text,
            Err(e) => {
                let mut bad = e.into_bytes();
                bad.zeroize();
                return Err("recovery key on stdin must be valid ASCII/UTF-8".to_string());
            }
        });
        // Strip ONLY a single trailing newline; do NOT `.trim()` so `decode_recovery_key`'s
        // pre-trim ASCII + <= 128 byte check runs on raw input!
        strip_trailing_line_ending(&mut s);
        let seed = decode_recovery_key(s.as_str()).map_err(|e| e.to_string())?;
        Zeroizing::new(seed)
    } else if let Some(path) = mpkey_path {
        let raw_bytes = read_regular_file_bounded_nofollow(&path, MAX_PEM_BYTES)
            .map_err(|e| format!("failed to read .mpkey file '{}': {e}", path.display()))?;
        let pem = String::from_utf8(raw_bytes)
            .map_err(|_| format!(".mpkey file '{}' is not valid UTF-8", path.display()))?;
        let passphrase = if passphrase_stdin {
            read_passphrase_from_stdin()?
        } else {
            read_secret_from_tty("account recover", "Enter .mpkey passphrase: ")?
        };
        let payload = decrypt_mpkey(&pem, &passphrase)?;
        drop(passphrase);
        mpkey_expected_account_id = payload.account_id;
        Zeroizing::new(payload.root_seed)
    } else if let Some(path) = root_key_file {
        read_root_key_file(&path)?
    } else {
        let rk = read_secret_from_tty("account recover", "Enter Recovery Key (mprk1_...): ")?;
        // `read_secret_from_tty` strips only trailing line ending; pass directly to `decode_recovery_key`!
        let seed = decode_recovery_key(rk.as_str()).map_err(|e| e.to_string())?;
        Zeroizing::new(seed)
    };

    let root_sk = SigningKey::from_bytes(&root_secret);
    let root_pubkey = root_sk.verifying_key().to_bytes();

    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let lookup = client
        .recover_lookup(*root_secret)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(mpkey_aid) = mpkey_expected_account_id
        && mpkey_aid != lookup.account_id
    {
        return Err(format!(
            "REFUSING recovery: .mpkey account_id={mpkey_aid} disagrees with server lookup account_id={}",
            lookup.account_id
        ));
    }

    let srv_root_pk = B64
        .decode(lookup.root_pubkey_b64.trim().as_bytes())
        .map_err(|e| format!("invalid server root_pubkey_b64: {e}"))?;
    if srv_root_pk.as_slice() != root_pubkey.as_slice() {
        return Err(
            "REFUSING recovery: server returned a different root_pubkey than local Recovery Key!"
                .to_string(),
        );
    }

    let local_sn = compute_safety_number(lookup.account_id, &root_pubkey);
    if lookup.safety_number != local_sn {
        return Err(format!(
            "REFUSING recovery: server safety_number '{}' disagrees with locally computed '{local_sn}'!",
            sanitize_cli_meta(&lookup.safety_number)
        ));
    }

    let safe_handle = sanitize_cli_meta(&lookup.handle);
    let active_list: Vec<_> = lookup
        .devices
        .iter()
        .filter(|d| d.revoked_at_ms.is_none())
        .collect();

    // Display verified account identity and active device inventory BEFORE enrolling
    // (so if the account is at the 8-device limit, the operator sees all active devices immediately!).
    if !opts.json {
        println!(
            "Verified account @{} (account_id={})\nSafety Number: {}",
            safe_handle, lookup.account_id, local_sn
        );
        if !active_list.is_empty() {
            println!("Currently active devices on this account ({}):", active_list.len());
            for d in &active_list {
                println!(
                    "  - device_id={} label=\"{}\" (cwt_expires_ms={})",
                    d.device_id,
                    sanitize_cli_meta(&d.label),
                    d.cwt_expires_ms
                );
            }
        }
    }

    let device_secret = random_bytes_32_zeroizing()?;
    let device_pubkey = SigningKey::from_bytes(&device_secret)
        .verifying_key()
        .to_bytes();
    let now_s = wall_now_secs();
    let device_cwt = encode_device_cwt(
        &root_sk,
        &device_pubkey,
        now_s,
        now_s.saturating_add(MAX_CWT_TTL_SECS),
    )
    .map_err(|e| format!("failed signing device CWT: {e}"))?;

    let aid = AccountId::new(lookup.account_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);
    let enroll_resp = client
        .enroll_device(
            &root_signer,
            &EnrollDeviceRequest {
                device_pubkey,
                device_label: device_label.clone(),
                device_cwt: device_cwt.clone(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    let dev_rec = DeviceRecord {
        account_id: lookup.account_id,
        device_id: enroll_resp.device_id,
        root_pubkey,
        device_secret: *device_secret,
        device_pubkey,
        device_cwt,
        local_relay_policy: relay_policy,
        api_authority,
        default_relay_url: relay_url,
        device_label,
    };
    drop(device_secret);

    let lock = lock_state(&state_dir)?;
    check_no_colliding_device_record(&state_dir_path, &dev_rec).map_err(|e| {
        format!(
            "{e} (newly enrolled server device_id={}; revoke with `mp-outpost device revoke --device-id {}` if unused)",
            enroll_resp.device_id, enroll_resp.device_id
        )
    })?;
    save_device_record(&state_dir_path, &lock, &dev_rec).map_err(|e| {
        format!(
            "failed saving recovered device record (enrolled device_id={}): {e}",
            enroll_resp.device_id
        )
    })?;
    save_default_device_id(&state_dir, &lock, enroll_resp.device_id).map_err(|e| {
        format!(
            "failed saving default device id (enrolled device_id={}): {e}",
            enroll_resp.device_id
        )
    })?;
    drop(lock);

    if let Some(out_path) = root_key_out.as_ref() {
        write_root_key_file(out_path, &root_secret).map_err(|e| {
            format!(
                "device_id={} was enrolled and saved, but failed writing --root-key-out: {e}",
                enroll_resp.device_id
            )
        })?;
        eprintln!(
            "WARNING: Root private key written to '{}' (mode 0600, canonical mprk1_). Move it to cold offline storage!",
            out_path.display()
        );
    }
    drop(root_secret);

    notify_daemon_reload_if_running(opts, enroll_resp.device_id).await;

    let active_existing: Vec<Value> = active_list
        .iter()
        .map(|d| {
            json!({
                "device_id": d.device_id,
                "label": sanitize_cli_meta(&d.label),
                "cwt_expires_ms": d.cwt_expires_ms,
                "created_at_ms": d.created_at_ms,
            })
        })
        .collect();

    if opts.json {
        print_json(&json!({
            "account_id": lookup.account_id,
            "handle": safe_handle,
            "device_id": enroll_resp.device_id,
            "cwt_expires_ms": enroll_resp.cwt_expires_ms,
            "safety_number": local_sn,
            "active_devices": active_existing,
        }));
    } else {
        println!(
            "Recovered @{} (account_id={})\nNew device_id: {}\nSafety Number: {}",
            safe_handle, lookup.account_id, enroll_resp.device_id, local_sn
        );
        if !active_list.is_empty() {
            if is_interactive_tty()
                && let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty")
            {
                let prompt = "\nRevoke a lost/stolen device now? Enter device_id (or press Enter to skip): ";
                if tty.write_all(prompt.as_bytes()).is_ok()
                    && tty.flush().is_ok()
                    && let Ok(cloned) = tty.try_clone()
                {
                    let mut reader = BufReader::new(cloned);
                    let mut choice = String::new();
                    if reader.read_line(&mut choice).is_ok() {
                        let trimmed = choice.trim();
                        if !trimmed.is_empty() {
                            match parse_safe_id(trimmed, "device_id") {
                                Ok(rev_id) if active_list.iter().any(|d| d.device_id == rev_id) => {
                                    let confirm_prompt = format!(
                                        "Confirm revoking device_id={rev_id}? Type 'yes': "
                                    );
                                    if tty.write_all(confirm_prompt.as_bytes()).is_ok()
                                        && tty.flush().is_ok()
                                    {
                                        let mut conf = String::new();
                                        if reader.read_line(&mut conf).is_ok()
                                            && conf.trim() == "yes"
                                            && let Ok(did) = DeviceId::new(rev_id)
                                        {
                                            match client.revoke_device(&root_signer, did).await {
                                                Ok(r) => println!(
                                                    "Revoked device_id={rev_id} (revoked={}).",
                                                    r.revoked
                                                ),
                                                Err(e) => eprintln!(
                                                    "warning: failed revoking device_id={rev_id}: {e}"
                                                ),
                                            }
                                        } else {
                                            println!("Skipped device revocation.");
                                        }
                                    }
                                }
                                _ => {
                                    eprintln!(
                                        "warning: '{trimmed}' is not one of the previously active devices; skipping revocation."
                                    );
                                }
                            }
                        }
                    }
                }
            } else {
                println!(
                    "To revoke a lost or stolen machine, run:\n  mp-outpost device revoke --device-id <id> --root-key-file <path>"
                );
            }
        }
    }
    Ok(())
}

async fn cmd_account_rename(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut handle: Option<String> = None;
    let mut root_key_file: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--handle" => handle = Some(next_val(args, &mut i, "--handle")?.to_string()),
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            other => {
                return Err(format!(
                    "unknown argument to `account rename`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }
    let handle = handle.ok_or_else(|| "account rename requires --handle <h>".to_string())?;
    let root_path = root_key_file
        .ok_or_else(|| "account rename requires --root-key-file <path>".to_string())?;
    let root_secret = read_root_key_file(&root_path)?;

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
    let dev = load_device_record(&state_dir_path, device_id)?;
    let aid = AccountId::new(dev.account_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);
    drop(root_secret);

    let cfg = build_control_client_config(&dev.api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);
    let resp = client
        .rename_handle(&root_signer, &handle)
        .await
        .map_err(|e| e.to_string())?;

    let safe_handle = sanitize_cli_meta(&resp.handle);
    if opts.json {
        print_json(&json!({
            "account_id": resp.account_id,
            "handle": safe_handle,
        }));
    } else {
        println!("Renamed account {} -> {}", resp.account_id, safe_handle);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `whoami` Command (Offline!)
// ---------------------------------------------------------------------------

fn cmd_whoami(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut show_sn = false;
    for a in args {
        match a.as_str() {
            "--safety-number" => show_sn = true,
            other => {
                return Err(format!(
                    "unknown argument to `whoami`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
    let dev = load_device_record(&state_dir_path, device_id)?;
    let sn = compute_safety_number(dev.account_id, &dev.root_pubkey);
    let fp = pubkey_fingerprint_hex(&dev.root_pubkey);

    if opts.json {
        print_json(&json!({
            "account_id": dev.account_id,
            "device_id": dev.device_id,
            "device_label": dev.device_label,
            "api_authority": dev.api_authority,
            "local_relay_policy": relay_policy_name(dev.local_relay_policy as u8),
            "default_relay_url": dev.default_relay_url,
            "root_pubkey_b64": B64.encode(dev.root_pubkey),
            "root_pubkey_fingerprint": fp,
            "device_pubkey_b64": B64.encode(dev.device_pubkey),
            "safety_number": sn,
        }));
    } else if show_sn {
        println!("{sn}");
    } else if opts.debug {
        println!(
            "account_id:    {}\ndevice_id:     {}\ndevice_label:  {}\napi_authority: {}\nrelay_policy:  {}\nsafety_number: {}",
            dev.account_id,
            dev.device_id,
            dev.device_label,
            dev.api_authority,
            relay_policy_name(dev.local_relay_policy as u8),
            sn
        );
    } else {
        println!(
            "device:  {}\nserver:  {}",
            sanitize_cli_meta(&dev.device_label),
            sanitize_cli_meta(&dev.api_authority),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `device` Commands
// ---------------------------------------------------------------------------

async fn cmd_device(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(
            "usage: mp-outpost device <init|install-cwt|enroll|renew|revoke|link> ...".to_string(),
        );
    };
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        "init" => cmd_device_init(opts, rest),
        "install-cwt" => cmd_device_install_cwt(opts, rest).await,
        "enroll" => cmd_device_enroll(opts, rest).await,
        "renew" => cmd_device_renew(opts, rest).await,
        "revoke" => cmd_device_revoke(opts, rest).await,
        "link" => cmd_device_link(opts, rest).await,
        other => Err(format!("unknown device subcommand '{other}'")),
    }
}

async fn cmd_device_link(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost device link <create|join|approve> ...".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        "create" => cmd_device_link_create(opts, rest).await,
        "join" => cmd_device_link_join(opts, rest).await,
        "approve" => cmd_device_link_approve(opts, rest).await,
        other => Err(format!("unknown device link subcommand '{other}'")),
    }
}

async fn cmd_device_link_create(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut root_key_file: Option<PathBuf> = None;
    let mut device_label: Option<String> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut api_authority_opt: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--device-label" => {
                device_label = Some(next_val(args, &mut i, "--device-label")?.to_string())
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--api-authority" => {
                api_authority_opt = Some(next_val(args, &mut i, "--api-authority")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `device link create`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    if let Some(lbl) = device_label.as_deref() {
        validate_device_label(lbl)?;
    }
    let root_path = root_key_file
        .ok_or_else(|| "device link create requires --root-key-file <path>".to_string())?;
    let root_secret = read_root_key_file(&root_path)?;

    let (account_id, api_authority) = resolve_account_and_authority(
        opts,
        account_id_opt,
        api_authority_opt.as_deref(),
    )?;

    let aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);
    drop(root_secret);

    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);
    let resp = client
        .device_link_create(&root_signer, device_label.as_deref())
        .await
        .map_err(|e| e.to_string())?;

    if opts.json {
        print_json(&json!({
            "link_code": resp.link_code,
            "expires_at_ms": resp.expires_at_ms,
            "account_id": account_id,
        }));
    } else {
        let safe_code = sanitize_cli_meta(&resp.link_code);
        let quoted_code = shell_single_quote(&resp.link_code);
        let quoted_root = shell_single_quote(&root_path.display().to_string());
        println!(
            "Created device link code: {safe_code} (expires_at_ms={})\n\n\
             Run this on your new machine:\n  mp-outpost device link join {quoted_code} --device-label <name>\n\n\
             Then approve on this machine:\n  mp-outpost device link approve {quoted_code} --root-key-file {quoted_root} --wait",
            resp.expires_at_ms
        );
    }
    Ok(())
}

async fn cmd_device_link_join(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let link_code = args
        .first()
        .map(String::as_str)
        .filter(|s| !s.starts_with('-'))
        .ok_or_else(|| {
            "usage: mp-outpost device link join <XXXX-XXXX> [--device-label <name>] [--relay-policy <allow|force|no>] [--api-authority <host>] [--relay-url <url>] [--timeout-secs <n>] [--set-default] [--yes-safety-number <sn>]"
                .to_string()
        })?
        .to_string();

    let mut device_label = "outpost".to_string();
    let mut relay_policy = RelayPolicy::AllowRelays;
    let mut api_authority = DEFAULT_API_AUTHORITY.to_string();
    let mut relay_url = DEFAULT_RELAY_URL.to_string();
    let mut timeout_secs: u64 = 300;
    let mut set_default = false;
    let mut yes_safety_number: Option<String> = None;

    let mut i = 1usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--device-label" => {
                device_label = next_val(args, &mut i, "--device-label")?.to_string()
            }
            "--relay-policy" => {
                relay_policy = parse_relay_policy(next_val(args, &mut i, "--relay-policy")?)?
            }
            "--api-authority" => {
                api_authority = next_val(args, &mut i, "--api-authority")?.to_string()
            }
            "--relay-url" => relay_url = next_val(args, &mut i, "--relay-url")?.to_string(),
            "--timeout-secs" => {
                let raw = next_val(args, &mut i, "--timeout-secs")?;
                timeout_secs = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --timeout-secs '{raw}'"))?;
                if timeout_secs == 0 || timeout_secs > 600 {
                    return Err("--timeout-secs must be in 1..=600".to_string());
                }
            }
            "--set-default" => {
                set_default = true;
                i += 1;
            }
            "--yes-safety-number" => {
                yes_safety_number =
                    Some(next_val(args, &mut i, "--yes-safety-number")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `device link join`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    validate_device_label(&device_label)?;

    // Validate local state dir BEFORE calling `device_link_claim` so we fail fast on bad paths/permissions!
    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let state_dir = open_state_dir(&state_dir_path)?;

    let device_secret = random_bytes_32_zeroizing()?;
    let device_pubkey = SigningKey::from_bytes(&device_secret)
        .verifying_key()
        .to_bytes();

    // ALWAYS compute the 128-bit mpdevfp2: fingerprint LOCALLY (never trust server copy!).
    let local_fp = compute_device_fingerprint(&device_pubkey);

    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let claim = client
        .device_link_claim(*device_secret, &link_code, Some(&device_label))
        .await
        .map_err(|e| e.to_string())?;
    let poll_token = Zeroizing::new(claim.poll_token);

    if opts.json {
        eprintln!("Device fingerprint (verify on primary): {local_fp}");
    } else {
        println!("Device fingerprint (verify on primary): {local_fp}");
        println!("Waiting for approval on primary machine...");
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut transient_attempt = 0u32;
    let approved = loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out after {timeout_secs}s waiting for primary approval"
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        let poll_res = tokio::time::timeout(
            remaining,
            client.device_link_poll(*device_secret, &link_code, poll_token.as_str()),
        )
        .await;
        match poll_res {
            Err(_) => {
                return Err(format!(
                    "timed out after {timeout_secs}s waiting for primary approval"
                ));
            }
            Ok(Ok(DeviceLinkPollResponse::Approved {
                account_id,
                handle,
                device_id,
                root_pubkey_b64,
                device_cwt_b64,
                cwt_expires_ms: _unverified_server_exp,
                safety_number,
            })) => {
                break (
                    account_id,
                    handle,
                    device_id,
                    root_pubkey_b64,
                    device_cwt_b64,
                    safety_number,
                );
            }
            Ok(Ok(DeviceLinkPollResponse::Pending { expires_at_ms })) => {
                transient_attempt = 0;
                let now = Instant::now();
                if wall_now_ms_adjusted(&client) >= expires_at_ms {
                    return Err("device link code expired before approval".to_string());
                }
                if now >= deadline {
                    return Err(format!(
                        "timed out after {timeout_secs}s waiting for primary approval"
                    ));
                }
                let rem = deadline.saturating_duration_since(now);
                let sleep_dur = Duration::from_millis(3_000 + jitter_ms(500)).min(rem);
                tokio::time::sleep(sleep_dur).await;
            }
            Ok(Err(err)) => {
                let now = Instant::now();
                let rem = deadline.saturating_duration_since(now);
                if rem.is_zero() {
                    return Err(format!(
                        "timed out after {timeout_secs}s waiting for primary approval (last error: {err})"
                    ));
                }
                if let Some(sleep_dur) = classify_poll_retry_sleep(&err, transient_attempt, rem) {
                    transient_attempt = transient_attempt.saturating_add(1);
                    tokio::time::sleep(sleep_dur).await;
                } else {
                    return Err(err.to_string());
                }
            }
        }
    };
    drop(poll_token);

    let (account_id, handle, device_id, root_pubkey_b64, device_cwt_b64, server_sn) = approved;

    let _ = AccountId::new(account_id).map_err(|e| format!("invalid server account_id: {e}"))?;
    let _ = DeviceId::new(device_id).map_err(|e| format!("invalid server device_id: {e}"))?;

    let root_raw = B64
        .decode(root_pubkey_b64.trim().as_bytes())
        .map_err(|e| format!("invalid root_pubkey_b64 from server: {e}"))?;
    let root_pubkey: [u8; 32] = root_raw
        .try_into()
        .map_err(|_| "server root_pubkey_b64 did not decode to 32 bytes".to_string())?;
    let _ = validate_ed25519_pubkey_strict(&root_pubkey)
        .map_err(|e| format!("invalid server root_pubkey: {e}"))?;

    let device_cwt = B64
        .decode(device_cwt_b64.trim().as_bytes())
        .map_err(|e| format!("invalid device_cwt_b64 from server: {e}"))?;

    // Strictly verify returned CWT against root_pubkey and our own device_pubkey!
    let claims = verify_device_cwt(
        &device_cwt,
        &root_pubkey,
        Some(&device_pubkey),
        wall_now_secs(),
    )
    .map_err(|e| format!("REFUSING link completion: CWT verification failed: {e}"))?;
    let verified_cwt_expires_ms = claims.exp.saturating_mul(1_000);

    // Recompute canonical Safety Number locally and require non-empty exact match!
    let local_sn = compute_safety_number(account_id, &root_pubkey);
    if server_sn.is_empty() || server_sn != local_sn {
        return Err(format!(
            "REFUSING link completion: server safety_number '{}' disagrees with locally computed '{local_sn}'",
            sanitize_cli_meta(&server_sn)
        ));
    }

    if let Some(expected_sn) = yes_safety_number.as_deref()
        && !verify_safety_number(account_id, &root_pubkey, expected_sn.trim())
    {
        return Err(format!(
            "REFUSING link completion: --yes-safety-number '{}' does not match verified Safety Number '{local_sn}'",
            sanitize_cli_meta(expected_sn.trim())
        ));
    }

    let safe_handle = sanitize_cli_meta(&handle);
    // Display verified `@handle` and locally computed Safety Number BEFORE persisting!
    if !opts.json {
        println!(
            "Verified link approval for @{safe_handle} (account_id={account_id}, device_id={device_id})\nSafety Number: {local_sn}"
        );
    }

    let dev_rec = DeviceRecord {
        account_id,
        device_id,
        root_pubkey,
        device_secret: *device_secret,
        device_pubkey,
        device_cwt,
        local_relay_policy: relay_policy,
        api_authority,
        default_relay_url: relay_url,
        device_label,
    };
    drop(device_secret);

    let existing_default = {
        let lock = lock_state(&state_dir)?;
        check_no_colliding_device_record(&state_dir_path, &dev_rec)?;
        save_device_record(&state_dir_path, &lock, &dev_rec)?;
        let prev_default = load_default_device_id(&state_dir)?;
        if prev_default.is_none() || prev_default == Some(device_id) || set_default || yes_safety_number.is_some() {
            save_default_device_id(&state_dir, &lock, device_id)?;
            None
        } else {
            prev_default
        }
    };

    let mut default_updated = existing_default.is_none();
    if let Some(prev_id) = existing_default {
        let same_account = load_device_record(&state_dir_path, prev_id)
            .map(|r| r.account_id == account_id)
            .unwrap_or(false);
        if same_account {
            let lock = lock_state(&state_dir)?;
            save_default_device_id(&state_dir, &lock, device_id)?;
            drop(lock);
            default_updated = true;
        } else if is_interactive_tty()
            && let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty")
        {
            let prompt = format!(
                "Existing default device_id={prev_id} belongs to another account. Replace default with device_id={device_id} (@{safe_handle}, SN {local_sn})? [y/N]: "
            );
            if tty.write_all(prompt.as_bytes()).is_ok()
                && tty.flush().is_ok()
                && let Ok(cloned) = tty.try_clone()
            {
                let mut reader = BufReader::new(cloned);
                let mut answer = String::new();
                if reader.read_line(&mut answer).is_ok() {
                    let ans = answer.trim().to_ascii_lowercase();
                    if ans == "y" || ans == "yes" {
                        let lock = lock_state(&state_dir)?;
                        save_default_device_id(&state_dir, &lock, device_id)?;
                        drop(lock);
                        default_updated = true;
                    }
                }
            }
        }
    }

    notify_daemon_reload_if_running(opts, device_id).await;

    if opts.json {
        print_json(&json!({
            "linked": true,
            "account_id": account_id,
            "handle": safe_handle,
            "device_id": device_id,
            "cwt_expires_ms": verified_cwt_expires_ms,
            "safety_number": local_sn,
            "device_fingerprint": local_fp,
            "default_device_updated": default_updated,
        }));
    } else {
        println!(
            "Linked device_id={device_id} to @{safe_handle} (account_id={account_id})\nSafety Number: {local_sn}"
        );
        if !default_updated {
            println!(
                "Kept existing default device (pass --device-id {device_id} or re-run with --set-default)."
            );
        }
    }
    Ok(())
}

async fn cmd_device_link_approve(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let link_code = args
        .first()
        .map(String::as_str)
        .filter(|s| !s.starts_with('-'))
        .ok_or_else(|| {
            "usage: mp-outpost device link approve <XXXX-XXXX> --root-key-file <path> [--device-label <override>] [--account-id <u64>] [--api-authority <host>] [--wait] [--yes-fingerprint <fp>]"
                .to_string()
        })?
        .to_string();

    let mut root_key_file: Option<PathBuf> = None;
    let mut device_label_override: Option<String> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut api_authority_opt: Option<String> = None;
    let mut wait = false;
    let mut yes_fingerprint: Option<String> = None;

    let mut i = 1usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--device-label" => {
                device_label_override = Some(next_val(args, &mut i, "--device-label")?.to_string())
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--api-authority" => {
                api_authority_opt = Some(next_val(args, &mut i, "--api-authority")?.to_string())
            }
            "--wait" => {
                wait = true;
                i += 1;
            }
            "--yes-fingerprint" => {
                yes_fingerprint = Some(next_val(args, &mut i, "--yes-fingerprint")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `device link approve`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    if let Some(lbl) = device_label_override.as_deref() {
        validate_device_label(lbl)?;
    }
    if let Some(fp) = yes_fingerprint.as_deref()
        && normalize_device_fingerprint_arg(fp).is_none()
    {
        return Err(
            "invalid --yes-fingerprint (expected 35-char canonical hex fingerprint xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx)"
                .to_string(),
        );
    }

    let root_path = root_key_file
        .ok_or_else(|| "device link approve requires --root-key-file <path>".to_string())?;
    let root_secret = read_root_key_file(&root_path)?;

    let (account_id, api_authority) = resolve_account_and_authority(
        opts,
        account_id_opt,
        api_authority_opt.as_deref(),
    )?;

    let aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);
    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let wait_deadline = Instant::now() + Duration::from_secs(300);
    let mut transient_attempt = 0u32;
    let (device_pubkey_b64, claimed_label, requester_country) = loop {
        let now = Instant::now();
        let remaining = wait_deadline.saturating_duration_since(now);
        if wait && remaining.is_zero() {
            return Err("link code expired before new device claimed it".to_string());
        }
        let inspect_res = if wait {
            match tokio::time::timeout(
                remaining,
                client.device_link_inspect(&root_signer, &link_code),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    return Err("link code expired before new device claimed it".to_string());
                }
            }
        } else {
            client.device_link_inspect(&root_signer, &link_code).await
        };

        match inspect_res {
            Ok(DeviceLinkInspectResponse::PendingApproval {
                device_pubkey_b64,
                device_fingerprint: _ignored_server_fp,
                device_label,
                requester_country,
                ..
            }) => break (device_pubkey_b64, device_label, requester_country),
            Ok(DeviceLinkInspectResponse::WaitingForDevice { expires_at_ms, .. }) => {
                transient_attempt = 0;
                if !wait {
                    return Err(
                        "link code is waiting for the new device to claim it; pass --wait to poll until claimed"
                            .to_string(),
                    );
                }
                let now = Instant::now();
                if wall_now_ms_adjusted(&client) >= expires_at_ms || now >= wait_deadline {
                    return Err("link code expired before new device claimed it".to_string());
                }
                let rem = wait_deadline.saturating_duration_since(now);
                let sleep_dur = Duration::from_millis(3_000 + jitter_ms(500)).min(rem);
                tokio::time::sleep(sleep_dur).await;
            }
            Err(err) if wait => {
                let now = Instant::now();
                let rem = wait_deadline.saturating_duration_since(now);
                if rem.is_zero() {
                    return Err(format!(
                        "timed out waiting for device claim (last error: {err})"
                    ));
                }
                if let Some(sleep_dur) = classify_poll_retry_sleep(&err, transient_attempt, rem) {
                    transient_attempt = transient_attempt.saturating_add(1);
                    tokio::time::sleep(sleep_dur).await;
                } else {
                    return Err(err.to_string());
                }
            }
            Err(e) => {
                return Err(e.to_string());
            }
        }
    };

    let pub_raw = B64
        .decode(device_pubkey_b64.trim().as_bytes())
        .map_err(|e| format!("invalid device_pubkey_b64 from server: {e}"))?;
    let device_pubkey: [u8; 32] = pub_raw
        .try_into()
        .map_err(|_| "server device_pubkey_b64 did not decode to 32 bytes".to_string())?;
    let _ = validate_ed25519_pubkey_strict(&device_pubkey)
        .map_err(|e| format!("invalid claimed device_pubkey: {e}"))?;

    // ALWAYS compute the 128-bit mpdevfp2: fingerprint LOCALLY from device_pubkey!
    let local_fp = compute_device_fingerprint(&device_pubkey);
    let safe_label = sanitize_cli_meta(&claimed_label);
    let safe_country = sanitize_cli_meta(&requester_country);

    if let Some(expected_fp) = yes_fingerprint {
        let normalized = normalize_device_fingerprint_arg(&expected_fp).unwrap_or("");
        if normalized != local_fp {
            return Err(format!(
                "REFUSING approval: --yes-fingerprint '{}' does not match locally computed fingerprint '{local_fp}'",
                sanitize_cli_meta(expected_fp.trim())
            ));
        }
    } else {
        let mut tty = open_interactive_tty("device link approve").map_err(|e| {
            format!("{e} (or pass exact --yes-fingerprint <local_fp> after verifying on new machine)")
        })?;
        // Quote `device_label` cleanly and place locally computed `Device fingerprint` LAST!
        let prompt = format!(
            "Approve new device link:\n\
               Device label:        \"{safe_label}\"\n\
               Requester country:   {safe_country}\n\
               Device fingerprint:  {local_fp}\n\
             Verify the fingerprint matches the new machine, then type 'yes' to sign its 30-day CWT: "
        );
        tty.write_all(prompt.as_bytes())
            .and_then(|()| tty.flush())
            .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;
        let mut reader = BufReader::new(
            tty.try_clone()
                .map_err(|e| format!("failed cloning /dev/tty: {e}"))?,
        );
        let mut confirm = String::new();
        reader
            .read_line(&mut confirm)
            .map_err(|e| format!("failed reading from /dev/tty: {e}"))?;
        if confirm.trim() != "yes" {
            return Err("device link approval aborted by operator".to_string());
        }
    }

    let now_s = wall_now_secs();
    let root_sk = SigningKey::from_bytes(&root_secret);
    let device_cwt = encode_device_cwt(
        &root_sk,
        &device_pubkey,
        now_s,
        now_s.saturating_add(MAX_CWT_TTL_SECS),
    )
    .map_err(|e| format!("failed signing device CWT: {e}"))?;
    drop(root_secret);

    let resp = client
        .device_link_approve(
            &root_signer,
            &DeviceLinkApproveRequest {
                link_code,
                device_pubkey,
                device_cwt,
                device_label: device_label_override,
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    if !resp.approved {
        return Err("server did not confirm device link approval (approved=false)".to_string());
    }

    let safe_resp_label = sanitize_cli_meta(&resp.device_label);
    if opts.json {
        print_json(&json!({
            "approved": resp.approved,
            "account_id": resp.account_id,
            "device_id": resp.device_id,
            "device_label": safe_resp_label,
            "device_fingerprint": local_fp,
            "cwt_expires_ms": resp.cwt_expires_ms,
        }));
    } else {
        println!(
            "Approved device_id={} (label=\"{}\", fingerprint={}, cwt_expires_ms={})",
            resp.device_id, safe_resp_label, local_fp, resp.cwt_expires_ms
        );
    }
    Ok(())
}

fn cmd_device_init(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut device_label = "outpost".to_string();
    let mut relay_policy = RelayPolicy::AllowRelays;
    let mut api_authority = DEFAULT_API_AUTHORITY.to_string();
    let mut relay_url = DEFAULT_RELAY_URL.to_string();

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--device-label" => {
                device_label = next_val(args, &mut i, "--device-label")?.to_string()
            }
            "--relay-policy" => {
                relay_policy = parse_relay_policy(next_val(args, &mut i, "--relay-policy")?)?
            }
            "--api-authority" => {
                api_authority = next_val(args, &mut i, "--api-authority")?.to_string()
            }
            "--relay-url" => relay_url = next_val(args, &mut i, "--relay-url")?.to_string(),
            other => {
                return Err(format!(
                    "unknown argument to `device init`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let device_secret = random_bytes_32_zeroizing()?;
    let device_pubkey = SigningKey::from_bytes(&device_secret)
        .verifying_key()
        .to_bytes();

    let rec = PendingDeviceRecord {
        device_secret: *device_secret,
        device_pubkey,
        device_label: device_label.clone(),
        local_relay_policy: relay_policy,
        api_authority: api_authority.clone(),
        default_relay_url: relay_url.clone(),
        created_at_ms: wall_now_ms(),
    };
    drop(device_secret);

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let state_dir = open_state_dir(&state_dir_path)?;
    let lock = lock_state(&state_dir)?;
    save_pending_device(&state_dir, &lock, &rec)?;
    drop(lock);

    let pub_b64 = B64.encode(device_pubkey);
    if opts.json {
        print_json(&json!({
            "device_pubkey_b64": pub_b64,
            "device_label": device_label,
            "local_relay_policy": relay_policy_name(relay_policy as u8),
            "api_authority": api_authority,
            "default_relay_url": relay_url,
        }));
    } else {
        println!(
            "Initialized pending device.\ndevice_pubkey_b64: {pub_b64}\nNext: enroll with root key and run `mp-outpost device install-cwt`."
        );
    }
    Ok(())
}

async fn cmd_device_install_cwt(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut account_id: Option<u64> = None;
    let mut device_id: Option<u64> = opts.device_id;
    let mut root_pubkey_b64: Option<String> = None;
    let mut cwt_stdin = false;
    let mut skip_probe = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--account-id" => {
                account_id = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--device-id" => {
                device_id = Some(parse_safe_id(
                    next_val(args, &mut i, "--device-id")?,
                    "--device-id",
                )?)
            }
            "--root-pubkey-b64" => {
                root_pubkey_b64 = Some(next_val(args, &mut i, "--root-pubkey-b64")?.to_string())
            }
            "--cwt-stdin" => {
                cwt_stdin = true;
                i += 1;
            }
            "--skip-probe" => {
                skip_probe = true;
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown argument to `device install-cwt`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let account_id =
        account_id.ok_or_else(|| "device install-cwt requires --account-id <u64>".to_string())?;
    let device_id =
        device_id.ok_or_else(|| "device install-cwt requires --device-id <u64>".to_string())?;
    let root_b64 = root_pubkey_b64
        .ok_or_else(|| "device install-cwt requires --root-pubkey-b64 <b64>".to_string())?;
    if !cwt_stdin {
        return Err("device install-cwt requires --cwt-stdin".to_string());
    }

    let root_raw = B64
        .decode(root_b64.trim().as_bytes())
        .map_err(|e| format!("invalid --root-pubkey-b64: {e}"))?;
    let root_pubkey: [u8; 32] = root_raw
        .try_into()
        .map_err(|_| "--root-pubkey-b64 must decode to 32 bytes".to_string())?;

    let raw_stdin = read_all_stdin_trimmed(2048)?;
    let device_cwt = decode_cwt_input(&raw_stdin)?;

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let state_dir = open_state_dir(&state_dir_path)?;

    // Read candidate device record under StateLock, verify CWT cryptographically, then
    // drop StateLock BEFORE running the network PoP probe so we never commit an unprobed
    // device record or hold StateLock across network I/O.
    let (dev_rec, consumed_pending, claims) = {
        let lock = lock_state(&state_dir)?;
        let (dev_rec, consumed_pending) = if let Some(pending) = load_pending_device(&state_dir)? {
            (
                DeviceRecord {
                    account_id,
                    device_id,
                    root_pubkey,
                    device_secret: pending.device_secret,
                    device_pubkey: pending.device_pubkey,
                    device_cwt: device_cwt.clone(),
                    local_relay_policy: pending.local_relay_policy,
                    api_authority: pending.api_authority,
                    default_relay_url: pending.default_relay_url,
                    device_label: pending.device_label,
                },
                true,
            )
        } else {
            let mut existing = load_device_record(&state_dir_path, device_id)?;
            if existing.account_id != account_id || existing.root_pubkey != root_pubkey {
                return Err("existing device record account_id/root_pubkey mismatch".to_string());
            }
            existing.device_cwt = device_cwt.clone();
            (existing, false)
        };

        let claims = verify_device_cwt(
            &dev_rec.device_cwt,
            &dev_rec.root_pubkey,
            Some(&dev_rec.device_pubkey),
            wall_now_secs(),
        )
        .map_err(|e| format!("CWT verification failed (refusing install): {e}"))?;
        drop(lock);
        (dev_rec, consumed_pending, claims)
    };

    let mut pop_verified = false;
    if !skip_probe {
        let cfg =
            build_control_client_config(&dev_rec.api_authority).map_err(|e| e.to_string())?;
        let aid = AccountId::new(dev_rec.account_id).map_err(|e| e.to_string())?;
        let did = DeviceId::new(dev_rec.device_id).map_err(|e| e.to_string())?;
        let signer = RequestSigner::device(aid, did, dev_rec.device_secret);
        let client = ControlClient::with_device_signer(cfg, signer);
        let _ = client
            .get_me()
            .await
            .map_err(|e| format!("GET /v1/accounts/me PoP probe failed (pass --skip-probe for offline install): {e}"))?;
        pop_verified = true;
    }

    // Commit atomically only after both CWT verification and PoP probe succeed.
    let lock = lock_state(&state_dir)?;
    save_device_record(&state_dir_path, &lock, &dev_rec)?;
    save_default_device_id(&state_dir, &lock, device_id)?;
    if consumed_pending {
        remove_state_file(&state_dir, &lock, PENDING_DEV_FILE);
    }
    drop(lock);

    // Best-effort notify running daemon if one exists for this device_id.
    notify_daemon_reload_if_running(opts, device_id).await;

    let sn = compute_safety_number(dev_rec.account_id, &dev_rec.root_pubkey);
    if opts.json {
        print_json(&json!({
            "installed": true,
            "account_id": dev_rec.account_id,
            "device_id": dev_rec.device_id,
            "cwt_exp_s": claims.exp,
            "pop_verified": pop_verified,
            "safety_number": sn,
        }));
    } else {
        println!(
            "Installed CWT for account_id={} device_id={} (exp={}, pop_verified={})\nSafety Number: {}",
            dev_rec.account_id, dev_rec.device_id, claims.exp, pop_verified, sn
        );
    }
    Ok(())
}

fn decode_cwt_input(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.first() == Some(&0xd2) && raw.len() <= 256 {
        return Ok(raw.to_vec());
    }
    if let Ok(text) = core::str::from_utf8(raw) {
        let trimmed = text.trim();
        if let Ok(dec) = B64.decode(trimmed.as_bytes())
            && dec.first() == Some(&0xd2)
        {
            return Ok(dec);
        }
        if let Ok(dec) = B64U.decode(trimmed.as_bytes())
            && dec.first() == Some(&0xd2)
        {
            return Ok(dec);
        }
    }
    Err("stdin did not contain a valid COSE_Sign1 CWT (raw bytes or base64)".to_string())
}

async fn cmd_device_enroll(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut pubkey_b64: Option<String> = None;
    let mut device_label = "outpost".to_string();
    let mut root_key_file: Option<PathBuf> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut api_authority_opt: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--device-pubkey-b64" => {
                pubkey_b64 = Some(next_val(args, &mut i, "--device-pubkey-b64")?.to_string())
            }
            "--device-label" => {
                device_label = next_val(args, &mut i, "--device-label")?.to_string()
            }
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--api-authority" => {
                api_authority_opt = Some(next_val(args, &mut i, "--api-authority")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `device enroll`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let pub_b64 =
        pubkey_b64.ok_or_else(|| "device enroll requires --device-pubkey-b64 <b64>".to_string())?;
    let root_path =
        root_key_file.ok_or_else(|| "device enroll requires --root-key-file <path>".to_string())?;
    let root_secret = read_root_key_file(&root_path)?;
    let pub_raw = B64
        .decode(pub_b64.trim().as_bytes())
        .map_err(|e| format!("invalid --device-pubkey-b64: {e}"))?;
    let device_pubkey: [u8; 32] = pub_raw
        .try_into()
        .map_err(|_| "--device-pubkey-b64 must decode to 32 bytes".to_string())?;

    let (account_id, api_authority) = resolve_account_and_authority(
        opts,
        account_id_opt,
        api_authority_opt.as_deref(),
    )?;

    let now_s = wall_now_secs();
    let root_sk = SigningKey::from_bytes(&root_secret);
    let device_cwt = encode_device_cwt(
        &root_sk,
        &device_pubkey,
        now_s,
        now_s.saturating_add(MAX_CWT_TTL_SECS),
    )
    .map_err(|e| format!("failed signing device CWT: {e}"))?;

    let aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);
    drop(root_secret);
    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let resp = client
        .enroll_device(
            &root_signer,
            &EnrollDeviceRequest {
                device_pubkey,
                device_label,
                device_cwt: device_cwt.clone(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    let cwt_b64 = B64.encode(&device_cwt);
    let root_pub_b64 = B64.encode(root_sk.verifying_key().to_bytes());
    if opts.json {
        print_json(&json!({
            "account_id": account_id,
            "device_id": resp.device_id,
            "cwt_expires_ms": resp.cwt_expires_ms,
            "root_pubkey_b64": root_pub_b64,
            "device_cwt_b64": cwt_b64,
        }));
    } else {
        println!(
            "Enrolled device_id={} (expires_ms={})\nroot_pubkey_b64: {}\ndevice_cwt_b64:  {}",
            resp.device_id, resp.cwt_expires_ms, root_pub_b64, cwt_b64
        );
    }
    Ok(())
}

async fn cmd_device_renew(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut target_device_id: Option<u64> = opts.device_id;
    let mut root_key_file: Option<PathBuf> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut device_pubkey_b64_opt: Option<String> = None;
    let mut api_authority_opt: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--device-id" => {
                target_device_id = Some(parse_safe_id(
                    next_val(args, &mut i, "--device-id")?,
                    "--device-id",
                )?)
            }
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--device-pubkey-b64" => {
                device_pubkey_b64_opt =
                    Some(next_val(args, &mut i, "--device-pubkey-b64")?.to_string())
            }
            "--api-authority" => {
                api_authority_opt = Some(next_val(args, &mut i, "--api-authority")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `device renew`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let device_id = target_device_id
        .ok_or_else(|| "device renew requires --device-id <u64>".to_string())?;
    let root_path =
        root_key_file.ok_or_else(|| "device renew requires --root-key-file <path>".to_string())?;
    let root_secret = read_root_key_file(&root_path)?;

    let (account_id, api_authority) = resolve_account_and_authority(
        opts,
        account_id_opt,
        api_authority_opt.as_deref(),
    )?;

    let aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
    let did = DeviceId::new(device_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);
    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    // CRITICAL (L4-1): NEVER blindly root-sign a pubkey returned by an untrusted server!
    // Always source `device_pubkey` from explicit `--device-pubkey-b64` or derive it from the
    // local enrolled `d<13hex>.dev.bin` secret key, then cross-check against `/v1/accounts/me`.
    let device_pubkey: [u8; 32] = if let Some(b64) = device_pubkey_b64_opt {
        let raw = B64
            .decode(b64.trim().as_bytes())
            .map_err(|e| format!("invalid --device-pubkey-b64: {e}"))?;
        raw.try_into()
            .map_err(|_| "--device-pubkey-b64 must decode to 32 bytes".to_string())?
    } else {
        let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
        let local_dev = load_device_record(&state_dir_path, device_id).map_err(|_| {
            format!(
                "local enrolled record for device_id={device_id} not found; pass --device-pubkey-b64 <b64> explicitly (refusing to sign server-supplied pubkey)"
            )
        })?;
        if local_dev.account_id != account_id {
            return Err(format!(
                "local device record account_id={} does not match --account-id={account_id}",
                local_dev.account_id
            ));
        }
        let derived = SigningKey::from_bytes(&local_dev.device_secret)
            .verifying_key()
            .to_bytes();
        if derived != local_dev.device_pubkey {
            return Err("local device record device_secret/device_pubkey mismatch".to_string());
        }
        derived
    };

    // Cross-check server record if reachable: refuse to sign if the server claims a different pubkey!
    if let Ok(me) = client.get_me_with_signer(&root_signer).await
        && let Some(dev_info) = me.devices.iter().find(|d| d.device_id == device_id)
    {
        let srv_raw = B64
            .decode(dev_info.pubkey_b64.as_bytes())
            .map_err(|e| format!("invalid server pubkey_b64: {e}"))?;
        let srv_pk: [u8; 32] = srv_raw
            .try_into()
            .map_err(|_| "server device pubkey is not 32 bytes".to_string())?;
        if srv_pk != device_pubkey {
            return Err(format!(
                "REFUSING CWT renewal: server pubkey for device_id={device_id} disagrees with local/expected device_pubkey!"
            ));
        }
    }

    let now_s = wall_now_secs();
    let root_sk = SigningKey::from_bytes(&root_secret);
    let new_cwt = encode_device_cwt(
        &root_sk,
        &device_pubkey,
        now_s,
        now_s.saturating_add(MAX_CWT_TTL_SECS),
    )
    .map_err(|e| format!("failed signing renewed CWT: {e}"))?;
    drop(root_secret);

    let resp = client
        .renew_device_cwt(&root_signer, did, &new_cwt)
        .await
        .map_err(|e| e.to_string())?;

    let cwt_b64 = B64.encode(&new_cwt);
    if opts.json {
        print_json(&json!({
            "device_id": resp.device_id,
            "cwt_expires_ms": resp.cwt_expires_ms,
            "device_cwt_b64": cwt_b64,
        }));
    } else {
        println!(
            "Renewed CWT for device_id={} (expires_ms={})\ndevice_cwt_b64: {}",
            resp.device_id, resp.cwt_expires_ms, cwt_b64
        );
    }
    Ok(())
}

async fn cmd_device_revoke(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut target_device_id: Option<u64> = opts.device_id;
    let mut root_key_file: Option<PathBuf> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut api_authority_opt: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--device-id" => {
                target_device_id = Some(parse_safe_id(
                    next_val(args, &mut i, "--device-id")?,
                    "--device-id",
                )?)
            }
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--api-authority" => {
                api_authority_opt = Some(next_val(args, &mut i, "--api-authority")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `device revoke`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let device_id = target_device_id
        .ok_or_else(|| "device revoke requires --device-id <u64>".to_string())?;
    let root_path =
        root_key_file.ok_or_else(|| "device revoke requires --root-key-file <path>".to_string())?;
    let root_secret = read_root_key_file(&root_path)?;

    let (account_id, api_authority) = resolve_account_and_authority(
        opts,
        account_id_opt,
        api_authority_opt.as_deref(),
    )?;

    let aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
    let did = DeviceId::new(device_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);
    drop(root_secret);
    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let resp = client
        .revoke_device(&root_signer, did)
        .await
        .map_err(|e| e.to_string())?;

    if opts.json {
        print_json(&json!({
            "revoked": resp.revoked,
            "evicted_parties": resp.evicted_parties,
            "pending_retries": resp.pending_retries,
        }));
    } else {
        println!(
            "Revoked device_id={} (revoked={}, evicted_parties={:?})",
            device_id, resp.revoked, resp.evicted_parties
        );
    }
    Ok(())
}

fn resolve_account_and_authority(
    opts: &GlobalOpts,
    account_id_opt: Option<u64>,
    api_authority_opt: Option<&str>,
) -> Result<(u64, String), String> {
    if let (Some(aid), Some(auth)) = (account_id_opt, api_authority_opt) {
        return Ok((aid, auth.to_string()));
    }
    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    if let Ok(did) = resolve_active_device_id(&state_dir_path, opts.device_id)
        && let Ok(dev) = load_device_record(&state_dir_path, did)
    {
        return Ok((
            account_id_opt.unwrap_or(dev.account_id),
            api_authority_opt
                .map(str::to_string)
                .unwrap_or(dev.api_authority),
        ));
    }
    let aid = account_id_opt
        .ok_or_else(|| "pass --account-id <u64> when no local device is enrolled".to_string())?;
    Ok((
        aid,
        api_authority_opt
            .unwrap_or(DEFAULT_API_AUTHORITY)
            .to_string(),
    ))
}

// ---------------------------------------------------------------------------
// `peer` Commands (STRICTLY Interactive `/dev/tty` for trust & revoke!)
// ---------------------------------------------------------------------------

fn require_interactive_tty(op: &str) -> Result<File, String> {
    let stdin_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    let stdout_tty = unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 };
    if !stdin_tty || !stdout_tty {
        return Err(format!(
            "`peer {op}` requires an interactive terminal (TTY stdin/stdout); headless/piped execution is refused"
        ));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("failed to open controlling /dev/tty: {e}"))
}

async fn cmd_peer(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost peers <list|verify|trust|revoke> ...".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        "list" => cmd_peer_list(opts, rest),
        "trust" | "verify" => cmd_peer_trust(opts, rest).await,
        "revoke" => cmd_peer_revoke(opts, rest).await,
        other => Err(format!("unknown peer subcommand '{other}'")),
    }
}

fn cmd_peer_list(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err(format!(
            "unexpected argument to `peer list`: {}",
            args.first().map(String::as_str).unwrap_or_default()
        ));
    }
    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let state_dir = open_state_dir(&state_dir_path)?;
    let _lock = lock_state(&state_dir)?;
    let store = load_peers_store(&state_dir)?;

    if opts.json {
        let items: Vec<Value> = store
            .peers
            .iter()
            .map(|p| {
                json!({
                    "account_id": p.account_id,
                    "trust_state": trust_state_name(p.trust_state as u8),
                    "handle": p.handle_prop,
                    "safety_number": compute_safety_number(p.account_id, &p.root_pubkey),
                    "root_pubkey_fingerprint": pubkey_fingerprint_hex(&p.root_pubkey),
                    "pinned_at_ms": p.pinned_at_ms,
                })
            })
            .collect();
        print_json(&json!({ "peers": items }));
    } else if store.peers.is_empty() {
        println!("No pinned peers.");
    } else {
        for p in &store.peers {
            println!(
                "account_id={} state={} handle={} sn={}",
                p.account_id,
                trust_state_name(p.trust_state as u8),
                sanitize_cli_meta(&p.handle_prop),
                compute_safety_number(p.account_id, &p.root_pubkey)
            );
        }
    }
    Ok(())
}

async fn cmd_peer_trust(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    // Strictly forbid any `--safety-number` or extra flags!
    for a in args {
        if a.starts_with('-') {
            return Err(
                "`peer trust` accepts ONLY `<account_id>` and reads Safety Number interactively from /dev/tty"
                    .to_string(),
            );
        }
    }
    if args.len() != 1 {
        return Err("usage: mp-outpost peer trust <account_id>".to_string());
    }
    let account_id = parse_safe_id(
        args.first().map(String::as_str).unwrap_or_default(),
        "<account_id>",
    )?;

    // Fail closed immediately if stdin/stdout is not a real interactive TTY!
    let mut tty = require_interactive_tty("trust")?;

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
    let dev = load_device_record(&state_dir_path, device_id)?;
    let auth_hash = api_authority_hash(&dev.api_authority);

    // Discover candidate `(root_pubkey, handle)` from running daemon alerts, existing peers.bin,
    // or control-plane `GET /v1/accounts/<account_id>`.
    let (candidate_root, candidate_handle) =
        discover_peer_candidate(opts, &state_dir_path, &dev, auth_hash, account_id).await?;
    if candidate_root == [0u8; 32] {
        return Err("refusing invalid all-zero candidate root_pubkey".to_string());
    }
    let candidate_fp = pubkey_fingerprint_hex(&candidate_root);
    let short_fp = candidate_fp.get(..16).unwrap_or(candidate_fp.as_str());
    let safe_handle = sanitize_cli_meta(&candidate_handle);

    let mut reader = BufReader::new(
        tty.try_clone()
            .map_err(|e| format!("failed cloning /dev/tty handle: {e}"))?,
    );

    // Check if `peers.bin` already has a DIFFERENT pinned root_pubkey for this account!
    let existing_root_opt = {
        let state_dir = open_state_dir(&state_dir_path)?;
        let _lock = lock_state(&state_dir)?;
        let store = load_peers_store(&state_dir)?;
        store
            .peers
            .iter()
            .find(|p| p.api_authority_hash == auth_hash && p.account_id == account_id)
            .map(|p| p.root_pubkey)
            .filter(|pk| *pk != [0u8; 32])
    };
    if let Some(old_root) = existing_root_opt
        && old_root != candidate_root
    {
        let old_fp = pubkey_fingerprint_hex(&old_root);
        let warn = format!(
            "WARNING: ROOT KEY CHANGED for account_id={account_id}!\n\
             Previously pinned root fingerprint: {old_fp}\n\
             Observed new root fingerprint:      {candidate_fp}\n\
             This could indicate a MitM attack or account compromise.\n\
             Type 'yes-replace-key' to acknowledge and continue: "
        );
        tty.write_all(warn.as_bytes())
            .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;
        tty.flush()
            .map_err(|e| format!("failed flushing /dev/tty: {e}"))?;
        let mut confirm = String::new();
        reader
            .read_line(&mut confirm)
            .map_err(|e| format!("failed reading from /dev/tty: {e}"))?;
        if confirm.trim() != "yes-replace-key" {
            return Err("root key replacement aborted by operator".to_string());
        }
    }

    // Do NOT print the full expected Safety Number above the prompt — require genuine
    // out-of-band verification from the peer's `mp-outpost whoami --safety-number`.
    let prompt = format!(
        "Verifying peer account_id={account_id} (server handle: {safe_handle}, root fp: {short_fp}...)\n\
         Obtain the peer's Safety Number out-of-band (`mp-outpost whoami --safety-number`) and type it below to pin:\n> "
    );
    tty.write_all(prompt.as_bytes())
        .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;
    tty.flush()
        .map_err(|e| format!("failed flushing /dev/tty: {e}"))?;

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed reading from /dev/tty: {e}"))?;

    if !verify_safety_number(account_id, &candidate_root, line.trim()) {
        return Err("Safety Number verification FAILED; peer NOT pinned".to_string());
    }
    let expected_sn = compute_safety_number(account_id, &candidate_root);

    let state_dir = open_state_dir(&state_dir_path)?;
    let lock = lock_state(&state_dir)?;
    let mut store = load_peers_store(&state_dir)?;
    let now_ms = wall_now_ms();
    if let Some(existing) = store
        .peers
        .iter_mut()
        .find(|p| p.api_authority_hash == auth_hash && p.account_id == account_id)
    {
        existing.root_pubkey = candidate_root;
        existing.trust_state = TrustState::PinnedTrusted;
        existing.pinned_at_ms = now_ms;
        existing.handle_prop = candidate_handle.clone();
        existing.handle_fetched_ms = now_ms;
    } else {
        store.peers.push(PeerRecord {
            api_authority_hash: auth_hash,
            account_id,
            root_pubkey: candidate_root,
            trust_state: TrustState::PinnedTrusted,
            pinned_at_ms: now_ms,
            handle_prop: candidate_handle.clone(),
            handle_fetched_ms: now_ms,
        });
    }
    save_peers_store(&state_dir, &lock, &store)?;
    drop(lock);

    notify_daemon_reload_if_running(opts, device_id).await;

    println!("Pinned trusted peer account_id={account_id} ({expected_sn}).");
    Ok(())
}

async fn discover_peer_candidate(
    opts: &GlobalOpts,
    state_dir_path: &Path,
    dev: &DeviceRecord,
    auth_hash: [u8; 8],
    account_id: u64,
) -> Result<([u8; 32], String), String> {
    // 1. Check running daemon status unpinned alerts / party members (without spawning).
    if let Ok((mut client, _)) = connect_daemon_cli(opts, true, false).await
        && let Ok(raw) = client.request(IpcOpcode::GetStatus, Vec::new()).await
        && let Ok(status) = decode_status_resp(&raw)
    {
        if let Some(a) = status
            .unpinned_alerts
            .iter()
            .find(|u| u.account_id == account_id)
        {
            return Ok((a.root_pubkey, a.server_handle.clone()));
        }
        if let Some(party) = status.active_party
            && let Ok(m_raw) = client
                .request(IpcOpcode::PartyMembers, encode_u64_req(party.party_id))
                .await
            && let Ok(m_resp) = decode_party_members_resp(&m_raw)
            && let Some(m) = m_resp.members.iter().find(|m| m.account_id == account_id)
        {
            return Ok((m.root_pubkey, m.server_handle.clone()));
        }
    }

    // 2. Check existing peers.bin entry (e.g. re-trusting a previously revoked peer).
    let state_dir = open_state_dir(state_dir_path)?;
    if let Ok(store) = load_peers_store(&state_dir)
        && let Some(p) = store
            .peers
            .iter()
            .find(|p| p.api_authority_hash == auth_hash && p.account_id == account_id)
    {
        return Ok((p.root_pubkey, p.handle_prop.clone()));
    }

    // 3. Query control plane `GET /v1/accounts/<account_id>`.
    let cfg = build_control_client_config(&dev.api_authority).map_err(|e| e.to_string())?;
    let aid = AccountId::new(dev.account_id).map_err(|e| e.to_string())?;
    let did = DeviceId::new(dev.device_id).map_err(|e| e.to_string())?;
    let signer = RequestSigner::device(aid, did, dev.device_secret);
    let control = ControlClient::with_device_signer(cfg, signer);
    let target_aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
    let pub_acc = control
        .get_account(target_aid)
        .await
        .map_err(|e| format!("unable to locate candidate root_pubkey for account {account_id}: {e}"))?;
    let raw_pk = B64
        .decode(pub_acc.root_pubkey_b64.as_bytes())
        .map_err(|e| format!("invalid root_pubkey_b64: {e}"))?;
    let pk: [u8; 32] = raw_pk
        .try_into()
        .map_err(|_| "root_pubkey is not 32 bytes".to_string())?;
    Ok((pk, pub_acc.handle))
}

async fn cmd_peer_revoke(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    for a in args {
        if a.starts_with('-') {
            return Err("usage: mp-outpost peer revoke <account_id>".to_string());
        }
    }
    if args.len() != 1 {
        return Err("usage: mp-outpost peer revoke <account_id>".to_string());
    }
    let account_id = parse_safe_id(
        args.first().map(String::as_str).unwrap_or_default(),
        "<account_id>",
    )?;

    let mut tty = require_interactive_tty("revoke")?;

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
    let dev = load_device_record(&state_dir_path, device_id)?;
    let auth_hash = api_authority_hash(&dev.api_authority);

    let prompt = format!(
        "Revoke and block peer account_id={account_id}? Active P2P connections will close with 4403.\nType 'revoke' to confirm: "
    );
    tty.write_all(prompt.as_bytes())
        .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;
    tty.flush()
        .map_err(|e| format!("failed flushing /dev/tty: {e}"))?;

    let mut reader = BufReader::new(
        tty.try_clone()
            .map_err(|e| format!("failed cloning /dev/tty handle: {e}"))?,
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed reading from /dev/tty: {e}"))?;
    if line.trim() != "revoke" {
        return Err("revocation cancelled by operator".to_string());
    }

    let state_dir = open_state_dir(&state_dir_path)?;
    let lock = lock_state(&state_dir)?;
    let mut store = load_peers_store(&state_dir)?;
    let now_ms = wall_now_ms();
    if let Some(existing) = store
        .peers
        .iter_mut()
        .find(|p| p.api_authority_hash == auth_hash && p.account_id == account_id)
    {
        existing.trust_state = TrustState::RevokedBlocked;
        existing.pinned_at_ms = now_ms;
    } else {
        store.peers.push(PeerRecord {
            api_authority_hash: auth_hash,
            account_id,
            root_pubkey: [0u8; 32],
            trust_state: TrustState::RevokedBlocked,
            pinned_at_ms: now_ms,
            handle_prop: String::new(),
            handle_fetched_ms: 0,
        });
    }
    save_peers_store(&state_dir, &lock, &store)?;
    drop(lock);

    // Notify ALL enrolled local daemons so multi-device revocation takes effect immediately!
    let mut all_devices = list_enrolled_device_ids(&state_dir_path);
    if !all_devices.contains(&device_id) {
        all_devices.push(device_id);
    }
    for did in all_devices {
        notify_daemon_reload_if_running(opts, did).await;
    }
    println!("Revoked and blocked peer account_id={account_id}.");
    Ok(())
}

// ---------------------------------------------------------------------------
// `friend` Commands
// ---------------------------------------------------------------------------

fn friend_state_label(state: u8) -> &'static str {
    match state {
        0 => "friends",
        1 => "pending_out",
        2 => "pending_in",
        3 => "blocked",
        _ => "unknown",
    }
}

fn friend_state_sort_key(state: u8) -> u8 {
    match state {
        2 => 0, // Incoming pending requests FIRST!
        0 => 1, // Active friends
        1 => 2, // Outgoing pending requests
        3 => 3, // Blocked
        _ => 4,
    }
}

pub(crate) async fn resolve_account_target(
    client: &mut DaemonClient,
    raw: &str,
) -> Result<u64, String> {
    if let Ok(id) = parse_safe_id(raw, "account_id") {
        return Ok(id);
    }
    let handle = raw.strip_prefix('@').unwrap_or(raw).trim();
    if handle.is_empty() {
        return Err("handle or account_id must not be empty".to_string());
    }
    let req = encode_resolve_handle_req(handle).map_err(|e| e.to_string())?;
    let resp_raw = client
        .request(IpcOpcode::ResolveHandle, req)
        .await
        .map_err(|e| e.to_string())?;
    let resolved = decode_resolve_handle_resp(&resp_raw).map_err(|e| e.to_string())?;
    Ok(resolved.account_id)
}

async fn cmd_friend(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(
            "usage: mp-outpost friend <list|add|accept|deny|decline|remove|block> ..."
                .to_string(),
        );
    };
    let rest = args.get(1..).unwrap_or_default();
    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;

    match sub {
        "list" => {
            let raw = client
                .request(IpcOpcode::FriendsList, Vec::new())
                .await
                .map_err(|e| e.to_string())?;
            let mut resp = decode_friends_list_resp(&raw).map_err(|e| e.to_string())?;
            resp.friends.sort_by(|a, b| {
                friend_state_sort_key(a.state)
                    .cmp(&friend_state_sort_key(b.state))
                    .then_with(|| {
                        a.handle
                            .to_ascii_lowercase()
                            .cmp(&b.handle.to_ascii_lowercase())
                    })
                    .then_with(|| a.account_id.cmp(&b.account_id))
            });
            if opts.json {
                let items: Vec<Value> = resp
                    .friends
                    .iter()
                    .map(|f| {
                        json!({
                            "account_id": f.account_id,
                            "handle": f.handle,
                            "safety_number": f.safety_number,
                            "state": f.state,
                            "state_label": friend_state_label(f.state),
                            "presence_status": f.presence_status,
                            "joinable_party_id": f.joinable_party_id,
                            "updated_at_ms": f.updated_at_ms,
                        })
                    })
                    .collect();
                print_json(&json!({ "friends": items }));
            } else if resp.friends.is_empty() {
                println!("No friends.");
            } else {
                let incoming: Vec<_> = resp.friends.iter().filter(|f| f.state == 2).collect();
                if !incoming.is_empty() {
                    println!("Incoming friend requests ({}):", incoming.len());
                    for f in &incoming {
                        let safe_h = sanitize_cli_meta(&f.handle);
                        let target_ref = if safe_h.is_empty() {
                            if opts.debug {
                                f.account_id.to_string()
                            } else {
                                "unknown".to_string()
                            }
                        } else {
                            format!("@{safe_h}")
                        };
                        if opts.debug {
                            println!(
                                "  {target_ref} (account_id={} safety_number={})",
                                f.account_id,
                                sanitize_cli_meta(&f.safety_number)
                            );
                        } else {
                            println!("  {target_ref}");
                        }
                        println!(
                            "    Accept: mp-outpost add {target_ref}  |  Deny: mp-outpost friend deny {target_ref}"
                        );
                    }
                }
                let others: Vec<_> = resp.friends.iter().filter(|f| f.state != 2).collect();
                if !others.is_empty() {
                    if !incoming.is_empty() {
                        println!();
                    }
                    for f in others {
                        let safe_h = sanitize_cli_meta(&f.handle);
                        if opts.debug {
                            let handle_part = if safe_h.is_empty() {
                                String::new()
                            } else {
                                format!(" handle=@{safe_h}")
                            };
                            let sn_part = if f.safety_number.is_empty() {
                                String::new()
                            } else {
                                format!(" safety_number={}", sanitize_cli_meta(&f.safety_number))
                            };
                            println!(
                                "account_id={}{handle_part} state={} ({}) presence={}{sn_part}",
                                f.account_id,
                                friend_state_label(f.state),
                                f.state,
                                f.presence_status
                            );
                        } else {
                            let icon = if f.presence_status > 0 { "●" } else { "○" };
                            let label = if safe_h.is_empty() {
                                "friend".to_string()
                            } else {
                                format!("@{safe_h}")
                            };
                            let status = match (f.state, f.presence_status) {
                                (0, 2) => "in party",
                                (0, 1) => "online",
                                (0, _) => "offline",
                                (1, _) => "request sent",
                                (3, _) => "blocked",
                                _ => friend_state_label(f.state),
                            };
                            println!("{icon} {label} — {status}");
                        }
                    }
                }
            }
            Ok(())
        }
        "add" | "accept" => {
            let target_str = rest
                .first()
                .map(String::as_str)
                .ok_or_else(|| format!("usage: mp-outpost friend {sub} <@handle|account_id>"))?;
            let target_id = resolve_account_target(&mut client, target_str).await?;
            let raw = client
                .request(IpcOpcode::FriendRequest, encode_u64_req(target_id))
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_friend_edge_resp(&raw).map_err(|e| e.to_string())?;
            let state_label = friend_state_label(resp.state);
            if opts.json {
                print_json(&json!({
                    "target_account_id": resp.target_account_id,
                    "state": resp.state,
                    "state_label": state_label,
                }));
            } else if sub == "accept" {
                println!(
                    "Accepted friend request for account_id={} (state={} [{}])",
                    resp.target_account_id, state_label, resp.state
                );
            } else {
                println!(
                    "Friend request processed for account_id={} (state={} [{}])",
                    resp.target_account_id, state_label, resp.state
                );
            }
            Ok(())
        }
        "deny" | "decline" | "remove" => {
            let target_str = rest
                .first()
                .map(String::as_str)
                .ok_or_else(|| format!("usage: mp-outpost friend {sub} <@handle|account_id>"))?;
            let target_id = resolve_account_target(&mut client, target_str).await?;
            let raw = client
                .request(IpcOpcode::FriendRemove, encode_u64_req(target_id))
                .await
                .map_err(|e| e.to_string())?;
            let removed = decode_bool_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "target_account_id": target_id,
                    "removed": removed,
                }));
            } else if sub == "remove" {
                println!("Removed friend account_id={target_id}: {removed}");
            } else {
                println!("Declined friend request from account_id={target_id}: {removed}");
            }
            Ok(())
        }
        "block" => {
            let target_str = rest
                .first()
                .map(String::as_str)
                .ok_or_else(|| "usage: mp-outpost friend block <@handle|account_id>".to_string())?;
            let target_id = resolve_account_target(&mut client, target_str).await?;
            let raw = client
                .request(IpcOpcode::FriendBlock, encode_u64_req(target_id))
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_friend_edge_resp(&raw).map_err(|e| e.to_string())?;
            let state_label = friend_state_label(resp.state);
            if opts.json {
                print_json(&json!({
                    "target_account_id": resp.target_account_id,
                    "state": resp.state,
                    "state_label": state_label,
                }));
            } else {
                println!(
                    "Blocked account_id={} (state={} [{}])",
                    resp.target_account_id, state_label, resp.state
                );
            }
            Ok(())
        }
        other => Err(format!(
            "unknown friend subcommand '{}'",
            redact_unknown_arg(other)
        )),
    }
}

// ---------------------------------------------------------------------------
// `party` Commands
// ---------------------------------------------------------------------------

async fn cmd_party(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost party <create|join|invite|requests|approve|reject|leave|disband|kick|promote|status|list|members|say|read|wait> ...".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();
    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;

    match sub {
        "create" => {
            let mut visibility = PartyVisibility::Private;
            let mut join_mode = PartyJoinMode::InviteOnly;
            let mut relay_policy = RelayPolicy::AllowRelays;
            let mut max_members: u8 = 8;
            let mut relay_url = String::new();
            let mut org_id: Option<u64> = None;
            let mut group_id: Option<u64> = None;
            let mut i = 0usize;
            while i < rest.len() {
                let a = rest.get(i).map(String::as_str).unwrap_or_default();
                match a {
                    "--visibility" => {
                        visibility = match next_val(rest, &mut i, "--visibility")? {
                            "private" => PartyVisibility::Private,
                            "friends" => PartyVisibility::Friends,
                            v => return Err(format!("invalid --visibility '{v}'")),
                        };
                    }
                    "--join-mode" => {
                        join_mode = match next_val(rest, &mut i, "--join-mode")? {
                            "invite" | "invite_only" => PartyJoinMode::InviteOnly,
                            "approval" | "approval_required" => PartyJoinMode::ApprovalRequired,
                            v => return Err(format!("invalid --join-mode '{v}'")),
                        };
                    }
                    "--relay-policy" => {
                        relay_policy =
                            parse_relay_policy(next_val(rest, &mut i, "--relay-policy")?)?;
                    }
                    "--max-members" => {
                        let n = next_val(rest, &mut i, "--max-members")?
                            .parse::<u8>()
                            .map_err(|_| "invalid --max-members".to_string())?;
                        if !(2..=12).contains(&n) {
                            return Err("--max-members must be in 2..=12".to_string());
                        }
                        max_members = n;
                    }
                    "--relay-url" => {
                        relay_url = next_val(rest, &mut i, "--relay-url")?.to_string();
                    }
                    "--org-id" => {
                        org_id = Some(parse_safe_id(
                            next_val(rest, &mut i, "--org-id")?,
                            "--org-id",
                        )?);
                    }
                    "--group-id" => {
                        group_id = Some(parse_safe_id(
                            next_val(rest, &mut i, "--group-id")?,
                            "--group-id",
                        )?);
                    }
                    other => {
                        return Err(format!(
                            "unknown argument to `party create`: {}",
                            redact_unknown_arg(other)
                        ));
                    }
                }
            }

            let req = PartyCreateReq {
                visibility: visibility as u8,
                join_mode: join_mode as u8,
                relay_policy: relay_policy as u8,
                max_members,
                relay_url,
                org_id,
                group_id,
            };
            let raw = client
                .request(
                    IpcOpcode::PartyCreate,
                    encode_party_create_req(&req).map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_create_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "party_id": resp.party_id,
                    "party_epoch": resp.party_epoch,
                    "pinned_relay_url": resp.pinned_relay_url,
                }));
            } else {
                println!(
                    "Created party_id={} party_epoch={} pinned_relay_url={}",
                    resp.party_id, resp.party_epoch, resp.pinned_relay_url
                );
            }
            Ok(())
        }
        "join" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party join <party_id> [--invite-stdin] [--relay-policy allow|force|none]".to_string())?,
                "<party_id>",
            )?;
            let mut invite_stdin = false;
            let mut relay_override: Option<u8> = None;
            let mut i = 1usize;
            while i < rest.len() {
                let a = rest.get(i).map(String::as_str).unwrap_or_default();
                match a {
                    "--invite-stdin" => {
                        invite_stdin = true;
                        i += 1;
                    }
                    "--relay-policy" => {
                        relay_override = Some(
                            parse_relay_policy(next_val(rest, &mut i, "--relay-policy")?)? as u8,
                        );
                    }
                    other => {
                        return Err(format!(
                            "unknown argument to `party join`: {}",
                            redact_unknown_arg(other)
                        ));
                    }
                }
            }
            let invite_link = if invite_stdin {
                let raw = read_all_stdin_trimmed(512)?;
                Some(
                    String::from_utf8(raw)
                        .map_err(|_| "invite link on stdin must be UTF-8".to_string())?
                        .trim()
                        .to_string(),
                )
            } else {
                None
            };
            let req = PartyJoinReq {
                party_id,
                relay_policy_override: relay_override,
                invite_link,
            };
            let raw = client
                .request(
                    IpcOpcode::PartyJoin,
                    encode_party_join_req(&req).map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_join_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                if resp.status == 0 {
                    print_json(&json!({
                        "status": "joined",
                        "party_id": party_id,
                        "party_epoch": resp.party_epoch,
                    }));
                } else {
                    print_json(&json!({
                        "status": "pending_approval",
                        "party_id": party_id,
                        "request_id": resp.request_id,
                    }));
                }
            } else if resp.status == 0 {
                println!("Joined party_id={} (party_epoch={})", party_id, resp.party_epoch);
            } else {
                println!(
                    "Join request submitted for party_id={} (request_id={})",
                    party_id, resp.request_id
                );
            }
            Ok(())
        }
        "invite" => cmd_party_invite(opts, &mut client, rest).await,
        "requests" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party requests <party_id>".to_string())?,
                "<party_id>",
            )?;
            let raw = client
                .request(
                    IpcOpcode::PartyRequestsList,
                    encode_party_requests_list_req(&PartyRequestsListReq {
                        party_id,
                        cursor: None,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_requests_list_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                let items: Vec<Value> = resp
                    .requests
                    .iter()
                    .map(|r| {
                        json!({
                            "request_id": r.request_id,
                            "account_id": r.account_id,
                            "device_id": r.device_id,
                            "root_pubkey_b64": r.root_pubkey_b64,
                            "device_pubkey_b64": r.device_pubkey_b64,
                            "requested_at_ms": r.requested_at_ms,
                            "reserved_until_ms": r.reserved_until_ms,
                        })
                    })
                    .collect();
                print_json(&json!({ "requests": items }));
            } else {
                for r in &resp.requests {
                    println!(
                        "request_id={} account_id={} device_id={}",
                        r.request_id, r.account_id, r.device_id
                    );
                }
            }
            Ok(())
        }
        "approve" => {
            if rest.len() < 2 {
                return Err(
                    "usage: mp-outpost party approve <party_id> <request_id> [--expected-epoch <u64>]"
                        .to_string(),
                );
            }
            let party_id =
                parse_safe_id(rest.first().map(String::as_str).unwrap_or_default(), "<party_id>")?;
            let request_id =
                parse_safe_id(rest.get(1).map(String::as_str).unwrap_or_default(), "<request_id>")?;
            let mut expected_party_epoch = 0u64;
            let mut i = 2usize;
            while i < rest.len() {
                if rest.get(i).map(String::as_str) == Some("--expected-epoch") {
                    expected_party_epoch = next_val(rest, &mut i, "--expected-epoch")?
                        .parse::<u64>()
                        .map_err(|_| "invalid --expected-epoch".to_string())?;
                } else {
                    return Err("unknown argument to `party approve`".to_string());
                }
            }
            // Fetch pending request details to bind account_id + device_id + device_pubkey_sha256.
            let list_raw = client
                .request(
                    IpcOpcode::PartyRequestsList,
                    encode_party_requests_list_req(&PartyRequestsListReq {
                        party_id,
                        cursor: None,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let list = decode_party_requests_list_resp(&list_raw).map_err(|e| e.to_string())?;
            let item = list
                .requests
                .iter()
                .find(|r| r.request_id == request_id)
                .ok_or_else(|| format!("request_id {request_id} not found"))?;
            let dev_pk_raw = B64
                .decode(item.device_pubkey_b64.as_bytes())
                .map_err(|e| format!("invalid device_pubkey_b64: {e}"))?;
            let dev_pk_hash = sha256(&dev_pk_raw);

            let raw = client
                .request(
                    IpcOpcode::PartyRequestApprove,
                    encode_party_request_approve_req(&PartyRequestApproveReq {
                        party_id,
                        request_id,
                        expected_party_epoch,
                        account_id: item.account_id,
                        device_id: item.device_id,
                        device_pubkey_sha256: dev_pk_hash,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_request_approve_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "approved": resp.approved,
                    "reserved_until_ms": resp.reserved_until_ms,
                }));
            } else {
                println!(
                    "Approved request_id={} (reserved_until_ms={})",
                    request_id, resp.reserved_until_ms
                );
            }
            Ok(())
        }
        "reject" => {
            if rest.len() < 2 {
                return Err("usage: mp-outpost party reject <party_id> <request_id>".to_string());
            }
            let party_id =
                parse_safe_id(rest.first().map(String::as_str).unwrap_or_default(), "<party_id>")?;
            let request_id =
                parse_safe_id(rest.get(1).map(String::as_str).unwrap_or_default(), "<request_id>")?;
            let raw = client
                .request(
                    IpcOpcode::PartyRequestReject,
                    encode_party_request_reject_req(&PartyRequestRejectReq {
                        party_id,
                        request_id,
                        expected_party_epoch: None,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let rejected = decode_bool_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({ "rejected": rejected }));
            } else {
                println!("Rejected request_id={request_id}: {rejected}");
            }
            Ok(())
        }
        "leave" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party leave <party_id>".to_string())?,
                "<party_id>",
            )?;
            let raw = client
                .request(IpcOpcode::PartyLeave, encode_u64_req(party_id))
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_epoch_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({ "left": resp.ok, "party_epoch": resp.party_epoch }));
            } else {
                println!("Left party_id={party_id} (epoch={})", resp.party_epoch);
            }
            Ok(())
        }
        "disband" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party disband <party_id>".to_string())?,
                "<party_id>",
            )?;
            let raw = client
                .request(
                    IpcOpcode::PartyDisband,
                    encode_party_epoch_op_req(&PartyEpochOpReq {
                        party_id,
                        expected_party_epoch: 0,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_epoch_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({ "disbanded": resp.ok, "party_epoch": resp.party_epoch }));
            } else {
                println!("Disbanded party_id={party_id} (epoch={})", resp.party_epoch);
            }
            Ok(())
        }
        "kick" => {
            if rest.len() < 2 {
                return Err("usage: mp-outpost party kick <party_id> <account_id>".to_string());
            }
            let party_id =
                parse_safe_id(rest.first().map(String::as_str).unwrap_or_default(), "<party_id>")?;
            let target_account_id =
                parse_safe_id(rest.get(1).map(String::as_str).unwrap_or_default(), "<account_id>")?;
            let raw = client
                .request(
                    IpcOpcode::PartyKick,
                    encode_party_kick_req(&PartyKickReq {
                        party_id,
                        target_account_id,
                        expected_party_epoch: 0,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_epoch_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({ "kicked": resp.ok, "party_epoch": resp.party_epoch }));
            } else {
                println!(
                    "Kicked account_id={target_account_id} from party_id={party_id} (epoch={})",
                    resp.party_epoch
                );
            }
            Ok(())
        }
        "promote" => {
            if rest.len() < 2 {
                return Err("usage: mp-outpost party promote <party_id> <device_id>".to_string());
            }
            let party_id =
                parse_safe_id(rest.first().map(String::as_str).unwrap_or_default(), "<party_id>")?;
            let target_device_id =
                parse_safe_id(rest.get(1).map(String::as_str).unwrap_or_default(), "<device_id>")?;
            let raw = client
                .request(
                    IpcOpcode::PartyPromote,
                    encode_party_promote_req(&PartyPromoteReq {
                        party_id,
                        target_device_id,
                        expected_party_epoch: 0,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_epoch_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({ "promoted": resp.ok, "party_epoch": resp.party_epoch }));
            } else {
                println!(
                    "Promoted device_id={target_device_id} in party_id={party_id} (epoch={})",
                    resp.party_epoch
                );
            }
            Ok(())
        }
        "status" => {
            let raw = client
                .request(IpcOpcode::GetStatus, Vec::new())
                .await
                .map_err(|e| e.to_string())?;
            let st = decode_status_resp(&raw).map_err(|e| e.to_string())?;
            print_status_resp(opts, &st);
            Ok(())
        }
        "list" => {
            let raw = client
                .request(IpcOpcode::PartyList, Vec::new())
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_list_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                let items: Vec<Value> = resp
                    .parties
                    .iter()
                    .map(|p| {
                        json!({
                            "party_id": p.party_id,
                            "party_epoch": p.party_epoch,
                            "relay_policy": relay_policy_name(p.relay_policy),
                            "member_count": p.member_count,
                            "next_seq": p.next_seq,
                            "daemon_epoch": p.daemon_epoch,
                        })
                    })
                    .collect();
                print_json(&json!({ "daemon_epoch": resp.daemon_epoch, "parties": items }));
            } else if resp.parties.is_empty() {
                println!("No active party.");
            } else {
                for p in &resp.parties {
                    if opts.debug {
                        println!(
                            "party_id={} code={} epoch={} policy={} members={} next_seq={}",
                            p.party_id,
                            sanitize_cli_meta(&p.room_code),
                            p.party_epoch,
                            relay_policy_name(p.relay_policy),
                            p.member_count,
                            p.next_seq
                        );
                    } else {
                        let title = if p.room_name.is_empty() {
                            "Active party".to_string()
                        } else {
                            sanitize_cli_meta(&p.room_name)
                        };
                        if p.room_code.is_empty() {
                            println!("● {title} · {} live", p.member_count);
                        } else {
                            println!(
                                "● {title} (code {}) · {} live",
                                sanitize_cli_meta(&p.room_code),
                                p.member_count
                            );
                        }
                    }
                }
            }
            Ok(())
        }
        "members" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party members <party_id>".to_string())?,
                "<party_id>",
            )?;
            let raw = client
                .request(IpcOpcode::PartyMembers, encode_u64_req(party_id))
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_members_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                let items: Vec<Value> = resp
                    .members
                    .iter()
                    .map(|m| {
                        json!({
                            "device_id": m.device_id,
                            "account_id": m.account_id,
                            "handle": m.server_handle,
                            "trust_state": trust_state_name(m.trust_state),
                            "safety_number": m.safety_number,
                            "connected_mp1": m.connected_mp1,
                            "connected_p2p": m.connected_p2p,
                            "key_mismatch": m.key_mismatch,
                        })
                    })
                    .collect();
                print_json(&json!({
                    "party_id": resp.party_id,
                    "party_epoch": resp.party_epoch,
                    "members": items,
                }));
            } else {
                for m in &resp.members {
                    if opts.debug {
                        println!(
                            "device={} account={} handle={} trust={} p2p={} sn={}",
                            m.device_id,
                            m.account_id,
                            sanitize_cli_meta(&m.server_handle),
                            trust_state_name(m.trust_state),
                            m.connected_p2p,
                            m.safety_number
                        );
                    } else {
                        let icon = if m.connected_p2p || m.connected_mp1 {
                            "●"
                        } else {
                            "○"
                        };
                        let display = format_member_display(m.account_id, &m.server_handle);
                        let state = if m.connected_p2p || m.connected_mp1 {
                            "live"
                        } else {
                            "away"
                        };
                        println!("{icon} {display} ({state})");
                    }
                }
            }
            Ok(())
        }
        "say" => {
            if rest.len() < 2 {
                return Err("usage: mp-outpost party say <party_id> <text> [--scope <s>] [--to-device <u64>]".to_string());
            }
            let party_id =
                parse_safe_id(rest.first().map(String::as_str).unwrap_or_default(), "<party_id>")?;
            let mut text_parts: Vec<String> = Vec::new();
            let mut room_scope = "party/main".to_string();
            let mut target_device_id: Option<u64> = None;
            let mut i = 1usize;
            while i < rest.len() {
                let a = rest.get(i).map(String::as_str).unwrap_or_default();
                match a {
                    "--scope" => room_scope = next_val(rest, &mut i, "--scope")?.to_string(),
                    "--to-device" => {
                        target_device_id = Some(parse_safe_id(
                            next_val(rest, &mut i, "--to-device")?,
                            "--to-device",
                        )?)
                    }
                    other => {
                        text_parts.push(other.to_string());
                        i += 1;
                    }
                }
            }
            let body = text_parts.join(" ");
            let req = PartySendChatReq {
                party_id,
                client_msg_id: random_safe_id()?,
                room_scope,
                target_device_id,
                body,
            };
            let raw = client
                .request(
                    IpcOpcode::PartySendChat,
                    encode_party_send_chat_req(&req).map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_send_result_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "party_id": resp.party_id,
                    "delivered_to": resp.delivered_to,
                    "withheld_unpinned": resp.withheld_unpinned,
                    "disconnected": resp.disconnected,
                }));
            } else if opts.debug {
                println!("Delivered to devices {:?}", resp.delivered_to);
            } else {
                println!("Sent.");
            }
            Ok(())
        }
        "read" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party read <party_id> [--after-seq <u64>] [--limit <u16>]".to_string())?,
                "<party_id>",
            )?;
            let mut after_seq = 0u64;
            let mut limit = 50u16;
            let mut cursor_epoch = 0u64;
            let mut i = 1usize;
            while i < rest.len() {
                let a = rest.get(i).map(String::as_str).unwrap_or_default();
                match a {
                    "--after-seq" => {
                        after_seq = next_val(rest, &mut i, "--after-seq")?
                            .parse::<u64>()
                            .map_err(|_| "invalid --after-seq".to_string())?
                    }
                    "--limit" => {
                        limit = next_val(rest, &mut i, "--limit")?
                            .parse::<u16>()
                            .map_err(|_| "invalid --limit".to_string())?
                    }
                    "--cursor-epoch" => {
                        cursor_epoch = next_val(rest, &mut i, "--cursor-epoch")?
                            .parse::<u64>()
                            .map_err(|_| "invalid --cursor-epoch".to_string())?
                    }
                    other => {
                        return Err(format!(
                            "unknown argument to `party read`: {}",
                            redact_unknown_arg(other)
                        ));
                    }
                }
            }
            let raw = client
                .request(
                    IpcOpcode::PartyPoll,
                    encode_party_poll_req(&PartyPollIpcReq {
                        party_id,
                        cursor_epoch,
                        after_seq,
                        limit,
                        max_bytes: DEFAULT_POLL_MAX_BYTES as u32,
                        board_only: false,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_poll_resp(&raw).map_err(|e| e.to_string())?;
            print_poll_resp(opts, &resp)?;
            Ok(())
        }
        "wait" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party wait <party_id> [--after-seq <u64>] [--timeout-ms <u32>]".to_string())?,
                "<party_id>",
            )?;
            let mut after_seq = 0u64;
            let mut cursor_epoch = 0u64;
            let mut timeout_ms = 25_000u32;
            let mut i = 1usize;
            while i < rest.len() {
                let a = rest.get(i).map(String::as_str).unwrap_or_default();
                match a {
                    "--after-seq" => {
                        after_seq = next_val(rest, &mut i, "--after-seq")?
                            .parse::<u64>()
                            .map_err(|_| "invalid --after-seq".to_string())?
                    }
                    "--cursor-epoch" => {
                        cursor_epoch = next_val(rest, &mut i, "--cursor-epoch")?
                            .parse::<u64>()
                            .map_err(|_| "invalid --cursor-epoch".to_string())?
                    }
                    "--timeout-ms" => {
                        timeout_ms = next_val(rest, &mut i, "--timeout-ms")?
                            .parse::<u32>()
                            .map_err(|_| "invalid --timeout-ms".to_string())?
                            .min(45_000)
                    }
                    other => {
                        return Err(format!(
                            "unknown argument to `party wait`: {}",
                            redact_unknown_arg(other)
                        ));
                    }
                }
            }
            let raw = client
                .request(
                    IpcOpcode::PartyWait,
                    encode_party_wait_req(&PartyWaitIpcReq {
                        party_id,
                        cursor_epoch,
                        after_seq,
                        timeout_ms,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_poll_resp(&raw).map_err(|e| e.to_string())?;
            print_poll_resp(opts, &resp)?;
            Ok(())
        }
        "notice" => {
            if rest.len() < 3 {
                return Err(
                    "usage: mp-outpost party notice <party_id> <sync_ack|scope_changed|status> <text>"
                        .to_string(),
                );
            }
            let party_id =
                parse_safe_id(rest.first().map(String::as_str).unwrap_or_default(), "<party_id>")?;
            let kind = match rest.get(1).map(String::as_str).unwrap_or_default() {
                "sync_ack" => 0u8,
                "scope_changed" => 1u8,
                "status" => 2u8,
                other => return Err(format!("invalid notice kind '{other}'")),
            };
            let text = rest.get(2..).unwrap_or_default().join(" ");
            let req = PartyControlNoticeReq {
                party_id,
                notice_kind: kind,
                party_epoch: 0,
                text,
            };
            let raw = client
                .request(
                    IpcOpcode::PartySendControlNotice,
                    encode_control_notice_req(&req).map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_send_result_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "party_id": resp.party_id,
                    "delivered_to": resp.delivered_to,
                }));
            } else {
                println!("Sent control notice to devices {:?}", resp.delivered_to);
            }
            Ok(())
        }
        other => Err(format!("unknown party subcommand '{other}'")),
    }
}

async fn cmd_party_invite(
    opts: &GlobalOpts,
    client: &mut DaemonClient,
    args: &[String],
) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost party invite <mint|revoke> ...".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        "mint" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost party invite mint <party_id> [--friend <account_id> | --link --max-uses N] [--ttl-sec N]".to_string())?,
                "<party_id>",
            )?;
            let mut target_account_id: Option<u64> = None;
            let mut max_uses: Option<u8> = None;
            let mut ttl_sec: Option<u32> = None;
            let mut i = 1usize;
            while i < rest.len() {
                let a = rest.get(i).map(String::as_str).unwrap_or_default();
                match a {
                    "--friend" => {
                        target_account_id = Some(parse_safe_id(
                            next_val(rest, &mut i, "--friend")?,
                            "--friend",
                        )?)
                    }
                    "--link" => {
                        i += 1;
                    }
                    "--max-uses" => {
                        max_uses = Some(
                            next_val(rest, &mut i, "--max-uses")?
                                .parse::<u8>()
                                .map_err(|_| "invalid --max-uses".to_string())?,
                        )
                    }
                    "--ttl-sec" => {
                        ttl_sec = Some(
                            next_val(rest, &mut i, "--ttl-sec")?
                                .parse::<u32>()
                                .map_err(|_| "invalid --ttl-sec".to_string())?,
                        )
                    }
                    other => {
                        return Err(format!(
                            "unknown argument to `party invite mint`: {}",
                            redact_unknown_arg(other)
                        ));
                    }
                }
            }
            let raw = client
                .request(
                    IpcOpcode::PartyInviteMint,
                    encode_party_invite_mint_req(&PartyInviteMintReq {
                        party_id,
                        target_account_id,
                        max_uses,
                        ttl_sec,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_invite_mint_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "party_invite_id": resp.party_invite_id,
                    "expires_at_ms": resp.expires_at_ms,
                    "invite_link": resp.invite_link,
                }));
            } else {
                println!(
                    "Minted party_invite_id={} expires_at_ms={}",
                    resp.party_invite_id, resp.expires_at_ms
                );
                if let Some(link) = resp.invite_link {
                    println!("invite_link: {link}");
                }
            }
            Ok(())
        }
        "revoke" => {
            if rest.len() < 2 {
                return Err(
                    "usage: mp-outpost party invite revoke <party_id> <invite_id>".to_string(),
                );
            }
            let party_id =
                parse_safe_id(rest.first().map(String::as_str).unwrap_or_default(), "<party_id>")?;
            let party_invite_id = parse_safe_id(
                rest.get(1).map(String::as_str).unwrap_or_default(),
                "<invite_id>",
            )?;
            let raw = client
                .request(
                    IpcOpcode::PartyInviteRevoke,
                    encode_party_invite_revoke_req(&PartyInviteRevokeReq {
                        party_id,
                        party_invite_id,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let revoked = decode_bool_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({ "revoked": revoked }));
            } else {
                println!("Revoked invite {party_invite_id}: {revoked}");
            }
            Ok(())
        }
        other => Err(format!("unknown party invite subcommand '{other}'")),
    }
}

// ---------------------------------------------------------------------------
// `board` Commands
// ---------------------------------------------------------------------------

async fn cmd_board(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost board <post|read> ...".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();
    let (mut client, _) = connect_daemon_cli(opts, false, true).await?;

    match sub {
        "post" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost board post <party_id> --scope <s> (--payload-stdin | --payload-file <path>)".to_string())?,
                "<party_id>",
            )?;
            let mut scope: Option<String> = None;
            let mut payload_stdin = false;
            let mut payload_file: Option<PathBuf> = None;
            let mut i = 1usize;
            while i < rest.len() {
                let a = rest.get(i).map(String::as_str).unwrap_or_default();
                match a {
                    "--scope" => scope = Some(next_val(rest, &mut i, "--scope")?.to_string()),
                    "--payload-stdin" => {
                        payload_stdin = true;
                        i += 1;
                    }
                    "--payload-file" => {
                        payload_file =
                            Some(PathBuf::from(next_val(rest, &mut i, "--payload-file")?))
                    }
                    other => {
                        return Err(format!(
                            "unknown argument to `board post`: {}",
                            redact_unknown_arg(other)
                        ));
                    }
                }
            }
            let room_scope = scope.ok_or_else(|| "board post requires --scope <s>".to_string())?;
            let payload = if payload_stdin {
                read_all_stdin_trimmed(1024 * 1024)?
            } else if let Some(path) = payload_file {
                std::fs::read(&path)
                    .map_err(|e| format!("failed reading payload file '{}': {e}", path.display()))?
            } else {
                return Err("board post requires --payload-stdin or --payload-file <path>".to_string());
            };
            let req = PartyPostBoardReq {
                party_id,
                client_msg_id: random_safe_id()?,
                room_scope,
                payload,
            };
            let raw = client
                .request(
                    IpcOpcode::PartyPostBoard,
                    encode_party_post_board_req(&req).map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_send_result_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "party_id": resp.party_id,
                    "delivered_to": resp.delivered_to,
                    "withheld_unpinned": resp.withheld_unpinned,
                    "disconnected": resp.disconnected,
                }));
            } else {
                println!("Posted board envelope to devices {:?}", resp.delivered_to);
            }
            Ok(())
        }
        "read" => {
            let party_id = parse_safe_id(
                rest.first()
                    .map(String::as_str)
                    .ok_or_else(|| "usage: mp-outpost board read <party_id> [--after-seq <u64>]".to_string())?,
                "<party_id>",
            )?;
            let mut after_seq = 0u64;
            let mut i = 1usize;
            while i < rest.len() {
                if rest.get(i).map(String::as_str) == Some("--after-seq") {
                    after_seq = next_val(rest, &mut i, "--after-seq")?
                        .parse::<u64>()
                        .map_err(|_| "invalid --after-seq".to_string())?;
                } else {
                    return Err("unknown argument to `board read`".to_string());
                }
            }
            let raw = client
                .request(
                    IpcOpcode::PartyPoll,
                    encode_party_poll_req(&PartyPollIpcReq {
                        party_id,
                        cursor_epoch: 0,
                        after_seq,
                        limit: 50,
                        max_bytes: DEFAULT_POLL_MAX_BYTES as u32,
                        board_only: true,
                    }),
                )
                .await
                .map_err(|e| e.to_string())?;
            let resp = decode_party_poll_resp(&raw).map_err(|e| e.to_string())?;
            print_poll_resp(opts, &resp)?;
            Ok(())
        }
        other => Err(format!("unknown board subcommand '{other}'")),
    }
}

// ---------------------------------------------------------------------------
// `daemon` Commands
// ---------------------------------------------------------------------------

async fn cmd_daemon(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost daemon <status|start|stop|restart|logs>".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();

    match sub {
        "status" => {
            match connect_daemon_cli(opts, true, false).await {
                Ok((mut client, _device_id)) => {
                    let raw = client
                        .request(IpcOpcode::GetStatus, Vec::new())
                        .await
                        .map_err(|e| e.to_string())?;
                    let st = decode_status_resp(&raw).map_err(|e| e.to_string())?;
                    if opts.json {
                        print_json(&json!({
                            "running": true,
                            "account_id": st.account_id,
                            "device_id": st.device_id,
                            "daemon_pid": st.daemon_pid,
                            "daemon_epoch": st.daemon_epoch,
                            "build_order": st.build_order,
                            "build_digest": encode_hex(&st.build_digest),
                            "exe_path": st.exe_path,
                            "control_ws_connected": st.control_ws_connected,
                            "dual_host_churn_alert": st.dual_host_churn_alert,
                            "active_party_id": st.active_party.as_ref().map(|p| p.party_id),
                        }));
                    } else {
                        print_status_resp(opts, &st);
                    }
                    Ok(())
                }
                Err(msg) => {
                    if opts.json {
                        print_json(&json!({ "running": false, "detail": msg }));
                    } else {
                        println!("Daemon is not running ({msg}).");
                    }
                    Ok(())
                }
            }
        }
        "start" => {
            let (mut client, _) = connect_daemon_cli(opts, false, true).await?;
            let raw = client
                .request(IpcOpcode::GetStatus, Vec::new())
                .await
                .map_err(|e| e.to_string())?;
            let st = decode_status_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "running": true,
                    "device_id": st.device_id,
                    "daemon_pid": st.daemon_pid,
                    "daemon_epoch": st.daemon_epoch,
                }));
            } else {
                println!(
                    "Daemon running (device_id={} pid={} epoch={})",
                    st.device_id, st.daemon_pid, st.daemon_epoch
                );
            }
            Ok(())
        }
        "stop" => {
            let mut force = false;
            let mut leave_party = false;
            for a in rest {
                match a.as_str() {
                    "--force" => force = true,
                    "--leave-party" => leave_party = true,
                    other => {
                        return Err(format!(
                            "unknown argument to `daemon stop`: {}",
                            redact_unknown_arg(other)
                        ));
                    }
                }
            }
            let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
            let runtime_override =
                resolve_effective_runtime_override(opts.runtime_dir.as_deref());
            let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
            let rt_path = resolve_runtime_dir(device_id, runtime_override.as_deref())
                .map_err(|e| e.to_string())?;
            let rt_dir = open_or_create_private_dir(&rt_path).map_err(|e| e.to_string())?;

            if force {
                let rt_path_b = rt_path.clone();
                let outcome = tokio::task::spawn_blocking(move || {
                    let rt_dir = open_or_create_private_dir(&rt_path_b)?;
                    force_stop_daemon(
                        &rt_dir,
                        device_id,
                        Duration::from_secs(2),
                        Duration::from_secs(2),
                    )
                })
                .await
                .map_err(|e| format!("force stop task failed: {e}"))?
                .map_err(|e| e.to_string())?;
                if opts.json {
                    print_json(&json!({
                        "stopped": true,
                        "outcome": format!("{outcome:?}"),
                    }));
                } else {
                    match outcome {
                        ForceStopOutcome::AlreadyStopped => println!("Daemon already stopped."),
                        ForceStopOutcome::TerminatedBySigterm { pid } => {
                            println!("Stopped daemon pid={pid} via SIGTERM.")
                        }
                        ForceStopOutcome::KilledBySigkill { pid } => {
                            println!("Force-killed daemon pid={pid} via SIGKILL.")
                        }
                    }
                }
                return Ok(());
            }

            // Graceful stop serialized under startup.lock (acquired via spawn_blocking).
            let rt_path_b = rt_path.clone();
            let (_startup_lock, already_stopped) = tokio::task::spawn_blocking(move || {
                let rt_dir = open_or_create_private_dir(&rt_path_b)?;
                let lock = FlockGuard::lock_exclusive_with_deadline(
                    &rt_dir,
                    STARTUP_LOCK_NAME,
                    Duration::from_secs(5),
                )?;
                let free = FlockGuard::probe_lock_free(&rt_dir, DAEMON_LOCK_NAME)?;
                Ok::<(FlockGuard, bool), DaemonError>((lock, free))
            })
            .await
            .map_err(|e| format!("startup lock task failed: {e}"))?
            .map_err(|e| e.to_string())?;

            if already_stopped {
                if opts.json {
                    print_json(&json!({ "stopped": true, "already_stopped": true }));
                } else {
                    println!("Daemon already stopped.");
                }
                return Ok(());
            }

            let mode = if leave_party {
                DrainMode::StopLeaveParty
            } else {
                DrainMode::StopDetach
            };
            // Connect directly to d.sock with a bounded 3s timeout so a wedged daemon cannot hang stop.
            let stop_res = tokio::time::timeout(
                Duration::from_secs(3),
                send_drain_direct(&rt_path, device_id, mode),
            )
            .await
            .map_err(|_| "timed out sending graceful stop to daemon (3s)".to_string())
            .and_then(|r| r.map_err(|e| e.to_string()));
            if let Err(err) = stop_res {
                return Err(format!(
                    "graceful stop failed ({err}); retry with `mp-outpost daemon stop --force`"
                ));
            }
            wait_daemon_lock_free(&rt_dir, Duration::from_secs(5)).await?;

            if opts.json {
                print_json(&json!({ "stopped": true, "device_id": device_id }));
            } else {
                println!("Daemon stopped cleanly (device_id={device_id}).");
            }
            Ok(())
        }
        "restart" => {
            let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
            let runtime_override =
                resolve_effective_runtime_override(opts.runtime_dir.as_deref());
            let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
            let rt_path = resolve_runtime_dir(device_id, runtime_override.as_deref())
                .map_err(|e| e.to_string())?;
            let rt_dir = open_or_create_private_dir(&rt_path).map_err(|e| e.to_string())?;

            {
                let rt_path_b = rt_path.clone();
                let (_startup_lock, lock_free) = tokio::task::spawn_blocking(move || {
                    let rt_dir = open_or_create_private_dir(&rt_path_b)?;
                    let lock = FlockGuard::lock_exclusive_with_deadline(
                        &rt_dir,
                        STARTUP_LOCK_NAME,
                        Duration::from_secs(5),
                    )?;
                    let free = FlockGuard::probe_lock_free(&rt_dir, DAEMON_LOCK_NAME)?;
                    Ok::<(FlockGuard, bool), DaemonError>((lock, free))
                })
                .await
                .map_err(|e| format!("startup lock task failed: {e}"))?
                .map_err(|e| e.to_string())?;
                if !lock_free {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(3),
                        send_drain_direct(&rt_path, device_id, DrainMode::RestartKeepParty),
                    )
                    .await;
                    wait_daemon_lock_free(&rt_dir, Duration::from_secs(5)).await?;
                }
            }

            let (mut client, _) = connect_daemon_cli(opts, false, true).await?;
            let raw = client
                .request(IpcOpcode::GetStatus, Vec::new())
                .await
                .map_err(|e| e.to_string())?;
            let st = decode_status_resp(&raw).map_err(|e| e.to_string())?;
            if opts.json {
                print_json(&json!({
                    "restarted": true,
                    "device_id": st.device_id,
                    "daemon_pid": st.daemon_pid,
                    "daemon_epoch": st.daemon_epoch,
                }));
            } else {
                println!(
                    "Restarted daemon (device_id={} pid={} epoch={})",
                    st.device_id, st.daemon_pid, st.daemon_epoch
                );
            }
            Ok(())
        }
        "logs" => {
            let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
            let runtime_override =
                resolve_effective_runtime_override(opts.runtime_dir.as_deref());
            let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
            let rt_path = resolve_runtime_dir(device_id, runtime_override.as_deref())
                .map_err(|e| e.to_string())?;
            let rt_dir = open_or_create_private_dir(&rt_path).map_err(|e| e.to_string())?;
            match read_file_in_dir(rt_dir.as_raw_fd(), DAEMON_LOG_NAME, 4 * 1024 * 1024) {
                Ok(Some(raw)) => {
                    let content = String::from_utf8_lossy(&raw);
                    print!("{content}");
                    Ok(())
                }
                Ok(None) => {
                    println!(
                        "No daemon log file yet at '{}'.",
                        rt_path.join(DAEMON_LOG_NAME).display()
                    );
                    Ok(())
                }
                Err(e) => Err(format!("failed reading daemon log: {e}")),
            }
        }
        other => Err(format!("unknown daemon subcommand '{other}'")),
    }
}

async fn send_drain_direct(
    rt_path: &Path,
    device_id: u64,
    mode: DrainMode,
) -> Result<(), DaemonError> {
    use outpost_core::ipc_wire::IpcFrame;
    use outpost_daemon::{
        SOCKET_FILE_NAME, decode_hello_ack, encode_drain_payload, encode_hello, read_ipc_frame,
        verify_peer_same_uid, write_ipc_frame,
    };
    use std::os::fd::AsRawFd as _;
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(rt_path.join(SOCKET_FILE_NAME))
        .await
        .map_err(|e| DaemonError::io("connect d.sock for stop", e))?;
    verify_peer_same_uid(stream.as_raw_fd())?;

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
    .await?;
    let Some(ack_frame) = read_ipc_frame(&mut stream).await? else {
        return Err(DaemonError::Protocol("EOF during Hello".to_string()));
    };
    if ack_frame.opcode != IpcOpcode::HelloAck {
        return Err(DaemonError::Protocol("unexpected opcode on stop Hello".to_string()));
    }
    let ack = decode_hello_ack(&ack_frame.payload)?;
    if ack.device_id != device_id {
        return Err(DaemonError::DeviceIdMismatch {
            expected: device_id,
            actual: ack.device_id,
        });
    }
    write_ipc_frame(
        &mut stream,
        &IpcFrame {
            opcode: IpcOpcode::DrainAndShutdown,
            request_id: 2,
            payload: encode_drain_payload(mode),
        },
    )
    .await?;
    let _ = tokio::time::timeout(Duration::from_millis(500), read_ipc_frame(&mut stream)).await;
    Ok(())
}

async fn wait_daemon_lock_free(
    rt_dir: &outpost_daemon::VerifiedDir,
    timeout: Duration,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        if FlockGuard::probe_lock_free(rt_dir, DAEMON_LOCK_NAME).map_err(|e| e.to_string())? {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err("timed out waiting for daemon.lock release (try --force)".to_string());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// `web` Commands
// ---------------------------------------------------------------------------

async fn cmd_web(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost web approve <XXXX-XXXX> ...".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        "approve" => cmd_web_approve(opts, rest).await,
        other => Err(format!("unknown web subcommand '{other}'")),
    }
}

async fn cmd_web_approve(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let user_code = args
        .first()
        .map(String::as_str)
        .filter(|s| !s.starts_with('-'))
        .ok_or_else(|| {
            "usage: mp-outpost web approve <XXXX-XXXX> [--root-key-file <path>] [--account-id <u64>] [--api-authority <host>] [--yes-browser-fingerprint <8hex>]"
                .to_string()
        })?
        .to_string();

    let mut root_key_file: Option<PathBuf> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut api_authority_opt: Option<String> = None;
    let mut yes_browser_fp: Option<String> = None;

    let mut i = 1usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--api-authority" => {
                api_authority_opt = Some(next_val(args, &mut i, "--api-authority")?.to_string())
            }
            "--yes-browser-fingerprint" => {
                yes_browser_fp =
                    Some(next_val(args, &mut i, "--yes-browser-fingerprint")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `web approve`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    // CRITICAL (G2-L3-2): Validate --yes-browser-fingerprint format AND refuse headless
    // device-key auto-approval unless `--root-key-file` is explicitly supplied!
    if let Some(expected_fp) = yes_browser_fp.as_deref() {
        if !is_valid_browser_fingerprint(expected_fp.trim()) {
            return Err(
                "invalid --yes-browser-fingerprint (expected 8 lowercase ASCII hex characters)"
                    .to_string(),
            );
        }
        if !is_interactive_tty() && root_key_file.is_none() {
            return Err(
                "refusing headless --yes-browser-fingerprint without --root-key-file; run interactively in a TTY or pass --root-key-file <path>"
                    .to_string(),
            );
        }
    }

    let (signer, api_authority) = if let Some(root_path) = root_key_file {
        let root_secret = read_root_key_file(&root_path)?;
        let (account_id, authority) = resolve_account_and_authority(
            opts,
            account_id_opt,
            api_authority_opt.as_deref(),
        )?;
        let aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
        let s = RequestSigner::root(aid, *root_secret);
        drop(root_secret);
        (s, authority)
    } else {
        let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
        let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
        let dev = load_device_record(&state_dir_path, device_id)?;
        if let Some(expected_aid) = account_id_opt
            && dev.account_id != expected_aid
        {
            return Err(format!(
                "local device record account_id={} does not match --account-id={expected_aid}",
                dev.account_id
            ));
        }
        let aid = AccountId::new(dev.account_id).map_err(|e| e.to_string())?;
        let did = DeviceId::new(dev.device_id).map_err(|e| e.to_string())?;
        let authority = api_authority_opt.unwrap_or(dev.api_authority);
        let dev_secret = Zeroizing::new(dev.device_secret);
        (RequestSigner::device(aid, did, *dev_secret), authority)
    };

    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let inspect = client
        .web_session_inspect_with_signer(&signer, &user_code)
        .await
        .map_err(|e| e.to_string())?;
    if !inspect.pending {
        return Err("web session code is not pending approval".to_string());
    }
    if wall_now_ms_adjusted(&client) >= inspect.expires_at_ms {
        return Err("web session code has expired".to_string());
    }
    let inspected_fp = inspect.browser_fingerprint.trim();
    if !is_valid_browser_fingerprint(inspected_fp) {
        return Err(format!(
            "REFUSING web session approval: server returned invalid browser_fingerprint '{}'",
            sanitize_cli_meta(inspected_fp)
        ));
    }

    let safe_fp = sanitize_cli_meta(inspected_fp);
    let safe_country = sanitize_cli_meta(&inspect.requester_country);
    let safe_client = sanitize_cli_meta(&inspect.requester_client);
    let safe_scope = sanitize_cli_meta(&inspect.scope);

    if let Some(expected_fp) = yes_browser_fp {
        if expected_fp.trim() != inspected_fp {
            return Err(format!(
                "REFUSING web session approval: --yes-browser-fingerprint '{}' does not match '{safe_fp}'",
                sanitize_cli_meta(expected_fp.trim()),
            ));
        }
    } else {
        let mut tty = open_interactive_tty("web approve").map_err(|e| {
            format!("{e} (or pass --root-key-file <path> with exact --yes-browser-fingerprint <8hex>)")
        })?;
        let prompt = format!(
            "Approve web portal sign-in:\n\
               Browser fingerprint: {safe_fp}\n\
               Requester country:   {safe_country}\n\
               Requester client:    {safe_client}\n\
               Scope:               {safe_scope}\n\
             Verify the browser fingerprint matches your browser, then type 'yes' to approve: "
        );
        tty.write_all(prompt.as_bytes())
            .and_then(|()| tty.flush())
            .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;
        let mut reader = BufReader::new(
            tty.try_clone()
                .map_err(|e| format!("failed cloning /dev/tty: {e}"))?,
        );
        let mut confirm = String::new();
        reader
            .read_line(&mut confirm)
            .map_err(|e| format!("failed reading from /dev/tty: {e}"))?;
        if confirm.trim() != "yes" {
            return Err("web session approval aborted by operator".to_string());
        }
    }

    let resp = client
        .web_session_approve_with_signer(&signer, &user_code)
        .await
        .map_err(|e| e.to_string())?;

    if !resp.approved {
        return Err("server did not confirm web session approval (approved=false)".to_string());
    }
    if resp.browser_fingerprint.trim() != inspected_fp {
        return Err(format!(
            "REFUSING web session confirmation: approved browser_fingerprint '{}' disagrees with inspected '{safe_fp}'",
            sanitize_cli_meta(&resp.browser_fingerprint)
        ));
    }

    if opts.json {
        print_json(&json!({
            "approved": resp.approved,
            "scope": sanitize_cli_meta(&resp.scope),
            "account_id": resp.account_id,
            "approved_device_id": resp.approved_device_id,
            "approved_by_root": resp.approved_by_root,
            "browser_fingerprint": sanitize_cli_meta(&resp.browser_fingerprint),
            "requester_country": sanitize_cli_meta(&resp.requester_country),
            "requester_client": sanitize_cli_meta(&resp.requester_client),
        }));
    } else {
        println!(
            "Approved web session for account_id={} (scope={}, browser_fingerprint={}, approved_by_root={})",
            resp.account_id,
            sanitize_cli_meta(&resp.scope),
            sanitize_cli_meta(&resp.browser_fingerprint),
            resp.approved_by_root
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `doctor` Command (Read-Only Diagnostic Health Report)
// ---------------------------------------------------------------------------

fn extract_https_authority_from_url(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let end = rest
        .bytes()
        .position(|b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let auth = rest.get(..end)?;
    if auth.is_empty() { None } else { Some(auth) }
}

async fn cmd_relays(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut ping = false;
    let mut api_authority_override: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--ping" => {
                ping = true;
                i += 1;
            }
            "--api-authority" => {
                api_authority_override =
                    Some(next_val(args, &mut i, "--api-authority")?.to_string());
            }
            "-h" | "--help" => {
                println!("Usage: mp-outpost relays [--ping] [--api-authority <host>] [--json]");
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unknown argument to `relays`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    let device_authority = resolve_effective_state_dir(opts.state_dir.as_deref())
        .ok()
        .and_then(|st_dir| {
            open_state_dir(&st_dir).ok()?;
            let dev_id = resolve_active_device_id(&st_dir, opts.device_id).ok()?;
            load_device_record(&st_dir, dev_id)
                .ok()
                .map(|d| d.api_authority)
        });
    let effective_authority = api_authority_override
        .or(device_authority)
        .unwrap_or_else(|| DEFAULT_API_AUTHORITY.to_string());

    let cfg = build_control_client_config(&effective_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg.with_request_timeout(Duration::from_secs(10)));
    let discovered = client.list_relays().await.map_err(|e| e.to_string())?;

    struct RelayRow {
        orig_idx: usize,
        url: String,
        region: String,
        label: String,
        is_default: bool,
        ok: Option<bool>,
        rtt_ms: Option<u64>,
        error: Option<String>,
    }

    let mut rows: Vec<RelayRow> = discovered
        .relays
        .into_iter()
        .enumerate()
        .map(|(idx, r)| {
            let is_default = r.default || r.url == discovered.default_relay_url;
            RelayRow {
                orig_idx: idx,
                url: r.url,
                region: r.region,
                label: r.label,
                is_default,
                ok: None,
                rtt_ms: None,
                error: None,
            }
        })
        .collect();

    if ping {
        let mut join_set = tokio::task::JoinSet::new();
        for row in &rows {
            let idx = row.orig_idx;
            let url = row.url.clone();
            join_set.spawn(async move {
                let auth = extract_https_authority_from_url(&url)
                    .unwrap_or(DEFAULT_API_AUTHORITY)
                    .to_string();
                match build_control_client_config(&auth) {
                    Ok(relay_cfg) => {
                        let probe_client =
                            ControlClient::new(relay_cfg.with_request_timeout(Duration::from_secs(10)));
                        match probe_client.probe_relay_ping(&url).await {
                            Ok(rtt) => {
                                let ms = u64::try_from(rtt.as_millis()).unwrap_or(u64::MAX);
                                (idx, true, Some(ms), None)
                            }
                            Err(e) => (idx, false, None, Some(sanitize_cli_meta(&e.to_string()))),
                        }
                    }
                    Err(e) => (idx, false, None, Some(sanitize_cli_meta(&e.to_string()))),
                }
            });
        }
        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, ok, rtt_ms, error)) = res
                && let Some(row) = rows.get_mut(idx)
            {
                row.ok = Some(ok);
                row.rtt_ms = rtt_ms;
                row.error = error;
            }
        }
        rows.sort_by(|a, b| {
            let a_rank = match (a.ok, a.rtt_ms) {
                (Some(true), Some(ms)) => (0u8, ms),
                _ => (1u8, u64::MAX),
            };
            let b_rank = match (b.ok, b.rtt_ms) {
                (Some(true), Some(ms)) => (0u8, ms),
                _ => (1u8, u64::MAX),
            };
            a_rank.cmp(&b_rank).then_with(|| a.orig_idx.cmp(&b.orig_idx))
        });
    }

    let fastest_relay_url = if ping {
        rows.iter()
            .find(|r| r.ok == Some(true))
            .map(|r| r.url.clone())
    } else {
        None
    };

    if opts.json {
        let items: Vec<Value> = rows
            .iter()
            .map(|r| {
                if ping {
                    json!({
                        "url": r.url,
                        "region": r.region,
                        "label": r.label,
                        "default": r.is_default,
                        "ok": r.ok.unwrap_or(false),
                        "rtt_ms": r.rtt_ms,
                        "error": r.error,
                    })
                } else {
                    json!({
                        "url": r.url,
                        "region": r.region,
                        "label": r.label,
                        "default": r.is_default,
                    })
                }
            })
            .collect();
        print_json(&json!({
            "api_authority": sanitize_cli_meta(&effective_authority),
            "default_relay_url": discovered.default_relay_url,
            "pinged": ping,
            "fastest_relay_url": fastest_relay_url,
            "relays": items,
        }));
    } else {
        println!(
            "Regional relays (authority={}, default={}):",
            sanitize_cli_meta(&effective_authority),
            sanitize_cli_meta(&discovered.default_relay_url)
        );
        if rows.is_empty() {
            println!("  (no regional relays advertised)");
        } else {
            for r in &rows {
                let mut tags = Vec::new();
                if r.is_default {
                    tags.push("default");
                }
                if fastest_relay_url.as_deref() == Some(r.url.as_str()) {
                    tags.push("fastest");
                }
                let tag_suffix = if tags.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", tags.join(", "))
                };
                if ping {
                    let status_col = match (r.ok, r.rtt_ms, r.error.as_deref()) {
                        (Some(true), Some(ms), _) => format!("ok ({ms}ms)"),
                        (_, _, Some(err)) => format!("FAIL ({err})"),
                        _ => "FAIL".to_string(),
                    };
                    println!(
                        "  {:<12}  {:<24}  {}  {}{tag_suffix}",
                        sanitize_cli_meta(&r.region),
                        sanitize_cli_meta(&r.label),
                        sanitize_cli_meta(&r.url),
                        status_col,
                    );
                } else {
                    println!(
                        "  {:<12}  {:<24}  {}{tag_suffix}",
                        sanitize_cli_meta(&r.region),
                        sanitize_cli_meta(&r.label),
                        sanitize_cli_meta(&r.url),
                    );
                }
            }
        }
    }

    Ok(())
}

async fn cmd_doctor(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut api_authority_override: Option<String> = None;
    let mut relay_url_override: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--api-authority" => {
                api_authority_override =
                    Some(next_val(args, &mut i, "--api-authority")?.to_string())
            }
            "--relay-url" => {
                relay_url_override = Some(next_val(args, &mut i, "--relay-url")?.to_string())
            }
            other => {
                return Err(format!(
                    "unknown argument to `doctor`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }

    // 1. Binary check
    let exe_path = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    let exe_matches = on_disk_exe_matches_local();

    // 2. Enrolled device check (read-only, preserving real state/decode errors!)
    let mut device_error: Option<String> = None;
    let device_opt = match resolve_effective_state_dir(opts.state_dir.as_deref()) {
        Ok(st_dir) => match open_state_dir(&st_dir) {
            Ok(_) => match resolve_active_device_id(&st_dir, opts.device_id) {
                Ok(dev_id) => match load_device_record(&st_dir, dev_id) {
                    Ok(rec) => Some(rec),
                    Err(e) => {
                        device_error = Some(e);
                        None
                    }
                },
                Err(e) => {
                    if !e.contains("no enrolled device found") {
                        device_error = Some(e);
                    }
                    None
                }
            },
            Err(e) => {
                device_error = Some(e);
                None
            }
        },
        Err(e) => {
            device_error = Some(e);
            None
        }
    };

    let now_s = wall_now_secs();
    let mut cwt_warning: Option<String> = None;
    let device_json = if let Some(dev) = device_opt.as_ref() {
        let sn = compute_safety_number(dev.account_id, &dev.root_pubkey);
        let (cwt_valid, cwt_remaining_secs, cwt_remaining_days, cwt_status) = match verify_device_cwt(
            &dev.device_cwt,
            &dev.root_pubkey,
            Some(&dev.device_pubkey),
            now_s,
        ) {
            Ok(claims) => {
                let rem_secs = claims.exp.saturating_sub(now_s);
                let rem_days = rem_secs / 86_400;
                if rem_secs < 5 * 86_400 {
                    cwt_warning = Some(format!(
                        "Device CWT expires in {rem_days} day(s) ({rem_secs}s); renew with `mp-outpost device renew`"
                    ));
                }
                (true, Some(rem_secs), Some(rem_days), "valid".to_string())
            }
            Err(CwtError::Expired) => {
                cwt_warning = Some(
                    "Device CWT is EXPIRED; renew with `mp-outpost device renew`".to_string(),
                );
                (false, Some(0), Some(0), "expired".to_string())
            }
            Err(e) => {
                cwt_warning = Some(format!("Device CWT invalid: {e}"));
                (false, None, None, format!("invalid: {e}"))
            }
        };
        json!({
            "enrolled": true,
            "account_id": dev.account_id,
            "device_id": dev.device_id,
            "api_authority": dev.api_authority,
            "local_relay_policy": relay_policy_name(dev.local_relay_policy as u8),
            "default_relay_url": dev.default_relay_url,
            "safety_number": sn,
            "cwt_valid": cwt_valid,
            "cwt_status": cwt_status,
            "cwt_remaining_secs": cwt_remaining_secs,
            "cwt_remaining_days": cwt_remaining_days,
            "cwt_warning": cwt_warning,
        })
    } else if let Some(ref err) = device_error {
        json!({
            "enrolled": false,
            "error": sanitize_cli_meta(err),
        })
    } else {
        json!({ "enrolled": false })
    };

    // 3. Local daemon probe (strictly read-only, auto_spawn = false; distinguish stopped vs IPC error)
    let daemon_json = match connect_daemon_cli(opts, true, false).await {
        Ok((mut client, _)) => match client.request(IpcOpcode::GetStatus, Vec::new()).await {
            Ok(raw) => match decode_status_resp(&raw) {
                Ok(st) => json!({
                    "running": true,
                    "status": "running",
                    "daemon_pid": st.daemon_pid,
                    "daemon_epoch": st.daemon_epoch,
                    "control_ws_connected": st.control_ws_connected,
                    "dual_host_churn_alert": st.dual_host_churn_alert,
                    "active_party_id": st.active_party.as_ref().map(|p| p.party_id),
                }),
                Err(e) => {
                    let safe_err = sanitize_cli_meta(&e.to_string());
                    json!({
                        "running": false,
                        "status": "error",
                        "error": safe_err,
                        "detail": safe_err,
                    })
                }
            },
            Err(e) => {
                let safe_err = sanitize_cli_meta(&e.to_string());
                json!({
                    "running": false,
                    "status": "error",
                    "error": safe_err,
                    "detail": safe_err,
                })
            }
        },
        Err(msg) => {
            let safe_msg = sanitize_cli_meta(&msg);
            let is_stopped = msg.contains("not running")
                || msg.contains("No such file")
                || msg.contains("Connection refused")
                || msg.contains("no enrolled device");
            if is_stopped {
                json!({
                    "running": false,
                    "status": "stopped",
                    "detail": safe_msg,
                })
            } else {
                json!({
                    "running": false,
                    "status": "error",
                    "error": safe_msg,
                    "detail": safe_msg,
                })
            }
        }
    };

    // 4. Independent live TLS 1.3 GET /v1/health RTT + clock skew AND relay ping probe!
    let effective_authority = api_authority_override
        .or_else(|| device_opt.as_ref().map(|d| d.api_authority.clone()))
        .unwrap_or_else(|| DEFAULT_API_AUTHORITY.to_string());
    let effective_relay_url = relay_url_override
        .or_else(|| device_opt.as_ref().map(|d| d.default_relay_url.clone()))
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());

    let control_json = match build_control_client_config(&effective_authority) {
        Ok(cfg) => {
            let client = ControlClient::new(cfg.with_request_timeout(Duration::from_secs(10)));
            let t0 = Instant::now();
            match client.health().await {
                Ok(h) => {
                    let rtt_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let local_ms = i64::try_from(wall_now_ms()).unwrap_or(i64::MAX);
                    let server_ms = i64::try_from(h.server_now_ms).unwrap_or(i64::MAX);
                    let clock_skew_ms = server_ms.saturating_sub(local_ms);
                    json!({
                        "ok": h.ok,
                        "authority": sanitize_cli_meta(&effective_authority),
                        "rtt_ms": rtt_ms,
                        "server_now_ms": h.server_now_ms,
                        "clock_skew_ms": clock_skew_ms,
                    })
                }
                Err(e) => json!({
                    "ok": false,
                    "authority": sanitize_cli_meta(&effective_authority),
                    "error": sanitize_cli_meta(&e.to_string()),
                }),
            }
        }
        Err(e) => json!({
            "ok": false,
            "authority": sanitize_cli_meta(&effective_authority),
            "error": sanitize_cli_meta(&e.to_string()),
        }),
    };

    let relay_cfg_authority =
        extract_https_authority_from_url(&effective_relay_url).unwrap_or(DEFAULT_API_AUTHORITY);
    let relay_json = match build_control_client_config(relay_cfg_authority) {
        Ok(cfg) => {
            let client = ControlClient::new(cfg.with_request_timeout(Duration::from_secs(10)));
            match client.probe_relay_ping(&effective_relay_url).await {
                Ok(rtt) => json!({
                    "ok": true,
                    "relay_url": sanitize_cli_meta(&effective_relay_url),
                    "rtt_ms": u64::try_from(rtt.as_millis()).unwrap_or(u64::MAX),
                }),
                Err(e) => json!({
                    "ok": false,
                    "relay_url": sanitize_cli_meta(&effective_relay_url),
                    "error": sanitize_cli_meta(&e.to_string()),
                }),
            }
        }
        Err(e) => json!({
            "ok": false,
            "relay_url": sanitize_cli_meta(&effective_relay_url),
            "error": sanitize_cli_meta(&e.to_string()),
        }),
    };

    if opts.json {
        print_json(&json!({
            "binary": {
                "version": PKG_VERSION,
                "exe_path": exe_path,
                "on_disk_exe_matches_local": exe_matches,
                "on_disk_match": exe_matches,
                "build_stamp_verified": exe_matches,
                "build_order": build_order(),
                "build_digest": crate::build_info::BUILD_DIGEST_HEX,
            },
            "device": device_json,
            "daemon": daemon_json,
            "control_plane": control_json,
            "relay": relay_json,
        }));
    } else {
        println!("mp-outpost doctor (v{PKG_VERSION})");
        println!("  binary:               {exe_path}");
        println!("  build_stamp_verified: {exe_matches} (on_disk_match={exe_matches})");
        if let Some(dev) = device_opt.as_ref() {
            println!("  account_id:           {}", dev.account_id);
            println!("  device_id:            {}", dev.device_id);
            println!("  api_authority:        {}", sanitize_cli_meta(&dev.api_authority));
            println!(
                "  relay_policy:         {}",
                relay_policy_name(dev.local_relay_policy as u8)
            );
            println!(
                "  safety_number:        {}",
                compute_safety_number(dev.account_id, &dev.root_pubkey)
            );
            if let Some(days) = device_json.get("cwt_remaining_days").and_then(Value::as_u64)
                && let Some(secs) = device_json.get("cwt_remaining_secs").and_then(Value::as_u64)
            {
                println!("  cwt_remaining:        {days}d ({secs}s)");
            } else {
                println!(
                    "  cwt_status:           {}",
                    sanitize_cli_meta(
                        device_json
                            .get("cwt_status")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                    )
                );
            }
            if let Some(warn) = cwt_warning.as_deref() {
                println!("  WARNING:              {}", sanitize_cli_meta(warn));
            }
        } else if let Some(ref err) = device_error {
            println!("  device:               ERROR ({})", sanitize_cli_meta(err));
        } else {
            println!("  device:               not enrolled");
        }
        if daemon_json.get("running").and_then(Value::as_bool) == Some(true) {
            println!(
                "  daemon:               running (pid={}, ws_connected={})",
                daemon_json
                    .get("daemon_pid")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                daemon_json
                    .get("control_ws_connected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            );
        } else if daemon_json.get("status").and_then(Value::as_str) == Some("error") {
            println!(
                "  daemon:               ERROR ({})",
                sanitize_cli_meta(
                    daemon_json
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                )
            );
        } else {
            println!("  daemon:               stopped");
        }
        if control_json.get("ok").and_then(Value::as_bool) == Some(true) {
            println!(
                "  control_plane:        ok ({}, rtt={}ms, clock_skew={}ms)",
                sanitize_cli_meta(&effective_authority),
                control_json
                    .get("rtt_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                control_json
                    .get("clock_skew_ms")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
            );
        } else {
            println!(
                "  control_plane:        ERROR ({}: {})",
                sanitize_cli_meta(&effective_authority),
                sanitize_cli_meta(
                    control_json
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                )
            );
        }
        if relay_json.get("ok").and_then(Value::as_bool) == Some(true) {
            println!(
                "  relay_ping:           ok ({}, rtt={}ms)",
                sanitize_cli_meta(&effective_relay_url),
                relay_json
                    .get("rtt_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            );
        } else {
            println!(
                "  relay_ping:           ERROR ({}: {})",
                sanitize_cli_meta(&effective_relay_url),
                sanitize_cli_meta(
                    relay_json
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                )
            );
        }
    }
    Ok(())
}

// `mcp setup` lives in `crate::mcp_setup`.

// ---------------------------------------------------------------------------
// Output Formatting Helpers
// ---------------------------------------------------------------------------

fn print_status_resp(opts: &GlobalOpts, st: &crate::ipc_payloads::StatusResp) {
    if opts.json {
        print_json(&json!({
            "account_id": st.account_id,
            "device_id": st.device_id,
            "handle": st.handle,
            "api_authority": st.api_authority,
            "local_relay_policy": relay_policy_name(st.local_relay_policy),
            "cwt_expires_ms": st.cwt_expires_ms,
            "daemon_epoch": st.daemon_epoch,
            "daemon_pid": st.daemon_pid,
            "control_ws_connected": st.control_ws_connected,
            "dual_host_churn_alert": st.dual_host_churn_alert,
            "active_party_id": st.active_party.as_ref().map(|p| p.party_id),
            "active_party_room_code": st.active_party.as_ref().map(|p| p.room_code.as_str()),
        }));
    } else if opts.debug {
        println!(
            "account_id={} device_id={} handle=@{} pid={} epoch={} ws={} active_party={:?}",
            st.account_id,
            st.device_id,
            sanitize_cli_meta(&st.handle),
            st.daemon_pid,
            st.daemon_epoch,
            st.control_ws_connected,
            st.active_party.as_ref().map(|p| p.party_id)
        );
    } else {
        let who = if st.handle.is_empty() {
            "Signed in".to_string()
        } else {
            format!("@{}", sanitize_cli_meta(st.handle.trim_start_matches('@')))
        };
        let conn = if st.control_ws_connected {
            "● Online"
        } else {
            "◐ Reconnecting…"
        };
        println!("{who} · {conn}");
        if let Some(ref p) = st.active_party {
            let title = if p.room_name.is_empty() {
                "Active party".to_string()
            } else {
                sanitize_cli_meta(&p.room_name)
            };
            if p.room_code.is_empty() {
                println!("Party: {title} · {} live", p.member_count);
            } else {
                println!(
                    "Party: {title} (code {}) · {} live",
                    sanitize_cli_meta(&p.room_code),
                    p.member_count
                );
            }
        } else {
            println!("Party: none (run `mp-outpost invite` or `mp-outpost join`)");
        }
    }
}

fn print_poll_resp(
    opts: &GlobalOpts,
    resp: &crate::ipc_payloads::PartyPollIpcResp,
) -> Result<(), String> {
    let nonce = random_safe_id()?;
    if opts.json {
        let events: Vec<Value> = resp
            .events
            .iter()
            .map(|ev| match &ev.kind {
                IpcPartyEventKind::Chat {
                    provenance,
                    room_scope,
                    target_selector,
                    timestamp_ns,
                    body,
                } => json!({
                    "event_seq": ev.event_seq,
                    "kind": "chat_message",
                    "untrusted_remote": true,
                    "sender_account_id": provenance.sender_account_id,
                    "sender_device_id": provenance.sender_device_id,
                    "sender_handle": sanitize_peer_text(&provenance.sender_handle),
                    "safety_number": provenance.safety_number,
                    "room_scope": sanitize_peer_text(room_scope),
                    "target_selector": sanitize_peer_text(target_selector),
                    "timestamp_ns": timestamp_ns,
                    "body": sanitize_peer_text(body),
                }),
                IpcPartyEventKind::BridgeEnvelope {
                    provenance,
                    room_scope,
                    payload,
                } => json!({
                    "event_seq": ev.event_seq,
                    "kind": "bridge_envelope",
                    "untrusted_remote": true,
                    "sender_account_id": provenance.sender_account_id,
                    "sender_device_id": provenance.sender_device_id,
                    "sender_handle": sanitize_peer_text(&provenance.sender_handle),
                    "safety_number": provenance.safety_number,
                    "room_scope": sanitize_peer_text(room_scope),
                    "payload_b64": B64.encode(payload),
                }),
                IpcPartyEventKind::ControlNotice {
                    provenance,
                    notice_kind,
                    party_epoch,
                    text,
                } => json!({
                    "event_seq": ev.event_seq,
                    "kind": "control_notice",
                    "untrusted_remote": true,
                    "sender_account_id": provenance.sender_account_id,
                    "sender_device_id": provenance.sender_device_id,
                    "sender_handle": sanitize_peer_text(&provenance.sender_handle),
                    "notice_kind": notice_kind,
                    "party_epoch": party_epoch,
                    "text": sanitize_peer_text(text),
                }),
                IpcPartyEventKind::MembershipChanged {
                    party_epoch,
                    summary,
                } => json!({
                    "event_seq": ev.event_seq,
                    "kind": "membership_changed",
                    "party_epoch": party_epoch,
                    "summary": sanitize_peer_text(summary),
                }),
            })
            .collect();
        print_json(&json!({
            "party_id": resp.party_id,
            "daemon_epoch": resp.daemon_epoch,
            "next_seq": resp.next_seq,
            "dropped_before_seq": resp.dropped_before_seq,
            "cursor_reset": resp.cursor_reset,
            "gap_possible": resp.gap_possible,
            "timed_out": resp.timed_out,
            "events": events,
        }));
    } else {
        for ev in &resp.events {
            match &ev.kind {
                IpcPartyEventKind::Chat {
                    provenance,
                    room_scope,
                    target_selector,
                    body,
                    ..
                } => {
                    let payload = format!(
                        "scope: {room_scope}\ntarget: {target_selector}\n{body}"
                    );
                    if opts.debug {
                        println!(
                            "[seq={} from={}({})]\n{}",
                            ev.event_seq,
                            sanitize_cli_meta(&provenance.sender_handle),
                            provenance.sender_account_id,
                            fence_peer_text(&payload, nonce)
                        );
                    } else {
                        println!(
                            "[#{} {}]\n{}",
                            ev.event_seq,
                            format_member_display(
                                provenance.sender_account_id,
                                &provenance.sender_handle,
                            ),
                            fence_peer_text(&payload, nonce)
                        );
                    }
                }
                IpcPartyEventKind::BridgeEnvelope {
                    provenance,
                    room_scope,
                    payload,
                } => {
                    let fenced_body = format!(
                        "scope: {room_scope}\npayload_b64: {}",
                        B64.encode(payload)
                    );
                    if opts.debug {
                        println!(
                            "[seq={} board from={}({}) bytes={}]\n{}",
                            ev.event_seq,
                            sanitize_cli_meta(&provenance.sender_handle),
                            provenance.sender_account_id,
                            payload.len(),
                            fence_peer_text(&fenced_body, nonce)
                        );
                    } else {
                        println!(
                            "[#{} card {}]\n{}",
                            ev.event_seq,
                            format_member_display(
                                provenance.sender_account_id,
                                &provenance.sender_handle,
                            ),
                            fence_peer_text(&fenced_body, nonce)
                        );
                    }
                }
                IpcPartyEventKind::ControlNotice {
                    provenance, text, ..
                } => {
                    println!(
                        "[seq={} notice from={}({})]\n{}",
                        ev.event_seq,
                        sanitize_cli_meta(&provenance.sender_handle),
                        provenance.sender_account_id,
                        fence_peer_text(text, nonce)
                    );
                }
                IpcPartyEventKind::MembershipChanged { summary, .. } => {
                    println!(
                        "[seq={} membership] {}",
                        ev.event_seq,
                        sanitize_cli_meta(summary)
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn argv_guard_blocks_all_secret_classes_without_echoing() {
        let rk = encode_recovery_key(&[0x42u8; 32]);
        assert!(reject_secrets_in_argv(&s(&["mp-outpost", "mcp", &rk])).is_err());
        assert!(
            reject_secrets_in_argv(&s(&["mp-outpost", "account", "recover", &rk.to_uppercase()]))
                .is_err()
        );

        // Space-split unprefixed 55-char Crockford recovery key across multiple argv args
        let unprefixed = rk.strip_prefix("mprk1_").unwrap_or(&rk);
        let parts: Vec<&str> = unprefixed.split('-').collect();
        let mut argv = vec!["mp-outpost".to_string(), "account".to_string(), "recover".to_string()];
        for p in parts {
            argv.push(p.to_string());
        }
        assert!(reject_secrets_in_argv(&argv).is_err());

        // --passphrase=secret MUST NOT echo `supersecret999`
        let err = reject_secrets_in_argv(&s(&[
            "mp-outpost",
            "account",
            "export-mpkey",
            "--passphrase=supersecret999",
        ]))
        .err()
        .unwrap_or_default();
        assert!(!err.is_empty());
        assert!(!err.contains("supersecret999"));

        // --pin and --pin=... (case-insensitive) MUST be rejected without echoing value!
        for bad_pin in [
            vec!["mp-outpost", "lan", "host", "--pin", "424242"],
            vec!["mp-outpost", "lan", "host", "--pin=424242"],
            vec!["mp-outpost", "lan", "join", "--PIN=424242"],
            vec!["mp-outpost", "lan", "join", "--PIN", "424242"],
        ] {
            let pin_err = reject_secrets_in_argv(&s(&bad_pin))
                .err()
                .unwrap_or_default();
            assert!(
                pin_err.contains("PINs are forbidden on CLI argv"),
                "expected PIN guard error, got: {pin_err}"
            );
            assert!(!pin_err.contains("424242"));
        }
        assert!(
            reject_secrets_in_argv(&s(&[
                "mp-outpost",
                "lan",
                "host",
                "--require-pin",
                "--pin-stdin",
            ]))
            .is_ok()
        );

        // PEM header and .mpkey
        assert!(
            reject_secrets_in_argv(&s(&[
                "mp-outpost",
                "foo",
                "-----BEGIN PRIVATE KEY-----\nabc"
            ]))
            .is_err()
        );
        assert!(
            reject_secrets_in_argv(&s(&[
                "mp-outpost",
                "foo",
                "-----BEGIN MULTIPLAYER RECOVERY KEY-----\nabc"
            ]))
            .is_err()
        );

        // Device link token & invite token (case-insensitive)
        assert!(
            reject_secrets_in_argv(&s(&["mp-outpost", "MCP", "MPDL1_abc123"]))
                .is_err()
        );
        assert!(
            reject_secrets_in_argv(&s(&["mp-outpost", "account", "MPINV1_abc123"]))
                .is_err()
        );

        // Normal clean command passes
        assert!(
            reject_secrets_in_argv(&s(&[
                "mp-outpost",
                "account",
                "export-mpkey",
                "--passphrase-stdin",
                "--out",
                "/tmp/backup.mpkey",
            ]))
            .is_ok()
        );
    }

    #[test]
    fn unknown_arg_redaction_and_shell_toml_quoting() {
        assert_eq!(redact_unknown_arg("--token=abc123"), "--token=[REDACTED]");
        assert_eq!(redact_unknown_arg("--secret=xyz"), "--secret=[REDACTED]");
        assert_eq!(redact_unknown_arg("--api-key=xyz"), "--api-key=[REDACTED]");
        assert_eq!(redact_unknown_arg("--bogus"), "--bogus");

        assert_eq!(
            shell_single_quote("/tmp/o'brien/mp-outpost"),
            "'/tmp/o'\\''brien/mp-outpost'"
        );
        assert_eq!(
            toml_basic_string("/tmp/o'brien/a\"b\\c\n"),
            "\"/tmp/o'brien/a\\\"b\\\\c\\n\""
        );
    }

    #[test]
    fn codex_toml_upsert_is_idempotent_and_preserves_other_sections() {
        let initial = "[model]\nprovider = \"openai\"\n\n[mcp_servers.multiplayer]\ncommand = \"/old/bin\"\nargs = [\"mcp\"]\n\n[other]\nkey = \"val\"\n";
        let once = crate::mcp_setup::upsert_codex_mcp_toml(initial, "/Users/o'brien/mp-outpost");
        let twice = crate::mcp_setup::upsert_codex_mcp_toml(&once, "/Users/o'brien/mp-outpost");
        assert_eq!(once, twice);
        assert!(once.contains("command = \"/Users/o'brien/mp-outpost\""));
        assert!(once.contains("[model]"));
        assert!(once.contains("[other]\nkey = \"val\""));
        assert!(!once.contains("/old/bin"));
    }

    #[test]
    fn fingerprint_validators_and_friend_sort_order() {
        assert!(is_valid_browser_fingerprint("a1b2c3d4"));
        assert!(!is_valid_browser_fingerprint("A1B2C3D4"));
        assert!(!is_valid_browser_fingerprint("a1b2c3d"));
        assert!(!is_valid_browser_fingerprint(""));

        let fp = compute_device_fingerprint(&[0x77u8; 32]);
        assert_eq!(normalize_device_fingerprint_arg(&fp), Some(fp.as_str()));
        assert_eq!(
            normalize_device_fingerprint_arg(&format!("mpdevfp2: {fp}")),
            Some(fp.as_str())
        );
        assert!(normalize_device_fingerprint_arg("not-a-fp").is_none());

        // Incoming pending requests (2) sort strictly before friends (0) < pending_out (1) < blocked (3)
        assert!(friend_state_sort_key(2) < friend_state_sort_key(0));
        assert!(friend_state_sort_key(0) < friend_state_sort_key(1));
        assert!(friend_state_sort_key(1) < friend_state_sort_key(3));
    }

    #[test]
    fn browser_url_and_guest_display_hardening() {
        assert!(is_safe_browser_url(
            "https://multiplayer.tech/login?code=ABCD-EFGH"
        ));
        assert!(!is_safe_browser_url("http://multiplayer.tech/login"));
        assert!(!is_safe_browser_url("https://multiplayer.tech/login with space"));
        assert!(!is_safe_browser_url("https://multiplayer.tech/login\r\n"));
        assert!(!is_safe_browser_url("https://multiplayer.tech/l\u{0007}gin"));
        assert!(!is_safe_browser_url("https://multiplayer.tech/café"));
        let too_long = format!("https://multiplayer.tech/{}", "a".repeat(500));
        assert!(!is_safe_browser_url(&too_long));

        // Guests (`account_id == 0` or `" (guest)"`) NEVER render with `@` prefix!
        assert_eq!(format_member_display(0, "phall"), "phall (guest)");
        assert_eq!(format_member_display(0, "@phall"), "phall (guest)");
        assert_eq!(format_member_display(0, "phall (guest)"), "phall (guest)");
        assert_eq!(format_member_display(0, ""), "guest");
        assert_eq!(format_member_display(1001, "phall"), "@phall");
        assert_eq!(format_member_display(1001, "@phall"), "@phall");
    }
}
