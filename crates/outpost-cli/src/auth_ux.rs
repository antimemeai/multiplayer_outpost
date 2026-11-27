//! Auth UX Stage 2: Friendly CLI `login`, `add-device`, and 1Password-style offline
//! `account emergency-kit` HTML card (`AUTH_UX_STAGE2_SPEC.md`).
//!
//! Security invariants:
//! - Zero external URLs, zero `<script>`, strict HTML-entity escaping on all interpolated fields.
//! - `account emergency-kit` REQUIRES explicit `--out <path.html>`, writes atomically with mode
//!   `0600` (`O_NOFOLLOW`, no-replace unless `--force`), NEVER auto-writes to `~/Downloads`, and
//!   NEVER emits `mprk1_` to stdout or `--json`.
//! - Terminal QR code (standards-compliant ISO/IEC 18004 Version 1 ECC-L, 21x21 modules)
//!   encodes ONLY the opaque 9-character link code (`XXXX-XXXX`), NEVER root keys or account IDs.
//! - Interactive secrets are read unbuffered from `/dev/tty` with echo disabled via `TCSAFLUSH`
//!   + async-signal-safe `SIGINT`/`SIGTERM` restoration into `Zeroizing` buffers.

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
    AccountId, DeviceId, MAX_CWT_TTL_SECS, MAX_SAFE_ID, RelayPolicy, compute_device_fingerprint,
    decode_recovery_key, encode_device_cwt, encode_recovery_key, validate_ed25519_pubkey_strict,
    verify_device_cwt,
};
use outpost_control::{
    ControlClient, ControlError, DEFAULT_API_AUTHORITY, DeviceLinkApproveRequest,
    DeviceLinkInspectResponse, RegisterAccountRequest, RequestSigner, validate_link_code,
    wall_now_ms, wall_now_secs,
};
use outpost_core::fence::sanitize_peer_text;
use outpost_core::storage_codec::DeviceRecord;
use outpost_core::trust::compute_safety_number;
use outpost_daemon::{
    DaemonError, atomic_write_in_dir, atomic_write_in_dir_no_replace, fill_random,
    open_dir_nofollow, read_regular_file_bounded_nofollow,
};
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

use crate::build_info::decode_hex_32;
use crate::cli::{GlobalOpts, run_cli_command};
use crate::mpkey::{MAX_PEM_BYTES, PEM_BEGIN, decrypt_mpkey};
use crate::storage::{
    DEFAULT_RELAY_URL, build_control_client_config, load_device_record, lock_state, open_state_dir,
    resolve_active_device_id, resolve_effective_state_dir, save_default_device_id,
    save_device_record,
};

const MAX_TTY_SECRET_BYTES: usize = 512;

// ---------------------------------------------------------------------------
// 1. Offline Emergency Kit HTML Card (Zero JS, Zero External URLs)
// ---------------------------------------------------------------------------

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn format_recovery_key_blocks(recovery_key: &str) -> String {
    let trimmed = recovery_key.trim();
    let (prefix, rest) = match trimmed.split_once('_') {
        Some((p, r)) => (Some(p), r),
        None => (None, trimmed),
    };
    let groups: Vec<&str> = rest.split('-').filter(|g| !g.is_empty()).collect();
    if groups.len() <= 4 {
        return html_escape(trimmed);
    }
    let mut lines = Vec::new();
    let mut idx = 0usize;
    while idx < groups.len() {
        let end = (idx + 4).min(groups.len());
        let chunk = groups.get(idx..end).unwrap_or_default().join("-");
        let mut line = String::new();
        if idx == 0
            && let Some(p) = prefix
        {
            line.push_str(p);
            line.push('_');
        }
        line.push_str(&chunk);
        if end < groups.len() {
            line.push('-');
        }
        lines.push(html_escape(&line));
        idx = end;
    }
    lines.join("\n")
}

/// Renders a strictly self-contained, zero-JS, zero-external-URL, print-ready offline
/// Emergency Kit HTML card with strict HTML-entity escaping on every interpolated field.
pub fn render_emergency_kit_html(
    handle: &str,
    account_id: u64,
    safety_number: &str,
    recovery_key: &str,
    created_date_utc: &str,
) -> String {
    let clean_handle = handle.trim().trim_start_matches('@');
    let esc_handle = html_escape(clean_handle);
    let esc_sn = html_escape(safety_number.trim());
    let esc_date = html_escape(created_date_utc.trim());
    let esc_rk_full = html_escape(recovery_key.trim());
    let esc_rk_blocks = format_recovery_key_blocks(recovery_key);

    format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>Multiplayer Outpost Emergency Kit — @{esc_handle}</title>\n\
<style>\n\
  * {{ box-sizing: border-box; }}\n\
  body {{\n\
    margin: 0;\n\
    padding: 32px;\n\
    background: #f4f5f7;\n\
    color: #111827;\n\
    font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif;\n\
    line-height: 1.5;\n\
  }}\n\
  .card {{\n\
    max-width: 720px;\n\
    margin: 0 auto;\n\
    background: #ffffff;\n\
    border: 2px solid #111827;\n\
    border-radius: 10px;\n\
    padding: 28px 32px;\n\
  }}\n\
  .header {{\n\
    display: flex;\n\
    justify-content: space-between;\n\
    align-items: baseline;\n\
    border-bottom: 2px solid #e5e7eb;\n\
    padding-bottom: 14px;\n\
    margin-bottom: 20px;\n\
  }}\n\
  .brand {{ font-size: 20px; font-weight: 700; letter-spacing: -0.01em; }}\n\
  .date {{ font-size: 13px; color: #4b5563; }}\n\
  .banner {{\n\
    background: #fef3c7;\n\
    border: 1px solid #d97706;\n\
    border-radius: 6px;\n\
    padding: 12px 14px;\n\
    font-size: 13px;\n\
    margin-bottom: 20px;\n\
  }}\n\
  .grid {{\n\
    display: grid;\n\
    grid-template-columns: 1fr 1fr;\n\
    gap: 14px;\n\
    margin-bottom: 18px;\n\
  }}\n\
  .field {{ border: 1px solid #d1d5db; border-radius: 6px; padding: 10px 12px; }}\n\
  .label {{\n\
    font-size: 11px;\n\
    text-transform: uppercase;\n\
    letter-spacing: 0.06em;\n\
    color: #4b5563;\n\
    margin-bottom: 4px;\n\
  }}\n\
  .val {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 14px; font-weight: 600; word-break: break-all; }}\n\
  .secret-box {{\n\
    border: 2px dashed #111827;\n\
    border-radius: 8px;\n\
    background: #f9fafb;\n\
    padding: 16px;\n\
    margin: 18px 0;\n\
  }}\n\
  .secret-blocks {{\n\
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;\n\
    font-size: 15px;\n\
    font-weight: 700;\n\
    letter-spacing: 0.04em;\n\
    white-space: pre-wrap;\n\
    margin: 8px 0 10px 0;\n\
  }}\n\
  .secret-single {{\n\
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;\n\
    font-size: 11px;\n\
    color: #374151;\n\
    word-break: break-all;\n\
  }}\n\
  .recovery-steps {{\n\
    border-top: 1px solid #e5e7eb;\n\
    padding-top: 14px;\n\
    font-size: 13px;\n\
  }}\n\
  code {{\n\
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;\n\
    background: #f3f4f6;\n\
    padding: 2px 6px;\n\
    border-radius: 4px;\n\
  }}\n\
  @media print {{\n\
    body {{ background: #ffffff; padding: 0; }}\n\
    .card {{ border: 2px solid #000000; box-shadow: none; max-width: 100%; }}\n\
  }}\n\
</style>\n\
</head>\n\
<body>\n\
  <main class=\"card\">\n\
    <header class=\"header\">\n\
      <div class=\"brand\">Multiplayer Outpost — Emergency Kit</div>\n\
      <div class=\"date\">Created (UTC): {esc_date}</div>\n\
    </header>\n\
    <div class=\"banner\">\n\
      <strong>KEEP THIS SECRET OFFLINE.</strong> Anyone with this Recovery Key controls your account identity. Store this card in 1Password / Apple Passwords or print it and keep it in a safe place, then securely delete the temporary HTML file from disk.\n\
    </div>\n\
    <section class=\"grid\">\n\
      <div class=\"field\">\n\
        <div class=\"label\">Handle</div>\n\
        <div class=\"val\">@{esc_handle}</div>\n\
      </div>\n\
      <div class=\"field\">\n\
        <div class=\"label\">Immutable Account ID</div>\n\
        <div class=\"val\">{account_id}</div>\n\
      </div>\n\
    </section>\n\
    <section class=\"field\">\n\
      <div class=\"label\">Canonical Safety Number</div>\n\
      <div class=\"val\">{esc_sn}</div>\n\
    </section>\n\
    <section class=\"secret-box\">\n\
      <div class=\"label\">Root Recovery Key (mprk1_)</div>\n\
      <pre class=\"secret-blocks\">{esc_rk_blocks}</pre>\n\
      <div class=\"secret-single\">Canonical single-line: {esc_rk_full}</div>\n\
    </section>\n\
    <section class=\"recovery-steps\">\n\
      <div class=\"label\">Offline Account Recovery</div>\n\
      <p>To recover your account on a new machine, install <code>mp-outpost</code> and run <code>mp-outpost login</code> (choose <strong>[3] Recover a lost account</strong> and enter the Recovery Key above when prompted).</p>\n\
    </section>\n\
  </main>\n\
</body>\n\
</html>\n"
    )
}

/// Converts Unix epoch seconds into `YYYY-MM-DD` UTC using Howard Hinnant's civil-from-days algorithm.
fn format_utc_date(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let z = days.saturating_add(719_468);
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

fn write_emergency_kit_file(path: &Path, html: &str, force: bool) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid output path '{}'", path.display()))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir_fd = open_dir_nofollow(parent)
        .map_err(|e| format!("failed to open output directory '{}': {e}", parent.display()))?;
    if force {
        atomic_write_in_dir(dir_fd.as_raw_fd(), file_name, html.as_bytes())
            .map_err(|e| format!("failed writing emergency kit '{}': {e}", path.display()))
    } else {
        match atomic_write_in_dir_no_replace(dir_fd.as_raw_fd(), file_name, html.as_bytes(), 0o600)
        {
            Ok(()) => Ok(()),
            Err(DaemonError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                Err(format!(
                    "refusing to overwrite existing file '{}' (pass --force to replace)",
                    path.display()
                ))
            }
            Err(e) => Err(format!(
                "failed writing emergency kit '{}': {e}",
                path.display()
            )),
        }
    }
}

/// CLI entrypoint for `mp-outpost account emergency-kit --out <path.html> ...`.
/// Hard spec rule: `--out <path.html>` is REQUIRED (never auto-writes to `~/Downloads`) and
/// NEVER prints `mprk1_` to stdout or `--json`.
pub fn run_emergency_kit_cmd(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut out_path: Option<PathBuf> = None;
    let mut root_key_file: Option<PathBuf> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut handle_opt: Option<String> = None;
    let mut force = false;
    let mut json_out = opts.json;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--out" => out_path = Some(PathBuf::from(next_val(args, &mut i, "--out")?)),
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?))
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?)
            }
            "--handle" => handle_opt = Some(next_val(args, &mut i, "--handle")?.to_string()),
            "--force" => {
                force = true;
                i += 1;
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown argument to `account emergency-kit`: {other}"
                ));
            }
        }
    }

    let out_path = out_path.ok_or_else(|| {
        "account emergency-kit requires explicit --out <path.html> (never auto-writes to ~/Downloads)"
            .to_string()
    })?;
    if !force && out_path.exists() {
        return Err(format!(
            "refusing to overwrite existing file '{}' (pass --force to replace)",
            out_path.display()
        ));
    }

    let (root_secret, mpkey_aid, mpkey_handle) = if let Some(ref rk_path) = root_key_file {
        load_root_key_from_path(rk_path, "account emergency-kit")?
    } else {
        let raw_rk = read_secret_from_tty(
            "account emergency-kit",
            "Enter Root Recovery Key (mprk1_...): ",
        )?;
        let seed = decode_recovery_key(raw_rk.as_str()).map_err(|e| e.to_string())?;
        (Zeroizing::new(seed), None, None)
    };

    let root_pubkey = SigningKey::from_bytes(&root_secret)
        .verifying_key()
        .to_bytes();

    let local_account_id = resolve_effective_state_dir(opts.state_dir.as_deref())
        .ok()
        .and_then(|st| {
            let did = resolve_active_device_id(&st, opts.device_id).ok()?;
            let dev = load_device_record(&st, did).ok()?;
            (dev.root_pubkey == root_pubkey).then_some(dev.account_id)
        });

    let account_id = account_id_opt
        .or(mpkey_aid)
        .or(local_account_id)
        .ok_or_else(|| {
            "unable to determine account_id locally; pass --account-id <u64>".to_string()
        })?;

    let handle = handle_opt
        .or(mpkey_handle)
        .unwrap_or_else(|| format!("account-{account_id}"));
    let safety_number = compute_safety_number(account_id, &root_pubkey);
    let created_date_utc = format_utc_date(wall_now_secs());
    let recovery_key = Zeroizing::new(encode_recovery_key(&root_secret));
    drop(root_secret);

    let html = Zeroizing::new(render_emergency_kit_html(
        &handle,
        account_id,
        &safety_number,
        recovery_key.as_str(),
        &created_date_utc,
    ));
    drop(recovery_key);

    write_emergency_kit_file(&out_path, html.as_str(), force)?;
    drop(html);

    if json_out {
        print_json(&json!({
            "written": true,
            "path": out_path.display().to_string(),
            "account_id": account_id,
            "handle": sanitize_meta(&handle),
            "safety_number": safety_number,
            "created_date_utc": created_date_utc,
        }));
    } else {
        println!(
            "Wrote offline Emergency Kit to '{}' (mode 0600).\n\
             Account: @{} (account_id={})\n\
             Safety Number: {}\n\n\
             Save this file into 1Password / Apple Passwords or print it, then securely delete\n\
             the temporary file from disk (`rm {}`).",
            out_path.display(),
            sanitize_meta(&handle),
            account_id,
            safety_number,
            out_path.display()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Pure-Rust ISO/IEC 18004 Version-1 (21x21) ECC-L QR Code Renderer
// ---------------------------------------------------------------------------

const QR_V1_SIZE: usize = 21;
const QR_V1_L_DATA_BYTES: usize = 19;
const QR_V1_L_EC_BYTES: usize = 7;
const QR_V1_L_MAX_BYTE_PAYLOAD: usize = 17;

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let carry = (a & 0x80) != 0;
        a <<= 1;
        if carry {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    acc
}

/// Computes the 7 Reed-Solomon error-correction bytes over GF(256) (poly `0x11d`) for
/// QR Version 1 Level L (19 data codewords -> 7 EC codewords).
fn rs_encode_v1_l(data: &[u8; QR_V1_L_DATA_BYTES]) -> [u8; QR_V1_L_EC_BYTES] {
    // Generator polynomial g(x) = prod_{i=0..7} (x - alpha^i), stored as [1, g1, g2, ..., g7].
    let mut gen_poly = [0u8; QR_V1_L_EC_BYTES + 1];
    if let Some(first) = gen_poly.first_mut() {
        *first = 1;
    }
    for i in 0..QR_V1_L_EC_BYTES {
        let root = 1u8 << i; // alpha^i for i in 0..7 is 1, 2, 4, 8, 16, 32, 64
        for j in (1..=i + 1).rev() {
            let prev = gen_poly.get(j - 1).copied().unwrap_or(0);
            if let Some(slot) = gen_poly.get_mut(j) {
                *slot ^= gf256_mul(prev, root);
            }
        }
    }

    let mut rem = [0u8; QR_V1_L_EC_BYTES];
    for &byte in data {
        let factor = byte ^ rem.first().copied().unwrap_or(0);
        for k in 0..(QR_V1_L_EC_BYTES - 1) {
            let next = rem.get(k + 1).copied().unwrap_or(0);
            if let Some(slot) = rem.get_mut(k) {
                *slot = next;
            }
        }
        if let Some(last) = rem.last_mut() {
            *last = 0;
        }
        for k in 0..QR_V1_L_EC_BYTES {
            let g_coeff = gen_poly.get(k + 1).copied().unwrap_or(0);
            if let Some(slot) = rem.get_mut(k) {
                *slot ^= gf256_mul(g_coeff, factor);
            }
        }
    }
    rem
}

fn qr_format_bits_l_mask0() -> u16 {
    // EC level L = 0b01, Mask 0 = 0b000 -> data = 0b01000.
    let data: u16 = 0b01_000;
    let mut rem: u16 = data << 10;
    for bit in (10..15).rev() {
        if ((rem >> bit) & 1) != 0 {
            rem ^= 0x537 << (bit - 10);
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

struct QrMatrixV1 {
    dark: [bool; QR_V1_SIZE * QR_V1_SIZE],
    reserved: [bool; QR_V1_SIZE * QR_V1_SIZE],
}

impl QrMatrixV1 {
    fn new() -> Self {
        Self {
            dark: [false; QR_V1_SIZE * QR_V1_SIZE],
            reserved: [false; QR_V1_SIZE * QR_V1_SIZE],
        }
    }

    fn set_function(&mut self, r: usize, c: usize, is_dark: bool) {
        let idx = r * QR_V1_SIZE + c;
        if let Some(slot) = self.dark.get_mut(idx) {
            *slot = is_dark;
        }
        if let Some(slot) = self.reserved.get_mut(idx) {
            *slot = true;
        }
    }

    fn set_data(&mut self, r: usize, c: usize, is_dark: bool) {
        let idx = r * QR_V1_SIZE + c;
        if let Some(slot) = self.dark.get_mut(idx) {
            *slot = is_dark;
        }
    }

    fn is_reserved(&self, r: usize, c: usize) -> bool {
        self.reserved
            .get(r * QR_V1_SIZE + c)
            .copied()
            .unwrap_or(true)
    }

    fn is_dark(&self, r: usize, c: usize) -> bool {
        self.dark.get(r * QR_V1_SIZE + c).copied().unwrap_or(false)
    }

    fn place_finder(&mut self, top: isize, left: isize) {
        for dr in -1isize..=7 {
            for dc in -1isize..=7 {
                let r = top + dr;
                let c = left + dc;
                if (0..QR_V1_SIZE as isize).contains(&r) && (0..QR_V1_SIZE as isize).contains(&c) {
                    let is_dark = (0..=6).contains(&dr)
                        && (0..=6).contains(&dc)
                        && (dr == 0
                            || dr == 6
                            || dc == 0
                            || dc == 6
                            || ((2..=4).contains(&dr) && (2..=4).contains(&dc)));
                    self.set_function(r as usize, c as usize, is_dark);
                }
            }
        }
    }
}

fn encode_qr_v1_l_matrix(payload: &[u8]) -> QrMatrixV1 {
    let take_len = payload.len().min(QR_V1_L_MAX_BYTE_PAYLOAD);
    let mut bits: Vec<bool> = Vec::with_capacity(QR_V1_L_DATA_BYTES * 8);

    // Byte mode indicator: 0100
    bits.extend_from_slice(&[false, true, false, false]);
    // 8-bit character count
    let count_u8 = take_len as u8;
    for shift in (0..8).rev() {
        bits.push(((count_u8 >> shift) & 1) != 0);
    }
    // Payload bytes
    for &b in payload.get(..take_len).unwrap_or_default() {
        for shift in (0..8).rev() {
            bits.push(((b >> shift) & 1) != 0);
        }
    }
    // Terminator (up to 4 zero bits)
    let cap_bits = QR_V1_L_DATA_BYTES * 8;
    let term_bits = 4usize.min(cap_bits.saturating_sub(bits.len()));
    bits.resize(bits.len() + term_bits, false);
    // Pad to byte boundary
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }

    let mut data_cw = [0u8; QR_V1_L_DATA_BYTES];
    let mut cw_idx = 0usize;
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | u8::from(bit);
        }
        if let Some(slot) = data_cw.get_mut(cw_idx) {
            *slot = byte;
        }
        cw_idx += 1;
    }
    let pad_cycle = [0xECu8, 0x11u8];
    let mut pad_step = 0usize;
    while cw_idx < QR_V1_L_DATA_BYTES {
        if let Some(slot) = data_cw.get_mut(cw_idx) {
            *slot = pad_cycle.get(pad_step % 2).copied().unwrap_or(0xEC);
        }
        cw_idx += 1;
        pad_step += 1;
    }

    let ec_cw = rs_encode_v1_l(&data_cw);
    let mut all_bits = Vec::with_capacity((QR_V1_L_DATA_BYTES + QR_V1_L_EC_BYTES) * 8);
    for &b in data_cw.iter().chain(ec_cw.iter()) {
        for shift in (0..8).rev() {
            all_bits.push(((b >> shift) & 1) != 0);
        }
    }

    let mut m = QrMatrixV1::new();
    // Finder patterns + separators
    m.place_finder(0, 0);
    m.place_finder(0, 14);
    m.place_finder(14, 0);

    // Timing patterns
    for i in 8usize..13 {
        let dark = i.is_multiple_of(2);
        m.set_function(6, i, dark);
        m.set_function(i, 6, dark);
    }

    // Dark module at (row=13, col=8)
    m.set_function(13, 8, true);

    // Reserve format info modules before placing data
    let fmt_bits = qr_format_bits_l_mask0();
    let fmt_coords_1: [(usize, usize); 15] = [
        (8, 0),
        (8, 1),
        (8, 2),
        (8, 3),
        (8, 4),
        (8, 5),
        (8, 7),
        (8, 8),
        (7, 8),
        (5, 8),
        (4, 8),
        (3, 8),
        (2, 8),
        (1, 8),
        (0, 8),
    ];
    let fmt_coords_2: [(usize, usize); 15] = [
        (20, 8),
        (19, 8),
        (18, 8),
        (17, 8),
        (16, 8),
        (15, 8),
        (14, 8),
        (8, 13),
        (8, 14),
        (8, 15),
        (8, 16),
        (8, 17),
        (8, 18),
        (8, 19),
        (8, 20),
    ];
    for (idx, &(r, c)) in fmt_coords_1.iter().enumerate() {
        let bit = ((fmt_bits >> (14 - idx)) & 1) != 0;
        m.set_function(r, c, bit);
    }
    for (idx, &(r, c)) in fmt_coords_2.iter().enumerate() {
        let bit = ((fmt_bits >> (14 - idx)) & 1) != 0;
        m.set_function(r, c, bit);
    }

    // Zigzag data placement with Mask 0 (`(r + c) % 2 == 0`)
    let mut bit_idx = 0usize;
    let mut col: isize = (QR_V1_SIZE as isize) - 1;
    let mut upward = true;
    while col > 0 {
        if col == 6 {
            col -= 1;
        }
        for step in 0..QR_V1_SIZE {
            let r = if upward {
                QR_V1_SIZE - 1 - step
            } else {
                step
            };
            for dc in [0isize, -1isize] {
                let c = (col + dc) as usize;
                if !m.is_reserved(r, c) {
                    let raw_bit = all_bits.get(bit_idx).copied().unwrap_or(false);
                    let mask = (r + c).is_multiple_of(2);
                    m.set_data(r, c, raw_bit ^ mask);
                    bit_idx += 1;
                }
            }
        }
        col -= 2;
        upward = !upward;
    }

    m
}

/// Renders a compact, scannable ISO/IEC 18004 Version-1 (21x21, ECC-L) QR code in Unicode
/// half-blocks (`▀`/`▄`/`█`/` `) with a 2-module quiet zone.
///
/// Security invariant: callers MUST pass ONLY the opaque 9-character link code (`XXXX-XXXX`),
/// NEVER root keys, recovery keys, or account IDs.
pub fn render_code_ascii_qr(code: &str) -> String {
    let trimmed = code.trim();
    let matrix = encode_qr_v1_l_matrix(trimmed.as_bytes());
    let quiet: usize = 2;
    let total = QR_V1_SIZE + quiet * 2;

    let module_is_dark = |r: usize, c: usize| -> bool {
        if r < quiet || c < quiet || r >= quiet + QR_V1_SIZE || c >= quiet + QR_V1_SIZE {
            false
        } else {
            matrix.is_dark(r - quiet, c - quiet)
        }
    };

    // Render using inverted terminal half-blocks so the quiet zone is bright (`█`) and
    // dark QR modules are empty (` `), scanning cleanly on dark terminals.
    let mut out = String::new();
    let mut r = 0usize;
    while r < total {
        for c in 0..total {
            let top_light = !module_is_dark(r, c);
            let bot_light = if r + 1 < total {
                !module_is_dark(r + 1, c)
            } else {
                true
            };
            let ch = match (top_light, bot_light) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            out.push(ch);
        }
        out.push('\n');
        r += 2;
    }
    out
}

// ---------------------------------------------------------------------------
// 3. Signal-Safe Masked `/dev/tty` Prompts & Shared Helpers
// ---------------------------------------------------------------------------

struct AuthTermiosCell(UnsafeCell<MaybeUninit<libc::termios>>);
unsafe impl Sync for AuthTermiosCell {}

static AUTH_SAVED_TTY_FD: AtomicI32 = AtomicI32::new(-1);
static AUTH_SAVED_TERMIOS_VALID: AtomicBool = AtomicBool::new(false);
static AUTH_SAVED_TERMIOS: AuthTermiosCell =
    AuthTermiosCell(UnsafeCell::new(MaybeUninit::uninit()));

extern "C" fn auth_restore_termios_on_signal(sig: libc::c_int) {
    let was_valid = AUTH_SAVED_TERMIOS_VALID.swap(false, Ordering::AcqRel);
    let fd = AUTH_SAVED_TTY_FD.swap(-1, Ordering::AcqRel);
    if was_valid && fd >= 0 {
        unsafe {
            let ptr = (*AUTH_SAVED_TERMIOS.0.get()).as_ptr();
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

struct AuthTermiosEchoGuard {
    fd: RawFd,
    saved: libc::termios,
    prev_sigint: libc::sigaction,
    prev_sigterm: libc::sigaction,
}

impl AuthTermiosEchoGuard {
    fn disable_echo(fd: RawFd) -> Result<Self, String> {
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return Err(format!("tcgetattr failed: {}", io::Error::last_os_error()));
        }
        AUTH_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
        unsafe {
            (*AUTH_SAVED_TERMIOS.0.get()).write(orig);
        }
        AUTH_SAVED_TTY_FD.store(fd, Ordering::Release);
        AUTH_SAVED_TERMIOS_VALID.store(true, Ordering::Release);

        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = auth_restore_termios_on_signal as *const () as usize;
        let _ = unsafe { libc::sigemptyset(&mut act.sa_mask) };

        let mut prev_sigint: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut prev_sigterm: libc::sigaction = unsafe { std::mem::zeroed() };
        let rc_int = unsafe { libc::sigaction(libc::SIGINT, &act, &mut prev_sigint) };
        let rc_term = unsafe { libc::sigaction(libc::SIGTERM, &act, &mut prev_sigterm) };
        if rc_int != 0 || rc_term != 0 {
            AUTH_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
            AUTH_SAVED_TTY_FD.store(-1, Ordering::Release);
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
            AUTH_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
            AUTH_SAVED_TTY_FD.store(-1, Ordering::Release);
            let _ = unsafe { libc::sigaction(libc::SIGINT, &prev_sigint, std::ptr::null_mut()) };
            let _ = unsafe { libc::sigaction(libc::SIGTERM, &prev_sigterm, std::ptr::null_mut()) };
            return Err(format!("tcsetattr failed: {err}"));
        }

        Ok(Self {
            fd,
            saved: orig,
            prev_sigint,
            prev_sigterm,
        })
    }
}

impl Drop for AuthTermiosEchoGuard {
    fn drop(&mut self) {
        AUTH_SAVED_TERMIOS_VALID.store(false, Ordering::Release);
        AUTH_SAVED_TTY_FD.store(-1, Ordering::Release);
        unsafe {
            let _ = libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
            let _ = libc::sigaction(libc::SIGINT, &self.prev_sigint, std::ptr::null_mut());
            let _ = libc::sigaction(libc::SIGTERM, &self.prev_sigterm, std::ptr::null_mut());
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

fn strip_crlf(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

fn read_secret_from_tty(op: &str, prompt: &str) -> Result<Zeroizing<String>, String> {
    let mut tty = open_interactive_tty(op)?;
    let guard = AuthTermiosEchoGuard::disable_echo(tty.as_raw_fd())?;
    tty.write_all(prompt.as_bytes())
        .and_then(|()| tty.flush())
        .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;

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
    strip_crlf(&mut s);
    Ok(s)
}

fn read_line_from_tty(op: &str, prompt: &str) -> Result<String, String> {
    let mut tty = open_interactive_tty(op)?;
    tty.write_all(prompt.as_bytes())
        .and_then(|()| tty.flush())
        .map_err(|e| format!("failed writing to /dev/tty: {e}"))?;
    let cloned = tty
        .try_clone()
        .map_err(|e| format!("failed cloning /dev/tty: {e}"))?;
    let mut reader = BufReader::new(cloned);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed reading from /dev/tty: {e}"))?;
    strip_crlf(&mut line);
    Ok(line)
}

type LoadedRootKey = (Zeroizing<[u8; 32]>, Option<u64>, Option<String>);

fn load_root_key_from_path(path: &Path, op: &str) -> Result<LoadedRootKey, String> {
    let raw = Zeroizing::new(
        read_regular_file_bounded_nofollow(path, MAX_PEM_BYTES)
            .map_err(|e| format!("failed to read root key file '{}': {e}", path.display()))?,
    );
    if raw.len() == 32 {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&raw);
        return Ok((out, None, None));
    }
    let text = core::str::from_utf8(&raw).map_err(|_| {
        "root key file must be 32 raw bytes, .mpkey PEM, base64, 64-char hex, or mprk1_ recovery key"
            .to_string()
    })?;
    let trimmed = text.trim();
    if trimmed.starts_with(PEM_BEGIN) {
        let pass = read_secret_from_tty(op, "Enter .mpkey passphrase: ")?;
        let payload = decrypt_mpkey(trimmed, &pass)?;
        drop(pass);
        return Ok((
            Zeroizing::new(payload.root_seed),
            payload.account_id,
            payload.handle.clone(),
        ));
    }
    if let Ok(seed) = decode_recovery_key(trimmed) {
        return Ok((Zeroizing::new(seed), None, None));
    }
    if let Ok(decoded) = B64.decode(trimmed.as_bytes()).map(Zeroizing::new)
        && decoded.len() == 32
    {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&decoded);
        return Ok((out, None, None));
    }
    if let Some(arr) = decode_hex_32(trimmed) {
        return Ok((Zeroizing::new(arr), None, None));
    }
    Err(
        "root key file must contain 32-byte Ed25519 seed (raw, .mpkey PEM, base64, 64-char hex, or mprk1_ recovery key)"
            .to_string(),
    )
}

fn next_val<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Result<&'a str, String> {
    let val = args
        .get(*idx + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))?;
    *idx += 2;
    Ok(val)
}

fn parse_safe_id(raw: &str, name: &str) -> Result<u64, String> {
    let id = raw
        .parse::<u64>()
        .map_err(|_| format!("invalid integer for {name}: '{raw}'"))?;
    if id == 0 || id > MAX_SAFE_ID {
        return Err(format!("{name} must be in 1..={MAX_SAFE_ID}"));
    }
    Ok(id)
}

fn validate_device_label(label: &str) -> Result<(), String> {
    if label.is_empty()
        || label.len() > 64
        || !label.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(
            "device label must be 1..=64 printable ASCII characters (0x20..=0x7e)".to_string(),
        );
    }
    Ok(())
}

fn sanitize_meta(input: &str) -> String {
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

fn print_json(val: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(val) {
        println!("{s}");
    }
}

fn build_delegated_argv(opts: &GlobalOpts, tail: &[String]) -> Vec<String> {
    let mut argv = vec!["mp-outpost".to_string()];
    if let Some(ref st) = opts.state_dir {
        argv.push("--state-dir".to_string());
        argv.push(st.display().to_string());
    }
    if let Some(ref rt) = opts.runtime_dir {
        argv.push("--runtime-dir".to_string());
        argv.push(rt.display().to_string());
    }
    if let Some(did) = opts.device_id {
        argv.push("--device-id".to_string());
        argv.push(did.to_string());
    }
    if opts.json {
        argv.push("--json".to_string());
    }
    argv.extend(tail.iter().cloned());
    argv
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

// ---------------------------------------------------------------------------
// 4. `mp-outpost login [--code <XXXX-XXXX>] [--web] [--label <name>]`
// ---------------------------------------------------------------------------

pub async fn run_login_cmd(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut code: Option<String> = None;
    let mut web = false;
    let mut label: Option<String> = None;
    let mut api_authority = DEFAULT_API_AUTHORITY.to_string();

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--code" => code = Some(next_val(args, &mut i, "--code")?.to_string()),
            "--web" => {
                web = true;
                i += 1;
            }
            "--label" | "--device-label" => {
                label = Some(next_val(args, &mut i, a)?.to_string());
            }
            "--api-authority" => {
                api_authority = next_val(args, &mut i, "--api-authority")?.to_string();
            }
            other => {
                return Err(format!("unknown argument to `login`: {other}"));
            }
        }
    }

    if let Some(ref lbl) = label {
        validate_device_label(lbl)?;
    }

    // 1. Direct `--code <XXXX-XXXX>` delegates straight to `device link join`.
    if let Some(raw_code) = code {
        let trimmed = raw_code.trim().to_ascii_uppercase();
        validate_link_code(&trimmed).map_err(|e| e.to_string())?;
        let mut tail = vec!["device".to_string(), "link".to_string(), "join".to_string(), trimmed];
        if let Some(lbl) = label {
            tail.push("--device-label".to_string());
            tail.push(lbl);
        }
        if api_authority != DEFAULT_API_AUTHORITY {
            tail.push("--api-authority".to_string());
            tail.push(api_authority);
        }
        let delegated = build_delegated_argv(opts, &tail);
        return Box::pin(run_cli_command(&delegated)).await;
    }

    // 2. Check existing local enrolled device with valid CWT.
    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    if let Ok(did) = resolve_active_device_id(&state_dir_path, opts.device_id)
        && let Ok(dev) = load_device_record(&state_dir_path, did)
        && let Ok(claims) = verify_device_cwt(
            &dev.device_cwt,
            &dev.root_pubkey,
            Some(&dev.device_pubkey),
            wall_now_secs(),
        )
    {
        let sn = compute_safety_number(dev.account_id, &dev.root_pubkey);
        // Best-effort handle lookup (works gracefully offline too).
        let handle_opt = async {
            let cfg = build_control_client_config(&dev.api_authority).ok()?;
            let aid = AccountId::new(dev.account_id).ok()?;
            let dev_id = DeviceId::new(dev.device_id).ok()?;
            let signer = RequestSigner::device(aid, dev_id, dev.device_secret);
            let client = ControlClient::with_device_signer(cfg, signer);
            client.get_me().await.ok().map(|me| me.handle)
        }
        .await;

        if opts.json {
            print_json(&json!({
                "logged_in": true,
                "account_id": dev.account_id,
                "device_id": dev.device_id,
                "handle": handle_opt.as_deref().map(sanitize_meta),
                "device_label": sanitize_meta(&dev.device_label),
                "cwt_exp_s": claims.exp,
                "safety_number": sn,
            }));
        } else {
            let handle_disp = handle_opt
                .as_deref()
                .map(|h| format!("@{}", sanitize_meta(h)))
                .unwrap_or_else(|| format!("account_id={}", dev.account_id));
            println!(
                "Already logged in as {handle_disp}\n\
                 device_id:     {} (\"{}\")\n\
                 cwt_exp_s:     {}\n\
                 safety_number: {}",
                dev.device_id,
                sanitize_meta(&dev.device_label),
                claims.exp,
                sn
            );
        }

        if web {
            let web_code = read_line_from_tty(
                "login --web",
                "Enter the 8-character web sign-in code (XXXX-XXXX) shown in your browser: ",
            )?;
            let normalized = web_code.trim().to_ascii_uppercase();
            validate_link_code(&normalized).map_err(|e| e.to_string())?;
            let delegated = build_delegated_argv(
                opts,
                &["web".to_string(), "approve".to_string(), normalized],
            );
            return Box::pin(run_cli_command(&delegated)).await;
        }
        return Ok(());
    }

    // 3. Not enrolled yet: require interactive `/dev/tty` and show the 3-option Stage 2 menu.
    let choice = read_line_from_tty(
        "login",
        "Multiplayer Outpost — Sign In\n\
           [1] Register with an invite (mpinv1_...)\n\
           [2] Link to another machine I already use (XXXX-XXXX code)\n\
           [3] Recover a lost account (.mpkey file or mprk1_ Recovery Key)\n\
         Select [1-3]: ",
    )?;

    match choice.trim() {
        "1" => {
            interactive_register_flow(opts, &state_dir_path, label.as_deref(), &api_authority, web)
                .await
        }
        "2" => {
            let raw_code = read_line_from_tty(
                "login",
                "Enter the 8-character device link code (XXXX-XXXX) from your primary machine: ",
            )?;
            let normalized = raw_code.trim().to_ascii_uppercase();
            validate_link_code(&normalized).map_err(|e| e.to_string())?;
            let chosen_label = match label {
                Some(l) => l,
                None => {
                    let entered =
                        read_line_from_tty("login", "Machine label [outpost]: ")?;
                    if entered.trim().is_empty() {
                        "outpost".to_string()
                    } else {
                        entered.trim().to_string()
                    }
                }
            };
            validate_device_label(&chosen_label)?;
            let mut tail = vec![
                "device".to_string(),
                "link".to_string(),
                "join".to_string(),
                normalized,
                "--device-label".to_string(),
                chosen_label,
            ];
            if api_authority != DEFAULT_API_AUTHORITY {
                tail.push("--api-authority".to_string());
                tail.push(api_authority);
            }
            let delegated = build_delegated_argv(opts, &tail);
            Box::pin(run_cli_command(&delegated)).await
        }
        "3" => {
            let chosen_label = match label {
                Some(l) => l,
                None => {
                    let entered =
                        read_line_from_tty("login", "Machine label for recovered device [outpost]: ")?;
                    if entered.trim().is_empty() {
                        "outpost".to_string()
                    } else {
                        entered.trim().to_string()
                    }
                }
            };
            validate_device_label(&chosen_label)?;
            let mpkey_answer = read_line_from_tty(
                "login",
                "Path to .mpkey recovery file (or press Enter to type mprk1_ Recovery Key): ",
            )?;
            let mut tail = vec![
                "account".to_string(),
                "recover".to_string(),
                "--device-label".to_string(),
                chosen_label,
            ];
            let mpkey_trimmed = mpkey_answer.trim();
            if !mpkey_trimmed.is_empty() {
                tail.push("--mpkey".to_string());
                tail.push(mpkey_trimmed.to_string());
            }
            if api_authority != DEFAULT_API_AUTHORITY {
                tail.push("--api-authority".to_string());
                tail.push(api_authority);
            }
            let delegated = build_delegated_argv(opts, &tail);
            Box::pin(run_cli_command(&delegated)).await
        }
        other => Err(format!("invalid menu choice '{other}' (expected 1, 2, or 3)")),
    }
}

async fn interactive_register_flow(
    opts: &GlobalOpts,
    state_dir_path: &Path,
    label_opt: Option<&str>,
    api_authority: &str,
    web: bool,
) -> Result<(), String> {
    let invite_secret = read_secret_from_tty("login", "Enter invite secret (mpinv1_...): ")?;
    if invite_secret.trim().is_empty() {
        return Err("invite secret must not be empty".to_string());
    }
    let handle_raw = read_line_from_tty("login", "Desired @handle: ")?;
    let handle = handle_raw.trim().trim_start_matches('@').to_string();
    if handle.is_empty() || handle.len() > 64 {
        return Err("handle must be 1..=64 characters".to_string());
    }
    let device_label = match label_opt {
        Some(l) => l.to_string(),
        None => {
            let entered = read_line_from_tty("login", "Machine label [outpost]: ")?;
            if entered.trim().is_empty() {
                "outpost".to_string()
            } else {
                entered.trim().to_string()
            }
        }
    };
    validate_device_label(&device_label)?;

    let mut root_secret = Zeroizing::new([0u8; 32]);
    fill_random(&mut *root_secret).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let root_sk = SigningKey::from_bytes(&root_secret);
    let root_pubkey = root_sk.verifying_key().to_bytes();

    let mut device_secret = Zeroizing::new([0u8; 32]);
    fill_random(&mut *device_secret).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let device_pubkey = SigningKey::from_bytes(&device_secret)
        .verifying_key()
        .to_bytes();

    let mut idempotency_key = [0u8; 32];
    fill_random(&mut idempotency_key).map_err(|e| format!("CSPRNG failure: {e}"))?;

    let now_s = wall_now_secs();
    let device_cwt = encode_device_cwt(
        &root_sk,
        &device_pubkey,
        now_s,
        now_s.saturating_add(MAX_CWT_TTL_SECS),
    )
    .map_err(|e| format!("failed signing device CWT: {e}"))?;

    let cfg = build_control_client_config(api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);
    let idem_str = B64U.encode(idempotency_key);
    let resp = client
        .register_account(
            *root_secret,
            &idem_str,
            &RegisterAccountRequest {
                invite_secret: invite_secret.trim().to_string(),
                handle: handle.clone(),
                device_pubkey,
                device_label: device_label.clone(),
                device_cwt: device_cwt.clone(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    drop(invite_secret);

    let state_dir = open_state_dir(state_dir_path)?;
    let dev_rec = DeviceRecord {
        account_id: resp.account_id,
        device_id: resp.device_id,
        root_pubkey,
        device_secret: *device_secret,
        device_pubkey,
        device_cwt,
        local_relay_policy: RelayPolicy::AllowRelays,
        api_authority: api_authority.to_string(),
        default_relay_url: DEFAULT_RELAY_URL.to_string(),
        device_label,
    };
    drop(device_secret);

    let lock = lock_state(&state_dir)?;
    save_device_record(state_dir_path, &lock, &dev_rec)?;
    save_default_device_id(&state_dir, &lock, resp.device_id)?;
    drop(lock);

    let sn = compute_safety_number(resp.account_id, &root_pubkey);
    let safe_handle = sanitize_meta(&resp.handle);
    println!(
        "\nRegistered @{safe_handle} (account_id={}, device_id={})\nSafety Number: {sn}",
        resp.account_id, resp.device_id
    );

    let recovery_key = Zeroizing::new(encode_recovery_key(&root_secret));
    drop(root_secret);

    // Offer explicit-path Emergency Kit backup (NEVER auto-writes to ~/Downloads!).
    let kit_path_raw = read_line_from_tty(
        "login",
        "\nSave an offline Emergency Kit HTML card? Enter explicit file path (e.g. ./emergency-kit.html) or press Enter to skip: ",
    )?;
    let kit_trimmed = kit_path_raw.trim();
    if !kit_trimmed.is_empty() {
        let kit_path = PathBuf::from(kit_trimmed);
        let html = Zeroizing::new(render_emergency_kit_html(
            &resp.handle,
            resp.account_id,
            &sn,
            recovery_key.as_str(),
            &format_utc_date(wall_now_secs()),
        ));
        write_emergency_kit_file(&kit_path, html.as_str(), false)?;
        drop(html);
        println!(
            "Wrote Emergency Kit to '{}' (mode 0600).\n\
             Save this file into 1Password / Apple Passwords or print it, then securely delete it (`rm {}`).",
            kit_path.display(),
            kit_path.display()
        );
    } else if let Ok(mut tty) = open_interactive_tty("login") {
        let box_msg = Zeroizing::new(format!(
            "\n========================================================================\n\
             IMPORTANT — SAVE YOUR RECOVERY KEY NOW:\n  {}\n\
             ========================================================================\n",
            recovery_key.as_str()
        ));
        let _ = tty.write_all(box_msg.as_bytes()).and_then(|()| tty.flush());
    }
    drop(recovery_key);

    if web {
        let web_code = read_line_from_tty(
            "login --web",
            "Enter the 8-character web sign-in code (XXXX-XXXX) to approve (or press Enter to skip): ",
        )?;
        let normalized = web_code.trim().to_ascii_uppercase();
        if !normalized.is_empty() {
            validate_link_code(&normalized).map_err(|e| e.to_string())?;
            let delegated = build_delegated_argv(
                opts,
                &["web".to_string(), "approve".to_string(), normalized],
            );
            return Box::pin(run_cli_command(&delegated)).await;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. `mp-outpost add-device [--label <name>] [--root-key-file <path>] ...`
// ---------------------------------------------------------------------------

pub async fn run_add_device_cmd(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut label: Option<String> = None;
    let mut root_key_file: Option<PathBuf> = None;
    let mut account_id_opt: Option<u64> = None;
    let mut api_authority_opt: Option<String> = None;
    let mut timeout_secs: u64 = 300;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--label" | "--device-label" => {
                label = Some(next_val(args, &mut i, a)?.to_string());
            }
            "--root-key-file" => {
                root_key_file = Some(PathBuf::from(next_val(args, &mut i, "--root-key-file")?));
            }
            "--account-id" => {
                account_id_opt = Some(parse_safe_id(
                    next_val(args, &mut i, "--account-id")?,
                    "--account-id",
                )?);
            }
            "--api-authority" => {
                api_authority_opt = Some(next_val(args, &mut i, "--api-authority")?.to_string());
            }
            "--timeout-secs" => {
                let raw = next_val(args, &mut i, "--timeout-secs")?;
                timeout_secs = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --timeout-secs '{raw}'"))?;
                if timeout_secs == 0 || timeout_secs > 600 {
                    return Err("--timeout-secs must be in 1..=600".to_string());
                }
            }
            other => {
                return Err(format!("unknown argument to `add-device`: {other}"));
            }
        }
    }

    if let Some(ref lbl) = label {
        validate_device_label(lbl)?;
    }

    let (root_secret, mpkey_aid) = if let Some(ref rk_path) = root_key_file {
        let (seed, aid, _) = load_root_key_from_path(rk_path, "add-device")?;
        (seed, aid)
    } else {
        let path_answer = read_line_from_tty(
            "add-device",
            "Path to root key or .mpkey file (or press Enter to type mprk1_ Recovery Key): ",
        )?;
        let trimmed = path_answer.trim();
        if !trimmed.is_empty() {
            let (seed, aid, _) = load_root_key_from_path(Path::new(trimmed), "add-device")?;
            (seed, aid)
        } else {
            let rk = read_secret_from_tty("add-device", "Enter Root Recovery Key (mprk1_...): ")?;
            let seed = decode_recovery_key(rk.as_str()).map_err(|e| e.to_string())?;
            (Zeroizing::new(seed), None)
        }
    };

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let local_dev = resolve_active_device_id(&state_dir_path, opts.device_id)
        .ok()
        .and_then(|did| load_device_record(&state_dir_path, did).ok());

    let api_authority = api_authority_opt
        .or_else(|| local_dev.as_ref().map(|d| d.api_authority.clone()))
        .unwrap_or_else(|| DEFAULT_API_AUTHORITY.to_string());

    let cfg = build_control_client_config(&api_authority).map_err(|e| e.to_string())?;
    let client = ControlClient::new(cfg);

    let account_id = match account_id_opt
        .or(mpkey_aid)
        .or_else(|| local_dev.as_ref().map(|d| d.account_id))
    {
        Some(id) => id,
        None => {
            let lookup = client
                .recover_lookup(*root_secret)
                .await
                .map_err(|e| format!("failed resolving account_id from root key: {e}"))?;
            lookup.account_id
        }
    };

    let aid = AccountId::new(account_id).map_err(|e| e.to_string())?;
    let root_signer = RequestSigner::root(aid, *root_secret);

    let created = client
        .device_link_create(&root_signer, label.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    validate_link_code(&created.link_code).map_err(|e| e.to_string())?;

    let qr = render_code_ascii_qr(&created.link_code);
    if !opts.json {
        println!(
            "\nLink a new device to account_id={account_id}\n\n\
             Run this on your new machine:\n  \
               mp-outpost login --code {}\n\n\
             Or scan this code (contains ONLY the link code):\n{qr}\n\
             Waiting up to {timeout_secs}s for the new machine to claim code {}...",
            created.link_code, created.link_code
        );
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut transient_attempt = 0u32;
    let (device_pubkey_b64, claimed_label, requester_country) = loop {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return Err("link code expired before the new device claimed it".to_string());
        }
        let inspect_res = tokio::time::timeout(
            remaining,
            client.device_link_inspect(&root_signer, &created.link_code),
        )
        .await
        .map_err(|_| "link code expired before the new device claimed it".to_string())?;

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
                if wall_now_ms_adjusted(&client) >= expires_at_ms || Instant::now() >= deadline {
                    return Err("link code expired before the new device claimed it".to_string());
                }
                let rem = deadline.saturating_duration_since(Instant::now());
                let sleep_dur = Duration::from_millis(3_000 + jitter_ms(500)).min(rem);
                tokio::time::sleep(sleep_dur).await;
            }
            Err(err) => {
                let rem = deadline.saturating_duration_since(Instant::now());
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

    // ALWAYS compute the 128-bit mpdevfp2: fingerprint LOCALLY (never trust server copy!).
    let local_fp = compute_device_fingerprint(&device_pubkey);
    let safe_label = sanitize_meta(&claimed_label);
    let safe_country = sanitize_meta(&requester_country);

    let confirm_prompt = format!(
        "\nNew device claimed link code {}:\n  \
           Device label:       \"{safe_label}\"\n  \
           Requester country:  {safe_country}\n  \
           Device fingerprint: mpdevfp2:{local_fp}\n\
         Verify this fingerprint matches the new machine, then type 'yes' to sign its 30-day CWT: ",
        created.link_code
    );
    let confirm = read_line_from_tty("add-device", &confirm_prompt)?;
    if confirm.trim() != "yes" {
        return Err("add-device approval aborted by operator".to_string());
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
                link_code: created.link_code,
                device_pubkey,
                device_cwt,
                device_label: label,
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    if !resp.approved {
        return Err("server did not confirm device link approval (approved=false)".to_string());
    }

    let safe_resp_label = sanitize_meta(&resp.device_label);
    if opts.json {
        print_json(&json!({
            "approved": resp.approved,
            "account_id": resp.account_id,
            "device_id": resp.device_id,
            "device_label": safe_resp_label,
            "device_fingerprint": format!("mpdevfp2:{local_fp}"),
            "cwt_expires_ms": resp.cwt_expires_ms,
        }));
    } else {
        println!(
            "Approved device_id={} (label=\"{}\", fingerprint=mpdevfp2:{}, cwt_expires_ms={})",
            resp.device_id, safe_resp_label, local_fp, resp.cwt_expires_ms
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emergency_kit_html_escapes_all_fields_and_has_no_js_or_external_urls() {
        let html = render_emergency_kit_html(
            "alice<script>alert(1)</script>&\"'",
            42,
            "0123-4567-<img src=x>",
            "mprk1_000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FPD00",
            "2026-11-23",
        );
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;&quot;&#39;"));
        assert!(html.contains("0123-4567-&lt;img src=x&gt;"));
        assert!(html.contains("42"));
        assert!(html.contains("2026-11-23"));
        assert!(html.contains("mp-outpost login"));
    }

    #[test]
    fn qr_v1_l_renders_valid_dimensions_and_finder_patterns() {
        assert_eq!(qr_format_bits_l_mask0(), 0x77C4);

        let m = encode_qr_v1_l_matrix(b"ABCD-EFGH");
        // Verify top-left, top-right, and bottom-left 7x7 finder centers & borders.
        for &(r0, c0) in &[(0usize, 0usize), (0, 14), (14, 0)] {
            assert!(m.is_dark(r0, c0));
            assert!(m.is_dark(r0 + 3, c0 + 3));
            assert!(!m.is_dark(r0 + 1, c0 + 1));
            assert!(m.is_dark(r0 + 6, c0 + 6));
        }
        // Dark module at (13, 8)
        assert!(m.is_dark(13, 8));

        let rendered = render_code_ascii_qr("ABCD-EFGH");
        let lines: Vec<&str> = rendered.lines().collect();
        // 21 + 4 quiet = 25 rows -> ceil(25/2) = 13 half-block lines, each 25 chars wide.
        assert_eq!(lines.len(), 13);
        for line in lines {
            assert_eq!(line.chars().count(), 25);
        }
    }

    #[test]
    fn format_utc_date_matches_known_dates() {
        assert_eq!(format_utc_date(0), "1970-01-01");
        assert_eq!(format_utc_date(1_700_000_000), "2023-11-14");
    }
}
