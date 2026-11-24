//! Interactive second-window live party chat (`mp-outpost chat`).
//!
//! Designed so a user can run Claude Code / Codex / Cursor / OpenCode in Window 1
//! (wired to `mp-outpost mcp`) and live party chat in Window 2 (`mp-outpost chat`),
//! both sharing the exact same local `mp-outpost` daemon & live `mp2` party.
//!
//! Safety & UX invariants:
//! - ZERO new external dependencies (uses only `tokio`, `libc`, `base64`, `serde_json`, etc.).
//! - Sacred Native Text Selection: NEVER emits SGR mouse reporting (`?1000h`, `?1002h`, `?1006h`).
//! - Strict terminal sanitization: strips ALL ANSI/ESC/CSI/OSC/DCS sequences, C0/C1 controls,
//!   and Unicode BiDi overrides/isolates/zero-width/tag chars from every peer-supplied string.
//! - Secret refusal: refuses outbound chat or `/board` payloads containing secrets/tokens/PEM keys.
//! - RAII `TerminalGuard`: unconditionally restores original `termios`, resets scroll region,
//!   shows cursor, resets SGR, and exits onto a clean line.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Write as _};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use outpost_control::sanitize_server_error;
use outpost_core::fence::{
    contains_device_link_token, contains_recovery_file, contains_recovery_key,
    scan_outbound_secrets,
};
use outpost_core::ipc_wire::IpcOpcode;
use outpost_core::party_state::DEFAULT_POLL_MAX_BYTES;
use outpost_daemon::DaemonClient;
use serde_json::Value;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::cli::{
    GlobalOpts, connect_daemon_cli, contains_private_pem_header_local, format_member_display,
    next_val, parse_safe_id, random_safe_id, redact_unknown_arg, rpc_add_friend, rpc_friends_live,
    rpc_get_status, rpc_party_list, rpc_party_members, rpc_room_enter, rpc_room_invite,
    rpc_room_leave,
};
use crate::ipc_payloads::{
    ActivePartySummary, IpcPartyEvent, IpcPartyEventKind, MemberInfo, PartyPollIpcReq,
    PartyPollIpcResp, PartyPostBoardReq, PartySendChatReq, PartyWaitIpcReq, RoomEnterIpcReq,
    RoomInviteIpcReq, RoomMemberIpc, decode_party_poll_resp, decode_send_result_resp,
    encode_party_poll_req, encode_party_post_board_req, encode_party_send_chat_req,
    encode_party_wait_req,
};
use crate::storage::{
    load_device_record, resolve_active_device_id, resolve_effective_state_dir,
};

const MAX_INPUT_BYTES: usize = 4096;
const MAX_HISTORY_ITEMS: usize = 128;
const MAX_TRANSCRIPT_LINES: usize = 500;
const MAX_LOCAL_ECHOES: usize = 32;
const LOCAL_ECHO_TTL: Duration = Duration::from_secs(15);
const PARTY_WAIT_TIMEOUT_MS: u32 = 2_000;
const PERIODIC_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const BEL_COOLDOWN: Duration = Duration::from_secs(5);
const STATUS_NOTICE_TTL: Duration = Duration::from_secs(4);
const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 24;

// ---------------------------------------------------------------------------
// CLI Argument Parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChatArgs {
    pub target: Option<String>,
    pub party_id: Option<u64>,
    pub no_tty: bool,
    pub show_help: bool,
}

pub fn parse_chat_args(args: &[String]) -> Result<ChatArgs, String> {
    let mut parsed = ChatArgs::default();
    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "-h" | "--help" => {
                parsed.show_help = true;
                i += 1;
            }
            "--no-tty" => {
                parsed.no_tty = true;
                i += 1;
            }
            "--party" => {
                let val = next_val(args, &mut i, "--party")?;
                parsed.party_id = Some(parse_safe_id(val, "--party")?);
            }
            other if !other.starts_with('-') && parsed.target.is_none() => {
                let trimmed = other.trim();
                if !trimmed.is_empty() {
                    parsed.target = Some(trimmed.to_string());
                }
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown argument to `chat`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }
    Ok(parsed)
}

fn print_chat_usage() {
    println!(
        "Usage: mp-outpost chat [target] [--party <id>] [--no-tty]\n\n\
Interactive second-window live party chat sharing your local mp-outpost daemon.\n\n\
Arguments:\n\
  [target]          Optional @handle, 4-char code, or clank.party/mp.gg/multiplayer.tech URL to join first\n\
  --party <id>      Attach to a specific active party ID\n\
  --no-tty          Line-oriented mode for pipes, dumb terminals, and scripts\n\n\
In-chat commands:\n\
  /board <text>             Post to shared party board\n\
  /invite [@handle]         Create room or invite a friend (prints share link)\n\
  /join [@handle|CODE|url]  Join or switch party live\n\
  /leave                    Leave active party (return to lobby)\n\
  /friends                  Show live friends & joinable rooms\n\
  /add @handle              Add friend or accept incoming request\n\
  /members                  Show squad roster\n\
  /copy                     Copy share link via OSC 52\n\
  /mute                     Toggle terminal bell notifications\n\
  /help                     Show command guide\n\
  /quit | /exit             Exit chat"
    );
}

// ---------------------------------------------------------------------------
// Strict Terminal Sanitization (ANSI/ESC/CSI/OSC/DCS/C0/C1/BiDi)
// ---------------------------------------------------------------------------

/// Strips ALL ANSI/ESC/CSI/OSC/DCS/SOS/PM/APC sequences, C0/C1 controls, DEL,
/// Unicode BiDi overrides/isolates, line/paragraph separators, zero-width chars,
/// and Unicode Tag characters from untrusted peer text.
///
/// When `allow_newlines` is true, `\n` is preserved (and `\r\n` normalized to `\n`,
/// `\t` expanded to a single space). When false, `\n`/`\r`/`\t` become spaces.
pub fn sanitize_terminal_text(input: &str, allow_newlines: bool) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        let cp = ch as u32;

        // 7-bit ESC sequences (`\x1b ...`)
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    // CSI: ESC [ params (0x30..=0x3F) intermediates (0x20..=0x2F) final (0x40..=0x7E)
                    let _ = chars.next();
                    consume_csi(&mut chars);
                }
                Some(']') => {
                    // OSC: ESC ] ... (BEL | ST)
                    let _ = chars.next();
                    consume_string_term(&mut chars);
                }
                Some('P' | 'X' | '^' | '_') => {
                    // DCS / SOS / PM / APC: ESC <type> ... ST
                    let _ = chars.next();
                    consume_string_term(&mut chars);
                }
                Some(next) if (0x20..=0x2F).contains(&(next as u32)) => {
                    // nF escape sequence: intermediate bytes 0x20..=0x2F then final 0x30..=0x7E
                    while let Some(c) = chars.peek().copied() {
                        let ccp = c as u32;
                        if (0x20..=0x2F).contains(&ccp) {
                            let _ = chars.next();
                        } else {
                            if (0x30..=0x7E).contains(&ccp) {
                                let _ = chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(next) if (0x30..=0x7E).contains(&(next as u32)) => {
                    // 2-byte ESC sequence (e.g. ESC c, ESC 7, ESC 8, ESC M, ESC =)
                    let _ = chars.next();
                }
                _ => {}
            }
            continue;
        }

        // 8-bit C1 CSI (`U+009B`)
        if cp == 0x9B {
            consume_csi(&mut chars);
            continue;
        }

        // 8-bit C1 OSC / DCS / SOS / PM / APC (`U+009D`, `0x90`, `0x98`, `0x9E`, `0x9F`)
        if matches!(cp, 0x90 | 0x98 | 0x9D | 0x9E | 0x9F) {
            consume_string_term(&mut chars);
            continue;
        }

        // Handle whitespace controls
        if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                let _ = chars.next();
            }
            if allow_newlines {
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if ch == '\n' {
            if allow_newlines {
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if ch == '\t' {
            out.push(' ');
            continue;
        }

        // Drop remaining C0, DEL, C1
        if cp <= 0x1F || cp == 0x7F || (0x80..=0x9F).contains(&cp) {
            continue;
        }

        // Drop Unicode line/paragraph separators, BiDi overrides/isolates/marks,
        // zero-width characters, BOM, and Unicode Tag characters
        if matches!(
            ch,
            '\u{2028}'
                | '\u{2029}'
                | '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200B}'..='\u{200D}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
        ) {
            continue;
        }

        out.push(ch);
    }

    out
}

/// Single-line sanitized field (handles, room codes, party names, client names, agent names).
pub fn sanitize_terminal_inline(input: &str) -> String {
    sanitize_terminal_text(input, false).trim().to_string()
}

fn consume_csi(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.peek().copied() {
        let cp = c as u32;
        if (0x30..=0x3F).contains(&cp) || (0x20..=0x2F).contains(&cp) {
            let _ = chars.next();
        } else if (0x40..=0x7E).contains(&cp) {
            let _ = chars.next();
            break;
        } else {
            break;
        }
    }
}

fn consume_string_term(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next() {
        if c == '\x07' || c == '\u{009C}' {
            break;
        }
        if c == '\x1b' && chars.peek() == Some(&'\\') {
            let _ = chars.next();
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound Secret Refusal
// ---------------------------------------------------------------------------

struct LocalSecretMaterial {
    device_secret: Zeroizing<[u8; 32]>,
    device_cwt: Zeroizing<Vec<u8>>,
}

/// Client-side secret refusal check run BEFORE sending any chat message or `/board` post.
/// Refuses `mprk1_`, `mpinv1_`, `mppi1_`, `mpdl1_`, `mpcs1_`, `mpguest1_`, PEM private keys,
/// checksum-verified recovery keys, `.mpkey` recovery files, and (when device state is loaded)
/// the local device's own `device_secret` and `device_cwt`.
///
/// NEVER echoes any part of the offending secret in the error message.
pub fn check_chat_secret_refusal(
    text: &str,
    local_secrets: Option<(&[u8; 32], &[u8])>,
) -> Result<(), &'static str> {
    const FORBIDDEN_PREFIXES: [&str; 6] = [
        "mprk1_",
        "mpinv1_",
        "mppi1_",
        "mpdl1_",
        "mpcs1_",
        "mpguest1_",
    ];

    let lower = text.to_ascii_lowercase();
    for prefix in FORBIDDEN_PREFIXES {
        if lower.contains(prefix) {
            return Err(
                "refused to send: message contains a protected credential/token prefix (secret-disclosure guard)",
            );
        }
    }

    let bytes = text.as_bytes();
    if contains_recovery_key(bytes)
        || contains_device_link_token(bytes)
        || contains_recovery_file(bytes)
        || contains_private_pem_header_local(bytes)
    {
        return Err(
            "refused to send: message contains a private key or recovery secret (secret-disclosure guard)",
        );
    }

    if let Some((dev_secret, dev_cwt)) = local_secrets
        && scan_outbound_secrets(bytes, dev_secret, dev_cwt).is_some()
    {
        return Err(
            "refused to send: message contains local device secret or credential (secret-disclosure guard)",
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Slash Command Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashCommand {
    Board(String),
    Invite(Option<String>),
    Join(String),
    Leave,
    Friends,
    Add(String),
    Members,
    Copy,
    Mute,
    Help,
    Quit,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserInputAction {
    Empty,
    Chat(String),
    Command(SlashCommand),
}

pub fn parse_user_input(raw: &str) -> UserInputAction {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return UserInputAction::Empty;
    }
    if !trimmed.starts_with('/') {
        return UserInputAction::Chat(trimmed.to_string());
    }

    let after_slash = trimmed.strip_prefix('/').unwrap_or_default();
    let (cmd_raw, rest_raw) = match after_slash.split_once(char::is_whitespace) {
        Some((c, r)) => (c, r.trim()),
        None => (after_slash, ""),
    };
    let cmd = cmd_raw.to_ascii_lowercase();
    match cmd.as_str() {
        "board" => UserInputAction::Command(SlashCommand::Board(rest_raw.to_string())),
        "invite" => {
            let target = rest_raw
                .split_whitespace()
                .next()
                .map(|s| s.trim_start_matches('@').to_string())
                .filter(|s| !s.is_empty());
            UserInputAction::Command(SlashCommand::Invite(target))
        }
        "join" => UserInputAction::Command(SlashCommand::Join(rest_raw.to_string())),
        "leave" => UserInputAction::Command(SlashCommand::Leave),
        "friends" => UserInputAction::Command(SlashCommand::Friends),
        "add" => UserInputAction::Command(SlashCommand::Add(rest_raw.to_string())),
        "members" | "who" => UserInputAction::Command(SlashCommand::Members),
        "copy" => UserInputAction::Command(SlashCommand::Copy),
        "mute" => UserInputAction::Command(SlashCommand::Mute),
        "help" | "?" => UserInputAction::Command(SlashCommand::Help),
        "quit" | "exit" | "q" => UserInputAction::Command(SlashCommand::Quit),
        other => UserInputAction::Command(SlashCommand::Unknown(format!("/{other}"))),
    }
}

// ---------------------------------------------------------------------------
// UTF-8-Safe Single-Line Editor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LineEditor {
    buf: String,
    cursor_byte: usize,
    history: VecDeque<String>,
    history_pos: Option<usize>,
    draft: String,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    pub fn new() -> Self {
        Self {
            buf: String::new(),
            cursor_byte: 0,
            history: VecDeque::new(),
            history_pos: None,
            draft: String::new(),
        }
    }

    #[cfg(test)]
    pub fn text(&self) -> &str {
        &self.buf
    }

    #[cfg(test)]
    pub fn cursor_byte(&self) -> usize {
        self.cursor_byte
    }

    fn clamp_cursor(&mut self) {
        let mut pos = self.cursor_byte.min(self.buf.len());
        while pos > 0 && !self.buf.is_char_boundary(pos) {
            pos -= 1;
        }
        self.cursor_byte = pos;
    }

    pub fn insert_char(&mut self, ch: char) {
        if ch.is_control() {
            return;
        }
        if self.buf.len().saturating_add(ch.len_utf8()) > MAX_INPUT_BYTES {
            return;
        }
        self.clamp_cursor();
        self.buf.insert(self.cursor_byte, ch);
        self.cursor_byte += ch.len_utf8();
        self.history_pos = None;
    }

    pub fn backspace(&mut self) -> bool {
        self.clamp_cursor();
        if self.cursor_byte == 0 {
            return false;
        }
        let Some(prefix) = self.buf.get(..self.cursor_byte) else {
            return false;
        };
        let Some((prev_idx, _)) = prefix.char_indices().next_back() else {
            return false;
        };
        self.buf.drain(prev_idx..self.cursor_byte);
        self.cursor_byte = prev_idx;
        self.history_pos = None;
        true
    }

    pub fn delete_forward(&mut self) -> bool {
        self.clamp_cursor();
        if self.cursor_byte >= self.buf.len() {
            return false;
        }
        let Some(suffix) = self.buf.get(self.cursor_byte..) else {
            return false;
        };
        let Some(ch) = suffix.chars().next() else {
            return false;
        };
        let end = self.cursor_byte.saturating_add(ch.len_utf8());
        if end <= self.buf.len() {
            self.buf.drain(self.cursor_byte..end);
            self.history_pos = None;
            return true;
        }
        false
    }

    pub fn move_left(&mut self) -> bool {
        self.clamp_cursor();
        if self.cursor_byte == 0 {
            return false;
        }
        if let Some(prefix) = self.buf.get(..self.cursor_byte)
            && let Some((prev_idx, _)) = prefix.char_indices().next_back()
        {
            self.cursor_byte = prev_idx;
            return true;
        }
        false
    }

    pub fn move_right(&mut self) -> bool {
        self.clamp_cursor();
        if self.cursor_byte >= self.buf.len() {
            return false;
        }
        if let Some(suffix) = self.buf.get(self.cursor_byte..)
            && let Some(ch) = suffix.chars().next()
        {
            self.cursor_byte = self.cursor_byte.saturating_add(ch.len_utf8());
            return true;
        }
        false
    }

    pub fn move_home(&mut self) {
        self.cursor_byte = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor_byte = self.buf.len();
    }

    pub fn clear_line(&mut self) {
        self.buf.clear();
        self.cursor_byte = 0;
        self.history_pos = None;
    }

    pub fn delete_word_back(&mut self) -> bool {
        self.clamp_cursor();
        if self.cursor_byte == 0 {
            return false;
        }
        let Some(prefix) = self.buf.get(..self.cursor_byte) else {
            return false;
        };
        let mut cut = self.cursor_byte;
        let mut saw_non_ws = false;
        for (idx, ch) in prefix.char_indices().rev() {
            if ch.is_whitespace() {
                if saw_non_ws {
                    break;
                }
                cut = idx;
            } else {
                saw_non_ws = true;
                cut = idx;
            }
        }
        if cut < self.cursor_byte {
            self.buf.drain(cut..self.cursor_byte);
            self.cursor_byte = cut;
            self.history_pos = None;
            return true;
        }
        false
    }

    pub fn history_up(&mut self) -> bool {
        if self.history.is_empty() {
            return false;
        }
        let new_pos = match self.history_pos {
            None => {
                self.draft = self.buf.clone();
                self.history.len().saturating_sub(1)
            }
            Some(0) => return false,
            Some(p) => p.saturating_sub(1),
        };
        if let Some(entry) = self.history.get(new_pos) {
            self.buf = entry.clone();
            self.cursor_byte = self.buf.len();
            self.history_pos = Some(new_pos);
            return true;
        }
        false
    }

    pub fn history_down(&mut self) -> bool {
        let Some(pos) = self.history_pos else {
            return false;
        };
        let next = pos.saturating_add(1);
        if next >= self.history.len() {
            self.buf = std::mem::take(&mut self.draft);
            self.cursor_byte = self.buf.len();
            self.history_pos = None;
            return true;
        }
        if let Some(entry) = self.history.get(next) {
            self.buf = entry.clone();
            self.cursor_byte = self.buf.len();
            self.history_pos = Some(next);
            return true;
        }
        false
    }

    pub fn submit(&mut self) -> String {
        let line = std::mem::take(&mut self.buf);
        self.cursor_byte = 0;
        self.history_pos = None;
        self.draft.clear();

        let trimmed = line.trim();
        if !trimmed.is_empty() && self.history.back().map(String::as_str) != Some(trimmed) {
            while self.history.len() >= MAX_HISTORY_ITEMS {
                let _ = self.history.pop_front();
            }
            self.history.push_back(trimmed.to_string());
        }
        line
    }

    /// Returns `(visible_text, cursor_display_col)` sliced safely on char boundaries
    /// so the composer fits cleanly within `max_cols` terminal columns.
    pub fn visible_slice(&self, max_cols: usize) -> (String, usize) {
        if max_cols == 0 {
            return (String::new(), 0);
        }
        let chars: Vec<(usize, char, usize)> = self
            .buf
            .char_indices()
            .map(|(byte_idx, ch)| (byte_idx, ch, char_display_width(ch)))
            .collect();

        let mut cursor_char_idx = chars.len();
        for (i, &(byte_idx, _, _)) in chars.iter().enumerate() {
            if byte_idx >= self.cursor_byte {
                cursor_char_idx = i;
                break;
            }
        }

        // Compute prefix widths up to each char index.
        let mut prefix_cols: Vec<usize> = Vec::with_capacity(chars.len() + 1);
        prefix_cols.push(0);
        let mut acc = 0usize;
        for &(_, _, w) in &chars {
            acc = acc.saturating_add(w);
            prefix_cols.push(acc);
        }

        let cursor_total_col = prefix_cols.get(cursor_char_idx).copied().unwrap_or(0);
        let window_start_col = if cursor_total_col >= max_cols {
            cursor_total_col.saturating_sub(max_cols.saturating_sub(1))
        } else {
            0
        };

        let mut start_idx = 0usize;
        while start_idx < chars.len()
            && prefix_cols.get(start_idx).copied().unwrap_or(0) < window_start_col
        {
            start_idx += 1;
        }

        let start_col = prefix_cols.get(start_idx).copied().unwrap_or(0);
        let mut out = String::new();
        let mut used = 0usize;
        for &(_, ch, w) in chars.get(start_idx..).unwrap_or_default() {
            if used.saturating_add(w) > max_cols {
                break;
            }
            out.push(ch);
            used = used.saturating_add(w);
        }

        let cursor_col = cursor_total_col
            .saturating_sub(start_col)
            .min(max_cols.saturating_sub(1));
        (out, cursor_col)
    }
}

/// Conservative terminal column width estimate without external `unicode-width` crate.
/// Handles ASCII (1), CJK/Fullwidth/Emoji blocks (2), and combining marks (0).
fn char_display_width(ch: char) -> usize {
    let cp = ch as u32;
    if cp < 0x20 || cp == 0x7F {
        return 0;
    }
    // Combining diacritical marks
    if (0x0300..=0x036F).contains(&cp)
        || (0x1AB0..=0x1AFF).contains(&cp)
        || (0x1DC0..=0x1DFF).contains(&cp)
        || (0x20D0..=0x20FF).contains(&cp)
        || (0xFE00..=0xFE0F).contains(&cp)
        || (0xFE20..=0xFE2F).contains(&cp)
    {
        return 0;
    }
    // Wide East Asian / CJK / Fullwidth / Emoji ranges
    if (0x1100..=0x115F).contains(&cp)
        || (0x2E80..=0x303E).contains(&cp)
        || (0x3040..=0x33FF).contains(&cp)
        || (0x3400..=0x4DBF).contains(&cp)
        || (0x4E00..=0xA4CF).contains(&cp)
        || (0xAC00..=0xD7A3).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0xFE10..=0xFE19).contains(&cp)
        || (0xFE30..=0xFE6F).contains(&cp)
        || (0xFF00..=0xFF60).contains(&cp)
        || (0xFFE0..=0xFFE6).contains(&cp)
        || (0x1F300..=0x1FAFF).contains(&cp)
        || (0x20000..=0x3FFFD).contains(&cp)
    {
        return 2;
    }
    1
}

fn truncate_to_cols(s: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(s.len().min(max_cols.saturating_mul(4)));
    let mut cols = 0usize;
    for ch in s.chars() {
        let w = char_display_width(ch);
        if cols.saturating_add(w) > max_cols {
            break;
        }
        out.push(ch);
        cols = cols.saturating_add(w);
    }
    out
}

fn wrap_to_cols(s: &str, max_cols: usize) -> Vec<String> {
    let width = max_cols.max(1);
    let mut lines = Vec::new();
    for raw_line in s.split('\n') {
        if raw_line.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut cur = String::new();
        let mut cur_cols = 0usize;
        for ch in raw_line.chars() {
            let w = char_display_width(ch);
            if cur_cols > 0 && cur_cols.saturating_add(w) > width {
                lines.push(std::mem::take(&mut cur));
                cur_cols = 0;
            }
            cur.push(ch);
            cur_cols = cur_cols.saturating_add(w);
        }
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Validates a shareable URL before displaying or emitting in an OSC 52 clipboard escape.
/// Requires `https://`, non-empty host/path, no whitespace, strict printable ASCII, and `<= 256` bytes.
pub fn validate_share_url(raw: &str) -> Option<String> {
    let cleaned = sanitize_terminal_inline(raw);
    if !cleaned.starts_with("https://")
        || cleaned.len() <= "https://".len()
        || cleaned.len() > 256
        || cleaned.chars().any(char::is_whitespace)
        || !cleaned.bytes().all(|b| (0x21..=0x7E).contains(&b))
    {
        return None;
    }
    Some(cleaned)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalLayout {
    cols: usize,
    rows: u16,
    header_row: Option<u16>,
    squad_row: Option<u16>,
    transcript_bounds: Option<(u16, u16)>,
    divider_row: Option<u16>,
    composer_row: u16,
}

impl TerminalLayout {
    fn compute(cols: u16, rows: u16) -> Self {
        let cols = usize::from(cols.max(1));
        let rows = rows.max(1);
        match rows {
            1 => Self {
                cols,
                rows,
                header_row: None,
                squad_row: None,
                transcript_bounds: None,
                divider_row: None,
                composer_row: 1,
            },
            2 => Self {
                cols,
                rows,
                header_row: Some(1),
                squad_row: None,
                transcript_bounds: None,
                divider_row: None,
                composer_row: 2,
            },
            3 => Self {
                cols,
                rows,
                header_row: Some(1),
                squad_row: None,
                transcript_bounds: Some((2, 2)),
                divider_row: None,
                composer_row: 3,
            },
            4 => Self {
                cols,
                rows,
                header_row: Some(1),
                squad_row: None,
                transcript_bounds: Some((2, 2)),
                divider_row: Some(3),
                composer_row: 4,
            },
            5 => Self {
                cols,
                rows,
                header_row: Some(1),
                squad_row: Some(2),
                transcript_bounds: Some((3, 3)),
                divider_row: Some(4),
                composer_row: 5,
            },
            _ => Self {
                cols,
                rows,
                header_row: Some(1),
                squad_row: Some(2),
                transcript_bounds: Some((3, rows.saturating_sub(2))),
                divider_row: Some(rows.saturating_sub(1)),
                composer_row: rows,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Local Echo + Sequence Deduplication & Cursor Tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoKind {
    Chat,
    Board,
}

#[derive(Debug, Clone)]
struct PendingEcho {
    id: u64,
    kind: EchoKind,
    body: String,
    sent_at: Instant,
}

#[derive(Debug, Default)]
pub struct MessageDedupState {
    party_id: Option<u64>,
    daemon_epoch: u64,
    next_seq: u64,
    next_echo_id: u64,
    seen_seqs: HashSet<u64>,
    seen_order: VecDeque<u64>,
    pending_echoes: VecDeque<PendingEcho>,
}

impl MessageDedupState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset_for_party(&mut self, party_id: Option<u64>) {
        self.party_id = party_id;
        self.daemon_epoch = 0;
        self.next_seq = 0;
        self.seen_seqs.clear();
        self.seen_order.clear();
        self.pending_echoes.clear();
    }

    pub fn record_local_echo(&mut self, kind: EchoKind, body: String, now: Instant) -> u64 {
        self.prune_echoes(now);
        while self.pending_echoes.len() >= MAX_LOCAL_ECHOES {
            let _ = self.pending_echoes.pop_front();
        }
        self.next_echo_id = self.next_echo_id.saturating_add(1);
        let id = self.next_echo_id;
        self.pending_echoes.push_back(PendingEcho {
            id,
            kind,
            body,
            sent_at: now,
        });
        id
    }

    /// Rolls back a previously recorded local echo (e.g. when outbound send fails).
    pub fn cancel_local_echo(&mut self, id: u64) {
        if let Some(pos) = self.pending_echoes.iter().position(|e| e.id == id) {
            let _ = self.pending_echoes.remove(pos);
        }
    }

    fn prune_echoes(&mut self, now: Instant) {
        while let Some(front) = self.pending_echoes.front() {
            if now.saturating_duration_since(front.sent_at) > LOCAL_ECHO_TTL {
                let _ = self.pending_echoes.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns `true` if this event matches a recently sent local echo and consumes it.
    pub fn consume_matching_echo(&mut self, kind: EchoKind, body: &str, now: Instant) -> bool {
        self.prune_echoes(now);
        if let Some(pos) = self
            .pending_echoes
            .iter()
            .position(|e| e.kind == kind && e.body == body)
        {
            let _ = self.pending_echoes.remove(pos);
            return true;
        }
        false
    }

    /// Advances the cursor from a `PartyPollIpcResp` and returns only unseen events.
    pub fn filter_and_advance(&mut self, resp: PartyPollIpcResp) -> Vec<IpcPartyEvent> {
        if self.party_id != Some(resp.party_id) {
            return Vec::new();
        }
        if resp.cursor_reset || (self.daemon_epoch != 0 && self.daemon_epoch != resp.daemon_epoch) {
            self.seen_seqs.clear();
            self.seen_order.clear();
            self.next_seq = 0;
        }
        if resp.daemon_epoch != 0 {
            self.daemon_epoch = resp.daemon_epoch;
        }
        if resp.next_seq > self.next_seq {
            self.next_seq = resp.next_seq;
        }

        let mut fresh = Vec::with_capacity(resp.events.len());
        for ev in resp.events {
            if ev.event_seq > self.next_seq {
                self.next_seq = ev.event_seq;
            }
            if self.seen_seqs.insert(ev.event_seq) {
                self.seen_order.push_back(ev.event_seq);
                while self.seen_order.len() > 2048 {
                    if let Some(old) = self.seen_order.pop_front() {
                        self.seen_seqs.remove(&old);
                    }
                }
                fresh.push(ev);
            }
        }
        fresh
    }

    pub fn cursor(&self) -> (u64, u64) {
        (self.daemon_epoch, self.next_seq)
    }
}

// ---------------------------------------------------------------------------
// Timestamp & Message Formatting
// ---------------------------------------------------------------------------

fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn format_hhmm_from_unix_secs(unix_secs: i64) -> String {
    let t = unix_secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if ok {
        format!(
            "{:02}:{:02}",
            tm.tm_hour.clamp(0, 23),
            tm.tm_min.clamp(0, 59)
        )
    } else {
        let secs_in_day = unix_secs.rem_euclid(86_400);
        format!("{:02}:{:02}", secs_in_day / 3600, (secs_in_day % 3600) / 60)
    }
}

fn format_hhmm_now() -> String {
    format_hhmm_from_unix_secs(current_unix_secs())
}

fn format_hhmm_from_ns(timestamp_ns: i64) -> String {
    if timestamp_ns <= 0 {
        return format_hhmm_now();
    }
    let secs = timestamp_ns / 1_000_000_000;
    if secs <= 0 {
        return format_hhmm_now();
    }
    format_hhmm_from_unix_secs(secs)
}

/// Formats a `BridgeEnvelope` (board / agent card) payload safely for terminal display.
pub fn format_board_payload(payload: &[u8]) -> String {
    match core::str::from_utf8(payload) {
        Ok(text) => {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text.trim()) {
                let title = map.get("title").and_then(Value::as_str);
                let summary = map.get("summary").and_then(Value::as_str);
                match (title, summary) {
                    (Some(t), Some(s)) if !t.is_empty() && !s.is_empty() => {
                        return format!(
                            "{} — {}",
                            sanitize_terminal_inline(t),
                            sanitize_terminal_text(s, false).trim()
                        );
                    }
                    (Some(t), _) if !t.is_empty() => return sanitize_terminal_inline(t),
                    (_, Some(s)) if !s.is_empty() => {
                        return sanitize_terminal_text(s, false).trim().to_string();
                    }
                    _ => {}
                }
            }
            sanitize_terminal_text(text, true).trim().to_string()
        }
        Err(_) => format!("<{} bytes binary>", payload.len()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineStyle {
    RemoteChat,
    SelfChat,
    AgentChat,
    Board,
    System,
    Error,
}

#[derive(Debug, Clone)]
struct TranscriptEntry {
    text: String,
    style: LineStyle,
}

// ---------------------------------------------------------------------------
// RAII Terminal Guard & Raw Keyboard Reader (TTY Mode ONLY — NO SGR Mouse!)
// ---------------------------------------------------------------------------

struct TerminalGuard {
    fd: RawFd,
    saved: libc::termios,
    rows: u16,
}

impl TerminalGuard {
    fn enter_raw(fd: RawFd, rows: u16) -> Result<Self, String> {
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return Err(format!("tcgetattr failed: {}", io::Error::last_os_error()));
        }

        let mut raw = orig;
        // Disable canonical mode, echo, extended input processing, Ctrl-C/Z signals (handled as keys),
        // software flow control, and CR-to-NL translation. Keep OPOST so `\r\n` behaves normally.
        raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::IEXTEN | libc::ISIG);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(format!("tcsetattr failed: {}", io::Error::last_os_error()));
        }

        Ok(Self {
            fd,
            saved: orig,
            rows,
        })
    }

    fn set_rows(&mut self, rows: u16) {
        self.rows = rows;
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
        }
        let mut out = io::stdout();
        // Reset scroll region, reset SGR, show cursor, move to bottom row, and emit a clean newline.
        let _ = write!(out, "\x1b[r\x1b[0m\x1b[?25h\x1b[{};1H\r\n", self.rows.max(1));
        let _ = out.flush();
    }
}

fn is_interactive_tty(no_tty: bool) -> bool {
    if no_tty {
        return false;
    }
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

fn query_terminal_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        (ws.ws_col, ws.ws_row)
    } else {
        (DEFAULT_COLS, DEFAULT_ROWS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyEvent {
    Char(char),
    Enter,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    CtrlU,
    CtrlW,
    CtrlC,
    CtrlD,
    Eof,
}

fn read_byte_with_timeout(fd: RawFd, timeout_ms: i32) -> io::Result<Option<u8>> {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Ok(None);
        }
        let mut byte = [0u8; 1];
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stdin EOF"));
        }
        return Ok(byte.first().copied());
    }
}

fn spawn_tty_key_reader(
    stop: Arc<AtomicBool>,
) -> (mpsc::UnboundedReceiver<KeyEvent>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = std::thread::spawn(move || {
        let fd = libc::STDIN_FILENO;
        while !stop.load(Ordering::Acquire) {
            let b = match read_byte_with_timeout(fd, 100) {
                Ok(Some(byte)) => byte,
                Ok(None) => continue,
                Err(_) => {
                    let _ = tx.send(KeyEvent::Eof);
                    break;
                }
            };

            let ev = match b {
                0x03 => KeyEvent::CtrlC,
                0x04 => KeyEvent::CtrlD,
                0x01 => KeyEvent::Home,
                0x05 => KeyEvent::End,
                0x15 => KeyEvent::CtrlU,
                0x17 => KeyEvent::CtrlW,
                0x0D | 0x0A => KeyEvent::Enter,
                0x7F | 0x08 => KeyEvent::Backspace,
                0x1B => match parse_escape_key(fd) {
                    Some(k) => k,
                    None => continue,
                },
                0x20..=0x7E => KeyEvent::Char(b as char),
                lead if lead >= 0xC2 => {
                    let needed = utf8_char_len(lead);
                    let mut buf = [0u8; 4];
                    if let Some(slot) = buf.first_mut() {
                        *slot = lead;
                    }
                    let mut valid = (2..=4).contains(&needed);
                    for i in 1..needed {
                        match read_byte_with_timeout(fd, 30) {
                            Ok(Some(cont)) if (cont & 0xC0) == 0x80 => {
                                if let Some(slot) = buf.get_mut(i) {
                                    *slot = cont;
                                }
                            }
                            _ => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if valid
                        && let Some(slice) = buf.get(..needed)
                        && let Ok(s) = core::str::from_utf8(slice)
                        && let Some(ch) = s.chars().next()
                    {
                        KeyEvent::Char(ch)
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            if tx.send(ev).is_err() {
                break;
            }
        }
    });
    (rx, handle)
}

const fn utf8_char_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead < 0xE0 {
        2
    } else if lead < 0xF0 {
        3
    } else if lead < 0xF8 {
        4
    } else {
        0
    }
}

fn parse_escape_key(fd: RawFd) -> Option<KeyEvent> {
    let b1 = read_byte_with_timeout(fd, 25).ok()??;
    match b1 {
        b'[' => {
            let b2 = read_byte_with_timeout(fd, 25).ok()??;
            match b2 {
                b'A' => Some(KeyEvent::Up),
                b'B' => Some(KeyEvent::Down),
                b'C' => Some(KeyEvent::Right),
                b'D' => Some(KeyEvent::Left),
                b'H' => Some(KeyEvent::Home),
                b'F' => Some(KeyEvent::End),
                b'1' | b'3' | b'4' | b'7' | b'8' => {
                    // Consume until `~` or final CSI byte (0x40..=0x7E)
                    let mut final_byte = b'~';
                    while let Ok(Some(next)) = read_byte_with_timeout(fd, 25) {
                        if (0x40..=0x7E).contains(&next) {
                            final_byte = next;
                            break;
                        }
                    }
                    if final_byte == b'~' {
                        match b2 {
                            b'1' | b'7' => Some(KeyEvent::Home),
                            b'3' => Some(KeyEvent::Delete),
                            b'4' | b'8' => Some(KeyEvent::End),
                            _ => None,
                        }
                    } else {
                        None
                    }
                }
                _ => {
                    // Drain any remaining CSI bytes so garbage doesn't leak into composer.
                    if !(0x40..=0x7E).contains(&b2) {
                        while let Ok(Some(next)) = read_byte_with_timeout(fd, 20) {
                            if (0x40..=0x7E).contains(&next) {
                                break;
                            }
                        }
                    }
                    None
                }
            }
        }
        b'O' => {
            let b2 = read_byte_with_timeout(fd, 25).ok()??;
            match b2 {
                b'H' => Some(KeyEvent::Home),
                b'F' => Some(KeyEvent::End),
                b'A' => Some(KeyEvent::Up),
                b'B' => Some(KeyEvent::Down),
                b'C' => Some(KeyEvent::Right),
                b'D' => Some(KeyEvent::Left),
                _ => None,
            }
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StdinLineEvent {
    Line(String),
    TooLong,
    Eof,
}

/// Non-TTY poll-driven bounded line reader thread that exits promptly on `stop` even if the
/// parent keeps stdin open, and caps buffered line memory at `MAX_INPUT_BYTES`.
fn spawn_non_tty_line_reader(
    stop: Arc<AtomicBool>,
) -> (
    mpsc::UnboundedReceiver<StdinLineEvent>,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = std::thread::spawn(move || {
        let fd = libc::STDIN_FILENO;
        let mut line_buf: Vec<u8> = Vec::with_capacity(256);
        let mut discarding = false;
        let mut chunk = [0u8; 512];

        while !stop.load(Ordering::Acquire) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, 100) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = tx.send(StdinLineEvent::Eof);
                return;
            }
            if rc == 0 {
                continue;
            }

            let n = unsafe {
                libc::read(
                    fd,
                    chunk.as_mut_ptr().cast::<libc::c_void>(),
                    chunk.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = tx.send(StdinLineEvent::Eof);
                return;
            }
            if n == 0 {
                if discarding {
                    let _ = tx.send(StdinLineEvent::TooLong);
                } else if !line_buf.is_empty() {
                    if line_buf.last() == Some(&b'\r') {
                        let _ = line_buf.pop();
                    }
                    let text = String::from_utf8_lossy(&line_buf).into_owned();
                    let _ = tx.send(StdinLineEvent::Line(text));
                }
                let _ = tx.send(StdinLineEvent::Eof);
                return;
            }

            let read_len = usize::try_from(n).unwrap_or(0).min(chunk.len());
            for &b in chunk.get(..read_len).unwrap_or_default() {
                if b == b'\n' {
                    if discarding {
                        discarding = false;
                        if tx.send(StdinLineEvent::TooLong).is_err() {
                            return;
                        }
                    } else {
                        if line_buf.last() == Some(&b'\r') {
                            let _ = line_buf.pop();
                        }
                        let text = String::from_utf8_lossy(&line_buf).into_owned();
                        line_buf.clear();
                        if tx.send(StdinLineEvent::Line(text)).is_err() {
                            return;
                        }
                    }
                } else if !discarding {
                    if line_buf.len() >= MAX_INPUT_BYTES {
                        line_buf.clear();
                        discarding = true;
                    } else {
                        line_buf.push(b);
                    }
                }
            }
        }
    });
    (rx, handle)
}

// ---------------------------------------------------------------------------
// Background Daemon Poller (`PartyWait` with 2s timeout)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PollerTarget {
    party_id: u64,
    cursor_epoch: u64,
    after_seq: u64,
    generation: u64,
}

#[derive(Debug)]
enum PollerEvent {
    Batch(PartyPollIpcResp),
    PartyDetached(u64),
    ConnectionState(bool),
}

fn spawn_daemon_poller(
    opts: GlobalOpts,
    mut target_rx: watch::Receiver<Option<PollerTarget>>,
) -> mpsc::UnboundedReceiver<PollerEvent> {
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut client: Option<DaemonClient> = None;
        let mut cur_party: Option<u64> = None;
        let mut cur_gen: u64 = 0;
        let mut cursor_epoch: u64 = 0;
        let mut after_seq: u64 = 0;
        let mut backoff_ms: u64 = 250;

        loop {
            let desired = *target_rx.borrow();
            let Some(target) = desired else {
                cur_party = None;
                if target_rx.changed().await.is_err() {
                    return;
                }
                continue;
            };

            if cur_party != Some(target.party_id) || cur_gen != target.generation {
                cur_party = Some(target.party_id);
                cur_gen = target.generation;
                cursor_epoch = target.cursor_epoch;
                after_seq = target.after_seq;
            }

            if client.is_none() {
                match connect_daemon_cli(&opts, true, false).await {
                    Ok((c, _)) => {
                        client = Some(c);
                        backoff_ms = 250;
                        let _ = ev_tx.send(PollerEvent::ConnectionState(true));
                    }
                    Err(_) => {
                        let _ = ev_tx.send(PollerEvent::ConnectionState(false));
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                            res = target_rx.changed() => {
                                if res.is_err() {
                                    return;
                                }
                            }
                        }
                        backoff_ms = backoff_ms.saturating_mul(2).min(2_000);
                        continue;
                    }
                }
            }

            let req_bytes = encode_party_wait_req(&PartyWaitIpcReq {
                party_id: target.party_id,
                cursor_epoch,
                after_seq,
                timeout_ms: PARTY_WAIT_TIMEOUT_MS,
            });

            let Some(mut active_client) = client.take() else {
                continue;
            };

            let wait_res = tokio::select! {
                res = active_client.request(IpcOpcode::PartyWait, req_bytes) => Some(res),
                changed = target_rx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    // Target changed mid-wait; drop old socket cleanly to abort in-flight wait.
                    None
                }
            };

            let Some(res) = wait_res else {
                continue;
            };

            match res {
                Ok(raw) => {
                    client = Some(active_client);
                    match decode_party_poll_resp(&raw) {
                        Ok(resp) => {
                            if resp.cursor_reset {
                                cursor_epoch = resp.daemon_epoch;
                                after_seq = resp.next_seq;
                            } else {
                                if resp.daemon_epoch != 0 {
                                    cursor_epoch = resp.daemon_epoch;
                                }
                                if resp.next_seq > after_seq {
                                    after_seq = resp.next_seq;
                                }
                            }
                            if (!resp.events.is_empty() || resp.cursor_reset)
                                && ev_tx.send(PollerEvent::Batch(resp)).is_err()
                            {
                                return;
                            }
                        }
                        Err(_) => {
                            client = None;
                        }
                    }
                }
                Err(err) => {
                    let msg = err.to_string();
                    if msg.contains("no active party")
                        || msg.contains("is not active")
                        || msg.contains("no longer active")
                    {
                        client = Some(active_client);
                        let _ = ev_tx.send(PollerEvent::PartyDetached(target.party_id));
                        if target_rx.changed().await.is_err() {
                            return;
                        }
                    } else {
                        // Daemon disconnected or transient socket error; reconnect with backoff.
                        let _ = ev_tx.send(PollerEvent::ConnectionState(false));
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                            res = target_rx.changed() => {
                                if res.is_err() {
                                    return;
                                }
                            }
                        }
                        backoff_ms = backoff_ms.saturating_mul(2).min(2_000);
                    }
                }
            }
        }
    });
    ev_rx
}

// ---------------------------------------------------------------------------
// Chat Session State & Renderer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SquadMemberView {
    account_id: u64,
    handle: String,
    client_label: Option<String>,
    live: bool,
}

struct ChatApp {
    opts: GlobalOpts,
    cmd_client: DaemonClient,
    local_secrets: Option<LocalSecretMaterial>,
    own_account_id: u64,
    own_device_id: u64,
    own_handle: String,
    connected: bool,
    active_party: Option<ActivePartySummary>,
    members: Vec<SquadMemberView>,
    /// Preserves rich client/agent tags returned by `RoomEnter` keyed by `(account_id, lower_handle)`.
    member_client_hints: HashMap<(u64, String), String>,
    dedup: MessageDedupState,
    transcript: VecDeque<TranscriptEntry>,
    editor: LineEditor,
    tty: bool,
    cols: u16,
    rows: u16,
    muted: bool,
    last_bel_at: Option<Instant>,
    status_notice: Option<(String, Instant)>,
    poller_tx: watch::Sender<Option<PollerTarget>>,
    poller_gen: u64,
    should_quit: bool,
}

impl ChatApp {
    fn local_secret_refs(&self) -> Option<(&[u8; 32], &[u8])> {
        self.local_secrets
            .as_ref()
            .map(|s| (&*s.device_secret, s.device_cwt.as_slice()))
    }

    fn set_status_notice(&mut self, msg: String) {
        let safe = sanitize_terminal_inline(&msg);
        self.status_notice = Some((safe, Instant::now()));
        if self.tty {
            self.render_divider();
            self.render_composer();
        }
    }

    fn clear_expired_status_notice(&mut self) {
        if let Some((_, at)) = &self.status_notice
            && at.elapsed() >= STATUS_NOTICE_TTL
        {
            self.status_notice = None;
            if self.tty {
                self.render_divider();
                self.render_composer();
            }
        }
    }

    fn maybe_ring_bel(&mut self) {
        if !self.tty || self.muted {
            return;
        }
        let now = Instant::now();
        if let Some(prev) = self.last_bel_at
            && now.saturating_duration_since(prev) < BEL_COOLDOWN
        {
            return;
        }
        self.last_bel_at = Some(now);
        let mut out = io::stdout();
        let _ = out.write_all(b"\x07");
        let _ = out.flush();
    }

    fn push_line(&mut self, text: String, style: LineStyle) {
        while self.transcript.len() >= MAX_TRANSCRIPT_LINES {
            let _ = self.transcript.pop_front();
        }
        let entry = TranscriptEntry {
            text: text.clone(),
            style,
        };
        self.transcript.push_back(entry);

        if self.tty {
            self.append_tty_line(&text, style);
        } else {
            let mut out = io::stdout();
            let _ = writeln!(out, "{text}");
            let _ = out.flush();
        }
    }

    fn push_system(&mut self, msg: &str) {
        let ts = format_hhmm_now();
        let safe = sanitize_terminal_text(msg, true);
        for part in safe.split('\n') {
            self.push_line(format!("[{ts}] [system] {part}"), LineStyle::System);
        }
    }

    fn push_error(&mut self, msg: &str) {
        let ts = format_hhmm_now();
        let safe = sanitize_terminal_inline(&sanitize_server_error(msg));
        self.push_line(format!("[{ts}] [error] {safe}"), LineStyle::Error);
    }

    fn format_header_bar(&self) -> String {
        let conn = if self.connected { "connected" } else { "reconnecting" };
        match &self.active_party {
            Some(p) => {
                let name = if p.room_name.trim().is_empty() {
                    "Party".to_string()
                } else {
                    sanitize_terminal_inline(&p.room_name)
                };
                let link_part = if !p.room_code.trim().is_empty() {
                    format!(" · clank.party/{}", sanitize_terminal_inline(&p.room_code))
                } else if !p.share_url.trim().is_empty() {
                    format!(" · {}", sanitize_terminal_inline(&p.share_url))
                } else {
                    String::new()
                };
                let live_count = self
                    .members
                    .iter()
                    .filter(|m| m.live)
                    .count()
                    .max(usize::from(p.member_count));
                let mute_tag = if self.muted { " · muted" } else { "" };
                format!(
                    " ● Party: {name}{link_part} · {live_count} live · {conn}{mute_tag}"
                )
            }
            None => {
                let who = if self.own_handle.is_empty() {
                    String::new()
                } else {
                    format!(" · @{}", sanitize_terminal_inline(&self.own_handle))
                };
                format!(" ○ Outpost Lobby{who} · no active party · {conn}")
            }
        }
    }

    fn format_squad_strip(&self) -> String {
        if self.active_party.is_none() {
            return " Squad: (none) — run /invite, /join @friend, /join CODE, or /friends"
                .to_string();
        }
        if self.members.is_empty() {
            return " Squad: waiting for roster...".to_string();
        }
        let mut parts = Vec::with_capacity(self.members.len());
        for m in &self.members {
            let dot = if m.live { "●" } else { "○" };
            let name = format_member_display(m.account_id, &m.handle);
            let safe_name = sanitize_terminal_inline(&name);
            let tag = match &m.client_label {
                Some(lbl) if !lbl.is_empty() => format!(" ({})", sanitize_terminal_inline(lbl)),
                _ => String::new(),
            };
            parts.push(format!("{dot} {safe_name}{tag}"));
        }
        format!(" Squad: {}", parts.join(" · "))
    }

    fn format_divider(&self) -> String {
        if let Some((ref notice, _)) = self.status_notice {
            format!("─── {notice} ───")
        } else {
            "─── Enter send · /invite /join /board /friends /members /copy /help /quit ───"
                .to_string()
        }
    }

    fn ansi_prefix(style: LineStyle) -> &'static str {
        match style {
            LineStyle::RemoteChat => "\x1b[0m",
            LineStyle::SelfChat => "\x1b[36m",
            LineStyle::AgentChat => "\x1b[35m",
            LineStyle::Board => "\x1b[33m",
            LineStyle::System => "\x1b[90m",
            LineStyle::Error => "\x1b[31m",
        }
    }

    fn layout(&self) -> TerminalLayout {
        TerminalLayout::compute(self.cols, self.rows)
    }

    fn render_full_screen(&self) {
        if !self.tty {
            return;
        }
        let layout = self.layout();
        let mut out = io::stdout();
        let _ = write!(out, "\x1b[?25l\x1b[0m\x1b[r\x1b[2J\x1b[H");

        if let Some(row) = layout.header_row {
            let header = truncate_to_cols(&self.format_header_bar(), layout.cols);
            let _ = write!(out, "\x1b[{row};1H\x1b[1;7m{header}\x1b[K\x1b[0m");
        }

        if let Some(row) = layout.squad_row {
            let squad = truncate_to_cols(&self.format_squad_strip(), layout.cols);
            let _ = write!(out, "\x1b[{row};1H\x1b[2m{squad}\x1b[K\x1b[0m");
        }

        if let Some((top, bottom)) = layout.transcript_bounds {
            if bottom > top {
                let _ = write!(out, "\x1b[{top};{bottom}r");
            }
            let viewport_rows = usize::from(bottom.saturating_sub(top).saturating_add(1));

            let mut wrapped: Vec<(String, LineStyle)> = Vec::new();
            for entry in &self.transcript {
                for l in wrap_to_cols(&entry.text, layout.cols) {
                    wrapped.push((l, entry.style));
                }
            }
            let skip = wrapped.len().saturating_sub(viewport_rows);
            for (idx, (line, style)) in wrapped.iter().skip(skip).enumerate() {
                let row = top.saturating_add(u16::try_from(idx).unwrap_or(0));
                if row > bottom {
                    break;
                }
                let prefix = Self::ansi_prefix(*style);
                let _ = write!(out, "\x1b[{row};1H{prefix}{line}\x1b[0m\x1b[K");
            }
        }

        if let Some(div_row) = layout.divider_row {
            let divider = truncate_to_cols(&self.format_divider(), layout.cols);
            let _ = write!(out, "\x1b[{div_row};1H\x1b[2m{divider}\x1b[K\x1b[0m");
        }

        self.write_composer_to(&mut out, layout);
        let _ = write!(out, "\x1b[?25h");
        let _ = out.flush();
    }

    fn render_header_and_squad(&self) {
        if !self.tty {
            return;
        }
        let layout = self.layout();
        let mut out = io::stdout();
        let _ = write!(out, "\x1b[?25l");
        if let Some(row) = layout.header_row {
            let header = truncate_to_cols(&self.format_header_bar(), layout.cols);
            let _ = write!(out, "\x1b[{row};1H\x1b[1;7m{header}\x1b[K\x1b[0m");
        }
        if let Some(row) = layout.squad_row {
            let squad = truncate_to_cols(&self.format_squad_strip(), layout.cols);
            let _ = write!(out, "\x1b[{row};1H\x1b[2m{squad}\x1b[K\x1b[0m");
        }
        self.write_composer_to(&mut out, layout);
        let _ = write!(out, "\x1b[?25h");
        let _ = out.flush();
    }

    fn render_divider(&self) {
        if !self.tty {
            return;
        }
        let layout = self.layout();
        let Some(div_row) = layout.divider_row else {
            return;
        };
        let divider = truncate_to_cols(&self.format_divider(), layout.cols);
        let mut out = io::stdout();
        let _ = write!(
            out,
            "\x1b[?25l\x1b[{div_row};1H\x1b[2m{divider}\x1b[K\x1b[0m"
        );
        self.write_composer_to(&mut out, layout);
        let _ = write!(out, "\x1b[?25h");
        let _ = out.flush();
    }

    fn render_composer(&self) {
        if !self.tty {
            return;
        }
        let layout = self.layout();
        let mut out = io::stdout();
        let _ = write!(out, "\x1b[?25l");
        self.write_composer_to(&mut out, layout);
        let _ = write!(out, "\x1b[?25h");
        let _ = out.flush();
    }

    fn write_composer_to(&self, out: &mut impl io::Write, layout: TerminalLayout) {
        let input_row = layout.composer_row;
        let cols = layout.cols;
        let prompt = if cols >= 3 {
            "> "
        } else if cols == 2 {
            ">"
        } else {
            ""
        };
        let avail = cols.saturating_sub(prompt.len());
        let (vis, cursor_col) = self.editor.visible_slice(avail);
        let cursor_1based = prompt
            .len()
            .saturating_add(cursor_col)
            .saturating_add(1)
            .min(cols);
        let _ = write!(
            out,
            "\x1b[{input_row};1H\x1b[0m{prompt}{vis}\x1b[K\x1b[{input_row};{cursor_1based}H"
        );
    }

    fn append_tty_line(&self, text: &str, style: LineStyle) {
        let layout = self.layout();
        let mut out = io::stdout();
        let _ = write!(out, "\x1b[?25l");
        let prefix = Self::ansi_prefix(style);
        if let Some((top, bottom)) = layout.transcript_bounds {
            let wrapped = wrap_to_cols(text, layout.cols);
            if bottom > top {
                let _ = write!(out, "\x1b[{top};{bottom}r");
                for line in wrapped {
                    let _ = write!(out, "\x1b[{bottom};1H\r\n{prefix}{line}\x1b[0m\x1b[K");
                }
            } else if let Some(last) = wrapped.last() {
                // Single-row transcript viewport on very short terminals (rows 3..=5):
                // overwrite the viewport row cleanly without scrolling headers/composer.
                let _ = write!(out, "\x1b[{top};1H{prefix}{last}\x1b[0m\x1b[K");
            }
        }
        self.write_composer_to(&mut out, layout);
        let _ = write!(out, "\x1b[?25h");
        let _ = out.flush();
    }

    fn notify_poller(&mut self) {
        self.poller_gen = self.poller_gen.saturating_add(1);
        let target = self.active_party.as_ref().map(|p| {
            let (cursor_epoch, after_seq) = self.dedup.cursor();
            PollerTarget {
                party_id: p.party_id,
                cursor_epoch,
                after_seq,
                generation: self.poller_gen,
            }
        });
        let _ = self.poller_tx.send(target);
    }

    fn ingest_room_member_hints(&mut self, members: &[RoomMemberIpc]) {
        for m in members {
            let label = match (&m.agent_name, m.client.as_str()) {
                (Some(agent), _) if !agent.trim().is_empty() => {
                    sanitize_terminal_inline(agent)
                }
                (_, client) if !client.trim().is_empty() => sanitize_terminal_inline(client),
                _ => continue,
            };
            let key = (
                m.account_id,
                sanitize_terminal_inline(&m.handle).to_ascii_lowercase(),
            );
            self.member_client_hints.insert(key, label);
        }
    }

    fn apply_members_from_ipc(&mut self, members: &[MemberInfo]) {
        self.members = members
            .iter()
            .map(|m| {
                let clean_handle = sanitize_terminal_inline(&m.server_handle);
                let hint = self
                    .member_client_hints
                    .get(&(m.account_id, clean_handle.to_ascii_lowercase()))
                    .cloned();
                SquadMemberView {
                    account_id: m.account_id,
                    handle: clean_handle,
                    client_label: hint,
                    live: m.connected_p2p || m.connected_mp1,
                }
            })
            .collect();
        if self.tty {
            self.render_header_and_squad();
        }
    }

    fn apply_members_from_room_enter(&mut self, members: &[RoomMemberIpc]) {
        self.ingest_room_member_hints(members);
        self.members = members
            .iter()
            .map(|m| {
                let clean_handle = sanitize_terminal_inline(&m.handle);
                let label = match (&m.agent_name, m.client.as_str()) {
                    (Some(agent), _) if !agent.trim().is_empty() => {
                        Some(sanitize_terminal_inline(agent))
                    }
                    (_, client) if !client.trim().is_empty() => {
                        Some(sanitize_terminal_inline(client))
                    }
                    _ => None,
                };
                SquadMemberView {
                    account_id: m.account_id,
                    handle: clean_handle,
                    client_label: label,
                    live: m.status.is_empty() || m.status == "live",
                }
            })
            .collect();
        if self.tty {
            self.render_header_and_squad();
        }
    }

    async fn reconnect_cmd_client(&mut self) -> Result<(), String> {
        let (client, _) = connect_daemon_cli(&self.opts, false, true).await?;
        self.cmd_client = client;
        self.connected = true;
        Ok(())
    }

    async fn attach_to_party(
        &mut self,
        party: ActivePartySummary,
        announce: bool,
    ) {
        let pid = party.party_id;
        let same_party = self
            .active_party
            .as_ref()
            .is_some_and(|p| p.party_id == pid);
        self.active_party = Some(party.clone());
        if !same_party {
            self.dedup.reset_for_party(Some(pid));
        }

        if let Ok(members_resp) = rpc_party_members(&mut self.cmd_client, pid).await
            && !members_resp.members.is_empty()
        {
            self.apply_members_from_ipc(&members_resp.members);
        }

        if self.tty {
            self.render_header_and_squad();
        }

        if announce {
            let name = if party.room_name.trim().is_empty() {
                "Party".to_string()
            } else {
                sanitize_terminal_inline(&party.room_name)
            };
            let code = sanitize_terminal_inline(&party.room_code);
            let share = self.best_share_url().unwrap_or_default();
            if !code.is_empty() && !share.is_empty() {
                self.push_system(&format!("Attached to {name} (code {code} · {share})"));
            } else if !code.is_empty() {
                self.push_system(&format!("Attached to {name} (code {code})"));
            } else {
                self.push_system(&format!("Attached to {name}"));
            }
        }

        // Load recent history from daemon ring buffer (includes both chat & board envelopes!).
        let poll_req = encode_party_poll_req(&PartyPollIpcReq {
            party_id: pid,
            cursor_epoch: self.dedup.cursor().0,
            after_seq: self.dedup.cursor().1,
            limit: 100,
            max_bytes: DEFAULT_POLL_MAX_BYTES as u32,
            board_only: false,
        });
        if let Ok(raw) = self
            .cmd_client
            .request(IpcOpcode::PartyPoll, poll_req)
            .await
            && let Ok(resp) = decode_party_poll_resp(&raw)
        {
            self.handle_poll_batch(resp, true).await;
        }

        self.notify_poller();
    }

    async fn refresh_members(&mut self) {
        let Some(pid) = self.active_party.as_ref().map(|p| p.party_id) else {
            return;
        };
        if let Ok(resp) = rpc_party_members(&mut self.cmd_client, pid).await
            && !resp.members.is_empty()
        {
            self.apply_members_from_ipc(&resp.members);
        }
    }

    async fn periodic_sync(&mut self) {
        self.clear_expired_status_notice();

        let list = match rpc_party_list(&mut self.cmd_client).await {
            Ok(l) => {
                if !self.connected {
                    self.connected = true;
                    if self.tty {
                        self.render_header_and_squad();
                    }
                }
                l
            }
            Err(_) => {
                if self.reconnect_cmd_client().await.is_ok() {
                    match rpc_party_list(&mut self.cmd_client).await {
                        Ok(l) => l,
                        Err(_) => return,
                    }
                } else {
                    self.connected = false;
                    if self.tty {
                        self.render_header_and_squad();
                    }
                    return;
                }
            }
        };

        match (self.active_party.as_ref().map(|p| p.party_id), list.parties.last().cloned()) {
            (Some(cur_id), Some(latest)) if latest.party_id == cur_id => {
                // Keep room code / name / member count fresh.
                self.active_party = Some(latest);
                self.refresh_members().await;
            }
            (Some(_cur_id), Some(other)) => {
                // Window 1 switched to a different party!
                self.attach_to_party(other, true).await;
            }
            (Some(_cur_id), None) => {
                // Window 1 left/disbanded the party!
                self.enter_lobby("Active party ended; returned to lobby.");
            }
            (None, Some(joined)) => {
                // Window 1 joined/created a party while we were in lobby!
                self.attach_to_party(joined, true).await;
            }
            (None, None) => {}
        }
    }

    fn enter_lobby(&mut self, notice: &str) {
        self.active_party = None;
        self.members.clear();
        self.dedup.reset_for_party(None);
        self.notify_poller();
        if self.tty {
            self.render_header_and_squad();
        }
        self.push_system(notice);
    }

    async fn handle_poll_batch(&mut self, resp: PartyPollIpcResp, is_history: bool) {
        let fresh = self.dedup.filter_and_advance(resp);
        if fresh.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut need_member_refresh = false;
        let mut ring_bel = false;

        for ev in fresh {
            match ev.kind {
                IpcPartyEventKind::Chat {
                    provenance,
                    room_scope: _,
                    target_selector: _,
                    timestamp_ns,
                    body,
                } => {
                    let clean_body = sanitize_terminal_text(&body, true);
                    let is_self = provenance.sender_account_id != 0
                        && provenance.sender_account_id == self.own_account_id;
                    if is_self
                        && self
                            .dedup
                            .consume_matching_echo(EchoKind::Chat, clean_body.trim(), now)
                    {
                        continue;
                    }
                    let ts = format_hhmm_from_ns(timestamp_ns);
                    let (sender_label, style) = if is_self {
                        if provenance.sender_device_id != 0
                            && provenance.sender_device_id != self.own_device_id
                        {
                            let h = sanitize_terminal_inline(&provenance.sender_handle);
                            (format!("@{h} (agent)"), LineStyle::AgentChat)
                        } else {
                            ("you".to_string(), LineStyle::SelfChat)
                        }
                    } else {
                        let disp = format_member_display(
                            provenance.sender_account_id,
                            &provenance.sender_handle,
                        );
                        (sanitize_terminal_inline(&disp), LineStyle::RemoteChat)
                    };
                    self.emit_multiline(&ts, &sender_label, &clean_body, style);
                    if !is_history && !is_self {
                        ring_bel = true;
                    }
                }
                IpcPartyEventKind::BridgeEnvelope {
                    provenance,
                    room_scope: _,
                    payload,
                } => {
                    let formatted = format_board_payload(&payload);
                    let is_self = provenance.sender_account_id != 0
                        && provenance.sender_account_id == self.own_account_id;
                    if is_self
                        && self
                            .dedup
                            .consume_matching_echo(EchoKind::Board, formatted.trim(), now)
                    {
                        continue;
                    }
                    let ts = format_hhmm_now();
                    let sender = if is_self {
                        "you".to_string()
                    } else {
                        sanitize_terminal_inline(&format_member_display(
                            provenance.sender_account_id,
                            &provenance.sender_handle,
                        ))
                    };
                    self.emit_multiline(
                        &ts,
                        &format!("[board] {sender}"),
                        &formatted,
                        LineStyle::Board,
                    );
                    if !is_history && !is_self {
                        ring_bel = true;
                    }
                }
                IpcPartyEventKind::ControlNotice {
                    provenance,
                    notice_kind: _,
                    party_epoch: _,
                    text,
                } => {
                    let ts = format_hhmm_now();
                    let sender = sanitize_terminal_inline(&format_member_display(
                        provenance.sender_account_id,
                        &provenance.sender_handle,
                    ));
                    let clean = sanitize_terminal_text(&text, false);
                    self.push_line(
                        format!("[{ts}] [system] {sender}: {}", clean.trim()),
                        LineStyle::System,
                    );
                }
                IpcPartyEventKind::MembershipChanged {
                    party_epoch: _,
                    summary,
                } => {
                    let ts = format_hhmm_now();
                    let clean = sanitize_terminal_text(&summary, false);
                    self.push_line(
                        format!("[{ts}] [system] {}", clean.trim()),
                        LineStyle::System,
                    );
                    need_member_refresh = true;
                }
            }
        }

        if need_member_refresh {
            self.refresh_members().await;
        }
        if ring_bel {
            self.maybe_ring_bel();
        }
    }

    fn emit_multiline(&mut self, ts: &str, label: &str, body: &str, style: LineStyle) {
        let mut lines = body.split('\n');
        let first = lines.next().unwrap_or_default();
        self.push_line(format!("[{ts}] {label}: {first}"), style);
        for cont in lines {
            self.push_line(format!("        {cont}"), style);
        }
    }

    fn best_share_url(&self) -> Option<String> {
        if let Some(ref p) = self.active_party {
            if let Some(valid) = validate_share_url(&p.share_url) {
                return Some(valid);
            }
            let code = sanitize_terminal_inline(&p.room_code);
            if !code.is_empty()
                && code.len() <= 32
                && code
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && let Some(valid) = validate_share_url(&format!("https://clank.party/{code}"))
            {
                return Some(valid);
            }
        }
        if !self.own_handle.is_empty() {
            let handle = sanitize_terminal_inline(self.own_handle.trim_start_matches('@'));
            if !handle.is_empty()
                && handle.len() <= 64
                && handle
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                && let Some(valid) = validate_share_url(&format!("https://clank.party/@{handle}"))
            {
                return Some(valid);
            }
        }
        None
    }

    async fn handle_user_line(&mut self, raw: &str) {
        match parse_user_input(raw) {
            UserInputAction::Empty => {}
            UserInputAction::Chat(body) => self.handle_send_chat(&body).await,
            UserInputAction::Command(cmd) => self.handle_slash_command(cmd).await,
        }
    }

    async fn handle_send_chat(&mut self, body: &str) {
        if let Err(reason) = check_chat_secret_refusal(body, self.local_secret_refs()) {
            self.push_error(reason);
            return;
        }
        let Some(party_id) = self.active_party.as_ref().map(|p| p.party_id) else {
            self.push_system(
                "Not in a party yet. Run /invite to start one, /join @friend or /join CODE, or /friends.",
            );
            return;
        };
        let client_msg_id = match random_safe_id() {
            Ok(id) => id,
            Err(e) => {
                self.push_error(&e);
                return;
            }
        };
        let req = PartySendChatReq {
            party_id,
            client_msg_id,
            room_scope: "party/main".to_string(),
            target_device_id: None,
            body: body.to_string(),
        };
        let encoded = match encode_party_send_chat_req(&req) {
            Ok(b) => b,
            Err(e) => {
                self.push_error(&e.to_string());
                return;
            }
        };
        let clean_body = sanitize_terminal_text(body, true);
        let ts = format_hhmm_now();
        // Record local echo BEFORE send completes so a fast server echo never duplicates,
        // and roll it back on send/decode failure so retries are never swallowed.
        let echo_id = self.dedup.record_local_echo(
            EchoKind::Chat,
            clean_body.trim().to_string(),
            Instant::now(),
        );

        let send_res = self
            .cmd_client
            .request(IpcOpcode::PartySendChat, encoded)
            .await;
        match send_res {
            Ok(raw) => match decode_send_result_resp(&raw) {
                Ok(resp) => {
                    self.emit_multiline(&ts, "you", &clean_body, LineStyle::SelfChat);
                    if !resp.withheld_unpinned.is_empty() {
                        self.set_status_notice(format!(
                            "Sent (withheld from {} unpinned peer(s))",
                            resp.withheld_unpinned.len()
                        ));
                    }
                }
                Err(e) => {
                    self.dedup.cancel_local_echo(echo_id);
                    self.push_error(&e.to_string());
                }
            },
            Err(e) => {
                self.dedup.cancel_local_echo(echo_id);
                self.push_error(&format!("send failed: {e}"));
            }
        }
    }

    async fn handle_slash_command(&mut self, cmd: SlashCommand) {
        match cmd {
            SlashCommand::Board(text) => {
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    self.push_system("Usage: /board <text>");
                    return;
                }
                if let Err(reason) = check_chat_secret_refusal(trimmed, self.local_secret_refs()) {
                    self.push_error(reason);
                    return;
                }
                let Some(party_id) = self.active_party.as_ref().map(|p| p.party_id) else {
                    self.push_system("Not in a party. Run /invite or /join first.");
                    return;
                };
                let client_msg_id = match random_safe_id() {
                    Ok(id) => id,
                    Err(e) => {
                        self.push_error(&e);
                        return;
                    }
                };
                let req = PartyPostBoardReq {
                    party_id,
                    client_msg_id,
                    room_scope: "party/main".to_string(),
                    payload: trimmed.as_bytes().to_vec(),
                };
                let encoded = match encode_party_post_board_req(&req) {
                    Ok(b) => b,
                    Err(e) => {
                        self.push_error(&e.to_string());
                        return;
                    }
                };
                let formatted = format_board_payload(trimmed.as_bytes());
                let ts = format_hhmm_now();
                let echo_id = self.dedup.record_local_echo(
                    EchoKind::Board,
                    formatted.trim().to_string(),
                    Instant::now(),
                );
                match self
                    .cmd_client
                    .request(IpcOpcode::PartyPostBoard, encoded)
                    .await
                {
                    Ok(raw) => match decode_send_result_resp(&raw) {
                        Ok(_) => {
                            self.emit_multiline(&ts, "[board] you", &formatted, LineStyle::Board);
                        }
                        Err(e) => {
                            self.dedup.cancel_local_echo(echo_id);
                            self.push_error(&e.to_string());
                        }
                    },
                    Err(e) => {
                        self.dedup.cancel_local_echo(echo_id);
                        self.push_error(&format!("board post failed: {e}"));
                    }
                }
            }
            SlashCommand::Invite(handle) => {
                let req = RoomInviteIpcReq {
                    handle,
                    party_id: self.active_party.as_ref().map(|p| p.party_id),
                    name: None,
                };
                match rpc_room_invite(&mut self.cmd_client, req).await {
                    Ok(resp) => {
                        let code = sanitize_terminal_inline(&resp.room_code);
                        let share = sanitize_terminal_inline(&resp.share_url);
                        if let Some(ref inv) = resp.invited_handle
                            && !inv.is_empty()
                        {
                            self.push_system(&format!(
                                "Invited @{} — code {code} ({share})",
                                sanitize_terminal_inline(inv.trim_start_matches('@'))
                            ));
                        } else {
                            self.push_system(&format!("Party ready — code {code} ({share})"));
                        }
                        if !resp.handle_url.is_empty() {
                            self.push_system(&format!(
                                "Link: {}",
                                sanitize_terminal_inline(&resp.handle_url)
                            ));
                        }
                        // Attach immediately to the invited/created party.
                        if let Ok(list) = rpc_party_list(&mut self.cmd_client).await
                            && let Some(p) = list
                                .parties
                                .into_iter()
                                .find(|p| p.party_id == resp.party_id)
                        {
                            self.attach_to_party(p, false).await;
                        }
                    }
                    Err(e) => self.push_error(&format!("invite failed: {e}")),
                }
            }
            SlashCommand::Join(target) => {
                let req = RoomEnterIpcReq {
                    target: target.trim().to_string(),
                    agent_name: None,
                };
                match rpc_room_enter(&mut self.cmd_client, req).await {
                    Ok(resp) => {
                        self.apply_members_from_room_enter(&resp.members);
                        let name = if resp.name.trim().is_empty() {
                            "Party".to_string()
                        } else {
                            sanitize_terminal_inline(&resp.name)
                        };
                        let code = sanitize_terminal_inline(&resp.room_code);
                        self.push_system(&format!(
                            "Joined {name} (code {code}) · {} live",
                            resp.members.len()
                        ));
                        if let Ok(list) = rpc_party_list(&mut self.cmd_client).await
                            && let Some(p) = list
                                .parties
                                .into_iter()
                                .find(|p| p.party_id == resp.party_id)
                        {
                            self.attach_to_party(p, false).await;
                        } else {
                            let summary = ActivePartySummary {
                                party_id: resp.party_id,
                                party_epoch: 1,
                                leader_account_id: 0,
                                leader_device_id: 0,
                                visibility: 0,
                                join_mode: 0,
                                relay_policy: 0,
                                effective_relay_policy: 0,
                                pinned_relay_url: String::new(),
                                max_members: 12,
                                member_count: u8::try_from(resp.members.len()).unwrap_or(u8::MAX),
                                next_seq: 0,
                                daemon_epoch: 0,
                                room_code: resp.room_code,
                                room_name: resp.name,
                                share_url: resp.share_url,
                            };
                            self.attach_to_party(summary, false).await;
                        }
                    }
                    Err(e) => self.push_error(&format!("join failed: {e}")),
                }
            }
            SlashCommand::Leave => {
                let pid = self.active_party.as_ref().map(|p| p.party_id);
                if pid.is_none() {
                    self.push_system("Not currently in a party.");
                    return;
                }
                match rpc_room_leave(&mut self.cmd_client, pid).await {
                    Ok(_) => {
                        self.enter_lobby("Left party. You are now in lobby mode.");
                    }
                    Err(e) => self.push_error(&format!("leave failed: {e}")),
                }
            }
            SlashCommand::Friends => match rpc_friends_live(&mut self.cmd_client).await {
                Ok(resp) => {
                    if !resp.pending_invites.is_empty() {
                        self.push_system("Pending party invites:");
                        for inv in &resp.pending_invites {
                            self.push_system(&format!(
                                "  ● @{} invited you (code {}) — run /join",
                                sanitize_terminal_inline(inv.from_handle.trim_start_matches('@')),
                                sanitize_terminal_inline(&inv.room_code)
                            ));
                        }
                    }
                    if resp.friends.is_empty() {
                        if resp.pending_invites.is_empty() {
                            self.push_system("No friends yet. Run /add @handle to add someone.");
                        }
                    } else {
                        for f in &resp.friends {
                            let h = sanitize_terminal_inline(f.handle.trim_start_matches('@'));
                            let icon = match f.presence.as_str() {
                                "online" | "in_party" => "●",
                                _ => "○",
                            };
                            let status = if f.state == "pending_in" {
                                format!("incoming request — run /add @{h}")
                            } else if f.state == "pending_out" {
                                "request sent".to_string()
                            } else if f.presence == "in_party" {
                                match (&f.party_room_code, f.joinable) {
                                    (Some(code), true) => format!(
                                        "in party ({}) [/join @{h}]",
                                        sanitize_terminal_inline(code)
                                    ),
                                    (Some(code), false) => {
                                        format!("in party ({})", sanitize_terminal_inline(code))
                                    }
                                    (None, true) => format!("in party [/join @{h}]"),
                                    (None, false) => "in party".to_string(),
                                }
                            } else if f.presence == "online" {
                                "online".to_string()
                            } else {
                                "offline".to_string()
                            };
                            self.push_system(&format!("{icon} @{h} — {status}"));
                        }
                    }
                }
                Err(e) => self.push_error(&format!("friends failed: {e}")),
            },
            SlashCommand::Add(target) => {
                let target = target.trim();
                if target.is_empty() {
                    self.push_system("Usage: /add @handle");
                    return;
                }
                match rpc_add_friend(&mut self.cmd_client, target).await {
                    Ok((display, resp)) => {
                        let safe = sanitize_terminal_inline(&display);
                        if resp.state == 0 {
                            self.push_system(&format!("You and @{safe} are now friends."));
                        } else {
                            self.push_system(&format!("Sent friend request to @{safe}."));
                        }
                    }
                    Err(e) => self.push_error(&format!("add friend failed: {e}")),
                }
            }
            SlashCommand::Members => {
                if self.active_party.is_none() {
                    self.push_system("Not in a party. Run /invite or /join first.");
                    return;
                }
                self.refresh_members().await;
                if self.members.is_empty() {
                    self.push_system("No members reported yet.");
                } else {
                    let snapshot = self.members.clone();
                    self.push_system(&format!("Squad ({}):", snapshot.len()));
                    for m in &snapshot {
                        let icon = if m.live { "●" } else { "○" };
                        let disp = sanitize_terminal_inline(&format_member_display(
                            m.account_id,
                            &m.handle,
                        ));
                        let tag = match &m.client_label {
                            Some(lbl) if !lbl.is_empty() => {
                                format!(" ({})", sanitize_terminal_inline(lbl))
                            }
                            _ => String::new(),
                        };
                        let st = if m.live { "live" } else { "away" };
                        self.push_system(&format!("  {icon} {disp}{tag} — {st}"));
                    }
                }
            }
            SlashCommand::Copy => match self.best_share_url() {
                Some(url) => {
                    if self.tty {
                        let b64 = B64.encode(url.as_bytes());
                        let mut out = io::stdout();
                        let _ = write!(out, "\x1b]52;c;{b64}\x07");
                        let _ = out.flush();
                        self.set_status_notice(format!("Copied {url}"));
                    }
                    self.push_system(&format!("Share link: {url}"));
                }
                None => {
                    self.push_system("No share link available yet. Run /invite first.");
                }
            },
            SlashCommand::Mute => {
                self.muted = !self.muted;
                let state = if self.muted { "muted" } else { "unmuted" };
                self.set_status_notice(format!("Notifications {state}"));
                self.push_system(&format!("Terminal bell notifications {state}."));
                if self.tty {
                    self.render_header_and_squad();
                }
            }
            SlashCommand::Help => {
                self.push_system(
                    "Commands: /board <text> · /invite [@handle] · /join [@handle|CODE|url] · /leave · /friends · /add @handle · /members · /copy · /mute · /help · /quit",
                );
            }
            SlashCommand::Quit => {
                self.should_quit = true;
            }
            SlashCommand::Unknown(name) => {
                let safe = sanitize_terminal_inline(&name);
                self.push_system(&format!("Unknown command {safe}. Type /help for commands."));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public Subcommand Entrypoint
// ---------------------------------------------------------------------------

pub async fn cmd_chat(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let chat_args = parse_chat_args(args)?;
    if chat_args.show_help {
        print_chat_usage();
        return Ok(());
    }

    // Load local device secret material (optional) for client-side secret refusal.
    let local_secrets = (|| -> Option<LocalSecretMaterial> {
        let state_dir = resolve_effective_state_dir(opts.state_dir.as_deref()).ok()?;
        let dev_id = resolve_active_device_id(&state_dir, opts.device_id).ok()?;
        let rec = load_device_record(&state_dir, dev_id).ok()?;
        Some(LocalSecretMaterial {
            device_secret: Zeroizing::new(rec.device_secret),
            device_cwt: Zeroizing::new(rec.device_cwt),
        })
    })();

    let (mut cmd_client, device_id) = connect_daemon_cli(opts, false, true).await?;
    let status = rpc_get_status(&mut cmd_client).await?;

    let tty = is_interactive_tty(chat_args.no_tty);
    let (cols, rows) = if tty {
        query_terminal_size()
    } else {
        (DEFAULT_COLS, DEFAULT_ROWS)
    };

    // Enter TTY raw mode BEFORE printing UI so TermiosGuard guarantees clean teardown.
    let mut tty_guard = if tty {
        Some(TerminalGuard::enter_raw(libc::STDIN_FILENO, rows)?)
    } else {
        None
    };

    let (poller_tx, poller_rx) = watch::channel(None);
    let mut poller_events = spawn_daemon_poller(opts.clone(), poller_rx);

    let mut app = ChatApp {
        opts: opts.clone(),
        cmd_client,
        local_secrets,
        own_account_id: status.account_id,
        own_device_id: device_id,
        own_handle: sanitize_terminal_inline(&status.handle),
        connected: true,
        active_party: None,
        members: Vec::new(),
        member_client_hints: HashMap::new(),
        dedup: MessageDedupState::new(),
        transcript: VecDeque::new(),
        editor: LineEditor::new(),
        tty,
        cols,
        rows,
        muted: false,
        last_bel_at: None,
        status_notice: None,
        poller_tx,
        poller_gen: 0,
        should_quit: false,
    };

    if tty {
        app.render_full_screen();
    }

    // Initial party resolution:
    // 1. Positional target -> join first!
    // 2. Explicit --party <id> or active party from daemon -> attach!
    // 3. Otherwise -> open cleanly in lobby mode!
    if let Some(ref target) = chat_args.target {
        app.handle_slash_command(SlashCommand::Join(target.clone()))
            .await;
    } else {
        match rpc_party_list(&mut app.cmd_client).await {
            Ok(list) => {
                let chosen = if let Some(req_pid) = chat_args.party_id {
                    list.parties.into_iter().find(|p| p.party_id == req_pid)
                } else {
                    list.parties.into_iter().next_back()
                };
                if let Some(party) = chosen {
                    app.attach_to_party(party, true).await;
                } else if let Some(req_pid) = chat_args.party_id {
                    app.push_system(&format!(
                        "Party {req_pid} is not active. Opened in lobby mode — run /invite, /join <target>, or /friends."
                    ));
                } else {
                    app.push_system(
                        "Lobby mode — not in a party yet. Run /invite, /invite @friend, /join @friend, /join CODE, or /friends.",
                    );
                }
            }
            Err(e) => {
                app.push_error(&format!("failed to query active parties: {e}"));
                app.push_system(
                    "Lobby mode — run /invite, /join <target>, /friends, or /help.",
                );
            }
        }
    }

    let mut refresh_iv = tokio::time::interval(PERIODIC_REFRESH_INTERVAL);
    refresh_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    refresh_iv.tick().await;

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| format!("failed to install SIGINT handler: {e}"))?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("failed to install SIGTERM handler: {e}"))?;
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .map_err(|e| format!("failed to install SIGWINCH handler: {e}"))?;

    if tty {
        let reader_stop = Arc::new(AtomicBool::new(false));
        let (mut key_rx, reader_handle) = spawn_tty_key_reader(Arc::clone(&reader_stop));

        while !app.should_quit {
            tokio::select! {
                biased;
                _ = sigint.recv() => {
                    app.should_quit = true;
                }
                _ = sigterm.recv() => {
                    app.should_quit = true;
                }
                _ = sigwinch.recv() => {
                    let (c, r) = query_terminal_size();
                    app.cols = c;
                    app.rows = r;
                    if let Some(ref mut g) = tty_guard {
                        g.set_rows(r);
                    }
                    app.render_full_screen();
                }
                maybe_key = key_rx.recv() => {
                    match maybe_key {
                        Some(KeyEvent::CtrlC | KeyEvent::CtrlD | KeyEvent::Eof) | None => {
                            app.should_quit = true;
                        }
                        Some(KeyEvent::Enter) => {
                            let line = app.editor.submit();
                            app.render_composer();
                            app.handle_user_line(&line).await;
                        }
                        Some(KeyEvent::Char(ch)) => {
                            app.editor.insert_char(ch);
                            app.render_composer();
                        }
                        Some(KeyEvent::Backspace) => {
                            if app.editor.backspace() {
                                app.render_composer();
                            }
                        }
                        Some(KeyEvent::Delete) => {
                            if app.editor.delete_forward() {
                                app.render_composer();
                            }
                        }
                        Some(KeyEvent::Left) => {
                            if app.editor.move_left() {
                                app.render_composer();
                            }
                        }
                        Some(KeyEvent::Right) => {
                            if app.editor.move_right() {
                                app.render_composer();
                            }
                        }
                        Some(KeyEvent::Home) => {
                            app.editor.move_home();
                            app.render_composer();
                        }
                        Some(KeyEvent::End) => {
                            app.editor.move_end();
                            app.render_composer();
                        }
                        Some(KeyEvent::CtrlU) => {
                            app.editor.clear_line();
                            app.render_composer();
                        }
                        Some(KeyEvent::CtrlW) => {
                            if app.editor.delete_word_back() {
                                app.render_composer();
                            }
                        }
                        Some(KeyEvent::Up) => {
                            if app.editor.history_up() {
                                app.render_composer();
                            }
                        }
                        Some(KeyEvent::Down) => {
                            if app.editor.history_down() {
                                app.render_composer();
                            }
                        }
                    }
                }
                maybe_ev = poller_events.recv() => {
                    handle_poller_event(&mut app, maybe_ev).await;
                }
                _ = refresh_iv.tick() => {
                    app.periodic_sync().await;
                }
            }
        }

        reader_stop.store(true, Ordering::Release);
        let _ = reader_handle.join();
    } else {
        // Non-TTY / `--no-tty` bounded poll-based line reader (exits promptly on /quit/SIGINT/SIGTERM
        // even while the parent keeps stdin open, and caps buffered line memory at MAX_INPUT_BYTES).
        let reader_stop = Arc::new(AtomicBool::new(false));
        let (mut line_rx, reader_handle) = spawn_non_tty_line_reader(Arc::clone(&reader_stop));

        while !app.should_quit {
            tokio::select! {
                biased;
                _ = sigint.recv() => {
                    app.should_quit = true;
                }
                _ = sigterm.recv() => {
                    app.should_quit = true;
                }
                maybe_line = line_rx.recv() => {
                    match maybe_line {
                        Some(StdinLineEvent::Line(line)) => {
                            app.handle_user_line(&line).await;
                        }
                        Some(StdinLineEvent::TooLong) => {
                            app.push_error(&format!(
                                "input line exceeded max {MAX_INPUT_BYTES} bytes"
                            ));
                        }
                        Some(StdinLineEvent::Eof) | None => {
                            app.should_quit = true;
                        }
                    }
                }
                maybe_ev = poller_events.recv() => {
                    handle_poller_event(&mut app, maybe_ev).await;
                }
                _ = refresh_iv.tick() => {
                    app.periodic_sync().await;
                }
            }
        }

        reader_stop.store(true, Ordering::Release);
        let _ = reader_handle.join();
    }

    // Drop poller sender so background poller task exits cleanly.
    drop(app.poller_tx);
    drop(tty_guard);
    Ok(())
}

async fn handle_poller_event(app: &mut ChatApp, ev: Option<PollerEvent>) {
    match ev {
        Some(PollerEvent::Batch(resp)) => {
            app.handle_poll_batch(resp, false).await;
        }
        Some(PollerEvent::PartyDetached(pid)) => {
            if app.active_party.as_ref().is_some_and(|p| p.party_id == pid) {
                app.enter_lobby("Active party ended; returned to lobby.");
            }
        }
        Some(PollerEvent::ConnectionState(is_up)) => {
            if app.connected != is_up {
                app.connected = is_up;
                if app.tty {
                    app.render_header_and_squad();
                }
            }
        }
        None => {}
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc_payloads::IpcProvenance;

    #[test]
    fn sanitize_strips_ansi_csi_osc_dcs_c0_c1_and_bidi() {
        // CSI color + cursor move + erase screen
        let raw = "\x1b[31mred\x1b[0m \x1b[2J\x1b[1;1Hclean";
        assert_eq!(sanitize_terminal_text(raw, false), "red clean");

        // OSC 0 window title (BEL terminated) + OSC 52 clipboard hijack (ST terminated)
        let osc = "hi\x1b]0;pwned\x07 \x1b]52;c;Zm9v\x1b\\there";
        assert_eq!(sanitize_terminal_text(osc, false), "hi there");

        // 8-bit C1 CSI (`\u{009B}`) and C1 OSC (`\u{009D}...\u{009C}`)
        let c1 = "a\u{009B}31mB\u{009D}0;evil\u{009C}c";
        assert_eq!(sanitize_terminal_text(c1, false), "aBc");

        // DCS / APC / 2-byte ESC
        let dcs = "x\x1bP1$q\x1b\\y\x1b_apc\x1b\\z\x1bc!";
        assert_eq!(sanitize_terminal_text(dcs, false), "xyz!");

        // C0 controls (NUL, BEL, BS, CR) and DEL
        let c0 = "ab\x00\x07\x08cd\x7fef";
        assert_eq!(sanitize_terminal_text(c0, false), "abcdef");

        // Unicode BiDi overrides, isolates, LRM/RLM, zero-width, and Unicode Tag smuggling
        let bidi = "safe\u{202E}gnirts\u{202C}\u{2066}iso\u{2069}\u{200E}\u{200F}\u{200B}\u{E0001}\u{E0041}end";
        assert_eq!(sanitize_terminal_text(bidi, false), "safegnirtsisoend");

        // Inline flattens newlines; multiline preserves `\n`
        assert_eq!(sanitize_terminal_inline("foo\r\nbar\tbaz"), "foo bar baz");
        assert_eq!(sanitize_terminal_text("foo\r\nbar", true), "foo\nbar");
    }

    #[test]
    fn line_editor_utf8_emoji_cjk_and_history_never_panic() {
        let mut ed = LineEditor::new();
        for ch in "hi 🚀 日本語!".chars() {
            ed.insert_char(ch);
        }
        assert_eq!(ed.text(), "hi 🚀 日本語!");

        // Move left across multibyte chars and insert in middle
        assert!(ed.move_left()); // before '!'
        assert!(ed.move_left()); // before '語'
        ed.insert_char('✨');
        assert_eq!(ed.text(), "hi 🚀 日本✨語!");

        // Backspace removes '✨' cleanly on char boundary
        assert!(ed.backspace());
        assert_eq!(ed.text(), "hi 🚀 日本語!");

        // Delete forward removes '語'
        assert!(ed.delete_forward());
        assert_eq!(ed.text(), "hi 🚀 日本!");

        // Home / End / Right / Left boundaries
        ed.move_home();
        assert_eq!(ed.cursor_byte(), 0);
        assert!(!ed.move_left());
        ed.move_end();
        assert!(!ed.move_right());

        // Ctrl-W deletes last word ("日本!")
        assert!(ed.delete_word_back());
        assert_eq!(ed.text(), "hi 🚀 ");

        // Ctrl-U clears line
        ed.clear_line();
        assert_eq!(ed.text(), "");
        assert_eq!(ed.cursor_byte(), 0);

        // Visible slice handles narrow width with wide UTF-8 chars cleanly
        for ch in "🚀日本語abcdef".chars() {
            ed.insert_char(ch);
        }
        let (vis, col) = ed.visible_slice(6);
        assert!(!vis.is_empty());
        assert!(col < 6);

        // History up/down preserves draft
        let s1 = ed.submit();
        assert_eq!(s1, "🚀日本語abcdef");
        for ch in "second msg".chars() {
            ed.insert_char(ch);
        }
        let _ = ed.submit();
        for ch in "draft".chars() {
            ed.insert_char(ch);
        }
        assert!(ed.history_up());
        assert_eq!(ed.text(), "second msg");
        assert!(ed.history_up());
        assert_eq!(ed.text(), "🚀日本語abcdef");
        assert!(!ed.history_up());
        assert!(ed.history_down());
        assert_eq!(ed.text(), "second msg");
        assert!(ed.history_down());
        assert_eq!(ed.text(), "draft");
        assert!(!ed.history_down());
    }

    #[test]
    fn slash_command_parsing_and_secret_refusal() {
        assert_eq!(parse_user_input("   "), UserInputAction::Empty);
        assert_eq!(
            parse_user_input("hello squad"),
            UserInputAction::Chat("hello squad".to_string())
        );
        assert_eq!(
            parse_user_input("/board deployed v0.5.1"),
            UserInputAction::Command(SlashCommand::Board("deployed v0.5.1".to_string()))
        );
        assert_eq!(
            parse_user_input("/invite"),
            UserInputAction::Command(SlashCommand::Invite(None))
        );
        assert_eq!(
            parse_user_input("/invite @phall"),
            UserInputAction::Command(SlashCommand::Invite(Some("phall".to_string())))
        );
        assert_eq!(
            parse_user_input("/join https://clank.party/KAIH"),
            UserInputAction::Command(SlashCommand::Join(
                "https://clank.party/KAIH".to_string()
            ))
        );
        assert_eq!(
            parse_user_input("/leave"),
            UserInputAction::Command(SlashCommand::Leave)
        );
        assert_eq!(
            parse_user_input("/friends"),
            UserInputAction::Command(SlashCommand::Friends)
        );
        assert_eq!(
            parse_user_input("/add @bob"),
            UserInputAction::Command(SlashCommand::Add("@bob".to_string()))
        );
        assert_eq!(
            parse_user_input("/members"),
            UserInputAction::Command(SlashCommand::Members)
        );
        assert_eq!(
            parse_user_input("/copy"),
            UserInputAction::Command(SlashCommand::Copy)
        );
        assert_eq!(
            parse_user_input("/mute"),
            UserInputAction::Command(SlashCommand::Mute)
        );
        assert_eq!(
            parse_user_input("/help"),
            UserInputAction::Command(SlashCommand::Help)
        );
        assert_eq!(
            parse_user_input("/quit"),
            UserInputAction::Command(SlashCommand::Quit)
        );
        assert_eq!(
            parse_user_input("/exit"),
            UserInputAction::Command(SlashCommand::Quit)
        );
        assert_eq!(
            parse_user_input("/unknown arg"),
            UserInputAction::Command(SlashCommand::Unknown("/unknown".to_string()))
        );

        // Secret refusal catches all required prefixes + PEM private keys
        assert!(check_chat_secret_refusal("hello normal chat", None).is_ok());
        for bad in [
            "my key is mprk1_ABCD1234",
            "invite mpinv1_secret_token",
            "party invite mppi1_secret_token",
            "link mpdl1_secret_token",
            "session mpcs1_session_tok",
            "guest mpguest1_guest_tok",
            "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ] {
            let res = check_chat_secret_refusal(bad, None);
            assert!(res.is_err(), "expected refusal for: {bad}");
            if let Err(msg) = res {
                assert!(
                    !msg.contains("mprk1_")
                        && !msg.contains("mpcs1_")
                        && !msg.contains("PRIVATE KEY"),
                    "refusal error must never echo secret material"
                );
            }
        }
    }

    #[test]
    fn dedup_state_handles_local_echo_seq_dedup_and_cursor_reset() {
        let mut dedup = MessageDedupState::new();
        dedup.reset_for_party(Some(8801));
        let now = Instant::now();

        // Local echo consumes exactly once
        dedup.record_local_echo(EchoKind::Chat, "hello world".to_string(), now);
        assert!(dedup.consume_matching_echo(EchoKind::Chat, "hello world", now));
        assert!(!dedup.consume_matching_echo(EchoKind::Chat, "hello world", now));
        // Wrong kind does not consume
        dedup.record_local_echo(EchoKind::Board, "status".to_string(), now);
        assert!(!dedup.consume_matching_echo(EchoKind::Chat, "status", now));
        assert!(dedup.consume_matching_echo(EchoKind::Board, "status", now));

        let make_ev = |seq: u64, body: &str| IpcPartyEvent {
            event_seq: seq,
            party_id: 8801,
            party_epoch: 1,
            kind: IpcPartyEventKind::Chat {
                provenance: IpcProvenance {
                    sender_account_id: 1002,
                    sender_device_id: 2002,
                    sender_handle: "bob".to_string(),
                    root_pubkey_fingerprint: String::new(),
                    safety_number: String::new(),
                },
                room_scope: "party/main".to_string(),
                target_selector: "@all".to_string(),
                timestamp_ns: 1_700_000_000_000_000_000,
                body: body.to_string(),
            },
        };

        // First batch delivers seq 1, 2
        let batch1 = PartyPollIpcResp {
            party_id: 8801,
            daemon_epoch: 7,
            next_seq: 2,
            dropped_before_seq: 0,
            cursor_reset: false,
            gap_possible: false,
            timed_out: false,
            events: vec![make_ev(1, "one"), make_ev(2, "two")],
        };
        let fresh1 = dedup.filter_and_advance(batch1);
        assert_eq!(fresh1.len(), 2);
        assert_eq!(dedup.cursor(), (7, 2));

        // Overlapping batch containing seq 2 + seq 3 returns ONLY seq 3
        let batch2 = PartyPollIpcResp {
            party_id: 8801,
            daemon_epoch: 7,
            next_seq: 3,
            dropped_before_seq: 0,
            cursor_reset: false,
            gap_possible: false,
            timed_out: false,
            events: vec![make_ev(2, "two"), make_ev(3, "three")],
        };
        let fresh2 = dedup.filter_and_advance(batch2);
        assert_eq!(fresh2.len(), 1);
        assert_eq!(fresh2.first().map(|e| e.event_seq), Some(3));
        assert_eq!(dedup.cursor(), (7, 3));

        // Cursor reset on new daemon_epoch clears seen set and accepts seq 1 again
        let batch3 = PartyPollIpcResp {
            party_id: 8801,
            daemon_epoch: 8,
            next_seq: 1,
            dropped_before_seq: 0,
            cursor_reset: true,
            gap_possible: true,
            timed_out: false,
            events: vec![make_ev(1, "after restart")],
        };
        let fresh3 = dedup.filter_and_advance(batch3);
        assert_eq!(fresh3.len(), 1);
        assert_eq!(dedup.cursor(), (8, 1));
    }

    #[test]
    fn parse_chat_args_variants() -> Result<(), String> {
        let a1 = parse_chat_args(&[])?;
        assert_eq!(a1, ChatArgs::default());

        let a2 = parse_chat_args(&[
            "https://clank.party/KAIH".to_string(),
            "--no-tty".to_string(),
        ])?;
        assert_eq!(a2.target.as_deref(), Some("https://clank.party/KAIH"));
        assert!(a2.no_tty);

        let a3 = parse_chat_args(&["--party".to_string(), "8801".to_string()])?;
        assert_eq!(a3.party_id, Some(8801));

        assert!(parse_chat_args(&["--bogus".to_string()]).is_err());
        Ok(())
    }

    #[test]
    fn format_board_payload_json_and_sanitization() {
        let card_json = r#"{"title":"Fixed \u001b[31mauth","summary":"2 files\u202Eok"}"#;
        assert_eq!(
            format_board_payload(card_json.as_bytes()),
            "Fixed auth — 2 filesok"
        );
        // Plain text / non-JSON board post with raw ESC & BiDi is also stripped cleanly
        let raw_plain = "release \x1b[31mv0.5.1\x1b[0m \u{202E}ready";
        assert_eq!(
            format_board_payload(raw_plain.as_bytes()),
            "release v0.5.1 ready"
        );
        assert_eq!(format_board_payload(b"\xff\xfe\xfd"), "<3 bytes binary>");
    }

    #[test]
    fn tiny_terminal_layout_never_overlaps_or_overflows() {
        for rows in 0u16..=10 {
            for cols in 0u16..=25 {
                let l = TerminalLayout::compute(cols, rows);
                let eff_rows = rows.max(1);
                let eff_cols = usize::from(cols.max(1));
                assert_eq!(l.rows, eff_rows);
                assert_eq!(l.cols, eff_cols);
                assert!(l.composer_row >= 1 && l.composer_row <= eff_rows);

                // Every active region must occupy disjoint row ranges within 1..=eff_rows.
                let mut used = HashSet::new();
                assert!(used.insert(l.composer_row));
                if let Some(r) = l.header_row {
                    assert!(r >= 1 && r <= eff_rows);
                    assert!(used.insert(r), "header collided at rows={rows}");
                }
                if let Some(r) = l.squad_row {
                    assert!(r >= 1 && r <= eff_rows);
                    assert!(used.insert(r), "squad collided at rows={rows}");
                }
                if let Some(r) = l.divider_row {
                    assert!(r >= 1 && r <= eff_rows);
                    assert!(used.insert(r), "divider collided at rows={rows}");
                }
                if let Some((top, bottom)) = l.transcript_bounds {
                    assert!(top >= 1 && top <= bottom && bottom <= eff_rows);
                    for r in top..=bottom {
                        assert!(used.insert(r), "transcript collided at rows={rows}");
                    }
                }

                // Narrow wrapping & truncation respect actual cols (never clamped up to 8 or 20!)
                let wrapped = wrap_to_cols("hello world from narrow terminal", eff_cols);
                for wline in &wrapped {
                    let line_cols: usize = wline.chars().map(char_display_width).sum();
                    assert!(line_cols <= eff_cols, "wrapped line overflowed cols={eff_cols}");
                }
                let trunc = truncate_to_cols("header bar text", eff_cols);
                let trunc_cols: usize = trunc.chars().map(char_display_width).sum();
                assert!(trunc_cols <= eff_cols);
            }
        }
    }

    #[test]
    fn local_echo_rollback_and_json_board_echo_matching() {
        let mut dedup = MessageDedupState::new();
        dedup.reset_for_party(Some(8801));
        let now = Instant::now();

        // Failed send rolls back echo so a retry / Window-1 message is NOT swallowed
        let id = dedup.record_local_echo(EchoKind::Chat, "retry me".to_string(), now);
        dedup.cancel_local_echo(id);
        assert!(!dedup.consume_matching_echo(EchoKind::Chat, "retry me", now));

        // JSON board payload formatted via format_board_payload matches decoded echo
        let raw_json = r#"{"title":"Shipped","summary":"all green"}"#;
        let formatted = format_board_payload(raw_json.as_bytes());
        assert_eq!(formatted, "Shipped — all green");
        let _ = dedup.record_local_echo(EchoKind::Board, formatted.trim().to_string(), now);
        assert!(dedup.consume_matching_echo(EchoKind::Board, "Shipped — all green", now));
    }

    #[test]
    fn validate_share_url_enforces_https_bounds_and_no_whitespace() {
        assert_eq!(
            validate_share_url("https://clank.party/KAIH"),
            Some("https://clank.party/KAIH".to_string())
        );
        assert_eq!(validate_share_url("http://clank.party/KAIH"), None);
        assert_eq!(validate_share_url("javascript:alert(1)"), None);
        assert_eq!(validate_share_url("https://"), None);
        assert_eq!(validate_share_url("https://clank.party/KAIH extra"), None);
        let huge = format!("https://clank.party/{}", "a".repeat(250));
        assert_eq!(validate_share_url(&huge), None);
    }
}
