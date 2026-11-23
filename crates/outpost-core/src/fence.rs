//! Decoded-layer per-response CSPRNG nonce provenance fencing and accidental-secret-disclosure guard.

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD, URL_SAFE as B64U_PAD,
    URL_SAFE_NO_PAD as B64U,
};
use sha2::{Digest as _, Sha256};

/// Sanitizes remote peer text while preserving `\n` (`0x0A`) and `\t` (`0x09`).
/// Strips all other C0, DEL, C1, Unicode line/paragraph separators (`U+2028`, `U+2029`),
/// Unicode BiDi overrides/isolates, zero-width characters, and Unicode Tag characters (`U+E0000..=U+E007F`).
pub fn sanitize_peer_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let cp = ch as u32;
        let keep = match ch {
            '\n' | '\t' => true,
            _ if cp <= 0x1F || cp == 0x7F => false,
            _ if (0x80..=0x9F).contains(&cp) => false,
            // Unicode line/paragraph separators
            '\u{2028}' | '\u{2029}' => false,
            // Unicode BiDi controls & isolates
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}' => false,
            // Zero-width characters & BOM
            '\u{200B}'..='\u{200D}' | '\u{FEFF}' => false,
            // Unicode Tag characters (invisible prompt-injection smuggling)
            '\u{E0000}'..='\u{E007F}' => false,
            _ => true,
        };
        if keep {
            out.push(ch);
        }
    }
    out
}

/// Single O(n) pass that breaks any contiguous run of `>= 3` `<` or `>` characters into
/// space-separated characters (`<<<<<` -> `< < < < <`), while preserving single/double `<`/`>`.
fn break_angle_runs(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '<' || ch == '>' {
            let mut count = 1usize;
            while chars.peek() == Some(&ch) {
                chars.next();
                count += 1;
            }
            if count >= 3 {
                for i in 0..count {
                    if i > 0 {
                        out.push(' ');
                    }
                    out.push(ch);
                }
            } else {
                for _ in 0..count {
                    out.push(ch);
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Wraps untrusted peer text in a per-response CSPRNG nonce fence and deterministically
/// neutralizes any decoded occurrence of `<<<`, `>>>`, or the 16-hex nonce inside the payload.
pub fn fence_peer_text(raw: &str, nonce: u64) -> String {
    let clean = sanitize_peer_text(raw);
    let nonce_lower = format!("{nonce:016x}");
    let neutralized = replace_ascii_case_insensitive(&clean, &nonce_lower, "[redacted-nonce]");
    let neutralized = break_angle_runs(&neutralized);
    format!(
        "<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_{nonce_lower}>>>\n{neutralized}\n<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END_{nonce_lower}>>>"
    )
}

fn replace_ascii_case_insensitive(haystack: &str, needle_lower: &str, replacement: &str) -> String {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return haystack.to_string();
    }
    let hay_bytes = haystack.as_bytes();
    let needle_bytes = needle_lower.as_bytes();
    let nlen = needle_bytes.len();
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0usize;
    while i < hay_bytes.len() {
        let matched = if let Some(win) = hay_bytes.get(i..i + nlen) {
            win.iter()
                .zip(needle_bytes.iter())
                .all(|(h, n)| h.to_ascii_lowercase() == *n)
        } else {
            false
        };
        if matched {
            out.push_str(replacement);
            i += nlen;
        } else {
            let Some(rest) = haystack.get(i..) else {
                break;
            };
            let Some(ch) = rest.chars().next() else {
                break;
            };
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretMatchKind {
    OwnDeviceSecret,
    OwnDeviceCwt,
    InviteToken,
    PrivateKeyPem,
    RecoveryKey,
    DeviceLinkToken,
    RecoveryFile,
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    let Some(&first) = needle.first() else {
        return false;
    };
    let nlen = needle.len();
    if haystack.len() < nlen {
        return false;
    }
    if let (Ok(h), Ok(n)) = (core::str::from_utf8(haystack), core::str::from_utf8(needle)) {
        return h.contains(n);
    }
    let last_start = haystack.len() - nlen;
    let Some(search_area) = haystack.get(..=last_start) else {
        return false;
    };
    for (idx, &b) in search_area.iter().enumerate() {
        if b == first && haystack.get(idx..idx + nlen) == Some(needle) {
            return true;
        }
    }
    false
}

fn contains_subslice_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    let Some(&first) = needle.first() else {
        return false;
    };
    let nlen = needle.len();
    if haystack.len() < nlen {
        return false;
    }
    // Fast prefilter: if the needle contains any case-invariant byte (digit, '-', '_', etc.),
    // check its presence via `contains_subslice` (which uses precompiled `str::contains` on UTF-8).
    if let Some(&anchor) = needle.iter().find(|b| !b.is_ascii_alphabetic())
        && !contains_subslice(haystack, core::slice::from_ref(&anchor))
    {
        return false;
    }
    let first_lo = first.to_ascii_lowercase();
    let first_hi = first.to_ascii_uppercase();
    let last_start = haystack.len() - nlen;
    let Some(search_area) = haystack.get(..=last_start) else {
        return false;
    };
    for (idx, &b) in search_area.iter().enumerate() {
        if (b == first_lo || b == first_hi)
            && haystack
                .get(idx..idx + nlen)
                .is_some_and(|w| w.eq_ignore_ascii_case(needle))
        {
            return true;
        }
    }
    false
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

const fn is_b64u_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn contains_exact_invite_token(haystack: &[u8]) -> bool {
    // Match ASCII case-insensitive `mpinv1_<43+ base64url chars>` or
    // `mppi1_<digits>_<43+ base64url chars>` with non-alphanumeric left boundary.
    const INV_PREFIX: &[u8] = b"mpinv1_";
    const PARTY_INV_PREFIX: &[u8] = b"mppi1_";

    // Both `mpinv1_` and `mppi1_` contain the case-invariant substring `1_`.
    if !contains_subslice(haystack, b"1_") {
        return false;
    }

    for (idx, &b) in haystack.iter().enumerate() {
        if b != b'm' && b != b'M' {
            continue;
        }
        let prev_ok = idx == 0
            || haystack
                .get(idx - 1)
                .is_none_or(|&prev| !prev.is_ascii_alphanumeric());
        if !prev_ok {
            continue;
        }
        if haystack
            .get(idx..idx + INV_PREFIX.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(INV_PREFIX))
        {
            let body_start = idx + INV_PREFIX.len();
            let body_end = body_start + 43;
            if haystack
                .get(body_start..body_end)
                .is_some_and(|s| s.iter().all(|&c| is_b64u_char(c)))
            {
                return true;
            }
        }
        if haystack
            .get(idx..idx + PARTY_INV_PREFIX.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(PARTY_INV_PREFIX))
        {
            let mut p = idx + PARTY_INV_PREFIX.len();
            let digits_start = p;
            while let Some(&d) = haystack.get(p) {
                if d.is_ascii_digit() {
                    p += 1;
                } else {
                    break;
                }
            }
            if p > digits_start && haystack.get(p) == Some(&b'_') {
                let tok_start = p + 1;
                let tok_end = tok_start + 43;
                if haystack
                    .get(tok_start..tok_end)
                    .is_some_and(|s| s.iter().all(|&c| is_b64u_char(c)))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn contains_private_pem_header(haystack: &[u8]) -> bool {
    const PREFIX: &[u8] = b"-----BEGIN ";
    const SUFFIXES: [&[u8]; 3] = [
        b"PRIVATE KEY-----",
        b"RECOVERY KEY-----",
        b"SECRET KEY-----",
    ];
    if haystack.len() < PREFIX.len() || !contains_subslice(haystack, b"-----") {
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
                        && (label.is_empty()
                            || matches!(label.last(), Some(b' ' | b'-')))
                })
            {
                return true;
            }
        }
    }
    false
}

fn matches_secret_bytes(payload: &[u8], secret: &[u8]) -> bool {
    if contains_subslice(payload, secret)
        || contains_subslice_ascii_ci(payload, hex_lower(secret).as_bytes())
        || contains_subslice(payload, B64.encode(secret).as_bytes())
        || contains_subslice(payload, B64_NO_PAD.encode(secret).as_bytes())
        || contains_subslice(payload, B64U_PAD.encode(secret).as_bytes())
        || contains_subslice(payload, B64U.encode(secret).as_bytes())
    {
        return true;
    }

    // Check alignment-invariant inner Base64 slices for offsets 0, 1, and 2 in both
    // standard and URL-safe alphabets so secrets embedded in larger binary blobs before
    // Base64 encoding cannot evade detection via 1/2-byte misalignment or suffix bleed.
    let mut buf = Vec::with_capacity(secret.len() + 2);
    for offset in 0usize..=2 {
        buf.clear();
        buf.resize(offset, 0u8);
        buf.extend_from_slice(secret);
        let start = if offset == 0 { 0 } else { 4 };
        let end = (buf.len() / 3) * 4;
        if end.saturating_sub(start) < 8 {
            continue;
        }
        let std_enc = B64_NO_PAD.encode(&buf);
        if let Some(slice) = std_enc.as_bytes().get(start..end)
            && contains_subslice(payload, slice)
        {
            return true;
        }
        let url_enc = B64U.encode(&buf);
        if let Some(slice) = url_enc.as_bytes().get(start..end)
            && contains_subslice(payload, slice)
        {
            return true;
        }
    }

    false
}

#[inline(always)]
const fn crockford_decode_byte(b: u8) -> Option<u8> {
    match b {
        b'0' | b'O' | b'o' => Some(0),
        b'1' | b'I' | b'i' | b'L' | b'l' => Some(1),
        b'2'..=b'9' => Some(b - b'0'),
        b'A'..=b'H' => Some(b - b'A' + 10),
        b'a'..=b'h' => Some(b - b'a' + 10),
        b'J' | b'j' => Some(18),
        b'K' | b'k' => Some(19),
        b'M' | b'm' => Some(20),
        b'N' | b'n' => Some(21),
        b'P'..=b'T' => Some(b - b'P' + 22),
        b'p'..=b't' => Some(b - b'p' + 22),
        b'V'..=b'Z' => Some(b - b'V' + 27),
        b'v'..=b'z' => Some(b - b'v' + 27),
        _ => None,
    }
}

#[inline(always)]
const fn is_recovery_sep(b: u8) -> bool {
    matches!(b, b'-' | b'_' | b'.' | b',' | b'/' | b':' | b'|') || b.is_ascii_whitespace()
}

enum NormChar {
    Ignore,
    Ascii(u8),
    UnicodeSpace,
    Other,
}

fn classify_recovery_char(ch: char) -> NormChar {
    match ch {
        // Default_Ignorable / zero-width / soft hyphen
        '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{2060}' | '\u{FEFF}' => NormChar::Ignore,
        // Fullwidth ASCII variants U+FF01..=U+FF5E -> ASCII 0x21..=0x7E
        '\u{FF01}'..='\u{FF5E}' => {
            let ascii = u8::try_from((ch as u32) - 0xFF01 + 0x21).unwrap_or(0);
            NormChar::Ascii(ascii)
        }
        // Common Unicode dashes/hyphens folded to ASCII '-'
        '\u{2010}'..='\u{2015}' | '\u{2212}' => NormChar::Ascii(b'-'),
        // Ideographic space
        '\u{3000}' => NormChar::UnicodeSpace,
        c if c.is_ascii() => NormChar::Ascii(u8::try_from(c as u32).unwrap_or(0)),
        c if c.is_whitespace() => NormChar::UnicodeSpace,
        _ => NormChar::Other,
    }
}

#[derive(Clone, Copy)]
struct CrockfordRunSym {
    val: u8,
    norm_pos: usize,
    starts_after_boundary: bool,
    ends_before_boundary: bool,
}

impl CrockfordRunSym {
    const EMPTY: Self = Self {
        val: 0,
        norm_pos: 0,
        starts_after_boundary: false,
        ends_before_boundary: false,
    };
}

/// Real recovery keys have 1 unbroken group or 11 groups of 5 (or up to 16 wrapped/4-char groups),
/// never 19..55 degenerate 1-3 char separated tokens like `"0 0 0 0..."`.
const MAX_RECOVERY_WINDOW_TOKENS: usize = 16;
const MAX_RECOVERY_WINDOW_SPAN: usize = 160;

struct CrockfordRing {
    buf: [CrockfordRunSym; 55],
    head: usize,
    len: usize,
    token_starts: usize,
    at_boundary: bool,
    token_open: bool,
    norm_pos: usize,
}

impl CrockfordRing {
    const fn new() -> Self {
        Self {
            buf: [CrockfordRunSym::EMPTY; 55],
            head: 0,
            len: 0,
            token_starts: 0,
            at_boundary: true,
            token_open: false,
            norm_pos: 0,
        }
    }

    #[inline(always)]
    fn push_sym(&mut self, val: u8) {
        if self.len == 55 {
            if let Some(popped) = self.buf.get(self.head)
                && popped.starts_after_boundary
            {
                self.token_starts = self.token_starts.saturating_sub(1);
            }
            if let Some(slot) = self.buf.get_mut(self.head) {
                *slot = CrockfordRunSym {
                    val,
                    norm_pos: self.norm_pos,
                    starts_after_boundary: self.at_boundary,
                    ends_before_boundary: false,
                };
            }
            self.head += 1;
            if self.head == 55 {
                self.head = 0;
            }
        } else {
            let idx = (self.head + self.len) % 55;
            if let Some(slot) = self.buf.get_mut(idx) {
                *slot = CrockfordRunSym {
                    val,
                    norm_pos: self.norm_pos,
                    starts_after_boundary: self.at_boundary,
                    ends_before_boundary: false,
                };
            }
            self.len += 1;
        }
        if self.at_boundary {
            self.token_starts += 1;
        }
        self.at_boundary = false;
        self.token_open = true;
    }

    #[inline(always)]
    fn close_token_and_check(&mut self) -> bool {
        if !self.token_open {
            return false;
        }
        let back_idx = (self.head + self.len + 54) % 55;
        if let Some(last) = self.buf.get_mut(back_idx) {
            last.ends_before_boundary = true;
        }
        self.token_open = false;
        if self.len != 55 || self.token_starts > MAX_RECOVERY_WINDOW_TOKENS {
            return false;
        }
        self.verify_window()
    }

    fn clear_run(&mut self) {
        self.head = 0;
        self.len = 0;
        self.token_starts = 0;
        self.at_boundary = true;
        self.token_open = false;
    }

    fn verify_window(&self) -> bool {
        let Some(first) = self.buf.get(self.head) else {
            return false;
        };
        let back_idx = if self.head == 0 { 54 } else { self.head - 1 };
        let Some(last) = self.buf.get(back_idx) else {
            return false;
        };
        if !first.starts_after_boundary || !last.ends_before_boundary {
            return false;
        }
        if last.norm_pos.saturating_sub(first.norm_pos) > MAX_RECOVERY_WINDOW_SPAN {
            return false;
        }
        // Canonical 55th Crockford Base32 symbol of a 34-byte recovery payload must have
        // its 3 trailing unused padding bits set to zero (symbol value in {0, 8, 16, 24}).
        if (last.val & 0x07) != 0 {
            return false;
        }
        let first_val = first.val;
        let mut all_identical = true;

        let mut payload = [0u8; 34];
        let mut out_idx = 0usize;
        let mut bit_buf: u32 = 0;
        let mut bit_len: u32 = 0;
        for step in 0..55usize {
            let idx = (self.head + step) % 55;
            let Some(s) = self.buf.get(idx) else {
                mp_protocol::crypto::zeroize_bytes(&mut payload);
                return false;
            };
            if s.val != first_val {
                all_identical = false;
            }
            bit_buf = (bit_buf << 5) | u32::from(s.val);
            bit_len += 5;
            while bit_len >= 8 {
                bit_len -= 8;
                if let Some(slot) = payload.get_mut(out_idx) {
                    *slot = u8::try_from((bit_buf >> bit_len) & 0xff).unwrap_or(0);
                }
                out_idx += 1;
            }
        }
        if all_identical || out_idx != 34 || bit_len != 3 || (bit_buf & 0x07) != 0 {
            mp_protocol::crypto::zeroize_bytes(&mut payload);
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(mp_protocol::RECOVERY_KEY_DOMAIN_SEP.as_bytes());
        if let Some(seed_slice) = payload.get(0..32) {
            hasher.update(seed_slice);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        let matched = payload.get(32) == digest.first() && payload.get(33) == digest.get(1);
        mp_protocol::crypto::zeroize_bytes(&mut payload);
        matched
    }
}

struct PrefixedRecoveryScan {
    prefix_state: u8,
    active: bool,
    lookahead: usize,
    crockford_count: usize,
    distinct_mask: u32,
    distinct_mask_first40: u32,
}

impl PrefixedRecoveryScan {
    const fn new() -> Self {
        Self {
            prefix_state: 0,
            active: false,
            lookahead: 0,
            crockford_count: 0,
            distinct_mask: 0,
            distinct_mask_first40: 0,
        }
    }

    fn reset_all(&mut self) {
        self.prefix_state = 0;
        self.active = false;
    }

    fn feed_unicode_space(&mut self) {
        if self.active {
            self.lookahead += 1;
            if self.lookahead > 256 || self.crockford_count == 0 {
                self.active = false;
            }
        }
        self.prefix_state = 0;
    }

    #[inline(always)]
    fn feed_ascii(&mut self, b: u8) -> bool {
        const MAX_PREFIX_LOOKAHEAD: usize = 256;

        if self.active {
            self.lookahead += 1;
            if self.lookahead > MAX_PREFIX_LOOKAHEAD {
                self.active = false;
            } else if let Some(val) = crockford_decode_byte(b) {
                self.crockford_count += 1;
                let bit = 1u32 << val;
                self.distinct_mask |= bit;
                if self.crockford_count <= 40 {
                    self.distinct_mask_first40 |= bit;
                }
                if (self.crockford_count >= 40 && self.distinct_mask_first40.count_ones() >= 2)
                    || (self.crockford_count == 55 && self.distinct_mask.count_ones() >= 2)
                {
                    return true;
                }
                if self.crockford_count >= 55 {
                    self.active = false;
                }
            } else if is_recovery_sep(b) {
                // Reject space/tab immediately after `mprk1_` so prose like
                // `"The mprk1_ format encodes a 32-byte Ed25519 root key..."` never false-positives.
                if self.crockford_count == 0 && matches!(b, b' ' | b'\t') {
                    self.active = false;
                }
            } else {
                self.active = false;
            }
        }

        // Exact 6-state DFA for ASCII case-insensitive `"mprk1_"` (all 6 bytes distinct).
        let lo = b.to_ascii_lowercase();
        self.prefix_state = match (self.prefix_state, lo) {
            (0, b'm') => 1,
            (1, b'p') => 2,
            (2, b'r') => 3,
            (3, b'k') => 4,
            (4, b'1') => 5,
            (5, b'_') => {
                if !self.active || self.distinct_mask.count_ones() <= 1 {
                    self.active = true;
                    self.lookahead = 0;
                    self.crockford_count = 0;
                    self.distinct_mask = 0;
                    self.distinct_mask_first40 = 0;
                }
                0
            }
            (_, b'm') => 1,
            _ => 0,
        };
        false
    }
}

#[inline(always)]
fn feed_recovery_ascii(
    b: u8,
    prefixed: &mut PrefixedRecoveryScan,
    ring: &mut CrockfordRing,
) -> bool {
    if prefixed.feed_ascii(b) {
        return true;
    }
    if let Some(val) = crockford_decode_byte(b) {
        ring.push_sym(val);
    } else if is_recovery_sep(b) {
        if ring.close_token_and_check() {
            return true;
        }
        ring.at_boundary = true;
    } else {
        if ring.close_token_and_check() {
            return true;
        }
        ring.clear_run();
    }
    ring.norm_pos += 1;
    false
}

/// Detects canonical, lowercase, fullwidth, zero-width-obfuscated, and separator/whitespace-folded
/// `mprk1_...` recovery keys, as well as unprefixed 55-symbol Crockford Base32 recovery keys whose
/// canonical padding and 16-bit SHA-256 checksum verify under `mp-recovery-v1:`.
///
/// Uses a bounded O(1)-memory 55-symbol stack ring buffer and rejects degenerate token-flood inputs
/// (such as `"0 0 0 0..."`) without heap spikes or CPU amplification.
pub fn contains_recovery_key(payload: &[u8]) -> bool {
    let mut prefixed = PrefixedRecoveryScan::new();
    let mut ring = CrockfordRing::new();

    for chunk in payload.utf8_chunks() {
        let valid = chunk.valid();
        if valid.is_ascii() {
            for &b in valid.as_bytes() {
                if feed_recovery_ascii(b, &mut prefixed, &mut ring) {
                    return true;
                }
            }
        } else {
            for ch in valid.chars() {
                match classify_recovery_char(ch) {
                    NormChar::Ignore => {}
                    NormChar::Ascii(b) => {
                        if feed_recovery_ascii(b, &mut prefixed, &mut ring) {
                            return true;
                        }
                    }
                    NormChar::UnicodeSpace => {
                        prefixed.feed_unicode_space();
                        if ring.close_token_and_check() {
                            return true;
                        }
                        ring.at_boundary = true;
                        ring.norm_pos += 1;
                    }
                    NormChar::Other => {
                        prefixed.reset_all();
                        if ring.close_token_and_check() {
                            return true;
                        }
                        ring.clear_run();
                        ring.norm_pos += 1;
                    }
                }
            }
        }

        if !chunk.invalid().is_empty() {
            prefixed.reset_all();
            if ring.close_token_and_check() {
                return true;
            }
            ring.clear_run();
            ring.norm_pos += 1;
        }
    }

    ring.close_token_and_check()
}

/// Detects device-link poll tokens (ASCII case-insensitive `mpdl1_<43+ base64url chars>`
/// with non-alphanumeric left boundary).
pub fn contains_device_link_token(payload: &[u8]) -> bool {
    const PREFIX: &[u8] = b"mpdl1_";
    if payload.len() < PREFIX.len() + 43 || !contains_subslice(payload, b"1_") {
        return false;
    }
    let last_start = payload.len() - (PREFIX.len() + 43);
    let Some(search_area) = payload.get(..=last_start) else {
        return false;
    };
    for (idx, &b) in search_area.iter().enumerate() {
        if b != b'm' && b != b'M' {
            continue;
        }
        let prev_ok = idx == 0
            || payload
                .get(idx - 1)
                .is_none_or(|&prev| !prev.is_ascii_alphanumeric());
        if !prev_ok {
            continue;
        }
        if payload
            .get(idx..idx + PREFIX.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(PREFIX))
        {
            let body_start = idx + PREFIX.len();
            let body_end = body_start + 43;
            if payload
                .get(body_start..body_end)
                .is_some_and(|s| s.iter().all(|&c| is_b64u_char(c)))
            {
                return true;
            }
        }
    }
    false
}

fn ring_matches_exact<const N: usize>(ring: &[u8; N], end_pos: usize, needle: &[u8; N]) -> bool {
    for (i, &expected) in needle.iter().enumerate() {
        let idx = (end_pos + i) % N;
        if ring.get(idx) != Some(&expected) {
            return false;
        }
    }
    true
}

fn ring_matches_ascii_ci<const N: usize>(ring: &[u8; N], end_pos: usize, needle: &[u8; N]) -> bool {
    for (i, &expected) in needle.iter().enumerate() {
        let idx = (end_pos + i) % N;
        if !ring.get(idx).is_some_and(|b| b.eq_ignore_ascii_case(&expected)) {
            return false;
        }
    }
    true
}

/// Detects portable encrypted `.mpkey` recovery files via case-insensitive PEM header/footer
/// (`-----BEGIN/END MULTIPLAYER RECOVERY KEY-----`), raw binary magic (`MPKEY1\0\0`),
/// case-insensitive hex magic (`4d504b4559310000`, contiguous or whitespace-separated),
/// or standard/URL-safe Base64 encodings of `MPKEY1\0\0` at 0/1/2-byte alignment offsets
/// (including line-wrapped / whitespace-split Base64 such as `base64 -w64`).
pub fn contains_recovery_file(payload: &[u8]) -> bool {
    const PEM_HEADER: &[u8] = b"-----BEGIN MULTIPLAYER RECOVERY KEY-----";
    const PEM_FOOTER: &[u8] = b"-----END MULTIPLAYER RECOVERY KEY-----";
    const RAW_MAGIC: &[u8] = b"MPKEY1\0\0";
    const HEX_MAGIC: &[u8; 16] = b"4d504b4559310000";
    // Alignment-invariant 10-char Base64 slices for `b"MPKEY1\0\0"` (identical in standard & URL-safe alphabets):
    // offset 0: B64("MPKEY1\0\0" || ..)        -> "TVBLRVkxAA.."
    // offset 1: B64(xx || "MPKEY1\0\0" || ..)  -> "..1QS0VZMQAA.."
    // offset 2: B64(xx || yy || "MPKEY1\0\0")  -> "...NUEtFWTEAA.."
    const B64_MAGIC_OFF0: &[u8; 10] = b"TVBLRVkxAA";
    const B64_MAGIC_OFF1: &[u8; 10] = b"1QS0VZMQAA";
    const B64_MAGIC_OFF2: &[u8; 10] = b"NUEtFWTEAA";

    if contains_subslice(payload, b"-----")
        && (contains_subslice_ascii_ci(payload, PEM_HEADER)
            || contains_subslice_ascii_ci(payload, PEM_FOOTER))
    {
        return true;
    }
    if contains_subslice(payload, RAW_MAGIC) {
        return true;
    }
    // Every Base64 magic needle contains `'A'` and the hex magic (`4d504b4559310000`) contains `'1'`.
    if !contains_subslice(payload, b"A") && !contains_subslice(payload, b"1") {
        return false;
    }

    // Single O(n) circular-ring pass stripping ASCII whitespace (`' '`, `'\t'`, `'\r'`, `'\n'`)
    // to catch wrapped Base64 (`base64 -w64`) and contiguous or spaced hex (`4d504b4559310000`).
    let mut b64_ring = [0u8; 10];
    let mut b64_pos = 0usize;
    let mut b64_filled = 0usize;
    let mut hex_ring = [0u8; 16];
    let mut hex_pos = 0usize;
    let mut hex_filled = 0usize;

    for &b in payload {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if let Some(slot) = b64_ring.get_mut(b64_pos) {
            *slot = b;
        }
        b64_pos += 1;
        if b64_pos == 10 {
            b64_pos = 0;
        }
        if b64_filled < 10 {
            b64_filled += 1;
        }
        // All 3 Base64 needles end with `b'A'`.
        if b == b'A'
            && b64_filled == 10
            && (ring_matches_exact(&b64_ring, b64_pos, B64_MAGIC_OFF0)
                || ring_matches_exact(&b64_ring, b64_pos, B64_MAGIC_OFF1)
                || ring_matches_exact(&b64_ring, b64_pos, B64_MAGIC_OFF2))
        {
            return true;
        }

        if let Some(slot) = hex_ring.get_mut(hex_pos) {
            *slot = b;
        }
        hex_pos += 1;
        if hex_pos == 16 {
            hex_pos = 0;
        }
        if hex_filled < 16 {
            hex_filled += 1;
        }
        // `4d504b4559310000` ends with `10000`, so gate on `b == b'0'` and `'1'` 4 bytes earlier.
        if b == b'0'
            && hex_filled == 16
            && hex_ring.get((hex_pos + 11) % 16) == Some(&b'1')
            && ring_matches_ascii_ci(&hex_ring, hex_pos, HEX_MAGIC)
        {
            return true;
        }
    }

    false
}

/// Accidental-disclosure guard for outbound chat & board payloads:
/// 1. Exact-matches our own `device_secret` and `device_cwt` across raw, hex (case-insensitive),
///    standard/URL-safe base64 (padded & unpadded), plus alignment-invariant inner base64 chunks
///    for 0/1/2-byte offsets (zero false positives).
/// 2. Refuses exact-grammar `mpinv1_` / `mppi1_` invite tokens, `mpdl1_` device-link tokens,
///    `.mpkey` recovery files (PEM / raw / base64), `mprk1_` & unprefixed checksum-verified
///    recovery keys, and `-----BEGIN * PRIVATE KEY-----`.
pub fn scan_outbound_secrets(
    payload: &[u8],
    own_device_secret: &[u8; 32],
    own_device_cwt: &[u8],
) -> Option<SecretMatchKind> {
    // 1. Own device_secret (raw, hex ci, b64 variants, misaligned b64 chunks)
    if matches_secret_bytes(payload, own_device_secret) {
        return Some(SecretMatchKind::OwnDeviceSecret);
    }

    // 2. Own device_cwt (when non-trivial length >= 8)
    if own_device_cwt.len() >= 8 && matches_secret_bytes(payload, own_device_cwt) {
        return Some(SecretMatchKind::OwnDeviceCwt);
    }

    // 3. Exact-grammar invite tokens
    if contains_exact_invite_token(payload) {
        return Some(SecretMatchKind::InviteToken);
    }

    // 4. Exact-grammar device-link poll tokens (`mpdl1_<43 b64u>`)
    if contains_device_link_token(payload) {
        return Some(SecretMatchKind::DeviceLinkToken);
    }

    // 5. Portable `.mpkey` recovery files (PEM header, raw magic, Base64 magic)
    if contains_recovery_file(payload) {
        return Some(SecretMatchKind::RecoveryFile);
    }

    // 6. Recovery keys (`mprk1_...`, space/newline-folded, and unprefixed checksum-verified 55-char Crockford)
    if contains_recovery_key(payload) {
        return Some(SecretMatchKind::RecoveryKey);
    }

    // 7. Private key PEM headers
    if contains_private_pem_header(payload) {
        return Some(SecretMatchKind::PrivateKeyPem);
    }

    None
}
