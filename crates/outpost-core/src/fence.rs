//! Decoded-layer per-response CSPRNG nonce provenance fencing and accidental-secret-disclosure guard.

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD, URL_SAFE as B64U_PAD,
    URL_SAFE_NO_PAD as B64U,
};

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
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn contains_subslice_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
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
    // Match `mpinv1_<43 base64url chars>`
    for (idx, win) in haystack.windows(7).enumerate() {
        if win == b"mpinv1_" {
            let prev_ok = idx == 0
                || haystack
                    .get(idx - 1)
                    .map(|&b| !is_b64u_char(b))
                    .unwrap_or(true);
            let body_end = idx + 7 + 43;
            let body_ok = haystack
                .get(idx + 7..body_end)
                .map(|s| s.iter().all(|&b| is_b64u_char(b)))
                .unwrap_or(false);
            let next_ok = haystack
                .get(body_end)
                .map(|&b| !is_b64u_char(b))
                .unwrap_or(true);
            if prev_ok && body_ok && next_ok {
                return true;
            }
        }
    }
    // Match `mppi1_<digits>_<43 base64url chars>`
    for (idx, win) in haystack.windows(6).enumerate() {
        if win == b"mppi1_" {
            let prev_ok = idx == 0
                || haystack
                    .get(idx - 1)
                    .map(|&b| !is_b64u_char(b))
                    .unwrap_or(true);
            if !prev_ok {
                continue;
            }
            let mut p = idx + 6;
            let digits_start = p;
            while let Some(&b) = haystack.get(p) {
                if b.is_ascii_digit() {
                    p += 1;
                } else {
                    break;
                }
            }
            if p == digits_start || haystack.get(p) != Some(&b'_') {
                continue;
            }
            let tok_start = p + 1;
            let tok_end = tok_start + 43;
            let body_ok = haystack
                .get(tok_start..tok_end)
                .map(|s| s.iter().all(|&b| is_b64u_char(b)))
                .unwrap_or(false);
            let next_ok = haystack
                .get(tok_end)
                .map(|&b| !is_b64u_char(b))
                .unwrap_or(true);
            if body_ok && next_ok {
                return true;
            }
        }
    }
    false
}

fn contains_private_pem_header(haystack: &[u8]) -> bool {
    const PREFIX: &[u8] = b"-----BEGIN ";
    const SUFFIX: &[u8] = b"PRIVATE KEY-----";
    for (idx, win) in haystack.windows(PREFIX.len()).enumerate() {
        if win != PREFIX {
            continue;
        }
        let scan_start = idx + PREFIX.len();
        let scan_limit = (scan_start + 48).min(haystack.len());
        if let Some(window) = haystack.get(scan_start..scan_limit)
            && let Some(pos) = window.windows(SUFFIX.len()).position(|w| w == SUFFIX)
            && window
                .get(0..pos)
                .map(|label| label.iter().all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' '))
                .unwrap_or(false)
        {
            return true;
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

/// Accidental-disclosure guard for outbound chat & board payloads:
/// 1. Exact-matches our own `device_secret` and `device_cwt` across raw, hex (case-insensitive),
///    standard/URL-safe base64 (padded & unpadded), plus alignment-invariant inner base64 chunks
///    for 0/1/2-byte offsets (zero false positives).
/// 2. Refuses exact-grammar `mpinv1_` / `mppi1_` invite tokens and `-----BEGIN * PRIVATE KEY-----`.
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

    // 4. Private key PEM headers
    if contains_private_pem_header(payload) {
        return Some(SecretMatchKind::PrivateKeyPem);
    }

    None
}
