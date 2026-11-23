//! Bit-exact `mp1-lan/1` LAN Party Protocol & RFC 6762/6763 `_mp1-lan._udp.local.` mDNS Wire Core.
//!
//! Cross-verified against Blackbird `v0.3.0`:
//! - `include/blackbird/lan_party_protocol.hpp` / `src/lan_party_protocol.cpp`
//! - `include/blackbird/lan_mdns.hpp` / `src/lan_mdns.cpp`

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mp_protocol::{MAX_SAFE_ID, compute_safety_number, validate_ed25519_pubkey_strict};
use zeroize::Zeroizing;

use crate::p2p_wire::P2pLane;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

pub const LAN_PIN_DERIVE_CONTEXT: &str = "mp1-lan-pin-v1";
pub const LAN_JOIN_PROOF_DOMAIN: &str = "mp1-lan-join";
pub const LAN_PIN_MAX_BYTES: usize = 64;
pub const LAN_PARTY_ID_BYTES: usize = 8;
pub const LAN_PARTY_ID_HEX_LEN: usize = 16;
pub const LAN_NONCE_BYTES: usize = 32;
pub const LAN_PIN_PROOF_BYTES: usize = 32;

pub const DEFAULT_LAN_IDLE_TIMEOUT_SEC: u32 = 300;
pub const MAX_LAN_IDLE_TIMEOUT_SEC: u32 = 1800;
pub const DEFAULT_LAN_SCAN_TIMEOUT_SEC: u32 = 15;
pub const MAX_LAN_SCAN_TIMEOUT_SEC: u32 = 60;
pub const DEFAULT_SYSTEM_LAN_POLICY_PATH: &str = "/etc/multiplayer/lan.toml";
pub const MAX_LAN_POLICY_FILE_BYTES: usize = 16 * 1024;

pub const LAN_HANDSHAKE_VERSION: u8 = 1;
pub const LAN_HANDSHAKE_HEADER_BYTES: usize = 4;
pub const LAN_MAX_NAME_BYTES: usize = 32;
pub const LAN_MAX_MEMBERS: usize = 12;
pub const LAN_MAX_REJECT_REASON_BYTES: usize = 128;
pub const LAN_HANDSHAKE_MAX_FRAME_BYTES: usize = 65536;

pub const LAN_PIN_MAX_PEER_FAILURES: u32 = 5;
pub const LAN_PIN_MAX_LOBBY_FAILURES: u32 = 15;

pub const LAN_MDNS_SERVICE_TYPE: &str = "_mp1-lan._udp.local.";
pub const LAN_MDNS_LOCAL_DOMAIN: &str = ".local.";
pub const LAN_MDNS_MULTICAST_GROUP: &str = "224.0.0.251";
pub const LAN_MDNS_DEFAULT_PORT: u16 = 5353;
pub const LAN_BEACON_VERSION: u32 = 1;
pub const LAN_BEACON_ALPN: &str = "blackbird-mp/1";
pub const LAN_PUBKEY_B64URL_LEN: usize = 43;
pub const LAN_MAX_TXT_BYTES: usize = 256;
pub const LAN_MDNS_MAX_PACKET_BYTES: usize = 4096;
pub const LAN_MDNS_MAX_NAME_LENGTH: usize = 255;
pub const LAN_MDNS_MAX_LABEL_LENGTH: usize = 63;
pub const LAN_MDNS_MAX_NAME_JUMPS: usize = 16;
pub const LAN_MDNS_MAX_RECORDS_PER_PACKET: usize = 128;
pub const LAN_MDNS_DEFAULT_TTL_SEC: u32 = 120;
pub const LAN_MDNS_MAX_DIRECT_ADDRS: usize = 8;

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_MASK: u16 = 0x7fff;
pub const DNS_CLASS_UNICAST_OR_FLUSH: u16 = 0x8000;

const DNS_HEADER_BYTES: usize = 12;
const MAX_DIRECT_TARGET_BYTES: usize = 64;
const JSON_MAX_NODES: usize = 1024;
const JSON_MAX_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanProtocolError {
    // Cryptography & PIN proofs
    InvalidPin,
    InvalidLanPartyId,
    InvalidPubkey,
    InvalidAccountId,
    InvalidDisplayName,

    // Policy TOML
    PolicyParseError,

    // In-TLS Lane-0 handshake framing
    FrameTooLarge,
    FrameTruncated,
    FrameUnsupportedVersion,
    FrameUnknownKind,
    FrameNonZeroReserved,
    FrameLaneMismatch,
    FrameInvalidUtf8,
    FrameInvalidJson,
    FrameInvalidField,
    FrameTooManyMembers,

    // Beacon & TXT codec
    BeaconInvalidVersion,
    BeaconInvalidPartyId,
    BeaconInvalidLobbyName,
    BeaconInvalidHostName,
    BeaconInvalidPubkey,
    BeaconInvalidPinFlag,
    BeaconInvalidAlpn,
    TxtTooLarge,
    TxtMalformed,
    TxtDuplicateKey,
    TxtMissingKey,
    TxtUnknownKey,

    // DNS / mDNS wire codec
    DnsTruncated,
    DnsMalformedHeader,
    DnsNameTooLong,
    DnsLabelTooLong,
    DnsPointerLoop,
    DnsPointerOob,
    DnsInvalidRecord,
    DnsPacketTooLarge,
    InvalidPort,

    // Direct target parser
    InvalidDirectTarget,
}

impl fmt::Display for LanProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LanProtocolError {}

// ---------------------------------------------------------------------------
// Shared validation & hex helpers
// ---------------------------------------------------------------------------

const fn is_printable_ascii_byte(b: u8) -> bool {
    matches!(b, 0x20..=0x7e)
}

const fn is_disallowed_pin_char(ch: char) -> bool {
    let cp = ch as u32;
    matches!(
        cp,
        0x00..=0x1f
            | 0x7f..=0x9f
            | 0x200e
            | 0x200f
            | 0x202a..=0x202e
            | 0x2066..=0x2069
            | 0xfeff
            | 0xe0000..=0xe007f
    )
}

const fn hex_nibble_lower(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        _ => None,
    }
}

fn parse_exact_hex_lower<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let bytes = hex.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble_lower(*bytes.get(i * 2)?)?;
        let lo = hex_nibble_lower(*bytes.get(i * 2 + 1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        if let (Some(&hi), Some(&lo)) = (
            HEX.get(usize::from(b >> 4)),
            HEX.get(usize::from(b & 0x0f)),
        ) {
            out.push(char::from(hi));
            out.push(char::from(lo));
        }
    }
    out
}

pub fn is_valid_lan_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > LAN_MAX_NAME_BYTES {
        return false;
    }
    if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') {
        return false;
    }
    bytes.iter().all(|&b| is_printable_ascii_byte(b))
}

pub fn sanitize_lan_display_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(LAN_MAX_NAME_BYTES));
    for b in raw.bytes() {
        if is_printable_ascii_byte(b) {
            out.push(char::from(b));
        }
    }
    let trimmed = out.trim_matches(' ');
    let truncated = if trimmed.len() > LAN_MAX_NAME_BYTES {
        trimmed
            .get(0..LAN_MAX_NAME_BYTES)
            .unwrap_or("")
            .trim_end_matches(' ')
    } else {
        trimmed
    };
    if truncated.is_empty() {
        "lan-player".to_string()
    } else {
        truncated.to_string()
    }
}

fn is_valid_reason_text(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() <= LAN_MAX_REJECT_REASON_BYTES && bytes.iter().all(|&b| is_printable_ascii_byte(b))
}

fn is_valid_beacon_display_text(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > LAN_MAX_NAME_BYTES {
        return false;
    }
    let mut has_non_space = false;
    for &b in bytes {
        if !is_printable_ascii_byte(b) {
            return false;
        }
        if b != b' ' {
            has_non_space = true;
        }
    }
    has_non_space
}

// ---------------------------------------------------------------------------
// 1. BLAKE3 PIN Challenge-Response & Canonical Safety Number
// ---------------------------------------------------------------------------

/// Validates a PIN for `mp1-lan/1`: 1..=64 UTF-8 bytes, no C0/DEL/C1/BiDi/BOM/Tag controls.
pub fn validate_lan_pin(pin: &str) -> Result<(), LanProtocolError> {
    if pin.is_empty() || pin.len() > LAN_PIN_MAX_BYTES {
        return Err(LanProtocolError::InvalidPin);
    }
    if pin.chars().any(is_disallowed_pin_char) {
        return Err(LanProtocolError::InvalidPin);
    }
    Ok(())
}

/// Parses a strict 16-char lowercase hex `lan_party_id`.
pub fn parse_lan_party_id_hex(hex: &str) -> Result<[u8; LAN_PARTY_ID_BYTES], LanProtocolError> {
    parse_exact_hex_lower::<LAN_PARTY_ID_BYTES>(hex).ok_or(LanProtocolError::InvalidLanPartyId)
}

/// Formats an 8-byte `lan_party_id` as 16 lowercase hex chars.
pub fn format_lan_party_id_hex(id: &[u8; LAN_PARTY_ID_BYTES]) -> String {
    encode_hex_lower(id)
}

/// Computes the `mp1-lan/1` BLAKE3 PIN challenge-response proof:
/// - `key = blake3::derive_key("mp1-lan-pin-v1", pin_nfc.as_bytes())`
/// - `msg = b"mp1-lan-join" || lan_party_id(8B) || host_pubkey(32B) || joiner_pubkey(32B) || host_nonce(32B)`
/// - `proof = blake3::keyed_hash(&key, &msg)`
pub fn compute_lan_pin_proof(
    pin_nfc: &str,
    lan_party_id_hex: &str,
    host_pubkey: &[u8; 32],
    joiner_pubkey: &[u8; 32],
    host_nonce: &[u8; LAN_NONCE_BYTES],
) -> Result<[u8; LAN_PIN_PROOF_BYTES], LanProtocolError> {
    validate_lan_pin(pin_nfc)?;
    let party_id = parse_lan_party_id_hex(lan_party_id_hex)?;

    let key = Zeroizing::new(blake3::derive_key(
        LAN_PIN_DERIVE_CONTEXT,
        pin_nfc.as_bytes(),
    ));

    let mut msg = Zeroizing::new([0u8; 116]);
    if let Some(dst) = msg.get_mut(0..12) {
        dst.copy_from_slice(LAN_JOIN_PROOF_DOMAIN.as_bytes());
    }
    if let Some(dst) = msg.get_mut(12..20) {
        dst.copy_from_slice(&party_id);
    }
    if let Some(dst) = msg.get_mut(20..52) {
        dst.copy_from_slice(host_pubkey);
    }
    if let Some(dst) = msg.get_mut(52..84) {
        dst.copy_from_slice(joiner_pubkey);
    }
    if let Some(dst) = msg.get_mut(84..116) {
        dst.copy_from_slice(host_nonce);
    }

    Ok(*blake3::keyed_hash(&key, &*msg).as_bytes())
}

/// Constant-time verification of a `mp1-lan/1` BLAKE3 PIN proof, zeroizing the expected proof on exit.
pub fn verify_lan_pin_proof(
    pin_nfc: &str,
    lan_party_id_hex: &str,
    host_pubkey: &[u8; 32],
    joiner_pubkey: &[u8; 32],
    host_nonce: &[u8; LAN_NONCE_BYTES],
    provided_proof: &[u8; LAN_PIN_PROOF_BYTES],
) -> Result<bool, LanProtocolError> {
    let expected = Zeroizing::new(compute_lan_pin_proof(
        pin_nfc,
        lan_party_id_hex,
        host_pubkey,
        joiner_pubkey,
        host_nonce,
    )?);
    let mut diff = 0u8;
    for (&a, &b) in expected.iter().zip(provided_proof.iter()) {
        diff |= a ^ b;
    }
    Ok(core::hint::black_box(diff) == 0)
}

/// Computes the canonical 39-char Crockford Base32 Safety Number (`XXXX-XXXX-...-XXXX`)
/// for BOTH `account_id == 0` (local-only LAN identity) and `account_id in 1..=MAX_SAFE_ID`.
pub fn compute_lan_safety_number(
    account_id: u64,
    pubkey: &[u8; 32],
) -> Result<String, LanProtocolError> {
    if account_id > MAX_SAFE_ID {
        return Err(LanProtocolError::InvalidAccountId);
    }
    validate_ed25519_pubkey_strict(pubkey).map_err(|_| LanProtocolError::InvalidPubkey)?;
    Ok(compute_safety_number(account_id, pubkey))
}

// ---------------------------------------------------------------------------
// 2. Strict RFC 8259 JSON Codec (rejects duplicate keys, trailing data, floats)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum StrictJsonValue {
    Null,
    Bool(bool),
    U64(u64),
    Str(String),
    Array(Vec<StrictJsonValue>),
    Object(Vec<(String, StrictJsonValue)>),
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
}

impl<'a> JsonParser<'a> {
    const fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
            nodes: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn bump_node(&mut self) -> Result<(), LanProtocolError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > JSON_MAX_NODES {
            return Err(LanProtocolError::FrameInvalidJson);
        }
        Ok(())
    }

    fn parse_root(&mut self) -> Result<StrictJsonValue, LanProtocolError> {
        self.skip_ws();
        let val = self.parse_value(0)?;
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(LanProtocolError::FrameInvalidJson);
        }
        Ok(val)
    }

    fn parse_value(&mut self, depth: usize) -> Result<StrictJsonValue, LanProtocolError> {
        if depth > JSON_MAX_DEPTH {
            return Err(LanProtocolError::FrameInvalidJson);
        }
        self.bump_node()?;
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(StrictJsonValue::Str),
            Some(b't') => self.parse_literal(b"true", StrictJsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", StrictJsonValue::Bool(false)),
            Some(b'n') => self.parse_literal(b"null", StrictJsonValue::Null),
            Some(b'0'..=b'9') => self.parse_u64().map(StrictJsonValue::U64),
            _ => Err(LanProtocolError::FrameInvalidJson),
        }
    }

    fn parse_literal(
        &mut self,
        expected: &[u8],
        val: StrictJsonValue,
    ) -> Result<StrictJsonValue, LanProtocolError> {
        let end = self
            .pos
            .checked_add(expected.len())
            .ok_or(LanProtocolError::FrameInvalidJson)?;
        if self.bytes.get(self.pos..end) == Some(expected) {
            self.pos = end;
            Ok(val)
        } else {
            Err(LanProtocolError::FrameInvalidJson)
        }
    }

    fn parse_u64(&mut self) -> Result<u64, LanProtocolError> {
        let start = self.pos;
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(LanProtocolError::FrameInvalidJson);
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(LanProtocolError::FrameInvalidJson),
        }
        // Reject floats/exponents cleanly (handshake schema only uses non-negative integers).
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(LanProtocolError::FrameInvalidField);
        }
        let slice = self
            .bytes
            .get(start..self.pos)
            .ok_or(LanProtocolError::FrameInvalidJson)?;
        let s = core::str::from_utf8(slice).map_err(|_| LanProtocolError::FrameInvalidJson)?;
        s.parse::<u64>().map_err(|_| LanProtocolError::FrameInvalidField)
    }

    fn parse_hex4(&mut self) -> Result<u16, LanProtocolError> {
        let mut val = 0u16;
        for _ in 0..4 {
            let b = self.peek().ok_or(LanProtocolError::FrameInvalidJson)?;
            self.pos += 1;
            let nib = match b {
                b'0'..=b'9' => u16::from(b - b'0'),
                b'a'..=b'f' => u16::from(10 + (b - b'a')),
                b'A'..=b'F' => u16::from(10 + (b - b'A')),
                _ => return Err(LanProtocolError::FrameInvalidJson),
            };
            val = (val << 4) | nib;
        }
        Ok(val)
    }

    fn parse_string(&mut self) -> Result<String, LanProtocolError> {
        if self.peek() != Some(b'"') {
            return Err(LanProtocolError::FrameInvalidJson);
        }
        self.pos += 1;
        let mut out = String::new();
        while let Some(b) = self.peek() {
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = self.peek().ok_or(LanProtocolError::FrameInvalidJson)?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                return Err(LanProtocolError::FrameInvalidJson);
                            }
                            self.pos += 2;
                            let low = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(LanProtocolError::FrameInvalidJson);
                            }
                            let combined = 0x1_0000
                                + ((u32::from(code) - 0xD800) << 10)
                                + (u32::from(low) - 0xDC00);
                            let ch = char::from_u32(combined)
                                .ok_or(LanProtocolError::FrameInvalidJson)?;
                            out.push(ch);
                        } else if (0xDC00..=0xDFFF).contains(&code) {
                            return Err(LanProtocolError::FrameInvalidJson);
                        } else {
                            let ch = char::from_u32(u32::from(code))
                                .ok_or(LanProtocolError::FrameInvalidJson)?;
                            out.push(ch);
                        }
                    }
                    _ => return Err(LanProtocolError::FrameInvalidJson),
                }
            } else if b < 0x20 {
                return Err(LanProtocolError::FrameInvalidJson);
            } else if b < 0x80 {
                self.pos += 1;
                out.push(char::from(b));
            } else {
                // Input was validated as UTF-8, slice next scalar.
                let rest = self
                    .bytes
                    .get(self.pos..)
                    .ok_or(LanProtocolError::FrameInvalidJson)?;
                let rest_str =
                    core::str::from_utf8(rest).map_err(|_| LanProtocolError::FrameInvalidUtf8)?;
                let ch = rest_str
                    .chars()
                    .next()
                    .ok_or(LanProtocolError::FrameInvalidJson)?;
                self.pos += ch.len_utf8();
                out.push(ch);
            }
        }
        Err(LanProtocolError::FrameInvalidJson)
    }

    fn parse_array(&mut self, depth: usize) -> Result<StrictJsonValue, LanProtocolError> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(StrictJsonValue::Array(items));
        }
        loop {
            let item = self.parse_value(depth)?;
            items.push(item);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(StrictJsonValue::Array(items));
                }
                _ => return Err(LanProtocolError::FrameInvalidJson),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<StrictJsonValue, LanProtocolError> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(StrictJsonValue::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(LanProtocolError::FrameInvalidJson);
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(LanProtocolError::FrameInvalidJson);
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(StrictJsonValue::Object(entries));
                }
                _ => return Err(LanProtocolError::FrameInvalidJson),
            }
        }
    }
}

fn append_json_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn dump_json_value(out: &mut String, v: &StrictJsonValue) {
    match v {
        StrictJsonValue::Null => out.push_str("null"),
        StrictJsonValue::Bool(true) => out.push_str("true"),
        StrictJsonValue::Bool(false) => out.push_str("false"),
        StrictJsonValue::U64(n) => {
            use core::fmt::Write as _;
            let _ = write!(out, "{n}");
        }
        StrictJsonValue::Str(s) => append_json_escaped_str(out, s),
        StrictJsonValue::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                dump_json_value(out, item);
            }
            out.push(']');
        }
        StrictJsonValue::Object(entries) => {
            out.push('{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                append_json_escaped_str(out, k);
                out.push(':');
                dump_json_value(out, val);
            }
            out.push('}');
        }
    }
}

fn check_allowed_unique_keys(
    obj: &[(String, StrictJsonValue)],
    allowed: &[&str],
) -> Result<(), LanProtocolError> {
    let mut seen = BTreeSet::new();
    for (k, _) in obj {
        if !allowed.contains(&k.as_str()) {
            return Err(LanProtocolError::FrameInvalidField);
        }
        if !seen.insert(k.as_str()) {
            return Err(LanProtocolError::FrameInvalidField);
        }
    }
    Ok(())
}

fn find_field<'a>(obj: &'a [(String, StrictJsonValue)], key: &str) -> Option<&'a StrictJsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn get_required_string<'a>(
    obj: &'a [(String, StrictJsonValue)],
    key: &str,
) -> Result<&'a str, LanProtocolError> {
    match find_field(obj, key) {
        Some(StrictJsonValue::Str(s)) => Ok(s.as_str()),
        _ => Err(LanProtocolError::FrameInvalidField),
    }
}

fn get_required_bool(
    obj: &[(String, StrictJsonValue)],
    key: &str,
) -> Result<bool, LanProtocolError> {
    match find_field(obj, key) {
        Some(StrictJsonValue::Bool(b)) => Ok(*b),
        _ => Err(LanProtocolError::FrameInvalidField),
    }
}

fn get_required_safe_u64(
    obj: &[(String, StrictJsonValue)],
    key: &str,
) -> Result<u64, LanProtocolError> {
    match find_field(obj, key) {
        Some(StrictJsonValue::U64(n)) if *n <= MAX_SAFE_ID => Ok(*n),
        _ => Err(LanProtocolError::FrameInvalidField),
    }
}

// ---------------------------------------------------------------------------
// 3. In-TLS Lane-0 Handshake Framing (`0x10..=0x13`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LanHandshakeKind {
    LanHello = 0x10,
    LanJoin = 0x11,
    LanWelcome = 0x12,
    LanRoster = 0x13,
}

impl LanHandshakeKind {
    pub const fn from_u8(v: u8) -> Result<Self, LanProtocolError> {
        match v {
            0x10 => Ok(Self::LanHello),
            0x11 => Ok(Self::LanJoin),
            0x12 => Ok(Self::LanWelcome),
            0x13 => Ok(Self::LanRoster),
            _ => Err(LanProtocolError::FrameUnknownKind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanMemberInfo {
    pub account_id: u64,
    pub display_name: String,
    pub pubkey: [u8; 32],
    pub is_host: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanHelloMessage {
    pub lan_party_id: String,
    pub lobby_name: String,
    pub host_name: String,
    pub host_account_id: u64,
    pub host_pubkey: [u8; 32],
    pub require_pin: bool,
    pub host_nonce: [u8; LAN_NONCE_BYTES],
    pub max_members: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanJoinMessage {
    pub lan_party_id: String,
    pub display_name: String,
    pub account_id: u64,
    pub pin_proof: Option<[u8; LAN_PIN_PROOF_BYTES]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanWelcomeMessage {
    pub lan_party_id: String,
    pub accepted: bool,
    pub reason: String,
    pub roster_epoch: u64,
    pub members: Vec<LanMemberInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanRosterMessage {
    pub lan_party_id: String,
    pub roster_epoch: u64,
    pub locked: bool,
    pub members: Vec<LanMemberInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanHandshakeMessage {
    Hello(LanHelloMessage),
    Join(LanJoinMessage),
    Welcome(LanWelcomeMessage),
    Roster(LanRosterMessage),
}

impl LanHandshakeMessage {
    pub const fn kind(&self) -> LanHandshakeKind {
        match self {
            Self::Hello(_) => LanHandshakeKind::LanHello,
            Self::Join(_) => LanHandshakeKind::LanJoin,
            Self::Welcome(_) => LanHandshakeKind::LanWelcome,
            Self::Roster(_) => LanHandshakeKind::LanRoster,
        }
    }
}

pub fn is_lan_handshake_frame(bytes: &[u8]) -> bool {
    bytes.len() >= LAN_HANDSHAKE_HEADER_BYTES
        && bytes.first() == Some(&LAN_HANDSHAKE_VERSION)
        && matches!(bytes.get(1), Some(0x10..=0x13))
}

fn validate_member_info(member: &LanMemberInfo) -> Result<(), LanProtocolError> {
    if member.account_id > MAX_SAFE_ID {
        return Err(LanProtocolError::FrameInvalidField);
    }
    if !is_valid_lan_name(&member.display_name) {
        return Err(LanProtocolError::FrameInvalidField);
    }
    validate_ed25519_pubkey_strict(&member.pubkey).map_err(|_| LanProtocolError::InvalidPubkey)?;
    Ok(())
}

fn validate_member_list(
    members: &[LanMemberInfo],
    allow_empty: bool,
) -> Result<(), LanProtocolError> {
    if !allow_empty && members.is_empty() {
        return Err(LanProtocolError::FrameInvalidField);
    }
    if members.len() > LAN_MAX_MEMBERS {
        return Err(LanProtocolError::FrameTooManyMembers);
    }
    let mut seen_pubkeys = BTreeSet::new();
    for m in members {
        validate_member_info(m)?;
        if !seen_pubkeys.insert(m.pubkey) {
            return Err(LanProtocolError::FrameInvalidField);
        }
    }
    Ok(())
}

fn member_to_json(member: &LanMemberInfo) -> StrictJsonValue {
    StrictJsonValue::Object(vec![
        ("account_id".to_string(), StrictJsonValue::U64(member.account_id)),
        (
            "display_name".to_string(),
            StrictJsonValue::Str(member.display_name.clone()),
        ),
        (
            "pubkey".to_string(),
            StrictJsonValue::Str(encode_hex_lower(&member.pubkey)),
        ),
        ("is_host".to_string(), StrictJsonValue::Bool(member.is_host)),
    ])
}

fn member_from_json(val: &StrictJsonValue) -> Result<LanMemberInfo, LanProtocolError> {
    let StrictJsonValue::Object(obj) = val else {
        return Err(LanProtocolError::FrameInvalidField);
    };
    check_allowed_unique_keys(obj, &["account_id", "display_name", "pubkey", "is_host"])?;
    let account_id = get_required_safe_u64(obj, "account_id")?;
    let display_name = get_required_string(obj, "display_name")?.to_string();
    let pubkey_hex = get_required_string(obj, "pubkey")?;
    let is_host = get_required_bool(obj, "is_host")?;
    let pubkey = parse_exact_hex_lower::<32>(pubkey_hex).ok_or(LanProtocolError::FrameInvalidField)?;
    let info = LanMemberInfo {
        account_id,
        display_name,
        pubkey,
        is_host,
    };
    validate_member_info(&info)?;
    Ok(info)
}

fn members_array_from_json(
    obj: &[(String, StrictJsonValue)],
    allow_empty: bool,
) -> Result<Vec<LanMemberInfo>, LanProtocolError> {
    let Some(StrictJsonValue::Array(arr)) = find_field(obj, "members") else {
        return Err(LanProtocolError::FrameInvalidField);
    };
    if arr.len() > LAN_MAX_MEMBERS {
        return Err(LanProtocolError::FrameTooManyMembers);
    }
    let mut out = Vec::with_capacity(arr.len());
    for elem in arr {
        out.push(member_from_json(elem)?);
    }
    validate_member_list(&out, allow_empty)?;
    Ok(out)
}

pub fn encode_lan_handshake_frame(
    message: &LanHandshakeMessage,
) -> Result<Vec<u8>, LanProtocolError> {
    let (kind, obj) = match message {
        LanHandshakeMessage::Hello(hello) => {
            let _ = parse_lan_party_id_hex(&hello.lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            if !is_valid_lan_name(&hello.lobby_name)
                || !is_valid_lan_name(&hello.host_name)
                || hello.host_account_id > MAX_SAFE_ID
                || hello.max_members == 0
                || usize::from(hello.max_members) > LAN_MAX_MEMBERS
            {
                return Err(LanProtocolError::FrameInvalidField);
            }
            validate_ed25519_pubkey_strict(&hello.host_pubkey)
                .map_err(|_| LanProtocolError::InvalidPubkey)?;
            (
                LanHandshakeKind::LanHello,
                StrictJsonValue::Object(vec![
                    (
                        "lan_party_id".to_string(),
                        StrictJsonValue::Str(hello.lan_party_id.clone()),
                    ),
                    (
                        "lobby_name".to_string(),
                        StrictJsonValue::Str(hello.lobby_name.clone()),
                    ),
                    (
                        "host_name".to_string(),
                        StrictJsonValue::Str(hello.host_name.clone()),
                    ),
                    (
                        "host_account_id".to_string(),
                        StrictJsonValue::U64(hello.host_account_id),
                    ),
                    (
                        "host_pubkey".to_string(),
                        StrictJsonValue::Str(encode_hex_lower(&hello.host_pubkey)),
                    ),
                    (
                        "require_pin".to_string(),
                        StrictJsonValue::Bool(hello.require_pin),
                    ),
                    (
                        "host_nonce".to_string(),
                        StrictJsonValue::Str(encode_hex_lower(&hello.host_nonce)),
                    ),
                    (
                        "max_members".to_string(),
                        StrictJsonValue::U64(u64::from(hello.max_members)),
                    ),
                ]),
            )
        }
        LanHandshakeMessage::Join(join) => {
            let _ = parse_lan_party_id_hex(&join.lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            if !is_valid_lan_name(&join.display_name) || join.account_id > MAX_SAFE_ID {
                return Err(LanProtocolError::FrameInvalidField);
            }
            let mut entries = vec![
                (
                    "lan_party_id".to_string(),
                    StrictJsonValue::Str(join.lan_party_id.clone()),
                ),
                (
                    "display_name".to_string(),
                    StrictJsonValue::Str(join.display_name.clone()),
                ),
                (
                    "account_id".to_string(),
                    StrictJsonValue::U64(join.account_id),
                ),
            ];
            if let Some(proof) = join.pin_proof {
                entries.push((
                    "pin_proof".to_string(),
                    StrictJsonValue::Str(encode_hex_lower(&proof)),
                ));
            }
            (LanHandshakeKind::LanJoin, StrictJsonValue::Object(entries))
        }
        LanHandshakeMessage::Welcome(welcome) => {
            let _ = parse_lan_party_id_hex(&welcome.lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            if !is_valid_reason_text(&welcome.reason) || welcome.roster_epoch > MAX_SAFE_ID {
                return Err(LanProtocolError::FrameInvalidField);
            }
            if !welcome.accepted && !welcome.members.is_empty() {
                return Err(LanProtocolError::FrameInvalidField);
            }
            validate_member_list(&welcome.members, !welcome.accepted)?;
            let members_arr: Vec<StrictJsonValue> =
                welcome.members.iter().map(member_to_json).collect();
            (
                LanHandshakeKind::LanWelcome,
                StrictJsonValue::Object(vec![
                    (
                        "lan_party_id".to_string(),
                        StrictJsonValue::Str(welcome.lan_party_id.clone()),
                    ),
                    (
                        "accepted".to_string(),
                        StrictJsonValue::Bool(welcome.accepted),
                    ),
                    (
                        "reason".to_string(),
                        StrictJsonValue::Str(welcome.reason.clone()),
                    ),
                    (
                        "roster_epoch".to_string(),
                        StrictJsonValue::U64(welcome.roster_epoch),
                    ),
                    ("members".to_string(), StrictJsonValue::Array(members_arr)),
                ]),
            )
        }
        LanHandshakeMessage::Roster(roster) => {
            let _ = parse_lan_party_id_hex(&roster.lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            if roster.roster_epoch > MAX_SAFE_ID {
                return Err(LanProtocolError::FrameInvalidField);
            }
            validate_member_list(&roster.members, false)?;
            let members_arr: Vec<StrictJsonValue> =
                roster.members.iter().map(member_to_json).collect();
            (
                LanHandshakeKind::LanRoster,
                StrictJsonValue::Object(vec![
                    (
                        "lan_party_id".to_string(),
                        StrictJsonValue::Str(roster.lan_party_id.clone()),
                    ),
                    (
                        "roster_epoch".to_string(),
                        StrictJsonValue::U64(roster.roster_epoch),
                    ),
                    ("locked".to_string(), StrictJsonValue::Bool(roster.locked)),
                    ("members".to_string(), StrictJsonValue::Array(members_arr)),
                ]),
            )
        }
    };

    let mut json = String::with_capacity(256);
    dump_json_value(&mut json, &obj);
    let total_len = LAN_HANDSHAKE_HEADER_BYTES
        .checked_add(json.len())
        .ok_or(LanProtocolError::FrameTooLarge)?;
    if total_len > LAN_HANDSHAKE_MAX_FRAME_BYTES {
        return Err(LanProtocolError::FrameTooLarge);
    }

    let mut frame = Vec::with_capacity(total_len);
    frame.push(LAN_HANDSHAKE_VERSION);
    frame.push(kind as u8);
    frame.push(0x00);
    frame.push(0x00);
    frame.extend_from_slice(json.as_bytes());
    Ok(frame)
}

pub fn decode_lan_handshake_frame(
    lane: P2pLane,
    bytes: &[u8],
) -> Result<LanHandshakeMessage, LanProtocolError> {
    if lane != P2pLane::Control {
        return Err(LanProtocolError::FrameLaneMismatch);
    }
    if bytes.len() < LAN_HANDSHAKE_HEADER_BYTES {
        return Err(LanProtocolError::FrameTruncated);
    }
    if bytes.len() > LAN_HANDSHAKE_MAX_FRAME_BYTES {
        return Err(LanProtocolError::FrameTooLarge);
    }
    if bytes.first() != Some(&LAN_HANDSHAKE_VERSION) {
        return Err(LanProtocolError::FrameUnsupportedVersion);
    }
    let kind = LanHandshakeKind::from_u8(
        bytes
            .get(1)
            .copied()
            .ok_or(LanProtocolError::FrameTruncated)?,
    )?;
    if bytes.get(2) != Some(&0x00) || bytes.get(3) != Some(&0x00) {
        return Err(LanProtocolError::FrameNonZeroReserved);
    }

    let payload_bytes = bytes
        .get(LAN_HANDSHAKE_HEADER_BYTES..)
        .ok_or(LanProtocolError::FrameTruncated)?;
    if payload_bytes.is_empty() {
        return Err(LanProtocolError::FrameTruncated);
    }
    let payload_text =
        core::str::from_utf8(payload_bytes).map_err(|_| LanProtocolError::FrameInvalidUtf8)?;
    let mut parser = JsonParser::new(payload_text);
    let parsed = parser.parse_root()?;
    let StrictJsonValue::Object(obj) = parsed else {
        return Err(LanProtocolError::FrameInvalidJson);
    };

    match kind {
        LanHandshakeKind::LanHello => {
            check_allowed_unique_keys(
                &obj,
                &[
                    "lan_party_id",
                    "lobby_name",
                    "host_name",
                    "host_account_id",
                    "host_pubkey",
                    "require_pin",
                    "host_nonce",
                    "max_members",
                ],
            )?;
            let lan_party_id = get_required_string(&obj, "lan_party_id")?.to_string();
            let lobby_name = get_required_string(&obj, "lobby_name")?.to_string();
            let host_name = get_required_string(&obj, "host_name")?.to_string();
            let host_account_id = get_required_safe_u64(&obj, "host_account_id")?;
            let host_pubkey_hex = get_required_string(&obj, "host_pubkey")?;
            let require_pin = get_required_bool(&obj, "require_pin")?;
            let host_nonce_hex = get_required_string(&obj, "host_nonce")?;
            let max_members_u64 = get_required_safe_u64(&obj, "max_members")?;

            let _ = parse_lan_party_id_hex(&lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            let host_pubkey = parse_exact_hex_lower::<32>(host_pubkey_hex)
                .ok_or(LanProtocolError::FrameInvalidField)?;
            let host_nonce = parse_exact_hex_lower::<LAN_NONCE_BYTES>(host_nonce_hex)
                .ok_or(LanProtocolError::FrameInvalidField)?;
            if !is_valid_lan_name(&lobby_name)
                || !is_valid_lan_name(&host_name)
                || max_members_u64 == 0
                || max_members_u64 > LAN_MAX_MEMBERS as u64
            {
                return Err(LanProtocolError::FrameInvalidField);
            }
            validate_ed25519_pubkey_strict(&host_pubkey)
                .map_err(|_| LanProtocolError::InvalidPubkey)?;
            let max_members =
                u8::try_from(max_members_u64).map_err(|_| LanProtocolError::FrameInvalidField)?;
            Ok(LanHandshakeMessage::Hello(LanHelloMessage {
                lan_party_id,
                lobby_name,
                host_name,
                host_account_id,
                host_pubkey,
                require_pin,
                host_nonce,
                max_members,
            }))
        }
        LanHandshakeKind::LanJoin => {
            check_allowed_unique_keys(
                &obj,
                &["lan_party_id", "display_name", "account_id", "pin_proof"],
            )?;
            let lan_party_id = get_required_string(&obj, "lan_party_id")?.to_string();
            let display_name = get_required_string(&obj, "display_name")?.to_string();
            let account_id = get_required_safe_u64(&obj, "account_id")?;
            let _ = parse_lan_party_id_hex(&lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            if !is_valid_lan_name(&display_name) {
                return Err(LanProtocolError::FrameInvalidField);
            }
            let pin_proof = match find_field(&obj, "pin_proof") {
                None | Some(StrictJsonValue::Null) => None,
                Some(StrictJsonValue::Str(hex)) => Some(
                    parse_exact_hex_lower::<LAN_PIN_PROOF_BYTES>(hex)
                        .ok_or(LanProtocolError::FrameInvalidField)?,
                ),
                Some(_) => return Err(LanProtocolError::FrameInvalidField),
            };
            Ok(LanHandshakeMessage::Join(LanJoinMessage {
                lan_party_id,
                display_name,
                account_id,
                pin_proof,
            }))
        }
        LanHandshakeKind::LanWelcome => {
            check_allowed_unique_keys(
                &obj,
                &[
                    "lan_party_id",
                    "accepted",
                    "reason",
                    "roster_epoch",
                    "members",
                ],
            )?;
            let lan_party_id = get_required_string(&obj, "lan_party_id")?.to_string();
            let accepted = get_required_bool(&obj, "accepted")?;
            let reason = get_required_string(&obj, "reason")?.to_string();
            let roster_epoch = get_required_safe_u64(&obj, "roster_epoch")?;
            let _ = parse_lan_party_id_hex(&lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            if !is_valid_reason_text(&reason) {
                return Err(LanProtocolError::FrameInvalidField);
            }
            let members = members_array_from_json(&obj, !accepted)?;
            if !accepted && !members.is_empty() {
                return Err(LanProtocolError::FrameInvalidField);
            }
            Ok(LanHandshakeMessage::Welcome(LanWelcomeMessage {
                lan_party_id,
                accepted,
                reason,
                roster_epoch,
                members,
            }))
        }
        LanHandshakeKind::LanRoster => {
            check_allowed_unique_keys(
                &obj,
                &["lan_party_id", "roster_epoch", "locked", "members"],
            )?;
            let lan_party_id = get_required_string(&obj, "lan_party_id")?.to_string();
            let roster_epoch = get_required_safe_u64(&obj, "roster_epoch")?;
            let locked = get_required_bool(&obj, "locked")?;
            let _ = parse_lan_party_id_hex(&lan_party_id)
                .map_err(|_| LanProtocolError::FrameInvalidField)?;
            let members = members_array_from_json(&obj, false)?;
            Ok(LanHandshakeMessage::Roster(LanRosterMessage {
                lan_party_id,
                roster_epoch,
                locked,
                members,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// 4. LanPinRateLimiter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LanPinPeerKey {
    pub joiner_pubkey: [u8; 32],
    pub source_ip: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LanPinLockoutStatus {
    Allowed = 0,
    PeerLocked = 1,
    LobbyLocked = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanPinRateLimitConfig {
    pub max_peer_failures: u32,
    pub max_lobby_failures: u32,
}

impl Default for LanPinRateLimitConfig {
    fn default() -> Self {
        Self {
            max_peer_failures: LAN_PIN_MAX_PEER_FAILURES,
            max_lobby_failures: LAN_PIN_MAX_LOBBY_FAILURES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPinRateLimiter {
    config: LanPinRateLimitConfig,
    total_failures: u32,
    peer_failures: BTreeMap<LanPinPeerKey, u32>,
}

impl Default for LanPinRateLimiter {
    fn default() -> Self {
        Self::new(LanPinRateLimitConfig::default())
    }
}

impl LanPinRateLimiter {
    pub fn new(mut config: LanPinRateLimitConfig) -> Self {
        if config.max_peer_failures == 0 {
            config.max_peer_failures = 1;
        }
        if config.max_lobby_failures == 0 {
            config.max_lobby_failures = 1;
        }
        Self {
            config,
            total_failures: 0,
            peer_failures: BTreeMap::new(),
        }
    }

    pub fn check(&self, peer: &LanPinPeerKey) -> LanPinLockoutStatus {
        if self.is_lobby_locked() {
            return LanPinLockoutStatus::LobbyLocked;
        }
        if self.is_peer_locked(peer) {
            return LanPinLockoutStatus::PeerLocked;
        }
        LanPinLockoutStatus::Allowed
    }

    pub fn record_failure(&mut self, peer: &LanPinPeerKey) -> LanPinLockoutStatus {
        if self.is_lobby_locked() {
            return LanPinLockoutStatus::LobbyLocked;
        }
        self.total_failures = self.total_failures.saturating_add(1);
        let new_peer_count = {
            let peer_count = self.peer_failures.entry(peer.clone()).or_insert(0);
            *peer_count = peer_count.saturating_add(1);
            *peer_count
        };
        if self.is_lobby_locked() {
            return LanPinLockoutStatus::LobbyLocked;
        }
        if new_peer_count >= self.config.max_peer_failures {
            return LanPinLockoutStatus::PeerLocked;
        }
        LanPinLockoutStatus::Allowed
    }

    pub fn record_success(&mut self, peer: &LanPinPeerKey) {
        if self.is_lobby_locked() || self.is_peer_locked(peer) {
            return;
        }
        self.peer_failures.remove(peer);
    }

    pub fn peer_failures(&self, peer: &LanPinPeerKey) -> u32 {
        self.peer_failures.get(peer).copied().unwrap_or(0)
    }

    pub const fn total_failures(&self) -> u32 {
        self.total_failures
    }

    pub fn is_peer_locked(&self, peer: &LanPinPeerKey) -> bool {
        self.peer_failures(peer) >= self.config.max_peer_failures
    }

    pub const fn is_lobby_locked(&self) -> bool {
        self.total_failures >= self.config.max_lobby_failures
    }

    pub fn reset(&mut self) {
        self.total_failures = 0;
        self.peer_failures.clear();
    }
}

// ---------------------------------------------------------------------------
// 5. Strict `[lan]` Policy TOML Parser & Non-Overridable System Floor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanPolicyConfig {
    pub disabled: bool,
    pub require_pin: bool,
    pub require_local_auth: bool,
    pub idle_timeout_sec: u32,
    pub scan_timeout_sec: u32,
}

impl Default for LanPolicyConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            require_pin: false,
            require_local_auth: false,
            idle_timeout_sec: DEFAULT_LAN_IDLE_TIMEOUT_SEC,
            scan_timeout_sec: DEFAULT_LAN_SCAN_TIMEOUT_SEC,
        }
    }
}

fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

fn parse_policy_bool(raw: &str) -> Option<bool> {
    match raw {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_policy_timeout_u32(raw: &str, max_val: u32) -> Option<u32> {
    if raw.is_empty() || (raw.len() > 1 && raw.starts_with('0')) {
        return None;
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let val = raw.parse::<u32>().ok()?;
    if val == 0 || val > max_val {
        return None;
    }
    Some(val)
}

/// Strict minimal TOML parser for `[lan]`. Fails closed on unknown sections, duplicate `[lan]`,
/// unknown keys, duplicate keys, malformed lines, invalid types, or out-of-range timeouts
/// (`0`, `> 1800` for `idle_timeout_sec`, `> 60` for `scan_timeout_sec`).
pub fn parse_lan_policy_toml(text: &str) -> Result<LanPolicyConfig, LanProtocolError> {
    if text.len() > MAX_LAN_POLICY_FILE_BYTES || text.as_bytes().contains(&0) {
        return Err(LanProtocolError::PolicyParseError);
    }

    let mut cfg = LanPolicyConfig::default();
    let mut in_lan_section = false;
    let mut seen_lan_section = false;
    let mut seen_keys: BTreeSet<&str> = BTreeSet::new();

    for raw_line in text.split('\n') {
        let mut line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if let Some(hash) = line.find('#') {
            line = line.get(0..hash).unwrap_or("");
        }
        line = trim_ows(line);
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(LanProtocolError::PolicyParseError);
            }
            let inner = line
                .get(1..line.len().saturating_sub(1))
                .ok_or(LanProtocolError::PolicyParseError)?;
            let section = trim_ows(inner);
            if section != "lan" || seen_lan_section {
                return Err(LanProtocolError::PolicyParseError);
            }
            in_lan_section = true;
            seen_lan_section = true;
            continue;
        }

        if !in_lan_section {
            return Err(LanProtocolError::PolicyParseError);
        }

        let Some((raw_key, raw_val)) = line.split_once('=') else {
            return Err(LanProtocolError::PolicyParseError);
        };
        let key = trim_ows(raw_key);
        let val = trim_ows(raw_val);
        if key.is_empty() || val.is_empty() || !seen_keys.insert(key) {
            return Err(LanProtocolError::PolicyParseError);
        }

        match key {
            "disabled" => {
                cfg.disabled = parse_policy_bool(val).ok_or(LanProtocolError::PolicyParseError)?;
            }
            "require_pin" => {
                cfg.require_pin =
                    parse_policy_bool(val).ok_or(LanProtocolError::PolicyParseError)?;
            }
            "require_local_auth" => {
                cfg.require_local_auth =
                    parse_policy_bool(val).ok_or(LanProtocolError::PolicyParseError)?;
            }
            "idle_timeout_sec" => {
                cfg.idle_timeout_sec = parse_policy_timeout_u32(val, MAX_LAN_IDLE_TIMEOUT_SEC)
                    .ok_or(LanProtocolError::PolicyParseError)?;
            }
            "scan_timeout_sec" => {
                cfg.scan_timeout_sec = parse_policy_timeout_u32(val, MAX_LAN_SCAN_TIMEOUT_SEC)
                    .ok_or(LanProtocolError::PolicyParseError)?;
            }
            _ => return Err(LanProtocolError::PolicyParseError),
        }
    }

    Ok(cfg)
}

/// Merges optional system & user LAN policies so the system floor can NEVER be weakened:
/// - Booleans are OR'd (`env_disabled` forces `disabled = true`)
/// - Timeouts take `min`, clamped to `1..=MAX`
pub fn merge_lan_policy_floor(
    system: Option<&LanPolicyConfig>,
    user: Option<&LanPolicyConfig>,
    env_disabled: bool,
) -> LanPolicyConfig {
    let base = match (system, user) {
        (Some(sys), Some(usr)) => LanPolicyConfig {
            disabled: sys.disabled || usr.disabled,
            require_pin: sys.require_pin || usr.require_pin,
            require_local_auth: sys.require_local_auth || usr.require_local_auth,
            idle_timeout_sec: sys
                .idle_timeout_sec
                .min(usr.idle_timeout_sec)
                .clamp(1, MAX_LAN_IDLE_TIMEOUT_SEC),
            scan_timeout_sec: sys
                .scan_timeout_sec
                .min(usr.scan_timeout_sec)
                .clamp(1, MAX_LAN_SCAN_TIMEOUT_SEC),
        },
        (Some(only), None) | (None, Some(only)) => LanPolicyConfig {
            disabled: only.disabled,
            require_pin: only.require_pin,
            require_local_auth: only.require_local_auth,
            idle_timeout_sec: only.idle_timeout_sec.clamp(1, MAX_LAN_IDLE_TIMEOUT_SEC),
            scan_timeout_sec: only.scan_timeout_sec.clamp(1, MAX_LAN_SCAN_TIMEOUT_SEC),
        },
        (None, None) => LanPolicyConfig::default(),
    };

    LanPolicyConfig {
        disabled: base.disabled || env_disabled,
        ..base
    }
}

// ---------------------------------------------------------------------------
// 6. RFC 6762 / 6763 `_mp1-lan._udp.local.` mDNS Wire & TXT Codec + Direct Target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanBeaconRecord {
    pub version: u32,
    pub lan_party_id: String,
    pub lobby_name: String,
    pub host_name: String,
    pub host_pubkey: [u8; 32],
    pub require_pin: bool,
    pub alpn: String,
}

fn is_all_zero_pubkey(pubkey: &[u8; 32]) -> bool {
    pubkey.iter().all(|&b| b == 0)
}

pub fn encode_lan_pubkey_base64url(pubkey: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(pubkey)
}

pub fn decode_lan_pubkey_base64url(encoded: &str) -> Result<[u8; 32], LanProtocolError> {
    if encoded.len() != LAN_PUBKEY_B64URL_LEN {
        return Err(LanProtocolError::BeaconInvalidPubkey);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| LanProtocolError::BeaconInvalidPubkey)?;
    let arr: [u8; 32] = decoded
        .try_into()
        .map_err(|_| LanProtocolError::BeaconInvalidPubkey)?;
    if is_all_zero_pubkey(&arr) {
        return Err(LanProtocolError::BeaconInvalidPubkey);
    }
    Ok(arr)
}

pub fn validate_lan_beacon_record(beacon: &LanBeaconRecord) -> Result<(), LanProtocolError> {
    if beacon.version != LAN_BEACON_VERSION {
        return Err(LanProtocolError::BeaconInvalidVersion);
    }
    if parse_lan_party_id_hex(&beacon.lan_party_id).is_err() {
        return Err(LanProtocolError::BeaconInvalidPartyId);
    }
    if !is_valid_beacon_display_text(&beacon.lobby_name) {
        return Err(LanProtocolError::BeaconInvalidLobbyName);
    }
    if !is_valid_beacon_display_text(&beacon.host_name) {
        return Err(LanProtocolError::BeaconInvalidHostName);
    }
    if is_all_zero_pubkey(&beacon.host_pubkey) {
        return Err(LanProtocolError::BeaconInvalidPubkey);
    }
    if beacon.alpn != LAN_BEACON_ALPN {
        return Err(LanProtocolError::BeaconInvalidAlpn);
    }
    Ok(())
}

pub fn encode_lan_txt_record(beacon: &LanBeaconRecord) -> Result<Vec<u8>, LanProtocolError> {
    validate_lan_beacon_record(beacon)?;
    let entries = [
        "v=1".to_string(),
        format!("id={}", beacon.lan_party_id),
        format!("name={}", beacon.lobby_name),
        format!("host={}", beacon.host_name),
        format!("pk={}", encode_lan_pubkey_base64url(&beacon.host_pubkey)),
        format!("pin={}", if beacon.require_pin { "1" } else { "0" }),
        format!("alpn={}", beacon.alpn),
    ];

    let mut out = Vec::with_capacity(LAN_MAX_TXT_BYTES);
    for entry in &entries {
        let len = entry.len();
        if len == 0 || len > 255 || out.len().saturating_add(1 + len) > LAN_MAX_TXT_BYTES {
            return Err(LanProtocolError::TxtTooLarge);
        }
        let len_u8 = u8::try_from(len).map_err(|_| LanProtocolError::TxtTooLarge)?;
        out.push(len_u8);
        out.extend_from_slice(entry.as_bytes());
    }
    Ok(out)
}

pub fn decode_lan_txt_record(wire: &[u8]) -> Result<LanBeaconRecord, LanProtocolError> {
    if wire.len() > LAN_MAX_TXT_BYTES {
        return Err(LanProtocolError::TxtTooLarge);
    }
    if wire.is_empty() {
        return Err(LanProtocolError::TxtMalformed);
    }

    let mut version: Option<u32> = None;
    let mut lan_party_id: Option<String> = None;
    let mut lobby_name: Option<String> = None;
    let mut host_name: Option<String> = None;
    let mut host_pubkey: Option<[u8; 32]> = None;
    let mut require_pin: Option<bool> = None;
    let mut alpn: Option<String> = None;

    let mut offset = 0usize;
    while offset < wire.len() {
        let entry_len = usize::from(
            wire.get(offset)
                .copied()
                .ok_or(LanProtocolError::TxtMalformed)?,
        );
        offset += 1;
        let end = offset
            .checked_add(entry_len)
            .ok_or(LanProtocolError::TxtMalformed)?;
        if entry_len == 0 || end > wire.len() {
            return Err(LanProtocolError::TxtMalformed);
        }
        let raw_entry = wire
            .get(offset..end)
            .ok_or(LanProtocolError::TxtMalformed)?;
        offset = end;

        if !raw_entry.iter().all(|&b| is_printable_ascii_byte(b)) {
            return Err(LanProtocolError::TxtMalformed);
        }
        let entry = core::str::from_utf8(raw_entry).map_err(|_| LanProtocolError::TxtMalformed)?;
        let Some((key, val)) = entry.split_once('=') else {
            return Err(LanProtocolError::TxtMalformed);
        };
        if key.is_empty() {
            return Err(LanProtocolError::TxtMalformed);
        }

        match key {
            "v" => {
                if version.is_some() {
                    return Err(LanProtocolError::TxtDuplicateKey);
                }
                if val != "1" {
                    return Err(LanProtocolError::BeaconInvalidVersion);
                }
                version = Some(LAN_BEACON_VERSION);
            }
            "id" => {
                if lan_party_id.is_some() {
                    return Err(LanProtocolError::TxtDuplicateKey);
                }
                if parse_lan_party_id_hex(val).is_err() {
                    return Err(LanProtocolError::BeaconInvalidPartyId);
                }
                lan_party_id = Some(val.to_string());
            }
            "name" => {
                if lobby_name.is_some() {
                    return Err(LanProtocolError::TxtDuplicateKey);
                }
                if !is_valid_beacon_display_text(val) {
                    return Err(LanProtocolError::BeaconInvalidLobbyName);
                }
                lobby_name = Some(val.to_string());
            }
            "host" => {
                if host_name.is_some() {
                    return Err(LanProtocolError::TxtDuplicateKey);
                }
                if !is_valid_beacon_display_text(val) {
                    return Err(LanProtocolError::BeaconInvalidHostName);
                }
                host_name = Some(val.to_string());
            }
            "pk" => {
                if host_pubkey.is_some() {
                    return Err(LanProtocolError::TxtDuplicateKey);
                }
                host_pubkey = Some(decode_lan_pubkey_base64url(val)?);
            }
            "pin" => {
                if require_pin.is_some() {
                    return Err(LanProtocolError::TxtDuplicateKey);
                }
                require_pin = Some(match val {
                    "0" => false,
                    "1" => true,
                    _ => return Err(LanProtocolError::BeaconInvalidPinFlag),
                });
            }
            "alpn" => {
                if alpn.is_some() {
                    return Err(LanProtocolError::TxtDuplicateKey);
                }
                if val != LAN_BEACON_ALPN {
                    return Err(LanProtocolError::BeaconInvalidAlpn);
                }
                alpn = Some(val.to_string());
            }
            _ => return Err(LanProtocolError::TxtUnknownKey),
        }
    }

    Ok(LanBeaconRecord {
        version: version.ok_or(LanProtocolError::TxtMissingKey)?,
        lan_party_id: lan_party_id.ok_or(LanProtocolError::TxtMissingKey)?,
        lobby_name: lobby_name.ok_or(LanProtocolError::TxtMissingKey)?,
        host_name: host_name.ok_or(LanProtocolError::TxtMissingKey)?,
        host_pubkey: host_pubkey.ok_or(LanProtocolError::TxtMissingKey)?,
        require_pin: require_pin.ok_or(LanProtocolError::TxtMissingKey)?,
        alpn: alpn.ok_or(LanProtocolError::TxtMissingKey)?,
    })
}

fn is_allowed_ipv4_octets(ip: [u8; 4]) -> bool {
    let [a, b, c, d] = ip;
    if a == 0 {
        return false;
    }
    if (a & 0xf0) == 0xe0 {
        return false;
    }
    if a == 255 && b == 255 && c == 255 && d == 255 {
        return false;
    }
    true
}

fn is_allowed_ipv6_octets(ip: [u8; 16]) -> bool {
    if ip.first() == Some(&0xff) {
        return false;
    }
    ip.iter().any(|&b| b != 0)
}

fn is_allowed_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_allowed_ipv4_octets(v4.octets()),
        IpAddr::V6(v6) => is_allowed_ipv6_octets(v6.octets()),
    }
}

pub fn dns_names_equal_ci(lhs: &str, rhs: &str) -> bool {
    lhs.eq_ignore_ascii_case(rhs)
}

fn encode_dns_name(mut name: &str, out: &mut Vec<u8>) -> Result<(), LanProtocolError> {
    if name.is_empty() || name == "." {
        out.push(0);
        return Ok(());
    }
    if let Some(stripped) = name.strip_suffix('.') {
        name = stripped;
    }
    if name.is_empty() {
        return Err(LanProtocolError::DnsInvalidRecord);
    }

    let mut wire_len = 0usize;
    for label in name.split('.') {
        if label.is_empty() || label.len() > LAN_MDNS_MAX_LABEL_LENGTH {
            return Err(LanProtocolError::DnsLabelTooLong);
        }
        wire_len = wire_len.saturating_add(1 + label.len());
        if wire_len.saturating_add(1) > LAN_MDNS_MAX_NAME_LENGTH {
            return Err(LanProtocolError::DnsNameTooLong);
        }
        let len_u8 = u8::try_from(label.len()).map_err(|_| LanProtocolError::DnsLabelTooLong)?;
        out.push(len_u8);
        for &b in label.as_bytes() {
            if b == 0 {
                return Err(LanProtocolError::DnsInvalidRecord);
            }
            out.push(b);
        }
    }
    out.push(0);
    Ok(())
}

fn decode_dns_name(packet: &[u8], start_offset: usize) -> Result<(String, usize), LanProtocolError> {
    if start_offset >= packet.len() {
        return Err(LanProtocolError::DnsTruncated);
    }
    let mut out = String::new();
    let mut pos = start_offset;
    let mut next_offset = 0usize;
    let mut jumped = false;
    let mut jumps = 0usize;
    let mut wire_len = 0usize;
    let mut label_steps = 0usize;
    let mut visited = [0usize; LAN_MDNS_MAX_NAME_JUMPS];

    loop {
        let tag = packet
            .get(pos)
            .copied()
            .ok_or(LanProtocolError::DnsTruncated)?;
        label_steps += 1;
        if label_steps > 128 {
            return Err(LanProtocolError::DnsPointerLoop);
        }

        if tag == 0 {
            if !jumped {
                next_offset = pos + 1;
            }
            if out.is_empty() {
                out.push('.');
            }
            return Ok((out, next_offset));
        }

        let prefix = tag & 0xc0;
        if prefix == 0xc0 {
            let next_byte = packet
                .get(pos + 1)
                .copied()
                .ok_or(LanProtocolError::DnsTruncated)?;
            let target = (usize::from(tag & 0x3f) << 8) | usize::from(next_byte);
            if target >= packet.len() {
                return Err(LanProtocolError::DnsPointerOob);
            }
            if target == pos {
                return Err(LanProtocolError::DnsPointerLoop);
            }
            for &v in visited.get(0..jumps).unwrap_or(&[]) {
                if v == pos || v == target {
                    return Err(LanProtocolError::DnsPointerLoop);
                }
            }
            let Some(slot) = visited.get_mut(jumps) else {
                return Err(LanProtocolError::DnsPointerLoop);
            };
            *slot = pos;
            jumps += 1;
            if !jumped {
                next_offset = pos + 2;
                jumped = true;
            }
            pos = target;
            continue;
        }

        if prefix != 0 {
            return Err(LanProtocolError::DnsInvalidRecord);
        }

        let label_len = usize::from(tag);
        if label_len > LAN_MDNS_MAX_LABEL_LENGTH {
            return Err(LanProtocolError::DnsLabelTooLong);
        }
        let label_end = pos
            .checked_add(1 + label_len)
            .ok_or(LanProtocolError::DnsTruncated)?;
        let label_bytes = packet
            .get(pos + 1..label_end)
            .ok_or(LanProtocolError::DnsTruncated)?;
        wire_len = wire_len.saturating_add(1 + label_len);
        if wire_len.saturating_add(1) > LAN_MDNS_MAX_NAME_LENGTH {
            return Err(LanProtocolError::DnsNameTooLong);
        }
        for &b in label_bytes {
            if b == 0 {
                return Err(LanProtocolError::DnsInvalidRecord);
            }
            out.push(char::from(b));
        }
        out.push('.');
        pos = label_end;
    }
}

fn read_be16(data: &[u8], offset: usize) -> Result<u16, LanProtocolError> {
    let slice = data
        .get(offset..offset + 2)
        .ok_or(LanProtocolError::DnsTruncated)?;
    let arr: [u8; 2] = slice.try_into().map_err(|_| LanProtocolError::DnsTruncated)?;
    Ok(u16::from_be_bytes(arr))
}

fn read_be32(data: &[u8], offset: usize) -> Result<u32, LanProtocolError> {
    let slice = data
        .get(offset..offset + 4)
        .ok_or(LanProtocolError::DnsTruncated)?;
    let arr: [u8; 4] = slice.try_into().map_err(|_| LanProtocolError::DnsTruncated)?;
    Ok(u32::from_be_bytes(arr))
}

fn extract_party_id_from_instance_name(instance_name: &str) -> Option<String> {
    let expected_len = LAN_PARTY_ID_HEX_LEN + 1 + LAN_MDNS_SERVICE_TYPE.len();
    if instance_name.len() != expected_len {
        return None;
    }
    if instance_name.as_bytes().get(LAN_PARTY_ID_HEX_LEN) != Some(&b'.') {
        return None;
    }
    let suffix = instance_name.get(LAN_PARTY_ID_HEX_LEN + 1..)?;
    if !dns_names_equal_ci(suffix, LAN_MDNS_SERVICE_TYPE) {
        return None;
    }
    let lowered = instance_name.get(0..LAN_PARTY_ID_HEX_LEN)?.to_ascii_lowercase();
    if parse_lan_party_id_hex(&lowered).is_err() {
        return None;
    }
    Some(lowered)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanMdnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub unicast_response: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanMdnsAnnouncement {
    pub beacon: LanBeaconRecord,
    pub service_port: u16,
    pub addrs: Vec<SocketAddr>,
    pub ttl_sec: u32,
}

impl LanMdnsAnnouncement {
    pub const fn is_goodbye(&self) -> bool {
        self.ttl_sec == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanMdnsPacket {
    pub transaction_id: u16,
    pub is_response: bool,
    pub questions: Vec<LanMdnsQuestion>,
    pub announcement: Option<LanMdnsAnnouncement>,
    pub goodbye_party_ids: Vec<String>,
}

pub fn encode_lan_ptr_query(unicast_response: bool) -> Result<Vec<u8>, LanProtocolError> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&0u16.to_be_bytes()); // ID
    out.extend_from_slice(&0u16.to_be_bytes()); // Flags (standard query)
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    encode_dns_name(LAN_MDNS_SERVICE_TYPE, &mut out)?;
    out.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
    let qclass = if unicast_response {
        DNS_CLASS_IN | DNS_CLASS_UNICAST_OR_FLUSH
    } else {
        DNS_CLASS_IN
    };
    out.extend_from_slice(&qclass.to_be_bytes());
    Ok(out)
}

pub fn encode_lan_announcement(
    announcement: &LanMdnsAnnouncement,
) -> Result<Vec<u8>, LanProtocolError> {
    if announcement.service_port == 0 {
        return Err(LanProtocolError::InvalidPort);
    }
    if announcement.addrs.len() > LAN_MDNS_MAX_DIRECT_ADDRS {
        return Err(LanProtocolError::DnsInvalidRecord);
    }
    for addr in &announcement.addrs {
        if !is_allowed_lan_ip(addr.ip()) {
            return Err(LanProtocolError::DnsInvalidRecord);
        }
    }

    let txt_wire = encode_lan_txt_record(&announcement.beacon)?;
    let instance_name = format!(
        "{}.{}",
        announcement.beacon.lan_party_id, LAN_MDNS_SERVICE_TYPE
    );
    let host_target = format!(
        "{}{}",
        announcement.beacon.lan_party_id, LAN_MDNS_LOCAL_DOMAIN
    );

    let mut instance_wire = Vec::new();
    encode_dns_name(&instance_name, &mut instance_wire)?;
    let mut target_wire = Vec::new();
    encode_dns_name(&host_target, &mut target_wire)?;

    let arcount = u16::try_from(2 + announcement.addrs.len())
        .map_err(|_| LanProtocolError::DnsInvalidRecord)?;
    let unique_class = DNS_CLASS_IN | DNS_CLASS_UNICAST_OR_FLUSH;

    let mut out = Vec::with_capacity(512);
    // Header: ID=0, Flags=0x8400 (QR=1, AA=1), QD=0, AN=1 (PTR), NS=0, AR=2+addrs
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0x8400u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&arcount.to_be_bytes());

    // Answer 1: PTR _mp1-lan._udp.local. -> <id>._mp1-lan._udp.local.
    encode_dns_name(LAN_MDNS_SERVICE_TYPE, &mut out)?;
    out.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
    out.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    out.extend_from_slice(&announcement.ttl_sec.to_be_bytes());
    let inst_len =
        u16::try_from(instance_wire.len()).map_err(|_| LanProtocolError::DnsPacketTooLarge)?;
    out.extend_from_slice(&inst_len.to_be_bytes());
    out.extend_from_slice(&instance_wire);

    // Additional 1: SRV <id>._mp1-lan._udp.local. -> 0, 0, port, <id>.local.
    out.extend_from_slice(&instance_wire);
    out.extend_from_slice(&DNS_TYPE_SRV.to_be_bytes());
    out.extend_from_slice(&unique_class.to_be_bytes());
    out.extend_from_slice(&announcement.ttl_sec.to_be_bytes());
    let srv_len =
        u16::try_from(6 + target_wire.len()).map_err(|_| LanProtocolError::DnsPacketTooLarge)?;
    out.extend_from_slice(&srv_len.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // priority
    out.extend_from_slice(&0u16.to_be_bytes()); // weight
    out.extend_from_slice(&announcement.service_port.to_be_bytes());
    out.extend_from_slice(&target_wire);

    // Additional 2: TXT <id>._mp1-lan._udp.local.
    out.extend_from_slice(&instance_wire);
    out.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&unique_class.to_be_bytes());
    out.extend_from_slice(&announcement.ttl_sec.to_be_bytes());
    let txt_len =
        u16::try_from(txt_wire.len()).map_err(|_| LanProtocolError::DnsPacketTooLarge)?;
    out.extend_from_slice(&txt_len.to_be_bytes());
    out.extend_from_slice(&txt_wire);

    // Additional 3+: A / AAAA <id>.local.
    for addr in &announcement.addrs {
        out.extend_from_slice(&target_wire);
        match addr.ip() {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
                out.extend_from_slice(&unique_class.to_be_bytes());
                out.extend_from_slice(&announcement.ttl_sec.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&unique_class.to_be_bytes());
                out.extend_from_slice(&announcement.ttl_sec.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }

    if out.len() > LAN_MDNS_MAX_PACKET_BYTES {
        return Err(LanProtocolError::DnsPacketTooLarge);
    }
    Ok(out)
}

pub fn encode_lan_goodbye(
    beacon: &LanBeaconRecord,
    service_port: u16,
    addrs: &[SocketAddr],
) -> Result<Vec<u8>, LanProtocolError> {
    let goodbye = LanMdnsAnnouncement {
        beacon: beacon.clone(),
        service_port,
        addrs: addrs.to_vec(),
        ttl_sec: 0,
    };
    encode_lan_announcement(&goodbye)
}

pub fn decode_lan_mdns_packet(packet: &[u8]) -> Result<LanMdnsPacket, LanProtocolError> {
    if packet.len() > LAN_MDNS_MAX_PACKET_BYTES {
        return Err(LanProtocolError::DnsPacketTooLarge);
    }
    if packet.len() < DNS_HEADER_BYTES {
        return Err(LanProtocolError::DnsTruncated);
    }

    let tx_id = read_be16(packet, 0)?;
    let flags = read_be16(packet, 2)?;
    let qdcount = read_be16(packet, 4)?;
    let ancount = read_be16(packet, 6)?;
    let nscount = read_be16(packet, 8)?;
    let arcount = read_be16(packet, 10)?;

    let is_response = (flags & 0x8000) != 0;
    let opcode = (flags >> 11) & 0x0f;
    let rcode = flags & 0x0f;
    if opcode != 0 || rcode != 0 {
        return Err(LanProtocolError::DnsMalformedHeader);
    }

    let total_rr = usize::from(qdcount)
        + usize::from(ancount)
        + usize::from(nscount)
        + usize::from(arcount);
    if total_rr > LAN_MDNS_MAX_RECORDS_PER_PACKET {
        return Err(LanProtocolError::DnsMalformedHeader);
    }

    let mut result = LanMdnsPacket {
        transaction_id: tx_id,
        is_response,
        questions: Vec::with_capacity(usize::from(qdcount)),
        announcement: None,
        goodbye_party_ids: Vec::new(),
    };

    let mut offset = DNS_HEADER_BYTES;
    for _ in 0..qdcount {
        let (qname, next) = decode_dns_name(packet, offset)?;
        offset = next;
        let qtype = read_be16(packet, offset)?;
        let raw_qclass = read_be16(packet, offset + 2)?;
        offset += 4;
        result.questions.push(LanMdnsQuestion {
            qname,
            qtype,
            qclass: raw_qclass & DNS_CLASS_MASK,
            unicast_response: (raw_qclass & DNS_CLASS_UNICAST_OR_FLUSH) != 0,
        });
    }

    struct RawPtr {
        target: String,
        ttl: u32,
    }
    struct RawSrv {
        owner: String,
        port: u16,
        target: String,
        ttl: u32,
    }
    struct RawTxt<'a> {
        owner: String,
        rdata: &'a [u8],
        ttl: u32,
    }
    struct RawAddr {
        owner: String,
        ip: IpAddr,
        ttl: u32,
    }

    let mut ptrs: Vec<RawPtr> = Vec::new();
    let mut srvs: Vec<RawSrv> = Vec::new();
    let mut txts: Vec<RawTxt<'_>> = Vec::new();
    let mut addrs: Vec<RawAddr> = Vec::new();

    let rr_count = usize::from(ancount) + usize::from(nscount) + usize::from(arcount);
    for _ in 0..rr_count {
        let (owner, next) = decode_dns_name(packet, offset)?;
        offset = next;
        let rtype = read_be16(packet, offset)?;
        let raw_rclass = read_be16(packet, offset + 2)?;
        let ttl = read_be32(packet, offset + 4)?;
        let rdlength = usize::from(read_be16(packet, offset + 8)?);
        offset += 10;

        let rdata_start = offset;
        let rdata_end = offset
            .checked_add(rdlength)
            .ok_or(LanProtocolError::DnsTruncated)?;
        if rdata_end > packet.len() {
            return Err(LanProtocolError::DnsTruncated);
        }
        let rclass = raw_rclass & DNS_CLASS_MASK;

        if rclass == DNS_CLASS_IN {
            match rtype {
                DNS_TYPE_PTR => {
                    let (target, ptr_end) = decode_dns_name(packet, rdata_start)?;
                    if ptr_end != rdata_end {
                        return Err(LanProtocolError::DnsInvalidRecord);
                    }
                    if dns_names_equal_ci(&owner, LAN_MDNS_SERVICE_TYPE) {
                        ptrs.push(RawPtr { target, ttl });
                    }
                }
                DNS_TYPE_SRV => {
                    if rdlength < 7 {
                        return Err(LanProtocolError::DnsInvalidRecord);
                    }
                    let port = read_be16(packet, rdata_start + 4)?;
                    let (target, srv_end) = decode_dns_name(packet, rdata_start + 6)?;
                    if srv_end != rdata_end {
                        return Err(LanProtocolError::DnsInvalidRecord);
                    }
                    srvs.push(RawSrv {
                        owner,
                        port,
                        target,
                        ttl,
                    });
                }
                DNS_TYPE_TXT => {
                    let rdata = packet
                        .get(rdata_start..rdata_end)
                        .ok_or(LanProtocolError::DnsTruncated)?;
                    txts.push(RawTxt { owner, rdata, ttl });
                }
                DNS_TYPE_A => {
                    if rdlength != 4 {
                        return Err(LanProtocolError::DnsInvalidRecord);
                    }
                    let slice = packet
                        .get(rdata_start..rdata_end)
                        .ok_or(LanProtocolError::DnsTruncated)?;
                    let ip: [u8; 4] = slice
                        .try_into()
                        .map_err(|_| LanProtocolError::DnsInvalidRecord)?;
                    addrs.push(RawAddr {
                        owner,
                        ip: IpAddr::V4(Ipv4Addr::from(ip)),
                        ttl,
                    });
                }
                DNS_TYPE_AAAA => {
                    if rdlength != 16 {
                        return Err(LanProtocolError::DnsInvalidRecord);
                    }
                    let slice = packet
                        .get(rdata_start..rdata_end)
                        .ok_or(LanProtocolError::DnsTruncated)?;
                    let ip: [u8; 16] = slice
                        .try_into()
                        .map_err(|_| LanProtocolError::DnsInvalidRecord)?;
                    addrs.push(RawAddr {
                        owner,
                        ip: IpAddr::V6(Ipv6Addr::from(ip)),
                        ttl,
                    });
                }
                _ => {}
            }
        }

        offset = rdata_end;
    }

    if offset != packet.len() {
        return Err(LanProtocolError::DnsMalformedHeader);
    }

    if !is_response {
        return Ok(result);
    }

    for ptr in &ptrs {
        let Some(parsed_id) = extract_party_id_from_instance_name(&ptr.target) else {
            continue;
        };

        let matched_txt = txts
            .iter()
            .find(|t| dns_names_equal_ci(&t.owner, &ptr.target));
        let matched_srv = srvs
            .iter()
            .find(|s| dns_names_equal_ci(&s.owner, &ptr.target));

        let Some(txt) = matched_txt else {
            if ptr.ttl == 0 {
                result.goodbye_party_ids.push(parsed_id);
            }
            continue;
        };

        let beacon = decode_lan_txt_record(txt.rdata)?;
        if beacon.lan_party_id != parsed_id {
            return Err(LanProtocolError::BeaconInvalidPartyId);
        }

        let Some(srv) = matched_srv else {
            if ptr.ttl == 0 || txt.ttl == 0 {
                result.announcement = Some(LanMdnsAnnouncement {
                    beacon,
                    service_port: 0,
                    addrs: Vec::new(),
                    ttl_sec: 0,
                });
                break;
            }
            return Err(LanProtocolError::DnsInvalidRecord);
        };

        let effective_ttl = ptr.ttl.min(srv.ttl).min(txt.ttl);
        if effective_ttl > 0 && srv.port == 0 {
            return Err(LanProtocolError::InvalidPort);
        }

        let mut ann_addrs: Vec<SocketAddr> = Vec::new();
        for addr_rr in &addrs {
            if !dns_names_equal_ci(&addr_rr.owner, &srv.target) {
                continue;
            }
            if effective_ttl > 0 && addr_rr.ttl == 0 {
                continue;
            }
            if !is_allowed_lan_ip(addr_rr.ip) {
                continue;
            }
            let sa = SocketAddr::new(addr_rr.ip, srv.port);
            if ann_addrs.len() < LAN_MDNS_MAX_DIRECT_ADDRS && !ann_addrs.contains(&sa) {
                ann_addrs.push(sa);
            }
        }

        result.announcement = Some(LanMdnsAnnouncement {
            beacon,
            service_port: srv.port,
            addrs: ann_addrs,
            ttl_sec: effective_ttl,
        });
        break;
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// 7. Quake-Style Direct Target Parser & Formatter (`ip:port` / `[ipv6]:port`)
// ---------------------------------------------------------------------------

fn parse_strict_port(text: &str) -> Result<u16, LanProtocolError> {
    if text.is_empty() || text.len() > 5 {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    let port = text
        .parse::<u16>()
        .map_err(|_| LanProtocolError::InvalidDirectTarget)?;
    if port == 0 {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    Ok(port)
}

fn parse_strict_ipv4(text: &str) -> Result<Ipv4Addr, LanProtocolError> {
    if text.is_empty() || text.len() > 15 {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for slot in &mut octets {
        let part = parts.next().ok_or(LanProtocolError::InvalidDirectTarget)?;
        if part.is_empty() || part.len() > 3 {
            return Err(LanProtocolError::InvalidDirectTarget);
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err(LanProtocolError::InvalidDirectTarget);
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(LanProtocolError::InvalidDirectTarget);
        }
        *slot = part
            .parse::<u8>()
            .map_err(|_| LanProtocolError::InvalidDirectTarget)?;
    }
    if parts.next().is_some() {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    Ok(Ipv4Addr::from(octets))
}

/// Strictly parses a Quake-style direct LAN target (`a.b.c.d:port` or `[ipv6]:port`).
/// Rejects whitespace, hostnames, leading zeros, port 0, zone IDs (`%`), multicast, unspecified,
/// and limited broadcast addresses.
pub fn parse_lan_direct_target(input: &str) -> Result<SocketAddr, LanProtocolError> {
    if input.is_empty() || input.len() > MAX_DIRECT_TARGET_BYTES {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    if input.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return Err(LanProtocolError::InvalidDirectTarget);
    }

    if let Some(rest) = input.strip_prefix('[') {
        let Some((ip_text, after_bracket)) = rest.split_once(']') else {
            return Err(LanProtocolError::InvalidDirectTarget);
        };
        let Some(port_text) = after_bracket.strip_prefix(':') else {
            return Err(LanProtocolError::InvalidDirectTarget);
        };
        if ip_text.is_empty() || !ip_text.contains(':') {
            return Err(LanProtocolError::InvalidDirectTarget);
        }
        if !ip_text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(LanProtocolError::InvalidDirectTarget);
        }
        let port = parse_strict_port(port_text)?;
        let v6: Ipv6Addr = ip_text
            .parse()
            .map_err(|_| LanProtocolError::InvalidDirectTarget)?;
        if !is_allowed_ipv6_octets(v6.octets()) {
            return Err(LanProtocolError::InvalidDirectTarget);
        }
        return Ok(SocketAddr::new(IpAddr::V6(v6), port));
    }

    let Some((ip_text, port_text)) = input.split_once(':') else {
        return Err(LanProtocolError::InvalidDirectTarget);
    };
    if ip_text.is_empty() || port_text.is_empty() || port_text.contains(':') {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    let v4 = parse_strict_ipv4(ip_text)?;
    let port = parse_strict_port(port_text)?;
    if !is_allowed_ipv4_octets(v4.octets()) {
        return Err(LanProtocolError::InvalidDirectTarget);
    }
    Ok(SocketAddr::new(IpAddr::V4(v4), port))
}

/// Formats a `SocketAddr` into canonical Quake-style `ip:port` / `[ipv6]:port` form.
pub fn format_lan_direct_target(addr: SocketAddr) -> String {
    addr.to_string()
}
