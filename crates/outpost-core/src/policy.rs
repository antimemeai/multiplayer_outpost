//! Unified `/etc/multiplayer/policy.toml` Parser, Monotonic Floor Merger & Party Trust Tiers.
//!
//! Aligned with Blackbird `seq: 46` (`2026-11-23-brakes-containment-peer-trust-frumentarii.md` §3.1):
//! - Sections: `[brakes]`, `[party_trust]`, `[lan]`, `[online]`
//! - Strict fail-closed TOML parser (rejects unknown sections, duplicate sections, unknown keys,
//!   duplicate keys, invalid types/ranges, NUL/control characters).
//! - Monotonic floor merge with 100% backward compatibility for legacy `/etc/multiplayer/lan.toml`.
//! - `effective_peer_trust` clamping for default peers, per-peer overrides, and external guests.

use core::fmt;
use std::collections::BTreeSet;

use crate::lan_protocol::{
    EffectiveLanPolicy, MAX_LAN_IDLE_TIMEOUT_SEC, MAX_LAN_SCAN_TIMEOUT_SEC, PartialLanPolicy,
    resolve_lan_policy,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DEFAULT_SYSTEM_POLICY_PATH: &str = "/etc/multiplayer/policy.toml";
pub const MAX_UNIFIED_POLICY_FILE_BYTES: usize = 16 * 1024;
pub const MAX_POLICY_ARRAY_ITEMS: usize = 64;
pub const MAX_POLICY_STRING_BYTES: usize = 256;
pub const DEFAULT_MAX_TURNS_PER_PEER: u32 = 32;
pub const MAX_ALLOWED_TURNS_PER_PEER: u32 = 10_000;
/// Default spend cap: `$2.00` expressed in exact micro-USD (`1 USD = 1_000_000`).
pub const DEFAULT_MAX_COST_USD_PER_PEER_MICROS: u64 = 2_000_000;
/// Maximum allowed spend cap: `$100,000.00` in micro-USD.
pub const MAX_ALLOWED_COST_USD_PER_PEER_MICROS: u64 = 100_000_000_000;

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    FileTooLarge,
    InvalidCharacter,
    UnknownSection,
    DuplicateSection,
    KeyBeforeSection,
    UnknownKey,
    DuplicateKey,
    MalformedLine,
    InvalidValue,
    PolicyFloorViolation,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PolicyError {}

// ---------------------------------------------------------------------------
// Ordered Containment & Trust Profiles
// ---------------------------------------------------------------------------

/// OS/tool containment profile ordered from loosest (`BlackFlag`) to strictest (`Airgap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BrakesProfile {
    BlackFlag = 0,
    Guarded = 1,
    Sandboxed = 2,
    Airgap = 3,
}

impl BrakesProfile {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "black-flag" => Some(Self::BlackFlag),
            "guarded" => Some(Self::Guarded),
            "sandboxed" => Some(Self::Sandboxed),
            "airgap" => Some(Self::Airgap),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlackFlag => "black-flag",
            Self::Guarded => "guarded",
            Self::Sandboxed => "sandboxed",
            Self::Airgap => "airgap",
        }
    }
}

impl fmt::Display for BrakesProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Remote peer trust profile ordered from STRICTEST (`Advisory`) to LOOSEST (`BlackFlag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PartyTrustProfile {
    Advisory = 0,
    HumanGated = 1,
    PeerTrusted = 2,
    BlackFlag = 3,
}

impl PartyTrustProfile {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "advisory" => Some(Self::Advisory),
            "human-gated" => Some(Self::HumanGated),
            "peer-trusted" => Some(Self::PeerTrusted),
            "black-flag" => Some(Self::BlackFlag),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::HumanGated => "human-gated",
            Self::PeerTrusted => "peer-trusted",
            Self::BlackFlag => "black-flag",
        }
    }
}

impl fmt::Display for PartyTrustProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Parsed Partial Policy File Structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialBrakesPolicy {
    pub min_profile: Option<BrakesProfile>,
    pub default_profile: Option<BrakesProfile>,
    pub allow_escalation: Option<bool>,
    pub require_local_auth_for_escalation: Option<bool>,
    pub extra_denied_paths: Option<Vec<String>>,
    pub fail_closed_on_missing_sandbox: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialPartyTrustPolicy {
    pub max_default_profile: Option<PartyTrustProfile>,
    pub max_peer_override: Option<PartyTrustProfile>,
    pub max_external_guest_profile: Option<PartyTrustProfile>,
    pub max_turns_per_peer: Option<u32>,
    pub max_cost_usd_per_peer_micros: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialOnlinePolicy {
    pub disabled: Option<bool>,
    pub require_force_relays: Option<bool>,
    pub allowed_authorities: Option<Vec<String>>,
    pub allowed_org_slugs: Option<Vec<String>>,
    pub allow_personal_parties: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnifiedPolicyFile {
    pub brakes: PartialBrakesPolicy,
    pub party_trust: PartialPartyTrustPolicy,
    pub lan: PartialLanPolicy,
    pub online: PartialOnlinePolicy,
}

// ---------------------------------------------------------------------------
// Effective Merged Policy Structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveBrakesPolicy {
    pub min_profile: BrakesProfile,
    pub default_profile: BrakesProfile,
    pub active_profile: BrakesProfile,
    pub allow_escalation: bool,
    pub require_local_auth_for_escalation: bool,
    pub extra_denied_paths: Vec<String>,
    pub fail_closed_on_missing_sandbox: bool,
}

impl Default for EffectiveBrakesPolicy {
    fn default() -> Self {
        Self {
            min_profile: BrakesProfile::BlackFlag,
            default_profile: BrakesProfile::BlackFlag,
            active_profile: BrakesProfile::BlackFlag,
            allow_escalation: true,
            require_local_auth_for_escalation: false,
            extra_denied_paths: Vec::new(),
            fail_closed_on_missing_sandbox: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectivePartyTrustPolicy {
    pub max_default_profile: PartyTrustProfile,
    pub max_peer_override: PartyTrustProfile,
    pub max_external_guest_profile: PartyTrustProfile,
    pub max_turns_per_peer: u32,
    pub max_cost_usd_per_peer_micros: u64,
}

impl Default for EffectivePartyTrustPolicy {
    fn default() -> Self {
        Self {
            max_default_profile: PartyTrustProfile::HumanGated,
            max_peer_override: PartyTrustProfile::BlackFlag,
            max_external_guest_profile: PartyTrustProfile::Advisory,
            max_turns_per_peer: DEFAULT_MAX_TURNS_PER_PEER,
            max_cost_usd_per_peer_micros: DEFAULT_MAX_COST_USD_PER_PEER_MICROS,
        }
    }
}

impl EffectivePartyTrustPolicy {
    pub fn max_cost_usd_per_peer(&self) -> f64 {
        (self.max_cost_usd_per_peer_micros as f64) / 1_000_000.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveOnlinePolicy {
    pub disabled: bool,
    pub require_force_relays: bool,
    /// `None` means unrestricted; `Some(list)` restricts strictly to the listed authorities.
    pub allowed_authorities: Option<Vec<String>>,
    /// `None` means unrestricted; `Some(list)` restricts strictly to the listed org slugs.
    pub allowed_org_slugs: Option<Vec<String>>,
    pub allow_personal_parties: bool,
}

impl Default for EffectiveOnlinePolicy {
    fn default() -> Self {
        Self {
            disabled: false,
            require_force_relays: false,
            allowed_authorities: None,
            allowed_org_slugs: None,
            allow_personal_parties: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveUnifiedPolicy {
    pub brakes: EffectiveBrakesPolicy,
    pub party_trust: EffectivePartyTrustPolicy,
    pub lan: EffectiveLanPolicy,
    pub online: EffectiveOnlinePolicy,
}

impl EffectiveUnifiedPolicy {
    /// Validates an explicit CLI `--brakes <profile>` request against the non-overridable floor.
    pub fn validate_cli_brakes(
        &self,
        requested: BrakesProfile,
    ) -> Result<BrakesProfile, PolicyError> {
        if requested < self.brakes.min_profile {
            return Err(PolicyError::PolicyFloorViolation);
        }
        Ok(requested)
    }

    pub fn is_authority_allowed(&self, authority: &str) -> bool {
        let lower = authority.to_ascii_lowercase();
        match &self.online.allowed_authorities {
            None => true,
            Some(list) => list.iter().any(|a| a == &lower),
        }
    }

    pub fn is_org_slug_allowed(&self, slug: &str) -> bool {
        let lower = slug.to_ascii_lowercase();
        match &self.online.allowed_org_slugs {
            None => true,
            Some(list) => list.iter().any(|s| s == &lower),
        }
    }
}

// ---------------------------------------------------------------------------
// Strict Fail-Closed TOML Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Brakes,
    PartyTrust,
    Lan,
    Online,
}

fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// Strips a `# ...` comment outside of basic double-quoted strings.
fn strip_toml_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b'#' {
            return line.get(0..i).unwrap_or("");
        }
    }
    line
}

fn parse_bool(raw: &str) -> Result<bool, PolicyError> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(PolicyError::InvalidValue),
    }
}

fn parse_bounded_u32(raw: &str, max_val: u32) -> Result<u32, PolicyError> {
    if raw.is_empty() || (raw.len() > 1 && raw.starts_with('0')) {
        return Err(PolicyError::InvalidValue);
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PolicyError::InvalidValue);
    }
    let v = raw.parse::<u32>().map_err(|_| PolicyError::InvalidValue)?;
    if v == 0 || v > max_val {
        return Err(PolicyError::InvalidValue);
    }
    Ok(v)
}

/// Parses a strictly positive decimal USD amount (e.g. `2`, `2.0`, `0.25`) into micro-USD.
fn parse_usd_micros(raw: &str) -> Result<u64, PolicyError> {
    if raw.is_empty() || raw.len() > 20 {
        return Err(PolicyError::InvalidValue);
    }
    let (whole_s, frac_s) = match raw.split_once('.') {
        Some((w, f)) => {
            if f.is_empty() || f.len() > 6 || f.contains('.') {
                return Err(PolicyError::InvalidValue);
            }
            (w, f)
        }
        None => (raw, ""),
    };
    if whole_s.is_empty() || (whole_s.len() > 1 && whole_s.starts_with('0')) {
        return Err(PolicyError::InvalidValue);
    }
    if !whole_s.bytes().all(|b| b.is_ascii_digit()) || !frac_s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PolicyError::InvalidValue);
    }
    let whole = whole_s.parse::<u64>().map_err(|_| PolicyError::InvalidValue)?;
    let mut frac_micros = 0u64;
    let mut mult = 100_000u64;
    for b in frac_s.bytes() {
        frac_micros = frac_micros
            .checked_add(u64::from(b - b'0') * mult)
            .ok_or(PolicyError::InvalidValue)?;
        mult /= 10;
    }
    let total = whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac_micros))
        .ok_or(PolicyError::InvalidValue)?;
    if total == 0 || total > MAX_ALLOWED_COST_USD_PER_PEER_MICROS {
        return Err(PolicyError::InvalidValue);
    }
    Ok(total)
}

/// Parses a TOML basic string `"..."` at the start of `s`, returning `(decoded, rest)`.
fn parse_toml_string_prefix(s: &str) -> Result<(String, &str), PolicyError> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err(PolicyError::InvalidValue);
    }
    let mut i = 1usize;
    let mut out = String::new();
    while i < bytes.len() {
        let b = bytes.get(i).copied().ok_or(PolicyError::InvalidValue)?;
        if b == b'"' {
            let rest = s.get(i + 1..).ok_or(PolicyError::InvalidValue)?;
            return Ok((out, rest));
        }
        if b == b'\\' {
            i += 1;
            let esc = bytes.get(i).copied().ok_or(PolicyError::InvalidValue)?;
            i += 1;
            let ch = match esc {
                b'"' => '"',
                b'\\' => '\\',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                _ => return Err(PolicyError::InvalidValue),
            };
            if out.len().saturating_add(1) > MAX_POLICY_STRING_BYTES {
                return Err(PolicyError::InvalidValue);
            }
            out.push(ch);
        } else if b < 0x20 || b == 0x7f {
            return Err(PolicyError::InvalidCharacter);
        } else if b < 0x80 {
            if out.len().saturating_add(1) > MAX_POLICY_STRING_BYTES {
                return Err(PolicyError::InvalidValue);
            }
            out.push(char::from(b));
            i += 1;
        } else {
            let ch = s
                .get(i..)
                .and_then(|tail| tail.chars().next())
                .ok_or(PolicyError::InvalidValue)?;
            if out.len().saturating_add(ch.len_utf8()) > MAX_POLICY_STRING_BYTES {
                return Err(PolicyError::InvalidValue);
            }
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    Err(PolicyError::InvalidValue)
}

fn parse_toml_string(raw: &str) -> Result<String, PolicyError> {
    let (s, rest) = parse_toml_string_prefix(raw)?;
    if !trim_ows(rest).is_empty() {
        return Err(PolicyError::InvalidValue);
    }
    Ok(s)
}

fn parse_toml_string_array(raw: &str) -> Result<Vec<String>, PolicyError> {
    let inner = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(PolicyError::InvalidValue)?;
    let mut rest = inner.trim();
    let mut items = Vec::new();
    if rest.is_empty() {
        return Ok(items);
    }
    loop {
        let (item, after) = parse_toml_string_prefix(rest)?;
        if item.is_empty() || items.len() >= MAX_POLICY_ARRAY_ITEMS {
            return Err(PolicyError::InvalidValue);
        }
        items.push(item);
        rest = after.trim();
        if rest.is_empty() {
            return Ok(items);
        }
        if let Some(next) = rest.strip_prefix(',') {
            rest = next.trim();
            if rest.is_empty() {
                // Allow trailing comma in TOML arrays.
                return Ok(items);
            }
        } else {
            return Err(PolicyError::InvalidValue);
        }
    }
}

fn validate_denied_path(path: &str) -> Result<String, PolicyError> {
    if path.is_empty() || path.len() > MAX_POLICY_STRING_BYTES {
        return Err(PolicyError::InvalidValue);
    }
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(PolicyError::InvalidCharacter);
    }
    Ok(path.to_string())
}

fn validate_authority(raw: &str) -> Result<String, PolicyError> {
    if raw.is_empty() || raw.len() > 255 {
        return Err(PolicyError::InvalidValue);
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(PolicyError::InvalidValue);
    }
    if raw.starts_with('.') || raw.ends_with('.') || raw.contains("..") {
        return Err(PolicyError::InvalidValue);
    }
    Ok(raw.to_ascii_lowercase())
}

fn validate_org_slug(raw: &str) -> Result<String, PolicyError> {
    if raw.is_empty() || raw.len() > 64 {
        return Err(PolicyError::InvalidValue);
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(PolicyError::InvalidValue);
    }
    Ok(raw.to_ascii_lowercase())
}

/// Strictly parses `/etc/multiplayer/policy.toml` (or user `policy.toml`).
/// Fails closed on unknown sections, duplicate sections, unknown keys, duplicate keys,
/// invalid types/ranges, or control/NUL bytes.
pub fn parse_unified_policy_toml(text: &str) -> Result<UnifiedPolicyFile, PolicyError> {
    if text.len() > MAX_UNIFIED_POLICY_FILE_BYTES {
        return Err(PolicyError::FileTooLarge);
    }
    for &b in text.as_bytes() {
        if b == 0 || (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n')) || b == 0x7f {
            return Err(PolicyError::InvalidCharacter);
        }
    }

    let mut out = UnifiedPolicyFile::default();
    let mut current_section: Option<Section> = None;
    let mut seen_sections = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();

    // Support multi-line `[ ... ]` arrays by joining continued array lines.
    let raw_lines: Vec<&str> = text.split('\n').collect();
    let mut idx = 0usize;
    while idx < raw_lines.len() {
        let raw_line = raw_lines.get(idx).copied().unwrap_or("");
        idx += 1;
        let cleaned = trim_ows(strip_toml_comment(raw_line.strip_suffix('\r').unwrap_or(raw_line)));
        if cleaned.is_empty() {
            continue;
        }

        if cleaned.starts_with('[') {
            if !cleaned.ends_with(']') {
                return Err(PolicyError::MalformedLine);
            }
            let inner = cleaned
                .get(1..cleaned.len().saturating_sub(1))
                .ok_or(PolicyError::MalformedLine)?;
            let sec_name = trim_ows(inner);
            let sec = match sec_name {
                "brakes" => Section::Brakes,
                "party_trust" => Section::PartyTrust,
                "lan" => Section::Lan,
                "online" => Section::Online,
                _ => return Err(PolicyError::UnknownSection),
            };
            if !seen_sections.insert(sec_name) {
                return Err(PolicyError::DuplicateSection);
            }
            current_section = Some(sec);
            seen_keys.clear();
            continue;
        }

        let Some(sec) = current_section else {
            return Err(PolicyError::KeyBeforeSection);
        };

        let Some((raw_key, raw_val_start)) = cleaned.split_once('=') else {
            return Err(PolicyError::MalformedLine);
        };
        let key = trim_ows(raw_key);
        let mut val_owned = trim_ows(raw_val_start).to_string();
        if key.is_empty() || val_owned.is_empty() {
            return Err(PolicyError::MalformedLine);
        }

        // Accumulate multi-line array values if `[` was not closed on this line.
        if val_owned.starts_with('[') && !val_owned.ends_with(']') {
            while idx < raw_lines.len() && !val_owned.ends_with(']') {
                let next_raw = raw_lines.get(idx).copied().unwrap_or("");
                idx += 1;
                let next_clean =
                    trim_ows(strip_toml_comment(next_raw.strip_suffix('\r').unwrap_or(next_raw)));
                if !next_clean.is_empty() {
                    val_owned.push(' ');
                    val_owned.push_str(next_clean);
                }
            }
            if !val_owned.ends_with(']') {
                return Err(PolicyError::MalformedLine);
            }
        }

        if !seen_keys.insert(key.to_string()) {
            return Err(PolicyError::DuplicateKey);
        }
        let val = val_owned.as_str();

        match sec {
            Section::Brakes => match key {
                "min_profile" => {
                    let s = parse_toml_string(val)?;
                    out.brakes.min_profile =
                        Some(BrakesProfile::parse(&s).ok_or(PolicyError::InvalidValue)?);
                }
                "default_profile" => {
                    let s = parse_toml_string(val)?;
                    out.brakes.default_profile =
                        Some(BrakesProfile::parse(&s).ok_or(PolicyError::InvalidValue)?);
                }
                "allow_escalation" => {
                    out.brakes.allow_escalation = Some(parse_bool(val)?);
                }
                "require_local_auth_for_escalation" => {
                    out.brakes.require_local_auth_for_escalation = Some(parse_bool(val)?);
                }
                "extra_denied_paths" => {
                    let raw_items = parse_toml_string_array(val)?;
                    let mut validated = Vec::with_capacity(raw_items.len());
                    for p in raw_items {
                        validated.push(validate_denied_path(&p)?);
                    }
                    out.brakes.extra_denied_paths = Some(validated);
                }
                "fail_closed_on_missing_sandbox" => {
                    out.brakes.fail_closed_on_missing_sandbox = Some(parse_bool(val)?);
                }
                _ => return Err(PolicyError::UnknownKey),
            },
            Section::PartyTrust => match key {
                "max_default_profile" => {
                    let s = parse_toml_string(val)?;
                    out.party_trust.max_default_profile =
                        Some(PartyTrustProfile::parse(&s).ok_or(PolicyError::InvalidValue)?);
                }
                "max_peer_override" => {
                    let s = parse_toml_string(val)?;
                    out.party_trust.max_peer_override =
                        Some(PartyTrustProfile::parse(&s).ok_or(PolicyError::InvalidValue)?);
                }
                "max_external_guest_profile" => {
                    let s = parse_toml_string(val)?;
                    out.party_trust.max_external_guest_profile =
                        Some(PartyTrustProfile::parse(&s).ok_or(PolicyError::InvalidValue)?);
                }
                "max_turns_per_peer" => {
                    out.party_trust.max_turns_per_peer =
                        Some(parse_bounded_u32(val, MAX_ALLOWED_TURNS_PER_PEER)?);
                }
                "max_cost_usd_per_peer" => {
                    out.party_trust.max_cost_usd_per_peer_micros = Some(parse_usd_micros(val)?);
                }
                _ => return Err(PolicyError::UnknownKey),
            },
            Section::Lan => match key {
                "disabled" => {
                    out.lan.disabled = Some(parse_bool(val)?);
                }
                "require_pin" => {
                    out.lan.require_pin = Some(parse_bool(val)?);
                }
                "require_local_auth" => {
                    out.lan.require_local_auth = Some(parse_bool(val)?);
                }
                "idle_timeout_sec" => {
                    out.lan.idle_timeout_sec =
                        Some(parse_bounded_u32(val, MAX_LAN_IDLE_TIMEOUT_SEC)?);
                }
                "scan_timeout_sec" => {
                    out.lan.scan_timeout_sec =
                        Some(parse_bounded_u32(val, MAX_LAN_SCAN_TIMEOUT_SEC)?);
                }
                _ => return Err(PolicyError::UnknownKey),
            },
            Section::Online => match key {
                "disabled" => {
                    out.online.disabled = Some(parse_bool(val)?);
                }
                "require_force_relays" => {
                    out.online.require_force_relays = Some(parse_bool(val)?);
                }
                "allowed_authorities" => {
                    let raw_items = parse_toml_string_array(val)?;
                    let mut validated = Vec::with_capacity(raw_items.len());
                    for a in raw_items {
                        validated.push(validate_authority(&a)?);
                    }
                    out.online.allowed_authorities = Some(validated);
                }
                "allowed_org_slugs" => {
                    let raw_items = parse_toml_string_array(val)?;
                    let mut validated = Vec::with_capacity(raw_items.len());
                    for slug in raw_items {
                        validated.push(validate_org_slug(&slug)?);
                    }
                    out.online.allowed_org_slugs = Some(validated);
                }
                "allow_personal_parties" => {
                    out.online.allow_personal_parties = Some(parse_bool(val)?);
                }
                _ => return Err(PolicyError::UnknownKey),
            },
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Monotonic Floor Merge & Party Trust Clamping
// ---------------------------------------------------------------------------

fn opt_bool_or(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x || y),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn opt_u32_min(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn merge_partial_lan_stricter(
    a: Option<&PartialLanPolicy>,
    b: Option<&PartialLanPolicy>,
) -> Option<PartialLanPolicy> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) | (None, Some(x)) => Some(*x),
        (Some(x), Some(y)) => Some(PartialLanPolicy {
            disabled: opt_bool_or(x.disabled, y.disabled),
            require_pin: opt_bool_or(x.require_pin, y.require_pin),
            require_local_auth: opt_bool_or(x.require_local_auth, y.require_local_auth),
            idle_timeout_sec: opt_u32_min(x.idle_timeout_sec, y.idle_timeout_sec),
            scan_timeout_sec: opt_u32_min(x.scan_timeout_sec, y.scan_timeout_sec),
        }),
    }
}

fn merge_trust_cap(
    sys: Option<PartyTrustProfile>,
    usr: Option<PartyTrustProfile>,
    default_val: PartyTrustProfile,
) -> PartyTrustProfile {
    match (sys, usr) {
        (Some(s), Some(u)) => s.min(u),
        (Some(s), None) => s,
        (None, Some(u)) => u,
        (None, None) => default_val,
    }
}

fn merge_allowlist_intersection(
    sys: Option<&Vec<String>>,
    usr: Option<&Vec<String>>,
) -> Option<Vec<String>> {
    match (sys, usr) {
        (None, None) => None,
        (Some(list), None) | (None, Some(list)) => {
            let dedup: BTreeSet<String> = list.iter().cloned().collect();
            Some(dedup.into_iter().collect())
        }
        (Some(s_list), Some(u_list)) => {
            let s_set: BTreeSet<&str> = s_list.iter().map(String::as_str).collect();
            let inter: BTreeSet<String> = u_list
                .iter()
                .filter(|item| s_set.contains(item.as_str()))
                .cloned()
                .collect();
            Some(inter.into_iter().collect())
        }
    }
}

/// Monotonically merges optional system `/etc/multiplayer/policy.toml`, legacy system
/// `/etc/multiplayer/lan.toml`, user `policy.toml`, legacy user `lan.toml`, `MP_DISABLE_LAN`,
/// and `BLACKBIRD_BRAKES`/`MP_BRAKES`.
///
/// Invariant: The system floor can NEVER be weakened by user config or env overrides.
/// If `env_brakes_override` explicitly requests a profile looser than the system `min_profile`,
/// returns `Err(PolicyError::PolicyFloorViolation)` (fail closed).
pub fn merge_unified_policy_floor(
    system_policy: Option<&UnifiedPolicyFile>,
    legacy_system_lan: Option<&PartialLanPolicy>,
    user_policy: Option<&UnifiedPolicyFile>,
    legacy_user_lan: Option<&PartialLanPolicy>,
    env_lan_disabled: bool,
    env_brakes_override: Option<BrakesProfile>,
) -> Result<EffectiveUnifiedPolicy, PolicyError> {
    // 1. [brakes]
    let sys_b = system_policy.map(|p| &p.brakes);
    let usr_b = user_policy.map(|p| &p.brakes);

    let sys_min_profile = sys_b
        .and_then(|b| b.min_profile)
        .unwrap_or(BrakesProfile::BlackFlag);
    let usr_min_profile = usr_b
        .and_then(|b| b.min_profile)
        .unwrap_or(BrakesProfile::BlackFlag);
    let min_profile = sys_min_profile.max(usr_min_profile);

    let sys_def = sys_b.and_then(|b| b.default_profile);
    let usr_def = usr_b.and_then(|b| b.default_profile);
    let raw_default = match (sys_def, usr_def) {
        (Some(s), Some(u)) => s.max(u),
        (Some(s), None) | (None, Some(s)) => s,
        (None, None) => BrakesProfile::BlackFlag,
    };
    let default_profile = raw_default.max(min_profile);

    let active_profile = match env_brakes_override {
        Some(req) => {
            if req < sys_min_profile {
                return Err(PolicyError::PolicyFloorViolation);
            }
            req.max(min_profile)
        }
        None => default_profile,
    };

    let allow_escalation = sys_b.and_then(|b| b.allow_escalation).unwrap_or(true)
        && usr_b.and_then(|b| b.allow_escalation).unwrap_or(true);
    let require_local_auth_for_escalation = sys_b
        .and_then(|b| b.require_local_auth_for_escalation)
        .unwrap_or(false)
        || usr_b
            .and_then(|b| b.require_local_auth_for_escalation)
            .unwrap_or(false);

    let mut denied_set: BTreeSet<String> = BTreeSet::new();
    if let Some(paths) = sys_b.and_then(|b| b.extra_denied_paths.as_ref()) {
        for p in paths {
            denied_set.insert(p.clone());
        }
    }
    if let Some(paths) = usr_b.and_then(|b| b.extra_denied_paths.as_ref()) {
        for p in paths {
            denied_set.insert(p.clone());
        }
    }

    let fail_closed_raw = sys_b
        .and_then(|b| b.fail_closed_on_missing_sandbox)
        .unwrap_or(true)
        || usr_b
            .and_then(|b| b.fail_closed_on_missing_sandbox)
            .unwrap_or(false);
    let fail_closed_on_missing_sandbox =
        fail_closed_raw || active_profile >= BrakesProfile::Guarded;

    let brakes = EffectiveBrakesPolicy {
        min_profile,
        default_profile,
        active_profile,
        allow_escalation,
        require_local_auth_for_escalation,
        extra_denied_paths: denied_set.into_iter().collect(),
        fail_closed_on_missing_sandbox,
    };

    // 2. [party_trust]
    let sys_t = system_policy.map(|p| &p.party_trust);
    let usr_t = user_policy.map(|p| &p.party_trust);

    let max_peer_override = merge_trust_cap(
        sys_t.and_then(|t| t.max_peer_override),
        usr_t.and_then(|t| t.max_peer_override),
        PartyTrustProfile::BlackFlag,
    );
    let max_default_profile = merge_trust_cap(
        sys_t.and_then(|t| t.max_default_profile),
        usr_t.and_then(|t| t.max_default_profile),
        PartyTrustProfile::HumanGated,
    )
    .min(max_peer_override);
    let max_external_guest_profile = merge_trust_cap(
        sys_t.and_then(|t| t.max_external_guest_profile),
        usr_t.and_then(|t| t.max_external_guest_profile),
        PartyTrustProfile::Advisory,
    )
    .min(max_peer_override);

    let max_turns_per_peer = opt_u32_min(
        sys_t.and_then(|t| t.max_turns_per_peer),
        usr_t.and_then(|t| t.max_turns_per_peer),
    )
    .unwrap_or(DEFAULT_MAX_TURNS_PER_PEER);

    let max_cost_usd_per_peer_micros = match (
        sys_t.and_then(|t| t.max_cost_usd_per_peer_micros),
        usr_t.and_then(|t| t.max_cost_usd_per_peer_micros),
    ) {
        (Some(s), Some(u)) => s.min(u),
        (Some(s), None) | (None, Some(s)) => s,
        (None, None) => DEFAULT_MAX_COST_USD_PER_PEER_MICROS,
    };

    let party_trust = EffectivePartyTrustPolicy {
        max_default_profile,
        max_peer_override,
        max_external_guest_profile,
        max_turns_per_peer,
        max_cost_usd_per_peer_micros,
    };

    // 3. [lan] (backward-compatible merge of policy.toml [lan] + legacy lan.toml!)
    let combined_sys_lan = merge_partial_lan_stricter(
        system_policy.map(|p| &p.lan),
        legacy_system_lan,
    );
    let combined_usr_lan = merge_partial_lan_stricter(
        user_policy.map(|p| &p.lan),
        legacy_user_lan,
    );
    let lan = resolve_lan_policy(
        combined_sys_lan.as_ref(),
        combined_usr_lan.as_ref(),
        env_lan_disabled,
    );

    // 4. [online]
    let sys_o = system_policy.map(|p| &p.online);
    let usr_o = user_policy.map(|p| &p.online);

    let online = EffectiveOnlinePolicy {
        disabled: sys_o.and_then(|o| o.disabled).unwrap_or(false)
            || usr_o.and_then(|o| o.disabled).unwrap_or(false),
        require_force_relays: sys_o.and_then(|o| o.require_force_relays).unwrap_or(false)
            || usr_o.and_then(|o| o.require_force_relays).unwrap_or(false),
        allowed_authorities: merge_allowlist_intersection(
            sys_o.and_then(|o| o.allowed_authorities.as_ref()),
            usr_o.and_then(|o| o.allowed_authorities.as_ref()),
        ),
        allowed_org_slugs: merge_allowlist_intersection(
            sys_o.and_then(|o| o.allowed_org_slugs.as_ref()),
            usr_o.and_then(|o| o.allowed_org_slugs.as_ref()),
        ),
        allow_personal_parties: sys_o.and_then(|o| o.allow_personal_parties).unwrap_or(true)
            && usr_o.and_then(|o| o.allow_personal_parties).unwrap_or(true),
    };

    Ok(EffectiveUnifiedPolicy {
        brakes,
        party_trust,
        lan,
        online,
    })
}

/// Computes the effective trust tier for a remote peer, monotonically clamping against
/// `max_default_profile`, `max_peer_override`, and (for external org guests)
/// `max_external_guest_profile`.
pub fn effective_peer_trust(
    base_profile: PartyTrustProfile,
    peer_override: Option<PartyTrustProfile>,
    is_external_guest: bool,
    policy: &EffectivePartyTrustPolicy,
) -> PartyTrustProfile {
    let chosen = match peer_override {
        Some(ov) => ov.min(policy.max_peer_override),
        None => base_profile.min(policy.max_default_profile),
    };
    if is_external_guest {
        chosen.min(policy.max_external_guest_profile)
    } else {
        chosen
    }
}
