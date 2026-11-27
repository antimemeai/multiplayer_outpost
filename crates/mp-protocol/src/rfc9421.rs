//! Strict RFC 9421 (HTTP Message Signatures) + RFC 9530 (Digest Fields) profile `mp1`.
//!
//! Enforces:
//! - Exactly one signature label `mp1`, `alg="ed25519"`, `tag="mp1"`.
//! - Covered components:
//!   - GET:    ("@method" "@authority" "@path" "@query") — body must be empty
//!   - Body:   ("@method" "@authority" "@path" "@query" "content-type" "content-digest")
//! - Strict URL hygiene: rejects dot-segments, `//`, `%2f`/`%5c`, non-ASCII, queries on non-whitelisted routes.
//! - Strict time window: `created < expires`, `expires - created <= 120`, `created <= now + 60`, `now <= expires`.
//! - Retention bound: `retain_until_ms = max(expires, created + 60) * 1000 + 5000`.
//! - Strict Ed25519 verification (`verify_strict`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use core::fmt;

use crate::crypto::{CryptoError, Ed25519PubKey, Ed25519Sig, sha256, verify_ed25519_strict};
use crate::ids::{AccountId, DeviceId, PartyId};

pub const MAX_CLOCK_SKEW_SECS: i64 = 60;
pub const MAX_SIGNATURE_WINDOW_SECS: i64 = 120;
pub const NONCE_RETENTION_SLACK_MS: i64 = 5_000;
pub const MIN_NONCE_LEN: usize = 22;
pub const MAX_NONCE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    pub fn parse(s: &str) -> Result<Self, Rfc9421Error> {
        match s {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            _ => Err(Rfc9421Error::UnsupportedMethod),
        }
    }

    pub const fn requires_body_headers(self) -> bool {
        !matches!(self, Self::Get)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyId {
    Device { account_id: AccountId, device_id: DeviceId },
    Root { account_id: AccountId },
    Registration { root_pubkey_sha256_prefix: [u8; 16] },
    Recovery { root_pubkey_sha256_prefix: [u8; 16] },
    DeviceLink { device_pubkey_sha256_prefix: [u8; 16] },
}

fn parse_hex16_prefix(hex_part: &str) -> Result<[u8; 16], Rfc9421Error> {
    if hex_part.len() != 32 {
        return Err(Rfc9421Error::InvalidKeyId);
    }
    let mut prefix = [0u8; 16];
    for (i, slot) in prefix.iter_mut().enumerate() {
        let hi = hex_nibble(hex_part.as_bytes().get(i * 2).copied())?;
        let lo = hex_nibble(hex_part.as_bytes().get(i * 2 + 1).copied())?;
        *slot = (hi << 4) | lo;
    }
    Ok(prefix)
}

fn format_hex16_prefix(label: &str, bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(label.len() + 32);
    out.push_str(label);
    for &b in bytes {
        if let (Some(&c1), Some(&c2)) =
            (HEX.get(usize::from(b >> 4)), HEX.get(usize::from(b & 0x0f)))
        {
            out.push(char::from(c1));
            out.push(char::from(c2));
        }
    }
    out
}

impl KeyId {
    pub fn parse(raw: &str) -> Result<Self, Rfc9421Error> {
        if let Some(hex_part) = raw.strip_prefix("reg.") {
            return Ok(Self::Registration {
                root_pubkey_sha256_prefix: parse_hex16_prefix(hex_part)?,
            });
        }
        if let Some(hex_part) = raw.strip_prefix("rec.") {
            return Ok(Self::Recovery {
                root_pubkey_sha256_prefix: parse_hex16_prefix(hex_part)?,
            });
        }
        if let Some(hex_part) = raw.strip_prefix("link.") {
            return Ok(Self::DeviceLink {
                device_pubkey_sha256_prefix: parse_hex16_prefix(hex_part)?,
            });
        }

        let (acct_str, rest) = raw.split_once('.').ok_or(Rfc9421Error::InvalidKeyId)?;
        let account_id = AccountId::parse_decimal(acct_str).map_err(|_| Rfc9421Error::InvalidKeyId)?;
        if rest == "root" {
            return Ok(Self::Root { account_id });
        }
        let device_id = DeviceId::parse_decimal(rest).map_err(|_| Rfc9421Error::InvalidKeyId)?;
        Ok(Self::Device {
            account_id,
            device_id,
        })
    }

    pub fn format(&self) -> String {
        match self {
            Self::Device {
                account_id,
                device_id,
            } => format!("{account_id}.{device_id}"),
            Self::Root { account_id } => format!("{account_id}.root"),
            Self::Registration {
                root_pubkey_sha256_prefix,
            } => format_hex16_prefix("reg.", root_pubkey_sha256_prefix),
            Self::Recovery {
                root_pubkey_sha256_prefix,
            } => format_hex16_prefix("rec.", root_pubkey_sha256_prefix),
            Self::DeviceLink {
                device_pubkey_sha256_prefix,
            } => format_hex16_prefix("link.", device_pubkey_sha256_prefix),
        }
    }
}

fn hex_nibble(b: Option<u8>) -> Result<u8, Rfc9421Error> {
    match b {
        Some(c @ b'0'..=b'9') => Ok(c - b'0'),
        Some(c @ b'a'..=b'f') => Ok(c - b'a' + 10),
        _ => Err(Rfc9421Error::InvalidKeyId),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rfc9421Error {
    UnsupportedMethod,
    InvalidAuthority,
    InvalidPath,
    QueryNotAllowed,
    UnexpectedBodyOnGet,
    ContentEncodingForbidden,
    MissingContentType,
    InvalidContentDigest,
    ContentDigestMismatch,
    InvalidSignatureInput,
    InvalidCoveredComponents,
    InvalidAlgorithm,
    InvalidTag,
    InvalidKeyId,
    InvalidNonce,
    InvalidWindow,
    ClockSkew,
    Expired,
    InvalidSignatureHeader,
    Crypto(CryptoError),
}

impl fmt::Display for Rfc9421Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Rfc9421Error {}

impl From<CryptoError> for Rfc9421Error {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignatureInput {
    pub components: Vec<String>,
    /// Canonical RFC 9421 §2.3 / RFC 8941 serialized `@signature-params` value.
    pub canonical_params: String,
    pub created: i64,
    pub expires: i64,
    pub nonce: String,
    pub keyid_raw: String,
    pub keyid: KeyId,
}

/// Computes RFC 9530 `Content-Digest` header value (`sha-256=:<b64>:`).
pub fn compute_content_digest(body: &[u8]) -> String {
    let digest = sha256(body);
    let b64 = B64_STD.encode(digest);
    format!("sha-256=:{b64}:")
}

fn is_party_requests_path(path: &str) -> bool {
    let mut segs = path.split('/').skip(1);
    match (segs.next(), segs.next(), segs.next(), segs.next(), segs.next()) {
        (Some("v1"), Some("parties"), Some(id_str), Some("requests"), None) => {
            PartyId::parse_decimal(id_str).is_ok()
        }
        _ => false,
    }
}

fn is_party_mls_commits_path(path: &str) -> bool {
    let mut segs = path.split('/').skip(1);
    match (
        segs.next(),
        segs.next(),
        segs.next(),
        segs.next(),
        segs.next(),
        segs.next(),
    ) {
        (Some("v1"), Some("parties"), Some(id_str), Some("mls"), Some("commits"), None) => {
            PartyId::parse_decimal(id_str).is_ok()
        }
        _ => false,
    }
}

/// Validates path and query hygiene strictly per Spec v2.1 §6.1:
/// - `@path` must start with `/`, be ASCII printable without whitespace, contain NO `%`
///   (all API paths are static ASCII or decimal integer IDs; rejecting `%` kills `%2e`, `%2f`, `%5c`,
///   and malformed percent escapes), NO `//`, NO `\`, and NO `.` or `..` segments.
/// - `@query` per RFC 9421 §2.2.7 is always `?<raw_query>` (leading `?` even when empty).
///   Non-empty queries are permitted ONLY on `GET /v1/accounts/resolve`,
///   `GET /v1/parties/<id>/requests`, and `GET /v1/parties/<id>/mls/commits`.
pub fn validate_path_and_query(
    method: HttpMethod,
    path: &str,
    query: &str,
) -> Result<(), Rfc9421Error> {
    if !path.starts_with('/') || path.len() > 256 {
        return Err(Rfc9421Error::InvalidPath);
    }
    if path.contains("//") || path.contains('\\') || path.contains('%') {
        return Err(Rfc9421Error::InvalidPath);
    }
    if !path.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(Rfc9421Error::InvalidPath);
    }
    for seg in path.split('/').skip(1) {
        if seg == "." || seg == ".." {
            return Err(Rfc9421Error::InvalidPath);
        }
    }

    if !query.starts_with('?') || query.len() > 256 {
        return Err(Rfc9421Error::InvalidPath);
    }
    if !query.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(Rfc9421Error::InvalidPath);
    }
    if query.len() > 1 {
        let query_allowed = method == HttpMethod::Get
            && (path == "/v1/accounts/resolve"
                || is_party_requests_path(path)
                || is_party_mls_commits_path(path));
        if !query_allowed {
            return Err(Rfc9421Error::QueryNotAllowed);
        }
    }
    Ok(())
}

/// Parses a strict single-label `Signature-Input` header per RFC 9421 / RFC 8941 and
/// produces its canonical `@signature-params` serialization (RFC 9421 §2.3).
pub fn parse_signature_input(header: &str) -> Result<ParsedSignatureInput, Rfc9421Error> {
    // Trim HTTP OWS (SP / HTAB) only — reject CR/LF/VT/FF and other control chars.
    let trimmed = header.trim_matches(|c| c == ' ' || c == '\t');
    if !trimmed.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Rfc9421Error::InvalidSignatureInput);
    }
    let rest = trimmed
        .strip_prefix("mp1=")
        .ok_or(Rfc9421Error::InvalidSignatureInput)?;
    if !rest.starts_with('(') {
        return Err(Rfc9421Error::InvalidSignatureInput);
    }
    let close_paren = rest.find(')').ok_or(Rfc9421Error::InvalidSignatureInput)?;
    let inner = rest
        .get(1..close_paren)
        .ok_or(Rfc9421Error::InvalidSignatureInput)?;
    let params_part = rest
        .get(close_paren + 1..)
        .ok_or(Rfc9421Error::InvalidSignatureInput)?;

    // Reject multiple signature dictionary members (no commas outside quotes).
    if params_part.contains(',') {
        return Err(Rfc9421Error::InvalidSignatureInput);
    }

    // RFC 8941 §3.1.1: Inner List members are separated by one or more SP (0x20) only.
    let mut components = Vec::new();
    for tok in inner.split(' ') {
        if tok.is_empty() {
            continue;
        }
        let unquoted = tok
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or(Rfc9421Error::InvalidSignatureInput)?;
        if unquoted.is_empty() || unquoted.contains('"') || unquoted.contains('\\') {
            return Err(Rfc9421Error::InvalidSignatureInput);
        }
        components.push(unquoted.to_owned());
    }
    if components.is_empty() {
        return Err(Rfc9421Error::InvalidCoveredComponents);
    }

    let mut created: Option<i64> = None;
    let mut expires: Option<i64> = None;
    let mut nonce: Option<String> = None;
    let mut keyid_raw: Option<String> = None;
    let mut alg: Option<String> = None;
    let mut tag: Option<String> = None;
    let mut param_order: Vec<&'static str> = Vec::with_capacity(6);

    if !params_part.starts_with(';') {
        return Err(Rfc9421Error::InvalidSignatureInput);
    }
    for param in params_part.split(';').skip(1) {
        // RFC 8941 §3.1.2 allows optional SP after `;` before key.
        let param = param.trim_start_matches(' ');
        let (k, v) = param
            .split_once('=')
            .ok_or(Rfc9421Error::InvalidSignatureInput)?;
        match k {
            "created" => {
                if created.is_some() {
                    return Err(Rfc9421Error::InvalidSignatureInput);
                }
                created = Some(parse_sf_int(v)?);
                param_order.push("created");
            }
            "expires" => {
                if expires.is_some() {
                    return Err(Rfc9421Error::InvalidSignatureInput);
                }
                expires = Some(parse_sf_int(v)?);
                param_order.push("expires");
            }
            "nonce" => {
                if nonce.is_some() {
                    return Err(Rfc9421Error::InvalidSignatureInput);
                }
                nonce = Some(parse_sf_string(v)?);
                param_order.push("nonce");
            }
            "keyid" => {
                if keyid_raw.is_some() {
                    return Err(Rfc9421Error::InvalidSignatureInput);
                }
                keyid_raw = Some(parse_sf_string(v)?);
                param_order.push("keyid");
            }
            "alg" => {
                if alg.is_some() {
                    return Err(Rfc9421Error::InvalidSignatureInput);
                }
                alg = Some(parse_sf_string(v)?);
                param_order.push("alg");
            }
            "tag" => {
                if tag.is_some() {
                    return Err(Rfc9421Error::InvalidSignatureInput);
                }
                tag = Some(parse_sf_string(v)?);
                param_order.push("tag");
            }
            _ => return Err(Rfc9421Error::InvalidSignatureInput),
        }
    }

    if alg.as_deref() != Some("ed25519") {
        return Err(Rfc9421Error::InvalidAlgorithm);
    }
    if tag.as_deref() != Some("mp1") {
        return Err(Rfc9421Error::InvalidTag);
    }
    let created = created.ok_or(Rfc9421Error::InvalidSignatureInput)?;
    let expires = expires.ok_or(Rfc9421Error::InvalidSignatureInput)?;
    let nonce = nonce.ok_or(Rfc9421Error::InvalidNonce)?;
    validate_nonce(&nonce)?;
    let keyid_raw = keyid_raw.ok_or(Rfc9421Error::InvalidKeyId)?;
    let keyid = KeyId::parse(&keyid_raw)?;

    // Canonically serialize `@signature-params` per RFC 9421 §2.3 / RFC 8941 §4.1.1.
    let mut canonical_params = String::with_capacity(rest.len());
    canonical_params.push('(');
    for (idx, comp) in components.iter().enumerate() {
        if idx > 0 {
            canonical_params.push(' ');
        }
        canonical_params.push('"');
        canonical_params.push_str(comp);
        canonical_params.push('"');
    }
    canonical_params.push(')');
    for k in param_order {
        canonical_params.push(';');
        canonical_params.push_str(k);
        canonical_params.push('=');
        match k {
            "created" => canonical_params.push_str(&created.to_string()),
            "expires" => canonical_params.push_str(&expires.to_string()),
            "nonce" => {
                canonical_params.push('"');
                canonical_params.push_str(&nonce);
                canonical_params.push('"');
            }
            "keyid" => {
                canonical_params.push('"');
                canonical_params.push_str(&keyid_raw);
                canonical_params.push('"');
            }
            "alg" => canonical_params.push_str("\"ed25519\""),
            "tag" => canonical_params.push_str("\"mp1\""),
            _ => {}
        }
    }

    Ok(ParsedSignatureInput {
        components,
        canonical_params,
        created,
        expires,
        nonce,
        keyid_raw,
        keyid,
    })
}

fn parse_sf_int(v: &str) -> Result<i64, Rfc9421Error> {
    if v.is_empty() || v.len() > 15 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Rfc9421Error::InvalidSignatureInput);
    }
    v.parse::<i64>().map_err(|_| Rfc9421Error::InvalidSignatureInput)
}

fn parse_sf_string(v: &str) -> Result<String, Rfc9421Error> {
    let inner = v
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(Rfc9421Error::InvalidSignatureInput)?;
    if inner.contains('"') || inner.contains('\\') || !inner.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Rfc9421Error::InvalidSignatureInput);
    }
    Ok(inner.to_owned())
}

fn validate_nonce(nonce: &str) -> Result<(), Rfc9421Error> {
    if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
        return Err(Rfc9421Error::InvalidNonce);
    }
    if !nonce
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Rfc9421Error::InvalidNonce);
    }
    Ok(())
}

/// Parses RFC 9421 `Signature` header (`mp1=:<base64(64B)>:`).
pub fn parse_signature_header(header: &str) -> Result<Ed25519Sig, Rfc9421Error> {
    let trimmed = header.trim();
    let b64 = trimmed
        .strip_prefix("mp1=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or(Rfc9421Error::InvalidSignatureHeader)?;
    if b64.contains(':') || b64.contains(',') {
        return Err(Rfc9421Error::InvalidSignatureHeader);
    }
    let bytes = B64_STD
        .decode(b64)
        .map_err(|_| Rfc9421Error::InvalidSignatureHeader)?;
    bytes
        .try_into()
        .map_err(|_| Rfc9421Error::InvalidSignatureHeader)
}

#[derive(Debug, Clone)]
pub struct Rfc9421Request<'a> {
    pub method: HttpMethod,
    pub authority: &'a str,
    pub path: &'a str,
    /// Per RFC 9421 §2.2.7: always starts with `?` (just `"?"` when no query string).
    pub query: &'a str,
    pub content_type: Option<&'a str>,
    pub content_digest: Option<&'a str>,
    pub has_content_encoding: bool,
    pub body: &'a [u8],
    pub signature_input: &'a str,
    pub signature: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    pub keyid: KeyId,
    pub nonce: String,
    pub created: i64,
    pub expires: i64,
    /// Exact millisecond timestamp until which the nonce MUST remain in `nonce_replay`.
    pub retain_until_ms: i64,
}

/// Builds the exact RFC 9421 §2.5 canonical signature base for the `mp1` profile.
pub fn build_signature_base(
    req: &Rfc9421Request<'_>,
    parsed: &ParsedSignatureInput,
) -> Result<Vec<u8>, Rfc9421Error> {
    let expected: &[&str] = if req.method.requires_body_headers() {
        &[
            "@method",
            "@authority",
            "@path",
            "@query",
            "content-type",
            "content-digest",
        ]
    } else {
        &["@method", "@authority", "@path", "@query"]
    };

    if parsed.components.len() != expected.len() {
        return Err(Rfc9421Error::InvalidCoveredComponents);
    }
    for (got, want) in parsed.components.iter().zip(expected.iter()) {
        if got != want {
            return Err(Rfc9421Error::InvalidCoveredComponents);
        }
    }

    let mut base = String::with_capacity(256);
    base.push_str("\"@method\": ");
    base.push_str(req.method.as_str());
    base.push('\n');

    base.push_str("\"@authority\": ");
    base.push_str(req.authority);
    base.push('\n');

    base.push_str("\"@path\": ");
    base.push_str(req.path);
    base.push('\n');

    base.push_str("\"@query\": ");
    base.push_str(req.query);
    base.push('\n');

    if req.method.requires_body_headers() {
        let ct = req.content_type.ok_or(Rfc9421Error::MissingContentType)?;
        let cd = req.content_digest.ok_or(Rfc9421Error::InvalidContentDigest)?;
        base.push_str("\"content-type\": ");
        base.push_str(ct.trim());
        base.push('\n');
        base.push_str("\"content-digest\": ");
        base.push_str(cd.trim());
        base.push('\n');
    }

    base.push_str("\"@signature-params\": ");
    base.push_str(&parsed.canonical_params);
    Ok(base.into_bytes())
}

/// Verifies an incoming HTTP/WS Upgrade request against our strict RFC 9421 + RFC 9530 profile.
pub fn verify_rfc9421_request(
    req: &Rfc9421Request<'_>,
    expected_authority: &str,
    pubkey: &Ed25519PubKey,
    now_s: i64,
) -> Result<VerifiedSignature, Rfc9421Error> {
    if req.authority != expected_authority {
        return Err(Rfc9421Error::InvalidAuthority);
    }
    if req.has_content_encoding {
        return Err(Rfc9421Error::ContentEncodingForbidden);
    }
    validate_path_and_query(req.method, req.path, req.query)?;

    if !req.method.requires_body_headers() && !req.body.is_empty() {
        return Err(Rfc9421Error::UnexpectedBodyOnGet);
    }

    let parsed = parse_signature_input(req.signature_input)?;

    // Bind `reg.<hex>`, `rec.<hex>`, and `link.<hex>` keyids cryptographically to sha256(pubkey)[..16]!
    match parsed.keyid {
        KeyId::Registration {
            root_pubkey_sha256_prefix: prefix,
        }
        | KeyId::Recovery {
            root_pubkey_sha256_prefix: prefix,
        }
        | KeyId::DeviceLink {
            device_pubkey_sha256_prefix: prefix,
        } => {
            let digest = sha256(pubkey);
            if digest.get(0..16) != Some(prefix.as_slice()) {
                return Err(Rfc9421Error::InvalidKeyId);
            }
        }
        KeyId::Device { .. } | KeyId::Root { .. } => {}
    }

    // 1. Validate time window syntax (`created < expires`, `expires - created <= 120`) —
    //    NOT server clock (`clock_skew`/`expired`) yet! We MUST verify Ed25519 signature BEFORE
    //    returning `ClockSkew`/`Expired` so unauthenticated probes cannot use clock_skew as an
    //    account/device existence oracle (Gate #2 10th Dentist H2).
    let window = parsed
        .expires
        .checked_sub(parsed.created)
        .ok_or(Rfc9421Error::InvalidWindow)?;
    if window <= 0 || window > MAX_SIGNATURE_WINDOW_SECS {
        return Err(Rfc9421Error::InvalidWindow);
    }

    if req.method.requires_body_headers() {
        let ct = req
            .content_type
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(Rfc9421Error::MissingContentType)?;
        if ct.contains('\r') || ct.contains('\n') {
            return Err(Rfc9421Error::MissingContentType);
        }
        let ct_base = ct
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or("")
            .to_ascii_lowercase();
        if ct_base != "application/json" {
            return Err(Rfc9421Error::MissingContentType);
        }
        let expected_cd = compute_content_digest(req.body);
        let got_cd = req
            .content_digest
            .map(str::trim)
            .ok_or(Rfc9421Error::InvalidContentDigest)?;
        if got_cd != expected_cd {
            return Err(Rfc9421Error::ContentDigestMismatch);
        }
    }

    // 2. Cryptographic verification FIRST!
    let sig_bytes = parse_signature_header(req.signature)?;
    let sig_base = build_signature_base(req, &parsed)?;
    verify_ed25519_strict(pubkey, &sig_base, &sig_bytes)?;

    // 3. Only AFTER valid Ed25519 signature: evaluate clock_skew / expired!
    let max_created = now_s.saturating_add(MAX_CLOCK_SKEW_SECS);
    if parsed.created > max_created {
        return Err(Rfc9421Error::ClockSkew);
    }
    if now_s > parsed.expires {
        // Distinguish drifted client (created too far in the past) vs expired short window.
        if parsed.created < now_s.saturating_sub(MAX_CLOCK_SKEW_SECS) {
            return Err(Rfc9421Error::ClockSkew);
        }
        return Err(Rfc9421Error::Expired);
    }

    let retain_until_s = parsed
        .expires
        .max(parsed.created.saturating_add(MAX_CLOCK_SKEW_SECS));
    let retain_until_ms = retain_until_s
        .saturating_mul(1000)
        .saturating_add(NONCE_RETENTION_SLACK_MS);

    Ok(VerifiedSignature {
        keyid: parsed.keyid,
        nonce: parsed.nonce,
        created: parsed.created,
        expires: parsed.expires,
        retain_until_ms,
    })
}
