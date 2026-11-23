//! Strict Ed25519 verification (`verify_strict`), SHA-256, invite hashing, and handle validation.
//! Uses audited open-source primitives only (`ed25519-dalek`, `sha2`).

use core::fmt;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::ids::PartyId;

pub type Ed25519PubKey = [u8; 32];
pub type Ed25519Sig = [u8; 64];
pub type Sha256Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidPublicKey,
    WeakPublicKey,
    InvalidSignature,
    InvalidHandle,
    ReservedHandle,
    InvalidRecoveryKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key encoding"),
            Self::WeakPublicKey => write!(f, "Ed25519 public key is a small-order/weak point"),
            Self::InvalidSignature => write!(f, "Ed25519 strict signature verification failed"),
            Self::InvalidHandle => write!(f, "invalid handle format"),
            Self::ReservedHandle => write!(f, "handle is reserved"),
            Self::InvalidRecoveryKey => write!(f, "invalid recovery key encoding or checksum"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn sha256(data: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hex_lower_32(bytes: &Sha256Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0f);
        if let (Some(&c1), Some(&c2)) = (HEX.get(hi), HEX.get(lo)) {
            out.push(char::from(c1));
            out.push(char::from(c2));
        }
    }
    out
}

/// Validates an Ed25519 public key strictly:
/// 1. Must decode to a valid canonical compressed Edwards Y coordinate (`p = 2^255 - 19`).
/// 2. Must NOT be a weak / small-order point and MUST be torsion-free (prime-order subgroup only,
///    rejecting mixed-order points for cross-library cofactorless/cofactored consistency).
pub fn validate_ed25519_pubkey_strict(pubkey: &Ed25519PubKey) -> Result<VerifyingKey, CryptoError> {
    // Reject non-canonical Y >= 2^255 - 19 explicitly (clear sign bit in byte 31).
    let mut y_bytes = *pubkey;
    if let Some(last) = y_bytes.get_mut(31) {
        *last &= 0x7f;
    }
    // p = 2^255 - 19 in little-endian: [0xed, 0xff, ..., 0xff, 0x7f]
    if is_non_canonical_field_elem(&y_bytes) {
        return Err(CryptoError::InvalidPublicKey);
    }

    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| CryptoError::InvalidPublicKey)?;
    if vk.is_weak() || !vk.to_edwards().is_torsion_free() {
        return Err(CryptoError::WeakPublicKey);
    }
    Ok(vk)
}

fn is_non_canonical_field_elem(le_bytes: &[u8; 32]) -> bool {
    // p = 2^255 - 19: bytes 1..=30 are 0xff, byte 31 is 0x7f, byte 0 is 0xed.
    // Since sign bit was cleared, le_bytes[31] <= 0x7f.
    // Value >= p iff byte 31 == 0x7f && bytes 1..=30 == 0xff && byte 0 >= 0xed.
    if le_bytes.get(31) != Some(&0x7f) {
        return false;
    }
    for i in 1..31 {
        if le_bytes.get(i) != Some(&0xff) {
            return false;
        }
    }
    matches!(le_bytes.first(), Some(&b) if b >= 0xed)
}

/// Strictly verifies an Ed25519 signature using `ed25519_dalek::VerifyingKey::verify_strict`,
/// rejecting small-order keys, non-canonical `R`, and non-canonical `S >= L`.
pub fn verify_ed25519_strict(
    pubkey: &Ed25519PubKey,
    message: &[u8],
    signature: &Ed25519Sig,
) -> Result<(), CryptoError> {
    let vk = validate_ed25519_pubkey_strict(pubkey)?;
    // Explicitly check R is canonical too (verify_strict checks small-order R and S < L).
    let mut r_y = [0u8; 32];
    if let Some(r_slice) = signature.get(0..32) {
        r_y.copy_from_slice(r_slice);
    }
    if let Some(last) = r_y.get_mut(31) {
        *last &= 0x7f;
    }
    if is_non_canonical_field_elem(&r_y) {
        return Err(CryptoError::InvalidSignature);
    }

    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Domain separation string defined by `iroh-relay` v1.5.0 (`protos/handshake.rs`).
pub const IROH_RELAY_CHALLENGE_DOMAIN_SEP: &str = "iroh-relay handshake v1 challenge signature";

/// Verifies an `iroh-relay` v1/v2 `ClientAuth` challenge-response Ed25519 signature:
/// `msg = blake3::derive_key("iroh-relay handshake v1 challenge signature", challenge)`,
/// verified strictly (torsion-free pubkey, canonical R and S < L).
pub fn verify_iroh_relay_challenge(
    pubkey: &Ed25519PubKey,
    challenge: &[u8; 16],
    signature: &Ed25519Sig,
) -> Result<(), CryptoError> {
    let derived = blake3::derive_key(IROH_RELAY_CHALLENGE_DOMAIN_SEP, challenge);
    verify_ed25519_strict(pubkey, &derived, signature)
}

/// Domain separation string for canonical cross-client Safety Numbers (Blackbird & Outpost).
pub const SAFETY_NUMBER_DOMAIN_SEP: &str = "mp-safety-v1:";

/// Prefix and domain separation string for canonical cross-client Root Recovery Keys (`mprk1_...`).
pub const RECOVERY_KEY_PREFIX: &str = "mprk1_";
pub const RECOVERY_KEY_DOMAIN_SEP: &str = "mp-recovery-v1:";

/// Domain separation string for 128-bit device-link confirmation fingerprints.
pub const DEVICE_FP_DOMAIN_SEP: &str = "mpdevfp2:";

/// Domain separation string for per-device signed X25519 encryption subkey certs (Unit 5).
pub const ENC_SUBKEY_CERT_DOMAIN_SEP: &str = "mp-enc-subkey-v1:";
/// Exact canonical byte length of `enc_cert`:
/// `version(1) || account_id(8) || device_id(8) || root_pubkey(32) || enc_pk(32) || iat_s(8) || exp_s(8) || ed25519_sig(64) = 161 B`.
pub const ENC_SUBKEY_CERT_BYTES: usize = 161;
pub const ENC_SUBKEY_CERT_BODY_BYTES: usize = 97;
pub const MAX_ENC_CERT_TTL_SECS: i64 = 30 * 86_400;
pub const ENC_CERT_CLOCK_SKEW_SECS: i64 = 300;

/// All 12 low-order Curve25519 Montgomery u-coordinates (RFC 7748 / libsodium) after clearing bit 255.
const LOW_ORDER_X25519_POINTS: [[u8; 32]; 12] = [
    // 0
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 1
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 325606250916557431795983626356110631294008115727848805560023387167927233504
    [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
     0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823
    [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
     0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
    // p - 1
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    // p
    [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    // p + 1
    [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    // 2p - 1 (high bit cleared -> same as p - 1, include canonical non-reduced equivalents below)
    [0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
     0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x7f],
    [0x4c, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
     0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
    // p + 2^255 - 19 (already covered by high-bit mask, also reject u >= p explicitly!)
    [0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
];

/// Validates a 32-byte X25519 public key strictly: rejects non-canonical `u >= p`,
/// high bit set (`>= 2^255`), all-zero, and all 12 low-order Curve25519 points.
pub fn validate_x25519_pubkey_strict(enc_pk: &[u8; 32]) -> Result<(), CryptoError> {
    let mut masked = *enc_pk;
    if let Some(last) = masked.get_mut(31) {
        if (*last & 0x80) != 0 {
            return Err(CryptoError::InvalidPublicKey);
        }
        *last &= 0x7f;
    }
    if is_non_canonical_field_elem(&masked) {
        return Err(CryptoError::InvalidPublicKey);
    }
    for low in &LOW_ORDER_X25519_POINTS {
        if &masked == low {
            return Err(CryptoError::WeakPublicKey);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncSubkeyCertClaims {
    pub account_id: u64,
    pub device_id: u64,
    pub root_pubkey: Ed25519PubKey,
    pub enc_pk: [u8; 32],
    pub iat_s: i64,
    pub exp_s: i64,
}

/// Strictly verifies a canonical `161 B` per-device X25519 encryption subkey certificate.
/// Signed by `expected_device_pk` (the device's authoritative Ed25519 key from `AccountDO`)
/// over `"mp-enc-subkey-v1:" || body[0..97]`, binding `(account_id, device_id, root_pubkey, enc_pk, iat_s, exp_s)`.
pub fn verify_enc_subkey_cert(
    cert: &[u8],
    expected_account_id: u64,
    expected_device_id: u64,
    expected_root_pk: &Ed25519PubKey,
    expected_device_pk: &Ed25519PubKey,
    now_s: i64,
) -> Result<EncSubkeyCertClaims, CryptoError> {
    if cert.len() != ENC_SUBKEY_CERT_BYTES {
        return Err(CryptoError::InvalidSignature);
    }
    let body = cert
        .get(0..ENC_SUBKEY_CERT_BODY_BYTES)
        .ok_or(CryptoError::InvalidSignature)?;
    let sig_s = cert
        .get(ENC_SUBKEY_CERT_BODY_BYTES..ENC_SUBKEY_CERT_BYTES)
        .ok_or(CryptoError::InvalidSignature)?;
    let sig: Ed25519Sig = sig_s.try_into().map_err(|_| CryptoError::InvalidSignature)?;

    if body.first() != Some(&1u8) {
        return Err(CryptoError::InvalidSignature);
    }
    let account_id = u64::from_le_bytes(
        body.get(1..9)
            .ok_or(CryptoError::InvalidSignature)?
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?,
    );
    let device_id = u64::from_le_bytes(
        body.get(9..17)
            .ok_or(CryptoError::InvalidSignature)?
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?,
    );
    let root_pubkey: Ed25519PubKey = body
        .get(17..49)
        .ok_or(CryptoError::InvalidSignature)?
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let enc_pk: [u8; 32] = body
        .get(49..81)
        .ok_or(CryptoError::InvalidSignature)?
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let iat_s = i64::from_le_bytes(
        body.get(81..89)
            .ok_or(CryptoError::InvalidSignature)?
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?,
    );
    let exp_s = i64::from_le_bytes(
        body.get(89..97)
            .ok_or(CryptoError::InvalidSignature)?
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?,
    );

    if account_id != expected_account_id
        || device_id != expected_device_id
        || &root_pubkey != expected_root_pk
    {
        return Err(CryptoError::InvalidSignature);
    }
    let ttl = exp_s.saturating_sub(iat_s);
    if !(1..=MAX_ENC_CERT_TTL_SECS).contains(&ttl)
        || iat_s > now_s.saturating_add(ENC_CERT_CLOCK_SKEW_SECS)
        || exp_s <= now_s
    {
        return Err(CryptoError::InvalidSignature);
    }
    validate_x25519_pubkey_strict(&enc_pk)?;

    let mut msg = Vec::with_capacity(ENC_SUBKEY_CERT_DOMAIN_SEP.len() + ENC_SUBKEY_CERT_BODY_BYTES);
    msg.extend_from_slice(ENC_SUBKEY_CERT_DOMAIN_SEP.as_bytes());
    msg.extend_from_slice(body);
    verify_ed25519_strict(expected_device_pk, &msg, &sig)?;

    Ok(EncSubkeyCertClaims {
        account_id,
        device_id,
        root_pubkey,
        enc_pk,
        iat_s,
        exp_s,
    })
}

const CROCKFORD_B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_decode_char(b: u8) -> Option<u8> {
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

fn recovery_key_checksum(root_seed: &[u8; 32]) -> [u8; 2] {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_KEY_DOMAIN_SEP.as_bytes());
    hasher.update(root_seed);
    let digest: [u8; 32] = hasher.finalize().into();
    [
        digest.first().copied().unwrap_or(0),
        digest.get(1).copied().unwrap_or(0),
    ]
}

pub fn zeroize_bytes(buf: &mut [u8]) {
    zeroize::Zeroize::zeroize(buf);
}

/// Encodes a 32-byte Ed25519 root private seed as a canonical human-copyable Recovery Key:
/// `payload[34] = root_seed[32] || SHA-256("mp-recovery-v1:" || root_seed)[0..2]`
/// encoded MSB-first into 55 Crockford Base32 chars (272 payload bits + 3 trailing zero bits)
/// grouped as `mprk1_XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
pub fn encode_recovery_key(root_seed: &[u8; 32]) -> String {
    let chk = recovery_key_checksum(root_seed);
    let mut payload = [0u8; 34];
    if let Some(dst) = payload.get_mut(0..32) {
        dst.copy_from_slice(root_seed);
    }
    if let Some(slot) = payload.get_mut(32) {
        *slot = chk[0];
    }
    if let Some(slot) = payload.get_mut(33) {
        *slot = chk[1];
    }

    let mut out = String::with_capacity(RECOVERY_KEY_PREFIX.len() + 55 + 10);
    out.push_str(RECOVERY_KEY_PREFIX);

    let mut bit_buf: u32 = 0;
    let mut bit_len: u32 = 0;
    let mut emitted: usize = 0;

    for &byte in &payload {
        bit_buf = (bit_buf << 8) | u32::from(byte);
        bit_len += 8;
        while bit_len >= 5 {
            bit_len -= 5;
            let idx = usize::try_from((bit_buf >> bit_len) & 0x1f).unwrap_or(0);
            if emitted > 0 && emitted.is_multiple_of(5) {
                out.push('-');
            }
            if let Some(&ch) = CROCKFORD_B32.get(idx) {
                out.push(char::from(ch));
            }
            emitted += 1;
        }
    }
    // 272 mod 5 == 2 remaining bits; pad 3 trailing zero bits for the 55th symbol.
    if bit_len > 0 {
        let idx = usize::try_from((bit_buf << (5 - bit_len)) & 0x1f).unwrap_or(0);
        if emitted > 0 && emitted.is_multiple_of(5) {
            out.push('-');
        }
        if let Some(&ch) = CROCKFORD_B32.get(idx) {
            out.push(char::from(ch));
        }
    }
    zeroize_bytes(&mut payload);
    out
}

/// Decodes and validates a canonical `mprk1_...` Recovery Key.
/// Accepts case-insensitive ASCII (<= 128 chars), optional `-`/ASCII whitespace separators,
/// and Crockford typo aliases (`O->0`, `I/L->1`). Rejects non-canonical trailing padding bits
/// and bad checksums.
pub fn decode_recovery_key(raw: &str) -> Result<[u8; 32], CryptoError> {
    if raw.len() > 128 || !raw.is_ascii() {
        return Err(CryptoError::InvalidRecoveryKey);
    }
    let trimmed = raw.trim();
    let body = if let Some(rest) = trimmed.strip_prefix(RECOVERY_KEY_PREFIX) {
        rest
    } else if trimmed.len() >= RECOVERY_KEY_PREFIX.len()
        && trimmed
            .get(0..RECOVERY_KEY_PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(RECOVERY_KEY_PREFIX))
    {
        trimmed
            .get(RECOVERY_KEY_PREFIX.len()..)
            .ok_or(CryptoError::InvalidRecoveryKey)?
    } else {
        return Err(CryptoError::InvalidRecoveryKey);
    };

    let mut symbols = [0u8; 55];
    let mut count = 0usize;
    for &b in body.as_bytes() {
        if b == b'-' || b.is_ascii_whitespace() {
            continue;
        }
        let Some(val) = crockford_decode_char(b) else {
            zeroize_bytes(&mut symbols);
            return Err(CryptoError::InvalidRecoveryKey);
        };
        let Some(slot) = symbols.get_mut(count) else {
            zeroize_bytes(&mut symbols);
            return Err(CryptoError::InvalidRecoveryKey);
        };
        *slot = val;
        count += 1;
    }
    if count != 55 {
        zeroize_bytes(&mut symbols);
        return Err(CryptoError::InvalidRecoveryKey);
    }

    let mut payload = [0u8; 34];
    let mut out_idx = 0usize;
    let mut bit_buf: u32 = 0;
    let mut bit_len: u32 = 0;
    for &sym in &symbols {
        bit_buf = (bit_buf << 5) | u32::from(sym);
        bit_len += 5;
        while bit_len >= 8 {
            bit_len -= 8;
            let Some(slot) = payload.get_mut(out_idx) else {
                zeroize_bytes(&mut symbols);
                zeroize_bytes(&mut payload);
                return Err(CryptoError::InvalidRecoveryKey);
            };
            *slot = u8::try_from((bit_buf >> bit_len) & 0xff).unwrap_or(0);
            out_idx += 1;
        }
    }
    zeroize_bytes(&mut symbols);

    // Enforce canonical zero padding in the final 3 unused bits.
    if out_idx != 34 || bit_len != 3 || (bit_buf & 0x07) != 0 {
        zeroize_bytes(&mut payload);
        return Err(CryptoError::InvalidRecoveryKey);
    }

    let mut seed = [0u8; 32];
    let Some(seed_slice) = payload.get(0..32) else {
        zeroize_bytes(&mut payload);
        return Err(CryptoError::InvalidRecoveryKey);
    };
    seed.copy_from_slice(seed_slice);
    let expected = recovery_key_checksum(&seed);
    let c0 = payload.get(32).copied().unwrap_or(0);
    let c1 = payload.get(33).copied().unwrap_or(0);
    zeroize_bytes(&mut payload);

    let diff = core::hint::black_box((c0 ^ expected[0]) | (c1 ^ expected[1]));
    if diff != 0 {
        zeroize_bytes(&mut seed);
        return Err(CryptoError::InvalidRecoveryKey);
    }
    Ok(seed)
}

/// Computes the 128-bit device-link confirmation fingerprint (`XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX`):
/// first 16 bytes of `SHA-256("mpdevfp2:" || device_pubkey)` formatted as 32 lowercase hex chars
/// in 4 groups of 8 (35 ASCII chars total).
pub fn compute_device_fingerprint(device_pubkey: &Ed25519PubKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_FP_DOMAIN_SEP.as_bytes());
    hasher.update(device_pubkey);
    let digest: [u8; 32] = hasher.finalize().into();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(35);
    for i in 0usize..16 {
        if i > 0 && i.is_multiple_of(4) {
            out.push('-');
        }
        let b = digest.get(i).copied().unwrap_or(0);
        if let (Some(&c1), Some(&c2)) = (HEX.get(usize::from(b >> 4)), HEX.get(usize::from(b & 0x0f))) {
            out.push(char::from(c1));
            out.push(char::from(c2));
        }
    }
    out
}

/// Computes the canonical 39-character Crockford Base32 Safety Number shared by Blackbird,
/// Outpost, and the web account portal:
/// `first 20 bytes of SHA-256("mp-safety-v1:" || account_id_le64 || root_pubkey[32])`
/// encoded MSB-first (RFC 4648 bit order) into 32 uppercase Crockford Base32 characters
/// grouped as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
pub fn compute_safety_number(account_id: u64, root_pubkey: &Ed25519PubKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SAFETY_NUMBER_DOMAIN_SEP.as_bytes());
    hasher.update(account_id.to_le_bytes());
    hasher.update(root_pubkey);
    let digest: [u8; 32] = hasher.finalize().into();

    let mut out = String::with_capacity(39);
    // 20 bytes = 160 bits = 32 groups of 5 bits (4 chunks of 5 bytes -> 8 Base32 chars each).
    for chunk_idx in 0..4 {
        let base = chunk_idx * 5;
        let b0 = u64::from(digest.get(base).copied().unwrap_or(0));
        let b1 = u64::from(digest.get(base + 1).copied().unwrap_or(0));
        let b2 = u64::from(digest.get(base + 2).copied().unwrap_or(0));
        let b3 = u64::from(digest.get(base + 3).copied().unwrap_or(0));
        let b4 = u64::from(digest.get(base + 4).copied().unwrap_or(0));
        let bits40: u64 = (b0 << 32) | (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;

        for g in 0..8 {
            if (chunk_idx > 0 && g == 0) || g == 4 {
                out.push('-');
            }
            let shift = 35 - g * 5;
            let idx = usize::try_from((bits40 >> shift) & 0x1f).unwrap_or(0);
            if let Some(&ch) = CROCKFORD_B32.get(idx) {
                out.push(char::from(ch));
            }
        }
    }
    out
}

/// Domain-separated SHA-256 hash for account onboarding invite secrets (`mpinv1:`).
pub fn hash_account_invite_secret(raw_secret: &[u8; 32]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"mpinv1:");
    hasher.update(raw_secret);
    hasher.finalize().into()
}

/// Domain-separated SHA-256 hash for party invite secrets (`mppi1:` || party_id_le64 || secret).
pub fn hash_party_invite_secret(party_id: PartyId, raw_secret: &[u8; 32]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"mppi1:");
    hasher.update(party_id.to_le_bytes());
    hasher.update(raw_secret);
    hasher.finalize().into()
}

/// Mutable user handle property (never a primary key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    display: String,
    normalized: String,
}

const RESERVED_HANDLES: &[&str] = &[
    "admin",
    "administrator",
    "api",
    "auth",
    "blackbird",
    "help",
    "lobby",
    "mod",
    "moderator",
    "multiplayer",
    "neon",
    "official",
    "operator",
    "party",
    "privacy",
    "relay",
    "root",
    "security",
    "staff",
    "status",
    "support",
    "sys",
    "system",
    "team",
    "waitlist",
    "www",
];

impl Handle {
    /// Rules: 3..=32 ASCII chars, starts and ends with `[A-Za-z0-9]`, interior `[A-Za-z0-9_-]`,
    /// no consecutive `__` or `--`. Stored normalized as lowercase ASCII.
    pub fn parse(raw: &str) -> Result<Self, CryptoError> {
        let bytes = raw.as_bytes();
        if bytes.len() < 3 || bytes.len() > 32 {
            return Err(CryptoError::InvalidHandle);
        }
        let first = bytes.first().copied().ok_or(CryptoError::InvalidHandle)?;
        let last = bytes.last().copied().ok_or(CryptoError::InvalidHandle)?;
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return Err(CryptoError::InvalidHandle);
        }
        let mut prev_sep = false;
        for &b in bytes {
            let is_sep = b == b'-' || b == b'_';
            if !(b.is_ascii_alphanumeric() || is_sep) {
                return Err(CryptoError::InvalidHandle);
            }
            if is_sep && prev_sep {
                return Err(CryptoError::InvalidHandle);
            }
            prev_sep = is_sep;
        }
        let normalized = raw.to_ascii_lowercase();
        if RESERVED_HANDLES.contains(&normalized.as_str()) {
            return Err(CryptoError::ReservedHandle);
        }
        Ok(Self {
            display: raw.to_owned(),
            normalized,
        })
    }

    pub fn display(&self) -> &str {
        &self.display
    }

    pub fn normalized(&self) -> &str {
        &self.normalized
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod enc_cert_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_enc_cert(
        device_sk: &SigningKey,
        account_id: u64,
        device_id: u64,
        root_pk: &Ed25519PubKey,
        enc_pk: &[u8; 32],
        iat_s: i64,
        exp_s: i64,
    ) -> [u8; ENC_SUBKEY_CERT_BYTES] {
        let mut body = [0u8; ENC_SUBKEY_CERT_BODY_BYTES];
        body[0] = 1;
        body[1..9].copy_from_slice(&account_id.to_le_bytes());
        body[9..17].copy_from_slice(&device_id.to_le_bytes());
        body[17..49].copy_from_slice(root_pk);
        body[49..81].copy_from_slice(enc_pk);
        body[81..89].copy_from_slice(&iat_s.to_le_bytes());
        body[89..97].copy_from_slice(&exp_s.to_le_bytes());

        let mut msg = Vec::with_capacity(ENC_SUBKEY_CERT_DOMAIN_SEP.len() + ENC_SUBKEY_CERT_BODY_BYTES);
        msg.extend_from_slice(ENC_SUBKEY_CERT_DOMAIN_SEP.as_bytes());
        msg.extend_from_slice(&body);
        let sig = device_sk.sign(&msg).to_bytes();

        let mut cert = [0u8; ENC_SUBKEY_CERT_BYTES];
        cert[0..ENC_SUBKEY_CERT_BODY_BYTES].copy_from_slice(&body);
        cert[ENC_SUBKEY_CERT_BODY_BYTES..ENC_SUBKEY_CERT_BYTES].copy_from_slice(&sig);
        cert
    }

    #[test]
    fn enc_subkey_cert_verifies_valid_and_rejects_low_order_x25519_points() {
        let root_sk = SigningKey::from_bytes(&[0x11; 32]);
        let dev_sk = SigningKey::from_bytes(&[0x22; 32]);
        let root_pk = root_sk.verifying_key().to_bytes();
        let dev_pk = dev_sk.verifying_key().to_bytes();
        let mut valid_x25519 = [0x42u8; 32];
        valid_x25519[31] &= 0x7f;

        let now_s = 1_800_000_000i64;
        let cert = make_enc_cert(&dev_sk, 1001, 2002, &root_pk, &valid_x25519, now_s - 10, now_s + 86_400);
        let claims = verify_enc_subkey_cert(&cert, 1001, 2002, &root_pk, &dev_pk, now_s)
            .expect("valid cert must verify");
        assert_eq!(claims.enc_pk, valid_x25519);

        assert!(verify_enc_subkey_cert(&cert, 1001, 2003, &root_pk, &dev_pk, now_s).is_err());
        let too_long = make_enc_cert(&dev_sk, 1001, 2002, &root_pk, &valid_x25519, now_s, now_s + 31 * 86_400);
        assert!(verify_enc_subkey_cert(&too_long, 1001, 2002, &root_pk, &dev_pk, now_s).is_err());

        for low in &LOW_ORDER_X25519_POINTS {
            let bad = make_enc_cert(&dev_sk, 1001, 2002, &root_pk, low, now_s - 10, now_s + 3600);
            assert!(verify_enc_subkey_cert(&bad, 1001, 2002, &root_pk, &dev_pk, now_s).is_err());
        }
    }
}
