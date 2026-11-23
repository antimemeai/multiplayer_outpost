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
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key encoding"),
            Self::WeakPublicKey => write!(f, "Ed25519 public key is a small-order/weak point"),
            Self::InvalidSignature => write!(f, "Ed25519 strict signature verification failed"),
            Self::InvalidHandle => write!(f, "invalid handle format"),
            Self::ReservedHandle => write!(f, "handle is reserved"),
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

const CROCKFORD_B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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
