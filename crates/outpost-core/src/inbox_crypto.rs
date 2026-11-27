//! E2EE Async Dead-Drop Inbox Suite 1 Cryptography Core (`#![forbid(unsafe_code)]`).
//!
//! Zero new external crates: built purely on safe Rust + workspace `ring`, `mp-protocol`,
//! `ed25519-dalek`, and `zeroize`.
//!
//! Implements:
//! 1. Constant-time RFC 7748 X25519 scalar multiplication over `GF(2^255 - 19)`.
//! 2. Standards-exact RFC 9180 HPKE `ModeAuth` (`KEM=0x0020`, `KDF=0x0001`, `AEAD=0x0003`:
//!    `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`).
//! 3. Dead-Drop Inbox Suite 1:
//!    - Canonical 161-byte `enc_cert` signing (`mp-enc-subkey-v1:`).
//!    - Exact ciphertext buckets (`1024 / 4096 / 16384 / 65536` bytes).
//!    - HKDF-SHA256 key-committing `(aead_key, aead_nonce, key_commit)` derivation.
//!    - Canonical `inbox_aad` & `wrap_aad` binding `key_commit` + `sha256(ciphertext)`.
//!    - Multi-device `seal_inbox_drop` & single-device `open_inbox_drop`.

use core::fmt;
use std::collections::BTreeSet;

use ed25519_dalek::{Signer as _, SigningKey};
use mp_protocol::{
    AccountId, DeviceId, ENC_SUBKEY_CERT_BODY_BYTES, ENC_SUBKEY_CERT_BYTES,
    ENC_SUBKEY_CERT_DOMAIN_SEP, sha256, validate_ed25519_pubkey_strict,
    validate_x25519_pubkey_strict,
};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

pub const INBOX_SUITE_1: u8 = 1;
pub const INBOX_BUCKETS: [usize; 4] = [1024, 4096, 16384, 65536];
pub const INBOX_AEAD_TAG_BYTES: usize = 16;
pub const INBOX_LENGTH_PREFIX_BYTES: usize = 4;
pub const INBOX_MAX_PLAINTEXT_BYTES: usize =
    65536 - INBOX_AEAD_TAG_BYTES - INBOX_LENGTH_PREFIX_BYTES;
pub const INBOX_AEAD_HKDF_INFO: &[u8] = b"mp-inbox-aead-v1";
pub const INBOX_HPKE_INFO: &[u8] = b"mp-inbox-hpke-v1";
pub const INBOX_KEY_COMMIT_BYTES: usize = 32;
pub const INBOX_HPKE_ENC_BYTES: usize = 32;
pub const INBOX_HPKE_WRAPPED_CEK_BYTES: usize = INBOX_HPKE_ENC_BYTES + 32 + INBOX_AEAD_TAG_BYTES;
/// Suite 1 `wrapped_key` wire layout: `key_commit(32) || hpke_enc(32) || hpke_ct(48) = 112 B`.
pub const INBOX_SUITE1_WRAPPED_KEY_BYTES: usize =
    INBOX_KEY_COMMIT_BYTES + INBOX_HPKE_WRAPPED_CEK_BYTES;
pub const INBOX_MAX_RECIPIENT_DEVICES: usize = 32;

pub const MAX_ENC_CERT_TTL_SECS: i64 = 30 * 86_400;

/// RFC 9180 HPKE cipher suite identifiers (Appendix A.2 / Suite 1).
pub const HPKE_KEM_DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;
pub const HPKE_MODE_AUTH: u8 = 0x02;

const HPKE_V1_PREFIX: &[u8] = b"HPKE-v1";
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

const INBOX_AAD_DOMAIN: &[u8; 16] = b"mp-inbox-aad-v1\0";
const INBOX_WRAP_AAD_DOMAIN: &[u8; 16] = b"mp-inbox-wrap-v1";

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxCryptoError {
    InvalidPublicKey,
    WeakPublicKey,
    WeakSharedSecret,
    InvalidCertTtl,
    InvalidSuite,
    PlaintextTooLarge,
    InvalidBucketSize,
    InvalidPadding,
    InvalidWrappedKey,
    KeyCommitMismatch,
    AeadFailed,
    HpkeFailed,
    SequenceOverflow,
    InvalidExpandLength,
    EmptyRecipients,
    TooManyRecipients,
    DuplicateRecipientDevice,
    EphemeralKeyCountMismatch,
}

impl fmt::Display for InboxCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for InboxCryptoError {}

// ---------------------------------------------------------------------------
// Constant-Time Helpers
// ---------------------------------------------------------------------------

fn is_all_zero_ct(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    core::hint::black_box(acc) == 0
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

// ---------------------------------------------------------------------------
// 1. Constant-Time RFC 7748 X25519 over GF(2^255 - 19)
// ---------------------------------------------------------------------------

const MASK51: u64 = (1u64 << 51) - 1;
const X25519_A24: u64 = 121_665;
const X25519_BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

/// Field element in `GF(2^255 - 19)` represented in radix `2^51` (`[u64; 5]`).
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Zeroize for Fe {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Fe {
    const ZERO: Self = Self([0, 0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    #[inline]
    fn load_le64(bytes: &[u8; 32], offset: usize) -> u64 {
        let b0 = u64::from(bytes.get(offset).copied().unwrap_or(0));
        let b1 = u64::from(bytes.get(offset + 1).copied().unwrap_or(0));
        let b2 = u64::from(bytes.get(offset + 2).copied().unwrap_or(0));
        let b3 = u64::from(bytes.get(offset + 3).copied().unwrap_or(0));
        let b4 = u64::from(bytes.get(offset + 4).copied().unwrap_or(0));
        let b5 = u64::from(bytes.get(offset + 5).copied().unwrap_or(0));
        let b6 = u64::from(bytes.get(offset + 6).copied().unwrap_or(0));
        let b7 = u64::from(bytes.get(offset + 7).copied().unwrap_or(0));
        b0 | (b1 << 8)
            | (b2 << 16)
            | (b3 << 24)
            | (b4 << 32)
            | (b5 << 40)
            | (b6 << 48)
            | (b7 << 56)
    }

    /// Decodes a 32-byte little-endian Montgomery u-coordinate, clearing bit 255 per RFC 7748 §5.
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut masked = *bytes;
        if let Some(last) = masked.get_mut(31) {
            *last &= 0x7f;
        }
        let l0 = Self::load_le64(&masked, 0) & MASK51;
        let l1 = (Self::load_le64(&masked, 6) >> 3) & MASK51;
        let l2 = (Self::load_le64(&masked, 12) >> 6) & MASK51;
        let l3 = (Self::load_le64(&masked, 19) >> 1) & MASK51;
        let l4 = (Self::load_le64(&masked, 24) >> 12) & MASK51;
        Self([l0, l1, l2, l3, l4])
    }

    #[inline]
    fn carry_reduce(mut l0: u64, mut l1: u64, mut l2: u64, mut l3: u64, mut l4: u64) -> Self {
        let c0 = l0 >> 51;
        l0 &= MASK51;
        l1 += c0;
        let c1 = l1 >> 51;
        l1 &= MASK51;
        l2 += c1;
        let c2 = l2 >> 51;
        l2 &= MASK51;
        l3 += c2;
        let c3 = l3 >> 51;
        l3 &= MASK51;
        l4 += c3;
        let c4 = l4 >> 51;
        l4 &= MASK51;
        l0 += c4 * 19;
        let c0 = l0 >> 51;
        l0 &= MASK51;
        l1 += c0;
        Self([l0, l1, l2, l3, l4])
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        Self::carry_reduce(a0 + b0, a1 + b1, a2 + b2, a3 + b3, a4 + b4)
    }

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        // Add 2p before subtracting so each limb stays strictly non-negative for reduced inputs.
        const TWO_P0: u64 = (1u64 << 52) - 38; // 2 * (2^51 - 19)
        const TWO_PN: u64 = (1u64 << 52) - 2; // 2 * (2^51 - 1)
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        Self::carry_reduce(
            (a0 + TWO_P0) - b0,
            (a1 + TWO_PN) - b1,
            (a2 + TWO_PN) - b2,
            (a3 + TWO_PN) - b3,
            (a4 + TWO_PN) - b4,
        )
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        let a0 = u128::from(a0);
        let a1 = u128::from(a1);
        let a2 = u128::from(a2);
        let a3 = u128::from(a3);
        let a4 = u128::from(a4);
        let b0 = u128::from(b0);
        let b1 = u128::from(b1);
        let b2 = u128::from(b2);
        let b3 = u128::from(b3);
        let b4 = u128::from(b4);

        let b1_19 = b1 * 19;
        let b2_19 = b2 * 19;
        let b3_19 = b3 * 19;
        let b4_19 = b4 * 19;

        let mut r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let mut r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let mut r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let mut r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let mut r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let mask = u128::from(MASK51);
        let c0 = r0 >> 51;
        r0 &= mask;
        r1 += c0;
        let c1 = r1 >> 51;
        r1 &= mask;
        r2 += c1;
        let c2 = r2 >> 51;
        r2 &= mask;
        r3 += c2;
        let c3 = r3 >> 51;
        r3 &= mask;
        r4 += c3;
        let c4 = r4 >> 51;
        r4 &= mask;
        r0 += c4 * 19;
        let c0 = r0 >> 51;
        r0 &= mask;
        r1 += c0;

        Self([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
    }

    #[inline]
    fn sq(self) -> Self {
        self.mul(self)
    }

    #[inline]
    fn pow2k(mut self, k: u32) -> Self {
        for _ in 0..k {
            self = self.sq();
        }
        self
    }

    #[inline]
    fn mul_a24(self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let k = u128::from(X25519_A24);
        let mut r0 = u128::from(a0) * k;
        let mut r1 = u128::from(a1) * k;
        let mut r2 = u128::from(a2) * k;
        let mut r3 = u128::from(a3) * k;
        let mut r4 = u128::from(a4) * k;

        let mask = u128::from(MASK51);
        let c0 = r0 >> 51;
        r0 &= mask;
        r1 += c0;
        let c1 = r1 >> 51;
        r1 &= mask;
        r2 += c1;
        let c2 = r2 >> 51;
        r2 &= mask;
        r3 += c2;
        let c3 = r3 >> 51;
        r3 &= mask;
        r4 += c3;
        let c4 = r4 >> 51;
        r4 &= mask;
        r0 += c4 * 19;
        let c0 = r0 >> 51;
        r0 &= mask;
        r1 += c0;

        Self([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
    }

    /// Computes `self^(p - 2) mod p` (`p - 2 = 2^255 - 21`).
    fn invert(self) -> Self {
        let t0 = self.sq(); // 2
        let t1 = t0.pow2k(2); // 8
        let t1 = t1.mul(self); // 9
        let t0 = t0.mul(t1); // 11
        let t2 = t0.sq(); // 22
        let t1 = t1.mul(t2); // 31 = 2^5 - 1
        let t2 = t1.pow2k(5).mul(t1); // 2^10 - 1
        let t3 = t2.pow2k(10).mul(t2); // 2^20 - 1
        let t3 = t3.pow2k(20).mul(t3); // 2^40 - 1
        let t3 = t3.pow2k(10).mul(t2); // 2^50 - 1
        let t4 = t3.pow2k(50).mul(t3); // 2^100 - 1
        let t4 = t4.pow2k(100).mul(t4); // 2^200 - 1
        let t4 = t4.pow2k(50).mul(t3); // 2^250 - 1
        t4.pow2k(5).mul(t0) // 2^255 - 21
    }

    /// Constant-time conditional swap (`choice` must be 0 or 1).
    #[inline]
    fn cswap(choice: u64, a: &mut Self, b: &mut Self) {
        let mask = 0u64.wrapping_sub(choice & 1);
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let diff = mask & (*x ^ *y);
            *x ^= diff;
            *y ^= diff;
        }
    }

    /// Constant-time canonical reduction modulo `2^255 - 19` and little-endian encoding.
    fn to_bytes(self) -> [u8; 32] {
        // Two carry passes guarantee all five limbs are strictly < 2^51.
        let [l0, l1, l2, l3, l4] = self.0;
        let r = Self::carry_reduce(l0, l1, l2, l3, l4);
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = r.0;
        let c1 = t1 >> 51;
        t1 &= MASK51;
        t2 += c1;
        let c2 = t2 >> 51;
        t2 &= MASK51;
        t3 += c2;
        let c3 = t3 >> 51;
        t3 &= MASK51;
        t4 += c3;
        let c4 = t4 >> 51;
        t4 &= MASK51;
        t0 += c4 * 19;
        let c0 = t0 >> 51;
        t0 &= MASK51;
        t1 += c0;

        // q = 1 iff value >= 2^255 - 19, else 0.
        let mut q = (t0 + 19) >> 51;
        q = (t1 + q) >> 51;
        q = (t2 + q) >> 51;
        q = (t3 + q) >> 51;
        q = (t4 + q) >> 51;

        t0 += 19 * q;
        let c0 = t0 >> 51;
        t0 &= MASK51;
        t1 += c0;
        let c1 = t1 >> 51;
        t1 &= MASK51;
        t2 += c1;
        let c2 = t2 >> 51;
        t2 &= MASK51;
        t3 += c2;
        let c3 = t3 >> 51;
        t3 &= MASK51;
        t4 += c3;
        t4 &= MASK51;

        // Pack 5 x 51-bit limbs into 32 little-endian bytes.
        let mut out = [0u8; 32];
        let w0 = t0 | (t1 << 51);
        let w1 = (t1 >> 13) | (t2 << 38);
        let w2 = (t2 >> 26) | (t3 << 25);
        let w3 = (t3 >> 39) | (t4 << 12);
        if let Some(s) = out.get_mut(0..8) {
            s.copy_from_slice(&w0.to_le_bytes());
        }
        if let Some(s) = out.get_mut(8..16) {
            s.copy_from_slice(&w1.to_le_bytes());
        }
        if let Some(s) = out.get_mut(16..24) {
            s.copy_from_slice(&w2.to_le_bytes());
        }
        if let Some(s) = out.get_mut(24..32) {
            s.copy_from_slice(&w3.to_le_bytes());
        }
        out
    }
}

/// Constant-time RFC 7748 X25519 scalar multiplication (`X25519(scalar, point)`).
///
/// Clamps a local zeroized copy of `scalar` per RFC 7748 §5, clears bit 255 of `point`,
/// and executes the constant-time Montgomery ladder with zero secret-dependent branches.
pub fn x25519_scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut k = Zeroizing::new(*scalar);
    if let Some(b0) = k.get_mut(0) {
        *b0 &= 248;
    }
    if let Some(b31) = k.get_mut(31) {
        *b31 &= 127;
        *b31 |= 64;
    }

    let x_1 = Fe::from_bytes(point);
    let mut x_2 = Fe::ONE;
    let mut z_2 = Fe::ZERO;
    let mut x_3 = x_1;
    let mut z_3 = Fe::ONE;
    let mut swap = 0u64;

    for t in (0..255usize).rev() {
        let byte = k.get(t >> 3).copied().unwrap_or(0);
        let k_t = u64::from((byte >> (t & 7)) & 1);
        swap ^= k_t;
        Fe::cswap(swap, &mut x_2, &mut x_3);
        Fe::cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = x_2.add(z_2);
        let aa = a.sq();
        let b = x_2.sub(z_2);
        let bb = b.sq();
        let e = aa.sub(bb);
        let c = x_3.add(z_3);
        let d = x_3.sub(z_3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x_3 = da.add(cb).sq();
        z_3 = x_1.mul(da.sub(cb).sq());
        x_2 = aa.mul(bb);
        z_2 = e.mul(aa.add(e.mul_a24()));
    }

    Fe::cswap(swap, &mut x_2, &mut x_3);
    Fe::cswap(swap, &mut z_2, &mut z_3);

    let out = x_2.mul(z_2.invert()).to_bytes();
    x_2.zeroize();
    z_2.zeroize();
    x_3.zeroize();
    z_3.zeroize();
    out
}

/// Derives the canonical 32-byte X25519 public key (`X25519(scalar, 9)`).
pub fn x25519_public_key(scalar: &[u8; 32]) -> [u8; 32] {
    x25519_scalarmult(scalar, &X25519_BASEPOINT)
}

// ---------------------------------------------------------------------------
// 2. HKDF-SHA256 & RFC 9180 HPKE `ModeAuth` (`KEM=0x0020, KDF=0x0001, AEAD=0x0003`)
// ---------------------------------------------------------------------------

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let salt_key_bytes: &[u8] = if salt.is_empty() { &[0u8; 32] } else { salt };
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt_key_bytes);
    let tag = hmac::sign(&key, ikm);
    let mut prk = Zeroizing::new([0u8; 32]);
    prk.copy_from_slice(tag.as_ref());
    prk
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, InboxCryptoError> {
    if len == 0 || len > 255 * 32 {
        return Err(InboxCryptoError::InvalidExpandLength);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let blocks = len.div_ceil(32);
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut prev = Zeroizing::new([0u8; 32]);
    let mut has_prev = false;

    for i in 1..=blocks {
        let mut ctx = hmac::Context::with_key(&key);
        if has_prev {
            ctx.update(&*prev);
        }
        ctx.update(info);
        let counter = u8::try_from(i).map_err(|_| InboxCryptoError::InvalidExpandLength)?;
        ctx.update(&[counter]);
        let tag = ctx.sign();
        prev.copy_from_slice(tag.as_ref());
        has_prev = true;
        let remaining = len.saturating_sub(out.len());
        let take = remaining.min(32);
        if let Some(slice) = prev.get(0..take) {
            out.extend_from_slice(slice);
        }
    }
    Ok(out)
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut labeled_ikm =
        Zeroizing::new(Vec::with_capacity(HPKE_V1_PREFIX.len() + suite_id.len() + label.len() + ikm.len()));
    labeled_ikm.extend_from_slice(HPKE_V1_PREFIX);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    hkdf_extract(salt, &labeled_ikm)
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, InboxCryptoError> {
    let len_u16 = u16::try_from(len).map_err(|_| InboxCryptoError::InvalidExpandLength)?;
    let mut labeled_info = Zeroizing::new(Vec::with_capacity(
        2 + HPKE_V1_PREFIX.len() + suite_id.len() + label.len() + info.len(),
    ));
    labeled_info.extend_from_slice(&len_u16.to_be_bytes());
    labeled_info.extend_from_slice(HPKE_V1_PREFIX);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    hkdf_expand(prk, &labeled_info, len)
}

fn extract_and_expand(dh: &[u8; 64], kem_context: &[u8; 96]) -> Result<Zeroizing<[u8; 32]>, InboxCryptoError> {
    let eae_prk = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh);
    let expanded = labeled_expand(KEM_SUITE_ID, &eae_prk, b"shared_secret", kem_context, 32)?;
    let mut ss = Zeroizing::new([0u8; 32]);
    ss.copy_from_slice(&expanded);
    Ok(ss)
}

/// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for `DHKEM(X25519, HKDF-SHA256)`.
pub fn hpke_derive_key_pair(ikm: &[u8]) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), InboxCryptoError> {
    let dkp_prk = labeled_extract(KEM_SUITE_ID, b"", b"dkp_prk", ikm);
    let sk_vec = labeled_expand(KEM_SUITE_ID, &dkp_prk, b"sk", b"", 32)?;
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&sk_vec);
    let pk = x25519_public_key(&sk);
    Ok((sk, pk))
}

/// RFC 9180 §4.1 `AuthEncap(pkR, skS)` with caller-supplied ephemeral scalar `sk_e`.
pub fn auth_encap_deterministic(
    pk_r: &[u8; 32],
    sk_s: &[u8; 32],
    sk_e: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), InboxCryptoError> {
    validate_x25519_pubkey_strict(pk_r).map_err(|_| InboxCryptoError::InvalidPublicKey)?;
    let enc = x25519_public_key(sk_e);
    let pk_s = x25519_public_key(sk_s);

    let dh1 = Zeroizing::new(x25519_scalarmult(sk_e, pk_r));
    let dh2 = Zeroizing::new(x25519_scalarmult(sk_s, pk_r));
    if is_all_zero_ct(&*dh1) || is_all_zero_ct(&*dh2) {
        return Err(InboxCryptoError::WeakSharedSecret);
    }

    let mut dh = Zeroizing::new([0u8; 64]);
    if let Some(s) = dh.get_mut(0..32) {
        s.copy_from_slice(&*dh1);
    }
    if let Some(s) = dh.get_mut(32..64) {
        s.copy_from_slice(&*dh2);
    }

    let mut kem_context = [0u8; 96];
    if let Some(s) = kem_context.get_mut(0..32) {
        s.copy_from_slice(&enc);
    }
    if let Some(s) = kem_context.get_mut(32..64) {
        s.copy_from_slice(pk_r);
    }
    if let Some(s) = kem_context.get_mut(64..96) {
        s.copy_from_slice(&pk_s);
    }

    let shared_secret = extract_and_expand(&dh, &kem_context)?;
    Ok((shared_secret, enc))
}

/// RFC 9180 §4.1 `AuthDecap(enc, skR, pkS)`.
pub fn auth_decap(
    enc: &[u8; 32],
    sk_r: &[u8; 32],
    pk_s: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, InboxCryptoError> {
    validate_x25519_pubkey_strict(enc).map_err(|_| InboxCryptoError::InvalidPublicKey)?;
    validate_x25519_pubkey_strict(pk_s).map_err(|_| InboxCryptoError::InvalidPublicKey)?;
    let pk_r = x25519_public_key(sk_r);

    let dh1 = Zeroizing::new(x25519_scalarmult(sk_r, enc));
    let dh2 = Zeroizing::new(x25519_scalarmult(sk_r, pk_s));
    if is_all_zero_ct(&*dh1) || is_all_zero_ct(&*dh2) {
        return Err(InboxCryptoError::WeakSharedSecret);
    }

    let mut dh = Zeroizing::new([0u8; 64]);
    if let Some(s) = dh.get_mut(0..32) {
        s.copy_from_slice(&*dh1);
    }
    if let Some(s) = dh.get_mut(32..64) {
        s.copy_from_slice(&*dh2);
    }

    let mut kem_context = [0u8; 96];
    if let Some(s) = kem_context.get_mut(0..32) {
        s.copy_from_slice(enc);
    }
    if let Some(s) = kem_context.get_mut(32..64) {
        s.copy_from_slice(&pk_r);
    }
    if let Some(s) = kem_context.get_mut(64..96) {
        s.copy_from_slice(pk_s);
    }

    extract_and_expand(&dh, &kem_context)
}

#[derive(Clone)]
pub struct HpkeKeySchedule {
    pub key: Zeroizing<[u8; 32]>,
    pub base_nonce: Zeroizing<[u8; 12]>,
    pub exporter_secret: Zeroizing<[u8; 32]>,
}

/// RFC 9180 §5.1 `KeyScheduleAuth(mode=0x02, shared_secret, info, psk=b"", psk_id=b"")`.
pub fn key_schedule_auth(
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<HpkeKeySchedule, InboxCryptoError> {
    let psk_id_hash = labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", info);

    let mut ks_context = [0u8; 65];
    if let Some(first) = ks_context.first_mut() {
        *first = HPKE_MODE_AUTH;
    }
    if let Some(s) = ks_context.get_mut(1..33) {
        s.copy_from_slice(&*psk_id_hash);
    }
    if let Some(s) = ks_context.get_mut(33..65) {
        s.copy_from_slice(&*info_hash);
    }

    let secret = labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", b"");
    let key_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"key", &ks_context, 32)?;
    let nonce_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"base_nonce", &ks_context, 12)?;
    let exp_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"exp", &ks_context, 32)?;

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&key_vec);
    let mut base_nonce = Zeroizing::new([0u8; 12]);
    base_nonce.copy_from_slice(&nonce_vec);
    let mut exporter_secret = Zeroizing::new([0u8; 32]);
    exporter_secret.copy_from_slice(&exp_vec);

    Ok(HpkeKeySchedule {
        key,
        base_nonce,
        exporter_secret,
    })
}

/// Stateful RFC 9180 HPKE `ModeAuth` encryption/decryption context (`ContextS` / `ContextR`).
pub struct HpkeAuthContext {
    key: Zeroizing<[u8; 32]>,
    base_nonce: Zeroizing<[u8; 12]>,
    exporter_secret: Zeroizing<[u8; 32]>,
    seq: u64,
}

impl HpkeAuthContext {
    pub fn setup_sender_deterministic(
        pk_r: &[u8; 32],
        sk_s: &[u8; 32],
        info: &[u8],
        ephemeral_sk: &[u8; 32],
    ) -> Result<([u8; 32], Self), InboxCryptoError> {
        let (shared_secret, enc) = auth_encap_deterministic(pk_r, sk_s, ephemeral_sk)?;
        let ks = key_schedule_auth(&shared_secret, info)?;
        Ok((
            enc,
            Self {
                key: ks.key,
                base_nonce: ks.base_nonce,
                exporter_secret: ks.exporter_secret,
                seq: 0,
            },
        ))
    }

    pub fn setup_receiver(
        enc: &[u8; 32],
        sk_r: &[u8; 32],
        pk_s: &[u8; 32],
        info: &[u8],
    ) -> Result<Self, InboxCryptoError> {
        let shared_secret = auth_decap(enc, sk_r, pk_s)?;
        let ks = key_schedule_auth(&shared_secret, info)?;
        Ok(Self {
            key: ks.key,
            base_nonce: ks.base_nonce,
            exporter_secret: ks.exporter_secret,
            seq: 0,
        })
    }

    pub fn base_nonce(&self) -> &[u8; 12] {
        &self.base_nonce
    }

    pub fn exporter_secret(&self) -> &[u8; 32] {
        &self.exporter_secret
    }

    pub fn sequence(&self) -> u64 {
        self.seq
    }

    fn compute_nonce(&self) -> Result<[u8; 12], InboxCryptoError> {
        if self.seq == u64::MAX {
            return Err(InboxCryptoError::SequenceOverflow);
        }
        let mut nonce = *self.base_nonce;
        let seq_be = self.seq.to_be_bytes();
        for (i, &b) in seq_be.iter().enumerate() {
            if let Some(slot) = nonce.get_mut(4 + i) {
                *slot ^= b;
            }
        }
        Ok(nonce)
    }

    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, InboxCryptoError> {
        let nonce_bytes = self.compute_nonce()?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*self.key)
            .map_err(|_| InboxCryptoError::HpkeFailed)?;
        let aead_key = LessSafeKey::new(unbound);
        let mut buf = Vec::with_capacity(pt.len().saturating_add(INBOX_AEAD_TAG_BYTES));
        buf.extend_from_slice(pt);
        aead_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| InboxCryptoError::AeadFailed)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(InboxCryptoError::SequenceOverflow)?;
        Ok(buf)
    }

    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, InboxCryptoError> {
        if ct.len() < INBOX_AEAD_TAG_BYTES {
            return Err(InboxCryptoError::AeadFailed);
        }
        let nonce_bytes = self.compute_nonce()?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*self.key)
            .map_err(|_| InboxCryptoError::HpkeFailed)?;
        let aead_key = LessSafeKey::new(unbound);
        let mut buf = ct.to_vec();
        let pt_len = aead_key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| InboxCryptoError::AeadFailed)?
            .len();
        buf.truncate(pt_len);
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(InboxCryptoError::SequenceOverflow)?;
        Ok(buf)
    }

    /// RFC 9180 §5.3 `Context.Export(exporter_context, L)`.
    pub fn export(
        &self,
        exporter_context: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, InboxCryptoError> {
        labeled_expand(
            HPKE_SUITE_ID,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }
}

/// RFC 9180 §6.1.3 single-shot `SealAuth` returning `enc(32) || ct(pt.len() + 16)`.
/// For a 32-byte CEK, returns exact 80 bytes (`32 enc + 32 ct + 16 tag`).
pub fn hpke_auth_seal_single_shot(
    pk_r: &[u8; 32],
    sk_s: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    ephemeral_sk: &[u8; 32],
) -> Result<Vec<u8>, InboxCryptoError> {
    let (enc, mut ctx) = HpkeAuthContext::setup_sender_deterministic(pk_r, sk_s, info, ephemeral_sk)?;
    let ct = ctx.seal(aad, pt)?;
    let mut out = Vec::with_capacity(enc.len().saturating_add(ct.len()));
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// RFC 9180 §6.1.3 single-shot `OpenAuth` accepting `enc(32) || ct(pt.len() + 16)`.
pub fn hpke_auth_open_single_shot(
    enc_and_ct: &[u8],
    sk_r: &[u8; 32],
    pk_s: &[u8; 32],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, InboxCryptoError> {
    if enc_and_ct.len() < INBOX_HPKE_ENC_BYTES + INBOX_AEAD_TAG_BYTES {
        return Err(InboxCryptoError::InvalidWrappedKey);
    }
    let enc_slice = enc_and_ct
        .get(0..INBOX_HPKE_ENC_BYTES)
        .ok_or(InboxCryptoError::InvalidWrappedKey)?;
    let ct = enc_and_ct
        .get(INBOX_HPKE_ENC_BYTES..)
        .ok_or(InboxCryptoError::InvalidWrappedKey)?;
    let enc: [u8; 32] = enc_slice
        .try_into()
        .map_err(|_| InboxCryptoError::InvalidWrappedKey)?;
    let mut ctx = HpkeAuthContext::setup_receiver(&enc, sk_r, pk_s, info)?;
    ctx.open(aad, ct)
}

// ---------------------------------------------------------------------------
// 3. Dead-Drop Inbox Suite 1: `enc_cert`, Buckets, Key-Committing AEAD & Drops
// ---------------------------------------------------------------------------

/// Signs a canonical 161-byte per-device X25519 encryption subkey certificate (`mp-enc-subkey-v1:`).
///
/// Layout: `version(1=1) || account_id(8 le) || device_id(8 le) || root_pubkey(32) ||
/// enc_pk(32) || iat_s(8 le) || exp_s(8 le) || ed25519_sig(64)`.
pub fn sign_enc_subkey_cert(
    account_id: AccountId,
    device_id: DeviceId,
    root_pubkey: &[u8; 32],
    enc_pk: &[u8; 32],
    iat_s: i64,
    exp_s: i64,
    device_signing_key: &SigningKey,
) -> Result<[u8; ENC_SUBKEY_CERT_BYTES], InboxCryptoError> {
    validate_ed25519_pubkey_strict(root_pubkey).map_err(|_| InboxCryptoError::InvalidPublicKey)?;
    validate_x25519_pubkey_strict(enc_pk).map_err(|_| InboxCryptoError::WeakPublicKey)?;
    let ttl = exp_s.saturating_sub(iat_s);
    if !(1..=MAX_ENC_CERT_TTL_SECS).contains(&ttl) {
        return Err(InboxCryptoError::InvalidCertTtl);
    }

    let mut body = [0u8; ENC_SUBKEY_CERT_BODY_BYTES];
    if let Some(slot) = body.first_mut() {
        *slot = 1u8;
    }
    if let Some(s) = body.get_mut(1..9) {
        s.copy_from_slice(&account_id.get().to_le_bytes());
    }
    if let Some(s) = body.get_mut(9..17) {
        s.copy_from_slice(&device_id.get().to_le_bytes());
    }
    if let Some(s) = body.get_mut(17..49) {
        s.copy_from_slice(root_pubkey);
    }
    if let Some(s) = body.get_mut(49..81) {
        s.copy_from_slice(enc_pk);
    }
    if let Some(s) = body.get_mut(81..89) {
        s.copy_from_slice(&iat_s.to_le_bytes());
    }
    if let Some(s) = body.get_mut(89..97) {
        s.copy_from_slice(&exp_s.to_le_bytes());
    }

    let mut msg = Vec::with_capacity(ENC_SUBKEY_CERT_DOMAIN_SEP.len() + ENC_SUBKEY_CERT_BODY_BYTES);
    msg.extend_from_slice(ENC_SUBKEY_CERT_DOMAIN_SEP.as_bytes());
    msg.extend_from_slice(&body);
    let sig = device_signing_key.sign(&msg).to_bytes();

    let mut cert = [0u8; ENC_SUBKEY_CERT_BYTES];
    if let Some(s) = cert.get_mut(0..ENC_SUBKEY_CERT_BODY_BYTES) {
        s.copy_from_slice(&body);
    }
    if let Some(s) = cert.get_mut(ENC_SUBKEY_CERT_BODY_BYTES..ENC_SUBKEY_CERT_BYTES) {
        s.copy_from_slice(&sig);
    }
    Ok(cert)
}

/// Pads `plaintext` into `[u32_le pt.len()][pt][0x00...]` of exact length `bucket - 16`,
/// so `ChaCha20Poly1305` ciphertext + 16-byte tag matches `1024 / 4096 / 16384 / 65536`.
pub fn pad_to_bucket(plaintext: &[u8]) -> Result<Vec<u8>, InboxCryptoError> {
    if plaintext.len() > INBOX_MAX_PLAINTEXT_BYTES {
        return Err(InboxCryptoError::PlaintextTooLarge);
    }
    let needed_ct = INBOX_LENGTH_PREFIX_BYTES
        .checked_add(plaintext.len())
        .and_then(|n| n.checked_add(INBOX_AEAD_TAG_BYTES))
        .ok_or(InboxCryptoError::PlaintextTooLarge)?;
    let bucket = INBOX_BUCKETS
        .iter()
        .copied()
        .find(|&b| needed_ct <= b)
        .ok_or(InboxCryptoError::PlaintextTooLarge)?;
    let padded_len = bucket - INBOX_AEAD_TAG_BYTES;
    let mut out = vec![0u8; padded_len];
    let pt_len_u32 = u32::try_from(plaintext.len()).map_err(|_| InboxCryptoError::PlaintextTooLarge)?;
    if let Some(s) = out.get_mut(0..INBOX_LENGTH_PREFIX_BYTES) {
        s.copy_from_slice(&pt_len_u32.to_le_bytes());
    }
    if let Some(s) = out.get_mut(INBOX_LENGTH_PREFIX_BYTES..INBOX_LENGTH_PREFIX_BYTES + plaintext.len()) {
        s.copy_from_slice(plaintext);
    }
    Ok(out)
}

/// Unpads a Suite 1 bucket plaintext (`bucket - 16` bytes), verifying exact bucket size
/// and that every trailing padding byte is strictly `0x00`.
pub fn unpad_from_bucket(padded: &[u8]) -> Result<Vec<u8>, InboxCryptoError> {
    let ct_len = padded
        .len()
        .checked_add(INBOX_AEAD_TAG_BYTES)
        .ok_or(InboxCryptoError::InvalidBucketSize)?;
    if !INBOX_BUCKETS.contains(&ct_len) {
        return Err(InboxCryptoError::InvalidBucketSize);
    }
    let len_slice = padded
        .get(0..INBOX_LENGTH_PREFIX_BYTES)
        .ok_or(InboxCryptoError::InvalidPadding)?;
    let len_arr: [u8; 4] = len_slice
        .try_into()
        .map_err(|_| InboxCryptoError::InvalidPadding)?;
    let pt_len = u32::from_le_bytes(len_arr) as usize;
    let pt_end = INBOX_LENGTH_PREFIX_BYTES
        .checked_add(pt_len)
        .ok_or(InboxCryptoError::InvalidPadding)?;
    if pt_end > padded.len() {
        return Err(InboxCryptoError::InvalidPadding);
    }
    let pad_slice = padded.get(pt_end..).ok_or(InboxCryptoError::InvalidPadding)?;
    if !is_all_zero_ct(pad_slice) {
        return Err(InboxCryptoError::InvalidPadding);
    }
    let pt_slice = padded
        .get(INBOX_LENGTH_PREFIX_BYTES..pt_end)
        .ok_or(InboxCryptoError::InvalidPadding)?;
    Ok(pt_slice.to_vec())
}

/// Derived Suite 1 AEAD material: `(aead_key[32], aead_nonce[12], key_commit[32])`.
pub type InboxAeadMaterial = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 12]>, Zeroizing<[u8; 32]>);

/// Derives `(aead_key[32], aead_nonce[12], key_commit[32])` via HKDF-SHA256:
/// `Extract(salt=msg_id, ikm=cek)` + `Expand(info="mp-inbox-aead-v1", L=76)`.
pub fn derive_inbox_aead_material(cek: &[u8; 32], msg_id: &[u8; 16]) -> InboxAeadMaterial {
    let prk = hkdf_extract(msg_id, cek);
    // 76 bytes is always valid (`1..=255*32`), so hkdf_expand cannot fail.
    let okm = match hkdf_expand(&prk, INBOX_AEAD_HKDF_INFO, 76) {
        Ok(v) => v,
        Err(_) => Zeroizing::new(vec![0u8; 76]),
    };
    let mut aead_key = Zeroizing::new([0u8; 32]);
    let mut aead_nonce = Zeroizing::new([0u8; 12]);
    let mut key_commit = Zeroizing::new([0u8; 32]);
    if let Some(s) = okm.get(0..32) {
        aead_key.copy_from_slice(s);
    }
    if let Some(s) = okm.get(32..44) {
        aead_nonce.copy_from_slice(s);
    }
    if let Some(s) = okm.get(44..76) {
        key_commit.copy_from_slice(s);
    }
    (aead_key, aead_nonce, key_commit)
}

/// Canonical 97-byte AAD for Suite 1 payload `ChaCha20Poly1305`.
pub fn canonical_inbox_aad(
    suite: u8,
    sender_account_id: u64,
    sender_device_id: u64,
    recipient_account_id: u64,
    msg_id: &[u8; 16],
    expires_at_ms: i64,
    key_commit: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(97);
    out.extend_from_slice(INBOX_AAD_DOMAIN);
    out.push(suite);
    out.extend_from_slice(&sender_account_id.to_le_bytes());
    out.extend_from_slice(&sender_device_id.to_le_bytes());
    out.extend_from_slice(&recipient_account_id.to_le_bytes());
    out.extend_from_slice(msg_id);
    out.extend_from_slice(&expires_at_ms.to_le_bytes());
    out.extend_from_slice(key_commit);
    out
}

/// Canonical 137-byte AAD for per-device `HPKE.AuthSeal` CEK wrapping,
/// binding `target_device_id`, `key_commit`, and `sha256(ciphertext)`.
#[allow(clippy::too_many_arguments)]
pub fn canonical_wrap_aad(
    suite: u8,
    sender_account_id: u64,
    sender_device_id: u64,
    recipient_account_id: u64,
    target_device_id: u64,
    msg_id: &[u8; 16],
    expires_at_ms: i64,
    key_commit: &[u8; 32],
    ciphertext_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(137);
    out.extend_from_slice(INBOX_WRAP_AAD_DOMAIN);
    out.push(suite);
    out.extend_from_slice(&sender_account_id.to_le_bytes());
    out.extend_from_slice(&sender_device_id.to_le_bytes());
    out.extend_from_slice(&recipient_account_id.to_le_bytes());
    out.extend_from_slice(&target_device_id.to_le_bytes());
    out.extend_from_slice(msg_id);
    out.extend_from_slice(&expires_at_ms.to_le_bytes());
    out.extend_from_slice(key_commit);
    out.extend_from_slice(ciphertext_sha256);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxRecipientDevice {
    pub device_id: DeviceId,
    pub enc_pk: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxWrappedDeviceKey {
    pub target_device_id: DeviceId,
    /// Suite 1 wrapped key (112 B): `key_commit(32) || hpke_enc(32) || hpke_ct(48)`.
    pub wrapped_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedInboxDrop {
    pub suite: u8,
    pub msg_id: [u8; 16],
    pub expires_at_ms: i64,
    pub ciphertext: Vec<u8>,
    pub ciphertext_sha256: [u8; 32],
    pub key_commit: [u8; 32],
    pub wrapped_keys: Vec<InboxWrappedDeviceKey>,
}

/// Seals a Dead-Drop Inbox Suite 1 message once into a bucketed ciphertext and wraps the CEK
/// via `HPKE.AuthSeal` for each target recipient device.
#[allow(clippy::too_many_arguments)]
pub fn seal_inbox_drop(
    sender_account_id: AccountId,
    sender_device_id: DeviceId,
    sender_enc_sk: &[u8; 32],
    recipient_account_id: AccountId,
    recipients: &[InboxRecipientDevice],
    msg_id: [u8; 16],
    expires_at_ms: i64,
    plaintext: &[u8],
    cek: &[u8; 32],
    ephemeral_sks: &[[u8; 32]],
) -> Result<SealedInboxDrop, InboxCryptoError> {
    if recipients.is_empty() {
        return Err(InboxCryptoError::EmptyRecipients);
    }
    if recipients.len() > INBOX_MAX_RECIPIENT_DEVICES {
        return Err(InboxCryptoError::TooManyRecipients);
    }
    if ephemeral_sks.len() != recipients.len() {
        return Err(InboxCryptoError::EphemeralKeyCountMismatch);
    }

    let mut seen_devices = BTreeSet::new();
    for r in recipients {
        if !seen_devices.insert(r.device_id.get()) {
            return Err(InboxCryptoError::DuplicateRecipientDevice);
        }
        validate_x25519_pubkey_strict(&r.enc_pk).map_err(|_| InboxCryptoError::InvalidPublicKey)?;
    }

    let padded = Zeroizing::new(pad_to_bucket(plaintext)?);
    let (aead_key, aead_nonce, key_commit) = derive_inbox_aead_material(cek, &msg_id);
    let inbox_aad = canonical_inbox_aad(
        INBOX_SUITE_1,
        sender_account_id.get(),
        sender_device_id.get(),
        recipient_account_id.get(),
        &msg_id,
        expires_at_ms,
        &key_commit,
    );

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*aead_key)
        .map_err(|_| InboxCryptoError::AeadFailed)?;
    let cipher = LessSafeKey::new(unbound);
    let mut ciphertext = Vec::with_capacity(padded.len().saturating_add(INBOX_AEAD_TAG_BYTES));
    ciphertext.extend_from_slice(&padded);
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*aead_nonce),
            Aad::from(&inbox_aad),
            &mut ciphertext,
        )
        .map_err(|_| InboxCryptoError::AeadFailed)?;

    let ciphertext_sha256 = sha256(&ciphertext);

    let mut wrapped_keys = Vec::with_capacity(recipients.len());
    for (recip, eph_sk) in recipients.iter().zip(ephemeral_sks.iter()) {
        let wrap_aad = canonical_wrap_aad(
            INBOX_SUITE_1,
            sender_account_id.get(),
            sender_device_id.get(),
            recipient_account_id.get(),
            recip.device_id.get(),
            &msg_id,
            expires_at_ms,
            &key_commit,
            &ciphertext_sha256,
        );
        let enc_and_ct = hpke_auth_seal_single_shot(
            &recip.enc_pk,
            sender_enc_sk,
            INBOX_HPKE_INFO,
            &wrap_aad,
            cek,
            eph_sk,
        )?;
        let mut wrapped = Vec::with_capacity(INBOX_SUITE1_WRAPPED_KEY_BYTES);
        wrapped.extend_from_slice(&*key_commit);
        wrapped.extend_from_slice(&enc_and_ct);
        wrapped_keys.push(InboxWrappedDeviceKey {
            target_device_id: recip.device_id,
            wrapped_key: wrapped,
        });
    }

    Ok(SealedInboxDrop {
        suite: INBOX_SUITE_1,
        msg_id,
        expires_at_ms,
        ciphertext,
        ciphertext_sha256,
        key_commit: *key_commit,
        wrapped_keys,
    })
}

/// Opens a Dead-Drop Inbox Suite 1 message for `target_device_id`, verifying HPKE `ModeAuth`
/// sender authentication, `wrap_aad` (`key_commit` + `sha256(ciphertext)`), HKDF key commitment,
/// ChaCha20-Poly1305 AEAD tag, and exact zero-padded bucket framing.
#[allow(clippy::too_many_arguments)]
pub fn open_inbox_drop(
    suite: u8,
    sender_account_id: AccountId,
    sender_device_id: DeviceId,
    sender_enc_pk: &[u8; 32],
    recipient_account_id: AccountId,
    target_device_id: DeviceId,
    recipient_enc_sk: &[u8; 32],
    msg_id: &[u8; 16],
    expires_at_ms: i64,
    ciphertext: &[u8],
    wrapped_key: &[u8],
) -> Result<Vec<u8>, InboxCryptoError> {
    if suite != INBOX_SUITE_1 {
        return Err(InboxCryptoError::InvalidSuite);
    }
    if !INBOX_BUCKETS.contains(&ciphertext.len()) {
        return Err(InboxCryptoError::InvalidBucketSize);
    }
    if wrapped_key.len() != INBOX_SUITE1_WRAPPED_KEY_BYTES {
        return Err(InboxCryptoError::InvalidWrappedKey);
    }
    validate_x25519_pubkey_strict(sender_enc_pk).map_err(|_| InboxCryptoError::InvalidPublicKey)?;

    let provided_commit_slice = wrapped_key
        .get(0..INBOX_KEY_COMMIT_BYTES)
        .ok_or(InboxCryptoError::InvalidWrappedKey)?;
    let provided_key_commit: [u8; 32] = provided_commit_slice
        .try_into()
        .map_err(|_| InboxCryptoError::InvalidWrappedKey)?;
    let enc_and_ct = wrapped_key
        .get(INBOX_KEY_COMMIT_BYTES..INBOX_SUITE1_WRAPPED_KEY_BYTES)
        .ok_or(InboxCryptoError::InvalidWrappedKey)?;

    let ciphertext_sha256 = sha256(ciphertext);
    let wrap_aad = canonical_wrap_aad(
        suite,
        sender_account_id.get(),
        sender_device_id.get(),
        recipient_account_id.get(),
        target_device_id.get(),
        msg_id,
        expires_at_ms,
        &provided_key_commit,
        &ciphertext_sha256,
    );

    let cek_vec = Zeroizing::new(hpke_auth_open_single_shot(
        enc_and_ct,
        recipient_enc_sk,
        sender_enc_pk,
        INBOX_HPKE_INFO,
        &wrap_aad,
    )?);
    if cek_vec.len() != 32 {
        return Err(InboxCryptoError::InvalidWrappedKey);
    }
    let mut cek = Zeroizing::new([0u8; 32]);
    cek.copy_from_slice(&cek_vec);

    let (aead_key, aead_nonce, derived_key_commit) = derive_inbox_aead_material(&cek, msg_id);
    if !ct_eq_32(&derived_key_commit, &provided_key_commit) {
        return Err(InboxCryptoError::KeyCommitMismatch);
    }

    let inbox_aad = canonical_inbox_aad(
        suite,
        sender_account_id.get(),
        sender_device_id.get(),
        recipient_account_id.get(),
        msg_id,
        expires_at_ms,
        &derived_key_commit,
    );

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*aead_key)
        .map_err(|_| InboxCryptoError::AeadFailed)?;
    let cipher = LessSafeKey::new(unbound);
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let pt_len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(*aead_nonce),
            Aad::from(&inbox_aad),
            &mut buf,
        )
        .map_err(|_| InboxCryptoError::AeadFailed)?
        .len();
    buf.truncate(pt_len);

    unpad_from_bucket(&buf)
}
