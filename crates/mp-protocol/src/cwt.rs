//! Standard RFC 8392 CBOR Web Token (CWT) + RFC 8747 `cnf` Proof-of-Possession
//! wrapped in RFC 9052 `COSE_Sign1` with RFC 9864 fully-specified `alg = Ed25519 (-19)`.
//!
//! Zero custom sigchain protocol:
//! - Only the account's `root_pubkey` may sign device CWTs.
//! - Verified over exact received protected & payload bytes (no Deterministic CBOR needed).
//! - Rejects deprecated polymorphic `EdDSA (-8)` and any non-`-19` algorithm.

use ciborium::Value;
use core::fmt;
use ed25519_dalek::{Signer, SigningKey};

use crate::crypto::{
    CryptoError, Ed25519PubKey, hex_lower_32, sha256, validate_ed25519_pubkey_strict,
    verify_ed25519_strict,
};

/// Maximum encoded size of a device CWT (`COSE_Sign1`) on the wire and in DO SQLite.
pub const MAX_CWT_BYTES: usize = 256;

/// Maximum lifetime of a device CWT (`exp - iat <= 30 days`).
pub const MAX_CWT_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Maximum future skew allowed on `iat`.
pub const MAX_CWT_IAT_SKEW_SECS: i64 = 60;

/// Exact CBOR encoding of protected header map `{ 1: -19 }` (RFC 9864 `alg = Ed25519`).
/// 0xa1 = 1-entry map, 0x01 = key 1 (alg), 0x32 = negative int -1 - 18 = -19.
pub const PROTECTED_HEADER_ED25519: &[u8] = &[0xa1, 0x01, 0x32];

const COSE_SIGN1_TAG: u64 = 18;
const CWT_CLAIM_ISS: i64 = 1;
const CWT_CLAIM_EXP: i64 = 4;
const CWT_CLAIM_IAT: i64 = 6;
const CWT_CLAIM_CNF: i64 = 8;

const CNF_COSE_KEY: i64 = 1;
const COSE_KEY_KTY: i64 = 1;
const COSE_KEY_ALG: i64 = 3;
const COSE_KEY_CRV: i64 = -1;
const COSE_KEY_X: i64 = -2;

const KTY_OKP: i64 = 1;
const ALG_ED25519: i64 = -19;
const CRV_ED25519: i64 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CwtClaims {
    /// RFC 8392 text string `iss = lowercase_hex(sha256(root_pubkey))`.
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub device_pubkey: Ed25519PubKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CwtError {
    TooLarge,
    InvalidCbor,
    InvalidEnvelopeShape,
    InvalidProtectedHeader,
    NonEmptyUnprotectedHeader,
    InvalidSignatureLength,
    InvalidClaims,
    IssuerMismatch,
    DeviceKeyMismatch,
    FutureIssuedAt,
    Expired,
    TtlExceeded,
    Crypto(CryptoError),
}

impl fmt::Display for CwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CwtError {}

impl From<CryptoError> for CwtError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Builds RFC 9052 §4.4 `Sig_structure = ["Signature1", body_protected, external_aad, payload]`.
fn build_sig_structure(protected_bytes: &[u8], payload_bytes: &[u8]) -> Result<Vec<u8>, CwtError> {
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected_bytes.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload_bytes.to_vec()),
    ]);
    let mut out = Vec::with_capacity(protected_bytes.len() + payload_bytes.len() + 32);
    ciborium::into_writer(&sig_structure, &mut out).map_err(|_| CwtError::InvalidCbor)?;
    Ok(out)
}

/// Shared overflow-safe CWT lifetime validator: requires `iat >= 0` and `1 <= exp - iat <= MAX_CWT_TTL_SECS`.
fn validate_cwt_ttl(iat: i64, exp: i64) -> Result<(), CwtError> {
    if iat < 0 {
        return Err(CwtError::InvalidClaims);
    }
    let ttl = exp.checked_sub(iat).ok_or(CwtError::TtlExceeded)?;
    if ttl <= 0 || ttl > MAX_CWT_TTL_SECS {
        return Err(CwtError::TtlExceeded);
    }
    Ok(())
}

/// Exact canonical definite-length COSE_Sign1 prefix for our strict profile:
/// `0xd2` (Tag 18) || `0x84` (4-element definite array) || `0x43 a1 01 32` (3-byte definite bstr `{1: -19}`) || `0xa0` (empty definite map).
const CANONICAL_SIGN1_PREFIX: &[u8] = &[0xd2, 0x84, 0x43, 0xa1, 0x01, 0x32, 0xa0];

/// Encodes and signs a standards-compliant RFC 8392/8747/9052/9864 device CWT (`COSE_Sign1`, tag 18).
pub fn encode_device_cwt(
    root_signing_key: &SigningKey,
    device_pubkey: &Ed25519PubKey,
    iat: i64,
    exp: i64,
) -> Result<Vec<u8>, CwtError> {
    let root_pubkey: Ed25519PubKey = root_signing_key.verifying_key().to_bytes();
    let _ = validate_ed25519_pubkey_strict(&root_pubkey)?;
    let _ = validate_ed25519_pubkey_strict(device_pubkey)?;

    validate_cwt_ttl(iat, exp)?;

    let iss = hex_lower_32(&sha256(&root_pubkey));
    let cose_key = Value::Map(vec![
        (Value::Integer(COSE_KEY_KTY.into()), Value::Integer(KTY_OKP.into())),
        (Value::Integer(COSE_KEY_ALG.into()), Value::Integer(ALG_ED25519.into())),
        (Value::Integer(COSE_KEY_CRV.into()), Value::Integer(CRV_ED25519.into())),
        (Value::Integer(COSE_KEY_X.into()), Value::Bytes(device_pubkey.to_vec())),
    ]);
    let cnf = Value::Map(vec![(Value::Integer(CNF_COSE_KEY.into()), cose_key)]);
    let claims = Value::Map(vec![
        (Value::Integer(CWT_CLAIM_ISS.into()), Value::Text(iss)),
        (Value::Integer(CWT_CLAIM_EXP.into()), Value::Integer(exp.into())),
        (Value::Integer(CWT_CLAIM_IAT.into()), Value::Integer(iat.into())),
        (Value::Integer(CWT_CLAIM_CNF.into()), cnf),
    ]);

    let mut payload_bytes = Vec::with_capacity(140);
    ciborium::into_writer(&claims, &mut payload_bytes).map_err(|_| CwtError::InvalidCbor)?;

    let to_be_signed = build_sig_structure(PROTECTED_HEADER_ED25519, &payload_bytes)?;
    let sig = root_signing_key.sign(&to_be_signed).to_bytes();

    let sign1 = Value::Tag(
        COSE_SIGN1_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(PROTECTED_HEADER_ED25519.to_vec()),
            Value::Map(Vec::new()),
            Value::Bytes(payload_bytes),
            Value::Bytes(sig.to_vec()),
        ])),
    );

    let mut out = Vec::with_capacity(MAX_CWT_BYTES);
    ciborium::into_writer(&sign1, &mut out).map_err(|_| CwtError::InvalidCbor)?;
    if out.len() > MAX_CWT_BYTES {
        return Err(CwtError::TooLarge);
    }
    Ok(out)
}

/// Strictly verifies a received RFC 8392/8747/9052/9864 device CWT (`COSE_Sign1`).
/// Checks exact wire bytes without re-encoding payload; rejects `EdDSA (-8)`, non-empty
/// unprotected headers, trailing CBOR bytes, weak keys, mismatched `iss`/`cnf`, and invalid times.
pub fn verify_device_cwt(
    cwt_bytes: &[u8],
    expected_root_pubkey: &Ed25519PubKey,
    expected_device_pubkey: Option<&Ed25519PubKey>,
    now_s: i64,
) -> Result<CwtClaims, CwtError> {
    if cwt_bytes.is_empty() || cwt_bytes.len() > MAX_CWT_BYTES {
        return Err(CwtError::TooLarge);
    }
    let _ = validate_ed25519_pubkey_strict(expected_root_pubkey)?;

    // Strictly require Tag 18 + definite 4-element array + exact definite protected header h'A10132' + empty definite map {}.
    // Eliminates untagged envelopes and non-canonical / indefinite-length protected header malleability.
    if !cwt_bytes.starts_with(CANONICAL_SIGN1_PREFIX) {
        return Err(CwtError::InvalidEnvelopeShape);
    }
    // Also require payload bstr to use definite-length CBOR major type 2 (0x40..=0x5a, NOT indefinite 0x5f).
    let payload_hdr = *cwt_bytes
        .get(CANONICAL_SIGN1_PREFIX.len())
        .ok_or(CwtError::InvalidEnvelopeShape)?;
    if payload_hdr == 0x5f || (payload_hdr & 0xe0) != 0x40 {
        return Err(CwtError::InvalidEnvelopeShape);
    }

    let mut cursor = cwt_bytes;
    let root_val: Value = ciborium::from_reader(&mut cursor).map_err(|_| CwtError::InvalidCbor)?;
    if !cursor.is_empty() {
        return Err(CwtError::InvalidCbor);
    }

    let arr = match root_val {
        Value::Tag(COSE_SIGN1_TAG, inner) => match *inner {
            Value::Array(a) => a,
            _ => return Err(CwtError::InvalidEnvelopeShape),
        },
        _ => return Err(CwtError::InvalidEnvelopeShape),
    };
    if arr.len() != 4 {
        return Err(CwtError::InvalidEnvelopeShape);
    }

    let protected_bytes = match arr.first() {
        Some(Value::Bytes(b)) => b.as_slice(),
        _ => return Err(CwtError::InvalidEnvelopeShape),
    };
    // Strictly require protected header == h'A10132' ({1: -19}, RFC 9864 Ed25519).
    if protected_bytes != PROTECTED_HEADER_ED25519 {
        return Err(CwtError::InvalidProtectedHeader);
    }

    match arr.get(1) {
        Some(Value::Map(m)) if m.is_empty() => {}
        _ => return Err(CwtError::NonEmptyUnprotectedHeader),
    }

    let payload_bytes = match arr.get(2) {
        Some(Value::Bytes(b)) => b.as_slice(),
        _ => return Err(CwtError::InvalidEnvelopeShape),
    };

    let sig_slice = match arr.get(3) {
        Some(Value::Bytes(b)) => b.as_slice(),
        _ => return Err(CwtError::InvalidSignatureLength),
    };
    let sig_arr: [u8; 64] = sig_slice
        .try_into()
        .map_err(|_| CwtError::InvalidSignatureLength)?;

    let to_be_signed = build_sig_structure(protected_bytes, payload_bytes)?;
    verify_ed25519_strict(expected_root_pubkey, &to_be_signed, &sig_arr)?;

    // Parse payload claims strictly (no trailing bytes, no duplicate/unknown claim keys).
    let mut payload_cursor = payload_bytes;
    let payload_val: Value =
        ciborium::from_reader(&mut payload_cursor).map_err(|_| CwtError::InvalidClaims)?;
    if !payload_cursor.is_empty() {
        return Err(CwtError::InvalidClaims);
    }

    let map = match payload_val {
        Value::Map(m) => m,
        _ => return Err(CwtError::InvalidClaims),
    };

    let mut iss: Option<String> = None;
    let mut exp: Option<i64> = None;
    let mut iat: Option<i64> = None;
    let mut device_pubkey: Option<Ed25519PubKey> = None;

    for (k, v) in map {
        let key_int = value_to_i64(&k).ok_or(CwtError::InvalidClaims)?;
        match key_int {
            CWT_CLAIM_ISS => {
                if iss.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                match v {
                    Value::Text(s) => iss = Some(s),
                    _ => return Err(CwtError::InvalidClaims),
                }
            }
            CWT_CLAIM_EXP => {
                if exp.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                exp = Some(value_to_i64(&v).ok_or(CwtError::InvalidClaims)?);
            }
            CWT_CLAIM_IAT => {
                if iat.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                iat = Some(value_to_i64(&v).ok_or(CwtError::InvalidClaims)?);
            }
            CWT_CLAIM_CNF => {
                if device_pubkey.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                device_pubkey = Some(parse_cnf_ed25519(&v)?);
            }
            _ => return Err(CwtError::InvalidClaims),
        }
    }

    let iss = iss.ok_or(CwtError::InvalidClaims)?;
    let exp = exp.ok_or(CwtError::InvalidClaims)?;
    let iat = iat.ok_or(CwtError::InvalidClaims)?;
    let device_pubkey = device_pubkey.ok_or(CwtError::InvalidClaims)?;

    let expected_iss = hex_lower_32(&sha256(expected_root_pubkey));
    if iss != expected_iss {
        return Err(CwtError::IssuerMismatch);
    }
    let _ = validate_ed25519_pubkey_strict(&device_pubkey)?;
    if let Some(expected_dev) = expected_device_pubkey
        && &device_pubkey != expected_dev
    {
        return Err(CwtError::DeviceKeyMismatch);
    }

    // Time bounds: iat >= 0, iat <= now + 60s, exp > iat, exp - iat <= 30d, now < exp.
    validate_cwt_ttl(iat, exp)?;
    let max_iat = now_s.saturating_add(MAX_CWT_IAT_SKEW_SECS);
    if iat > max_iat {
        return Err(CwtError::FutureIssuedAt);
    }
    if now_s >= exp {
        return Err(CwtError::Expired);
    }

    Ok(CwtClaims {
        iss,
        iat,
        exp,
        device_pubkey,
    })
}

fn parse_cnf_ed25519(val: &Value) -> Result<Ed25519PubKey, CwtError> {
    let cnf_map = match val {
        Value::Map(m) if m.len() == 1 => m,
        _ => return Err(CwtError::InvalidClaims),
    };
    let (k, v) = cnf_map.first().ok_or(CwtError::InvalidClaims)?;
    if value_to_i64(k) != Some(CNF_COSE_KEY) {
        return Err(CwtError::InvalidClaims);
    }
    let key_map = match v {
        Value::Map(m) => m,
        _ => return Err(CwtError::InvalidClaims),
    };

    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Ed25519PubKey> = None;

    for (mk, mv) in key_map {
        let mk_i = value_to_i64(mk).ok_or(CwtError::InvalidClaims)?;
        match mk_i {
            COSE_KEY_KTY => {
                if kty.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                kty = Some(value_to_i64(mv).ok_or(CwtError::InvalidClaims)?);
            }
            COSE_KEY_ALG => {
                if alg.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                alg = Some(value_to_i64(mv).ok_or(CwtError::InvalidClaims)?);
            }
            COSE_KEY_CRV => {
                if crv.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                crv = Some(value_to_i64(mv).ok_or(CwtError::InvalidClaims)?);
            }
            COSE_KEY_X => {
                if x.is_some() {
                    return Err(CwtError::InvalidClaims);
                }
                match mv {
                    Value::Bytes(b) => {
                        let arr: Ed25519PubKey =
                            b.as_slice().try_into().map_err(|_| CwtError::InvalidClaims)?;
                        x = Some(arr);
                    }
                    _ => return Err(CwtError::InvalidClaims),
                }
            }
            _ => return Err(CwtError::InvalidClaims),
        }
    }

    if kty != Some(KTY_OKP) || crv != Some(CRV_ED25519) || alg != Some(ALG_ED25519) {
        return Err(CwtError::InvalidClaims);
    }
    x.ok_or(CwtError::InvalidClaims)
}

fn value_to_i128(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

fn value_to_i64(v: &Value) -> Option<i64> {
    i64::try_from(value_to_i128(v)?).ok()
}
