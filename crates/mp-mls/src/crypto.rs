//! Strict RFC 8032 Ed25519 verification (explicit `S < L` scalar precheck, canonical Y/R,
//! small-order and mixed-order point rejection), constant-time byte equality, Crockford Base32
//! encoding, and the strict `OpenMlsProvider` wrapper with bounded-allocation binary storage import.

use std::collections::HashMap;
use std::sync::RwLock;

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, VerifyingKey};
use openmls::prelude::OpenMlsProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKeyPair, SignatureScheme,
    },
};
use sha2::{Digest, Sha256};
use tls_codec::SecretVLBytes;

use crate::error::MpMlsError;

pub type Ed25519PubKey = [u8; 32];
pub type Ed25519Sig = [u8; 64];
pub type Sha256Digest = [u8; 32];

/// Ed25519 prime subgroup order `L = 2^252 + 27742317777372353535851937790883648493` (little-endian).
const ED25519_ORDER_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

pub fn sha256(data: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Constant-time equality over equal-length byte slices (for secret fields).
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_non_canonical_field_elem(le_bytes: &[u8; 32]) -> bool {
    // p = 2^255 - 19 in little-endian: [0xed, 0xff, ..., 0xff, 0x7f]
    // Caller clears bit 255 before calling, so byte 31 <= 0x7f.
    if le_bytes[31] != 0x7f {
        return false;
    }
    for &b in &le_bytes[1..31] {
        if b != 0xff {
            return false;
        }
    }
    le_bytes[0] >= 0xed
}

/// Constant-time canonical Ed25519 scalar check: returns `true` iff `s_le < L`.
/// Enforced explicitly BEFORE delegating to `ed25519-dalek` so RFC 8032 strictness
/// never depends on transitive Cargo feature flags (Spec v3.1 §2 / Astra #1).
pub fn is_canonical_ed25519_scalar(s_le: &[u8; 32]) -> bool {
    let mut borrow: u16 = 0;
    for i in 0..32 {
        let diff = u16::from(s_le[i])
            .wrapping_sub(u16::from(ED25519_ORDER_L_LE[i]))
            .wrapping_sub(borrow);
        borrow = (diff >> 15) & 1;
    }
    borrow == 1
}

/// Validates an Ed25519 public key strictly:
/// 1. Canonical compressed Edwards Y coordinate (`Y < 2^255 - 19`).
/// 2. Valid Edwards curve point.
/// 3. NOT a small-order point AND torsion-free (prime-order subgroup only, rejecting
///    all 8 small-order points and all mixed-order points for cross-library consistency).
pub fn validate_ed25519_pubkey_strict(pubkey: &Ed25519PubKey) -> Result<VerifyingKey, MpMlsError> {
    let mut y_bytes = *pubkey;
    y_bytes[31] &= 0x7f;
    if is_non_canonical_field_elem(&y_bytes) {
        return Err(MpMlsError::InvalidPublicKey);
    }

    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| MpMlsError::InvalidPublicKey)?;
    if vk.is_weak() || !vk.to_edwards().is_torsion_free() {
        return Err(MpMlsError::WeakOrTorsionPoint);
    }
    Ok(vk)
}

/// Strictly verifies a pure RFC 8032 Ed25519 signature:
/// - Rejects non-canonical `Y`, small-order `Y`, and mixed-order `Y`.
/// - Rejects non-canonical `R`, small-order `R`, and mixed-order `R`.
/// - Explicitly rejects non-canonical `S >= L` in constant time before delegating.
/// - Verifies cofactorless `[S]B == R + [k]A`.
pub fn verify_ed25519_strict(
    pubkey: &Ed25519PubKey,
    message: &[u8],
    signature: &Ed25519Sig,
) -> Result<(), MpMlsError> {
    let vk = validate_ed25519_pubkey_strict(pubkey)?;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[0..32]);
    let mut r_y = r_bytes;
    r_y[31] &= 0x7f;
    if is_non_canonical_field_elem(&r_y) {
        return Err(MpMlsError::InvalidSignature);
    }

    // Reject small-order or mixed-order R (honest R = [r]B always lies in prime-order subgroup).
    let r_point = VerifyingKey::from_bytes(&r_bytes).map_err(|_| MpMlsError::InvalidSignature)?;
    if r_point.is_weak() || !r_point.to_edwards().is_torsion_free() {
        return Err(MpMlsError::WeakOrTorsionPoint);
    }

    // Explicit canonical S < L check independent of ed25519-dalek feature flags.
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..64]);
    if !is_canonical_ed25519_scalar(&s_bytes) {
        return Err(MpMlsError::InvalidSignature);
    }

    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig)
        .map_err(|_| MpMlsError::InvalidSignature)
}

/// Signs `message` with a pure RFC 8032 Ed25519 `SigningKey`.
pub fn sign_ed25519(sk: &SigningKey, message: &[u8]) -> Ed25519Sig {
    sk.sign(message).to_bytes()
}

const CROCKFORD_B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encodes `5 * num_chunks` bytes MSB-first into `8 * num_chunks` Crockford Base32 characters
/// grouped in chunks of 4 separated by `-`.
pub fn encode_crockford_grouped_4(bytes: &[u8]) -> String {
    debug_assert!(bytes.len().is_multiple_of(5));
    let num_chunks = bytes.len() / 5;
    let total_chars = num_chunks * 8;
    let num_dashes = if total_chars > 4 {
        (total_chars / 4) - 1
    } else {
        0
    };
    let mut out = String::with_capacity(total_chars + num_dashes);

    for chunk_idx in 0..num_chunks {
        let base = chunk_idx * 5;
        let bits40: u64 = (u64::from(bytes[base]) << 32)
            | (u64::from(bytes[base + 1]) << 24)
            | (u64::from(bytes[base + 2]) << 16)
            | (u64::from(bytes[base + 3]) << 8)
            | u64::from(bytes[base + 4]);

        for g in 0..8 {
            if (chunk_idx > 0 && g == 0) || g == 4 {
                out.push('-');
            }
            let shift = 35 - g * 5;
            let idx = ((bits40 >> shift) & 0x1f) as usize;
            out.push(char::from(CROCKFORD_B32[idx]));
        }
    }
    out
}

/// Strict `OpenMlsCrypto` + `OpenMlsRand` wrapper around `openmls_rust_crypto::RustCrypto`
/// that enforces our explicit `S < L` + torsion-free + canonical Ed25519 verification pre-checks
/// on every MLS-internal Ed25519 signature verification as well.
#[derive(Debug, Default)]
pub struct MpStrictCrypto {
    inner: RustCrypto,
}

impl OpenMlsRand for MpStrictCrypto {
    type Error = <RustCrypto as OpenMlsRand>::Error;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.inner.random_array()
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.inner.random_vec(len)
    }
}

impl OpenMlsCrypto for MpStrictCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if ciphersuite == Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedCiphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.inner.signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if alg == SignatureScheme::ED25519 {
            let pk_arr: &[u8; 32] = pk.try_into().map_err(|_| CryptoError::InvalidLength)?;
            let sig_arr: &[u8; 64] = signature
                .try_into()
                .map_err(|_| CryptoError::InvalidLength)?;
            verify_ed25519_strict(pk_arr, data, sig_arr).map_err(|_| CryptoError::InvalidSignature)
        } else {
            self.inner.verify_signature(alg, data, pk, signature)
        }
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.inner.hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        self.inner
            .hpke_setup_sender_and_export(config, pk_r, info, exporter_context, exporter_length)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.inner.hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        self.inner.derive_hpke_keypair(config, ikm)
    }
}

/// Production `OpenMlsProvider` backed by `MpStrictCrypto` and `MemoryStorage`
/// with isolated snapshot cloning and bounded-allocation binary state export/import.
#[derive(Debug, Default)]
pub struct MpCryptoProvider {
    crypto: MpStrictCrypto,
    storage: MemoryStorage,
}

impl MpCryptoProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an isolated provider containing a deep copy of all storage entries.
    /// Used to stage Welcome, Commit, encryption, and decryption without mutating active state.
    pub fn fork_isolated(&self) -> Result<Self, MpMlsError> {
        let map = self
            .storage
            .values
            .read()
            .map_err(|_| MpMlsError::OpenMls("storage lock poisoned".into()))?
            .clone();
        Ok(Self {
            crypto: MpStrictCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(map),
            },
        })
    }

    /// Atomically replaces the underlying storage map with `other`'s storage map.
    pub fn commit_from_isolated(&mut self, other: Self) -> Result<(), MpMlsError> {
        let new_map = other
            .storage
            .values
            .into_inner()
            .map_err(|_| MpMlsError::OpenMls("storage lock poisoned".into()))?;
        let mut dst = self
            .storage
            .values
            .write()
            .map_err(|_| MpMlsError::OpenMls("storage lock poisoned".into()))?;
        *dst = new_map;
        Ok(())
    }

    /// Serializes the raw storage map into a canonical deterministic binary blob (sorted unique keys).
    pub fn export_storage_binary(&self) -> Result<Vec<u8>, MpMlsError> {
        let guard = self
            .storage
            .values
            .read()
            .map_err(|_| MpMlsError::OpenMls("storage lock poisoned".into()))?;
        let mut entries: Vec<(&Vec<u8>, &Vec<u8>)> = guard.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut out = Vec::new();
        let count = u32::try_from(entries.len())
            .map_err(|_| MpMlsError::OpenMls("storage entry count overflow".into()))?;
        out.extend_from_slice(&count.to_be_bytes());
        for (k, v) in entries {
            let k_len = u32::try_from(k.len())
                .map_err(|_| MpMlsError::OpenMls("storage key too large".into()))?;
            let v_len = u32::try_from(v.len())
                .map_err(|_| MpMlsError::OpenMls("storage val too large".into()))?;
            out.extend_from_slice(&k_len.to_be_bytes());
            out.extend_from_slice(&v_len.to_be_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(v);
        }
        Ok(out)
    }

    /// Restores a provider from a binary blob produced by `export_storage_binary`.
    /// Caps preallocation by `remaining / 8` and rejects duplicate or unsorted keys (Astra #2 / Fable H7).
    pub fn import_storage_binary(bytes: &[u8]) -> Result<Self, MpMlsError> {
        let mut cursor = bytes;
        if cursor.len() < 4 {
            return Err(MpMlsError::TruncatedInput);
        }
        let count = u32::from_be_bytes(
            cursor[0..4]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        ) as usize;
        cursor = &cursor[4..];
        // Each entry consumes at least 8 bytes (`k_len: u32` + `v_len: u32`).
        if count > cursor.len() / 8 {
            return Err(MpMlsError::TruncatedInput);
        }
        let mut map = HashMap::with_capacity(count);
        let mut prev_key: Option<Vec<u8>> = None;
        for _ in 0..count {
            if cursor.len() < 8 {
                return Err(MpMlsError::TruncatedInput);
            }
            let k_len = u32::from_be_bytes(
                cursor[0..4]
                    .try_into()
                    .map_err(|_| MpMlsError::TruncatedInput)?,
            ) as usize;
            let v_len = u32::from_be_bytes(
                cursor[4..8]
                    .try_into()
                    .map_err(|_| MpMlsError::TruncatedInput)?,
            ) as usize;
            cursor = &cursor[8..];
            let entry_len = k_len
                .checked_add(v_len)
                .ok_or(MpMlsError::TruncatedInput)?;
            if cursor.len() < entry_len {
                return Err(MpMlsError::TruncatedInput);
            }
            let k = cursor[..k_len].to_vec();
            let v = cursor[k_len..entry_len].to_vec();
            cursor = &cursor[entry_len..];

            if let Some(ref prev) = prev_key
                && k <= *prev
            {
                return Err(MpMlsError::DuplicateOrUnsortedStorageKey);
            }
            prev_key = Some(k.clone());
            map.insert(k, v);
        }
        if !cursor.is_empty() {
            return Err(MpMlsError::TrailingBytes);
        }
        Ok(Self {
            crypto: MpStrictCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(map),
            },
        })
    }
}

impl OpenMlsProvider for MpCryptoProvider {
    type CryptoProvider = MpStrictCrypto;
    type RandProvider = MpStrictCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
