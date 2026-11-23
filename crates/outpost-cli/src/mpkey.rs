//! Portable encrypted `.mpkey` v1 recovery file codec (`IDENTITY_PORTABILITY_SPEC.md` §3).
//!
//! Wire format:
//! - Passphrase: UTF-8 normalized with Unicode NFC (`icu_normalizer`).
//! - KDF: Argon2id v0x13 (RFC 9106), empty secret & empty AD, 16-byte salt, 32-byte key.
//!   - Writer exact params: `m = 65536` KiB (64 MiB), `t = 3`, `p = 1`.
//!   - Reader validates PEM size (`<= 4096`), decoded binary length (`64..=1024`),
//!     magic (`b"MPKEY1\0\0"`), and KDF bounds (`65536 <= m <= 524288`, `3 <= t <= 16`,
//!     `1 <= p <= 8`) STRICTLY BEFORE allocating KDF memory.
//! - AEAD: AES-256-GCM, 12-byte nonce, 16-byte tag,
//!   AAD = `b"mpkey-v1:" || salt[16] || m_le32 || t_le32 || p_le32`.
//! - Plaintext JSON (parsed strictly AFTER AEAD tag verification):
//!   `{"v":1,"account_id":<u64|null>,"handle":<string|null>,"root_seed_b64":"<44-char canonical base64>"}`
//!   with unknown keys and duplicate keys strictly rejected.

use core::fmt;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use icu_normalizer::ComposingNormalizerBorrowed;
use outpost_daemon::{atomic_write_in_dir, fill_random};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroize as _;

pub const PEM_BEGIN: &str = "-----BEGIN MULTIPLAYER RECOVERY KEY-----";
pub const PEM_END: &str = "-----END MULTIPLAYER RECOVERY KEY-----";
pub const MPKEY_MAGIC: &[u8; 8] = b"MPKEY1\0\0";
pub const MPKEY_AAD_PREFIX: &[u8] = b"mpkey-v1:";

pub const MAX_PEM_BYTES: usize = 4096;
pub const MIN_BINARY_BYTES: usize = 64;
pub const MAX_BINARY_BYTES: usize = 1024;

pub const WRITER_M_KIB: u32 = 65_536;
pub const WRITER_T_COST: u32 = 3;
pub const WRITER_P_LANES: u32 = 1;

pub const MIN_M_KIB: u32 = 65_536;
pub const MAX_M_KIB: u32 = 524_288;
pub const MIN_T_COST: u32 = 3;
pub const MAX_T_COST: u32 = 16;
pub const MIN_P_LANES: u32 = 1;
pub const MAX_P_LANES: u32 = 8;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + SALT_LEN + 4 + 4 + 4; // 36
const AAD_LEN: usize = 9 + SALT_LEN + 4 + 4 + 4; // 37
const PEM_LINE_WIDTH: usize = 64;

/// Decrypted `.mpkey` payload. Automatically zeroizes `root_seed` on drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpkeyPayload {
    pub account_id: Option<u64>,
    pub handle: Option<String>,
    pub root_seed: [u8; 32],
}

impl Drop for MpkeyPayload {
    fn drop(&mut self) {
        self.root_seed.zeroize();
    }
}

#[derive(Serialize)]
struct MpkeyPlaintextWrite<'a> {
    v: u64,
    account_id: Option<u64>,
    handle: Option<&'a str>,
    root_seed_b64: &'a str,
}

struct MpkeyPlaintextRead {
    v: u64,
    account_id: Option<u64>,
    handle: Option<String>,
    root_seed_b64: String,
}

impl Drop for MpkeyPlaintextRead {
    fn drop(&mut self) {
        self.root_seed_b64.zeroize();
    }
}

impl<'de> Deserialize<'de> for MpkeyPlaintextRead {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PlaintextVisitor;

        impl<'de> Visitor<'de> for PlaintextVisitor {
            type Value = MpkeyPlaintextRead;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a .mpkey v1 plaintext JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut v: Option<u64> = None;
                let mut account_id: Option<Option<u64>> = None;
                let mut handle: Option<Option<String>> = None;
                let mut root_seed_b64: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "v" => {
                            if v.is_some() {
                                return Err(de::Error::duplicate_field("v"));
                            }
                            v = Some(map.next_value()?);
                        }
                        "account_id" => {
                            if account_id.is_some() {
                                return Err(de::Error::duplicate_field("account_id"));
                            }
                            account_id = Some(map.next_value()?);
                        }
                        "handle" => {
                            if handle.is_some() {
                                return Err(de::Error::duplicate_field("handle"));
                            }
                            handle = Some(map.next_value()?);
                        }
                        "root_seed_b64" => {
                            if root_seed_b64.is_some() {
                                return Err(de::Error::duplicate_field("root_seed_b64"));
                            }
                            root_seed_b64 = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["v", "account_id", "handle", "root_seed_b64"],
                            ));
                        }
                    }
                }

                let v = v.ok_or_else(|| de::Error::missing_field("v"))?;
                let account_id =
                    account_id.ok_or_else(|| de::Error::missing_field("account_id"))?;
                let handle = handle.ok_or_else(|| de::Error::missing_field("handle"))?;
                let root_seed_b64 =
                    root_seed_b64.ok_or_else(|| de::Error::missing_field("root_seed_b64"))?;

                Ok(MpkeyPlaintextRead {
                    v,
                    account_id,
                    handle,
                    root_seed_b64,
                })
            }
        }

        deserializer.deserialize_map(PlaintextVisitor)
    }
}

fn build_aad(salt: &[u8; SALT_LEN], m_kib: u32, t_cost: u32, p_lanes: u32) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    if let Some(dst) = aad.get_mut(0..9) {
        dst.copy_from_slice(MPKEY_AAD_PREFIX);
    }
    if let Some(dst) = aad.get_mut(9..25) {
        dst.copy_from_slice(salt);
    }
    if let Some(dst) = aad.get_mut(25..29) {
        dst.copy_from_slice(&m_kib.to_le_bytes());
    }
    if let Some(dst) = aad.get_mut(29..33) {
        dst.copy_from_slice(&t_cost.to_le_bytes());
    }
    if let Some(dst) = aad.get_mut(33..37) {
        dst.copy_from_slice(&p_lanes.to_le_bytes());
    }
    aad
}

fn derive_key_argon2id(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    m_kib: u32,
    t_cost: u32,
    p_lanes: u32,
) -> Result<[u8; 32], String> {
    let normalizer = ComposingNormalizerBorrowed::new_nfc();
    let mut normalized = normalizer.normalize(passphrase).into_owned();

    let params = Params::new(m_kib, t_cost, p_lanes, Some(32))
        .map_err(|e| format!("invalid Argon2id parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    let kdf_res = argon2.hash_password_into(normalized.as_bytes(), salt, &mut key);
    normalized.zeroize();

    if let Err(e) = kdf_res {
        key.zeroize();
        return Err(format!("Argon2id key derivation failed: {e}"));
    }
    Ok(key)
}

fn encode_pem(binary: &[u8]) -> Result<String, String> {
    let b64 = B64.encode(binary);
    let mut out = String::with_capacity(
        PEM_BEGIN.len() + PEM_END.len() + b64.len() + (b64.len() / PEM_LINE_WIDTH) + 8,
    );
    out.push_str(PEM_BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(PEM_LINE_WIDTH) {
        let line = core::str::from_utf8(chunk)
            .map_err(|_| "internal error: non-UTF8 base64 chunk".to_string())?;
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(PEM_END);
    out.push('\n');
    if out.len() > MAX_PEM_BYTES {
        return Err(format!(
            "encoded .mpkey PEM exceeds {MAX_PEM_BYTES}-byte limit"
        ));
    }
    Ok(out)
}

fn decode_pem(pem: &str) -> Result<Vec<u8>, String> {
    if pem.len() > MAX_PEM_BYTES {
        return Err(format!(
            ".mpkey PEM exceeds maximum allowed size ({MAX_PEM_BYTES} bytes)"
        ));
    }
    if !pem.is_ascii() {
        return Err(".mpkey PEM must be valid ASCII".to_string());
    }

    let mut lines = pem.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines
        .next()
        .ok_or_else(|| "empty .mpkey PEM input".to_string())?;
    if first != PEM_BEGIN {
        return Err(format!(
            "invalid .mpkey PEM header (expected '{PEM_BEGIN}')"
        ));
    }

    let mut b64_body = String::new();
    let mut saw_end = false;
    for line in lines {
        if saw_end {
            return Err("unexpected trailing data after .mpkey PEM footer".to_string());
        }
        if line == PEM_END {
            saw_end = true;
            continue;
        }
        if line.contains("-----") {
            return Err("unexpected PEM boundary marker inside .mpkey body".to_string());
        }
        if !line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        {
            return Err("invalid Base64 character in .mpkey PEM body".to_string());
        }
        b64_body.push_str(line);
    }

    if !saw_end {
        return Err(format!(
            "missing .mpkey PEM footer (expected '{PEM_END}')"
        ));
    }
    if b64_body.is_empty() {
        return Err("empty .mpkey PEM body".to_string());
    }

    let binary = B64
        .decode(b64_body.as_bytes())
        .map_err(|e| format!("invalid canonical Base64 in .mpkey: {e}"))?;
    if !(MIN_BINARY_BYTES..=MAX_BINARY_BYTES).contains(&binary.len()) {
        return Err(format!(
            "decoded .mpkey binary length {} outside allowed range {}..={}",
            binary.len(),
            MIN_BINARY_BYTES,
            MAX_BINARY_BYTES
        ));
    }
    Ok(binary)
}

/// Encrypts a 32-byte Ed25519 root seed into a canonical `.mpkey` v1 PEM string using fresh
/// CSPRNG 16-byte salt and 12-byte nonce.
pub fn encrypt_mpkey(
    root_seed: &[u8; 32],
    passphrase: &str,
    account_id: Option<u64>,
    handle: Option<&str>,
) -> Result<String, String> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt).map_err(|e| format!("CSPRNG failure generating salt: {e}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce).map_err(|e| format!("CSPRNG failure generating nonce: {e}"))?;
    encrypt_mpkey_deterministic(root_seed, passphrase, account_id, handle, salt, nonce)
}

/// Deterministic `.mpkey` v1 encryption with explicit `salt` and `nonce` (for golden vector tests).
pub fn encrypt_mpkey_deterministic(
    root_seed: &[u8; 32],
    passphrase: &str,
    account_id: Option<u64>,
    handle: Option<&str>,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<String, String> {
    let mut root_seed_b64 = B64.encode(root_seed);
    let plaintext_wire = MpkeyPlaintextWrite {
        v: 1,
        account_id,
        handle,
        root_seed_b64: &root_seed_b64,
    };
    let mut plaintext = serde_json::to_vec(&plaintext_wire)
        .map_err(|e| format!("failed serializing .mpkey plaintext: {e}"))?;
    root_seed_b64.zeroize();

    let mut key = derive_key_argon2id(
        passphrase,
        &salt,
        WRITER_M_KIB,
        WRITER_T_COST,
        WRITER_P_LANES,
    )?;

    let aad = build_aad(&salt, WRITER_M_KIB, WRITER_T_COST, WRITER_P_LANES);
    let cipher_res = Aes256Gcm::new_from_slice(&key);
    key.zeroize();
    let cipher = match cipher_res {
        Ok(c) => c,
        Err(_) => {
            plaintext.zeroize();
            return Err("failed initializing AES-256-GCM".to_string());
        }
    };

    let nonce_ref = Nonce::from_slice(&nonce);
    let ct_res = cipher.encrypt(
        nonce_ref,
        Payload {
            msg: plaintext.as_slice(),
            aad: &aad,
        },
    );
    plaintext.zeroize();
    let ct_and_tag = ct_res.map_err(|_| "AES-256-GCM encryption failed".to_string())?;

    let total_len = HEADER_LEN + NONCE_LEN + ct_and_tag.len();
    if !(MIN_BINARY_BYTES..=MAX_BINARY_BYTES).contains(&total_len) {
        return Err(format!(
            "encoded .mpkey binary length {total_len} exceeds spec limit {MAX_BINARY_BYTES}"
        ));
    }

    let mut container = Vec::with_capacity(total_len);
    container.extend_from_slice(MPKEY_MAGIC);
    container.extend_from_slice(&salt);
    container.extend_from_slice(&WRITER_M_KIB.to_le_bytes());
    container.extend_from_slice(&WRITER_T_COST.to_le_bytes());
    container.extend_from_slice(&WRITER_P_LANES.to_le_bytes());
    container.extend_from_slice(&nonce);
    container.extend_from_slice(&ct_and_tag);

    encode_pem(&container)
}

/// Validates and decrypts a `.mpkey` v1 PEM file.
///
/// Enforces PEM size (`<= 4096`), decoded length (`64..=1024`), exact magic (`b"MPKEY1\0\0"`),
/// and Argon2id parameter bounds (`m in 65536..=524288`, `t in 3..=16`, `p in 1..=8`)
/// STRICTLY BEFORE allocating KDF memory. Parses plaintext JSON STRICTLY AFTER AEAD verification.
pub fn decrypt_mpkey(pem: &str, passphrase: &str) -> Result<MpkeyPayload, String> {
    let binary = decode_pem(pem)?;

    let magic = binary
        .get(0..8)
        .ok_or_else(|| "truncated .mpkey header".to_string())?;
    if magic != MPKEY_MAGIC {
        return Err("invalid .mpkey magic or non-zero reserved header bytes".to_string());
    }

    let salt: [u8; SALT_LEN] = binary
        .get(8..24)
        .ok_or_else(|| "truncated .mpkey salt".to_string())?
        .try_into()
        .map_err(|_| "truncated .mpkey salt".to_string())?;

    let m_bytes: [u8; 4] = binary
        .get(24..28)
        .ok_or_else(|| "truncated .mpkey Argon2 m param".to_string())?
        .try_into()
        .map_err(|_| "truncated .mpkey Argon2 m param".to_string())?;
    let t_bytes: [u8; 4] = binary
        .get(28..32)
        .ok_or_else(|| "truncated .mpkey Argon2 t param".to_string())?
        .try_into()
        .map_err(|_| "truncated .mpkey Argon2 t param".to_string())?;
    let p_bytes: [u8; 4] = binary
        .get(32..36)
        .ok_or_else(|| "truncated .mpkey Argon2 p param".to_string())?
        .try_into()
        .map_err(|_| "truncated .mpkey Argon2 p param".to_string())?;

    let m_kib = u32::from_le_bytes(m_bytes);
    let t_cost = u32::from_le_bytes(t_bytes);
    let p_lanes = u32::from_le_bytes(p_bytes);

    // STRICTLY validate KDF bounds BEFORE allocating Argon2id memory!
    if !(MIN_M_KIB..=MAX_M_KIB).contains(&m_kib) {
        return Err(format!(
            "refusing .mpkey with out-of-bounds Argon2id memory m={m_kib} KiB (allowed {MIN_M_KIB}..={MAX_M_KIB})"
        ));
    }
    if !(MIN_T_COST..=MAX_T_COST).contains(&t_cost) {
        return Err(format!(
            "refusing .mpkey with out-of-bounds Argon2id iterations t={t_cost} (allowed {MIN_T_COST}..={MAX_T_COST})"
        ));
    }
    if !(MIN_P_LANES..=MAX_P_LANES).contains(&p_lanes) {
        return Err(format!(
            "refusing .mpkey with out-of-bounds Argon2id parallelism p={p_lanes} (allowed {MIN_P_LANES}..={MAX_P_LANES})"
        ));
    }

    let nonce_slice = binary
        .get(HEADER_LEN..HEADER_LEN + NONCE_LEN)
        .ok_or_else(|| "truncated .mpkey nonce".to_string())?;
    let ct_and_tag = binary
        .get(HEADER_LEN + NONCE_LEN..)
        .ok_or_else(|| "truncated .mpkey ciphertext".to_string())?;
    if ct_and_tag.len() < TAG_LEN {
        return Err("truncated .mpkey AEAD authentication tag".to_string());
    }

    let mut key = derive_key_argon2id(passphrase, &salt, m_kib, t_cost, p_lanes)?;
    let aad = build_aad(&salt, m_kib, t_cost, p_lanes);
    let cipher_res = Aes256Gcm::new_from_slice(&key);
    key.zeroize();
    let cipher = cipher_res.map_err(|_| "failed initializing AES-256-GCM".to_string())?;

    let nonce_ref = Nonce::from_slice(nonce_slice);
    let mut plaintext = cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: ct_and_tag,
                aad: &aad,
            },
        )
        .map_err(|_| "failed to decrypt .mpkey (wrong passphrase or tampered file)".to_string())?;

    // Strictly AFTER AEAD verification succeeds: parse strict UTF-8 JSON object.
    let parse_res = parse_verified_plaintext(&plaintext);
    plaintext.zeroize();
    parse_res
}

fn parse_verified_plaintext(plaintext: &[u8]) -> Result<MpkeyPayload, String> {
    let text = core::str::from_utf8(plaintext)
        .map_err(|_| ".mpkey plaintext is not valid UTF-8".to_string())?;
    let parsed: MpkeyPlaintextRead = serde_json::from_str(text)
        .map_err(|e| format!("invalid .mpkey plaintext JSON: {e}"))?;

    if parsed.v != 1 {
        return Err(format!("unsupported .mpkey plaintext version {}", parsed.v));
    }
    if parsed.root_seed_b64.len() != 44 {
        return Err("invalid root_seed_b64 length (expected 44 canonical Base64 chars)".to_string());
    }
    let mut decoded = B64
        .decode(parsed.root_seed_b64.as_bytes())
        .map_err(|e| format!("invalid root_seed_b64: {e}"))?;
    if decoded.len() != 32 {
        decoded.zeroize();
        return Err("root_seed_b64 did not decode to exactly 32 bytes".to_string());
    }
    let mut canonical_check = B64.encode(&decoded);
    let is_canonical = canonical_check == parsed.root_seed_b64;
    canonical_check.zeroize();
    if !is_canonical {
        decoded.zeroize();
        return Err("root_seed_b64 is not canonical Base64".to_string());
    }

    let mut root_seed = [0u8; 32];
    root_seed.copy_from_slice(&decoded);
    decoded.zeroize();

    Ok(MpkeyPayload {
        account_id: parsed.account_id,
        handle: parsed.handle.clone(),
        root_seed,
    })
}

/// Atomically writes a `.mpkey` PEM file with strict `0600` permissions in the target
/// directory (`openat(O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, 0o600)` -> `write_all` ->
/// `fsync` -> `renameat` -> `fsync(dirfd)`).
pub fn write_mpkey_atomic_0600(path: &Path, pem: &str) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid output path '{}'", path.display()))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let parent_c = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| "output directory path contains interior NUL byte".to_string())?;
    let raw_fd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(format!(
            "failed to open output directory '{}': {}",
            parent.display(),
            io::Error::last_os_error()
        ));
    }
    let dir_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    atomic_write_in_dir(dir_fd.as_raw_fd(), file_name, pem.as_bytes())
        .map_err(|e| format!("failed writing .mpkey file '{}': {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const GOLDEN_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const GOLDEN_SALT: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const GOLDEN_NONCE: [u8; 12] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    ];
    const GOLDEN_PASSPHRASE: &str = "correct-horse-battery-staple";

    fn build_custom_plaintext_container(
        plaintext: &[u8],
        passphrase: &str,
    ) -> Result<String, String> {
        let mut key = derive_key_argon2id(
            passphrase,
            &GOLDEN_SALT,
            WRITER_M_KIB,
            WRITER_T_COST,
            WRITER_P_LANES,
        )?;
        let aad = build_aad(&GOLDEN_SALT, WRITER_M_KIB, WRITER_T_COST, WRITER_P_LANES);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "aes init".to_string())?;
        key.zeroize();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&GOLDEN_NONCE),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| "encrypt".to_string())?;
        let mut bin = Vec::new();
        bin.extend_from_slice(MPKEY_MAGIC);
        bin.extend_from_slice(&GOLDEN_SALT);
        bin.extend_from_slice(&WRITER_M_KIB.to_le_bytes());
        bin.extend_from_slice(&WRITER_T_COST.to_le_bytes());
        bin.extend_from_slice(&WRITER_P_LANES.to_le_bytes());
        bin.extend_from_slice(&GOLDEN_NONCE);
        bin.extend_from_slice(&ct);
        encode_pem(&bin)
    }

    #[test]
    fn deterministic_golden_vector_roundtrip() -> Result<(), String> {
        let pem = encrypt_mpkey_deterministic(
            &GOLDEN_SEED,
            GOLDEN_PASSPHRASE,
            Some(1001),
            Some("antimeme"),
            GOLDEN_SALT,
            GOLDEN_NONCE,
        )?;
        assert!(pem.starts_with(PEM_BEGIN));
        assert!(pem.trim_end().ends_with(PEM_END));

        // Verify deterministic reproducibility.
        let pem2 = encrypt_mpkey_deterministic(
            &GOLDEN_SEED,
            GOLDEN_PASSPHRASE,
            Some(1001),
            Some("antimeme"),
            GOLDEN_SALT,
            GOLDEN_NONCE,
        )?;
        assert_eq!(pem, pem2);

        let dec = decrypt_mpkey(&pem, GOLDEN_PASSPHRASE)?;
        assert_eq!(dec.account_id, Some(1001));
        assert_eq!(dec.handle.as_deref(), Some("antimeme"));
        assert_eq!(dec.root_seed, GOLDEN_SEED);

        // Wrong passphrase MUST fail.
        assert!(decrypt_mpkey(&pem, "wrong-passphrase-12345").is_err());

        // Print golden vector when running with --nocapture for cross-client sharing.
        let raw_bin = decode_pem(&pem)?;
        eprintln!("GOLDEN_MPKEY_PEM:\n{pem}");
        eprintln!("GOLDEN_MPKEY_HEX: {}", crate::build_info::encode_hex(&raw_bin));
        Ok(())
    }

    #[test]
    fn nfc_passphrase_equivalence() -> Result<(), String> {
        let nfd = "cafe\u{0301}-passphrase-1234";
        let nfc = "caf\u{00e9}-passphrase-1234";
        assert_ne!(nfd.as_bytes(), nfc.as_bytes());

        let pem_from_nfd = encrypt_mpkey_deterministic(
            &GOLDEN_SEED,
            nfd,
            None,
            None,
            GOLDEN_SALT,
            GOLDEN_NONCE,
        )?;
        let pem_from_nfc = encrypt_mpkey_deterministic(
            &GOLDEN_SEED,
            nfc,
            None,
            None,
            GOLDEN_SALT,
            GOLDEN_NONCE,
        )?;
        // Identical salt/nonce + NFC-equivalent passphrases produce byte-identical PEM!
        assert_eq!(pem_from_nfd, pem_from_nfc);

        let dec1 = decrypt_mpkey(&pem_from_nfd, nfc)?;
        let dec2 = decrypt_mpkey(&pem_from_nfc, nfd)?;
        assert_eq!(dec1.root_seed, GOLDEN_SEED);
        assert_eq!(dec2.root_seed, GOLDEN_SEED);
        assert_eq!(dec1.account_id, None);
        assert_eq!(dec1.handle, None);
        Ok(())
    }

    #[test]
    fn rejects_tampered_tag_aad_magic_and_bounds_before_kdf() -> Result<(), String> {
        let pem = encrypt_mpkey_deterministic(
            &GOLDEN_SEED,
            GOLDEN_PASSPHRASE,
            Some(42),
            Some("alice"),
            GOLDEN_SALT,
            GOLDEN_NONCE,
        )?;
        let valid_bin = decode_pem(&pem)?;

        // 1. Tampered AEAD tag (last byte flipped).
        let mut bad_tag = valid_bin.clone();
        if let Some(last) = bad_tag.last_mut() {
            *last ^= 0x01;
        }
        assert!(decrypt_mpkey(&encode_pem(&bad_tag)?, GOLDEN_PASSPHRASE).is_err());

        // 2. Tampered header param (m changed within valid bounds -> AAD + KDF mismatch).
        let mut bad_aad = valid_bin.clone();
        if let Some(m_slot) = bad_aad.get_mut(24..28) {
            m_slot.copy_from_slice(&65_537u32.to_le_bytes());
        }
        assert!(decrypt_mpkey(&encode_pem(&bad_aad)?, GOLDEN_PASSPHRASE).is_err());

        // 3. Out-of-bounds KDF params MUST fail immediately BEFORE allocating KDF memory!
        //    Use huge m = u32::MAX (4 TiB) — if KDF were invoked it would OOM/hang.
        let mut huge_m = valid_bin.clone();
        if let Some(m_slot) = huge_m.get_mut(24..28) {
            m_slot.copy_from_slice(&u32::MAX.to_le_bytes());
        }
        let err_huge_m = decrypt_mpkey(&encode_pem(&huge_m)?, GOLDEN_PASSPHRASE)
            .err()
            .unwrap_or_default();
        assert!(err_huge_m.contains("out-of-bounds Argon2id memory"));

        // m < 65536
        let mut tiny_m = valid_bin.clone();
        if let Some(m_slot) = tiny_m.get_mut(24..28) {
            m_slot.copy_from_slice(&32_768u32.to_le_bytes());
        }
        assert!(decrypt_mpkey(&encode_pem(&tiny_m)?, GOLDEN_PASSPHRASE).is_err());

        // t < 3 or t > 16
        let mut bad_t = valid_bin.clone();
        if let Some(t_slot) = bad_t.get_mut(28..32) {
            t_slot.copy_from_slice(&2u32.to_le_bytes());
        }
        assert!(decrypt_mpkey(&encode_pem(&bad_t)?, GOLDEN_PASSPHRASE).is_err());
        if let Some(t_slot) = bad_t.get_mut(28..32) {
            t_slot.copy_from_slice(&17u32.to_le_bytes());
        }
        assert!(decrypt_mpkey(&encode_pem(&bad_t)?, GOLDEN_PASSPHRASE).is_err());

        // p < 1 or p > 8
        let mut bad_p = valid_bin.clone();
        if let Some(p_slot) = bad_p.get_mut(32..36) {
            p_slot.copy_from_slice(&0u32.to_le_bytes());
        }
        assert!(decrypt_mpkey(&encode_pem(&bad_p)?, GOLDEN_PASSPHRASE).is_err());
        if let Some(p_slot) = bad_p.get_mut(32..36) {
            p_slot.copy_from_slice(&9u32.to_le_bytes());
        }
        assert!(decrypt_mpkey(&encode_pem(&bad_p)?, GOLDEN_PASSPHRASE).is_err());

        // 4. Non-zero reserved magic bytes (bytes 6..8).
        let mut bad_magic = valid_bin.clone();
        if let Some(b) = bad_magic.get_mut(7) {
            *b = 0x01;
        }
        assert!(decrypt_mpkey(&encode_pem(&bad_magic)?, GOLDEN_PASSPHRASE).is_err());

        // 5. Oversized PEM (> 4096 bytes) rejected immediately.
        let mut oversized = String::from(PEM_BEGIN);
        oversized.push('\n');
        for _ in 0..70 {
            oversized.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        }
        oversized.push_str(PEM_END);
        oversized.push('\n');
        assert!(oversized.len() > MAX_PEM_BYTES);
        assert!(decrypt_mpkey(&oversized, GOLDEN_PASSPHRASE).is_err());

        // 6. Decoded binary < 64 bytes rejected.
        let short_pem = encode_pem(&[0u8; 63])?;
        assert!(decrypt_mpkey(&short_pem, GOLDEN_PASSPHRASE).is_err());

        Ok(())
    }

    #[test]
    fn rejects_invalid_plaintext_json_schemas() -> Result<(), String> {
        let seed_b64 = B64.encode(GOLDEN_SEED);

        // Unknown key
        let unknown_key = format!(
            r#"{{"v":1,"account_id":1,"handle":"a","root_seed_b64":"{seed_b64}","extra":true}}"#
        );
        let pem_unk = build_custom_plaintext_container(unknown_key.as_bytes(), GOLDEN_PASSPHRASE)?;
        assert!(decrypt_mpkey(&pem_unk, GOLDEN_PASSPHRASE).is_err());

        // Duplicate key (even with null!)
        let dup_key = format!(
            r#"{{"v":1,"account_id":null,"account_id":null,"handle":null,"root_seed_b64":"{seed_b64}"}}"#
        );
        let pem_dup = build_custom_plaintext_container(dup_key.as_bytes(), GOLDEN_PASSPHRASE)?;
        assert!(decrypt_mpkey(&pem_dup, GOLDEN_PASSPHRASE).is_err());

        // Wrong version v != 1
        let bad_ver = format!(
            r#"{{"v":2,"account_id":null,"handle":null,"root_seed_b64":"{seed_b64}"}}"#
        );
        let pem_ver = build_custom_plaintext_container(bad_ver.as_bytes(), GOLDEN_PASSPHRASE)?;
        assert!(decrypt_mpkey(&pem_ver, GOLDEN_PASSPHRASE).is_err());

        // Wrong length root_seed_b64 (31 bytes instead of 32)
        let short_seed = B64.encode([0x42u8; 31]);
        let bad_seed = format!(
            r#"{{"v":1,"account_id":null,"handle":null,"root_seed_b64":"{short_seed}"}}"#
        );
        let pem_seed = build_custom_plaintext_container(bad_seed.as_bytes(), GOLDEN_PASSPHRASE)?;
        assert!(decrypt_mpkey(&pem_seed, GOLDEN_PASSPHRASE).is_err());

        Ok(())
    }

    #[test]
    fn atomic_write_sets_0600_permissions() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let out_path = dir.path().join("backup.mpkey");
        let pem = encrypt_mpkey(&GOLDEN_SEED, GOLDEN_PASSPHRASE, Some(7), Some("bob"))?;
        write_mpkey_atomic_0600(&out_path, &pem)?;

        let meta = std::fs::metadata(&out_path).map_err(|e| format!("metadata: {e}"))?;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let read_back = std::fs::read_to_string(&out_path).map_err(|e| format!("read: {e}"))?;
        assert_eq!(read_back, pem);
        let dec = decrypt_mpkey(&read_back, GOLDEN_PASSPHRASE)?;
        assert_eq!(dec.root_seed, GOLDEN_SEED);
        Ok(())
    }
}
