//! E2EE Dead-Drop Inbox Suite 1 local encryption subkey storage (`d<13hex>.enc.bin`),
//! CLI subcommands (`mp-outpost inbox init-key|send|read|ack`), and MCP backend helpers.
//!
//! Security invariants:
//! - Per-device X25519 private scalar `enc_sk` is stored mode `0600` (`O_NOFOLLOW`, atomic
//!   write under `StateLock`), wrapped in `Zeroizing`, and never logged or printed.
//! - Outbound messages are scanned via `scan_outbound_secrets` with the real device secret &
//!   CWT BEFORE any network call or encryption.
//! - Every recipient device's `device_cwt` AND 161-byte `enc_cert` are verified locally
//!   against the recipient's `root_pubkey`, cross-checked against local `peers.bin` (refusing
//!   `RevokedBlocked` or `KeyMismatch`).
//! - Every inbound drop's `sender_cwt` AND 161-byte `sender_enc_cert` are verified locally,
//!   cross-checked against local `peers.bin`, decrypted via Suite 1 HPKE `ModeAuth` +
//!   key-committing ChaCha20-Poly1305, and nonce-fenced (`fence_peer_text`) before display.

use core::fmt;
use std::collections::HashMap;
use std::io::{self, Read as _};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use mp_protocol::{
    AccountId, DeviceId, ENC_SUBKEY_CERT_BYTES, MAX_SAFE_ID, validate_ed25519_pubkey_strict,
    verify_device_cwt, verify_enc_subkey_cert,
};
use outpost_control::{
    AckInboxResponse, ControlClient, ControlError, MAX_INBOX_PENDING_DROPS, PostInboxDropRequest,
    PostInboxDropResponse, RequestSigner, WrappedDeviceKey, wall_now_ms, wall_now_secs,
};
use outpost_core::fence::{SecretMatchKind, fence_peer_text, sanitize_peer_text, scan_outbound_secrets};
use outpost_core::inbox_crypto::{
    INBOX_MAX_PLAINTEXT_BYTES, INBOX_SUITE_1, InboxRecipientDevice, MAX_ENC_CERT_TTL_SECS,
    open_inbox_drop, seal_inbox_drop, sign_enc_subkey_cert, x25519_public_key,
};
use outpost_core::storage_codec::{DeviceRecord, PeersStoreRecord, TrustState};
use outpost_core::trust::{api_authority_hash, compute_safety_number};
use outpost_daemon::{
    VerifiedDir, atomic_write_in_dir, fill_random, format_device_dir_name, read_file_in_dir,
};
use outpost_mcp::{
    BackendError, InboxAckArgs, InboxAckResult, InboxDecryptedDrop, InboxReadArgs, InboxReadResult,
    InboxSendArgs, InboxSendResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::build_info::{decode_hex_32, encode_hex};
use crate::cli::GlobalOpts;
use crate::storage::{
    build_control_client_config, load_device_record, load_peers_store, lock_state, open_state_dir,
    resolve_active_device_id, resolve_effective_state_dir,
};

pub const INBOX_MIN_TTL_SECS: u64 = 300;
pub const INBOX_MAX_TTL_SECS: u64 = 604_800;
pub const INBOX_DEFAULT_TTL_SECS: u64 = 604_800;
const ENC_KEY_RENEW_MARGIN_SECS: i64 = 86_400;
const MAX_ENC_KEY_FILE_BYTES: usize = 4096;

/// Local per-device X25519 encryption keypair & signed 161-byte `enc_cert`.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEncKeyRecord {
    pub enc_sk: Zeroizing<[u8; 32]>,
    pub enc_pk: [u8; 32],
    pub enc_cert: Vec<u8>,
    pub enc_cert_b64: String,
    pub enc_cert_exp_s: i64,
}

impl fmt::Debug for LocalEncKeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEncKeyRecord")
            .field("enc_sk", &"[REDACTED]")
            .field("enc_pk_hex", &encode_hex(&self.enc_pk))
            .field("enc_cert_exp_s", &self.enc_cert_exp_s)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct EncKeyDiskRecord {
    enc_sk_hex: String,
    enc_pk_hex: String,
    enc_cert_b64: String,
    enc_cert_exp_s: i64,
}

#[derive(Debug)]
enum InboxOpError {
    SecretRefused(SecretMatchKind),
    InvalidParams(String),
    Failed(String),
}

impl InboxOpError {
    fn into_cli_string(self) -> String {
        match self {
            Self::SecretRefused(kind) => format!(
                "refused to send inbox message matching protected secret material ({kind:?})"
            ),
            Self::InvalidParams(msg) | Self::Failed(msg) => msg,
        }
    }

    fn into_backend_error(self) -> BackendError {
        match self {
            Self::SecretRefused(kind) => BackendError::SecretRefused(kind),
            Self::InvalidParams(msg) => BackendError::InvalidParams(msg),
            Self::Failed(msg) => BackendError::ToolError {
                code: "inbox_error".to_string(),
                message: msg,
            },
        }
    }
}

/// Returns the canonical filename `d<13hex>.enc.bin` for a device's X25519 encryption keypair.
pub fn enc_key_filename(device_id: u64) -> Result<String, String> {
    let prefix = format_device_dir_name(device_id).map_err(|e| e.to_string())?;
    Ok(format!("{prefix}.enc.bin"))
}

/// Loads `d<13hex>.enc.bin` from `state_dir` using `O_NOFOLLOW` + bounded read.
pub fn load_local_enc_key(
    state_dir: &VerifiedDir,
    device_id: u64,
) -> Result<Option<LocalEncKeyRecord>, String> {
    let fname = enc_key_filename(device_id)?;
    let Some(raw_bytes) = read_file_in_dir(state_dir.as_raw_fd(), &fname, MAX_ENC_KEY_FILE_BYTES)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let raw_bytes = Zeroizing::new(raw_bytes);
    let parsed: EncKeyDiskRecord = serde_json::from_slice(raw_bytes.as_slice())
        .map_err(|e| format!("corrupt inbox encryption key file '{fname}': {e}"))?;
    let sk_hex = Zeroizing::new(parsed.enc_sk_hex);
    let enc_sk = Zeroizing::new(
        decode_hex_32(sk_hex.as_str())
            .ok_or_else(|| format!("corrupt enc_sk_hex in '{fname}'"))?,
    );
    let enc_pk = decode_hex_32(&parsed.enc_pk_hex)
        .ok_or_else(|| format!("corrupt enc_pk_hex in '{fname}'"))?;
    let derived_pk = x25519_public_key(&enc_sk);
    if derived_pk != enc_pk {
        return Err(format!("enc_sk/enc_pk mismatch in '{fname}'"));
    }
    let enc_cert = B64
        .decode(parsed.enc_cert_b64.as_bytes())
        .map_err(|e| format!("corrupt enc_cert_b64 in '{fname}': {e}"))?;
    if enc_cert.len() != ENC_SUBKEY_CERT_BYTES {
        return Err(format!(
            "invalid enc_cert length {} in '{fname}' (expected {ENC_SUBKEY_CERT_BYTES})",
            enc_cert.len()
        ));
    }
    Ok(Some(LocalEncKeyRecord {
        enc_sk,
        enc_pk,
        enc_cert,
        enc_cert_b64: parsed.enc_cert_b64,
        enc_cert_exp_s: parsed.enc_cert_exp_s,
    }))
}

fn save_local_enc_key(
    state_dir: &VerifiedDir,
    device_id: u64,
    rec: &LocalEncKeyRecord,
) -> Result<(), String> {
    let fname = enc_key_filename(device_id)?;
    let disk = EncKeyDiskRecord {
        enc_sk_hex: encode_hex(&*rec.enc_sk),
        enc_pk_hex: encode_hex(&rec.enc_pk),
        enc_cert_b64: rec.enc_cert_b64.clone(),
        enc_cert_exp_s: rec.enc_cert_exp_s,
    };
    let serialized = Zeroizing::new(
        serde_json::to_vec(&disk).map_err(|e| format!("failed serializing '{fname}': {e}"))?,
    );
    let _lock = lock_state(state_dir)?;
    atomic_write_in_dir(state_dir.as_raw_fd(), &fname, serialized.as_slice())
        .map_err(|e| format!("failed writing '{fname}': {e}"))
}

/// Ensures the enrolled device has a valid, non-expiring (`>= 24h` remaining) X25519
/// encryption subkey and 161-byte `enc_cert` uploaded to the control plane and persisted
/// atomically (`0600`) to `d<13hex>.enc.bin`.
pub async fn ensure_or_rotate_device_enc_key(
    state_dir: &VerifiedDir,
    dev_rec: &DeviceRecord,
    client: &ControlClient,
    force_rotate: bool,
) -> Result<LocalEncKeyRecord, String> {
    let now_s = wall_now_secs();

    if !force_rotate {
        let existing_opt = {
            let _lock = lock_state(state_dir)?;
            load_local_enc_key(state_dir, dev_rec.device_id)?
        };
        if let Some(existing) = existing_opt
            && existing.enc_cert_exp_s.saturating_sub(now_s) >= ENC_KEY_RENEW_MARGIN_SECS
            && let Ok(claims) = verify_enc_subkey_cert(
                &existing.enc_cert,
                dev_rec.account_id,
                dev_rec.device_id,
                &dev_rec.root_pubkey,
                &dev_rec.device_pubkey,
                now_s,
            )
            && claims.enc_pk == existing.enc_pk
        {
            return Ok(existing);
        }
    }

    let mut enc_sk = Zeroizing::new([0u8; 32]);
    fill_random(&mut *enc_sk).map_err(|e| format!("CSPRNG failure generating enc_sk: {e}"))?;
    let enc_pk = x25519_public_key(&enc_sk);

    let aid = AccountId::new(dev_rec.account_id).map_err(|e| e.to_string())?;
    let did = DeviceId::new(dev_rec.device_id).map_err(|e| e.to_string())?;
    let dev_sk = SigningKey::from_bytes(&dev_rec.device_secret);
    let exp_s = now_s.saturating_add(MAX_ENC_CERT_TTL_SECS);
    let enc_cert_arr = sign_enc_subkey_cert(
        aid,
        did,
        &dev_rec.root_pubkey,
        &enc_pk,
        now_s,
        exp_s,
        &dev_sk,
    )
    .map_err(|e| format!("failed signing enc_cert: {e}"))?;
    let enc_cert = enc_cert_arr.to_vec();
    let enc_cert_b64 = B64.encode(&enc_cert);

    let _ = client
        .put_device_enc_key(dev_rec.device_id, &enc_cert_b64)
        .await
        .map_err(|e| format!("failed uploading device encryption key: {e}"))?;

    let record = LocalEncKeyRecord {
        enc_sk,
        enc_pk,
        enc_cert,
        enc_cert_b64,
        enc_cert_exp_s: exp_s,
    };
    save_local_enc_key(state_dir, dev_rec.device_id, &record)?;
    Ok(record)
}

fn build_device_control_client(dev: &DeviceRecord) -> Result<ControlClient, String> {
    let cfg = build_control_client_config(&dev.api_authority).map_err(|e| e.to_string())?;
    let aid = AccountId::new(dev.account_id).map_err(|e| e.to_string())?;
    let did = DeviceId::new(dev.device_id).map_err(|e| e.to_string())?;
    let signer = RequestSigner::device(aid, did, dev.device_secret);
    Ok(ControlClient::with_device_signer(cfg, signer))
}

fn sanitize_single_line(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in sanitize_peer_text(input).chars() {
        match ch {
            '\n' | '\r' | '\t' => out.push(' '),
            '[' | ']' | '<' | '>' | '=' => {}
            _ => out.push(ch),
        }
    }
    out
}

fn decode_exact_32(b64: &str, label: &str) -> Result<[u8; 32], String> {
    let raw = B64
        .decode(b64.trim().as_bytes())
        .map_err(|e| format!("invalid {label} base64: {e}"))?;
    raw.try_into()
        .map_err(|_| format!("{label} did not decode to 32 bytes"))
}

fn decode_exact_16(b64: &str, label: &str) -> Result<[u8; 16], String> {
    let raw = B64
        .decode(b64.trim().as_bytes())
        .map_err(|e| format!("invalid {label} base64: {e}"))?;
    raw.try_into()
        .map_err(|_| format!("{label} did not decode to 16 bytes"))
}

fn check_peer_store_key_policy(
    peers: &PeersStoreRecord,
    auth_hash: [u8; 8],
    account_id: u64,
    observed_root_pk: &[u8; 32],
) -> Result<Option<String>, String> {
    if let Some(peer) = peers
        .peers
        .iter()
        .find(|p| p.api_authority_hash == auth_hash && p.account_id == account_id)
    {
        if peer.trust_state == TrustState::RevokedBlocked {
            return Err(format!(
                "refusing inbox operation for revoked/blocked account_id={account_id}"
            ));
        }
        if peer.root_pubkey != [0u8; 32] && &peer.root_pubkey != observed_root_pk {
            return Err(format!(
                "KEY MISMATCH for account_id={account_id}: server root_pubkey disagrees with locally pinned peers.bin"
            ));
        }
        return Ok(Some(peer.handle_prop.clone()));
    }
    Ok(None)
}

async fn resolve_recipient(
    client: &ControlClient,
    recipient: &str,
) -> Result<(u64, Option<[u8; 32]>), InboxOpError> {
    let trimmed = recipient.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 64 {
        return Err(InboxOpError::InvalidParams(
            "recipient must be 1..=64 characters".to_string(),
        ));
    }
    if !trimmed.starts_with('@') && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        let id = trimmed
            .parse::<u64>()
            .map_err(|_| InboxOpError::InvalidParams(format!("invalid account_id '{trimmed}'")))?;
        if id == 0 || id > MAX_SAFE_ID {
            return Err(InboxOpError::InvalidParams(format!(
                "recipient account_id must be in 1..={MAX_SAFE_ID}"
            )));
        }
        return Ok((id, None));
    }
    let handle = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let resolved = client
        .resolve_handle(handle)
        .await
        .map_err(|e| InboxOpError::Failed(format!("failed resolving recipient '@{handle}': {e}")))?;
    let expected_root = decode_exact_32(&resolved.root_pubkey_b64, "resolved root_pubkey")
        .map_err(InboxOpError::Failed)?;
    Ok((resolved.account_id, Some(expected_root)))
}

async fn inbox_send_core(
    state_dir_path: &Path,
    device_id_override: Option<u64>,
    recipient: &str,
    body: &str,
    ttl_secs: Option<u64>,
) -> Result<PostInboxDropResponse, InboxOpError> {
    if body.is_empty() || body.len() > INBOX_MAX_PLAINTEXT_BYTES {
        return Err(InboxOpError::InvalidParams(format!(
            "inbox message body must be 1..={INBOX_MAX_PLAINTEXT_BYTES} bytes"
        )));
    }
    let effective_ttl = ttl_secs.unwrap_or(INBOX_DEFAULT_TTL_SECS);
    if !(INBOX_MIN_TTL_SECS..=INBOX_MAX_TTL_SECS).contains(&effective_ttl) {
        return Err(InboxOpError::InvalidParams(format!(
            "ttl_secs must be in {INBOX_MIN_TTL_SECS}..={INBOX_MAX_TTL_SECS}"
        )));
    }

    let device_id =
        resolve_active_device_id(state_dir_path, device_id_override).map_err(InboxOpError::Failed)?;
    let dev = load_device_record(state_dir_path, device_id).map_err(InboxOpError::Failed)?;

    // CRITICAL: Scan outbound plaintext against own device_secret, device_cwt, and all static secrets.
    if let Some(kind) = scan_outbound_secrets(body.as_bytes(), &dev.device_secret, &dev.device_cwt)
    {
        return Err(InboxOpError::SecretRefused(kind));
    }

    let state_dir = open_state_dir(state_dir_path).map_err(InboxOpError::Failed)?;
    let client = build_device_control_client(&dev).map_err(InboxOpError::Failed)?;

    let (recipient_aid_u64, resolved_root_opt) = resolve_recipient(&client, recipient).await?;
    let local_enc = ensure_or_rotate_device_enc_key(&state_dir, &dev, &client, false)
        .await
        .map_err(InboxOpError::Failed)?;

    let enc_keys = client
        .get_account_enc_keys(recipient_aid_u64)
        .await
        .map_err(|e| InboxOpError::Failed(format!("failed fetching recipient encryption keys: {e}")))?;
    if enc_keys.account_id != recipient_aid_u64 {
        return Err(InboxOpError::Failed(format!(
            "server returned enc-keys for account_id={} (expected {recipient_aid_u64})",
            enc_keys.account_id
        )));
    }

    let recipient_root_pk = decode_exact_32(&enc_keys.root_pubkey_b64, "recipient root_pubkey")
        .map_err(InboxOpError::Failed)?;
    let _ = validate_ed25519_pubkey_strict(&recipient_root_pk)
        .map_err(|e| InboxOpError::Failed(format!("invalid recipient root_pubkey: {e}")))?;
    if let Some(resolved_root) = resolved_root_opt
        && resolved_root != recipient_root_pk
    {
        return Err(InboxOpError::Failed(
            "recipient root_pubkey from resolve_handle disagrees with get_account_enc_keys"
                .to_string(),
        ));
    }
    if recipient_aid_u64 == dev.account_id && recipient_root_pk != dev.root_pubkey {
        return Err(InboxOpError::Failed(
            "server returned mismatched root_pubkey for own account".to_string(),
        ));
    }

    // Zero-trust cross-check against local `peers.bin`.
    let peers = {
        let _lock = lock_state(&state_dir).map_err(InboxOpError::Failed)?;
        load_peers_store(&state_dir).map_err(InboxOpError::Failed)?
    };
    let auth_hash = api_authority_hash(&dev.api_authority);
    let _ = check_peer_store_key_policy(&peers, auth_hash, recipient_aid_u64, &recipient_root_pk)
        .map_err(InboxOpError::Failed)?;

    // Cryptographically verify EVERY recipient device's `device_cwt` AND 161-byte `enc_cert`.
    let now_s = wall_now_secs();
    let mut recipients = Vec::with_capacity(enc_keys.devices.len());
    for d in &enc_keys.devices {
        let dev_pk = decode_exact_32(&d.device_pubkey_b64, "recipient device_pubkey")
            .map_err(InboxOpError::Failed)?;
        let _ = validate_ed25519_pubkey_strict(&dev_pk).map_err(|e| {
            InboxOpError::Failed(format!(
                "invalid recipient device_pubkey for device_id={}: {e}",
                d.device_id
            ))
        })?;
        let cwt_bytes = B64.decode(d.device_cwt_b64.trim().as_bytes()).map_err(|e| {
            InboxOpError::Failed(format!(
                "invalid device_cwt_b64 for device_id={}: {e}",
                d.device_id
            ))
        })?;
        let _ = verify_device_cwt(&cwt_bytes, &recipient_root_pk, Some(&dev_pk), now_s).map_err(
            |e| {
                InboxOpError::Failed(format!(
                    "recipient device_id={} failed CWT verification: {e}",
                    d.device_id
                ))
            },
        )?;

        let cert_bytes = B64.decode(d.enc_cert_b64.trim().as_bytes()).map_err(|e| {
            InboxOpError::Failed(format!(
                "invalid enc_cert_b64 for device_id={}: {e}",
                d.device_id
            ))
        })?;
        let cert_claims = verify_enc_subkey_cert(
            &cert_bytes,
            recipient_aid_u64,
            d.device_id,
            &recipient_root_pk,
            &dev_pk,
            now_s,
        )
        .map_err(|e| {
            InboxOpError::Failed(format!(
                "recipient device_id={} failed enc_cert verification: {e}",
                d.device_id
            ))
        })?;
        let declared_enc_pk = decode_exact_32(&d.enc_pk_b64, "recipient enc_pk")
            .map_err(InboxOpError::Failed)?;
        if cert_claims.enc_pk != declared_enc_pk {
            return Err(InboxOpError::Failed(format!(
                "recipient device_id={} enc_pk disagrees with signed enc_cert",
                d.device_id
            )));
        }

        let target_did = DeviceId::new(d.device_id)
            .map_err(|e| InboxOpError::Failed(format!("invalid recipient device_id: {e}")))?;
        recipients.push(InboxRecipientDevice {
            device_id: target_did,
            enc_pk: cert_claims.enc_pk,
        });
    }

    if recipients.is_empty() {
        return Err(InboxOpError::Failed(format!(
            "recipient account_id={recipient_aid_u64} has no active inbox encryption devices (ask them to run `mp-outpost inbox init-key`)"
        )));
    }

    let mut msg_id = [0u8; 16];
    fill_random(&mut msg_id)
        .map_err(|e| InboxOpError::Failed(format!("CSPRNG failure generating msg_id: {e}")))?;
    let mut cek = Zeroizing::new([0u8; 32]);
    fill_random(&mut *cek)
        .map_err(|e| InboxOpError::Failed(format!("CSPRNG failure generating CEK: {e}")))?;
    let mut ephemeral_sks: Vec<[u8; 32]> = Vec::with_capacity(recipients.len());
    for _ in 0..recipients.len() {
        let mut eph = [0u8; 32];
        fill_random(&mut eph).map_err(|e| {
            InboxOpError::Failed(format!("CSPRNG failure generating ephemeral_sk: {e}"))
        })?;
        ephemeral_sks.push(eph);
    }

    let expires_at_ms_u64 = wall_now_ms().saturating_add(effective_ttl.saturating_mul(1_000));
    if expires_at_ms_u64 == 0 || expires_at_ms_u64 > MAX_SAFE_ID {
        return Err(InboxOpError::Failed(
            "computed expires_at_ms out of safe integer range".to_string(),
        ));
    }
    let expires_at_ms_i64 = i64::try_from(expires_at_ms_u64)
        .map_err(|_| InboxOpError::Failed("expires_at_ms overflow".to_string()))?;

    let sender_aid = AccountId::new(dev.account_id).map_err(|e| InboxOpError::Failed(e.to_string()))?;
    let sender_did = DeviceId::new(dev.device_id).map_err(|e| InboxOpError::Failed(e.to_string()))?;
    let recip_aid =
        AccountId::new(recipient_aid_u64).map_err(|e| InboxOpError::Failed(e.to_string()))?;

    let sealed_res = seal_inbox_drop(
        sender_aid,
        sender_did,
        &local_enc.enc_sk,
        recip_aid,
        &recipients,
        msg_id,
        expires_at_ms_i64,
        body.as_bytes(),
        &cek,
        &ephemeral_sks,
    );
    // Zeroize ephemeral scalars immediately after sealing.
    for sk in &mut ephemeral_sks {
        zeroize::Zeroize::zeroize(sk);
    }
    let sealed = sealed_res
        .map_err(|e| InboxOpError::Failed(format!("failed sealing Suite 1 inbox drop: {e}")))?;

    let wrapped_keys: Vec<WrappedDeviceKey> = sealed
        .wrapped_keys
        .iter()
        .map(|wk| WrappedDeviceKey {
            device_id: wk.target_device_id.get(),
            wrapped_key_b64: B64.encode(&wk.wrapped_key),
        })
        .collect();

    let post_req = PostInboxDropRequest {
        msg_id_b64: B64.encode(sealed.msg_id),
        suite: sealed.suite,
        sender_cwt_b64: B64.encode(&dev.device_cwt),
        sender_enc_cert_b64: local_enc.enc_cert_b64,
        ciphertext_b64: B64.encode(&sealed.ciphertext),
        wrapped_keys,
        expires_at_ms: expires_at_ms_u64,
    };

    client
        .post_inbox_drop(recipient_aid_u64, &post_req)
        .await
        .map_err(|e| InboxOpError::Failed(format!("POST /v1/inbox failed: {e}")))
}

struct InboxReadOutcome {
    drops: Vec<InboxDecryptedDrop>,
    skipped: Vec<(u64, String)>,
    ack_response: Option<AckInboxResponse>,
}

async fn resolve_sender_identity(
    client: &ControlClient,
    dev: &DeviceRecord,
    peers: &PeersStoreRecord,
    auth_hash: [u8; 8],
    sender_account_id: u64,
    cache: &mut HashMap<u64, Result<([u8; 32], String), String>>,
) -> Result<([u8; 32], String), String> {
    if let Some(cached) = cache.get(&sender_account_id) {
        return cached.clone();
    }

    let outcome: Result<([u8; 32], String), String> = async {
        // Check local peers.bin first so RevokedBlocked fails closed before any network call.
        let local_peer = peers
            .peers
            .iter()
            .find(|p| p.api_authority_hash == auth_hash && p.account_id == sender_account_id);
        if let Some(peer) = local_peer
            && peer.trust_state == TrustState::RevokedBlocked
        {
            return Err(format!(
                "sender account_id={sender_account_id} is RevokedBlocked in local peers.bin"
            ));
        }

        if sender_account_id == dev.account_id {
            return Ok((dev.root_pubkey, "self".to_string()));
        }

        let sender_aid = AccountId::new(sender_account_id).map_err(|e| e.to_string())?;
        let pub_acc = client
            .get_account(sender_aid)
            .await
            .map_err(|e| format!("failed fetching sender account {sender_account_id}: {e}"))?;
        let observed_root = decode_exact_32(&pub_acc.root_pubkey_b64, "sender root_pubkey")?;
        let _ = validate_ed25519_pubkey_strict(&observed_root)
            .map_err(|e| format!("invalid sender root_pubkey: {e}"))?;

        if let Some(peer) = local_peer
            && peer.root_pubkey != [0u8; 32]
            && peer.root_pubkey != observed_root
        {
            return Err(format!(
                "KeyMismatch for sender account_id={sender_account_id}: server root_pubkey disagrees with pinned peers.bin"
            ));
        }

        Ok((observed_root, pub_acc.handle))
    }
    .await;

    cache.insert(sender_account_id, outcome.clone());
    outcome
}

async fn inbox_read_core(
    state_dir_path: &Path,
    device_id_override: Option<u64>,
    ack: bool,
) -> Result<InboxReadOutcome, InboxOpError> {
    let device_id =
        resolve_active_device_id(state_dir_path, device_id_override).map_err(InboxOpError::Failed)?;
    let dev = load_device_record(state_dir_path, device_id).map_err(InboxOpError::Failed)?;
    let state_dir = open_state_dir(state_dir_path).map_err(InboxOpError::Failed)?;

    let (local_enc, peers) = {
        let _lock = lock_state(&state_dir).map_err(InboxOpError::Failed)?;
        let enc = load_local_enc_key(&state_dir, dev.device_id)
            .map_err(InboxOpError::Failed)?
            .ok_or_else(|| {
                InboxOpError::Failed(
                    "no local inbox encryption key found; run `mp-outpost inbox init-key` first"
                        .to_string(),
                )
            })?;
        let peers = load_peers_store(&state_dir).map_err(InboxOpError::Failed)?;
        (enc, peers)
    };

    let client = build_device_control_client(&dev).map_err(InboxOpError::Failed)?;
    let resp = client
        .get_inbox_drops()
        .await
        .map_err(|e| InboxOpError::Failed(format!("GET /v1/inbox failed: {e}")))?;

    let auth_hash = api_authority_hash(&dev.api_authority);
    let now_s = wall_now_secs();
    let my_aid = AccountId::new(dev.account_id).map_err(|e| InboxOpError::Failed(e.to_string()))?;
    let my_did = DeviceId::new(dev.device_id).map_err(|e| InboxOpError::Failed(e.to_string()))?;

    let mut sender_cache: HashMap<u64, Result<([u8; 32], String), String>> = HashMap::new();
    let mut decrypted = Vec::with_capacity(resp.drops.len());
    let mut skipped: Vec<(u64, String)> = Vec::new();
    let mut decrypted_ids: Vec<u64> = Vec::new();

    for item in resp.drops {
        let drop_id = item.drop_id;
        let process_res: Result<InboxDecryptedDrop, String> = async {
            if item.suite != INBOX_SUITE_1 {
                return Err(format!("unsupported suite {}", item.suite));
            }
            let (sender_root_pk, sender_handle) = resolve_sender_identity(
                &client,
                &dev,
                &peers,
                auth_hash,
                item.sender_account_id,
                &mut sender_cache,
            )
            .await?;

            let sender_cwt = B64
                .decode(item.sender_cwt_b64.trim().as_bytes())
                .map_err(|e| format!("invalid sender_cwt_b64: {e}"))?;
            let cwt_claims = verify_device_cwt(&sender_cwt, &sender_root_pk, None, now_s)
                .map_err(|e| format!("sender CWT verification failed: {e}"))?;

            let sender_enc_cert = B64
                .decode(item.sender_enc_cert_b64.trim().as_bytes())
                .map_err(|e| format!("invalid sender_enc_cert_b64: {e}"))?;
            let cert_claims = verify_enc_subkey_cert(
                &sender_enc_cert,
                item.sender_account_id,
                item.sender_device_id,
                &sender_root_pk,
                &cwt_claims.device_pubkey,
                now_s,
            )
            .map_err(|e| format!("sender enc_cert verification failed: {e}"))?;

            let msg_id = decode_exact_16(&item.msg_id_b64, "msg_id")?;
            let ciphertext = B64
                .decode(item.ciphertext_b64.trim().as_bytes())
                .map_err(|e| format!("invalid ciphertext_b64: {e}"))?;
            let wrapped_key = B64
                .decode(item.wrapped_key_b64.trim().as_bytes())
                .map_err(|e| format!("invalid wrapped_key_b64: {e}"))?;

            let sender_aid = AccountId::new(item.sender_account_id).map_err(|e| e.to_string())?;
            let sender_did = DeviceId::new(item.sender_device_id).map_err(|e| e.to_string())?;
            let expires_at_ms_i64 = i64::try_from(item.expires_at_ms)
                .map_err(|_| "drop expires_at_ms overflow".to_string())?;

            let pt = open_inbox_drop(
                item.suite,
                sender_aid,
                sender_did,
                &cert_claims.enc_pk,
                my_aid,
                my_did,
                &local_enc.enc_sk,
                &msg_id,
                expires_at_ms_i64,
                &ciphertext,
                &wrapped_key,
            )
            .map_err(|e| format!("Suite 1 decryption failed: {e}"))?;

            let body = String::from_utf8(pt)
                .map_err(|_| "decrypted inbox payload is not valid UTF-8".to_string())?;
            let safety_number = compute_safety_number(item.sender_account_id, &sender_root_pk);

            Ok(InboxDecryptedDrop {
                drop_id,
                sender_account_id: item.sender_account_id,
                sender_device_id: item.sender_device_id,
                sender_handle,
                safety_number,
                created_at_ms: item.created_at_ms,
                expires_at_ms: item.expires_at_ms,
                body,
            })
        }
        .await;

        match process_res {
            Ok(drop_rec) => {
                decrypted_ids.push(drop_rec.drop_id);
                decrypted.push(drop_rec);
            }
            Err(reason) => {
                skipped.push((drop_id, reason));
            }
        }
    }

    let ack_response = if ack && !decrypted_ids.is_empty() {
        let acked = client
            .ack_inbox_drops(&decrypted_ids)
            .await
            .map_err(|e| InboxOpError::Failed(format!("POST /v1/inbox/ack failed: {e}")))?;
        Some(acked)
    } else {
        None
    };

    Ok(InboxReadOutcome {
        drops: decrypted,
        skipped,
        ack_response,
    })
}

async fn inbox_ack_core(
    state_dir_path: &Path,
    device_id_override: Option<u64>,
    drop_ids: &[u64],
) -> Result<AckInboxResponse, InboxOpError> {
    if drop_ids.is_empty() || drop_ids.len() > MAX_INBOX_PENDING_DROPS {
        return Err(InboxOpError::InvalidParams(format!(
            "drop_ids must contain 1..={MAX_INBOX_PENDING_DROPS} entries"
        )));
    }
    for &id in drop_ids {
        if id == 0 || id > MAX_SAFE_ID {
            return Err(InboxOpError::InvalidParams(format!(
                "drop_id ({id}) must be in 1..={MAX_SAFE_ID}"
            )));
        }
    }
    let device_id =
        resolve_active_device_id(state_dir_path, device_id_override).map_err(InboxOpError::Failed)?;
    let dev = load_device_record(state_dir_path, device_id).map_err(InboxOpError::Failed)?;
    let client = build_device_control_client(&dev).map_err(InboxOpError::Failed)?;
    client
        .ack_inbox_drops(drop_ids)
        .await
        .map_err(|e: ControlError| InboxOpError::Failed(format!("POST /v1/inbox/ack failed: {e}")))
}

// ---------------------------------------------------------------------------
// MCP Bridge Helpers
// ---------------------------------------------------------------------------

pub async fn mcp_inbox_send(
    state_dir: &Path,
    device_id_override: Option<u64>,
    args: InboxSendArgs,
) -> Result<InboxSendResult, BackendError> {
    let resp = inbox_send_core(
        state_dir,
        device_id_override,
        &args.recipient,
        &args.body,
        args.ttl_secs,
    )
    .await
    .map_err(InboxOpError::into_backend_error)?;
    Ok(InboxSendResult {
        drop_id: resp.drop_id,
        delivered_devices: resp.delivered_devices,
        idempotent: resp.idempotent,
    })
}

pub async fn mcp_inbox_read(
    state_dir: &Path,
    device_id_override: Option<u64>,
    args: InboxReadArgs,
) -> Result<InboxReadResult, BackendError> {
    let outcome = inbox_read_core(state_dir, device_id_override, args.ack)
        .await
        .map_err(InboxOpError::into_backend_error)?;
    Ok(InboxReadResult {
        drops: outcome.drops,
    })
}

pub async fn mcp_inbox_ack(
    state_dir: &Path,
    device_id_override: Option<u64>,
    args: InboxAckArgs,
) -> Result<InboxAckResult, BackendError> {
    let resp = inbox_ack_core(state_dir, device_id_override, &args.drop_ids)
        .await
        .map_err(InboxOpError::into_backend_error)?;
    Ok(InboxAckResult {
        acked: resp.acked,
        pruned_drops: resp.pruned_drops,
    })
}

// ---------------------------------------------------------------------------
// CLI Subcommand Dispatcher (`mp-outpost inbox init-key|send|read|ack`)
// ---------------------------------------------------------------------------

fn print_json(val: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(val) {
        println!("{s}");
    }
}

fn csprng_nonce_u64() -> Result<u64, String> {
    let mut b = [0u8; 8];
    fill_random(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(u64::from_le_bytes(b))
}

fn next_arg<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Result<&'a str, String> {
    let val = args
        .get(*idx + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))?;
    *idx += 2;
    Ok(val)
}

pub async fn run_inbox_cmd(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mp-outpost inbox <init-key|send|read|ack> ...".to_string());
    };
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        "init-key" => cmd_inbox_init_key(opts, rest).await,
        "send" => cmd_inbox_send(opts, rest).await,
        "read" => cmd_inbox_read(opts, rest).await,
        "ack" => cmd_inbox_ack(opts, rest).await,
        other => Err(format!(
            "unknown inbox subcommand '{other}' (expected: init-key|send|read|ack)"
        )),
    }
}

async fn cmd_inbox_init_key(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut force = false;
    let mut json_out = opts.json;
    for a in args {
        match a.as_str() {
            "--force" => force = true,
            "--json" => json_out = true,
            other => {
                return Err(format!("unknown argument to `inbox init-key`: {other}"));
            }
        }
    }

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let device_id = resolve_active_device_id(&state_dir_path, opts.device_id)?;
    let dev = load_device_record(&state_dir_path, device_id)?;
    let state_dir = open_state_dir(&state_dir_path)?;
    let client = build_device_control_client(&dev)?;

    let rec = ensure_or_rotate_device_enc_key(&state_dir, &dev, &client, force).await?;
    let enc_pk_b64 = B64.encode(rec.enc_pk);

    if json_out {
        print_json(&json!({
            "account_id": dev.account_id,
            "device_id": dev.device_id,
            "enc_pk_b64": enc_pk_b64,
            "enc_cert_exp_s": rec.enc_cert_exp_s,
            "rotated": force,
        }));
    } else {
        println!(
            "Inbox X25519 encryption key active for device_id={} (enc_pk={}, exp_s={})",
            dev.device_id, enc_pk_b64, rec.enc_cert_exp_s
        );
    }
    Ok(())
}

async fn cmd_inbox_send(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut recipient: Option<String> = None;
    let mut message: Option<String> = None;
    let mut read_stdin = false;
    let mut ttl_secs: Option<u64> = None;
    let mut json_out = opts.json;

    let mut i = 0usize;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--stdin" => {
                read_stdin = true;
                i += 1;
            }
            "--ttl-secs" => {
                let raw = next_arg(args, &mut i, "--ttl-secs")?;
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --ttl-secs '{raw}'"))?;
                if !(INBOX_MIN_TTL_SECS..=INBOX_MAX_TTL_SECS).contains(&v) {
                    return Err(format!(
                        "--ttl-secs must be in {INBOX_MIN_TTL_SECS}..={INBOX_MAX_TTL_SECS}"
                    ));
                }
                ttl_secs = Some(v);
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown argument to `inbox send`: {other}"));
            }
            positional => {
                if recipient.is_none() {
                    recipient = Some(positional.to_string());
                } else if message.is_none() {
                    message = Some(positional.to_string());
                } else {
                    return Err(format!(
                        "unexpected extra positional argument to `inbox send`: {positional}"
                    ));
                }
                i += 1;
            }
        }
    }

    let recipient = recipient.ok_or_else(|| {
        "usage: mp-outpost inbox send <@handle|account_id> [<message>] [--stdin] [--ttl-secs <300..604800>] [--json]"
            .to_string()
    })?;

    let body = if read_stdin {
        if message.is_some() {
            return Err("specify either a message argument or --stdin, not both".to_string());
        }
        let mut buf = Vec::new();
        let limit = (INBOX_MAX_PLAINTEXT_BYTES as u64).saturating_add(1);
        io::stdin()
            .take(limit)
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed reading stdin: {e}"))?;
        if buf.len() > INBOX_MAX_PLAINTEXT_BYTES {
            return Err(format!(
                "stdin message exceeds max {INBOX_MAX_PLAINTEXT_BYTES} bytes"
            ));
        }
        String::from_utf8(buf).map_err(|_| "stdin message must be valid UTF-8".to_string())?
    } else {
        message.ok_or_else(|| {
            "inbox send requires <message> or --stdin".to_string()
        })?
    };

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let resp = inbox_send_core(&state_dir_path, opts.device_id, &recipient, &body, ttl_secs)
        .await
        .map_err(InboxOpError::into_cli_string)?;

    if json_out {
        print_json(&json!({
            "drop_id": resp.drop_id,
            "delivered_devices": resp.delivered_devices,
            "idempotent": resp.idempotent,
        }));
    } else {
        println!(
            "Sent E2EE dead-drop drop_id={} to {} (delivered_devices={}, idempotent={})",
            resp.drop_id,
            sanitize_single_line(&recipient),
            resp.delivered_devices,
            resp.idempotent
        );
    }
    Ok(())
}

async fn cmd_inbox_read(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut ack = false;
    let mut json_out = opts.json;
    for a in args {
        match a.as_str() {
            "--ack" => ack = true,
            "--json" => json_out = true,
            other => {
                return Err(format!("unknown argument to `inbox read`: {other}"));
            }
        }
    }

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let outcome = inbox_read_core(&state_dir_path, opts.device_id, ack)
        .await
        .map_err(InboxOpError::into_cli_string)?;
    let nonce = csprng_nonce_u64()?;
    let nonce_hex = format!("{nonce:016x}");

    if json_out {
        let drops_json: Vec<Value> = outcome
            .drops
            .iter()
            .map(|d| {
                json!({
                    "drop_id": d.drop_id,
                    "untrusted_remote": true,
                    "sender_account_id": d.sender_account_id,
                    "sender_device_id": d.sender_device_id,
                    "sender_handle": sanitize_single_line(&d.sender_handle),
                    "safety_number": sanitize_single_line(&d.safety_number),
                    "created_at_ms": d.created_at_ms,
                    "expires_at_ms": d.expires_at_ms,
                    "body": sanitize_peer_text(&d.body),
                    "fenced_body": fence_peer_text(&d.body, nonce),
                })
            })
            .collect();
        let skipped_json: Vec<Value> = outcome
            .skipped
            .iter()
            .map(|(id, reason)| {
                json!({
                    "drop_id": id,
                    "reason": sanitize_single_line(reason),
                })
            })
            .collect();
        let ack_json = outcome.ack_response.as_ref().map(|a| {
            json!({
                "acked": a.acked,
                "pruned_drops": a.pruned_drops,
            })
        });
        print_json(&json!({
            "fence_nonce": nonce_hex,
            "drops": drops_json,
            "skipped": skipped_json,
            "ack": ack_json,
        }));
    } else {
        for (id, reason) in &outcome.skipped {
            eprintln!(
                "warning: skipped inbox drop_id={id}: {}",
                sanitize_single_line(reason)
            );
        }
        if outcome.drops.is_empty() {
            println!("No pending inbox drops.");
        } else {
            for d in &outcome.drops {
                let fenced = fence_peer_text(&d.body, nonce);
                println!(
                    "[drop_id={} untrusted_remote=true sender_account_id={} sender_device_id={} sender_handle={} safety_number={} created_at_ms={} expires_at_ms={}]\n{}",
                    d.drop_id,
                    d.sender_account_id,
                    d.sender_device_id,
                    sanitize_single_line(&d.sender_handle),
                    sanitize_single_line(&d.safety_number),
                    d.created_at_ms,
                    d.expires_at_ms,
                    fenced
                );
            }
        }
        if let Some(a) = outcome.ack_response {
            println!(
                "Acknowledged {} drop(s) (pruned_drops={}).",
                a.acked, a.pruned_drops
            );
        }
    }
    Ok(())
}

async fn cmd_inbox_ack(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut drop_ids: Vec<u64> = Vec::new();
    let mut json_out = opts.json;
    for a in args {
        match a.as_str() {
            "--json" => json_out = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown argument to `inbox ack`: {other}"));
            }
            raw_id => {
                let id = raw_id
                    .parse::<u64>()
                    .map_err(|_| format!("invalid drop_id '{raw_id}'"))?;
                if id == 0 || id > MAX_SAFE_ID {
                    return Err(format!("drop_id must be in 1..={MAX_SAFE_ID}"));
                }
                drop_ids.push(id);
            }
        }
    }

    if drop_ids.is_empty() {
        return Err("usage: mp-outpost inbox ack <drop_id...> [--json]".to_string());
    }

    let state_dir_path = resolve_effective_state_dir(opts.state_dir.as_deref())?;
    let resp = inbox_ack_core(&state_dir_path, opts.device_id, &drop_ids)
        .await
        .map_err(InboxOpError::into_cli_string)?;

    if json_out {
        print_json(&json!({
            "acked": resp.acked,
            "pruned_drops": resp.pruned_drops,
        }));
    } else {
        println!(
            "Acknowledged {} drop(s) (pruned_drops={}).",
            resp.acked, resp.pruned_drops
        );
    }
    Ok(())
}
