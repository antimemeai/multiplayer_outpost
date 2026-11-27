//! Encrypted AES-256-GCM binary local MLS store (`MPM1`, zero JSON, zero `unsafe`).
//!
//! Persists per-room MLS state atomically under `StateLock` BEFORE any WebSocket transmit:
//! - Encrypted OpenMLS `MpCryptoProvider` binary storage snapshot
//! - Plaintext outbox for same-epoch exact-byte retries & `409 mls_epoch_stale` requeues
//! - Bounded `(group_id, auth_device_id, inner_msg_id)` deduplication ring
//! - Locally persisted `PinnedAccountRoot` records
//! - Crash-safe single-use `KeyPackage` bundles & idempotent `Welcome` receipts
//!
//! Outer container format (`MPM1`):
//! `magic[4] || ver_le16(1) || flags_le16(0) || device_id_le64 || party_id_le64 || group_id[24] || nonce[12] || ct_and_tag[N] || crc32c[4]`
//!
//! AES-256-GCM AAD binds `(magic, ver, flags, device_id, party_id, group_id)` so an encrypted
//! snapshot cannot be transplanted across devices, parties, or group incarnations.

use core::fmt;
use std::collections::VecDeque;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use mp_mls::{CustodyMode, MP_GROUP_ID_LEN, PinnedAccountRoot};
use mp_protocol::MAX_SAFE_ID;
use ring::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

use crate::crc32c::crc32c;

pub const MLS_STORE_MAGIC: [u8; 4] = *b"MPM1";
pub const MLS_STORE_VERSION: u16 = 1;
pub const MLS_STORE_HEADER_LEN: usize = 4 + 2 + 2 + 8 + 8 + MP_GROUP_ID_LEN; // 48 bytes
pub const MLS_STORE_NONCE_LEN: usize = 12;
pub const MLS_STORE_GCM_TAG_LEN: usize = 16;
pub const MLS_STORE_CRC_LEN: usize = 4;
pub const MLS_STORE_MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MLS_DEDUP_ENTRIES: usize = 1024;
pub const MAX_MLS_OUTBOX_ENTRIES: usize = 256;
pub const MAX_MLS_PINNED_ROOTS: usize = 128;
pub const MAX_MLS_PENDING_KPS: usize = 16;

const MLS_STORE_KEY_CONTEXT: &str = "mp-outpost-mls-store-aes256gcm-v1";
const MAX_BLOB_BYTES: usize = 2 * 1024 * 1024;
const MAX_SMALL_STR: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsStoreError {
    Truncated,
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    NonZeroFlags,
    CrcMismatch,
    AadBindingMismatch,
    DecryptionFailed,
    EncryptionFailed,
    RandomFailure,
    InvalidId,
    InvalidEnum,
    InvalidUtf8,
    FieldTooLarge,
    TooManyEntries,
}

impl fmt::Display for MlsStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for MlsStoreError {}

/// Derives a deterministic 32-byte AES-256-GCM encryption key for `<state_dir>/mls/d<13hex>/`
/// from the enrolled device secret and `device_id` using BLAKE3 key derivation.
pub fn derive_mls_store_key(device_secret: &[u8; 32], device_id: u64) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new([0u8; 40]);
    if let Some(dst) = input.get_mut(0..32) {
        dst.copy_from_slice(device_secret);
    }
    if let Some(dst) = input.get_mut(32..40) {
        dst.copy_from_slice(&device_id.to_le_bytes());
    }
    Zeroizing::new(blake3::derive_key(MLS_STORE_KEY_CONTEXT, input.as_slice()))
}

/// Persisted outbound application message awaiting `PartyDO` acknowledgement (§7.2).
///
/// Retained in encrypted local outbox storage until `PartyDO` acks delivery:
/// - Same-epoch retries resend exact `wire_bytes` without advancing the MLS ratchet.
/// - `409 mls_epoch_stale` catches up to `E+1` and re-encrypts `plaintext` keeping exact `inner_msg_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedOutboxEntry {
    pub inner_msg_id: [u8; 16],
    pub client_msg_id: String,
    pub msg_class: u8,
    pub target_selector: String,
    pub plaintext: Vec<u8>,
    pub sent_epoch: u64,
    pub device_epoch_seq: u64,
    pub wire_bytes: Vec<u8>,
}

/// Persisted `(group_id, auth_device_id, inner_msg_id)` deduplication entry (§7.1 / §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlsDedupEntry {
    pub group_id: [u8; MP_GROUP_ID_LEN],
    pub auth_device_id: u64,
    pub inner_msg_id: [u8; 16],
}

/// Bounded FIFO deduplication ring keyed by `(group_id, auth_device_id, inner_msg_id)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MlsDedupRing {
    entries: VecDeque<MlsDedupEntry>,
}

impl MlsDedupRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_vec(entries: Vec<MlsDedupEntry>) -> Self {
        let mut ring = Self::new();
        for entry in entries {
            let _ = ring.check_and_insert(entry.group_id, entry.auth_device_id, entry.inner_msg_id);
        }
        ring
    }

    pub fn to_vec(&self) -> Vec<MlsDedupEntry> {
        self.entries.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(
        &self,
        group_id: [u8; MP_GROUP_ID_LEN],
        auth_device_id: u64,
        inner_msg_id: [u8; 16],
    ) -> bool {
        let needle = MlsDedupEntry {
            group_id,
            auth_device_id,
            inner_msg_id,
        };
        self.entries.iter().any(|e| *e == needle)
    }

    /// Inserts `(group_id, auth_device_id, inner_msg_id)` if unseen.
    /// Returns `true` iff this tuple was ALREADY seen (i.e. duplicate!).
    pub fn check_and_insert(
        &mut self,
        group_id: [u8; MP_GROUP_ID_LEN],
        auth_device_id: u64,
        inner_msg_id: [u8; 16],
    ) -> bool {
        let entry = MlsDedupEntry {
            group_id,
            auth_device_id,
            inner_msg_id,
        };
        if self.entries.iter().any(|e| *e == entry) {
            return true;
        }
        while self.entries.len() >= MAX_MLS_DEDUP_ENTRIES {
            let _ = self.entries.pop_front();
        }
        self.entries.push_back(entry);
        false
    }
}

/// Persisted `PinnedAccountRoot` record (1-to-1 with `mp_mls::PinnedAccountRoot`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistedPinnedRoot {
    pub account_id: u64,
    pub root_pubkey: [u8; 32],
    pub root_gen: u32,
    pub custody_mode: u8,
    pub verified_oob: bool,
    pub pending_oob_reverify: bool,
}

impl From<PinnedAccountRoot> for PersistedPinnedRoot {
    fn from(p: PinnedAccountRoot) -> Self {
        Self {
            account_id: p.account_id,
            root_pubkey: p.root_pubkey,
            root_gen: p.root_gen,
            custody_mode: p.custody_mode as u8,
            verified_oob: p.verified_oob,
            pending_oob_reverify: p.pending_oob_reverify,
        }
    }
}

impl TryFrom<PersistedPinnedRoot> for PinnedAccountRoot {
    type Error = MlsStoreError;

    fn try_from(p: PersistedPinnedRoot) -> Result<Self, Self::Error> {
        let custody_mode = CustodyMode::from_u8(p.custody_mode).map_err(|_| MlsStoreError::InvalidEnum)?;
        Ok(Self {
            account_id: p.account_id,
            root_pubkey: p.root_pubkey,
            root_gen: p.root_gen,
            custody_mode,
            verified_oob: p.verified_oob,
            pending_oob_reverify: p.pending_oob_reverify,
        })
    }
}

/// Crash-safe single-use `KeyPackage` private bundle persisted BEFORE upload (§4.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedKeyPackage {
    pub kp_ref: [u8; 32],
    pub kp_wire_bytes: Vec<u8>,
    pub provider_blob: Vec<u8>,
    pub created_at_s: u64,
}

/// Durable `Welcome` receipt persisted in the same atomic write as Welcome installation (§4.2.4)
/// so `POST /v1/parties/:id/mls/welcome/ack` can be retried idempotently after a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedWelcomeReceipt {
    pub party_id: u64,
    pub group_id: [u8; MP_GROUP_ID_LEN],
    pub target_epoch: u64,
    pub kp_ref: [u8; 32],
    pub acked: bool,
}

/// Plaintext payload encrypted inside an `MPM1` AES-256-GCM room snapshot file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MlsRoomSnapshotPlain {
    pub mls_storage_blob: Vec<u8>,
    pub epoch: u64,
    pub device_epoch_seq: u64,
    pub total_sent_frames_in_epoch: u64,
    pub cloned_device_key_suspected: bool,
    pub local_cache_wiped: bool,
    pub inviter_unconfirmed: bool,
    pub outbox: Vec<PersistedOutboxEntry>,
    pub dedup_ring: Vec<MlsDedupEntry>,
    pub pinned_roots: Vec<PersistedPinnedRoot>,
    pub pending_key_packages: Vec<PersistedKeyPackage>,
    pub device_binding_236b: Vec<u8>,
    pub device_list_blob: Vec<u8>,
    pub welcome_receipt: Option<PersistedWelcomeReceipt>,
}

impl MlsRoomSnapshotPlain {
    pub fn upsert_outbox_entry(&mut self, entry: PersistedOutboxEntry) -> Result<(), MlsStoreError> {
        if let Some(existing) = self
            .outbox
            .iter_mut()
            .find(|e| e.inner_msg_id == entry.inner_msg_id || e.client_msg_id == entry.client_msg_id)
        {
            *existing = entry;
            return Ok(());
        }
        if self.outbox.len() >= MAX_MLS_OUTBOX_ENTRIES {
            return Err(MlsStoreError::TooManyEntries);
        }
        self.outbox.push(entry);
        Ok(())
    }

    pub fn remove_outbox_by_client_msg_id(&mut self, client_msg_id: &str) -> bool {
        let before = self.outbox.len();
        self.outbox.retain(|e| e.client_msg_id != client_msg_id);
        self.outbox.len() != before
    }

    pub fn find_outbox_by_client_msg_id(&self, client_msg_id: &str) -> Option<&PersistedOutboxEntry> {
        self.outbox.iter().find(|e| e.client_msg_id == client_msg_id)
    }

    pub fn encode_plain(&self) -> Result<Vec<u8>, MlsStoreError> {
        if self.mls_storage_blob.len() > MAX_BLOB_BYTES
            || self.device_binding_236b.len() > 1024
            || self.device_list_blob.len() > 4096
        {
            return Err(MlsStoreError::FieldTooLarge);
        }
        if self.outbox.len() > MAX_MLS_OUTBOX_ENTRIES
            || self.dedup_ring.len() > MAX_MLS_DEDUP_ENTRIES
            || self.pinned_roots.len() > MAX_MLS_PINNED_ROOTS
            || self.pending_key_packages.len() > MAX_MLS_PENDING_KPS
        {
            return Err(MlsStoreError::TooManyEntries);
        }

        let mut w = BinWriter::new();
        w.u8(1); // inner plain schema version
        w.bytes_u32(&self.mls_storage_blob, MAX_BLOB_BYTES)?;
        w.u64(self.epoch);
        w.u64(self.device_epoch_seq);
        w.u64(self.total_sent_frames_in_epoch);
        w.bool(self.cloned_device_key_suspected);
        w.bool(self.local_cache_wiped);
        w.bool(self.inviter_unconfirmed);

        w.u16(u16::try_from(self.outbox.len()).map_err(|_| MlsStoreError::TooManyEntries)?);
        for entry in &self.outbox {
            w.fixed(&entry.inner_msg_id);
            w.str_u16(&entry.client_msg_id, MAX_SMALL_STR)?;
            w.u8(entry.msg_class);
            w.str_u16(&entry.target_selector, MAX_SMALL_STR)?;
            w.bytes_u32(&entry.plaintext, 64 * 1024)?;
            w.u64(entry.sent_epoch);
            w.u64(entry.device_epoch_seq);
            w.bytes_u32(&entry.wire_bytes, 64 * 1024)?;
        }

        w.u16(u16::try_from(self.dedup_ring.len()).map_err(|_| MlsStoreError::TooManyEntries)?);
        for d in &self.dedup_ring {
            w.fixed(&d.group_id);
            w.u64(d.auth_device_id);
            w.fixed(&d.inner_msg_id);
        }

        w.u16(u16::try_from(self.pinned_roots.len()).map_err(|_| MlsStoreError::TooManyEntries)?);
        for p in &self.pinned_roots {
            w.u64(p.account_id);
            w.fixed(&p.root_pubkey);
            w.u32(p.root_gen);
            w.u8(p.custody_mode);
            w.bool(p.verified_oob);
            w.bool(p.pending_oob_reverify);
        }

        w.u16(
            u16::try_from(self.pending_key_packages.len())
                .map_err(|_| MlsStoreError::TooManyEntries)?,
        );
        for kp in &self.pending_key_packages {
            w.fixed(&kp.kp_ref);
            w.bytes_u32(&kp.kp_wire_bytes, 64 * 1024)?;
            w.bytes_u32(&kp.provider_blob, MAX_BLOB_BYTES)?;
            w.u64(kp.created_at_s);
        }

        w.bytes_u32(&self.device_binding_236b, 1024)?;
        w.bytes_u32(&self.device_list_blob, 4096)?;

        match &self.welcome_receipt {
            Some(r) => {
                w.bool(true);
                w.u64(r.party_id);
                w.fixed(&r.group_id);
                w.u64(r.target_epoch);
                w.fixed(&r.kp_ref);
                w.bool(r.acked);
            }
            None => w.bool(false),
        }

        Ok(w.finish())
    }

    pub fn decode_plain(bytes: &[u8]) -> Result<Self, MlsStoreError> {
        let mut r = BinReader::new(bytes);
        let ver = r.u8()?;
        if ver != 1 {
            return Err(MlsStoreError::UnsupportedVersion);
        }
        let mls_storage_blob = r.bytes_u32(MAX_BLOB_BYTES)?;
        let epoch = r.u64()?;
        let device_epoch_seq = r.u64()?;
        let total_sent_frames_in_epoch = r.u64()?;
        let cloned_device_key_suspected = r.bool()?;
        let local_cache_wiped = r.bool()?;
        let inviter_unconfirmed = r.bool()?;

        let outbox_len = usize::from(r.u16()?);
        if outbox_len > MAX_MLS_OUTBOX_ENTRIES {
            return Err(MlsStoreError::TooManyEntries);
        }
        let mut outbox = Vec::with_capacity(outbox_len);
        for _ in 0..outbox_len {
            outbox.push(PersistedOutboxEntry {
                inner_msg_id: r.fixed::<16>()?,
                client_msg_id: r.str_u16(MAX_SMALL_STR)?,
                msg_class: r.u8()?,
                target_selector: r.str_u16(MAX_SMALL_STR)?,
                plaintext: r.bytes_u32(64 * 1024)?,
                sent_epoch: r.u64()?,
                device_epoch_seq: r.u64()?,
                wire_bytes: r.bytes_u32(64 * 1024)?,
            });
        }

        let dedup_len = usize::from(r.u16()?);
        if dedup_len > MAX_MLS_DEDUP_ENTRIES {
            return Err(MlsStoreError::TooManyEntries);
        }
        let mut dedup_ring = Vec::with_capacity(dedup_len);
        for _ in 0..dedup_len {
            dedup_ring.push(MlsDedupEntry {
                group_id: r.fixed::<MP_GROUP_ID_LEN>()?,
                auth_device_id: r.u64()?,
                inner_msg_id: r.fixed::<16>()?,
            });
        }

        let pins_len = usize::from(r.u16()?);
        if pins_len > MAX_MLS_PINNED_ROOTS {
            return Err(MlsStoreError::TooManyEntries);
        }
        let mut pinned_roots = Vec::with_capacity(pins_len);
        for _ in 0..pins_len {
            pinned_roots.push(PersistedPinnedRoot {
                account_id: r.u64()?,
                root_pubkey: r.fixed::<32>()?,
                root_gen: r.u32()?,
                custody_mode: r.u8()?,
                verified_oob: r.bool()?,
                pending_oob_reverify: r.bool()?,
            });
        }

        let kp_len = usize::from(r.u16()?);
        if kp_len > MAX_MLS_PENDING_KPS {
            return Err(MlsStoreError::TooManyEntries);
        }
        let mut pending_key_packages = Vec::with_capacity(kp_len);
        for _ in 0..kp_len {
            pending_key_packages.push(PersistedKeyPackage {
                kp_ref: r.fixed::<32>()?,
                kp_wire_bytes: r.bytes_u32(64 * 1024)?,
                provider_blob: r.bytes_u32(MAX_BLOB_BYTES)?,
                created_at_s: r.u64()?,
            });
        }

        let device_binding_236b = r.bytes_u32(1024)?;
        let device_list_blob = r.bytes_u32(4096)?;

        let welcome_receipt = if r.bool()? {
            Some(PersistedWelcomeReceipt {
                party_id: r.u64()?,
                group_id: r.fixed::<MP_GROUP_ID_LEN>()?,
                target_epoch: r.u64()?,
                kp_ref: r.fixed::<32>()?,
                acked: r.bool()?,
            })
        } else {
            None
        };

        r.finish()?;
        Ok(Self {
            mls_storage_blob,
            epoch,
            device_epoch_seq,
            total_sent_frames_in_epoch,
            cloned_device_key_suspected,
            local_cache_wiped,
            inviter_unconfirmed,
            outbox,
            dedup_ring,
            pinned_roots,
            pending_key_packages,
            device_binding_236b,
            device_list_blob,
            welcome_receipt,
        })
    }
}

fn check_safe_id(id: u64) -> Result<(), MlsStoreError> {
    if id == 0 || id > MAX_SAFE_ID {
        return Err(MlsStoreError::InvalidId);
    }
    Ok(())
}

fn build_aad_header(
    device_id: u64,
    party_id: u64,
    group_id: &[u8; MP_GROUP_ID_LEN],
) -> Result<[u8; MLS_STORE_HEADER_LEN], MlsStoreError> {
    check_safe_id(device_id)?;
    check_safe_id(party_id)?;
    let mut hdr = [0u8; MLS_STORE_HEADER_LEN];
    if let Some(dst) = hdr.get_mut(0..4) {
        dst.copy_from_slice(&MLS_STORE_MAGIC);
    }
    if let Some(dst) = hdr.get_mut(4..6) {
        dst.copy_from_slice(&MLS_STORE_VERSION.to_le_bytes());
    }
    if let Some(dst) = hdr.get_mut(6..8) {
        dst.copy_from_slice(&0u16.to_le_bytes());
    }
    if let Some(dst) = hdr.get_mut(8..16) {
        dst.copy_from_slice(&device_id.to_le_bytes());
    }
    if let Some(dst) = hdr.get_mut(16..24) {
        dst.copy_from_slice(&party_id.to_le_bytes());
    }
    if let Some(dst) = hdr.get_mut(24..48) {
        dst.copy_from_slice(group_id);
    }
    Ok(hdr)
}

/// Encrypts `snapshot` with AES-256-GCM using an explicit 96-bit `nonce` and AAD bound to
/// `(magic, ver, flags, device_id, party_id, group_id)`, appending a CRC32C trailer.
pub fn encrypt_mls_snapshot(
    store_key: &[u8; 32],
    device_id: u64,
    party_id: u64,
    group_id: &[u8; MP_GROUP_ID_LEN],
    snapshot: &MlsRoomSnapshotPlain,
    nonce: [u8; MLS_STORE_NONCE_LEN],
) -> Result<Vec<u8>, MlsStoreError> {
    let header = build_aad_header(device_id, party_id, group_id)?;
    let plaintext = Zeroizing::new(snapshot.encode_plain()?);
    let cipher = Aes256Gcm::new_from_slice(store_key).map_err(|_| MlsStoreError::EncryptionFailed)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| MlsStoreError::EncryptionFailed)?;

    let total_len = MLS_STORE_HEADER_LEN
        .saturating_add(MLS_STORE_NONCE_LEN)
        .saturating_add(ct.len())
        .saturating_add(MLS_STORE_CRC_LEN);
    if total_len > MLS_STORE_MAX_FILE_BYTES {
        return Err(MlsStoreError::FieldTooLarge);
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    let sum = crc32c(&out);
    out.extend_from_slice(&sum.to_le_bytes());
    Ok(out)
}

/// Encrypts `snapshot` with a fresh OS CSPRNG 96-bit nonce via `ring::rand::SystemRandom`.
pub fn encrypt_mls_snapshot_random(
    store_key: &[u8; 32],
    device_id: u64,
    party_id: u64,
    group_id: &[u8; MP_GROUP_ID_LEN],
    snapshot: &MlsRoomSnapshotPlain,
) -> Result<Vec<u8>, MlsStoreError> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; MLS_STORE_NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|_| MlsStoreError::RandomFailure)?;
    encrypt_mls_snapshot(store_key, device_id, party_id, group_id, snapshot, nonce)
}

/// Verifies CRC32C, header bindings (`device_id`, `party_id`, `group_id`), AES-256-GCM tag,
/// and decodes the canonical binary `MlsRoomSnapshotPlain` fail-closed.
pub fn decrypt_mls_snapshot(
    store_key: &[u8; 32],
    expected_device_id: u64,
    expected_party_id: u64,
    expected_group_id: &[u8; MP_GROUP_ID_LEN],
    bytes: &[u8],
) -> Result<MlsRoomSnapshotPlain, MlsStoreError> {
    let min_len = MLS_STORE_HEADER_LEN + MLS_STORE_NONCE_LEN + MLS_STORE_GCM_TAG_LEN + MLS_STORE_CRC_LEN;
    if bytes.len() < min_len {
        return Err(MlsStoreError::Truncated);
    }
    if bytes.len() > MLS_STORE_MAX_FILE_BYTES {
        return Err(MlsStoreError::FieldTooLarge);
    }

    let body_len = bytes
        .len()
        .checked_sub(MLS_STORE_CRC_LEN)
        .ok_or(MlsStoreError::Truncated)?;
    let (content, crc_slice) = bytes.split_at(body_len);
    let expected_crc_arr: [u8; 4] = crc_slice.try_into().map_err(|_| MlsStoreError::Truncated)?;
    if crc32c(content) != u32::from_le_bytes(expected_crc_arr) {
        return Err(MlsStoreError::CrcMismatch);
    }

    let header = content
        .get(0..MLS_STORE_HEADER_LEN)
        .ok_or(MlsStoreError::Truncated)?;
    if header.get(0..4) != Some(MLS_STORE_MAGIC.as_slice()) {
        return Err(MlsStoreError::BadMagic);
    }
    let ver_arr: [u8; 2] = header
        .get(4..6)
        .ok_or(MlsStoreError::Truncated)?
        .try_into()
        .map_err(|_| MlsStoreError::Truncated)?;
    if u16::from_le_bytes(ver_arr) != MLS_STORE_VERSION {
        return Err(MlsStoreError::UnsupportedVersion);
    }
    let flags_arr: [u8; 2] = header
        .get(6..8)
        .ok_or(MlsStoreError::Truncated)?
        .try_into()
        .map_err(|_| MlsStoreError::Truncated)?;
    if u16::from_le_bytes(flags_arr) != 0 {
        return Err(MlsStoreError::NonZeroFlags);
    }

    let expected_header = build_aad_header(expected_device_id, expected_party_id, expected_group_id)?;
    if header != expected_header.as_slice() {
        return Err(MlsStoreError::AadBindingMismatch);
    }

    let nonce_slice = content
        .get(MLS_STORE_HEADER_LEN..MLS_STORE_HEADER_LEN + MLS_STORE_NONCE_LEN)
        .ok_or(MlsStoreError::Truncated)?;
    let ciphertext = content
        .get(MLS_STORE_HEADER_LEN + MLS_STORE_NONCE_LEN..)
        .ok_or(MlsStoreError::Truncated)?;

    let cipher = Aes256Gcm::new_from_slice(store_key).map_err(|_| MlsStoreError::DecryptionFailed)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce_slice),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| MlsStoreError::DecryptionFailed)?,
    );

    MlsRoomSnapshotPlain::decode_plain(plaintext.as_slice())
}

// ---------------------------------------------------------------------------
// Minimal owned little-endian binary reader/writer (zero JSON, zero indexing)
// ---------------------------------------------------------------------------

struct BinWriter {
    buf: Vec<u8>,
}

impl BinWriter {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn fixed<const N: usize>(&mut self, b: &[u8; N]) {
        self.buf.extend_from_slice(b);
    }

    fn str_u16(&mut self, s: &str, max_len: usize) -> Result<(), MlsStoreError> {
        if s.len() > max_len {
            return Err(MlsStoreError::FieldTooLarge);
        }
        let len = u16::try_from(s.len()).map_err(|_| MlsStoreError::FieldTooLarge)?;
        self.u16(len);
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }

    fn bytes_u32(&mut self, b: &[u8], max_len: usize) -> Result<(), MlsStoreError> {
        if b.len() > max_len {
            return Err(MlsStoreError::FieldTooLarge);
        }
        let len = u32::try_from(b.len()).map_err(|_| MlsStoreError::FieldTooLarge)?;
        self.u32(len);
        self.buf.extend_from_slice(b);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

struct BinReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BinReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], MlsStoreError> {
        let end = self.pos.checked_add(n).ok_or(MlsStoreError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(MlsStoreError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, MlsStoreError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(MlsStoreError::Truncated)
    }

    fn bool(&mut self) -> Result<bool, MlsStoreError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MlsStoreError::InvalidEnum),
        }
    }

    fn u16(&mut self) -> Result<u16, MlsStoreError> {
        let arr: [u8; 2] = self.take(2)?.try_into().map_err(|_| MlsStoreError::Truncated)?;
        Ok(u16::from_le_bytes(arr))
    }

    fn u32(&mut self) -> Result<u32, MlsStoreError> {
        let arr: [u8; 4] = self.take(4)?.try_into().map_err(|_| MlsStoreError::Truncated)?;
        Ok(u32::from_le_bytes(arr))
    }

    fn u64(&mut self) -> Result<u64, MlsStoreError> {
        let arr: [u8; 8] = self.take(8)?.try_into().map_err(|_| MlsStoreError::Truncated)?;
        Ok(u64::from_le_bytes(arr))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], MlsStoreError> {
        self.take(N)?.try_into().map_err(|_| MlsStoreError::Truncated)
    }

    fn str_u16(&mut self, max_len: usize) -> Result<String, MlsStoreError> {
        let len = usize::from(self.u16()?);
        if len > max_len {
            return Err(MlsStoreError::FieldTooLarge);
        }
        let raw = self.take(len)?;
        let s = core::str::from_utf8(raw).map_err(|_| MlsStoreError::InvalidUtf8)?;
        Ok(s.to_string())
    }

    fn bytes_u32(&mut self, max_len: usize) -> Result<Vec<u8>, MlsStoreError> {
        let len = self.u32()? as usize;
        if len > max_len {
            return Err(MlsStoreError::FieldTooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<(), MlsStoreError> {
        if self.pos != self.buf.len() {
            return Err(MlsStoreError::TrailingBytes);
        }
        Ok(())
    }
}
