//! Full `mp2` E2EE MLS room session state machine wrapping `mp_mls::MpMlsClient` (Spec v3).
//!
//! Enforces:
//! - Exact padded wire buckets (`512`, `2048`, `8192`, `24000` B) for `chat`, `agent_card`, and `ephemeral_status`
//! - Persist-before-send outbox & MLS snapshot durability (aborting transmit on persist error)
//! - Same-epoch exact-byte retry & `409 mls_epoch_stale` requeue preserving `inner_msg_id[16]`
//! - Strict fail-closed rejection of non-`opaque_b64` frames in `e2ee_mode == 1` rooms
//! - Persistent `(group_id, auth_device_id, inner_msg_id)` deduplication
//! - Tentative Commit isolated staging + signed `CommitAckV1`
//! - Finalized Commit merge + local policy evaluation + outbox requeue flush
//! - `500`-frame PCS self-Update trigger + `900`-frame single-epoch hard send cap
//! - `PastEpochDeletion::older_than_duration(120s)` periodic past-epoch zeroization
//! - Send suspension on clone detection, `inviter_unconfirmed` (Tier 0), pending removals, or `mls_rekey_required`
//! - Honest Tier 0–3 trust tier, `has_declared_agent`, and `epoch_authenticator_b32` reporting

use core::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mp_mls::{
    AddMemberCommitOutput, ClientClass, CommitAckV1, Ed25519PubKey, LocalPolicyReport,
    MP_GROUP_ID_LEN, MP_PCS_UPDATE_FRAME_THRESHOLD, MpMlsClient, MpMlsError, MpRoomPolicyExtV1,
    MsgClass, PendingOutboxEntry, RoomTrustTier,
};
use ring::rand::{SecureRandom as _, SystemRandom};

use crate::mls_store::{
    MlsDedupRing, MlsRoomSnapshotPlain, MlsStoreError, PersistedOutboxEntry, PersistedPinnedRoot,
    encrypt_mls_snapshot_random,
};

/// Hard cap on total outbound frames (durable + ephemeral) in a single epoch (§7.2).
/// Strictly `< MP_MAX_FORWARD_DISTANCE (1024)` so ephemeral status frames can NEVER exhaust
/// the receiver's forward ratchet window before the next durable message.
pub const MP_HARD_CAP_FRAMES_PER_EPOCH: u64 = 900;

/// Retention bound for past epoch decryption trees (`120 s`, Spec v3 §1.1 / §7.2).
pub const MP_PAST_EPOCH_RETENTION: Duration = Duration::from_secs(120);

/// Periodic timer cadence for invoking `PastEpochDeletion::older_than_duration(120s)` (`30 s`).
pub const MP_PAST_EPOCH_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Failover commit delay when `MlsRekeyNeeded` arrives and no elected commit finalizes (`3 s`).
pub const MP_FAILOVER_REKEY_DELAY: Duration = Duration::from_secs(3);

/// Magic prefix for canonical inner binary chat payloads carrying encrypted inner `target`.
const INNER_CHAT_MAGIC: [u8; 4] = *b"MP2C";
/// Magic prefix for canonical inner binary ephemeral status payloads.
const INNER_STATUS_MAGIC: [u8; 4] = *b"MP2S";

/// Decoded inner ephemeral status payload decrypted from `MsgClass::EphemeralStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerEphemeralStatus {
    pub agent_name: String,
    pub agent_state: String,
    pub agent_summary: Option<String>,
}

/// Encodes `(target_selector, text)` into canonical binary `MP2C` so inner routing targets
/// remain hidden from `PartyDO` while outer `mp2` `target` is strictly `"*"`.
pub fn encode_inner_chat(target_selector: &str, text: &str) -> Result<Vec<u8>, MlsSessionError> {
    let target_len = u16::try_from(target_selector.len())
        .map_err(|_| MlsSessionError::InvalidPayload("target_selector exceeds u16"))?;
    let text_len = u32::try_from(text.len())
        .map_err(|_| MlsSessionError::InvalidPayload("chat text exceeds u32"))?;
    let mut out = Vec::with_capacity(4 + 1 + 2 + target_selector.len() + 4 + text.len());
    out.extend_from_slice(&INNER_CHAT_MAGIC);
    out.push(1);
    out.extend_from_slice(&target_len.to_be_bytes());
    out.extend_from_slice(target_selector.as_bytes());
    out.extend_from_slice(&text_len.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(out)
}

/// Decodes a `MP2C` inner chat payload into `(target_selector, text)`.
/// If a peer sent raw UTF-8 text without the `MP2C` envelope, falls back cleanly to `("@all", utf8)`.
pub fn decode_inner_chat(bytes: &[u8]) -> Result<(String, String), MlsSessionError> {
    if bytes.len() >= 11 && bytes.get(0..4) == Some(INNER_CHAT_MAGIC.as_slice()) && bytes.get(4) == Some(&1) {
        let t_len_arr: [u8; 2] = bytes
            .get(5..7)
            .ok_or(MlsSessionError::InvalidPayload("truncated MP2C target_len"))?
            .try_into()
            .map_err(|_| MlsSessionError::InvalidPayload("truncated MP2C target_len"))?;
        let t_len = usize::from(u16::from_be_bytes(t_len_arr));
        let t_end = 7usize
            .checked_add(t_len)
            .ok_or(MlsSessionError::InvalidPayload("MP2C target_len overflow"))?;
        let target_raw = bytes
            .get(7..t_end)
            .ok_or(MlsSessionError::InvalidPayload("truncated MP2C target"))?;
        let body_len_end = t_end
            .checked_add(4)
            .ok_or(MlsSessionError::InvalidPayload("MP2C body_len overflow"))?;
        let b_len_arr: [u8; 4] = bytes
            .get(t_end..body_len_end)
            .ok_or(MlsSessionError::InvalidPayload("truncated MP2C body_len"))?
            .try_into()
            .map_err(|_| MlsSessionError::InvalidPayload("truncated MP2C body_len"))?;
        let b_len = u32::from_be_bytes(b_len_arr) as usize;
        let b_end = body_len_end
            .checked_add(b_len)
            .ok_or(MlsSessionError::InvalidPayload("MP2C body overflow"))?;
        if b_end == bytes.len() {
            let target = core::str::from_utf8(target_raw)
                .map_err(|_| MlsSessionError::InvalidPayload("invalid UTF-8 target"))?;
            let text_raw = bytes
                .get(body_len_end..b_end)
                .ok_or(MlsSessionError::InvalidPayload("truncated MP2C text"))?;
            let text = core::str::from_utf8(text_raw)
                .map_err(|_| MlsSessionError::InvalidPayload("invalid UTF-8 chat text"))?;
            return Ok((target.to_string(), text.to_string()));
        }
    }
    let text = core::str::from_utf8(bytes)
        .map_err(|_| MlsSessionError::InvalidPayload("non-UTF8 chat payload"))?;
    Ok(("@all".to_string(), text.to_string()))
}

/// Encodes an encrypted ephemeral status update (`MP2S` v1 binary payload).
pub fn encode_inner_status(
    agent_name: &str,
    agent_state: &str,
    agent_summary: Option<&str>,
) -> Result<Vec<u8>, MlsSessionError> {
    let summary = agent_summary.unwrap_or("");
    let n_len = u16::try_from(agent_name.len())
        .map_err(|_| MlsSessionError::InvalidPayload("agent_name exceeds u16"))?;
    let s_len = u16::try_from(agent_state.len())
        .map_err(|_| MlsSessionError::InvalidPayload("agent_state exceeds u16"))?;
    let m_len = u16::try_from(summary.len())
        .map_err(|_| MlsSessionError::InvalidPayload("agent_summary exceeds u16"))?;
    let mut out = Vec::with_capacity(4 + 1 + 2 + agent_name.len() + 2 + agent_state.len() + 2 + summary.len());
    out.extend_from_slice(&INNER_STATUS_MAGIC);
    out.push(1);
    out.extend_from_slice(&n_len.to_be_bytes());
    out.extend_from_slice(agent_name.as_bytes());
    out.extend_from_slice(&s_len.to_be_bytes());
    out.extend_from_slice(agent_state.as_bytes());
    out.extend_from_slice(&m_len.to_be_bytes());
    out.extend_from_slice(summary.as_bytes());
    Ok(out)
}

/// Decodes a canonical `MP2S` v1 binary ephemeral status payload.
pub fn decode_inner_status(bytes: &[u8]) -> Result<InnerEphemeralStatus, MlsSessionError> {
    if bytes.len() < 11 || bytes.get(0..4) != Some(INNER_STATUS_MAGIC.as_slice()) || bytes.get(4) != Some(&1) {
        return Err(MlsSessionError::InvalidPayload("invalid MP2S header"));
    }
    let mut pos = 5usize;
    let read_str = |buf: &[u8], pos: &mut usize| -> Result<String, MlsSessionError> {
        let len_end = pos.checked_add(2).ok_or(MlsSessionError::InvalidPayload("MP2S len overflow"))?;
        let arr: [u8; 2] = buf
            .get(*pos..len_end)
            .ok_or(MlsSessionError::InvalidPayload("truncated MP2S len"))?
            .try_into()
            .map_err(|_| MlsSessionError::InvalidPayload("truncated MP2S len"))?;
        let len = usize::from(u16::from_be_bytes(arr));
        let str_end = len_end.checked_add(len).ok_or(MlsSessionError::InvalidPayload("MP2S str overflow"))?;
        let slice = buf
            .get(len_end..str_end)
            .ok_or(MlsSessionError::InvalidPayload("truncated MP2S str"))?;
        *pos = str_end;
        let s = core::str::from_utf8(slice)
            .map_err(|_| MlsSessionError::InvalidPayload("invalid UTF-8 in MP2S"))?;
        Ok(s.to_string())
    };
    let agent_name = read_str(bytes, &mut pos)?;
    let agent_state = read_str(bytes, &mut pos)?;
    let summary_raw = read_str(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(MlsSessionError::InvalidPayload("trailing bytes in MP2S"));
    }
    let agent_summary = if summary_raw.is_empty() {
        None
    } else {
        Some(summary_raw)
    };
    Ok(InnerEphemeralStatus {
        agent_name,
        agent_state,
        agent_summary,
    })
}

/// Errors produced by [`MlsRoomSession`].
#[derive(Debug)]
pub enum MlsSessionError {
    SendBlockedCloneDetected,
    SendBlockedInviterUnconfirmed,
    SendBlockedPendingRemovals,
    SendBlockedRekeyRequired,
    EpochFrameCapReached { count: u64, cap: u64 },
    PlaintextRejectedInE2eeRoom,
    InvalidBase64,
    InvalidPayload(&'static str),
    OutboxEntryNotFound,
    PersistFailed(String),
    Store(MlsStoreError),
    Mls(MpMlsError),
    RandomFailure,
}

impl fmt::Display for MlsSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendBlockedCloneDetected => {
                write!(f, "outbound sends suspended: cloned device key suspected")
            }
            Self::SendBlockedInviterUnconfirmed => {
                write!(f, "outbound sends blocked: Tier 0 inviter unconfirmed")
            }
            Self::SendBlockedPendingRemovals => {
                write!(f, "outbound sends suspended: pending member/device removal or pin violation")
            }
            Self::SendBlockedRekeyRequired => {
                write!(f, "outbound sends suspended: MLS rekey required")
            }
            Self::EpochFrameCapReached { count, cap } => {
                write!(f, "outbound sends hard-blocked at {count}/{cap} frames in current epoch; PCS update required")
            }
            Self::PlaintextRejectedInE2eeRoom => {
                write!(f, "rejected non-opaque_b64 plaintext frame in e2ee_mode == 1 room")
            }
            Self::InvalidBase64 => write!(f, "invalid base64 in opaque_b64 frame"),
            Self::InvalidPayload(msg) => write!(f, "invalid E2EE inner payload: {msg}"),
            Self::OutboxEntryNotFound => write!(f, "outbox entry not found"),
            Self::PersistFailed(msg) => write!(f, "MLS state persistence failed before transmit: {msg}"),
            Self::Store(e) => write!(f, "MLS store error: {e}"),
            Self::Mls(e) => write!(f, "MLS protocol error: {e}"),
            Self::RandomFailure => write!(f, "CSPRNG failure"),
        }
    }
}

impl std::error::Error for MlsSessionError {}

impl From<MpMlsError> for MlsSessionError {
    fn from(e: MpMlsError) -> Self {
        Self::Mls(e)
    }
}

impl From<MlsStoreError> for MlsSessionError {
    fn from(e: MlsStoreError) -> Self {
        Self::Store(e)
    }
}

/// Snapshot of E2EE room security status surfaced in MCP `outpost_status` / `party_list` / `party_poll` / `party_wait`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MlsRoomStatusSnapshot {
    pub e2ee_mode: u8,
    pub mls_epoch: u64,
    /// `0..=3` matching Spec v3 §3.4 Tier 0–3.
    pub trust_tier: u8,
    pub has_declared_agent: bool,
    /// RFC 9420 §8.7 `epoch_authenticator` formatted as 6×4 Crockford Base32 (empty when `e2ee_mode == 0`).
    pub epoch_authenticator_b32: String,
    pub clone_detected: bool,
    pub has_pending_removals: bool,
    pub mls_rekey_required: bool,
}

impl MlsRoomStatusSnapshot {
    pub const fn trust_tier_label(tier: u8) -> &'static str {
        match tier {
            3 => "self_custody_native_verified",
            2 => "self_custody_native_unverified",
            1 => "cloud_assisted_or_browser_present",
            _ => "unverified_or_post_wipe",
        }
    }
}

/// Decrypted & authenticated inbound `mp2` E2EE application frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedInboundFrame {
    pub epoch: u64,
    pub auth_account_id: u64,
    pub auth_device_id: u64,
    pub device_epoch_seq: u64,
    pub msg_class: MsgClass,
    pub inner_msg_id: [u8; 16],
    pub sender_is_browser: bool,
    pub sender_client_class: u8,
    pub sender_agent_capable: bool,
    pub is_duplicate: bool,
    pub is_historical_catchup: bool,
    pub payload: DecryptedInboundPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptedInboundPayload {
    Chat {
        target_selector: String,
        body: String,
    },
    AgentCard {
        payload: Vec<u8>,
    },
    EphemeralStatus(InnerEphemeralStatus),
    InviteControl(Vec<u8>),
}

/// Prepared outbound E2EE wire frame ready for WebSocket transmission AFTER durable local persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOutboundE2ee {
    pub client_msg_id: String,
    pub inner_msg_id: [u8; 16],
    pub mls_epoch: u64,
    pub msg_class: MsgClass,
    pub wire_bytes: Vec<u8>,
    pub body_b64: String,
    pub needs_pcs_self_update: bool,
}

/// Full `mp2` E2EE MLS session controller held inside `ActivePartySession`.
pub struct MlsRoomSession {
    client: MpMlsClient,
    store_key: [u8; 32],
    e2ee_mode: u8,
    min_allowed_mls_epoch: u64,
    mls_rekey_required: bool,
    inviter_unconfirmed: bool,
    pinned_inviter_root_pk: Option<Ed25519PubKey>,
    clone_detected: bool,
    has_pending_removals: bool,
    outbox: Vec<PersistedOutboxEntry>,
    dedup_ring: MlsDedupRing,
    device_binding_236b: Vec<u8>,
    device_list_blob: Vec<u8>,
}

impl MlsRoomSession {
    pub fn new(client: MpMlsClient, store_key: [u8; 32]) -> Self {
        Self {
            client,
            store_key,
            e2ee_mode: 1,
            min_allowed_mls_epoch: 0,
            mls_rekey_required: false,
            inviter_unconfirmed: false,
            pinned_inviter_root_pk: None,
            clone_detected: false,
            has_pending_removals: false,
            outbox: Vec::new(),
            dedup_ring: MlsDedupRing::new(),
            device_binding_236b: Vec::new(),
            device_list_blob: Vec::new(),
        }
    }

    pub fn with_inviter_unconfirmed(mut self, inviter_root_pk: Ed25519PubKey) -> Self {
        self.inviter_unconfirmed = true;
        self.pinned_inviter_root_pk = Some(inviter_root_pk);
        self
    }

    pub fn party_id(&self) -> u64 {
        self.client.party_id()
    }

    pub fn group_id(&self) -> [u8; MP_GROUP_ID_LEN] {
        self.client.group_id()
    }

    pub fn epoch(&self) -> u64 {
        self.client.epoch()
    }

    pub fn e2ee_mode(&self) -> u8 {
        self.e2ee_mode
    }

    pub fn min_allowed_mls_epoch(&self) -> u64 {
        self.min_allowed_mls_epoch
    }

    pub fn set_min_allowed_mls_epoch(&mut self, epoch: u64) {
        if epoch > self.min_allowed_mls_epoch {
            self.min_allowed_mls_epoch = epoch;
        }
    }

    pub fn mls_rekey_required(&self) -> bool {
        self.mls_rekey_required
    }

    pub fn set_mls_rekey_required(&mut self, required: bool) {
        self.mls_rekey_required = required;
    }

    pub fn clone_detected(&self) -> bool {
        self.clone_detected || self.client.cloned_device_key_suspected()
    }

    /// Flags `409 device_seq_rollback` from `PartyDO` as clone detection (§7.2), suspending sends.
    pub fn mark_clone_detected(&mut self) {
        self.clone_detected = true;
    }

    pub fn has_pending_removals(&self) -> bool {
        self.has_pending_removals
    }

    pub fn inviter_unconfirmed(&self) -> bool {
        self.inviter_unconfirmed || self.client.inviter_unconfirmed()
    }

    pub fn total_sent_frames_in_epoch(&self) -> u64 {
        self.client.total_sent_frames_in_epoch()
    }

    pub fn needs_pcs_self_update(&self) -> bool {
        self.client.total_sent_frames_in_epoch() >= MP_PCS_UPDATE_FRAME_THRESHOLD
    }

    pub fn outbox_entries(&self) -> &[PersistedOutboxEntry] {
        &self.outbox
    }

    pub fn dedup_ring(&self) -> &MlsDedupRing {
        &self.dedup_ring
    }

    pub fn client(&self) -> &MpMlsClient {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut MpMlsClient {
        &mut self.client
    }

    pub fn set_device_binding_and_list(&mut self, binding_236b: Vec<u8>, list_blob: Vec<u8>) {
        self.device_binding_236b = binding_236b;
        self.device_list_blob = list_blob;
    }

    /// Computes honest Tier 0–3 trust tier, `has_declared_agent`, `epoch_authenticator_b32`,
    /// and `clone_detected` for MCP `outpost_status` / `party_list` / `party_poll` / `party_wait`.
    pub fn status_snapshot(&self) -> MlsRoomStatusSnapshot {
        let (raw_tier, has_declared_agent) = self
            .client
            .room_trust_tier()
            .unwrap_or((RoomTrustTier::Tier0UnverifiedPostWipe, false));
        let trust_tier = if self.inviter_unconfirmed() {
            0
        } else {
            match raw_tier {
                RoomTrustTier::Tier0UnverifiedPostWipe => 0,
                RoomTrustTier::Tier1CloudOrBrowserPresent => 1,
                RoomTrustTier::Tier2SelfCustodyNativeUnverified => 2,
                RoomTrustTier::Tier3SelfCustodyNativeAllVerified => 3,
            }
        };
        let epoch_authenticator_b32 = self
            .client
            .epoch_authenticator_code()
            .unwrap_or_default();

        MlsRoomStatusSnapshot {
            e2ee_mode: self.e2ee_mode,
            mls_epoch: self.client.epoch(),
            trust_tier,
            has_declared_agent,
            epoch_authenticator_b32,
            clone_detected: self.clone_detected(),
            has_pending_removals: self.has_pending_removals,
            mls_rekey_required: self.mls_rekey_required,
        }
    }

    fn check_send_allowed(&self) -> Result<(), MlsSessionError> {
        if self.clone_detected() {
            return Err(MlsSessionError::SendBlockedCloneDetected);
        }
        if self.inviter_unconfirmed() {
            return Err(MlsSessionError::SendBlockedInviterUnconfirmed);
        }
        if self.has_pending_removals {
            return Err(MlsSessionError::SendBlockedPendingRemovals);
        }
        if self.mls_rekey_required {
            return Err(MlsSessionError::SendBlockedRekeyRequired);
        }
        let sent = self.client.total_sent_frames_in_epoch();
        if sent >= MP_HARD_CAP_FRAMES_PER_EPOCH {
            return Err(MlsSessionError::EpochFrameCapReached {
                count: sent,
                cap: MP_HARD_CAP_FRAMES_PER_EPOCH,
            });
        }
        Ok(())
    }

    /// Exports the complete room state into a canonical plaintext snapshot ready for AES-256-GCM sealing.
    pub fn export_snapshot_plain(&mut self) -> Result<MlsRoomSnapshotPlain, MlsSessionError> {
        let leaves = self.client.current_leaves_map().unwrap_or_default();
        let mut pinned_roots = Vec::new();
        for info in leaves.values() {
            let acc_id = info.cred.binding.body.account_id;
            if let Some(pin) = self.client.pins().get(acc_id)
                && !pinned_roots
                    .iter()
                    .any(|p: &PersistedPinnedRoot| p.account_id == acc_id)
            {
                pinned_roots.push(PersistedPinnedRoot::from(*pin));
            }
        }
        let mls_storage_blob = {
            let (_, provider) = self.client.raw_group_and_provider_mut();
            provider.export_storage_binary()?
        };
        let last_seq = self.outbox.last().map_or(0, |e| e.device_epoch_seq);
        Ok(MlsRoomSnapshotPlain {
            mls_storage_blob,
            epoch: self.client.epoch(),
            device_epoch_seq: last_seq,
            total_sent_frames_in_epoch: self.client.total_sent_frames_in_epoch(),
            cloned_device_key_suspected: self.clone_detected(),
            local_cache_wiped: false,
            inviter_unconfirmed: self.inviter_unconfirmed,
            outbox: self.outbox.clone(),
            dedup_ring: self.dedup_ring.to_vec(),
            pinned_roots,
            pending_key_packages: Vec::new(),
            device_binding_236b: self.device_binding_236b.clone(),
            device_list_blob: self.device_list_blob.clone(),
            welcome_receipt: None,
        })
    }

    /// Encrypts the current snapshot into an `MPM1` AES-256-GCM binary blob ready for atomic disk write.
    pub fn export_encrypted_snapshot(&mut self) -> Result<Vec<u8>, MlsSessionError> {
        let plain = self.export_snapshot_plain()?;
        let device_id = self.client.identity().device_id();
        let party_id = self.client.party_id();
        let group_id = self.client.group_id();
        Ok(encrypt_mls_snapshot_random(
            &self.store_key,
            device_id,
            party_id,
            &group_id,
            &plain,
        )?)
    }

    /// Generates a fresh 16-byte CSPRNG `inner_msg_id` for epoch-stale deduplication.
    pub fn generate_inner_msg_id() -> Result<[u8; 16], MlsSessionError> {
        let rng = SystemRandom::new();
        let mut id = [0u8; 16];
        rng.fill(&mut id)
            .map_err(|_| MlsSessionError::RandomFailure)?;
        Ok(id)
    }

    /// Encrypts an outbound `chat` message (`MP2C` inner envelope), persists encrypted snapshot +
    /// outbox via `persist_fn` BEFORE returning the wire frame (Spec v3.1 §7.2 persist-before-send).
    pub fn prepare_outbound_chat<F>(
        &mut self,
        client_msg_id: &str,
        target_selector: &str,
        body: &str,
        now_s: u64,
        persist_fn: F,
    ) -> Result<PreparedOutboundE2ee, MlsSessionError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        let inner = encode_inner_chat(target_selector, body)?;
        self.prepare_outbound_raw(
            client_msg_id,
            MsgClass::DurableChat,
            target_selector,
            &inner,
            None,
            now_s,
            persist_fn,
        )
    }

    /// Encrypts an outbound `agent_card` payload (`MsgClass::DurableAgentCard`), persisting
    /// snapshot + outbox atomically BEFORE returning wire bytes.
    pub fn prepare_outbound_agent_card<F>(
        &mut self,
        client_msg_id: &str,
        card_payload: &[u8],
        now_s: u64,
        persist_fn: F,
    ) -> Result<PreparedOutboundE2ee, MlsSessionError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        self.prepare_outbound_raw(
            client_msg_id,
            MsgClass::DurableAgentCard,
            "@all",
            card_payload,
            None,
            now_s,
            persist_fn,
        )
    }

    /// Encrypts an outbound `ephemeral_status` payload (`MsgClass::EphemeralStatus`), counting
    /// toward BOTH the 500-frame PCS trigger AND 900-frame single-epoch hard cap (§7.2).
    pub fn prepare_outbound_ephemeral_status<F>(
        &mut self,
        client_msg_id: &str,
        agent_name: &str,
        agent_state: &str,
        agent_summary: Option<&str>,
        now_s: u64,
        persist_fn: F,
    ) -> Result<PreparedOutboundE2ee, MlsSessionError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        let inner = encode_inner_status(agent_name, agent_state, agent_summary)?;
        self.prepare_outbound_raw(
            client_msg_id,
            MsgClass::EphemeralStatus,
            "*",
            &inner,
            None,
            now_s,
            persist_fn,
        )
    }

    /// Core persist-before-send encryption path:
    /// 1. Enforces send gates (clone, Tier 0 inviter unconfirmed, pending removals, rekey, `< 900` cap).
    /// 2. If `client_msg_id` already exists in the outbox for the **current epoch**, returns the
    ///    exact stored `wire_bytes` (same-epoch retry, zero ratchet advance!).
    /// 3. Otherwise encrypts via `MpMlsClient::encrypt_app_message`, appends to outbox, exports
    ///    encrypted `MPM1` snapshot, and invokes `persist_fn(&encrypted_bytes)` BEFORE returning!
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_outbound_raw<F>(
        &mut self,
        client_msg_id: &str,
        msg_class: MsgClass,
        target_selector: &str,
        plaintext: &[u8],
        explicit_inner_msg_id: Option<[u8; 16]>,
        now_s: u64,
        persist_fn: F,
    ) -> Result<PreparedOutboundE2ee, MlsSessionError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        self.check_send_allowed()?;

        let current_epoch = self.client.epoch();
        // Same-epoch idempotent retry: resend EXACT stored wire bytes without advancing ratchet!
        if let Some(existing) = self
            .outbox
            .iter()
            .find(|e| e.client_msg_id == client_msg_id && e.sent_epoch == current_epoch)
        {
            return Ok(PreparedOutboundE2ee {
                client_msg_id: existing.client_msg_id.clone(),
                inner_msg_id: existing.inner_msg_id,
                mls_epoch: existing.sent_epoch,
                msg_class,
                wire_bytes: existing.wire_bytes.clone(),
                body_b64: B64.encode(&existing.wire_bytes),
                needs_pcs_self_update: self.needs_pcs_self_update(),
            });
        }

        let inner_msg_id = match explicit_inner_msg_id {
            Some(id) => id,
            None => Self::generate_inner_msg_id()?,
        };
        let pending = self
            .client
            .encrypt_app_message(inner_msg_id, msg_class, plaintext, now_s)?;

        let outbox_entry = PersistedOutboxEntry {
            inner_msg_id: pending.inner_msg_id,
            client_msg_id: client_msg_id.to_string(),
            msg_class: pending.msg_class as u8,
            target_selector: target_selector.to_string(),
            plaintext: pending.plaintext,
            sent_epoch: pending.sent_epoch,
            device_epoch_seq: pending.device_epoch_seq,
            wire_bytes: pending.wire_bytes.clone(),
        };

        // Ephemeral frames are fire-and-forget (not requeued across epochs), durable frames stay in outbox.
        let added_outbox = msg_class != MsgClass::EphemeralStatus;
        if added_outbox {
            if let Some(slot) = self
                .outbox
                .iter_mut()
                .find(|e| e.client_msg_id == client_msg_id)
            {
                *slot = outbox_entry;
            } else {
                self.outbox.push(outbox_entry);
            }
        }

        let encrypted = self.export_encrypted_snapshot()?;
        if let Err(err_msg) = persist_fn(&encrypted) {
            if added_outbox {
                self.outbox.retain(|e| e.client_msg_id != client_msg_id);
            }
            return Err(MlsSessionError::PersistFailed(err_msg));
        }

        Ok(PreparedOutboundE2ee {
            client_msg_id: client_msg_id.to_string(),
            inner_msg_id,
            mls_epoch: pending.sent_epoch,
            msg_class,
            body_b64: B64.encode(&pending.wire_bytes),
            wire_bytes: pending.wire_bytes,
            needs_pcs_self_update: self.needs_pcs_self_update(),
        })
    }

    /// Re-encrypts a stale outbox entry in the current (advanced) epoch keeping the EXACT
    /// `inner_msg_id[16]` for receiver deduplication (§7.2), persisting BEFORE returning wire bytes!
    pub fn requeue_stale_outbox_entry<F>(
        &mut self,
        client_msg_id: &str,
        now_s: u64,
        persist_fn: F,
    ) -> Result<PreparedOutboundE2ee, MlsSessionError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        self.check_send_allowed()?;

        let existing = self
            .outbox
            .iter()
            .find(|e| e.client_msg_id == client_msg_id)
            .cloned()
            .ok_or(MlsSessionError::OutboxEntryNotFound)?;
        let msg_class = MsgClass::from_u8(existing.msg_class)?;

        // Same-epoch retry returns exact stored bytes without advancing ratchet!
        if existing.sent_epoch == self.client.epoch() {
            return Ok(PreparedOutboundE2ee {
                client_msg_id: existing.client_msg_id,
                inner_msg_id: existing.inner_msg_id,
                mls_epoch: existing.sent_epoch,
                msg_class,
                body_b64: B64.encode(&existing.wire_bytes),
                wire_bytes: existing.wire_bytes,
                needs_pcs_self_update: self.needs_pcs_self_update(),
            });
        }

        let stale = PendingOutboxEntry {
            inner_msg_id: existing.inner_msg_id,
            msg_class,
            plaintext: existing.plaintext.clone(),
            sent_epoch: existing.sent_epoch,
            device_epoch_seq: existing.device_epoch_seq,
            wire_bytes: existing.wire_bytes.clone(),
        };
        let requeued = self.client.requeue_stale_outbox_entry(&stale, now_s)?;
        let updated = PersistedOutboxEntry {
            inner_msg_id: requeued.inner_msg_id,
            client_msg_id: existing.client_msg_id.clone(),
            msg_class: requeued.msg_class as u8,
            target_selector: existing.target_selector,
            plaintext: requeued.plaintext,
            sent_epoch: requeued.sent_epoch,
            device_epoch_seq: requeued.device_epoch_seq,
            wire_bytes: requeued.wire_bytes.clone(),
        };

        if let Some(slot) = self
            .outbox
            .iter_mut()
            .find(|e| e.client_msg_id == client_msg_id)
        {
            *slot = updated;
        }

        let encrypted = self.export_encrypted_snapshot()?;
        if let Err(err_msg) = persist_fn(&encrypted) {
            return Err(MlsSessionError::PersistFailed(err_msg));
        }

        Ok(PreparedOutboundE2ee {
            client_msg_id: existing.client_msg_id,
            inner_msg_id: requeued.inner_msg_id,
            mls_epoch: requeued.sent_epoch,
            msg_class,
            body_b64: B64.encode(&requeued.wire_bytes),
            wire_bytes: requeued.wire_bytes,
            needs_pcs_self_update: self.needs_pcs_self_update(),
        })
    }

    /// Acknowledges an outbound message, removing it from the local outbox and persisting.
    pub fn ack_outbox<F>(&mut self, client_msg_id: &str, persist_fn: F) -> Result<bool, MlsSessionError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        let before = self.outbox.len();
        self.outbox.retain(|e| e.client_msg_id != client_msg_id);
        let removed = self.outbox.len() != before;
        if removed {
            let encrypted = self.export_encrypted_snapshot()?;
            persist_fn(&encrypted).map_err(MlsSessionError::PersistFailed)?;
        }
        Ok(removed)
    }

    /// Returns all `client_msg_id`s in the outbox whose `sent_epoch < current_epoch`.
    pub fn stale_outbox_client_msg_ids(&self) -> Vec<String> {
        let cur = self.client.epoch();
        self.outbox
            .iter()
            .filter(|e| e.sent_epoch < cur)
            .map(|e| e.client_msg_id.clone())
            .collect()
    }

    /// Decrypts and verifies an inbound `mp2` frame in an `e2ee_mode == 1` room:
    /// - Strictly rejects ANY non-`opaque_b64` frame (`PlaintextRejectedInE2eeRoom`)!
    /// - Decrypts on an isolated OpenMLS snapshot via `MpMlsClient::decrypt_app_message`
    ///   (which verifies `MpAppAadV1` vs authenticated `sender_leaf` `MpMlsLeafCredV1`).
    /// - Deduplicates via persistent `(group_id, auth_device_id, inner_msg_id)` ring.
    /// - Extracts authenticated `ClientClass` & `agent_capable` from the sender's MLS leaf.
    /// - Clears `inviter_unconfirmed` if the authenticated sender chains to `pinned_inviter_root_pk`.
    /// - Sets `clone_detected = true` on `MpMlsError::ClonedDeviceKeySuspected`.
    pub fn decrypt_inbound_mp2(
        &mut self,
        body_encoding: &str,
        body: &str,
        is_historical_catchup: bool,
    ) -> Result<DecryptedInboundFrame, MlsSessionError> {
        if self.e2ee_mode == 1 && body_encoding != "opaque_b64" {
            return Err(MlsSessionError::PlaintextRejectedInE2eeRoom);
        }
        let wire_bytes = B64
            .decode(body.as_bytes())
            .map_err(|_| MlsSessionError::InvalidBase64)?;

        let dec = match self.client.decrypt_app_message(&wire_bytes) {
            Ok(d) => d,
            Err(MpMlsError::ClonedDeviceKeySuspected) => {
                self.clone_detected = true;
                return Err(MlsSessionError::Mls(MpMlsError::ClonedDeviceKeySuspected));
            }
            Err(other) => return Err(MlsSessionError::Mls(other)),
        };

        let leaves = self.client.current_leaves_map().unwrap_or_default();
        let sender_leaf = leaves
            .values()
            .find(|l| l.cred.binding.body.device_id == dec.auth_device_id);
        let (sender_is_browser, sender_client_class, sender_agent_capable) = match sender_leaf {
            Some(info) => {
                let b = &info.cred.binding.body;
                if self.inviter_unconfirmed
                    && self
                        .pinned_inviter_root_pk
                        .is_some_and(|pk| pk == b.root_pubkey)
                {
                    self.inviter_unconfirmed = false;
                }
                (
                    b.client_class == ClientClass::Browser,
                    b.client_class as u8,
                    b.agent_capable,
                )
            }
            None => (false, 0, false),
        };

        let group_id = self.client.group_id();
        let ring_dup = self
            .dedup_ring
            .check_and_insert(group_id, dec.auth_device_id, dec.inner_msg_id);
        let is_duplicate = dec.is_duplicate || ring_dup;

        let payload = match dec.msg_class {
            MsgClass::DurableChat => {
                let (target_selector, text) = decode_inner_chat(&dec.body)?;
                DecryptedInboundPayload::Chat {
                    target_selector,
                    body: text,
                }
            }
            MsgClass::DurableAgentCard => DecryptedInboundPayload::AgentCard { payload: dec.body },
            MsgClass::EphemeralStatus => {
                DecryptedInboundPayload::EphemeralStatus(decode_inner_status(&dec.body)?)
            }
            MsgClass::InviteControl => DecryptedInboundPayload::InviteControl(dec.body),
        };

        Ok(DecryptedInboundFrame {
            epoch: dec.epoch,
            auth_account_id: dec.auth_account_id,
            auth_device_id: dec.auth_device_id,
            device_epoch_seq: dec.device_epoch_seq,
            msg_class: dec.msg_class,
            inner_msg_id: dec.inner_msg_id,
            sender_is_browser,
            sender_client_class,
            sender_agent_capable,
            is_duplicate,
            is_historical_catchup,
            payload,
        })
    }

    /// Applies any attached proposals (e.g. DS External `Remove`) and validates a tentative Commit
    /// on an isolated OpenMLS snapshot, returning a signed `CommitAckV1` (`OK` with `epoch_auth_hash`
    /// or `REJECT`).
    pub fn handle_tentative_commit(
        &mut self,
        proposal_blobs: &[Vec<u8>],
        commit_bytes: &[u8],
    ) -> Result<CommitAckV1, MlsSessionError> {
        for prop in proposal_blobs {
            let _ = self.client.apply_proposal(prop);
        }
        Ok(self
            .client
            .validate_tentative_commit_and_sign_ack(commit_bytes)?)
    }

    /// Applies a finalized Commit (and any referenced proposals), updates local policy send gates,
    /// invokes deterministic 120-second `prune_past_epochs(now_s)`, and clears `mls_rekey_required`
    /// if no pending removals remain.
    pub fn handle_finalized_commit(
        &mut self,
        proposal_blobs: &[Vec<u8>],
        commit_bytes: &[u8],
        now_s: u64,
    ) -> Result<LocalPolicyReport, MlsSessionError> {
        for prop in proposal_blobs {
            let _ = self.client.apply_proposal(prop);
        }
        let report = match self.client.apply_finalized_commit(commit_bytes, now_s) {
            Ok(r) => r,
            Err(MpMlsError::ClonedDeviceKeySuspected) => {
                self.clone_detected = true;
                return Err(MlsSessionError::Mls(MpMlsError::ClonedDeviceKeySuspected));
            }
            Err(other) => return Err(MlsSessionError::Mls(other)),
        };

        self.has_pending_removals = report.should_block_send();
        if !self.has_pending_removals {
            self.mls_rekey_required = false;
        }
        let _ = self.prune_past_epochs(now_s);
        Ok(report)
    }

    /// Applies pending DS proposals from `MlsRekeyNeeded` and sets `mls_rekey_required = true`.
    pub fn handle_rekey_needed(&mut self, proposal_blobs: &[Vec<u8>]) {
        self.mls_rekey_required = true;
        for prop in proposal_blobs {
            let _ = self.client.apply_proposal(prop);
        }
    }

    /// Builds a failover Commit covering all queued proposals (e.g. DS External `Remove`).
    pub fn build_failover_rekey_commit(
        &mut self,
        updated_policy: Option<MpRoomPolicyExtV1>,
    ) -> Result<Vec<u8>, MlsSessionError> {
        Ok(self.client.commit_pending_proposals(updated_policy)?)
    }

    /// Builds a PCS self-Update Commit (triggered at `>= 500` total frames in an epoch).
    pub fn build_pcs_self_update_commit(&mut self) -> Result<Vec<u8>, MlsSessionError> {
        Ok(self.client.commit_self_update(None)?)
    }

    /// Builds an invite-authenticated `Add` Commit + `Welcome` + `WelcomeAuthV1`.
    pub fn build_add_member_commit(
        &mut self,
        kp_bytes: &[u8],
        invite_id: u64,
        join_proof: &[u8; 32],
        now_s: u64,
        allow_delegated: bool,
    ) -> Result<AddMemberCommitOutput, MlsSessionError> {
        Ok(self.client.commit_add_member_with_invite(
            kp_bytes,
            invite_id,
            join_proof,
            now_s,
            allow_delegated,
        )?)
    }

    /// Enforces the deterministic 120-second forward-secrecy retention bound on past epoch
    /// decryption trees (`MpMlsClient::prune_past_epochs(now_s)`).
    pub fn prune_past_epochs(&mut self, now_s: u64) -> Result<usize, MlsSessionError> {
        Ok(self.client.prune_past_epochs(now_s)?)
    }
}
