//! Pure Sans-IO party event ring buffer, `(daemon_epoch, after_seq)` cursor pagination,
//! live per-client `client_msg_id` dedupe cache, durable epoch-floor state machine, and
//! per-destination trust send planner.

use std::collections::{BTreeMap, VecDeque};

use mp_protocol::Sha256Digest;

use crate::storage_codec::{EpochFloorEntry, EpochsStoreRecord, MAX_EPOCH_ENTRIES, TrustState};

pub const MAX_RING_EVENTS: usize = 512;
pub const MAX_RING_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_POLL_MAX_BYTES: usize = 512 * 1024;
pub const MAX_DEDUPE_ENTRIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartyEventBody {
    Chat {
        sender_account_id: u64,
        sender_device_id: u64,
        sender_handle: String,
        room_scope: String,
        target_selector: String,
        timestamp_ns: i64,
        body: String,
    },
    BridgeEnvelope {
        sender_account_id: u64,
        sender_device_id: u64,
        sender_handle: String,
        room_scope: String,
        payload: Vec<u8>,
    },
    ControlNotice {
        sender_account_id: u64,
        sender_device_id: u64,
        notice_kind: u8,
        party_epoch: u64,
        text: String,
    },
    MembershipChanged {
        party_epoch: u64,
        summary: String,
    },
}

impl PartyEventBody {
    pub fn approx_bytes(&self) -> usize {
        match self {
            Self::Chat {
                sender_handle,
                room_scope,
                target_selector,
                body,
                ..
            } => 64 + sender_handle.len() + room_scope.len() + target_selector.len() + body.len(),
            Self::BridgeEnvelope {
                sender_handle,
                room_scope,
                payload,
                ..
            } => 64 + sender_handle.len() + room_scope.len() + payload.len(),
            Self::ControlNotice { text, .. } => 48 + text.len(),
            Self::MembershipChanged { summary, .. } => 32 + summary.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyEvent {
    pub seq: u64,
    pub body: PartyEventBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollResult {
    pub daemon_epoch: u64,
    pub next_seq: u64,
    pub dropped_before_seq: u64,
    pub cursor_reset: bool,
    pub gap_possible: bool,
    pub events: Vec<PartyEvent>,
}

#[derive(Debug, Clone)]
pub struct PartyEventRing {
    pub party_id: u64,
    pub daemon_epoch: u64,
    next_seq: u64,
    dropped_before_seq: u64,
    total_bytes: usize,
    events: VecDeque<(PartyEvent, usize)>,
}

impl PartyEventRing {
    pub const fn new(party_id: u64, daemon_epoch: u64) -> Self {
        Self {
            party_id,
            daemon_epoch,
            next_seq: 0,
            dropped_before_seq: 0,
            total_bytes: 0,
            events: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub const fn latest_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn push(&mut self, body: PartyEventBody) -> u64 {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;
        let sz = body.approx_bytes();
        self.events.push_back((PartyEvent { seq, body }, sz));
        self.total_bytes = self.total_bytes.saturating_add(sz);

        while self.events.len() > MAX_RING_EVENTS
            || (self.events.len() > 1 && self.total_bytes > MAX_RING_BYTES)
        {
            if let Some((ev, evicted_sz)) = self.events.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(evicted_sz);
                self.dropped_before_seq = self.dropped_before_seq.max(ev.seq);
            } else {
                break;
            }
        }
        seq
    }

    pub fn poll(
        &self,
        cursor_epoch: Option<u64>,
        after_seq: u64,
        limit: usize,
        max_bytes: usize,
    ) -> PollResult {
        let epoch_mismatch = cursor_epoch.is_some_and(|e| e != 0 && e != self.daemon_epoch);
        if epoch_mismatch || after_seq > self.next_seq {
            return PollResult {
                daemon_epoch: self.daemon_epoch,
                next_seq: self.next_seq,
                dropped_before_seq: self.dropped_before_seq,
                cursor_reset: true,
                gap_possible: true,
                events: Vec::new(),
            };
        }

        let eff_limit = limit.clamp(1, 100);
        let eff_budget = max_bytes.max(1);
        let mut out = Vec::new();
        let mut used_bytes = 0usize;
        let mut last_returned = after_seq;

        for (ev, sz) in &self.events {
            if ev.seq <= after_seq {
                continue;
            }
            if !out.is_empty() && (out.len() >= eff_limit || used_bytes.saturating_add(*sz) > eff_budget) {
                break;
            }
            out.push(ev.clone());
            used_bytes = used_bytes.saturating_add(*sz);
            last_returned = ev.seq;
        }

        let gap_possible = after_seq < self.dropped_before_seq;
        PollResult {
            daemon_epoch: self.daemon_epoch,
            next_seq: last_returned,
            dropped_before_seq: self.dropped_before_seq,
            cursor_reset: false,
            gap_possible,
            events: out,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupeOutcome {
    New,
    Duplicate,
    PayloadConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DedupeKey {
    client_id: u64,
    party_id: u64,
    opcode: u16,
    client_msg_id: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DedupeCache {
    order: VecDeque<DedupeKey>,
    entries: BTreeMap<DedupeKey, Sha256Digest>,
}

impl DedupeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_or_insert(
        &mut self,
        client_id: u64,
        party_id: u64,
        opcode: u16,
        client_msg_id: u64,
        payload_hash: Sha256Digest,
    ) -> DedupeOutcome {
        let key = DedupeKey {
            client_id,
            party_id,
            opcode,
            client_msg_id,
        };
        if let Some(existing) = self.entries.get(&key) {
            return if *existing == payload_hash {
                DedupeOutcome::Duplicate
            } else {
                DedupeOutcome::PayloadConflict
            };
        }
        while self.entries.len() >= MAX_DEDUPE_ENTRIES {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(key);
        self.entries.insert(key, payload_hash);
        DedupeOutcome::New
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochFloorError {
    EpochRegression { floor: u64, observed: u64 },
    ResurrectedDisbandedParty { party_id: u64 },
}

#[derive(Debug, Clone, Default)]
pub struct EpochFloorStore {
    entries: BTreeMap<([u8; 8], u64), EpochFloorEntry>,
}

impl EpochFloorStore {
    pub fn from_record(rec: EpochsStoreRecord) -> Self {
        let mut entries = BTreeMap::new();
        for e in rec.entries {
            entries.insert((e.api_authority_hash, e.party_id), e);
        }
        Self { entries }
    }

    pub fn to_record(&self) -> EpochsStoreRecord {
        EpochsStoreRecord {
            entries: self.entries.values().copied().collect(),
        }
    }

    pub fn check_and_advance(
        &mut self,
        api_authority_hash: [u8; 8],
        party_id: u64,
        observed_epoch: u64,
        is_disband: bool,
        now_ms: u64,
    ) -> Result<bool, EpochFloorError> {
        let key = (api_authority_hash, party_id);
        if let Some(existing) = self.entries.get(&key) {
            if existing.terminal_disbanded {
                return Err(EpochFloorError::ResurrectedDisbandedParty { party_id });
            }
            if observed_epoch < existing.highest_party_epoch {
                return Err(EpochFloorError::EpochRegression {
                    floor: existing.highest_party_epoch,
                    observed: observed_epoch,
                });
            }
            if observed_epoch == existing.highest_party_epoch && !is_disband {
                return Ok(false);
            }
        }

        if !self.entries.contains_key(&key)
            && self.entries.len() >= MAX_EPOCH_ENTRIES
            && let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.updated_at_ms)
                .map(|(k, _)| *k)
        {
            self.entries.remove(&oldest_key);
        }

        self.entries.insert(
            key,
            EpochFloorEntry {
                api_authority_hash,
                party_id,
                highest_party_epoch: observed_epoch,
                terminal_disbanded: is_disband,
                updated_at_ms: now_ms,
            },
        );
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSendCandidate {
    pub account_id: u64,
    pub device_id: u64,
    pub trust: TrustState,
    pub connected_p2p: bool,
    pub key_mismatch: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendTarget {
    Broadcast,
    Device(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPlan {
    pub deliver_to: Vec<u64>,
    pub withheld_unpinned: Vec<u64>,
    pub disconnected: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPlanError {
    KeyMismatchPresent { account_id: u64 },
    TargetNotFound { device_id: u64 },
    TargetNotPinned { account_id: u64 },
    TargetDisconnected { device_id: u64 },
    NoPinnedConnectedRecipients,
}

/// Unified per-destination send planner for `party_send` and `board_post`:
/// - Any `key_mismatch` in the party fails closed hard (critical MitM alert).
/// - Targeted send checks only the selected recipient (never frozen by an unrelated unpinned joiner).
/// - Broadcast sends to all `PinnedTrusted` connected peers and reports `withheld_unpinned` & `disconnected`.
pub fn plan_send_recipients(
    candidates: &[PeerSendCandidate],
    target: SendTarget,
) -> Result<SendPlan, SendPlanError> {
    for c in candidates {
        if c.key_mismatch {
            return Err(SendPlanError::KeyMismatchPresent {
                account_id: c.account_id,
            });
        }
    }

    match target {
        SendTarget::Device(target_dev) => {
            let Some(peer) = candidates.iter().find(|c| c.device_id == target_dev) else {
                return Err(SendPlanError::TargetNotFound {
                    device_id: target_dev,
                });
            };
            if peer.trust != TrustState::PinnedTrusted {
                return Err(SendPlanError::TargetNotPinned {
                    account_id: peer.account_id,
                });
            }
            if !peer.connected_p2p {
                return Err(SendPlanError::TargetDisconnected {
                    device_id: target_dev,
                });
            }
            Ok(SendPlan {
                deliver_to: vec![target_dev],
                withheld_unpinned: Vec::new(),
                disconnected: Vec::new(),
            })
        }
        SendTarget::Broadcast => {
            let mut deliver_to = Vec::new();
            let mut withheld_unpinned = Vec::new();
            let mut disconnected = Vec::new();
            for c in candidates {
                match c.trust {
                    TrustState::PinnedTrusted => {
                        if c.connected_p2p {
                            deliver_to.push(c.device_id);
                        } else {
                            disconnected.push(c.device_id);
                        }
                    }
                    TrustState::Unpinned => {
                        if !withheld_unpinned.contains(&c.account_id) {
                            withheld_unpinned.push(c.account_id);
                        }
                    }
                    TrustState::RevokedBlocked => {}
                }
            }
            if deliver_to.is_empty() {
                return Err(SendPlanError::NoPinnedConnectedRecipients);
            }
            Ok(SendPlan {
                deliver_to,
                withheld_unpinned,
                disconnected,
            })
        }
    }
}
