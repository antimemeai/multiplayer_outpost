//! Full `mp-outpost __daemon` engine implementing `outpost_daemon::DaemonHandler`.
//!
//! Coordinates:
//! - Binary state loading (`d<13hex>.dev.bin`, `peers.bin`, `epochs.bin`) under `StateLock`
//! - Background Account WS (`/v1/ws`) with 20s `"MP1:PING"`, presence/friends, and `EvictionChurnDetector`
//! - At most 1 active Party per `device_id` in v1:
//!   - Party WS (`/v1/parties/<id>/ws`) with sleep-aware 45s/60s timers, terminal 404/403 teardown,
//!     and durable `epochs.bin` monotonic floor
//!   - Lazy per-party `PartyP2pTransport` (`iroh` v1.5.0, ALPN `blackbird-mp/1`)
//!   - 5-link `evaluate_peer_admission` + `UnpinnedPeerAlert` / `KeyMismatch`
//!   - Authenticated `peer_pubkey` attribution into `PartyEventRing` + `Notify` waiters
//!   - Outbound `scan_outbound_secrets` + `DedupeCache` + `plan_send_recipients`

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use mp_mls::{
    AccountDeviceListV1, DeviceIdentity, InviteFragmentV2, InviteRecordV1, InviteSecrets,
    MP_GROUP_ID_LEN, MpCryptoProvider, MpGroupId, MpMlsClient, MpMlsDeviceBindingV1,
    MpMlsLeafCredV1, MpRoomPolicyExtV1, WelcomeAuthV1, compute_join_proof,
    generate_single_use_key_package,
};
use mp_protocol::{
    AccountId, DeviceId, EndpointDescriptor, MAX_DIRECT_ADDRS, Mp1Message, PartyId, PartyInviteId,
    PartyJoinMode, PartyMemberRecord, PartySnapshot, PartyVisibility, RelayPolicy, RequestId,
    TransportKind, sha256, validate_relay_url, verify_device_cwt,
};
use outpost_control::{
    ApprovePartyRequest, ChurnStatus, ControlClient, ControlError, CreatePartyRequest,
    EndpointUpdateCoalescer, EvictionChurnDetector, JoinPartyRequest, JoinPartyResponse,
    MAX_MP2_BODY_BYTES, MintPartyInviteRequest, MlsCommitAckRequest, MlsCommitRequest,
    MlsCreateInviteRequest, MlsInitRequest, MlsJoinRequest, MlsWelcomeAckRequest, MlsWelcomeEntry,
    Mp1WsEvent, Mp1WsTarget, Mp2Ack, Mp2Event, Mp2EventKind, Mp2Member, Mp2RoomEvent,
    RequestSigner, RoomEnterRequest, RoomInviteRequest, WsConnectError, sleep_aware_now_ms,
    wall_now_ms, wall_now_secs,
};
use outpost_core::fence::{sanitize_peer_text, scan_outbound_secrets};
use outpost_core::ipc_wire::IpcOpcode;
use outpost_core::mls_session::{
    DecryptedInboundPayload, MP_FAILOVER_REKEY_DELAY, MP_PAST_EPOCH_SWEEP_INTERVAL, MlsRoomSession,
    MlsRoomStatusSnapshot,
};
use outpost_core::mls_store::{PersistedKeyPackage, derive_mls_store_key};
use outpost_core::p2p_wire::{
    P2pActivityState, P2pBridgeEnvelope, P2pChatMessage, P2pControlNotice, P2pControlNoticeKind,
    P2pEphemeralPulse, P2pPartyFrame,
};
use outpost_core::party_state::{
    DEFAULT_POLL_MAX_BYTES, DedupeCache, DedupeLookup, EpochFloorStore, PartyEventBody,
    PartyEventRing, PeerSendCandidate, SendPlanError, SendTarget, SendTrustPolicy,
    plan_send_recipients_with_policy,
};
use outpost_core::storage_codec::{DeviceRecord, PeerRecord, PeersStoreRecord, TrustState};
use outpost_core::trust::{
    AdmissionDecision, PeerTrustLookup, api_authority_hash, compute_safety_number,
    effective_relay_policy, evaluate_peer_admission,
};
use outpost_daemon::{
    CancellationToken, DaemonHandler, DrainMode, fill_random, write_log_lock_free,
};
use outpost_p2p::{
    CLOSE_PEER_REVOKED, CLOSE_UNAUTHORIZED, P2pEventStream, P2pTransportEvent, PartyP2pConfig,
    PartyP2pHandle, PartyP2pTransport, PeerDialTarget, Watcher as _,
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::build_info::{build_digest, build_order};
use crate::ipc_payloads::{
    ActivePartySummary, ERR_CANCELLED, ERR_CONFLICT, ERR_CONTROL_PLANE, ERR_IDEMPOTENCY_CONFLICT,
    ERR_INTERNAL, ERR_INVALID_PARAMS, ERR_NOT_FOUND, ERR_UNAUTHORIZED, FriendItem, FriendsListResp,
    FriendsLiveIpcResp, IpcPartyEvent, IpcPartyEventKind, IpcProvenance, JoinRequestItem,
    KeyMismatchAlert, LiveFriendIpc, MemberInfo, PartyCreateResp, PartyEpochResp,
    PartyInviteMintResp, PartyJoinResp, PartyListResp, PartyMembersResp, PartyPollIpcResp,
    PartyRequestApproveResp, PartyRequestsListResp, PendingInviteIpc, ReloadDeviceResp,
    ResolveHandleResp, RoomEnterIpcResp, RoomInviteIpcResp, RoomLeaveIpcResp, RoomMemberIpc,
    SendResultResp, StatusResp, UnpinnedPeerAlert, decode_control_notice_req,
    decode_party_create_req, decode_party_epoch_op_req, decode_party_invite_mint_req,
    decode_party_invite_revoke_req, decode_party_join_req, decode_party_kick_req,
    decode_party_poll_req, decode_party_post_board_req, decode_party_promote_req,
    decode_party_request_approve_req, decode_party_request_reject_req,
    decode_party_requests_list_req, decode_party_send_chat_req, decode_party_wait_req,
    decode_resolve_handle_req, decode_room_enter_req, decode_room_invite_req,
    decode_room_leave_req, decode_u64_req, encode_bool_resp, encode_friend_edge_resp,
    encode_friends_list_resp, encode_friends_live_resp, encode_party_create_resp,
    encode_party_epoch_resp, encode_party_invite_mint_resp, encode_party_join_resp,
    encode_party_list_resp, encode_party_members_resp, encode_party_poll_resp,
    encode_party_request_approve_resp, encode_party_requests_list_resp, encode_reload_resp,
    encode_resolve_handle_resp, encode_room_enter_resp, encode_room_invite_resp,
    encode_room_leave_resp, encode_send_result_resp, encode_status_resp, secret_kind_to_error_code,
    trust_state_to_u8,
};
use crate::storage::{
    build_control_client_config, load_device_record, load_epochs_store, load_mls_device_identity,
    load_mls_room_snapshot, load_peers_store, lock_state, open_state_dir, pubkey_fingerprint_hex,
    remove_mls_pending_key_package, remove_mls_room_snapshot, save_device_record,
    save_epochs_store, save_mls_device_identity, save_mls_pending_key_package, save_mls_room_bytes,
    save_peers_store,
};

const WS_PING_INTERVAL: Duration = Duration::from_secs(20);
const WS_RECONNECT_SILENCE_MS: u64 = 45_000;
const WS_P2P_REVOKE_SILENCE_MS: u64 = 60_000;
const CWT_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const CWT_AUTO_RENEW_THRESHOLD_MS: u64 = 3 * 24 * 3600 * 1000;
const CWT_AUTO_RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(3600);
const MP2_ACK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TRACKED_MP2_MSG_IDS: usize = 256;
const MAX_WAIT_TIMEOUT_MS: u32 = 45_000;
const P2P_DIAL_TIMEOUT: Duration = Duration::from_secs(3);
const UNATTENDED_DETACH_MS: u64 = 30 * 60 * 1000;
const UNATTENDED_POLL_INTERVAL: Duration = Duration::from_secs(5);

type IpcErr = (u16, bool, String);

fn ipc_err(code: u16, retryable: bool, msg: impl Into<String>) -> IpcErr {
    (code, retryable, msg.into())
}

fn log_line(msg: &str) {
    let mut line = String::with_capacity(msg.len() + 18);
    line.push_str("[outpost-daemon] ");
    line.push_str(msg);
    line.push('\n');
    write_log_lock_free(line.as_bytes());
}

fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn sanitize_validated_friend_handle(raw: &str) -> Option<String> {
    let cleaned: String = sanitize_peer_text(raw)
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .collect();
    if cleaned.is_empty() || cleaned.len() > 64 {
        return None;
    }
    Some(cleaned)
}

// ---------------------------------------------------------------------------
// Active Party State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PartyMemberState {
    record: PartyMemberRecord,
    trust_state: TrustState,
    admitted: bool,
    key_mismatch: bool,
    cwt_exp_s: i64,
    safety_number: String,
    server_handle: String,
}

#[derive(Debug, Clone)]
struct CachedAccountProvenance {
    handle: String,
    fingerprint: String,
    safety_number: String,
}

enum Mp2OutboundCmd {
    Send {
        client_msg_id: String,
        kind: Mp2EventKind,
        target: String,
        body_encoding: String,
        body: String,
        ack_tx: oneshot::Sender<Result<Mp2Ack, String>>,
    },
    SendE2eeApp {
        client_msg_id: String,
        mls_epoch: u64,
        body_b64: String,
        ack_tx: oneshot::Sender<Result<Mp2Ack, String>>,
    },
    #[allow(dead_code)]
    SendE2eeEphemeral {
        client_msg_id: String,
        mls_epoch: u64,
        body_b64: String,
    },
    Nick {
        nick: String,
    },
    Topic {
        topic: String,
    },
}

struct PendingJoinKeyPackage {
    kp_ref: [u8; 32],
    provider_blob: Vec<u8>,
    kp_submitted: bool,
}

struct ActivePartySession {
    party_id: u64,
    party_epoch: u64,
    leader_account_id: u64,
    leader_device_id: u64,
    visibility: PartyVisibility,
    join_mode: PartyJoinMode,
    relay_policy: RelayPolicy,
    effective_relay_policy: RelayPolicy,
    max_members: u8,
    pinned_relay_url: String,
    room_code: String,
    room_name: String,
    share_url: String,
    ws_path: String,
    e2ee_mode: u8,
    mls_epoch: u64,
    min_allowed_mls_epoch: u64,
    mls_rekey_required: bool,
    mls_invite_epoch: u64,
    group_id_b64: Option<String>,
    party_ds_pubkey: Option<[u8; 32]>,
    is_mls_creator: bool,
    pending_invite_fragment: Option<InviteFragmentV2>,
    pending_join_kp: Option<PendingJoinKeyPackage>,
    processed_kp_refs: HashSet<[u8; 32]>,
    mls_session: Option<MlsRoomSession>,
    members: HashMap<u64, PartyMemberState>,
    mp2_members: Vec<Mp2Member>,
    mp2_connected: bool,
    mp2_last_seq: u64,
    mp2_seen_seqs: VecDeque<u64>,
    sent_mp2_msg_ids: VecDeque<String>,
    mp2_tx: Option<mpsc::Sender<Mp2OutboundCmd>>,
    pubkey_to_device: HashMap<[u8; 32], u64>,
    provenance_by_account: HashMap<u64, CachedAccountProvenance>,
    unpinned_alerts: HashMap<u64, UnpinnedPeerAlert>,
    key_mismatch_alerts: HashMap<u64, KeyMismatchAlert>,
    ring: PartyEventRing,
    wait_notify: Arc<Notify>,
    p2p: Option<Arc<PartyP2pHandle>>,
    p2p_event_task: Option<JoinHandle<()>>,
    ws_stop: CancellationToken,
    ws_task: Option<JoinHandle<()>>,
    cwt_task: Option<JoinHandle<()>>,
}

impl ActivePartySession {
    fn mls_status_snapshot(&self) -> MlsRoomStatusSnapshot {
        if let Some(ref mls) = self.mls_session {
            mls.status_snapshot()
        } else {
            MlsRoomStatusSnapshot {
                e2ee_mode: self.e2ee_mode,
                mls_epoch: self.mls_epoch,
                trust_tier: 0,
                has_declared_agent: false,
                epoch_authenticator_b32: String::new(),
                clone_detected: false,
                has_pending_removals: false,
                mls_rekey_required: self.mls_rekey_required,
            }
        }
    }

    fn summary(&self) -> ActivePartySummary {
        let member_count = self.members.len().max(self.mp2_members.len());
        let mls = self.mls_status_snapshot();
        ActivePartySummary {
            party_id: self.party_id,
            party_epoch: self.party_epoch,
            leader_account_id: self.leader_account_id,
            leader_device_id: self.leader_device_id,
            visibility: self.visibility as u8,
            join_mode: self.join_mode as u8,
            relay_policy: self.relay_policy as u8,
            effective_relay_policy: self.effective_relay_policy as u8,
            pinned_relay_url: self.pinned_relay_url.clone(),
            max_members: self.max_members,
            member_count: u8::try_from(member_count).unwrap_or(u8::MAX),
            next_seq: self.ring.latest_seq(),
            daemon_epoch: self.ring.daemon_epoch,
            room_code: self.room_code.clone(),
            room_name: self.room_name.clone(),
            share_url: self.share_url.clone(),
            e2ee_mode: mls.e2ee_mode,
            mls_epoch: mls.mls_epoch,
            trust_tier: mls.trust_tier,
            has_declared_agent: mls.has_declared_agent,
            epoch_authenticator_b32: mls.epoch_authenticator_b32,
            clone_detected: mls.clone_detected,
        }
    }

    fn push_event(&mut self, body: PartyEventBody) -> u64 {
        self.push_event_with_catchup(body, false)
    }

    fn push_event_with_catchup(&mut self, body: PartyEventBody, is_historical_catchup: bool) -> u64 {
        let seq = self.ring.push_with_catchup(body, is_historical_catchup);
        self.wait_notify.notify_waiters();
        seq
    }

    fn record_sent_mp2_msg_id(&mut self, id: String) {
        while self.sent_mp2_msg_ids.len() >= MAX_TRACKED_MP2_MSG_IDS {
            let _ = self.sent_mp2_msg_ids.pop_front();
        }
        self.sent_mp2_msg_ids.push_back(id);
    }

    fn mark_mp2_seq_seen(&mut self, seq: u64) -> bool {
        if self.mp2_seen_seqs.iter().any(|&seen| seen == seq) {
            return false;
        }
        while self.mp2_seen_seqs.len() >= MAX_TRACKED_MP2_MSG_IDS {
            let _ = self.mp2_seen_seqs.pop_front();
        }
        self.mp2_seen_seqs.push_back(seq);
        if seq > self.mp2_last_seq {
            self.mp2_last_seq = seq;
        }
        true
    }
}

struct DaemonRuntimeState {
    device: DeviceRecord,
    cwt_expires_ms: u64,
    control: ControlClient,
    peers: PeersStoreRecord,
    epochs: EpochFloorStore,
    own_handle: String,
    control_ws_connected: bool,
    dual_host_churn_alert: bool,
    friends: HashMap<u64, FriendItem>,
    handle_cache: HashMap<u64, String>,
    dedupe: DedupeCache,
    active_party: Option<ActivePartySession>,
}

/// Complete `mp-outpost` daemon engine implementing `outpost_daemon::DaemonHandler`.
pub struct AppDaemon {
    state_dir_path: PathBuf,
    device_id: u64,
    strict_pins: bool,
    exe_path: String,
    cached_daemon_epoch: AtomicU64,
    active_party_atomic: AtomicU64,
    bg_started: AtomicBool,
    connected_clients_count: AtomicUsize,
    unattended_cancel: StdMutex<Option<CancellationToken>>,
    party_transition: Arc<Mutex<()>>,
    inner: Arc<Mutex<DaemonRuntimeState>>,
    shutdown: CancellationToken,
}

impl AppDaemon {
    #[cfg(test)]
    pub fn load(
        state_dir_path: PathBuf,
        runtime_dir_override: Option<PathBuf>,
        device_id: u64,
    ) -> Result<Arc<Self>, String> {
        let env_strict = std::env::var("OUTPOST_STRICT_PINS")
            .ok()
            .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"));
        Self::load_with_options(state_dir_path, runtime_dir_override, device_id, env_strict)
    }

    pub fn load_with_options(
        state_dir_path: PathBuf,
        _runtime_dir_override: Option<PathBuf>,
        device_id: u64,
        strict_pins: bool,
    ) -> Result<Arc<Self>, String> {
        let env_strict = std::env::var("OUTPOST_STRICT_PINS")
            .ok()
            .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"));
        let effective_strict = strict_pins || env_strict;
        let state_dir = open_state_dir(&state_dir_path)?;
        let _lock = lock_state(&state_dir)?;
        let device = load_device_record(&state_dir_path, device_id)?;
        let peers = load_peers_store(&state_dir)?;
        let epochs_rec = load_epochs_store(&state_dir)?;
        let epochs = EpochFloorStore::from_record(epochs_rec);

        let cwt_expires_ms = extract_cwt_expiry_ms(&device);
        let control = build_device_control_client(&device)?;

        let mut handle_cache = HashMap::new();
        for p in &peers.peers {
            if !p.handle_prop.is_empty() {
                handle_cache.insert(p.account_id, p.handle_prop.clone());
            }
        }

        let exe_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_else(|| "mp-outpost".to_string());

        let runtime_state = DaemonRuntimeState {
            device,
            cwt_expires_ms,
            control,
            peers,
            epochs,
            own_handle: String::new(),
            control_ws_connected: false,
            dual_host_churn_alert: false,
            friends: HashMap::new(),
            handle_cache,
            dedupe: DedupeCache::new(),
            active_party: None,
        };

        let daemon = Arc::new(Self {
            state_dir_path,
            device_id,
            strict_pins: effective_strict,
            exe_path,
            cached_daemon_epoch: AtomicU64::new(0),
            active_party_atomic: AtomicU64::new(0),
            bg_started: AtomicBool::new(false),
            connected_clients_count: AtomicUsize::new(0),
            unattended_cancel: StdMutex::new(None),
            party_transition: Arc::new(Mutex::new(())),
            inner: Arc::new(Mutex::new(runtime_state)),
            shutdown: CancellationToken::new(),
        });

        Ok(daemon)
    }

    const fn send_trust_policy(&self) -> SendTrustPolicy {
        if self.strict_pins {
            SendTrustPolicy::StrictManualPins
        } else {
            SendTrustPolicy::AllowUnpinnedAuthenticated
        }
    }

    /// Starts background control-plane Account WS & silent CWT auto-renewal once after
    /// `daemon.lock` is held and `daemon_epoch` is assigned (never before!).
    pub fn start_background_tasks(self: &Arc<Self>) {
        if self.bg_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.run_account_ws_loop().await;
        });
        let this_renew = Arc::clone(self);
        tokio::spawn(async move {
            this_renew.run_cwt_auto_renew_loop().await;
        });
    }

    async fn run_cwt_auto_renew_loop(self: Arc<Self>) {
        let _ = self.maybe_renew_cwt_silently().await;
        let mut iv = tokio::time::interval(CWT_AUTO_RENEW_CHECK_INTERVAL);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        iv.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return,
                _ = iv.tick() => {
                    let _ = self.maybe_renew_cwt_silently().await;
                }
            }
        }
    }

    /// Silently renews the local ephemeral device CWT via `POST /v1/devices/me/renew`
    /// whenever `< 3` days remain (`ROOM_PROTOCOL_V2.md` §4.3).
    pub(crate) async fn maybe_renew_cwt_silently(&self) -> bool {
        let now_ms = wall_now_ms();
        let (control, root_pubkey, device_pubkey, needs_renew) = {
            let st = self.inner.lock().await;
            let remaining = st.cwt_expires_ms.saturating_sub(now_ms);
            (
                st.control.clone(),
                st.device.root_pubkey,
                st.device.device_pubkey,
                remaining < CWT_AUTO_RENEW_THRESHOLD_MS,
            )
        };
        if !needs_renew {
            return false;
        }

        let Ok(resp) = control.renew_my_device().await else {
            return false;
        };
        if resp.device_id != self.device_id {
            log_line("ignoring /v1/devices/me/renew response with mismatched device_id");
            return false;
        }
        let Ok(new_cwt) = B64.decode(resp.device_cwt_b64.as_bytes()) else {
            return false;
        };
        let adjusted_now_ms = i128::from(wall_now_ms())
            .saturating_add(i128::from(control.clock_offset_ms()))
            .max(0);
        let adjusted_now_s =
            i64::try_from(adjusted_now_ms / 1000).unwrap_or_else(|_| wall_now_secs());
        let Ok(claims) = verify_device_cwt(
            &new_cwt,
            &root_pubkey,
            Some(&device_pubkey),
            adjusted_now_s,
        ) else {
            log_line("ignoring invalid device_cwt returned by /v1/devices/me/renew");
            return false;
        };

        let new_exp_ms = u64::try_from(claims.exp.max(0))
            .unwrap_or(0)
            .saturating_mul(1000)
            .max(resp.cwt_expires_ms);

        let updated_dev = {
            let mut st = self.inner.lock().await;
            st.device.device_cwt = new_cwt;
            st.cwt_expires_ms = new_exp_ms;
            st.device.clone()
        };

        let state_dir_path = self.state_dir_path.clone();
        let persist = tokio::task::spawn_blocking(move || {
            let state_dir = open_state_dir(&state_dir_path)?;
            let lock = lock_state(&state_dir)?;
            save_device_record(&state_dir_path, &lock, &updated_dev)
        })
        .await;
        if let Ok(Ok(())) = persist {
            log_line("silently renewed device CWT via /v1/devices/me/renew");
            true
        } else {
            false
        }
    }

    fn daemon_epoch(&self) -> u64 {
        self.cached_daemon_epoch.load(Ordering::Acquire)
    }

    fn cancel_unattended_timer(&self) {
        let mut guard = self
            .unattended_cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tok) = guard.take() {
            tok.cancel();
        }
    }

    /// Implements Spec §5.2 unattended-party policy:
    /// - When client count drops to `0` while in an active party, immediately emit Lane 2
    ///   `ephemeral_pulse(Idle, "unattended")` to connected peers and arm a 30-minute
    ///   sleep-aware timer that cleanly detaches from the party so `ControlPersist` idle exit
    ///   can reclaim the daemon.
    /// - When client count becomes `> 0`, cancel any armed unattended timer immediately.
    fn handle_client_count_changed(self: &Arc<Self>, count: usize) {
        self.connected_clients_count.store(count, Ordering::Release);
        if count > 0 {
            self.cancel_unattended_timer();
            return;
        }
        let active_pid = self.active_party_atomic.load(Ordering::Acquire);
        if active_pid == 0 {
            return;
        }
        let tok = {
            let mut guard = self
                .unattended_cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.is_some() {
                return;
            }
            let t = CancellationToken::new();
            *guard = Some(t.clone());
            t
        };

        let this = Arc::clone(self);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                // 1. Immediately send Lane 2 Idle pulse to all connected admitted P2P peers (if P2P active).
                let pulse_targets: Option<(Arc<PartyP2pHandle>, Vec<[u8; 32]>)> = {
                    let st = this.inner.lock().await;
                    st.active_party
                        .as_ref()
                        .filter(|s| s.party_id == active_pid)
                        .and_then(|sess| {
                            let p2p = sess.p2p.as_ref()?;
                            let pks: Vec<[u8; 32]> = sess
                                .members
                                .values()
                                .filter(|m| {
                                    m.record.device_id.get() != this.device_id
                                        && m.admitted
                                        && p2p.is_peer_connected(&m.record.device_pubkey)
                                })
                                .map(|m| m.record.device_pubkey)
                                .collect();
                            Some((Arc::clone(p2p), pks))
                        })
                };
                if let Some((p2p, pks)) = pulse_targets {
                    let pulse = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
                        activity_state: P2pActivityState::Idle,
                        timestamp_ns: now_unix_ns(),
                        status: "unattended".to_string(),
                    });
                    for pk in pks {
                        let _ = p2p.send_frame(pk, &pulse).await;
                    }
                }

                // 2. Sleep-aware 30-minute auto-detach watchdog (polled every 5s so
                //    elapsed sleep duration is caught immediately on wake).
                let start_ms = sleep_aware_now_ms();
                loop {
                    tokio::select! {
                        biased;
                        _ = tok.cancelled() => return,
                        _ = this.shutdown.cancelled() => return,
                        _ = tokio::time::sleep(UNATTENDED_POLL_INTERVAL) => {}
                    }
                    if this.connected_clients_count.load(Ordering::Acquire) > 0 {
                        this.cancel_unattended_timer();
                        return;
                    }
                    if this.active_party_atomic.load(Ordering::Acquire) != active_pid {
                        this.cancel_unattended_timer();
                        return;
                    }
                    if sleep_aware_now_ms().saturating_sub(start_ms) >= UNATTENDED_DETACH_MS {
                        let _tx = this.party_transition.lock().await;
                        if this.connected_clients_count.load(Ordering::Acquire) == 0
                            && this.active_party_atomic.load(Ordering::Acquire) == active_pid
                        {
                            log_line(&format!(
                                "unattended party {active_pid} exceeded 30m with 0 clients; detaching"
                            ));
                            this.teardown_active_party(active_pid, "unattended_timeout")
                                .await;
                        }
                        this.cancel_unattended_timer();
                        return;
                    }
                }
            });
        }
    }

    async fn run_account_ws_loop(self: Arc<Self>) {
        let mut churn = EvictionChurnDetector::new();
        let mut backoff_ms: u64 = 500;
        let mut had_session = false;

        // Best-effort initial `/v1/accounts/me` to learn own handle & reattach active party.
        {
            let control = {
                let st = self.inner.lock().await;
                st.control.clone()
            };
            if let Ok(me) = control.get_me().await {
                let reattach_pid = {
                    let mut st = self.inner.lock().await;
                    st.own_handle = me.handle;
                    if st.active_party.is_none() {
                        me.active_party_ids.first().copied()
                    } else {
                        None
                    }
                };
                if let Some(pid) = reattach_pid {
                    self.try_reattach_party(pid).await;
                }
            }
        }

        loop {
            if self.shutdown.is_cancelled() {
                break;
            }

            let control = {
                let st = self.inner.lock().await;
                st.control.clone()
            };

            match control.connect_ws(Mp1WsTarget::Account).await {
                Ok(mut ws) => {
                    backoff_ms = 500;
                    {
                        let mut st = self.inner.lock().await;
                        st.control_ws_connected = true;
                    }
                    let mut ping_iv = tokio::time::interval(WS_PING_INTERVAL);
                    ping_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    ping_iv.tick().await;

                    loop {
                        tokio::select! {
                            biased;
                            _ = self.shutdown.cancelled() => {
                                let _ = ws.close(1000, "shutdown").await;
                                return;
                            }
                            _ = ping_iv.tick() => {
                                if ws.silence_ms() > WS_RECONNECT_SILENCE_MS {
                                    let _ = ws.close(1000, "ping_timeout").await;
                                    break;
                                }
                                if ws.send_ping().await.is_err() {
                                    break;
                                }
                            }
                            ev = ws.next_event() => {
                                match ev {
                                    Ok(Some(Mp1WsEvent::Pong)) => {}
                                    Ok(Some(Mp1WsEvent::Closed { code, .. })) => {
                                        if matches!(code, Some(4401) | Some(4403)) {
                                            log_line(&format!(
                                                "Account WS closed with {code:?}; tearing down active party P2P"
                                            ));
                                            let active_pid =
                                                self.active_party_atomic.load(Ordering::Acquire);
                                            if active_pid != 0 {
                                                self.teardown_active_party(
                                                    active_pid,
                                                    "account_ws_closed_unauthorized",
                                                )
                                                .await;
                                            }
                                        }
                                        break;
                                    }
                                    Ok(None) | Err(_) => {
                                        break;
                                    }
                                    Ok(Some(Mp1WsEvent::Frame { message, .. })) => {
                                        self.handle_account_ws_message(
                                            message,
                                            &mut churn,
                                            had_session,
                                        )
                                        .await;
                                        had_session = true;
                                    }
                                }
                            }
                        }
                    }

                    {
                        let mut st = self.inner.lock().await;
                        st.control_ws_connected = false;
                    }
                }
                Err(WsConnectError::Terminal(code)) => {
                    // Device revoked or unauthorized — tear down active party P2P immediately
                    // and stop hammering control plane until reload.
                    {
                        let mut st = self.inner.lock().await;
                        st.control_ws_connected = false;
                    }
                    if matches!(code, 401 | 403) {
                        log_line(&format!(
                            "Account WS terminal HTTP {code}; tearing down active party P2P"
                        ));
                        let active_pid = self.active_party_atomic.load(Ordering::Acquire);
                        if active_pid != 0 {
                            self.teardown_active_party(
                                active_pid,
                                &format!("account_ws_terminal_http_{code}"),
                            )
                            .await;
                        }
                    }
                    tokio::select! {
                        _ = self.shutdown.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    }
                }
                Err(_) => {
                    let mut st = self.inner.lock().await;
                    st.control_ws_connected = false;
                }
            }

            tokio::select! {
                _ = self.shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
            }
            backoff_ms = (backoff_ms.saturating_mul(2)).min(10_000);
        }
    }

    async fn handle_account_ws_message(
        &self,
        msg: Mp1Message,
        churn: &mut EvictionChurnDetector,
        unexpected_reconnect: bool,
    ) {
        match msg {
            Mp1Message::HelloAck { session_id, .. } => {
                let status = churn.record_hello_ack(session_id, unexpected_reconnect);
                if matches!(status, ChurnStatus::DualHostChurnDetected { .. }) {
                    log_line("ALERT: dual_host_churn_detected on Account WS (device_id in use elsewhere); pausing party P2P with 4401");
                    let p2p = {
                        let mut st = self.inner.lock().await;
                        st.dual_host_churn_alert = true;
                        st.active_party
                            .as_ref()
                            .and_then(|s| s.p2p.as_ref().map(Arc::clone))
                    };
                    if let Some(p) = p2p {
                        p.set_allowed_peers_with_close_code(HashSet::new(), CLOSE_UNAUTHORIZED);
                    }
                }
            }
            Mp1Message::PresenceSnapshot { entries } => {
                let mut st = self.inner.lock().await;
                for entry in entries {
                    let acc = entry.account_id.get();
                    let handle = st.handle_cache.get(&acc).cloned().unwrap_or_default();
                    let item = st.friends.entry(acc).or_insert_with(|| FriendItem {
                        account_id: acc,
                        state: 0,
                        updated_at_ms: entry.updated_ms,
                        presence_status: entry.status as u8,
                        joinable_party_id: entry.joinable_party_id.map(PartyId::get),
                        handle,
                        safety_number: String::new(),
                    });
                    item.presence_status = entry.status as u8;
                    item.joinable_party_id = entry.joinable_party_id.map(PartyId::get);
                    item.updated_at_ms = entry.updated_ms;
                }
            }
            Mp1Message::PresenceDelta(entry) => {
                let mut st = self.inner.lock().await;
                let acc = entry.account_id.get();
                let handle = st.handle_cache.get(&acc).cloned().unwrap_or_default();
                let item = st.friends.entry(acc).or_insert_with(|| FriendItem {
                    account_id: acc,
                    state: 0,
                    updated_at_ms: entry.updated_ms,
                    presence_status: entry.status as u8,
                    joinable_party_id: entry.joinable_party_id.map(PartyId::get),
                    handle,
                    safety_number: String::new(),
                });
                item.presence_status = entry.status as u8;
                item.joinable_party_id = entry.joinable_party_id.map(PartyId::get);
                item.updated_at_ms = entry.updated_ms;
            }
            Mp1Message::SocialEvent {
                kind,
                peer_account_id,
            } => {
                let mut st = self.inner.lock().await;
                let acc = peer_account_id.get();
                match kind {
                    mp_protocol::SocialEventKind::Unfriended => {
                        st.friends.remove(&acc);
                    }
                    mp_protocol::SocialEventKind::FriendAccepted => {
                        let handle = st.handle_cache.get(&acc).cloned().unwrap_or_default();
                        st.friends.entry(acc).or_insert_with(|| FriendItem {
                            account_id: acc,
                            state: 0,
                            updated_at_ms: wall_now_ms(),
                            presence_status: 0,
                            joinable_party_id: None,
                            handle,
                            safety_number: String::new(),
                        });
                    }
                    mp_protocol::SocialEventKind::FriendRequest => {}
                }
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Party Lifecycle Helpers
    // -----------------------------------------------------------------------

    fn spawn_p2p_event_loop(
        self: &Arc<Self>,
        party_id: u64,
        mut event_stream: P2pEventStream,
        stop: CancellationToken,
    ) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => return,
                    _ = this.shutdown.cancelled() => return,
                    maybe_ev = event_stream.recv_event() => {
                        let Some(ev) = maybe_ev else {
                            return;
                        };
                        if let P2pTransportEvent::FrameReceived { peer_pubkey, frame, .. } = ev {
                            this.on_p2p_frame_received(party_id, peer_pubkey, frame).await;
                        }
                    }
                }
            }
        })
    }

    async fn on_p2p_frame_received(
        &self,
        party_id: u64,
        peer_pubkey: [u8; 32],
        frame: P2pPartyFrame,
    ) {
        let mut st = self.inner.lock().await;
        let Some(session) = st.active_party.as_mut() else {
            return;
        };
        if session.party_id != party_id {
            return;
        }
        // Strictly attribute exclusively from authenticated TLS 1.3 RPK `peer_pubkey`
        // bound through CWT!
        let Some(&dev_id) = session.pubkey_to_device.get(&peer_pubkey) else {
            let p2p = session.p2p.as_ref().map(Arc::clone);
            drop(st);
            if let Some(p) = p2p {
                p.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
            }
            return;
        };
        let Some(member) = session.members.get(&dev_id) else {
            let p2p = session.p2p.as_ref().map(Arc::clone);
            drop(st);
            if let Some(p) = p2p {
                p.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
            }
            return;
        };
        let trust_ok = if self.strict_pins {
            member.trust_state == TrustState::PinnedTrusted
        } else {
            member.trust_state != TrustState::RevokedBlocked
        };
        if !member.admitted || !trust_ok || member.key_mismatch {
            let p2p = session.p2p.as_ref().map(Arc::clone);
            drop(st);
            if let Some(p) = p2p {
                p.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
            }
            return;
        }

        let sender_account_id = member.record.account_id.get();
        let sender_device_id = member.record.device_id.get();
        let sender_handle = if !member.server_handle.is_empty() {
            member.server_handle.clone()
        } else {
            format!("account-{sender_account_id}")
        };

        let body = match frame {
            P2pPartyFrame::ChatMessage(chat) => {
                // NEVER trust wire `chat.sender_handle`! Always use verified `sender_handle`.
                PartyEventBody::Chat {
                    sender_account_id,
                    sender_device_id,
                    sender_handle,
                    is_browser: false,
                    sender_client: String::new(),
                    room_scope: chat.room_scope,
                    target_selector: chat.target_selector,
                    timestamp_ns: chat.timestamp_ns,
                    body: chat.body,
                }
            }
            P2pPartyFrame::BridgeEnvelope(env) => PartyEventBody::BridgeEnvelope {
                sender_account_id,
                sender_device_id,
                sender_handle,
                is_browser: false,
                sender_client: String::new(),
                room_scope: env.room_scope,
                payload: env.payload,
            },
            P2pPartyFrame::ControlNotice(notice) => PartyEventBody::ControlNotice {
                sender_account_id,
                sender_device_id,
                notice_kind: notice.kind as u8,
                party_epoch: notice.party_epoch,
                text: notice.text,
            },
            P2pPartyFrame::EphemeralPulse(_) => {
                // Ephemeral pulses are not stored in the causal ring buffer.
                return;
            }
        };

        let _ = session.push_event(body);
    }

    fn spawn_party_drivers(
        self: &Arc<Self>,
        party_id: u64,
        ws_stop: CancellationToken,
        mp2_rx: mpsc::Receiver<Mp2OutboundCmd>,
    ) -> (JoinHandle<()>, JoinHandle<()>) {
        let this_ws = Arc::clone(self);
        let stop_ws = ws_stop.clone();
        let ws_task = tokio::spawn(async move {
            this_ws.run_party_ws_loop(party_id, stop_ws, mp2_rx).await;
        });

        let this_cwt = Arc::clone(self);
        let stop_cwt = ws_stop;
        let cwt_task = tokio::spawn(async move {
            let mut iv = tokio::time::interval(CWT_SWEEP_INTERVAL);
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stop_cwt.cancelled() => return,
                    _ = iv.tick() => {
                        this_cwt.sweep_expired_cwts(party_id).await;
                    }
                }
            }
        });

        (ws_task, cwt_task)
    }

    async fn sweep_expired_cwts(&self, party_id: u64) {
        let now_s = wall_now_secs();
        let mut to_revoke: Vec<[u8; 32]> = Vec::new();
        let mut p2p_opt: Option<Arc<PartyP2pHandle>> = None;
        let mut local_expired = false;

        {
            let mut st = self.inner.lock().await;
            let local_cwt_invalid = !is_local_cwt_valid(&st.device, now_s);
            let local_dev_id = st.device.device_id;
            let local_dev_pk = st.device.device_pubkey;
            if local_cwt_invalid
                || (st.cwt_expires_ms > 0 && (st.cwt_expires_ms / 1000) <= now_s.max(0) as u64)
            {
                local_expired = true;
            }
            if let Some(session) = st.active_party.as_mut()
                && session.party_id == party_id
            {
                p2p_opt = session.p2p.as_ref().map(Arc::clone);
                let mut any_expired = false;
                for m in session.members.values_mut() {
                    if m.record.device_id.get() != local_dev_id
                        && m.admitted
                        && m.cwt_exp_s <= now_s
                    {
                        m.admitted = false;
                        to_revoke.push(m.record.device_pubkey);
                        any_expired = true;
                    }
                }
                if any_expired {
                    let dup_pks = rebuild_pubkey_to_device(
                        session,
                        local_dev_id,
                        local_dev_pk,
                        self.strict_pins,
                    );
                    to_revoke.extend(dup_pks);
                }
            }
        }

        if local_expired {
            log_line("local device CWT expired; closing party P2P with 4403 and tearing down party");
            if let Some(p2p) = p2p_opt {
                p2p.set_allowed_peers_with_close_code(HashSet::new(), CLOSE_PEER_REVOKED);
            }
            self.teardown_active_party(party_id, "local_cwt_expired")
                .await;
            return;
        }

        if let Some(p2p) = p2p_opt {
            for pk in to_revoke {
                p2p.revoke_peer(pk, CLOSE_PEER_REVOKED);
            }
        }
    }

    async fn run_party_ws_loop(
        self: Arc<Self>,
        party_id: u64,
        stop: CancellationToken,
        mut mp2_rx: mpsc::Receiver<Mp2OutboundCmd>,
    ) {
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let mut backoff_ms: u64 = 250;

        loop {
            if stop.is_cancelled() || self.shutdown.is_cancelled() {
                return;
            }

            let (control, ws_path, has_p2p, needs_mls_pre_ws, is_creator, has_ds_pk) = {
                let st = self.inner.lock().await;
                let Some(sess) = st.active_party.as_ref() else {
                    return;
                };
                if sess.party_id != party_id {
                    return;
                }
                let expected_path = format!("/v1/parties/{party_id}/ws");
                let path = if sess.ws_path.is_empty() || sess.ws_path == expected_path {
                    expected_path
                } else {
                    log_line(&format!(
                        "Party {party_id} rejecting unexpected mp2 ws_path; tearing down party"
                    ));
                    return;
                };
                let needs_mls = sess.e2ee_mode == 1 && sess.mls_session.is_none();
                (
                    st.control.clone(),
                    path,
                    sess.p2p.is_some(),
                    needs_mls,
                    sess.is_mls_creator,
                    sess.party_ds_pubkey.is_some(),
                )
            };

            if needs_mls_pre_ws {
                let ready = if is_creator && has_ds_pk {
                    match self.bootstrap_mls_creator_group(party_id).await {
                        Ok(true) => true,
                        Ok(false) => {
                            // Room already initialized on server (e.g. sibling device) -> join via KP/Welcome!
                            self.drive_mls_join_step(party_id).await.unwrap_or(false)
                        }
                        Err(e) => {
                            log_line(&format!("Party {party_id} MLS creator bootstrap failed: {e}"));
                            false
                        }
                    }
                } else {
                    match self.drive_mls_join_step(party_id).await {
                        Ok(joined) => joined,
                        Err(e) => {
                            log_line(&format!("Party {party_id} MLS join step error: {e}"));
                            false
                        }
                    }
                };
                if !ready {
                    // Wait briefly for Welcome delivery before retrying (do NOT dial /ws before
                    // membership is finalized in `party_mls_members`, which returns HTTP 404).
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = self.shutdown.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_millis(120)) => {}
                    }
                    continue;
                }
            }

            match control.connect_mp2_room_path(&ws_path).await {
                Ok(mut ws) => {
                    backoff_ms = 250;
                    {
                        let mut st = self.inner.lock().await;
                        if let Some(sess) = st.active_party.as_mut()
                            && sess.party_id == party_id
                        {
                            sess.mp2_connected = true;
                        }
                    }

                    let mut ping_iv = tokio::time::interval(WS_PING_INTERVAL);
                    ping_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    ping_iv.tick().await;
                    let mut mls_prune_iv = tokio::time::interval(MP_PAST_EPOCH_SWEEP_INTERVAL);
                    mls_prune_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    mls_prune_iv.tick().await;
                    let mut failover_rekey_deadline: Option<tokio::time::Instant> = None;
                    let mut ack_waiters: VecDeque<(
                        String,
                        oneshot::Sender<Result<Mp2Ack, String>>,
                    )> = VecDeque::new();

                    loop {
                        let rekey_sleep = async {
                            match failover_rekey_deadline {
                                Some(deadline) => tokio::time::sleep_until(deadline).await,
                                None => std::future::pending::<()>().await,
                            }
                        };
                        tokio::select! {
                            biased;
                            _ = stop.cancelled() => {
                                let _ = ws.close(1000, "party_stop").await;
                                return;
                            }
                            _ = self.shutdown.cancelled() => {
                                let _ = ws.close(1000, "daemon_shutdown").await;
                                return;
                            }
                            _ = rekey_sleep => {
                                failover_rekey_deadline = None;
                                self.submit_failover_rekey_commit(party_id).await;
                            }
                            maybe_cmd = mp2_rx.recv() => {
                                let Some(cmd) = maybe_cmd else {
                                    let _ = ws.close(1000, "channel_closed").await;
                                    return;
                                };
                                ack_waiters.retain(|(_, tx)| !tx.is_closed());
                                match cmd {
                                    Mp2OutboundCmd::Send {
                                        client_msg_id,
                                        kind,
                                        target,
                                        body_encoding,
                                        body,
                                        ack_tx,
                                    } => {
                                        match ws
                                            .send_event(
                                                &client_msg_id,
                                                kind,
                                                &target,
                                                &body_encoding,
                                                &body,
                                            )
                                            .await
                                        {
                                            Ok(()) => {
                                                ack_waiters.push_back((client_msg_id, ack_tx));
                                            }
                                            Err(e) => {
                                                let _ = ack_tx.send(Err(e.to_string()));
                                                break;
                                            }
                                        }
                                    }
                                    Mp2OutboundCmd::SendE2eeApp {
                                        client_msg_id,
                                        mls_epoch,
                                        body_b64,
                                        ack_tx,
                                    } => {
                                        match ws
                                            .send_e2ee_app(&client_msg_id, mls_epoch, &body_b64)
                                            .await
                                        {
                                            Ok(()) => {
                                                ack_waiters.push_back((client_msg_id, ack_tx));
                                            }
                                            Err(e) => {
                                                let _ = ack_tx.send(Err(e.to_string()));
                                                break;
                                            }
                                        }
                                    }
                                    Mp2OutboundCmd::SendE2eeEphemeral {
                                        client_msg_id,
                                        mls_epoch,
                                        body_b64,
                                    } => {
                                        if ws
                                            .send_e2ee_ephemeral(&client_msg_id, mls_epoch, &body_b64)
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Mp2OutboundCmd::Nick { nick } => {
                                        if ws.send_nick(&nick).await.is_err() {
                                            break;
                                        }
                                    }
                                    Mp2OutboundCmd::Topic { topic } => {
                                        if ws.send_topic(&topic).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            _ = mls_prune_iv.tick() => {
                                self.sweep_mls_past_epochs(party_id).await;
                            }
                            _ = ping_iv.tick() => {
                                ack_waiters.retain(|(_, tx)| !tx.is_closed());
                                if ws.silence_ms() > WS_RECONNECT_SILENCE_MS {
                                    let _ = ws.close(1000, "ping_timeout").await;
                                    break;
                                }
                                if ws.send_ping().await.is_err() {
                                    break;
                                }
                            }
                            ev = ws.next_event() => {
                                match ev {
                                    Ok(Some(Mp2RoomEvent::Pong)) => {}
                                    Ok(Some(Mp2RoomEvent::Hello(hello))) => {
                                        let hello_e2ee_mode = hello.e2ee_mode;
                                        let hello_rekey_required = hello.mls_rekey_required;
                                        let hello_mls_epoch = hello.mls_epoch;
                                        let hello_group_id_b64 = hello.group_id_b64.clone();
                                        ws.set_e2ee_mode(hello_e2ee_mode);
                                        let resume_seq = self.handle_mp2_hello(party_id, hello).await;
                                        if let Some(seq) = resume_seq
                                            && ws.send_resume(seq).await.is_err()
                                        {
                                            break;
                                        }
                                        if hello_e2ee_mode == 1 {
                                            // Ensure creator bootstrap or persisted snapshot restore + commit catch-up!
                                            let has_session = {
                                                let st = self.inner.lock().await;
                                                st.active_party
                                                    .as_ref()
                                                    .filter(|s| s.party_id == party_id)
                                                    .is_some_and(|s| s.mls_session.is_some())
                                            };
                                            if !has_session {
                                                if let Some(ref gid_b64) = hello_group_id_b64 {
                                                    let _ = self
                                                        .try_restore_persisted_mls_session(
                                                            party_id, gid_b64,
                                                        )
                                                        .await;
                                                } else {
                                                    let _ = self
                                                        .bootstrap_mls_creator_group(party_id)
                                                        .await;
                                                }
                                            }
                                            let local_epoch = {
                                                let st = self.inner.lock().await;
                                                st.active_party
                                                    .as_ref()
                                                    .filter(|s| s.party_id == party_id)
                                                    .and_then(|s| s.mls_session.as_ref())
                                                    .map(|m| m.epoch())
                                            };
                                            if let Some(cur_ep) = local_epoch {
                                                if hello_mls_epoch > cur_ep {
                                                    let flush_frames =
                                                        self.catchup_mls_commits(party_id).await;
                                                    for frame in flush_frames {
                                                        if ws
                                                            .send_e2ee_app(
                                                                &frame.client_msg_id,
                                                                frame.mls_epoch,
                                                                &frame.body_b64,
                                                            )
                                                            .await
                                                            .is_err()
                                                        {
                                                            break;
                                                        }
                                                    }
                                                }
                                                self.poll_pending_key_packages(party_id).await;
                                            }
                                            // Spec v3 §4.5: NEVER send clear `status` in `e2ee_mode == 1` rooms;
                                            // emit encrypted `e2ee_ephemeral` status instead when MLS session is ready.
                                            if let Some(prep) = self
                                                .prepare_e2ee_ephemeral_status(
                                                    party_id,
                                                    "Outpost",
                                                    "idle",
                                                    None,
                                                )
                                                .await
                                            {
                                                let _ = ws
                                                    .send_e2ee_ephemeral(
                                                        &prep.client_msg_id,
                                                        prep.mls_epoch,
                                                        &prep.body_b64,
                                                    )
                                                    .await;
                                            }
                                            if hello_rekey_required {
                                                self.fetch_and_apply_pending_proposals(party_id)
                                                    .await;
                                                if failover_rekey_deadline.is_none() {
                                                    failover_rekey_deadline = Some(
                                                        tokio::time::Instant::now()
                                                            + MP_FAILOVER_REKEY_DELAY,
                                                    );
                                                }
                                            }
                                        } else {
                                            let _ = ws
                                                .send_status("outpost", "Outpost", "idle", None)
                                                .await;
                                        }
                                    }
                                    Ok(Some(Mp2RoomEvent::Event(room_ev))) => {
                                        self.handle_mp2_event(party_id, room_ev).await;
                                    }
                                    Ok(Some(Mp2RoomEvent::EphemeralEvent {
                                        mls_epoch,
                                        body_encoding,
                                        body,
                                        ..
                                    })) => {
                                        self.handle_mp2_ephemeral_event(
                                            party_id,
                                            mls_epoch.unwrap_or(0),
                                            &body_encoding,
                                            &body,
                                        )
                                        .await;
                                    }
                                    Ok(Some(Mp2RoomEvent::MlsCommitTentative {
                                        target_epoch,
                                        committer_account_id,
                                        committer_device_id,
                                        commit_b64,
                                        proposal_blobs_b64,
                                        ..
                                    })) => {
                                        self.handle_mp2_mls_commit_tentative(
                                            party_id,
                                            target_epoch,
                                            committer_account_id,
                                            committer_device_id,
                                            &proposal_blobs_b64,
                                            &commit_b64,
                                        )
                                        .await;
                                    }
                                    Ok(Some(Mp2RoomEvent::MlsCommitFinalized {
                                        epoch,
                                        commit_b64,
                                        proposal_blobs_b64,
                                        ..
                                    })) => {
                                        failover_rekey_deadline = None;
                                        let flush_frames = self
                                            .handle_mp2_mls_commit_finalized(
                                                party_id,
                                                epoch,
                                                &proposal_blobs_b64,
                                                &commit_b64,
                                            )
                                            .await;
                                        for frame in flush_frames {
                                            if ws
                                                .send_e2ee_app(
                                                    &frame.client_msg_id,
                                                    frame.mls_epoch,
                                                    &frame.body_b64,
                                                )
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                    }
                                    Ok(Some(Mp2RoomEvent::MlsJoinRequest {
                                        account_id,
                                        device_id,
                                        invite_id,
                                        kp_ref_b64,
                                        kp_blob_b64,
                                        join_proof_b64,
                                        ..
                                    })) => {
                                        self.handle_mls_join_request(
                                            party_id,
                                            account_id,
                                            device_id,
                                            invite_id,
                                            &kp_ref_b64,
                                            &kp_blob_b64,
                                            join_proof_b64.as_deref(),
                                        )
                                        .await;
                                    }
                                    Ok(Some(Mp2RoomEvent::MlsCommitDiscarded { .. })) => {
                                        self.handle_mp2_mls_commit_discarded(party_id).await;
                                    }
                                    Ok(Some(Mp2RoomEvent::MlsRekeyNeeded {
                                        elected_committer_device_id,
                                        proposal_blobs_b64,
                                        ..
                                    })) => {
                                        self.handle_mp2_mls_rekey_needed(
                                            party_id,
                                            &proposal_blobs_b64,
                                        )
                                        .await;
                                        if elected_committer_device_id == Some(self.device_id) {
                                            failover_rekey_deadline = None;
                                            self.submit_failover_rekey_commit(party_id).await;
                                        } else {
                                            failover_rekey_deadline = Some(
                                                tokio::time::Instant::now()
                                                    + MP_FAILOVER_REKEY_DELAY,
                                            );
                                        }
                                    }
                                    Ok(Some(Mp2RoomEvent::MlsWelcomeReady {
                                        target_epoch,
                                        ..
                                    })) => {
                                        log_line(&format!(
                                            "Party {party_id} MLS welcome ready for local device at epoch {target_epoch}"
                                        ));
                                        let _ = self.poll_and_install_mls_welcome(party_id).await;
                                    }
                                    Ok(Some(Mp2RoomEvent::Ack(ack))) => {
                                        self.handle_mp2_ack(party_id, &ack.client_msg_id).await;
                                        ack_waiters.retain(|(_, tx)| !tx.is_closed());
                                        if let Some(pos) = ack_waiters
                                            .iter()
                                            .position(|(id, _)| id == &ack.client_msg_id)
                                            && let Some((_, tx)) = ack_waiters.remove(pos)
                                        {
                                            let _ = tx.send(Ok(ack));
                                        }
                                    }
                                    Ok(Some(Mp2RoomEvent::Presence { members })) => {
                                        self.handle_mp2_presence(party_id, members).await;
                                    }
                                    Ok(Some(Mp2RoomEvent::Error {
                                        code,
                                        message,
                                        retry_ms,
                                    })) => {
                                        ack_waiters.retain(|(_, tx)| !tx.is_closed());
                                        if code == "device_seq_rollback" {
                                            self.handle_mls_clone_detected(party_id).await;
                                        } else if code == "mls_epoch_stale" {
                                            let flush_frames =
                                                self.handle_mls_epoch_stale(party_id).await;
                                            for frame in flush_frames {
                                                let _ = ws
                                                    .send_e2ee_app(
                                                        &frame.client_msg_id,
                                                        frame.mls_epoch,
                                                        &frame.body_b64,
                                                    )
                                                    .await;
                                            }
                                        }
                                        let err_text = if let Some(ms) = retry_ms {
                                            format!("mp2 room error ({code}, retry_ms={ms}): {message}")
                                        } else {
                                            format!("mp2 room error ({code}): {message}")
                                        };
                                        log_line(&format!("Party {party_id} {err_text}"));
                                        let is_room_fatal = matches!(
                                            code.as_str(),
                                            "party_closed"
                                                | "room_closed"
                                                | "forbidden"
                                                | "unauthorized"
                                                | "banned"
                                                | "not_member"
                                        );
                                        if is_room_fatal {
                                            for (_, tx) in ack_waiters.drain(..) {
                                                let _ = tx.send(Err(err_text.clone()));
                                            }
                                        } else if let Some((_, tx)) = ack_waiters.pop_front() {
                                            let _ = tx.send(Err(err_text));
                                        }
                                    }
                                    Ok(Some(Mp2RoomEvent::Closed { code, .. })) => {
                                        if matches!(code, Some(4401) | Some(4403)) {
                                            self.teardown_active_party(
                                                party_id,
                                                "mp2_ws_closed_unauthorized",
                                            )
                                            .await;
                                            return;
                                        }
                                        break;
                                    }
                                    Ok(None) | Err(_) => {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    for (_, tx) in ack_waiters.drain(..) {
                        let _ = tx.send(Err("mp2 WebSocket disconnected before ack".to_string()));
                    }
                    {
                        let mut st = self.inner.lock().await;
                        if let Some(sess) = st.active_party.as_mut()
                            && sess.party_id == party_id
                        {
                            sess.mp2_connected = false;
                        }
                    }
                }
                Err(WsConnectError::MissingSubprotocol { .. }) if has_p2p => {
                    // Server speaks legacy `mp1` only (no `mp2` support); fall back cleanly.
                    self.run_legacy_mp1_party_ws_loop(pid, stop).await;
                    return;
                }
                Err(WsConnectError::Terminal(404)) => {
                    // On `e2ee_mode == 1` rooms where `/v1/rooms/enter` did not advertise `e2ee_mode`,
                    // `PartyDO` returns HTTP 404 on `/ws` until this device is added to `party_mls_members`.
                    // Probe `GET /v1/parties/:id/mls/welcome` once to detect an active E2EE room!
                    let probed_e2ee = if let Ok(wel) = control.mls_fetch_welcome(pid).await {
                        if let Some(ds_b64) = wel.party_ds_pubkey_b64
                            && let Some(ds_pk) = decode_ds_pubkey_b64(&ds_b64)
                        {
                            let mut st = self.inner.lock().await;
                            if let Some(sess) = st.active_party.as_mut()
                                && sess.party_id == party_id
                            {
                                sess.e2ee_mode = 1;
                                sess.party_ds_pubkey = Some(ds_pk);
                            }
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if probed_e2ee {
                        continue;
                    }
                    log_line(&format!(
                        "Party {party_id} mp2 WS terminal HTTP 404; tearing down party"
                    ));
                    self.teardown_active_party(party_id, "ws_terminal_http_404")
                        .await;
                    return;
                }
                Err(WsConnectError::Terminal(code)) => {
                    log_line(&format!(
                        "Party {party_id} mp2 WS terminal HTTP {code}; tearing down party"
                    ));
                    self.teardown_active_party(party_id, &format!("ws_terminal_http_{code}"))
                        .await;
                    return;
                }
                Err(_) => {
                    // Drain any waiting outbound sends so callers fail fast instead of hanging.
                    while let Ok(cmd) = mp2_rx.try_recv() {
                        match cmd {
                            Mp2OutboundCmd::Send { ack_tx, .. }
                            | Mp2OutboundCmd::SendE2eeApp { ack_tx, .. } => {
                                let _ = ack_tx.send(Err("reconnecting to party room...".to_string()));
                            }
                            Mp2OutboundCmd::SendE2eeEphemeral { .. }
                            | Mp2OutboundCmd::Nick { .. }
                            | Mp2OutboundCmd::Topic { .. } => {}
                        }
                    }
                }
            }

            tokio::select! {
                _ = stop.cancelled() => return,
                _ = self.shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
            }
            backoff_ms = (backoff_ms.saturating_mul(2)).min(5_000);
        }
    }

    async fn handle_mp2_hello(
        &self,
        party_id: u64,
        hello: outpost_control::Mp2Hello,
    ) -> Option<u64> {
        let mut st = self.inner.lock().await;
        if !hello.self_info.handle.is_empty() {
            st.own_handle = hello.self_info.handle.clone();
        }
        let prev_seq = st
            .active_party
            .as_ref()
            .filter(|s| s.party_id == party_id)
            .map_or(0, |s| s.mp2_last_seq);

        for m in &hello.members {
            if m.account_id > 0 && !m.is_guest && !m.handle.is_empty() {
                st.handle_cache.insert(m.account_id, m.handle.clone());
            }
        }
        let peers_clone = st.peers.clone();
        let auth_hash = api_authority_hash(&st.device.api_authority);

        if let Some(sess) = st.active_party.as_mut()
            && sess.party_id == party_id
        {
            if !hello.room_code.is_empty() {
                sess.room_code = hello.room_code;
            }
            if !hello.name.is_empty() {
                sess.room_name = hello.name;
            }
            sess.mp2_connected = true;
            sess.e2ee_mode = hello.e2ee_mode;
            sess.mls_epoch = hello.mls_epoch;
            sess.min_allowed_mls_epoch = sess
                .min_allowed_mls_epoch
                .max(hello.min_allowed_mls_epoch);
            sess.mls_rekey_required = hello.mls_rekey_required;
            sess.mls_invite_epoch = sess.mls_invite_epoch.max(hello.mls_invite_epoch);
            if hello.group_id_b64.is_some() {
                sess.group_id_b64 = hello.group_id_b64;
            }
            if let Some(ref ds_b64) = hello.party_ds_pubkey_b64
                && let Some(ds_pk) = decode_ds_pubkey_b64(ds_b64)
            {
                sess.party_ds_pubkey = Some(ds_pk);
            }
            if let Some(ref mut mls) = sess.mls_session {
                mls.set_min_allowed_mls_epoch(sess.min_allowed_mls_epoch);
                if hello.mls_rekey_required {
                    mls.set_mls_rekey_required(true);
                }
            }
            sess.mp2_members = hello.members.clone();
            update_mp2_provenance_cache(sess, &hello.members, auth_hash, &peers_clone);

            let earliest_history_seq = hello.history.first().map(|e| e.seq);
            let history_was_empty = hello.history.is_empty();
            for ev in hello.history {
                ingest_mp2_event_into_session(sess, ev, true);
            }
            // If we reconnected after having seen `prev_seq > 0`, check whether `hello.history`
            // left a gap between `prev_seq` and the earliest history event (or was empty while
            // `latest_seq > prev_seq`). Resume from `prev_seq` so no missed messages are dropped.
            if prev_seq > 0 {
                let has_gap_before_history =
                    earliest_history_seq.is_some_and(|first| first > prev_seq.saturating_add(1));
                if has_gap_before_history || (history_was_empty && hello.latest_seq > prev_seq) {
                    return Some(prev_seq);
                }
                if hello.latest_seq > sess.mp2_last_seq {
                    return Some(sess.mp2_last_seq);
                }
            } else if sess.mp2_last_seq < hello.latest_seq {
                sess.mp2_last_seq = hello.latest_seq;
            }
        }
        None
    }

    async fn handle_mp2_event(&self, party_id: u64, ev: Mp2Event) {
        let mut st = self.inner.lock().await;
        if !ev.sender.is_guest && !ev.sender.handle.is_empty() && ev.sender.account_id > 0 {
            st.handle_cache
                .insert(ev.sender.account_id, ev.sender.handle.clone());
        }
        if let Some(sess) = st.active_party.as_mut()
            && sess.party_id == party_id
        {
            if !ev.sender.is_guest && !ev.sender.handle.is_empty() && ev.sender.account_id > 0 {
                sess.provenance_by_account
                    .entry(ev.sender.account_id)
                    .and_modify(|p| p.handle = ev.sender.handle.clone())
                    .or_insert_with(|| CachedAccountProvenance {
                        handle: ev.sender.handle.clone(),
                        fingerprint: String::new(),
                        safety_number: String::new(),
                    });
            }
            let was_e2ee_app = sess.e2ee_mode == 1 && ev.kind != Mp2EventKind::System;
            ingest_mp2_event_into_session(sess, ev, false);
            if was_e2ee_app
                && let Some(ref mut mls) = sess.mls_session
                && let Ok(enc) = mls.export_encrypted_snapshot()
            {
                let _ = self.persist_mls_bytes_locked(party_id, &enc);
            }
        }
    }

    async fn handle_mp2_presence(&self, party_id: u64, members: Vec<Mp2Member>) {
        let mut st = self.inner.lock().await;
        for m in &members {
            if m.account_id > 0 && !m.is_guest && !m.handle.is_empty() {
                st.handle_cache.insert(m.account_id, m.handle.clone());
            }
        }
        let peers_clone = st.peers.clone();
        let auth_hash = api_authority_hash(&st.device.api_authority);
        if let Some(sess) = st.active_party.as_mut()
            && sess.party_id == party_id
        {
            sess.mp2_members = members.clone();
            update_mp2_provenance_cache(sess, &members, auth_hash, &peers_clone);
        }
    }

    fn persist_mls_bytes_locked(&self, party_id: u64, encrypted: &[u8]) -> Result<(), String> {
        let state_dir = open_state_dir(&self.state_dir_path)?;
        let lock = lock_state(&state_dir)?;
        save_mls_room_bytes(&self.state_dir_path, &lock, self.device_id, party_id, encrypted)
    }

    async fn handle_mp2_ack(&self, party_id: u64, client_msg_id: &str) {
        let mut st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_mut() else {
            return;
        };
        if sess.party_id != party_id {
            return;
        }
        if let Some(ref mut mls) = sess.mls_session {
            let _ = mls.ack_outbox(client_msg_id, |enc| {
                self.persist_mls_bytes_locked(party_id, enc)
            });
        }
    }

    async fn handle_mp2_ephemeral_event(
        &self,
        party_id: u64,
        _mls_epoch: u64,
        body_encoding: &str,
        body: &str,
    ) {
        let mut st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_mut() else {
            return;
        };
        if sess.party_id != party_id {
            return;
        }
        let Some(ref mut mls) = sess.mls_session else {
            return;
        };
        if let Ok(dec) = mls.decrypt_inbound_mp2(body_encoding, body, false)
            && !dec.is_duplicate
            && let DecryptedInboundPayload::EphemeralStatus(status) = dec.payload
        {
            apply_decrypted_ephemeral_status(sess, dec.auth_account_id, dec.auth_device_id, status);
        }
    }

    async fn prepare_e2ee_ephemeral_status(
        &self,
        party_id: u64,
        agent_name: &str,
        agent_state: &str,
        agent_summary: Option<&str>,
    ) -> Option<outpost_core::mls_session::PreparedOutboundE2ee> {
        let mut st = self.inner.lock().await;
        let sess = st.active_party.as_mut()?;
        if sess.party_id != party_id || sess.e2ee_mode != 1 {
            return None;
        }
        let mls = sess.mls_session.as_mut()?;
        let cid = format!("mp2-eph-{}-{}", self.device_id, wall_now_ms());
        let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
        mls.prepare_outbound_ephemeral_status(
            &cid,
            agent_name,
            agent_state,
            agent_summary,
            now_s,
            |enc| self.persist_mls_bytes_locked(party_id, enc),
        )
        .ok()
    }

    async fn handle_mp2_mls_commit_tentative(
        &self,
        party_id: u64,
        commit_epoch: u64,
        committer_account_id: u64,
        committer_device_id: u64,
        proposals_b64: &[String],
        commit_b64: &str,
    ) {
        if committer_device_id == self.device_id {
            return;
        }
        let Ok(commit_bytes) = B64.decode(commit_b64.as_bytes()) else {
            return;
        };
        let mut proposal_blobs = Vec::with_capacity(proposals_b64.len());
        for p in proposals_b64 {
            if let Ok(b) = B64.decode(p.as_bytes()) {
                proposal_blobs.push(b);
            }
        }
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let (control, ack_req) = {
            let mut st = self.inner.lock().await;
            let local_account_id = st.device.account_id;
            if committer_account_id != 0 && committer_account_id == local_account_id {
                return;
            }
            let control = st.control.clone();
            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            let Some(ref mut mls) = sess.mls_session else {
                return;
            };
            let Ok(ack) = mls.handle_tentative_commit(&proposal_blobs, &commit_bytes) else {
                return;
            };
            let req = MlsCommitAckRequest {
                group_id_b64: B64.encode(ack.group_id),
                parent_epoch: ack.parent_epoch,
                target_epoch: ack.target_epoch,
                commit_sha256_b64: B64.encode(ack.commit_sha256),
                status: ack.status as u8,
                epoch_auth_hash_b64: ack.epoch_auth_hash.map(|h| B64.encode(h)),
                ack_sig_b64: B64.encode(ack.ack_sig),
            };
            (control, req)
        };
        if let Err(e) = control.mls_submit_ack(pid, &ack_req).await {
            log_line(&format!(
                "Party {party_id} POST /mls/ack failed for epoch {commit_epoch}: {e}"
            ));
        }
    }

    async fn handle_mp2_mls_commit_finalized(
        &self,
        party_id: u64,
        commit_epoch: u64,
        proposals_b64: &[String],
        commit_b64: &str,
    ) -> Vec<outpost_core::mls_session::PreparedOutboundE2ee> {
        let local_epoch = {
            let st = self.inner.lock().await;
            st.active_party
                .as_ref()
                .filter(|s| s.party_id == party_id)
                .and_then(|s| s.mls_session.as_ref())
                .map(|m| m.epoch())
        };
        if let Some(cur) = local_epoch {
            if commit_epoch <= cur {
                return Vec::new();
            }
            if commit_epoch > cur.saturating_add(1) {
                return self.catchup_mls_commits(party_id).await;
            }
        }
        self.apply_finalized_mls_commit_single(party_id, commit_epoch, proposals_b64, commit_b64)
            .await
    }

    async fn apply_finalized_mls_commit_single(
        &self,
        party_id: u64,
        commit_epoch: u64,
        proposals_b64: &[String],
        commit_b64: &str,
    ) -> Vec<outpost_core::mls_session::PreparedOutboundE2ee> {
        let Ok(commit_bytes) = B64.decode(commit_b64.as_bytes()) else {
            return Vec::new();
        };
        let mut proposal_blobs = Vec::with_capacity(proposals_b64.len());
        for p in proposals_b64 {
            if let Ok(b) = B64.decode(p.as_bytes()) {
                proposal_blobs.push(b);
            }
        }
        let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
        let mut st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_mut() else {
            return Vec::new();
        };
        if sess.party_id != party_id {
            return Vec::new();
        }
        sess.mls_epoch = sess.mls_epoch.max(commit_epoch);
        let Some(ref mut mls) = sess.mls_session else {
            return Vec::new();
        };
        if commit_epoch <= mls.epoch() {
            return Vec::new();
        }
        if let Err(e) = mls.handle_finalized_commit(&proposal_blobs, &commit_bytes, now_s) {
            log_line(&format!(
                "Party {party_id} failed to merge finalized MLS commit epoch {commit_epoch}: {e}"
            ));
            return Vec::new();
        }
        sess.mls_epoch = mls.epoch();
        sess.mls_rekey_required = mls.mls_rekey_required();
        if let Ok(enc) = mls.export_encrypted_snapshot() {
            let _ = self.persist_mls_bytes_locked(party_id, &enc);
        }
        let stale_ids = mls.stale_outbox_client_msg_ids();
        let mut flushed = Vec::new();
        for cid in stale_ids {
            if let Ok(prep) = mls.requeue_stale_outbox_entry(&cid, now_s, |enc| {
                self.persist_mls_bytes_locked(party_id, enc)
            }) {
                flushed.push(prep);
            }
        }
        flushed
    }

    async fn handle_mp2_mls_rekey_needed(&self, party_id: u64, proposals_b64: &[String]) {
        let mut proposal_blobs = Vec::with_capacity(proposals_b64.len());
        for p in proposals_b64 {
            if let Ok(b) = B64.decode(p.as_bytes()) {
                proposal_blobs.push(b);
            }
        }
        let mut st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_mut() else {
            return;
        };
        if sess.party_id != party_id {
            return;
        }
        sess.mls_rekey_required = true;
        if let Some(ref mut mls) = sess.mls_session {
            mls.handle_rekey_needed(&proposal_blobs);
        }
    }

    async fn submit_failover_rekey_commit(&self, party_id: u64) {
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let (control, req) = {
            let mut st = self.inner.lock().await;
            let control = st.control.clone();
            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id || !sess.mls_rekey_required {
                return;
            }
            let Some(ref mut mls) = sess.mls_session else {
                return;
            };
            let parent_epoch = mls.epoch();
            let Ok(commit_bytes) = mls.build_failover_rekey_commit(None) else {
                return;
            };
            let req = MlsCommitRequest {
                parent_epoch,
                commit_b64: B64.encode(&commit_bytes),
                welcome_b64: None,
                welcome_auth_b64: None,
                joiner_device_id: None,
                welcomes: Vec::new(),
            };
            (control, req)
        };
        match control.mls_submit_commit(pid, &req).await {
            Ok(resp) if resp.is_finalized() => {
                let _ = self
                    .handle_mp2_mls_commit_finalized(
                        party_id,
                        resp.target_epoch,
                        &[],
                        &req.commit_b64,
                    )
                    .await;
            }
            Ok(_) => {}
            Err(e) => {
                log_line(&format!(
                    "Party {party_id} failover rekey commit submission failed: {e}"
                ));
                self.handle_mp2_mls_commit_discarded(party_id).await;
            }
        }
    }

    async fn submit_pcs_self_update_commit(&self, party_id: u64) {
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let (control, req) = {
            let mut st = self.inner.lock().await;
            let control = st.control.clone();
            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            let Some(ref mut mls) = sess.mls_session else {
                return;
            };
            if !mls.needs_pcs_self_update() {
                return;
            }
            let parent_epoch = mls.epoch();
            let Ok(commit_bytes) = mls.build_pcs_self_update_commit() else {
                return;
            };
            let req = MlsCommitRequest {
                parent_epoch,
                commit_b64: B64.encode(&commit_bytes),
                welcome_b64: None,
                welcome_auth_b64: None,
                joiner_device_id: None,
                welcomes: Vec::new(),
            };
            (control, req)
        };
        match control.mls_submit_commit(pid, &req).await {
            Ok(resp) if resp.is_finalized() => {
                let _ = self
                    .handle_mp2_mls_commit_finalized(
                        party_id,
                        resp.target_epoch,
                        &[],
                        &req.commit_b64,
                    )
                    .await;
            }
            Ok(_) => {}
            Err(e) => {
                log_line(&format!(
                    "Party {party_id} PCS self-Update commit failed: {e}"
                ));
                self.handle_mp2_mls_commit_discarded(party_id).await;
            }
        }
    }

    async fn handle_mls_epoch_stale(
        &self,
        party_id: u64,
    ) -> Vec<outpost_core::mls_session::PreparedOutboundE2ee> {
        let Ok(pid) = PartyId::new(party_id) else {
            return Vec::new();
        };
        let (control, from_epoch) = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return Vec::new();
            };
            if sess.party_id != party_id {
                return Vec::new();
            }
            let cur = sess.mls_session.as_ref().map_or(sess.mls_epoch, |m| m.epoch());
            (st.control.clone(), cur.saturating_add(1))
        };
        let Ok(page) = control.mls_fetch_commits(pid, from_epoch, 32).await else {
            return Vec::new();
        };
        let mut flushed = Vec::new();
        for rec in page.commits {
            let mut batch = self
                .handle_mp2_mls_commit_finalized(
                    party_id,
                    rec.epoch,
                    &rec.proposal_blobs_b64,
                    &rec.commit_b64,
                )
                .await;
            flushed.append(&mut batch);
        }
        flushed
    }

    async fn handle_mls_clone_detected(&self, party_id: u64) {
        let mut st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_mut() else {
            return;
        };
        if sess.party_id != party_id {
            return;
        }
        if let Some(ref mut mls) = sess.mls_session {
            mls.mark_clone_detected();
            if let Ok(enc) = mls.export_encrypted_snapshot() {
                let _ = self.persist_mls_bytes_locked(party_id, &enc);
            }
        }
    }

    async fn sweep_mls_past_epochs(&self, party_id: u64) {
        let mut st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_mut() else {
            return;
        };
        if sess.party_id != party_id {
            return;
        }
        let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
        if let Some(ref mut mls) = sess.mls_session
            && mls.prune_past_epochs(now_s).is_ok()
            && let Ok(enc) = mls.export_encrypted_snapshot()
        {
            let _ = self.persist_mls_bytes_locked(party_id, &enc);
        }
    }

    async fn handle_mp2_mls_commit_discarded(&self, party_id: u64) {
        let mut st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_mut() else {
            return;
        };
        if sess.party_id != party_id {
            return;
        }
        if let Some(ref mut mls) = sess.mls_session {
            let _ = mls.client_mut().discard_pending_commit();
        }
    }

    async fn load_local_mls_identity(
        &self,
        party_id: Option<u64>,
    ) -> Result<(DeviceIdentity, Vec<u8>, Vec<u8>), String> {
        let (account_id, device_id, root_pubkey, device_secret, device_pubkey, control) = {
            let st = self.inner.lock().await;
            (
                st.device.account_id,
                st.device.device_id,
                st.device.root_pubkey,
                Zeroizing::new(st.device.device_secret),
                st.device.device_pubkey,
                st.control.clone(),
            )
        };

        let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
        let cached = load_mls_device_identity(&self.state_dir_path, &device_secret, device_id)?;
        let (binding_bytes, mut list_bytes) = match cached {
            Some((b_bytes, l_bytes))
                if MpMlsDeviceBindingV1::decode_and_verify(&b_bytes)
                    .is_ok_and(|b| b.body.exp_s > now_s.saturating_add(3600)) =>
            {
                (b_bytes, l_bytes)
            }
            _ => {
                // Cloud-managed (`custody_mode = 0`) automatic 2-step MLS credential bootstrap
                // via `POST /v1/accounts/me/mls/cloud-bind`:
                //   Step 1: request deterministic `body_b64`, `root_sig_b64`, `pop_message_b64`.
                //   Verify `body` + `root_sig` + `pop_message == DEV_POP_DOMAIN_SEP || SHA-256(body || root_sig)`
                //   locally before signing `device_pop_sig` with `device_sk` (never blind-sign!).
                //   Step 2: submit `device_sig_b64` to receive finalized 236B `binding_b64` + `device_list_b64`.
                let device_sk = SigningKey::from_bytes(&device_secret);
                let iat_s = now_s;
                let exp_s = iat_s.saturating_add(mp_mls::identity::MAX_NATIVE_BINDING_TTL_S);
                let step1_req = outpost_control::MlsCloudBindRequest {
                    mls_sig_pubkey_b64: B64.encode(device_pubkey),
                    client_class: mp_mls::identity::ClientClass::Outpost as u8,
                    agent_capable: true,
                    iat_s,
                    exp_s,
                    device_sig_b64: None,
                };
                let step1_resp = control.mls_cloud_bind(&step1_req).await.map_err(|e| {
                    format!(
                        "local MLS identity not provisioned and cloud-bind step 1 failed: {e}"
                    )
                })?;

                let body_raw = B64
                    .decode(
                        step1_resp
                            .body_b64
                            .as_deref()
                            .ok_or_else(|| "cloud-bind step 1 missing body_b64".to_string())?
                            .as_bytes(),
                    )
                    .map_err(|_| "cloud-bind step 1 returned invalid body_b64".to_string())?;
                let root_sig_raw = B64
                    .decode(
                        step1_resp
                            .root_sig_b64
                            .as_deref()
                            .ok_or_else(|| "cloud-bind step 1 missing root_sig_b64".to_string())?
                            .as_bytes(),
                    )
                    .map_err(|_| "cloud-bind step 1 returned invalid root_sig_b64".to_string())?;
                let pop_msg_raw = B64
                    .decode(
                        step1_resp
                            .pop_message_b64
                            .as_deref()
                            .ok_or_else(|| {
                                "cloud-bind step 1 missing pop_message_b64".to_string()
                            })?
                            .as_bytes(),
                    )
                    .map_err(|_| "cloud-bind step 1 returned invalid pop_message_b64".to_string())?;

                let parsed_body = mp_mls::identity::MpMlsDeviceBindingBodyV1::decode(&body_raw)
                    .map_err(|e| format!("cloud-bind step 1 invalid binding body: {e}"))?;
                if parsed_body.account_id != account_id
                    || parsed_body.device_id != device_id
                    || parsed_body.root_pubkey != root_pubkey
                    || parsed_body.mls_sig_pubkey != device_pubkey
                    || parsed_body.custody_mode != mp_mls::identity::CustodyMode::CloudManaged
                {
                    return Err(
                        "cloud-bind step 1 binding body does not match local device identity"
                            .to_string(),
                    );
                }
                let root_sig: [u8; 64] = root_sig_raw
                    .try_into()
                    .map_err(|_| "cloud-bind step 1 root_sig must be 64 bytes".to_string())?;

                let mut bind_msg = Vec::with_capacity(
                    mp_mls::identity::DEV_BIND_DOMAIN_SEP.len() + body_raw.len(),
                );
                bind_msg.extend_from_slice(mp_mls::identity::DEV_BIND_DOMAIN_SEP);
                bind_msg.extend_from_slice(&body_raw);
                mp_mls::crypto::verify_ed25519_strict(&root_pubkey, &bind_msg, &root_sig)
                    .map_err(|e| format!("cloud-bind step 1 invalid root_sig: {e}"))?;

                let mut pop_hash_in = Vec::with_capacity(body_raw.len() + 64);
                pop_hash_in.extend_from_slice(&body_raw);
                pop_hash_in.extend_from_slice(&root_sig);
                let pop_digest = mp_mls::crypto::sha256(&pop_hash_in);
                let mut expected_pop_msg =
                    Vec::with_capacity(mp_mls::identity::DEV_POP_DOMAIN_SEP.len() + 32);
                expected_pop_msg.extend_from_slice(mp_mls::identity::DEV_POP_DOMAIN_SEP);
                expected_pop_msg.extend_from_slice(&pop_digest);
                if pop_msg_raw != expected_pop_msg {
                    return Err(
                        "cloud-bind step 1 pop_message_b64 mismatch (refusing blind PoP sign)"
                            .to_string(),
                    );
                }

                let device_pop_sig = mp_mls::crypto::sign_ed25519(&device_sk, &expected_pop_msg);
                let eff_iat_s = if step1_resp.iat_s > 0 {
                    step1_resp.iat_s
                } else {
                    iat_s
                };
                let eff_exp_s = if step1_resp.exp_s > 0 {
                    step1_resp.exp_s
                } else {
                    exp_s
                };
                let step2_req = outpost_control::MlsCloudBindRequest {
                    mls_sig_pubkey_b64: B64.encode(device_pubkey),
                    client_class: mp_mls::identity::ClientClass::Outpost as u8,
                    agent_capable: true,
                    iat_s: eff_iat_s,
                    exp_s: eff_exp_s,
                    device_sig_b64: Some(B64.encode(device_pop_sig)),
                };
                let step2_resp = control
                    .mls_cloud_bind(&step2_req)
                    .await
                    .map_err(|e| format!("cloud-bind step 2 failed: {e}"))?;

                let b_bytes = B64
                    .decode(
                        step2_resp
                            .binding_b64
                            .as_deref()
                            .ok_or_else(|| "cloud-bind step 2 missing binding_b64".to_string())?
                            .as_bytes(),
                    )
                    .map_err(|_| "cloud-bind step 2 returned invalid binding_b64".to_string())?;
                let l_bytes = B64
                    .decode(
                        step2_resp
                            .device_list_b64
                            .as_deref()
                            .ok_or_else(|| {
                                "cloud-bind step 2 missing device_list_b64".to_string()
                            })?
                            .as_bytes(),
                    )
                    .map_err(|_| {
                        "cloud-bind step 2 returned invalid device_list_b64".to_string()
                    })?;

                // Persist encrypted MLS identity locally (0600) so subsequent joins reuse it.
                if let Ok(sd) = open_state_dir(&self.state_dir_path)
                    && let Ok(lock) = lock_state(&sd)
                {
                    let _ = save_mls_device_identity(
                        &self.state_dir_path,
                        &lock,
                        &device_secret,
                        device_id,
                        &b_bytes,
                        &l_bytes,
                    );
                }
                (b_bytes, l_bytes)
            }
        };

        let binding = MpMlsDeviceBindingV1::decode_and_verify(&binding_bytes)
            .map_err(|e| format!("invalid local MLS device binding: {e}"))?;
        if binding.body.account_id != account_id
            || binding.body.device_id != device_id
            || binding.body.root_pubkey != root_pubkey
            || binding.body.mls_sig_pubkey != device_pubkey
        {
            return Err("local MLS device binding does not match enrolled device record".to_string());
        }

        // Best-effort refresh of own AccountDeviceListV1 from server if a newer list exists.
        let mut device_list = AccountDeviceListV1::decode(&list_bytes)
            .map_err(|e| format!("invalid local MLS device list: {e}"))?;
        device_list
            .verify(&root_pubkey)
            .map_err(|e| format!("local MLS device list signature invalid: {e}"))?;

        if let Ok(remote) = control.get_device_list().await
            && let Ok(remote_raw) = B64.decode(remote.device_list_b64.as_bytes())
            && let Ok(remote_list) = AccountDeviceListV1::decode(&remote_raw)
            && remote_list.account_id == account_id
            && remote_list.root_gen == binding.body.root_gen
            && remote_list.list_version > device_list.list_version
            && remote_list.verify(&root_pubkey).is_ok()
            && remote_list.authorizes_leaf(&binding.body)
        {
            list_bytes = remote_raw;
            device_list = remote_list;
            if let Ok(sd) = open_state_dir(&self.state_dir_path)
                && let Ok(lock) = lock_state(&sd)
            {
                let _ = save_mls_device_identity(
                    &self.state_dir_path,
                    &lock,
                    &device_secret,
                    device_id,
                    &binding_bytes,
                    &list_bytes,
                );
            }
        } else if let Some(pid_u64) = party_id
            && let Ok(pid) = PartyId::new(pid_u64)
            && let Ok(dls) = control.mls_fetch_device_lists(pid).await
        {
            for item in dls.device_lists {
                if item.account_id != account_id {
                    continue;
                }
                if let Ok(remote_raw) = B64.decode(item.device_list_b64.as_bytes())
                    && let Ok(remote_list) = AccountDeviceListV1::decode(&remote_raw)
                    && remote_list.account_id == account_id
                    && remote_list.root_gen == binding.body.root_gen
                    && remote_list.list_version > device_list.list_version
                    && remote_list.verify(&root_pubkey).is_ok()
                    && remote_list.authorizes_leaf(&binding.body)
                {
                    list_bytes = remote_raw;
                    device_list = remote_list;
                    if let Ok(sd) = open_state_dir(&self.state_dir_path)
                        && let Ok(lock) = lock_state(&sd)
                    {
                        let _ = save_mls_device_identity(
                            &self.state_dir_path,
                            &lock,
                            &device_secret,
                            device_id,
                            &binding_bytes,
                            &list_bytes,
                        );
                    }
                }
            }
        }

        let list_hash = device_list
            .list_hash()
            .map_err(|e| format!("failed hashing local MLS device list: {e}"))?;
        let cred = MpMlsLeafCredV1 {
            binding,
            list_version: device_list.list_version,
            list_hash,
        };
        let identity = DeviceIdentity::new(cred, device_list, SigningKey::from_bytes(&device_secret))
            .map_err(|e| format!("failed building MLS DeviceIdentity: {e}"))?;
        Ok((identity, binding_bytes, list_bytes))
    }

    async fn try_restore_persisted_mls_session(
        &self,
        party_id: u64,
        group_id_b64: &str,
    ) -> Result<bool, String> {
        let gid_raw = B64
            .decode(group_id_b64.as_bytes())
            .map_err(|_| "invalid group_id_b64".to_string())?;
        let group_id: [u8; MP_GROUP_ID_LEN] = gid_raw
            .try_into()
            .map_err(|_| "group_id_b64 must decode to 24 bytes".to_string())?;
        let device_secret = {
            let st = self.inner.lock().await;
            Zeroizing::new(st.device.device_secret)
        };
        let Some(snap) = load_mls_room_snapshot(
            &self.state_dir_path,
            &device_secret,
            self.device_id,
            party_id,
            &group_id,
        )?
        else {
            return Ok(false);
        };
        let (identity, _, _) = self.load_local_mls_identity(Some(party_id)).await?;
        let store_key = derive_mls_store_key(&device_secret, self.device_id);
        let session =
            MlsRoomSession::restore_from_snapshot(party_id, group_id, identity, *store_key, snap)
                .map_err(|e| format!("fail-closed MLS snapshot restore error: {e}"))?;

        let mut st = self.inner.lock().await;
        if let Some(sess) = st.active_party.as_mut()
            && sess.party_id == party_id
            && sess.mls_session.is_none()
        {
            sess.mls_epoch = session.epoch();
            sess.group_id_b64 = Some(B64.encode(session.group_id()));
            sess.mls_session = Some(session);
            return Ok(true);
        }
        Ok(false)
    }

    async fn bootstrap_mls_creator_group(&self, party_id: u64) -> Result<bool, String> {
        let pid = PartyId::new(party_id).map_err(|e| e.to_string())?;
        let (control, account_id, device_secret, ds_pubkey_opt) = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return Ok(false);
            };
            if sess.party_id != party_id {
                return Ok(false);
            }
            if sess.mls_session.is_some() {
                return Ok(true);
            }
            (
                st.control.clone(),
                st.device.account_id,
                Zeroizing::new(st.device.device_secret),
                sess.party_ds_pubkey,
            )
        };
        let Some(ds_pubkey) = ds_pubkey_opt else {
            return Ok(false);
        };

        let (identity, binding_bytes, list_bytes) =
            self.load_local_mls_identity(Some(party_id)).await?;

        let mut incarnation_nonce = [0u8; 8];
        fill_random(&mut incarnation_nonce).map_err(|e| format!("CSPRNG failure: {e}"))?;

        let policy = MpRoomPolicyExtV1 {
            version: 1,
            party_id,
            e2ee_mode: 1,
            require_self_custody: false,
            allow_browser_devices: true,
            org_id: 0,
            invite_epoch: 0,
            host_account_ids: vec![account_id],
            banned_account_ids: Vec::new(),
        };

        let (client, group_info_bytes) =
            MpMlsClient::create_room(party_id, incarnation_nonce, &ds_pubkey, policy, identity)
                .map_err(|e| format!("MpMlsClient::create_room failed: {e}"))?;
        let group_id = client.group_id();
        let group_id_b64 = B64.encode(group_id);

        let init_req = MlsInitRequest {
            group_id_b64: group_id_b64.clone(),
            group_info_b64: B64.encode(&group_info_bytes),
        };
        match control.mls_init_group(pid, &init_req).await {
            Ok(_) => {}
            Err(ControlError::Api {
                status: 409,
                ref error,
                ..
            }) if error == "mls_already_initialized" => {
                let mut st = self.inner.lock().await;
                if let Some(sess) = st.active_party.as_mut()
                    && sess.party_id == party_id
                {
                    sess.is_mls_creator = false;
                }
                return Ok(false);
            }
            Err(e) => return Err(format!("POST /v1/parties/{party_id}/mls/init failed: {e}")),
        }

        let store_key = derive_mls_store_key(&device_secret, self.device_id);
        let mut mls = MlsRoomSession::new(client, *store_key);
        mls.set_device_binding_and_list(binding_bytes, list_bytes);
        let enc = mls
            .export_encrypted_snapshot()
            .map_err(|e| format!("export initial MLS snapshot failed: {e}"))?;
        self.persist_mls_bytes_locked(party_id, &enc)?;

        let mut st = self.inner.lock().await;
        if let Some(sess) = st.active_party.as_mut()
            && sess.party_id == party_id
        {
            sess.e2ee_mode = 1;
            sess.mls_epoch = 0;
            sess.group_id_b64 = Some(group_id_b64);
            sess.is_mls_creator = false;
            sess.mls_session = Some(mls);
        }
        Ok(true)
    }

    async fn mint_mls_invite_for_active_party(&self, party_id: u64) -> Result<(u64, String), String> {
        let pid = PartyId::new(party_id).map_err(|e| e.to_string())?;
        let (control, group_id, invite_epoch, inviter_root_pk) = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return Err("no active party".to_string());
            };
            if sess.party_id != party_id {
                return Err("party not active".to_string());
            }
            let Some(ref mls) = sess.mls_session else {
                return Err("MLS session not initialized".to_string());
            };
            let policy = mls
                .client()
                .room_policy()
                .map_err(|e| format!("failed reading room policy: {e}"))?;
            (
                st.control.clone(),
                mls.group_id(),
                policy.invite_epoch,
                st.device.root_pubkey,
            )
        };

        let mut invite_seed = Zeroizing::new([0u8; 32]);
        fill_random(invite_seed.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let secrets = InviteSecrets::derive(&group_id, &invite_seed)
            .map_err(|e| format!("derive invite secrets failed: {e}"))?;
        let now_ms = wall_now_ms();
        let expires_at_ms = now_ms.saturating_add(3_600_000);
        let expires_at_s = expires_at_ms / 1_000;
        let max_uses = 8u32;

        let req = MlsCreateInviteRequest {
            server_token_hash_b64: B64.encode(secrets.server_token_hash),
            max_uses,
            expires_at_ms,
            invite_epoch: Some(invite_epoch),
        };
        let resp = control
            .mls_create_invite(pid, &req)
            .await
            .map_err(|e| format!("POST /v1/parties/{party_id}/mls/invites failed: {e}"))?;

        let effective_exp_s = if resp.expires_at_ms > 0 {
            resp.expires_at_ms / 1_000
        } else {
            expires_at_s
        };
        let frag = InviteFragmentV2 {
            group_id,
            invite_id: resp.invite_id,
            invite_epoch: resp.invite_epoch,
            expires_at_s: effective_exp_s,
            policy_bits: 0,
            inviter_root_pk,
            invite_seed: *invite_seed,
        };
        let frag_b64u = frag
            .encode_b64url()
            .map_err(|e| format!("encode InviteFragmentV2 failed: {e}"))?;

        let record = InviteRecordV1 {
            invite_id: resp.invite_id,
            invite_epoch: resp.invite_epoch,
            max_uses,
            expires_at_s: effective_exp_s,
            inviter_root_pk,
            member_join_mac_key: secrets.member_join_mac_key,
        };
        {
            let mut st = self.inner.lock().await;
            if let Some(sess) = st.active_party.as_mut()
                && sess.party_id == party_id
                && let Some(ref mut mls) = sess.mls_session
            {
                mls.register_active_invite(record);
            }
        }
        Ok((resp.invite_id, frag_b64u))
    }

    async fn drive_mls_join_step(&self, party_id: u64) -> Result<bool, String> {
        let pid = PartyId::new(party_id).map_err(|e| e.to_string())?;
        let (control, account_id, device_secret, existing_gid, already_submitted, invite_frag) = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return Ok(false);
            };
            if sess.party_id != party_id {
                return Ok(false);
            }
            if sess.mls_session.is_some() {
                return Ok(true);
            }
            (
                st.control.clone(),
                st.device.account_id,
                Zeroizing::new(st.device.device_secret),
                sess.group_id_b64.clone(),
                sess.pending_join_kp
                    .as_ref()
                    .is_some_and(|kp| kp.kp_submitted),
                sess.pending_invite_fragment.clone(),
            )
        };

        // First try restoring a persisted encrypted MLS snapshot if group_id is already known.
        if let Some(ref gid_b64) = existing_gid
            && self
                .try_restore_persisted_mls_session(party_id, gid_b64)
                .await
                .unwrap_or(false)
        {
            let _ = self.catchup_mls_commits(party_id).await;
            return Ok(true);
        }

        if !already_submitted {
            let (identity, _, _) = self.load_local_mls_identity(Some(party_id)).await?;
            let provider = MpCryptoProvider::new();
            let (kp_wire_bytes, kp_ref) = generate_single_use_key_package(&identity, &provider)
                .map_err(|e| format!("generate_single_use_key_package failed: {e}"))?;
            let provider_blob = provider
                .export_storage_binary()
                .map_err(|e| format!("export KP provider blob failed: {e}"))?;

            // Spec v3.1 §4.2.2: Persist single-use KeyPackage private bundle encrypted BEFORE upload!
            let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
            {
                let sd = open_state_dir(&self.state_dir_path)?;
                let lock = lock_state(&sd)?;
                save_mls_pending_key_package(
                    &self.state_dir_path,
                    &lock,
                    &device_secret,
                    self.device_id,
                    party_id,
                    PersistedKeyPackage {
                        kp_ref,
                        kp_wire_bytes: kp_wire_bytes.clone(),
                        provider_blob: provider_blob.clone(),
                        created_at_s: now_s,
                    },
                )?;
            }

            let join_req = if let Some(ref frag) = invite_frag {
                let secrets = frag
                    .derive_secrets()
                    .map_err(|e| format!("derive invite secrets failed: {e}"))?;
                let join_proof = compute_join_proof(
                    &secrets.member_join_mac_key,
                    &frag.group_id,
                    frag.invite_id,
                    frag.invite_epoch,
                    frag.expires_at_s,
                    account_id,
                    self.device_id,
                    &kp_ref,
                )
                .map_err(|e| format!("compute_join_proof failed: {e}"))?;
                MlsJoinRequest {
                    invite_id: Some(frag.invite_id),
                    server_invite_token_b64: Some(B64.encode(secrets.server_invite_token)),
                    kp_ref_b64: B64.encode(kp_ref),
                    kp_blob_b64: B64.encode(&kp_wire_bytes),
                    join_proof_b64: Some(B64.encode(join_proof)),
                }
            } else {
                MlsJoinRequest {
                    invite_id: None,
                    server_invite_token_b64: None,
                    kp_ref_b64: B64.encode(kp_ref),
                    kp_blob_b64: B64.encode(&kp_wire_bytes),
                    join_proof_b64: None,
                }
            };

            control
                .mls_submit_join(pid, &join_req)
                .await
                .map_err(|e| format!("POST /v1/parties/{party_id}/mls/join failed: {e}"))?;

            let mut st = self.inner.lock().await;
            if let Some(sess) = st.active_party.as_mut()
                && sess.party_id == party_id
            {
                sess.pending_join_kp = Some(PendingJoinKeyPackage {
                    kp_ref,
                    provider_blob,
                    kp_submitted: true,
                });
            }
        }

        self.poll_and_install_mls_welcome(party_id).await
    }

    async fn poll_and_install_mls_welcome(&self, party_id: u64) -> Result<bool, String> {
        let pid = PartyId::new(party_id).map_err(|e| e.to_string())?;
        let (control, device_secret, pending_kp_opt, known_ds_pk, invite_frag) = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return Ok(false);
            };
            if sess.party_id != party_id || sess.mls_session.is_some() {
                return Ok(sess.mls_session.is_some());
            }
            let kp = sess
                .pending_join_kp
                .as_ref()
                .map(|k| (k.kp_ref, k.provider_blob.clone()));
            (
                st.control.clone(),
                Zeroizing::new(st.device.device_secret),
                kp,
                sess.party_ds_pubkey,
                sess.pending_invite_fragment.clone(),
            )
        };

        let resp = control
            .mls_fetch_welcome(pid)
            .await
            .map_err(|e| format!("GET /v1/parties/{party_id}/mls/welcome failed: {e}"))?;

        let ds_pubkey_opt = resp
            .party_ds_pubkey_b64
            .as_deref()
            .and_then(decode_ds_pubkey_b64)
            .or(known_ds_pk);
        if let Some(ds_pk) = ds_pubkey_opt {
            let mut st = self.inner.lock().await;
            if let Some(sess) = st.active_party.as_mut()
                && sess.party_id == party_id
            {
                sess.party_ds_pubkey = Some(ds_pk);
            }
        }

        let (Some(welcome_b64), Some(welcome_auth_b64)) = (
            resp.resolved_welcome_b64(),
            resp.resolved_welcome_auth_b64(),
        ) else {
            return Ok(false);
        };
        let Some((expected_kp_ref, provider_blob)) = pending_kp_opt else {
            return Ok(false);
        };
        let Some(ds_pubkey) = ds_pubkey_opt else {
            return Err("Welcome arrived but party_ds_pubkey is unknown".to_string());
        };

        let welcome_bytes = B64
            .decode(welcome_b64.as_bytes())
            .map_err(|_| "invalid welcome_b64".to_string())?;
        let auth_bytes = B64
            .decode(welcome_auth_b64.as_bytes())
            .map_err(|_| "invalid welcome_auth_b64".to_string())?;
        let welcome_auth = WelcomeAuthV1::decode(&auth_bytes)
            .map_err(|e| format!("invalid WelcomeAuthV1: {e}"))?;

        let (identity, binding_bytes, list_bytes) =
            self.load_local_mls_identity(Some(party_id)).await?;
        let mut provider = MpCryptoProvider::import_storage_binary(&provider_blob)
            .map_err(|e| format!("restore KP provider failed: {e}"))?;

        let client = if let Some(ref frag) = invite_frag {
            let secrets = frag
                .derive_secrets()
                .map_err(|e| format!("derive invite secrets failed: {e}"))?;
            MpMlsClient::join_from_welcome(
                &welcome_bytes,
                &welcome_auth,
                &secrets.member_join_mac_key,
                &expected_kp_ref,
                frag.group_id,
                party_id,
                &ds_pubkey,
                frag.policy_bits,
                frag.invite_epoch,
                &frag.inviter_root_pk,
                identity,
                &mut provider,
            )
            .map_err(|e| format!("MpMlsClient::join_from_welcome failed: {e}"))?
        } else {
            MpMlsClient::join_from_welcome_sibling(
                &welcome_bytes,
                &welcome_auth,
                &expected_kp_ref,
                welcome_auth.group_id,
                party_id,
                &ds_pubkey,
                0,
                welcome_auth.invite_epoch,
                identity,
                &mut provider,
            )
            .map_err(|e| format!("MpMlsClient::join_from_welcome_sibling failed: {e}"))?
        };

        let store_key = derive_mls_store_key(&device_secret, self.device_id);
        let group_id = client.group_id();
        let target_epoch = client.epoch();
        let mut mls = MlsRoomSession::new(client, *store_key);
        mls.set_device_binding_and_list(binding_bytes, list_bytes);
        let enc = mls
            .export_encrypted_snapshot()
            .map_err(|e| format!("export post-Welcome MLS snapshot failed: {e}"))?;

        // Persist Welcome-installed group state atomically BEFORE acking Welcome to PartyDO (§4.2.4)!
        self.persist_mls_bytes_locked(party_id, &enc)?;
        if let Ok(sd) = open_state_dir(&self.state_dir_path)
            && let Ok(lock) = lock_state(&sd)
        {
            remove_mls_pending_key_package(&self.state_dir_path, &lock, self.device_id, party_id);
        }

        let ack_req = MlsWelcomeAckRequest {
            group_id_b64: B64.encode(group_id),
            target_epoch,
            kp_ref_b64: B64.encode(expected_kp_ref),
            welcome_id: resp.resolved_welcome_id(),
        };
        let _ = control.mls_ack_welcome(pid, &ack_req).await;

        {
            let mut st = self.inner.lock().await;
            if let Some(sess) = st.active_party.as_mut()
                && sess.party_id == party_id
            {
                sess.e2ee_mode = 1;
                sess.mls_epoch = target_epoch;
                sess.group_id_b64 = Some(B64.encode(group_id));
                sess.pending_join_kp = None;
                sess.mls_session = Some(mls);
            }
        }
        let _ = self.catchup_mls_commits(party_id).await;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_mls_join_request(
        &self,
        party_id: u64,
        joiner_account_id: u64,
        joiner_device_id: u64,
        invite_id: Option<u64>,
        kp_ref_b64: &str,
        kp_blob_b64: &str,
        join_proof_b64: Option<&str>,
    ) {
        // NEVER skip sibling devices of our own account_id — skip ONLY our exact device_id!
        if joiner_device_id == 0 || joiner_device_id == self.device_id {
            return;
        }
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let Ok(kp_bytes) = B64.decode(kp_blob_b64.as_bytes()) else {
            return;
        };
        let kp_ref_opt: Option<[u8; 32]> = B64
            .decode(kp_ref_b64.as_bytes())
            .ok()
            .and_then(|v| v.try_into().ok());

        // Best-effort refresh of account device lists before KeyPackage admission so newly
        // enrolled sibling devices are recognized in `DeviceListTracker`.
        let (control, local_account_id) = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return;
            };
            if sess.party_id != party_id || sess.mls_session.is_none() {
                return;
            }
            if let Some(ref kp_ref) = kp_ref_opt
                && sess.processed_kp_refs.contains(kp_ref)
            {
                return;
            }
            (st.control.clone(), st.device.account_id)
        };

        if let Ok(dls) = control.mls_fetch_device_lists(pid).await {
            let mut st = self.inner.lock().await;
            if let Some(sess) = st.active_party.as_mut()
                && sess.party_id == party_id
                && let Some(ref mut mls) = sess.mls_session
            {
                for item in dls.device_lists {
                    if let Ok(raw) = B64.decode(item.device_list_b64.as_bytes())
                        && let Ok(list) = AccountDeviceListV1::decode(&raw)
                    {
                        let _ = mls.client_mut().observe_device_list(list, None);
                    }
                }
            }
        }

        let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
        let commit_req_opt = {
            let mut st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            if let Some(ref kp_ref) = kp_ref_opt
                && sess.processed_kp_refs.contains(kp_ref)
            {
                return;
            }
            let Some(ref mut mls) = sess.mls_session else {
                return;
            };
            let parent_epoch = mls.epoch();

            let add_out_res = if let (Some(inv_id), Some(jp_b64)) = (invite_id, join_proof_b64)
                && let Ok(jp_raw) = B64.decode(jp_b64.as_bytes())
                && let Ok(jp_arr) = <[u8; 32]>::try_from(jp_raw)
            {
                mls.build_add_member_commit(&kp_bytes, inv_id, &jp_arr, now_s, false)
            } else if joiner_account_id == local_account_id {
                mls.build_add_sibling_device_commit(&kp_bytes, now_s)
            } else {
                return;
            };

            match add_out_res {
                Ok(out) => {
                    let welcome_auth_bytes = match out.welcome_auth.encode() {
                        Ok(b) => b,
                        Err(_) => {
                            let _ = mls.client_mut().discard_pending_commit();
                            return;
                        }
                    };
                    let eff_kp_ref_b64 = if kp_ref_b64.is_empty() {
                        B64.encode(out.welcome_auth.joiner_kp_ref)
                    } else {
                        kp_ref_b64.to_string()
                    };
                    sess.processed_kp_refs
                        .insert(out.welcome_auth.joiner_kp_ref);
                    let welcome_b64 = B64.encode(&out.welcome_bytes);
                    let welcome_auth_b64 = B64.encode(welcome_auth_bytes);
                    Some(MlsCommitRequest {
                        parent_epoch,
                        commit_b64: B64.encode(&out.commit_bytes),
                        welcome_b64: Some(welcome_b64.clone()),
                        welcome_auth_b64: Some(welcome_auth_b64.clone()),
                        joiner_device_id: Some(joiner_device_id),
                        welcomes: vec![MlsWelcomeEntry {
                            target_device_id: joiner_device_id,
                            kp_ref_b64: eff_kp_ref_b64,
                            welcome_blob_b64: welcome_b64,
                            welcome_auth_blob_b64: welcome_auth_b64,
                        }],
                    })
                }
                Err(e) => {
                    log_line(&format!(
                        "Party {party_id} skipped Add commit for device {joiner_device_id}: {e}"
                    ));
                    None
                }
            }
        };

        let Some(commit_req) = commit_req_opt else {
            return;
        };

        match control.mls_submit_commit(pid, &commit_req).await {
            Ok(resp) if resp.is_finalized() => {
                let _ = self
                    .handle_mp2_mls_commit_finalized(
                        party_id,
                        resp.target_epoch,
                        &[],
                        &commit_req.commit_b64,
                    )
                    .await;
            }
            Ok(_) => {}
            Err(e) => {
                log_line(&format!(
                    "Party {party_id} POST /mls/commit (Add device {joiner_device_id}) failed: {e}"
                ));
                let mut st = self.inner.lock().await;
                if let Some(sess) = st.active_party.as_mut()
                    && sess.party_id == party_id
                {
                    if let Some(ref kp_ref) = kp_ref_opt {
                        sess.processed_kp_refs.remove(kp_ref);
                    }
                    if let Some(ref mut mls) = sess.mls_session {
                        let _ = mls.client_mut().discard_pending_commit();
                    }
                }
            }
        }
    }

    async fn poll_pending_key_packages(&self, party_id: u64) {
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let control = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return;
            };
            if sess.party_id != party_id || sess.mls_session.is_none() {
                return;
            }
            st.control.clone()
        };
        let Ok(resp) = control.mls_fetch_pending_key_packages(pid).await else {
            return;
        };
        for item in resp.key_packages {
            self.handle_mls_join_request(
                party_id,
                item.account_id,
                item.device_id,
                item.invite_id,
                &item.kp_ref_b64,
                &item.kp_blob_b64,
                item.join_proof_b64.as_deref(),
            )
            .await;
        }
    }

    async fn fetch_and_apply_pending_proposals(&self, party_id: u64) {
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let control = {
            let st = self.inner.lock().await;
            st.control.clone()
        };
        if let Ok(resp) = control.mls_fetch_pending_proposals(pid).await
            && !resp.proposals_b64.is_empty()
        {
            self.handle_mp2_mls_rekey_needed(party_id, &resp.proposals_b64)
                .await;
        }
    }

    async fn catchup_mls_commits(
        &self,
        party_id: u64,
    ) -> Vec<outpost_core::mls_session::PreparedOutboundE2ee> {
        let Ok(pid) = PartyId::new(party_id) else {
            return Vec::new();
        };
        let mut flushed = Vec::new();
        for _ in 0..16 {
            let (control, from_epoch) = {
                let st = self.inner.lock().await;
                let Some(sess) = st.active_party.as_ref() else {
                    break;
                };
                if sess.party_id != party_id {
                    break;
                }
                let Some(ref mls) = sess.mls_session else {
                    break;
                };
                (st.control.clone(), mls.epoch().saturating_add(1))
            };
            let Ok(page) = control.mls_fetch_commits(pid, from_epoch, 32).await else {
                break;
            };
            if page.commits.is_empty() {
                break;
            }
            let page_len = page.commits.len();
            for rec in page.commits {
                let mut batch = self
                    .apply_finalized_mls_commit_single(
                        party_id,
                        rec.epoch,
                        &rec.proposal_blobs_b64,
                        &rec.commit_b64,
                    )
                    .await;
                flushed.append(&mut batch);
            }
            if page_len < 32 {
                break;
            }
        }
        flushed
    }

    async fn run_legacy_mp1_party_ws_loop(self: Arc<Self>, pid: PartyId, stop: CancellationToken) {
        let party_id = pid.get();
        let mut churn = EvictionChurnDetector::new();
        let mut backoff_ms: u64 = 250;
        let mut had_session = false;
        let mut last_confirmed_ms = sleep_aware_now_ms();
        let mut p2p_suspended_for_silence = false;

        loop {
            if stop.is_cancelled() || self.shutdown.is_cancelled() {
                return;
            }

            let (control, eff_policy, pinned_relay_url, p2p_handle) = {
                let st = self.inner.lock().await;
                let Some(sess) = st.active_party.as_ref() else {
                    return;
                };
                if sess.party_id != party_id {
                    return;
                }
                let Some(p2p) = sess.p2p.as_ref() else {
                    return;
                };
                (
                    st.control.clone(),
                    sess.effective_relay_policy,
                    sess.pinned_relay_url.clone(),
                    Arc::clone(p2p),
                )
            };

            match control.connect_ws(Mp1WsTarget::Party(pid)).await {
                Ok(mut ws) => {
                    backoff_ms = 250;
                    let mut coalescer = EndpointUpdateCoalescer::new(eff_policy);
                    let mut addr_watcher = p2p_handle.watch_addr();
                    let mut ping_iv = tokio::time::interval(WS_PING_INTERVAL);
                    ping_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    ping_iv.tick().await;

                    // Submit current sanitized descriptor if not ForceRelays.
                    if eff_policy != RelayPolicy::ForceRelays {
                        let raw_desc = p2p_handle.local_endpoint_descriptor();
                        let desc =
                            sanitize_endpoint_for_mp1(raw_desc, eff_policy, &pinned_relay_url);
                        if (!desc.direct_addrs.is_empty() || !desc.relay_url.is_empty())
                            && let Some(to_send) = coalescer.submit(desc)
                        {
                            let _ = ws.send_party_endpoint_update(to_send).await;
                        }
                    }

                    loop {
                        let coalescer_delay = coalescer.next_allowed_at_ms().map(|next_ms| {
                            Duration::from_millis(next_ms.saturating_sub(sleep_aware_now_ms()))
                        });
                        let has_coalescer_timer =
                            eff_policy != RelayPolicy::ForceRelays && coalescer_delay.is_some();
                        let coalescer_sleep =
                            tokio::time::sleep(coalescer_delay.unwrap_or(Duration::from_secs(3600)));
                        tokio::pin!(coalescer_sleep);

                        tokio::select! {
                            biased;
                            _ = stop.cancelled() => {
                                let _ = ws.close(1000, "party_stop").await;
                                return;
                            }
                            _ = self.shutdown.cancelled() => {
                                let _ = ws.close(1000, "daemon_shutdown").await;
                                return;
                            }
                            _ = &mut coalescer_sleep, if has_coalescer_timer => {
                                if let Some(to_send) = coalescer.poll_ready() {
                                    let _ = ws.send_party_endpoint_update(to_send).await;
                                }
                            }
                            roam = addr_watcher.updated(), if eff_policy != RelayPolicy::ForceRelays => {
                                if roam.is_ok() {
                                    let raw_desc = p2p_handle.local_endpoint_descriptor();
                                    let desc = sanitize_endpoint_for_mp1(
                                        raw_desc,
                                        eff_policy,
                                        &pinned_relay_url,
                                    );
                                    if (!desc.direct_addrs.is_empty() || !desc.relay_url.is_empty())
                                        && let Some(to_send) = coalescer.submit(desc)
                                    {
                                        let _ = ws.send_party_endpoint_update(to_send).await;
                                    }
                                }
                            }
                            _ = ping_iv.tick() => {
                                if ws.silence_ms() > WS_RECONNECT_SILENCE_MS {
                                    let _ = ws.close(1000, "ping_timeout").await;
                                    break;
                                }
                                if ws.send_ping().await.is_err() {
                                    break;
                                }
                                if let Some(to_send) = coalescer.poll_ready() {
                                    let _ = ws.send_party_endpoint_update(to_send).await;
                                }
                            }
                            ev = ws.next_event() => {
                                match ev {
                                    Ok(Some(Mp1WsEvent::Pong)) => {
                                        last_confirmed_ms = sleep_aware_now_ms();
                                    }
                                    Ok(Some(Mp1WsEvent::Closed { code, .. })) => {
                                        if matches!(code, Some(4401) | Some(4403)) {
                                            self.teardown_active_party(party_id, "ws_closed_unauthorized").await;
                                            return;
                                        }
                                        break;
                                    }
                                    Ok(None) | Err(_) => {
                                        break;
                                    }
                                    Ok(Some(Mp1WsEvent::Frame { message, .. })) => {
                                        last_confirmed_ms = sleep_aware_now_ms();
                                        p2p_suspended_for_silence = false;
                                        if let Mp1Message::Error(ref ef) = message
                                            && ef.retry_after_ms > 0
                                        {
                                            coalescer.record_retry_after(ef.retry_after_ms);
                                        }
                                        let terminal = self
                                            .handle_party_ws_message(
                                                party_id,
                                                message,
                                                &mut churn,
                                                had_session,
                                            )
                                            .await;
                                        had_session = true;
                                        if terminal {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(WsConnectError::Terminal(code)) => {
                    log_line(&format!(
                        "Party {party_id} WS terminal HTTP {code}; tearing down party"
                    ));
                    self.teardown_active_party(party_id, &format!("ws_terminal_http_{code}"))
                        .await;
                    return;
                }
                Err(_) => {}
            }

            // Sleep-aware 60s silence gate: close party P2P connections with 4401 until fresh snapshot.
            if !p2p_suspended_for_silence
                && sleep_aware_now_ms().saturating_sub(last_confirmed_ms) > WS_P2P_REVOKE_SILENCE_MS
            {
                p2p_suspended_for_silence = true;
                p2p_handle.set_allowed_peers_with_close_code(HashSet::new(), CLOSE_UNAUTHORIZED);
            }

            tokio::select! {
                _ = stop.cancelled() => return,
                _ = self.shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
            }
            backoff_ms = (backoff_ms.saturating_mul(2)).min(5_000);
        }
    }

    async fn handle_party_ws_message(
        self: &Arc<Self>,
        party_id: u64,
        msg: Mp1Message,
        churn: &mut EvictionChurnDetector,
        unexpected_reconnect: bool,
    ) -> bool {
        match msg {
            Mp1Message::HelloAck { session_id, .. } => {
                let status = churn.record_hello_ack(session_id, unexpected_reconnect);
                if matches!(status, ChurnStatus::DualHostChurnDetected { .. }) {
                    log_line("ALERT: dual_host_churn_detected on Party WS; pausing P2P with 4401");
                    let p2p = {
                        let mut st = self.inner.lock().await;
                        st.dual_host_churn_alert = true;
                        st.active_party
                            .as_ref()
                            .and_then(|s| s.p2p.as_ref().map(Arc::clone))
                    };
                    if let Some(p) = p2p {
                        p.set_allowed_peers_with_close_code(HashSet::new(), CLOSE_UNAUTHORIZED);
                    }
                }
                false
            }
            Mp1Message::PartySnapshot(snapshot) => {
                if snapshot.party_id.get() != party_id {
                    return false;
                }
                if let Err(err) = self
                    .check_and_persist_epoch(party_id, snapshot.party_epoch, false)
                    .await
                {
                    log_line(&format!("rejected PartySnapshot epoch floor check: {err}"));
                    return false;
                }
                self.apply_party_snapshot(snapshot).await
            }
            Mp1Message::PartyMemberJoined {
                party_epoch,
                member,
            } => {
                if let Err(err) = self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
                    log_line(&format!("rejected PartyMemberJoined epoch floor check: {err}"));
                    return false;
                }
                self.apply_member_joined(party_id, party_epoch, member).await;
                false
            }
            Mp1Message::PartyMemberUpdated {
                party_epoch,
                device_id,
                connected,
                device_cwt,
                endpoint,
            } => {
                if let Err(err) = self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
                    log_line(&format!(
                        "rejected PartyMemberUpdated epoch floor check: {err}"
                    ));
                    return false;
                }
                self.apply_member_updated(
                    party_id,
                    party_epoch,
                    device_id.get(),
                    connected,
                    device_cwt,
                    endpoint,
                )
                .await;
                false
            }
            Mp1Message::PartyMemberLeft {
                party_epoch,
                device_id,
                account_id,
                reason,
            } => {
                if let Err(err) = self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
                    log_line(&format!("rejected PartyMemberLeft epoch floor check: {err}"));
                    return false;
                }
                if device_id.get() == self.device_id {
                    self.teardown_active_party(party_id, "local_device_removed")
                        .await;
                    return true;
                }
                self.apply_member_left(party_id, party_epoch, device_id.get(), account_id.get(), reason)
                    .await;
                false
            }
            Mp1Message::PartyLeaderChanged {
                party_epoch,
                new_leader_account_id,
                new_leader_device_id,
                ..
            } => {
                if let Err(err) = self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
                    log_line(&format!(
                        "rejected PartyLeaderChanged epoch floor check: {err}"
                    ));
                    return false;
                }
                let mut st = self.inner.lock().await;
                if let Some(sess) = st.active_party.as_mut()
                    && sess.party_id == party_id
                {
                    sess.party_epoch = party_epoch;
                    sess.leader_account_id = new_leader_account_id.get();
                    sess.leader_device_id = new_leader_device_id.get();
                    sess.push_event(PartyEventBody::MembershipChanged {
                        party_epoch,
                        summary: format!(
                            "leader_changed: account={} device={}",
                            new_leader_account_id.get(),
                            new_leader_device_id.get()
                        ),
                    });
                }
                false
            }
            Mp1Message::PartyDisbanded {
                party_epoch,
                reason,
            } => {
                if let Err(err) = self
                    .check_and_persist_epoch(party_id, party_epoch, true)
                    .await
                {
                    log_line(&format!(
                        "rejected stale/invalid PartyDisbanded (epoch={party_epoch}): {err}"
                    ));
                    return false;
                }
                self.teardown_active_party(party_id, &format!("party_disbanded:{reason:?}"))
                    .await;
                true
            }
            _ => false,
        }
    }

    /// Durable fail-closed `epochs.bin` floor check and persistence under `StateLock` inside
    /// `spawn_blocking`. Updates RAM ONLY AFTER disk write+fsync succeeds!
    async fn check_and_persist_epoch(
        &self,
        party_id: u64,
        observed_epoch: u64,
        is_disband: bool,
    ) -> Result<(), String> {
        let (auth_hash, in_mem_rec) = {
            let st = self.inner.lock().await;
            (
                api_authority_hash(&st.device.api_authority),
                st.epochs.to_record(),
            )
        };
        let state_dir_path = self.state_dir_path.clone();
        let now_ms = wall_now_ms();

        let persisted_rec = tokio::task::spawn_blocking(move || {
            let state_dir = open_state_dir(&state_dir_path)?;
            let lock = lock_state(&state_dir)?;
            let disk_rec = load_epochs_store(&state_dir)?;
            let mut store = EpochFloorStore::from_record(disk_rec);
            store.merge_from(&in_mem_rec);
            let changed = store
                .check_and_advance(auth_hash, party_id, observed_epoch, is_disband, now_ms)
                .map_err(|e| format!("{e:?}"))?;
            let rec = store.to_record();
            if changed {
                save_epochs_store(&state_dir, &lock, &rec)?;
            }
            Ok::<_, String>(rec)
        })
        .await
        .map_err(|e| format!("epochs persistence task failed: {e}"))??;

        let mut st = self.inner.lock().await;
        st.epochs.merge_from(&persisted_rec);
        Ok(())
    }

    /// Persists `RevokedBlocked` records into `peers.bin` under `StateLock` (via `spawn_blocking`)
    /// for every `KeyMismatchAlert` observed, preserving `expected_root_pubkey` so the compromised
    /// account stays blocked across daemon restarts.
    async fn persist_key_mismatch_blocks(
        &self,
        auth_hash: [u8; 8],
        mismatches: Vec<KeyMismatchAlert>,
    ) {
        if mismatches.is_empty() {
            return;
        }
        let state_dir_path = self.state_dir_path.clone();
        let now_ms = wall_now_ms();
        let res = tokio::task::spawn_blocking(move || {
            let state_dir = open_state_dir(&state_dir_path)?;
            let lock = lock_state(&state_dir)?;
            let mut store = load_peers_store(&state_dir)?;
            for mm in &mismatches {
                if let Some(existing) = store
                    .peers
                    .iter_mut()
                    .find(|p| p.api_authority_hash == auth_hash && p.account_id == mm.account_id)
                {
                    existing.trust_state = TrustState::RevokedBlocked;
                    if existing.root_pubkey == [0u8; 32] {
                        existing.root_pubkey = mm.expected_root_pubkey;
                    }
                    existing.pinned_at_ms = now_ms;
                } else {
                    store.peers.push(PeerRecord {
                        api_authority_hash: auth_hash,
                        account_id: mm.account_id,
                        root_pubkey: mm.expected_root_pubkey,
                        trust_state: TrustState::RevokedBlocked,
                        pinned_at_ms: now_ms,
                        handle_prop: String::new(),
                        handle_fetched_ms: 0,
                    });
                }
            }
            save_peers_store(&state_dir, &lock, &store)?;
            Ok::<PeersStoreRecord, String>(store)
        })
        .await;

        match res {
            Ok(Ok(updated_store)) => {
                let mut st = self.inner.lock().await;
                st.peers = updated_store;
            }
            Ok(Err(e)) => log_line(&format!("failed persisting key_mismatch block: {e}")),
            Err(e) => log_line(&format!("key_mismatch persist task panicked/cancelled: {e}")),
        }
    }

    /// Returns `true` if a fatal relay-policy / pinned-relay mismatch required tearing down the party.
    async fn apply_party_snapshot(self: &Arc<Self>, snapshot: PartySnapshot) -> bool {
        let now_s = wall_now_secs();
        let mut to_dial: Vec<PeerDialTarget> = Vec::new();
        let mut allowed: HashSet<[u8; 32]> = HashSet::new();
        let mut revoke_4401: Vec<[u8; 32]> = Vec::new();
        let mut mismatches_to_persist: Vec<KeyMismatchAlert> = Vec::new();
        let mut accounts_to_resolve: Vec<u64> = Vec::new();
        let mut policy_violation_reason: Option<String> = None;
        let auth_hash: [u8; 8];
        let p2p_opt: Option<Arc<PartyP2pHandle>>;

        {
            let mut st = self.inner.lock().await;
            auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let local_dev_pk = st.device.device_pubkey;
            let local_policy = st.device.local_relay_policy;
            let peers_clone = st.peers.clone();
            let handle_cache_clone = st.handle_cache.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return false;
            };
            if sess.party_id != snapshot.party_id.get() {
                return false;
            }

            // L4-4: Validate snapshot relay_policy & pinned_relay_url against running endpoint
            // BEFORE admitting any peers!
            match effective_relay_policy(local_policy, snapshot.relay_policy) {
                Err(_) => {
                    policy_violation_reason = Some(format!(
                        "snapshot relay_policy {:?} incompatible with local_relay_policy {:?}",
                        snapshot.relay_policy, local_policy
                    ));
                }
                Ok(expected_eff) => {
                    if snapshot.relay_policy == RelayPolicy::ForceRelays
                        && sess.effective_relay_policy != RelayPolicy::ForceRelays
                    {
                        policy_violation_reason = Some(
                            "snapshot requires ForceRelays but running endpoint allows direct IPs"
                                .to_string(),
                        );
                    } else if expected_eff == RelayPolicy::NoRelays
                        && sess.effective_relay_policy != RelayPolicy::NoRelays
                    {
                        policy_violation_reason = Some(
                            "snapshot requires NoRelays but running endpoint has relays enabled"
                                .to_string(),
                        );
                    } else if (expected_eff == RelayPolicy::ForceRelays
                        || sess.effective_relay_policy == RelayPolicy::ForceRelays)
                        && !snapshot.pinned_relay_url.is_empty()
                        && sess.pinned_relay_url != snapshot.pinned_relay_url
                    {
                        policy_violation_reason = Some(format!(
                            "snapshot pinned_relay_url '{}' differs from endpoint pinned relay '{}'",
                            snapshot.pinned_relay_url, sess.pinned_relay_url
                        ));
                    }
                }
            }

            if policy_violation_reason.is_some() {
                p2p_opt = sess.p2p.as_ref().map(Arc::clone);
            } else {
                sess.party_epoch = snapshot.party_epoch;
                sess.leader_account_id = snapshot.leader_account_id.get();
                sess.leader_device_id = snapshot.leader_device_id.get();
                sess.visibility = snapshot.visibility;
                sess.join_mode = snapshot.join_mode;
                sess.relay_policy = snapshot.relay_policy;
                sess.max_members = snapshot.max_members;
                if !snapshot.pinned_relay_url.is_empty() {
                    sess.pinned_relay_url = snapshot.pinned_relay_url;
                }
                sess.members.clear();
                sess.pubkey_to_device.clear();
                sess.unpinned_alerts.clear();
                sess.key_mismatch_alerts.clear();

                let eff_policy = sess.effective_relay_policy;
                let party_relay = sess.relay_policy;
                let pinned_relay = sess.pinned_relay_url.clone();
                p2p_opt = sess.p2p.as_ref().map(Arc::clone);

                for member in snapshot.members {
                    let dev_id = member.device_id.get();
                    let acc_id = member.account_id.get();
                    let cached_handle = handle_cache_clone.get(&acc_id).cloned().unwrap_or_default();
                    if cached_handle.is_empty() && !accounts_to_resolve.contains(&acc_id) {
                        accounts_to_resolve.push(acc_id);
                    }

                    let m_state = evaluate_member_state(
                        &member,
                        local_dev_id,
                        local_acc_id,
                        local_root_pk,
                        local_dev_pk,
                        auth_hash,
                        &peers_clone,
                        now_s,
                        cached_handle,
                        self.strict_pins,
                        &mut sess.unpinned_alerts,
                        &mut sess.key_mismatch_alerts,
                    );

                    sess.provenance_by_account.insert(
                        acc_id,
                        CachedAccountProvenance {
                            handle: m_state.server_handle.clone(),
                            fingerprint: pubkey_fingerprint_hex(&member.root_pubkey),
                            safety_number: m_state.safety_number.clone(),
                        },
                    );
                    sess.members.insert(dev_id, m_state);
                }

                // L4-6: Propagate KeyMismatch across ALL devices of any mismatched account!
                let mismatched_accounts: HashSet<u64> =
                    sess.key_mismatch_alerts.keys().copied().collect();
                for m in sess.members.values_mut() {
                    if mismatched_accounts.contains(&m.record.account_id.get()) {
                        m.admitted = false;
                        m.key_mismatch = true;
                        m.trust_state = TrustState::RevokedBlocked;
                        if m.record.device_id.get() != local_dev_id {
                            revoke_4401.push(m.record.device_pubkey);
                        }
                    }
                }
                mismatches_to_persist = sess
                    .key_mismatch_alerts
                    .values()
                    .filter(|mm| mm.account_id != local_acc_id)
                    .cloned()
                    .collect();

                // L4-6: Rebuild `pubkey_to_device` strictly from admitted non-duplicate remote peers.
                let dup_pks =
                    rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk, self.strict_pins);
                revoke_4401.extend(dup_pks);

                for (&dev_id, m) in &sess.members {
                    if dev_id != local_dev_id && m.admitted {
                        allowed.insert(m.record.device_pubkey);
                        if m.record.connected
                            && let Some(target) = prepare_peer_dial_target(
                                eff_policy,
                                &pinned_relay,
                                party_relay,
                                &m.record,
                            )
                        {
                            to_dial.push(target);
                        }
                    }
                }

                sess.push_event(PartyEventBody::MembershipChanged {
                    party_epoch: sess.party_epoch,
                    summary: format!("party_snapshot: members={}", sess.members.len()),
                });
            }
        }

        if let Some(reason) = policy_violation_reason {
            log_line(&format!(
                "PARTY_SNAPSHOT relay policy violation: {reason}; tearing down party fail-closed"
            ));
            if let Some(p2p) = p2p_opt {
                p2p.set_allowed_peers_with_close_code(HashSet::new(), CLOSE_UNAUTHORIZED);
            }
            self.teardown_active_party(snapshot.party_id.get(), "relay_policy_mismatch")
                .await;
            return true;
        }

        if !mismatches_to_persist.is_empty() {
            self.persist_key_mismatch_blocks(auth_hash, mismatches_to_persist)
                .await;
        }

        if let Some(p2p) = p2p_opt {
            for pk in revoke_4401 {
                p2p.revoke_peer(pk, CLOSE_UNAUTHORIZED);
            }
            p2p.set_allowed_peers(allowed);
            self.schedule_dials(p2p, to_dial);
        }

        if !accounts_to_resolve.is_empty() {
            self.spawn_handle_resolution(accounts_to_resolve);
        }
        false
    }

    async fn apply_member_joined(
        self: &Arc<Self>,
        party_id: u64,
        party_epoch: u64,
        member: PartyMemberRecord,
    ) {
        let now_s = wall_now_secs();
        let dev_id = member.device_id.get();
        let acc_id = member.account_id.get();
        let mut to_dial: Vec<PeerDialTarget> = Vec::new();
        let mut allowed: HashSet<[u8; 32]> = HashSet::new();
        let mut revoke_4401: Vec<[u8; 32]> = Vec::new();
        let mut mismatches_to_persist: Vec<KeyMismatchAlert> = Vec::new();
        let mut resolve_acc = None;
        let auth_hash: [u8; 8];
        let p2p_opt: Option<Arc<PartyP2pHandle>>;

        {
            let mut st = self.inner.lock().await;
            auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let local_dev_pk = st.device.device_pubkey;
            let peers_clone = st.peers.clone();
            let cached_handle = st.handle_cache.get(&acc_id).cloned().unwrap_or_default();
            if cached_handle.is_empty() {
                resolve_acc = Some(acc_id);
            }

            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            sess.party_epoch = party_epoch;
            let eff_policy = sess.effective_relay_policy;
            let party_relay = sess.relay_policy;
            let pinned_relay = sess.pinned_relay_url.clone();
            p2p_opt = sess.p2p.as_ref().map(Arc::clone);

            let m_state = evaluate_member_state(
                &member,
                local_dev_id,
                local_acc_id,
                local_root_pk,
                local_dev_pk,
                auth_hash,
                &peers_clone,
                now_s,
                cached_handle,
                self.strict_pins,
                &mut sess.unpinned_alerts,
                &mut sess.key_mismatch_alerts,
            );

            sess.provenance_by_account.insert(
                acc_id,
                CachedAccountProvenance {
                    handle: m_state.server_handle.clone(),
                    fingerprint: pubkey_fingerprint_hex(&member.root_pubkey),
                    safety_number: m_state.safety_number.clone(),
                },
            );
            sess.members.insert(dev_id, m_state);

            if let Some(mm) = sess.key_mismatch_alerts.get(&acc_id).cloned() {
                for m in sess.members.values_mut() {
                    if m.record.account_id.get() == acc_id {
                        m.admitted = false;
                        m.key_mismatch = true;
                        m.trust_state = TrustState::RevokedBlocked;
                        if m.record.device_id.get() != local_dev_id {
                            revoke_4401.push(m.record.device_pubkey);
                        }
                    }
                }
                if acc_id != local_acc_id {
                    mismatches_to_persist.push(mm);
                }
            }

            let dup_pks =
                rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk, self.strict_pins);
            revoke_4401.extend(dup_pks);

            if let Some(m) = sess.members.get(&dev_id)
                && dev_id != local_dev_id
                && m.admitted
                && m.record.connected
                && let Some(target) =
                    prepare_peer_dial_target(eff_policy, &pinned_relay, party_relay, &m.record)
            {
                to_dial.push(target);
            }

            for (&did, m) in &sess.members {
                if did != local_dev_id && m.admitted {
                    allowed.insert(m.record.device_pubkey);
                }
            }

            sess.push_event(PartyEventBody::MembershipChanged {
                party_epoch,
                summary: format!("member_joined: account={acc_id} device={dev_id}"),
            });
        }

        if !mismatches_to_persist.is_empty() {
            self.persist_key_mismatch_blocks(auth_hash, mismatches_to_persist)
                .await;
        }

        if let Some(p2p) = p2p_opt {
            for pk in revoke_4401 {
                p2p.revoke_peer(pk, CLOSE_UNAUTHORIZED);
            }
            p2p.set_allowed_peers(allowed);
            self.schedule_dials(p2p, to_dial);
        }

        if let Some(acc) = resolve_acc {
            self.spawn_handle_resolution(vec![acc]);
        }
    }

    async fn apply_member_updated(
        self: &Arc<Self>,
        party_id: u64,
        party_epoch: u64,
        device_id: u64,
        connected: bool,
        device_cwt: Vec<u8>,
        endpoint: EndpointDescriptor,
    ) {
        let now_s = wall_now_secs();
        let mut to_dial: Vec<PeerDialTarget> = Vec::new();
        let mut allowed: HashSet<[u8; 32]> = HashSet::new();
        let mut revoke_4401: Vec<[u8; 32]> = Vec::new();
        let mut mismatches_to_persist: Vec<KeyMismatchAlert> = Vec::new();
        let auth_hash: [u8; 8];
        let p2p_opt: Option<Arc<PartyP2pHandle>>;

        {
            let mut st = self.inner.lock().await;
            auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let local_dev_pk = st.device.device_pubkey;
            let peers_clone = st.peers.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            sess.party_epoch = party_epoch;
            let eff_policy = sess.effective_relay_policy;
            let party_relay = sess.relay_policy;
            let pinned_relay = sess.pinned_relay_url.clone();
            p2p_opt = sess.p2p.as_ref().map(Arc::clone);

            if let Some(existing) = sess.members.get(&device_id).cloned() {
                let acc_id = existing.record.account_id.get();
                let mut updated_rec = existing.record;
                updated_rec.connected = connected;
                if !device_cwt.is_empty() {
                    updated_rec.device_cwt = device_cwt;
                }
                updated_rec.endpoint = endpoint;
                let m_state = evaluate_member_state(
                    &updated_rec,
                    local_dev_id,
                    local_acc_id,
                    local_root_pk,
                    local_dev_pk,
                    auth_hash,
                    &peers_clone,
                    now_s,
                    existing.server_handle,
                    self.strict_pins,
                    &mut sess.unpinned_alerts,
                    &mut sess.key_mismatch_alerts,
                );
                sess.members.insert(device_id, m_state);

                if let Some(mm) = sess.key_mismatch_alerts.get(&acc_id).cloned() {
                    for m in sess.members.values_mut() {
                        if m.record.account_id.get() == acc_id {
                            m.admitted = false;
                            m.key_mismatch = true;
                            m.trust_state = TrustState::RevokedBlocked;
                            if m.record.device_id.get() != local_dev_id {
                                revoke_4401.push(m.record.device_pubkey);
                            }
                        }
                    }
                    if acc_id != local_acc_id {
                        mismatches_to_persist.push(mm);
                    }
                }
            }

            let dup_pks =
                rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk, self.strict_pins);
            revoke_4401.extend(dup_pks);

            if let Some(m) = sess.members.get(&device_id)
                && device_id != local_dev_id
                && m.admitted
                && m.record.connected
                && let Some(target) =
                    prepare_peer_dial_target(eff_policy, &pinned_relay, party_relay, &m.record)
            {
                to_dial.push(target);
            }

            for (&did, m) in &sess.members {
                if did != local_dev_id && m.admitted {
                    allowed.insert(m.record.device_pubkey);
                }
            }
        }

        if !mismatches_to_persist.is_empty() {
            self.persist_key_mismatch_blocks(auth_hash, mismatches_to_persist)
                .await;
        }

        if let Some(p2p) = p2p_opt {
            for pk in revoke_4401 {
                p2p.revoke_peer(pk, CLOSE_UNAUTHORIZED);
            }
            p2p.set_allowed_peers(allowed);
            self.schedule_dials(p2p, to_dial);
        }
    }

    async fn apply_member_left(
        &self,
        party_id: u64,
        party_epoch: u64,
        device_id: u64,
        account_id: u64,
        reason: mp_protocol::MemberLeaveReason,
    ) {
        let (p2p_opt, revoked_pk) = {
            let mut st = self.inner.lock().await;
            let local_dev_id = st.device.device_id;
            let local_dev_pk = st.device.device_pubkey;
            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            sess.party_epoch = party_epoch;
            let removed = sess.members.remove(&device_id);
            let pk = removed.map(|m| m.record.device_pubkey);
            let _ = rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk, self.strict_pins);
            // Remove account alerts if no other devices of that account remain.
            if !sess
                .members
                .values()
                .any(|m| m.record.account_id.get() == account_id)
            {
                sess.unpinned_alerts.remove(&account_id);
                sess.key_mismatch_alerts.remove(&account_id);
            }
            sess.push_event(PartyEventBody::MembershipChanged {
                party_epoch,
                summary: format!(
                    "member_left: account={account_id} device={device_id} reason={reason:?}"
                ),
            });
            (sess.p2p.as_ref().map(Arc::clone), pk)
        };

        if let (Some(p2p), Some(pk)) = (p2p_opt, revoked_pk) {
            p2p.revoke_peer(pk, CLOSE_PEER_REVOKED);
        }
    }

    async fn reevaluate_active_party_trust(self: &Arc<Self>) {
        let now_s = wall_now_secs();
        let mut allowed: HashSet<[u8; 32]> = HashSet::new();
        let mut to_revoke_4403: Vec<[u8; 32]> = Vec::new();
        let mut to_revoke_4401: Vec<[u8; 32]> = Vec::new();
        let mismatches_to_persist: Vec<KeyMismatchAlert>;
        let mut to_dial: Vec<PeerDialTarget> = Vec::new();
        let auth_hash: [u8; 8];
        let p2p_opt: Option<Arc<PartyP2pHandle>>;

        {
            let mut st = self.inner.lock().await;
            auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let local_dev_pk = st.device.device_pubkey;
            let peers_clone = st.peers.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            let eff_policy = sess.effective_relay_policy;
            let party_relay = sess.relay_policy;
            let pinned_relay = sess.pinned_relay_url.clone();
            p2p_opt = sess.p2p.as_ref().map(Arc::clone);
            sess.unpinned_alerts.clear();
            sess.key_mismatch_alerts.clear();

            let old_members: Vec<(u64, PartyMemberState)> = sess.members.drain().collect();
            for (did, existing) in old_members {
                let m_state = evaluate_member_state(
                    &existing.record,
                    local_dev_id,
                    local_acc_id,
                    local_root_pk,
                    local_dev_pk,
                    auth_hash,
                    &peers_clone,
                    now_s,
                    existing.server_handle,
                    self.strict_pins,
                    &mut sess.unpinned_alerts,
                    &mut sess.key_mismatch_alerts,
                );
                if did != local_dev_id
                    && !m_state.admitted
                    && (existing.admitted || m_state.trust_state == TrustState::RevokedBlocked)
                {
                    if m_state.key_mismatch {
                        to_revoke_4401.push(m_state.record.device_pubkey);
                    } else {
                        to_revoke_4403.push(m_state.record.device_pubkey);
                    }
                }
                sess.members.insert(did, m_state);
            }

            let mismatched_accounts: HashSet<u64> =
                sess.key_mismatch_alerts.keys().copied().collect();
            for m in sess.members.values_mut() {
                if mismatched_accounts.contains(&m.record.account_id.get()) {
                    m.admitted = false;
                    m.key_mismatch = true;
                    m.trust_state = TrustState::RevokedBlocked;
                    if m.record.device_id.get() != local_dev_id {
                        to_revoke_4401.push(m.record.device_pubkey);
                    }
                }
            }
            mismatches_to_persist = sess
                .key_mismatch_alerts
                .values()
                .filter(|mm| mm.account_id != local_acc_id)
                .cloned()
                .collect();

            let dup_pks =
                rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk, self.strict_pins);
            to_revoke_4401.extend(dup_pks);

            for (&did, m) in &sess.members {
                if did != local_dev_id && m.admitted {
                    allowed.insert(m.record.device_pubkey);
                    if sess
                        .p2p
                        .as_ref()
                        .is_some_and(|p| !p.is_peer_connected(&m.record.device_pubkey))
                        && m.record.connected
                        && let Some(target) = prepare_peer_dial_target(
                            eff_policy,
                            &pinned_relay,
                            party_relay,
                            &m.record,
                        )
                    {
                        to_dial.push(target);
                    }
                }
            }
        }

        if !mismatches_to_persist.is_empty() {
            self.persist_key_mismatch_blocks(auth_hash, mismatches_to_persist)
                .await;
        }

        if let Some(p2p) = p2p_opt {
            for pk in to_revoke_4401 {
                p2p.revoke_peer(pk, CLOSE_UNAUTHORIZED);
            }
            for pk in to_revoke_4403 {
                p2p.revoke_peer(pk, CLOSE_PEER_REVOKED);
            }
            p2p.set_allowed_peers(allowed);
            self.schedule_dials(p2p, to_dial);
        }
    }

    fn schedule_dials(self: &Arc<Self>, p2p: Arc<PartyP2pHandle>, targets: Vec<PeerDialTarget>) {
        let local_dev_id = self.device_id;
        for target in targets {
            if p2p.is_peer_connected(&target.device_pubkey) {
                continue;
            }
            let p2p_c = Arc::clone(&p2p);
            if local_dev_id < target.device_id {
                // Single-flight primary dialer: smaller device_id dials immediately.
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(P2P_DIAL_TIMEOUT, p2p_c.connect_peer(target)).await;
                });
            } else {
                // Larger device_id initiates recovery dial if still unconnected after 1.5s.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    if !p2p_c.is_peer_connected(&target.device_pubkey) {
                        let _ =
                            tokio::time::timeout(P2P_DIAL_TIMEOUT, p2p_c.connect_peer(target)).await;
                    }
                });
            }
        }
    }

    fn spawn_handle_resolution(self: &Arc<Self>, accounts: Vec<u64>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let control = {
                let st = this.inner.lock().await;
                st.control.clone()
            };
            for acc in accounts {
                let Ok(aid) = AccountId::new(acc) else {
                    continue;
                };
                if let Ok(info) = control.get_account(aid).await {
                    let mut st = this.inner.lock().await;
                    st.handle_cache.insert(acc, info.handle.clone());
                    if let Some(sess) = st.active_party.as_mut() {
                        for m in sess.members.values_mut() {
                            if m.record.account_id.get() == acc {
                                m.server_handle = info.handle.clone();
                            }
                        }
                        if let Some(alert) = sess.unpinned_alerts.get_mut(&acc) {
                            alert.server_handle = info.handle.clone();
                        }
                        if let Some(prov) = sess.provenance_by_account.get_mut(&acc) {
                            prov.handle = info.handle.clone();
                        }
                    }
                    if let Some(f) = st.friends.get_mut(&acc) {
                        f.handle = info.handle;
                    }
                }
            }
        });
    }

    /// Best-effort party reattach on daemon startup when `/v1/accounts/me` reports an active party.
    async fn try_reattach_party(self: &Arc<Self>, party_id: u64) {
        let _tx_guard = self.party_transition.lock().await;
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
        let (control, device_secret, local_policy, default_relay_url) = {
            let st = self.inner.lock().await;
            if st.active_party.is_some() || !is_local_cwt_valid(&st.device, wall_now_secs()) {
                return;
            }
            (
                st.control.clone(),
                st.device.device_secret,
                st.device.local_relay_policy,
                st.device.default_relay_url.clone(),
            )
        };

        let Ok(summary) = control.get_party(pid).await else {
            return;
        };
        let Ok(party_policy) = RelayPolicy::from_u8(summary.relay_policy) else {
            return;
        };
        let Ok(eff_policy) = effective_relay_policy(local_policy, party_policy) else {
            return;
        };
        if self
            .check_and_persist_epoch(party_id, summary.party_epoch, false)
            .await
            .is_err()
        {
            return;
        }
        let relay_for_p2p = match eff_policy {
            RelayPolicy::NoRelays => None,
            RelayPolicy::AllowRelays | RelayPolicy::ForceRelays => {
                if !summary.pinned_relay_url.is_empty() {
                    Some(summary.pinned_relay_url.clone())
                } else if !default_relay_url.is_empty() {
                    Some(default_relay_url)
                } else {
                    None
                }
            }
        };
        let Ok(transport) = PartyP2pTransport::spawn(PartyP2pConfig {
            local_device_id: self.device_id,
            device_secret,
            effective_relay_policy: eff_policy,
            pinned_relay_url: relay_for_p2p.clone(),
        })
        .await
        else {
            return;
        };

        let (p2p, event_stream) = transport.split();
        let visibility = PartyVisibility::from_u8(summary.visibility).unwrap_or(PartyVisibility::Private);
        let join_mode = PartyJoinMode::from_u8(summary.join_mode).unwrap_or(PartyJoinMode::InviteOnly);
        let ws_stop = CancellationToken::new();
        let daemon_epoch = self.daemon_epoch();
        let (mp2_tx, mp2_rx) = mpsc::channel(64);

        // Install ActivePartySession BEFORE spawning any driver tasks!
        {
            let mut st = self.inner.lock().await;
            if st.active_party.is_some() {
                drop(st);
                p2p.close().await;
                return;
            }
            st.active_party = Some(ActivePartySession {
                party_id,
                party_epoch: summary.party_epoch,
                leader_account_id: summary.leader_account_id,
                leader_device_id: summary.leader_device_id,
                visibility,
                join_mode,
                relay_policy: party_policy,
                effective_relay_policy: eff_policy,
                max_members: summary.max_members,
                pinned_relay_url: relay_for_p2p.unwrap_or_default(),
                room_code: String::new(),
                room_name: String::new(),
                share_url: String::new(),
                ws_path: format!("/v1/parties/{party_id}/ws"),
                e2ee_mode: 0,
                mls_epoch: 0,
                min_allowed_mls_epoch: 0,
                mls_rekey_required: false,
                mls_invite_epoch: 0,
                group_id_b64: None,
                party_ds_pubkey: None,
                is_mls_creator: false,
                pending_invite_fragment: None,
                pending_join_kp: None,
                processed_kp_refs: std::collections::HashSet::new(),
                mls_session: None,
                members: HashMap::new(),
                mp2_members: Vec::new(),
                mp2_connected: false,
                mp2_last_seq: 0,
                mp2_seen_seqs: VecDeque::new(),
                sent_mp2_msg_ids: VecDeque::new(),
                mp2_tx: Some(mp2_tx),
                pubkey_to_device: HashMap::new(),
                provenance_by_account: HashMap::new(),
                unpinned_alerts: HashMap::new(),
                key_mismatch_alerts: HashMap::new(),
                ring: PartyEventRing::new(party_id, daemon_epoch),
                wait_notify: Arc::new(Notify::new()),
                p2p: Some(Arc::clone(&p2p)),
                p2p_event_task: None,
                ws_stop: ws_stop.clone(),
                ws_task: None,
                cwt_task: None,
            });
            self.active_party_atomic.store(party_id, Ordering::Release);
        }

        let p2p_event_task = self.spawn_p2p_event_loop(party_id, event_stream, ws_stop.clone());
        let (ws_task, cwt_task) = self.spawn_party_drivers(party_id, ws_stop, mp2_rx);
        self.attach_party_tasks(party_id, Some(p2p_event_task), ws_task, cwt_task)
            .await;
        log_line(&format!("reattached active party {party_id} on daemon startup"));
    }

    async fn attach_party_tasks(
        &self,
        party_id: u64,
        p2p_event_task: Option<JoinHandle<()>>,
        ws_task: JoinHandle<()>,
        cwt_task: JoinHandle<()>,
    ) {
        let mut st = self.inner.lock().await;
        if let Some(sess) = st.active_party.as_mut()
            && sess.party_id == party_id
        {
            sess.p2p_event_task = p2p_event_task;
            sess.ws_task = Some(ws_task);
            sess.cwt_task = Some(cwt_task);
        } else {
            if let Some(t) = p2p_event_task {
                t.abort();
            }
            ws_task.abort();
            cwt_task.abort();
        }
    }

    async fn teardown_active_party(&self, expected_party_id: u64, reason: &str) {
        self.cancel_unattended_timer();
        let removed = {
            let mut st = self.inner.lock().await;
            let matches = st
                .active_party
                .as_ref()
                .is_some_and(|s| s.party_id == expected_party_id);
            if matches {
                let mut sess = st.active_party.take();
                if let Some(ref mut s) = sess {
                    s.push_event(PartyEventBody::MembershipChanged {
                        party_epoch: s.party_epoch,
                        summary: format!("party_closed: {reason}"),
                    });
                }
                self.active_party_atomic.store(0, Ordering::Release);
                sess
            } else {
                None
            }
        };

        if let Some(mut sess) = removed {
            sess.ws_stop.cancel();
            sess.mp2_tx = None;
            if let Some(t) = sess.p2p_event_task.take() {
                t.abort();
            }
            if let Some(t) = sess.ws_task.take() {
                t.abort();
            }
            if let Some(t) = sess.cwt_task.take() {
                t.abort();
            }
            if let Some(p2p) = sess.p2p.take() {
                p2p.close().await;
            }
        }
    }

    // -----------------------------------------------------------------------
    // IPC Opcode Implementations
    // -----------------------------------------------------------------------

    async fn op_get_status(&self) -> Result<Vec<u8>, IpcErr> {
        let daemon_epoch = self.daemon_epoch();
        let st = self.inner.lock().await;
        let (active_party, unpinned_alerts, key_mismatch_alerts) = match &st.active_party {
            Some(s) => (
                Some(s.summary()),
                s.unpinned_alerts.values().cloned().collect(),
                s.key_mismatch_alerts.values().cloned().collect(),
            ),
            None => (None, Vec::new(), Vec::new()),
        };
        let resp = StatusResp {
            account_id: st.device.account_id,
            device_id: st.device.device_id,
            handle: st.own_handle.clone(),
            api_authority: st.device.api_authority.clone(),
            local_relay_policy: st.device.local_relay_policy as u8,
            cwt_expires_ms: st.cwt_expires_ms,
            daemon_epoch,
            daemon_pid: std::process::id(),
            build_order: build_order(),
            build_digest: build_digest(),
            exe_path: self.exe_path.clone(),
            control_ws_connected: st.control_ws_connected,
            dual_host_churn_alert: st.dual_host_churn_alert,
            active_party,
            unpinned_alerts,
            key_mismatch_alerts,
        };
        encode_status_resp(&resp).map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_reload_device(self: &Arc<Self>) -> Result<Vec<u8>, IpcErr> {
        let state_dir_path = self.state_dir_path.clone();
        let dev_id = self.device_id;
        let (new_device, new_peers, new_epochs_rec) = tokio::task::spawn_blocking(move || {
            let state_dir = open_state_dir(&state_dir_path)?;
            let _lock = lock_state(&state_dir)?;
            let dev = load_device_record(&state_dir_path, dev_id)?;
            let peers = load_peers_store(&state_dir)?;
            let epochs = load_epochs_store(&state_dir)?;
            Ok::<_, String>((dev, peers, epochs))
        })
        .await
        .map_err(|e| ipc_err(ERR_INTERNAL, false, format!("reload task failed: {e}")))?
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e))?;

        let new_cwt_exp = extract_cwt_expiry_ms(&new_device);
        let new_control =
            build_device_control_client(&new_device).map_err(|e| ipc_err(ERR_INTERNAL, false, e))?;

        let active_party_id = {
            let mut st = self.inner.lock().await;
            st.device = new_device;
            st.cwt_expires_ms = new_cwt_exp;
            st.control = new_control;
            st.peers = new_peers;
            // Merge disk epochs so in-memory floors can NEVER regress on reload.
            st.epochs.merge_from(&new_epochs_rec);
            st.active_party.as_ref().map_or(0, |s| s.party_id)
        };

        self.reevaluate_active_party_trust().await;

        Ok(encode_reload_resp(&ReloadDeviceResp {
            reloaded: true,
            device_id: self.device_id,
            active_party_id,
        }))
    }

    async fn op_party_list(&self) -> Result<Vec<u8>, IpcErr> {
        let daemon_epoch = self.daemon_epoch();
        let st = self.inner.lock().await;
        let parties = st
            .active_party
            .as_ref()
            .map(|s| vec![s.summary()])
            .unwrap_or_default();
        encode_party_list_resp(&PartyListResp {
            daemon_epoch,
            parties,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_members(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let party_id =
            decode_u64_req(payload).map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_ref() else {
            return Err(ipc_err(ERR_NOT_FOUND, false, "no active party"));
        };
        if sess.party_id != party_id {
            return Err(ipc_err(
                ERR_NOT_FOUND,
                false,
                format!("party {party_id} is not active"),
            ));
        }

        let mut members: Vec<MemberInfo> = if !sess.members.is_empty() {
            sess.members
                .values()
                .map(|m| MemberInfo {
                    device_id: m.record.device_id.get(),
                    account_id: m.record.account_id.get(),
                    server_handle: m.server_handle.clone(),
                    root_pubkey: m.record.root_pubkey,
                    trust_state: trust_state_to_u8(m.trust_state),
                    safety_number: m.safety_number.clone(),
                    connected_mp1: m.record.connected,
                    connected_p2p: m.record.device_id.get() == self.device_id
                        || sess.mp2_connected
                        || sess
                            .p2p
                            .as_ref()
                            .is_some_and(|p| p.is_peer_connected(&m.record.device_pubkey)),
                    joined_seq: m.record.joined_seq,
                    key_mismatch: m.key_mismatch,
                })
                .collect()
        } else {
            let auth_hash = api_authority_hash(&st.device.api_authority);
            sess.mp2_members
                .iter()
                .enumerate()
                .map(|(idx, m)| {
                    let is_guest = m.is_guest || m.account_id == 0;
                    let (ts, root_pk, sn) = if is_guest {
                        (TrustState::Unpinned, [0u8; 32], String::new())
                    } else {
                        lookup_mp2_member_trust(
                            auth_hash,
                            m.account_id,
                            st.device.account_id,
                            st.device.root_pubkey,
                            &st.peers,
                        )
                    };
                    let dev_id = if is_guest {
                        0
                    } else if m.account_id == st.device.account_id {
                        m.device_id.unwrap_or(self.device_id)
                    } else {
                        m.device_id.unwrap_or(m.account_id)
                    };
                    let is_live = m.status.is_empty() || m.status == "live";
                    MemberInfo {
                        device_id: dev_id,
                        account_id: if is_guest { 0 } else { m.account_id },
                        server_handle: if is_guest {
                            format_guest_display_name(&m.handle)
                        } else {
                            m.handle.clone()
                        },
                        root_pubkey: root_pk,
                        trust_state: trust_state_to_u8(ts),
                        safety_number: sn,
                        connected_mp1: is_live,
                        connected_p2p: is_live,
                        joined_seq: (idx as u64).saturating_add(1),
                        key_mismatch: false,
                    }
                })
                .collect()
        };
        members.sort_by_key(|m| (m.joined_seq, m.device_id));

        encode_party_members_resp(&PartyMembersResp {
            party_id: sess.party_id,
            party_epoch: sess.party_epoch,
            members,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn snapshot_secret_guard_material(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<Vec<u8>>) {
        let st = self.inner.lock().await;
        (
            Zeroizing::new(st.device.device_secret),
            Zeroizing::new(st.device.device_cwt.clone()),
        )
    }

    async fn op_party_send_chat(&self, conn_id: u64, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_send_chat_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let payload_hash = hash_chat_req(&req);
        let party_id = req.party_id;
        let client_msg_id = req.client_msg_id;

        // 1. Secret disclosure guard on BOTH room_scope AND body OUTSIDE `self.inner` mutex
        //    so scanning never stalls concurrent IPC/P2P/WS tasks (NEVER echo offending secret!).
        {
            let (device_secret, device_cwt) = self.snapshot_secret_guard_material().await;
            if let Some(kind) = scan_outbound_secrets(
                req.room_scope.as_bytes(),
                &device_secret,
                device_cwt.as_slice(),
            )
            .or_else(|| {
                scan_outbound_secrets(
                    req.body.as_bytes(),
                    &device_secret,
                    device_cwt.as_slice(),
                )
            }) {
                return Err(ipc_err(
                    secret_kind_to_error_code(kind),
                    false,
                    "outbound message refused by secret-disclosure guard",
                ));
            }
        }

        enum ChatDispatch {
            Mp2 {
                tx: mpsc::Sender<Mp2OutboundCmd>,
                mp2_msg_id: String,
                target: String,
                body: String,
                delivered_preview: Vec<u64>,
                withheld_unpinned: Vec<u64>,
            },
            Mp2E2ee {
                tx: mpsc::Sender<Mp2OutboundCmd>,
                mp2_msg_id: String,
                mls_epoch: u64,
                body_b64: String,
                needs_pcs_self_update: bool,
                delivered_preview: Vec<u64>,
                withheld_unpinned: Vec<u64>,
            },
            P2p {
                p2p: Arc<PartyP2pHandle>,
                target_pks: Vec<(u64, [u8; 32])>,
                plan: outpost_core::party_state::SendPlan,
                frame: P2pPartyFrame,
            },
        }

        let dispatch = {
            let mut st = self.inner.lock().await;

            // 2. Live per-connection idempotency dedupe check (read-only until send succeeds!).
            match st.dedupe.check(
                conn_id,
                party_id,
                IpcOpcode::PartySendChat as u16,
                client_msg_id,
                payload_hash,
            ) {
                DedupeLookup::New => {}
                DedupeLookup::Duplicate(cached) => {
                    return Ok(cached.to_vec());
                }
                DedupeLookup::PayloadConflict => {
                    return Err(ipc_err(
                        ERR_IDEMPOTENCY_CONFLICT,
                        false,
                        "idempotency_conflict: client_msg_id reused with different payload",
                    ));
                }
            }

            let own_handle = if st.own_handle.is_empty() {
                format!("account-{}", st.device.account_id)
            } else {
                st.own_handle.clone()
            };
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let peers_clone = st.peers.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return Err(ipc_err(ERR_NOT_FOUND, false, "no active party"));
            };
            if sess.party_id != party_id {
                return Err(ipc_err(
                    ERR_NOT_FOUND,
                    false,
                    format!("party {party_id} is not active"),
                ));
            }

            // Any key_mismatch ALWAYS fails closed hard.
            if let Some(&bad_acc) = sess.key_mismatch_alerts.keys().next() {
                return Err(map_send_plan_err(SendPlanError::KeyMismatchPresent {
                    account_id: bad_acc,
                }));
            }

            if let Some(tx) = sess.mp2_tx.clone()
                && (sess.mp2_connected || sess.p2p.is_none())
            {
                let (delivered_preview, withheld_unpinned) = plan_mp2_recipients(
                    sess,
                    local_acc_id,
                    self.device_id,
                    local_root_pk,
                    auth_hash,
                    &peers_clone,
                    self.strict_pins,
                    req.target_device_id,
                )?;
                let target = resolve_mp2_target_selector(sess, req.target_device_id);
                let mp2_msg_id = format!("mp2-{}-{client_msg_id}", self.device_id);
                if sess.e2ee_mode == 1 {
                    let Some(ref mut mls) = sess.mls_session else {
                        return Err(ipc_err(
                            ERR_CONFLICT,
                            true,
                            "E2EE room requires initialized MLS group before sending",
                        ));
                    };
                    let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
                    let prepared = mls
                        .prepare_outbound_chat(&mp2_msg_id, &target, &req.body, now_s, |enc| {
                            self.persist_mls_bytes_locked(party_id, enc)
                        })
                        .map_err(|e| ipc_err(ERR_CONFLICT, false, e.to_string()))?;
                    sess.record_sent_mp2_msg_id(mp2_msg_id.clone());
                    ChatDispatch::Mp2E2ee {
                        tx,
                        mp2_msg_id,
                        mls_epoch: prepared.mls_epoch,
                        body_b64: prepared.body_b64,
                        needs_pcs_self_update: prepared.needs_pcs_self_update,
                        delivered_preview,
                        withheld_unpinned,
                    }
                } else {
                    sess.record_sent_mp2_msg_id(mp2_msg_id.clone());
                    ChatDispatch::Mp2 {
                        tx,
                        mp2_msg_id,
                        target,
                        body: req.body,
                        delivered_preview,
                        withheld_unpinned,
                    }
                }
            } else {
                let Some(p2p) = sess.p2p.as_ref().map(Arc::clone) else {
                    return Err(ipc_err(
                        ERR_CONFLICT,
                        true,
                        "party room connection is reconnecting; retry shortly",
                    ));
                };
                let candidates = build_send_candidates(sess, self.device_id);
                let target = match req.target_device_id {
                    Some(did) => SendTarget::Device(did),
                    None => SendTarget::Broadcast,
                };
                let plan = plan_send_recipients_with_policy(
                    &candidates,
                    target,
                    self.send_trust_policy(),
                )
                .map_err(map_send_plan_err)?;

                let mut pks = Vec::with_capacity(plan.deliver_to.len());
                for &did in &plan.deliver_to {
                    if let Some(m) = sess.members.get(&did) {
                        pks.push((did, m.record.device_pubkey));
                    }
                }

                let target_selector = match req.target_device_id {
                    Some(did) => format!("device:{did}"),
                    None => "@all".to_string(),
                };
                let room_scope = if req.room_scope.is_empty() {
                    "party/main".to_string()
                } else {
                    req.room_scope.clone()
                };

                let frame = P2pPartyFrame::ChatMessage(P2pChatMessage {
                    room_scope,
                    target_selector,
                    sender_handle: own_handle,
                    timestamp_ns: now_unix_ns(),
                    body: req.body,
                });
                ChatDispatch::P2p {
                    p2p,
                    target_pks: pks,
                    plan,
                    frame,
                }
            }
        };

        let (delivered, withheld_unpinned, disconnected) = match dispatch {
            ChatDispatch::Mp2 {
                tx,
                mp2_msg_id,
                target,
                body,
                delivered_preview,
                withheld_unpinned,
            } => {
                // In standard (`e2ee_mode == 0`) rooms, translate shared `{"mp_irc":1,"t":"nick"|"topic",...}`
                // payloads into native `{ v: 2, t: "nick", nick }` / `{ v: 2, t: "topic", topic }` frames!
                let mut sent_irc_meta = false;
                if body.starts_with("{\"mp_irc\":1,")
                    && let Ok(serde_json::Value::Object(map)) =
                        serde_json::from_str::<serde_json::Value>(&body)
                    && map.get("mp_irc").and_then(serde_json::Value::as_u64) == Some(1)
                {
                    match map.get("t").and_then(serde_json::Value::as_str) {
                        Some("nick") => {
                            if let Some(nick) =
                                map.get("nick").and_then(serde_json::Value::as_str)
                            {
                                tx.send(Mp2OutboundCmd::Nick {
                                    nick: nick.to_string(),
                                })
                                .await
                                .map_err(|_| {
                                    ipc_err(
                                        ERR_CONFLICT,
                                        true,
                                        "party room socket is not active; reconnect or rejoin",
                                    )
                                })?;
                                sent_irc_meta = true;
                            }
                        }
                        Some("topic") => {
                            if let Some(topic) =
                                map.get("topic").and_then(serde_json::Value::as_str)
                            {
                                tx.send(Mp2OutboundCmd::Topic {
                                    topic: topic.to_string(),
                                })
                                .await
                                .map_err(|_| {
                                    ipc_err(
                                        ERR_CONFLICT,
                                        true,
                                        "party room socket is not active; reconnect or rejoin",
                                    )
                                })?;
                                sent_irc_meta = true;
                            }
                        }
                        _ => {}
                    }
                }
                if !sent_irc_meta {
                    let (ack_tx, ack_rx) = oneshot::channel();
                    tx.send(Mp2OutboundCmd::Send {
                        client_msg_id: mp2_msg_id,
                        kind: Mp2EventKind::Chat,
                        target,
                        body_encoding: "utf8".to_string(),
                        body,
                        ack_tx,
                    })
                    .await
                    .map_err(|_| {
                        ipc_err(
                            ERR_CONFLICT,
                            true,
                            "party room socket is not active; reconnect or rejoin",
                        )
                    })?;
                    let _ack = tokio::time::timeout(MP2_ACK_TIMEOUT, ack_rx)
                        .await
                        .map_err(|_| {
                            ipc_err(
                                ERR_CONFLICT,
                                true,
                                "timed out waiting for room acknowledgement",
                            )
                        })?
                        .map_err(|_| {
                            ipc_err(
                                ERR_CONFLICT,
                                true,
                                "party room socket closed before acknowledgement",
                            )
                        })?
                        .map_err(|msg| ipc_err(ERR_CONFLICT, true, msg))?;
                }
                (delivered_preview, withheld_unpinned, Vec::new())
            }
            ChatDispatch::Mp2E2ee {
                tx,
                mp2_msg_id,
                mls_epoch,
                body_b64,
                needs_pcs_self_update,
                delivered_preview,
                withheld_unpinned,
            } => {
                let (ack_tx, ack_rx) = oneshot::channel();
                tx.send(Mp2OutboundCmd::SendE2eeApp {
                    client_msg_id: mp2_msg_id,
                    mls_epoch,
                    body_b64,
                    ack_tx,
                })
                .await
                .map_err(|_| {
                    ipc_err(
                        ERR_CONFLICT,
                        true,
                        "party room socket is not active; reconnect or rejoin",
                    )
                })?;
                let _ack = tokio::time::timeout(MP2_ACK_TIMEOUT, ack_rx)
                    .await
                    .map_err(|_| {
                        ipc_err(
                            ERR_CONFLICT,
                            true,
                            "timed out waiting for E2EE room acknowledgement",
                        )
                    })?
                    .map_err(|_| {
                        ipc_err(
                            ERR_CONFLICT,
                            true,
                            "party room socket closed before E2EE acknowledgement",
                        )
                    })?
                    .map_err(|msg| ipc_err(ERR_CONFLICT, true, msg))?;
                if needs_pcs_self_update {
                    self.submit_pcs_self_update_commit(party_id).await;
                }
                (delivered_preview, withheld_unpinned, Vec::new())
            }
            ChatDispatch::P2p {
                p2p,
                target_pks,
                plan,
                frame,
            } => {
                let mut delivered = Vec::new();
                let mut disconnected = plan.disconnected;
                for (did, pk) in target_pks {
                    match p2p.send_frame(pk, &frame).await {
                        Ok(()) => delivered.push(did),
                        Err(_) => disconnected.push(did),
                    }
                }
                if delivered.is_empty() {
                    return Err(ipc_err(
                        ERR_CONFLICT,
                        true,
                        "failed to deliver chat message to any connected peer",
                    ));
                }
                (delivered, plan.withheld_unpinned, disconnected)
            }
        };

        let resp_bytes = encode_send_result_resp(&SendResultResp {
            party_id,
            client_msg_id,
            delivered_to: delivered,
            withheld_unpinned,
            disconnected,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))?;

        // Record exact first-attempt response bytes ONLY after delivery succeeds!
        {
            let mut st = self.inner.lock().await;
            st.dedupe.record(
                conn_id,
                party_id,
                IpcOpcode::PartySendChat as u16,
                client_msg_id,
                payload_hash,
                resp_bytes.clone(),
            );
        }

        Ok(resp_bytes)
    }

    async fn op_party_post_board(&self, conn_id: u64, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_post_board_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let payload_hash = hash_board_req(&req);
        let party_id = req.party_id;
        let client_msg_id = req.client_msg_id;

        // Scan BOTH room_scope AND payload OUTSIDE `self.inner` mutex!
        {
            let (device_secret, device_cwt) = self.snapshot_secret_guard_material().await;
            let static_match = core::str::from_utf8(&req.payload)
                .ok()
                .and_then(outpost_mcp::scan_static_secret_text)
                .or_else(|| outpost_mcp::scan_static_secret_text(&req.room_scope));
            if let Some(kind) = scan_outbound_secrets(
                req.room_scope.as_bytes(),
                &device_secret,
                device_cwt.as_slice(),
            )
            .or_else(|| {
                scan_outbound_secrets(
                    &req.payload,
                    &device_secret,
                    device_cwt.as_slice(),
                )
            })
            .or(static_match)
            {
                return Err(ipc_err(
                    secret_kind_to_error_code(kind),
                    false,
                    "outbound board envelope refused by secret-disclosure guard",
                ));
            }
        }

        enum BoardDispatch {
            Mp2 {
                tx: mpsc::Sender<Mp2OutboundCmd>,
                mp2_msg_id: String,
                body_encoding: String,
                body: String,
                delivered_preview: Vec<u64>,
                withheld_unpinned: Vec<u64>,
            },
            Mp2E2ee {
                tx: mpsc::Sender<Mp2OutboundCmd>,
                mp2_msg_id: String,
                mls_epoch: u64,
                body_b64: String,
                needs_pcs_self_update: bool,
                delivered_preview: Vec<u64>,
                withheld_unpinned: Vec<u64>,
            },
            P2p {
                p2p: Arc<PartyP2pHandle>,
                target_pks: Vec<(u64, [u8; 32])>,
                plan: outpost_core::party_state::SendPlan,
                frame: P2pPartyFrame,
            },
        }

        let dispatch = {
            let mut st = self.inner.lock().await;

            match st.dedupe.check(
                conn_id,
                party_id,
                IpcOpcode::PartyPostBoard as u16,
                client_msg_id,
                payload_hash,
            ) {
                DedupeLookup::New => {}
                DedupeLookup::Duplicate(cached) => {
                    return Ok(cached.to_vec());
                }
                DedupeLookup::PayloadConflict => {
                    return Err(ipc_err(
                        ERR_IDEMPOTENCY_CONFLICT,
                        false,
                        "idempotency_conflict: client_msg_id reused with different payload",
                    ));
                }
            }

            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let peers_clone = st.peers.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return Err(ipc_err(ERR_NOT_FOUND, false, "no active party"));
            };
            if sess.party_id != party_id {
                return Err(ipc_err(
                    ERR_NOT_FOUND,
                    false,
                    format!("party {party_id} is not active"),
                ));
            }
            if let Some(&bad_acc) = sess.key_mismatch_alerts.keys().next() {
                return Err(map_send_plan_err(SendPlanError::KeyMismatchPresent {
                    account_id: bad_acc,
                }));
            }

            if let Some(tx) = sess.mp2_tx.clone()
                && (sess.mp2_connected || sess.p2p.is_none())
            {
                let (delivered_preview, withheld_unpinned) = plan_mp2_recipients(
                    sess,
                    local_acc_id,
                    self.device_id,
                    local_root_pk,
                    auth_hash,
                    &peers_clone,
                    self.strict_pins,
                    None,
                )?;
                let mp2_msg_id = format!("mp2-card-{}-{client_msg_id}", self.device_id);
                if sess.e2ee_mode == 1 {
                    let Some(ref mut mls) = sess.mls_session else {
                        return Err(ipc_err(
                            ERR_CONFLICT,
                            true,
                            "E2EE room requires initialized MLS group before posting agent card",
                        ));
                    };
                    let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
                    let prepared = mls
                        .prepare_outbound_agent_card(&mp2_msg_id, &req.payload, now_s, |enc| {
                            self.persist_mls_bytes_locked(party_id, enc)
                        })
                        .map_err(|e| ipc_err(ERR_CONFLICT, false, e.to_string()))?;
                    sess.record_sent_mp2_msg_id(mp2_msg_id.clone());
                    BoardDispatch::Mp2E2ee {
                        tx,
                        mp2_msg_id,
                        mls_epoch: prepared.mls_epoch,
                        body_b64: prepared.body_b64,
                        needs_pcs_self_update: prepared.needs_pcs_self_update,
                        delivered_preview,
                        withheld_unpinned,
                    }
                } else {
                    let (body_encoding, body) = match std::str::from_utf8(&req.payload) {
                        Ok(text) if text.len() <= MAX_MP2_BODY_BYTES => {
                            ("utf8".to_string(), text.to_string())
                        }
                        _ => {
                            let enc = B64.encode(&req.payload);
                            if enc.len() > MAX_MP2_BODY_BYTES {
                                return Err(ipc_err(
                                    ERR_INVALID_PARAMS,
                                    false,
                                    format!(
                                        "agent_card payload exceeds mp2 32 KiB body limit ({} bytes)",
                                        enc.len()
                                    ),
                                ));
                            }
                            ("opaque_b64".to_string(), enc)
                        }
                    };
                    sess.record_sent_mp2_msg_id(mp2_msg_id.clone());
                    BoardDispatch::Mp2 {
                        tx,
                        mp2_msg_id,
                        body_encoding,
                        body,
                        delivered_preview,
                        withheld_unpinned,
                    }
                }
            } else {
                let Some(p2p) = sess.p2p.as_ref().map(Arc::clone) else {
                    return Err(ipc_err(
                        ERR_CONFLICT,
                        true,
                        "party room connection is reconnecting; retry shortly",
                    ));
                };
                let candidates = build_send_candidates(sess, self.device_id);
                let plan = plan_send_recipients_with_policy(
                    &candidates,
                    SendTarget::Broadcast,
                    self.send_trust_policy(),
                )
                .map_err(map_send_plan_err)?;

                let mut pks = Vec::with_capacity(plan.deliver_to.len());
                for &did in &plan.deliver_to {
                    if let Some(m) = sess.members.get(&did) {
                        pks.push((did, m.record.device_pubkey));
                    }
                }

                let frame = P2pPartyFrame::BridgeEnvelope(P2pBridgeEnvelope {
                    room_scope: req.room_scope,
                    payload: req.payload,
                });
                BoardDispatch::P2p {
                    p2p,
                    target_pks: pks,
                    plan,
                    frame,
                }
            }
        };

        let (delivered, withheld_unpinned, disconnected) = match dispatch {
            BoardDispatch::Mp2 {
                tx,
                mp2_msg_id,
                body_encoding,
                body,
                delivered_preview,
                withheld_unpinned,
            } => {
                let (ack_tx, ack_rx) = oneshot::channel();
                tx.send(Mp2OutboundCmd::Send {
                    client_msg_id: mp2_msg_id,
                    kind: Mp2EventKind::AgentCard,
                    target: "@all".to_string(),
                    body_encoding,
                    body,
                    ack_tx,
                })
                .await
                .map_err(|_| {
                    ipc_err(
                        ERR_CONFLICT,
                        true,
                        "party room socket is not active; reconnect or rejoin",
                    )
                })?;
                let _ack = tokio::time::timeout(MP2_ACK_TIMEOUT, ack_rx)
                    .await
                    .map_err(|_| {
                        ipc_err(
                            ERR_CONFLICT,
                            true,
                            "timed out waiting for room acknowledgement",
                        )
                    })?
                    .map_err(|_| {
                        ipc_err(
                            ERR_CONFLICT,
                            true,
                            "party room socket closed before acknowledgement",
                        )
                    })?
                    .map_err(|msg| ipc_err(ERR_CONFLICT, true, msg))?;
                (delivered_preview, withheld_unpinned, Vec::new())
            }
            BoardDispatch::Mp2E2ee {
                tx,
                mp2_msg_id,
                mls_epoch,
                body_b64,
                needs_pcs_self_update,
                delivered_preview,
                withheld_unpinned,
            } => {
                let (ack_tx, ack_rx) = oneshot::channel();
                tx.send(Mp2OutboundCmd::SendE2eeApp {
                    client_msg_id: mp2_msg_id,
                    mls_epoch,
                    body_b64,
                    ack_tx,
                })
                .await
                .map_err(|_| {
                    ipc_err(
                        ERR_CONFLICT,
                        true,
                        "party room socket is not active; reconnect or rejoin",
                    )
                })?;
                let _ack = tokio::time::timeout(MP2_ACK_TIMEOUT, ack_rx)
                    .await
                    .map_err(|_| {
                        ipc_err(
                            ERR_CONFLICT,
                            true,
                            "timed out waiting for E2EE room acknowledgement",
                        )
                    })?
                    .map_err(|_| {
                        ipc_err(
                            ERR_CONFLICT,
                            true,
                            "party room socket closed before E2EE acknowledgement",
                        )
                    })?
                    .map_err(|msg| ipc_err(ERR_CONFLICT, true, msg))?;
                if needs_pcs_self_update {
                    self.submit_pcs_self_update_commit(party_id).await;
                }
                (delivered_preview, withheld_unpinned, Vec::new())
            }
            BoardDispatch::P2p {
                p2p,
                target_pks,
                plan,
                frame,
            } => {
                let mut delivered = Vec::new();
                let mut disconnected = plan.disconnected;
                for (did, pk) in target_pks {
                    match p2p.send_frame(pk, &frame).await {
                        Ok(()) => delivered.push(did),
                        Err(_) => disconnected.push(did),
                    }
                }
                if delivered.is_empty() {
                    return Err(ipc_err(
                        ERR_CONFLICT,
                        true,
                        "failed to deliver board envelope to any connected peer",
                    ));
                }
                (delivered, plan.withheld_unpinned, disconnected)
            }
        };

        let resp_bytes = encode_send_result_resp(&SendResultResp {
            party_id,
            client_msg_id,
            delivered_to: delivered,
            withheld_unpinned,
            disconnected,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))?;

        {
            let mut st = self.inner.lock().await;
            st.dedupe.record(
                conn_id,
                party_id,
                IpcOpcode::PartyPostBoard as u16,
                client_msg_id,
                payload_hash,
                resp_bytes.clone(),
            );
        }

        Ok(resp_bytes)
    }

    async fn op_party_send_control_notice(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_control_notice_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let kind = P2pControlNoticeKind::from_u8(req.notice_kind)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        // Enforce accidental-secret-disclosure guard on control notice text OUTSIDE `self.inner`!
        {
            let (device_secret, device_cwt) = self.snapshot_secret_guard_material().await;
            if let Some(secret_kind) = scan_outbound_secrets(
                req.text.as_bytes(),
                &device_secret,
                device_cwt.as_slice(),
            ) {
                return Err(ipc_err(
                    secret_kind_to_error_code(secret_kind),
                    false,
                    "outbound control notice refused by secret-disclosure guard",
                ));
            }
        }

        let (p2p, target_pks, plan, frame) = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return Err(ipc_err(ERR_NOT_FOUND, false, "no active party"));
            };
            if sess.party_id != req.party_id {
                return Err(ipc_err(ERR_NOT_FOUND, false, "party is not active"));
            }
            let Some(p2p) = sess.p2p.as_ref().map(Arc::clone) else {
                return Err(ipc_err(
                    ERR_CONFLICT,
                    false,
                    "control notices require P2P transport",
                ));
            };
            let candidates = build_send_candidates(sess, self.device_id);
            let plan = plan_send_recipients_with_policy(
                &candidates,
                SendTarget::Broadcast,
                self.send_trust_policy(),
            )
            .map_err(map_send_plan_err)?;
            let mut pks = Vec::with_capacity(plan.deliver_to.len());
            for &did in &plan.deliver_to {
                if let Some(m) = sess.members.get(&did) {
                    pks.push((did, m.record.device_pubkey));
                }
            }
            let epoch = if req.party_epoch == 0 {
                sess.party_epoch
            } else {
                req.party_epoch
            };
            let frame = P2pPartyFrame::ControlNotice(P2pControlNotice {
                kind,
                party_epoch: epoch,
                text: req.text,
            });
            (p2p, pks, plan, frame)
        };

        let mut delivered = Vec::new();
        let mut disconnected = plan.disconnected;
        for (did, pk) in target_pks {
            match p2p.send_frame(pk, &frame).await {
                Ok(()) => delivered.push(did),
                Err(_) => disconnected.push(did),
            }
        }

        encode_send_result_resp(&SendResultResp {
            party_id: req.party_id,
            client_msg_id: 0,
            delivered_to: delivered,
            withheld_unpinned: plan.withheld_unpinned,
            disconnected,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_poll(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_poll_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let st = self.inner.lock().await;
        let Some(sess) = st.active_party.as_ref() else {
            return Err(ipc_err(ERR_NOT_FOUND, false, "no active party"));
        };
        if sess.party_id != req.party_id {
            return Err(ipc_err(
                ERR_NOT_FOUND,
                false,
                format!("party {} is not active", req.party_id),
            ));
        }

        let cursor_epoch = if req.cursor_epoch == 0 {
            None
        } else {
            Some(req.cursor_epoch)
        };
        let poll = if req.board_only {
            sess.ring.poll_filtered(
                cursor_epoch,
                req.after_seq,
                usize::from(req.limit),
                req.max_bytes as usize,
                |b| matches!(b, PartyEventBody::BridgeEnvelope { .. }),
            )
        } else {
            sess.ring.poll(
                cursor_epoch,
                req.after_seq,
                usize::from(req.limit),
                req.max_bytes as usize,
            )
        };
        let resp = build_ipc_poll_resp(sess, poll, false, req.board_only);
        encode_party_poll_resp(&resp).map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_wait(
        &self,
        payload: &[u8],
        cancel: CancellationToken,
    ) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_wait_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let capped_ms = req.timeout_ms.clamp(1, MAX_WAIT_TIMEOUT_MS);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(u64::from(capped_ms));

        let wait_notify = {
            let st = self.inner.lock().await;
            let Some(sess) = st.active_party.as_ref() else {
                return Err(ipc_err(ERR_NOT_FOUND, false, "no active party"));
            };
            if sess.party_id != req.party_id {
                return Err(ipc_err(
                    ERR_NOT_FOUND,
                    false,
                    format!("party {} is not active", req.party_id),
                ));
            }
            Arc::clone(&sess.wait_notify)
        };

        let cursor_epoch = if req.cursor_epoch == 0 {
            None
        } else {
            Some(req.cursor_epoch)
        };

        loop {
            // CRITICAL: Register `notified()` BEFORE locking state & checking ring predicate!
            let notified = wait_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let st = self.inner.lock().await;
                let Some(sess) = st.active_party.as_ref() else {
                    let resp = PartyPollIpcResp {
                        party_id: req.party_id,
                        daemon_epoch: self.daemon_epoch(),
                        next_seq: 0,
                        dropped_before_seq: 0,
                        cursor_reset: true,
                        gap_possible: true,
                        timed_out: false,
                        e2ee_mode: 0,
                        mls_epoch: 0,
                        trust_tier: 0,
                        has_declared_agent: false,
                        epoch_authenticator_b32: String::new(),
                        clone_detected: false,
                        events: Vec::new(),
                    };
                    return encode_party_poll_resp(&resp)
                        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()));
                };
                if sess.party_id != req.party_id {
                    return Err(ipc_err(ERR_NOT_FOUND, false, "party is no longer active"));
                }
                let poll = sess
                    .ring
                    .poll(cursor_epoch, req.after_seq, 100, DEFAULT_POLL_MAX_BYTES);
                if poll.cursor_reset || !poll.events.is_empty() {
                    let resp = build_ipc_poll_resp(sess, poll, false, false);
                    return encode_party_poll_resp(&resp)
                        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()));
                }
            }

            if cancel.is_cancelled() {
                return Err(ipc_err(ERR_CANCELLED, false, "party_wait cancelled"));
            }

            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    return Err(ipc_err(ERR_CANCELLED, false, "party_wait cancelled"));
                }
                _ = &mut notified => {
                    continue;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let st = self.inner.lock().await;
                    let resp = if let Some(sess) = st.active_party.as_ref()
                        && sess.party_id == req.party_id
                    {
                        let poll = sess.ring.poll(cursor_epoch, req.after_seq, 100, DEFAULT_POLL_MAX_BYTES);
                        build_ipc_poll_resp(sess, poll, true, false)
                    } else {
                        PartyPollIpcResp {
                            party_id: req.party_id,
                            daemon_epoch: self.daemon_epoch(),
                            next_seq: req.after_seq,
                            dropped_before_seq: 0,
                            cursor_reset: false,
                            gap_possible: false,
                            timed_out: true,
                            e2ee_mode: 0,
                            mls_epoch: 0,
                            trust_tier: 0,
                            has_declared_agent: false,
                            epoch_authenticator_b32: String::new(),
                            clone_detected: false,
                            events: Vec::new(),
                        }
                    };
                    return encode_party_poll_resp(&resp)
                        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()));
                }
            }
        }
    }

    async fn op_friends_list(&self) -> Result<Vec<u8>, IpcErr> {
        let control = {
            let st = self.inner.lock().await;
            st.control.clone()
        };
        if let Ok(rest_friends) = control.list_friends().await {
            // Refresh local pinned peers from disk so recent `peer trust`/`revoke` updates
            // are reflected when cross-checking server-reported root public keys.
            let fresh_peers = {
                let state_dir_path = self.state_dir_path.clone();
                tokio::task::spawn_blocking(move || {
                    let dir = open_state_dir(&state_dir_path).ok()?;
                    let _lock = lock_state(&dir).ok()?;
                    load_peers_store(&dir).ok()
                })
                .await
                .ok()
                .flatten()
            };

            let mut st = self.inner.lock().await;
            if let Some(peers) = fresh_peers {
                st.peers = peers;
            }
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let mut active_ids: HashSet<u64> = HashSet::with_capacity(rest_friends.friends.len());

            for edge in rest_friends.friends {
                active_ids.insert(edge.peer_account_id);
                if let Some(raw_h) = edge.peer_handle.as_deref()
                    && let Some(clean_h) = sanitize_validated_friend_handle(raw_h)
                {
                    st.handle_cache.insert(edge.peer_account_id, clean_h);
                }

                let verified_sn: String = match edge.peer_root_pubkey_b64.as_deref() {
                    Some(pk_b64) => match B64
                        .decode(pk_b64.as_bytes())
                        .ok()
                        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                    {
                        Some(pk) if mp_protocol::validate_ed25519_pubkey_strict(&pk).is_ok() => {
                            let pinned_mismatch = st.peers.peers.iter().any(|p| {
                                p.api_authority_hash == auth_hash
                                    && p.account_id == edge.peer_account_id
                                    && p.root_pubkey != [0u8; 32]
                                    && p.root_pubkey != pk
                            });
                            if pinned_mismatch {
                                log_line(&format!(
                                    "WARNING: KEY_MISMATCH for friend account_id={}: server root_pubkey disagrees with locally pinned peers.bin",
                                    edge.peer_account_id
                                ));
                                "KEY_MISMATCH".to_string()
                            } else {
                                let local_sn =
                                    compute_safety_number(edge.peer_account_id, &pk);
                                if let Some(srv_sn) = edge.peer_safety_number.as_deref()
                                    && !srv_sn.is_empty()
                                    && srv_sn != local_sn
                                {
                                    log_line(&format!(
                                        "ignoring mismatched server peer_safety_number for account_id={}; using locally computed SN",
                                        edge.peer_account_id
                                    ));
                                }
                                local_sn
                            }
                        }
                        _ => {
                            // Invalid pubkey: never trust server-provided safety number.
                            String::new()
                        }
                    },
                    // Omitted pubkey (e.g. blocked state == 3): clear any stale safety number.
                    None => String::new(),
                };

                let handle = st
                    .handle_cache
                    .get(&edge.peer_account_id)
                    .and_then(|h| sanitize_validated_friend_handle(h))
                    .unwrap_or_default();
                let entry = st
                    .friends
                    .entry(edge.peer_account_id)
                    .or_insert_with(|| FriendItem {
                        account_id: edge.peer_account_id,
                        state: edge.state,
                        updated_at_ms: edge.updated_at_ms,
                        presence_status: 0,
                        joinable_party_id: None,
                        handle: handle.clone(),
                        safety_number: String::new(),
                    });
                entry.state = edge.state;
                entry.updated_at_ms = edge.updated_at_ms;
                if !handle.is_empty() {
                    entry.handle = handle;
                }
                entry.safety_number = verified_sn;
            }

            // Reconcile snapshot: retain ONLY active REST edges while preserving
            // presence_status / joinable_party_id on surviving edges.
            st.friends.retain(|aid, _| active_ids.contains(aid));
        }

        let st = self.inner.lock().await;
        let mut friends: Vec<FriendItem> = st.friends.values().cloned().collect();
        friends.sort_by_key(|f| f.account_id);
        encode_friends_list_resp(&FriendsListResp { friends })
            .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_create(self: &Arc<Self>, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let _tx_guard = self.party_transition.lock().await;
        let req = decode_party_create_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let visibility = PartyVisibility::from_u8(req.visibility)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let join_mode = PartyJoinMode::from_u8(req.join_mode)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let req_policy = RelayPolicy::from_u8(req.relay_policy)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        let (control, device_secret, local_policy, default_relay_url) = {
            let st = self.inner.lock().await;
            if st.active_party.is_some() {
                return Err(ipc_err(
                    ERR_CONFLICT,
                    false,
                    "already in an active party (v1 enforces at most 1 active party per device_id)",
                ));
            }
            if !is_local_cwt_valid(&st.device, wall_now_secs()) {
                return Err(ipc_err(
                    ERR_CONFLICT,
                    false,
                    "local device CWT is expired or invalid; renew and reinstall CWT first",
                ));
            }
            (
                st.control.clone(),
                st.device.device_secret,
                st.device.local_relay_policy,
                st.device.default_relay_url.clone(),
            )
        };

        let eff_policy = effective_relay_policy(local_policy, req_policy).map_err(|_| {
            ipc_err(
                ERR_INVALID_PARAMS,
                false,
                "relay_policy_incompatible with local_relay_policy",
            )
        })?;

        let chosen_relay = match eff_policy {
            RelayPolicy::NoRelays => None,
            RelayPolicy::AllowRelays | RelayPolicy::ForceRelays => {
                if !req.relay_url.is_empty() {
                    Some(req.relay_url.clone())
                } else if !default_relay_url.is_empty() {
                    Some(default_relay_url)
                } else {
                    None
                }
            }
        };

        let transport = PartyP2pTransport::spawn(PartyP2pConfig {
            local_device_id: self.device_id,
            device_secret,
            effective_relay_policy: eff_policy,
            pinned_relay_url: chosen_relay.clone(),
        })
        .await
        .map_err(|e| ipc_err(ERR_INTERNAL, false, format!("p2p spawn failed: {e}")))?;

        let (p2p, event_stream) = transport.split();
        let pinned_for_sanitize = chosen_relay.as_deref().unwrap_or("");
        let endpoint_desc =
            gather_mp1_endpoint_descriptor(&p2p, eff_policy, pinned_for_sanitize).await;

        let req_body = CreatePartyRequest {
            visibility,
            join_mode,
            relay_policy: eff_policy,
            max_members: req.max_members.clamp(2, 12),
            endpoint: endpoint_desc,
            relay_url: chosen_relay,
        };
        let create_resp = match control
            .create_party_with_scope(&req_body, req.org_id, req.group_id)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                p2p.close().await;
                return Err(ipc_err(ERR_CONTROL_PLANE, true, e.to_string()));
            }
        };

        let party_id = create_resp.party_id;
        if let Err(err) = self
            .check_and_persist_epoch(party_id, create_resp.party_epoch, false)
            .await
        {
            p2p.close().await;
            if let Ok(pid) = PartyId::new(party_id) {
                let _ = control.leave_party(pid).await;
            }
            return Err(ipc_err(
                ERR_CONFLICT,
                false,
                format!("epoch floor check/persistence failed: {err}"),
            ));
        }

        let daemon_epoch = self.daemon_epoch();
        let ws_stop = CancellationToken::new();
        let (mp2_tx, mp2_rx) = mpsc::channel(64);

        // Install ActivePartySession BEFORE spawning driver tasks (zero startup race!).
        {
            let mut st = self.inner.lock().await;
            if st.active_party.is_some() {
                drop(st);
                p2p.close().await;
                return Err(ipc_err(
                    ERR_CONFLICT,
                    false,
                    "already in an active party",
                ));
            }
            let acc_id = st.device.account_id;
            let dev_id = st.device.device_id;
            st.active_party = Some(ActivePartySession {
                party_id,
                party_epoch: create_resp.party_epoch,
                leader_account_id: acc_id,
                leader_device_id: dev_id,
                visibility,
                join_mode,
                relay_policy: eff_policy,
                effective_relay_policy: eff_policy,
                max_members: req.max_members.clamp(2, 12),
                pinned_relay_url: create_resp.pinned_relay_url.clone(),
                room_code: String::new(),
                room_name: String::new(),
                share_url: String::new(),
                ws_path: format!("/v1/parties/{party_id}/ws"),
                e2ee_mode: 0,
                mls_epoch: 0,
                min_allowed_mls_epoch: 0,
                mls_rekey_required: false,
                mls_invite_epoch: 0,
                group_id_b64: None,
                party_ds_pubkey: None,
                is_mls_creator: false,
                pending_invite_fragment: None,
                pending_join_kp: None,
                processed_kp_refs: std::collections::HashSet::new(),
                mls_session: None,
                members: HashMap::new(),
                mp2_members: Vec::new(),
                mp2_connected: false,
                mp2_last_seq: 0,
                mp2_seen_seqs: VecDeque::new(),
                sent_mp2_msg_ids: VecDeque::new(),
                mp2_tx: Some(mp2_tx),
                pubkey_to_device: HashMap::new(),
                provenance_by_account: HashMap::new(),
                unpinned_alerts: HashMap::new(),
                key_mismatch_alerts: HashMap::new(),
                ring: PartyEventRing::new(party_id, daemon_epoch),
                wait_notify: Arc::new(Notify::new()),
                p2p: Some(Arc::clone(&p2p)),
                p2p_event_task: None,
                ws_stop: ws_stop.clone(),
                ws_task: None,
                cwt_task: None,
            });
            self.active_party_atomic.store(party_id, Ordering::Release);
        }

        let p2p_event_task = self.spawn_p2p_event_loop(party_id, event_stream, ws_stop.clone());
        let (ws_task, cwt_task) = self.spawn_party_drivers(party_id, ws_stop, mp2_rx);
        self.attach_party_tasks(party_id, Some(p2p_event_task), ws_task, cwt_task)
            .await;

        encode_party_create_resp(&PartyCreateResp {
            party_id: create_resp.party_id,
            party_epoch: create_resp.party_epoch,
            pinned_relay_url: create_resp.pinned_relay_url,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_join(self: &Arc<Self>, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let _tx_guard = self.party_transition.lock().await;
        let req = decode_party_join_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        let (control, device_secret, local_policy, default_relay_url) = {
            let st = self.inner.lock().await;
            if st.active_party.is_some() {
                return Err(ipc_err(
                    ERR_CONFLICT,
                    false,
                    "already in an active party (v1 enforces at most 1 active party per device_id)",
                ));
            }
            if !is_local_cwt_valid(&st.device, wall_now_secs()) {
                return Err(ipc_err(
                    ERR_CONFLICT,
                    false,
                    "local device CWT is expired or invalid; renew and reinstall CWT first",
                ));
            }
            (
                st.control.clone(),
                st.device.device_secret,
                st.device.local_relay_policy,
                st.device.default_relay_url.clone(),
            )
        };

        let effective_local = match req.relay_policy_override {
            Some(raw) => {
                let ov = RelayPolicy::from_u8(raw)
                    .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
                effective_relay_policy(local_policy, ov).map_err(|_| {
                    ipc_err(
                        ERR_INVALID_PARAMS,
                        false,
                        "relay_policy_incompatible with local_relay_policy",
                    )
                })?
            }
            None => local_policy,
        };

        // L4-4: Fetch party summary to validate relay policy & pinned relay URL before spawning P2P.
        // On 404 for a private invite-link party: if `invite_link.is_some()`, start safely in
        // ForceRelays (relay-only, zero direct IP leak!) when `AllowRelays` + default relay URL
        // are available; if `invite_link.is_none()`, fail closed with ERR_NOT_FOUND!
        let (
            party_policy,
            eff_policy,
            pinned_relay_str,
            visibility,
            join_mode,
            max_members,
            leader_acc,
            leader_dev,
        ) = match control.get_party(pid).await {
            Ok(s) => {
                let pp = RelayPolicy::from_u8(s.relay_policy).map_err(|_| {
                    ipc_err(
                        ERR_CONTROL_PLANE,
                        false,
                        "control plane returned invalid party relay_policy",
                    )
                })?;
                let eff = effective_relay_policy(effective_local, pp).map_err(|_| {
                    ipc_err(
                        ERR_INVALID_PARAMS,
                        false,
                        "relay_policy_incompatible with target party",
                    )
                })?;
                let vis =
                    PartyVisibility::from_u8(s.visibility).unwrap_or(PartyVisibility::Private);
                let jm = PartyJoinMode::from_u8(s.join_mode).unwrap_or(PartyJoinMode::InviteOnly);
                (
                    pp,
                    eff,
                    s.pinned_relay_url,
                    vis,
                    jm,
                    s.max_members,
                    s.leader_account_id,
                    s.leader_device_id,
                )
            }
            Err(ControlError::Api { status: 404, .. }) => {
                if req.invite_link.is_none() {
                    return Err(ipc_err(
                        ERR_NOT_FOUND,
                        false,
                        format!("party {} not found", req.party_id),
                    ));
                }
                // Private invite-link party hides GET /v1/parties/<id> before join.
                // Start strictly relay-only (`ForceRelays`) when local policy is `AllowRelays`
                // and a default relay URL is configured so direct IPs are NEVER leaked if the
                // party turns out to be `ForceRelays`!
                let safe_eff = if effective_local == RelayPolicy::AllowRelays
                    && !default_relay_url.is_empty()
                {
                    RelayPolicy::ForceRelays
                } else {
                    effective_local
                };
                let safe_relay = if safe_eff == RelayPolicy::NoRelays {
                    String::new()
                } else {
                    default_relay_url.clone()
                };
                (
                    safe_eff,
                    safe_eff,
                    safe_relay,
                    PartyVisibility::Private,
                    PartyJoinMode::InviteOnly,
                    12,
                    0,
                    0,
                )
            }
            Err(e) => {
                return Err(ipc_err(ERR_CONTROL_PLANE, true, e.to_string()));
            }
        };

        let relay_for_p2p = match eff_policy {
            RelayPolicy::NoRelays => None,
            RelayPolicy::AllowRelays | RelayPolicy::ForceRelays => {
                if !pinned_relay_str.is_empty() {
                    Some(pinned_relay_str.clone())
                } else if !default_relay_url.is_empty() {
                    Some(default_relay_url)
                } else {
                    None
                }
            }
        };

        let transport = PartyP2pTransport::spawn(PartyP2pConfig {
            local_device_id: self.device_id,
            device_secret,
            effective_relay_policy: eff_policy,
            pinned_relay_url: relay_for_p2p.clone(),
        })
        .await
        .map_err(|e| ipc_err(ERR_INTERNAL, false, format!("p2p spawn failed: {e}")))?;

        let (p2p, event_stream) = transport.split();
        let pinned_for_sanitize = relay_for_p2p.as_deref().unwrap_or("");
        let endpoint_desc =
            gather_mp1_endpoint_descriptor(&p2p, eff_policy, pinned_for_sanitize).await;

        let join_resp = match control
            .join_party(
                pid,
                &JoinPartyRequest {
                    endpoint: endpoint_desc,
                    invite_link: req.invite_link,
                },
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                p2p.close().await;
                if let Some((policy, pinned_url)) = e.relay_mismatch_info() {
                    let policy_label = policy
                        .map(crate::ipc_payloads::relay_policy_name)
                        .unwrap_or("unknown");
                    let msg = match pinned_url {
                        Some(pinned) => format!(
                            "relay_mismatch: party requires pinned relay '{}' (policy={:?}); inspect available relays with `mp-outpost relays` and update your device relay configuration",
                            pinned, policy
                        ),
                        None => format!(
                            "relay_mismatch: party relay policy '{policy_label}' is incompatible with your local relay policy; pass --relay-policy or update device relay configuration"
                        ),
                    };
                    return Err(ipc_err(ERR_CONFLICT, false, msg));
                }
                return Err(ipc_err(ERR_CONTROL_PLANE, true, e.to_string()));
            }
        };

        match join_resp {
            JoinPartyResponse::Joined { party_epoch } => {
                if let Err(err) = self
                    .check_and_persist_epoch(req.party_id, party_epoch, false)
                    .await
                {
                    p2p.close().await;
                    let _ = control.leave_party(pid).await;
                    return Err(ipc_err(
                        ERR_CONFLICT,
                        false,
                        format!("epoch floor check/persistence failed: {err}"),
                    ));
                }
                let daemon_epoch = self.daemon_epoch();
                let ws_stop = CancellationToken::new();
                let (mp2_tx, mp2_rx) = mpsc::channel(64);

                // Install ActivePartySession BEFORE spawning driver tasks (zero startup race!).
                {
                    let mut st = self.inner.lock().await;
                    if st.active_party.is_some() {
                        drop(st);
                        p2p.close().await;
                        return Err(ipc_err(
                            ERR_CONFLICT,
                            false,
                            "already in an active party",
                        ));
                    }
                    st.active_party = Some(ActivePartySession {
                        party_id: req.party_id,
                        party_epoch,
                        leader_account_id: leader_acc,
                        leader_device_id: leader_dev,
                        visibility,
                        join_mode,
                        relay_policy: party_policy,
                        effective_relay_policy: eff_policy,
                        max_members,
                        pinned_relay_url: relay_for_p2p.unwrap_or_default(),
                        room_code: String::new(),
                        room_name: String::new(),
                        share_url: String::new(),
                        ws_path: format!("/v1/parties/{}/ws", req.party_id),
                        e2ee_mode: 0,
                        mls_epoch: 0,
                        min_allowed_mls_epoch: 0,
                        mls_rekey_required: false,
                        mls_invite_epoch: 0,
                        group_id_b64: None,
                        party_ds_pubkey: None,
                        is_mls_creator: false,
                        pending_invite_fragment: None,
                        pending_join_kp: None,
                        processed_kp_refs: std::collections::HashSet::new(),
                        mls_session: None,
                        members: HashMap::new(),
                        mp2_members: Vec::new(),
                        mp2_connected: false,
                        mp2_last_seq: 0,
                        mp2_seen_seqs: VecDeque::new(),
                        sent_mp2_msg_ids: VecDeque::new(),
                        mp2_tx: Some(mp2_tx),
                        pubkey_to_device: HashMap::new(),
                        provenance_by_account: HashMap::new(),
                        unpinned_alerts: HashMap::new(),
                        key_mismatch_alerts: HashMap::new(),
                        ring: PartyEventRing::new(req.party_id, daemon_epoch),
                        wait_notify: Arc::new(Notify::new()),
                        p2p: Some(Arc::clone(&p2p)),
                        p2p_event_task: None,
                        ws_stop: ws_stop.clone(),
                        ws_task: None,
                        cwt_task: None,
                    });
                    self.active_party_atomic
                        .store(req.party_id, Ordering::Release);
                }

                let p2p_event_task =
                    self.spawn_p2p_event_loop(req.party_id, event_stream, ws_stop.clone());
                let (ws_task, cwt_task) = self.spawn_party_drivers(req.party_id, ws_stop, mp2_rx);
                self.attach_party_tasks(req.party_id, Some(p2p_event_task), ws_task, cwt_task)
                    .await;

                Ok(encode_party_join_resp(&PartyJoinResp {
                    status: 0,
                    party_epoch,
                    request_id: 0,
                }))
            }
            JoinPartyResponse::PendingApproval { request_id } => {
                p2p.close().await;
                Ok(encode_party_join_resp(&PartyJoinResp {
                    status: 1,
                    party_epoch: 0,
                    request_id,
                }))
            }
        }
    }

    async fn op_party_leave(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let _tx_guard = self.party_transition.lock().await;
        let party_id =
            decode_u64_req(payload).map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = {
            let st = self.inner.lock().await;
            st.control.clone()
        };
        let resp = control
            .leave_party(pid)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        self.teardown_active_party(party_id, "operator_leave").await;
        if let Ok(state_dir) = open_state_dir(&self.state_dir_path)
            && let Ok(lock) = lock_state(&state_dir)
        {
            remove_mls_room_snapshot(&self.state_dir_path, &lock, self.device_id, party_id);
        }
        Ok(encode_party_epoch_resp(&PartyEpochResp {
            ok: resp.left,
            party_epoch: resp.party_epoch,
        }))
    }

    async fn op_party_disband(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let _tx_guard = self.party_transition.lock().await;
        let req = decode_party_epoch_op_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let (control, expected_epoch) = {
            let st = self.inner.lock().await;
            let ep = if req.expected_party_epoch > 0 {
                req.expected_party_epoch
            } else {
                st.active_party
                    .as_ref()
                    .filter(|s| s.party_id == req.party_id)
                    .map_or(0, |s| s.party_epoch)
            };
            (st.control.clone(), ep)
        };
        let resp = control
            .disband_party(pid, expected_epoch)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        let persist_res = self
            .check_and_persist_epoch(req.party_id, resp.party_epoch, true)
            .await;
        self.teardown_active_party(req.party_id, "operator_disband")
            .await;
        if let Err(err) = persist_res {
            return Err(ipc_err(
                ERR_INTERNAL,
                false,
                format!("party disbanded on server but durable epoch floor persist failed: {err}"),
            ));
        }
        Ok(encode_party_epoch_resp(&PartyEpochResp {
            ok: resp.disbanded,
            party_epoch: resp.party_epoch,
        }))
    }

    async fn op_party_kick(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_kick_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let target = AccountId::new(req.target_account_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let (control, expected_epoch) = {
            let st = self.inner.lock().await;
            let ep = if req.expected_party_epoch > 0 {
                req.expected_party_epoch
            } else {
                st.active_party
                    .as_ref()
                    .filter(|s| s.party_id == req.party_id)
                    .map_or(0, |s| s.party_epoch)
            };
            (st.control.clone(), ep)
        };
        let resp = control
            .kick_member(pid, target, expected_epoch)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        Ok(encode_party_epoch_resp(&PartyEpochResp {
            ok: resp.kicked,
            party_epoch: resp.party_epoch,
        }))
    }

    async fn op_party_promote(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_promote_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let target = DeviceId::new(req.target_device_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let (control, expected_epoch) = {
            let st = self.inner.lock().await;
            let ep = if req.expected_party_epoch > 0 {
                req.expected_party_epoch
            } else {
                st.active_party
                    .as_ref()
                    .filter(|s| s.party_id == req.party_id)
                    .map_or(0, |s| s.party_epoch)
            };
            (st.control.clone(), ep)
        };
        let resp = control
            .promote_member(pid, target, expected_epoch)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        Ok(encode_party_epoch_resp(&PartyEpochResp {
            ok: resp.promoted,
            party_epoch: resp.party_epoch,
        }))
    }

    async fn op_party_invite_mint(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_invite_mint_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let target = match req.target_account_id {
            Some(id) => Some(
                AccountId::new(id)
                    .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?,
            ),
            None => None,
        };
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .mint_party_invite(
                pid,
                &MintPartyInviteRequest {
                    target_account_id: target,
                    max_uses: req.max_uses,
                    ttl_sec: req.ttl_sec,
                },
            )
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        encode_party_invite_mint_resp(&PartyInviteMintResp {
            party_invite_id: resp.party_invite_id,
            expires_at_ms: resp.expires_at_ms,
            invite_link: resp.invite_link,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_invite_revoke(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_invite_revoke_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let inv_id = PartyInviteId::new(req.party_invite_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .revoke_party_invite(pid, inv_id)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        Ok(encode_bool_resp(resp.revoked))
    }

    async fn op_party_requests_list(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_requests_list_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .list_party_requests(pid, req.cursor)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        let items = resp
            .requests
            .into_iter()
            .map(|r| JoinRequestItem {
                request_id: r.request_id,
                account_id: r.account_id,
                device_id: r.device_id,
                root_pubkey_b64: r.root_pubkey_b64,
                device_pubkey_b64: r.device_pubkey_b64,
                requested_at_ms: r.requested_at_ms,
                reserved_until_ms: r.reserved_until_ms,
            })
            .collect();
        encode_party_requests_list_resp(&PartyRequestsListResp { requests: items })
            .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_request_approve(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_request_approve_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let rid = RequestId::new(req.request_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let aid = AccountId::new(req.account_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let did = DeviceId::new(req.device_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let (control, expected_epoch) = {
            let st = self.inner.lock().await;
            let ep = if req.expected_party_epoch > 0 {
                req.expected_party_epoch
            } else {
                st.active_party
                    .as_ref()
                    .filter(|s| s.party_id == req.party_id)
                    .map_or(0, |s| s.party_epoch)
            };
            (st.control.clone(), ep)
        };
        let resp = control
            .approve_party_request(
                pid,
                rid,
                &ApprovePartyRequest {
                    expected_party_epoch: expected_epoch,
                    account_id: aid,
                    device_id: did,
                    device_pubkey_sha256: req.device_pubkey_sha256,
                },
            )
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        Ok(encode_party_request_approve_resp(&PartyRequestApproveResp {
            approved: resp.approved,
            reserved_until_ms: resp.reserved_until_ms,
        }))
    }

    async fn op_party_request_reject(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_request_reject_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let pid = PartyId::new(req.party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let rid = RequestId::new(req.request_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .reject_party_request(pid, rid, req.expected_party_epoch)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        Ok(encode_bool_resp(resp.rejected))
    }

    async fn op_friend_request(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let target = decode_u64_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let aid = AccountId::new(target)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .send_friend_request(aid)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        Ok(encode_friend_edge_resp(&crate::ipc_payloads::FriendEdgeResp {
            target_account_id: resp.target_account_id,
            state: resp.state,
        }))
    }

    async fn op_friend_remove(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let target = decode_u64_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let aid = AccountId::new(target)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .remove_friend(aid)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        if resp.removed {
            self.inner.lock().await.friends.remove(&target);
        }
        Ok(encode_bool_resp(resp.removed))
    }

    async fn op_friend_block(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let target = decode_u64_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let aid = AccountId::new(target)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .block_account(aid)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        self.inner.lock().await.friends.remove(&target);
        Ok(encode_friend_edge_resp(&crate::ipc_payloads::FriendEdgeResp {
            target_account_id: resp.target_account_id,
            state: resp.state,
        }))
    }

    async fn op_resolve_handle(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let handle = decode_resolve_handle_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let control = self.inner.lock().await.control.clone();
        let resp = control
            .resolve_handle(&handle)
            .await
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, true, e.to_string()))?;
        let pk_raw = B64
            .decode(resp.root_pubkey_b64.as_bytes())
            .map_err(|e| ipc_err(ERR_CONTROL_PLANE, false, format!("invalid root_pubkey_b64: {e}")))?;
        let root_pubkey: [u8; 32] = pk_raw
            .try_into()
            .map_err(|_| ipc_err(ERR_CONTROL_PLANE, false, "root_pubkey is not 32 bytes"))?;
        self.inner
            .lock()
            .await
            .handle_cache
            .insert(resp.account_id, resp.handle.clone());
        encode_resolve_handle_resp(&ResolveHandleResp {
            account_id: resp.account_id,
            handle: resp.handle,
            root_pubkey,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    /// Attaches (or updates) an `mp2`-only active party session without spawning `iroh` P2P.
    #[allow(clippy::too_many_arguments)]
    async fn attach_mp2_room_session(
        self: &Arc<Self>,
        party_id: u64,
        room_code: String,
        room_name: String,
        share_url: String,
        ws_path: String,
        initial_members: Vec<Mp2Member>,
        e2ee_mode: u8,
        party_ds_pubkey: Option<[u8; 32]>,
        group_id_b64: Option<String>,
        is_creator: bool,
        invite_fragment: Option<InviteFragmentV2>,
    ) {
        let existing_pid = {
            let mut st = self.inner.lock().await;
            if let Some(sess) = st.active_party.as_mut() {
                if sess.party_id == party_id {
                    if !room_code.is_empty() {
                        sess.room_code = room_code;
                    }
                    if !room_name.is_empty() {
                        sess.room_name = room_name;
                    }
                    if !share_url.is_empty() {
                        sess.share_url = share_url;
                    }
                    if !initial_members.is_empty() {
                        sess.mp2_members = initial_members;
                    }
                    if e2ee_mode == 1 {
                        sess.e2ee_mode = 1;
                    }
                    if party_ds_pubkey.is_some() {
                        sess.party_ds_pubkey = party_ds_pubkey;
                    }
                    if group_id_b64.is_some() {
                        sess.group_id_b64 = group_id_b64;
                    }
                    if invite_fragment.is_some() {
                        sess.pending_invite_fragment = invite_fragment;
                    }
                    return;
                }
                Some(sess.party_id)
            } else {
                None
            }
        };

        if let Some(old_pid) = existing_pid {
            self.teardown_active_party(old_pid, "switched_room").await;
        }

        let daemon_epoch = self.daemon_epoch();
        let ws_stop = CancellationToken::new();
        let (mp2_tx, mp2_rx) = mpsc::channel(64);
        let expected_ws_path = format!("/v1/parties/{party_id}/ws");
        let eff_ws_path = if ws_path.is_empty() {
            expected_ws_path
        } else {
            ws_path
        };

        {
            let mut st = self.inner.lock().await;
            let acc_id = st.device.account_id;
            let dev_id = st.device.device_id;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let peers_clone = st.peers.clone();
            for m in &initial_members {
                if m.account_id > 0 && !m.is_guest && !m.handle.is_empty() {
                    st.handle_cache.insert(m.account_id, m.handle.clone());
                }
            }
            let mut sess = ActivePartySession {
                party_id,
                party_epoch: 1,
                leader_account_id: acc_id,
                leader_device_id: dev_id,
                visibility: PartyVisibility::Friends,
                join_mode: PartyJoinMode::InviteOnly,
                relay_policy: RelayPolicy::AllowRelays,
                effective_relay_policy: RelayPolicy::AllowRelays,
                max_members: 12,
                pinned_relay_url: String::new(),
                room_code,
                room_name,
                share_url,
                ws_path: eff_ws_path,
                e2ee_mode,
                mls_epoch: 0,
                min_allowed_mls_epoch: 0,
                mls_rekey_required: false,
                mls_invite_epoch: 0,
                group_id_b64: group_id_b64.clone(),
                party_ds_pubkey,
                is_mls_creator: is_creator,
                pending_invite_fragment: invite_fragment,
                pending_join_kp: None,
                processed_kp_refs: std::collections::HashSet::new(),
                mls_session: None,
                members: HashMap::new(),
                mp2_members: initial_members.clone(),
                mp2_connected: false,
                mp2_last_seq: 0,
                mp2_seen_seqs: VecDeque::new(),
                sent_mp2_msg_ids: VecDeque::new(),
                mp2_tx: Some(mp2_tx),
                pubkey_to_device: HashMap::new(),
                provenance_by_account: HashMap::new(),
                unpinned_alerts: HashMap::new(),
                key_mismatch_alerts: HashMap::new(),
                ring: PartyEventRing::new(party_id, daemon_epoch),
                wait_notify: Arc::new(Notify::new()),
                p2p: None,
                p2p_event_task: None,
                ws_stop: ws_stop.clone(),
                ws_task: None,
                cwt_task: None,
            };
            update_mp2_provenance_cache(&mut sess, &initial_members, auth_hash, &peers_clone);
            st.active_party = Some(sess);
            self.active_party_atomic.store(party_id, Ordering::Release);
        }

        // For `e2ee_mode == 1`, attempt immediate snapshot restore or creator bootstrap BEFORE
        // spawning the live WS loop so the creator's epoch-0 MLS group is ready synchronously!
        if e2ee_mode == 1 {
            let mut restored = false;
            if let Some(ref gid_b64) = group_id_b64 {
                restored = self
                    .try_restore_persisted_mls_session(party_id, gid_b64)
                    .await
                    .unwrap_or(false);
            }
            if !restored
                && is_creator
                && party_ds_pubkey.is_some()
                && let Err(e) = self.bootstrap_mls_creator_group(party_id).await
            {
                log_line(&format!(
                    "Party {party_id} synchronous MLS creator bootstrap deferred/failed: {e}"
                ));
            }
        }

        let (ws_task, cwt_task) = self.spawn_party_drivers(party_id, ws_stop, mp2_rx);
        self.attach_party_tasks(party_id, None, ws_task, cwt_task)
            .await;
    }

    async fn op_room_invite(self: &Arc<Self>, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let _tx_guard = self.party_transition.lock().await;
        let req = decode_room_invite_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        let (control, active_pid) = {
            let st = self.inner.lock().await;
            (st.control.clone(), st.active_party.as_ref().map(|s| s.party_id))
        };

        let clean_handle = req
            .handle
            .as_deref()
            .map(|h| h.trim().trim_start_matches('@').to_string())
            .filter(|h| !h.is_empty());

        let creating_new = req.party_id.or(active_pid).is_none();
        let rest_req = RoomInviteRequest {
            handle: clean_handle,
            party_id: req.party_id.or(active_pid),
            name: req.name.clone(),
            e2ee_mode: Some(1),
        };
        let resp = control
            .room_invite(&rest_req)
            .await
            .map_err(|e| map_control_err_to_ipc(&e))?;

        let validated_ws_path = validate_party_ws_path(resp.party_id, &resp.ws_path)?;
        let ds_pubkey = resp
            .party_ds_pubkey_b64
            .as_deref()
            .and_then(decode_ds_pubkey_b64);
        let is_creator = resp.is_creator.unwrap_or(creating_new);

        self.attach_mp2_room_session(
            resp.party_id,
            resp.room_code.clone(),
            req.name.unwrap_or_default(),
            resp.share_url.clone(),
            validated_ws_path.clone(),
            Vec::new(),
            resp.e2ee_mode,
            ds_pubkey,
            resp.group_id_b64.clone(),
            is_creator,
            None,
        )
        .await;

        let mut share_url = resp.share_url;
        if resp.e2ee_mode == 1
            && let Ok((_invite_id, frag_b64u)) =
                self.mint_mls_invite_for_active_party(resp.party_id).await
        {
            share_url = format!("https://multiplayer.tech/p/i/{}#{frag_b64u}", resp.party_id);
            let mut st = self.inner.lock().await;
            if let Some(sess) = st.active_party.as_mut()
                && sess.party_id == resp.party_id
            {
                sess.share_url = share_url.clone();
            }
        }

        encode_room_invite_resp(&RoomInviteIpcResp {
            party_id: resp.party_id,
            room_code: resp.room_code,
            share_url,
            handle_url: resp.handle_url,
            ws_path: validated_ws_path,
            invited_handle: resp.invited_handle,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_room_enter(self: &Arc<Self>, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let _tx_guard = self.party_transition.lock().await;
        let req = decode_room_enter_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        // Extract any 114-byte `InviteFragmentV2` locally so `invite_seed` NEVER leaves the
        // client to `POST /v1/rooms/enter` (Spec v3.1 §4.2)!
        let (enter_target, invite_fragment) =
            if let Some((pid_from_frag, frag)) = extract_mls_invite_fragment(&req.target) {
                (pid_from_frag.to_string(), Some(frag))
            } else {
                (normalize_room_enter_target(&req.target), None)
            };

        let control = self.inner.lock().await.control.clone();
        let rest_req = RoomEnterRequest {
            target: enter_target,
            client: "outpost".to_string(),
            agent_name: req.agent_name.or_else(|| Some("Outpost".to_string())),
        };
        let resp = control
            .room_enter(&rest_req)
            .await
            .map_err(|e| map_control_err_to_ipc(&e))?;

        let validated_ws_path = validate_party_ws_path(resp.party_id, &resp.ws_path)?;
        let ds_pubkey = resp
            .party_ds_pubkey_b64
            .as_deref()
            .and_then(decode_ds_pubkey_b64);
        let eff_e2ee_mode = if resp.e2ee_mode == 1 || invite_fragment.is_some() {
            1
        } else {
            0
        };
        let eff_group_id_b64 = resp.group_id_b64.clone().or_else(|| {
            invite_fragment
                .as_ref()
                .map(|f| B64.encode(f.group_id))
        });

        let mp2_members: Vec<Mp2Member> = resp
            .members
            .iter()
            .map(|m| {
                let is_guest = m.is_guest || m.account_id == 0;
                let is_browser = m.is_browser
                    || m.client.trim().eq_ignore_ascii_case("web")
                    || m.client.trim().eq_ignore_ascii_case("browser");
                Mp2Member {
                    account_id: if is_guest { 0 } else { m.account_id },
                    handle: m.handle.clone(),
                    client: m.client.clone(),
                    is_guest,
                    is_browser,
                    agent_name: m.agent_name.clone(),
                    agent_state: None,
                    agent_summary: None,
                    status: m.status.clone(),
                    device_id: m.device_id,
                    nick: None,
                }
            })
            .collect();

        self.attach_mp2_room_session(
            resp.party_id,
            resp.room_code.clone(),
            resp.name.clone(),
            resp.share_url.clone(),
            validated_ws_path.clone(),
            mp2_members,
            eff_e2ee_mode,
            ds_pubkey,
            eff_group_id_b64,
            false,
            invite_fragment,
        )
        .await;

        let ipc_members: Vec<RoomMemberIpc> = resp
            .members
            .into_iter()
            .map(|m| {
                let is_guest = m.is_guest || m.account_id == 0;
                RoomMemberIpc {
                    account_id: if is_guest { 0 } else { m.account_id },
                    handle: if is_guest {
                        format_guest_display_name(&m.handle)
                    } else {
                        m.handle
                    },
                    client: m.client,
                    agent_name: m.agent_name,
                    status: m.status,
                }
            })
            .collect();

        encode_room_enter_resp(&RoomEnterIpcResp {
            party_id: resp.party_id,
            room_code: resp.room_code,
            name: resp.name,
            share_url: resp.share_url,
            ws_path: validated_ws_path,
            members: ipc_members,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_room_leave(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let _tx_guard = self.party_transition.lock().await;
        let req = decode_room_leave_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        let (control, target_pid) = {
            let st = self.inner.lock().await;
            let pid = req
                .party_id
                .or_else(|| st.active_party.as_ref().map(|s| s.party_id));
            (st.control.clone(), pid)
        };
        let Some(party_id) = target_pid else {
            return Err(ipc_err(ERR_NOT_FOUND, false, "not currently in a party"));
        };
        let pid = PartyId::new(party_id)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        let left = match control.room_leave(pid).await {
            Ok(resp) => resp.left,
            Err(ControlError::Api { status: 404, .. }) => control
                .leave_party(pid)
                .await
                .map(|r| r.left)
                .map_err(|e| map_control_err_to_ipc(&e))?,
            Err(e) => return Err(map_control_err_to_ipc(&e)),
        };
        self.teardown_active_party(party_id, "operator_leave").await;
        Ok(encode_room_leave_resp(&RoomLeaveIpcResp { left, party_id }))
    }

    async fn op_friends_live(&self) -> Result<Vec<u8>, IpcErr> {
        let control = self.inner.lock().await.control.clone();
        match control.friends_live().await {
            Ok(live) => {
                {
                    let mut st = self.inner.lock().await;
                    for f in &live.friends {
                        if !f.handle.is_empty() {
                            st.handle_cache.insert(f.account_id, f.handle.clone());
                        }
                    }
                }
                let resp = FriendsLiveIpcResp {
                    friends: live
                        .friends
                        .into_iter()
                        .map(|f| LiveFriendIpc {
                            account_id: f.account_id,
                            handle: f.handle,
                            state: f.state,
                            presence: f.presence,
                            client: f.client,
                            party_room_code: f.party_room_code,
                            joinable: f.joinable,
                        })
                        .collect(),
                    pending_invites: live
                        .pending_invites
                        .into_iter()
                        .map(|inv| PendingInviteIpc {
                            party_id: inv.party_id,
                            room_code: inv.room_code,
                            from_handle: inv.from_handle,
                            created_at_ms: inv.created_at_ms,
                        })
                        .collect(),
                };
                encode_friends_live_resp(&resp)
                    .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
            }
            Err(ControlError::Api { status: 404, .. }) => {
                let _ = self.op_friends_list().await;
                let st = self.inner.lock().await;
                let friends = st
                    .friends
                    .values()
                    .map(|f| LiveFriendIpc {
                        account_id: f.account_id,
                        handle: f.handle.clone(),
                        state: match f.state {
                            0 => "friend",
                            1 => "pending_out",
                            2 => "pending_in",
                            3 => "blocked",
                            _ => "unknown",
                        }
                        .to_string(),
                        presence: match f.presence_status {
                            1 => "online",
                            2 => "in_party",
                            _ => "offline",
                        }
                        .to_string(),
                        client: None,
                        party_room_code: None,
                        joinable: f.joinable_party_id.is_some(),
                    })
                    .collect();
                encode_friends_live_resp(&FriendsLiveIpcResp {
                    friends,
                    pending_invites: Vec::new(),
                })
                .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
            }
            Err(e) => Err(map_control_err_to_ipc(&e)),
        }
    }
}

impl DaemonHandler for AppDaemon {
    async fn handle_request(
        &self,
        conn_id: u64,
        opcode: IpcOpcode,
        _request_id: u64,
        payload: Vec<u8>,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>, (u16, bool, String)> {
        // Note: `handle_request` takes `&self`, whereas a few operations spawn background tasks
        // requiring `Arc<Self>`. We use `AppDaemonHandle(Arc<AppDaemon>)` below as the actual
        // `DaemonHandler` impl! This fallback never gets used directly.
        let _ = (conn_id, opcode, payload, cancel);
        Err(ipc_err(
            ERR_INTERNAL,
            false,
            "use AppDaemonHandler wrapper",
        ))
    }

    fn active_party_id(&self) -> u64 {
        self.active_party_atomic.load(Ordering::Acquire)
    }
}

/// Thin `Arc<AppDaemon>` wrapper implementing `DaemonHandler` so background tasks can hold `Arc<AppDaemon>`.
pub struct AppDaemonHandler {
    daemon: Arc<AppDaemon>,
}

impl AppDaemonHandler {
    pub fn new(daemon: Arc<AppDaemon>) -> Self {
        Self { daemon }
    }
}

impl DaemonHandler for AppDaemonHandler {
    async fn handle_request(
        &self,
        conn_id: u64,
        opcode: IpcOpcode,
        _request_id: u64,
        payload: Vec<u8>,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>, (u16, bool, String)> {
        match opcode {
            IpcOpcode::GetStatus => self.daemon.op_get_status().await,
            IpcOpcode::ReloadDevice => self.daemon.op_reload_device().await,
            IpcOpcode::PartyList => self.daemon.op_party_list().await,
            IpcOpcode::PartyMembers => self.daemon.op_party_members(&payload).await,
            IpcOpcode::PartySendChat => self.daemon.op_party_send_chat(conn_id, &payload).await,
            IpcOpcode::PartyPostBoard => self.daemon.op_party_post_board(conn_id, &payload).await,
            IpcOpcode::PartyPoll => self.daemon.op_party_poll(&payload).await,
            IpcOpcode::PartyWait => self.daemon.op_party_wait(&payload, cancel).await,
            IpcOpcode::PartySendControlNotice => {
                self.daemon.op_party_send_control_notice(&payload).await
            }
            IpcOpcode::FriendsList => self.daemon.op_friends_list().await,
            IpcOpcode::PartyCreate => self.daemon.op_party_create(&payload).await,
            IpcOpcode::PartyJoin => self.daemon.op_party_join(&payload).await,
            IpcOpcode::PartyLeave => self.daemon.op_party_leave(&payload).await,
            IpcOpcode::PartyDisband => self.daemon.op_party_disband(&payload).await,
            IpcOpcode::PartyKick => self.daemon.op_party_kick(&payload).await,
            IpcOpcode::PartyPromote => self.daemon.op_party_promote(&payload).await,
            IpcOpcode::PartyInviteMint => self.daemon.op_party_invite_mint(&payload).await,
            IpcOpcode::PartyInviteRevoke => self.daemon.op_party_invite_revoke(&payload).await,
            IpcOpcode::PartyRequestsList => self.daemon.op_party_requests_list(&payload).await,
            IpcOpcode::PartyRequestApprove => self.daemon.op_party_request_approve(&payload).await,
            IpcOpcode::PartyRequestReject => self.daemon.op_party_request_reject(&payload).await,
            IpcOpcode::FriendRequest => self.daemon.op_friend_request(&payload).await,
            IpcOpcode::FriendRemove => self.daemon.op_friend_remove(&payload).await,
            IpcOpcode::FriendBlock => self.daemon.op_friend_block(&payload).await,
            IpcOpcode::ResolveHandle => self.daemon.op_resolve_handle(&payload).await,
            IpcOpcode::RoomInvite => self.daemon.op_room_invite(&payload).await,
            IpcOpcode::RoomEnter => self.daemon.op_room_enter(&payload).await,
            IpcOpcode::RoomLeave => self.daemon.op_room_leave(&payload).await,
            IpcOpcode::FriendsLive => self.daemon.op_friends_live().await,
            _ => Err(ipc_err(
                ERR_INVALID_PARAMS,
                false,
                format!("unsupported opcode {opcode:?}"),
            )),
        }
    }

    fn active_party_id(&self) -> u64 {
        self.daemon.active_party_atomic.load(Ordering::Acquire)
    }

    fn on_daemon_started(&self, daemon_epoch: u64) {
        self.daemon
            .cached_daemon_epoch
            .store(daemon_epoch, Ordering::Release);
        self.daemon.start_background_tasks();
    }

    fn on_client_count_changed(&self, count: usize) {
        self.daemon.handle_client_count_changed(count);
    }

    async fn health_tick(&self) {
        // Briefly acquire the daemon runtime state lock to prove the engine is not wedged.
        let _guard = self.daemon.inner.lock().await;
    }

    async fn on_drain(&self, mode: DrainMode) {
        self.daemon.shutdown.cancel();
        self.daemon.cancel_unattended_timer();
        let active_pid = self.daemon.active_party_atomic.load(Ordering::Acquire);
        if active_pid != 0 {
            if mode == DrainMode::StopLeaveParty
                && let Ok(pid) = PartyId::new(active_pid)
            {
                let control = self.daemon.inner.lock().await.control.clone();
                let _ = tokio::time::timeout(Duration::from_millis(800), control.leave_party(pid))
                    .await;
            }
            self.daemon
                .teardown_active_party(active_pid, "daemon_drain")
                .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Pure Helpers
// ---------------------------------------------------------------------------

fn build_device_control_client(device: &DeviceRecord) -> Result<ControlClient, String> {
    let cfg = build_control_client_config(&device.api_authority).map_err(|e| e.to_string())?;
    let aid = AccountId::new(device.account_id).map_err(|e| e.to_string())?;
    let did = DeviceId::new(device.device_id).map_err(|e| e.to_string())?;
    let signer = RequestSigner::device(aid, did, device.device_secret);
    Ok(ControlClient::with_device_signer(cfg, signer))
}

/// Strictly sanitizes a local `EndpointDescriptor` for publication to `api.multiplayer.tech`
/// using `mp-protocol`'s exact `EndpointDescriptor::validate_against_policy` rules:
/// - `ForceRelays`: clears `direct_addrs` and keeps `relay_url`.
/// - `NoRelays`: clears `relay_url` and retains only direct addresses accepted under `NoRelays`.
/// - `AllowRelays`: retains ONLY public routable direct addresses accepted under `AllowRelays`
///   (zero RFC 1918, CGNAT, link-local, ULA, or loopback addresses!).
pub(crate) fn sanitize_endpoint_for_mp1(
    mut desc: EndpointDescriptor,
    eff_policy: RelayPolicy,
    pinned_relay_url: &str,
) -> EndpointDescriptor {
    match eff_policy {
        RelayPolicy::ForceRelays => {
            desc.transport_kind = TransportKind::IrohQuic;
            desc.direct_addrs.clear();
            if !pinned_relay_url.is_empty() {
                desc.relay_url = pinned_relay_url.to_string();
            }
            desc
        }
        RelayPolicy::NoRelays => {
            desc.relay_url.clear();
            desc.direct_addrs.retain(|&a| {
                EndpointDescriptor {
                    transport_kind: desc.transport_kind,
                    relay_url: String::new(),
                    direct_addrs: vec![a],
                }
                .validate_against_policy(RelayPolicy::NoRelays, "")
                .is_ok()
            });
            desc.direct_addrs.truncate(MAX_DIRECT_ADDRS);
            desc
        }
        RelayPolicy::AllowRelays => {
            if desc.relay_url.is_empty() && !pinned_relay_url.is_empty() {
                desc.relay_url = pinned_relay_url.to_string();
            }
            if validate_relay_url(&desc.relay_url).is_err() {
                desc.relay_url.clear();
            }
            let check_relay = desc.relay_url.clone();
            desc.direct_addrs.retain(|&a| {
                EndpointDescriptor {
                    transport_kind: desc.transport_kind,
                    relay_url: check_relay.clone(),
                    direct_addrs: vec![a],
                }
                .validate_against_policy(RelayPolicy::AllowRelays, &check_relay)
                .is_ok()
            });
            desc.direct_addrs.truncate(MAX_DIRECT_ADDRS);
            desc
        }
    }
}

/// Prepares a policy-compliant `PeerDialTarget` for `outpost-p2p`:
/// - Under `ForceRelays`: strips `direct_addrs` and pins `relay_url` so dialing an `allow_relays`
///   peer never triggers `PolicyViolation("force_relays forbids direct IP addresses")`.
/// - Under `NoRelays`: strips `relay_url` and requires at least one valid direct address.
/// - Under `AllowRelays`: keeps valid relay URL (if party allows relays) and valid direct addrs.
pub(crate) fn prepare_peer_dial_target(
    eff_policy: RelayPolicy,
    pinned_relay_url: &str,
    party_relay: RelayPolicy,
    member: &PartyMemberRecord,
) -> Option<PeerDialTarget> {
    let dev_id = member.device_id.get();
    match eff_policy {
        RelayPolicy::ForceRelays => {
            let relay_url = if !pinned_relay_url.is_empty() {
                pinned_relay_url.to_string()
            } else if !member.endpoint.relay_url.is_empty() {
                member.endpoint.relay_url.clone()
            } else {
                return None;
            };
            if validate_relay_url(&relay_url).is_err() {
                return None;
            }
            Some(PeerDialTarget {
                device_id: dev_id,
                device_pubkey: member.device_pubkey,
                remote_relay_policy: RelayPolicy::ForceRelays,
                endpoint: EndpointDescriptor {
                    transport_kind: TransportKind::IrohQuic,
                    relay_url,
                    direct_addrs: Vec::new(),
                },
            })
        }
        RelayPolicy::NoRelays => {
            let direct_addrs: Vec<_> = member
                .endpoint
                .direct_addrs
                .iter()
                .copied()
                .filter(|&a| {
                    EndpointDescriptor {
                        transport_kind: member.endpoint.transport_kind,
                        relay_url: String::new(),
                        direct_addrs: vec![a],
                    }
                    .validate_against_policy(RelayPolicy::NoRelays, "")
                    .is_ok()
                })
                .take(MAX_DIRECT_ADDRS)
                .collect();
            if direct_addrs.is_empty() {
                return None;
            }
            Some(PeerDialTarget {
                device_id: dev_id,
                device_pubkey: member.device_pubkey,
                remote_relay_policy: RelayPolicy::NoRelays,
                endpoint: EndpointDescriptor {
                    transport_kind: member.endpoint.transport_kind,
                    relay_url: String::new(),
                    direct_addrs,
                },
            })
        }
        RelayPolicy::AllowRelays => {
            let relay_url = if party_relay != RelayPolicy::NoRelays
                && !member.endpoint.relay_url.is_empty()
                && validate_relay_url(&member.endpoint.relay_url).is_ok()
            {
                member.endpoint.relay_url.clone()
            } else {
                String::new()
            };
            let direct_addrs: Vec<_> = member
                .endpoint
                .direct_addrs
                .iter()
                .copied()
                .filter(|&a| {
                    EndpointDescriptor {
                        transport_kind: member.endpoint.transport_kind,
                        relay_url: relay_url.clone(),
                        direct_addrs: vec![a],
                    }
                    .validate_against_policy(RelayPolicy::AllowRelays, &relay_url)
                    .is_ok()
                })
                .take(MAX_DIRECT_ADDRS)
                .collect();
            if relay_url.is_empty() && direct_addrs.is_empty() {
                return None;
            }
            Some(PeerDialTarget {
                device_id: dev_id,
                device_pubkey: member.device_pubkey,
                remote_relay_policy: party_relay,
                endpoint: EndpointDescriptor {
                    transport_kind: member.endpoint.transport_kind,
                    relay_url,
                    direct_addrs,
                },
            })
        }
    }
}

async fn gather_mp1_endpoint_descriptor(
    p2p: &PartyP2pHandle,
    eff_policy: RelayPolicy,
    pinned_relay_url: &str,
) -> EndpointDescriptor {
    match eff_policy {
        RelayPolicy::ForceRelays => {
            sanitize_endpoint_for_mp1(p2p.local_endpoint_descriptor(), eff_policy, pinned_relay_url)
        }
        RelayPolicy::AllowRelays => {
            p2p.wait_online(Duration::from_secs(3)).await;
            sanitize_endpoint_for_mp1(p2p.local_endpoint_descriptor(), eff_policy, pinned_relay_url)
        }
        RelayPolicy::NoRelays => {
            let first = sanitize_endpoint_for_mp1(p2p.local_endpoint_descriptor(), eff_policy, "");
            if !first.direct_addrs.is_empty() {
                return first;
            }
            let mut watcher = p2p.watch_addr();
            let _ = tokio::time::timeout(Duration::from_millis(500), watcher.updated()).await;
            sanitize_endpoint_for_mp1(p2p.local_endpoint_descriptor(), eff_policy, "")
        }
    }
}

pub(crate) fn is_local_cwt_valid(device: &DeviceRecord, now_s: i64) -> bool {
    verify_device_cwt(
        &device.device_cwt,
        &device.root_pubkey,
        Some(&device.device_pubkey),
        now_s,
    )
    .is_ok()
}

pub(crate) fn extract_cwt_expiry_ms(device: &DeviceRecord) -> u64 {
    match verify_device_cwt(
        &device.device_cwt,
        &device.root_pubkey,
        Some(&device.device_pubkey),
        wall_now_secs(),
    ) {
        Ok(claims) => u64::try_from(claims.exp.max(0))
            .unwrap_or(0)
            .saturating_mul(1000),
        Err(_) => 1,
    }
}

/// Rebuilds `sess.pubkey_to_device` strictly from validated, admitted, non-duplicate remote peers.
/// Rejects any duplicate `device_pubkey` claimed by `> 1` distinct `device_id`s OR colliding with
/// `local_device_pubkey`, marking all colliding remote members unadmitted and returning their
/// pubkeys for immediate `CLOSE_UNAUTHORIZED (4401)` revocation.
fn rebuild_pubkey_to_device(
    sess: &mut ActivePartySession,
    local_device_id: u64,
    local_device_pubkey: [u8; 32],
    strict_pins: bool,
) -> Vec<[u8; 32]> {
    let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
    for (&did, m) in &sess.members {
        if did != local_device_id {
            *counts.entry(m.record.device_pubkey).or_insert(0) += 1;
        }
    }

    let mut duplicate_pks = Vec::new();
    for (&did, m) in sess.members.iter_mut() {
        if did == local_device_id {
            continue;
        }
        let pk = m.record.device_pubkey;
        if pk == local_device_pubkey || counts.get(&pk).copied().unwrap_or(0) > 1 {
            m.admitted = false;
            if !duplicate_pks.contains(&pk) {
                duplicate_pks.push(pk);
            }
        }
    }

    sess.pubkey_to_device.clear();
    for (&did, m) in &sess.members {
        let trust_ok = if strict_pins {
            m.trust_state == TrustState::PinnedTrusted
        } else {
            m.trust_state != TrustState::RevokedBlocked
        };
        if did != local_device_id && m.admitted && trust_ok && !m.key_mismatch {
            sess.pubkey_to_device.insert(m.record.device_pubkey, did);
        }
    }
    duplicate_pks
}

fn lookup_peer_trust(
    auth_hash: [u8; 8],
    account_id: u64,
    local_account_id: u64,
    local_root_pubkey: [u8; 32],
    peers: &PeersStoreRecord,
) -> PeerTrustLookup {
    // Anonymous browser guests carry `account_id == 0`; never match local or pinned accounts.
    if account_id == 0 {
        return PeerTrustLookup::Unpinned;
    }
    // Operator's own (account_id, root_pubkey) is implicitly pinned_trusted.
    if account_id == local_account_id {
        return PeerTrustLookup::PinnedTrusted {
            root_pubkey: local_root_pubkey,
        };
    }
    for p in &peers.peers {
        if p.api_authority_hash == auth_hash && p.account_id == account_id {
            return match p.trust_state {
                TrustState::PinnedTrusted => PeerTrustLookup::PinnedTrusted {
                    root_pubkey: p.root_pubkey,
                },
                TrustState::RevokedBlocked => PeerTrustLookup::Revoked,
                TrustState::Unpinned => PeerTrustLookup::Unpinned,
            };
        }
    }
    PeerTrustLookup::Unpinned
}

fn lookup_mp2_member_trust(
    auth_hash: [u8; 8],
    account_id: u64,
    local_account_id: u64,
    local_root_pubkey: [u8; 32],
    peers: &PeersStoreRecord,
) -> (TrustState, [u8; 32], String) {
    match lookup_peer_trust(
        auth_hash,
        account_id,
        local_account_id,
        local_root_pubkey,
        peers,
    ) {
        PeerTrustLookup::PinnedTrusted { root_pubkey } => (
            TrustState::PinnedTrusted,
            root_pubkey,
            compute_safety_number(account_id, &root_pubkey),
        ),
        PeerTrustLookup::Revoked => (TrustState::RevokedBlocked, [0u8; 32], String::new()),
        PeerTrustLookup::Unpinned => (TrustState::Unpinned, [0u8; 32], String::new()),
    }
}

fn map_control_err_to_ipc(err: &ControlError) -> IpcErr {
    match err {
        ControlError::Api {
            status: 401, error, ..
        } => ipc_err(
            ERR_UNAUTHORIZED,
            false,
            format!(
                "HTTP 401 ({error}): local CLI device credential was rejected or expired. Signing in on multiplayer.tech in your browser is separate from authorizing this local CLI device; run `mp-outpost login` to authorize this device."
            ),
        ),
        other => ipc_err(ERR_CONTROL_PLANE, true, other.to_string()),
    }
}

fn validate_party_ws_path(party_id: u64, ws_path: &str) -> Result<String, IpcErr> {
    let canonical = format!("/v1/parties/{party_id}/ws");
    if ws_path.is_empty() {
        return Ok(canonical);
    }
    if ws_path != canonical {
        return Err(ipc_err(
            ERR_CONTROL_PLANE,
            false,
            format!("server returned unexpected mp2 ws_path for party {party_id}"),
        ));
    }
    Ok(canonical)
}

fn decode_ds_pubkey_b64(raw: &str) -> Option<[u8; 32]> {
    let bytes = B64.decode(raw.trim().as_bytes()).ok()?;
    bytes.try_into().ok()
}

/// Extracts a 114-byte `InviteFragmentV2` from `#<b64url>` in a room invite URL (or bare `#<b64url>`),
/// returning `(party_id, InviteFragmentV2)` so `invite_seed` is NEVER transmitted to `/v1/rooms/enter`.
fn extract_mls_invite_fragment(raw: &str) -> Option<(u64, InviteFragmentV2)> {
    let (_, frag_str) = raw.trim().split_once('#')?;
    let clean = frag_str.trim();
    if clean.is_empty() {
        return None;
    }
    let frag = InviteFragmentV2::decode_b64url(clean).ok()?;
    let gid = MpGroupId::parse(&frag.group_id).ok()?;
    Some((gid.party_id, frag))
}

fn format_guest_display_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('@').trim();
    let base = trimmed.strip_suffix(" (guest)").unwrap_or(trimmed).trim();
    if base.is_empty() {
        "guest".to_string()
    } else {
        format!("{base} (guest)")
    }
}

/// Normalizes room join targets including `#fragment` invite links
/// (`multiplayer.tech/p/i/<id>#<secret>`, `clank.party/i/<id>#<secret>`) and short invite domains
/// (`multiplayer.tech`, `mp.gg`, `clank.party`) while NEVER stripping `#<secret>` on `/p/i/` or
/// `/i/` invite URLs.
fn normalize_room_enter_target(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let (has_scheme, without_scheme) = if let Some(rest) = trimmed.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        (true, rest)
    } else {
        (false, trimmed)
    };
    let Some((host_raw, path_raw)) = without_scheme.split_once('/') else {
        return trimmed.to_string();
    };
    let host = host_raw
        .split(':')
        .next()
        .unwrap_or(host_raw)
        .to_ascii_lowercase();
    let is_known_invite_host = matches!(
        host.as_str(),
        "multiplayer.tech"
            | "www.multiplayer.tech"
            | "mp.gg"
            | "www.mp.gg"
            | "clank.party"
            | "www.clank.party"
    );
    if !is_known_invite_host {
        return trimmed.to_string();
    }
    let path_without_leading = path_raw.trim_start_matches('/');
    let path_lower = path_without_leading.to_ascii_lowercase();
    // Preserve `#fragment` invite links verbatim (`multiplayer.tech/p/i/<id>#<secret>`,
    // `clank.party/i/<id>#<secret>`, `mp.gg/i/<id>#<secret>`, etc.) so `/v1/rooms/enter`
    // receives the full `#<secret>` in the POST body without ever stripping it.
    if path_lower.starts_with("p/i/") || path_lower.starts_with("i/") {
        return if has_scheme && trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{host}/{path_without_leading}")
        };
    }
    let path = path_raw
        .split(['?', '#'])
        .next()
        .unwrap_or(path_raw)
        .trim_matches('/');
    if let Some(handle) = path.strip_prefix('@') {
        let clean = handle.split('/').next().unwrap_or(handle).trim();
        if !clean.is_empty() {
            return format!("@{clean}");
        }
    }
    if let Some(code) = path.strip_prefix("p/").or_else(|| path.strip_prefix("P/")) {
        let clean = code.split('/').next().unwrap_or(code).trim();
        if !clean.is_empty() {
            return clean.to_ascii_uppercase();
        }
    }
    if path.len() == 4 && path.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return path.to_ascii_uppercase();
    }
    trimmed.to_string()
}

fn update_mp2_provenance_cache(
    sess: &mut ActivePartySession,
    members: &[Mp2Member],
    auth_hash: [u8; 8],
    peers: &PeersStoreRecord,
) {
    for m in members {
        if m.account_id == 0 || m.is_guest {
            continue;
        }
        let (fp, sn) = peers
            .peers
            .iter()
            .find(|p| p.api_authority_hash == auth_hash && p.account_id == m.account_id)
            .map(|p| {
                (
                    pubkey_fingerprint_hex(&p.root_pubkey),
                    compute_safety_number(m.account_id, &p.root_pubkey),
                )
            })
            .unwrap_or_default();
        sess.provenance_by_account
            .entry(m.account_id)
            .and_modify(|prov| {
                if !m.handle.is_empty() {
                    prov.handle = m.handle.clone();
                }
                if !fp.is_empty() {
                    prov.fingerprint = fp.clone();
                    prov.safety_number = sn.clone();
                }
            })
            .or_insert_with(|| CachedAccountProvenance {
                handle: m.handle.clone(),
                fingerprint: fp,
                safety_number: sn,
            });
    }
}

fn apply_decrypted_ephemeral_status(
    sess: &mut ActivePartySession,
    auth_account_id: u64,
    auth_device_id: u64,
    status: outpost_core::mls_session::InnerEphemeralStatus,
) {
    if let Some(member) = sess.mp2_members.iter_mut().find(|m| {
        m.device_id == Some(auth_device_id)
            || (m.device_id.is_none() && m.account_id == auth_account_id)
    }) {
        member.agent_name = Some(status.agent_name);
        member.agent_state = Some(status.agent_state);
        member.agent_summary = status.agent_summary;
    }
}

fn ingest_mp2_event_into_session(
    sess: &mut ActivePartySession,
    ev: Mp2Event,
    is_historical_catchup: bool,
) {
    if !sess.mark_mp2_seq_seen(ev.seq) {
        return;
    }

    if let Some(ref cid) = ev.client_msg_id
        && sess.sent_mp2_msg_ids.iter().any(|seen| seen == cid)
    {
        return;
    }

    // Spec v3 §4.5 / §7.3 fail-closed E2EE boundary:
    // In `e2ee_mode == 1` rooms, NEVER render or agent-trigger non-`opaque_b64` app frames!
    let room_is_e2ee = sess.e2ee_mode == 1 || ev.e2ee_mode == Some(1);
    if room_is_e2ee && ev.kind != Mp2EventKind::System {
        if ev.body_encoding != "opaque_b64" {
            log_line(&format!(
                "Party {} rejected non-opaque_b64 frame (encoding='{}') in e2ee_mode=1 room",
                sess.party_id, ev.body_encoding
            ));
            return;
        }
        let Some(ref mut mls) = sess.mls_session else {
            return;
        };
        let dec = match mls.decrypt_inbound_mp2(&ev.body_encoding, &ev.body, is_historical_catchup)
        {
            Ok(d) => d,
            Err(e) => {
                log_line(&format!(
                    "Party {} failed to decrypt inbound E2EE frame seq={}: {e}",
                    sess.party_id, ev.seq
                ));
                return;
            }
        };
        if dec.is_duplicate {
            return;
        }
        let sender_account_id = dec.auth_account_id;
        let sender_device_id = dec.auth_device_id;
        let is_browser = dec.sender_is_browser;
        let sender_client = if is_browser {
            "web".to_string()
        } else if !ev.sender.client.is_empty() {
            ev.sender.client
        } else {
            "outpost".to_string()
        };
        let sender_handle = sess
            .provenance_by_account
            .get(&sender_account_id)
            .map(|p| p.handle.clone())
            .filter(|h| !h.is_empty())
            .or(
                if !ev.sender.handle.is_empty() && ev.sender.account_id == sender_account_id {
                    Some(ev.sender.handle)
                } else {
                    None
                },
            )
            .unwrap_or_else(|| format!("account-{sender_account_id}"));

        let body = match dec.payload {
            DecryptedInboundPayload::Chat {
                target_selector,
                body,
            } => PartyEventBody::Chat {
                sender_account_id,
                sender_device_id,
                sender_handle,
                is_browser,
                sender_client,
                room_scope: "party/main".to_string(),
                target_selector,
                timestamp_ns: i64::try_from(ev.ts_ms)
                    .unwrap_or(0)
                    .saturating_mul(1_000_000),
                body,
            },
            DecryptedInboundPayload::AgentCard { payload } => PartyEventBody::BridgeEnvelope {
                sender_account_id,
                sender_device_id,
                sender_handle,
                is_browser,
                sender_client,
                room_scope: "party/main".to_string(),
                payload,
            },
            DecryptedInboundPayload::EphemeralStatus(status) => {
                apply_decrypted_ephemeral_status(sess, sender_account_id, sender_device_id, status);
                return;
            }
            DecryptedInboundPayload::InviteControl(_) => {
                return;
            }
        };
        let _ = sess.push_event_with_catchup(body, is_historical_catchup);
        return;
    }

    let is_guest = ev.sender.is_guest || ev.sender.account_id == 0;
    let is_browser = ev.sender.is_browser_origin();
    let sender_client = if is_browser && ev.sender.client.trim().is_empty() {
        "web".to_string()
    } else {
        ev.sender.client.clone()
    };
    let sender_account_id = if is_guest { 0 } else { ev.sender.account_id };
    // Browser sessions are account-level web participants, never native enrolled devices.
    let sender_device_id = if is_guest || is_browser {
        0
    } else {
        ev.sender.device_id.unwrap_or(sender_account_id)
    };
    let sender_handle = if is_guest {
        format_guest_display_name(&ev.sender.handle)
    } else if !ev.sender.handle.is_empty() {
        ev.sender.handle
    } else {
        format!("account-{sender_account_id}")
    };

    let body = match ev.kind {
        Mp2EventKind::Chat => PartyEventBody::Chat {
            sender_account_id,
            sender_device_id,
            sender_handle,
            is_browser,
            sender_client,
            room_scope: "party/main".to_string(),
            target_selector: ev.target,
            timestamp_ns: i64::try_from(ev.ts_ms)
                .unwrap_or(0)
                .saturating_mul(1_000_000),
            body: ev.body,
        },
        Mp2EventKind::AgentCard => {
            let payload = if ev.body_encoding == "opaque_b64" {
                B64.decode(ev.body.as_bytes())
                    .unwrap_or_else(|_| ev.body.into_bytes())
            } else {
                ev.body.into_bytes()
            };
            PartyEventBody::BridgeEnvelope {
                sender_account_id,
                sender_device_id,
                sender_handle,
                is_browser,
                sender_client,
                room_scope: "party/main".to_string(),
                payload,
            }
        }
        Mp2EventKind::System => PartyEventBody::MembershipChanged {
            party_epoch: sess.party_epoch,
            summary: ev.body,
        },
        Mp2EventKind::E2eeApp | Mp2EventKind::E2eeEphemeral => {
            return;
        }
    };

    let _ = sess.push_event_with_catchup(body, is_historical_catchup);
}

#[allow(clippy::too_many_arguments)]
fn plan_mp2_recipients(
    sess: &ActivePartySession,
    local_account_id: u64,
    local_device_id: u64,
    local_root_pubkey: [u8; 32],
    auth_hash: [u8; 8],
    peers: &PeersStoreRecord,
    strict_pins: bool,
    target_device_id: Option<u64>,
) -> Result<(Vec<u64>, Vec<u64>), IpcErr> {
    let mut delivered = Vec::new();
    let mut withheld_unpinned = Vec::new();
    let mut target_matched = false;

    // `mp2` is a server-hosted room broadcast: every `send` is fanned out by `PartyDO` to all
    // connected members in the room. Therefore trust checks MUST evaluate the full room roster,
    // never allowing a broadcast into a room containing a `RevokedBlocked` member (or any
    // unpinned/guest member when `--strict-pins` is enabled).
    for m in &sess.mp2_members {
        let is_guest = m.is_guest || m.account_id == 0;
        let is_own_device = !is_guest
            && (m.device_id == Some(local_device_id)
                || (m.device_id.is_none() && m.account_id == local_account_id));
        if is_own_device {
            continue;
        }
        let dev_id = if is_guest {
            0
        } else {
            m.device_id.unwrap_or(m.account_id)
        };
        let is_explicit_target = target_device_id
            .is_some_and(|target| !is_guest && (dev_id == target || m.account_id == target));
        if is_explicit_target {
            target_matched = true;
        }
        let (ts, _, _) = if is_guest {
            (TrustState::Unpinned, [0u8; 32], String::new())
        } else {
            lookup_mp2_member_trust(
                auth_hash,
                m.account_id,
                local_account_id,
                local_root_pubkey,
                peers,
            )
        };
        match ts {
            TrustState::RevokedBlocked => {
                return Err(map_send_plan_err(SendPlanError::TargetRevoked {
                    account_id: m.account_id,
                }));
            }
            TrustState::Unpinned if strict_pins => {
                if is_explicit_target {
                    return Err(map_send_plan_err(SendPlanError::TargetNotPinned {
                        account_id: m.account_id,
                    }));
                }
                if !withheld_unpinned.contains(&m.account_id) {
                    withheld_unpinned.push(m.account_id);
                }
            }
            TrustState::PinnedTrusted | TrustState::Unpinned => {
                if target_device_id.is_none() || is_explicit_target {
                    delivered.push(dev_id);
                }
            }
        }
    }

    if strict_pins {
        if !withheld_unpinned.is_empty() {
            return Err(ipc_err(
                ERR_CONFLICT,
                false,
                "cannot broadcast to mp2 room under --strict-pins while unpinned or guest members are present; pin all members via `mp-outpost peers verify` first",
            ));
        }
        if target_device_id.is_some() && !target_matched {
            return Err(map_send_plan_err(SendPlanError::NoPinnedConnectedRecipients));
        }
        if delivered.is_empty() {
            return Err(map_send_plan_err(SendPlanError::NoPinnedConnectedRecipients));
        }
    } else if delivered.is_empty() {
        if let Some(target) = target_device_id {
            delivered.push(target);
        } else {
            // Room is server-hosted and persistent: PartyDO accepts and persists events
            // even while peers are reconnecting or joining asynchronously.
            delivered.push(local_device_id);
        }
    }
    Ok((delivered, withheld_unpinned))
}

fn resolve_mp2_target_selector(sess: &ActivePartySession, target_device_id: Option<u64>) -> String {
    let Some(did) = target_device_id else {
        return "@all".to_string();
    };
    if let Some(m) = sess
        .mp2_members
        .iter()
        .find(|m| m.device_id == Some(did) || m.account_id == did)
        && !m.handle.is_empty()
    {
        return format!("@{}", m.handle.trim_start_matches('@'));
    }
    if let Some(m) = sess.members.get(&did)
        && !m.server_handle.is_empty()
    {
        return format!("@{}", m.server_handle.trim_start_matches('@'));
    }
    format!("device:{did}")
}

#[allow(clippy::too_many_arguments)]
fn evaluate_member_state(
    member: &PartyMemberRecord,
    local_device_id: u64,
    local_account_id: u64,
    local_root_pubkey: [u8; 32],
    local_device_pubkey: [u8; 32],
    auth_hash: [u8; 8],
    peers: &PeersStoreRecord,
    now_local_s: i64,
    server_handle: String,
    strict_pins: bool,
    unpinned_alerts: &mut HashMap<u64, UnpinnedPeerAlert>,
    key_mismatch_alerts: &mut HashMap<u64, KeyMismatchAlert>,
) -> PartyMemberState {
    let acc_id = member.account_id.get();
    let sn = compute_safety_number(acc_id, &member.root_pubkey);

    if member.device_id.get() == local_device_id {
        // L4-6: Verify the server did not spoof our own device row!
        if member.account_id.get() != local_account_id
            || member.root_pubkey != local_root_pubkey
            || member.device_pubkey != local_device_pubkey
        {
            key_mismatch_alerts.insert(
                local_account_id,
                KeyMismatchAlert {
                    account_id: local_account_id,
                    expected_root_pubkey: local_root_pubkey,
                    observed_root_pubkey: member.root_pubkey,
                },
            );
            return PartyMemberState {
                record: member.clone(),
                trust_state: TrustState::RevokedBlocked,
                admitted: false,
                key_mismatch: true,
                cwt_exp_s: 0,
                safety_number: sn,
                server_handle,
            };
        }
        return PartyMemberState {
            record: member.clone(),
            trust_state: TrustState::PinnedTrusted,
            admitted: true,
            key_mismatch: false,
            cwt_exp_s: i64::MAX,
            safety_number: sn,
            server_handle,
        };
    }

    let trust = lookup_peer_trust(
        auth_hash,
        acc_id,
        local_account_id,
        local_root_pubkey,
        peers,
    );

    match evaluate_peer_admission(&member.device_pubkey, member, &trust, now_local_s) {
        AdmissionDecision::Admitted { cwt_exp_s, .. } => PartyMemberState {
            record: member.clone(),
            trust_state: TrustState::PinnedTrusted,
            admitted: true,
            key_mismatch: false,
            cwt_exp_s,
            safety_number: sn,
            server_handle,
        },
        AdmissionDecision::UnpinnedFirstContact {
            account_id,
            root_pubkey,
            safety_number,
            cwt_exp_s,
        } => {
            if strict_pins {
                unpinned_alerts.insert(
                    account_id.get(),
                    UnpinnedPeerAlert {
                        account_id: account_id.get(),
                        root_pubkey,
                        safety_number: safety_number.clone(),
                        server_handle: server_handle.clone(),
                    },
                );
            }
            PartyMemberState {
                record: member.clone(),
                trust_state: TrustState::Unpinned,
                admitted: !strict_pins,
                key_mismatch: false,
                cwt_exp_s,
                safety_number,
                server_handle,
            }
        }
        AdmissionDecision::KeyMismatch {
            account_id,
            expected_root,
            observed_root,
        } => {
            key_mismatch_alerts.insert(
                account_id.get(),
                KeyMismatchAlert {
                    account_id: account_id.get(),
                    expected_root_pubkey: expected_root,
                    observed_root_pubkey: observed_root,
                },
            );
            PartyMemberState {
                record: member.clone(),
                trust_state: TrustState::RevokedBlocked,
                admitted: false,
                key_mismatch: true,
                cwt_exp_s: 0,
                safety_number: sn,
                server_handle,
            }
        }
        AdmissionDecision::RejectRevoked => PartyMemberState {
            record: member.clone(),
            trust_state: TrustState::RevokedBlocked,
            admitted: false,
            key_mismatch: false,
            cwt_exp_s: 0,
            safety_number: sn,
            server_handle,
        },
        AdmissionDecision::RejectTlsRpkMismatch | AdmissionDecision::RejectCwtInvalid(_) => {
            let ts = match trust {
                PeerTrustLookup::PinnedTrusted { .. } => TrustState::PinnedTrusted,
                PeerTrustLookup::Revoked => TrustState::RevokedBlocked,
                PeerTrustLookup::Unpinned => TrustState::Unpinned,
            };
            PartyMemberState {
                record: member.clone(),
                trust_state: ts,
                admitted: false,
                key_mismatch: false,
                cwt_exp_s: 0,
                safety_number: sn,
                server_handle,
            }
        }
    }
}

fn build_send_candidates(sess: &ActivePartySession, local_device_id: u64) -> Vec<PeerSendCandidate> {
    sess.members
        .values()
        .filter(|m| m.record.device_id.get() != local_device_id)
        .map(|m| PeerSendCandidate {
            account_id: m.record.account_id.get(),
            device_id: m.record.device_id.get(),
            trust: m.trust_state,
            connected_p2p: m.admitted
                && (sess.mp2_connected
                    || sess
                        .p2p
                        .as_ref()
                        .is_some_and(|p| p.is_peer_connected(&m.record.device_pubkey))),
            key_mismatch: m.key_mismatch,
        })
        .collect()
}

fn map_send_plan_err(err: SendPlanError) -> IpcErr {
    match err {
        SendPlanError::KeyMismatchPresent { account_id } => ipc_err(
            ERR_CONFLICT,
            false,
            format!("key_mismatch_blocked: account {account_id} presented unexpected root_pubkey"),
        ),
        SendPlanError::TargetNotFound { device_id } => ipc_err(
            ERR_NOT_FOUND,
            false,
            format!("target device {device_id} not in party"),
        ),
        SendPlanError::TargetNotPinned { account_id } => ipc_err(
            ERR_CONFLICT,
            false,
            format!(
                "strict_pins: target account {account_id} is not pinned_trusted; run `mp-outpost peers verify {account_id}`"
            ),
        ),
        SendPlanError::TargetRevoked { account_id } => ipc_err(
            ERR_CONFLICT,
            false,
            format!("target account {account_id} is revoked/blocked"),
        ),
        SendPlanError::TargetDisconnected { device_id } => ipc_err(
            ERR_CONFLICT,
            true,
            format!("target device {device_id} is not currently connected"),
        ),
        SendPlanError::NoPinnedConnectedRecipients => ipc_err(
            ERR_CONFLICT,
            true,
            "no eligible connected recipients in party",
        ),
    }
}

fn hash_chat_req(req: &crate::ipc_payloads::PartySendChatReq) -> [u8; 32] {
    let mut data = Vec::with_capacity(64 + req.room_scope.len() + req.body.len());
    data.extend_from_slice(&req.party_id.to_le_bytes());
    data.extend_from_slice(&req.target_device_id.unwrap_or(0).to_le_bytes());
    data.extend_from_slice(&(req.room_scope.len() as u32).to_le_bytes());
    data.extend_from_slice(req.room_scope.as_bytes());
    data.extend_from_slice(req.body.as_bytes());
    sha256(&data)
}

fn hash_board_req(req: &crate::ipc_payloads::PartyPostBoardReq) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + req.room_scope.len() + req.payload.len());
    data.extend_from_slice(&req.party_id.to_le_bytes());
    data.extend_from_slice(&(req.room_scope.len() as u32).to_le_bytes());
    data.extend_from_slice(req.room_scope.as_bytes());
    data.extend_from_slice(&req.payload);
    sha256(&data)
}

fn build_provenance(
    sess: &ActivePartySession,
    sender_account_id: u64,
    sender_device_id: u64,
    fallback_handle: &str,
    is_browser: bool,
    sender_client: &str,
) -> IpcProvenance {
    if let Some(prov) = sess.provenance_by_account.get(&sender_account_id) {
        let handle = if !prov.handle.is_empty() {
            prov.handle.clone()
        } else if !fallback_handle.is_empty() {
            fallback_handle.to_string()
        } else {
            format!("account-{sender_account_id}")
        };
        IpcProvenance {
            sender_account_id,
            sender_device_id,
            sender_handle: handle,
            root_pubkey_fingerprint: prov.fingerprint.clone(),
            safety_number: prov.safety_number.clone(),
            is_browser,
            sender_client: sender_client.to_string(),
        }
    } else {
        IpcProvenance {
            sender_account_id,
            sender_device_id,
            sender_handle: if fallback_handle.is_empty() {
                format!("account-{sender_account_id}")
            } else {
                fallback_handle.to_string()
            },
            root_pubkey_fingerprint: String::new(),
            safety_number: String::new(),
            is_browser,
            sender_client: sender_client.to_string(),
        }
    }
}

fn build_ipc_poll_resp(
    sess: &ActivePartySession,
    poll: outpost_core::party_state::PollResult,
    timed_out: bool,
    board_only: bool,
) -> PartyPollIpcResp {
    let mut events = Vec::with_capacity(poll.events.len());
    for ev in poll.events {
        let kind = match ev.body {
            PartyEventBody::Chat {
                sender_account_id,
                sender_device_id,
                sender_handle,
                is_browser,
                sender_client,
                room_scope,
                target_selector,
                timestamp_ns,
                body,
            } => {
                if board_only {
                    continue;
                }
                IpcPartyEventKind::Chat {
                    provenance: build_provenance(
                        sess,
                        sender_account_id,
                        sender_device_id,
                        &sender_handle,
                        is_browser,
                        &sender_client,
                    ),
                    room_scope,
                    target_selector,
                    timestamp_ns,
                    body,
                }
            }
            PartyEventBody::BridgeEnvelope {
                sender_account_id,
                sender_device_id,
                sender_handle,
                is_browser,
                sender_client,
                room_scope,
                payload,
            } => IpcPartyEventKind::BridgeEnvelope {
                provenance: build_provenance(
                    sess,
                    sender_account_id,
                    sender_device_id,
                    &sender_handle,
                    is_browser,
                    &sender_client,
                ),
                room_scope,
                payload,
            },
            PartyEventBody::ControlNotice {
                sender_account_id,
                sender_device_id,
                notice_kind,
                party_epoch,
                text,
            } => {
                if board_only {
                    continue;
                }
                IpcPartyEventKind::ControlNotice {
                    provenance: build_provenance(
                        sess,
                        sender_account_id,
                        sender_device_id,
                        "",
                        false,
                        "",
                    ),
                    notice_kind,
                    party_epoch,
                    text,
                }
            }
            PartyEventBody::MembershipChanged {
                party_epoch,
                summary,
            } => {
                if board_only {
                    continue;
                }
                IpcPartyEventKind::MembershipChanged {
                    party_epoch,
                    summary,
                }
            }
        };
        events.push(IpcPartyEvent {
            event_seq: ev.seq,
            party_id: sess.party_id,
            party_epoch: sess.party_epoch,
            is_historical_catchup: ev.is_historical_catchup,
            kind,
        });
    }

    let mls = sess.mls_status_snapshot();
    PartyPollIpcResp {
        party_id: sess.party_id,
        daemon_epoch: poll.daemon_epoch,
        next_seq: poll.next_seq,
        dropped_before_seq: poll.dropped_before_seq,
        cursor_reset: poll.cursor_reset,
        gap_possible: poll.gap_possible,
        timed_out,
        e2ee_mode: mls.e2ee_mode,
        mls_epoch: mls.mls_epoch,
        trust_tier: mls.trust_tier,
        has_declared_agent: mls.has_declared_agent,
        epoch_authenticator_b32: mls.epoch_authenticator_b32,
        clone_detected: mls.clone_detected,
        events,
    }
}

#[cfg(test)]
#[path = "mls_live_e2e_tests.rs"]
mod mls_live_e2e_tests;

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use mp_protocol::{
        AccountId, DeviceId, DirectAddr, EndpointDescriptor, MAX_CWT_TTL_SECS, PartyJoinMode,
        PartyMemberRecord, PartyVisibility, RelayPolicy, TransportKind, encode_device_cwt,
    };
    use outpost_control::{Mp2Event, Mp2EventKind, Mp2Member, wall_now_secs};
    use outpost_core::party_state::{PartyEventBody, PartyEventRing};
    use outpost_core::storage_codec::{DeviceRecord, PeerRecord, PeersStoreRecord, TrustState};
    use outpost_daemon::CancellationToken;
    use tokio::sync::Notify;

    use super::{
        ActivePartySession, AppDaemon, api_authority_hash, extract_cwt_expiry_ms,
        ingest_mp2_event_into_session, is_local_cwt_valid, normalize_room_enter_target,
        plan_mp2_recipients, prepare_peer_dial_target, sanitize_endpoint_for_mp1,
        update_mp2_provenance_cache, validate_party_ws_path,
    };
    use crate::ipc_payloads::{
        ERR_CONFLICT, ERR_SECRET_INVITE_TOKEN, PartyControlNoticeReq, encode_control_notice_req,
    };
    use crate::storage::{lock_state, open_state_dir, save_device_record};

    fn make_test_device(cwt_offset_s: i64, cwt_ttl_s: i64) -> (DeviceRecord, i64) {
        let root_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let dev_sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let root_pk = root_sk.verifying_key().to_bytes();
        let dev_pk = dev_sk.verifying_key().to_bytes();
        let now = wall_now_secs();
        let iat = now + cwt_offset_s;
        let exp = iat + cwt_ttl_s;
        let cwt = encode_device_cwt(&root_sk, &dev_pk, iat, exp).unwrap_or_default();
        (
            DeviceRecord {
                account_id: 1001,
                device_id: 2001,
                root_pubkey: root_pk,
                device_secret: [0x22u8; 32],
                device_pubkey: dev_pk,
                device_cwt: cwt,
                local_relay_policy: RelayPolicy::AllowRelays,
                api_authority: "api.multiplayer.tech".to_string(),
                default_relay_url: "https://relay.multiplayer.tech".to_string(),
                device_label: "unit".to_string(),
            },
            exp,
        )
    }

    #[test]
    fn extract_cwt_expiry_ms_returns_real_exp_and_detects_expired() {
        let (valid_dev, expected_exp_s) = make_test_device(0, MAX_CWT_TTL_SECS);
        let exp_ms = extract_cwt_expiry_ms(&valid_dev);
        assert_eq!(exp_ms, (expected_exp_s as u64) * 1000);
        assert!(exp_ms > 0);
        assert!(is_local_cwt_valid(&valid_dev, wall_now_secs()));

        let (expired_dev, _) = make_test_device(-7200, 60);
        assert_eq!(extract_cwt_expiry_ms(&expired_dev), 1);
        assert!(!is_local_cwt_valid(&expired_dev, wall_now_secs()));
    }

    #[test]
    fn sanitize_endpoint_for_mp1_strips_private_ips_under_allow_relays() {
        let raw = EndpointDescriptor {
            transport_kind: TransportKind::IrohQuic,
            relay_url: "https://relay.multiplayer.tech".to_string(),
            direct_addrs: vec![
                DirectAddr::V4 {
                    ip: [127, 0, 0, 1],
                    port: 4000,
                },
                DirectAddr::V4 {
                    ip: [10, 0, 0, 5],
                    port: 4001,
                },
                DirectAddr::V4 {
                    ip: [172, 16, 1, 2],
                    port: 4002,
                },
                DirectAddr::V4 {
                    ip: [192, 168, 1, 10],
                    port: 4003,
                },
                DirectAddr::V4 {
                    ip: [100, 64, 1, 9],
                    port: 4004,
                },
                DirectAddr::V4 {
                    ip: [169, 254, 1, 1],
                    port: 4005,
                },
                DirectAddr::V6 {
                    ip: [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    port: 4006,
                },
                DirectAddr::V6 {
                    ip: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    port: 4007,
                },
                DirectAddr::V4 {
                    ip: [203, 0, 113, 42],
                    port: 4008,
                },
            ],
        };

        let sanitized = sanitize_endpoint_for_mp1(
            raw.clone(),
            RelayPolicy::AllowRelays,
            "https://relay.multiplayer.tech",
        );
        assert_eq!(
            sanitized.direct_addrs,
            vec![DirectAddr::V4 {
                ip: [203, 0, 113, 42],
                port: 4008,
            }]
        );
        assert_eq!(
            sanitized.validate_against_policy(
                RelayPolicy::AllowRelays,
                "https://relay.multiplayer.tech"
            ),
            Ok(())
        );

        let forced = sanitize_endpoint_for_mp1(
            raw,
            RelayPolicy::ForceRelays,
            "https://relay.multiplayer.tech",
        );
        assert!(forced.direct_addrs.is_empty());
        assert_eq!(
            forced.validate_against_policy(
                RelayPolicy::ForceRelays,
                "https://relay.multiplayer.tech"
            ),
            Ok(())
        );
    }

    #[test]
    fn prepare_peer_dial_target_strips_direct_addrs_under_force_relays() {
        let Ok(dev_id) = DeviceId::new(2002) else {
            return;
        };
        let Ok(acc_id) = AccountId::new(1002) else {
            return;
        };
        let member = PartyMemberRecord {
            device_id: dev_id,
            account_id: acc_id,
            root_pubkey: [0xAA; 32],
            device_pubkey: [0xBB; 32],
            device_cwt: Vec::new(),
            endpoint: EndpointDescriptor {
                transport_kind: TransportKind::IrohQuic,
                relay_url: "https://relay.multiplayer.tech".to_string(),
                direct_addrs: vec![DirectAddr::V4 {
                    ip: [203, 0, 113, 9],
                    port: 5555,
                }],
            },
            joined_seq: 1,
            connected: true,
        };

        let target = prepare_peer_dial_target(
            RelayPolicy::ForceRelays,
            "https://relay.multiplayer.tech",
            RelayPolicy::AllowRelays,
            &member,
        );
        assert!(target.is_some());
        if let Some(t) = target {
            assert!(t.endpoint.direct_addrs.is_empty());
            assert_eq!(t.endpoint.relay_url, "https://relay.multiplayer.tech");
            assert_eq!(t.remote_relay_policy, RelayPolicy::ForceRelays);
        }
    }

    #[tokio::test]
    async fn op_party_send_control_notice_refuses_secret_material() {
        let Ok(tmp) = tempfile::tempdir() else {
            return;
        };
        let state_dir_path = tmp.path().join("state");
        let Ok(state_dir) = open_state_dir(&state_dir_path) else {
            return;
        };
        let (dev, _) = make_test_device(0, MAX_CWT_TTL_SECS);
        {
            let Ok(lock) = lock_state(&state_dir) else {
                return;
            };
            assert!(save_device_record(&state_dir_path, &lock, &dev).is_ok());
        }
        let Ok(daemon) = AppDaemon::load(state_dir_path, None, dev.device_id) else {
            return;
        };

        let req = PartyControlNoticeReq {
            party_id: 7001,
            notice_kind: 2,
            party_epoch: 1,
            text: "leak mpinv1_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG".to_string(),
        };
        let Ok(encoded) = encode_control_notice_req(&req) else {
            return;
        };
        let err = daemon.op_party_send_control_notice(&encoded).await;
        assert!(matches!(err, Err((code, false, _)) if code == ERR_SECRET_INVITE_TOKEN));
    }

    fn make_mp2_test_session(members: Vec<Mp2Member>) -> ActivePartySession {
        ActivePartySession {
            party_id: 8801,
            party_epoch: 1,
            leader_account_id: 1001,
            leader_device_id: 2001,
            visibility: PartyVisibility::Friends,
            join_mode: PartyJoinMode::InviteOnly,
            relay_policy: RelayPolicy::AllowRelays,
            effective_relay_policy: RelayPolicy::AllowRelays,
            max_members: 12,
            pinned_relay_url: String::new(),
            room_code: "KAIH".to_string(),
            room_name: "Squad".to_string(),
            share_url: "https://clank.party/KAIH".to_string(),
            ws_path: "/v1/parties/8801/ws".to_string(),
            e2ee_mode: 0,
            mls_epoch: 0,
            min_allowed_mls_epoch: 0,
            mls_rekey_required: false,
            mls_invite_epoch: 0,
            group_id_b64: None,
            party_ds_pubkey: None,
            is_mls_creator: false,
            pending_invite_fragment: None,
            pending_join_kp: None,
            processed_kp_refs: std::collections::HashSet::new(),
            mls_session: None,
            members: HashMap::new(),
            mp2_members: members,
            mp2_connected: true,
            mp2_last_seq: 0,
            mp2_seen_seqs: VecDeque::new(),
            sent_mp2_msg_ids: VecDeque::new(),
            mp2_tx: None,
            pubkey_to_device: HashMap::new(),
            provenance_by_account: HashMap::new(),
            unpinned_alerts: HashMap::new(),
            key_mismatch_alerts: HashMap::new(),
            ring: PartyEventRing::new(8801, 1),
            wait_notify: Arc::new(Notify::new()),
            p2p: None,
            p2p_event_task: None,
            ws_stop: CancellationToken::new(),
            ws_task: None,
            cwt_task: None,
        }
    }

    #[test]
    fn plan_mp2_recipients_strict_pins_and_revoked_fail_closed() {
        let auth_hash = api_authority_hash("api.multiplayer.tech");
        let local_root = [0x11u8; 32];
        let peers = PeersStoreRecord {
            peers: vec![
                PeerRecord {
                    api_authority_hash: auth_hash,
                    account_id: 1002,
                    root_pubkey: [0x22u8; 32],
                    trust_state: TrustState::PinnedTrusted,
                    handle_prop: "bob".to_string(),
                    handle_fetched_ms: 1_000,
                    pinned_at_ms: 1_000,
                },
                PeerRecord {
                    api_authority_hash: auth_hash,
                    account_id: 1004,
                    root_pubkey: [0x44u8; 32],
                    trust_state: TrustState::RevokedBlocked,
                    handle_prop: "mallory".to_string(),
                    handle_fetched_ms: 2_000,
                    pinned_at_ms: 0,
                },
            ],
        };

        let alice = Mp2Member {
            account_id: 1001,
            handle: "alice".to_string(),
            client: "outpost".to_string(),
            is_guest: false,
            is_browser: false,
            agent_name: None,
            agent_state: None,
            agent_summary: None,
            status: "live".to_string(),
            device_id: Some(2001),
            nick: None,
        };
        let bob_pinned = Mp2Member {
            account_id: 1002,
            handle: "bob".to_string(),
            client: "outpost".to_string(),
            is_guest: false,
            is_browser: false,
            agent_name: None,
            agent_state: None,
            agent_summary: None,
            status: "live".to_string(),
            device_id: Some(2002),
            nick: None,
        };
        let carol_unpinned = Mp2Member {
            account_id: 1003,
            handle: "carol".to_string(),
            client: "blackbird".to_string(),
            is_guest: false,
            is_browser: false,
            agent_name: None,
            agent_state: None,
            agent_summary: None,
            status: "live".to_string(),
            device_id: Some(2003),
            nick: None,
        };
        let mallory_revoked = Mp2Member {
            account_id: 1004,
            handle: "mallory".to_string(),
            client: "outpost".to_string(),
            is_guest: false,
            is_browser: false,
            agent_name: None,
            agent_state: None,
            agent_summary: None,
            status: "live".to_string(),
            device_id: Some(2004),
            nick: None,
        };
        let web_guest = Mp2Member {
            account_id: 0,
            handle: "phall".to_string(),
            client: "web".to_string(),
            is_guest: true,
            is_browser: true,
            agent_name: None,
            agent_state: None,
            agent_summary: None,
            status: "live".to_string(),
            device_id: None,
            nick: None,
        };

        // 1. Mixed pinned + unpinned room: strict_pins MUST fail closed (no broadcast leak!)
        let mixed_sess = make_mp2_test_session(vec![
            alice.clone(),
            bob_pinned.clone(),
            carol_unpinned.clone(),
        ]);
        let strict_mixed = plan_mp2_recipients(
            &mixed_sess,
            1001,
            2001,
            local_root,
            auth_hash,
            &peers,
            true,
            None,
        );
        assert!(matches!(strict_mixed, Err((code, false, _)) if code == ERR_CONFLICT));
        // Default policy allows authenticated unpinned peer in room.
        let default_mixed = plan_mp2_recipients(
            &mixed_sess,
            1001,
            2001,
            local_root,
            auth_hash,
            &peers,
            false,
            None,
        );
        assert!(default_mixed.is_ok());

        // 2. Mixed pinned + browser guest: strict_pins MUST fail closed!
        let guest_sess =
            make_mp2_test_session(vec![alice.clone(), bob_pinned.clone(), web_guest]);
        let strict_guest = plan_mp2_recipients(
            &guest_sess,
            1001,
            2001,
            local_root,
            auth_hash,
            &peers,
            true,
            None,
        );
        assert!(matches!(strict_guest, Err((code, false, _)) if code == ERR_CONFLICT));

        // 3. Empty roster / unknown target under strict_pins MUST fail closed!
        let empty_sess = make_mp2_test_session(Vec::new());
        assert!(matches!(
            plan_mp2_recipients(&empty_sess, 1001, 2001, local_root, auth_hash, &peers, true, None),
            Err((code, _, _)) if code == ERR_CONFLICT
        ));
        let pinned_only = make_mp2_test_session(vec![alice.clone(), bob_pinned.clone()]);
        assert!(matches!(
            plan_mp2_recipients(
                &pinned_only,
                1001,
                2001,
                local_root,
                auth_hash,
                &peers,
                true,
                Some(9999)
            ),
            Err((code, _, _)) if code == ERR_CONFLICT
        ));
        assert!(plan_mp2_recipients(
            &pinned_only,
            1001,
            2001,
            local_root,
            auth_hash,
            &peers,
            true,
            None
        )
        .is_ok());

        // 4. RevokedBlocked peer in broadcast room MUST fail closed under BOTH policies!
        let revoked_sess = make_mp2_test_session(vec![alice, bob_pinned, mallory_revoked]);
        for strict in [false, true] {
            let res = plan_mp2_recipients(
                &revoked_sess,
                1001,
                2001,
                local_root,
                auth_hash,
                &peers,
                strict,
                None,
            );
            assert!(matches!(res, Err((code, false, _)) if code == ERR_CONFLICT));
        }
    }

    #[test]
    fn guest_events_ws_path_validation_and_short_invite_domains() {
        let auth_hash = api_authority_hash("api.multiplayer.tech");
        let peers = PeersStoreRecord::default();
        let guest = Mp2Member {
            account_id: 0,
            handle: "phall".to_string(),
            client: "web".to_string(),
            is_guest: true,
            is_browser: true,
            agent_name: None,
            agent_state: None,
            agent_summary: None,
            status: "live".to_string(),
            device_id: None,
            nick: None,
        };
        let mut sess = make_mp2_test_session(vec![guest.clone()]);
        update_mp2_provenance_cache(&mut sess, &[guest], auth_hash, &peers);
        assert!(
            !sess.provenance_by_account.contains_key(&0),
            "guest account_id 0 must never pollute provenance_by_account"
        );

        ingest_mp2_event_into_session(
            &mut sess,
            Mp2Event {
                seq: 1,
                ts_ms: 1_700_000_000_000,
                client_msg_id: None,
                sender: outpost_control::Mp2Sender {
                    account_id: 0,
                    handle: "phall".to_string(),
                    client: "web".to_string(),
                    is_guest: true,
                    is_browser: true,
                    agent_name: None,
                    device_id: None,
                    nick: None,
                },
                target: "@all".to_string(),
                kind: Mp2EventKind::Chat,
                body_encoding: "utf8".to_string(),
                body: "hello from browser guest".to_string(),
                mls_epoch: None,
                e2ee_mode: None,
                group_id_b64: None,
            },
            false,
        );
        // Signed-in browser message under operator's own account/handle MUST be flagged is_browser=true & sender_device_id=0!
        ingest_mp2_event_into_session(
            &mut sess,
            Mp2Event {
                seq: 2,
                ts_ms: 1_700_000_000_100,
                client_msg_id: None,
                sender: outpost_control::Mp2Sender {
                    account_id: 1001,
                    handle: "alice".to_string(),
                    client: "web".to_string(),
                    is_guest: false,
                    is_browser: false,
                    agent_name: None,
                    device_id: Some(9999),
                    nick: None,
                },
                target: "@all".to_string(),
                kind: Mp2EventKind::Chat,
                body_encoding: "utf8".to_string(),
                body: "same handle browser chat".to_string(),
                mls_epoch: None,
                e2ee_mode: None,
                group_id_b64: None,
            },
            false,
        );
        ingest_mp2_event_into_session(
            &mut sess,
            Mp2Event {
                seq: 3,
                ts_ms: 1_700_000_000_200,
                client_msg_id: None,
                sender: outpost_control::Mp2Sender {
                    account_id: 1001,
                    handle: "alice".to_string(),
                    client: String::new(),
                    is_guest: false,
                    is_browser: true,
                    agent_name: None,
                    device_id: None,
                    nick: None,
                },
                target: "@all".to_string(),
                kind: Mp2EventKind::Chat,
                body_encoding: "utf8".to_string(),
                body: "explicit is_browser flag".to_string(),
                mls_epoch: None,
                e2ee_mode: None,
                group_id_b64: None,
            },
            false,
        );
        let polled = sess.ring.poll(None, 0, 10, 65_536);
        assert_eq!(polled.events.len(), 3);
        if let Some(ev) = polled.events.first() {
            assert!(matches!(
                &ev.body,
                PartyEventBody::Chat {
                    sender_account_id: 0,
                    sender_handle,
                    is_browser: true,
                    ..
                } if sender_handle == "phall (guest)"
            ));
        }
        for idx in [1usize, 2usize] {
            if let Some(ev) = polled.events.get(idx) {
                assert!(matches!(
                    &ev.body,
                    PartyEventBody::Chat {
                        sender_account_id: 1001,
                        sender_device_id: 0,
                        sender_handle,
                        is_browser: true,
                        sender_client,
                        ..
                    } if sender_handle == "alice" && sender_client == "web"
                ));
            }
        }

        // Server-supplied ws_path validation
        assert_eq!(
            validate_party_ws_path(8801, ""),
            Ok("/v1/parties/8801/ws".to_string())
        );
        assert_eq!(
            validate_party_ws_path(8801, "/v1/parties/8801/ws"),
            Ok("/v1/parties/8801/ws".to_string())
        );
        assert!(validate_party_ws_path(8801, "/v1/parties/9999/ws").is_err());
        assert!(validate_party_ws_path(8801, "/v1/parties/8801/ws?evil=1").is_err());

        // `#fragment` invite links MUST preserve `#<secret>` verbatim (NEVER stripped or uppercased!)
        assert_eq!(
            normalize_room_enter_target(
                "https://multiplayer.tech/p/i/123456789#AbCdEf0123456789_-xYz"
            ),
            "https://multiplayer.tech/p/i/123456789#AbCdEf0123456789_-xYz"
        );
        assert_eq!(
            normalize_room_enter_target(
                "multiplayer.tech/p/i/123456789#AbCdEf0123456789_-xYz"
            ),
            "https://multiplayer.tech/p/i/123456789#AbCdEf0123456789_-xYz"
        );
        assert_eq!(
            normalize_room_enter_target(
                "https://clank.party/i/123456789#AbCdEf0123456789_-xYz"
            ),
            "https://clank.party/i/123456789#AbCdEf0123456789_-xYz"
        );
        assert_eq!(
            normalize_room_enter_target("clank.party/i/123456789#AbCdEf0123456789_-xYz"),
            "https://clank.party/i/123456789#AbCdEf0123456789_-xYz"
        );

        // Short invite domains (`clank.party`, `multiplayer.tech`, `mp.gg`)
        assert_eq!(normalize_room_enter_target("https://clank.party/@phall"), "@phall");
        assert_eq!(normalize_room_enter_target("clank.party/kaih"), "KAIH");
        assert_eq!(normalize_room_enter_target("https://clank.party/p/kaih"), "KAIH");
        assert_eq!(normalize_room_enter_target("https://multiplayer.tech/p/KAIH"), "KAIH");
        assert_eq!(normalize_room_enter_target("https://mp.gg/KAIH"), "KAIH");
        assert_eq!(normalize_room_enter_target("@phall"), "@phall");
        assert_eq!(normalize_room_enter_target("KAIH"), "KAIH");
        assert_eq!(normalize_room_enter_target(""), "");
    }

    #[test]
    fn e2ee_session_rejects_plaintext_decrypts_opaque_and_marks_historical_catchup()
    -> Result<(), String> {
        use mp_mls::{
            AccountDeviceListV1, ActiveDeviceEntryV1, ClientClass, CustodyMode, DeviceIdentity,
            InviteRecordV1, InviteSecrets, MpCryptoProvider, MpMlsClient, MpMlsDeviceBindingBodyV1,
            MpMlsDeviceBindingV1, MpMlsLeafCredV1, MpRoomPolicyExtV1, compute_join_proof,
            generate_single_use_key_package,
        };
        use outpost_core::mls_session::MlsRoomSession;
        use outpost_core::mls_store::derive_mls_store_key;

        let now_s = 1_760_000_000u64;
        let party_id = 8801u64;
        let ds_pk = SigningKey::from_bytes(&[0xD5; 32]).verifying_key().to_bytes();

        let make_id = |acc: u64, dev: u64, rseed: u8, dseed: u8, agent: bool| -> Result<([u8; 32], DeviceIdentity), String> {
            let rsk = SigningKey::from_bytes(&[rseed; 32]);
            let dsk = SigningKey::from_bytes(&[dseed; 32]);
            let body = MpMlsDeviceBindingBodyV1 {
                version: 1,
                account_id: acc,
                root_gen: 1,
                device_id: dev,
                device_gen: 1,
                client_class: ClientClass::Outpost,
                agent_capable: agent,
                custody_mode: CustodyMode::SelfCustody,
                iat_s: now_s - 60,
                exp_s: now_s + 29 * 86_400,
                root_pubkey: rsk.verifying_key().to_bytes(),
                mls_sig_pubkey: dsk.verifying_key().to_bytes(),
            };
            let binding = MpMlsDeviceBindingV1::sign(body, &rsk, &dsk).map_err(|e| e.to_string())?;
            let device_list = AccountDeviceListV1::sign(
                acc,
                1,
                1,
                now_s - 60,
                now_s + 29 * 86_400,
                vec![ActiveDeviceEntryV1 {
                    device_id: dev,
                    device_gen: 1,
                    mls_sig_pubkey: dsk.verifying_key().to_bytes(),
                }],
                &rsk,
            )
            .map_err(|e| e.to_string())?;
            let cred = MpMlsLeafCredV1 {
                binding,
                list_version: device_list.list_version,
                list_hash: device_list.list_hash().map_err(|e| e.to_string())?,
            };
            Ok((
                rsk.verifying_key().to_bytes(),
                DeviceIdentity::new(cred, device_list, dsk).map_err(|e| e.to_string())?,
            ))
        };

        let (alice_root_pk, alice_id) = make_id(1001, 2001, 0x11, 0x21, true)?;
        let (_bob_root_pk, bob_id) = make_id(1002, 2002, 0x12, 0x22, false)?;
        let policy = MpRoomPolicyExtV1 {
            version: 1,
            party_id,
            e2ee_mode: 1,
            require_self_custody: false,
            allow_browser_devices: true,
            org_id: 0,
            invite_epoch: 0,
            host_account_ids: vec![1001],
            banned_account_ids: Vec::new(),
        };
        let (alice_client, _gi) =
            MpMlsClient::create_room(party_id, [9u8; 8], &ds_pk, policy, alice_id)
                .map_err(|e| e.to_string())?;
        let gid = alice_client.group_id();
        let mut alice_mls =
            MlsRoomSession::new(alice_client, *derive_mls_store_key(&[0xA1; 32], 2001));

        let secrets = InviteSecrets::derive(&gid, &[0x44; 32]).map_err(|e| e.to_string())?;
        alice_mls.client_mut().register_active_invite(InviteRecordV1 {
            invite_id: 101,
            invite_epoch: 0,
            max_uses: 2,
            expires_at_s: now_s + 3600,
            inviter_root_pk: alice_root_pk,
            member_join_mac_key: secrets.member_join_mac_key,
        });
        let mut bob_provider = MpCryptoProvider::new();
        let (bob_kp, bob_kp_ref) =
            generate_single_use_key_package(&bob_id, &bob_provider).map_err(|e| e.to_string())?;
        let jp = compute_join_proof(
            &secrets.member_join_mac_key,
            &gid,
            101,
            0,
            now_s + 3600,
            1002,
            2002,
            &bob_kp_ref,
        )
        .map_err(|e| e.to_string())?;
        let add = alice_mls
            .build_add_member_commit(&bob_kp, 101, &jp, now_s, false)
            .map_err(|e| e.to_string())?;
        alice_mls
            .handle_finalized_commit(&[], &add.commit_bytes, now_s)
            .map_err(|e| e.to_string())?;
        let bob_client = MpMlsClient::join_from_welcome(
            &add.welcome_bytes,
            &add.welcome_auth,
            &secrets.member_join_mac_key,
            &bob_kp_ref,
            gid,
            party_id,
            &ds_pk,
            0,
            0,
            &alice_root_pk,
            bob_id,
            &mut bob_provider,
        )
        .map_err(|e| e.to_string())?;
        let bob_mls = MlsRoomSession::new(bob_client, *derive_mls_store_key(&[0xB2; 32], 2002));

        let mut sess = make_mp2_test_session(Vec::new());
        sess.e2ee_mode = 1;
        sess.mls_epoch = bob_mls.epoch();
        sess.mls_session = Some(bob_mls);

        // 1. Plaintext utf8 frame in e2ee_mode=1 MUST be rejected (never added to ring)!
        ingest_mp2_event_into_session(
            &mut sess,
            Mp2Event {
                seq: 1,
                ts_ms: 1_760_000_000_000,
                client_msg_id: None,
                sender: outpost_control::Mp2Sender {
                    account_id: 1001,
                    handle: "alice".to_string(),
                    client: "outpost".to_string(),
                    is_guest: false,
                    is_browser: false,
                    agent_name: None,
                    device_id: Some(2001),
                    nick: None,
                },
                target: "@all".to_string(),
                kind: Mp2EventKind::Chat,
                body_encoding: "utf8".to_string(),
                body: "FORGED PLAINTEXT @bob:agent".to_string(),
                mls_epoch: Some(1),
                e2ee_mode: Some(1),
                group_id_b64: None,
            },
            false,
        );
        assert_eq!(sess.ring.poll(None, 0, 10, 65_536).events.len(), 0);

        // 2. Encrypted opaque_b64 frame during historical catch-up decrypts cleanly with is_historical_catchup=true!
        let prep = alice_mls
            .prepare_outbound_chat(
                "cid-hist",
                "@bob:agent",
                "historical @bob:agent ping",
                now_s,
                |_| Ok(()),
            )
            .map_err(|e| e.to_string())?;
        ingest_mp2_event_into_session(
            &mut sess,
            Mp2Event {
                seq: 2,
                ts_ms: 1_760_000_001_000,
                client_msg_id: Some("cid-hist".to_string()),
                sender: outpost_control::Mp2Sender {
                    account_id: 1001,
                    handle: "alice".to_string(),
                    client: "outpost".to_string(),
                    is_guest: false,
                    is_browser: false,
                    agent_name: None,
                    device_id: Some(2001),
                    nick: None,
                },
                target: "*".to_string(),
                kind: Mp2EventKind::E2eeApp,
                body_encoding: "opaque_b64".to_string(),
                body: prep.body_b64,
                mls_epoch: Some(1),
                e2ee_mode: Some(1),
                group_id_b64: None,
            },
            true,
        );

        let poll = sess.ring.poll(None, 0, 10, 65_536);
        let ipc_resp = super::build_ipc_poll_resp(&sess, poll, false, false);
        assert_eq!(ipc_resp.e2ee_mode, 1);
        assert_eq!(ipc_resp.mls_epoch, 1);
        assert_eq!(ipc_resp.trust_tier, 2);
        assert!(ipc_resp.has_declared_agent);
        assert_eq!(ipc_resp.epoch_authenticator_b32.len(), 29);
        assert!(!ipc_resp.clone_detected);
        assert_eq!(ipc_resp.events.len(), 1);
        assert_eq!(
            ipc_resp.events.first().map(|e| e.is_historical_catchup),
            Some(true)
        );

        let summary = sess.summary();
        assert_eq!(summary.e2ee_mode, 1);
        assert_eq!(summary.trust_tier, 2);
        assert!(summary.has_declared_agent);
        assert_eq!(summary.epoch_authenticator_b32, ipc_resp.epoch_authenticator_b32);
        Ok(())
    }
}
