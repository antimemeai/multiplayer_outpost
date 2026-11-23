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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mp_protocol::{
    AccountId, DeviceId, EndpointDescriptor, MAX_DIRECT_ADDRS, Mp1Message, PartyId, PartyInviteId,
    PartyJoinMode, PartyMemberRecord, PartySnapshot, PartyVisibility, RelayPolicy, RequestId,
    TransportKind, sha256, validate_relay_url, verify_device_cwt,
};
use outpost_control::{
    ApprovePartyRequest, ChurnStatus, ControlClient, ControlError, CreatePartyRequest,
    EndpointUpdateCoalescer, EvictionChurnDetector, JoinPartyRequest, JoinPartyResponse,
    MintPartyInviteRequest, Mp1WsEvent, Mp1WsTarget, RequestSigner, WsConnectError,
    sleep_aware_now_ms, wall_now_ms, wall_now_secs,
};
use outpost_core::fence::scan_outbound_secrets;
use outpost_core::ipc_wire::IpcOpcode;
use outpost_core::p2p_wire::{
    P2pActivityState, P2pBridgeEnvelope, P2pChatMessage, P2pControlNotice, P2pControlNoticeKind,
    P2pEphemeralPulse, P2pPartyFrame,
};
use outpost_core::party_state::{
    DEFAULT_POLL_MAX_BYTES, DedupeCache, DedupeLookup, EpochFloorStore, PartyEventBody,
    PartyEventRing, PeerSendCandidate, SendPlanError, SendTarget, plan_send_recipients,
};
use outpost_core::storage_codec::{DeviceRecord, PeerRecord, PeersStoreRecord, TrustState};
use outpost_core::trust::{
    AdmissionDecision, PeerTrustLookup, api_authority_hash, compute_safety_number,
    effective_relay_policy, evaluate_peer_admission,
};
use outpost_daemon::{CancellationToken, DaemonHandler, DrainMode, write_log_lock_free};
use outpost_p2p::{
    CLOSE_PEER_REVOKED, CLOSE_UNAUTHORIZED, P2pEventStream, P2pTransportEvent, PartyP2pConfig,
    PartyP2pHandle, PartyP2pTransport, PeerDialTarget, Watcher as _,
};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::build_info::{build_digest, build_order};
use crate::ipc_payloads::{
    ActivePartySummary, ERR_CANCELLED, ERR_CONFLICT, ERR_CONTROL_PLANE, ERR_IDEMPOTENCY_CONFLICT,
    ERR_INTERNAL, ERR_INVALID_PARAMS, ERR_NOT_FOUND, FriendItem, FriendsListResp, IpcPartyEvent,
    IpcPartyEventKind, IpcProvenance, JoinRequestItem, KeyMismatchAlert, MemberInfo,
    PartyCreateResp, PartyEpochResp, PartyInviteMintResp, PartyJoinResp, PartyListResp,
    PartyMembersResp, PartyPollIpcResp, PartyRequestApproveResp, PartyRequestsListResp,
    ReloadDeviceResp, ResolveHandleResp, SendResultResp, StatusResp, UnpinnedPeerAlert,
    decode_control_notice_req, decode_party_create_req, decode_party_epoch_op_req,
    decode_party_invite_mint_req, decode_party_invite_revoke_req, decode_party_join_req,
    decode_party_kick_req, decode_party_poll_req, decode_party_post_board_req,
    decode_party_promote_req, decode_party_request_approve_req, decode_party_request_reject_req,
    decode_party_requests_list_req, decode_party_send_chat_req, decode_party_wait_req,
    decode_resolve_handle_req, decode_u64_req, encode_bool_resp, encode_friend_edge_resp,
    encode_friends_list_resp, encode_party_create_resp, encode_party_epoch_resp,
    encode_party_invite_mint_resp, encode_party_join_resp, encode_party_list_resp,
    encode_party_members_resp, encode_party_poll_resp, encode_party_request_approve_resp,
    encode_party_requests_list_resp, encode_reload_resp, encode_resolve_handle_resp,
    encode_send_result_resp, encode_status_resp, secret_kind_to_error_code, trust_state_to_u8,
};
use crate::storage::{
    build_control_client_config, load_device_record, load_epochs_store, load_peers_store,
    lock_state, open_state_dir, pubkey_fingerprint_hex, save_epochs_store, save_peers_store,
};

const WS_PING_INTERVAL: Duration = Duration::from_secs(20);
const WS_RECONNECT_SILENCE_MS: u64 = 45_000;
const WS_P2P_REVOKE_SILENCE_MS: u64 = 60_000;
const CWT_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
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
    members: HashMap<u64, PartyMemberState>,
    pubkey_to_device: HashMap<[u8; 32], u64>,
    provenance_by_account: HashMap<u64, CachedAccountProvenance>,
    unpinned_alerts: HashMap<u64, UnpinnedPeerAlert>,
    key_mismatch_alerts: HashMap<u64, KeyMismatchAlert>,
    ring: PartyEventRing,
    wait_notify: Arc<Notify>,
    p2p: Arc<PartyP2pHandle>,
    p2p_event_task: Option<JoinHandle<()>>,
    ws_stop: CancellationToken,
    ws_task: Option<JoinHandle<()>>,
    cwt_task: Option<JoinHandle<()>>,
}

impl ActivePartySession {
    fn summary(&self) -> ActivePartySummary {
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
            member_count: u8::try_from(self.members.len()).unwrap_or(u8::MAX),
            next_seq: self.ring.latest_seq(),
            daemon_epoch: self.ring.daemon_epoch,
        }
    }

    fn push_event(&mut self, body: PartyEventBody) -> u64 {
        let seq = self.ring.push(body);
        self.wait_notify.notify_waiters();
        seq
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
    pub fn load(
        state_dir_path: PathBuf,
        _runtime_dir_override: Option<PathBuf>,
        device_id: u64,
    ) -> Result<Arc<Self>, String> {
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

    /// Starts background control-plane Account WS & account identity fetch once after
    /// `daemon.lock` is held and `daemon_epoch` is assigned (never before!).
    pub fn start_background_tasks(self: &Arc<Self>) {
        if self.bg_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.run_account_ws_loop().await;
        });
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
                // 1. Immediately send Lane 2 Idle pulse to all connected admitted peers.
                let pulse_targets: Option<(Arc<PartyP2pHandle>, Vec<[u8; 32]>)> = {
                    let st = this.inner.lock().await;
                    st.active_party
                        .as_ref()
                        .filter(|s| s.party_id == active_pid)
                        .map(|sess| {
                            let pks: Vec<[u8; 32]> = sess
                                .members
                                .values()
                                .filter(|m| {
                                    m.record.device_id.get() != this.device_id
                                        && m.admitted
                                        && sess.p2p.is_peer_connected(&m.record.device_pubkey)
                                })
                                .map(|m| m.record.device_pubkey)
                                .collect();
                            (Arc::clone(&sess.p2p), pks)
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
                        st.active_party.as_ref().map(|s| Arc::clone(&s.p2p))
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
        // bound through CWT + pinned root_pubkey!
        let Some(&dev_id) = session.pubkey_to_device.get(&peer_pubkey) else {
            let p2p = Arc::clone(&session.p2p);
            drop(st);
            p2p.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
            return;
        };
        let Some(member) = session.members.get(&dev_id) else {
            let p2p = Arc::clone(&session.p2p);
            drop(st);
            p2p.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
            return;
        };
        if !member.admitted || member.trust_state != TrustState::PinnedTrusted || member.key_mismatch {
            let p2p = Arc::clone(&session.p2p);
            drop(st);
            p2p.revoke_peer(peer_pubkey, CLOSE_UNAUTHORIZED);
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
    ) -> (JoinHandle<()>, JoinHandle<()>) {
        let this_ws = Arc::clone(self);
        let stop_ws = ws_stop.clone();
        let ws_task = tokio::spawn(async move {
            this_ws.run_party_ws_loop(party_id, stop_ws).await;
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
                p2p_opt = Some(Arc::clone(&session.p2p));
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
                    let dup_pks = rebuild_pubkey_to_device(session, local_dev_id, local_dev_pk);
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

    async fn run_party_ws_loop(self: Arc<Self>, party_id: u64, stop: CancellationToken) {
        let Ok(pid) = PartyId::new(party_id) else {
            return;
        };
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
                (
                    st.control.clone(),
                    sess.effective_relay_policy,
                    sess.pinned_relay_url.clone(),
                    Arc::clone(&sess.p2p),
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
                        st.active_party.as_ref().map(|s| Arc::clone(&s.p2p))
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
                p2p_opt = Some(Arc::clone(&sess.p2p));
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
                p2p_opt = Some(Arc::clone(&sess.p2p));

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
                let dup_pks = rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk);
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
            p2p_opt = Some(Arc::clone(&sess.p2p));

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

            let dup_pks = rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk);
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
            p2p_opt = Some(Arc::clone(&sess.p2p));

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

            let dup_pks = rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk);
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
            let _ = rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk);
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
            (Some(Arc::clone(&sess.p2p)), pk)
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
            p2p_opt = Some(Arc::clone(&sess.p2p));
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

            let dup_pks = rebuild_pubkey_to_device(sess, local_dev_id, local_dev_pk);
            to_revoke_4401.extend(dup_pks);

            for (&did, m) in &sess.members {
                if did != local_dev_id && m.admitted {
                    allowed.insert(m.record.device_pubkey);
                    if !sess.p2p.is_peer_connected(&m.record.device_pubkey)
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
                members: HashMap::new(),
                pubkey_to_device: HashMap::new(),
                provenance_by_account: HashMap::new(),
                unpinned_alerts: HashMap::new(),
                key_mismatch_alerts: HashMap::new(),
                ring: PartyEventRing::new(party_id, daemon_epoch),
                wait_notify: Arc::new(Notify::new()),
                p2p: Arc::clone(&p2p),
                p2p_event_task: None,
                ws_stop: ws_stop.clone(),
                ws_task: None,
                cwt_task: None,
            });
            self.active_party_atomic.store(party_id, Ordering::Release);
        }

        let p2p_event_task = self.spawn_p2p_event_loop(party_id, event_stream, ws_stop.clone());
        let (ws_task, cwt_task) = self.spawn_party_drivers(party_id, ws_stop);
        self.attach_party_tasks(party_id, p2p_event_task, ws_task, cwt_task)
            .await;
        log_line(&format!("reattached active party {party_id} on daemon startup"));
    }

    async fn attach_party_tasks(
        &self,
        party_id: u64,
        p2p_event_task: JoinHandle<()>,
        ws_task: JoinHandle<()>,
        cwt_task: JoinHandle<()>,
    ) {
        let mut st = self.inner.lock().await;
        if let Some(sess) = st.active_party.as_mut()
            && sess.party_id == party_id
        {
            sess.p2p_event_task = Some(p2p_event_task);
            sess.ws_task = Some(ws_task);
            sess.cwt_task = Some(cwt_task);
        } else {
            p2p_event_task.abort();
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
            if let Some(t) = sess.p2p_event_task.take() {
                t.abort();
            }
            if let Some(t) = sess.ws_task.take() {
                t.abort();
            }
            if let Some(t) = sess.cwt_task.take() {
                t.abort();
            }
            sess.p2p.close().await;
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

        let mut members: Vec<MemberInfo> = sess
            .members
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
                    || sess.p2p.is_peer_connected(&m.record.device_pubkey),
                joined_seq: m.record.joined_seq,
                key_mismatch: m.key_mismatch,
            })
            .collect();
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

        let (p2p, target_pks, plan, frame) = {
            let st = self.inner.lock().await;

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

            let candidates = build_send_candidates(sess, self.device_id);
            let target = match req.target_device_id {
                Some(did) => SendTarget::Device(did),
                None => SendTarget::Broadcast,
            };
            let plan = plan_send_recipients(&candidates, target).map_err(map_send_plan_err)?;

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
            (Arc::clone(&sess.p2p), pks, plan, frame)
        };

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
                "failed to deliver chat message to any pinned connected peer",
            ));
        }

        let resp_bytes = encode_send_result_resp(&SendResultResp {
            party_id,
            client_msg_id,
            delivered_to: delivered,
            withheld_unpinned: plan.withheld_unpinned,
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
            }) {
                return Err(ipc_err(
                    secret_kind_to_error_code(kind),
                    false,
                    "outbound board envelope refused by secret-disclosure guard",
                ));
            }
        }

        let (p2p, target_pks, plan, frame) = {
            let st = self.inner.lock().await;

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

            let candidates = build_send_candidates(sess, self.device_id);
            let plan = plan_send_recipients(&candidates, SendTarget::Broadcast)
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
            (Arc::clone(&sess.p2p), pks, plan, frame)
        };

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
                "failed to deliver board envelope to any pinned connected peer",
            ));
        }

        let resp_bytes = encode_send_result_resp(&SendResultResp {
            party_id,
            client_msg_id,
            delivered_to: delivered,
            withheld_unpinned: plan.withheld_unpinned,
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
            let candidates = build_send_candidates(sess, self.device_id);
            let plan = plan_send_recipients(&candidates, SendTarget::Broadcast)
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
            (Arc::clone(&sess.p2p), pks, plan, frame)
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
            let mut st = self.inner.lock().await;
            for edge in rest_friends.friends {
                if let Some(h) = edge.peer_handle.as_deref()
                    && !h.is_empty()
                {
                    st.handle_cache.insert(edge.peer_account_id, h.to_string());
                }
                let verified_sn: Option<String> = match edge.peer_root_pubkey_b64.as_deref() {
                    Some(pk_b64) => match B64
                        .decode(pk_b64.as_bytes())
                        .ok()
                        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                    {
                        Some(pk) if mp_protocol::validate_ed25519_pubkey_strict(&pk).is_ok() => {
                            let local_sn =
                                mp_protocol::compute_safety_number(edge.peer_account_id, &pk);
                            if let Some(srv_sn) = edge.peer_safety_number.as_deref()
                                && !srv_sn.is_empty()
                                && srv_sn != local_sn
                            {
                                log_line(&format!(
                                    "ignoring mismatched server peer_safety_number for account_id={}; using locally computed SN",
                                    edge.peer_account_id
                                ));
                            }
                            Some(local_sn)
                        }
                        _ => {
                            // Invalid pubkey: never trust server-provided safety number.
                            Some(String::new())
                        }
                    },
                    None => None,
                };
                let handle = st
                    .handle_cache
                    .get(&edge.peer_account_id)
                    .cloned()
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
                if let Some(sn) = verified_sn {
                    entry.safety_number = sn;
                }
            }
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
                members: HashMap::new(),
                pubkey_to_device: HashMap::new(),
                provenance_by_account: HashMap::new(),
                unpinned_alerts: HashMap::new(),
                key_mismatch_alerts: HashMap::new(),
                ring: PartyEventRing::new(party_id, daemon_epoch),
                wait_notify: Arc::new(Notify::new()),
                p2p: Arc::clone(&p2p),
                p2p_event_task: None,
                ws_stop: ws_stop.clone(),
                ws_task: None,
                cwt_task: None,
            });
            self.active_party_atomic.store(party_id, Ordering::Release);
        }

        let p2p_event_task = self.spawn_p2p_event_loop(party_id, event_stream, ws_stop.clone());
        let (ws_task, cwt_task) = self.spawn_party_drivers(party_id, ws_stop);
        self.attach_party_tasks(party_id, p2p_event_task, ws_task, cwt_task)
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
                            "relay_mismatch: party requires pinned relay '{pinned}' (policy={policy_label}); pass --relay-url {pinned} or update device relay config"
                        ),
                        None => format!(
                            "relay_mismatch: party relay policy '{policy_label}' is incompatible with your local relay policy; pass --relay-policy or update device relay config"
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
                        members: HashMap::new(),
                        pubkey_to_device: HashMap::new(),
                        provenance_by_account: HashMap::new(),
                        unpinned_alerts: HashMap::new(),
                        key_mismatch_alerts: HashMap::new(),
                        ring: PartyEventRing::new(req.party_id, daemon_epoch),
                        wait_notify: Arc::new(Notify::new()),
                        p2p: Arc::clone(&p2p),
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
                let (ws_task, cwt_task) = self.spawn_party_drivers(req.party_id, ws_stop);
                self.attach_party_tasks(req.party_id, p2p_event_task, ws_task, cwt_task)
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
        if did != local_device_id
            && m.admitted
            && m.trust_state == TrustState::PinnedTrusted
            && !m.key_mismatch
        {
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
        } => {
            unpinned_alerts.insert(
                account_id.get(),
                UnpinnedPeerAlert {
                    account_id: account_id.get(),
                    root_pubkey,
                    safety_number: safety_number.clone(),
                    server_handle: server_handle.clone(),
                },
            );
            PartyMemberState {
                record: member.clone(),
                trust_state: TrustState::Unpinned,
                admitted: false,
                key_mismatch: false,
                cwt_exp_s: 0,
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
            connected_p2p: m.admitted && sess.p2p.is_peer_connected(&m.record.device_pubkey),
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
            format!("target account {account_id} is not pinned_trusted; run `mp-outpost peer trust {account_id}`"),
        ),
        SendPlanError::TargetDisconnected { device_id } => ipc_err(
            ERR_CONFLICT,
            true,
            format!("target device {device_id} is not currently connected over P2P"),
        ),
        SendPlanError::NoPinnedConnectedRecipients => ipc_err(
            ERR_CONFLICT,
            true,
            "no pinned_trusted peers currently connected over P2P",
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
                room_scope,
                payload,
            } => IpcPartyEventKind::BridgeEnvelope {
                provenance: build_provenance(
                    sess,
                    sender_account_id,
                    sender_device_id,
                    &sender_handle,
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
                    provenance: build_provenance(sess, sender_account_id, sender_device_id, ""),
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
            kind,
        });
    }

    PartyPollIpcResp {
        party_id: sess.party_id,
        daemon_epoch: poll.daemon_epoch,
        next_seq: poll.next_seq,
        dropped_before_seq: poll.dropped_before_seq,
        cursor_reset: poll.cursor_reset,
        gap_possible: poll.gap_possible,
        timed_out,
        events,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use mp_protocol::{
        AccountId, DeviceId, DirectAddr, EndpointDescriptor, MAX_CWT_TTL_SECS, PartyMemberRecord,
        RelayPolicy, TransportKind, encode_device_cwt,
    };
    use outpost_control::wall_now_secs;
    use outpost_core::storage_codec::DeviceRecord;

    use super::{
        AppDaemon, extract_cwt_expiry_ms, is_local_cwt_valid, prepare_peer_dial_target,
        sanitize_endpoint_for_mp1,
    };
    use crate::ipc_payloads::{
        ERR_SECRET_INVITE_TOKEN, PartyControlNoticeReq, encode_control_notice_req,
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
}
