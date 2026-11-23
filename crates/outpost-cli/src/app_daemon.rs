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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mp_protocol::{
    AccountId, DeviceId, EndpointDescriptor, Mp1Message, PartyId, PartyInviteId, PartyJoinMode,
    PartyMemberRecord, PartySnapshot, PartyVisibility, RelayPolicy, RequestId, sha256,
    verify_device_cwt,
};
use outpost_control::{
    ApprovePartyRequest, ChurnStatus, ControlClient, CreatePartyRequest, EndpointUpdateCoalescer,
    EvictionChurnDetector, JoinPartyRequest, JoinPartyResponse, MintPartyInviteRequest, Mp1WsEvent,
    Mp1WsTarget, RequestSigner, WsConnectError, sleep_aware_now_ms, wall_now_ms, wall_now_secs,
};
use outpost_core::fence::scan_outbound_secrets;
use outpost_core::ipc_wire::IpcOpcode;
use outpost_core::p2p_wire::{
    P2pBridgeEnvelope, P2pChatMessage, P2pControlNotice, P2pControlNoticeKind, P2pPartyFrame,
};
use outpost_core::party_state::{
    DEFAULT_POLL_MAX_BYTES, DedupeCache, DedupeOutcome, EpochFloorStore, PartyEventBody,
    PartyEventRing, PeerSendCandidate, SendPlanError, SendTarget, plan_send_recipients,
};
use outpost_core::storage_codec::{
    DeviceRecord, PeersStoreRecord, TrustState, decode_daemon_info,
};
use outpost_core::trust::{
    AdmissionDecision, PeerTrustLookup, api_authority_hash, compute_safety_number,
    effective_relay_policy, evaluate_peer_admission,
};
use outpost_daemon::{
    CancellationToken, DAEMON_INFO_NAME, DaemonHandler, DrainMode, generate_daemon_epoch,
    open_or_create_private_dir, read_file_in_dir, resolve_runtime_dir, write_log_lock_free,
};
use outpost_p2p::{
    CLOSE_PEER_REVOKED, CLOSE_UNAUTHORIZED, P2pError, P2pTransportEvent, PartyP2pConfig,
    PartyP2pTransport, PeerDialTarget,
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::JoinHandle;

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
    lock_state, open_state_dir, pubkey_fingerprint_hex, save_epochs_store,
};

const WS_PING_INTERVAL: Duration = Duration::from_secs(20);
const WS_RECONNECT_SILENCE_MS: u64 = 45_000;
const WS_P2P_REVOKE_SILENCE_MS: u64 = 60_000;
const CWT_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const MAX_WAIT_TIMEOUT_MS: u32 = 45_000;
const P2P_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

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
// P2P Actor Handle
// ---------------------------------------------------------------------------

enum P2pCmd {
    SetAllowed(HashSet<[u8; 32]>),
    Revoke {
        pubkey: [u8; 32],
        close_code: u32,
    },
    Connect {
        target: PeerDialTarget,
    },
    SendFrame {
        pubkey: [u8; 32],
        frame: P2pPartyFrame,
        reply: oneshot::Sender<Result<(), P2pError>>,
    },
    GetDescriptor {
        reply: oneshot::Sender<EndpointDescriptor>,
    },
    Close {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
struct P2pHandle {
    tx: mpsc::Sender<P2pCmd>,
    connected_peers: Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
}

impl P2pHandle {
    fn is_connected(&self, pubkey: &[u8; 32]) -> bool {
        self.connected_peers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(pubkey)
    }

    async fn set_allowed(&self, allowed: HashSet<[u8; 32]>) {
        let _ = self.tx.send(P2pCmd::SetAllowed(allowed)).await;
    }

    async fn revoke(&self, pubkey: [u8; 32], close_code: u32) {
        let _ = self.tx.send(P2pCmd::Revoke { pubkey, close_code }).await;
    }

    async fn connect(&self, target: PeerDialTarget) {
        let _ = self.tx.send(P2pCmd::Connect { target }).await;
    }

    async fn send_frame(&self, pubkey: [u8; 32], frame: P2pPartyFrame) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(P2pCmd::SendFrame {
                pubkey,
                frame,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::Closed)?;
        rx.await.map_err(|_| P2pError::Closed)?
    }

    async fn local_descriptor(&self) -> Option<EndpointDescriptor> {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(P2pCmd::GetDescriptor { reply: tx }).await.is_err() {
            return None;
        }
        rx.await.ok()
    }

    async fn close(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(P2pCmd::Close { reply: tx }).await.is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(2), rx).await;
        }
    }
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
    p2p: P2pHandle,
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
    runtime_dir_override: Option<PathBuf>,
    device_id: u64,
    exe_path: String,
    cached_daemon_epoch: AtomicU64,
    active_party_atomic: AtomicU64,
    inner: Arc<Mutex<DaemonRuntimeState>>,
    shutdown: CancellationToken,
}

impl AppDaemon {
    pub fn load(
        state_dir_path: PathBuf,
        runtime_dir_override: Option<PathBuf>,
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
            runtime_dir_override,
            device_id,
            exe_path,
            cached_daemon_epoch: AtomicU64::new(0),
            active_party_atomic: AtomicU64::new(0),
            inner: Arc::new(Mutex::new(runtime_state)),
            shutdown: CancellationToken::new(),
        });

        Ok(daemon)
    }

    /// Starts background control-plane Account WS & account identity fetch (never blocks IPC).
    pub fn start_background_tasks(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.run_account_ws_loop().await;
        });
    }

    fn daemon_epoch(&self) -> u64 {
        let cached = self.cached_daemon_epoch.load(Ordering::Acquire);
        if cached != 0 {
            return cached;
        }
        if let Ok(rt_path) =
            resolve_runtime_dir(self.device_id, self.runtime_dir_override.as_deref())
            && let Ok(vdir) = open_or_create_private_dir(&rt_path)
            && let Ok(Some(raw)) = read_file_in_dir(vdir.as_raw_fd(), DAEMON_INFO_NAME, 16 * 1024)
            && let Ok(info) = decode_daemon_info(&raw)
        {
            self.cached_daemon_epoch
                .store(info.daemon_epoch, Ordering::Release);
            return info.daemon_epoch;
        }
        let fallback = generate_daemon_epoch();
        self.cached_daemon_epoch.store(fallback, Ordering::Release);
        fallback
    }

    async fn run_account_ws_loop(self: Arc<Self>) {
        let mut churn = EvictionChurnDetector::new();
        let mut backoff_ms: u64 = 500;
        let mut had_session = false;

        // Best-effort initial `/v1/accounts/me` to learn own handle.
        {
            let control = {
                let st = self.inner.lock().await;
                st.control.clone()
            };
            if let Ok(me) = control.get_me().await {
                let mut st = self.inner.lock().await;
                st.own_handle = me.handle;
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
                                    Ok(Some(Mp1WsEvent::Closed { .. })) | Ok(None) | Err(_) => {
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
                Err(WsConnectError::Terminal(_)) => {
                    // Device revoked or unauthorized — stop hammering control plane until reload.
                    let mut st = self.inner.lock().await;
                    st.control_ws_connected = false;
                    drop(st);
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
                    log_line("ALERT: dual_host_churn_detected on Account WS (device_id in use elsewhere)");
                    let mut st = self.inner.lock().await;
                    st.dual_host_churn_alert = true;
                }
            }
            Mp1Message::PresenceSnapshot { entries } => {
                let mut st = self.inner.lock().await;
                for entry in entries {
                    let acc = entry.account_id.get();
                    let handle = st.handle_cache.get(&acc).cloned().unwrap_or_default();
                    let item = st.friends.entry(acc).or_insert_with(|| FriendItem {
                        account_id: acc,
                        state: 2,
                        updated_at_ms: entry.updated_ms,
                        presence_status: entry.status as u8,
                        joinable_party_id: entry.joinable_party_id.map(PartyId::get),
                        handle,
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
                    state: 2,
                    updated_at_ms: entry.updated_ms,
                    presence_status: entry.status as u8,
                    joinable_party_id: entry.joinable_party_id.map(PartyId::get),
                    handle,
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
                            state: 2,
                            updated_at_ms: wall_now_ms(),
                            presence_status: 0,
                            joinable_party_id: None,
                            handle,
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

    fn spawn_p2p_actor(
        self: &Arc<Self>,
        party_id: u64,
        transport: PartyP2pTransport,
    ) -> P2pHandle {
        let (tx, mut rx) = mpsc::channel::<P2pCmd>(256);
        let connected_peers = Arc::new(std::sync::RwLock::new(HashSet::new()));
        let connected_clone = Arc::clone(&connected_peers);
        let this = Arc::clone(self);

        tokio::spawn(async move {
            let mut transport = transport;
            loop {
                tokio::select! {
                    biased;
                    maybe_cmd = rx.recv() => {
                        let Some(cmd) = maybe_cmd else {
                            transport.close().await;
                            return;
                        };
                        match cmd {
                            P2pCmd::SetAllowed(allowed) => {
                                transport.set_allowed_peers(allowed);
                            }
                            P2pCmd::Revoke { pubkey, close_code } => {
                                transport.revoke_peer(pubkey, close_code);
                                connected_clone
                                    .write()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .remove(&pubkey);
                            }
                            P2pCmd::Connect { target } => {
                                if !transport.is_peer_connected(&target.device_pubkey) {
                                    let _ = tokio::time::timeout(
                                        P2P_DIAL_TIMEOUT,
                                        transport.connect_peer(target),
                                    )
                                    .await;
                                }
                            }
                            P2pCmd::SendFrame { pubkey, frame, reply } => {
                                let res = transport.send_frame(pubkey, &frame).await;
                                let _ = reply.send(res);
                            }
                            P2pCmd::GetDescriptor { reply } => {
                                let _ = reply.send(transport.local_endpoint_descriptor());
                            }
                            P2pCmd::Close { reply } => {
                                transport.close().await;
                                let _ = reply.send(());
                                return;
                            }
                        }
                    }
                    maybe_ev = transport.recv_event() => {
                        let Some(ev) = maybe_ev else {
                            return;
                        };
                        match ev {
                            P2pTransportEvent::PeerConnected { peer_pubkey } => {
                                connected_clone
                                    .write()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .insert(peer_pubkey);
                            }
                            P2pTransportEvent::PeerDisconnected { peer_pubkey, .. } => {
                                connected_clone
                                    .write()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .remove(&peer_pubkey);
                            }
                            P2pTransportEvent::FrameReceived { peer_pubkey, frame, .. } => {
                                this.on_p2p_frame_received(party_id, peer_pubkey, frame).await;
                            }
                        }
                    }
                }
            }
        });

        P2pHandle {
            tx,
            connected_peers,
        }
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
            let p2p = session.p2p.clone();
            drop(st);
            p2p.revoke(peer_pubkey, CLOSE_UNAUTHORIZED).await;
            return;
        };
        let Some(member) = session.members.get(&dev_id) else {
            return;
        };
        if !member.admitted || member.trust_state != TrustState::PinnedTrusted || member.key_mismatch {
            let p2p = session.p2p.clone();
            drop(st);
            p2p.revoke(peer_pubkey, CLOSE_UNAUTHORIZED).await;
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

    fn spawn_party_drivers(self: &Arc<Self>, party_id: u64, ws_stop: CancellationToken) -> (JoinHandle<()>, JoinHandle<()>) {
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
        let mut p2p_opt: Option<P2pHandle> = None;
        let mut local_expired = false;

        {
            let mut st = self.inner.lock().await;
            if st.cwt_expires_ms > 0 && (st.cwt_expires_ms / 1000) <= now_s.max(0) as u64 {
                local_expired = true;
            }
            if let Some(session) = st.active_party.as_mut()
                && session.party_id == party_id
            {
                p2p_opt = Some(session.p2p.clone());
                for m in session.members.values_mut() {
                    if m.admitted && m.cwt_exp_s <= now_s {
                        m.admitted = false;
                        to_revoke.push(m.record.device_pubkey);
                    }
                }
            }
        }

        if local_expired {
            log_line("local device CWT expired; tearing down active party P2P");
            self.teardown_active_party(party_id, "local_cwt_expired").await;
            return;
        }

        if let Some(p2p) = p2p_opt {
            for pk in to_revoke {
                p2p.revoke(pk, CLOSE_PEER_REVOKED).await;
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

            let (control, eff_policy, p2p_handle) = {
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
                    sess.p2p.clone(),
                )
            };

            match control.connect_ws(Mp1WsTarget::Party(pid)).await {
                Ok(mut ws) => {
                    backoff_ms = 250;
                    let mut coalescer = EndpointUpdateCoalescer::new(eff_policy);
                    let mut ping_iv = tokio::time::interval(WS_PING_INTERVAL);
                    ping_iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    ping_iv.tick().await;

                    // Submit current descriptor if not ForceRelays.
                    if eff_policy != RelayPolicy::ForceRelays
                        && let Some(raw_desc) = p2p_handle.local_descriptor().await
                    {
                        let desc = sanitize_endpoint_for_mp1(raw_desc);
                        if (!desc.direct_addrs.is_empty() || !desc.relay_url.is_empty())
                            && let Some(to_send) = coalescer.submit(desc)
                        {
                            let _ = ws.send_party_endpoint_update(to_send).await;
                        }
                    }

                    loop {
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
                p2p_handle.set_allowed(HashSet::new()).await;
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
                    log_line("ALERT: dual_host_churn_detected on Party WS; pausing P2P");
                    let p2p = {
                        let mut st = self.inner.lock().await;
                        st.dual_host_churn_alert = true;
                        st.active_party.as_ref().map(|s| s.p2p.clone())
                    };
                    if let Some(p) = p2p {
                        p.set_allowed(HashSet::new()).await;
                    }
                }
                false
            }
            Mp1Message::PartySnapshot(snapshot) => {
                if snapshot.party_id.get() != party_id {
                    return false;
                }
                if !self
                    .check_and_persist_epoch(party_id, snapshot.party_epoch, false)
                    .await
                {
                    log_line("rejected PartySnapshot with regressed epoch");
                    return false;
                }
                self.apply_party_snapshot(snapshot).await;
                false
            }
            Mp1Message::PartyMemberJoined {
                party_epoch,
                member,
            } => {
                if !self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
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
                if !self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
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
                if !self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
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
                if !self
                    .check_and_persist_epoch(party_id, party_epoch, false)
                    .await
                {
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
                let _ = self
                    .check_and_persist_epoch(party_id, party_epoch, true)
                    .await;
                self.teardown_active_party(party_id, &format!("party_disbanded:{reason:?}"))
                    .await;
                true
            }
            _ => false,
        }
    }

    async fn check_and_persist_epoch(
        &self,
        party_id: u64,
        observed_epoch: u64,
        is_disband: bool,
    ) -> bool {
        let (auth_hash, epochs_to_save) = {
            let mut st = self.inner.lock().await;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            match st
                .epochs
                .check_and_advance(auth_hash, party_id, observed_epoch, is_disband, wall_now_ms())
            {
                Ok(changed) => (auth_hash, if changed { Some(st.epochs.to_record()) } else { None }),
                Err(_) => return false,
            }
        };
        let _ = auth_hash;
        if let Some(rec) = epochs_to_save
            && let Ok(state_dir) = open_state_dir(&self.state_dir_path)
            && let Ok(lock) = lock_state(&state_dir)
        {
            let _ = save_epochs_store(&state_dir, &lock, &rec);
        }
        true
    }

    async fn apply_party_snapshot(self: &Arc<Self>, snapshot: PartySnapshot) {
        let now_s = wall_now_secs();
        let mut to_dial: Vec<PeerDialTarget> = Vec::new();
        let mut allowed: HashSet<[u8; 32]> = HashSet::new();
        let mut accounts_to_resolve: Vec<u64> = Vec::new();
        let p2p_opt: Option<P2pHandle>;

        {
            let mut st = self.inner.lock().await;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let peers_clone = st.peers.clone();
            let handle_cache_clone = st.handle_cache.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != snapshot.party_id.get() {
                return;
            }

            sess.party_epoch = snapshot.party_epoch;
            sess.leader_account_id = snapshot.leader_account_id.get();
            sess.leader_device_id = snapshot.leader_device_id.get();
            sess.visibility = snapshot.visibility;
            sess.join_mode = snapshot.join_mode;
            sess.relay_policy = snapshot.relay_policy;
            sess.max_members = snapshot.max_members;
            sess.pinned_relay_url = snapshot.pinned_relay_url;
            sess.members.clear();
            sess.pubkey_to_device.clear();
            sess.unpinned_alerts.clear();
            sess.key_mismatch_alerts.clear();

            let party_relay = sess.relay_policy;
            p2p_opt = Some(sess.p2p.clone());

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

                if dev_id != local_dev_id && m_state.admitted {
                    allowed.insert(member.device_pubkey);
                    if member.connected
                        && (!member.endpoint.direct_addrs.is_empty()
                            || !member.endpoint.relay_url.is_empty())
                    {
                        to_dial.push(PeerDialTarget {
                            device_id: dev_id,
                            device_pubkey: member.device_pubkey,
                            remote_relay_policy: party_relay,
                            endpoint: member.endpoint.clone(),
                        });
                    }
                }
                sess.pubkey_to_device.insert(member.device_pubkey, dev_id);
                sess.members.insert(dev_id, m_state);
            }

            sess.push_event(PartyEventBody::MembershipChanged {
                party_epoch: sess.party_epoch,
                summary: format!("party_snapshot: members={}", sess.members.len()),
            });
        }

        if let Some(p2p) = p2p_opt {
            p2p.set_allowed(allowed).await;
            self.schedule_dials(p2p, to_dial);
        }

        if !accounts_to_resolve.is_empty() {
            self.spawn_handle_resolution(accounts_to_resolve);
        }
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
        let mut resolve_acc = None;
        let p2p_opt: Option<P2pHandle>;

        {
            let mut st = self.inner.lock().await;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
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
            let party_relay = sess.relay_policy;
            p2p_opt = Some(sess.p2p.clone());

            let m_state = evaluate_member_state(
                &member,
                local_dev_id,
                local_acc_id,
                local_root_pk,
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

            if dev_id != local_dev_id
                && m_state.admitted
                && member.connected
                && (!member.endpoint.direct_addrs.is_empty()
                    || !member.endpoint.relay_url.is_empty())
            {
                to_dial.push(PeerDialTarget {
                    device_id: dev_id,
                    device_pubkey: member.device_pubkey,
                    remote_relay_policy: party_relay,
                    endpoint: member.endpoint.clone(),
                });
            }

            sess.pubkey_to_device.insert(member.device_pubkey, dev_id);
            sess.members.insert(dev_id, m_state);

            for (did, m) in &sess.members {
                if *did != local_dev_id && m.admitted {
                    allowed.insert(m.record.device_pubkey);
                }
            }

            sess.push_event(PartyEventBody::MembershipChanged {
                party_epoch,
                summary: format!("member_joined: account={acc_id} device={dev_id}"),
            });
        }

        if let Some(p2p) = p2p_opt {
            p2p.set_allowed(allowed).await;
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
        let p2p_opt: Option<P2pHandle>;

        {
            let mut st = self.inner.lock().await;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let peers_clone = st.peers.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            sess.party_epoch = party_epoch;
            let party_relay = sess.relay_policy;
            p2p_opt = Some(sess.p2p.clone());

            if let Some(existing) = sess.members.get(&device_id).cloned() {
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
                    auth_hash,
                    &peers_clone,
                    now_s,
                    existing.server_handle,
                    &mut sess.unpinned_alerts,
                    &mut sess.key_mismatch_alerts,
                );
                if device_id != local_dev_id
                    && m_state.admitted
                    && updated_rec.connected
                    && (!updated_rec.endpoint.direct_addrs.is_empty()
                        || !updated_rec.endpoint.relay_url.is_empty())
                {
                    to_dial.push(PeerDialTarget {
                        device_id,
                        device_pubkey: updated_rec.device_pubkey,
                        remote_relay_policy: party_relay,
                        endpoint: updated_rec.endpoint.clone(),
                    });
                }
                sess.members.insert(device_id, m_state);
            }

            for (did, m) in &sess.members {
                if *did != local_dev_id && m.admitted {
                    allowed.insert(m.record.device_pubkey);
                }
            }
        }

        if let Some(p2p) = p2p_opt {
            p2p.set_allowed(allowed).await;
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
            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            if sess.party_id != party_id {
                return;
            }
            sess.party_epoch = party_epoch;
            let removed = sess.members.remove(&device_id);
            let pk = removed.map(|m| {
                sess.pubkey_to_device.remove(&m.record.device_pubkey);
                m.record.device_pubkey
            });
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
            (Some(sess.p2p.clone()), pk)
        };

        if let (Some(p2p), Some(pk)) = (p2p_opt, revoked_pk) {
            p2p.revoke(pk, CLOSE_PEER_REVOKED).await;
        }
    }

    async fn reevaluate_active_party_trust(self: &Arc<Self>) {
        let now_s = wall_now_secs();
        let mut allowed: HashSet<[u8; 32]> = HashSet::new();
        let mut to_revoke: Vec<[u8; 32]> = Vec::new();
        let mut to_dial: Vec<PeerDialTarget> = Vec::new();
        let p2p_opt: Option<P2pHandle>;

        {
            let mut st = self.inner.lock().await;
            let auth_hash = api_authority_hash(&st.device.api_authority);
            let local_dev_id = st.device.device_id;
            let local_acc_id = st.device.account_id;
            let local_root_pk = st.device.root_pubkey;
            let peers_clone = st.peers.clone();

            let Some(sess) = st.active_party.as_mut() else {
                return;
            };
            let party_relay = sess.relay_policy;
            p2p_opt = Some(sess.p2p.clone());
            sess.unpinned_alerts.clear();
            sess.key_mismatch_alerts.clear();

            let old_members: Vec<(u64, PartyMemberState)> = sess.members.drain().collect();
            for (did, existing) in old_members {
                let m_state = evaluate_member_state(
                    &existing.record,
                    local_dev_id,
                    local_acc_id,
                    local_root_pk,
                    auth_hash,
                    &peers_clone,
                    now_s,
                    existing.server_handle,
                    &mut sess.unpinned_alerts,
                    &mut sess.key_mismatch_alerts,
                );
                if did != local_dev_id {
                    if m_state.admitted {
                        allowed.insert(m_state.record.device_pubkey);
                        if !sess.p2p.is_connected(&m_state.record.device_pubkey)
                            && m_state.record.connected
                            && (!m_state.record.endpoint.direct_addrs.is_empty()
                                || !m_state.record.endpoint.relay_url.is_empty())
                        {
                            to_dial.push(PeerDialTarget {
                                device_id: did,
                                device_pubkey: m_state.record.device_pubkey,
                                remote_relay_policy: party_relay,
                                endpoint: m_state.record.endpoint.clone(),
                            });
                        }
                    } else if existing.admitted || m_state.trust_state == TrustState::RevokedBlocked {
                        to_revoke.push(m_state.record.device_pubkey);
                    }
                }
                sess.members.insert(did, m_state);
            }
        }

        if let Some(p2p) = p2p_opt {
            for pk in to_revoke {
                p2p.revoke(pk, CLOSE_PEER_REVOKED).await;
            }
            p2p.set_allowed(allowed).await;
            self.schedule_dials(p2p, to_dial);
        }
    }

    fn schedule_dials(self: &Arc<Self>, p2p: P2pHandle, targets: Vec<PeerDialTarget>) {
        let local_dev_id = self.device_id;
        for target in targets {
            if p2p.is_connected(&target.device_pubkey) {
                continue;
            }
            let p2p_c = p2p.clone();
            if local_dev_id < target.device_id {
                // Single-flight primary dialer: smaller device_id dials immediately.
                tokio::spawn(async move {
                    p2p_c.connect(target).await;
                });
            } else {
                // Larger device_id initiates recovery dial if still unconnected after 1.5s.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    if !p2p_c.is_connected(&target.device_pubkey) {
                        p2p_c.connect(target).await;
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

    async fn teardown_active_party(&self, expected_party_id: u64, reason: &str) {
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
        let (new_device, new_peers, new_epochs) = {
            let state_dir =
                open_state_dir(&self.state_dir_path).map_err(|e| ipc_err(ERR_INTERNAL, false, e))?;
            let _lock = lock_state(&state_dir).map_err(|e| ipc_err(ERR_INTERNAL, true, e))?;
            let dev = load_device_record(&self.state_dir_path, self.device_id)
                .map_err(|e| ipc_err(ERR_INTERNAL, false, e))?;
            let peers = load_peers_store(&state_dir).map_err(|e| ipc_err(ERR_INTERNAL, false, e))?;
            let epochs =
                load_epochs_store(&state_dir).map_err(|e| ipc_err(ERR_INTERNAL, false, e))?;
            (dev, peers, EpochFloorStore::from_record(epochs))
        };

        let new_cwt_exp = extract_cwt_expiry_ms(&new_device);
        let new_control =
            build_device_control_client(&new_device).map_err(|e| ipc_err(ERR_INTERNAL, false, e))?;

        let active_party_id = {
            let mut st = self.inner.lock().await;
            st.device = new_device;
            st.cwt_expires_ms = new_cwt_exp;
            st.control = new_control;
            st.peers = new_peers;
            st.epochs = new_epochs;
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
                    || sess.p2p.is_connected(&m.record.device_pubkey),
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

    async fn op_party_send_chat(&self, conn_id: u64, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_send_chat_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        let (p2p, target_pks, plan, frame) = {
            let mut st = self.inner.lock().await;

            // 1. Secret disclosure guard (NEVER echo offending secret!).
            if let Some(kind) = scan_outbound_secrets(
                req.body.as_bytes(),
                &st.device.device_secret,
                &st.device.device_cwt,
            ) {
                return Err(ipc_err(
                    secret_kind_to_error_code(kind),
                    false,
                    "outbound message refused by secret-disclosure guard",
                ));
            }

            // 2. Live per-connection idempotency dedupe check.
            let payload_hash = hash_chat_req(&req);
            match st.dedupe.check_or_insert(
                conn_id,
                req.party_id,
                IpcOpcode::PartySendChat as u16,
                req.client_msg_id,
                payload_hash,
            ) {
                DedupeOutcome::New => {}
                DedupeOutcome::Duplicate => {
                    return encode_send_result_resp(&SendResultResp {
                        party_id: req.party_id,
                        client_msg_id: req.client_msg_id,
                        delivered_to: Vec::new(),
                        withheld_unpinned: Vec::new(),
                        disconnected: Vec::new(),
                    })
                    .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()));
                }
                DedupeOutcome::PayloadConflict => {
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
            if sess.party_id != req.party_id {
                return Err(ipc_err(
                    ERR_NOT_FOUND,
                    false,
                    format!("party {} is not active", req.party_id),
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
            (sess.p2p.clone(), pks, plan, frame)
        };

        let mut delivered = Vec::new();
        let mut disconnected = plan.disconnected;
        for (did, pk) in target_pks {
            match p2p.send_frame(pk, frame.clone()).await {
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

        encode_send_result_resp(&SendResultResp {
            party_id: req.party_id,
            client_msg_id: req.client_msg_id,
            delivered_to: delivered,
            withheld_unpinned: plan.withheld_unpinned,
            disconnected,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_post_board(&self, conn_id: u64, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_party_post_board_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

        let (p2p, target_pks, plan, frame) = {
            let mut st = self.inner.lock().await;

            if let Some(kind) = scan_outbound_secrets(
                &req.payload,
                &st.device.device_secret,
                &st.device.device_cwt,
            ) {
                return Err(ipc_err(
                    secret_kind_to_error_code(kind),
                    false,
                    "outbound board envelope refused by secret-disclosure guard",
                ));
            }

            let payload_hash = hash_board_req(&req);
            match st.dedupe.check_or_insert(
                conn_id,
                req.party_id,
                IpcOpcode::PartyPostBoard as u16,
                req.client_msg_id,
                payload_hash,
            ) {
                DedupeOutcome::New => {}
                DedupeOutcome::Duplicate => {
                    return encode_send_result_resp(&SendResultResp {
                        party_id: req.party_id,
                        client_msg_id: req.client_msg_id,
                        delivered_to: Vec::new(),
                        withheld_unpinned: Vec::new(),
                        disconnected: Vec::new(),
                    })
                    .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()));
                }
                DedupeOutcome::PayloadConflict => {
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
            if sess.party_id != req.party_id {
                return Err(ipc_err(
                    ERR_NOT_FOUND,
                    false,
                    format!("party {} is not active", req.party_id),
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
            (sess.p2p.clone(), pks, plan, frame)
        };

        let mut delivered = Vec::new();
        let mut disconnected = plan.disconnected;
        for (did, pk) in target_pks {
            match p2p.send_frame(pk, frame.clone()).await {
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

        encode_send_result_resp(&SendResultResp {
            party_id: req.party_id,
            client_msg_id: req.client_msg_id,
            delivered_to: delivered,
            withheld_unpinned: plan.withheld_unpinned,
            disconnected,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_send_control_notice(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
        let req = decode_control_notice_req(payload)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;
        let kind = P2pControlNoticeKind::from_u8(req.notice_kind)
            .map_err(|e| ipc_err(ERR_INVALID_PARAMS, false, e.to_string()))?;

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
            (sess.p2p.clone(), pks, plan, frame)
        };

        let mut delivered = Vec::new();
        let mut disconnected = plan.disconnected;
        for (did, pk) in target_pks {
            match p2p.send_frame(pk, frame.clone()).await {
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
        let poll = sess.ring.poll(
            cursor_epoch,
            req.after_seq,
            usize::from(req.limit),
            req.max_bytes as usize,
        );
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
                        handle,
                    });
                entry.state = edge.state;
                entry.updated_at_ms = edge.updated_at_ms;
            }
        }

        let st = self.inner.lock().await;
        let mut friends: Vec<FriendItem> = st.friends.values().cloned().collect();
        friends.sort_by_key(|f| f.account_id);
        encode_friends_list_resp(&FriendsListResp { friends })
            .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_create(self: &Arc<Self>, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
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

        let endpoint_desc = gather_mp1_endpoint_descriptor(&transport, eff_policy).await;

        let create_resp = match control
            .create_party(&CreatePartyRequest {
                visibility,
                join_mode,
                relay_policy: eff_policy,
                max_members: req.max_members.clamp(2, 12),
                endpoint: endpoint_desc,
                relay_url: chosen_relay,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                transport.close().await;
                return Err(ipc_err(ERR_CONTROL_PLANE, true, e.to_string()));
            }
        };

        let party_id = create_resp.party_id;
        let _ = self
            .check_and_persist_epoch(party_id, create_resp.party_epoch, false)
            .await;

        let daemon_epoch = self.daemon_epoch();
        let p2p = self.spawn_p2p_actor(party_id, transport);
        let ws_stop = CancellationToken::new();
        let (ws_task, cwt_task) = self.spawn_party_drivers(party_id, ws_stop.clone());

        {
            let mut st = self.inner.lock().await;
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
                p2p,
                ws_stop,
                ws_task: Some(ws_task),
                cwt_task: Some(cwt_task),
            });
            self.active_party_atomic.store(party_id, Ordering::Release);
        }

        encode_party_create_resp(&PartyCreateResp {
            party_id: create_resp.party_id,
            party_epoch: create_resp.party_epoch,
            pinned_relay_url: create_resp.pinned_relay_url,
        })
        .map_err(|e| ipc_err(ERR_INTERNAL, false, e.to_string()))
    }

    async fn op_party_join(self: &Arc<Self>, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
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

        // Best-effort fetch of party summary to validate relay policy & pinned relay URL
        // before spawning iroh::Endpoint.
        let summary_opt = control.get_party(pid).await.ok();
        let (party_policy, pinned_relay_str, visibility, join_mode, max_members, leader_acc, leader_dev) =
            if let Some(ref s) = summary_opt {
                let pp = RelayPolicy::from_u8(s.relay_policy).unwrap_or(RelayPolicy::AllowRelays);
                let vis = PartyVisibility::from_u8(s.visibility).unwrap_or(PartyVisibility::Private);
                let jm = PartyJoinMode::from_u8(s.join_mode).unwrap_or(PartyJoinMode::InviteOnly);
                (
                    pp,
                    s.pinned_relay_url.clone(),
                    vis,
                    jm,
                    s.max_members,
                    s.leader_account_id,
                    s.leader_device_id,
                )
            } else {
                (
                    effective_local,
                    String::new(),
                    PartyVisibility::Private,
                    PartyJoinMode::InviteOnly,
                    12,
                    0,
                    0,
                )
            };

        let eff_policy = effective_relay_policy(effective_local, party_policy).map_err(|_| {
            ipc_err(
                ERR_INVALID_PARAMS,
                false,
                "relay_policy_incompatible with target party",
            )
        })?;

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

        let endpoint_desc = gather_mp1_endpoint_descriptor(&transport, eff_policy).await;

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
                transport.close().await;
                return Err(ipc_err(ERR_CONTROL_PLANE, true, e.to_string()));
            }
        };

        match join_resp {
            JoinPartyResponse::Joined { party_epoch } => {
                let _ = self
                    .check_and_persist_epoch(req.party_id, party_epoch, false)
                    .await;
                let daemon_epoch = self.daemon_epoch();
                let p2p = self.spawn_p2p_actor(req.party_id, transport);
                let ws_stop = CancellationToken::new();
                let (ws_task, cwt_task) = self.spawn_party_drivers(req.party_id, ws_stop.clone());

                {
                    let mut st = self.inner.lock().await;
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
                        p2p,
                        ws_stop,
                        ws_task: Some(ws_task),
                        cwt_task: Some(cwt_task),
                    });
                    self.active_party_atomic
                        .store(req.party_id, Ordering::Release);
                }

                Ok(encode_party_join_resp(&PartyJoinResp {
                    status: 0,
                    party_epoch,
                    request_id: 0,
                }))
            }
            JoinPartyResponse::PendingApproval { request_id } => {
                transport.close().await;
                Ok(encode_party_join_resp(&PartyJoinResp {
                    status: 1,
                    party_epoch: 0,
                    request_id,
                }))
            }
        }
    }

    async fn op_party_leave(&self, payload: &[u8]) -> Result<Vec<u8>, IpcErr> {
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
        let _ = self
            .check_and_persist_epoch(req.party_id, resp.party_epoch, true)
            .await;
        self.teardown_active_party(req.party_id, "operator_disband")
            .await;
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

    async fn on_drain(&self, mode: DrainMode) {
        self.daemon.shutdown.cancel();
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

fn is_mp1_allowed_direct_addr(addr: mp_protocol::DirectAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr {
        mp_protocol::DirectAddr::V4 { ip, .. } => {
            let [a, b, c, d] = ip;
            !(a == 0 || a == 127 || a >= 224 || (a == 255 && b == 255 && c == 255 && d == 255))
        }
        mp_protocol::DirectAddr::V6 { ip, .. } => {
            let is_unspec = ip.iter().all(|&b| b == 0);
            let is_loopback = ip.get(0..15).is_some_and(|s| s.iter().all(|&b| b == 0))
                && ip.get(15) == Some(&1);
            let is_multicast = ip.first() == Some(&0xff);
            let is_v4_mapped = ip.get(0..10).is_some_and(|s| s.iter().all(|&b| b == 0))
                && ip.get(10) == Some(&0xff)
                && ip.get(11) == Some(&0xff);
            !(is_unspec || is_loopback || is_multicast || is_v4_mapped)
        }
    }
}

fn probe_local_non_loopback_v4() -> Option<[u8; 4]> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("192.0.2.1:80").ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            if is_mp1_allowed_direct_addr(mp_protocol::DirectAddr::V4 {
                ip: octets,
                port: 1,
            }) {
                Some(octets)
            } else {
                None
            }
        }
        std::net::SocketAddr::V6(_) => None,
    }
}

fn sanitize_endpoint_for_mp1(mut desc: EndpointDescriptor) -> EndpointDescriptor {
    let fallback_v4_port = desc.direct_addrs.iter().find_map(|a| match *a {
        mp_protocol::DirectAddr::V4 { port, .. } if port > 0 => Some(port),
        _ => None,
    });
    desc.direct_addrs
        .retain(|a| is_mp1_allowed_direct_addr(*a));
    if desc.direct_addrs.is_empty()
        && let (Some(port), Some(ip)) = (fallback_v4_port, probe_local_non_loopback_v4())
    {
        desc.direct_addrs
            .push(mp_protocol::DirectAddr::V4 { ip, port });
    }
    desc
}

async fn gather_mp1_endpoint_descriptor(
    transport: &PartyP2pTransport,
    eff_policy: RelayPolicy,
) -> EndpointDescriptor {
    let first = sanitize_endpoint_for_mp1(transport.local_endpoint_descriptor());
    if eff_policy == RelayPolicy::ForceRelays || !first.direct_addrs.is_empty() {
        return first;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    sanitize_endpoint_for_mp1(transport.local_endpoint_descriptor())
}

fn extract_cwt_expiry_ms(device: &DeviceRecord) -> u64 {
    match verify_device_cwt(
        &device.device_cwt,
        &device.root_pubkey,
        Some(&device.device_pubkey),
        0,
    ) {
        Ok(claims) => u64::try_from(claims.exp.max(0))
            .unwrap_or(0)
            .saturating_mul(1000),
        Err(_) => 0,
    }
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
            connected_p2p: m.admitted && sess.p2p.is_connected(&m.record.device_pubkey),
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
