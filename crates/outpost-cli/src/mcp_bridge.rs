//! Stateless thin MCP stdio bridge implementing `outpost_mcp::McpOutpostBackend`.
//!
//! - Connects LAZILY on first `tools/call` (never on construction / `initialize` / `tools/list`).
//! - Uses a multiplexed `d.sock` connection so concurrent tool calls and `Cancel` frames on
//!   `party_wait` work without blocking each other.
//! - Bounded `30s` reconnect budget on disconnect; `120s` idle `d.sock` drop when `active_party_id == 0`.
//! - NEVER kills or replaces a running daemon (`ClientKind::Mcp`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use mp_protocol::MAX_SAFE_ID;
use outpost_control::sleep_aware_now_ms;
use outpost_core::fence::{SecretMatchKind, scan_outbound_secrets};
use outpost_core::ipc_wire::{ClientKind, HelloPayload, IPC_SCHEMA_VER, IpcFrame, IpcOpcode};
use outpost_daemon::{
    ClientConfig, DaemonClient, DaemonError, SpawnCommand, decode_error_payload,
    encode_cancel_payload, fill_random, read_ipc_frame, write_ipc_frame,
};
use outpost_mcp::{
    BackendError, BoardPostReq, BoardReadResp, BoxFuture, CancellationToken, McpOutpostBackend,
    PartyPollReq, PartyPollResp, PartySendReq, PartyWaitReq, ProgressSender,
};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::build_info::{build_digest, build_order, encode_hex};
use crate::ipc_payloads::{
    ERR_INVALID_PARAMS, ERR_NOT_FOUND, PartyPollIpcReq, PartyPostBoardReq, PartySendChatReq,
    PartyWaitIpcReq, decode_friends_list_resp, decode_party_list_resp, decode_party_members_resp,
    decode_party_poll_resp, decode_send_result_resp, decode_status_resp, encode_party_poll_req,
    encode_party_post_board_req, encode_party_send_chat_req, encode_party_wait_req,
    encode_u64_req, error_code_to_secret_kind, poll_resp_to_board_events, relay_policy_name,
    trust_state_name,
};
use crate::storage::{pubkey_fingerprint_hex, resolve_active_device_id};

const RECONNECT_BUDGET: Duration = Duration::from_secs(30);
const IDLE_DROP_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PARTY_WAIT_MS: u32 = 45_000;
const PARTY_WAIT_IPC_GRACE_MS: u64 = 5_000;

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<IpcFrame, DaemonError>>>>>;

/// RAII drop guard that cleans up the `pending` entry and transmits an IPC `Cancel` frame
/// if `MultiplexedConn::request` is dropped early (e.g. MCP cancellation or timeout).
struct PendingCancelGuard {
    pending: PendingMap,
    out_tx: mpsc::Sender<IpcFrame>,
    request_id: u64,
    cancel_req_id: u64,
    armed: bool,
}

impl PendingCancelGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingCancelGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let removed_sync = if let Ok(mut guard) = self.pending.try_lock() {
            guard.remove(&self.request_id);
            true
        } else {
            false
        };
        let cancel_frame = encode_cancel_payload(self.request_id).ok().map(|payload| IpcFrame {
            opcode: IpcOpcode::Cancel,
            request_id: self.cancel_req_id,
            payload,
        });
        let unsent_frame = match cancel_frame {
            Some(frame) => match self.out_tx.try_send(frame) {
                Ok(()) => None,
                Err(mpsc::error::TrySendError::Full(f)) => Some(f),
                Err(mpsc::error::TrySendError::Closed(_)) => None,
            },
            None => None,
        };
        if !removed_sync || unsent_frame.is_some() {
            let pending = Arc::clone(&self.pending);
            let out_tx = self.out_tx.clone();
            let req_id = self.request_id;
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    if !removed_sync {
                        pending.lock().await.remove(&req_id);
                    }
                    if let Some(frame) = unsent_frame {
                        let _ = out_tx.send(frame).await;
                    }
                });
            }
        }
    }
}

/// Multiplexed IPC client over a single `UnixStream` allowing concurrent requests and `Cancel`.
struct MultiplexedConn {
    out_tx: mpsc::Sender<IpcFrame>,
    pending: PendingMap,
    next_req_id: AtomicU64,
    alive: Arc<AtomicBool>,
    active_party_id: AtomicU64,
    last_activity_ms: AtomicU64,
    upgrade_available: bool,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<()>,
}

impl Drop for MultiplexedConn {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

impl MultiplexedConn {
    fn from_daemon_client(client: DaemonClient) -> Arc<Self> {
        let (stream, ack, upgrade_available, _peer_pid) = client.into_parts();
        let (mut reader, mut writer) = stream.into_split();
        let (out_tx, mut out_rx) = mpsc::channel::<IpcFrame>(64);
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));

        let alive_w = Arc::clone(&alive);
        let pending_w = Arc::clone(&pending);
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if write_ipc_frame(&mut writer, &frame).await.is_err() {
                    alive_w.store(false, Ordering::Release);
                    fail_all_pending(&pending_w).await;
                    return;
                }
            }
            alive_w.store(false, Ordering::Release);
        });

        let alive_r = Arc::clone(&alive);
        let pending_r = Arc::clone(&pending);
        let reader_task = tokio::spawn(async move {
            loop {
                match read_ipc_frame(&mut reader).await {
                    Ok(Some(frame)) => {
                        let tx = pending_r.lock().await.remove(&frame.request_id);
                        if let Some(tx) = tx {
                            let _ = tx.send(Ok(frame));
                        }
                    }
                    Ok(None) | Err(_) => {
                        alive_r.store(false, Ordering::Release);
                        fail_all_pending(&pending_r).await;
                        return;
                    }
                }
            }
        });

        Arc::new(Self {
            out_tx,
            pending,
            next_req_id: AtomicU64::new(2),
            alive,
            active_party_id: AtomicU64::new(ack.active_party_id),
            last_activity_ms: AtomicU64::new(sleep_aware_now_ms()),
            upgrade_available,
            reader_task,
            writer_task,
        })
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn touch(&self) {
        self.last_activity_ms
            .store(sleep_aware_now_ms(), Ordering::Release);
    }

    fn idle_duration(&self) -> Duration {
        let now_ms = sleep_aware_now_ms();
        let last = self.last_activity_ms.load(Ordering::Acquire);
        Duration::from_millis(now_ms.saturating_sub(last))
    }

    fn alloc_req_id(&self) -> u64 {
        let id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id > MAX_SAFE_ID {
            self.next_req_id.store(2, Ordering::Relaxed);
            return 2;
        }
        id
    }

    async fn send_cancel(&self, target_request_id: u64) {
        if let Ok(payload) = encode_cancel_payload(target_request_id) {
            let frame = IpcFrame {
                opcode: IpcOpcode::Cancel,
                request_id: self.alloc_req_id(),
                payload,
            };
            let _ = self.out_tx.send(frame).await;
        }
    }

    async fn request(
        &self,
        opcode: IpcOpcode,
        payload: Vec<u8>,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<u8>, BackendError> {
        if !self.is_alive() {
            return Err(BackendError::DaemonDisconnected);
        }
        self.touch();

        let request_id = self.alloc_req_id();
        let cancel_req_id = self.alloc_req_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id, tx);

        let mut guard = PendingCancelGuard {
            pending: Arc::clone(&self.pending),
            out_tx: self.out_tx.clone(),
            request_id,
            cancel_req_id,
            armed: true,
        };

        let frame = IpcFrame {
            opcode,
            request_id,
            payload,
        };
        if self.out_tx.send(frame).await.is_err() {
            guard.disarm();
            self.pending.lock().await.remove(&request_id);
            self.alive.store(false, Ordering::Release);
            return Err(BackendError::DaemonDisconnected);
        }

        let resp_frame = match cancel {
            Some(tok) => {
                tokio::select! {
                    biased;
                    _ = tok.cancelled() => {
                        guard.disarm();
                        self.pending.lock().await.remove(&request_id);
                        self.send_cancel(request_id).await;
                        return Err(BackendError::ToolError {
                            code: "cancelled".to_string(),
                            message: "request cancelled".to_string(),
                        });
                    }
                    r = rx => {
                        guard.disarm();
                        match r {
                            Ok(Ok(f)) => f,
                            Ok(Err(_)) | Err(_) => return Err(BackendError::DaemonDisconnected),
                        }
                    }
                }
            }
            None => match rx.await {
                Ok(Ok(f)) => {
                    guard.disarm();
                    f
                }
                Ok(Err(_)) | Err(_) => {
                    guard.disarm();
                    return Err(BackendError::DaemonDisconnected);
                }
            },
        };

        self.touch();
        if resp_frame.opcode == IpcOpcode::Error {
            return match decode_error_payload(&resp_frame.payload) {
                Ok((code, _retryable, message)) => Err(map_ipc_error(code, message)),
                Err(_) => Err(BackendError::DaemonDisconnected),
            };
        }
        if resp_frame.opcode != opcode {
            return Err(BackendError::DaemonDisconnected);
        }
        Ok(resp_frame.payload)
    }
}

async fn fail_all_pending(pending: &PendingMap) {
    let mut guard = pending.lock().await;
    for (_, tx) in guard.drain() {
        let _ = tx.send(Err(DaemonError::Protocol(
            "daemon IPC connection closed".to_string(),
        )));
    }
}

/// Stateless thin MCP backend bridging `outpost-mcp` to the local binary IPC daemon.
pub struct DaemonMcpBridge {
    state_dir: PathBuf,
    runtime_dir_override: Option<PathBuf>,
    device_id_override: Option<u64>,
    conn: Arc<Mutex<Option<Arc<MultiplexedConn>>>>,
    connect_lock: Mutex<()>,
    idle_reaper_started: AtomicBool,
}

impl DaemonMcpBridge {
    /// Creates a lazy bridge. Performs ZERO filesystem, socket, or daemon I/O on construction!
    pub fn new(
        state_dir: PathBuf,
        runtime_dir_override: Option<PathBuf>,
        device_id_override: Option<u64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state_dir,
            runtime_dir_override,
            device_id_override,
            conn: Arc::new(Mutex::new(None)),
            connect_lock: Mutex::new(()),
            idle_reaper_started: AtomicBool::new(false),
        })
    }

    fn ensure_idle_reaper_started(&self) {
        if !self.idle_reaper_started.swap(true, Ordering::AcqRel) {
            let conn_arc = Arc::clone(&self.conn);
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_secs(15));
                iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    iv.tick().await;
                    let mut guard = conn_arc.lock().await;
                    if let Some(ref c) = *guard {
                        let idle = c.idle_duration();
                        let active_party = c.active_party_id.load(Ordering::Acquire);
                        let has_inflight = !c.pending.lock().await.is_empty();
                        if !c.is_alive()
                            || (active_party == 0 && !has_inflight && idle >= IDLE_DROP_TIMEOUT)
                        {
                            *guard = None;
                        }
                    }
                }
            });
        }
    }

    async fn get_or_connect(&self) -> Result<Arc<MultiplexedConn>, BackendError> {
        self.ensure_idle_reaper_started();

        // Fast path: reuse healthy existing connection without serializing on `connect_lock`.
        {
            let guard = self.conn.lock().await;
            if let Some(ref c) = *guard
                && c.is_alive()
            {
                return Ok(Arc::clone(c));
            }
        }

        // Single-flight connection lock prevents concurrent tool calls from stampeding
        // `DaemonClient::connect_or_spawn`.
        let _connect_guard = self.connect_lock.lock().await;
        {
            let guard = self.conn.lock().await;
            if let Some(ref c) = *guard
                && c.is_alive()
            {
                return Ok(Arc::clone(c));
            }
        }

        let device_id = resolve_active_device_id(&self.state_dir, self.device_id_override)
            .map_err(|msg| BackendError::ToolError {
                code: "device_not_enrolled".to_string(),
                message: msg,
            })?;

        let cfg = build_mcp_client_config(
            device_id,
            &self.state_dir,
            self.runtime_dir_override.as_deref(),
        )?;

        let deadline = Instant::now() + RECONNECT_BUDGET;
        let mut backoff_ms = 50u64;

        loop {
            match DaemonClient::connect_or_spawn(&cfg).await {
                Ok(client) => {
                    let mux = MultiplexedConn::from_daemon_client(client);
                    let mut guard = self.conn.lock().await;
                    *guard = Some(Arc::clone(&mux));
                    return Ok(mux);
                }
                Err(DaemonError::IncompatibleSchema { daemon_schema, .. }) => {
                    return Err(BackendError::SchemaMismatchRestartMcp { daemon_schema });
                }
                Err(DaemonError::SpawnFailed(msg)) => {
                    return Err(BackendError::ToolError {
                        code: "daemon_spawn_failed".to_string(),
                        message: msg,
                    });
                }
                Err(_) => {
                    if Instant::now() >= deadline {
                        return Err(BackendError::DaemonUnavailable);
                    }
                    let rem = deadline.saturating_duration_since(Instant::now());
                    let nap = Duration::from_millis(backoff_ms).min(rem);
                    tokio::time::sleep(nap).await;
                    backoff_ms = (backoff_ms.saturating_mul(2)).min(2000);
                }
            }
        }
    }

    async fn clear_active_party_if_not_found(&self, party_id: u64, err: &BackendError) {
        let not_found_code = format!("ipc_{ERR_NOT_FOUND}");
        if let BackendError::ToolError { code, .. } = err
            && code == &not_found_code
        {
            let guard = self.conn.lock().await;
            if let Some(ref c) = *guard
                && c.active_party_id.load(Ordering::Acquire) == party_id
            {
                c.active_party_id.store(0, Ordering::Release);
            }
        }
    }

    async fn call_ipc(
        &self,
        opcode: IpcOpcode,
        payload: Vec<u8>,
        cancel: Option<CancellationToken>,
    ) -> Result<(Vec<u8>, Arc<MultiplexedConn>), BackendError> {
        let conn = self.get_or_connect().await?;
        match conn.request(opcode, payload, cancel).await {
            Ok(bytes) => Ok((bytes, conn)),
            Err(BackendError::DaemonDisconnected) => {
                // Drop dead connection so next retry reconnects cleanly.
                let mut guard = self.conn.lock().await;
                if guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn)) {
                    *guard = None;
                }
                Err(BackendError::DaemonDisconnected)
            }
            Err(other) => Err(other),
        }
    }
}

pub fn build_spawn_command(
    device_id: u64,
    state_dir: &std::path::Path,
    runtime_dir_override: Option<&std::path::Path>,
) -> Result<SpawnCommand, String> {
    let exe_path =
        std::env::current_exe().map_err(|e| format!("failed to locate current_exe: {e}"))?;
    let mut args = vec![
        "__daemon".to_string(),
        "--device-id".to_string(),
        device_id.to_string(),
        "--ready-fd".to_string(),
        "3".to_string(),
        "--state-dir".to_string(),
        state_dir.to_string_lossy().into_owned(),
    ];
    if let Some(rt) = runtime_dir_override {
        args.push("--runtime-dir".to_string());
        args.push(rt.to_string_lossy().into_owned());
    }
    Ok(SpawnCommand {
        exe_path,
        args,
        env: Vec::new(),
    })
}

fn build_mcp_client_config(
    device_id: u64,
    state_dir: &std::path::Path,
    runtime_dir_override: Option<&std::path::Path>,
) -> Result<ClientConfig, BackendError> {
    let spawn_cmd = build_spawn_command(device_id, state_dir, runtime_dir_override).map_err(
        |msg| BackendError::ToolError {
            code: "spawn_config_error".to_string(),
            message: msg,
        },
    )?;
    let hello = HelloPayload {
        ipc_schema_ver: IPC_SCHEMA_VER,
        build_order: build_order(),
        build_digest: build_digest(),
        client_kind: ClientKind::Mcp,
        client_pid: std::process::id(),
    };
    let mut cfg = ClientConfig::new(device_id, hello);
    cfg.runtime_dir_override = runtime_dir_override.map(std::path::Path::to_path_buf);
    cfg.read_only_cli = true;
    cfg.on_disk_exe_matches_local = false;
    cfg.spawn_command = Some(spawn_cmd);
    Ok(cfg)
}

/// Defense-in-depth bridge-side secret scan (static secret formats: `mprk1_`, `mpdl1_`,
/// `.mpkey`, PEM private keys, `mpinv1_`, `mppi1_`, etc.) BEFORE any outbound message crosses IPC.
///
/// Uses a process-local random sentinel for `own_device_secret` (the stateless MCP bridge does
/// not hold the device secret; the daemon still performs the full per-device secret & CWT scan)
/// so static secret patterns are always scanned without false positives on all-zero payloads.
fn check_mcp_outbound_secrets(fields: &[&[u8]]) -> Result<(), BackendError> {
    static DUMMY_SECRET: OnceLock<[u8; 32]> = OnceLock::new();
    let sentinel = DUMMY_SECRET.get_or_init(|| {
        let mut buf = [0u8; 32];
        if fill_random(&mut buf).is_err() {
            // Non-zero high-entropy fallback constant if CSPRNG is ever unavailable.
            buf = [
                0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed,
                0xc8, 0x34, 0x10, 0x82, 0x27, 0x6b, 0xf3, 0xa2, 0x72, 0x51, 0xf8, 0x6c, 0x6a, 0x11,
                0xd0, 0xc1, 0x8e, 0x95,
            ];
        }
        buf
    });

    for field in fields {
        if let Some(kind) = scan_outbound_secrets(field, sentinel, &[])
            && !matches!(
                kind,
                SecretMatchKind::OwnDeviceSecret | SecretMatchKind::OwnDeviceCwt
            )
        {
            return Err(BackendError::SecretRefused(kind));
        }
    }
    Ok(())
}

fn map_ipc_error(code: u16, message: String) -> BackendError {
    if let Some(secret_kind) = error_code_to_secret_kind(code) {
        return BackendError::SecretRefused(secret_kind);
    }
    if code == ERR_INVALID_PARAMS {
        return BackendError::InvalidParams(message);
    }
    BackendError::ToolError {
        code: format!("ipc_{code}"),
        message,
    }
}

impl McpOutpostBackend for DaemonMcpBridge {
    fn outpost_status(&self) -> BoxFuture<'_, Result<Value, BackendError>> {
        Box::pin(async move {
            let (raw, conn) = self.call_ipc(IpcOpcode::GetStatus, Vec::new(), None).await?;
            let status = decode_status_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            let active_id = status.active_party.as_ref().map_or(0, |p| p.party_id);
            conn.active_party_id.store(active_id, Ordering::Release);

            let active_party_json = status.active_party.as_ref().map(|p| {
                json!({
                    "party_id": p.party_id,
                    "party_epoch": p.party_epoch,
                    "leader_account_id": p.leader_account_id,
                    "leader_device_id": p.leader_device_id,
                    "relay_policy": relay_policy_name(p.relay_policy),
                    "effective_relay_policy": relay_policy_name(p.effective_relay_policy),
                    "pinned_relay_url": p.pinned_relay_url,
                    "max_members": p.max_members,
                    "member_count": p.member_count,
                    "next_seq": p.next_seq,
                    "daemon_epoch": p.daemon_epoch,
                })
            });

            let unpinned: Vec<Value> = status
                .unpinned_alerts
                .iter()
                .map(|a| {
                    json!({
                        "account_id": a.account_id,
                        "server_handle": a.server_handle,
                        "safety_number": a.safety_number,
                        "root_pubkey_fingerprint": pubkey_fingerprint_hex(&a.root_pubkey),
                    })
                })
                .collect();

            let mismatches: Vec<Value> = status
                .key_mismatch_alerts
                .iter()
                .map(|m| {
                    json!({
                        "account_id": m.account_id,
                        "expected_root_fingerprint": pubkey_fingerprint_hex(&m.expected_root_pubkey),
                        "observed_root_fingerprint": pubkey_fingerprint_hex(&m.observed_root_pubkey),
                    })
                })
                .collect();

            Ok(json!({
                "account_id": status.account_id,
                "device_id": status.device_id,
                "handle": status.handle,
                "api_authority": status.api_authority,
                "local_relay_policy": relay_policy_name(status.local_relay_policy),
                "cwt_expires_ms": status.cwt_expires_ms,
                "daemon_epoch": status.daemon_epoch,
                "daemon_pid": status.daemon_pid,
                "daemon_build_order": status.build_order,
                "daemon_build_digest": encode_hex(&status.build_digest),
                "daemon_exe_path": status.exe_path,
                "upgrade_available": conn.upgrade_available,
                "control_ws_connected": status.control_ws_connected,
                "dual_host_churn_alert": status.dual_host_churn_alert,
                "active_party": active_party_json,
                "unpinned_peer_alerts": unpinned,
                "key_mismatch_alerts": mismatches,
            }))
        })
    }

    fn party_list(&self) -> BoxFuture<'_, Result<Value, BackendError>> {
        Box::pin(async move {
            let (raw, conn) = self.call_ipc(IpcOpcode::PartyList, Vec::new(), None).await?;
            let list = decode_party_list_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            let active_id = list.parties.first().map_or(0, |p| p.party_id);
            conn.active_party_id.store(active_id, Ordering::Release);

            let parties: Vec<Value> = list
                .parties
                .iter()
                .map(|p| {
                    json!({
                        "party_id": p.party_id,
                        "party_epoch": p.party_epoch,
                        "leader_account_id": p.leader_account_id,
                        "leader_device_id": p.leader_device_id,
                        "relay_policy": relay_policy_name(p.relay_policy),
                        "effective_relay_policy": relay_policy_name(p.effective_relay_policy),
                        "member_count": p.member_count,
                        "max_members": p.max_members,
                        "next_seq": p.next_seq,
                        "daemon_epoch": p.daemon_epoch,
                    })
                })
                .collect();

            Ok(json!({
                "daemon_epoch": list.daemon_epoch,
                "parties": parties,
            }))
        })
    }

    fn party_members(&self, party_id: u64) -> BoxFuture<'_, Result<Value, BackendError>> {
        Box::pin(async move {
            let (raw, conn) = match self
                .call_ipc(IpcOpcode::PartyMembers, encode_u64_req(party_id), None)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    self.clear_active_party_if_not_found(party_id, &e).await;
                    return Err(e);
                }
            };
            let resp =
                decode_party_members_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            conn.active_party_id.store(resp.party_id, Ordering::Release);
            let members: Vec<Value> = resp
                .members
                .iter()
                .map(|m| {
                    json!({
                        "device_id": m.device_id,
                        "account_id": m.account_id,
                        "handle": m.server_handle,
                        "root_pubkey_fingerprint": pubkey_fingerprint_hex(&m.root_pubkey),
                        "trust_state": trust_state_name(m.trust_state),
                        "safety_number": m.safety_number,
                        "connected_mp1": m.connected_mp1,
                        "connected_p2p": m.connected_p2p,
                        "joined_seq": m.joined_seq,
                        "key_mismatch": m.key_mismatch,
                    })
                })
                .collect();

            Ok(json!({
                "party_id": resp.party_id,
                "party_epoch": resp.party_epoch,
                "members": members,
            }))
        })
    }

    fn party_send(&self, req: PartySendReq) -> BoxFuture<'_, Result<Value, BackendError>> {
        Box::pin(async move {
            let party_id = req.party_id;
            let room_scope = req.room_scope.unwrap_or_else(|| "party/main".to_string());
            check_mcp_outbound_secrets(&[room_scope.as_bytes(), req.body.as_bytes()])?;
            let wire_req = PartySendChatReq {
                party_id,
                client_msg_id: req.client_msg_id,
                room_scope,
                target_device_id: req.target_device_id,
                body: req.body,
            };
            let encoded = encode_party_send_chat_req(&wire_req)
                .map_err(|e| BackendError::InvalidParams(e.to_string()))?;
            let (raw, conn) = match self.call_ipc(IpcOpcode::PartySendChat, encoded, None).await {
                Ok(v) => v,
                Err(e) => {
                    self.clear_active_party_if_not_found(party_id, &e).await;
                    return Err(e);
                }
            };
            let resp = decode_send_result_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            conn.active_party_id.store(resp.party_id, Ordering::Release);
            Ok(json!({
                "party_id": resp.party_id,
                "client_msg_id": resp.client_msg_id,
                "delivered_to": resp.delivered_to,
                "withheld_unpinned": resp.withheld_unpinned,
                "disconnected": resp.disconnected,
            }))
        })
    }

    fn board_post(&self, req: BoardPostReq) -> BoxFuture<'_, Result<Value, BackendError>> {
        Box::pin(async move {
            let party_id = req.party_id;
            check_mcp_outbound_secrets(&[req.room_scope.as_bytes(), &req.payload])?;
            let wire_req = PartyPostBoardReq {
                party_id,
                client_msg_id: req.client_msg_id,
                room_scope: req.room_scope,
                payload: req.payload,
            };
            let encoded = encode_party_post_board_req(&wire_req)
                .map_err(|e| BackendError::InvalidParams(e.to_string()))?;
            let (raw, conn) = match self
                .call_ipc(IpcOpcode::PartyPostBoard, encoded, None)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    self.clear_active_party_if_not_found(party_id, &e).await;
                    return Err(e);
                }
            };
            let resp = decode_send_result_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            conn.active_party_id.store(resp.party_id, Ordering::Release);
            Ok(json!({
                "party_id": resp.party_id,
                "client_msg_id": resp.client_msg_id,
                "delivered_to": resp.delivered_to,
                "withheld_unpinned": resp.withheld_unpinned,
                "disconnected": resp.disconnected,
            }))
        })
    }

    fn party_poll(&self, req: PartyPollReq) -> BoxFuture<'_, Result<PartyPollResp, BackendError>> {
        Box::pin(async move {
            let party_id = req.party_id;
            let wire_req = PartyPollIpcReq {
                party_id,
                cursor_epoch: req.cursor_epoch.unwrap_or(0),
                after_seq: req.after_seq,
                limit: req.limit,
                max_bytes: req.max_bytes,
                board_only: false,
            };
            let (raw, conn) = match self
                .call_ipc(IpcOpcode::PartyPoll, encode_party_poll_req(&wire_req), None)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    self.clear_active_party_if_not_found(party_id, &e).await;
                    return Err(e);
                }
            };
            let resp = decode_party_poll_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            let next_active = if resp.cursor_reset && resp.next_seq == 0 && resp.events.is_empty() {
                0
            } else {
                resp.party_id
            };
            conn.active_party_id.store(next_active, Ordering::Release);
            Ok(resp.into())
        })
    }

    fn board_read(&self, req: PartyPollReq) -> BoxFuture<'_, Result<BoardReadResp, BackendError>> {
        Box::pin(async move {
            let party_id = req.party_id;
            let wire_req = PartyPollIpcReq {
                party_id,
                cursor_epoch: req.cursor_epoch.unwrap_or(0),
                after_seq: req.after_seq,
                limit: req.limit,
                max_bytes: req.max_bytes,
                board_only: true,
            };
            let (raw, conn) = match self
                .call_ipc(IpcOpcode::PartyPoll, encode_party_poll_req(&wire_req), None)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    self.clear_active_party_if_not_found(party_id, &e).await;
                    return Err(e);
                }
            };
            let resp = decode_party_poll_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            let next_active = if resp.cursor_reset && resp.next_seq == 0 && resp.events.is_empty() {
                0
            } else {
                resp.party_id
            };
            conn.active_party_id.store(next_active, Ordering::Release);
            Ok(poll_resp_to_board_events(resp))
        })
    }

    fn party_wait(
        &self,
        req: PartyWaitReq,
        cancel: CancellationToken,
        _progress: Option<ProgressSender>,
    ) -> BoxFuture<'_, Result<PartyPollResp, BackendError>> {
        Box::pin(async move {
            let party_id = req.party_id;
            let capped_ms = req.timeout_ms.clamp(1, MAX_PARTY_WAIT_MS);
            let total_budget = Duration::from_millis(
                u64::from(capped_ms).saturating_add(PARTY_WAIT_IPC_GRACE_MS),
            );
            let wire_req = PartyWaitIpcReq {
                party_id,
                cursor_epoch: req.cursor_epoch.unwrap_or(0),
                after_seq: req.after_seq,
                timeout_ms: capped_ms,
            };
            let call_res = tokio::time::timeout(
                total_budget,
                self.call_ipc(
                    IpcOpcode::PartyWait,
                    encode_party_wait_req(&wire_req),
                    Some(cancel),
                ),
            )
            .await;

            let (raw, conn) = match call_res {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    self.clear_active_party_if_not_found(party_id, &e).await;
                    return Err(e);
                }
                Err(_) => {
                    // Bounded wait deadline exceeded; dropping `call_ipc` triggers
                    // `PendingCancelGuard` to send an IPC `Cancel` frame.
                    return Err(BackendError::DaemonDisconnected);
                }
            };
            let resp = decode_party_poll_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            let next_active = if resp.cursor_reset && resp.next_seq == 0 && resp.events.is_empty() {
                0
            } else {
                resp.party_id
            };
            conn.active_party_id.store(next_active, Ordering::Release);
            Ok(resp.into())
        })
    }

    fn party_friends(&self) -> BoxFuture<'_, Result<Value, BackendError>> {
        Box::pin(async move {
            let (raw, _conn) = self
                .call_ipc(IpcOpcode::FriendsList, Vec::new(), None)
                .await?;
            let resp =
                decode_friends_list_resp(&raw).map_err(|_| BackendError::DaemonDisconnected)?;
            let friends: Vec<Value> = resp
                .friends
                .iter()
                .map(|f| {
                    json!({
                        "account_id": f.account_id,
                        "handle": f.handle,
                        "state": f.state,
                        "presence_status": f.presence_status,
                        "joinable_party_id": f.joinable_party_id,
                        "updated_at_ms": f.updated_at_ms,
                    })
                })
                .collect();
            Ok(json!({ "friends": friends }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use outpost_core::fence::SecretMatchKind;

    #[tokio::test]
    async fn bridge_refuses_static_secrets_before_connecting_to_daemon() {
        // Point at a nonexistent state_dir so any IPC/daemon attempt would fail with
        // ToolError(device_not_enrolled) rather than SecretRefused.
        let bridge = DaemonMcpBridge::new(
            PathBuf::from("/nonexistent/outpost-mcp-bridge-test-state"),
            None,
            None,
        );

        let rk = mp_protocol::encode_recovery_key(&[0x42u8; 32]);
        let res_chat_body = bridge
            .party_send(PartySendReq {
                party_id: 1,
                body: format!("oops here is {rk}"),
                room_scope: Some("party/main".to_string()),
                target_device_id: None,
                client_msg_id: 1,
            })
            .await;
        assert_eq!(
            res_chat_body,
            Err(BackendError::SecretRefused(SecretMatchKind::RecoveryKey))
        );

        let res_chat_scope = bridge
            .party_send(PartySendReq {
                party_id: 1,
                body: "hello".to_string(),
                room_scope: Some(
                    "-----BEGIN MULTIPLAYER RECOVERY KEY-----\nAAAA\n-----END MULTIPLAYER RECOVERY KEY-----"
                        .to_string(),
                ),
                target_device_id: None,
                client_msg_id: 2,
            })
            .await;
        assert_eq!(
            res_chat_scope,
            Err(BackendError::SecretRefused(SecretMatchKind::RecoveryFile))
        );

        let res_pem = bridge
            .party_send(PartySendReq {
                party_id: 1,
                body: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
                    .to_string(),
                room_scope: Some("party/main".to_string()),
                target_device_id: None,
                client_msg_id: 4,
            })
            .await;
        assert_eq!(
            res_pem,
            Err(BackendError::SecretRefused(SecretMatchKind::PrivateKeyPem))
        );

        let res_board = bridge
            .board_post(BoardPostReq {
                party_id: 1,
                room_scope: "board/main".to_string(),
                payload: b"mpdl1_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_vec(),
                client_msg_id: 3,
            })
            .await;
        assert_eq!(
            res_board,
            Err(BackendError::SecretRefused(
                SecretMatchKind::DeviceLinkToken
            ))
        );
    }
}
