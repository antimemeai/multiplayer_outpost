//! Lazy IPC backend abstraction (`McpOutpostBackend`), cancellation token,
//! progress notification channel, and typed request/response payloads.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use outpost_core::fence::SecretMatchKind;
use serde_json::Value;
use tokio::sync::{Notify, mpsc};

/// Boxed `Send` future alias used by `McpOutpostBackend` for object-safe async dispatch
/// without requiring the `async-trait` proc-macro dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
struct CancelInner {
    cancelled: AtomicBool,
    notify: Notify,
}

/// Owned, cloneable, race-free cancellation token propagated to long-running backend calls
/// (notably `party_wait`) and triggered immediately on `notifications/cancelled` or `stdin` EOF.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    inner: Arc<CancelInner>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancelInner {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::Release) {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Resolves immediately if already cancelled, or waits until `cancel()` is called.
    /// Registers the `Notify` waiter before checking the atomic flag to eliminate missed wakeups.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.inner.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

/// Progress update emitted as MCP `notifications/progress` when the client supplied `_meta.progressToken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressUpdate {
    pub progress: u64,
    pub total: Option<u64>,
    pub message: Option<String>,
}

/// Non-blocking progress sink handed to `party_wait` only when the client supplied `_meta.progressToken`.
#[derive(Debug, Clone)]
pub struct ProgressSender {
    tx: mpsc::Sender<ProgressUpdate>,
}

impl ProgressSender {
    pub(crate) fn new(tx: mpsc::Sender<ProgressUpdate>) -> Self {
        Self { tx }
    }

    /// Best-effort non-blocking progress emit; drops the tick if the outbound queue is full.
    pub fn send(&self, progress: u64, total: Option<u64>, message: Option<String>) {
        let _ = self.tx.try_send(ProgressUpdate {
            progress,
            total,
            message,
        });
    }
}

/// Request payload for `party_send` (`0x01 chat_message`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartySendReq {
    pub party_id: u64,
    pub body: String,
    pub room_scope: Option<String>,
    pub target_device_id: Option<u64>,
    /// Shim-generated CSPRNG idempotency key in `1..=MAX_SAFE_ID`.
    pub client_msg_id: u64,
}

/// Request payload for `board_post` (`0x02 bridge_envelope`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardPostReq {
    pub party_id: u64,
    pub room_scope: String,
    pub payload: Vec<u8>,
    /// Shim-generated CSPRNG idempotency key in `1..=MAX_SAFE_ID`.
    pub client_msg_id: u64,
}

/// Request payload for `party_poll` and `board_read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyPollReq {
    pub party_id: u64,
    pub cursor_epoch: Option<u64>,
    pub after_seq: u64,
    pub limit: u16,
    pub max_bytes: u32,
}

/// Request payload for `party_wait`.
/// `timeout_ms` is defaulted to `25_000` and hard-capped at `45_000` by the MCP proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyWaitReq {
    pub party_id: u64,
    pub cursor_epoch: Option<u64>,
    pub after_seq: u64,
    pub timeout_ms: u32,
}

/// Request payload for `party_invite` (creates a room if not in one and optionally rings `@handle`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PartyInviteReq {
    pub handle: Option<String>,
    pub name: Option<String>,
}

/// Request payload for `party_join` (joins by `@handle`, 4-char code, URL, or empty for latest invite).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PartyJoinReq {
    pub target: Option<String>,
}

/// Request payload for `party_leave` (leaves the active party or explicit `party_id`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PartyLeaveReq {
    pub party_id: Option<u64>,
}

/// Request payload for `friend_add` (sends or accepts a friend request by `@handle`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendAddReq {
    pub handle: String,
}

/// Cryptographically authenticated peer provenance resolved by the daemon (never from untrusted wire hints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProvenance {
    pub sender_account_id: u64,
    pub sender_device_id: u64,
    pub sender_handle: String,
    pub root_pubkey_fingerprint: String,
    pub safety_number: String,
}

/// Untrusted remote event payload returned by `party_poll` / `party_wait` before MCP-layer nonce fencing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpPartyEventKind {
    Chat {
        provenance: PeerProvenance,
        room_scope: String,
        target_selector: String,
        timestamp_ns: i64,
        body: String,
    },
    ControlNotice {
        provenance: PeerProvenance,
        notice_kind: u8,
        party_epoch: u64,
        text: String,
    },
    MembershipChanged {
        party_epoch: u64,
        summary: String,
    },
    BridgeEnvelope {
        provenance: PeerProvenance,
        room_scope: String,
        payload: Vec<u8>,
    },
}

/// Single event entry from `party_poll` or `party_wait`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpPartyEvent {
    pub event_seq: u64,
    pub party_id: u64,
    pub party_epoch: u64,
    pub kind: McpPartyEventKind,
}

/// Structured response from `party_poll` and `party_wait`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyPollResp {
    pub party_id: u64,
    pub daemon_epoch: u64,
    pub next_seq: u64,
    pub dropped_before_seq: u64,
    pub cursor_reset: bool,
    pub gap_possible: bool,
    pub timed_out: bool,
    pub events: Vec<McpPartyEvent>,
}

/// Single `0x02 bridge_envelope` event returned by `board_read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardEnvelopeEvent {
    pub event_seq: u64,
    pub party_id: u64,
    pub party_epoch: u64,
    pub provenance: PeerProvenance,
    pub room_scope: String,
    pub payload: Vec<u8>,
}

/// Structured response from `board_read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardReadResp {
    pub party_id: u64,
    pub daemon_epoch: u64,
    pub next_seq: u64,
    pub dropped_before_seq: u64,
    pub cursor_reset: bool,
    pub gap_possible: bool,
    pub events: Vec<BoardEnvelopeEvent>,
}

/// Typed backend error variants governing MCP retry, disconnect, schema-mismatch, and secret-guard semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// Local daemon IPC dropped mid-call:
    /// - Idempotent reads retry once transparently.
    /// - Interrupted writes return honest `delivery_unknown` (`isError: true`) without duplicating.
    /// - Interrupted `party_wait` returns `{ cursor_reset: true, gap_possible: true }` (`isError: false`).
    DaemonDisconnected,
    /// Running daemon uses an incompatible binary IPC schema; MCP proxy NEVER kills daemons and never retries.
    SchemaMismatchRestartMcp { daemon_schema: u32 },
    /// Daemon could not be reached or started within the bounded reconnect budget.
    DaemonUnavailable,
    /// Outbound payload matched a forbidden secret (never echoed back).
    SecretRefused(SecretMatchKind),
    /// Invalid tool argument rejected by backend validation.
    InvalidParams(String),
    /// Domain/tool-level error returned as MCP `isError: true`.
    ToolError { code: String, message: String },
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonDisconnected => write!(f, "daemon IPC connection dropped"),
            Self::SchemaMismatchRestartMcp { daemon_schema } => {
                write!(f, "daemon IPC schema mismatch (daemon={daemon_schema})")
            }
            Self::DaemonUnavailable => write!(f, "outpost daemon unavailable"),
            Self::SecretRefused(kind) => write!(f, "secret material refused ({kind:?})"),
            Self::InvalidParams(msg) => write!(f, "invalid params: {msg}"),
            Self::ToolError { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Lazy IPC backend trait representing `outpost-daemon`'s `DaemonClient` (or a test/fault-injection mock).
///
/// The MCP transport MUST NEVER call any method on this trait during `initialize`, `ping`, or `tools/list`.
pub trait McpOutpostBackend: Send + Sync + 'static {
    fn outpost_status(&self) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn party_list(&self) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn party_members(&self, party_id: u64) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn party_send(&self, req: PartySendReq) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn board_post(&self, req: BoardPostReq) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn party_poll(&self, req: PartyPollReq) -> BoxFuture<'_, Result<PartyPollResp, BackendError>>;
    fn board_read(&self, req: PartyPollReq) -> BoxFuture<'_, Result<BoardReadResp, BackendError>>;
    fn party_wait(
        &self,
        req: PartyWaitReq,
        cancel: CancellationToken,
        progress: Option<ProgressSender>,
    ) -> BoxFuture<'_, Result<PartyPollResp, BackendError>>;
    fn party_friends(&self) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn party_invite(&self, req: PartyInviteReq) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn party_join(&self, req: PartyJoinReq) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn party_leave(&self, req: PartyLeaveReq) -> BoxFuture<'_, Result<Value, BackendError>>;
    fn friend_add(&self, req: FriendAddReq) -> BoxFuture<'_, Result<Value, BackendError>>;
}
