//! Lazy per-party `iroh` v1.5.0 3-lane `blackbird-mp/1` P2P transport.
//!
//! Security & framing contract (exact `blackbird-p2p` parity):
//! - QUIC (RFC 9000) + TLS 1.3 Mutual Raw Public Keys (RFC 7250, Ed25519).
//! - 0-RTT disabled (`max_tls_tickets(0)` + full 1-RTT accept handshake).
//! - RFC 9221 Unreliable Datagrams explicitly enabled (Lane 2, <= 1200 B).
//! - Zero N0 public pkarr / DNS address publication (`presets::Minimal`).
//! - ALPN `"blackbird-mp/1"`.
//! - Non-downgradeable relay policy (`AllowRelays`, `ForceRelays`, `NoRelays`).
//! - Mandatory peer allowlist enforced in `EndpointHooks` + accept loop before any
//!   streams or datagrams are processed; `revoke_peer` immediately closes active
//!   QUIC connections.
//! - Deterministic simultaneous-dial glare tie-break (`4409 SUPERSEDED`):
//!   opposite-direction healthy connections are resolved by smaller `EndpointId` initiator.
//! - Strict byte-budgeted inbound & outbound queues with RAII semaphore permits.
//! - 3-lane framing:
//!   - Lane 0 (`Control`): Bidirectional Stream 0, `u32` LE length-prefixed, <= 64 KiB, priority 10.
//!   - Lane 1 (`Causal`): Bidirectional Stream 4, `u32` LE length-prefixed, <= 4 MiB, priority 0.
//!   - Lane 2 (`Ephemeral`): RFC 9221 Unreliable Datagrams, <= 1200 B.

#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use bytes::Bytes;
use iroh::address_lookup::AddrFilter;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, BindOpts, ConnectError, ConnectWithOptsError,
    ConnectingError, Connection, ConnectionError, EndpointHooks, Incoming, IncomingAddr,
    QuicTransportConfig, RecvStream, SendDatagramError, SendStream, VarInt, presets,
};
pub use iroh::{Endpoint, EndpointAddr, Watcher};
use iroh::{EndpointId, PublicKey, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr};
use mp_protocol::{
    DirectAddr, EndpointDescriptor, MAX_DIRECT_ADDRS, MAX_RELAY_URL_BYTES, RelayPolicy,
    TransportKind,
};
use outpost_core::lan_protocol::{
    LanHandshakeMessage, LanProtocolError, decode_lan_handshake_frame, encode_lan_handshake_frame,
    is_lan_handshake_frame,
};
use outpost_core::p2p_wire::{
    P2pLane, P2pPartyFrame, P2pWireError, decode_p2p_party_frame, encode_p2p_party_frame,
};
use outpost_core::trust::effective_relay_policy;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use url::Url;
use zeroize::Zeroize as _;

pub const ALPN: &[u8] = b"blackbird-mp/1";
pub const STREAM_INIT_MARKER: u32 = u32::MAX;
pub const MAX_PENDING_LAN_PEERS: usize = 16;
pub const MAX_ALLOWED_PEERS: usize = 1024;

pub const CLOSE_SHUTDOWN: u32 = 4000;
pub const CLOSE_PROTOCOL_VIOLATION: u32 = 4400;
pub const CLOSE_UNAUTHORIZED: u32 = 4401;
pub const CLOSE_PEER_REVOKED: u32 = 4403;
pub const CLOSE_SUPERSEDED: u32 = 4409;
pub const CLOSE_FRAME_TOO_LARGE: u32 = 4413;

const STREAM_ID_CONTROL: u64 = 0;
const STREAM_ID_CAUSAL: u64 = 4;
const LANE_CONTROL_PRIORITY: i32 = 10;
const LANE_CAUSAL_PRIORITY: i32 = 0;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
const CLOSE_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(2);

const LANE_CHANNEL_CAPACITY: usize = 256;
const LIFECYCLE_EVENT_CAPACITY: usize = 1024;
const CONTROL_EVENT_CAPACITY: usize = 1024;
const CAUSAL_EVENT_CAPACITY: usize = 2048;
const EPHEMERAL_EVENT_CAPACITY: usize = 512;
const MAX_CONCURRENT_INBOUND_HANDSHAKES: usize = 64;

const INBOUND_CONTROL_BYTE_BUDGET: usize = 4 * 1024 * 1024;
const INBOUND_CAUSAL_BYTE_BUDGET: usize = 16 * 1024 * 1024;
const INBOUND_EPHEMERAL_BYTE_BUDGET: usize = 512 * 1024;
const OUTBOUND_CONTROL_BYTE_BUDGET: usize = 1024 * 1024;
const OUTBOUND_CAUSAL_BYTE_BUDGET: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct PartyP2pConfig {
    pub local_device_id: u64,
    pub device_secret: [u8; 32],
    pub effective_relay_policy: RelayPolicy,
    pub pinned_relay_url: Option<String>,
}

impl fmt::Debug for PartyP2pConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartyP2pConfig")
            .field("local_device_id", &self.local_device_id)
            .field("device_secret", &"[REDACTED]")
            .field("effective_relay_policy", &self.effective_relay_policy)
            .field("pinned_relay_url", &self.pinned_relay_url)
            .finish()
    }
}

impl Drop for PartyP2pConfig {
    fn drop(&mut self) {
        self.device_secret.zeroize();
    }
}

/// Explicit opt-in LAN (`NoRelays`) transport options for [`PartyP2pTransport::spawn_with_lan`].
///
/// Online mode uses [`PartyP2pTransport::spawn`] (no LAN config) and remains 100% unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LanTransportConfig {
    /// Explicitly opts into `NoRelays` local direct UDP transport (zero relays, zero internet).
    pub no_relays: bool,
    /// When `true` (ONLY valid with `no_relays == true` and `RelayPolicy::NoRelays`), admits up
    /// to [`MAX_PENDING_LAN_PEERS`] un-allowlisted peers on Lane 0 (`Control`) only until
    /// promoted via [`PartyP2pHandle::allow_peer`] or rejected.
    pub lan_open_admission: bool,
    /// Optional local UDP bind port for direct LAN transport (`None` = ephemeral port `0`).
    pub lan_bind_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct PeerDialTarget {
    pub device_id: u64,
    pub device_pubkey: [u8; 32],
    pub remote_relay_policy: RelayPolicy,
    pub endpoint: EndpointDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pTransportEvent {
    PeerConnected {
        peer_pubkey: [u8; 32],
    },
    PeerDisconnected {
        peer_pubkey: [u8; 32],
        reason_code: u32,
    },
    FrameReceived {
        peer_pubkey: [u8; 32],
        lane: P2pLane,
        frame: P2pPartyFrame,
    },
    LanHandshakeReceived {
        peer_pubkey: [u8; 32],
        message: LanHandshakeMessage,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pError {
    InvalidConfig(String),
    InvalidRelayUrl(String),
    InvalidPeerPubkey,
    SelfConnect,
    PolicyViolation(String),
    PeerNotAllowed,
    PeerNotConnected,
    Capacity,
    WireError(P2pWireError),
    FrameTooLarge,
    Timeout,
    Closed,
    Transport(String),
}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid p2p config: {msg}"),
            Self::InvalidRelayUrl(msg) => write!(f, "invalid relay url: {msg}"),
            Self::InvalidPeerPubkey => write!(f, "invalid peer Ed25519 public key"),
            Self::SelfConnect => write!(f, "cannot dial local endpoint"),
            Self::PolicyViolation(msg) => write!(f, "relay policy violation: {msg}"),
            Self::PeerNotAllowed => write!(f, "peer not in allowlist"),
            Self::PeerNotConnected => write!(f, "peer not connected"),
            Self::Capacity => write!(f, "peer allowlist capacity exceeded"),
            Self::WireError(err) => write!(f, "wire codec error: {err}"),
            Self::FrameTooLarge => write!(f, "frame exceeds lane limit"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::Closed => write!(f, "transport closed"),
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

impl std::error::Error for P2pError {}

struct BudgetedEvent {
    event: P2pTransportEvent,
    _permit: OwnedSemaphorePermit,
}

struct BudgetedFrame {
    payload: Bytes,
    _permit: OwnedSemaphorePermit,
}

struct ActivePeer {
    conn_id: u64,
    is_outbound: bool,
    conn: Connection,
    remote_addr: Option<SocketAddr>,
    is_pending: Arc<AtomicBool>,
    control_tx: mpsc::Sender<BudgetedFrame>,
    control_budget: Arc<Semaphore>,
    causal_tx: mpsc::Sender<BudgetedFrame>,
    causal_budget: Arc<Semaphore>,
    tasks: Vec<JoinHandle<()>>,
}

impl ActivePeer {
    fn shutdown(&mut self) {
        self.control_budget.close();
        self.causal_budget.close();
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

struct InFlightPendingGuard {
    shared: Arc<SharedState>,
    peer_id: EndpointId,
}

impl Drop for InFlightPendingGuard {
    fn drop(&mut self) {
        let mut in_flight = self
            .shared
            .in_flight_pending_lan
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        in_flight.remove(&self.peer_id);
    }
}

struct SharedState {
    local_id: EndpointId,
    relay_policy: RelayPolicy,
    pinned_relay_url: Option<RelayUrl>,
    pinned_relay_url_str: Option<String>,
    lan_mode: bool,
    lan_open_admission: AtomicBool,
    in_flight_pending_lan: Mutex<HashSet<EndpointId>>,
    allowed_peers: RwLock<HashSet<EndpointId>>,
    peers: RwLock<HashMap<EndpointId, ActivePeer>>,
    next_conn_id: AtomicU64,
    closed: Arc<AtomicBool>,
    closed_notify: Arc<Notify>,
    lifecycle_tx: mpsc::Sender<P2pTransportEvent>,
    control_tx: mpsc::Sender<BudgetedEvent>,
    control_budget: Arc<Semaphore>,
    causal_tx: mpsc::Sender<BudgetedEvent>,
    causal_budget: Arc<Semaphore>,
    ephemeral_tx: mpsc::Sender<BudgetedEvent>,
    ephemeral_budget: Arc<Semaphore>,
}

impl SharedState {
    fn is_allowed(&self, id: &EndpointId) -> bool {
        let guard = self
            .allowed_peers
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        guard.contains(id)
    }

    fn is_lan_open_admission(&self) -> bool {
        self.lan_mode
            && self.relay_policy == RelayPolicy::NoRelays
            && self.lan_open_admission.load(Ordering::Acquire)
    }

    fn pending_lan_slots_full(&self, candidate: &EndpointId) -> bool {
        let peers = self.peers.read().unwrap_or_else(PoisonError::into_inner);
        let in_flight = self
            .in_flight_pending_lan
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if in_flight.contains(candidate) {
            return true;
        }
        let active_pending = peers
            .values()
            .filter(|p| p.is_pending.load(Ordering::Acquire))
            .count();
        active_pending.saturating_add(in_flight.len()) >= MAX_PENDING_LAN_PEERS
    }

    fn try_reserve_in_flight_pending(
        self: &Arc<Self>,
        candidate: &EndpointId,
    ) -> Option<InFlightPendingGuard> {
        let peers = self.peers.read().unwrap_or_else(PoisonError::into_inner);
        let mut in_flight = self
            .in_flight_pending_lan
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if in_flight.contains(candidate) {
            return None;
        }
        let active_pending = peers
            .values()
            .filter(|p| p.is_pending.load(Ordering::Acquire))
            .count();
        if active_pending.saturating_add(in_flight.len()) >= MAX_PENDING_LAN_PEERS {
            return None;
        }
        in_flight.insert(*candidate);
        Some(InFlightPendingGuard {
            shared: Arc::clone(self),
            peer_id: *candidate,
        })
    }

    fn close_and_remove_peer(
        &self,
        peer_id: &EndpointId,
        expected_conn_id: Option<u64>,
        close_code: u32,
        reason: &[u8],
        emit_disconnect: bool,
    ) {
        let removed = {
            let mut peers = self.peers.write().unwrap_or_else(PoisonError::into_inner);
            let should_remove = match (peers.get(peer_id), expected_conn_id) {
                (Some(entry), Some(id)) => entry.conn_id == id,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if should_remove {
                peers.remove(peer_id)
            } else {
                None
            }
        };
        if let Some(mut peer) = removed {
            peer.conn.close(VarInt::from_u32(close_code), reason);
            peer.shutdown();
            if emit_disconnect {
                let _ = self
                    .lifecycle_tx
                    .try_send(P2pTransportEvent::PeerDisconnected {
                        peer_pubkey: *peer_id.as_bytes(),
                        reason_code: close_code,
                    });
            }
        }
    }
}

struct AllowlistHooks {
    shared: Arc<SharedState>,
}

impl fmt::Debug for AllowlistHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllowlistHooks")
            .field("relay_policy", &self.shared.relay_policy)
            .finish()
    }
}

impl EndpointHooks for AllowlistHooks {
    async fn before_connect(
        &self,
        remote_addr: &EndpointAddr,
        alpn: &[u8],
    ) -> BeforeConnectOutcome {
        if self.shared.closed.load(Ordering::Acquire) {
            return BeforeConnectOutcome::Reject;
        }
        if alpn != ALPN {
            return BeforeConnectOutcome::Reject;
        }
        if !self.shared.is_allowed(&remote_addr.id) {
            return BeforeConnectOutcome::Reject;
        }
        if self.shared.relay_policy == RelayPolicy::ForceRelays
            && remote_addr.addrs.iter().any(TransportAddr::is_ip)
        {
            return BeforeConnectOutcome::Reject;
        }
        BeforeConnectOutcome::Accept
    }

    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        if self.shared.closed.load(Ordering::Acquire) {
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(CLOSE_SHUTDOWN),
                reason: b"endpoint_closed".to_vec(),
            };
        }
        if conn.alpn() != ALPN {
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                reason: b"wrong_alpn".to_vec(),
            };
        }
        let remote_id = conn.remote_id();
        if !self.shared.is_allowed(&remote_id) {
            if !self.shared.is_lan_open_admission() {
                return AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(CLOSE_UNAUTHORIZED),
                    reason: b"peer_not_allowed".to_vec(),
                };
            }
            if self.shared.pending_lan_slots_full(&remote_id) {
                return AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(CLOSE_UNAUTHORIZED),
                    reason: b"pending_lan_cap_reached".to_vec(),
                };
            }
        }
        AfterHandshakeOutcome::Accept
    }
}

/// Concurrent, `Arc`-shareable control & send handle for an active per-party P2P endpoint.
///
/// All methods take `&self`, allowing concurrent per-peer dialing, sending, allowlist updates,
/// revocation, and roaming observation without head-of-line blocking or event-loop deadlocks.
pub struct PartyP2pHandle {
    local_device_id: u64,
    endpoint: Endpoint,
    shared: Arc<SharedState>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
}

impl PartyP2pHandle {
    pub fn local_pubkey(&self) -> [u8; 32] {
        *self.endpoint.id().as_bytes()
    }

    pub const fn local_device_id(&self) -> u64 {
        self.local_device_id
    }

    pub fn effective_relay_policy(&self) -> RelayPolicy {
        self.shared.relay_policy
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Awaits `iroh::Endpoint::online()` bounded by `timeout`.
    /// No-op under `RelayPolicy::NoRelays` (or when no relay is configured).
    pub async fn wait_online(&self, timeout: Duration) {
        if self.shared.relay_policy == RelayPolicy::NoRelays
            || self.shared.pinned_relay_url.is_none()
        {
            return;
        }
        let _ = tokio::time::timeout(timeout, self.endpoint.online()).await;
    }

    /// Returns a watcher yielding updates whenever the local `EndpointAddr` changes (roaming).
    pub fn watch_addr(&self) -> impl Watcher<Value = EndpointAddr> + use<> {
        self.endpoint.watch_addr()
    }

    pub fn is_peer_connected(&self, pubkey: &[u8; 32]) -> bool {
        let Ok(peer_id) = PublicKey::from_bytes(pubkey) else {
            return false;
        };
        let peers = self
            .shared
            .peers
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        peers
            .get(&peer_id)
            .is_some_and(|active| active.conn.close_reason().is_none())
    }

    /// Returns the endpoint's bound and discovered local direct UDP socket addresses.
    ///
    /// Always returns an empty vector under [`RelayPolicy::ForceRelays`].
    pub fn local_direct_addrs(&self) -> Vec<SocketAddr> {
        if self.shared.relay_policy == RelayPolicy::ForceRelays {
            return Vec::new();
        }

        let mut collected: Vec<SocketAddr> = Vec::new();
        let mut seen: HashSet<SocketAddr> = HashSet::new();

        for bound in self.endpoint.bound_sockets() {
            let candidate = match bound {
                SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v4.port())
                }
                SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), v6.port())
                }
                other => other,
            };
            if candidate.port() != 0 && seen.insert(candidate) {
                collected.push(candidate);
            }
        }

        for addr in self.endpoint.addr().ip_addrs() {
            if addr.port() != 0 && seen.insert(*addr) {
                collected.push(*addr);
            }
        }

        collected
    }

    /// Returns the remote socket address of a currently connected peer (pending or allowed),
    /// for per-`(joiner_pubkey, source_ip)` LAN PIN rate limiting.
    pub async fn peer_remote_addr(&self, peer_pubkey: [u8; 32]) -> Option<SocketAddr> {
        let peer_id = PublicKey::from_bytes(&peer_pubkey).ok()?;
        let peers = self
            .shared
            .peers
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let active = peers.get(&peer_id)?;
        if active.conn.close_reason().is_some() {
            return None;
        }
        extract_conn_remote_ip(&active.conn).or(active.remote_addr)
    }

    pub fn local_endpoint_descriptor(&self) -> EndpointDescriptor {
        if self.shared.relay_policy == RelayPolicy::ForceRelays {
            return EndpointDescriptor {
                transport_kind: TransportKind::IrohQuic,
                relay_url: self
                    .shared
                    .pinned_relay_url_str
                    .clone()
                    .unwrap_or_default(),
                direct_addrs: Vec::new(),
            };
        }

        let mut collected: Vec<DirectAddr> = self
            .local_direct_addrs()
            .into_iter()
            .map(socket_addr_to_direct_addr)
            .collect();
        collected.truncate(MAX_DIRECT_ADDRS);

        let relay_url = match self.shared.relay_policy {
            RelayPolicy::NoRelays => String::new(),
            RelayPolicy::AllowRelays | RelayPolicy::ForceRelays => self
                .shared
                .pinned_relay_url_str
                .clone()
                .unwrap_or_default(),
        };

        EndpointDescriptor {
            transport_kind: TransportKind::IrohQuic,
            relay_url,
            direct_addrs: collected,
        }
    }

    /// Replaces the peer allowlist, disconnecting removed peers with `CLOSE_PEER_REVOKED (4403)`.
    pub fn set_allowed_peers(&self, pubkeys: HashSet<[u8; 32]>) {
        self.set_allowed_peers_with_close_code(pubkeys, CLOSE_PEER_REVOKED);
    }

    /// Replaces the peer allowlist, disconnecting removed peers with the supplied QUIC
    /// application close code (e.g. `CLOSE_UNAUTHORIZED (4401)` for temporary lease/churn
    /// suspension or `CLOSE_PEER_REVOKED (4403)` for explicit revocation).
    pub fn set_allowed_peers_with_close_code(
        &self,
        pubkeys: HashSet<[u8; 32]>,
        close_code: u32,
    ) {
        if self.shared.closed.load(Ordering::Acquire) {
            return;
        }
        let mut next_allowed = HashSet::with_capacity(pubkeys.len());
        for raw in pubkeys {
            if let Ok(pk) = PublicKey::from_bytes(&raw) {
                next_allowed.insert(pk);
            }
        }
        {
            let mut guard = self
                .shared
                .allowed_peers
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            *guard = next_allowed.clone();
        }
        let to_revoke: Vec<EndpointId> = {
            let peers = self
                .shared
                .peers
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            let mut revoke = Vec::new();
            for (id, peer) in peers.iter() {
                if next_allowed.contains(id) {
                    peer.is_pending.store(false, Ordering::Release);
                } else {
                    revoke.push(*id);
                }
            }
            revoke
        };
        for peer_id in to_revoke {
            self.shared.close_and_remove_peer(
                &peer_id,
                None,
                close_code,
                b"peer_removed_from_allowlist",
                true,
            );
        }
    }

    /// Additively adds `peer_pubkey` to `allowed_peers` AND promotes any currently connected
    /// pending LAN peer (`is_pending = false`), unlocking Lane 1 (`Causal`) and Lane 2
    /// (`Ephemeral`) immediately on the live QUIC connection without dropping it.
    pub async fn allow_peer(&self, peer_pubkey: [u8; 32]) -> Result<(), P2pError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(P2pError::Closed);
        }
        let peer_id =
            PublicKey::from_bytes(&peer_pubkey).map_err(|_| P2pError::InvalidPeerPubkey)?;

        {
            let mut guard = self
                .shared
                .allowed_peers
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            if !guard.contains(&peer_id) {
                if guard.len() >= MAX_ALLOWED_PEERS {
                    return Err(P2pError::Capacity);
                }
                guard.insert(peer_id);
            }
        }

        // Promote any currently connected pending peer immediately on the live connection.
        {
            let peers = self
                .shared
                .peers
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(peer) = peers.get(&peer_id) {
                peer.is_pending.store(false, Ordering::Release);
            }
        }
        Ok(())
    }

    /// Toggles opt-in open LAN admission (explicit LAN `NoRelays` mode only).
    ///
    /// Fail-closed no-op when not in explicit LAN mode or `effective_relay_policy != RelayPolicy::NoRelays`.
    /// Setting `open = false` immediately stops admitting new unknown LAN peers and closes
    /// all still-pending un-allowlisted peers (`CLOSE_UNAUTHORIZED`), while preserving
    /// already-allowlisted / promoted peers.
    pub async fn set_lan_open_admission(&self, open: bool) {
        if self.shared.closed.load(Ordering::Acquire) {
            return;
        }
        if !self.shared.lan_mode || self.shared.relay_policy != RelayPolicy::NoRelays {
            return;
        }

        self.shared
            .lan_open_admission
            .store(open, Ordering::Release);

        if !open {
            let drained_pending: Vec<(EndpointId, ActivePeer)> = {
                let mut peers = self
                    .shared
                    .peers
                    .write()
                    .unwrap_or_else(PoisonError::into_inner);
                let pending_ids: Vec<EndpointId> = peers
                    .iter()
                    .filter(|(id, p)| {
                        p.is_pending.load(Ordering::Acquire) && !self.shared.is_allowed(id)
                    })
                    .map(|(id, _)| *id)
                    .collect();
                let mut removed = Vec::with_capacity(pending_ids.len());
                for id in pending_ids {
                    if let Some(peer) = peers.remove(&id) {
                        removed.push((id, peer));
                    }
                }
                removed
            };
            for (peer_id, mut peer) in drained_pending {
                peer.conn
                    .close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"lan_admission_closed");
                peer.shutdown();
                let _ = self
                    .shared
                    .lifecycle_tx
                    .try_send(P2pTransportEvent::PeerDisconnected {
                        peer_pubkey: *peer_id.as_bytes(),
                        reason_code: CLOSE_UNAUTHORIZED,
                    });
            }
        }
    }

    /// Returns whether opt-in LAN open admission is currently active.
    pub fn is_lan_open_admission(&self) -> bool {
        self.shared.is_lan_open_admission()
    }

    pub fn revoke_peer(&self, pubkey: [u8; 32], close_code: u32) {
        if self.shared.closed.load(Ordering::Acquire) {
            return;
        }
        let Ok(peer_id) = PublicKey::from_bytes(&pubkey) else {
            return;
        };
        {
            let mut guard = self
                .shared
                .allowed_peers
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            guard.remove(&peer_id);
        }
        self.shared
            .close_and_remove_peer(&peer_id, None, close_code, b"peer_revoked", true);
    }

    pub async fn connect_peer(&self, target: PeerDialTarget) -> Result<(), P2pError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(P2pError::Closed);
        }

        let peer_id =
            PublicKey::from_bytes(&target.device_pubkey).map_err(|_| P2pError::InvalidPeerPubkey)?;
        if peer_id == self.endpoint.id() {
            return Err(P2pError::SelfConnect);
        }

        // Check symmetric compatibility + prevent dialing a ForceRelays peer from an AllowRelays endpoint.
        let _ = effective_relay_policy(self.shared.relay_policy, target.remote_relay_policy)
            .map_err(|e| P2pError::PolicyViolation(e.to_string()))?;
        if self.shared.relay_policy == RelayPolicy::AllowRelays
            && target.remote_relay_policy == RelayPolicy::ForceRelays
        {
            return Err(P2pError::PolicyViolation(
                "allow_relays endpoint cannot dial force_relays peer without upgrading".into(),
            ));
        }

        if target.endpoint.direct_addrs.len() > MAX_DIRECT_ADDRS {
            return Err(P2pError::InvalidConfig("too many direct addresses".into()));
        }

        let mut transport_addrs: Vec<TransportAddr> = Vec::new();
        let raw_relay_url = if target.endpoint.relay_url.is_empty() {
            None
        } else {
            Some(target.endpoint.relay_url.as_str())
        };

        match self.shared.relay_policy {
            RelayPolicy::ForceRelays => {
                if !target.endpoint.direct_addrs.is_empty() {
                    return Err(P2pError::PolicyViolation(
                        "force_relays forbids direct IP addresses".into(),
                    ));
                }
                let Some(pinned) = self.shared.pinned_relay_url.as_ref() else {
                    return Err(P2pError::PolicyViolation(
                        "force_relays missing pinned relay URL".into(),
                    ));
                };
                if let Some(raw) = raw_relay_url {
                    let (parsed, _) = validate_relay_url(raw)?;
                    if &parsed != pinned {
                        return Err(P2pError::PolicyViolation(
                            "target relay URL does not match pinned relay URL".into(),
                        ));
                    }
                }
                transport_addrs.push(TransportAddr::Relay(pinned.clone()));
            }
            RelayPolicy::NoRelays => {
                if raw_relay_url.is_some() {
                    return Err(P2pError::PolicyViolation(
                        "no_relays forbids relay URLs".into(),
                    ));
                }
                if target.endpoint.direct_addrs.is_empty() {
                    return Err(P2pError::InvalidConfig(
                        "no_relays requires at least one direct address".into(),
                    ));
                }
                for direct in &target.endpoint.direct_addrs {
                    transport_addrs.push(TransportAddr::Ip(direct_addr_to_socket_addr(direct)?));
                }
            }
            RelayPolicy::AllowRelays => {
                if target.remote_relay_policy == RelayPolicy::NoRelays && raw_relay_url.is_some() {
                    return Err(P2pError::PolicyViolation(
                        "remote peer forbids relays".into(),
                    ));
                }
                if let Some(raw) = raw_relay_url {
                    let (parsed, _) = validate_relay_url(raw)?;
                    transport_addrs.push(TransportAddr::Relay(parsed));
                }
                for direct in &target.endpoint.direct_addrs {
                    transport_addrs.push(TransportAddr::Ip(direct_addr_to_socket_addr(direct)?));
                }
                if transport_addrs.is_empty() {
                    return Err(P2pError::InvalidConfig(
                        "peer target has no usable transport addresses".into(),
                    ));
                }
            }
        }

        if !self.shared.is_allowed(&peer_id) {
            return Err(P2pError::PeerNotAllowed);
        }

        self.dial_validated(peer_id, target.device_pubkey, transport_addrs)
            .await
    }

    /// Dials an explicitly allowlisted peer directly by Ed25519 `peer_pubkey` and direct
    /// UDP `SocketAddr`s with zero relay URLs.
    pub async fn connect_direct(
        &self,
        peer_pubkey: [u8; 32],
        addrs: &[SocketAddr],
    ) -> Result<(), P2pError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(P2pError::Closed);
        }
        if self.shared.relay_policy == RelayPolicy::ForceRelays {
            return Err(P2pError::PolicyViolation(
                "force_relays forbids direct IP connections".into(),
            ));
        }

        let peer_id =
            PublicKey::from_bytes(&peer_pubkey).map_err(|_| P2pError::InvalidPeerPubkey)?;
        if peer_id == self.endpoint.id() {
            return Err(P2pError::SelfConnect);
        }
        if addrs.is_empty() {
            return Err(P2pError::InvalidConfig(
                "connect_direct requires at least one direct address".into(),
            ));
        }
        if addrs.len() > MAX_DIRECT_ADDRS {
            return Err(P2pError::InvalidConfig("too many direct addresses".into()));
        }

        let mut transport_addrs = Vec::with_capacity(addrs.len());
        for &addr in addrs {
            transport_addrs.push(TransportAddr::Ip(validate_direct_socket_addr(addr)?));
        }

        if !self.shared.is_allowed(&peer_id) {
            return Err(P2pError::PeerNotAllowed);
        }

        self.dial_validated(peer_id, peer_pubkey, transport_addrs)
            .await
    }

    async fn dial_validated(
        &self,
        peer_id: EndpointId,
        peer_pubkey: [u8; 32],
        transport_addrs: Vec<TransportAddr>,
    ) -> Result<(), P2pError> {
        let initial_remote_addr = transport_addrs.iter().find_map(|addr| match addr {
            TransportAddr::Ip(sock) => Some(*sock),
            _ => None,
        });
        let endpoint_addr = EndpointAddr::from_parts(peer_id, transport_addrs);
        let conn = tokio::time::timeout(
            DEFAULT_CONNECT_TIMEOUT,
            self.endpoint.connect(endpoint_addr, ALPN),
        )
        .await
        .map_err(|_| P2pError::Timeout)?
        .map_err(|e| map_endpoint_connect_error(&e))?;

        // Open Stream 0 (Control, prio 10) and Stream 4 (Causal, prio 0) in deterministic order.
        let setup = tokio::time::timeout(STREAM_SETUP_TIMEOUT, async {
            let (mut control_send, mut control_recv) = conn
                .open_bi()
                .await
                .map_err(|e| map_connect_error(&e))?;
            if u64::from(control_send.id()) != STREAM_ID_CONTROL {
                return Err(P2pError::Transport("unexpected control stream id".into()));
            }
            let _ = control_send.set_priority(LANE_CONTROL_PRIORITY);
            control_send
                .write_all(&STREAM_INIT_MARKER.to_le_bytes())
                .await
                .map_err(|_| match conn.close_reason() {
                    Some(reason) => map_connect_error(&reason),
                    None => P2pError::Transport("failed writing control init marker".into()),
                })?;

            let (mut causal_send, causal_recv) = conn
                .open_bi()
                .await
                .map_err(|e| map_connect_error(&e))?;
            if u64::from(causal_send.id()) != STREAM_ID_CAUSAL {
                return Err(P2pError::Transport("unexpected causal stream id".into()));
            }
            let _ = causal_send.set_priority(LANE_CAUSAL_PRIORITY);
            causal_send
                .write_all(&STREAM_INIT_MARKER.to_le_bytes())
                .await
                .map_err(|_| match conn.close_reason() {
                    Some(reason) => map_connect_error(&reason),
                    None => P2pError::Transport("failed writing causal init marker".into()),
                })?;

            // Await acceptor's 4-byte readiness ACK on Stream 0 so unauthorized
            // rejections fail closed immediately.
            let mut ack = [0u8; 4];
            control_recv
                .read_exact(&mut ack)
                .await
                .map_err(|_| match conn.close_reason() {
                    Some(reason) => map_connect_error(&reason),
                    None => P2pError::Transport("failed reading control readiness ack".into()),
                })?;
            if u32::from_le_bytes(ack) != STREAM_INIT_MARKER {
                return Err(P2pError::Transport("invalid control readiness ack".into()));
            }

            Ok((control_send, control_recv, causal_send, causal_recv))
        })
        .await;

        let (control_send, control_recv, causal_send, causal_recv) = match setup {
            Ok(Ok(streams)) => streams,
            Ok(Err(err)) => {
                // If the remote closed our losing glare dial with 4409 SUPERSEDED and we
                // already hold a live connection to `peer_id`, treat connect as succeeded.
                if is_superseded_close(&conn.close_reason())
                    && self.is_peer_connected(&peer_pubkey)
                {
                    return Ok(());
                }
                if conn.close_reason().is_none() {
                    conn.close(
                        VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                        b"connect_setup_failed",
                    );
                }
                return Err(err);
            }
            Err(_) => {
                if conn.close_reason().is_none() {
                    conn.close(
                        VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                        b"connect_setup_timeout",
                    );
                }
                return Err(P2pError::Timeout);
            }
        };

        register_active_peer(
            &self.shared,
            peer_id,
            true,
            conn,
            control_send,
            control_recv,
            causal_send,
            causal_recv,
            false,
            None,
            initial_remote_addr,
        )
    }

    pub async fn send_frame(
        &self,
        peer_pubkey: [u8; 32],
        frame: &P2pPartyFrame,
    ) -> Result<(), P2pError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(P2pError::Closed);
        }
        let peer_id =
            PublicKey::from_bytes(&peer_pubkey).map_err(|_| P2pError::InvalidPeerPubkey)?;
        let allowed = self.shared.is_allowed(&peer_id);

        let lane = frame.lane();

        enum SendHandle {
            Stream(mpsc::Sender<BudgetedFrame>, Arc<Semaphore>),
            Datagram(Connection),
        }

        let handle = {
            let peers = self
                .shared
                .peers
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(active) = peers.get(&peer_id) else {
                return Err(if allowed {
                    P2pError::PeerNotConnected
                } else {
                    P2pError::PeerNotAllowed
                });
            };
            if !allowed {
                let can_send_pending_control = lane == P2pLane::Control
                    && active.is_pending.load(Ordering::Acquire)
                    && self.shared.is_lan_open_admission();
                if !can_send_pending_control {
                    return Err(P2pError::PeerNotAllowed);
                }
            }
            if active.conn.close_reason().is_some() {
                return Err(P2pError::PeerNotConnected);
            }
            match lane {
                P2pLane::Control => {
                    SendHandle::Stream(active.control_tx.clone(), Arc::clone(&active.control_budget))
                }
                P2pLane::Causal => {
                    SendHandle::Stream(active.causal_tx.clone(), Arc::clone(&active.causal_budget))
                }
                P2pLane::Ephemeral => SendHandle::Datagram(active.conn.clone()),
            }
        };

        let encoded = encode_p2p_party_frame(frame).map_err(|e| match e {
            P2pWireError::FrameOversized | P2pWireError::FieldTooLarge => P2pError::FrameTooLarge,
            other => P2pError::WireError(other),
        })?;
        if encoded.len() > lane.max_frame_bytes() {
            return Err(P2pError::FrameTooLarge);
        }

        let payload = Bytes::from(encoded);
        match handle {
            SendHandle::Stream(tx, budget) => {
                let units = byte_budget_units(payload.len());
                let send_fut = async {
                    let permit = budget
                        .acquire_many_owned(units)
                        .await
                        .map_err(|_| P2pError::PeerNotConnected)?;
                    tx.send(BudgetedFrame {
                        payload,
                        _permit: permit,
                    })
                    .await
                    .map_err(|_| P2pError::PeerNotConnected)
                };
                match tokio::time::timeout(SEND_QUEUE_TIMEOUT, send_fut).await {
                    Ok(res) => res,
                    Err(_) => Err(P2pError::Timeout),
                }
            }
            SendHandle::Datagram(conn) => conn.send_datagram(payload).map_err(|e| match e {
                SendDatagramError::TooLarge => P2pError::FrameTooLarge,
                SendDatagramError::ConnectionLost(_) => P2pError::PeerNotConnected,
                other => P2pError::Transport(other.to_string()),
            }),
        }
    }

    /// Sends a `mp1-lan/1` Lane 0 (`Control`) handshake frame (`0x10..=0x13`) to a
    /// pending or allowlisted peer in strict `RelayPolicy::NoRelays` LAN mode.
    pub async fn send_lan_handshake(
        &self,
        peer_pubkey: [u8; 32],
        message: &LanHandshakeMessage,
    ) -> Result<(), P2pError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(P2pError::Closed);
        }
        if !self.shared.lan_mode || self.shared.relay_policy != RelayPolicy::NoRelays {
            return Err(P2pError::PolicyViolation(
                "LAN handshake frames are only permitted in explicit LAN no_relays mode".into(),
            ));
        }
        let peer_id =
            PublicKey::from_bytes(&peer_pubkey).map_err(|_| P2pError::InvalidPeerPubkey)?;
        let allowed = self.shared.is_allowed(&peer_id);

        let (tx, budget) = {
            let peers = self
                .shared
                .peers
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(active) = peers.get(&peer_id) else {
                return Err(if allowed {
                    P2pError::PeerNotConnected
                } else {
                    P2pError::PeerNotAllowed
                });
            };
            if !allowed {
                let can_send_pending_control = active.is_pending.load(Ordering::Acquire)
                    && self.shared.is_lan_open_admission();
                if !can_send_pending_control {
                    return Err(P2pError::PeerNotAllowed);
                }
            }
            if active.conn.close_reason().is_some() {
                return Err(P2pError::PeerNotConnected);
            }
            (active.control_tx.clone(), Arc::clone(&active.control_budget))
        };

        let encoded = encode_lan_handshake_frame(message).map_err(|e| match e {
            LanProtocolError::FrameTooLarge => P2pError::FrameTooLarge,
            other => P2pError::Transport(format!("invalid LAN handshake frame: {other}")),
        })?;
        if encoded.len() > P2pLane::Control.max_frame_bytes() {
            return Err(P2pError::FrameTooLarge);
        }

        let payload = Bytes::from(encoded);
        let units = byte_budget_units(payload.len());
        let send_fut = async {
            let permit = budget
                .acquire_many_owned(units)
                .await
                .map_err(|_| P2pError::PeerNotConnected)?;
            tx.send(BudgetedFrame {
                payload,
                _permit: permit,
            })
            .await
            .map_err(|_| P2pError::PeerNotConnected)
        };
        match tokio::time::timeout(SEND_QUEUE_TIMEOUT, send_fut).await {
            Ok(res) => res,
            Err(_) => Err(P2pError::Timeout),
        }
    }

    pub async fn close(&self) {
        self.shutdown_peers_and_tasks();
        let _ = tokio::time::timeout(CLOSE_ENDPOINT_TIMEOUT, self.endpoint.close()).await;
    }

    fn shutdown_peers_and_tasks(&self) {
        if self.shared.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shared.control_budget.close();
        self.shared.causal_budget.close();
        self.shared.ephemeral_budget.close();
        self.shared.closed_notify.notify_waiters();

        let drained: Vec<ActivePeer> = {
            let mut peers = self
                .shared
                .peers
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            peers.drain().map(|(_, p)| p).collect()
        };
        for mut peer in drained {
            peer.conn
                .close(VarInt::from_u32(CLOSE_SHUTDOWN), b"endpoint_shutdown");
            peer.shutdown();
        }
        let task = {
            let mut guard = self
                .accept_task
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            guard.take()
        };
        if let Some(task) = task {
            task.abort();
        }
    }
}

impl Drop for PartyP2pHandle {
    fn drop(&mut self) {
        self.shutdown_peers_and_tasks();
    }
}

/// Dedicated inbound event receiver stream returned by [`PartyP2pTransport::split`].
pub struct P2pEventStream {
    closed: Arc<AtomicBool>,
    closed_notify: Arc<Notify>,
    lifecycle_rx: mpsc::Receiver<P2pTransportEvent>,
    control_rx: mpsc::Receiver<BudgetedEvent>,
    causal_rx: mpsc::Receiver<BudgetedEvent>,
    ephemeral_rx: mpsc::Receiver<BudgetedEvent>,
}

impl P2pEventStream {
    fn try_recv_prioritized(&mut self) -> Option<P2pTransportEvent> {
        if let Ok(ev) = self.lifecycle_rx.try_recv() {
            return Some(ev);
        }
        if let Ok(ev) = self.control_rx.try_recv() {
            return Some(ev.event);
        }
        if let Ok(ev) = self.causal_rx.try_recv() {
            return Some(ev.event);
        }
        if let Ok(ev) = self.ephemeral_rx.try_recv() {
            return Some(ev.event);
        }
        None
    }

    /// Receives the next transport event using a biased select that strictly prioritizes
    /// Lifecycle and Control (Lane 0) events ahead of Causal (Lane 1) and Ephemeral (Lane 2).
    pub async fn recv_event(&mut self) -> Option<P2pTransportEvent> {
        let mut lifecycle_open = true;
        let mut control_open = true;
        let mut causal_open = true;
        let mut ephemeral_open = true;

        loop {
            if let Some(ev) = self.try_recv_prioritized() {
                return Some(ev);
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            if !lifecycle_open && !control_open && !causal_open && !ephemeral_open {
                return None;
            }

            let closed_notify = Arc::clone(&self.closed_notify);
            let notified = closed_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // Re-check closed flag after registering notification to avoid lost wakeups.
            if self.closed.load(Ordering::Acquire) {
                return self.try_recv_prioritized();
            }

            tokio::select! {
                biased;
                ev = self.lifecycle_rx.recv(), if lifecycle_open => {
                    match ev {
                        Some(event) => return Some(event),
                        None => lifecycle_open = false,
                    }
                }
                ev = self.control_rx.recv(), if control_open => {
                    match ev {
                        Some(budgeted) => return Some(budgeted.event),
                        None => control_open = false,
                    }
                }
                ev = self.causal_rx.recv(), if causal_open => {
                    match ev {
                        Some(budgeted) => return Some(budgeted.event),
                        None => causal_open = false,
                    }
                }
                ev = self.ephemeral_rx.recv(), if ephemeral_open => {
                    match ev {
                        Some(budgeted) => return Some(budgeted.event),
                        None => ephemeral_open = false,
                    }
                }
                () = &mut notified => {
                    // Loop back to drain any buffered events before returning None.
                }
            }
        }
    }
}

pub struct PartyP2pTransport {
    local_device_id: u64,
    handle: Arc<PartyP2pHandle>,
    events: P2pEventStream,
}

impl PartyP2pTransport {
    pub async fn spawn(config: PartyP2pConfig) -> Result<Self, P2pError> {
        Self::spawn_with_lan(config, None).await
    }

    /// Spawns a per-party P2P transport with optional explicit LAN (`NoRelays`) configuration.
    ///
    /// Fails closed with [`P2pError::InvalidConfig`] before opening any socket if:
    /// - `lan.lan_open_admission == true` without `lan.no_relays == true`
    /// - `lan.no_relays == true` with `effective_relay_policy != RelayPolicy::NoRelays`
    ///   (including `ForceRelays` or `AllowRelays`)
    /// - `lan.lan_bind_port.is_some()` without `lan.no_relays == true`
    /// - `lan.no_relays == true` with a non-empty `pinned_relay_url`
    pub async fn spawn_with_lan(
        config: PartyP2pConfig,
        lan: Option<LanTransportConfig>,
    ) -> Result<Self, P2pError> {
        let raw_relay = config
            .pinned_relay_url
            .as_deref()
            .filter(|s| !s.is_empty());

        let (lan_mode, initial_lan_open_admission, lan_bind_port) = if let Some(lan_cfg) = lan {
            if lan_cfg.lan_open_admission && !lan_cfg.no_relays {
                return Err(P2pError::InvalidConfig(
                    "lan_open_admission requires no_relays == true".into(),
                ));
            }
            if lan_cfg.lan_bind_port.is_some() && !lan_cfg.no_relays {
                return Err(P2pError::InvalidConfig(
                    "lan_bind_port requires no_relays == true".into(),
                ));
            }
            if lan_cfg.no_relays {
                if config.effective_relay_policy != RelayPolicy::NoRelays {
                    return Err(P2pError::InvalidConfig(
                        "no_relays LAN transport requires RelayPolicy::NoRelays".into(),
                    ));
                }
                if raw_relay.is_some() {
                    return Err(P2pError::InvalidConfig(
                        "no_relays LAN transport forbids pinned_relay_url".into(),
                    ));
                }
            }
            (
                lan_cfg.no_relays,
                lan_cfg.lan_open_admission,
                lan_cfg.lan_bind_port,
            )
        } else {
            (false, false, None)
        };

        let parsed_relay = match (config.effective_relay_policy, raw_relay) {
            (RelayPolicy::ForceRelays, None) => {
                return Err(P2pError::PolicyViolation(
                    "force_relays requires a valid https:// pinned_relay_url".into(),
                ));
            }
            (RelayPolicy::ForceRelays, Some(raw)) => Some(validate_relay_url(raw)?),
            (RelayPolicy::AllowRelays, Some(raw)) => Some(validate_relay_url(raw)?),
            (RelayPolicy::AllowRelays, None) => None,
            (RelayPolicy::NoRelays, Some(_)) => {
                return Err(P2pError::PolicyViolation(
                    "no_relays forbids pinned_relay_url".into(),
                ));
            }
            (RelayPolicy::NoRelays, None) => None,
        };

        let (pinned_relay_url, pinned_relay_url_str) = match parsed_relay {
            Some((url, canonical)) => (Some(url), Some(canonical)),
            None => (None, None),
        };

        let secret_key = SecretKey::from_bytes(&config.device_secret);
        let local_id = secret_key.public();

        let (lifecycle_tx, lifecycle_rx) = mpsc::channel(LIFECYCLE_EVENT_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_EVENT_CAPACITY);
        let (causal_tx, causal_rx) = mpsc::channel(CAUSAL_EVENT_CAPACITY);
        let (ephemeral_tx, ephemeral_rx) = mpsc::channel(EPHEMERAL_EVENT_CAPACITY);

        let closed = Arc::new(AtomicBool::new(false));
        let closed_notify = Arc::new(Notify::new());

        let shared = Arc::new(SharedState {
            local_id,
            relay_policy: config.effective_relay_policy,
            pinned_relay_url: pinned_relay_url.clone(),
            pinned_relay_url_str,
            lan_mode,
            lan_open_admission: AtomicBool::new(initial_lan_open_admission),
            in_flight_pending_lan: Mutex::new(HashSet::new()),
            allowed_peers: RwLock::new(HashSet::new()),
            peers: RwLock::new(HashMap::new()),
            next_conn_id: AtomicU64::new(0),
            closed: Arc::clone(&closed),
            closed_notify: Arc::clone(&closed_notify),
            lifecycle_tx,
            control_tx,
            control_budget: Arc::new(Semaphore::new(INBOUND_CONTROL_BYTE_BUDGET)),
            causal_tx,
            causal_budget: Arc::new(Semaphore::new(INBOUND_CAUSAL_BYTE_BUDGET)),
            ephemeral_tx,
            ephemeral_budget: Arc::new(Semaphore::new(INBOUND_EPHEMERAL_BYTE_BUDGET)),
        });

        let hooks = AllowlistHooks {
            shared: Arc::clone(&shared),
        };

        let mut transport_cfg = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(2))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .datagram_receive_buffer_size(Some(65_536))
            .datagram_send_buffer_size(65_536)
            .allow_spin(false)
            .keep_alive_interval(Duration::from_secs(5));
        if let Ok(idle) = Duration::from_secs(30).try_into() {
            transport_cfg = transport_cfg.max_idle_timeout(Some(idle));
        }

        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .max_tls_tickets(0)
            .transport_config(transport_cfg.build())
            .hooks(hooks);

        builder = match config.effective_relay_policy {
            RelayPolicy::ForceRelays => {
                let Some(url) = pinned_relay_url else {
                    return Err(P2pError::PolicyViolation(
                        "force_relays requires pinned_relay_url".into(),
                    ));
                };
                builder
                    .clear_ip_transports()
                    .addr_filter(AddrFilter::relay_only())
                    .relay_mode(RelayMode::Custom(RelayMap::from(url)))
            }
            RelayPolicy::NoRelays => {
                let mut no_relay_builder = builder.relay_mode(RelayMode::Disabled);
                if let Some(port) = lan_bind_port {
                    let v4_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
                    let v6_bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
                    no_relay_builder = no_relay_builder
                        .clear_ip_transports()
                        .bind_addr(v4_bind)
                        .map_err(|e| {
                            P2pError::InvalidConfig(format!("invalid IPv4 lan_bind_port: {e}"))
                        })?
                        .bind_addr_with_opts(v6_bind, BindOpts::default().set_is_required(false))
                        .map_err(|e| {
                            P2pError::InvalidConfig(format!("invalid IPv6 lan_bind_port: {e}"))
                        })?;
                }
                no_relay_builder
            }
            RelayPolicy::AllowRelays => {
                if let Some(url) = pinned_relay_url {
                    builder.relay_mode(RelayMode::Custom(RelayMap::from(url)))
                } else {
                    builder.relay_mode(RelayMode::Disabled)
                }
            }
        };

        let endpoint = builder
            .bind()
            .await
            .map_err(|e| P2pError::Transport(e.to_string()))?;

        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), Arc::clone(&shared)));

        let handle = Arc::new(PartyP2pHandle {
            local_device_id: config.local_device_id,
            endpoint,
            shared,
            accept_task: Mutex::new(Some(accept_task)),
        });

        let events = P2pEventStream {
            closed,
            closed_notify,
            lifecycle_rx,
            control_rx,
            causal_rx,
            ephemeral_rx,
        };

        Ok(Self {
            local_device_id: config.local_device_id,
            handle,
            events,
        })
    }

    /// Splits this transport into a concurrently shareable [`Arc<PartyP2pHandle>`] and a
    /// dedicated [`P2pEventStream`].
    pub fn split(self) -> (Arc<PartyP2pHandle>, P2pEventStream) {
        (self.handle, self.events)
    }

    /// Returns a cloned [`Arc<PartyP2pHandle>`] for concurrent control/send operations.
    pub fn handle(&self) -> Arc<PartyP2pHandle> {
        Arc::clone(&self.handle)
    }

    pub fn local_pubkey(&self) -> [u8; 32] {
        self.handle.local_pubkey()
    }

    pub const fn local_device_id(&self) -> u64 {
        self.local_device_id
    }

    pub fn effective_relay_policy(&self) -> RelayPolicy {
        self.handle.effective_relay_policy()
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.handle.endpoint()
    }

    pub async fn wait_online(&self, timeout: Duration) {
        self.handle.wait_online(timeout).await;
    }

    pub fn watch_addr(&self) -> impl Watcher<Value = EndpointAddr> + use<> {
        self.handle.watch_addr()
    }

    pub fn is_peer_connected(&self, pubkey: &[u8; 32]) -> bool {
        self.handle.is_peer_connected(pubkey)
    }

    pub fn local_direct_addrs(&self) -> Vec<SocketAddr> {
        self.handle.local_direct_addrs()
    }

    pub async fn peer_remote_addr(&self, peer_pubkey: [u8; 32]) -> Option<SocketAddr> {
        self.handle.peer_remote_addr(peer_pubkey).await
    }

    pub fn local_endpoint_descriptor(&self) -> EndpointDescriptor {
        self.handle.local_endpoint_descriptor()
    }

    pub fn set_allowed_peers(&self, pubkeys: HashSet<[u8; 32]>) {
        self.handle.set_allowed_peers(pubkeys);
    }

    pub fn set_allowed_peers_with_close_code(
        &self,
        pubkeys: HashSet<[u8; 32]>,
        close_code: u32,
    ) {
        self.handle
            .set_allowed_peers_with_close_code(pubkeys, close_code);
    }

    pub async fn allow_peer(&self, peer_pubkey: [u8; 32]) -> Result<(), P2pError> {
        self.handle.allow_peer(peer_pubkey).await
    }

    pub async fn set_lan_open_admission(&self, open: bool) {
        self.handle.set_lan_open_admission(open).await;
    }

    pub fn is_lan_open_admission(&self) -> bool {
        self.handle.is_lan_open_admission()
    }

    pub fn revoke_peer(&self, pubkey: [u8; 32], close_code: u32) {
        self.handle.revoke_peer(pubkey, close_code);
    }

    pub async fn connect_peer(&self, target: PeerDialTarget) -> Result<(), P2pError> {
        self.handle.connect_peer(target).await
    }

    pub async fn connect_direct(
        &self,
        peer_pubkey: [u8; 32],
        addrs: &[SocketAddr],
    ) -> Result<(), P2pError> {
        self.handle.connect_direct(peer_pubkey, addrs).await
    }

    pub async fn send_frame(
        &self,
        peer_pubkey: [u8; 32],
        frame: &P2pPartyFrame,
    ) -> Result<(), P2pError> {
        self.handle.send_frame(peer_pubkey, frame).await
    }

    pub async fn send_lan_handshake(
        &self,
        peer_pubkey: [u8; 32],
        message: &LanHandshakeMessage,
    ) -> Result<(), P2pError> {
        self.handle.send_lan_handshake(peer_pubkey, message).await
    }

    /// Receives the next transport event using a biased select that strictly prioritizes
    /// Lifecycle and Control (Lane 0) events ahead of Causal (Lane 1) and Ephemeral (Lane 2).
    pub async fn recv_event(&mut self) -> Option<P2pTransportEvent> {
        self.events.recv_event().await
    }

    pub async fn close(self) {
        self.handle.close().await;
    }
}

fn byte_budget_units(byte_len: usize) -> u32 {
    u32::try_from(byte_len.max(1)).unwrap_or(u32::MAX)
}

fn is_superseded_close(reason: &Option<ConnectionError>) -> bool {
    matches!(
        reason,
        Some(ConnectionError::ApplicationClosed(app))
            if app.error_code.into_inner() == u64::from(CLOSE_SUPERSEDED)
    )
}

fn validate_relay_url(raw: &str) -> Result<(RelayUrl, String), P2pError> {
    if raw.is_empty() || raw.len() > MAX_RELAY_URL_BYTES {
        return Err(P2pError::InvalidRelayUrl(
            "relay URL must be 1..=100 bytes".into(),
        ));
    }
    if raw.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return Err(P2pError::InvalidRelayUrl(
            "relay URL contains control or non-ASCII bytes".into(),
        ));
    }
    let parsed =
        Url::parse(raw).map_err(|_| P2pError::InvalidRelayUrl("invalid URL syntax".into()))?;
    if parsed.scheme() != "https" {
        return Err(P2pError::InvalidRelayUrl(
            "relay URL must use https:// scheme".into(),
        ));
    }
    if !parsed.has_host() {
        return Err(P2pError::InvalidRelayUrl("relay URL missing host".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(P2pError::InvalidRelayUrl(
            "relay URL must not contain credentials".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(P2pError::InvalidRelayUrl(
            "relay URL must not contain query or fragment".into(),
        ));
    }
    if !parsed.path().is_empty() && parsed.path() != "/" {
        return Err(P2pError::InvalidRelayUrl(
            "relay URL must not contain a path".into(),
        ));
    }
    let relay_url = raw
        .parse::<RelayUrl>()
        .map_err(|_| P2pError::InvalidRelayUrl("failed to parse iroh RelayUrl".into()))?;
    let canonical = raw.trim_end_matches('/').to_owned();
    Ok((relay_url, canonical))
}

fn validate_direct_socket_addr(addr: SocketAddr) -> Result<SocketAddr, P2pError> {
    if addr.port() == 0 {
        return Err(P2pError::InvalidConfig("direct address port is 0".into()));
    }
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip();
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(P2pError::InvalidConfig(
                    "disallowed IPv4 direct address".into(),
                ));
            }
            Ok(addr)
        }
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(P2pError::InvalidConfig(
                    "disallowed IPv6 direct address".into(),
                ));
            }
            if let Some(v4) = ip.to_ipv4_mapped()
                && (v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast())
            {
                return Err(P2pError::InvalidConfig(
                    "disallowed IPv4-mapped IPv6 direct address".into(),
                ));
            }
            Ok(addr)
        }
    }
}

fn direct_addr_to_socket_addr(addr: &DirectAddr) -> Result<SocketAddr, P2pError> {
    let sock = match *addr {
        DirectAddr::V4 { ip, port } => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port),
        DirectAddr::V6 { ip, port } => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port),
    };
    validate_direct_socket_addr(sock)
}

fn extract_conn_remote_ip(conn: &Connection) -> Option<SocketAddr> {
    let paths = conn.paths();
    let mut fallback: Option<SocketAddr> = None;
    for path in paths.iter() {
        if let TransportAddr::Ip(addr) = path.remote_addr() {
            if path.is_selected() {
                return Some(*addr);
            }
            if fallback.is_none() {
                fallback = Some(*addr);
            }
        }
    }
    fallback
}

fn socket_addr_to_direct_addr(addr: SocketAddr) -> DirectAddr {
    match addr {
        SocketAddr::V4(v4) => DirectAddr::V4 {
            ip: v4.ip().octets(),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => DirectAddr::V6 {
            ip: v6.ip().octets(),
            port: v6.port(),
        },
    }
}

fn close_reason_code(err: &ConnectionError) -> u32 {
    match err {
        ConnectionError::ApplicationClosed(app) => {
            let code = app.error_code.into_inner();
            u32::try_from(code).unwrap_or(u32::MAX)
        }
        ConnectionError::LocallyClosed => CLOSE_SHUTDOWN,
        ConnectionError::TimedOut => 4408,
        ConnectionError::Reset => 4499,
        ConnectionError::ConnectionClosed(_)
        | ConnectionError::TransportError(_)
        | ConnectionError::VersionMismatch
        | ConnectionError::CidsExhausted => 4500,
    }
}

fn map_connect_error(err: &ConnectionError) -> P2pError {
    match err {
        ConnectionError::ApplicationClosed(app) => {
            let code = app.error_code.into_inner();
            if code == u64::from(CLOSE_UNAUTHORIZED) || code == u64::from(CLOSE_PEER_REVOKED) {
                P2pError::PeerNotAllowed
            } else {
                P2pError::Transport(format!("peer closed connection with code {code}"))
            }
        }
        ConnectionError::TimedOut => P2pError::Timeout,
        other => P2pError::Transport(other.to_string()),
    }
}

fn map_endpoint_connect_error(err: &ConnectError) -> P2pError {
    match err {
        ConnectError::Connection { source, .. } => map_connect_error(source),
        ConnectError::Connecting { source, .. } => match source {
            ConnectingError::ConnectionError { source, .. } => map_connect_error(source),
            ConnectingError::LocallyRejected { .. } | ConnectingError::HandshakeFailure { .. } => {
                P2pError::PeerNotAllowed
            }
            other => P2pError::Transport(other.to_string()),
        },
        ConnectError::Connect { source, .. } => match source {
            ConnectWithOptsError::LocallyRejected { .. } => P2pError::PeerNotAllowed,
            ConnectWithOptsError::EndpointClosed { .. } => P2pError::Closed,
            ConnectWithOptsError::SelfConnect { .. } => P2pError::SelfConnect,
            other => P2pError::Transport(other.to_string()),
        },
        other => P2pError::Transport(other.to_string()),
    }
}

fn wire_error_close_code(err: P2pWireError) -> u32 {
    match err {
        P2pWireError::FrameOversized | P2pWireError::FieldTooLarge => CLOSE_FRAME_TOO_LARGE,
        _ => CLOSE_PROTOCOL_VIOLATION,
    }
}

async fn write_framed_stream(
    mut send: SendStream,
    mut rx: mpsc::Receiver<BudgetedFrame>,
    conn: Connection,
    shared: Arc<SharedState>,
) {
    while let Some(budgeted) = rx.recv().await {
        let payload = budgeted.payload;
        let Ok(len_u32) = u32::try_from(payload.len()) else {
            conn.close(VarInt::from_u32(CLOSE_FRAME_TOO_LARGE), b"frame_too_large");
            return;
        };
        if send.write_all(&len_u32.to_le_bytes()).await.is_err()
            || (!payload.is_empty() && send.write_all(&payload).await.is_err())
        {
            if !shared.closed.load(Ordering::Acquire) && conn.close_reason().is_none() {
                conn.close(
                    VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                    b"stream_write_failed",
                );
            }
            return;
        }
        drop(budgeted._permit);
    }
    let _ = send.finish();
}

fn check_inbound_lane_allowed(
    shared: &SharedState,
    peer_id: &EndpointId,
    lane: P2pLane,
    is_pending: &AtomicBool,
) -> Result<(), (u32, &'static [u8])> {
    if shared.is_allowed(peer_id) {
        return Ok(());
    }
    if is_pending.load(Ordering::Acquire) {
        if lane == P2pLane::Control {
            if shared.is_lan_open_admission() {
                return Ok(());
            }
            return Err((CLOSE_UNAUTHORIZED, b"lan_admission_closed"));
        }
        return Err((CLOSE_PROTOCOL_VIOLATION, b"pending_peer_lane_violation"));
    }
    Err((CLOSE_PEER_REVOKED, b"peer_revoked"))
}

async fn read_framed_stream(
    mut recv: RecvStream,
    lane: P2pLane,
    peer_id: EndpointId,
    conn_id: u64,
    is_pending: Arc<AtomicBool>,
    conn: Connection,
    shared: Arc<SharedState>,
) {
    let max_bytes = lane.max_frame_bytes();
    let mut len_buf = [0u8; 4];
    loop {
        if recv.read_exact(&mut len_buf).await.is_err() {
            if !shared.closed.load(Ordering::Acquire) && conn.close_reason().is_none() {
                shared.close_and_remove_peer(
                    &peer_id,
                    Some(conn_id),
                    CLOSE_PROTOCOL_VIOLATION,
                    b"stream_closed_unexpectedly",
                    true,
                );
            }
            return;
        }
        if let Err((code, reason)) =
            check_inbound_lane_allowed(&shared, &peer_id, lane, &is_pending)
        {
            shared.close_and_remove_peer(&peer_id, Some(conn_id), code, reason, true);
            return;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > max_bytes {
            shared.close_and_remove_peer(
                &peer_id,
                Some(conn_id),
                CLOSE_FRAME_TOO_LARGE,
                b"frame_too_large",
                true,
            );
            return;
        }
        let mut payload = vec![0u8; len];
        if len > 0 && recv.read_exact(&mut payload).await.is_err() {
            if !shared.closed.load(Ordering::Acquire) && conn.close_reason().is_none() {
                shared.close_and_remove_peer(
                    &peer_id,
                    Some(conn_id),
                    CLOSE_PROTOCOL_VIOLATION,
                    b"stream_truncated_unexpectedly",
                    true,
                );
            }
            return;
        }
        if let Err((code, reason)) =
            check_inbound_lane_allowed(&shared, &peer_id, lane, &is_pending)
        {
            shared.close_and_remove_peer(&peer_id, Some(conn_id), code, reason, true);
            return;
        }
        let event = if lane == P2pLane::Control
            && shared.lan_mode
            && shared.relay_policy == RelayPolicy::NoRelays
            && is_lan_handshake_frame(&payload)
        {
            match decode_lan_handshake_frame(lane, &payload) {
                Ok(message) => P2pTransportEvent::LanHandshakeReceived {
                    peer_pubkey: *peer_id.as_bytes(),
                    message,
                },
                Err(err) => {
                    let code = if err == LanProtocolError::FrameTooLarge {
                        CLOSE_FRAME_TOO_LARGE
                    } else {
                        CLOSE_PROTOCOL_VIOLATION
                    };
                    shared.close_and_remove_peer(
                        &peer_id,
                        Some(conn_id),
                        code,
                        b"invalid_lan_handshake_frame",
                        true,
                    );
                    return;
                }
            }
        } else {
            if !shared.is_allowed(&peer_id) {
                shared.close_and_remove_peer(
                    &peer_id,
                    Some(conn_id),
                    CLOSE_PROTOCOL_VIOLATION,
                    b"pending_peer_non_handshake_frame",
                    true,
                );
                return;
            }
            let frame = match decode_p2p_party_frame(lane, &payload) {
                Ok(frame) => frame,
                Err(err) => {
                    shared.close_and_remove_peer(
                        &peer_id,
                        Some(conn_id),
                        wire_error_close_code(err),
                        b"invalid_party_frame",
                        true,
                    );
                    return;
                }
            };
            P2pTransportEvent::FrameReceived {
                peer_pubkey: *peer_id.as_bytes(),
                lane,
                frame,
            }
        };
        let units = byte_budget_units(len);
        let send_res = match lane {
            P2pLane::Control => {
                let Ok(permit) = Arc::clone(&shared.control_budget)
                    .acquire_many_owned(units)
                    .await
                else {
                    return;
                };
                shared
                    .control_tx
                    .send(BudgetedEvent {
                        event,
                        _permit: permit,
                    })
                    .await
                    .is_ok()
            }
            P2pLane::Causal => {
                let Ok(permit) = Arc::clone(&shared.causal_budget)
                    .acquire_many_owned(units)
                    .await
                else {
                    return;
                };
                shared
                    .causal_tx
                    .send(BudgetedEvent {
                        event,
                        _permit: permit,
                    })
                    .await
                    .is_ok()
            }
            P2pLane::Ephemeral => true,
        };
        if !send_res {
            return;
        }
    }
}

async fn read_datagram_loop(
    peer_id: EndpointId,
    conn_id: u64,
    is_pending: Arc<AtomicBool>,
    conn: Connection,
    shared: Arc<SharedState>,
) {
    let max_bytes = P2pLane::Ephemeral.max_frame_bytes();
    loop {
        let Ok(dgram) = conn.read_datagram().await else {
            return;
        };
        if let Err((code, reason)) =
            check_inbound_lane_allowed(&shared, &peer_id, P2pLane::Ephemeral, &is_pending)
        {
            shared.close_and_remove_peer(&peer_id, Some(conn_id), code, reason, true);
            return;
        }
        if dgram.len() > max_bytes {
            // Drop oversized unreliable datagram cleanly without closing the QUIC connection.
            continue;
        }
        let Ok(frame) = decode_p2p_party_frame(P2pLane::Ephemeral, &dgram) else {
            // Drop malformed unreliable datagram cleanly without closing the QUIC connection.
            continue;
        };
        let units = byte_budget_units(dgram.len());
        let Ok(permit) = Arc::clone(&shared.ephemeral_budget).try_acquire_many_owned(units) else {
            // Drop datagram when ephemeral byte budget is saturated; never block!
            continue;
        };
        let _ = shared.ephemeral_tx.try_send(BudgetedEvent {
            event: P2pTransportEvent::FrameReceived {
                peer_pubkey: *peer_id.as_bytes(),
                lane: P2pLane::Ephemeral,
                frame,
            },
            _permit: permit,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn register_active_peer(
    shared: &Arc<SharedState>,
    peer_id: EndpointId,
    is_outbound: bool,
    conn: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    causal_send: SendStream,
    causal_recv: RecvStream,
    is_pending_lan: bool,
    pending_guard: Option<InFlightPendingGuard>,
    initial_remote_addr: Option<SocketAddr>,
) -> Result<(), P2pError> {
    if shared.closed.load(Ordering::Acquire) {
        conn.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"endpoint_closed");
        return Err(P2pError::Closed);
    }
    if !shared.is_allowed(&peer_id) && (!is_pending_lan || !shared.is_lan_open_admission()) {
        conn.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"peer_not_allowed");
        return Err(P2pError::PeerNotAllowed);
    }

    let remote_addr = extract_conn_remote_ip(&conn).or(initial_remote_addr);

    let old = {
        let mut peers = shared.peers.write().unwrap_or_else(PoisonError::into_inner);
        if shared.closed.load(Ordering::Acquire) {
            drop(peers);
            conn.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"endpoint_closed");
            return Err(P2pError::Closed);
        }
        let is_allowed_now = shared.is_allowed(&peer_id);
        let effective_pending = if is_allowed_now {
            false
        } else {
            if !is_pending_lan || !shared.is_lan_open_admission() {
                drop(peers);
                let (code, reason): (u32, &[u8]) = if is_pending_lan {
                    (CLOSE_UNAUTHORIZED, b"lan_admission_closed")
                } else {
                    (CLOSE_PEER_REVOKED, b"peer_revoked")
                };
                conn.close(VarInt::from_u32(code), reason);
                return Err(P2pError::PeerNotAllowed);
            }
            let other_pending = peers
                .iter()
                .filter(|(id, p)| **id != peer_id && p.is_pending.load(Ordering::Acquire))
                .count();
            if other_pending >= MAX_PENDING_LAN_PEERS {
                drop(peers);
                conn.close(
                    VarInt::from_u32(CLOSE_UNAUTHORIZED),
                    b"pending_lan_cap_reached",
                );
                return Err(P2pError::PeerNotAllowed);
            }
            true
        };

        // Deterministic simultaneous-dial glare tie-break on healthy opposite-direction connections:
        // the connection initiated by the lexicographically smaller EndpointId wins.
        if let Some(existing) = peers.get(&peer_id)
            && existing.conn.close_reason().is_none()
            && existing.is_outbound != is_outbound
        {
            let keep_outbound = shared.local_id.as_bytes() < peer_id.as_bytes();
            if existing.is_outbound == keep_outbound {
                drop(peers);
                conn.close(VarInt::from_u32(CLOSE_SUPERSEDED), b"superseded");
                return Ok(());
            }
        }

        let conn_id = shared.next_conn_id.fetch_add(1, Ordering::Relaxed) + 1;
        let is_pending = Arc::new(AtomicBool::new(effective_pending));
        let (control_tx, control_rx) = mpsc::channel(LANE_CHANNEL_CAPACITY);
        let (causal_tx, causal_rx) = mpsc::channel(LANE_CHANNEL_CAPACITY);
        let control_budget = Arc::new(Semaphore::new(OUTBOUND_CONTROL_BYTE_BUDGET));
        let causal_budget = Arc::new(Semaphore::new(OUTBOUND_CAUSAL_BYTE_BUDGET));

        let t_ctrl_w = tokio::spawn(write_framed_stream(
            control_send,
            control_rx,
            conn.clone(),
            Arc::clone(shared),
        ));
        let t_caus_w = tokio::spawn(write_framed_stream(
            causal_send,
            causal_rx,
            conn.clone(),
            Arc::clone(shared),
        ));
        let t_ctrl_r = tokio::spawn(read_framed_stream(
            control_recv,
            P2pLane::Control,
            peer_id,
            conn_id,
            Arc::clone(&is_pending),
            conn.clone(),
            Arc::clone(shared),
        ));
        let t_caus_r = tokio::spawn(read_framed_stream(
            causal_recv,
            P2pLane::Causal,
            peer_id,
            conn_id,
            Arc::clone(&is_pending),
            conn.clone(),
            Arc::clone(shared),
        ));
        let t_dgram_r = tokio::spawn(read_datagram_loop(
            peer_id,
            conn_id,
            Arc::clone(&is_pending),
            conn.clone(),
            Arc::clone(shared),
        ));

        let watcher_shared = Arc::clone(shared);
        let watcher_conn = conn.clone();
        let t_watcher = tokio::spawn(async move {
            let err = watcher_conn.closed().await;
            let code = close_reason_code(&err);
            watcher_shared.close_and_remove_peer(&peer_id, Some(conn_id), code, b"closed", true);
        });

        let active = ActivePeer {
            conn_id,
            is_outbound,
            conn,
            remote_addr,
            is_pending,
            control_tx,
            control_budget,
            causal_tx,
            causal_budget,
            tasks: vec![
                t_ctrl_w, t_caus_w, t_ctrl_r, t_caus_r, t_dgram_r, t_watcher,
            ],
        };

        let previous = peers.insert(peer_id, active);
        // Transfer slot accounting from in-flight to active map under the write lock.
        drop(pending_guard);
        previous
    };

    if let Some(mut previous) = old {
        previous
            .conn
            .close(VarInt::from_u32(CLOSE_SUPERSEDED), b"superseded");
        previous.shutdown();
    }

    let _ = shared
        .lifecycle_tx
        .try_send(P2pTransportEvent::PeerConnected {
            peer_pubkey: *peer_id.as_bytes(),
        });
    Ok(())
}

async fn handle_incoming_connection(incoming: Incoming, shared: Arc<SharedState>) {
    let initial_remote_addr = match incoming.remote_addr() {
        IncomingAddr::Ip(addr) => Some(addr),
        _ => None,
    };
    let Ok(accepting) = incoming.accept() else {
        return;
    };
    // Full 1-RTT TLS 1.3 Mutual RPK handshake — never call into_0rtt().
    let Ok(Ok(conn)) = tokio::time::timeout(STREAM_SETUP_TIMEOUT, accepting).await else {
        return;
    };

    let remote_id = conn.remote_id();
    if conn.alpn() != ALPN {
        conn.close(VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION), b"wrong_alpn");
        return;
    }
    let mut is_pending_lan = false;
    let mut pending_guard: Option<InFlightPendingGuard> = None;
    if !shared.is_allowed(&remote_id) {
        if !shared.is_lan_open_admission() {
            conn.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"peer_not_allowed");
            return;
        }
        match shared.try_reserve_in_flight_pending(&remote_id) {
            Some(guard) => {
                is_pending_lan = true;
                pending_guard = Some(guard);
            }
            None => {
                conn.close(
                    VarInt::from_u32(CLOSE_UNAUTHORIZED),
                    b"pending_lan_cap_reached",
                );
                return;
            }
        }
    }

    // Accept bidirectional Stream 0 (Control) and Stream 4 (Causal) in any arrival order.
    let setup = tokio::time::timeout(STREAM_SETUP_TIMEOUT, async {
        let mut control: Option<(SendStream, RecvStream)> = None;
        let mut causal: Option<(SendStream, RecvStream)> = None;

        while control.is_none() || causal.is_none() {
            let (send, mut recv) = conn
                .accept_bi()
                .await
                .map_err(|_| CLOSE_PROTOCOL_VIOLATION)?;
            let sid = u64::from(recv.id());
            let mut marker = [0u8; 4];
            recv.read_exact(&mut marker)
                .await
                .map_err(|_| CLOSE_PROTOCOL_VIOLATION)?;
            if u32::from_le_bytes(marker) != STREAM_INIT_MARKER {
                return Err(CLOSE_PROTOCOL_VIOLATION);
            }
            match sid {
                STREAM_ID_CONTROL if control.is_none() => {
                    let _ = send.set_priority(LANE_CONTROL_PRIORITY);
                    control = Some((send, recv));
                }
                STREAM_ID_CAUSAL if causal.is_none() => {
                    let _ = send.set_priority(LANE_CAUSAL_PRIORITY);
                    causal = Some((send, recv));
                }
                _ => return Err(CLOSE_PROTOCOL_VIOLATION),
            }
        }

        let Some((mut control_send, control_recv)) = control else {
            return Err(CLOSE_PROTOCOL_VIOLATION);
        };
        let Some((causal_send, causal_recv)) = causal else {
            return Err(CLOSE_PROTOCOL_VIOLATION);
        };

        if !shared.is_allowed(&remote_id) && (!is_pending_lan || !shared.is_lan_open_admission()) {
            return Err(CLOSE_UNAUTHORIZED);
        }

        // Send 4-byte readiness ACK on Stream 0 so the dialer knows both lanes
        // passed allowlist + stream verification.
        control_send
            .write_all(&STREAM_INIT_MARKER.to_le_bytes())
            .await
            .map_err(|_| CLOSE_PROTOCOL_VIOLATION)?;

        Ok((control_send, control_recv, causal_send, causal_recv))
    })
    .await;

    match setup {
        Ok(Ok((control_send, control_recv, causal_send, causal_recv))) => {
            let _ = register_active_peer(
                &shared,
                remote_id,
                false,
                conn,
                control_send,
                control_recv,
                causal_send,
                causal_recv,
                is_pending_lan,
                pending_guard,
                initial_remote_addr,
            );
        }
        Ok(Err(code)) => {
            conn.close(VarInt::from_u32(code), b"stream_setup_rejected");
        }
        Err(_) => {
            conn.close(
                VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                b"stream_setup_timeout",
            );
        }
    }
}

async fn accept_loop(endpoint: Endpoint, shared: Arc<SharedState>) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_INBOUND_HANDSHAKES));
    while let Some(incoming) = endpoint.accept().await {
        if shared.closed.load(Ordering::Acquire) {
            break;
        }
        let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
            break;
        };
        let shared_clone = Arc::clone(&shared);
        tokio::spawn(async move {
            let _permit = permit;
            handle_incoming_connection(incoming, shared_clone).await;
        });
    }
}
