//! TLS 1.3 + HTTP/1.1 ALPN RFC 6455 `MP1` WebSocket client, dual-host eviction churn detector,
//! and `PARTY_ENDPOINT_UPDATE` coalescer.

use core::fmt;
use std::collections::VecDeque;

use futures_util::{SinkExt as _, StreamExt as _};
use http::{HeaderName, HeaderValue, StatusCode};
use mp_protocol::{
    EndpointDescriptor, FrameHeader, HttpMethod, MAX_MP1_FRAME_BYTES, Mp1Error, Mp1Message,
    PartyId, PresenceVisibility, RelayPolicy, SessionId, SocketRole, decode_frame, encode_frame,
};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_websockets::{ClientBuilder, CloseCode, Limits, Message, WebSocketStream};

use crate::clock::sleep_aware_now_ms;
use crate::http::{
    ControlClientConfig, ControlError, MAX_RESPONSE_HEADERS_BYTES, RequestSigner, sign_request,
};
use crate::tls::connect_tls13;

/// Static application-layer ping payload (`MP1:PING`).
pub const MP1_PING_TEXT: &str = "MP1:PING";
/// Static application-layer pong payload (`MP1:PONG`).
pub const MP1_PONG_TEXT: &str = "MP1:PONG";
/// Sleep-aware window (`60_000 ms`) for detecting dual-host `device_id` churn.
pub const CHURN_WINDOW_MS: u64 = 60_000;
/// Number of unexpected changing-session replacements in `CHURN_WINDOW_MS` that triggers alert.
pub const CHURN_THRESHOLD: usize = 3;
/// Minimum interval (`30_000 ms`) between outbound `PARTY_ENDPOINT_UPDATE` frames.
pub const MIN_ENDPOINT_UPDATE_INTERVAL_MS: u64 = 30_000;

/// Target `MP1` WebSocket endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mp1WsTarget {
    /// `/v1/ws` (`AccountDO`).
    Account,
    /// `/v1/parties/<party_id>/ws` (`PartyDO`).
    Party(PartyId),
}

impl Mp1WsTarget {
    pub fn path(self) -> String {
        match self {
            Self::Account => "/v1/ws".to_owned(),
            Self::Party(party_id) => format!("/v1/parties/{party_id}/ws"),
        }
    }

    pub const fn role(self) -> SocketRole {
        match self {
            Self::Account => SocketRole::Account,
            Self::Party(_) => SocketRole::Party,
        }
    }
}

/// Errors encountered while upgrading/connecting an `MP1` WebSocket.
#[derive(Debug)]
pub enum WsConnectError {
    MissingSigner,
    /// Terminal HTTP `404` or `403` upgrade rejection — caller MUST stop retrying!
    Terminal(u16),
    /// Non-terminal HTTP upgrade rejection (e.g. `401`, `429`, `503`).
    UpgradeRejected(u16),
    /// Server did not echo `Sec-WebSocket-Protocol: mp1`.
    MissingMp1Subprotocol,
    /// Server negotiated a forbidden extension (e.g. `permessage-deflate`).
    ForbiddenExtension,
    ResponseHeadersTooLarge,
    Transport(ControlError),
    Websocket(tokio_websockets::Error),
    InvalidRequest(String),
    Timeout,
}

impl fmt::Display for WsConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSigner => write!(f, "no device signer configured for WebSocket"),
            Self::Terminal(code) => write!(f, "terminal WebSocket upgrade rejection HTTP {code}"),
            Self::UpgradeRejected(code) => write!(f, "WebSocket upgrade rejected with HTTP {code}"),
            Self::MissingMp1Subprotocol => {
                write!(f, "server did not echo Sec-WebSocket-Protocol: mp1")
            }
            Self::ForbiddenExtension => {
                write!(f, "server returned forbidden Sec-WebSocket-Extensions header")
            }
            Self::ResponseHeadersTooLarge => {
                write!(f, "WebSocket upgrade response headers exceed 8 KiB limit")
            }
            Self::Transport(e) => write!(f, "transport error during WebSocket connect: {e}"),
            Self::Websocket(e) => write!(f, "WebSocket handshake error: {e}"),
            Self::InvalidRequest(msg) => write!(f, "invalid WebSocket request: {msg}"),
            Self::Timeout => write!(f, "WebSocket connect timed out"),
        }
    }
}

impl std::error::Error for WsConnectError {}

/// Runtime errors on an established [`Mp1WsClient`].
#[derive(Debug)]
pub enum WsError {
    FrameTooLarge { len: usize, max_len: usize },
    UnexpectedTextFrame,
    DisallowedClientOpcode,
    Mp1(Mp1Error),
    Websocket(tokio_websockets::Error),
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { len, max_len } => {
                write!(f, "WebSocket frame size {len} exceeds {max_len} B cap")
            }
            Self::UnexpectedTextFrame => write!(f, "unexpected non-MP1:PONG text WebSocket frame"),
            Self::DisallowedClientOpcode => {
                write!(f, "attempted to send disallowed MP1 opcode for socket role")
            }
            Self::Mp1(e) => write!(f, "MP1 codec error: {e}"),
            Self::Websocket(e) => write!(f, "WebSocket stream error: {e}"),
        }
    }
}

impl std::error::Error for WsError {}

impl From<Mp1Error> for WsError {
    fn from(e: Mp1Error) -> Self {
        Self::Mp1(e)
    }
}

/// Decoded inbound events from [`Mp1WsClient::next_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mp1WsEvent {
    /// Decoded `MP1` binary control frame (`<= 8,192 B`).
    Frame {
        header: FrameHeader,
        message: Mp1Message,
    },
    /// Application-layer `"MP1:PONG"` response (updates sleep-aware `last_pong_ms`).
    Pong,
    /// RFC 6455 Close frame from peer.
    Closed {
        code: Option<u16>,
        reason: String,
    },
}

/// Active TLS 1.3 + HTTP/1.1 ALPN RFC 6455 `MP1` WebSocket client.
pub struct Mp1WsClient {
    stream: WebSocketStream<TlsStream<TcpStream>>,
    target: Mp1WsTarget,
    last_pong_ms: u64,
    next_seq: u32,
}

impl fmt::Debug for Mp1WsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mp1WsClient")
            .field("target", &self.target)
            .field("last_pong_ms", &self.last_pong_ms)
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

impl Mp1WsClient {
    /// Connects and upgrades an RFC 9421-signed `MP1` WebSocket over TLS 1.3 + HTTP/1.1 ALPN.
    pub async fn connect(
        config: &ControlClientConfig,
        signer: &RequestSigner,
        clock_offset_ms: i64,
        target: Mp1WsTarget,
    ) -> Result<Self, WsConnectError> {
        let path = target.path();
        let signed = sign_request(
            signer,
            HttpMethod::Get,
            &config.authority,
            &path,
            "?",
            &[],
            clock_offset_ms,
        )
        .map_err(WsConnectError::Transport)?;

        let tls_stream = connect_tls13(
            &config.authority,
            config.connect_addr,
            &config.tls_config,
            config.request_timeout,
        )
        .await
        .map_err(WsConnectError::Transport)?;

        let ws_uri = format!("wss://{}{}", config.authority, path);
        let limits = Limits::default().max_payload_len(Some(MAX_MP1_FRAME_BYTES));

        let builder = ClientBuilder::new()
            .uri(&ws_uri)
            .map_err(|e| WsConnectError::InvalidRequest(e.to_string()))?
            .limits(limits)
            .add_header(
                HeaderName::from_static("sec-websocket-protocol"),
                HeaderValue::from_static("mp1"),
            )
            .map_err(WsConnectError::Websocket)?
            .add_header(
                HeaderName::from_static("signature-input"),
                HeaderValue::from_str(&signed.signature_input)
                    .map_err(|e| WsConnectError::InvalidRequest(e.to_string()))?,
            )
            .map_err(WsConnectError::Websocket)?
            .add_header(
                HeaderName::from_static("signature"),
                HeaderValue::from_str(&signed.signature)
                    .map_err(|e| WsConnectError::InvalidRequest(e.to_string()))?,
            )
            .map_err(WsConnectError::Websocket)?;

        let (stream, resp) = tokio::time::timeout(
            config.request_timeout,
            builder.connect_on(tls_stream),
        )
        .await
        .map_err(|_| WsConnectError::Timeout)?
        .map_err(classify_ws_connect_error)?;

        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(classify_http_status(resp.status().as_u16()));
        }

        let mut header_bytes: usize = 0;
        for (name, value) in resp.headers() {
            header_bytes = header_bytes
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
                .saturating_add(4);
            if header_bytes > MAX_RESPONSE_HEADERS_BYTES {
                return Err(WsConnectError::ResponseHeadersTooLarge);
            }
        }

        let proto_ok = resp
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.trim() == "mp1");
        if !proto_ok {
            return Err(WsConnectError::MissingMp1Subprotocol);
        }

        if let Some(ext) = resp.headers().get("sec-websocket-extensions")
            && !ext.as_bytes().is_empty()
        {
            return Err(WsConnectError::ForbiddenExtension);
        }

        Ok(Self {
            stream,
            target,
            last_pong_ms: sleep_aware_now_ms(),
            next_seq: 1,
        })
    }

    pub const fn target(&self) -> Mp1WsTarget {
        self.target
    }

    /// Sleep-aware timestamp (`CLOCK_BOOTTIME` / `mach_continuous_time`) of the last `"MP1:PONG"`
    /// (or connection establishment).
    pub const fn last_pong_ms(&self) -> u64 {
        self.last_pong_ms
    }

    /// Sleep-aware milliseconds elapsed since the last `"MP1:PONG"`.
    pub fn silence_ms(&self) -> u64 {
        sleep_aware_now_ms().saturating_sub(self.last_pong_ms)
    }

    /// Sends the static `"MP1:PING"` text liveness frame.
    pub async fn send_ping(&mut self) -> Result<(), WsError> {
        self.stream
            .send(Message::text(MP1_PING_TEXT))
            .await
            .map_err(WsError::Websocket)
    }

    /// Sends a client-allowed binary `MP1` frame (`PRESENCE_SET` on Account,
    /// `PARTY_ENDPOINT_UPDATE` on Party) and returns its assigned `seq`.
    pub async fn send_message(&mut self, msg: &Mp1Message) -> Result<u32, WsError> {
        if !msg.opcode().is_allowed_from_client(self.target.role()) {
            return Err(WsError::DisallowedClientOpcode);
        }
        let seq = self.next_seq;
        let encoded = encode_frame(seq, msg)?;
        if encoded.len() > MAX_MP1_FRAME_BYTES {
            return Err(WsError::FrameTooLarge {
                len: encoded.len(),
                max_len: MAX_MP1_FRAME_BYTES,
            });
        }
        self.next_seq = self.next_seq.wrapping_add(1);
        if self.next_seq == 0 {
            self.next_seq = 1;
        }
        self.stream
            .send(Message::binary(encoded))
            .await
            .map_err(WsError::Websocket)?;
        Ok(seq)
    }

    /// Convenience helper for sending `PRESENCE_SET` on `/v1/ws`.
    pub async fn send_presence_set(
        &mut self,
        visibility: PresenceVisibility,
        share_party: bool,
    ) -> Result<u32, WsError> {
        self.send_message(&Mp1Message::PresenceSet {
            visibility,
            share_party,
        })
        .await
    }

    /// Convenience helper for sending `PARTY_ENDPOINT_UPDATE` on `/v1/parties/<id>/ws`.
    pub async fn send_party_endpoint_update(
        &mut self,
        endpoint: EndpointDescriptor,
    ) -> Result<u32, WsError> {
        self.send_message(&Mp1Message::PartyEndpointUpdate { endpoint })
            .await
    }

    /// Receives the next `MP1` event (`Frame`, `Pong`, or `Closed`), enforcing `<= 8,192 B`
    /// aggregate reassembled binary payload cap and transparently flushing RFC 6455 Pong replies
    /// to interleaved Ping frames.
    pub async fn next_event(&mut self) -> Result<Option<Mp1WsEvent>, WsError> {
        loop {
            let Some(item) = self.stream.next().await else {
                return Ok(None);
            };
            let msg = match item {
                Ok(m) => m,
                Err(tokio_websockets::Error::PayloadTooLong { len, max_len }) => {
                    return Err(WsError::FrameTooLarge { len, max_len });
                }
                Err(e) => return Err(WsError::Websocket(e)),
            };

            if msg.is_ping() {
                // `tokio-websockets` automatically queues the matching RFC 6455 Pong; flush it now.
                self.stream.flush().await.map_err(WsError::Websocket)?;
                continue;
            }
            if msg.is_pong() {
                continue;
            }
            if msg.is_close() {
                let (code, reason) = match msg.as_close() {
                    Some((c, r)) => (Some(u16::from(c)), r.to_owned()),
                    None => (None, String::new()),
                };
                return Ok(Some(Mp1WsEvent::Closed { code, reason }));
            }
            if msg.is_text() {
                let payload = msg.as_payload();
                if payload.len() > MAX_MP1_FRAME_BYTES {
                    return Err(WsError::FrameTooLarge {
                        len: payload.len(),
                        max_len: MAX_MP1_FRAME_BYTES,
                    });
                }
                if msg.as_text() == Some(MP1_PONG_TEXT) {
                    self.last_pong_ms = sleep_aware_now_ms();
                    return Ok(Some(Mp1WsEvent::Pong));
                }
                return Err(WsError::UnexpectedTextFrame);
            }
            if msg.is_binary() {
                let payload = msg.as_payload();
                if payload.len() > MAX_MP1_FRAME_BYTES {
                    return Err(WsError::FrameTooLarge {
                        len: payload.len(),
                        max_len: MAX_MP1_FRAME_BYTES,
                    });
                }
                let (header, message) = decode_frame(payload)?;
                return Ok(Some(Mp1WsEvent::Frame { header, message }));
            }
        }
    }

    /// Gracefully sends an RFC 6455 Close frame (e.g. `1000`) and flushes the stream.
    pub async fn close(&mut self, code: u16, reason: &str) -> Result<(), WsError> {
        let close_code = CloseCode::try_from(code).unwrap_or(CloseCode::NORMAL_CLOSURE);
        self.stream
            .send(Message::close(Some(close_code), reason))
            .await
            .map_err(WsError::Websocket)?;
        self.stream.flush().await.map_err(WsError::Websocket)
    }
}

fn classify_ws_connect_error(err: tokio_websockets::Error) -> WsConnectError {
    match err {
        tokio_websockets::Error::Upgrade(
            tokio_websockets::upgrade::Error::DidNotSwitchProtocols(code),
        ) => classify_http_status(code),
        other => WsConnectError::Websocket(other),
    }
}

fn classify_http_status(code: u16) -> WsConnectError {
    if code == 404 || code == 403 {
        WsConnectError::Terminal(code)
    } else {
        WsConnectError::UpgradeRejected(code)
    }
}

// ---------------------------------------------------------------------------
// Dual-Host `device_id` Eviction Churn Detector
// ---------------------------------------------------------------------------

/// Output of [`EvictionChurnDetector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChurnStatus {
    Ok,
    /// `>= 3` unexpected session replacements with changing `HELLO_ACK.session_id` within `60s`.
    DualHostChurnDetected { replacements_in_window: usize },
}

/// Detects dual-host `device_id` fighting (`>= 3` unexpected WS session replacements with
/// changing `HELLO_ACK.session_id` within `60_000 ms` on the sleep-aware clock).
#[derive(Debug, Clone, Default)]
pub struct EvictionChurnDetector {
    last_session_id: Option<SessionId>,
    replacements_ms: VecDeque<u64>,
}

impl EvictionChurnDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a newly established `HELLO_ACK.session_id` using [`sleep_aware_now_ms()`].
    /// Pass `unexpected_reconnect = true` when reconnecting after an unexpected eviction/close.
    pub fn record_hello_ack(
        &mut self,
        session_id: SessionId,
        unexpected_reconnect: bool,
    ) -> ChurnStatus {
        self.record_hello_ack_at(session_id, unexpected_reconnect, sleep_aware_now_ms())
    }

    /// Deterministic timestamped variant for unit/simulation testing.
    pub fn record_hello_ack_at(
        &mut self,
        session_id: SessionId,
        unexpected_reconnect: bool,
        now_ms: u64,
    ) -> ChurnStatus {
        let cutoff = now_ms.saturating_sub(CHURN_WINDOW_MS);
        while let Some(&oldest) = self.replacements_ms.front() {
            if oldest < cutoff {
                let _ = self.replacements_ms.pop_front();
            } else {
                break;
            }
        }

        if unexpected_reconnect
            && let Some(prev) = self.last_session_id
            && prev != session_id
        {
            self.replacements_ms.push_back(now_ms);
        }

        self.last_session_id = Some(session_id);

        if self.replacements_ms.len() >= CHURN_THRESHOLD {
            ChurnStatus::DualHostChurnDetected {
                replacements_in_window: self.replacements_ms.len(),
            }
        } else {
            ChurnStatus::Ok
        }
    }

    pub fn replacements_in_window(&self) -> usize {
        self.replacements_ms.len()
    }

    pub fn reset(&mut self) {
        self.last_session_id = None;
        self.replacements_ms.clear();
    }
}

// ---------------------------------------------------------------------------
// `PARTY_ENDPOINT_UPDATE` Coalescer (<= 1 / 30s, honors retry_after_ms, ForceRelays silent)
// ---------------------------------------------------------------------------

/// Coalesces rapid `EndpointDescriptor` roaming updates to `<= 1` frame per `30_000 ms`,
/// honors `ERROR.retry_after_ms`, and suppresses ALL updates under `RelayPolicy::ForceRelays`.
#[derive(Debug, Clone)]
pub struct EndpointUpdateCoalescer {
    relay_policy: RelayPolicy,
    last_sent_ms: Option<u64>,
    blocked_until_ms: u64,
    pending: Option<EndpointDescriptor>,
    last_sent_descriptor: Option<EndpointDescriptor>,
}

impl EndpointUpdateCoalescer {
    pub const fn new(relay_policy: RelayPolicy) -> Self {
        Self {
            relay_policy,
            last_sent_ms: None,
            blocked_until_ms: 0,
            pending: None,
            last_sent_descriptor: None,
        }
    }

    pub const fn relay_policy(&self) -> RelayPolicy {
        self.relay_policy
    }

    /// Records a server `ERROR.retry_after_ms` backoff using [`sleep_aware_now_ms()`].
    pub fn record_retry_after(&mut self, retry_after_ms: u32) {
        self.record_retry_after_at(retry_after_ms, sleep_aware_now_ms());
    }

    /// Deterministic timestamped variant of [`Self::record_retry_after`].
    pub fn record_retry_after_at(&mut self, retry_after_ms: u32, now_ms: u64) {
        let until = now_ms.saturating_add(u64::from(retry_after_ms));
        if until > self.blocked_until_ms {
            self.blocked_until_ms = until;
        }
    }

    /// Submits a newly observed local `EndpointDescriptor` using [`sleep_aware_now_ms()`].
    /// Returns `Some(descriptor)` immediately if eligible to transmit now, or `None` if coalesced
    /// / throttled / suppressed.
    pub fn submit(&mut self, descriptor: EndpointDescriptor) -> Option<EndpointDescriptor> {
        self.submit_at(descriptor, sleep_aware_now_ms())
    }

    /// Deterministic timestamped variant of [`Self::submit`].
    pub fn submit_at(
        &mut self,
        descriptor: EndpointDescriptor,
        now_ms: u64,
    ) -> Option<EndpointDescriptor> {
        if self.relay_policy == RelayPolicy::ForceRelays {
            self.pending = None;
            return None;
        }
        if self.last_sent_descriptor.as_ref() == Some(&descriptor) && self.pending.is_none() {
            return None;
        }
        self.pending = Some(descriptor);
        self.poll_ready_at(now_ms)
    }

    /// Polls whether a previously coalesced pending update is now eligible to transmit.
    pub fn poll_ready(&mut self) -> Option<EndpointDescriptor> {
        self.poll_ready_at(sleep_aware_now_ms())
    }

    /// Deterministic timestamped variant of [`Self::poll_ready`].
    pub fn poll_ready_at(&mut self, now_ms: u64) -> Option<EndpointDescriptor> {
        if self.relay_policy == RelayPolicy::ForceRelays {
            self.pending = None;
            return None;
        }
        self.pending.as_ref()?;
        if let Some(next_allowed) = self.next_allowed_at_ms()
            && now_ms < next_allowed
        {
            return None;
        }
        let desc = self.pending.take()?;
        if self.last_sent_descriptor.as_ref() == Some(&desc) {
            return None;
        }
        self.last_sent_ms = Some(now_ms);
        self.last_sent_descriptor = Some(desc.clone());
        Some(desc)
    }

    /// Returns the earliest sleep-aware timestamp (`ms`) when a pending update may be emitted.
    pub fn next_allowed_at_ms(&self) -> Option<u64> {
        if self.relay_policy == RelayPolicy::ForceRelays || self.pending.is_none() {
            return None;
        }
        let interval_gate = self
            .last_sent_ms
            .map(|t| t.saturating_add(MIN_ENDPOINT_UPDATE_INTERVAL_MS))
            .unwrap_or(0);
        Some(interval_gate.max(self.blocked_until_ms))
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}
