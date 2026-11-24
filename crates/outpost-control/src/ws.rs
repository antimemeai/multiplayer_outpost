//! TLS 1.3 + HTTP/1.1 ALPN RFC 6455 `MP1` WebSocket client, dual-host eviction churn detector,
//! and `PARTY_ENDPOINT_UPDATE` coalescer.

use core::fmt;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use bytes::{Buf as _, Bytes};
use futures_util::{SinkExt as _, StreamExt as _};
use mp_protocol::{
    EndpointDescriptor, FrameHeader, HttpMethod, MAX_MP1_FRAME_BYTES, Mp1Error, Mp1Message,
    PartyId, PresenceVisibility, RelayPolicy, SessionId, SocketRole, decode_frame, encode_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_websockets::{ClientBuilder, CloseCode, Limits, Message, WebSocketStream};

use crate::clock::sleep_aware_now_ms;
use crate::http::{
    ApiErrorBody, ControlClientConfig, ControlError, MAX_RESPONSE_BODY_BYTES,
    MAX_RESPONSE_HEADERS_BYTES, RequestSigner, sign_request,
};
use crate::tls::{canonicalize_authority, connect_tls13};

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

/// RFC 6455 §1.3 static GUID concatenated with `Sec-WebSocket-Key` prior to SHA-1.
const RFC6455_WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Maximum header lines accepted in a WebSocket HTTP/1.1 upgrade response.
const MAX_UPGRADE_HEADER_COUNT: usize = 64;

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
    /// HTTP `401` JSON `{"error":"clock_skew","server_now_ms":...}` response on WS upgrade.
    ClockSkew {
        server_now_ms: u64,
    },
    /// Terminal HTTP `404` or `403` upgrade rejection — caller MUST stop retrying!
    Terminal(u16),
    /// Non-terminal HTTP upgrade rejection (e.g. `401`, `429`, `503`).
    UpgradeRejected(u16),
    /// Server did not echo `Sec-WebSocket-Protocol: mp1`.
    MissingMp1Subprotocol,
    /// Server did not echo the expected `Sec-WebSocket-Protocol` (e.g. `mp2`).
    MissingSubprotocol {
        expected: &'static str,
    },
    /// Server negotiated a forbidden extension (e.g. `permessage-deflate`).
    ForbiddenExtension,
    /// Server upgrade response headers exceeded the `8 KiB` cap.
    ResponseHeadersTooLarge,
    /// Server sent a malformed or invalid RFC 6455 HTTP/1.1 upgrade response.
    InvalidUpgradeResponse(String),
    Transport(ControlError),
    Websocket(tokio_websockets::Error),
    InvalidRequest(String),
    Timeout,
}

impl fmt::Display for WsConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSigner => write!(f, "no device signer configured for WebSocket"),
            Self::ClockSkew { server_now_ms } => {
                write!(
                    f,
                    "WebSocket upgrade rejected with 401 clock_skew (server_now_ms={server_now_ms})"
                )
            }
            Self::Terminal(code) => write!(f, "terminal WebSocket upgrade rejection HTTP {code}"),
            Self::UpgradeRejected(code) => write!(f, "WebSocket upgrade rejected with HTTP {code}"),
            Self::MissingMp1Subprotocol => {
                write!(f, "server did not echo Sec-WebSocket-Protocol: mp1")
            }
            Self::MissingSubprotocol { expected } => {
                write!(f, "server did not echo Sec-WebSocket-Protocol: {expected}")
            }
            Self::ForbiddenExtension => {
                write!(f, "server returned forbidden Sec-WebSocket-Extensions header")
            }
            Self::ResponseHeadersTooLarge => {
                write!(f, "WebSocket upgrade response headers exceed 8 KiB limit")
            }
            Self::InvalidUpgradeResponse(msg) => {
                write!(f, "invalid WebSocket upgrade response: {msg}")
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

/// Stream adapter that replays bytes already read past `\r\n\r\n` during the manual
/// HTTP/1.1 `101 Switching Protocols` handshake before delegating reads to `inner`.
pub(crate) struct PrefixedIo<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedIo<S> {
    pub(crate) fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.has_remaining() {
            let to_copy = self.prefix.remaining().min(buf.remaining());
            if let Some(slice) = self.prefix.chunk().get(..to_copy) {
                buf.put_slice(slice);
                self.prefix.advance(to_copy);
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Active TLS 1.3 + HTTP/1.1 ALPN RFC 6455 `MP1` WebSocket client.
pub struct Mp1WsClient {
    stream: WebSocketStream<PrefixedIo<TlsStream<TcpStream>>>,
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
    /// Connects and upgrades an RFC 9421-signed `MP1` WebSocket over TLS 1.3 + HTTP/1.1 ALPN
    /// using an owned, strictly bounded HTTP/1.1 `101 Switching Protocols` handshake.
    pub async fn connect(
        config: &ControlClientConfig,
        signer: &RequestSigner,
        clock_offset_ms: i64,
        target: Mp1WsTarget,
    ) -> Result<Self, WsConnectError> {
        let canonical_authority =
            canonicalize_authority(&config.authority).map_err(WsConnectError::Transport)?;
        let path = target.path();
        let signed = sign_request(
            signer,
            HttpMethod::Get,
            &canonical_authority,
            &path,
            "?",
            &[],
            clock_offset_ms,
        )
        .map_err(WsConnectError::Transport)?;

        let mut tls_stream = connect_tls13(
            &canonical_authority,
            config.connect_addr,
            &config.tls_config,
            config.request_timeout,
        )
        .await
        .map_err(WsConnectError::Transport)?;

        let ws_key = generate_ws_key()?;
        let upgrade_req = build_ws_upgrade_request(
            &canonical_authority,
            &path,
            &ws_key,
            &signed.signature_input,
            &signed.signature,
        )?;

        let leftover = tokio::time::timeout(config.request_timeout, async {
            tls_stream
                .write_all(&upgrade_req)
                .await
                .map_err(|e| WsConnectError::Transport(ControlError::Io(e)))?;
            tls_stream
                .flush()
                .await
                .map_err(|e| WsConnectError::Transport(ControlError::Io(e)))?;

            perform_bounded_upgrade_read(&mut tls_stream, &ws_key).await
        })
        .await
        .map_err(|_| WsConnectError::Timeout)??;

        let limits = Limits::default().max_payload_len(Some(MAX_MP1_FRAME_BYTES));
        let stream = ClientBuilder::new()
            .limits(limits)
            .take_over(PrefixedIo::new(leftover, tls_stream));

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

// ---------------------------------------------------------------------------
// Owned Bounded HTTP/1.1 RFC 6455 Upgrade Handshake & FIPS 180-4 SHA-1
// ---------------------------------------------------------------------------

pub(crate) fn generate_ws_key() -> Result<String, WsConnectError> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw)
        .map_err(|e| WsConnectError::Transport(ControlError::RandomFailure(e.to_string())))?;
    Ok(B64_STD.encode(raw))
}

fn contains_crlf_or_ctl(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn build_ws_upgrade_request(
    authority: &str,
    path: &str,
    ws_key: &str,
    signature_input: &str,
    signature: &str,
) -> Result<Vec<u8>, WsConnectError> {
    build_ws_upgrade_request_with_protocol(
        authority,
        path,
        ws_key,
        "mp1",
        signature_input,
        signature,
    )
}

pub(crate) fn build_ws_upgrade_request_with_protocol(
    authority: &str,
    path: &str,
    ws_key: &str,
    subprotocol: &str,
    signature_input: &str,
    signature: &str,
) -> Result<Vec<u8>, WsConnectError> {
    if contains_crlf_or_ctl(authority)
        || contains_crlf_or_ctl(path)
        || contains_crlf_or_ctl(ws_key)
        || contains_crlf_or_ctl(subprotocol)
        || contains_crlf_or_ctl(signature_input)
        || contains_crlf_or_ctl(signature)
    {
        return Err(WsConnectError::InvalidRequest(
            "control characters in WebSocket upgrade request headers".to_owned(),
        ));
    }

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {subprotocol}\r\n\
         Signature-Input: {signature_input}\r\n\
         Signature: {signature}\r\n\
         \r\n"
    );
    Ok(req.into_bytes())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_http_token_byte(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
            | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

struct ParsedUpgradeHeaders {
    status: u16,
    headers: Vec<(String, String)>,
}

fn parse_upgrade_headers(raw_head: &[u8]) -> Result<ParsedUpgradeHeaders, WsConnectError> {
    let head_str = std::str::from_utf8(raw_head)
        .map_err(|_| WsConnectError::InvalidUpgradeResponse("non-UTF8 response headers".into()))?;
    let mut lines = head_str.split("\r\n");

    let status_line = lines.next().ok_or_else(|| {
        WsConnectError::InvalidUpgradeResponse("missing HTTP status line".to_owned())
    })?;
    if status_line.contains('\r') || status_line.contains('\n') {
        return Err(WsConnectError::InvalidUpgradeResponse(
            "bare CR/LF in status line".to_owned(),
        ));
    }
    let rest = status_line.strip_prefix("HTTP/1.1 ").ok_or_else(|| {
        WsConnectError::InvalidUpgradeResponse("response is not HTTP/1.1".to_owned())
    })?;
    let code_str = rest.get(..3).ok_or_else(|| {
        WsConnectError::InvalidUpgradeResponse("truncated HTTP status code".to_owned())
    })?;
    if !code_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WsConnectError::InvalidUpgradeResponse(
            "non-numeric HTTP status code".to_owned(),
        ));
    }
    if let Some(after_code) = rest.get(3..)
        && !after_code.is_empty()
        && !after_code.starts_with(' ')
    {
        return Err(WsConnectError::InvalidUpgradeResponse(
            "malformed HTTP status line".to_owned(),
        ));
    }
    let status = code_str.parse::<u16>().map_err(|_| {
        WsConnectError::InvalidUpgradeResponse("invalid HTTP status code".to_owned())
    })?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            return Err(WsConnectError::InvalidUpgradeResponse(
                "unexpected empty header line".to_owned(),
            ));
        }
        if line.contains('\r') || line.contains('\n') {
            return Err(WsConnectError::InvalidUpgradeResponse(
                "bare CR/LF in header line".to_owned(),
            ));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(WsConnectError::InvalidUpgradeResponse(
                "obs-fold multiline header rejected".to_owned(),
            ));
        }
        if headers.len() >= MAX_UPGRADE_HEADER_COUNT {
            return Err(WsConnectError::ResponseHeadersTooLarge);
        }
        let Some((raw_name, raw_val)) = line.split_once(':') else {
            return Err(WsConnectError::InvalidUpgradeResponse(
                "header line missing colon".to_owned(),
            ));
        };
        if raw_name.is_empty() || !raw_name.bytes().all(is_http_token_byte) {
            return Err(WsConnectError::InvalidUpgradeResponse(
                "invalid HTTP header name".to_owned(),
            ));
        }
        if raw_val
            .bytes()
            .any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            return Err(WsConnectError::InvalidUpgradeResponse(
                "control character in HTTP header value".to_owned(),
            ));
        }
        let name = raw_name.to_ascii_lowercase();
        let val = raw_val.trim_matches(|c| c == ' ' || c == '\t').to_owned();
        headers.push((name, val));
    }

    Ok(ParsedUpgradeHeaders { status, headers })
}

async fn perform_bounded_upgrade_read<S: AsyncRead + Unpin>(
    stream: &mut S,
    ws_key: &str,
) -> Result<Bytes, WsConnectError> {
    perform_bounded_upgrade_read_with_protocol(stream, ws_key, "mp1").await
}

pub(crate) async fn perform_bounded_upgrade_read_with_protocol<S: AsyncRead + Unpin>(
    stream: &mut S,
    ws_key: &str,
    expected_protocol: &'static str,
) -> Result<Bytes, WsConnectError> {
    // Allow up to MAX_RESPONSE_HEADERS_BYTES for the header section plus 4 bytes for `\r\n\r\n`.
    let max_read_before_delim = MAX_RESPONSE_HEADERS_BYTES + 4;
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            if pos > MAX_RESPONSE_HEADERS_BYTES {
                return Err(WsConnectError::ResponseHeadersTooLarge);
            }
            break pos;
        }
        if buf.len() >= max_read_before_delim {
            return Err(WsConnectError::ResponseHeadersTooLarge);
        }
        let remaining = max_read_before_delim.saturating_sub(buf.len());
        let cap = remaining.min(tmp.len());
        let Some(slice) = tmp.get_mut(..cap) else {
            return Err(WsConnectError::ResponseHeadersTooLarge);
        };
        let n = stream
            .read(slice)
            .await
            .map_err(|e| WsConnectError::Transport(ControlError::Io(e)))?;
        if n == 0 {
            return Err(WsConnectError::Transport(ControlError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before end of WebSocket upgrade headers",
            ))));
        }
        if let Some(read_bytes) = slice.get(..n) {
            buf.extend_from_slice(read_bytes);
        }
    };

    let head_slice = buf
        .get(..header_end)
        .ok_or(WsConnectError::ResponseHeadersTooLarge)?;
    let parsed = parse_upgrade_headers(head_slice)?;
    let body_start = header_end.saturating_add(4);
    let leftover_bytes = buf.get(body_start..).unwrap_or(&[]).to_vec();

    if parsed.status == 401 {
        if let Some(body) = read_bounded_error_body(stream, &parsed.headers, leftover_bytes).await
            && let Ok(err_body) = serde_json::from_slice::<ApiErrorBody>(&body)
            && err_body.error.as_deref() == Some("clock_skew")
            && let Some(server_now_ms) = err_body.server_now_ms
        {
            return Err(WsConnectError::ClockSkew { server_now_ms });
        }
        return Err(WsConnectError::UpgradeRejected(401));
    }

    if parsed.status != 101 {
        return Err(classify_http_status(parsed.status));
    }

    validate_101_headers(&parsed.headers, ws_key, expected_protocol)?;
    Ok(Bytes::from(leftover_bytes))
}

async fn read_bounded_error_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    headers: &[(String, String)],
    initial: Vec<u8>,
) -> Option<Vec<u8>> {
    let is_chunked = headers.iter().any(|(k, v)| {
        k == "transfer-encoding"
            && v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
    });

    if is_chunked {
        return read_bounded_chunked_body(stream, initial).await;
    }

    let content_length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.trim().parse::<usize>().ok());

    let mut body = initial;
    if let Some(target_len) = content_length {
        if target_len > MAX_RESPONSE_BODY_BYTES {
            return None;
        }
        let mut tmp = [0u8; 2048];
        while body.len() < target_len {
            let need = target_len.saturating_sub(body.len()).min(tmp.len());
            let slice = tmp.get_mut(..need)?;
            let n = stream.read(slice).await.ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(slice.get(..n)?);
        }
        body.truncate(target_len);
        return Some(body);
    }

    // Close-delimited fallback bounded strictly at MAX_RESPONSE_BODY_BYTES.
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        return None;
    }
    let mut tmp = [0u8; 2048];
    while body.len() < MAX_RESPONSE_BODY_BYTES {
        let cap = MAX_RESPONSE_BODY_BYTES
            .saturating_sub(body.len())
            .min(tmp.len());
        let slice = tmp.get_mut(..cap)?;
        let n = stream.read(slice).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(slice.get(..n)?);
    }
    Some(body)
}

async fn read_bounded_chunked_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut raw: Vec<u8>,
) -> Option<Vec<u8>> {
    let max_raw = MAX_RESPONSE_BODY_BYTES.saturating_mul(2);
    let mut tmp = [0u8; 2048];
    let mut decoded = Vec::new();
    let mut pos: usize = 0;

    loop {
        // Find chunk-size CRLF
        let crlf_rel = loop {
            if let Some(tail) = raw.get(pos..)
                && let Some(idx) = tail.windows(2).position(|w| w == b"\r\n")
            {
                break idx;
            }
            if raw.len() >= max_raw {
                return None;
            }
            let cap = max_raw.saturating_sub(raw.len()).min(tmp.len());
            let slice = tmp.get_mut(..cap)?;
            let n = stream.read(slice).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(slice.get(..n)?);
        };

        let size_line = std::str::from_utf8(raw.get(pos..pos.saturating_add(crlf_rel))?).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).ok()?;
        pos = pos.saturating_add(crlf_rel).saturating_add(2);

        if chunk_len == 0 {
            return Some(decoded);
        }
        if decoded.len().saturating_add(chunk_len) > MAX_RESPONSE_BODY_BYTES {
            return None;
        }

        let needed_end = pos.saturating_add(chunk_len).saturating_add(2);
        while raw.len() < needed_end {
            if raw.len() >= max_raw {
                return None;
            }
            let cap = max_raw.saturating_sub(raw.len()).min(tmp.len());
            let slice = tmp.get_mut(..cap)?;
            let n = stream.read(slice).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(slice.get(..n)?);
        }

        decoded.extend_from_slice(raw.get(pos..pos.saturating_add(chunk_len))?);
        if raw.get(pos.saturating_add(chunk_len)..needed_end) != Some(b"\r\n".as_slice()) {
            return None;
        }
        pos = needed_end;
    }
}

fn validate_101_headers(
    headers: &[(String, String)],
    ws_key: &str,
    expected_protocol: &'static str,
) -> Result<(), WsConnectError> {
    let mut upgrade_count: usize = 0;
    let mut connection_has_upgrade = false;
    let mut accept_value: Option<&str> = None;
    let mut accept_count: usize = 0;
    let mut proto_value: Option<&str> = None;
    let mut proto_count: usize = 0;

    for (name, val) in headers {
        match name.as_str() {
            "upgrade" => {
                if !val.eq_ignore_ascii_case("websocket") {
                    return Err(WsConnectError::InvalidUpgradeResponse(
                        "Upgrade header is not websocket".to_owned(),
                    ));
                }
                upgrade_count = upgrade_count.saturating_add(1);
            }
            "connection" => {
                if val
                    .split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
                {
                    connection_has_upgrade = true;
                }
            }
            "sec-websocket-accept" => {
                accept_count = accept_count.saturating_add(1);
                accept_value = Some(val.as_str());
            }
            "sec-websocket-protocol" => {
                proto_count = proto_count.saturating_add(1);
                proto_value = Some(val.as_str());
            }
            "sec-websocket-extensions" if !val.is_empty() => {
                return Err(WsConnectError::ForbiddenExtension);
            }
            _ => {}
        }
    }

    if upgrade_count == 0 {
        return Err(WsConnectError::InvalidUpgradeResponse(
            "missing Upgrade: websocket header".to_owned(),
        ));
    }
    if !connection_has_upgrade {
        return Err(WsConnectError::InvalidUpgradeResponse(
            "missing Connection: Upgrade header".to_owned(),
        ));
    }

    let expected_accept = compute_ws_accept(ws_key);
    if accept_count != 1 || accept_value != Some(expected_accept.as_str()) {
        return Err(WsConnectError::InvalidUpgradeResponse(
            "missing or mismatched Sec-WebSocket-Accept header".to_owned(),
        ));
    }

    if proto_count != 1 || proto_value != Some(expected_protocol) {
        if expected_protocol == "mp1" {
            return Err(WsConnectError::MissingMp1Subprotocol);
        }
        return Err(WsConnectError::MissingSubprotocol {
            expected: expected_protocol,
        });
    }

    Ok(())
}

/// Computes RFC 6455 §1.3 `base64(SHA-1(key || GUID))` using our owned FIPS 180-4 SHA-1.
pub(crate) fn compute_ws_accept(ws_key: &str) -> String {
    let mut input = Vec::with_capacity(ws_key.len().saturating_add(RFC6455_WS_GUID.len()));
    input.extend_from_slice(ws_key.as_bytes());
    input.extend_from_slice(RFC6455_WS_GUID);
    B64_STD.encode(sha1_fips180_4(&input))
}

/// Owned, dependency-free, index-free FIPS 180-4 SHA-1 implementation for RFC 6455
/// `Sec-WebSocket-Accept` verification.
fn sha1_fips180_4(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(input.len().saturating_add(72));
    msg.extend_from_slice(input);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let (chunks, _) = msg.as_chunks::<64>();
    for chunk in chunks {
        let mut w = [0u32; 80];
        let (word_chunks, _) = chunk.as_chunks::<4>();
        for (slot, word_bytes) in w.iter_mut().zip(word_chunks) {
            *slot = u32::from_be_bytes(*word_bytes);
        }
        for t in 16usize..80 {
            let a = w.get(t.saturating_sub(3)).copied().unwrap_or(0);
            let b = w.get(t.saturating_sub(8)).copied().unwrap_or(0);
            let c = w.get(t.saturating_sub(14)).copied().unwrap_or(0);
            let d = w.get(t.saturating_sub(16)).copied().unwrap_or(0);
            let val = (a ^ b ^ c ^ d).rotate_left(1);
            if let Some(slot) = w.get_mut(t) {
                *slot = val;
            }
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let words = [h0, h1, h2, h3, h4];
    let mut out = [0u8; 20];
    let (out_chunks, _) = out.as_chunks_mut::<4>();
    for (dst, word) in out_chunks.iter_mut().zip(words) {
        *dst = word.to_be_bytes();
    }
    out
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

#[cfg(test)]
mod tests {
    use super::compute_ws_accept;

    #[test]
    fn rfc6455_sec_websocket_accept_golden_vector() {
        assert_eq!(
            compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
