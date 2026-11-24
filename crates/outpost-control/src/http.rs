//! TLS 1.3-only HTTP/1.1 REST client with strict RFC 9421 + RFC 9530 signing,
//! bounded ingress, idempotency preservation across retries, and scoped `clock_skew` retry.

use core::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use bytes::{Bytes, BytesMut};
use ed25519_dalek::{Signer as _, SigningKey};
use http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use mp_protocol::{
    AccountId, DeviceId, EndpointDescriptor, HttpMethod, KeyId, MAX_SAFE_ID, PartyId,
    PartyInviteId, PartyJoinMode, PartyVisibility, RelayPolicy, RequestId, Rfc9421Error,
    Rfc9421Request, build_signature_base, compute_content_digest, parse_signature_input, sha256,
    validate_path_and_query, validate_relay_url,
};
use serde::{Deserialize, Serialize};

use crate::clock::wall_now_ms;
use crate::tls::{
    DEFAULT_API_AUTHORITY, canonicalize_authority, connect_tls13, default_tls13_client_config,
    parse_authority,
};
use crate::mp2::Mp2RoomSocket;
use crate::ws::{Mp1WsClient, Mp1WsTarget, WsConnectError};

/// Hard cap on inbound HTTP response bodies (`16 KiB`).
pub const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024;
/// Hard cap on inbound HTTP response header section size (`8 KiB`).
pub const MAX_RESPONSE_HEADERS_BYTES: usize = 8 * 1024;
/// Default per-request end-to-end timeout (`15s`).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum absolute `clock_offset_ms` accepted from `401 clock_skew` (`±10 min`).
pub const MAX_CLOCK_OFFSET_MS: i64 = 600_000;
/// Outbound RFC 9421 signature lifetime (`expires = created + 60`).
pub const SIGNATURE_LIFETIME_SECS: i64 = 60;
/// Minimum clamped `retry_after_ms` (`100 ms`).
pub const MIN_RETRY_AFTER_MS: u64 = 100;
/// Maximum clamped `retry_after_ms` (`60_000 ms`).
pub const MAX_RETRY_AFTER_MS: u64 = 60_000;
/// Maximum HTTPS redirects followed by [`ControlClient::fetch_https_bytes`].
pub const MAX_FETCH_REDIRECTS: usize = 3;
/// Overall deadline for [`ControlClient::fetch_https_bytes`] (`60s`).
pub const MAX_FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum number of regional relay entries accepted from `GET /v1/relays`.
pub const MAX_DISCOVERED_RELAYS: usize = 32;
/// Maximum sanitized Unicode scalar count for `region`/`label` in `GET /v1/relays`.
pub const MAX_RELAY_METADATA_CHARS: usize = 64;

const MAX_ERROR_MESSAGE_CHARS: usize = 256;
const MAX_FETCH_URL_BYTES: usize = 8 * 1024;
const FETCH_READ_BUF_BYTES: usize = 64 * 1024;

/// Errors returned by [`ControlClient`] REST calls.
#[derive(Debug)]
pub enum ControlError {
    MissingSigner,
    InvalidAuthority(String),
    InvalidRequest(String),
    InvalidIdempotencyKey,
    TlsConfig(String),
    TlsPolicyViolation(String),
    Rfc9421(Rfc9421Error),
    RandomFailure(String),
    Timeout,
    Io(std::io::Error),
    Http(hyper::Error),
    UnexpectedRedirect { status: u16 },
    ResponseHeadersTooLarge,
    ResponseTooLarge,
    InvalidJsonResponse(String),
    Protocol(String),
    Api {
        status: u16,
        error: String,
        server_now_ms: Option<u64>,
        retry_after_ms: Option<u64>,
        relay_policy: Option<u8>,
        pinned_relay_url: Option<String>,
        raw_body: String,
    },
}

impl ControlError {
    /// If this error is an HTTP `409` `relay_mismatch` API response, returns
    /// `(relay_policy, validated_pinned_relay_url)`.
    pub fn relay_mismatch_info(&self) -> Option<(Option<u8>, Option<&str>)> {
        match self {
            Self::Api {
                status: 409,
                error,
                relay_policy,
                pinned_relay_url,
                ..
            } if error == "relay_mismatch" => Some((*relay_policy, pinned_relay_url.as_deref())),
            _ => None,
        }
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSigner => write!(f, "no device signer configured on ControlClient"),
            Self::InvalidAuthority(a) => write!(f, "invalid control-plane authority: {a}"),
            Self::InvalidRequest(msg) => write!(f, "invalid request: {msg}"),
            Self::InvalidIdempotencyKey => {
                write!(f, "idempotency key must be 16..=64 printable ASCII bytes")
            }
            Self::TlsConfig(msg) => write!(f, "TLS config error: {msg}"),
            Self::TlsPolicyViolation(msg) => write!(f, "TLS policy violation: {msg}"),
            Self::Rfc9421(e) => write!(f, "RFC 9421 error: {e}"),
            Self::RandomFailure(msg) => write!(f, "CSPRNG failure: {msg}"),
            Self::Timeout => write!(f, "control-plane HTTP request timed out"),
            Self::Io(e) => write!(f, "transport I/O error: {e}"),
            Self::Http(e) => write!(f, "HTTP/1.1 protocol error: {e}"),
            Self::UnexpectedRedirect { status } => {
                write!(f, "HTTP redirect {status} refused (zero redirects policy)")
            }
            Self::ResponseHeadersTooLarge => write!(f, "response headers exceed 8 KiB limit"),
            Self::ResponseTooLarge => write!(f, "response body exceeds maximum allowed size"),
            Self::InvalidJsonResponse(msg) => write!(f, "invalid JSON response: {msg}"),
            Self::Protocol(msg) => write!(f, "control-plane protocol violation: {msg}"),
            Self::Api { status, error, .. } => write!(f, "API error HTTP {status}: {error}"),
        }
    }
}

impl std::error::Error for ControlError {}

impl From<Rfc9421Error> for ControlError {
    fn from(e: Rfc9421Error) -> Self {
        Self::Rfc9421(e)
    }
}

/// Ed25519 request-signing identity (`<account_id>.<device_id>`, `<account_id>.root`,
/// `reg.<sha256(root_pubkey)[..16]>`, `rec.<sha256(root_pubkey)[..16]>`,
/// or `link.<sha256(device_pubkey)[..16]>`).
#[derive(Clone)]
pub struct RequestSigner {
    key_id: KeyId,
    signing_key: SigningKey,
}

impl fmt::Debug for RequestSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestSigner")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

fn sha256_prefix16(pubkey: &[u8; 32]) -> [u8; 16] {
    let digest = sha256(pubkey);
    let mut prefix = [0u8; 16];
    if let Some(head) = digest.get(..16) {
        prefix.copy_from_slice(head);
    }
    prefix
}

impl RequestSigner {
    /// Creates an enrolled device signer (`<account_id>.<device_id>`).
    pub fn device(account_id: AccountId, device_id: DeviceId, device_secret: [u8; 32]) -> Self {
        Self {
            key_id: KeyId::Device {
                account_id,
                device_id,
            },
            signing_key: SigningKey::from_bytes(&device_secret),
        }
    }

    /// Creates a root signer (`<account_id>.root`). Never store this inside daemon RAM!
    pub fn root(account_id: AccountId, root_secret: [u8; 32]) -> Self {
        Self {
            key_id: KeyId::Root { account_id },
            signing_key: SigningKey::from_bytes(&root_secret),
        }
    }

    /// Creates a registration signer (`reg.<sha256(root_pubkey)[..16]>`).
    pub fn registration(root_secret: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&root_secret);
        let pubkey = signing_key.verifying_key().to_bytes();
        Self {
            key_id: KeyId::Registration {
                root_pubkey_sha256_prefix: sha256_prefix16(&pubkey),
            },
            signing_key,
        }
    }

    /// Creates an account recovery lookup signer (`rec.<sha256(root_pubkey)[..16]>`).
    pub fn recovery(root_secret: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&root_secret);
        let pubkey = signing_key.verifying_key().to_bytes();
        Self {
            key_id: KeyId::Recovery {
                root_pubkey_sha256_prefix: sha256_prefix16(&pubkey),
            },
            signing_key,
        }
    }

    /// Creates a device-link PoP signer (`link.<sha256(device_pubkey)[..16]>`).
    pub fn device_link(device_secret: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&device_secret);
        let pubkey = signing_key.verifying_key().to_bytes();
        Self {
            key_id: KeyId::DeviceLink {
                device_pubkey_sha256_prefix: sha256_prefix16(&pubkey),
            },
            signing_key,
        }
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn verifying_pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

/// Signed RFC 9421 + RFC 9530 header values for a single outbound request attempt.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub signature_input: String,
    pub signature: String,
    pub content_type: Option<&'static str>,
    pub content_digest: Option<String>,
    pub nonce: String,
    pub created: i64,
    pub expires: i64,
}

/// Generates a fresh 24-byte CSPRNG base64url (no-pad, 32-char) nonce via `getrandom`.
pub fn generate_nonce() -> Result<String, ControlError> {
    let mut raw = [0u8; 24];
    getrandom::getrandom(&mut raw).map_err(|e| ControlError::RandomFailure(e.to_string()))?;
    Ok(B64_URL.encode(raw))
}

/// Signs an outbound HTTP/1.1 or WebSocket Upgrade request using strict RFC 9421 + RFC 9530 (`mp1`).
///
/// `clock_offset_ms` is applied ONLY to this outbound signing timestamp (clamped to `±10 min`),
/// never to local or peer CWT verification.
pub fn sign_request(
    signer: &RequestSigner,
    method: HttpMethod,
    authority: &str,
    path: &str,
    query: &str,
    body: &[u8],
    clock_offset_ms: i64,
) -> Result<SignedHeaders, ControlError> {
    validate_path_and_query(method, path, query)?;
    if !method.requires_body_headers() && !body.is_empty() {
        return Err(ControlError::Rfc9421(Rfc9421Error::UnexpectedBodyOnGet));
    }

    let clamped_offset = clock_offset_ms.clamp(-MAX_CLOCK_OFFSET_MS, MAX_CLOCK_OFFSET_MS);
    let now_ms_i64 = i64::try_from(wall_now_ms()).unwrap_or(i64::MAX);
    let adjusted_ms = now_ms_i64.saturating_add(clamped_offset);
    let created = adjusted_ms.div_euclid(1_000);
    let expires = created.saturating_add(SIGNATURE_LIFETIME_SECS);
    let nonce = generate_nonce()?;
    let keyid_str = signer.key_id.format();

    let (components, content_type, content_digest) = if method.requires_body_headers() {
        let cd = compute_content_digest(body);
        (
            r#"("@method" "@authority" "@path" "@query" "content-type" "content-digest")"#,
            Some("application/json"),
            Some(cd),
        )
    } else {
        (r#"("@method" "@authority" "@path" "@query")"#, None, None)
    };

    let signature_input = format!(
        r#"mp1={components};created={created};expires={expires};nonce="{nonce}";keyid="{keyid_str}";alg="ed25519";tag="mp1""#
    );

    let parsed = parse_signature_input(&signature_input)?;
    let rfc_req = Rfc9421Request {
        method,
        authority,
        path,
        query,
        content_type,
        content_digest: content_digest.as_deref(),
        has_content_encoding: false,
        body,
        signature_input: &signature_input,
        signature: "",
    };
    let sig_base = build_signature_base(&rfc_req, &parsed)?;
    let sig = signer.signing_key.sign(&sig_base);
    let signature = format!("mp1=:{}:", B64_STD.encode(sig.to_bytes()));

    Ok(SignedHeaders {
        signature_input,
        signature,
        content_type,
        content_digest,
        nonce,
        created,
        expires,
    })
}

/// Configuration for [`ControlClient`] and [`Mp1WsClient`].
#[derive(Clone)]
pub struct ControlClientConfig {
    /// Canonical authority (`Host`, TLS SNI, and RFC 9421 `@authority`), e.g. `"api.multiplayer.tech"`.
    pub authority: String,
    /// TLS 1.3-only client configuration (default: `webpki-roots`, HTTP/1.1 ALPN, 0-RTT off).
    pub tls_config: Arc<rustls::ClientConfig>,
    /// Optional TCP connect address override (e.g. `127.0.0.1:<port>` for local TLS 1.3 tests)
    /// while still pinning SNI, `Host`, and `@authority` to `authority`.
    pub connect_addr: Option<SocketAddr>,
    /// Per-request end-to-end timeout (default: `15s`).
    pub request_timeout: Duration,
}

impl fmt::Debug for ControlClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlClientConfig")
            .field("authority", &self.authority)
            .field("connect_addr", &self.connect_addr)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl ControlClientConfig {
    /// Creates a production config pinned to `api.multiplayer.tech` with TLS 1.3 + `webpki-roots`.
    pub fn production() -> Result<Self, ControlError> {
        Self::new(DEFAULT_API_AUTHORITY)
    }

    /// Creates a config pinned to a custom canonical authority with default TLS 1.3 `webpki-roots`.
    ///
    /// Canonicalizes the authority by lowercasing the ASCII hostname and stripping default `:443`.
    pub fn new(authority: impl Into<String>) -> Result<Self, ControlError> {
        let raw = authority.into();
        let authority = canonicalize_authority(&raw)?;
        Ok(Self {
            authority,
            tls_config: default_tls13_client_config()?,
            connect_addr: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Overrides the `rustls::ClientConfig` (e.g., with a test trust store).
    pub fn with_tls_config(mut self, tls_config: Arc<rustls::ClientConfig>) -> Self {
        self.tls_config = tls_config;
        self
    }

    /// Overrides the TCP dial address while keeping SNI/`Host`/`@authority` pinned to `authority`.
    pub fn with_connect_addr(mut self, addr: SocketAddr) -> Self {
        self.connect_addr = Some(addr);
        self
    }

    /// Overrides the per-request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

/// TLS 1.3-only HTTP/1.1 REST client for `api.multiplayer.tech`.
#[derive(Clone)]
pub struct ControlClient {
    config: ControlClientConfig,
    device_signer: Option<RequestSigner>,
    /// Scoped outbound-RFC-9421-only clock offset in milliseconds, clamped to `±600_000 ms`.
    clock_offset_ms: Arc<AtomicI64>,
}

impl fmt::Debug for ControlClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlClient")
            .field("config", &self.config)
            .field("has_device_signer", &self.device_signer.is_some())
            .field("clock_offset_ms", &self.clock_offset_ms())
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorBody {
    pub(crate) error: Option<String>,
    pub(crate) server_now_ms: Option<u64>,
    pub(crate) retry_after_ms: Option<u64>,
    pub(crate) relay_policy: Option<u8>,
    pub(crate) pinned_relay_url: Option<String>,
}

/// RAII guard that aborts a spawned HTTP/1.1 connection driver task on drop
/// (including timeout cancellation and early error returns).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Raw bounded HTTP response.
#[derive(Debug, Clone)]
pub struct RawHttpResponse {
    pub status: u16,
    pub body: Bytes,
    pub retry_after_ms: Option<u64>,
}

impl ControlClient {
    /// Creates a new unauthenticated/root-only client (no default device key attached).
    pub fn new(config: ControlClientConfig) -> Self {
        Self {
            config,
            device_signer: None,
            clock_offset_ms: Arc::new(AtomicI64::new(0)),
        }
    }

    /// Creates a client with a default enrolled device signer for device-authenticated endpoints.
    pub fn with_device_signer(config: ControlClientConfig, device_signer: RequestSigner) -> Self {
        Self {
            config,
            device_signer: Some(device_signer),
            clock_offset_ms: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn config(&self) -> &ControlClientConfig {
        &self.config
    }

    /// Returns the current outbound-signing-only `clock_offset_ms` (clamped to `±600_000 ms`).
    /// Never use this offset for local or peer CWT verification!
    pub fn clock_offset_ms(&self) -> i64 {
        self.clock_offset_ms
            .load(Ordering::Relaxed)
            .clamp(-MAX_CLOCK_OFFSET_MS, MAX_CLOCK_OFFSET_MS)
    }

    /// Updates the scoped outbound-signing-only `clock_offset_ms` from a server timestamp,
    /// clamping strictly to `±600_000 ms` (`±10 min`).
    pub fn record_server_clock_ms(&self, server_now_ms: u64) -> i64 {
        let local_ms = i64::try_from(wall_now_ms()).unwrap_or(i64::MAX);
        let server_ms = i64::try_from(server_now_ms).unwrap_or(i64::MAX);
        let clamped = server_ms
            .saturating_sub(local_ms)
            .clamp(-MAX_CLOCK_OFFSET_MS, MAX_CLOCK_OFFSET_MS);
        self.clock_offset_ms.store(clamped, Ordering::Relaxed);
        clamped
    }

    /// Connects an RFC 6455 `MP1` WebSocket over the same TLS 1.3-only configuration using
    /// the client's default device signer and scoped outbound `clock_offset_ms`.
    pub async fn connect_ws(&self, target: Mp1WsTarget) -> Result<Mp1WsClient, WsConnectError> {
        let signer = self
            .device_signer
            .as_ref()
            .ok_or(WsConnectError::MissingSigner)?;
        self.connect_ws_with_signer(signer, target).await
    }

    /// Connects an RFC 6455 `MP1` WebSocket with an explicit signer.
    ///
    /// Automatically handles a single `401 clock_skew` upgrade rejection by updating
    /// the scoped outbound-signing `clock_offset_ms` and retrying once with a fresh
    /// RFC 9421 nonce and timestamp.
    pub async fn connect_ws_with_signer(
        &self,
        signer: &RequestSigner,
        target: Mp1WsTarget,
    ) -> Result<Mp1WsClient, WsConnectError> {
        match Mp1WsClient::connect(&self.config, signer, self.clock_offset_ms(), target).await {
            Err(WsConnectError::ClockSkew { server_now_ms }) => {
                let _ = self.record_server_clock_ms(server_now_ms);
                Mp1WsClient::connect(&self.config, signer, self.clock_offset_ms(), target).await
            }
            other => other,
        }
    }

    /// Connects an RFC 6455 `mp2` Room WebSocket (`GET /v1/parties/<party_id>/ws`,
    /// `Sec-WebSocket-Protocol: mp2`) with automatic single `401 clock_skew` retry.
    pub async fn connect_mp2_room(&self, party_id: PartyId) -> Result<Mp2RoomSocket, WsConnectError> {
        let signer = self
            .device_signer
            .as_ref()
            .ok_or(WsConnectError::MissingSigner)?;
        self.connect_mp2_room_with_signer(signer, party_id).await
    }

    /// Connects an `mp2` Room WebSocket to an explicit `ws_path` (e.g. `"/v1/parties/12345/ws"`)
    /// with automatic single `401 clock_skew` retry.
    pub async fn connect_mp2_room_path(&self, path: &str) -> Result<Mp2RoomSocket, WsConnectError> {
        let signer = self
            .device_signer
            .as_ref()
            .ok_or(WsConnectError::MissingSigner)?;
        match Mp2RoomSocket::connect_path(&self.config, signer, self.clock_offset_ms(), path).await
        {
            Err(WsConnectError::ClockSkew { server_now_ms }) => {
                let _ = self.record_server_clock_ms(server_now_ms);
                Mp2RoomSocket::connect_path(&self.config, signer, self.clock_offset_ms(), path)
                    .await
            }
            other => other,
        }
    }

    /// Connects an `mp2` Room WebSocket with an explicit signer and automatic single `clock_skew` retry.
    pub async fn connect_mp2_room_with_signer(
        &self,
        signer: &RequestSigner,
        party_id: PartyId,
    ) -> Result<Mp2RoomSocket, WsConnectError> {
        match Mp2RoomSocket::connect_party(&self.config, signer, self.clock_offset_ms(), party_id)
            .await
        {
            Err(WsConnectError::ClockSkew { server_now_ms }) => {
                let _ = self.record_server_clock_ms(server_now_ms);
                Mp2RoomSocket::connect_party(&self.config, signer, self.clock_offset_ms(), party_id)
                    .await
            }
            other => other,
        }
    }

    fn require_device_signer(&self) -> Result<&RequestSigner, ControlError> {
        self.device_signer
            .as_ref()
            .ok_or(ControlError::MissingSigner)
    }

    /// Executes an unsigned HTTP/1.1 GET request (used for `/v1/health`).
    async fn execute_unsigned_get(&self, path: &str) -> Result<RawHttpResponse, ControlError> {
        validate_path_and_query(HttpMethod::Get, path, "?")?;
        self.send_http1_once(HttpMethod::Get, path, "?", Bytes::new(), None, None)
            .await
    }

    /// Executes an unsigned HTTP/1.1 JSON POST request (used for `/v1/auth/session/start` & `poll`).
    async fn execute_unsigned_post(
        &self,
        path: &str,
        body: Bytes,
    ) -> Result<RawHttpResponse, ControlError> {
        validate_path_and_query(HttpMethod::Post, path, "?")?;
        self.send_http1_once(HttpMethod::Post, path, "?", body, None, None)
            .await
    }

    /// Executes a signed HTTP/1.1 request with automatic single `clock_skew` retry.
    ///
    /// Across the retry:
    /// - Preserves the EXACT same `idempotency_key` and `body` bytes (including `expected_party_epoch`).
    /// - Generates a FRESH RFC 9421 nonce, timestamp, and Ed25519 signature per attempt.
    pub async fn execute_signed(
        &self,
        signer: &RequestSigner,
        method: HttpMethod,
        path: &str,
        query: &str,
        body: Bytes,
        idempotency_key: Option<&str>,
    ) -> Result<RawHttpResponse, ControlError> {
        if let Some(key) = idempotency_key {
            validate_idempotency_key(key)?;
        }
        validate_path_and_query(method, path, query)?;

        let canonical_authority = canonicalize_authority(&self.config.authority)?;
        for attempt in 0..2u8 {
            let signed = sign_request(
                signer,
                method,
                &canonical_authority,
                path,
                query,
                &body,
                self.clock_offset_ms(),
            )?;
            let resp = self
                .send_http1_once(
                    method,
                    path,
                    query,
                    body.clone(),
                    Some(&signed),
                    idempotency_key,
                )
                .await?;

            if attempt == 0
                && resp.status == StatusCode::UNAUTHORIZED.as_u16()
                && let Ok(err_body) = serde_json::from_slice::<ApiErrorBody>(&resp.body)
                && err_body.error.as_deref() == Some("clock_skew")
                && let Some(server_now_ms) = err_body.server_now_ms
            {
                let _ = self.record_server_clock_ms(server_now_ms);
                continue;
            }

            return Ok(resp);
        }

        Err(ControlError::InvalidRequest(
            "unreachable retry loop exit".to_owned(),
        ))
    }

    async fn send_http1_once(
        &self,
        method: HttpMethod,
        path: &str,
        query: &str,
        body: Bytes,
        signed: Option<&SignedHeaders>,
        idempotency_key: Option<&str>,
    ) -> Result<RawHttpResponse, ControlError> {
        send_http1_raw(
            &self.config.authority,
            self.config.connect_addr,
            &self.config.tls_config,
            self.config.request_timeout,
            method,
            path,
            query,
            body,
            signed,
            idempotency_key,
        )
        .await
    }

    fn decode_json_response<T: serde::de::DeserializeOwned>(
        resp: RawHttpResponse,
        expected_statuses: &[u16],
    ) -> Result<T, ControlError> {
        if !expected_statuses.contains(&resp.status) {
            return Err(parse_api_error(resp));
        }
        serde_json::from_slice(&resp.body)
            .map_err(|e| ControlError::InvalidJsonResponse(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Typed REST API Methods covering all `/v1/*` endpoints
    // -----------------------------------------------------------------------

    /// `GET /v1/health` (unauthenticated).
    pub async fn health(&self) -> Result<HealthResponse, ControlError> {
        let resp = self.execute_unsigned_get("/v1/health").await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `GET /v1/relays` (unauthenticated regional relay discovery).
    ///
    /// Enforces TLS 1.3-only, zero redirects, `<= 16 KiB` body cap, `relays.len() <= 32`,
    /// strict HTTPS public-FQDN relay URL validation on `default_relay_url` and every
    /// `relay.url`, and `<= 64`-char sanitization on `region` and `label`.
    pub async fn list_relays(&self) -> Result<RelaysResponse, ControlError> {
        let resp = self.execute_unsigned_get("/v1/relays").await?;
        let mut decoded: RelaysResponse = Self::decode_json_response(resp, &[200])?;
        validate_discovered_relay_url(&decoded.default_relay_url, "default_relay_url")?;
        if decoded.relays.len() > MAX_DISCOVERED_RELAYS {
            return Err(ControlError::Protocol(format!(
                "GET /v1/relays returned {} entries (max {MAX_DISCOVERED_RELAYS})",
                decoded.relays.len()
            )));
        }
        for relay in &mut decoded.relays {
            validate_discovered_relay_url(&relay.url, "relay.url")?;
            relay.region = sanitize_untrusted_text(&relay.region, MAX_RELAY_METADATA_CHARS);
            relay.label = sanitize_untrusted_text(&relay.label, MAX_RELAY_METADATA_CHARS);
        }
        Ok(decoded)
    }

    /// `POST /v1/accounts/register` (`reg.<sha256(root_pk)[..16]>`, explicit `Idempotency-Key`).
    pub async fn register_account(
        &self,
        root_secret: [u8; 32],
        idempotency_key: &str,
        req: &RegisterAccountRequest,
    ) -> Result<RegisterAccountResponse, ControlError> {
        let signer = RequestSigner::registration(root_secret);
        let root_pubkey = signer.verifying_pubkey();
        let wire = RegisterAccountWire {
            invite_secret: &req.invite_secret,
            handle: &req.handle,
            root_pubkey_b64: B64_STD.encode(root_pubkey),
            device_pubkey_b64: B64_STD.encode(req.device_pubkey),
            device_label: &req.device_label,
            device_cwt_b64: B64_STD.encode(&req.device_cwt),
        };
        let body = encode_json(&wire)?;
        let resp = self
            .execute_signed(
                &signer,
                HttpMethod::Post,
                "/v1/accounts/register",
                "?",
                body,
                Some(idempotency_key),
            )
            .await?;
        Self::decode_json_response(resp, &[201])
    }

    /// `GET /v1/accounts/me` (device or root).
    pub async fn get_me(&self) -> Result<AccountMeResponse, ControlError> {
        let signer = self.require_device_signer()?;
        self.get_me_with_signer(signer).await
    }

    /// `GET /v1/accounts/me` with an explicit signer.
    pub async fn get_me_with_signer(
        &self,
        signer: &RequestSigner,
    ) -> Result<AccountMeResponse, ControlError> {
        let resp = self
            .execute_signed(signer, HttpMethod::Get, "/v1/accounts/me", "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `GET /v1/accounts/<account_id>`.
    pub async fn get_account(
        &self,
        account_id: AccountId,
    ) -> Result<PublicAccountResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/accounts/{account_id}");
        let resp = self
            .execute_signed(signer, HttpMethod::Get, &path, "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `GET /v1/accounts/resolve?handle=<handle>`.
    pub async fn resolve_handle(&self, handle: &str) -> Result<ResolvedHandleResponse, ControlError> {
        let signer = self.require_device_signer()?;
        if handle.is_empty()
            || handle.len() > 64
            || !handle
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(ControlError::InvalidRequest(
                "handle contains invalid characters for query".to_owned(),
            ));
        }
        let query = format!("?handle={handle}");
        let resp = self
            .execute_signed(
                signer,
                HttpMethod::Get,
                "/v1/accounts/resolve",
                &query,
                Bytes::new(),
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `PATCH /v1/accounts/me/handle` (`.root` required).
    pub async fn rename_handle(
        &self,
        root_signer: &RequestSigner,
        handle: &str,
    ) -> Result<RenameHandleResponse, ControlError> {
        require_root_signer(root_signer)?;
        let body = encode_json(&RenameHandleWire { handle })?;
        let resp = self
            .execute_signed(
                root_signer,
                HttpMethod::Patch,
                "/v1/accounts/me/handle",
                "?",
                body,
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/devices` (`.root` required).
    pub async fn enroll_device(
        &self,
        root_signer: &RequestSigner,
        req: &EnrollDeviceRequest,
    ) -> Result<EnrollDeviceResponse, ControlError> {
        require_root_signer(root_signer)?;
        let wire = EnrollDeviceWire {
            device_pubkey_b64: B64_STD.encode(req.device_pubkey),
            device_label: &req.device_label,
            device_cwt_b64: B64_STD.encode(&req.device_cwt),
        };
        let body = encode_json(&wire)?;
        let resp = self
            .execute_signed(root_signer, HttpMethod::Post, "/v1/devices", "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[201])
    }

    /// `PUT /v1/devices/<device_id>/cwt` (`.root` required).
    pub async fn renew_device_cwt(
        &self,
        root_signer: &RequestSigner,
        device_id: DeviceId,
        device_cwt: &[u8],
    ) -> Result<RenewDeviceCwtResponse, ControlError> {
        require_root_signer(root_signer)?;
        let path = format!("/v1/devices/{device_id}/cwt");
        let body = encode_json(&RenewDeviceCwtWire {
            device_cwt_b64: B64_STD.encode(device_cwt),
        })?;
        let resp = self
            .execute_signed(root_signer, HttpMethod::Put, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `DELETE /v1/devices/<device_id>` (`.root` required).
    pub async fn revoke_device(
        &self,
        root_signer: &RequestSigner,
        device_id: DeviceId,
    ) -> Result<RevokeDeviceResponse, ControlError> {
        require_root_signer(root_signer)?;
        let path = format!("/v1/devices/{device_id}");
        let resp = self
            .execute_signed(root_signer, HttpMethod::Delete, &path, "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `GET /v1/friends`.
    pub async fn list_friends(&self) -> Result<ListFriendsResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let resp = self
            .execute_signed(signer, HttpMethod::Get, "/v1/friends", "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/friends/requests` (returns HTTP 202 when sent or 200 when mutually accepted).
    pub async fn send_friend_request(
        &self,
        target_account_id: AccountId,
    ) -> Result<FriendRequestResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let body = encode_json(&TargetAccountWire {
            target_account_id: target_account_id.get(),
        })?;
        let resp = self
            .execute_signed(
                signer,
                HttpMethod::Post,
                "/v1/friends/requests",
                "?",
                body,
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200, 202])
    }

    /// `DELETE /v1/friends/<target_account_id>`.
    pub async fn remove_friend(
        &self,
        target_account_id: AccountId,
    ) -> Result<RemoveFriendResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/friends/{target_account_id}");
        let resp = self
            .execute_signed(signer, HttpMethod::Delete, &path, "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/friends/<target_account_id>/block`.
    pub async fn block_account(
        &self,
        target_account_id: AccountId,
    ) -> Result<BlockAccountResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/friends/{target_account_id}/block");
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties`.
    pub async fn create_party(
        &self,
        req: &CreatePartyRequest,
    ) -> Result<CreatePartyResponse, ControlError> {
        self.create_party_with_scope(req, None, None).await
    }

    /// `POST /v1/parties` with optional organization/group scoping (`org_id`, `group_id`).
    ///
    /// Rejects `org_id` or `group_id` outside `1..=MAX_SAFE_ID` locally before sending.
    pub async fn create_party_with_scope(
        &self,
        req: &CreatePartyRequest,
        org_id: Option<u64>,
        group_id: Option<u64>,
    ) -> Result<CreatePartyResponse, ControlError> {
        if let Some(id) = org_id
            && (id == 0 || id > MAX_SAFE_ID)
        {
            return Err(ControlError::InvalidRequest(format!(
                "org_id must be in 1..={MAX_SAFE_ID}"
            )));
        }
        if let Some(id) = group_id
            && (id == 0 || id > MAX_SAFE_ID)
        {
            return Err(ControlError::InvalidRequest(format!(
                "group_id must be in 1..={MAX_SAFE_ID}"
            )));
        }
        let signer = self.require_device_signer()?;
        let endpoint_bytes = req
            .endpoint
            .encode()
            .map_err(|e| ControlError::InvalidRequest(format!("invalid endpoint: {e}")))?;
        let wire = CreatePartyWire {
            visibility: req.visibility as u8,
            join_mode: req.join_mode as u8,
            relay_policy: req.relay_policy as u8,
            max_members: req.max_members,
            endpoint_b64: B64_STD.encode(endpoint_bytes),
            relay_url: req.relay_url.as_deref(),
            org_id,
            group_id,
        };
        let body = encode_json(&wire)?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, "/v1/parties", "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[201])
    }

    /// `GET /v1/parties/<party_id>`.
    pub async fn get_party(&self, party_id: PartyId) -> Result<PartySummaryResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}");
        let resp = self
            .execute_signed(signer, HttpMethod::Get, &path, "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties/<party_id>/join`.
    pub async fn join_party(
        &self,
        party_id: PartyId,
        req: &JoinPartyRequest,
    ) -> Result<JoinPartyResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let endpoint_bytes = req
            .endpoint
            .encode()
            .map_err(|e| ControlError::InvalidRequest(format!("invalid endpoint: {e}")))?;
        let wire = JoinPartyWire {
            endpoint_b64: B64_STD.encode(endpoint_bytes),
            invite_link: req.invite_link.as_deref(),
        };
        let path = format!("/v1/parties/{party_id}/join");
        let body = encode_json(&wire)?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200, 202])
    }

    /// `POST /v1/parties/<party_id>/leave`.
    pub async fn leave_party(&self, party_id: PartyId) -> Result<LeavePartyResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/leave");
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties/<party_id>/disband`.
    pub async fn disband_party(
        &self,
        party_id: PartyId,
        expected_party_epoch: u64,
    ) -> Result<DisbandPartyResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/disband");
        let body = encode_json(&ExpectedEpochWire {
            expected_party_epoch,
        })?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties/<party_id>/kick`.
    pub async fn kick_member(
        &self,
        party_id: PartyId,
        target_account_id: AccountId,
        expected_party_epoch: u64,
    ) -> Result<KickMemberResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/kick");
        let body = encode_json(&KickMemberWire {
            target_account_id: target_account_id.get(),
            expected_party_epoch,
        })?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties/<party_id>/promote`.
    pub async fn promote_member(
        &self,
        party_id: PartyId,
        target_device_id: DeviceId,
        expected_party_epoch: u64,
    ) -> Result<PromoteMemberResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/promote");
        let body = encode_json(&PromoteMemberWire {
            target_device_id: target_device_id.get(),
            expected_party_epoch,
        })?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties/<party_id>/invites`.
    pub async fn mint_party_invite(
        &self,
        party_id: PartyId,
        req: &MintPartyInviteRequest,
    ) -> Result<MintPartyInviteResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/invites");
        let wire = MintPartyInviteWire {
            target_account_id: req.target_account_id.map(AccountId::get),
            max_uses: req.max_uses,
            ttl_sec: req.ttl_sec,
        };
        let body = encode_json(&wire)?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[201])
    }

    /// `DELETE /v1/parties/<party_id>/invites/<party_invite_id>`.
    pub async fn revoke_party_invite(
        &self,
        party_id: PartyId,
        party_invite_id: PartyInviteId,
    ) -> Result<RevokePartyInviteResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/invites/{party_invite_id}");
        let resp = self
            .execute_signed(signer, HttpMethod::Delete, &path, "?", Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `GET /v1/parties/<party_id>/requests[?cursor=<cursor>]`.
    pub async fn list_party_requests(
        &self,
        party_id: PartyId,
        cursor: Option<u64>,
    ) -> Result<ListPartyRequestsResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/requests");
        let query = match cursor {
            Some(c) if c > 0 => format!("?cursor={c}"),
            _ => "?".to_owned(),
        };
        let resp = self
            .execute_signed(signer, HttpMethod::Get, &path, &query, Bytes::new(), None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties/<party_id>/requests/<request_id>/approve`.
    pub async fn approve_party_request(
        &self,
        party_id: PartyId,
        request_id: RequestId,
        req: &ApprovePartyRequest,
    ) -> Result<ApprovePartyRequestResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/requests/{request_id}/approve");
        let wire = ApprovePartyRequestWire {
            expected_party_epoch: req.expected_party_epoch,
            account_id: req.account_id.get(),
            device_id: req.device_id.get(),
            device_pubkey_sha256_hex: to_lower_hex(&req.device_pubkey_sha256),
        };
        let body = encode_json(&wire)?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/parties/<party_id>/requests/<request_id>/reject`.
    pub async fn reject_party_request(
        &self,
        party_id: PartyId,
        request_id: RequestId,
        expected_party_epoch: Option<u64>,
    ) -> Result<RejectPartyRequestResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let path = format!("/v1/parties/{party_id}/requests/{request_id}/reject");
        let body = encode_json(&RejectPartyRequestWire {
            expected_party_epoch,
        })?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, &path, "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    // -----------------------------------------------------------------------
    // Identity Portability & Web Portal Endpoints
    // -----------------------------------------------------------------------

    /// `POST /v1/accounts/recover-lookup` (`rec.<sha256(root_pubkey)[..16]>` PoP).
    pub async fn recover_lookup(
        &self,
        root_secret: [u8; 32],
    ) -> Result<RecoverLookupResponse, ControlError> {
        let signer = RequestSigner::recovery(root_secret);
        let root_pubkey = signer.verifying_pubkey();
        let body = encode_json(&RecoverLookupWire {
            root_pubkey_b64: B64_STD.encode(root_pubkey),
        })?;
        let resp = self
            .execute_signed(
                &signer,
                HttpMethod::Post,
                "/v1/accounts/recover-lookup",
                "?",
                body,
                None,
            )
            .await?;
        let decoded: RecoverLookupResponse = Self::decode_json_response(resp, &[200])?;
        validate_account_id(decoded.account_id, "recover_lookup")?;
        for dev in &decoded.devices {
            validate_device_id(dev.device_id, "recover_lookup")?;
        }
        Ok(decoded)
    }

    /// `POST /v1/web-sessions/inspect` (using the client's device signer).
    pub async fn web_session_inspect(
        &self,
        user_code: &str,
    ) -> Result<WebSessionInspectResponse, ControlError> {
        let signer = self.require_device_signer()?;
        self.web_session_inspect_with_signer(signer, user_code)
            .await
    }

    /// `POST /v1/web-sessions/inspect` with an explicit device or `.root` signer.
    pub async fn web_session_inspect_with_signer(
        &self,
        signer: &RequestSigner,
        user_code: &str,
    ) -> Result<WebSessionInspectResponse, ControlError> {
        require_device_or_root_signer(signer)?;
        let body = encode_json(&WebSessionCodeWire { user_code })?;
        let resp = self
            .execute_signed(
                signer,
                HttpMethod::Post,
                "/v1/web-sessions/inspect",
                "?",
                body,
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/web-sessions/approve` (using the client's device signer).
    pub async fn web_session_approve(
        &self,
        user_code: &str,
    ) -> Result<WebSessionApproveResponse, ControlError> {
        let signer = self.require_device_signer()?;
        self.web_session_approve_with_signer(signer, user_code)
            .await
    }

    /// `POST /v1/web-sessions/approve` with an explicit device or `.root` signer.
    pub async fn web_session_approve_with_signer(
        &self,
        signer: &RequestSigner,
        user_code: &str,
    ) -> Result<WebSessionApproveResponse, ControlError> {
        require_device_or_root_signer(signer)?;
        let body = encode_json(&WebSessionCodeWire { user_code })?;
        let resp = self
            .execute_signed(
                signer,
                HttpMethod::Post,
                "/v1/web-sessions/approve",
                "?",
                body,
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/device-links/create` (`.root` required).
    pub async fn device_link_create(
        &self,
        root_signer: &RequestSigner,
        device_label: Option<&str>,
    ) -> Result<DeviceLinkCreateResponse, ControlError> {
        require_root_signer(root_signer)?;
        let body = encode_json(&DeviceLinkCreateWire { device_label })?;
        let resp = self
            .execute_signed(
                root_signer,
                HttpMethod::Post,
                "/v1/device-links/create",
                "?",
                body,
                None,
            )
            .await?;
        let decoded: DeviceLinkCreateResponse = Self::decode_json_response(resp, &[201])?;
        validate_link_code(&decoded.link_code)?;
        Ok(decoded)
    }

    /// `POST /v1/device-links/claim` (`link.<sha256(device_pubkey)[..16]>` PoP).
    pub async fn device_link_claim(
        &self,
        device_secret: [u8; 32],
        link_code: &str,
        device_label: Option<&str>,
    ) -> Result<DeviceLinkClaimResponse, ControlError> {
        let signer = RequestSigner::device_link(device_secret);
        let device_pubkey = signer.verifying_pubkey();
        let body = encode_json(&DeviceLinkClaimWire {
            link_code,
            device_pubkey_b64: B64_STD.encode(device_pubkey),
            device_label,
        })?;
        let resp = self
            .execute_signed(
                &signer,
                HttpMethod::Post,
                "/v1/device-links/claim",
                "?",
                body,
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/device-links/inspect` (`.root` required).
    pub async fn device_link_inspect(
        &self,
        root_signer: &RequestSigner,
        link_code: &str,
    ) -> Result<DeviceLinkInspectResponse, ControlError> {
        require_root_signer(root_signer)?;
        let body = encode_json(&DeviceLinkInspectWire { link_code })?;
        let resp = self
            .execute_signed(
                root_signer,
                HttpMethod::Post,
                "/v1/device-links/inspect",
                "?",
                body,
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/device-links/approve` (`.root` required).
    pub async fn device_link_approve(
        &self,
        root_signer: &RequestSigner,
        req: &DeviceLinkApproveRequest,
    ) -> Result<DeviceLinkApproveResponse, ControlError> {
        require_root_signer(root_signer)?;
        let body = encode_json(&DeviceLinkApproveWire {
            link_code: &req.link_code,
            device_pubkey_b64: B64_STD.encode(req.device_pubkey),
            device_cwt_b64: B64_STD.encode(&req.device_cwt),
            device_label: req.device_label.as_deref(),
        })?;
        let resp = self
            .execute_signed(
                root_signer,
                HttpMethod::Post,
                "/v1/device-links/approve",
                "?",
                body,
                None,
            )
            .await?;
        let decoded: DeviceLinkApproveResponse = Self::decode_json_response(resp, &[200])?;
        validate_account_id(decoded.account_id, "device_link_approve")?;
        validate_device_id(decoded.device_id, "device_link_approve")?;
        Ok(decoded)
    }

    /// `POST /v1/device-links/poll` (`link.<sha256(device_pubkey)[..16]>` PoP).
    ///
    /// Handles both `202 Accepted` (`Pending`) and `200 OK` (`Approved`).
    pub async fn device_link_poll(
        &self,
        device_secret: [u8; 32],
        link_code: &str,
        poll_token: &str,
    ) -> Result<DeviceLinkPollResponse, ControlError> {
        let signer = RequestSigner::device_link(device_secret);
        let device_pubkey = signer.verifying_pubkey();
        let body = encode_json(&DeviceLinkPollWire {
            link_code,
            poll_token,
            device_pubkey_b64: B64_STD.encode(device_pubkey),
        })?;
        let resp = self
            .execute_signed(
                &signer,
                HttpMethod::Post,
                "/v1/device-links/poll",
                "?",
                body,
                None,
            )
            .await?;
        let status = resp.status;
        let decoded: DeviceLinkPollResponse = Self::decode_json_response(resp, &[200, 202])?;
        match (&decoded, status) {
            (DeviceLinkPollResponse::Pending { .. }, 202) => Ok(decoded),
            (
                DeviceLinkPollResponse::Approved {
                    account_id,
                    device_id,
                    ..
                },
                200,
            ) => {
                validate_account_id(*account_id, "device_link_poll")?;
                validate_device_id(*device_id, "device_link_poll")?;
                Ok(decoded)
            }
            _ => Err(ControlError::InvalidJsonResponse(format!(
                "unexpected HTTP {status} for device_link_poll response status"
            ))),
        }
    }

    // -----------------------------------------------------------------------
    // Room Protocol v2 (`mp2`) & Cloud Auth REST Endpoints
    // -----------------------------------------------------------------------

    /// `POST /v1/rooms/invite` (device-authenticated).
    ///
    /// Creates a room automatically if `party_id` is omitted, puts the caller in it,
    /// and optionally pushes a live invite to `@handle` over `AccountDO` `/v1/ws`.
    pub async fn room_invite(
        &self,
        req: &RoomInviteRequest,
    ) -> Result<RoomInviteResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let body = encode_json(req)?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, "/v1/rooms/invite", "?", body, None)
            .await?;
        let decoded: RoomInviteResponse = Self::decode_json_response(resp, &[200, 201])?;
        PartyId::new(decoded.party_id).map_err(|_| {
            ControlError::Protocol(format!(
                "invalid party_id ({}) in room_invite response",
                decoded.party_id
            ))
        })?;
        Ok(decoded)
    }

    /// `POST /v1/rooms/enter` (device-authenticated).
    ///
    /// Universal idempotent resolver: joins a party by `@handle`, 4-char `room_code`,
    /// URL, legacy `mppi1_...` token, numeric `party_id`, or `""` (latest pending invite).
    pub async fn room_enter(
        &self,
        req: &RoomEnterRequest,
    ) -> Result<RoomEnterResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let body = encode_json(req)?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, "/v1/rooms/enter", "?", body, None)
            .await?;
        let decoded: RoomEnterResponse = Self::decode_json_response(resp, &[200, 201])?;
        PartyId::new(decoded.party_id).map_err(|_| {
            ControlError::Protocol(format!(
                "invalid party_id ({}) in room_enter response",
                decoded.party_id
            ))
        })?;
        Ok(decoded)
    }

    /// `POST /v1/rooms/leave` (device-authenticated).
    pub async fn room_leave(&self, party_id: PartyId) -> Result<RoomLeaveResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let body = encode_json(&RoomLeaveWire {
            party_id: party_id.get(),
        })?;
        let resp = self
            .execute_signed(signer, HttpMethod::Post, "/v1/rooms/leave", "?", body, None)
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `GET /v1/friends/live` (device-authenticated).
    pub async fn friends_live(&self) -> Result<LiveFriendsResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let resp = self
            .execute_signed(
                signer,
                HttpMethod::Get,
                "/v1/friends/live",
                "?",
                Bytes::new(),
                None,
            )
            .await?;
        Self::decode_json_response(resp, &[200])
    }

    /// `POST /v1/auth/session/start` (unauthenticated browser-first CLI login).
    pub async fn auth_session_start(
        &self,
        req: &AuthSessionStartRequest,
    ) -> Result<AuthSessionStartResponse, ControlError> {
        let wire = AuthSessionStartWire {
            device_pubkey_b64: B64_STD.encode(req.device_pubkey),
            device_label: &req.device_label,
            client: &req.client,
        };
        let body = encode_json(&wire)?;
        let resp = self
            .execute_unsigned_post("/v1/auth/session/start", body)
            .await?;
        let decoded: AuthSessionStartResponse = Self::decode_json_response(resp, &[200, 201])?;
        if decoded.flow_id.is_empty() || decoded.poll_token.is_empty() {
            return Err(ControlError::Protocol(
                "auth_session_start response missing flow_id or poll_token".to_owned(),
            ));
        }
        Ok(decoded)
    }

    /// `POST /v1/auth/session/poll` (unauthenticated browser-first CLI login poll).
    pub async fn auth_session_poll(
        &self,
        flow_id: &str,
        poll_token: &str,
    ) -> Result<AuthSessionPollResponse, ControlError> {
        let body = encode_json(&AuthSessionPollWire {
            flow_id,
            poll_token,
        })?;
        let resp = self
            .execute_unsigned_post("/v1/auth/session/poll", body)
            .await?;
        let decoded: AuthSessionPollResponse = Self::decode_json_response(resp, &[200, 202])?;
        if let AuthSessionPollResponse::Approved {
            account_id,
            device_id,
            ..
        } = &decoded
        {
            validate_account_id(*account_id, "auth_session_poll")?;
            validate_device_id(*device_id, "auth_session_poll")?;
        }
        Ok(decoded)
    }

    /// `POST /v1/devices/me/renew` (RFC 9421 device-key authenticated silent auto-renewal).
    pub async fn renew_my_device(&self) -> Result<RenewMyDeviceResponse, ControlError> {
        let signer = self.require_device_signer()?;
        let body = Bytes::from_static(b"{}");
        let resp = self
            .execute_signed(
                signer,
                HttpMethod::Post,
                "/v1/devices/me/renew",
                "?",
                body,
                None,
            )
            .await?;
        let decoded: RenewMyDeviceResponse = Self::decode_json_response(resp, &[200])?;
        validate_device_id(decoded.device_id, "renew_my_device")?;
        Ok(decoded)
    }

    /// Downloads bounded bytes over TLS 1.3 + HTTP/1.1 with strict host-allowlisted
    /// HTTPS-only redirect following (at most 3 redirects, 60-second overall deadline).
    ///
    /// Inherits this client's TLS 1.3-only `ClientConfig` (including any test CA roots)
    /// and optional `connect_addr` override.
    pub async fn fetch_https_bytes(
        &self,
        url: &str,
        max_bytes: usize,
        allowed_hosts: &[&str],
    ) -> Result<Vec<u8>, ControlError> {
        fetch_https_bytes_with_transport(
            url,
            max_bytes,
            allowed_hosts,
            &self.config.tls_config,
            self.config.connect_addr,
            MAX_FETCH_TIMEOUT,
        )
        .await
    }

    /// Probes `<relay_url>/ping` over TLS 1.3 + HTTP/1.1 using this client's TLS config and
    /// timeout, returning the measured round-trip duration on HTTP 200 or 204.
    pub async fn probe_relay_ping(&self, relay_url: &str) -> Result<Duration, ControlError> {
        let trimmed = relay_url.trim_end_matches('/');
        let Some(after_scheme) = trimmed.strip_prefix("https://") else {
            return Err(ControlError::InvalidRequest(
                "relay_url must be a valid https:// origin".to_owned(),
            ));
        };
        if after_scheme.contains('/') || after_scheme.contains('?') || after_scheme.contains('#') {
            return Err(ControlError::InvalidRequest(
                "relay_url must be an origin without path, query, or fragment".to_owned(),
            ));
        }
        let ping_url = format!("{trimmed}/ping");
        let (status, rtt) = probe_https_get_with_transport(
            &ping_url,
            &self.config.tls_config,
            self.config.connect_addr,
            self.config.request_timeout,
        )
        .await?;
        if status == 200 || status == 204 {
            Ok(rtt)
        } else {
            Err(ControlError::Api {
                status,
                error: format!("relay_ping_http_{status}"),
                server_now_ms: None,
                retry_after_ms: None,
                relay_policy: None,
                pinned_relay_url: None,
                raw_body: String::new(),
            })
        }
    }
}

/// Downloads bounded bytes over TLS 1.3 + HTTP/1.1 using the default `webpki-roots`
/// trust store, with strict host-allowlisted HTTPS-only redirect following (at most 3
/// redirects, 60-second overall deadline).
pub async fn fetch_https_bytes(
    url: &str,
    max_bytes: usize,
    allowed_hosts: &[&str],
) -> Result<Vec<u8>, ControlError> {
    let tls_config = default_tls13_client_config()?;
    fetch_https_bytes_with_transport(
        url,
        max_bytes,
        allowed_hosts,
        &tls_config,
        None,
        MAX_FETCH_TIMEOUT,
    )
    .await
}

struct ParsedFetchUrl {
    canonical_authority: String,
    host_lower: String,
    request_target: String,
}

fn parse_fetch_https_url(url: &str) -> Result<ParsedFetchUrl, ControlError> {
    if url.len() > MAX_FETCH_URL_BYTES {
        return Err(ControlError::InvalidRequest(
            "HTTPS URL exceeds maximum length".to_owned(),
        ));
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(ControlError::InvalidRequest(
            "URL must start with https://".to_owned(),
        ));
    };
    if rest.is_empty()
        || !rest.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || rest.contains('#')
        || rest.contains('\\')
    {
        return Err(ControlError::InvalidRequest(
            "HTTPS URL contains forbidden characters, whitespace, or fragment".to_owned(),
        ));
    }

    let split_pos = rest
        .bytes()
        .position(|b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let raw_authority = rest.get(..split_pos).unwrap_or("");
    let tail = rest.get(split_pos..).unwrap_or("");

    let (canonical_authority, host_lower, _port) = parse_authority(raw_authority)?;
    let request_target = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };

    Ok(ParsedFetchUrl {
        canonical_authority,
        host_lower,
        request_target,
    })
}

fn host_is_allowed(canonical_authority: &str, host_lower: &str, allowed_hosts: &[&str]) -> bool {
    for &entry in allowed_hosts {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains(':') {
            if let Ok((allowed_canonical, _, _)) = parse_authority(trimmed)
                && canonical_authority == allowed_canonical
            {
                return true;
            }
        } else if let Ok((_, allowed_host, _)) = parse_authority(trimmed)
            && host_lower == allowed_host
        {
            return true;
        }
    }
    false
}

async fn fetch_https_bytes_with_transport(
    url: &str,
    max_bytes: usize,
    allowed_hosts: &[&str],
    tls_config: &Arc<rustls::ClientConfig>,
    connect_addr: Option<SocketAddr>,
    total_timeout: Duration,
) -> Result<Vec<u8>, ControlError> {
    let mut current = parse_fetch_https_url(url)?;
    if !host_is_allowed(
        &current.canonical_authority,
        &current.host_lower,
        allowed_hosts,
    ) {
        return Err(ControlError::InvalidRequest(format!(
            "host '{}' is not in the allowed host list",
            current.host_lower
        )));
    }

    let deadline = Instant::now() + total_timeout;
    let mut redirects_followed: usize = 0;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ControlError::Timeout);
        }

        let hop_result = tokio::time::timeout(remaining, async {
            let tls = connect_tls13(
                &current.canonical_authority,
                connect_addr,
                tls_config,
                remaining,
            )
            .await?;

            let io = TokioIo::new(tls);
            let mut h1 = hyper::client::conn::http1::Builder::new();
            h1.max_buf_size(FETCH_READ_BUF_BYTES);
            let (mut sender, conn) = h1.handshake(io).await.map_err(ControlError::Http)?;

            let _conn_guard = AbortOnDrop(tokio::spawn(async move {
                let _ = conn.await;
            }));

            let req = Request::builder()
                .method(Method::GET)
                .uri(&current.request_target)
                .header(http::header::HOST, &current.canonical_authority)
                .header(http::header::USER_AGENT, "mp-outpost")
                .header(http::header::CONNECTION, "close")
                .body(Full::new(Bytes::new()))
                .map_err(|e| ControlError::InvalidRequest(e.to_string()))?;

            let resp = sender.send_request(req).await.map_err(ControlError::Http)?;
            let status = resp.status();

            check_response_headers_size(resp.headers())?;

            let status_code = status.as_u16();
            if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
                if redirects_followed >= MAX_FETCH_REDIRECTS {
                    return Err(ControlError::UnexpectedRedirect {
                        status: status_code,
                    });
                }
                let location = resp
                    .headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .ok_or(ControlError::UnexpectedRedirect {
                        status: status_code,
                    })?;
                let next = parse_fetch_https_url(location).map_err(|_| {
                    ControlError::UnexpectedRedirect {
                        status: status_code,
                    }
                })?;
                if !host_is_allowed(&next.canonical_authority, &next.host_lower, allowed_hosts) {
                    return Err(ControlError::UnexpectedRedirect {
                        status: status_code,
                    });
                }
                return Ok(FetchHopOutcome::Redirect(next));
            }

            if status.is_redirection() {
                return Err(ControlError::UnexpectedRedirect {
                    status: status_code,
                });
            }

            let retry_after_ms = parse_retry_after_header_ms(resp.headers());

            if status != StatusCode::OK {
                let mut incoming = resp.into_body();
                let mut err_buf = BytesMut::new();
                while let Some(frame_res) = incoming.frame().await {
                    let frame = frame_res.map_err(ControlError::Http)?;
                    if let Some(data) = frame.data_ref() {
                        let space = MAX_RESPONSE_BODY_BYTES.saturating_sub(err_buf.len());
                        if space == 0 {
                            break;
                        }
                        let take = data.len().min(space);
                        if let Some(slice) = data.get(..take) {
                            err_buf.extend_from_slice(slice);
                        }
                    }
                }
                return Err(parse_api_error(RawHttpResponse {
                    status: status_code,
                    body: err_buf.freeze(),
                    retry_after_ms,
                }));
            }

            let mut initial_cap: usize = 0;
            if let Some(cl_val) = resp.headers().get(http::header::CONTENT_LENGTH) {
                let parsed = cl_val
                    .to_str()
                    .ok()
                    .and_then(|s| s.trim().parse::<usize>().ok());
                match parsed {
                    Some(n) if n <= max_bytes => {
                        initial_cap = n.min(FETCH_READ_BUF_BYTES);
                    }
                    _ => return Err(ControlError::ResponseTooLarge),
                }
            }

            let mut incoming = resp.into_body();
            let mut out = Vec::with_capacity(initial_cap);
            while let Some(frame_res) = incoming.frame().await {
                let frame = frame_res.map_err(ControlError::Http)?;
                if let Some(data) = frame.data_ref() {
                    if out.len().saturating_add(data.len()) > max_bytes {
                        return Err(ControlError::ResponseTooLarge);
                    }
                    out.extend_from_slice(data);
                }
            }

            Ok(FetchHopOutcome::Body(out))
        })
        .await
        .map_err(|_| ControlError::Timeout)??;

        match hop_result {
            FetchHopOutcome::Redirect(next) => {
                redirects_followed = redirects_followed.saturating_add(1);
                current = next;
            }
            FetchHopOutcome::Body(bytes) => return Ok(bytes),
        }
    }
}

enum FetchHopOutcome {
    Redirect(ParsedFetchUrl),
    Body(Vec<u8>),
}

fn check_response_headers_size(headers: &http::HeaderMap) -> Result<(), ControlError> {
    let mut header_bytes: usize = 0;
    for (name, value) in headers {
        header_bytes = header_bytes
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4);
        if header_bytes > MAX_RESPONSE_HEADERS_BYTES {
            return Err(ControlError::ResponseHeadersTooLarge);
        }
    }
    Ok(())
}

fn parse_retry_after_header_ms(headers: &http::HeaderMap) -> Option<u64> {
    let val = headers.get(http::header::RETRY_AFTER)?;
    let s = val.to_str().ok()?.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = s.parse::<u64>().ok()?;
    let ms = secs.saturating_mul(1_000);
    Some(ms.clamp(MIN_RETRY_AFTER_MS, MAX_RETRY_AFTER_MS))
}

/// Performs an unsigned TLS 1.3-only HTTP/1.1 `GET` probe against an `https://` URL
/// (for example `https://relay.multiplayer.tech/ping`) and returns `(http_status, rtt)`.
pub async fn probe_https_get(
    url: &str,
    timeout: Duration,
) -> Result<(u16, Duration), ControlError> {
    let tls_config = default_tls13_client_config()?;
    probe_https_get_with_transport(url, &tls_config, None, timeout).await
}

async fn probe_https_get_with_transport(
    url: &str,
    tls_config: &Arc<rustls::ClientConfig>,
    connect_addr: Option<SocketAddr>,
    timeout: Duration,
) -> Result<(u16, Duration), ControlError> {
    let (canonical_authority, path) = parse_https_url(url)?;
    let started = Instant::now();
    let resp = send_http1_raw(
        &canonical_authority,
        connect_addr,
        tls_config,
        timeout,
        HttpMethod::Get,
        &path,
        "?",
        Bytes::new(),
        None,
        None,
    )
    .await?;
    Ok((resp.status, started.elapsed()))
}

fn parse_https_url(url: &str) -> Result<(String, String), ControlError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(ControlError::InvalidRequest(
            "probe URL must start with https://".to_owned(),
        ));
    };
    if rest.contains('?') || rest.contains('#') {
        return Err(ControlError::InvalidRequest(
            "probe URL must not contain query or fragment".to_owned(),
        ));
    }
    let (raw_authority, path) = match rest.split_once('/') {
        Some((auth, tail)) => (auth, format!("/{tail}")),
        None => (rest, "/".to_owned()),
    };
    let canonical_authority = canonicalize_authority(raw_authority)?;
    validate_path_and_query(HttpMethod::Get, &path, "?")?;
    Ok((canonical_authority, path))
}

#[allow(clippy::too_many_arguments)]
async fn send_http1_raw(
    authority: &str,
    connect_addr: Option<SocketAddr>,
    tls_config: &Arc<rustls::ClientConfig>,
    timeout: Duration,
    method: HttpMethod,
    path: &str,
    query: &str,
    body: Bytes,
    signed: Option<&SignedHeaders>,
    idempotency_key: Option<&str>,
) -> Result<RawHttpResponse, ControlError> {
    tokio::time::timeout(timeout, async {
        let tls = connect_tls13(authority, connect_addr, tls_config, timeout).await?;

        let io = TokioIo::new(tls);
        let mut h1 = hyper::client::conn::http1::Builder::new();
        h1.max_buf_size(MAX_RESPONSE_HEADERS_BYTES + MAX_RESPONSE_BODY_BYTES);
        let (mut sender, conn) = h1.handshake(io).await.map_err(ControlError::Http)?;

        let _conn_guard = AbortOnDrop(tokio::spawn(async move {
            let _ = conn.await;
        }));

        let uri = if query.len() > 1 {
            format!("{path}{query}")
        } else {
            path.to_owned()
        };

        let canonical_authority = canonicalize_authority(authority)?;

        let mut req_builder = Request::builder()
            .method(to_http_method(method))
            .uri(&uri)
            .header(http::header::HOST, &canonical_authority)
            .header(http::header::CONNECTION, "close");

        if let Some(s) = signed {
            req_builder = req_builder
                .header(
                    HeaderName::from_static("signature-input"),
                    HeaderValue::from_str(&s.signature_input).map_err(|e| {
                        ControlError::InvalidRequest(format!("invalid Signature-Input: {e}"))
                    })?,
                )
                .header(
                    HeaderName::from_static("signature"),
                    HeaderValue::from_str(&s.signature).map_err(|e| {
                        ControlError::InvalidRequest(format!("invalid Signature: {e}"))
                    })?,
                );
            if let Some(ct) = s.content_type {
                req_builder = req_builder.header(http::header::CONTENT_TYPE, ct);
            }
            if let Some(cd) = &s.content_digest {
                req_builder = req_builder.header(
                    HeaderName::from_static("content-digest"),
                    HeaderValue::from_str(cd).map_err(|e| {
                        ControlError::InvalidRequest(format!("invalid Content-Digest: {e}"))
                    })?,
                );
            }
        } else if method.requires_body_headers() {
            req_builder = req_builder.header(http::header::CONTENT_TYPE, "application/json");
        }

        if let Some(idem) = idempotency_key {
            req_builder = req_builder.header(
                HeaderName::from_static("idempotency-key"),
                HeaderValue::from_str(idem).map_err(|_| ControlError::InvalidIdempotencyKey)?,
            );
        }

        let req = req_builder
            .body(Full::new(body))
            .map_err(|e| ControlError::InvalidRequest(e.to_string()))?;

        let resp = sender.send_request(req).await.map_err(ControlError::Http)?;
        let status = resp.status();

        if status.is_redirection() {
            return Err(ControlError::UnexpectedRedirect {
                status: status.as_u16(),
            });
        }

        check_response_headers_size(resp.headers())?;
        let retry_after_ms = parse_retry_after_header_ms(resp.headers());

        if let Some(cl_val) = resp.headers().get(http::header::CONTENT_LENGTH) {
            let parsed = cl_val
                .to_str()
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok());
            match parsed {
                Some(n) if n <= MAX_RESPONSE_BODY_BYTES => {}
                _ => {
                    return Err(ControlError::ResponseTooLarge);
                }
            }
        }

        let mut incoming = resp.into_body();
        let mut buf = BytesMut::new();
        while let Some(frame_res) = incoming.frame().await {
            let frame = frame_res.map_err(ControlError::Http)?;
            if let Some(data) = frame.data_ref() {
                if buf.len().saturating_add(data.len()) > MAX_RESPONSE_BODY_BYTES {
                    return Err(ControlError::ResponseTooLarge);
                }
                buf.extend_from_slice(data);
            }
        }

        Ok(RawHttpResponse {
            status: status.as_u16(),
            body: buf.freeze(),
            retry_after_ms,
        })
    })
    .await
    .map_err(|_| ControlError::Timeout)?
}

fn require_root_signer(signer: &RequestSigner) -> Result<(), ControlError> {
    if matches!(signer.key_id(), KeyId::Root { .. }) {
        Ok(())
    } else {
        Err(ControlError::InvalidRequest(
            "endpoint requires a .root RequestSigner".to_owned(),
        ))
    }
}

fn require_device_or_root_signer(signer: &RequestSigner) -> Result<(), ControlError> {
    if matches!(signer.key_id(), KeyId::Device { .. } | KeyId::Root { .. }) {
        Ok(())
    } else {
        Err(ControlError::InvalidRequest(
            "endpoint requires a device or .root RequestSigner".to_owned(),
        ))
    }
}

fn validate_idempotency_key(key: &str) -> Result<(), ControlError> {
    if !(16..=64).contains(&key.len()) || !key.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(ControlError::InvalidIdempotencyKey);
    }
    Ok(())
}

fn to_http_method(m: HttpMethod) -> Method {
    match m {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
    }
}

fn encode_json<T: Serialize>(value: &T) -> Result<Bytes, ControlError> {
    serde_json::to_vec(value)
        .map(Bytes::from)
        .map_err(|e| ControlError::InvalidRequest(e.to_string()))
}

/// Validates a server-returned device-link code strictly (`XXXX-XXXX`, 9 ASCII bytes
/// where each `X` is ASCII alphanumeric).
pub fn validate_link_code(code: &str) -> Result<(), ControlError> {
    let bytes = code.as_bytes();
    if bytes.len() != 9 {
        return Err(ControlError::Protocol(
            "malformed link_code: expected 9-character XXXX-XXXX code".to_owned(),
        ));
    }
    for (idx, &b) in bytes.iter().enumerate() {
        let ok = if idx == 4 {
            b == b'-'
        } else {
            b.is_ascii_alphanumeric()
        };
        if !ok {
            return Err(ControlError::Protocol(
                "malformed link_code: expected ASCII alphanumeric XXXX-XXXX code".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_account_id(id: u64, context: &'static str) -> Result<(), ControlError> {
    AccountId::new(id).map_err(|_| {
        ControlError::Protocol(format!("invalid account_id ({id}) in {context} response"))
    })?;
    Ok(())
}

fn validate_device_id(id: u64, context: &'static str) -> Result<(), ControlError> {
    DeviceId::new(id).map_err(|_| {
        ControlError::Protocol(format!("invalid device_id ({id}) in {context} response"))
    })?;
    Ok(())
}

fn is_forbidden_error_scalar(ch: char) -> bool {
    let cp = ch as u32;
    cp < 0x20
        || cp == 0x7F
        || (0x80..=0x9F).contains(&cp)
        || cp == 0x061C
        || (0x200B..=0x200F).contains(&cp)
        || (0x202A..=0x202E).contains(&cp)
        || cp == 0x2060
        || (0x2066..=0x2069).contains(&cp)
        || cp == 0xFEFF
        || (0xE0000..=0xE007F).contains(&cp)
}

fn validate_discovered_relay_url(url: &str, field: &'static str) -> Result<(), ControlError> {
    if url.is_empty() {
        return Err(ControlError::Protocol(format!(
            "empty {field} in control-plane response"
        )));
    }
    validate_relay_url(url).map_err(|_| {
        ControlError::Protocol(format!("invalid {field} in control-plane response"))
    })?;
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        ControlError::Protocol(format!("non-HTTPS {field} in control-plane response"))
    })?;
    let host = match rest.rsplit_once(':') {
        Some((h, _)) => h,
        None => rest,
    };
    const PRIVATE_SUFFIXES: &[&str] = &[
        ".localhost",
        ".local",
        ".internal",
        ".home.arpa",
        ".lan",
        ".home",
        ".localdomain",
        ".intranet",
        ".corp",
        ".invalid",
    ];
    if PRIVATE_SUFFIXES.iter().any(|sfx| host.ends_with(sfx)) {
        return Err(ControlError::Protocol(format!(
            "private-suffix {field} rejected in control-plane response"
        )));
    }
    Ok(())
}

/// Sanitizes an untrusted server-supplied error string before storing or printing it:
/// - strips ANSI CSI/OSC/DCS/SOS/PM/APC escape sequences
/// - strips C0 (`< 0x20`), DEL (`0x7F`), C1 (`0x80..=0x9F`), BiDi overrides/isolates,
///   zero-width/ignorable scalars, and Unicode Tag characters (`U+E0000..=U+E007F`)
/// - collapses ASCII whitespace runs to single ASCII spaces and trims ends
/// - caps output length at 256 Unicode scalar values.
pub fn sanitize_server_error(raw: &str) -> String {
    sanitize_untrusted_text(raw, MAX_ERROR_MESSAGE_CHARS)
}

fn sanitize_untrusted_text(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut chars = raw.chars().peekable();
    let mut pending_space = false;
    let mut char_count: usize = 0;

    while let Some(ch) = chars.next() {
        // Strip 7-bit ANSI escape sequences (ESC CSI / OSC / DCS / SOS / PM / APC).
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    let _ = chars.next();
                    for c in chars.by_ref() {
                        let b = c as u32;
                        if (0x40..=0x7E).contains(&b) {
                            break;
                        }
                        if !(0x20..=0x3F).contains(&b) {
                            break;
                        }
                    }
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    let _ = chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' || c == '\u{009C}' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            let _ = chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }

        // Strip 8-bit CSI (`U+009B`) and OSC (`U+009D`) sequences.
        if ch == '\u{009B}' {
            for c in chars.by_ref() {
                let b = c as u32;
                if (0x40..=0x7E).contains(&b) || !(0x20..=0x3F).contains(&b) {
                    break;
                }
            }
            continue;
        }
        if ch == '\u{009D}' {
            while let Some(c) = chars.next() {
                if c == '\x07' || c == '\u{009C}' {
                    break;
                }
                if c == '\x1b' && chars.peek() == Some(&'\\') {
                    let _ = chars.next();
                    break;
                }
            }
            continue;
        }

        if ch.is_ascii_whitespace() {
            if char_count > 0 {
                pending_space = true;
            }
            continue;
        }

        if is_forbidden_error_scalar(ch) {
            continue;
        }

        if pending_space {
            if char_count >= max_chars {
                break;
            }
            out.push(' ');
            char_count += 1;
            pending_space = false;
        }

        if char_count >= max_chars {
            break;
        }
        out.push(ch);
        char_count += 1;
    }

    out
}

fn parse_api_error(resp: RawHttpResponse) -> ControlError {
    let raw_body = String::from_utf8_lossy(&resp.body).into_owned();
    let parsed = serde_json::from_slice::<ApiErrorBody>(&resp.body).ok();
    let error = parsed
        .as_ref()
        .and_then(|p| p.error.as_deref())
        .map(sanitize_server_error)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("http_{}", resp.status));
    let retry_after_ms = parsed
        .as_ref()
        .and_then(|p| p.retry_after_ms)
        .or(resp.retry_after_ms)
        .map(|ms| ms.clamp(MIN_RETRY_AFTER_MS, MAX_RETRY_AFTER_MS));
    let relay_policy = parsed.as_ref().and_then(|p| p.relay_policy);
    let pinned_relay_url = parsed
        .as_ref()
        .and_then(|p| p.pinned_relay_url.as_deref())
        .filter(|url| validate_discovered_relay_url(url, "pinned_relay_url").is_ok())
        .map(str::to_owned);
    ControlError::Api {
        status: resp.status,
        error,
        server_now_ms: parsed.as_ref().and_then(|p| p.server_now_ms),
        retry_after_ms,
        relay_policy,
        pinned_relay_url,
        raw_body,
    }
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        if let (Some(&hi), Some(&lo)) = (
            HEX.get(usize::from(b >> 4)),
            HEX.get(usize::from(b & 0x0f)),
        ) {
            out.push(char::from(hi));
            out.push(char::from(lo));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Typed REST Request / Response Models (Exact `api.multiplayer.tech` schema)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub server_now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RelayInfo {
    pub url: String,
    pub region: String,
    pub label: String,
    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RelaysResponse {
    pub default_relay_url: String,
    pub relays: Vec<RelayInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAccountRequest {
    pub invite_secret: String,
    pub handle: String,
    pub device_pubkey: [u8; 32],
    pub device_label: String,
    pub device_cwt: Vec<u8>,
}

#[derive(Serialize)]
struct RegisterAccountWire<'a> {
    invite_secret: &'a str,
    handle: &'a str,
    root_pubkey_b64: String,
    device_pubkey_b64: String,
    device_label: &'a str,
    device_cwt_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegisterAccountResponse {
    pub account_id: u64,
    pub device_id: u64,
    pub handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountDeviceInfo {
    pub device_id: u64,
    pub pubkey_b64: String,
    pub label: String,
    pub cwt_expires_ms: u64,
    pub generation: u64,
    pub pop_verified: bool,
    pub created_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountMeResponse {
    pub account_id: u64,
    pub handle: String,
    pub root_pubkey_b64: String,
    pub devices: Vec<AccountDeviceInfo>,
    pub active_party_ids: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PublicDeviceInfo {
    pub device_id: u64,
    pub pubkey_b64: String,
    pub cwt_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PublicAccountResponse {
    pub account_id: u64,
    pub handle: String,
    pub root_pubkey_b64: String,
    #[serde(default)]
    pub devices: Option<Vec<PublicDeviceInfo>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ResolvedHandleResponse {
    pub account_id: u64,
    pub handle: String,
    pub root_pubkey_b64: String,
}

#[derive(Serialize)]
struct RenameHandleWire<'a> {
    handle: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RenameHandleResponse {
    pub account_id: u64,
    pub handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollDeviceRequest {
    pub device_pubkey: [u8; 32],
    pub device_label: String,
    pub device_cwt: Vec<u8>,
}

#[derive(Serialize)]
struct EnrollDeviceWire<'a> {
    device_pubkey_b64: String,
    device_label: &'a str,
    device_cwt_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EnrollDeviceResponse {
    pub device_id: u64,
    pub cwt_expires_ms: u64,
}

#[derive(Serialize)]
struct RenewDeviceCwtWire {
    device_cwt_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RenewDeviceCwtResponse {
    pub device_id: u64,
    pub cwt_expires_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RevokeDeviceResponse {
    pub revoked: bool,
    pub evicted_parties: Vec<u64>,
    pub pending_retries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FriendEdge {
    pub peer_account_id: u64,
    pub state: u8,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub peer_handle: Option<String>,
    #[serde(default)]
    pub peer_root_pubkey_b64: Option<String>,
    #[serde(default)]
    pub peer_safety_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ListFriendsResponse {
    pub friends: Vec<FriendEdge>,
}

#[derive(Serialize)]
struct TargetAccountWire {
    target_account_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FriendRequestResponse {
    pub target_account_id: u64,
    pub state: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RemoveFriendResponse {
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockAccountResponse {
    pub target_account_id: u64,
    pub state: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePartyRequest {
    pub visibility: PartyVisibility,
    pub join_mode: PartyJoinMode,
    pub relay_policy: RelayPolicy,
    pub max_members: u8,
    pub endpoint: EndpointDescriptor,
    pub relay_url: Option<String>,
}

#[derive(Serialize)]
struct CreatePartyWire<'a> {
    visibility: u8,
    join_mode: u8,
    relay_policy: u8,
    max_members: u8,
    endpoint_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreatePartyResponse {
    pub party_id: u64,
    pub party_epoch: u64,
    pub pinned_relay_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PartySummaryResponse {
    pub party_id: u64,
    pub party_epoch: u64,
    pub leader_account_id: u64,
    pub leader_device_id: u64,
    pub visibility: u8,
    pub join_mode: u8,
    pub relay_policy: u8,
    pub pinned_relay_url: String,
    pub max_members: u8,
    pub member_count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPartyRequest {
    pub endpoint: EndpointDescriptor,
    pub invite_link: Option<String>,
}

#[derive(Serialize)]
struct JoinPartyWire<'a> {
    endpoint_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    invite_link: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JoinPartyResponse {
    Joined { party_epoch: u64 },
    PendingApproval { request_id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LeavePartyResponse {
    pub left: bool,
    pub party_epoch: u64,
}

#[derive(Serialize)]
struct ExpectedEpochWire {
    expected_party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DisbandPartyResponse {
    pub disbanded: bool,
    pub party_epoch: u64,
}

#[derive(Serialize)]
struct KickMemberWire {
    target_account_id: u64,
    expected_party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KickMemberResponse {
    pub kicked: bool,
    pub party_epoch: u64,
}

#[derive(Serialize)]
struct PromoteMemberWire {
    target_device_id: u64,
    expected_party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PromoteMemberResponse {
    pub promoted: bool,
    pub party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MintPartyInviteRequest {
    pub target_account_id: Option<AccountId>,
    pub max_uses: Option<u8>,
    pub ttl_sec: Option<u32>,
}

#[derive(Serialize)]
struct MintPartyInviteWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    target_account_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_uses: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_sec: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MintPartyInviteResponse {
    pub party_invite_id: u64,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub invite_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RevokePartyInviteResponse {
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PartyJoinRequestItem {
    pub request_id: u64,
    pub account_id: u64,
    pub device_id: u64,
    pub root_pubkey_b64: String,
    pub device_pubkey_b64: String,
    pub requested_at_ms: u64,
    pub reserved_until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ListPartyRequestsResponse {
    pub requests: Vec<PartyJoinRequestItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovePartyRequest {
    pub expected_party_epoch: u64,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub device_pubkey_sha256: [u8; 32],
}

impl ApprovePartyRequest {
    pub fn for_device_pubkey(
        expected_party_epoch: u64,
        account_id: AccountId,
        device_id: DeviceId,
        device_pubkey: &[u8; 32],
    ) -> Self {
        Self {
            expected_party_epoch,
            account_id,
            device_id,
            device_pubkey_sha256: sha256(device_pubkey),
        }
    }
}

#[derive(Serialize)]
struct ApprovePartyRequestWire {
    expected_party_epoch: u64,
    account_id: u64,
    device_id: u64,
    device_pubkey_sha256_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApprovePartyRequestResponse {
    pub approved: bool,
    pub reserved_until_ms: u64,
}

#[derive(Serialize)]
struct RejectPartyRequestWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_party_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RejectPartyRequestResponse {
    pub rejected: bool,
}

// ---------------------------------------------------------------------------
// Identity Portability & Web Portal Request / Response Models
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RecoverLookupWire {
    root_pubkey_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecoverLookupResponse {
    pub account_id: u64,
    pub handle: String,
    pub root_pubkey_b64: String,
    pub safety_number: String,
    pub devices: Vec<AccountDeviceInfo>,
}

#[derive(Serialize)]
struct WebSessionCodeWire<'a> {
    user_code: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WebSessionInspectResponse {
    pub pending: bool,
    pub scope: String,
    pub browser_fingerprint: String,
    pub requester_country: String,
    pub requester_client: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WebSessionApproveResponse {
    pub approved: bool,
    pub scope: String,
    pub account_id: u64,
    pub approved_device_id: Option<u64>,
    pub approved_by_root: bool,
    pub browser_fingerprint: String,
    pub requester_country: String,
    pub requester_client: String,
}

#[derive(Serialize)]
struct DeviceLinkCreateWire<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    device_label: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceLinkCreateResponse {
    pub link_code: String,
    pub expires_at_ms: u64,
}

#[derive(Serialize)]
struct DeviceLinkClaimWire<'a> {
    link_code: &'a str,
    device_pubkey_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_label: Option<&'a str>,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceLinkClaimResponse {
    pub poll_token: String,
    pub device_fingerprint: String,
    pub expires_at_ms: u64,
}

impl fmt::Debug for DeviceLinkClaimResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLinkClaimResponse")
            .field("poll_token", &"[REDACTED]")
            .field("device_fingerprint", &self.device_fingerprint)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Serialize)]
struct DeviceLinkInspectWire<'a> {
    link_code: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "state")]
pub enum DeviceLinkInspectResponse {
    #[serde(rename = "waiting_for_device")]
    WaitingForDevice {
        suggested_label: String,
        created_at_ms: u64,
        expires_at_ms: u64,
    },
    #[serde(rename = "pending_approval")]
    PendingApproval {
        device_pubkey_b64: String,
        device_fingerprint: String,
        device_label: String,
        requester_country: String,
        created_at_ms: u64,
        expires_at_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLinkApproveRequest {
    pub link_code: String,
    pub device_pubkey: [u8; 32],
    pub device_cwt: Vec<u8>,
    pub device_label: Option<String>,
}

#[derive(Serialize)]
struct DeviceLinkApproveWire<'a> {
    link_code: &'a str,
    device_pubkey_b64: String,
    device_cwt_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_label: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceLinkApproveResponse {
    pub approved: bool,
    pub account_id: u64,
    pub device_id: u64,
    pub device_label: String,
    pub device_fingerprint: String,
    pub cwt_expires_ms: u64,
}

#[derive(Serialize)]
struct DeviceLinkPollWire<'a> {
    link_code: &'a str,
    poll_token: &'a str,
    device_pubkey_b64: String,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DeviceLinkPollResponse {
    Pending {
        expires_at_ms: u64,
    },
    Approved {
        account_id: u64,
        handle: String,
        device_id: u64,
        root_pubkey_b64: String,
        device_cwt_b64: String,
        cwt_expires_ms: u64,
        safety_number: String,
    },
}

impl fmt::Debug for DeviceLinkPollResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending { expires_at_ms } => f
                .debug_struct("Pending")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::Approved {
                account_id,
                handle,
                device_id,
                root_pubkey_b64,
                device_cwt_b64: _,
                cwt_expires_ms,
                safety_number,
            } => f
                .debug_struct("Approved")
                .field("account_id", account_id)
                .field("handle", handle)
                .field("device_id", device_id)
                .field("root_pubkey_b64", root_pubkey_b64)
                .field("device_cwt_b64", &"[REDACTED]")
                .field("cwt_expires_ms", cwt_expires_ms)
                .field("safety_number", safety_number)
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// Flexible numeric-or-string u64 deserializers (`ROOM_PROTOCOL_V2.md`)
// ---------------------------------------------------------------------------

pub(crate) fn deserialize_u64_or_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U64OrStringVisitor;

    impl serde::de::Visitor<'_> for U64OrStringVisitor {
        type Value = u64;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a u64 integer or decimal string")
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom("negative integer for u64"))
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<u64, E> {
            v.trim()
                .parse::<u64>()
                .map_err(|_| E::custom("invalid decimal string for u64"))
        }
    }

    deserializer.deserialize_any(U64OrStringVisitor)
}

pub(crate) fn deserialize_u64_or_string_opt<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OptVisitor;

    impl<'de> serde::de::Visitor<'de> for OptVisitor {
        type Value = Option<u64>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("null, a u64 integer, or a decimal string")
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }

        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            d: D2,
        ) -> Result<Option<u64>, D2::Error> {
            deserialize_u64_or_string(d).map(Some)
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Option<u64>, E> {
            Ok(Some(v))
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Option<u64>, E> {
            u64::try_from(v)
                .map(Some)
                .map_err(|_| E::custom("negative integer for u64"))
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Option<u64>, E> {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            trimmed
                .parse::<u64>()
                .map(Some)
                .map_err(|_| E::custom("invalid decimal string for u64"))
        }
    }

    deserializer.deserialize_any(OptVisitor)
}

// ---------------------------------------------------------------------------
// Room Protocol v2 (`mp2`) & Cloud Auth Models (`docs/ROOM_PROTOCOL_V2.md`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct RoomInviteRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RoomInviteResponse {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub party_id: u64,
    #[serde(default)]
    pub room_code: String,
    #[serde(default)]
    pub share_url: String,
    #[serde(default)]
    pub handle_url: String,
    #[serde(default)]
    pub ws_path: String,
    #[serde(default)]
    pub invited_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoomEnterRequest {
    pub target: String,
    pub client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RoomMemberSummary {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub account_id: u64,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RoomEnterResponse {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub party_id: u64,
    #[serde(default)]
    pub room_code: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub share_url: String,
    #[serde(default)]
    pub ws_path: String,
    #[serde(default)]
    pub members: Vec<RoomMemberSummary>,
}

#[derive(Serialize)]
struct RoomLeaveWire {
    party_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RoomLeaveResponse {
    pub left: bool,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub party_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LiveFriendItem {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub account_id: u64,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub presence: String,
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub party_room_code: Option<String>,
    #[serde(default)]
    pub joinable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PendingRoomInvite {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub party_id: u64,
    #[serde(default)]
    pub room_code: String,
    #[serde(default)]
    pub from_handle: String,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LiveFriendsResponse {
    #[serde(default)]
    pub friends: Vec<LiveFriendItem>,
    #[serde(default)]
    pub pending_invites: Vec<PendingRoomInvite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSessionStartRequest {
    pub device_pubkey: [u8; 32],
    pub device_label: String,
    pub client: String,
}

#[derive(Serialize)]
struct AuthSessionStartWire<'a> {
    device_pubkey_b64: String,
    device_label: &'a str,
    client: &'a str,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct AuthSessionStartResponse {
    pub flow_id: String,
    pub poll_token: String,
    pub user_code: String,
    pub verify_url: String,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub expires_at_ms: u64,
}

impl fmt::Debug for AuthSessionStartResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSessionStartResponse")
            .field("flow_id", &self.flow_id)
            .field("poll_token", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verify_url", &self.verify_url)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Serialize)]
struct AuthSessionPollWire<'a> {
    flow_id: &'a str,
    poll_token: &'a str,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthSessionPollResponse {
    Pending {
        #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
        expires_at_ms: Option<u64>,
    },
    Approved {
        #[serde(deserialize_with = "deserialize_u64_or_string")]
        account_id: u64,
        handle: String,
        #[serde(deserialize_with = "deserialize_u64_or_string")]
        device_id: u64,
        root_pubkey_b64: String,
        device_cwt_b64: String,
        #[serde(deserialize_with = "deserialize_u64_or_string")]
        cwt_expires_ms: u64,
        #[serde(default)]
        session_token: Option<String>,
    },
    Expired,
    Denied,
}

impl fmt::Debug for AuthSessionPollResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending { expires_at_ms } => f
                .debug_struct("Pending")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::Approved {
                account_id,
                handle,
                device_id,
                root_pubkey_b64,
                device_cwt_b64: _,
                cwt_expires_ms,
                session_token: _,
            } => f
                .debug_struct("Approved")
                .field("account_id", account_id)
                .field("handle", handle)
                .field("device_id", device_id)
                .field("root_pubkey_b64", root_pubkey_b64)
                .field("device_cwt_b64", &"[REDACTED]")
                .field("cwt_expires_ms", cwt_expires_ms)
                .field("session_token", &"[REDACTED]")
                .finish(),
            Self::Expired => write!(f, "Expired"),
            Self::Denied => write!(f, "Denied"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct RenewMyDeviceResponse {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub device_id: u64,
    pub device_cwt_b64: String,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub cwt_expires_ms: u64,
}

impl fmt::Debug for RenewMyDeviceResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenewMyDeviceResponse")
            .field("device_id", &self.device_id)
            .field("device_cwt_b64", &"[REDACTED]")
            .field("cwt_expires_ms", &self.cwt_expires_ms)
            .finish()
    }
}
