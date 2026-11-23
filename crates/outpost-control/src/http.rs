//! TLS 1.3-only HTTP/1.1 REST client with strict RFC 9421 + RFC 9530 signing,
//! bounded ingress, idempotency preservation across retries, and scoped `clock_skew` retry.

use core::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use bytes::{Bytes, BytesMut};
use ed25519_dalek::{Signer as _, SigningKey};
use http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use mp_protocol::{
    AccountId, DeviceId, EndpointDescriptor, HttpMethod, KeyId, PartyId, PartyInviteId,
    PartyJoinMode, PartyVisibility, RelayPolicy, RequestId, Rfc9421Error, Rfc9421Request,
    build_signature_base, compute_content_digest, parse_signature_input, sha256,
    validate_path_and_query,
};
use serde::{Deserialize, Serialize};

use crate::clock::wall_now_ms;
use crate::tls::{
    DEFAULT_API_AUTHORITY, canonicalize_authority, connect_tls13, default_tls13_client_config,
};
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
    Api {
        status: u16,
        error: String,
        server_now_ms: Option<u64>,
        retry_after_ms: Option<u64>,
        raw_body: String,
    },
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
            Self::ResponseTooLarge => write!(f, "response body exceeds 16 KiB limit"),
            Self::InvalidJsonResponse(msg) => write!(f, "invalid JSON response: {msg}"),
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
/// or `reg.<sha256(root_pubkey)[..16]>`).
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
        let digest = sha256(&pubkey);
        let mut prefix = [0u8; 16];
        if let Some(head) = digest.get(..16) {
            prefix.copy_from_slice(head);
        }
        Self {
            key_id: KeyId::Registration {
                root_pubkey_sha256_prefix: prefix,
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
        let timeout = self.config.request_timeout;
        tokio::time::timeout(timeout, async {
            let tls = connect_tls13(
                &self.config.authority,
                self.config.connect_addr,
                &self.config.tls_config,
                timeout,
            )
            .await?;

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

            let canonical_authority = canonicalize_authority(&self.config.authority)?;

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

            let mut header_bytes: usize = 0;
            for (name, value) in resp.headers() {
                header_bytes = header_bytes
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.as_bytes().len())
                    .saturating_add(4);
                if header_bytes > MAX_RESPONSE_HEADERS_BYTES {
                    return Err(ControlError::ResponseHeadersTooLarge);
                }
            }

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
            })
        })
        .await
        .map_err(|_| ControlError::Timeout)?
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

fn parse_api_error(resp: RawHttpResponse) -> ControlError {
    let raw_body = String::from_utf8_lossy(&resp.body).into_owned();
    let parsed = serde_json::from_slice::<ApiErrorBody>(&resp.body).ok();
    ControlError::Api {
        status: resp.status,
        error: parsed
            .as_ref()
            .and_then(|p| p.error.clone())
            .unwrap_or_else(|| format!("http_{}", resp.status)),
        server_now_ms: parsed.as_ref().and_then(|p| p.server_now_ms),
        retry_after_ms: parsed.as_ref().and_then(|p| p.retry_after_ms),
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
