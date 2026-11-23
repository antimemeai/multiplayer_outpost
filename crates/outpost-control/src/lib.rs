//! TLS 1.3-only HTTP/1.1 + RFC 6455 WebSocket `MP1` control-plane client.

#![deny(
    unsafe_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

pub mod clock;
pub mod http;
pub mod tls;
pub mod ws;

pub use clock::{sleep_aware_now_ms, wall_now_ms, wall_now_secs};
pub use http::{
    AccountDeviceInfo, AccountMeResponse, ApprovePartyRequest, ApprovePartyRequestResponse,
    BlockAccountResponse, ControlClient, ControlClientConfig, ControlError, CreatePartyRequest,
    CreatePartyResponse, DEFAULT_REQUEST_TIMEOUT, DeviceLinkApproveRequest,
    DeviceLinkApproveResponse, DeviceLinkClaimResponse, DeviceLinkCreateResponse,
    DeviceLinkInspectResponse, DeviceLinkPollResponse, DisbandPartyResponse, EnrollDeviceRequest,
    EnrollDeviceResponse, FriendEdge, FriendRequestResponse, HealthResponse, JoinPartyRequest,
    JoinPartyResponse, KickMemberResponse, LeavePartyResponse, ListFriendsResponse,
    ListPartyRequestsResponse, MAX_CLOCK_OFFSET_MS, MAX_FETCH_REDIRECTS, MAX_FETCH_TIMEOUT,
    MAX_RESPONSE_BODY_BYTES, MAX_RESPONSE_HEADERS_BYTES, MAX_RETRY_AFTER_MS, MIN_RETRY_AFTER_MS,
    MintPartyInviteRequest, MintPartyInviteResponse, PartyJoinRequestItem, PartySummaryResponse,
    PromoteMemberResponse, PublicAccountResponse, PublicDeviceInfo, RawHttpResponse,
    RecoverLookupResponse, RegisterAccountRequest, RegisterAccountResponse,
    RejectPartyRequestResponse, RemoveFriendResponse, RenameHandleResponse,
    RenewDeviceCwtResponse, RequestSigner, ResolvedHandleResponse, RevokeDeviceResponse,
    RevokePartyInviteResponse, SIGNATURE_LIFETIME_SECS, SignedHeaders, WebSessionApproveResponse,
    WebSessionInspectResponse, fetch_https_bytes, generate_nonce, probe_https_get,
    sanitize_server_error, sign_request, validate_link_code,
};
pub use tls::{
    DEFAULT_API_AUTHORITY, build_tls13_client_config_with_roots, default_tls13_client_config,
};
pub use ws::{
    CHURN_THRESHOLD, CHURN_WINDOW_MS, ChurnStatus, EndpointUpdateCoalescer, EvictionChurnDetector,
    MIN_ENDPOINT_UPDATE_INTERVAL_MS, MP1_PING_TEXT, MP1_PONG_TEXT, Mp1WsClient, Mp1WsEvent,
    Mp1WsTarget, WsConnectError, WsError,
};
