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
pub mod mp2;
pub mod tls;
pub mod ws;

pub use clock::{sleep_aware_now_ms, wall_now_ms, wall_now_secs};
pub use http::{
    AccountDeviceInfo, AccountEncKeysResponse, AccountMeResponse, AckInboxResponse,
    ApprovePartyRequest, ApprovePartyRequestResponse, AuthSessionPollResponse,
    AuthSessionStartRequest, AuthSessionStartResponse, BlockAccountResponse, ControlClient,
    ControlClientConfig, ControlError, CreatePartyRequest, CreatePartyResponse,
    DEFAULT_REQUEST_TIMEOUT, DeviceEncKeyInfo, DeviceLinkApproveRequest, DeviceLinkApproveResponse,
    DeviceLinkClaimResponse, DeviceLinkCreateResponse, DeviceLinkInspectResponse,
    DeviceLinkPollResponse, DisbandPartyResponse, ENC_CERT_BYTES, EnrollDeviceRequest,
    EnrollDeviceResponse, FriendEdge, FriendRequestResponse, HealthResponse, InboxDropItem,
    InboxDropsResponse, JoinPartyRequest, JoinPartyResponse, KickMemberResponse,
    LeavePartyResponse, ListFriendsResponse, ListPartyRequestsResponse, LiveFriendItem,
    LiveFriendsResponse, MAX_CLOCK_OFFSET_MS, MAX_DISCOVERED_RELAYS, MAX_ENC_KEYS_RESPONSE_BYTES,
    MAX_FETCH_REDIRECTS, MAX_FETCH_TIMEOUT, MAX_INBOX_GET_RESPONSE_BYTES, MAX_INBOX_PENDING_DROPS,
    MAX_INBOX_POST_BODY_BYTES, MAX_INBOX_RECIPIENT_DEVICES, MAX_RELAY_METADATA_CHARS,
    MAX_RESPONSE_BODY_BYTES, MAX_RESPONSE_HEADERS_BYTES, MAX_RETRY_AFTER_MS, MIN_RETRY_AFTER_MS,
    MintPartyInviteRequest, MintPartyInviteResponse, PartyJoinRequestItem, PartySummaryResponse,
    PendingRoomInvite, PostInboxDropRequest, PostInboxDropResponse, PromoteMemberResponse,
    PublicAccountResponse, PublicDeviceInfo, PutDeviceEncKeyResponse, RawHttpResponse,
    RecoverLookupResponse, RegisterAccountRequest, RegisterAccountResponse,
    RejectPartyRequestResponse, RelayInfo, RelaysResponse, RemoveFriendResponse,
    RenameHandleResponse, RenewDeviceCwtResponse, RenewMyDeviceResponse, RequestSigner,
    ResolvedHandleResponse, RevokeDeviceResponse, RevokePartyInviteResponse, RoomEnterRequest,
    RoomEnterResponse, RoomInviteRequest, RoomInviteResponse, RoomLeaveResponse, RoomMemberSummary,
    SIGNATURE_LIFETIME_SECS, SignedHeaders, WebSessionApproveResponse, WebSessionInspectResponse,
    WrappedDeviceKey, fetch_https_bytes, generate_nonce, is_public_routable_ip, probe_https_get,
    sanitize_server_error, sign_request, validate_link_code,
};
pub use mp2::{
    MAX_MP2_BODY_BYTES, MAX_MP2_FRAME_BYTES, MP2_PING_TEXT, MP2_PONG_TEXT, MP2_SUBPROTOCOL,
    Mp2Ack, Mp2Event, Mp2EventKind, Mp2Hello, Mp2Member, Mp2RoomEvent, Mp2RoomSocket, Mp2SelfInfo,
    Mp2Sender, Mp2WsError, parse_mp2_server_text, validate_mp2_ws_path,
};
pub use tls::{
    DEFAULT_API_AUTHORITY, build_tls13_client_config_with_roots, default_tls13_client_config,
};
pub use ws::{
    CHURN_THRESHOLD, CHURN_WINDOW_MS, ChurnStatus, EndpointUpdateCoalescer, EvictionChurnDetector,
    MIN_ENDPOINT_UPDATE_INTERVAL_MS, MP1_PING_TEXT, MP1_PONG_TEXT, Mp1WsClient, Mp1WsEvent,
    Mp1WsTarget, WsConnectError, WsError,
};
