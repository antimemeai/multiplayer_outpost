//! Server-hosted TLS 1.3 WebSocket Room Protocol v2 (`mp2`) client.
//!
//! Connects to `GET /v1/parties/:id/ws` with `Sec-WebSocket-Protocol: mp2` over TLS 1.3 + HTTP/1.1
//! ALPN (port `443`), using the exact UTF-8 JSON frame schema shared across `multiplayer_site`,
//! `blackbird`, `multiplayer_outpost`, and Web Browser clients (`docs/ROOM_PROTOCOL_V2.md`).

use core::fmt;

use futures_util::{SinkExt as _, StreamExt as _};
use mp_protocol::{HttpMethod, PartyId};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_websockets::{ClientBuilder, CloseCode, Limits, Message, WebSocketStream};

use crate::clock::sleep_aware_now_ms;
use crate::http::{
    ControlClientConfig, ControlError, RequestSigner, deserialize_u64_or_string,
    deserialize_u64_or_string_opt, sanitize_server_error, sign_request,
};
use crate::tls::{canonicalize_authority, connect_tls13};
use crate::ws::{
    PrefixedIo, WsConnectError, build_ws_upgrade_request_with_protocol, generate_ws_key,
    perform_bounded_upgrade_read_with_protocol,
};

/// RFC 6455 negotiated subprotocol for Room Protocol v2.
pub const MP2_SUBPROTOCOL: &str = "mp2";
/// Zero-DO-wakeup text heartbeat ping (`MP2:PING`).
pub const MP2_PING_TEXT: &str = "MP2:PING";
/// Zero-DO-wakeup text heartbeat pong (`MP2:PONG`).
pub const MP2_PONG_TEXT: &str = "MP2:PONG";
/// Hard cap on inbound/outbound `mp2` UTF-8 JSON application frame size (`48 KiB`).
pub const MAX_MP2_FRAME_BYTES: usize = 48 * 1024;
/// Hard cap on inbound `mp2` MLS control signal frame size (`256 KiB`).
pub const MAX_MP2_CONTROL_FRAME_BYTES: usize = 256 * 1024;
/// Hard cap on `mp2` opaque event `body` size (`32 KiB`).
pub const MAX_MP2_BODY_BYTES: usize = 32 * 1024;

/// Runtime errors on an established [`Mp2RoomSocket`].
#[derive(Debug)]
pub enum Mp2WsError {
    FrameTooLarge { len: usize, max_len: usize },
    BodyTooLarge { len: usize, max_len: usize },
    InvalidJson(String),
    UnexpectedBinaryFrame,
    Websocket(tokio_websockets::Error),
}

impl fmt::Display for Mp2WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { len, max_len } => {
                write!(f, "mp2 frame size {len} exceeds {max_len} B cap")
            }
            Self::BodyTooLarge { len, max_len } => {
                write!(f, "mp2 body size {len} exceeds {max_len} B cap")
            }
            Self::InvalidJson(msg) => write!(f, "invalid mp2 JSON frame: {msg}"),
            Self::UnexpectedBinaryFrame => write!(f, "unexpected binary WebSocket frame on mp2"),
            Self::Websocket(e) => write!(f, "mp2 WebSocket stream error: {e}"),
        }
    }
}

impl std::error::Error for Mp2WsError {}

/// Canonical `mp2` event kind (`"chat"`, `"agent_card"`, `"system"`, `"e2ee_app"`, or `"e2ee_ephemeral"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mp2EventKind {
    Chat,
    AgentCard,
    System,
    E2eeApp,
    E2eeEphemeral,
}

impl Mp2EventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::AgentCard => "agent_card",
            Self::System => "system",
            Self::E2eeApp => "e2ee_app",
            Self::E2eeEphemeral => "e2ee_ephemeral",
        }
    }
}

/// Self identity block inside `mp2` `hello`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Mp2SelfInfo {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub account_id: u64,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub is_guest: bool,
    #[serde(default)]
    pub is_browser: bool,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    pub device_id: Option<u64>,
}

/// Live room member roster entry inside `mp2` `hello` and `presence`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Mp2Member {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub account_id: u64,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub is_guest: bool,
    #[serde(default)]
    pub is_browser: bool,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub agent_state: Option<String>,
    #[serde(default)]
    pub agent_summary: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    pub device_id: Option<u64>,
    #[serde(default)]
    pub nick: Option<String>,
}

impl Mp2Member {
    /// Returns `true` when this member is connected via a browser session.
    pub fn is_browser_origin(&self) -> bool {
        self.is_browser
            || self.client.trim().eq_ignore_ascii_case("web")
            || self.client.trim().eq_ignore_ascii_case("browser")
    }
}

/// Authoritative sender block attached by `PartyDO` to every `mp2` `event`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Mp2Sender {
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub account_id: u64,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub is_guest: bool,
    #[serde(default)]
    pub is_browser: bool,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    pub device_id: Option<u64>,
    #[serde(default)]
    pub nick: Option<String>,
}

impl Mp2Sender {
    /// Returns `true` when the message originated from a web browser session
    /// (`is_browser: true` or `client == "web"` / `"browser"`). Browser-originated
    /// messages MUST always be treated as untrusted remote input even when
    /// `sender.handle` or `sender.account_id` matches the local operator.
    pub fn is_browser_origin(&self) -> bool {
        self.is_browser
            || self.client.trim().eq_ignore_ascii_case("web")
            || self.client.trim().eq_ignore_ascii_case("browser")
    }
}

/// Authoritative sequenced `mp2` room event (`chat`, `agent_card`, `system`, `e2ee_app`, or `e2ee_ephemeral`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Mp2Event {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub seq: u64,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub ts_ms: u64,
    #[serde(default)]
    pub client_msg_id: Option<String>,
    pub sender: Mp2Sender,
    #[serde(default = "default_target")]
    pub target: String,
    pub kind: Mp2EventKind,
    #[serde(default = "default_body_encoding")]
    pub body_encoding: String,
    #[serde(default)]
    pub body: String,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    pub mls_epoch: Option<u64>,
    #[serde(default)]
    pub e2ee_mode: Option<u8>,
    #[serde(default)]
    pub group_id_b64: Option<String>,
}

fn default_target() -> String {
    "@all".to_owned()
}

fn default_body_encoding() -> String {
    "utf8".to_owned()
}

/// Server `hello` snapshot delivered immediately on `mp2` upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Mp2Hello {
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub party_id: u64,
    #[serde(default)]
    pub room_code: String,
    #[serde(default)]
    pub name: String,
    pub self_info: Mp2SelfInfo,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub latest_seq: u64,
    #[serde(default)]
    pub members: Vec<Mp2Member>,
    #[serde(default)]
    pub history: Vec<Mp2Event>,
    #[serde(default)]
    pub e2ee_mode: u8,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub mls_epoch: u64,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub min_allowed_mls_epoch: u64,
    #[serde(default)]
    pub mls_rekey_required: bool,
    #[serde(default)]
    pub group_id_b64: Option<String>,
    #[serde(default)]
    pub party_ds_pubkey_b64: Option<String>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub mls_invite_epoch: u64,
    #[serde(default)]
    pub topic: Option<String>,
}

/// Authoritative delivery acknowledgement for an outbound `send`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Mp2Ack {
    pub client_msg_id: String,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub seq: u64,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub ts_ms: u64,
}

/// Decoded inbound events from [`Mp2RoomSocket::next_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mp2RoomEvent {
    Hello(Mp2Hello),
    Event(Mp2Event),
    Ack(Mp2Ack),
    Presence {
        members: Vec<Mp2Member>,
    },
    MlsCommitTentative {
        party_id: Option<u64>,
        group_id_b64: String,
        parent_epoch: u64,
        target_epoch: u64,
        commit_sha256_b64: String,
        committer_account_id: u64,
        committer_device_id: u64,
        commit_b64: String,
        proposal_blobs_b64: Vec<String>,
        deadline_ms: u64,
    },
    MlsCommitFinalized {
        party_id: Option<u64>,
        group_id_b64: String,
        epoch: u64,
        commit_sha256_b64: String,
        commit_b64: String,
        proposal_blobs_b64: Vec<String>,
        confirmed_transcript_hash_b64: Option<String>,
    },
    MlsRekeyNeeded {
        party_id: Option<u64>,
        group_id_b64: String,
        mls_epoch: u64,
        min_allowed_mls_epoch: u64,
        reason: String,
        proposal_blobs_b64: Vec<String>,
        elected_committer_device_id: Option<u64>,
    },
    MlsWelcomeReady {
        party_id: Option<u64>,
        group_id_b64: String,
        target_epoch: u64,
        welcome_id: Option<u64>,
    },
    MlsJoinRequest {
        kp_id: Option<u64>,
        account_id: u64,
        device_id: u64,
        invite_id: Option<u64>,
        kp_ref_b64: String,
        kp_blob_b64: String,
        join_proof_b64: Option<String>,
    },
    MlsCommitDiscarded {
        committer_device_id: u64,
        reason: String,
        strikes_5m: u64,
        rotate_committer: bool,
    },
    EphemeralEvent {
        seq: Option<u64>,
        ts_ms: u64,
        sender: Mp2Sender,
        mls_epoch: Option<u64>,
        target: String,
        kind: Mp2EventKind,
        body_encoding: String,
        body: String,
    },
    Error {
        code: String,
        message: String,
        retry_ms: Option<u64>,
    },
    Pong,
    Closed {
        code: Option<u16>,
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
struct RawInboundFrame {
    #[serde(default)]
    v: u8,
    t: String,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    party_id: Option<u64>,
    #[serde(default)]
    room_code: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(rename = "self", default)]
    self_info: Option<Mp2SelfInfo>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    latest_seq: Option<u64>,
    #[serde(default)]
    members: Option<Vec<Mp2Member>>,
    #[serde(default)]
    history: Option<Vec<Mp2Event>>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    seq: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    ts_ms: Option<u64>,
    #[serde(default)]
    client_msg_id: Option<String>,
    #[serde(default)]
    sender: Option<Mp2Sender>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    kind: Option<Mp2EventKind>,
    #[serde(default)]
    body_encoding: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    retry_ms: Option<u64>,
    #[serde(default)]
    e2ee_mode: Option<u8>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    mls_epoch: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    min_allowed_mls_epoch: Option<u64>,
    #[serde(default)]
    mls_rekey_required: Option<bool>,
    #[serde(default)]
    group_id_b64: Option<String>,
    #[serde(default)]
    party_ds_pubkey_b64: Option<String>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    mls_invite_epoch: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    parent_epoch: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    target_epoch: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    epoch: Option<u64>,
    #[serde(default)]
    commit_sha256_b64: Option<String>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    committer_account_id: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    committer_device_id: Option<u64>,
    #[serde(default)]
    commit_b64: Option<String>,
    #[serde(default)]
    commit_blob_b64: Option<String>,
    #[serde(default)]
    proposal_blobs_b64: Option<Vec<String>>,
    #[serde(default)]
    proposals_b64: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    deadline_ms: Option<u64>,
    #[serde(default)]
    confirmed_transcript_hash_b64: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    elected_committer_device_id: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    welcome_id: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    kp_id: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    account_id: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    device_id: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    invite_id: Option<u64>,
    #[serde(default)]
    kp_ref_b64: Option<String>,
    #[serde(default)]
    kp_blob_b64: Option<String>,
    #[serde(default)]
    join_proof_b64: Option<String>,
    #[serde(default, deserialize_with = "deserialize_u64_or_string_opt")]
    strikes_5m: Option<u64>,
    #[serde(default)]
    rotate_committer: Option<bool>,
}

fn is_mls_control_frame_type(t: &str) -> bool {
    matches!(
        t,
        "mls_commit_tentative"
            | "mls_commit_finalized"
            | "mls_rekey_needed"
            | "mls_welcome_ready"
            | "mls_welcome_available"
            | "mls_join_request"
            | "mls_key_package_available"
            | "mls_commit_discarded"
    )
}

/// Parses a single UTF-8 JSON `mp2` server frame (or `"MP2:PONG"`).
pub fn parse_mp2_server_text(text: &str) -> Result<Mp2RoomEvent, Mp2WsError> {
    if text == MP2_PONG_TEXT {
        return Ok(Mp2RoomEvent::Pong);
    }
    if text.len() > MAX_MP2_CONTROL_FRAME_BYTES {
        return Err(Mp2WsError::FrameTooLarge {
            len: text.len(),
            max_len: MAX_MP2_CONTROL_FRAME_BYTES,
        });
    }
    let raw: RawInboundFrame =
        serde_json::from_str(text).map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
    if !is_mls_control_frame_type(&raw.t) && text.len() > MAX_MP2_FRAME_BYTES {
        return Err(Mp2WsError::FrameTooLarge {
            len: text.len(),
            max_len: MAX_MP2_FRAME_BYTES,
        });
    }
    if raw.v != 0 && raw.v != 2 {
        return Err(Mp2WsError::InvalidJson(format!(
            "unsupported mp2 frame version {}",
            raw.v
        )));
    }
    match raw.t.as_str() {
        "hello" => {
            let party_id = raw
                .party_id
                .ok_or_else(|| Mp2WsError::InvalidJson("hello missing party_id".to_owned()))?;
            let self_info = raw
                .self_info
                .ok_or_else(|| Mp2WsError::InvalidJson("hello missing self".to_owned()))?;
            Ok(Mp2RoomEvent::Hello(Mp2Hello {
                party_id,
                room_code: raw.room_code.unwrap_or_default(),
                name: raw.name.unwrap_or_default(),
                self_info,
                latest_seq: raw.latest_seq.unwrap_or(0),
                members: raw.members.unwrap_or_default(),
                history: raw.history.unwrap_or_default(),
                e2ee_mode: raw.e2ee_mode.unwrap_or(0),
                mls_epoch: raw.mls_epoch.unwrap_or(0),
                min_allowed_mls_epoch: raw.min_allowed_mls_epoch.unwrap_or(0),
                mls_rekey_required: raw.mls_rekey_required.unwrap_or(false),
                group_id_b64: raw.group_id_b64,
                party_ds_pubkey_b64: raw.party_ds_pubkey_b64,
                mls_invite_epoch: raw.mls_invite_epoch.unwrap_or(0),
                topic: raw.topic,
            }))
        }
        "event" => {
            let seq = raw
                .seq
                .ok_or_else(|| Mp2WsError::InvalidJson("event missing seq".to_owned()))?;
            let sender = raw
                .sender
                .ok_or_else(|| Mp2WsError::InvalidJson("event missing sender".to_owned()))?;
            let kind = raw
                .kind
                .ok_or_else(|| Mp2WsError::InvalidJson("event missing kind".to_owned()))?;
            let body = raw.body.unwrap_or_default();
            if body.len() > MAX_MP2_BODY_BYTES {
                return Err(Mp2WsError::BodyTooLarge {
                    len: body.len(),
                    max_len: MAX_MP2_BODY_BYTES,
                });
            }
            Ok(Mp2RoomEvent::Event(Mp2Event {
                seq,
                ts_ms: raw.ts_ms.unwrap_or(0),
                client_msg_id: raw.client_msg_id,
                sender,
                target: raw.target.unwrap_or_else(default_target),
                kind,
                body_encoding: raw.body_encoding.unwrap_or_else(default_body_encoding),
                body,
                mls_epoch: raw.mls_epoch,
                e2ee_mode: raw.e2ee_mode,
                group_id_b64: raw.group_id_b64,
            }))
        }
        "ack" => {
            let client_msg_id = raw
                .client_msg_id
                .ok_or_else(|| Mp2WsError::InvalidJson("ack missing client_msg_id".to_owned()))?;
            let seq = raw
                .seq
                .ok_or_else(|| Mp2WsError::InvalidJson("ack missing seq".to_owned()))?;
            Ok(Mp2RoomEvent::Ack(Mp2Ack {
                client_msg_id,
                seq,
                ts_ms: raw.ts_ms.unwrap_or(0),
            }))
        }
        "presence" => Ok(Mp2RoomEvent::Presence {
            members: raw.members.unwrap_or_default(),
        }),
        "mls_commit_tentative" => {
            let group_id_b64 = raw.group_id_b64.unwrap_or_default();
            let parent_epoch = raw.parent_epoch.ok_or_else(|| {
                Mp2WsError::InvalidJson("mls_commit_tentative missing parent_epoch".to_owned())
            })?;
            let target_epoch = raw.target_epoch.ok_or_else(|| {
                Mp2WsError::InvalidJson("mls_commit_tentative missing target_epoch".to_owned())
            })?;
            let commit_b64 = raw.commit_b64.or(raw.commit_blob_b64).ok_or_else(|| {
                Mp2WsError::InvalidJson("mls_commit_tentative missing commit_b64".to_owned())
            })?;
            Ok(Mp2RoomEvent::MlsCommitTentative {
                party_id: raw.party_id,
                group_id_b64,
                parent_epoch,
                target_epoch,
                commit_sha256_b64: raw.commit_sha256_b64.unwrap_or_default(),
                committer_account_id: raw.committer_account_id.unwrap_or(0),
                committer_device_id: raw.committer_device_id.unwrap_or(0),
                commit_b64,
                proposal_blobs_b64: raw
                    .proposal_blobs_b64
                    .or(raw.proposals_b64)
                    .unwrap_or_default(),
                deadline_ms: raw.deadline_ms.unwrap_or(0),
            })
        }
        "mls_commit_finalized" => {
            let group_id_b64 = raw.group_id_b64.unwrap_or_default();
            let epoch = raw.epoch.or(raw.target_epoch).or(raw.mls_epoch).ok_or_else(|| {
                Mp2WsError::InvalidJson("mls_commit_finalized missing epoch".to_owned())
            })?;
            let commit_b64 = raw.commit_b64.or(raw.commit_blob_b64).ok_or_else(|| {
                Mp2WsError::InvalidJson("mls_commit_finalized missing commit_b64".to_owned())
            })?;
            Ok(Mp2RoomEvent::MlsCommitFinalized {
                party_id: raw.party_id,
                group_id_b64,
                epoch,
                commit_sha256_b64: raw.commit_sha256_b64.unwrap_or_default(),
                commit_b64,
                proposal_blobs_b64: raw
                    .proposal_blobs_b64
                    .or(raw.proposals_b64)
                    .unwrap_or_default(),
                confirmed_transcript_hash_b64: raw.confirmed_transcript_hash_b64,
            })
        }
        "mls_rekey_needed" => Ok(Mp2RoomEvent::MlsRekeyNeeded {
            party_id: raw.party_id,
            group_id_b64: raw.group_id_b64.unwrap_or_default(),
            mls_epoch: raw.mls_epoch.unwrap_or(0),
            min_allowed_mls_epoch: raw.min_allowed_mls_epoch.unwrap_or(0),
            reason: sanitize_server_error(raw.reason.as_deref().unwrap_or("rekey_needed")),
            proposal_blobs_b64: raw
                .proposal_blobs_b64
                .or(raw.proposals_b64)
                .unwrap_or_default(),
            elected_committer_device_id: raw.elected_committer_device_id,
        }),
        "mls_welcome_ready" | "mls_welcome_available" => Ok(Mp2RoomEvent::MlsWelcomeReady {
            party_id: raw.party_id,
            group_id_b64: raw.group_id_b64.unwrap_or_default(),
            target_epoch: raw.target_epoch.or(raw.mls_epoch).unwrap_or(0),
            welcome_id: raw.welcome_id,
        }),
        "mls_join_request" | "mls_key_package_available" => {
            let account_id = raw.account_id.ok_or_else(|| {
                Mp2WsError::InvalidJson("mls_join_request missing account_id".to_owned())
            })?;
            let device_id = raw.device_id.ok_or_else(|| {
                Mp2WsError::InvalidJson("mls_join_request missing device_id".to_owned())
            })?;
            let kp_blob_b64 = raw.kp_blob_b64.unwrap_or_default();
            Ok(Mp2RoomEvent::MlsJoinRequest {
                kp_id: raw.kp_id,
                account_id,
                device_id,
                invite_id: raw.invite_id,
                kp_ref_b64: raw.kp_ref_b64.unwrap_or_default(),
                kp_blob_b64,
                join_proof_b64: raw.join_proof_b64,
            })
        }
        "mls_commit_discarded" => Ok(Mp2RoomEvent::MlsCommitDiscarded {
            committer_device_id: raw.committer_device_id.unwrap_or(0),
            reason: sanitize_server_error(raw.reason.as_deref().unwrap_or("discarded")),
            strikes_5m: raw.strikes_5m.unwrap_or(0),
            rotate_committer: raw.rotate_committer.unwrap_or(false),
        }),
        "ephemeral_event" => {
            let sender = raw.sender.ok_or_else(|| {
                Mp2WsError::InvalidJson("ephemeral_event missing sender".to_owned())
            })?;
            let body = raw.body.unwrap_or_default();
            if body.len() > MAX_MP2_BODY_BYTES {
                return Err(Mp2WsError::BodyTooLarge {
                    len: body.len(),
                    max_len: MAX_MP2_BODY_BYTES,
                });
            }
            Ok(Mp2RoomEvent::EphemeralEvent {
                seq: raw.seq,
                ts_ms: raw.ts_ms.unwrap_or(0),
                sender,
                mls_epoch: raw.mls_epoch,
                target: raw.target.unwrap_or_else(|| "*".to_owned()),
                kind: raw.kind.unwrap_or(Mp2EventKind::E2eeEphemeral),
                body_encoding: raw.body_encoding.unwrap_or_else(|| "opaque_b64".to_owned()),
                body,
            })
        }
        "error" => Ok(Mp2RoomEvent::Error {
            code: sanitize_server_error(raw.code.as_deref().unwrap_or("error")),
            message: sanitize_server_error(raw.message.as_deref().unwrap_or("room error")),
            retry_ms: raw.retry_ms,
        }),
        "pong" => Ok(Mp2RoomEvent::Pong),
        other => Err(Mp2WsError::InvalidJson(format!(
            "unknown mp2 frame type '{}'",
            sanitize_server_error(other)
        ))),
    }
}

#[derive(Serialize)]
struct OutboundSendFrame<'a> {
    v: u8,
    t: &'static str,
    client_msg_id: &'a str,
    kind: Mp2EventKind,
    target: &'a str,
    body_encoding: &'a str,
    body: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mls_epoch: Option<u64>,
}

/// Builds a canonical outbound `mp2` `e2ee_app` JSON frame, strictly enforcing
/// `target == "*"`, `kind == "e2ee_app"`, `body_encoding == "opaque_b64"`, and `<= 32 KiB` body cap.
pub fn build_e2ee_app_frame_json(
    client_msg_id: &str,
    mls_epoch: u64,
    body_b64: &str,
) -> Result<String, Mp2WsError> {
    if body_b64.is_empty() {
        return Err(Mp2WsError::InvalidJson(
            "e2ee_app body_b64 must not be empty".to_owned(),
        ));
    }
    if body_b64.len() > MAX_MP2_BODY_BYTES {
        return Err(Mp2WsError::BodyTooLarge {
            len: body_b64.len(),
            max_len: MAX_MP2_BODY_BYTES,
        });
    }
    let frame = OutboundSendFrame {
        v: 2,
        t: "send",
        client_msg_id,
        kind: Mp2EventKind::E2eeApp,
        target: "*",
        body_encoding: "opaque_b64",
        body: body_b64,
        mls_epoch: Some(mls_epoch),
    };
    let text = serde_json::to_string(&frame).map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
    if text.len() > MAX_MP2_FRAME_BYTES {
        return Err(Mp2WsError::FrameTooLarge {
            len: text.len(),
            max_len: MAX_MP2_FRAME_BYTES,
        });
    }
    Ok(text)
}

/// Builds a canonical outbound `mp2` `e2ee_ephemeral` JSON frame, strictly enforcing
/// `target == "*"`, `kind == "e2ee_ephemeral"`, `body_encoding == "opaque_b64"`, and `<= 32 KiB` body cap.
pub fn build_e2ee_ephemeral_frame_json(
    client_msg_id: &str,
    mls_epoch: u64,
    body_b64: &str,
) -> Result<String, Mp2WsError> {
    if body_b64.is_empty() {
        return Err(Mp2WsError::InvalidJson(
            "e2ee_ephemeral body_b64 must not be empty".to_owned(),
        ));
    }
    if body_b64.len() > MAX_MP2_BODY_BYTES {
        return Err(Mp2WsError::BodyTooLarge {
            len: body_b64.len(),
            max_len: MAX_MP2_BODY_BYTES,
        });
    }
    let frame = OutboundSendFrame {
        v: 2,
        t: "ephemeral",
        client_msg_id,
        kind: Mp2EventKind::E2eeEphemeral,
        target: "*",
        body_encoding: "opaque_b64",
        body: body_b64,
        mls_epoch: Some(mls_epoch),
    };
    let text = serde_json::to_string(&frame).map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
    if text.len() > MAX_MP2_FRAME_BYTES {
        return Err(Mp2WsError::FrameTooLarge {
            len: text.len(),
            max_len: MAX_MP2_FRAME_BYTES,
        });
    }
    Ok(text)
}

#[derive(Serialize)]
struct OutboundResumeFrame {
    v: u8,
    t: &'static str,
    last_seq: u64,
}

#[derive(Serialize)]
struct OutboundStatusFrame<'a> {
    v: u8,
    t: &'static str,
    client: &'a str,
    agent_name: &'a str,
    agent_state: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_summary: Option<&'a str>,
}

#[derive(Serialize)]
struct OutboundNickFrame<'a> {
    v: u8,
    t: &'static str,
    nick: &'a str,
}

#[derive(Serialize)]
struct OutboundTopicFrame<'a> {
    v: u8,
    t: &'static str,
    topic: &'a str,
}

/// Strictly validates a server-supplied `mp2` WebSocket path before RFC 9421 signing.
///
/// Only canonical `/v1/parties/<party_id>/ws` paths with a valid decimal `PartyId` (no query,
/// fragment, traversal, whitespace, control characters, or extra segments) are accepted.
pub fn validate_mp2_ws_path(path: &str) -> Result<PartyId, ControlError> {
    let inner = path
        .strip_prefix("/v1/parties/")
        .and_then(|rest| rest.strip_suffix("/ws"))
        .ok_or_else(|| {
            ControlError::InvalidRequest("mp2 ws_path must match /v1/parties/<party_id>/ws".to_owned())
        })?;
    if inner.is_empty()
        || !inner.bytes().all(|b| b.is_ascii_digit())
        || (inner.len() > 1 && inner.starts_with('0'))
    {
        return Err(ControlError::InvalidRequest(
            "mp2 ws_path contains invalid party_id segment".to_owned(),
        ));
    }
    let id = inner.parse::<u64>().map_err(|_| {
        ControlError::InvalidRequest("mp2 ws_path party_id overflows u64".to_owned())
    })?;
    PartyId::new(id).map_err(|_| {
        ControlError::InvalidRequest("mp2 ws_path party_id out of valid range".to_owned())
    })
}

/// Active TLS 1.3 + HTTP/1.1 ALPN RFC 6455 `mp2` Room WebSocket client.
pub struct Mp2RoomSocket {
    stream: WebSocketStream<PrefixedIo<TlsStream<TcpStream>>>,
    path: String,
    last_pong_ms: u64,
    e2ee_mode: u8,
}

impl fmt::Debug for Mp2RoomSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mp2RoomSocket")
            .field("path", &self.path)
            .field("last_pong_ms", &self.last_pong_ms)
            .field("e2ee_mode", &self.e2ee_mode)
            .finish_non_exhaustive()
    }
}

impl Mp2RoomSocket {
    /// Connects to `GET /v1/parties/<party_id>/ws` with `Sec-WebSocket-Protocol: mp2`.
    pub async fn connect_party(
        config: &ControlClientConfig,
        signer: &RequestSigner,
        clock_offset_ms: i64,
        party_id: PartyId,
    ) -> Result<Self, WsConnectError> {
        let path = format!("/v1/parties/{party_id}/ws");
        Self::connect_path(config, signer, clock_offset_ms, &path).await
    }

    /// Connects to an explicit `ws_path` (e.g. `"/v1/parties/12345/ws"`) with `Sec-WebSocket-Protocol: mp2`.
    pub async fn connect_path(
        config: &ControlClientConfig,
        signer: &RequestSigner,
        clock_offset_ms: i64,
        path: &str,
    ) -> Result<Self, WsConnectError> {
        let _party_id = validate_mp2_ws_path(path).map_err(WsConnectError::Transport)?;
        let canonical_authority =
            canonicalize_authority(&config.authority).map_err(WsConnectError::Transport)?;
        let signed = sign_request(
            signer,
            HttpMethod::Get,
            &canonical_authority,
            path,
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
        let upgrade_req = build_ws_upgrade_request_with_protocol(
            &canonical_authority,
            path,
            &ws_key,
            MP2_SUBPROTOCOL,
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

            perform_bounded_upgrade_read_with_protocol(&mut tls_stream, &ws_key, MP2_SUBPROTOCOL)
                .await
        })
        .await
        .map_err(|_| WsConnectError::Timeout)??;

        let limits = Limits::default().max_payload_len(Some(MAX_MP2_CONTROL_FRAME_BYTES));
        let stream = ClientBuilder::new()
            .limits(limits)
            .take_over(PrefixedIo::new(leftover, tls_stream));

        Ok(Self {
            stream,
            path: path.to_owned(),
            last_pong_ms: sleep_aware_now_ms(),
            e2ee_mode: 0,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn last_pong_ms(&self) -> u64 {
        self.last_pong_ms
    }

    pub const fn e2ee_mode(&self) -> u8 {
        self.e2ee_mode
    }

    pub fn set_e2ee_mode(&mut self, mode: u8) {
        self.e2ee_mode = mode;
    }

    pub fn silence_ms(&self) -> u64 {
        sleep_aware_now_ms().saturating_sub(self.last_pong_ms)
    }

    /// Sends the zero-DO-wakeup `"MP2:PING"` text heartbeat frame.
    pub async fn send_ping(&mut self) -> Result<(), Mp2WsError> {
        self.stream
            .send(Message::text(MP2_PING_TEXT))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Sends an idempotent `mp2` `send` frame (`chat`, `agent_card`, `system`, `e2ee_app`, or `e2ee_ephemeral`).
    ///
    /// In `e2ee_mode == 1` rooms, fails closed if `target != "*"` or `body_encoding != "opaque_b64"`.
    pub async fn send_event(
        &mut self,
        client_msg_id: &str,
        kind: Mp2EventKind,
        target: &str,
        body_encoding: &str,
        body: &str,
    ) -> Result<(), Mp2WsError> {
        if self.e2ee_mode == 1 && (target != "*" || body_encoding != "opaque_b64") {
            return Err(Mp2WsError::InvalidJson(
                "e2ee_mode == 1 requires target == \"*\" and body_encoding == \"opaque_b64\""
                    .to_owned(),
            ));
        }
        if body.len() > MAX_MP2_BODY_BYTES {
            return Err(Mp2WsError::BodyTooLarge {
                len: body.len(),
                max_len: MAX_MP2_BODY_BYTES,
            });
        }
        let frame = OutboundSendFrame {
            v: 2,
            t: "send",
            client_msg_id,
            kind,
            target,
            body_encoding,
            body,
            mls_epoch: None,
        };
        let text = serde_json::to_string(&frame)
            .map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
        if text.len() > MAX_MP2_FRAME_BYTES {
            return Err(Mp2WsError::FrameTooLarge {
                len: text.len(),
                max_len: MAX_MP2_FRAME_BYTES,
            });
        }
        self.stream
            .send(Message::text(text))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Sends an encrypted durable `e2ee_app` frame strictly enforcing outer `target == "*"`
    /// and `body_encoding == "opaque_b64"`.
    pub async fn send_e2ee_app(
        &mut self,
        client_msg_id: &str,
        mls_epoch: u64,
        body_b64: &str,
    ) -> Result<(), Mp2WsError> {
        let text = build_e2ee_app_frame_json(client_msg_id, mls_epoch, body_b64)?;
        self.stream
            .send(Message::text(text))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Sends an encrypted ephemeral `e2ee_ephemeral` frame strictly enforcing outer `target == "*"`
    /// and `body_encoding == "opaque_b64"`.
    pub async fn send_e2ee_ephemeral(
        &mut self,
        client_msg_id: &str,
        mls_epoch: u64,
        body_b64: &str,
    ) -> Result<(), Mp2WsError> {
        let text = build_e2ee_ephemeral_frame_json(client_msg_id, mls_epoch, body_b64)?;
        self.stream
            .send(Message::text(text))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Convenience helper for sending a UTF-8 `chat` message.
    pub async fn send_chat(
        &mut self,
        client_msg_id: &str,
        target: &str,
        body: &str,
    ) -> Result<(), Mp2WsError> {
        self.send_event(client_msg_id, Mp2EventKind::Chat, target, "utf8", body)
            .await
    }

    /// Convenience helper for sending an `agent_card` (opaque UTF-8 JSON or `opaque_b64`).
    pub async fn send_agent_card(
        &mut self,
        client_msg_id: &str,
        target: &str,
        body_encoding: &str,
        body: &str,
    ) -> Result<(), Mp2WsError> {
        self.send_event(
            client_msg_id,
            Mp2EventKind::AgentCard,
            target,
            body_encoding,
            body,
        )
        .await
    }

    /// Sends a `resume` request to catch up all events with `seq > last_seq`.
    pub async fn send_resume(&mut self, last_seq: u64) -> Result<(), Mp2WsError> {
        let frame = OutboundResumeFrame {
            v: 2,
            t: "resume",
            last_seq,
        };
        let text = serde_json::to_string(&frame)
            .map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
        self.stream
            .send(Message::text(text))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Sends a `status` frame updating local client/agent status pill in room presence.
    ///
    /// Suppressed completely (no-op) in `e2ee_mode == 1` rooms so agent name/state/summary
    /// metadata is NEVER leaked in cleartext to `PartyDO` (use [`Self::send_e2ee_ephemeral`] instead).
    pub async fn send_status(
        &mut self,
        client: &str,
        agent_name: &str,
        agent_state: &str,
        agent_summary: Option<&str>,
    ) -> Result<(), Mp2WsError> {
        if self.e2ee_mode == 1 {
            return Ok(());
        }
        let frame = OutboundStatusFrame {
            v: 2,
            t: "status",
            client,
            agent_name,
            agent_state,
            agent_summary,
        };
        let text = serde_json::to_string(&frame)
            .map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
        if text.len() > MAX_MP2_FRAME_BYTES {
            return Err(Mp2WsError::FrameTooLarge {
                len: text.len(),
                max_len: MAX_MP2_FRAME_BYTES,
            });
        }
        self.stream
            .send(Message::text(text))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Sends a `{ v: 2, t: "nick", nick }` frame in standard (`e2ee_mode == 0`) rooms.
    ///
    /// Suppressed (no-op) in `e2ee_mode == 1` rooms where nick updates MUST travel inside
    /// encrypted `e2ee_app` payloads (`{"mp_irc":1,"t":"nick","nick":...}`).
    pub async fn send_nick(&mut self, nick: &str) -> Result<(), Mp2WsError> {
        if self.e2ee_mode == 1 {
            return Ok(());
        }
        let frame = OutboundNickFrame {
            v: 2,
            t: "nick",
            nick,
        };
        let text = serde_json::to_string(&frame)
            .map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
        self.stream
            .send(Message::text(text))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Sends a `{ v: 2, t: "topic", topic }` frame in standard (`e2ee_mode == 0`) rooms.
    ///
    /// Suppressed (no-op) in `e2ee_mode == 1` rooms where topic updates MUST travel inside
    /// encrypted `e2ee_app` payloads (`{"mp_irc":1,"t":"topic","topic":...}`).
    pub async fn send_topic(&mut self, topic: &str) -> Result<(), Mp2WsError> {
        if self.e2ee_mode == 1 {
            return Ok(());
        }
        let frame = OutboundTopicFrame {
            v: 2,
            t: "topic",
            topic,
        };
        let text = serde_json::to_string(&frame)
            .map_err(|e| Mp2WsError::InvalidJson(e.to_string()))?;
        self.stream
            .send(Message::text(text))
            .await
            .map_err(Mp2WsError::Websocket)
    }

    /// Receives the next `mp2` room event (`Hello`, `Event`, `Ack`, `Presence`, MLS signals,
    /// `EphemeralEvent`, `Error`, `Pong`, or `Closed`), answering RFC 6455 Ping automatically.
    pub async fn next_event(&mut self) -> Result<Option<Mp2RoomEvent>, Mp2WsError> {
        loop {
            let Some(item) = self.stream.next().await else {
                return Ok(None);
            };
            let msg = match item {
                Ok(m) => m,
                Err(tokio_websockets::Error::PayloadTooLong { len, max_len }) => {
                    return Err(Mp2WsError::FrameTooLarge { len, max_len });
                }
                Err(e) => return Err(Mp2WsError::Websocket(e)),
            };

            if msg.is_ping() {
                self.stream.flush().await.map_err(Mp2WsError::Websocket)?;
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
                return Ok(Some(Mp2RoomEvent::Closed { code, reason }));
            }
            if msg.is_text() {
                let payload = msg.as_payload();
                if payload.len() > MAX_MP2_CONTROL_FRAME_BYTES {
                    return Err(Mp2WsError::FrameTooLarge {
                        len: payload.len(),
                        max_len: MAX_MP2_CONTROL_FRAME_BYTES,
                    });
                }
                let text = msg
                    .as_text()
                    .ok_or_else(|| Mp2WsError::InvalidJson("non-UTF8 text frame".to_owned()))?;
                let ev = parse_mp2_server_text(text)?;
                match &ev {
                    Mp2RoomEvent::Pong => {
                        self.last_pong_ms = sleep_aware_now_ms();
                    }
                    Mp2RoomEvent::Hello(hello) => {
                        self.e2ee_mode = hello.e2ee_mode;
                    }
                    _ => {}
                }
                return Ok(Some(ev));
            }
            if msg.is_binary() {
                return Err(Mp2WsError::UnexpectedBinaryFrame);
            }
        }
    }

    /// Gracefully sends an RFC 6455 Close frame and flushes.
    pub async fn close(&mut self, code: u16, reason: &str) -> Result<(), Mp2WsError> {
        let close_code = CloseCode::try_from(code).unwrap_or(CloseCode::NORMAL_CLOSURE);
        self.stream
            .send(Message::close(Some(close_code), reason))
            .await
            .map_err(Mp2WsError::Websocket)?;
        self.stream.flush().await.map_err(Mp2WsError::Websocket)
    }
}
