//! Static catalog of all 17 MCP tools (9 core + 4 Xbox Live lifecycle + `party_post_card` + 3 E2EE dead-drop inbox tools)
//! and strict argument validation.
//!
//! Zero namespace collision with `https://multiplayer.tech/mcp` or `blackbird-command-post`.

use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mp_protocol::MAX_SAFE_ID;
use outpost_core::fence::{SecretMatchKind, scan_outbound_secrets};
use outpost_core::inbox_crypto::INBOX_MAX_PLAINTEXT_BYTES;
use outpost_core::p2p_wire::{
    MAX_BRIDGE_PAYLOAD_BYTES, MAX_CHAT_BODY_BYTES, MAX_ROOM_SCOPE_BYTES,
};
use serde_json::{Map, Value, json};

use crate::backend::{
    BoardPostReq, FriendAddReq, InboxAckArgs, InboxReadArgs, InboxSendArgs, PartyInviteReq,
    PartyJoinReq, PartyLeaveReq, PartyPollReq, PartyPostCardReq, PartySendReq, PartyWaitReq,
};

pub const SERVER_NAME: &str = "multiplayer-outpost";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const DEFAULT_WAIT_TIMEOUT_MS: u32 = 25_000;
pub const MAX_WAIT_TIMEOUT_MS: u32 = 45_000;
pub const DEFAULT_POLL_LIMIT: u16 = 50;
pub const MAX_POLL_LIMIT: u16 = 100;
pub const DEFAULT_POLL_MAX_BYTES: u32 = 512 * 1024;
pub const MAX_POLL_MAX_BYTES: u32 = 512 * 1024;
pub const MAX_AGENT_CARD_FILES: usize = 16;
pub const MAX_AGENT_CARD_JSON_BYTES: usize = 2048;
pub const VALID_AGENT_CARD_STATUSES: [&str; 5] =
    ["done", "working", "testing", "blocked", "error"];

pub const INBOX_MAX_RECIPIENT_CHARS: usize = 64;
pub const INBOX_MIN_TTL_SECS: u64 = 300;
pub const INBOX_MAX_TTL_SECS: u64 = 604_800;
pub const INBOX_MAX_ACK_IDS: usize = 16;

/// Exact list of all 17 MCP tool names (9 core + 4 Xbox Live lifecycle + `party_post_card` + 3 Dead-Drop Inbox).
pub const TOOL_NAMES: [&str; 17] = [
    "outpost_status",
    "party_list",
    "party_members",
    "party_send",
    "board_post",
    "party_poll",
    "board_read",
    "party_wait",
    "party_friends",
    "party_invite",
    "party_join",
    "party_leave",
    "friend_add",
    "party_post_card",
    "inbox_send",
    "inbox_read",
    "inbox_ack",
];

/// Parsed and validated MCP tool invocation ready for backend dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedToolCall {
    OutpostStatus,
    PartyList,
    PartyMembers { party_id: u64 },
    PartySend(PartySendReq),
    PartyPostCard(PartyPostCardReq),
    BoardPost(BoardPostReq),
    PartyPoll(PartyPollReq),
    BoardRead(PartyPollReq),
    PartyWait(PartyWaitReq),
    PartyFriends,
    PartyInvite(PartyInviteReq),
    PartyJoin(PartyJoinReq),
    PartyLeave(PartyLeaveReq),
    FriendAdd(FriendAddReq),
    InboxSend(InboxSendArgs),
    InboxRead(InboxReadArgs),
    InboxAck(InboxAckArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolParseError {
    pub message: String,
}

impl ToolParseError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for ToolParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ToolParseError {}

/// Returns the static MCP `tools/list` catalog for all 9 Spec v2 tools.
/// Requires zero daemon or network I/O.
pub fn tool_catalog() -> Vec<Value> {
    let safe_id_schema = || {
        json!({
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_SAFE_ID
        })
    };
    let safe_seq_schema = || {
        json!({
            "type": "integer",
            "minimum": 0,
            "maximum": MAX_SAFE_ID
        })
    };
    let read_only_ann = || {
        json!({
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        })
    };
    let send_ann = || {
        json!({
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": false,
            "openWorldHint": true
        })
    };

    vec![
        json!({
            "name": "outpost_status",
            "description": "Return local multiplayer-outpost identity, CWT expiry, daemon epoch/PID, active party summary, unpinned/key-mismatch alerts, and dual-host churn status.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
        json!({
            "name": "party_list",
            "description": "List the active party (0 or 1 in v1) with party_id, party_epoch, relay_policy, member_count, next_seq, and daemon_epoch.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
        json!({
            "name": "party_members",
            "description": "List cryptographically verified members of a party including account_id, device_id, server handle, trust_state, safety_number, and MP1/P2P connectivity.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema()
                },
                "required": ["party_id"],
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
        json!({
            "name": "party_send",
            "description": "Send a party chat message over mp2 WSS (or P2P fallback) to authenticated party members. Fails closed on key_mismatch or detected secret material.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema(),
                    "body": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_CHAT_BODY_BYTES
                    },
                    "room_scope": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_ROOM_SCOPE_BYTES
                    },
                    "target_device_id": safe_id_schema()
                },
                "required": ["party_id", "body"],
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "board_post",
            "description": "Post an agent_card / opaque base64-encoded board envelope over mp2 WSS (or P2P fallback) to authenticated party members.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema(),
                    "room_scope": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_ROOM_SCOPE_BYTES
                    },
                    "payload_b64": {
                        "type": "string"
                    }
                },
                "required": ["party_id", "room_scope", "payload_b64"],
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "party_poll",
            "description": "Non-blocking byte-budgeted cursor read of party chat, control notices, and membership events after after_seq. Peer content is nonce-fenced as untrusted data.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema(),
                    "cursor_epoch": safe_id_schema(),
                    "after_seq": safe_seq_schema(),
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_POLL_LIMIT,
                        "default": DEFAULT_POLL_LIMIT
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_POLL_MAX_BYTES,
                        "default": DEFAULT_POLL_MAX_BYTES
                    }
                },
                "required": ["party_id", "after_seq"],
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
        json!({
            "name": "board_read",
            "description": "Non-blocking byte-budgeted cursor read filtered to P2P Lane 1 board envelopes (0x02 bridge_envelope) with base64 payload and verified provenance.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema(),
                    "cursor_epoch": safe_id_schema(),
                    "after_seq": safe_seq_schema(),
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_POLL_LIMIT,
                        "default": DEFAULT_POLL_LIMIT
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_POLL_MAX_BYTES,
                        "default": DEFAULT_POLL_MAX_BYTES
                    }
                },
                "required": ["party_id", "after_seq"],
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
        json!({
            "name": "party_wait",
            "description": "Bounded long-poll waiting for new party events after after_seq (default 25000 ms, hard cap 45000 ms). Honors notifications/cancelled and emits progress only when _meta.progressToken is supplied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema(),
                    "cursor_epoch": safe_id_schema(),
                    "after_seq": safe_seq_schema(),
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_WAIT_TIMEOUT_MS,
                        "default": DEFAULT_WAIT_TIMEOUT_MS
                    }
                },
                "required": ["party_id", "after_seq"],
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
        json!({
            "name": "party_friends",
            "description": "Return friends list with live presence, active joinable room codes, and pending party invites.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
        json!({
            "name": "party_invite",
            "description": "Create or reuse an active mp2 party room, attach to it, and optionally ring a friend by @handle. Returns room_code and share_url.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64
                    },
                    "name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64
                    }
                },
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "party_join",
            "description": "Join a party by @handle, 4-character room code, share URL (multiplayer.tech, mp.gg, clank.party), or omit target to accept your latest pending incoming invite.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "minLength": 0,
                        "maxLength": 256
                    }
                },
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "party_leave",
            "description": "Leave the current active party room (or an explicit party_id).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema()
                },
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "friend_add",
            "description": "Send or accept a friend request by @handle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64
                    }
                },
                "required": ["handle"],
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "party_post_card",
            "description": "Post a structured agent_card update (title, summary, optional status/diff_stat/files/agent_name) to the active party or an explicit party_id over mp2 WSS. Fails closed on secret material and caps JSON payload at 2048 bytes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "party_id": safe_id_schema(),
                    "title": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200
                    },
                    "summary": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1500
                    },
                    "files": {
                        "type": "array",
                        "maxItems": MAX_AGENT_CARD_FILES,
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256
                        }
                    },
                    "status": {
                        "type": "string",
                        "enum": ["done", "working", "testing", "blocked", "error"]
                    },
                    "diff_stat": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128
                    },
                    "agent_name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64
                    }
                },
                "required": ["title", "summary"],
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "inbox_send",
            "description": "Send an E2EE Suite 1 async dead-drop inbox message to a recipient (@handle or account_id). Verifies recipient CWTs and encryption subkey certificates locally and refuses detected secret material.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": INBOX_MAX_RECIPIENT_CHARS
                    },
                    "body": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": INBOX_MAX_PLAINTEXT_BYTES
                    },
                    "ttl_secs": {
                        "type": "integer",
                        "minimum": INBOX_MIN_TTL_SECS,
                        "maximum": INBOX_MAX_TTL_SECS
                    }
                },
                "required": ["recipient", "body"],
                "additionalProperties": false
            },
            "annotations": send_ann()
        }),
        json!({
            "name": "inbox_read",
            "description": "Fetch and locally decrypt pending E2EE async dead-drop inbox messages. Optionally acknowledges decrypted drops when ack=true. Every decrypted body is nonce-fenced as untrusted external data.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ack": {
                        "type": "boolean",
                        "default": false
                    }
                },
                "additionalProperties": false
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": false,
                "idempotentHint": false,
                "openWorldHint": true
            }
        }),
        json!({
            "name": "inbox_ack",
            "description": "Acknowledge 1..=16 pending dead-drop inbox message IDs after processing so the server can prune delivered drops.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "drop_ids": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": INBOX_MAX_ACK_IDS,
                        "items": safe_id_schema()
                    }
                },
                "required": ["drop_ids"],
                "additionalProperties": false
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": true,
                "openWorldHint": true
            }
        }),
    ]
}

/// Builds and size-validates (`<= 2048` bytes) a compact UTF-8 JSON `agent_card` payload.
pub fn build_agent_card_json(
    title: &str,
    summary: &str,
    files: &[String],
    status: Option<&str>,
    diff_stat: Option<&str>,
    agent_name: Option<&str>,
) -> Result<String, ToolParseError> {
    let title_trimmed = title.trim();
    if title_trimmed.is_empty() {
        return Err(ToolParseError::new("field 'title' must not be empty"));
    }
    let summary_trimmed = summary.trim();
    if summary_trimmed.is_empty() {
        return Err(ToolParseError::new("field 'summary' must not be empty"));
    }
    if files.len() > MAX_AGENT_CARD_FILES {
        return Err(ToolParseError::new(format!(
            "field 'files' exceeds max count of {MAX_AGENT_CARD_FILES}"
        )));
    }
    if let Some(st) = status
        && !VALID_AGENT_CARD_STATUSES.contains(&st)
    {
        return Err(ToolParseError::new(
            "field 'status' must be one of done|working|testing|blocked|error",
        ));
    }

    let mut obj = Map::new();
    obj.insert("title".to_string(), Value::String(title_trimmed.to_string()));
    obj.insert(
        "summary".to_string(),
        Value::String(summary_trimmed.to_string()),
    );
    if let Some(st) = status {
        obj.insert("status".to_string(), Value::String(st.to_string()));
    }
    if let Some(diff) = diff_stat.map(str::trim).filter(|s| !s.is_empty()) {
        obj.insert("diff_stat".to_string(), Value::String(diff.to_string()));
    }
    if let Some(agent) = agent_name.map(str::trim).filter(|s| !s.is_empty()) {
        obj.insert("agent_name".to_string(), Value::String(agent.to_string()));
    }
    if !files.is_empty() {
        let arr: Vec<Value> = files.iter().map(|f| Value::String(f.clone())).collect();
        obj.insert("files".to_string(), Value::Array(arr));
    }

    let encoded = serde_json::to_string(&Value::Object(obj))
        .map_err(|e| ToolParseError::new(format!("failed to serialize agent_card JSON: {e}")))?;
    if encoded.len() > MAX_AGENT_CARD_JSON_BYTES {
        return Err(ToolParseError::new(format!(
            "agent_card JSON payload exceeds max length of {MAX_AGENT_CARD_JSON_BYTES} bytes ({} bytes)",
            encoded.len()
        )));
    }
    Ok(encoded)
}

/// Scans static text for protected credential prefixes (`mprk1_`, `mpinv1_`, `mppi1_`, `mpdl1_`,
/// `mpcs1_`, `mpguest1_`), PEM private/secret/recovery keys, `.mpkey` files, and recovery keys.
pub fn scan_static_secret_text(text: &str) -> Option<SecretMatchKind> {
    const SENTINEL: [u8; 32] = [
        0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8,
        0x34, 0x10, 0x82, 0x27, 0x6b, 0xf3, 0xa2, 0x72, 0x51, 0xf8, 0x6c, 0x6a, 0x11, 0xd0, 0xc1,
        0x8e, 0x95,
    ];

    let lower = text.to_ascii_lowercase();
    if lower.contains("mprk1_") {
        return Some(SecretMatchKind::RecoveryKey);
    }
    if lower.contains("mpdl1_") {
        return Some(SecretMatchKind::DeviceLinkToken);
    }
    if lower.contains("mpinv1_")
        || lower.contains("mppi1_")
        || lower.contains("mpcs1_")
        || lower.contains("mpguest1_")
    {
        return Some(SecretMatchKind::InviteToken);
    }

    if let Some(kind) = scan_outbound_secrets(text.as_bytes(), &SENTINEL, &[])
        && !matches!(
            kind,
            SecretMatchKind::OwnDeviceSecret | SecretMatchKind::OwnDeviceCwt
        )
    {
        return Some(kind);
    }
    None
}

/// Enforces strict secret refusal across `title`, `summary`, `diff_stat`, `agent_name`, and `files`.
pub fn scan_card_secrets(req: &PartyPostCardReq) -> Result<(), SecretMatchKind> {
    if let Some(kind) = scan_static_secret_text(&req.title) {
        return Err(kind);
    }
    if let Some(kind) = scan_static_secret_text(&req.summary) {
        return Err(kind);
    }
    if let Some(ref diff) = req.diff_stat
        && let Some(kind) = scan_static_secret_text(diff)
    {
        return Err(kind);
    }
    if let Some(ref agent) = req.agent_name
        && let Some(kind) = scan_static_secret_text(agent)
    {
        return Err(kind);
    }
    for f in &req.files {
        if let Some(kind) = scan_static_secret_text(f) {
            return Err(kind);
        }
    }
    Ok(())
}

fn reject_unknown_keys(args: &Map<String, Value>, allowed: &[&str]) -> Result<(), ToolParseError> {
    for key in args.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ToolParseError::new(format!("unknown argument '{key}'")));
        }
    }
    Ok(())
}

fn parse_exact_u64(val: &Value, field: &str) -> Result<u64, ToolParseError> {
    let Some(n) = val.as_number() else {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be an integer"
        )));
    };
    let Some(u) = n.as_u64() else {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be a non-negative integer"
        )));
    };
    Ok(u)
}

fn require_safe_id(args: &Map<String, Value>, field: &str) -> Result<u64, ToolParseError> {
    let Some(val) = args.get(field) else {
        return Err(ToolParseError::new(format!(
            "missing required field '{field}'"
        )));
    };
    let v = parse_exact_u64(val, field)?;
    if v == 0 || v > MAX_SAFE_ID {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be in 1..={MAX_SAFE_ID}"
        )));
    }
    Ok(v)
}

fn optional_safe_id(args: &Map<String, Value>, field: &str) -> Result<Option<u64>, ToolParseError> {
    let Some(val) = args.get(field) else {
        return Ok(None);
    };
    if val.is_null() {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be an integer in 1..={MAX_SAFE_ID}, not null"
        )));
    }
    let v = parse_exact_u64(val, field)?;
    if v == 0 || v > MAX_SAFE_ID {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be in 1..={MAX_SAFE_ID}"
        )));
    }
    Ok(Some(v))
}

fn require_safe_seq(args: &Map<String, Value>, field: &str) -> Result<u64, ToolParseError> {
    let Some(val) = args.get(field) else {
        return Err(ToolParseError::new(format!(
            "missing required field '{field}'"
        )));
    };
    let v = parse_exact_u64(val, field)?;
    if v > MAX_SAFE_ID {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be in 0..={MAX_SAFE_ID}"
        )));
    }
    Ok(v)
}

fn require_string<'a>(
    args: &'a Map<String, Value>,
    field: &str,
    min_len: usize,
    max_len: usize,
) -> Result<&'a str, ToolParseError> {
    let Some(val) = args.get(field) else {
        return Err(ToolParseError::new(format!(
            "missing required field '{field}'"
        )));
    };
    let Some(s) = val.as_str() else {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be a string"
        )));
    };
    if s.len() < min_len {
        return Err(ToolParseError::new(format!(
            "field '{field}' must not be empty"
        )));
    }
    if s.len() > max_len {
        return Err(ToolParseError::new(format!(
            "field '{field}' exceeds max length of {max_len} bytes"
        )));
    }
    Ok(s)
}

fn optional_string(
    args: &Map<String, Value>,
    field: &str,
    min_len: usize,
    max_len: usize,
) -> Result<Option<String>, ToolParseError> {
    let Some(val) = args.get(field) else {
        return Ok(None);
    };
    let Some(s) = val.as_str() else {
        return Err(ToolParseError::new(format!(
            "field '{field}' must be a string"
        )));
    };
    if s.len() < min_len {
        return Err(ToolParseError::new(format!(
            "field '{field}' must not be empty"
        )));
    }
    if s.len() > max_len {
        return Err(ToolParseError::new(format!(
            "field '{field}' exceeds max length of {max_len} bytes"
        )));
    }
    Ok(Some(s.to_string()))
}

fn parse_poll_args(args: &Map<String, Value>) -> Result<PartyPollReq, ToolParseError> {
    reject_unknown_keys(
        args,
        &["party_id", "cursor_epoch", "after_seq", "limit", "max_bytes"],
    )?;
    let party_id = require_safe_id(args, "party_id")?;
    let cursor_epoch = optional_safe_id(args, "cursor_epoch")?;
    let after_seq = require_safe_seq(args, "after_seq")?;

    let limit = match args.get("limit") {
        None => DEFAULT_POLL_LIMIT,
        Some(val) => {
            let v = parse_exact_u64(val, "limit")?;
            if v == 0 || v > u64::from(MAX_POLL_LIMIT) {
                return Err(ToolParseError::new(format!(
                    "field 'limit' must be in 1..={MAX_POLL_LIMIT}"
                )));
            }
            v as u16
        }
    };

    let max_bytes = match args.get("max_bytes") {
        None => DEFAULT_POLL_MAX_BYTES,
        Some(val) => {
            let v = parse_exact_u64(val, "max_bytes")?;
            if v == 0 || v > u64::from(MAX_POLL_MAX_BYTES) {
                return Err(ToolParseError::new(format!(
                    "field 'max_bytes' must be in 1..={MAX_POLL_MAX_BYTES}"
                )));
            }
            v as u32
        }
    };

    Ok(PartyPollReq {
        party_id,
        cursor_epoch,
        after_seq,
        limit,
        max_bytes,
    })
}

/// Validates and parses an MCP `tools/call` invocation.
/// `next_client_msg_id` is invoked only for write tools (`party_send`, `board_post`).
pub fn parse_tool_call(
    name: &str,
    args: &Map<String, Value>,
    next_client_msg_id: impl FnOnce() -> Result<u64, ToolParseError>,
) -> Result<ParsedToolCall, ToolParseError> {
    match name {
        "outpost_status" => {
            reject_unknown_keys(args, &[])?;
            Ok(ParsedToolCall::OutpostStatus)
        }
        "party_list" => {
            reject_unknown_keys(args, &[])?;
            Ok(ParsedToolCall::PartyList)
        }
        "party_members" => {
            reject_unknown_keys(args, &["party_id"])?;
            let party_id = require_safe_id(args, "party_id")?;
            Ok(ParsedToolCall::PartyMembers { party_id })
        }
        "party_send" => {
            reject_unknown_keys(
                args,
                &["party_id", "body", "room_scope", "target_device_id"],
            )?;
            let party_id = require_safe_id(args, "party_id")?;
            let body = require_string(args, "body", 1, MAX_CHAT_BODY_BYTES)?.to_string();
            let room_scope = optional_string(args, "room_scope", 1, MAX_ROOM_SCOPE_BYTES)?;
            let target_device_id = optional_safe_id(args, "target_device_id")?;
            let client_msg_id = next_client_msg_id()?;
            Ok(ParsedToolCall::PartySend(PartySendReq {
                party_id,
                body,
                room_scope,
                target_device_id,
                client_msg_id,
            }))
        }
        "board_post" => {
            reject_unknown_keys(args, &["party_id", "room_scope", "payload_b64"])?;
            let party_id = require_safe_id(args, "party_id")?;
            let room_scope =
                require_string(args, "room_scope", 1, MAX_ROOM_SCOPE_BYTES)?.to_string();
            // Max base64 length for 1 MiB payload is ceil(1_048_576 / 3) * 4 = 1_398_104 bytes.
            let max_b64_len = (MAX_BRIDGE_PAYLOAD_BYTES / 3 + 1) * 4;
            let payload_b64 = require_string(args, "payload_b64", 0, max_b64_len)?;
            let payload = B64
                .decode(payload_b64.as_bytes())
                .map_err(|_| ToolParseError::new("field 'payload_b64' is not valid base64"))?;
            if payload.len() > MAX_BRIDGE_PAYLOAD_BYTES {
                return Err(ToolParseError::new(format!(
                    "decoded payload exceeds max length of {MAX_BRIDGE_PAYLOAD_BYTES} bytes"
                )));
            }
            let client_msg_id = next_client_msg_id()?;
            Ok(ParsedToolCall::BoardPost(BoardPostReq {
                party_id,
                room_scope,
                payload,
                client_msg_id,
            }))
        }
        "party_poll" => Ok(ParsedToolCall::PartyPoll(parse_poll_args(args)?)),
        "board_read" => Ok(ParsedToolCall::BoardRead(parse_poll_args(args)?)),
        "party_wait" => {
            reject_unknown_keys(args, &["party_id", "cursor_epoch", "after_seq", "timeout_ms"])?;
            let party_id = require_safe_id(args, "party_id")?;
            let cursor_epoch = optional_safe_id(args, "cursor_epoch")?;
            let after_seq = require_safe_seq(args, "after_seq")?;
            let timeout_ms = match args.get("timeout_ms") {
                None => DEFAULT_WAIT_TIMEOUT_MS,
                Some(val) => {
                    let raw = parse_exact_u64(val, "timeout_ms")?;
                    if raw > MAX_SAFE_ID {
                        return Err(ToolParseError::new(format!(
                            "field 'timeout_ms' must be in 0..={MAX_SAFE_ID}"
                        )));
                    }
                    raw.min(u64::from(MAX_WAIT_TIMEOUT_MS)) as u32
                }
            };
            Ok(ParsedToolCall::PartyWait(PartyWaitReq {
                party_id,
                cursor_epoch,
                after_seq,
                timeout_ms,
            }))
        }
        "party_friends" => {
            reject_unknown_keys(args, &[])?;
            Ok(ParsedToolCall::PartyFriends)
        }
        "party_invite" => {
            reject_unknown_keys(args, &["handle", "name"])?;
            let handle = optional_string(args, "handle", 1, 64)?;
            let name = optional_string(args, "name", 1, 64)?;
            Ok(ParsedToolCall::PartyInvite(PartyInviteReq { handle, name }))
        }
        "party_join" => {
            reject_unknown_keys(args, &["target"])?;
            let target = optional_string(args, "target", 0, 256)?;
            Ok(ParsedToolCall::PartyJoin(PartyJoinReq { target }))
        }
        "party_leave" => {
            reject_unknown_keys(args, &["party_id"])?;
            let party_id = optional_safe_id(args, "party_id")?;
            Ok(ParsedToolCall::PartyLeave(PartyLeaveReq { party_id }))
        }
        "friend_add" => {
            reject_unknown_keys(args, &["handle"])?;
            let handle = require_string(args, "handle", 1, 64)?.to_string();
            Ok(ParsedToolCall::FriendAdd(FriendAddReq { handle }))
        }
        "party_post_card" => {
            reject_unknown_keys(
                args,
                &[
                    "party_id",
                    "title",
                    "summary",
                    "files",
                    "status",
                    "diff_stat",
                    "agent_name",
                ],
            )?;
            let party_id = optional_safe_id(args, "party_id")?;
            let title = require_string(args, "title", 1, 200)?.trim().to_string();
            if title.is_empty() {
                return Err(ToolParseError::new("field 'title' must not be empty"));
            }
            let summary = require_string(args, "summary", 1, 1500)?.trim().to_string();
            if summary.is_empty() {
                return Err(ToolParseError::new("field 'summary' must not be empty"));
            }
            let files = match args.get("files") {
                None => Vec::new(),
                Some(Value::Array(items)) => {
                    if items.len() > MAX_AGENT_CARD_FILES {
                        return Err(ToolParseError::new(format!(
                            "field 'files' exceeds max count of {MAX_AGENT_CARD_FILES}"
                        )));
                    }
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let Some(s) = item.as_str() else {
                            return Err(ToolParseError::new(
                                "each entry in 'files' must be a string",
                            ));
                        };
                        let trimmed = s.trim();
                        if trimmed.is_empty() || trimmed.len() > 256 {
                            return Err(ToolParseError::new(
                                "each entry in 'files' must be 1..=256 bytes",
                            ));
                        }
                        out.push(trimmed.to_string());
                    }
                    out
                }
                Some(_) => {
                    return Err(ToolParseError::new(
                        "field 'files' must be an array of strings",
                    ));
                }
            };
            let status = match optional_string(args, "status", 1, 16)? {
                None => None,
                Some(raw) => {
                    let norm = raw.trim().to_string();
                    if !VALID_AGENT_CARD_STATUSES.contains(&norm.as_str()) {
                        return Err(ToolParseError::new(
                            "field 'status' must be one of done|working|testing|blocked|error",
                        ));
                    }
                    Some(norm)
                }
            };
            let diff_stat = optional_string(args, "diff_stat", 1, 128)?
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let agent_name = optional_string(args, "agent_name", 1, 64)?
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            // Validate serialized JSON size <= 2048 bytes before dispatching.
            let _ = build_agent_card_json(
                &title,
                &summary,
                &files,
                status.as_deref(),
                diff_stat.as_deref(),
                agent_name.as_deref(),
            )?;

            let client_msg_id = next_client_msg_id()?;
            Ok(ParsedToolCall::PartyPostCard(PartyPostCardReq {
                party_id,
                title,
                summary,
                files,
                status,
                diff_stat,
                agent_name,
                client_msg_id,
            }))
        }
        "inbox_send" => {
            reject_unknown_keys(args, &["recipient", "body", "ttl_secs"])?;
            let recipient_raw = require_string(args, "recipient", 1, INBOX_MAX_RECIPIENT_CHARS)?;
            let recipient_chars = recipient_raw.chars().count();
            if recipient_raw.trim().is_empty() || recipient_chars > INBOX_MAX_RECIPIENT_CHARS {
                return Err(ToolParseError::new(format!(
                    "field 'recipient' must be 1..={INBOX_MAX_RECIPIENT_CHARS} non-empty characters"
                )));
            }
            let body = require_string(args, "body", 1, INBOX_MAX_PLAINTEXT_BYTES)?.to_string();
            let ttl_secs = match args.get("ttl_secs") {
                None => None,
                Some(val) => {
                    if val.is_null() {
                        return Err(ToolParseError::new(format!(
                            "field 'ttl_secs' must be an integer in {INBOX_MIN_TTL_SECS}..={INBOX_MAX_TTL_SECS}, not null"
                        )));
                    }
                    let v = parse_exact_u64(val, "ttl_secs")?;
                    if !(INBOX_MIN_TTL_SECS..=INBOX_MAX_TTL_SECS).contains(&v) {
                        return Err(ToolParseError::new(format!(
                            "field 'ttl_secs' must be in {INBOX_MIN_TTL_SECS}..={INBOX_MAX_TTL_SECS}"
                        )));
                    }
                    Some(v)
                }
            };
            Ok(ParsedToolCall::InboxSend(InboxSendArgs {
                recipient: recipient_raw.to_string(),
                body,
                ttl_secs,
            }))
        }
        "inbox_read" => {
            reject_unknown_keys(args, &["ack"])?;
            let ack = match args.get("ack") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => {
                    return Err(ToolParseError::new("field 'ack' must be a boolean"));
                }
            };
            Ok(ParsedToolCall::InboxRead(InboxReadArgs { ack }))
        }
        "inbox_ack" => {
            reject_unknown_keys(args, &["drop_ids"])?;
            let Some(arr_val) = args.get("drop_ids") else {
                return Err(ToolParseError::new("missing required field 'drop_ids'"));
            };
            let Some(arr) = arr_val.as_array() else {
                return Err(ToolParseError::new(
                    "field 'drop_ids' must be an array of integers",
                ));
            };
            if arr.is_empty() || arr.len() > INBOX_MAX_ACK_IDS {
                return Err(ToolParseError::new(format!(
                    "field 'drop_ids' must contain 1..={INBOX_MAX_ACK_IDS} entries"
                )));
            }
            let mut drop_ids = Vec::with_capacity(arr.len());
            for item in arr {
                let id = parse_exact_u64(item, "drop_ids[]")?;
                if id == 0 || id > MAX_SAFE_ID {
                    return Err(ToolParseError::new(format!(
                        "drop_id must be in 1..={MAX_SAFE_ID}"
                    )));
                }
                drop_ids.push(id);
            }
            Ok(ParsedToolCall::InboxAck(InboxAckArgs { drop_ids }))
        }
        _ => Err(ToolParseError::new(format!("unknown tool '{name}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn party_post_card_builds_compact_json_and_enforces_caps() {
        let json_str = build_agent_card_json(
            "Shipped mp2 cards",
            "Added structured card rendering",
            &["src/chat.rs".to_string(), "src/tools.rs".to_string()],
            Some("done"),
            Some("+42 -12"),
            Some("Claude Code"),
        );
        let Ok(encoded) = json_str else {
            unreachable!("valid card should encode");
        };
        assert!(encoded.len() <= MAX_AGENT_CARD_JSON_BYTES);
        let parsed: Value = match serde_json::from_str(&encoded) {
            Ok(v) => v,
            Err(_) => unreachable!("encoded card must be valid JSON"),
        };
        assert_eq!(parsed.get("title").and_then(Value::as_str), Some("Shipped mp2 cards"));
        assert_eq!(parsed.get("status").and_then(Value::as_str), Some("done"));
        assert_eq!(parsed.get("diff_stat").and_then(Value::as_str), Some("+42 -12"));
        assert_eq!(parsed.get("agent_name").and_then(Value::as_str), Some("Claude Code"));

        // Reject invalid status
        assert!(build_agent_card_json("t", "s", &[], Some("bogus"), None, None).is_err());

        // Reject > 16 files
        let too_many: Vec<String> = (0..17).map(|i| format!("f{i}.rs")).collect();
        assert!(build_agent_card_json("t", "s", &too_many, None, None, None).is_err());

        // Reject JSON > 2048 bytes
        let big_files: Vec<String> = (0..16).map(|i| format!("{i}_{}", "a".repeat(180))).collect();
        assert!(build_agent_card_json("t", "s", &big_files, Some("done"), None, None).is_err());
    }

    #[test]
    fn card_secret_refusal_catches_all_forbidden_prefixes_and_pem_across_fields() {
        let base = PartyPostCardReq {
            party_id: Some(1),
            title: "Clean title".to_string(),
            summary: "Clean summary".to_string(),
            files: vec!["src/main.rs".to_string()],
            status: Some("done".to_string()),
            diff_stat: Some("+10 -2".to_string()),
            agent_name: Some("Claude Code".to_string()),
            client_msg_id: 1,
        };
        assert!(scan_card_secrets(&base).is_ok());

        for secret in [
            "mprk1_ABCD1234",
            "mpinv1_secret_token",
            "mppi1_secret_token",
            "mpdl1_secret_token",
            "mpcs1_session_token",
            "mpguest1_guest_token",
            "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ] {
            let mut in_title = base.clone();
            in_title.title = format!("fix {secret}");
            assert!(scan_card_secrets(&in_title).is_err(), "missed secret in title: {secret}");

            let mut in_summary = base.clone();
            in_summary.summary = format!("detail {secret}");
            assert!(scan_card_secrets(&in_summary).is_err(), "missed secret in summary: {secret}");

            let mut in_diff = base.clone();
            in_diff.diff_stat = Some(secret.to_string());
            assert!(scan_card_secrets(&in_diff).is_err(), "missed secret in diff_stat: {secret}");

            let mut in_files = base.clone();
            in_files.files = vec![format!("path/{secret}.txt")];
            assert!(scan_card_secrets(&in_files).is_err(), "missed secret in files: {secret}");
        }
    }
}
