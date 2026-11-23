//! Static catalog of all 9 Spec v2 MCP tools and strict argument validation.
//!
//! Zero namespace collision with `https://multiplayer.tech/mcp` or `blackbird-command-post`.

use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mp_protocol::MAX_SAFE_ID;
use outpost_core::p2p_wire::{
    MAX_BRIDGE_PAYLOAD_BYTES, MAX_CHAT_BODY_BYTES, MAX_ROOM_SCOPE_BYTES,
};
use serde_json::{Map, Value, json};

use crate::backend::{BoardPostReq, PartyPollReq, PartySendReq, PartyWaitReq};

pub const SERVER_NAME: &str = "multiplayer-outpost";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const DEFAULT_WAIT_TIMEOUT_MS: u32 = 25_000;
pub const MAX_WAIT_TIMEOUT_MS: u32 = 45_000;
pub const DEFAULT_POLL_LIMIT: u16 = 50;
pub const MAX_POLL_LIMIT: u16 = 100;
pub const DEFAULT_POLL_MAX_BYTES: u32 = 512 * 1024;
pub const MAX_POLL_MAX_BYTES: u32 = 512 * 1024;

/// Exact list of all 9 Spec v2 MCP tool names.
pub const TOOL_NAMES: [&str; 9] = [
    "outpost_status",
    "party_list",
    "party_members",
    "party_send",
    "board_post",
    "party_poll",
    "board_read",
    "party_wait",
    "party_friends",
];

/// Parsed and validated MCP tool invocation ready for backend dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedToolCall {
    OutpostStatus,
    PartyList,
    PartyMembers { party_id: u64 },
    PartySend(PartySendReq),
    BoardPost(BoardPostReq),
    PartyPoll(PartyPollReq),
    BoardRead(PartyPollReq),
    PartyWait(PartyWaitReq),
    PartyFriends,
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
            "description": "Send a P2P Lane 1 chat message (0x01 chat_message) to pinned trusted party peers. Fails closed on key_mismatch or detected secret material.",
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
            "description": "Post an opaque base64-encoded P2P Lane 1 board envelope (0x02 bridge_envelope, <= 1 MiB decoded) to pinned trusted party peers.",
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
            "description": "Return read-only mutual friends list and live presence snapshot from the local daemon.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "annotations": read_only_ann()
        }),
    ]
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
        _ => Err(ToolParseError::new(format!("unknown tool '{name}'"))),
    }
}
