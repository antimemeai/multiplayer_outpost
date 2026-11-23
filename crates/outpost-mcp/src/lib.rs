//! Owned stateless thin MCP stdio JSON-RPC 2.0 proxy (`multiplayer-outpost`).
//!
//! Implements the Spec v2 §6.1–§6.3 MCP stdio proxy without `rmcp`:
//! - Uniform blocking stdin reader thread + single serialized stdout writer (macOS pipes & Linux `socketpair`s).
//! - Lazy backend abstraction (`McpOutpostBackend`) with zero backend I/O on `initialize` / `tools/list`.
//! - Static 9-tool catalog (`outpost_*`, `party_*`, `board_*`) with strict safe-integer validation.
//! - Decoded-layer per-response CSPRNG nonce provenance fencing via `outpost_core::fence::fence_peer_text`.

#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

pub mod backend;
pub mod json_strict;
pub mod stdio;
pub mod tools;

pub use backend::{
    BackendError, BoardEnvelopeEvent, BoardPostReq, BoardReadResp, BoxFuture, CancellationToken,
    McpOutpostBackend, McpPartyEvent, McpPartyEventKind, PartyPollReq, PartyPollResp,
    PartySendReq, PartyWaitReq, PeerProvenance, ProgressSender, ProgressUpdate,
};
pub use stdio::{
    DEFAULT_PROGRESS_INTERVAL, MAX_LINE_BYTES, McpServerConfig, SUPPORTED_PROTOCOL_VERSIONS,
    run_stdio, run_stdio_with_io,
};
pub use tools::{
    DEFAULT_POLL_LIMIT, DEFAULT_POLL_MAX_BYTES, DEFAULT_WAIT_TIMEOUT_MS, MAX_POLL_LIMIT,
    MAX_POLL_MAX_BYTES, MAX_WAIT_TIMEOUT_MS, SERVER_NAME, SERVER_VERSION, TOOL_NAMES, tool_catalog,
};
