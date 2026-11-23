# Journal

## 2026-11-23 — Founding & Company Orientation

Operator spun up `multiplayer_outpost` as the third Neon platoon in the company alongside `blackbird` (`blackbird-leader`) and `multiplayer_site` (`multiplayer-site`) to build the standalone Outpost / sidecar (CLI + MCP stdio server over `mp-protocol` + `iroh` v1.5.0) for non-Blackbird coding agents (Claude Code, Codex, Antigravity, etc.) to join `multiplayer.tech` parties and exchange P2P party chat / board messages without requiring the full Blackbird harness.

### Studied Sibling State

1. **`../multiplayer_site/` (`b9aefd3`, plus WIP `multiplayer.tech/mcp` worker):**
   - Deployed live control plane at `https://api.multiplayer.tech` (Cloudflare Workers + SQLite `AccountDO` & `PartyDO` + isolated `multiplayer-control` D1 + compiled 203 KiB `mp_wasm.wasm`, TLS 1.3 enforced, 8/8 real-edge conformance checks passing).
   - Locked Spec v2.1 (`docs/ARCHITECTURE_AND_PROTOCOL_SPEC.md`) and golden interop vectors (`docs/TEST_VECTORS.json`):
     - 52/53-bit integer PKs everywhere (`account_id`, `device_id`, `party_id`, `invite_id`).
     - Strict RFC 9421 (`label=mp1`, `alg="ed25519"`, `tag="mp1"`) + RFC 9530 `Content-Digest` on body methods; `.root` unthrottled revocation lane.
     - RFC 8392/8747 `COSE_Sign1` Device CWT pinned to RFC 9864 `Ed25519 = -19` (exact protected header `h'A10132'`, `exp - iat <= 30d`).
     - Multi-device single-operator parties (`party_members` keyed by `device_id`, `<= 8` devices/account, `<= 12` total, leader's own additional devices auto-admit without invites).
     - Binary `MP1` WebSocket protocol over HTTP/1.1 ALPN (`Sec-WebSocket-Protocol: mp1`), zero-wakeup text heartbeat `"MP1:PING"` -> `"MP1:PONG"`, strictly parsed `EndpointDescriptor <= 256 B`.
   - Rust workspace provides `crates/mp-protocol` (`#![forbid(unsafe_code)]`, zero JSON internals) ready to align on or share cleanly.
   - WIP `server/src/mcp_worker.ts` implements a zero-privilege remote Streamable HTTP MCP at `https://multiplayer.tech/mcp` for onboarding docs and crypto/vector verification (no secrets, no live party transport) — clean separation from our local stdio Outpost MCP which holds local device keys and runs live `iroh` P2P party sessions.

2. **`../blackbird/` (`f4acaa9` + staged Checkpoint #24 Wave 10):**
   - Wave 10A: byte-exact C++23 `MP1` codec + RFC 9421/9530 + `COSE_Sign1` CWT over OpenSSL 3, verified bit-for-bit against `mp-protocol`.
   - Wave 10B: `crates/blackbird-p2p` (`iroh` v1.5.0 staticlib, `presets::Minimal`, QUIC RFC 9000 + TLS 1.3 Mutual RPK RFC 7250, 0-RTT off, RFC 9221 datagrams, ALPN `"blackbird-mp/1"`, non-downgradeable `force_relays` via `.clear_ip_transports()` + `AddrFilter::relay_only()`, mandatory peer allowlist + immediate `4403` revocation close).
   - Exact 3-lane P2P framing on ALPN `"blackbird-mp/1"`:
     - Lane 0 (`CONTROL`): Bidirectional Stream 0, `u32` LE length-prefixed, `<= 64 KiB`, priority 10.
     - Lane 1 (`CAUSAL`): Bidirectional Stream 4, `u32` LE length-prefixed, `<= 4 MiB`, priority 0.
     - Lane 2 (`EPHEMERAL`): RFC 9221 Unreliable Datagrams, `<= 1200 B`.
   - Wave 10C: in-RAM UID-verified `party.sock` wired into `blackbird party serve` + `/party` TUI. Wave 11 next: connecting Blackbird live to `https://api.multiplayer.tech` + live P2P party lanes.

### Initial Observations & Cross-Platoon Alignment Questions

1. **P2P Application-Layer Payload Schema (Streams 0 / 4 / Datagrams):** `blackbird-p2p` locks the transport framing (ALPN `blackbird-mp/1`, Stream 0/4 `u32` LE length-prefix, Datagrams), while Wave 11 is about to wire live party chat / `BoardBridge` causal events / receipts over those lanes. `multiplayer_outpost` and `blackbird` must lock one byte-exact P2P data-plane wire schema (binary preferred per `BLACKBIRD.md` internal data formats doctrine, or exact agreed framing) so an Outpost agent and a full Blackbird client interoperate seamlessly in the same party from day one.
2. **Crate Sharing / Extraction:** `mp-protocol` (in `multiplayer_site`) and the pure-Rust core of `blackbird-p2p` (in `blackbird`) are both Rust Edition 2024 crates. Aligning on whether to keep a clean shared protocol crate or vendor/pin via git submodule/workspace path avoids codec drift.
3. **Outpost Architecture Shape:** Local daemon/sidecar holding one live `MP1` control connection + `iroh` v1.5.0 `Endpoint` (plus local UID-verified Unix socket for CLI commands & multiple local MCP stdio bridges, OR single-process stdio MCP + CLI subcommands), local encrypted/0600 key storage + `KnownPeersStore` TOFU pinning + Safety Numbers, strict untrusted-peer provenance fencing on all inbound MCP tool outputs so non-Blackbird agents (Claude Code, Codex, Antigravity) cannot be prompt-injected by party messages, and zero secret exposure through MCP responses.
4. **Relationship to `multiplayer.tech/mcp`:** Remote `https://multiplayer.tech/mcp` handles discovery, setup guidance, and interop verification; local `multiplayer-outpost mcp` (stdio) runs on the operator's machine with local keys and live P2P QUIC sockets.

### Actions Completed

- Created repository structure at `~/projects/multiplayer_outpost` with `BLACKBIRD.md` symlink, `.gitignore`, `AGENTS.md`, `README.md`, `QUARANTINE.md`, `JOURNAL.md`, `docs/`, `papers/`, `quarantine/`, and `context/`.
- Initialized Git repository on `master` and created private GitHub repository `antimemeai/multiplayer_outpost`.
- Joined the company `xplat-board` bridge (`~/projects/.blackbird/xplat-board`) as `multiplayer-outpost` and posted initial orientation + alignment questions to `blackbird-leader` and `multiplayer-site`.

## 2026-11-23 — Phase 1 Frumentarii Complete: Non-Sucky Local Daemon & MCP Boundary

Operator asked to send out Frumentarii specifically on building a local daemon/sidecar that does not drift out of sync or leave messes. Dispatched three parallel Frumentarii and received alignment replies on `xplat-board` (`seq: 11–12`):

- **Cross-platoon alignment (`xplat-board` `seq: 11–12`):**
  - `blackbird-leader` confirmed Wave 11B is locking the 4-frame little-endian binary P2P data-plane schema over `blackbird-mp/1` (`control_notice`, `chat_message`, `bridge_envelope`, `ephemeral_pulse`, attributing sender exclusively from TLS 1.3 RPK `peer_pubkey` in the CWT-verified `PartySnapshot`) and will post byte layouts + golden hex vectors once `@dentist-2` clears it.
  - `multiplayer-site` confirmed Outpost devices are 100% identical to Blackbird devices on `api.multiplayer.tech`, aligned on reusing canonical `crates/mp-protocol` + `TEST_VECTORS.json`, and aligned on the zero-privilege remote MCP (`multiplayer.tech/mcp`) vs local stdio Outpost MCP split.
- **Acquired & stripped 5 reference implementations into gitignored `quarantine/`** (documented with commits, licenses, directory SHA-256 hashes, and restore commands in `QUARANTINE.md`): `tmux`, `buck2` (daemon slice), `tailscale` (`safesocket`/`localapi`/`ipnauth`), `openssh-portable` (`mux.c`/`ssh.c`), and `rmcp` (v3.11.0).
- **Saved all three intermediate Frumentarii reports + synthesis in `papers/`:**
  - `papers/2026-11-23-frumentarii-daemon-failure-modes-and-patterns.md`
  - `papers/2026-11-23-frumentarii-refimpl-daemon-audit.md`
  - `papers/2026-11-23-frumentarii-mcp-and-sibling-audit.md`
  - `papers/2026-11-23-frumentarii-daemon-synthesis.md`
- **Key architectural conclusions ready for operator review before writing the Spec:**
  1. Hash-pinned, auto-spawning, idle-exiting single-binary sidecar (`outpost` + `outpost __daemon`) paired with a stateless, non-blocking thin MCP stdio proxy (`outpost mcp`). Reject in-process leader promotion and mandatory `launchd`/`systemd` install; reject `SCM_RIGHTS` QUIC/TLS FD migration in favor of fast reconnect + `MP1`'s 30s/60s disconnect grace window.
  2. Never-unlinked `flock(2)` `startup.lock` + kernel-held `daemon.lock`, double-checked `connect()`, atomic `umask(0177)` + temp `bind`/`listen` + `link(tmp, d.sock)` + `unlink(tmp)`, macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)` (never `$TMPDIR`), integer `device_id` dir naming (`< 103 B`), binary `u32` LE internal IPC, compile-time `build_digest` auto-restart, dedicated OS watchdog thread + panic `_exit(1)`, and verified-PID escalation.
  3. Own ~400-LOC MCP stdio JSON-RPC 2.0 (do NOT adopt `rmcp`), stealing `rmcp`'s 6 stdio transport invariants; primary messaging contract is cursor-based `party_poll` + bounded `party_wait` (25s default, 45s hard cap < Codex's 60s timeout) with strict untrusted-peer fencing and CLI-only secret/invite ingestion.

