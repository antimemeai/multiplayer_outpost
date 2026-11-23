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

## 2026-11-23 — Spec v1 5-Model Adversarial Tribunal Complete → Spec v2 & Implementation Plan

Authored `docs/OUTPOST_ARCHITECTURE_AND_SPEC.md` (v1 Draft) and ran all 5 independent read-only adversarial reviewers in parallel (Kimi `k3`, GPT/Codex, Claude, GLM 5.3, and isolated 10th Dentist). All five returned `REJECT` with razor-sharp convergence on structural defects, while `blackbird-leader` simultaneously posted the locked Wave 11B P2P data-plane wire v1 specification and golden hex vectors on `xplat-board` (`seq: 14`).

- Archived consolidated tribunal dispositions in `papers/2026-11-23-spec-v1-tribunal-dispositions.md`.
- Hardened `docs/OUTPOST_ARCHITECTURE_AND_SPEC.md` to **v2**:
  - **Eliminated daemon respawn wars & false kills:** decoupled `IPC_SCHEMA_VER` compatibility from deterministic `build.rs` `BUILD_DIGEST` + monotonic `BUILD_ORDER` (`mp-outpost mcp` NEVER kills a daemon; clients NEVER kill on slow `Hello`).
  - **Simplified & fixed OS lifecycle:** cut `session.bin`, `LISTEN_FDS`/`launch_activate_socket`, `startup.err`, and IPC `Ping/Pong`; switched to UID-only runtime dir (no `$XDG_RUNTIME_DIR`/`$TMPDIR` split-brain, no `/tmp` reaper), `d<13hex>/t.<8hex>` (`<= 88 B <= 103 B`), one-time `umask(0077)`, watchdog `(dev, ino)` self-fencing, atomic `Serving -> Draining -> Exited` holding `startup.lock` until `_exit`, double-fork zero-zombie spawn + `POSIX_SPAWN_CLOEXEC_DEFAULT`/`close_range`, sleep-aware `CLOCK_BOOTTIME`/`mach_continuous_time` timers, lazy `mcp` connect, and unattended-party `idle` pulse + timeout.
  - **Enforced 1 active party per `device_id` in v1** with lazy per-party `iroh::Endpoint`, symmetric `relay_policy` compatibility matrix, 5-link admission binding (`TLS RPK -> snapshot -> CWT.cnf -> CWT.iss -> PINNED root_pubkey`), durable `epochs.bin`, and exact Wave 11B 4-byte wire + golden hex vectors + Stream 0/4 `u32::MAX` handshake + `4409` glare close code.
  - **Reused `hyper 1` + `tokio-websockets 0.13`** already compiled unconditionally by `iroh 1.5.0` (verified in `blackbird-p2p/Cargo.lock`, zero new transitive crates) over TLS 1.3-only `tokio-rustls`.
  - **Hardened trust, fencing, cursors & MCP:** honest same-UID threat model, interactive `/dev/tty` `peer trust`/`revoke`, canonical `mp-safety-v1` Crockford Base32 Safety Number + `whoami --safety-number`, per-destination send gating (no late-joiner DoS), per-response CSPRNG nonce provenance fence at decoded-text layer, crown-jewel `device_secret`/`device_cwt` exact-match outbound scanner, `2 MiB` IPC cap + `512 KiB` byte-budgeted `(daemon_epoch, after_seq)` pagination, honest `delivery_unknown` on mid-send restart, uniform blocking `stdin` reader thread (avoids Linux `libuv` `socketpair` `ENXIO`), `board_read`, and approval-mode CLI commands.
- Authored `docs/IMPLEMENTATION_PLAN.md` (Phases A–D); awaiting operator approval on proposed Rust dependency list before launching Phase A (`crates/outpost-core`).


## 2026-11-23 — Full 6-Crate Build, 5-Model Gate #1 Tribunal & Remediation, and `v0.1.0` Standalone Release

1. **Full 6-Crate Implementation (`0c4049f`, `cb63c0e`, `b75e43e`, `f27b3a8`):**
   - Implemented `outpost-core`, `outpost-control`, `outpost-p2p`, `outpost-daemon`, `outpost-mcp`, and `outpost-cli` (`mp-outpost`, 12 MB single static binary with zero non-system dylibs).
   - Sibling platoon `multiplayer-site` (`xplat-board` `seq: 23`) verified two live release `mp-outpost` daemons end-to-end against live `https://api.multiplayer.tech` and live Cloudflare `https://relay.multiplayer.tech` (`force_relays`, 53 ms bidirectional QUIC + TLS 1.3 Mutual RPK roundtrip, all green in 7.36 s).

2. **Gate #1 5-Model Adversarial Code Review Tribunal & 4-Lane Remediation:**
   - Ran 5 independent read-only adversarial reviewers (GPT/Codex, Kimi `k3`, Claude, GLM 5.3, and 10th Dentist) across all 6 crates and archived consolidated dispositions in `papers/2026-11-23-code-gate1-tribunal-dispositions.md`.
   - Remediated every Critical, High, and Medium finding across 4 disjoint parallel lanes with failing-first regression oracles:
     - **Lane 1 (`outpost-core` + `outpost-mcp`):** fixed `<<<<<` fence bypass via single-pass run breaker, stripped `U+2028`/`U+2029`/`U+E0000..=U+E007F`, added misaligned & no-pad Base64 secret detection, added `PartyEventRing::poll_filtered` + `MAX_POLL_MAX_BYTES` clamp, cached-bytes `DedupeCache::check/record`, `EpochFloorStore::merge_from`, rejected `request_id == 0` in `ipc_wire`, moved `room_scope`/`target_selector` inside MCP nonce fences, switched to `getrandom`, byte-bounded `line_tx` + shutdown-aware `send_frame` (`< 50 ms` EOF even on blocked stdout), and emitted `null`/`reset` for interrupted `party_wait` `daemon_epoch`.
     - **Lane 2 (`outpost-control` + `outpost-p2p`):** replaced `tokio-websockets` upgrade path with owned bounded (`<= 8 KiB`) HTTP/1.1 `101` handshake + checked FIPS 180-4 SHA-1 `Sec-WebSocket-Accept` + `401 clock_skew` auto-retry; canonicalized authority + strict `http/1.1` ALPN + `24 KiB` `hyper` `max_buf_size` + RAII task abort; added byte-budget semaphores on all P2P queues, deterministic smaller-`EndpointId` `4409` glare tie-break, drop-only Lane 2 bad datagrams, `set_allowed_peers_with_close_code(4401)`, and concurrent `PartyP2pTransport::split() -> (Arc<PartyP2pHandle>, P2pEventStream)` with `wait_online` & `watch_addr`.
     - **Lane 3 (`outpost-daemon`):** replaced sleep-advancing watchdog stall timer with awake-only `Instant` probing the main coordinator loop + `DaemonHandler::health_tick()` + drain hard-exit deadline; switched `drain_reason` to synchronous `std::sync::Mutex` populated before `Draining` CAS; fixed Linux `pre_exec` `CLOSE_RANGE_CLOEXEC` + `/proc/self/fd` fallback; made CSPRNG fallible; added 200ms non-blocking `probe_peer_pidfd` + PID verification; replaced symlink checks with race-free component-wise `openat`/`mkdirat` walk; added macOS `F_FULLFSYNC`, `daemon.log` rotation, `on_daemon_started`/`on_client_count_changed` hooks, and `test-tls-overrides` env stripping.
     - **Lane 4 (`outpost-cli`):** fixed `device renew` to derive pubkey from local `d<13hex>.dev.bin` (or require `--device-pubkey-b64`) and refuse server mismatch; fixed `extract_cwt_expiry_ms` (`wall_now_secs()`) + live CWT expiry enforcement; removed LAN IP injection and validated `allow_relays` descriptors via `EndpointDescriptor::validate_against_policy` + `wait_online(3s)` + `watch_addr()` roaming; stripped `direct_addrs` under `ForceRelays` and validated snapshot relay policy; serialized party transitions + installed session before spawning drivers + eliminated `P2pActor` deadlock; hardened `pubkey_to_device` & persisted `KeyMismatch` `4401` revocations; made `epochs.bin` fail-closed read-merge-write under `StateLock` in `spawn_blocking`; gated `OUTPOST_TEST_*` behind `#[cfg(any(test, feature = "test-tls-overrides"))]`; embedded contiguous `MPO_BUILD_STAMP_V1` for real on-disk `BUILD_DIGEST` checks; scanned `room_scope` + `control_notice` secrets; wired unattended-party `Idle` pulse + 30m detach and startup party reattach; hardened `mcp_bridge`, `peer trust`/`revoke`, `device install-cwt` probe-before-commit, `account register --resume` CWT journaling, and bounded `O_NOFOLLOW` `daemon logs`.
   - Verified **63/63** default workspace tests, **10/10** `--features test-tls-overrides` CLI + 2-Outpost QUIC/MCP E2E tests, and **0 clippy warnings** across both feature sets.

3. **Standalone Public Packaging & `v0.1.0` Prebuilt Release:**
   - Vendored `crates/mp-protocol/` and `docs/TEST_VECTORS.json` directly into `multiplayer_outpost` so public clones and GitHub Actions build with zero private sibling paths (`antimemeai/multiplayer_site` is private while `antimemeai/multiplayer_outpost` is public).
   - Added `scripts/package-release.sh`, `scripts/install-outpost.sh`, and `.github/workflows/release.yml` building `darwin-arm64`, `linux-x86_64`, and `linux-arm64` tarballs + `SHA256SUMS.txt` + `release-manifest.json` and publishing directly to GitHub Releases.
