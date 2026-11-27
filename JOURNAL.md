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

## 2026-11-23 — `v0.1.0` Published Across All 3 Platforms + `v0.2.0` Identity Portability, Web Portal Approval, `.mpkey`, `doctor`, and `mcp setup`

1. **`v0.1.0` Live Release (`a9c8725`, GitHub Actions run `45226332928`):**
   - Fixed a real Linux 64 KiB pipe backpressure edge case in `outpost-mcp` (`handle_raw_line` spinning 250 ms per queued stdin frame on saturated `out_tx`) and 5 Rust `1.100.0` clippy lints (`as_chunks`, `collapsible_match`, `useless_borrows_in_formatting`, macOS-only import).
   - GitHub Actions built, tested (63/63 workspace tests + 0 clippy warnings), and published `v0.1.0` across `darwin-arm64`, `linux-x86_64`, and `linux-arm64` + `SHA256SUMS.txt` + `release-manifest.json` + `install-outpost.sh`.
   - Verified live end-to-end via `curl -fsSL https://multiplayer.tech/install-outpost.sh | sh` (zero non-system dylibs, `mp-outpost --version`, `mp-outpost mcp` initialize + EOF). Posted handoff on `xplat-board` (`seq: 26`).

2. **`v0.2.0` Identity Portability v1 + Web Portal + Operator Ergonomics (3 parallel lanes):**
   - Synced `crates/mp-protocol` with frozen `multiplayer_site/docs/IDENTITY_PORTABILITY_SPEC.md` (`mprk1_` Recovery Keys, 128-bit `mpdevfp2:` fingerprints, `KeyId::Recovery` `rec.<32hex>`, `KeyId::DeviceLink` `link.<32hex>`).
   - **Lane A (`outpost-core` + `outpost-mcp`):** verified frozen `mprk1_` & `mpdevfp2:` golden vectors; extended `scan_outbound_secrets` & MCP refusal codes to block `RecoveryKey` (canonical, folded, and checksum-verified unprefixed 55-char forms), `DeviceLinkToken` (`mpdl1_<43 b64u>`), and `RecoveryFile` (`-----BEGIN MULTIPLAYER RECOVERY KEY-----` + raw/aligned/misaligned Base64 `MPKEY1\0\0`).
   - **Lane B (`outpost-control`):** added `RequestSigner::recovery` / `device_link`, all 8 live Identity Portability & Web Portal REST endpoints (`/v1/accounts/recover-lookup`, `/v1/web-sessions/{inspect,approve}`, `/v1/device-links/{create,claim,inspect,approve,poll}`), TLS 1.3 `probe_relay_ping`, and real TLS 1.3 integration oracles.
   - **Lane C (`outpost-cli`):** added operator-approved `argon2 = "0.5"` alongside already-locked `aes-gcm`, `icu_normalizer`, and `zeroize`; implemented bit-exact `.mpkey` v1 (`MPKEY1\0\0`, NFC passphrase, Argon2id v0x13 `m=65536, t=3, p=1`, pre-KDF bounds check, AES-256-GCM + AAD, strict post-AEAD JSON, `zeroize`, atomic `0600` write) with deterministic golden vector; implemented `account recovery-key`, `account export-mpkey`, `account recover`, `mprk1_` printout on `account register`, primary-initiated `device link create|join|approve` (both sides computing 128-bit `mpdevfp2:` locally), `web approve`, `doctor`, and `mcp setup`.
   - Verified **72/72** default workspace tests, **17/17** `--features test-tls-overrides` CLI E2E tests (including full Identity Portability + bogus-server-fingerprint rejection), and **0 clippy warnings** on both Rust `1.94.1` and Rust `1.99.1`.

## 2026-11-23 — Gate #2 5-Model Adversarial Tribunal Remediation & `v0.3.0` (`upgrade`, Handle-First `friend`, `mcp setup --write`)

1. **Gate #2 5-Model Adversarial Code Review Tribunal (`papers/2026-11-23-code-gate2-tribunal-dispositions.md`):**
   - Five independent read-only models (Claude, GPT/Codex `gpt-6.2-sol`, GLM 5.3, Kimi `k3`, and isolated 10th Dentist) audited `v0.2.0` (`a9c8725..adb70c7`), confirmed low-level crypto and wire formats are spec-conformant, and surfaced security/resilience findings remediated across three parallel lanes:
     - **Lane 1 (`mp-protocol` + `outpost-core` + `outpost-mcp`):** bumped `IPC_SCHEMA_VER = 2` to prevent stale-daemon secret-guard downgrade; fixed `contains_recovery_key` O(1)-memory 55-symbol ring buffer eliminating CPU/heap DoS; hardened `fence.rs` boundaries, wrapped Base64/hex `.mpkey` magic, case-insensitive PEM headers, and Unicode/separator folding; switched `mp-protocol::crypto::zeroize_bytes` to workspace `zeroize`.
     - **Lane 2 (`outpost-control` + `outpost-daemon`):** parsed HTTP `429` `Retry-After` fallback; sanitized server API error strings against ANSI/control injection; enabled `ed25519-dalek/zeroize`, manual redacted `Debug` on link responses, and strict ID/`link_code` validation; added `atomic_write_in_dir_no_replace` (`linkat`), `open_dir_nofollow`, `read_regular_file_bounded_nofollow`, and TLS 1.3-only `fetch_https_bytes` for self-upgrade.
     - **Lane 3 (`outpost-cli`):** moved global `reject_secrets_in_argv` to top of `main()` before `__daemon`/`mcp`/CLI dispatch (catching case-insensitive prefixes, `--passphrase=`/`--recovery-key=`/`--invite-secret=`, `.mpkey`/PEM, and space-split unprefixed recovery keys) + sanitized stderr + redacted unknown secret-like flags; removed `mprk1_` from `--json` and headless stdout (requiring `/dev/tty` or `--recovery-key-out <path>`); hardened `TermiosEchoGuard` (`TCSAFLUSH` before prompt, unbuffered byte-by-byte `Zeroizing<Vec<u8>>`, async-signal-safe `SIGINT`/`SIGTERM` restore), bounded `O_NOFOLLOW` key reads, canonical `mprk1_` root-key files, `Zeroizing` across all CLI commands, and no-clobber `export-mpkey` (`--force` to replace); hardened `web approve` (8-hex fingerprint + `--root-key-file` required for headless `--yes-browser-fingerprint` + expiry/`approved == true`/response-fingerprint verification) and `device link` (`429` `Retry-After` + transient retries, clock-offset-adjusted expiry, collision guard, pre-persist `@handle`+SN display, quoted `device_label`); hardened `account recover` pre-validation, `.mpkey` `account_id` cross-check, pre-enroll inventory display, and optional TTY device revocation; fixed POSIX shell & TOML escaping and independent `doctor` probes with preserved state/IPC errors.
2. **`v0.3.0` Operator Features:**
   - Wired native `mp-outpost upgrade [--check] [--yes|-y] [--version TAG] [--base-url URL] [--install-path PATH]` (TLS 1.3-only, dual `release-manifest.json` + `SHA256SUMS.txt` verification, tarball traversal/symlink audit, offline `--version` smoke check, atomic `0755` swap, best-effort daemon drain).
   - Added handle-first `friend add|accept|deny|decline|remove|block <@handle|account_id>` and incoming-first sorted `friend list` with human labels and actionable accept/deny hints.
   - Added opt-in `mp-outpost mcp setup --client <claude|codex|cursor|antigravity> --write [--config <path>] [--global]` with `.bak` backup, non-destructive JSON merge / idempotent TOML upsert, and atomic write.

## 2026-11-23 — `v0.4.0` LAN Party! Mode (`mp1-lan/1`) & Roadmap v2 Online Parity

1. **Zero-Internet LAN Party! Mode (`mp1-lan/1`, interoperable with Blackbird `v0.3.0`):**
   - Implemented canonical `mp1-lan/1` protocol & mDNS codec (`crates/outpost-core/src/lan_protocol.rs`), `iroh` QUIC + TLS 1.3 Mutual RPK `LanTransport` (`crates/outpost-p2p`), and full `mp-outpost lan {status|scan|host|join}` runtime (`crates/outpost-cli/src/lan.rs`) enforcing all 6 Operator Security Mandates (zero-socket `lan status`, `MP_DISABLE_LAN=1` / `/etc/mp-outpost/lan.toml` fail-closed kill-switch, global `--pin`/`--pin=` argv rejection without echo, hidden `/dev/tty` or `--pin-stdin` PIN input with per-peer/lobby rate limits, Safety Number verification & pinning, and nonce-fenced peer chat).
2. **Roadmap v2 Online Parity & IPC Schema v3:**
   - Bumped `IPC_SCHEMA_VER = 3` (`crates/outpost-core/src/ipc_wire.rs`) for binary `FriendItem.safety_number` and `PartyCreateReq.{org_id, group_id}`.
   - Enriched `GET /v1/friends` handling in `app_daemon.rs` + `friend list`: populates `@handle` from `peer_handle` and computes canonical Safety Numbers locally from strictly validated `peer_root_pubkey_b64` (never trusting mismatched server `peer_safety_number`).
   - Added `mp-outpost relays [--ping] [--api-authority <host>] [--json]` with concurrent TLS 1.3 `/ping` probes and fastest-region ranking, plus actionable `409 relay_mismatch` IPC error diagnostics naming the party's `pinned_relay_url`.
   - Wired `--org-id <id>` and `--group-id <id>` scoped party creation through `party create` -> IPC -> `ControlClient::create_party_with_scope`.
   - Added compiled-binary E2E Oracle 7 verifying `lan status`, `MP_DISABLE_LAN=1` fail-closed, `--pin` argv guard, live 2-binary encrypted QUIC LAN Party chat on loopback, and TLS 1.3 `relays [--ping] --json`.

## 2026-11-23 — Gate #3 Remediation & `v0.5.0` (Dead-Drop Inbox Suite 1 E2EE, Auth UX Stage 2, Unified Policy & Party Trust Tiers)

1. **Gate #3 Adversarial Audit Fixes:**
   - Hardened `reject_secrets_in_argv` to reject `-pin`, `-pin=...`, `--pin ...`, and `-pin ...` case-insensitively without echoing values.
   - Enforced `--group-id requires --org-id` in `party create`, switched `friend list` accept/deny copyable hints to numeric `account_id`, bounded `relays --ping` concurrency to 6 (`Arc<tokio::sync::Semaphore>::new(6)`), and fixed `README.md` policy path documentation (`/etc/multiplayer/policy.toml` + legacy `/etc/multiplayer/lan.toml`).
   - Hardened daemon `op_friends_list` (`GET /v1/friends` enrichment): sanitized/bounded `peer_handle` (`<= 64` printable ASCII), reconciled `st.friends` snapshot to prune unfriended edges while preserving live presence fields, cleared `safety_number` when `peer_root_pubkey_b64` is omitted (e.g. blocked edges), and cross-checked server `peer_root_pubkey_b64` against locally pinned `peers.bin` (emitting `"KEY_MISMATCH"` + warning instead of silently trusting server-substituted keys).
   - Updated `409 relay_mismatch` diagnostic in `op_party_join` to direct operators to `mp-outpost relays` and device relay configuration (removing unsupported `--relay-url` suggestion).
   - Sanitized `handle` in `DaemonMcpBridge::party_friends`.

2. **`v0.5.0` Features:**
   - **E2EE Dead-Drop Inbox (Suite 1):** X25519 per-device subkey storage (`d<13hex>.enc.bin`, mode `0600`), 161-byte signed `enc_cert`, Suite 1 HPKE `ModeAuth` + key-committing ChaCha20-Poly1305 sealing/opening, `mp-outpost inbox init-key|send|read|ack`, and MCP tools `inbox_send`, `inbox_read`, `inbox_ack` (12 MCP tools total).
   - **Auth UX Stage 2:** Interactive `mp-outpost login`, guided `mp-outpost add-device` (with pure-Rust ISO/IEC 18004 V1 ECC-L terminal QR code for link code only + local 128-bit `mpdevfp2:` verification), and offline `mp-outpost account emergency-kit --out <path.html>` (mode `0600`, zero JS, zero external URLs, strict HTML escaping, no-clobber unless `--force`, zero stdout key echo).
   - **Unified Policy & Party Trust Tiers:** Verified `O_NOFOLLOW` fail-closed loader for `/etc/multiplayer/policy.toml` (with legacy `lan.toml` backward compatibility and `MP_DISABLE_LAN` / `MP_BRAKES` overrides), `mp-outpost policy status [--json]`, `mp-outpost doctor [--json]` policy reporting, and `DaemonMcpBridge::effective_trust_profile` (clamping to `Advisory` on policy failure).
   - **Compiled-Binary E2E Oracle 8:** Added `oracle_8_v050_dead_drop_inbox_auth_ux_and_unified_policy` covering full TLS 1.3 dead-drop inbox E2EE roundtrip + outbound secret refusal + ack pruning, Emergency Kit HTML security invariants, `policy status` + `doctor` reporting, and 12-tool `mp-outpost mcp` `tools/list`.

## 2026-11-27 — `v0.7.0` MLS (RFC 9420) E2EE, `is_browser` Containment & Onboarding Hardening

1. **Wave 2 Onboarding & Browser-Origin Containment (`IPC_SCHEMA_VER = 5`):**
   - Fixed `?code=` query-string link URL generation and enforced `#fragment` invite redaction across CLI/logs so invite secrets never leak via query parameters or diagnostics.
   - Bumped `IPC_SCHEMA_VER = 5` to propagate `is_browser` origin tagging across daemon IPC and MCP provenance fences for untrusted browser-origin containment.
   - Added explicit unauthenticated / HTTP `401` operator recovery guidance and `mp-outpost doctor --trace` diagnostics.

2. **MLS (RFC 9420) End-to-End Encryption (`openmls = "=0.9.2"`, vendored `crates/mp-mls`):**
   - Vendored `crates/mp-mls` into the workspace for 100% self-contained GitHub Actions builds and `--locked` verification.
   - Implemented backup-excluded AES-256-GCM MLS state persistence (`crates/outpost-core/src/mls_store.rs`) and MLS group session lifecycle (`crates/outpost-core/src/mls_session.rs`) with exact `512 / 2048 / 8192 / 24000 B` wire padding buckets.
   - Added epoch-stale outbound requeue on commit races, historical-catchup `@mention` suppression, Tier 0–3 trust/verification state + `epoch_authenticator` MCP surface, and unit/control oracles (`mls_e2ee_oracles.rs`, `mls_control_oracles.rs`).
