# `multiplayer_outpost` (`mp-outpost`) — Implementation Plan (v1)

- **Date:** 2026-11-23
- **Spec Reference:** [docs/OUTPOST_ARCHITECTURE_AND_SPEC.md](OUTPOST_ARCHITECTURE_AND_SPEC.md) (v2 Tribunal-Hardened)
- **Process:** Strict JSMNTL (`BLACKBIRD.md`: written sub-plan -> red oracle tests -> literature/refimpl-grounded code -> green tests -> adversarial review -> fix all findings). Zero `unsafe` in `outpost-core`; `#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]` on protocol/codec crates; `cargo clippy --workspace --all-targets -- -D warnings` must stay at 0 warnings throughout.

---

## Phase A — `crates/outpost-core` (Pure Sans-IO Core & Golden Vector Parity)

**Goal:** Build and exhaustively test every binary codec, state machine, trust/safety-number primitive, secret guard, and provenance fencer with zero OS/network I/O (`#![forbid(unsafe_code)]`).

1. **Workspace & Canonical `mp-protocol` Integration:**
   - Initialize `Cargo.toml` (Rust Edition 2024 workspace) linking canonical `mp-protocol` (with CI parity test against `../multiplayer_site/docs/TEST_VECTORS.json` + Wycheproof/Chalkias strict Ed25519 vectors).
2. **Blackbird P2P Data-Plane Wire v1 Codec (`p2p_wire.rs`):**
   - Exact 4-byte header (`version=1, kind=1..4, flags=0, reserved=0`), all 4 frame kinds (`chat_message`, `bridge_envelope`, `control_notice`, `ephemeral_pulse`), strict UTF-8, exact field bounds, wrong-lane & trailing-byte rejection.
   - **Oracle:** Bit-for-bit hex match on all 4 Wave 11B golden vectors (`xplat-board` `seq: 14`) + `proptest` roundtrip & adversarial mutation fuzzing.
3. **Binary Persistence & Local IPC Codecs (`storage_codec.rs`, `ipc_wire.rs`):**
   - Owned CRC32C (~35 LOC) + versioned binary codecs for `MPD1` (`device.bin`), `MPP1` (`peers.bin`), `MPE1` (`epochs.bin`), `MPN1` (`pending_dev.bin`), `MPR2` (`pending_reg.bin`), `MPI1` (`daemon.info`), and `d.sock` 16-byte LE binary IPC frames (`<= 2 MiB` body cap) + unified binary readiness pipe frames (`0x00`/`0x01`/`0x02`).
   - **Oracle:** Truncation, bit-flip CRC rejection, `> 2 MiB` rejection, IDs `0` or `> 2^53 - 1` rejection.
4. **Trust, Safety Number, Secret Guard & Provenance Fencer (`trust.rs`, `fence.rs`):**
   - Canonical `mp-safety-v1` Crockford Base32 Safety Number encoder/normalizer + 5-link admission verifier (`TLS RPK -> snapshot.device_pubkey -> CWT.cnf.x -> CWT.iss -> PINNED root_pubkey`).
   - Per-response CSPRNG nonce fence (`<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_<16hex>>>>`) + decoded-text `<<<`/`>>>`/nonce mangling + C0/C1/ESC/BiDi/ZW stripping preserving `\n`/`\t`.
   - Crown-jewel exact-match scanner (`device_secret` + `device_cwt` across raw/hex/b64/b64u) + exact-grammar `mpinv1_`/`mppi1_`/private-PEM scanner.
   - **Oracle:** Decoded-layer JSON roundtrip fence-breakout fuzzer; swapped-`device_pubkey` + valid-victim-CWT attack test; secret-encoding variant rejection tests.
5. **Sans-IO Ring Buffer, Cursor, Dedupe & Daemon Lifecycle State Machines (`party_state.rs`, `daemon_sm.rs`):**
   - Bounded `512`-event / `8 MiB` ring buffer, `(daemon_epoch, after_seq)` cursor reset detection, byte-budgeted (`512 KiB`) pagination, per-connection `client_msg_id` payload-hash dedupe, `epochs.bin` floor enforcement, symmetric `relay_policy` compatibility matrix, and sleep-aware lease/idle state machine.
   - **Oracle:** 100k-step Deterministic Simulation Test (DST) over random sequences of joins, wraps, restarts, clock jumps, suspend gaps, and revocations.

**Gate #1:** `cargo test -p outpost-core` + `cargo clippy -- -D warnings` + multi-model adversarial review of `outpost-core`.

---

## Phase B — `crates/outpost-control` & `crates/outpost-p2p` (Network & Transport Engines)

**Goal:** Wire the standards-only TLS 1.3 `MP1` control-plane client and the lazy per-party `iroh` v1.5.0 3-lane P2P transport.

1. **`crates/outpost-control` (TLS 1.3 `hyper 1` + `tokio-websockets 0.13` over `tokio-rustls`):**
   - Strictly TLS 1.3 (`&[&rustls::version::TLS13]`), HTTP/1.1 ALPN, pinned origin (SNI == `Host` == RFC 9421 `@authority`), zero redirects, `permessage-deflate` disabled, exact `Sec-WebSocket-Protocol: mp1`.
   - Full REST client for all `/v1/*` endpoints with RFC 9421 + RFC 9530 signing, `Idempotency-Key` preservation across transport retries (fresh nonce per attempt), scoped `±10m` `clock_skew` offset (outbound signing ONLY), and crash-safe `pending_reg.bin` resume.
   - Account & Party WebSocket drivers: `"MP1:PING"` (20s) / `"MP1:PONG"`, sleep-aware `CLOCK_BOOTTIME`/`mach_continuous_time` 45s/60s timers, terminal `404`/`403` handling, dual-host `<60s` eviction-churn detector, `PARTY_ENDPOINT_UPDATE` 30s coalescing + `retry_after_ms` compliance, lazy `GET /v1/accounts/<id>` handle cache.
   - **Oracle:** Local mock TLS 1.3 server testing chunked responses, post-`101` coalesced TLS records, fragmented WS frames with interleaved Ping/Pong, `clock_skew` retry, `404` terminal stop, and dual-host churn detection.
2. **`crates/outpost-p2p` (`iroh` v1.5.0 Lazy Per-Party Endpoint):**
   - Exact `blackbird-p2p` parity: `presets::Minimal`, ALPN `b"blackbird-mp/1"`, 0-RTT off, `max_concurrent_bidi_streams(2)`, RFC 9221 datagrams (`<= 1200 B`), `force_relays` (`.clear_ip_transports()` + `AddrFilter::relay_only()` + pinned `RelayMap`), `no_relays` (`RelayMode::Disabled`).
   - Stream 0 & Stream 4 `u32::MAX` init + Stream 0 ACK handshake; `EndpointHooks::after_handshake` enforcing the 5-link admission gate before any application byte is read; close codes `4000/4400/4401/4403/4409/4413`; single-flight dialer with `peer trust` wakeup and `4409` glare resolution.
   - **Oracle:** Dual-endpoint loopback QUIC tests (all 4 frame kinds, unpinned rejection, key-swap rejection, `4403` immediate revocation teardown, `4409` glare resolution, `force_relays` zero-direct-addrs check) + **live loopback interop test against compiled `../blackbird` binary/test harness!**

**Gate #2:** `cargo test --workspace` + live `mp-outpost` ↔ `blackbird` QUIC interop test + multi-model adversarial review of `outpost-control` and `outpost-p2p`.

---

## Phase C — `crates/outpost-cli` (Non-Sucky Daemon, Owned MCP Stdio Proxy & CLI)

**Goal:** Assemble the single static binary `mp-outpost` with zero-race POSIX/macOS daemon lifecycle, owned MCP stdio proxy, and full CLI surface.

1. **OS Runtime, Locking & Detached Double-Fork Daemon (`daemon_os.rs`, `daemon_main.rs`):**
   - UID-only runtime dir resolution (Linux `/run/user/<uid>/mpo/d<13hex>/` -> `$HOME/.cache/mpo/d<13hex>/`; macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `/mpo/d<13hex>/`), `O_NOFOLLOW` component-wise verification, `sun_path <= 103 B` guard.
   - One-time `umask(0077)` before threads; `startup.lock` + `daemon.lock` + `state.lock`; `t.<8hex>` `bind -> chmod(0600) -> listen -> link -> unlink` (with `EOPNOTSUPP` fallback).
   - Zero-leak spawn (`dup2(pipe_w, 3)` + macOS `POSIX_SPAWN_CLOEXEC_DEFAULT` / Linux `close_range(4, MAX)` + double-fork -> zero zombies) + unified binary readiness pipe (`0x00`/`0x01`/`0x02`).
   - Atomic `Serving -> Draining -> Exited`, OS watchdog thread (`(dev, ino)` self-fence + atime touch + coordinator progress tick -> lock-free `libc::write` + `_exit(2)`), sleep-aware `ControlPersist` idle exit holding `startup.lock` until `_exit`, unattended-party `idle` pulse + timeout.
   - Deterministic `build.rs` `BUILD_DIGEST` + `BUILD_ORDER` + schema-versioned coexistence (`mcp` NEVER kills a daemon!).
2. **Owned Thin MCP Stdio Proxy (`mcp_stdio.rs`):**
   - Uniform blocking `stdin` reader thread + serialized `stdout` writer task (works on both macOS pipes and Linux `libuv` `socketpair`s), `16 MiB` bounded line framing, BOM/CRLF + parse-error storm suppression, `["2025-06-18", "2025-03-26", "2024-11-05"]` negotiation, `< 20 ms` `initialize`/`tools/list`, lazy `d.sock` connect + 120s idle disconnect, `< 50 ms` EOF exit via `std::process::exit(0)`, `30s` reconnect cap, `notifications/cancelled` -> IPC `Cancel`, optional `notifications/progress`, and all 9 MCP tools (`outpost_status`, `party_list`, `party_members`, `party_send`, `board_post`, `party_poll`, `board_read`, `party_wait`, `party_friends`).
3. **CLI Surface (`cli.rs`):**
   - Full CLI subcommands (`account`, `whoami`, `device`, `peer` [strictly interactive `/dev/tty` for `trust`/`revoke`!], `friend`, `party` incl. approval `requests`/`approve`/`reject`, `board`, `daemon`, `mcp`), stdin/fd-only secret ingestion, `--json` output.

**Gate #3 — All 7 Real-OS Daemon Fault-Injection Oracles + Multi-Host MCP Conformance:**
- 32-way thundering herd, A/B/A mixed-build coexistence (zero kills!), `SIGKILL` with 2 live MCP shims, inode self-fence + 200-iter idle-exit race, macOS APFS + Linux socket publish & 60B `sun_path` budget, leaked non-`CLOEXEC` FD & zombie checks, `SIGSTOP` + `daemon stop --force` on both macOS and Linux, `socketpair` + pipe `< 50 ms` EOF exit.

---

## Phase D — Live Edge E2E, Cross-Host Beta Readiness & Company Handoff

1. Run live end-to-end conformance against `https://api.multiplayer.tech` (two enrolled Outpost devices + live Blackbird peer in the same party, full D1 cleanup).
2. Run final 5-model adversarial code review across the complete workspace; remediate every finding.
3. Test live inside Claude Code, Codex CLI, and Antigravity stdio MCP configs.
4. Post install/setup instructions on `xplat-board` so `multiplayer-site` can add `mp-outpost` as a first-class path in `https://multiplayer.tech/mcp`'s `set_me_up` tool!
