# Frumentarii Synthesis: Building a Non-Sucky Local Sidecar Daemon for `multiplayer_outpost`

- **Date:** 2026-11-23
- **Inputs:**
  - [Frumentarius 1 — Daemon Failure Modes & Systems Patterns](2026-11-23-frumentarii-daemon-failure-modes-and-patterns.md)
  - [Frumentarius 2 — Reference Implementation Audit (`tmux`, `buck2`, `tailscale`, `openssh-portable`, `rmcp`)](2026-11-23-frumentarii-refimpl-daemon-audit.md)
  - [Frumentarius 3 — Sibling `party.sock` & MCP Multi-Client Boundary Audit](2026-11-23-frumentarii-mcp-and-sibling-audit.md)
  - Tracked quarantine corpus in [QUARANTINE.md](../QUARANTINE.md)

---

## 1. Why a Shared Local Sidecar Is Forced (and Why Most Daemons Suck)

`MP1` (`https://api.multiplayer.tech`) allows one live `AccountDO`/`PartyDO` control session and one `iroh` v1.5.0 QUIC endpoint per `device_id`. Meanwhile, Claude Code, Codex CLI, Cursor, and Antigravity each spawn an isolated stdio MCP child process per window/session and kill it via `stdin` EOF -> `SIGTERM` -> `SIGKILL`.

Three alternatives were evaluated and rejected on concrete grounds:
1. **Daemonless (embed `MP1` + `iroh` in every MCP/CLI process):** Multiple windows on one machine fight over the same `device_id`, thrash WebSockets, burn the 8-device cap, and lose party state on every tab reload.
2. **In-process peer leader election (first MCP/CLI process becomes host):** Closing the leader's IDE kills `MP1` + `iroh` for every other host (or hangs the IDE's `waitpid()` until `SIGKILL`); short-lived CLI commands would have to fork anyway; upgrading the binary kills the host's MCP session.
3. **Mandatory OS supervision (`launchd` / `systemd --user`):** Breaks over macOS SSH/headless sessions (`launchctl bootstrap gui/<uid>` error `125`), breaks multi-checkout dev builds and containers without PID 1, and leaves persistent OS config residue. (Opportunistically adopting pre-bound `LISTEN_FDS` / `launch_activate_socket` FDs at startup is ~40 LOC and harmless, but never required.)

Traditional ad-hoc daemons suck for six concrete reasons, each solved directly by combining battle-tested patterns from `buck2`, `openssh-portable`, `tmux`, `tailscale`, and Blackbird's `party.sock`:

| Failure Mode ("Why Daemons Suck") | Structural Elimination in `multiplayer_outpost` | Provenance |
| --- | --- | --- |
| **1. Binary/daemon version skew** (stale daemon in RAM after upgrade) | Single binary (`outpost` + `outpost __daemon`) with compile-time `build_digest: [u8; 32]` + `ipc_schema_version: u32` verified on every `Hello`/`HelloAck`. On mismatch: serialized `DrainAndShutdown` -> wait for `daemon.lock` release -> respawn new binary. Because `MP1` `PartyDO` grants a **30s leader / 60s member disconnect grace window** on WS close `1000`, a <1s graceful restart upgrades cleanly without even leaving the party. | `buck2` (`DaemonConstraints` + `connect.rs:213-285`, `kill.rs:142-257`) + `MP1` Spec §9.1 |
| **2. Startup races & split-brain daemons** (two MCP windows auto-spawn simultaneously; or differing `$TMPDIR` creates two dirs) | Never trust caller-mutated `$TMPDIR` on macOS: query `confstr(_CS_DARWIN_USER_TEMP_DIR)` directly (Linux: `$XDG_RUNTIME_DIR`), keyed by integer `device_id` hex (`mpo/d<16-hex>/`, strictly `< 103 B` `sun_path`). Use **two persistent, never-unlinked `flock(2)` files** (`startup.lock` + kernel-held `daemon.lock`) + double-checked `connect()` under `startup.lock` (avoiding both `tmux`'s `unlink(lockfile)` inode race and `party_lobby.cpp`'s lockless `connect -> unlinkat` TOCTOU). | `buck2` (`buckd.lifecycle`, `UnidaemonLifetimeLock`) + `tmux` double-checked `connect()` |
| **3. Half-bound sockets & stale PID lies** (`ECONNREFUSED`, `EPERM` chmod window, killing recycled PIDs) | Under `startup.lock` + `daemon.lock`, create socket on `<dir>/d.sock.tmp.<rand>` under `umask(0177)` (`0600`), call `bind()` + `listen()`, then atomically publish via `link(tmp, d.sock)` + `unlink(tmp)` (fails `EEXIST` rather than clobbering a live socket) and signal readiness over an anonymous pipe. Never trust PID files: verify `(pid, pid_start_time)` (or Linux `SO_PEERPIDFD` + `pidfd_send_signal`) before any forced kill; write a fast-fail startup error file so broken launches abort in milliseconds instead of waiting for a 90s timeout. | `openssh-portable` (`mux.c:1355-1410`) + `buck2` (`daemon.rs:197-212`, `794-800`) |
| **4. Wedged event loops & zombie daemons** (`flock` held while Tokio is deadlocked) | Dedicated OS watchdog thread outside Tokio ticks an async heartbeat every 5s and calls `abort()` if stalled >15s (kernel immediately drops `daemon.lock`). Panic hook calls `libc::_exit(1)`. Client `Hello` has a hard 1.5s deadline with verified-peer `SIGTERM` -> `SIGKILL` escalation under `startup.lock`. | `buck2` (`daemon.rs:218-229`, `638-696`) |
| **5. Orphan lingering & stdout-pipe hangs** (daemon lives forever after work ends, or pins MCP host's stdout pipe open) | Spawn daemon with `setsid()`, `FD_CLOEXEC` on all non-handed FDs, `stdin`/`stdout` -> `/dev/null`, `stderr` -> rotating `daemon.log`. OpenSSH `ControlPersist` idle exit: when `connected_clients == 0 && active_parties == 0` for the grace window, daemon acquires `startup.lock` (`LOCK_EX \| LOCK_NB`), re-checks `connected_clients == 0`, unlinks `d.sock` only if `(st_dev, st_ino)` matches, closes `MP1` WS + `iroh::Endpoint`, and exits `0`. | `openssh-portable` (`ControlPersist`) + `tmux` (`server.c:291-315`) + Blackbird `party_lobby.cpp` inode check |
| **6. Broken MCP stdio sessions on restart & host incompatibilities** | Keep `outpost mcp` as a **stateless, non-blocking thin stdio proxy**: answers `initialize` + static `tools/list` (`listChanged: false`) in `< 50 ms` without waiting on network; absorbs daemon restarts/upgrades transparently via reconnect + `daemon_epoch`/`event_seq` resync (no fragile `SCM_RIGHTS` QUIC/TLS FD migration); exits `< 50 ms` on `stdin` EOF. Primary messaging contract is cursor-based `party_poll` + bounded `party_wait` (default 25s, hard cap 45s < Codex CLI's 60s tool timeout) because **no target host wakes an idle LLM on standard MCP notifications**. | Frumentarius 1 §3.2–3.3 + Frumentarius 3 §3.2–3.3 |

---

## 2. Binary Internals, Security & Dependency Decisions

1. **Binary Internal IPC on `d.sock` (`BLACKBIRD.md` compliant):**
   - `u32` LE length-prefixed frames (`<= 1 MiB`) carrying `(proto_ver: u16, opcode: u16, request_id: u64, payload)` — zero JSON over the Unix socket or in daemon metadata files.
   - Supports multiplexed concurrent requests + `CANCEL(target_request_id)` (wired to MCP `notifications/cancelled`) + bounded per-client outbound queues.
   - `0700` `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`-verified parent dir + `0600` socket + mutual kernel peercred (`SO_PEERCRED` on Linux, `getpeereid`/`LOCAL_PEERCRED` + `LOCAL_PEERPID` on macOS) enforcing `peer_uid == geteuid()`.
2. **Own the MCP Stdio Layer (Do NOT Adopt `rmcp`):**
   - Audited `rmcp` v3.11.0 (`quarantine/rmcp/`): pulls `schemars`, `pastey`, `uuid`, `chrono`, `indexmap`, `unicode-*`, `tokio-util/codec`, and 315 files of rapidly churning draft SEPs.
   - Own a ~400-LOC JSON-RPC 2.0 stdio transport stealing all 6 concrete invariants from `rmcp` + sibling audits: non-blocking stdin / clean macOS shutdown (no `tokio::io::stdin()` drop hang), cancellation-safe `fill_buf`/`consume` bounded line framing (16 MiB cap), BOM/CRLF normalization + parse-error storm suppression, single-writer serialized `stdout`, 5s EOF / 2s cancel drain, and lenient `["2025-06-18", "2025-03-26", "2024-11-05"]` negotiation (`structuredContent` gated on `>= 2025-06-18`).
3. **Strict Security & Non-Collision Boundaries:**
   - **CLI-only secrets:** Account registration (`mpinv1_...`), key management, and party invite redemption (`mppi1_...`) stay on the terminal CLI; MCP tool calls recursively refuse private keys, invite secrets, and API tokens without echoing them.
   - **Untrusted-peer provenance fencing:** Every peer message returned by `party_poll`/`party_wait` is control/BiDi-sanitized, `<`/`>`-escaped (`\u003c`/`\u003e`), and wrapped in `<<<OUTPOST_UNTRUSTED_PEER_DATA_BEGIN/END>>>` with `untrusted_remote: true` and cryptographic peer attribution exclusively from TLS 1.3 RPK `peer_pubkey` in the CWT-verified `PartySnapshot`.
   - **Zero MCP namespace collision:** `serverInfo.name = "multiplayer-outpost"`, tools under `outpost_*` / `party_*`, distinct from `multiplayer.tech/mcp` (`set_me_up`, `make_this_work`, `verify_interop_bundle`) and `blackbird-command-post` (`platoon_*`, `worktree_*`).

---

## 3. Seven Fault-Injection Oracles Required Before Shipping the Daemon

Per `BLACKBIRD.md` Testing Tiers 4–7, the daemon lifecycle must be proven by error-raising fault-injection tests before any release claim:
1. **Thundering herd (32 concurrent clients on empty dir):** exactly 1 daemon PID acquires `daemon.lock`, all 32 converge on the same `daemon_epoch`.
2. **`SIGKILL` mid-session with 2 live MCP shims:** stale socket auto-recovers, zero corrupted JSON-RPC lines on `stdout`, both shims transparently reconnect to a new `daemon_epoch`.
3. **Version-skew auto-upgrade while in a party:** mismatched `build_digest` drains old daemon within grace, respawns new binary, preserves party membership within `MP1`'s 30s/60s grace window, and keeps MCP shims alive.
4. **Wedged daemon (`SIGSTOP`):** client hits 1.5s `Hello` timeout, escalates `SIGTERM` -> verified-PID `SIGKILL`, respawns cleanly within 5s.
5. **Symlink & `0755` dir attack:** both daemon and client fail closed without touching anything outside the runtime dir.
6. **Idle-shutdown race (200 iterations hammering `connect()` at expiry):** zero unrecovered `ECONNRESET`/`ENOENT` failures.
7. **macOS `sun_path` budget:** verify every generated path including `d.sock.tmp.<rand>` fits strictly `<= 103` bytes under a 60-byte `/var/folders/.../T/` prefix.
