# `multiplayer_outpost` (`mp-outpost`) — Architecture & Protocol Specification (v2 — Tribunal-Hardened)

- **Status:** v2 Tribunal-Hardened Specification (resolving all 5-model Spec v1 Tribunal findings — see [papers/2026-11-23-spec-v1-tribunal-dispositions.md](../papers/2026-11-23-spec-v1-tribunal-dispositions.md))
- **Date:** 2026-11-23
- **Foundation:** [BLACKBIRD.md](../BLACKBIRD.md), [AGENTS.md](../AGENTS.md), [Frumentarii Daemon Synthesis](../papers/2026-11-23-frumentarii-daemon-synthesis.md), [multiplayer.tech Control Plane Spec v2.1](../../multiplayer_site/docs/ARCHITECTURE_AND_PROTOCOL_SPEC.md), [Blackbird P2P Wire v1](../../blackbird/include/blackbird/p2p_party_session.hpp) (`xplat-board` `seq: 14`)

---

## 1. Purpose, Boundaries & Honest Threat Model

`mp-outpost` is a standalone Rust sidecar (**CLI + stateless local MCP stdio server + detached single-binary background daemon**) that lets non-Blackbird coding agents (Claude Code, Codex CLI, Cursor, Antigravity, Gemini CLI, and shell-scripted agents) join `multiplayer.tech` parties and exchange peer-to-peer party chat and board messages directly with Blackbird peers and other Outposts.

### 1.1 Hard System Boundaries

- **`mp-outpost` Owns:**
  1. Enrolled device Ed25519 keypair custody (`0600` binary record) and short-TTL (`<= 30d`) root-signed `COSE_Sign1` Device CWT.
  2. Local `KnownPeersStore` (TOFU pinning + interactive `/dev/tty` Safety Number verification + fail-closed key-swap rejection).
  3. Online control-plane client to `https://api.multiplayer.tech` (TLS 1.3 only, strict RFC 9421 + RFC 9530 `tag="mp1"`, HTTP/1.1 ALPN WebSockets for `/v1/ws` and `/v1/parties/<id>/ws`, `MP1` binary control frames).
  4. Peer-to-peer data-plane transport via `iroh` v1.5.0 (QUIC RFC 9000 + TLS 1.3 Mutual Raw Public Keys RFC 7250, 0-RTT off, ALPN `blackbird-mp/1`, 3-lane framing, **1 active party per `device_id` in v1**, lazy per-party `iroh::Endpoint` with non-downgradeable local `relay_policy`).
  5. Per-`device_id` local daemon (`mp-outpost __daemon`) exposing a binary Unix domain socket (`d.sock`) with schema-versioned compatibility, never-unlinked `flock(2)` locks, inode self-fencing watchdog, and `ControlPersist` idle auto-exit.
  6. Stateless thin MCP stdio proxy (`mp-outpost mcp`) and structured-JSON CLI (`mp-outpost ...`) with nonce-fenced untrusted-peer provenance and accidental-secret-disclosure refusal.

- **`mp-outpost` Explicitly Does NOT Own:**
  1. **No Blackbird harness:** Zero TUI, Lua VM, provider adapters, context compaction, or local agent loop.
  2. **No `.root` private key in daemon RAM or default state directory:** `mp-outpost __daemon` and `mp-outpost mcp` hold ONLY an enrolled device key + CWT. Primary setup enrolls from a cold `.root` host (`device init` -> remote enroll -> `device install-cwt`). Standalone `account register` writes the `.root` key only to an explicit operator-chosen `--root-key-out <path>` with a clear warning to move it offline.
  3. **No remote execution authority:** `mp-outpost` never executes shell commands, edits local files, or grants tool capabilities on behalf of remote peers.
  4. **No party content through the control plane:** Zero chat bodies, board envelopes, diffs, or credentials cross `api.multiplayer.tech`.
  5. **No JSON internally:** All internal files (`device.bin`, `peers.bin`, `epochs.bin`, `pending_*.bin`, `daemon.info`) and local IPC frames (`d.sock`) use owned native binary formats. JSON is used strictly at external REST (`api.multiplayer.tech`), MCP stdio JSON-RPC 2.0, and CLI `--json` stdout boundaries.
  6. **No string primary keys (`BLACKBIRD.md` Tenet #6):** All entity PKs are integers (`account_id`, `device_id`, `party_id`, `event_seq`, `request_id`, `daemon_epoch`, `client_msg_id`), constrained to `1..=9_007_199_254_740_991` (`2^53 - 1`) wherever exposed through MCP JSON.

### 1.2 Honest Threat Model & Residual Risks

| Adversary / Fault Class | Concrete Attack / Residual Risk | Mandatory Defense in `mp-outpost` |
| --- | --- | --- |
| **Hostile party peer** | Prompt injection via chat/board payload (fence breakout, XML tags, ANSI/BiDi spoofing) or forging `sender_handle`/sender IDs on the wire. | 1. Attribute `(sender_account_id, sender_device_id)` **exclusively** from the authenticated TLS 1.3 RPK `peer_pubkey` bound through the 5-link CWT+pin chain (Section 5.2). Never trust payload `sender_handle` — resolve server-asserted handle lazily via `GET /v1/accounts/<id>` and always pair with integer `account_id`.<br>2. Preserve `\n` and `\t`, strip all other C0/C1/ESC/BiDi/zero-width scalars, wrap peer content in a **per-response CSPRNG nonce fence** (`<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_<16hex>>>>` ... `<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END_<16hex>>>>`), deterministically mangle any decoded occurrence of `<<<`/`>>>`/the nonce, and keep provenance fields structurally separate from body text in `structuredContent`. *Residual:* plain-prose prompt injection still reaches the LLM; the host agent decides tool invocation. |
| **Compromised `api.multiplayer.tech`** | Swaps peer `root_pubkey` in `PARTY_SNAPSHOT` to MitM P2P; replays lower `party_epoch`; shifts `clock_skew` to accept expired peer CWTs; downgrades party `relay_policy` from `force_relays` to `allow_relays`. *Residual:* a compromised server can still mint higher `party_epoch` or withhold revocation until peer CWT expiry (`<= 30d`), and observes client source IP. | 1. 5-link admission chain verifies `CWT.iss == hex(sha256(PINNED root_pubkey))` from `peers.bin`; any key swap for a pinned `account_id` fails closed immediately.<br>2. Persist durable `epochs.bin` floor across crashes.<br>3. Server `clock_offset_ms` applies **only** to outbound RFC 9421 signing — never to peer CWT verification.<br>4. Local `local_relay_policy` is a non-downgradeable floor (if local is `force_relays`, direct IP transports are never bound regardless of server policy). |
| **Other local UIDs on a shared host** | Symlink planting, connecting to `d.sock`, reading keys. | UID-derived `0700` runtime dir opened component-by-component with `O_DIRECTORY \| O_NOFOLLOW \| O_CLOEXEC`, `fstat` `st_uid == geteuid()` & `0700`, `0600` socket, mutual kernel peercred (`SO_PEERCRED` / `getpeereid` + `LOCAL_PEERPID`) enforcing `peer_uid == geteuid()`. |
| **Same-UID local AI agent (Honest Boundary)** | **Reality:** An agent with an unconstrained same-UID Bash tool owns the local UID (can run CLI commands or read `0600` files unless OS-sandboxed or gated by host tool approvals). | 1. **Real human gate:** `peer trust` and `peer revoke` require an interactive controlling `/dev/tty` (refusing non-TTY stdin and deleting `--safety-number` from argv) so headless agent subshells cannot silently pin a MitM key.<br>2. **LLM guardrail:** MCP tool surface omits invite/key/trust/daemon-control ops so non-shell or permission-prompted agents cannot invoke them via MCP; `client_kind` on `d.sock` is telemetry only, NOT a fake ACL.<br>3. **Accidental-leak guard:** Outbound scan exact-matches our own `device_secret` + `device_cwt` (raw/hex/b64/b64u) plus exact-grammar `mpinv1_`/`mppi1_`/private-PEM headers. |
| **Daemon drift, races, wedges, orphans** | A/B binary ping-pong, stale locks/reapers, `SIGSTOP` wedges, host FD leaks, zombie accumulation. | Schema-versioned compatibility (`mcp` never kills daemons), UID-only runtime dir, watchdog `(dev, ino)` self-fencing, atomic `Serving -> Draining -> Exited` holding `startup.lock` until `_exit`, double-fork + `close_range`/`POSIX_SPAWN_CLOEXEC_DEFAULT`, lazy `mcp` connect + `ControlPersist` idle exit (Section 3). |

---

## 2. Key Custody & Binary Persistence Layout

### 2.1 State Directory (`<state_dir>`) & Serialization Lock

- Explicit override: `OUTPOST_STATE_DIR` (validated: absolute, UTF-8, no `..`, no C0/C1/BiDi).
- Linux default: `${XDG_STATE_HOME:-$HOME/.local/state}/mp-outpost` (`0700`).
- macOS default: `$HOME/Library/Application Support/mp-outpost` (`0700`).
- **Component-wise verified open:** Walk and verify owned ancestor dirs with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, `fstat` checking `st_uid == geteuid()` and `(st_mode & 0o077) == 0`.
- **State serialization lock:** `<state_dir>/state.lock` (`0600`, never unlinked, `flock(LOCK_EX)`) serializes ALL read-modify-write updates to `peers.bin`, `epochs.bin`, `devices/*.dev.bin`, `default_device.bin`, and `pending_*.bin` across offline CLI and running daemon(s).
- **Atomic file writes:** Inside `state.lock`, write via `openat(dirfd, "<name>.tmp.<rand>", O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, 0o600)` -> `write_all` -> `fsync(file)` -> `renameat(dirfd, tmp, dirfd, target)` -> `fsync(dirfd)`.

### 2.2 Binary File Formats (Zero JSON, Magic + Version + CRC32C)

Every binary file begins with `[magic: [u8; 4]][format_ver: u16 LE (=1)][flags: u16 LE (=0)]` and ends with trailing `crc32c: u32 LE` over all preceding bytes. Unreadable or CRC-failed security files (`*.dev.bin`, `peers.bin`, `epochs.bin`) **fail closed** — never silently reset!

1. **Hot Enrolled Device Record (`<state_dir>/devices/d<13hex_device_id>.dev.bin`, `0600`):**
   - Magic `b"MPD1"`. Fields:
     - `account_id: u64` (`1..=2^52-1`), `device_id: u64` (`1..=2^52-1`)
     - `root_pubkey: [u8; 32]` (public only), `device_secret: [u8; 32]`, `device_pubkey: [u8; 32]`
     - `cwt_len: u16` (`<= 256`) + `device_cwt: [u8; cwt_len]` (RFC 8392/8747 `COSE_Sign1`, `alg = -19`)
     - `local_relay_policy: u8` (`0=allow_relays`, `1=force_relays`, `2=no_relays`)
     - `api_authority: u16+utf8` (default `"api.multiplayer.tech"`)
     - `default_relay_url: u16+utf8` (default `"https://relay.multiplayer.tech"`)
     - `device_label: u16+utf8` (`<= 64 B`)
   - Default device selector: `<state_dir>/default_device.bin` (Magic `b"MPX1"`, `device_id: u64`).
   - **One live host per `device_id` rule:** Never copy a `.dev.bin` to a second machine; enroll a separate device per host (up to 8 per account).

2. **Staged Enrollment / Registration Journals (Crash-Safe, `0600`):**
   - **`<state_dir>/pending_dev.bin` (Magic `b"MPN1"`):** Created by `mp-outpost device init` BEFORE `device_id` exists: `(device_secret[32], device_pubkey[32], device_label, local_relay_policy, api_authority, default_relay_url, created_at_ms)`. Consumed atomically by `mp-outpost device install-cwt` (which verifies `CWT.cnf.x == device_pubkey` and `CWT.iss == hex(sha256(root_pubkey))`, writes `d<13hex>.dev.bin`, runs `GET /v1/accounts/me` to flip `pop_verified = 1`, and removes `pending_dev.bin`).
   - **`<state_dir>/pending_reg.bin` (Magic `b"MPR2"`):** Written by `mp-outpost account register` **before** `POST /v1/accounts/register`: `(idempotency_key[32], root_pubkey[32], device_secret[32], device_pubkey[32], handle, device_label, api_authority)` (root secret lives only in `--root-key-out <path>`). If network drops after server commit, re-running `account register --resume` reuses the exact same `Idempotency-Key` + `root_pubkey` so `api.multiplayer.tech`'s kill-after-commit idempotent resume returns `(account_id, device_id)` without burning another invite!

3. **Known Peers TOFU Store (`<state_dir>/peers.bin`, `0600`):**
   - Magic `b"MPP1"`. Records keyed by `(api_authority_hash: [u8; 8], account_id: u64)` (namespaced by deployment origin so staging and production IDs never collide!):
     - `api_authority_hash: [u8; 8]` (first 8 bytes of `SHA-256(api_authority)`)
     - `account_id: u64` (integer PK)
     - `root_pubkey: [u8; 32]`
     - `trust_state: u8` (`1 = pinned_trusted`, `2 = revoked_blocked`)
     - `pinned_at_ms: u64`
     - `handle_prop: u16+utf8` (server-asserted mutable display prop from `GET /v1/accounts/<id>`)
     - `handle_fetched_ms: u64`
   - **Canonical Safety Number (One Exact Formula):**
     - `digest = SHA-256("mp-safety-v1:" || account_id_le64 || root_pubkey[32])`
     - Take first 20 bytes (160 bits) -> encode as **32 uppercase Crockford Base32 characters** (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, big-endian 5-bit groups), displayed as `8` groups of `4` separated by `-`: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
     - Input normalization on interactive verify: strip ASCII whitespace and `-`, uppercase, map Crockford lookalikes `I`/`L` -> `1` and `O` -> `0`, require exact 32 valid alphabet chars and constant-time equality.
     - Operator's own `(account_id, root_pubkey)` is implicitly `pinned_trusted` on device enrollment (enabling zero-friction single-operator multi-machine parties).
     - `mp-outpost whoami --safety-number` prints the operator's own Safety Number offline from enrolled state so peers can verify out-of-band.
     - *(Cross-repo note: propose adopting `mp-safety-v1` Crockford Base32 jointly with `blackbird-leader` on `xplat-board` so Blackbird and Outpost render identical Safety Numbers.)*

4. **Durable Party Epoch Floor (`<state_dir>/epochs.bin`, `0600`):**
   - Magic `b"MPE1"`. Bounded LRU of up to `64` entries per `(api_authority_hash[8], party_id: u64)`:
     - `api_authority_hash: [u8; 8]`, `party_id: u64`, `highest_party_epoch: u64`, `terminal_disbanded: u8 (0|1)`, `updated_at_ms: u64`.
   - Updated durably under `state.lock` **before** applying any higher `party_epoch` or terminal `PARTY_DISBANDED` state. Survives `SIGKILL`, idle exit, and restarts. Zero plaintext chat is ever persisted (`session.bin` deleted per Tenet #1).

---

## 3. Non-Sucky Local Sidecar Daemon (`mp-outpost __daemon`)

### 3.1 Single-Binary Roles & Zero-Zombie Spawning

One static binary (`mp-outpost`) runs in three roles:
- **`mp-outpost <cmd>`:** Terminal CLI (talks to `d.sock` for live ops; handles cold/offline setup directly).
- **`mp-outpost mcp`:** Stateless thin stdio JSON-RPC 2.0 proxy spawned by AI hosts. Connects to `d.sock` **lazily on first `tools/call`** (never on `initialize`/`tools/list`) and drops idle `d.sock` after `120s` when `active_parties == 0` so `ControlPersist` actually fires.
- **`mp-outpost __daemon --device-id <u64> --ready-fd 3`:** Detached per-`device_id` background engine. Always spawned via **double-fork** (or daemonizing child launcher that immediately exits `0` after `fork` + `setsid` so `init`/PID 1 reaps the daemon — **zero zombies** in long-lived `mp-outpost mcp` parents!).

### 3.2 UID-Only Runtime Directory & `sun_path` Budget (`<= 103 B` Guaranteed)

Never derive the runtime path from caller-mutable `$TMPDIR` or `$XDG_RUNTIME_DIR` (which differ between desktop sessions, SSH, cron, and IDE subprocesses and cause split-brain daemons!).

| Platform | Deterministic Runtime Dir (No Env-Var Split-Brain) | Leaf Layout | Max Temp Path (`t.<8hex>`, 10 B) |
| --- | --- | --- | --- |
| **Linux** | 1. `/run/user/<geteuid()>/mpo/d<13hex>/` if `/run/user/<geteuid()>` exists, is `0700`, owned by `geteuid()`<br>2. Else `$HOME/.cache/mpo/d<13hex>/` (never `/tmp`!) | `d.sock` (6 B), `t.<8hex>` (10 B) | ~48 B (`<= 107 B` incl. NUL) |
| **macOS** | `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `/mpo/d<13hex>/` (verified empirically ~49 B base; even at 60 B base: `60 + 4 + 14 + 10 = 88 B <= 103 B` incl. NUL!) | `d.sock` (6 B), `t.<8hex>` (10 B) | **88 B** (`<= 103 B`, 15 B headroom) |
| **Explicit Override** | `$OUTPOST_RUNTIME_DIR/d<13hex>/` (for tests/sandboxes only; rejected fail-closed if `len(temp_path) >= 103 B`) | same | checked `< 103 B` (`sizeof(sun_path) - 1`) |

- Open and verify directory chain with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, `fstat` checking `S_ISDIR`, `st_uid == geteuid()`, `(st_mode & 0o777) == 0o700`.
- Socket `bind()`/`connect()` uses the verified absolute path (because neither Linux nor macOS provides `bindat`/`connectat`, and `fchdir` is process-wide/racy in multithreaded Rust; verified `0700` user-owned directory prevents local hijacking).

### 3.3 Runtime Directory Files (Minimal — Zero Bloat)

| File | Mode | Format | Lifecycle & Invariants |
| --- | --- | --- | --- |
| `startup.lock` | `0600` | empty | **Never unlinked.** `flock(LOCK_EX)` held by clients during spawn/restart and by daemon (`LOCK_EX \| LOCK_NB`) across **entire** idle teardown until `_exit`. |
| `daemon.lock` | `0600` | empty | **Never unlinked.** `flock(LOCK_EX \| LOCK_NB)` held by `mp-outpost __daemon` for its entire lifetime (released by kernel immediately on crash/`SIGKILL`). |
| `daemon.info` | `0600` | binary (`MPI1`) | Written atomically (`fsync` + `rename`) before signaling ready: `(pid: u32, native_start_token: u64, daemon_epoch: u64, ipc_schema_ver: u32, build_order: u64, build_digest: [u8; 32], device_id: u64, exe_path_utf8)`. `native_start_token` is read from the daemon's own OS API (`proc_pidinfo(getpid())` microsecond timestamp on macOS; raw `/proc/self/stat` field 22 ticks on Linux — never cross-converted!). |
| `d.sock` | `0600` | `AF_UNIX` `SOCK_STREAM` | Published under `daemon.lock`: daemon unlinks any stale `d.sock` & `t.*`, binds `t.<8hex>`, `chmod(0600)`, `listen(128)`, `link(t.<8hex>, d.sock)` + `unlink(t.<8hex>)` (falling back to direct `bind("d.sock")` + `chmod(0600)` + `listen(128)` only if `link()` returns `EOPNOTSUPP`/`EPERM` on unusual filesystems). |
| `daemon.log` | `0600` | rotating stderr log | Max `2 x 4 MiB`. Raw FD stored in `AtomicI32` for lock-free panic/watchdog `libc::write()`. |

*(Explicitly deleted from v1 per Tribunal: `session.bin`, `startup.err`, `LISTEN_FDS`/`launch_activate_socket`, and IPC `Ping/Pong`.)*

### 3.4 Connect, Auto-Spawn & Zero-Ping-Pong Version Policy

Compile-time constants (deterministic `build.rs` — NEVER random `LC_UUID`!):
- `IPC_SCHEMA_VER: u32 = 1` (bumped ONLY on breaking binary IPC changes)
- `BUILD_ORDER: u64` (strictly monotonic version/timestamp integer)
- `BUILD_DIGEST: [u8; 32]` (deterministic SHA-256 of Cargo workspace lockfile + crate sources + target triple + profile)

**Hard Version Compatibility Rules (Eliminates A/B/A Respawn Wars Permanently):**
1. **Compatible schema (`ack.ipc_schema_ver == IPC_SCHEMA_VER`):** Client **ALWAYS** coexists with the running daemon, even if `build_digest` differs! Never kill a healthy compatible daemon on connect. `GetStatus` surfaces `daemon_build_digest`, `daemon_exe_path`, and `upgrade_available: bool` diagnostically.
2. **Incompatible schema (`ack.ipc_schema_ver != IPC_SCHEMA_VER`):**
   - **`mp-outpost mcp` NEVER kills or replaces a daemon.** It returns crisp `isError: true` (`daemon_schema_mismatch_restart_mcp`, naming running vs local schema and daemon exe path) and stops reconnecting.
   - **Read-only CLI (`daemon status`, `daemon logs`) NEVER kills or replaces a daemon.**
   - **Mutating CLI** may auto-upgrade **ONLY** if: (a) `local.ipc_schema_ver > ack.ipc_schema_ver` (strict upgrade, never downgrade), AND (b) on-disk `current_exe()` hash still matches `local.BUILD_DIGEST`. Otherwise fails with crisp CLI hint (`mp-outpost daemon restart`).
3. **Explicit operator replacement (`mp-outpost daemon restart` / `stop`):** Always acquires `startup.lock` (`LOCK_EX`), sends `DrainAndShutdown`, waits for `daemon.lock` release (up to `5000 ms`), and (for `restart`) spawns the chosen binary.

**Client Connect & Spawn State Machine (`ensure_connected`):**
1. **Fast Path (Lock-Free):**
   - Open verified `dirfd`. Connect to `d.sock` (deadline `3000 ms`, retrying brief `ECONNREFUSED` up to `100 ms`).
   - Verify peer credentials (`peer_uid == geteuid()`).
   - Send `Hello { ipc_schema_ver, build_order, build_digest, client_kind, client_pid }`; read `HelloAck` (deadline `5000 ms`).
   - **Never signal/kill a daemon on `Hello` timeout alone** (swap/laptop-wake/debugger safety — wedge recovery belongs to the daemon's watchdog!). If `Hello` times out, fall through to Slow Path to wait cleanly on `startup.lock` / `daemon.lock` or report `daemon_unresponsive` with CLI hint (`mp-outpost daemon stop --force`).
   - Verify `ack.device_id == expected_device_id` and apply Version Compatibility Rules above -> **READY**.
2. **Slow Path (Serialized Under `startup.lock`, overall deadline `15_000 ms`):**
   - Acquire `flock(startup.lock, LOCK_EX)` (5–100 ms polling up to deadline).
   - **Double-check:** Retry Fast Path once. If a racer just booted a healthy compatible daemon -> release `startup.lock`, return **READY**.
   - **Wait for any exiting owner:** Probe `daemon.lock` with `try_lock(LOCK_EX | LOCK_NB)`. If `EWOULDBLOCK` (old daemon finishing drain/exit), poll up to `4000 ms`. If STILL held after `4000 ms` and `d.sock` still fails `Hello`, return crisp error `daemon_wedged_run_force_stop` (for `daemon stop --force` ONLY: signal verified owner via Linux `SO_PEERPIDFD` + `pidfd_send_signal`, or native `daemon.info` `(pid, native_start_token)` verified via same OS API -> `SIGTERM` 2s -> `SIGKILL` 2s).
   - **Clean Detached Spawn (Zero Leaked Host FDs, Zero Zombies):**
     - Create pipe `(pipe_r, pipe_w)` with `O_CLOEXEC` on BOTH ends.
     - Spawn launcher child with:
       - **macOS:** `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT` + `dup2(pipe_w, 3)` + `stdin/stdout -> /dev/null` + `stderr -> daemon.log` (all leaked Node/Electron host FDs `>= 4` closed in-kernel!).
       - **Linux:** async-signal-safe `pre_exec` performing `dup2(pipe_w, 3)` (clearing `FD_CLOEXEC` on fd 3 only) + `close_range(4, u32::MAX, 0)` (fallback `/proc/self/fd` loop) + `stdin/stdout -> /dev/null` + `stderr -> daemon.log`.
     - Launcher child immediately calls `setsid()` + second `fork()` (parent launcher exits `0` via `_exit(0)` and is reaped by caller immediately -> **zero zombies!**; grandchild runs `__daemon`).
   - **Daemon Grandchild Boot Sequence:**
     - Single-threaded BEFORE starting Tokio: set `umask(0077)` once, set `SIGPIPE = SIG_IGN`, install lock-free panic hook (`libc::write(log_fd)` + `libc::_exit(1)`).
     - Verify `dirfd`; acquire `flock(daemon.lock, LOCK_EX | LOCK_NB)`. If `EWOULDBLOCK`: write unified binary reply `[0x02]` (`already_running`) to fd 3, close fd 3, `_exit(0)`.
     - Unlink any stale `d.sock` and `t.*` under `daemon.lock`; bind `t.<8hex>`, `chmod(0600)`, `listen(128)`, `link(t.<8hex>, d.sock)` + `unlink(t.<8hex>)`; record `(dir_dev, dir_ino, lock_dev, lock_ino, sock_dev, sock_ino)`.
     - Load `d<13hex>.dev.bin`, `peers.bin`, `epochs.bin` under `state.lock`. Write `daemon.info` atomically.
     - Start Tokio runtime + IPC accept loop + OS watchdog thread + async background `MP1` `/v1/accounts/me` attach (never blocking IPC readiness!).
     - Write unified binary readiness reply to fd 3 and close fd 3:
       - Success: `[0x00][daemon_epoch: u64 LE]` (9 bytes)
       - Fatal boot error: `[0x01][err_len: u16 LE (<= 2048)][utf8_err]`
       - Already running: `[0x02]` (1 byte)
   - **Client Readiness Handling:**
     - Read complete readiness frame from `pipe_r` (deadline `3000 ms`), reap launcher child (`waitpid`).
     - On `0x01`: release `startup.lock` and surface exact error immediately.
     - On `0x02`: re-run Fast Path once under lock.
     - On `0x00`: connect to `d.sock`, verify `HelloAck.daemon_epoch == ready_epoch`, release `startup.lock`, return **READY**.

### 3.5 Atomic Lifecycle State Machine, Watchdog & Idle Exit

One authoritative lifecycle state machine inside the daemon: **`Serving -> Draining -> Exited`**.
- **Accept & `Hello` hygiene:** Every accepted connection must send a valid `Hello` within `5000 ms` or be dropped; only authenticated post-`Hello` clients increment `connected_clients` (atomically before task spawn, decremented via RAII drop guard). On `EMFILE`/`ENFILE`, back off `1s`.
- **Dedicated OS Watchdog Thread (Outside Tokio, Lock-Free Exit):**
  - Every `5s`:
    1. **Inode Self-Fence (Defeats `dirhelper` / `tmpfiles.d` / Logout Wipe):** `stat()` runtime dir, `daemon.lock`, and `d.sock` and verify all three `(st_dev, st_ino)` still match the open handles; also touch atime (`utimensat`) on lock files to prevent 3-day macOS `dirhelper` purging. If any `(st_dev, st_ino)` diverges -> transition to `Draining` and exit cleanly!
    2. **Event-Loop Progress Tick:** Send a ping onto the main party/IPC coordinator task (measuring actual coordinator progress, not just a dummy worker thread); if unacknowledged for `> 20s` (measured via sleep-aware clock), write diagnostic via raw `libc::write(log_fd)` and call `libc::_exit(2)` so kernel releases `daemon.lock` immediately.
- **Race-Free Idle Auto-Exit & Unattended Party Policy:**
  - All idle/liveness timers use **sleep-aware monotonic clocks** (`CLOCK_BOOTTIME` on Linux; `mach_continuous_time` on macOS — never `Instant` which freezes during laptop sleep!).
  - **When `connected_clients == 0 && active_party.is_some()`:** Immediately send Lane 2 `ephemeral_pulse(idle)` so peers know no local agent is attending; if `connected_clients` remains `0` for `unattended_party_timeout_secs` (default `1800s` = 30m, configurable, `0` = stay), cleanly detach (`POST /v1/parties/<id>/leave` + close `iroh`) so Outpost never lingers forever as a ghost member!
  - **When `connected_clients == 0 && active_party.is_none()` for `idle_timeout_secs` (default `300s`):**
    1. Acquire `startup.lock` (`LOCK_EX | LOCK_NB`). If `EWOULDBLOCK`, abort teardown and reset timer.
    2. Atomically transition `Serving -> Draining` (stop accepting new connections; reject any late `Hello`).
    3. Re-check `connected_clients == 0 && active_party.is_none()`. If non-zero, transition back to `Serving`, release `startup.lock`, resume.
    4. Verify `d.sock` `(st_dev, st_ino)` and `unlinkat(dirfd, "d.sock", 0)`.
    5. Close `MP1` WS (`1000`) and `iroh::Endpoint::close().await` (cap `2000 ms`) **while still holding BOTH `startup.lock` and `daemon.lock`**.
    6. Exit `0` (kernel atomically releases both locks on exit!).
  - **On `DrainAndShutdown` (from CLI holding `startup.lock`):** Transition `Serving -> Draining` immediately (reject new IPC writes), close `iroh::Endpoint` (`500 ms` cap) and `MP1` WS with code `1000` (preserving `PartyDO`'s 30s/60s grace window on `restart`; explicit `stop` leaves if `--leave-party` passed), unlink verified `d.sock`, exit `0`.

---

## 4. Binary Local IPC Protocol (`d.sock`, Zero JSON)

### 4.1 Frame Envelope & Size Budgets

```text
Offset  Size  Field
0       4     body_len    : u32 LE   (0..=2_097_152 — 2 MiB hard cap)
4       2     proto_ver   : u16 LE   (MUST be 1)
6       2     opcode      : u16 LE
8       8     request_id  : u64 LE   (per-connection unique ID, 1..=2^53-1)
16      N     payload     : [u8; body_len]
```

- `2 MiB` IPC cap cleanly accommodates Blackbird's max `1 MiB` `bridge_envelope` plus metadata/provenance overhead.
- Framing violation, `proto_ver != 1`, duplicate active `request_id`, or `body_len > 2 MiB` immediately closes the connection.
- Per-client limits: max `16` concurrent in-flight requests, max `64` queued outbound frames / `4 MiB` outbound buffer; max `32` concurrent IPC clients.
- Cancellation (`Cancel(target_request_id)`) is strictly scoped to the originating IPC connection's `(conn_gen, request_id)` and immediately aborts an in-flight `PartyWait`.

### 4.2 Per-Party Event Ring & `(daemon_epoch, after_seq)` Cursors

- Each active party holds an in-RAM ring buffer capped at **`512` events OR `8 MiB`** (whichever hits first; oldest evicted first, advancing `dropped_before_seq`).
- Every event gets a strictly monotonic `event_seq: u64` (`1..=2^53-1`) scoped to `(daemon_epoch, party_id)`.
- **`PartyPoll` and `PartyWait` take `(party_id, cursor_epoch: u64, after_seq: u64, max_bytes: u32 <= 524_288, limit: u16 <= 100)`:**
  - If `cursor_epoch != 0 && cursor_epoch != daemon_epoch` OR `after_seq > next_seq`: return `{ cursor_reset: true, gap_possible: true, daemon_epoch, next_seq, dropped_before_seq, events: [] }` so callers **never go deaf** across restarts!
  - Otherwise return all events with `seq > after_seq` up to `limit` and `max_bytes` (always returning `>= 1` event if one exists, even if large, with optional truncation + `fetch_event(seq)` for oversized `> 64 KiB` bodies in MCP text mode).
  - Read watermarks are **per client** (each MCP window tracks its own `(daemon_epoch, after_seq)` — Window A reading never hides messages from Window B!).
- **`PartyWait` registration:** Register `tokio::sync::Notify::notified()` **before** checking the ring predicate (eliminating missed-wakeup races), propagate exact end-to-end deadline (`<= 45_000 ms`), and wake all eligible waiters on new event, membership change, or disconnect.
- **Honest send deduplication (`client_msg_id`):**
  - `mp-outpost mcp` generates `client_msg_id: u64` (`1..=2^53-1`, CSPRNG) — never relying on LLMs!
  - Daemon maintains a live per-`(conn_client_uuid, party_id, opcode, client_msg_id)` dedupe cache (`256` entries) storing `payload_sha256` + result; reusing the same ID with a different payload hash returns `idempotency_conflict` error instead of silently dropping!
  - Because `blackbird-mp/1` `chat_message` has no wire message ID and the dedupe cache is in-RAM, if `d.sock` drops mid-send before a reply arrives, `mp-outpost mcp` returns crisp **`delivery_unknown`** (`isError: true`) rather than falsely claiming restart-safe retry!

### 4.3 IPC Opcodes

| Opcode | Name | Purpose |
| --- | --- | --- |
| `0x0001` | `Hello` / `HelloAck` | Exchanges `ipc_schema_ver`, `build_order`, `build_digest[32]`, `client_kind` (telemetry only), `daemon_epoch`, `daemon_pid`, `device_id`, `exe_path`, `active_party_id_or_0`. |
| `0x0003` | `Error` | `(code: u16, retryable: u8, msg_utf8)`. |
| `0x0004` | `Cancel` | Aborts in-flight `target_request_id` on this connection. |
| `0x0005` | `DrainAndShutdown` | `(mode: u8 [0=restart_keep_party, 1=stop_detach, 2=stop_leave_party])`. |
| `0x0006` | `ReloadDevice` | Reloads `d<13hex>.dev.bin` (after `device install-cwt` / CWT renewal) and `peers.bin` (after `peer trust`/`revoke`, kicking dialer or immediately closing `4403`!). |
| `0x0010` | `GetStatus` | Identity, CWT expiry, `daemon_epoch`, `daemon_pid`, `build_digest`, `exe_path`, control WS state, `dual_host_churn_alert`, active party summary, unpinned/mismatch peer alerts. |
| `0x0020` | `PartyList` | Active party (0 or 1 in v1) with `party_id`, `party_epoch`, `relay_policy`, `member_count`, `next_seq`, `daemon_epoch`. |
| `0x0021` | `PartyMembers` | Verified roster: `(device_id, account_id, server_handle, root_pubkey, trust_state, safety_number, connected_mp1, connected_p2p, joined_seq)`. |
| `0x0022` | `PartySendChat` | Sends P2P Lane 1 `0x01 chat_message`. Per-destination trust gating: returns `{ delivered_to[], withheld_unpinned[], disconnected[] }`. |
| `0x0023` | `PartyPostBoard` | Sends P2P Lane 1 `0x02 bridge_envelope` (opaque raw bytes `<= 1 MiB` + `room_scope <= 128 B`). Same per-destination trust gating. |
| `0x0024` | `PartyPoll` | Byte-budgeted cursor read `(party_id, cursor_epoch, after_seq, max_bytes, limit)`. |
| `0x0025` | `PartyWait` | Bounded long-poll `(party_id, cursor_epoch, after_seq, timeout_ms <= 45_000)`. |
| `0x0026` | `PartySendControlNotice` | Sends P2P Lane 0 `0x03 control_notice` (`sync_ack` / `scope_changed` / `status`, `party_epoch`, `text <= 4 KiB`). |
| `0x0027` | `FriendsList` | Mutual friends + live presence snapshot from `AccountDO` WS. |
| `0x0030–0x003F` | Party & Social Lifecycle | `PartyCreate`, `PartyJoin`, `PartyLeave`, `PartyDisband`, `PartyKick`, `PartyPromote`, `PartyInviteMint`, `PartyInviteRevoke`, `PartyRequestsList`, `PartyRequestApprove`, `PartyRequestReject`, `FriendRequest`, `FriendRemove`, `FriendBlock`, `ResolveHandle`. |

---

## 5. `MP1` Control Plane & `iroh` v1.5.0 P2P Data Plane

### 5.1 Control-Plane Client (`crates/outpost-control`)

1. **Canonical Protocol Codec:** Imports `mp-protocol` (exact Rust Edition 2024 crate from `../multiplayer_site/crates/mp-protocol`, CI-verified bit-for-bit against `../multiplayer_site/docs/TEST_VECTORS.json`).
2. **Audited HTTP/1.1 & RFC 6455 Transport (Zero New Transitive Crates):**
   - Uses `hyper 1` (`http1` client) + `tokio-websockets 0.13` — **already unconditionally compiled by `iroh 1.5.0`** (`blackbird-p2p/Cargo.lock`) — layered directly over our own **TLS 1.3-only** `tokio-rustls` stream (`&[&rustls::version::TLS13]`, `webpki-roots`, ALPN `["http/1.1"]`, 0-RTT early data disabled, SNI + `Host` + RFC 9421 `@authority` pinned to one canonical origin, zero redirects, `permessage-deflate` disabled, exact `Sec-WebSocket-Protocol: mp1` verification).
   - Hard ingress limits: `<= 16 KiB` REST body, `<= 8,192 B` aggregate reassembled WS frame, `<= 8 KiB` headers, `15s` request timeout.
3. **Authentication, Idempotency & Clock Hygiene:**
   - Signs every HTTP/WS request via `mp_protocol::rfc9421` (`tag="mp1"`, 24-byte CSPRNG nonce, `expires = created + 60`, RFC 9530 `Content-Digest` on body methods).
   - **Retry separation:** Retrying an interrupted mutation preserves the **exact same `Idempotency-Key`, body bytes, and `expected_party_epoch`** while generating a **fresh RFC 9421 nonce & signature** per attempt. Never silently rebase a stale-epoch mutation.
   - **Scoped `clock_skew` offset:** `clock_offset_ms` learned from `401 {"error":"clock_skew","server_now_ms":...}` is clamped to `±10 min`, applied **only** to outbound RFC 9421 timestamps for `api_authority`, and **NEVER** applied to local or peer CWT expiry checks!
4. **Liveness, Sleep-Aware Timers, Eviction Churn & Epoch Sanity:**
   - Static `"MP1:PING"` every `20s`; sleep-aware timer (`CLOCK_BOOTTIME` / `mach_continuous_time`) tracks `last_pong`:
     - `> 45s` silent -> close WS (`1000`) and reconnect with jittered backoff (`250ms..5s`).
     - `> 60s` without fresh WS confirmation -> close party P2P connections with `4401` (`UNAUTHORIZED`) until reattached and a fresh `PARTY_SNAPSHOT` arrives.
     - Note: static `MP1:PONG` proves transport liveness only (not instantaneous revocation); hard authorization is additionally bounded by exact local & peer CWT expiry timers (on local system clock) and immediate `4403` teardown on `PARTY_MEMBER_LEFT` / `PARTY_DISBANDED` / WS `4401`/`4403`.
   - **Terminal reconnect errors:** HTTP `404` or `403` on `/v1/parties/<id>/ws` reconnect is terminal (party disbanded/kicked/expired -> stop retrying, tear down P2P, clear active party).
   - **Dual-host `device_id` churn detector:** If `AccountDO` or `PartyDO` WS is unexpectedly closed/replaced `>= 3` times within `60s` with changing `HELLO_ACK.session_id`, surface loud `device_id_in_use_elsewhere` alert and pause P2P (preventing infinite flapping).
   - **Durable epoch floor:** Before applying any roster message, check `incoming_epoch >= epochs.bin[party_id].highest_party_epoch` (sanity check against replay/rollback) and persist new high-water marks atomically under `state.lock`.

### 5.2 P2P Data Plane (`crates/outpost-p2p` over `iroh` v1.5.0)

1. **1 Active Party Per `device_id` in v1 + Lazy Per-Party `iroh::Endpoint`:**
   - Because Blackbird's `blackbird-mp/1` wire carries no `party_id`, `iroh` binds `relay_policy`/`RelayMap` per `Endpoint`, and two endpoints with one `device_pubkey` flap at `iroh-relay`, `mp-outpost` v1 enforces **at most 1 active party per `device_id`** (matching Blackbird's `P2pPartySession`; operators needing 2 simultaneous parties enroll a 2nd device out of 8).
   - **Symmetric Policy Compatibility Matrix (Checked BEFORE REST Join/Create):**
     - `local_relay_policy` is a non-downgradeable floor.
     - `local = force_relays` + `party = no_relays` -> **REFUSE** (`relay_policy_incompatible`).
     - `local = no_relays` + `party = force_relays` -> **REFUSE** (`relay_policy_incompatible`).
     - Otherwise `effective_policy = match (local, party) { (Force, _) | (_, Force) => Force, (No, _) | (_, No) => No, _ => Allow }`.
   - **Exact Endpoint Lifecycle:**
     - `PartyCreate`: build `iroh::Endpoint` with `effective_policy` + configured `relay_url` -> gather initial policy-filtered `EndpointDescriptor` (waiting up to `3s` for `net_report` under `allow_relays`; zero wait + zero direct IPs under `force_relays`) -> `POST /v1/parties` -> attach `/v1/parties/<id>/ws`.
     - `PartyJoin`: fetch/validate party summary (`GET /v1/parties/<id>`, or inspect invite + join response) to determine `party.relay_policy` & `party.pinned_relay_url` -> verify compatibility with `local_relay_policy` -> build `iroh::Endpoint` with `effective_policy` + `pinned_relay_url` -> `POST /v1/parties/<id>/join` -> attach `/v1/parties/<id>/ws`.
     - `PartyLeave` / `PartyDisband` / terminal WS `404`/`403`: close `iroh::Endpoint` and drop all peer state immediately.
   - **Endpoint Config Parity (`../blackbird/crates/blackbird-p2p/Cargo.toml` & `src/lib.rs`):**
     - `iroh = { version = "1.5.0", default-features = false, features = ["tls-ring", "fast-apple-datapath"] }` (`tls-ring` only on Linux).
     - `presets::Minimal`, ALPN `b"blackbird-mp/1"`, 0-RTT disabled (`max_tls_tickets(0)`), `max_concurrent_bidi_streams(2)`, RFC 9221 datagrams (`<= 1200 B`).
     - `effective_policy == ForceRelays`: `.clear_ip_transports()` + `.addr_filter(AddrFilter::relay_only())` + explicit `RelayMap` containing ONLY `pinned_relay_url` (zero direct UDP sockets, zero `PARTY_ENDPOINT_UPDATE` churn!).
     - `effective_policy == NoRelays`: `RelayMode::Disabled`.
     - `PARTY_ENDPOINT_UPDATE` debouncing: under `allow_relays`/`no_relays`, coalesce `watch_addr()` changes to `<= 1` update per `30s`, honor `ERROR.retry_after_ms`, emit zero updates under `force_relays`.

2. **5-Link Cryptographic Admission & Trust Gate (Custom `EndpointHooks` + Accept/Dial Check):**
   Before accepting or sending **any** application byte on a QUIC connection for `party_id`:
   1. **TLS RPK -> Snapshot:** Authenticated QUIC peer `EndpointId` (`tls_rpk[32]`) MUST match a connected/admitted `member.device_pubkey` in the current `PARTY_SNAPSHOT` allowlist.
   2. **Snapshot -> CWT `cnf`:** `mp_protocol::verify_device_cwt(member.device_cwt, ...)` MUST decode valid RFC 8392/8747 `COSE_Sign1` (`alg = -19`, `h'A10132'`) with `cwt.cnf.x == tls_rpk` AND `now_local < cwt.exp` (using local system clock, never server-shifted!).
   3. **CWT `iss` -> Pinned `root_pubkey`:** Look up `(api_authority_hash, member.account_id)` in `peers.bin`:
      - If **`pinned_trusted`**: require `member.root_pubkey == pinned.root_pubkey` AND `cwt.iss == lowercase_hex(sha256(pinned.root_pubkey))` AND CWT Ed25519 signature verifies strictly under `pinned.root_pubkey`! Any mismatch -> **`KeyMismatch` (close `4401`, block peer permanently, emit critical alert, fail closed on ALL party sends)**.
      - If **`revoked_blocked`**: close `4403` (`PEER_REVOKED`) immediately.
      - If **unpinned (first contact)**: verify CWT signature under `member.root_pubkey` (`cwt.iss == lowercase_hex(sha256(member.root_pubkey))`), compute canonical `mp-safety-v1` Crockford Safety Number directly from `(member.account_id, member.root_pubkey)`, surface `UnpinnedPeerAlert` in `outpost_status` + `party_members` (with lazily fetched server handle from `GET /v1/accounts/<id>`), and **refuse QUIC admission (`4401`)** until the operator pins via interactive TTY `mp-outpost peer trust <account_id>`!
   4. **Immediate Revocation & Expiry Teardown:** On `PARTY_MEMBER_LEFT`, `PARTY_DISBANDED`, peer CWT expiry timer, local CWT expiry timer, or `peer revoke`: immediately close QUIC with `4403` (`PEER_REVOKED`) and purge `device_pubkey` from allowlist.

3. **Dialing, Glare & Close Codes (Exact `blackbird-p2p` Parity):**
   - Close codes: `4000` (`SHUTDOWN`), `4400` (`PROTOCOL_VIOLATION`), `4401` (`UNAUTHORIZED` / unpinned / lease expired), `4403` (`PEER_REVOKED`), `4409` (`SUPERSEDED` — newest connection replaces stale half-open one), `4413` (`FRAME_TOO_LARGE`).
   - **Single-flight dialer + recovery:** Strictly smaller `device_id` initiates primary dial; if the smaller peer is unpinned or fails to connect within `5s` after becoming pinned/updated, the larger peer may initiate once with jittered backoff (`2s..30s`). Calling `mp-outpost peer trust` immediately triggers a fresh dial attempt. Simultaneous connections resolve cleanly via `4409` (`SUPERSEDED`, deterministic tie-break: keep connection initiated by strictly smaller `device_id`, or newest established after handshake).

4. **Bit-Exact 3-Lane Transport & Blackbird Wave 11B Application Wire v1 (`p2p_party_session.hpp`, `xplat-board` `seq: 14`):**
   - **Stream handshake:** Initiator opens bidi Stream 0 (Control, prio 10, `<= 64 KiB`) + writes `u32::MAX` LE, opens bidi Stream 4 (Causal, prio 0, `<= 4 MiB`) + writes `u32::MAX` LE; Acceptor verifies both markers and echoes `u32::MAX` LE on Stream 0 as readiness ACK. Subsequent frames on Streams 0 & 4 are `u32 LE len` + payload. Lane 2 uses RFC 9221 Datagrams (`<= 1200 B`).
   - **Common 4-byte application header (offsets `0..3`):** `version = 0x01`, `kind = 1..4`, `flags = 0x00` (must be 0), `reserved = 0x00` (must be 0). Trailing bytes, invalid UTF-8, or wrong-lane delivery MUST be rejected!
     - `0x01 chat_message` (Lane 1): `i64 LE timestamp_ns`, `u16 LE room_scope (<=128)`, `u16 LE target_selector (<=64)`, `u16 LE sender_handle (<=64, display hint ignored in favor of server handle!)`, `u32 LE body (<=262144)`.
     - `0x02 bridge_envelope` (Lane 1): `u16 LE room_scope (<=128)`, `u32 LE payload (<=1048576)` (opaque raw bytes in v1; emitted/received byte-exact without mutating binary payload).
     - `0x03 control_notice` (Lane 0): `u8 notice_kind (0=sync_ack, 1=scope_changed, 2=status)`, `u8 reserved (0)`, `u64 LE party_epoch`, `u16 LE text (<=4096)`.
     - `0x04 ephemeral_pulse` (Lane 2, total `<=1200 B`): `u8 activity_state (0=offline, 1=online, 2=working, 3=idle, 4=typing)`, `u8 reserved (0)`, `i64 LE timestamp_ns`, `u16 LE status (<=256)`.
   - **CI Golden Hex Parity (from `../blackbird/tests/p2p_party_session_test.cpp`):**
     - `chat_message`: `0101000008070605040302010a0070617274792f6d61696e040040616c6c0500616c696365020000006869`
     - `bridge_envelope`: `01020000090070617274792f6f707304000000deadbeef`
     - `control_notice`: `010300000000070000000000000002006f6b`
     - `ephemeral_pulse`: `0104000002004433221100000000030072756e`

---

## 6. Stateless Thin MCP Stdio Proxy (`mp-outpost mcp`) & CLI Surface

### 6.1 Owned Stdio JSON-RPC 2.0 Transport (Uniform macOS & Linux)

Owned ~400-LOC implementation (no `rmcp` dependency):
1. **Uniform blocking stdin reader thread + serialized stdout writer task (BOTH macOS and Linux):** Avoids Linux `libuv` `socketpair` `ENXIO` on `/proc/self/fd/0` (Claude Code, Cursor, Gemini CLI) AND macOS `tokio::io::stdin()` drop hangs. Reader uses a persistent `line_buf` (`16 MiB` cap) + `discarding` flag. On `stdin` EOF or `SIGTERM`/`SIGINT`, cancel in-flight daemon requests, flush already-queued stdout bytes (bounded `50 ms` cap), and call `std::process::exit(0)` without joining the blocked reader thread -> guaranteed **`< 50 ms` exit**!
2. **Strict JSON-RPC hygiene:** Strip UTF-8 BOM + trailing `\r`, skip blank lines, silently ignore malformed JSON syntax (`Syntax|Eof`) to prevent error storms, reply `-32600` on invalid request shape, reject JSON-RPC batch arrays under `2025-06-18`, reject duplicate object keys and embedded NULs. Map string or integer JSON-RPC `id`s via an explicit per-connection table to binary IPC `request_id: u64`.
3. **Handshake & lazy daemon connect:** Negotiate `["2025-06-18", "2025-03-26", "2024-11-05"]`, allow pre-init `ping`, gate `structuredContent` on `>= 2025-06-18`, static tool catalog (`listChanged: false`), answer `initialize` + `tools/list` in **`< 20 ms`** with zero daemon/network I/O. Connect lazily on first `tools/call`; drop idle `d.sock` after `120s` when `active_parties == 0`.
4. **Bounded reconnect budget:** On `d.sock` `EOF`/`EPIPE`/`ECONNRESET`, keep MCP stdio open and retry `ensure_connected` with jittered backoff up to a **`30s` total cap** (returning retryable `daemon_unavailable` thereafter). Idempotent reads retry once; interrupted sends return honest `delivery_unknown`; interrupted `party_wait` returns `{ cursor_reset: true, gap_possible: true, daemon_epoch, next_seq }`.

### 6.2 Provenance Fencing & Accidental-Secret Guard

1. **Unbreakable Decoded-Layer Provenance Fence:**
   - Every inbound peer message rendered into MCP `content[0].text` or CLI text is sanitized (preserving `\n` and `\t`, stripping all other C0, C1, `0x1B` ESC, `0x7F` DEL, Unicode BiDi overrides/isolates `U+202A..202E`/`U+2066..2069`/`U+200E/F`/`U+061C`, and zero-width chars `U+200B..200D`/`U+FEFF`).
   - Wrapped in a **per-response 64-bit CSPRNG nonce fence**:
     `<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_<16hex>>>>` ... `<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END_<16hex>>>>`
   - Any occurrence of the nonce or literal `<<<` / `>>>` inside decoded peer text is deterministically mangled (`< < <` / `> > >`) at the text layer (never relying on JSON `\u003c`!).
   - In `structuredContent`, trusted provenance (`untrusted_remote: true`, `sender_account_id`, `sender_device_id`, `sender_handle`, `root_pubkey_fingerprint`, `safety_number`, `party_id`, `party_epoch`, `event_seq`) is kept in separate JSON fields from `body` / `payload_b64`.
2. **Accidental-Secret-Disclosure Guard (Outbound `party_send` / `board_post` on MCP & CLI):**
   - Exact-matches the local daemon's **own `device_secret` and `device_cwt`** across raw, lowercase/uppercase hex, base64, and base64url encodings (zero false positives, closes the crown-jewel leak!).
   - Also refuses exact-grammar tokens: `mpinv1_[A-Za-z0-9_-]{43}`, `mppi1_[0-9]+_[A-Za-z0-9_-]{43}`, and `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----` without echoing the offending value. (Documented honestly as accidental-disclosure prevention, not exfiltration prevention against a hostile shell.)

### 6.3 MCP Tool Catalog (`serverInfo.name = "multiplayer-outpost"`)

Zero collision with `https://multiplayer.tech/mcp` or `blackbird-command-post`.

| Tool | Inputs | Behavior |
| --- | --- | --- |
| `outpost_status` | `{}` | Account/device IDs, handle, CWT expiry, `daemon_epoch`, `daemon_pid`, active party, unpinned/mismatch alerts, `dual_host_churn_alert`. |
| `party_list` | `{}` | Active party (0 or 1 in v1), `party_id`, `party_epoch`, `relay_policy`, `member_count`, `next_seq`, `daemon_epoch`. |
| `party_members` | `{ party_id }` | Verified roster (`account_id`, `device_id`, server `handle`, `trust_state`, `safety_number`, `connected_mp1`, `connected_p2p`). |
| `party_send` | `{ party_id, body, room_scope?, target_device_id? }` | Scans secrets; fails closed on any `key_mismatch`; targeted send checks target pin only; broadcast delivers to `pinned_trusted` connected peers (refusing if 0 pinned recipients) and returns `{ delivered_to[], withheld_unpinned[], disconnected[] }`. |
| `board_post` | `{ party_id, room_scope, payload_b64 }` | Same secret scan and per-destination trust gating as `party_send`; sends P2P Lane 1 `0x02 bridge_envelope`. |
| `party_poll` | `{ party_id, cursor_epoch?, after_seq, limit?, max_bytes? }` | Non-blocking byte-budgeted (`512 KiB` cap) cursor read returning fenced chat/control events, `daemon_epoch`, `next_seq`, `dropped_before_seq`, `cursor_reset`, `gap_possible`. |
| `board_read` | `{ party_id, cursor_epoch?, after_seq, limit?, max_bytes? }` | Non-blocking byte-budgeted cursor read filtered to `0x02 bridge_envelope` events (base64 `payload_b64` + verified provenance). |
| `party_wait` | `{ party_id, cursor_epoch?, after_seq, timeout_ms? }` | Bounded long-poll (**default `25_000 ms`, hard cap `45_000 ms`** < Codex's 60s timeout). Returns events, `{ timed_out: true }`, or `{ cursor_reset: true, gap_possible: true }`; honors `notifications/cancelled`; emits `notifications/progress` every `10s` only if `_meta.progressToken` supplied. |
| `party_friends` | `{}` | Read-only mutual friends + live presence snapshot. |

### 6.4 CLI Surface (`mp-outpost ...`)

All invite secrets (`mpinv1_...`, `mppi1_...`) read exclusively from `stdin`, `--secret-fd <N>`, or TTY prompt — NEVER `argv`. All query commands support `--json`.

- **Account & Device Custody:**
  - `mp-outpost account register --handle <h> --root-key-out <path> [--invite-stdin | --resume] [--device-label <l>]`
  - `mp-outpost account rename --handle <h> --root-key-file <path>`
  - `mp-outpost whoami [--safety-number] [--json]`
  - `mp-outpost device init [--device-label <l>] [--relay-policy allow|force|none]` (writes `pending_dev.bin`, prints `device_pubkey_b64`)
  - `mp-outpost device install-cwt --account-id <u64> --device-id <u64> --root-pubkey-b64 <b64> --cwt-stdin` (verifies CWT, flips `pop_verified = 1`, notifies daemon to reload)
  - `mp-outpost device enroll --device-pubkey-b64 <b64> --device-label <l> --root-key-file <path>` (one-shot online `.root` call)
  - `mp-outpost device renew --device-id <u64> --root-key-file <path>` (one-shot online `.root` call, prints new CWT)
  - `mp-outpost device revoke --device-id <u64> --root-key-file <path>` (`.root` unthrottled priority lane)
- **Trust & Social (Trust Ops Strictly Interactive `/dev/tty`):**
  - `mp-outpost peer list [--json]`
  - `mp-outpost peer trust <account_id>` (**TTY-only:** prints candidate Safety Number & server handle, prompts operator to type peer-read SN + confirm)
  - `mp-outpost peer revoke <account_id>` (**TTY-only:** confirms revocation + immediately kicks daemon `4403` close)
  - `mp-outpost friend list | add <handle_or_id> | remove <account_id> | block <account_id>`
- **Party Lifecycle & Messaging:**
  - `mp-outpost party create [--visibility private|friends] [--join-mode invite|approval] [--relay-policy allow|force|none] [--max-members 2..12]`
  - `mp-outpost party join <party_id> [--invite-stdin] [--relay-policy allow|force|none]`
  - `mp-outpost party invite mint <party_id> [--friend <account_id> | --link --max-uses N] | revoke <party_id> <invite_id>`
  - `mp-outpost party requests <party_id> | approve <party_id> <request_id> | reject <party_id> <request_id>`
  - `mp-outpost party leave <party_id> | disband <party_id> | kick <party_id> <account_id> | promote <party_id> <device_id>`
  - `mp-outpost party status | list | members <party_id> | say <party_id> <text> | read <party_id> | wait <party_id>`
  - `mp-outpost board post <party_id> --scope <s> (--payload-stdin | --payload-file <path>) | read <party_id>`
- **Daemon & MCP:**
  - `mp-outpost mcp [--device-id <u64>]`
  - `mp-outpost daemon status | start | stop [--force] [--leave-party] | restart | logs`

---

## 7. Workspace Layout & Proposed Dependencies (For Operator Approval)

```text
multiplayer_outpost/
  Cargo.toml (workspace, Rust Edition 2024)
  crates/
    outpost-core/     # Sans-IO binary IPC frames, binary persistence codecs (MPD1/MPP1/MPE1/MPN1/MPR2/MPI1), Blackbird P2P wire v1 codec, Safety Number, ring buffer & cursor state machine, secret guard, nonce provenance fencer (#![forbid(unsafe_code)])
    outpost-control/  # TLS 1.3-only HTTP/1.1 (hyper 1) + RFC 6455 WS (tokio-websockets 0.13) MP1 client
    outpost-p2p/      # iroh v1.5.0 lazy per-party 3-lane blackbird-mp/1 endpoint + 5-link EndpointHooks admission gate
    outpost-cli/      # Single static binary `mp-outpost`: CLI + `__daemon` OS lifecycle + owned MCP stdio proxy
```

### Dependencies Summary (Zero Extra HTTP/WS Bloat)
- **Canonical protocol:** `mp-protocol` (pinned/shared from `../multiplayer_site/crates/mp-protocol`; pulls `ed25519-dalek`, `sha2`, `ciborium`, `base64`).
- **P2P + Async + Audited HTTP/WS (all from `iroh 1.5.0`'s existing `Cargo.lock`):** `iroh 1.5.0` (`tls-ring`, + `fast-apple-datapath` on macOS), `tokio`, `rustls` + `tokio-rustls` + `webpki-roots`, `hyper 1` (`http1`, `client`), `tokio-websockets 0.13`, `bytes`.
- **Boundary JSON + POSIX FFI:** `serde`, `serde_json` (external REST/MCP/CLI `--json` ONLY), `libc`.
- **Owned (NOT adopted):** MCP stdio JSON-RPC 2.0 (~400 LOC), CLI argv parser, binary persistence & IPC codecs, CRC32C (~35 LOC). Rejecting `rmcp`, `rusqlite`, `clap`.

---

## 8. Oracle-Grade Verification Plan (`BLACKBIRD.md` Tiers 4–7)

1. **Control-Plane Golden Vector Parity:** Bit-for-bit pass against `../multiplayer_site/docs/TEST_VECTORS.json` + Wycheproof/Chalkias Ed25519 strict rejection vectors.
2. **Blackbird P2P Wire v1 Parity & Live Loopback Interop:** Bit-for-bit pass against all 4 Wave 11B golden hex vectors (`seq: 14`) + live loopback `iroh` v1.5.0 QUIC session between `mp-outpost` and `blackbird` verifying Stream 0/4 `u32::MAX` handshake, 5-link CWT+pin binding (explicit test rejecting a compromised-server swapped `device_pubkey` with a victim's valid CWT!), `force_relays` zero-direct-socket packet verification, `4409` glare resolution, and `4403` revocation close.
3. **Sans-IO DST (`proptest` + state-machine simulation):** Ring-buffer wrap + byte-budgeted pagination, `(daemon_epoch, after_seq)` cursor reset, `client_msg_id` payload-hash conflict rejection, durable `epochs.bin` rollback rejection across simulated crashes, sleep-aware timer expiry across simulated suspend, decoded-layer nonce fence breakout fuzzing, and crown-jewel `device_secret`/`device_cwt` encoding-variant secret-guard tests.
4. **Real-OS Daemon Fault-Injection Oracles (macOS & Linux):**
   - **Thundering herd (32 concurrent clients):** exactly 1 daemon PID acquires `daemon.lock`, all converge on 1 `daemon_epoch`.
   - **A/B/A mixed-build coexistence:** running old `mp-outpost mcp` + new CLI at same `IPC_SCHEMA_VER` produces **zero** daemon kills or respawn loops; incompatible schema causes `mcp` to error cleanly without killing the newer daemon.
   - **`SIGKILL` mid-session with 2 live MCP shims:** zero broken JSON-RPC lines, automatic recovery, both shims receive `cursor_reset: true` and resume.
   - **Inode self-fence & idle-exit race:** unlinking `d.sock`/`daemon.lock` causes watchdog self-exit within 6s; 200-iteration idle-exit vs `connect()` race hammer produces zero unrecovered errors.
   - **Socket publish & `sun_path` budget:** test `bind -> chmod -> listen -> link -> unlink -> connect` on both macOS APFS and Linux, and verify max temp path `<= 103 B` under 60 B macOS prefix.
   - **Zero leaked FDs & zero zombies:** spawn daemon from an MCP parent holding extra non-`CLOEXEC` pipe FDs; verify pipe closes immediately (no leak) and daemon exit leaves zero zombie PIDs.
   - **Forced escalation on both OSes:** `SIGSTOP` daemon -> `daemon stop --force` verifies native start-token / `SO_PEERPIDFD` and terminates cleanly without risking recycled PIDs.
5. **MCP Multi-Host & Live Edge Conformance:** Test `< 20 ms` `initialize`/`tools/list` with zero daemon spawned, `< 50 ms` exit on `stdin` EOF (both pipe and `socketpair`!), `notifications/cancelled` aborting `party_wait`, `45s` cap enforcement, and live `https://api.multiplayer.tech` E2E conformance with full D1 cleanup.
