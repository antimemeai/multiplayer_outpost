# Frumentarius Report 1: Local Sidecar Daemon Failure Modes, Systems Patterns, and Architecture for `multiplayer_outpost`

- **Date:** 2026-11-23
- **Author:** Frumentarius 1 (Daemon Failure Modes & Systems Patterns)
- **Target System:** `multiplayer_outpost` — standalone Rust local Outpost owning one `device_id` `MP1` WebSocket to `https://api.multiplayer.tech` and one `iroh` v1.5.0 P2P QUIC endpoint (ALPN `blackbird-mp/1`, TLS 1.3 Mutual RPK RFC 7250, 0-RTT off), serving local CLI invocations and multiple concurrent MCP stdio bridges (Claude Code, Codex, Antigravity).
- **Doctrine Alignment:** Concrete syscalls, failure modes, and wire invariants (`BLACKBIRD.md`). Binary internal IPC (JSON strictly at external REST and MCP stdio JSON-RPC 2.0 boundaries). Primary keys are integer IDs or fixed digests, never string handles.

---

## Executive Recommendation

Adopt a **Hash-Pinned Auto-Spawning Ephemeral Child-Process Sidecar** paired with a **Thin Reconnecting MCP Stdio Shim**:

1. **Process topology:** Separate the long-lived network owner (`outpost-daemon`) from every caller (`outpost` CLI and `outpost mcp` stdio shim). Reject in-process leader promotion: an MCP stdio host (Claude Code, Codex, Antigravity) owns its child process lifetime via `stdin` EOF and `SIGTERM`/`SIGKILL`; promoting an MCP child to leader couples all other editors' `MP1` + `iroh` connections to one editor closing.
2. **Mutual exclusion & stale recovery:** Guard startup and liveness with a single whole-file `flock(2)` (`LOCK_EX`) on a companion `daemon.lock` file inside a `0700` user-private runtime directory. Never use POSIX `fcntl(F_SETLK)` (process-wide close hazard) and never trust PID files for liveness.
3. **Version-skew elimination:** Embed a compile-time `build_digest: [u8; 32]` and `ipc_schema_version: u32` inside the binary. Every binary IPC connection starts with a `Hello` / `HelloAck` exchange. On mismatch, the client acquires `startup.lock` (or coordinates via `daemon.lock`), sends a `DrainAndShutdown` frame to the old daemon (with bounded deadline + verified-peer termination fallback), waits for `daemon.lock` release, and spawns the new binary.
4. **Zero-downtime MCP survival without `SCM_RIGHTS`:** Do **not** attempt `SCM_RIGHTS` file-descriptor handoff for `MP1` TLS/WebSocket or `iroh` QUIC UDP sockets. Userspace TLS 1.3 key schedules, QUIC Connection IDs, and stream state cannot migrate over raw FDs. Instead, keep the thin `outpost mcp` stdio process alive across daemon restarts; the shim owns the MCP `initialize` state machine and transparently reconnects to the respawned daemon over the Unix socket.
5. **Zero-install default, optional OS supervision:** Do not require `launchctl bootstrap` or `systemctl --user enable` for normal operation. Opportunistically check `LISTEN_FDS` (Linux `systemd`) / `launch_activate_socket` (macOS `launchd`) at daemon startup so power users may supervise it if desired, while default usage remains zero-config and self-cleaning via idle auto-exit (OpenSSH `ControlPersist` semantics).

---

## 1. Failure Mode Taxonomy of Local Daemons

Local client-daemon tools fail in seven recurring ways on macOS and Linux. Each class below names the exact kernel mechanism, the concrete symptom, and the structural defense.

### 1.1 Binary / Daemon Version Skew & In-Place Replacement

- **Mechanism:** User upgrades `outpost` via `cargo install`, Homebrew, or `cp` while an older daemon remains resident. On Linux, replacing a running ELF binary unlinks the old directory entry while keeping its inode mapped in memory; `/proc/<pid>/exe` resolves to `<path> (deleted)` [Linux procfs; Group-IB / Arch Build-ID docs]. On macOS, `dyld` continues executing the unlinked Mach-O image (identified by its `LC_UUID` load command) while the path on disk now points to the new binary [Apple Mach-O `LC_UUID`].
- **Failure:**
  1. New CLI/MCP client connects to old daemon and sends new binary IPC frames -> framing error, silent field truncation, or protocol deadlock.
  2. Old daemon calls `std::env::current_exe()` to respawn helpers -> spawns the *new* binary on disk while running *old* state in RAM, causing split-brain skew (the exact failure mode seen in `rust-analyzer` vs `rust-analyzer-proc-macro-srv` ABI mismatches).
- **Defense:**
  - Never rely on runtime `current_exe()` hashes alone to identify the *running* daemon's code after startup; stamp a compile-time `BUILD_DIGEST` (32-byte digest of source/git/protocol schema, or read ELF `.note.gnu.build-id` / Mach-O `LC_UUID` once at startup from memory) and transmit it in the IPC `HelloAck`.
  - Include `ipc_schema_version: u32` + `build_digest: [u8; 32]` in every connect handshake. Mismatch triggers deterministic drain-and-respawn (Section 5.2).

### 1.2 Stale PID Files, PID Reuse, and Dead Unix Domain Sockets

- **Mechanism:** Unlike `AF_INET` sockets, `AF_UNIX` pathname sockets have no `SO_REUSEADDR` equivalent for an existing filesystem node. If a daemon dies via `SIGKILL`, OOM, or power loss, its socket node remains on disk. Subsequent `bind(2)` fails with `EADDRINUSE`; client `connect(2)` fails with `ECONNREFUSED` [Gavv Unix Sockets; `unix(7)`].
- **Failure:**
  1. **Blind `unlink()` race:** Two daemons start concurrently. Daemon A calls `unlink(path)` then `bind(path)`. Daemon B calls `unlink(path)` (destroying A's live directory entry) then `bind(path)`. Daemon A stays alive serving an unreferenced socket inode while new clients connect to B — classic split-brain.
  2. **PID file lie:** Process crashes leaving `daemon.pid`. Kernel recycles that PID to an unrelated process. `kill(pid, 0)` returns `0`; client either hangs believing the daemon is live or sends `SIGTERM` to an innocent process.
  3. **POSIX `fcntl(F_SETLK)` silent lock drop:** Classic POSIX record locks attach to `(pid, inode)`. Closing *any* file descriptor to that same file anywhere in the process — including another thread or a third-party library — immediately drops *all* `F_SETLK` locks held by the process on that inode [POSIX `fcntl(2)`; Lennart Poettering / Apenwarr lock analyses].
  4. **Dotlock wedge:** Tools like `gpg-agent` and `git` (`index.lock`) rely on `O_CREAT | O_EXCL` dotlock files; after `SIGKILL`, the file persists indefinitely until manual `rm -f` [GnuPG / `git-fsmonitor--daemon` failure reports].
- **Defense:**
  - Use **`flock(2)`** (`LOCK_EX`) on a dedicated lock file (`daemon.lock`). `flock` binds to the **open file description**, works identically on Linux and macOS, survives unrelated `open`/`close` calls in the same process, and is **guaranteed to be released by the kernel on process death** (even `SIGKILL` or kernel panic/reboot). (Note: Linux `F_OFD_SETLK` has the same safe open-file-description semantics since Linux 3.15, but does not exist on macOS.)
  - Never delete `daemon.lock` on shutdown. Deleting a lock file creates a classic race where Process A holds `flock` on unlinked inode 1 while Process B creates and locks new inode 2 at the same path. Keep `daemon.lock` persistent inside the runtime directory; only unlink/replace the socket node *while holding* `flock(LOCK_EX)` on `daemon.lock`.

### 1.3 Startup Thundering-Herd Races

- **Mechanism:** An AI workspace opens 3 MCP hosts (Claude Code, Codex, Antigravity) simultaneously at $t=0$, or a shell script runs 4 `outpost` CLI commands in parallel when no daemon is running. All callers receive `ENOENT` or `ECONNREFUSED` from `connect(2)`.
- **Failure:** Without serialization, all callers spawn a daemon simultaneously. Even if only one binds the socket, N-1 daemons briefly open `MP1` WebSockets with the same `device_id` (triggering control-plane session eviction) or collide on `iroh` state/ports. (OpenSSH `ControlMaster=auto` historically suffered this exact race under parallel Ansible runs: `ControlSocket ... already exists, disabling multiplexing` [OpenSSH `mux.c` / Ansible reports].)
- **Defense:** Double-checked locking (`tmux` `client.c` pattern):
  1. Fast path: `connect(sock)`. On success, run `Hello` handshake.
  2. On `ENOENT` / `ECONNREFUSED`: open `startup.lock` (separate from or coordinated with `daemon.lock`), call blocking `flock(startup_fd, LOCK_EX)` with bounded timeout.
  3. **Re-attempt `connect(sock)` after acquiring `startup.lock`.** If another racer spawned the daemon while this caller waited, the second `connect()` succeeds immediately.
  4. Only if the second `connect()` still fails does the lock holder spawn `outpost-daemon`, wait for a readiness pipe/socket signal, then drop `startup.lock`.

### 1.4 Orphan Daemons, Stdout Pipe Inheritance Hangs, and Session Lifecycle

- **Mechanism:** When a CLI tool or MCP shim spawns a background daemon, the child inherits open file descriptors by default unless marked `FD_CLOEXEC` and redirected.
- **Failure:**
  1. **Parent stdout hang:** A shell command like `$(outpost status)` or an MCP host capturing child `stdout` waits for EOF on the stdout pipe. If the spawned daemon inherits `stdout` (FD 1) or `stderr` (FD 2), the pipe stays open forever; the shell or MCP client hangs indefinitely even after the CLI exits.
  2. **MCP JSON-RPC stream corruption:** Any stray byte written by the daemon or child process to the MCP shim's `stdout` breaks newline-delimited JSON-RPC 2.0 parsing [MCP Stdio Transport Spec].
  3. **Signal group collateral damage:** If the daemon stays in the caller's process group / session, `Ctrl-C` (`SIGINT`) in one terminal or `SIGTERM` to a process group kills the shared daemon for all other MCP hosts.
  4. **Zombie/orphan accumulation:** Without idle timeout or logout teardown, background daemons accumulate across profiles, branches, and test runs.
- **Defense:**
  - Spawn the daemon detached: call `setsid()` in the child (so terminal `SIGINT`/`SIGHUP` does not hit it), set `FD_CLOEXEC` on all non-transferred FDs, redirect `stdin`/`stdout` to `/dev/null`, and redirect `stderr` to a bounded rotating log file inside the runtime dir (never to caller pipes).
  - Set `signal(SIGPIPE, SIG_IGN)` globally at daemon and shim startup so broken client sockets return `EPIPE` instead of terminating the process.
  - Note parent-death primitives for *non-detached* helpers (such as if a daemon spawns an internal worker): Linux uses `prctl(PR_SET_PDEATHSIG, SIGTERM)`; macOS has no `PR_SET_PDEATHSIG` and uses `kqueue(2)` with `EVFILT_PROC` + `NOTE_EXIT` (checking `getppid() == 1` right after registration to close the pre-registration race), or portably holds the read end of a parent-owned pipe and exits on `EOF` (`EV_EOF` / `read() == 0`). For the *shared* `outpost-daemon`, do **not** tie daemon death to the spawning caller's exit — tie daemon shutdown to `active_clients == 0 && active_parties == 0` idle timer instead.

### 1.5 Split-Brain Client Caches & Single-`device_id` Contention

- **Mechanism:** `multiplayer_outpost` owns one `device_id` authenticated via `COSE_Sign1` CWT over `MP1` WebSocket (`https://api.multiplayer.tech`) and one `iroh` v1.5.0 `Endpoint` bound to that device's Ed25519 keypair.
- **Failure:**
  1. If two local daemons run for the same `device_id` (e.g., because `TMPDIR` differed between two shells, producing two different runtime directories!), both dial `api.multiplayer.tech` with the same `device_id` -> control-plane connection thrashing, duplicate `EndpointDescriptor` advertisements, and split P2P party state where Editor A sees messages that Editor B misses.
  2. If each MCP shim caches party roster/board state locally without a monotonic daemon epoch + sequence number, a daemon restart leaves clients serving stale snapshots.
- **Defense:**
  - Derive the runtime directory from a **deterministic, environment-independent per-user base** (Section 4.1), never from a caller-mutable `$PWD` or an unvalidated `$TMPDIR` override unless explicitly requested via `--profile-dir` / `--runtime-dir`.
  - Enforce **single-writer ownership**: only `outpost-daemon` touches the `MP1` WebSocket, `iroh` `Endpoint`, and local state store. Every daemon boot generates a random `daemon_epoch: u64` and assigns strictly monotonic `event_seq: u64` to party/board events so reconnecting shims detect epoch rollover immediately and perform a full state resync.

### 1.6 Deadlocks, Wedged Event Loops, and Watchdog Recovery

- **Mechanism:** A daemon holds `daemon.lock` and has an open listening socket (kernel completes TCP/Unix `connect()` into the `listen(2)` backlog), yet its async runtime (Tokio) is deadlocked (e.g., blocking mutex held across `.await`, exhausted blocking pool, or hung DNS/socket call).
- **Failure:** `connect(2)` succeeds because the kernel accepts into the backlog queue, then the client blocks forever waiting for `HelloAck`. Holding `flock` proves *process liveness*, **not** *event-loop progress*.
- **Defense:**
  - Enforce strict client-side deadlines: `HELLO_TIMEOUT = 1500ms`, `RPC_TIMEOUT` per operation, and periodic `Ping`/`Pong` keepalives (e.g., every 10s, fail after 2 missed pongs) on long-lived MCP shim IPC streams.
  - Inside the daemon, run a dedicated OS watchdog thread (outside Tokio) that ticks a heartbeat against a Tokio task every 5s; if Tokio stalls for >15s, write a crash diagnostic to the daemon log and `abort()` so the kernel releases `daemon.lock` immediately and shims respawn a clean daemon.
  - If a client hits `HELLO_TIMEOUT` on an existing socket, acquire `startup.lock`, re-probe once, then escalate: read daemon's authenticated peer PID via `SO_PEERPIDFD` (Linux 6.5+) or `LOCAL_PEERPID` + `LOCAL_PEERTOKEN` (macOS) from the connected socket (never from a stale PID file), send `SIGTERM`, wait up to `DRAIN_GRACE = 2000ms` for `daemon.lock` release, then send `SIGKILL` (via `pidfd_send_signal` on Linux to eliminate PID-reuse risk).

### 1.7 macOS vs. Linux Runtime Directory & `sun_path` Pitfalls

| Dimension | Linux (`systemd` / XDG) | macOS (Darwin / XNU) | Concrete Pitfall & Mitigation |
| :--- | :--- | :--- | :--- |
| **`sockaddr_un.sun_path` max** | **108 bytes** (`UNIX_PATH_MAX`, incl. NUL) | **104 bytes** (`<sys/un.h>`, incl. NUL) | macOS `$TMPDIR` (`/var/folders/xx/<30+ chars>/T/`) consumes 49–60 bytes before the app appends anything. Appending a UUID/profile slug breaches 104 bytes -> `bind()`/`connect()` fails with `EINVAL` or `ENAMETOOLONG`. Keep relative/leaf names <= 24 bytes (e.g., `o/<8-hex>/d.sock`). |
| **Standard runtime dir** | `$XDG_RUNTIME_DIR` (`/run/user/<uid>`, `0700`, tmpfs) | `confstr(_CS_DARWIN_USER_TEMP_DIR)` (same as `$TMPDIR`, `/var/folders/.../T/`, `0700`) or `~/Library/Caches` | Linux `XDG_RUNTIME_DIR` is short (15–18 bytes). macOS `DARWIN_USER_TEMP_DIR` is ~50 bytes. Note: in headless/SSH/cron/container Linux, `$XDG_RUNTIME_DIR` may be unset; must have a safe `0700` fallback. |
| **Logout cleanup** | `pam_systemd` wipes `$XDG_RUNTIME_DIR` on last session logout | **NOT wiped on logout** — macOS purges unaccessed `/var/folders/.../T` files after ~3 days or on reboot | Never assume macOS cleans stale sockets/locks on logout; always rely on `flock` + `ECONNREFUSED` recovery. Conversely, on Linux, if a user logs out and back in, `$XDG_RUNTIME_DIR` is recreated; daemons must not assume files survive logout. |
| **Abstract sockets** | Supported (`\0`-prefixed `sun_path`) | **Not supported** | Do not rely on Linux abstract sockets: non-portable to macOS, and they bypass filesystem `0700` permissions (any local user in the same netns can connect unless `SO_PEERCRED` is enforced). |
| **Long-path `chdir()` trick** | `/proc/self/fd/<dirfd>` or `chdir()` | No `/proc`; only `chdir()` / `fchdir()` | `chdir()`/`fchdir()` mutates **process-wide** CWD, racing with other threads in multi-threaded Rust binaries. Prefer keeping absolute paths strictly `< 104` bytes rather than mutating CWD. |

---

## 2. Battle-Tested Architectural Patterns & Primary Sources

### 2.1 Hash-Pinned Auto-Spawning Ephemeral Daemon

**Reference systems:** Bazel (`src/main/cpp/blaze.cc`), Buck2 (`app/buck2_client_ctx`), `tmux` (`client.c`, `server.c`), Meta `watchman`, GnuPG `gpg-agent`, `git-fsmonitor--daemon`.

- **Bazel (`bazelbuild/bazel`, `src/main/cpp/blaze.cc`):**
  - Lightweight native C++ client extracts/verifies content-addressed `install_base` (`~/.cache/bazel/_bazel_<user>/install/<md5>/`) under an install lock.
  - Tracks running server via `$OUTPUT_BASE/server/` (`server.pid.txt`, `command_port`, and random `request_cookie`/`response_cookie` tokens to prevent local cross-talk and unauthorized command injection).
  - Serializes workspace mutations via advisory `flock()` (`--[no]block_for_lock`).
  - On client/server `install_base` hash mismatch or startup-option change (e.g., `--host_jvm_args`), the client gracefully shuts down the old server and starts a matching one automatically.
- **Buck2 (`facebook/buck2`, `app/buck2_client_ctx`):**
  - Isolates state per project + `--isolation-dir` (`buck-out/v2/`).
  - Writes `buckd.info` (PID + IPC endpoint) and coordinates startup/teardown via `buckd.lifecycle` file locks.
  - Validates `DaemonConstraints` (binary version, build config, startup constraints) on connect. Historically, mismatched `buck2` binaries required explicit `buck2 kill` or constraint-driven restart when protocol/daemon constraints diverged.
- **`tmux` (`client.c`, `server.c`):**
  - Fast path: `connect()` to `/tmp/tmux-<uid>/<socket>`.
  - On `ECONNREFUSED` / `ENOENT`: acquires `flock(LOCK_EX)` on `<socket>.lock`, retries `connect()`, and only on second failure calls `unlink(socket)`, `bind()`, `listen()`, forks the background server, and drops the lock.
  - Exits automatically when the last session closes (unless `exit-empty off`).
- **Lessons from `rust-analyzer` (`proc-macro-srv`), `git-fsmonitor--daemon`, and `gpg-agent`:**
  - `rust-analyzer` breaks when toolchain updates bump `proc-macro-srv` ABI ahead of the IDE binary — proving that client and daemon MUST be the **same single binary** (invoked as `outpost` vs `outpost __daemon`) and verify exact `build_digest` on connect.
  - `gpg-agent` and `git-fsmonitor--daemon` wedge when `SIGKILL` leaves behind dotlock files or unguarded `.ipc` sockets — proving that kernel-released `flock(2)` must replace dotlocks.

### 2.2 OS-Supervised Socket Activation & File Descriptor Store

**Reference systems:** `systemd` socket activation + `FDSTORE` (Lennart Poettering, `0pointer.de/blog/projects/socket-activation.html`, `systemd.io/FILE_DESCRIPTOR_STORE/`, `sd_listen_fds(3)`, `sd_pid_notify_with_fds(3)`); macOS `launchd` (`launch_activate_socket(3)`, `launchd.plist(5)`).

- **`systemd` mechanism:**
  - `systemd` binds the `.socket` unit beforehand and spawns the `.service` on first client connect, passing listening FDs starting at FD 3 (`SD_LISTEN_FDS_START`) with `LISTEN_FDS` and `LISTEN_PID` env vars.
  - With `FileDescriptorStoreMax=N` and `Type=notify`, a restarting daemon can push live FDs (e.g., local client Unix sockets or `memfd` state) into PID 1 via `sd_pid_notify_with_fds(0, 0, "FDSTORE=1\nFDNAME=...", fds, n)` and recover them on restart via `sd_listen_fds_with_names()`.
- **macOS `launchd` mechanism:**
  - A `~/Library/LaunchAgents/<label>.plist` declares a `Sockets` dictionary (`SockPathName`, `SockPathMode` in decimal, or `SecureSocketWithKey`).
  - On activation, the daemon calls `launch_activate_socket("Listeners", &fds, &cnt)` and frees `fds`.
- **Why developer CLI / MCP tools must NOT *require* OS supervision:**
  1. **macOS SSH / headless domain breakage:** `launchctl bootstrap gui/<uid> <plist>` fails with error `125: Domain does not support specified action` inside SSH sessions or headless CI because `gui/<uid>` only exists with an active Aqua/WindowServer login. Falling back to `user/<uid>` requires `<key>LimitLoadToSessionType</key><string>Background</string>` or fails with `Input/output error`.
  2. **Multi-checkout & developer workflow friction:** Developers run `./target/debug/outpost`, `cargo test`, Nix shells, or temporary profiles. A global `~/Library/LaunchAgents` plist or `~/.config/systemd/user` unit hardcodes one binary path, creating instant version skew against local builds and failing completely in Docker containers without `systemd` PID 1.
  3. **Install/uninstall residue:** Requiring `outpost install-service` leaves persistent OS state after the binary is deleted.
- **Correct synthesis:** Zero-install auto-spawn is the **primary** mode. Inside `outpost __daemon`, check `LISTEN_FDS` (Linux) / `launch_activate_socket` (macOS) before calling `bind()`; if pre-bound FDs exist, adopt them. This gives power users optional `systemd`/`launchd` support with ~40 lines of code and zero mandatory setup.

### 2.3 Ephemeral Connection Multiplexer (OpenSSH `ControlMaster` + `ControlPersist`)

**Reference system:** OpenSSH `ssh_config(5)` and `mux.c` (`muxserver_listen`, `muxclient`).

- **Mechanism:**
  - `ControlMaster auto` + `ControlPersist 10m` + `ControlPath ~/.ssh/cm-%C` (where `%C` is a compact hash of host/port/user to stay well under the 104-byte `sun_path` limit).
  - First `ssh` invocation establishes the network connection, binds a temporary Unix socket (`muxserver_listen: temporary control path ...`), and atomically moves it into `ControlPath` via `rename(2)`/`link(2)` so clients never observe a half-bound node.
  - When the initial foreground session ends, the master forks/backgrounds itself and starts an idle countdown (`ControlPersist` duration). New clients attach via `ControlPath`; when zero clients remain for the idle window, the master closes the upstream transport and exits cleanly.
  - Explicit control commands (`ssh -O check`, `ssh -O exit`) inspect or terminate the master over the same control socket.
- **Flaw to fix for `multiplayer_outpost`:** OpenSSH omits an external `flock` barrier around initial master creation, so simultaneous parallel invocations race and degrade to disabling multiplexing. Combining OpenSSH's **atomic temp-bind + `rename()` + idle-persist exit** with `tmux`'s **`flock(LOCK_EX)` startup barrier** eliminates both races and lingering processes.

### 2.4 In-Process Peer Leader-Election ("Daemonless-with-Promotion") vs. Dedicated Ephemeral Sidecar

**Reference systems:** Chromium `ProcessSingleton` (`SingletonLock` symlink `<host>-<pid>`, `SingletonSocket` symlink to `/tmp`, `SingletonCookie` random auth token); hypothetical first-caller-becomes-leader model where the first `outpost mcp` or `outpost` CLI process acquires `flock(LOCK_EX)` and runs `MP1` + `iroh` inside its own process while peers connect as thin clients.

**Why in-process leader promotion fails badly for `multiplayer_outpost`:**

1. **Fatal lifecycle mismatch with MCP stdio hosts:** Claude Code, Codex, and Antigravity spawn `outpost mcp` as a direct child process and expect it to exit promptly when they close `stdin` or send `SIGTERM` (and will escalate to `SIGKILL` after a short grace timeout).
   - *Case A (Leader exits when its host closes):* Closing Antigravity kills the `MP1` WebSocket and `iroh` QUIC endpoint for Claude Code and Codex, forcing leader election, `MP1` reconnect, `EndpointDescriptor` re-publication, and fresh NAT hole-punching across every active party peer.
   - *Case B (Leader stays alive after `stdin` EOF to serve peers):* The parent AI host hangs waiting on `waitpid()` for its MCP child to exit, then blasts the process (or its process group) with `SIGKILL` — crashing the leader anyway.
2. **Short-lived CLI promotion pathology:** If a user runs `outpost status` first (a 20ms CLI command), promoting it either forces it to stay alive (blocking the shell if it still holds `stdout`) or immediately tear down the `iroh` endpoint 20ms later. To avoid blocking the shell, it would have to fork a detached child anyway — which just reinvents the dedicated child-process sidecar with worse complexity.
3. **Host-specific `stdout` / sandbox contamination:** An MCP stdio process must keep `stdout` strictly pure JSON-RPC 2.0. Running `iroh` + control-plane tasks inside one AI host's process risks library panic output or FD leaks corrupting that host's stdio stream, and inherits that specific AI host's env vars, CWD, and macOS/Linux sandbox/seatbelt restrictions.
4. **Upgrade & version skew:** If Claude Code holds an old in-process leader while the user installs a new binary and runs `outpost` CLI, the CLI cannot replace the leader without killing Claude Code's MCP server process itself (breaking Claude Code's active MCP session!). With a dedicated sidecar, the CLI drains and respawns `outpost-daemon` while Claude Code's thin `outpost mcp` shim stays alive and transparently reconnects.

### 2.5 Comparative Architectural Trade-Off Matrix

| Architecture Pattern | Zero-Install UX | Concurrent MCP Survival (1 IDE closes) | Survives Binary Upgrade w/o Breaking MCP Stdio | Parallel Startup Race Safety | Stale Resource Cleanup | macOS SSH / Container Portability | Verdict for `multiplayer_outpost` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Hash-Pinned Auto-Spawning Ephemeral Child Sidecar** | **Yes** | **Yes** (daemon detached via `setsid`) | **Yes** (thin MCP shim reconnects transparently) | **Yes** (`flock` + double-check `connect`) | **High** (kernel `flock` + idle exit) | **Full** (POSIX syscalls only) | **PRIMARY CHOICE** |
| **2. OS-Supervised (`systemd` / `launchd` Socket Activation)** | **No** (requires unit/plist install) | **Yes** | Partial (`systemd` `FDSTORE` Linux-only; `launchd` drops active conns) | **Yes** (PID 1 owns socket) | **High** (OS managed) | **Poor** (macOS SSH `gui/<uid>` error 125; no PID 1 in containers) | **OPTIONAL ENHANCEMENT** (detect pre-bound FDs if present) |
| **3. OpenSSH-Style Multiplexer (`ControlMaster` + `ControlPersist`)** | **Yes** | **Yes** (once backgrounded) | **No** (no built-in binary hash handshake) | **No** (known parallel race without external `flock`) | **High** (idle timer) | **Full** | **ADOPT IDLE-PERSIST & ATOMIC SOCKET MECHANICS** |
| **4. In-Process Peer Leader Promotion** | **Yes** | **No** (closing leader IDE kills `MP1`+`iroh` for all peers) | **No** (killing leader kills parent IDE's MCP child) | **Yes** (with `flock`) | **Medium** | **Full** | **REJECT** |

---

## 3. Zero-Downtime Handoff, Thin MCP Stdio Shim, and `SCM_RIGHTS` vs. Fast Reconnect

### 3.1 MCP Stdio Transport Invariants

Per the Model Context Protocol (`stdio` transport specification):
- The AI host spawns the MCP server as a child process and exchanges **single-line, newline-delimited UTF-8 JSON-RPC 2.0** messages on `stdin`/`stdout` (no embedded newlines).
- `stdout` MUST contain **only** valid JSON-RPC messages; `stderr` carries diagnostics.
- The session is stateful: `initialize` (request) -> `initialize` (result negotiating `protocolVersion` and `capabilities`) -> `notifications/initialized` (notification) -> Operation phase (`tools/list`, `tools/call`, `resources/*`, server-initiated notifications) -> Shutdown (parent closes `stdin` / sends `SIGTERM`).
- If the child process exits unexpectedly, most AI hosts mark the MCP server failed/disconnected until the user manually restarts the host or reloads MCP servers.

### 3.2 Thin Self-Healing MCP Stdio Shim Architecture

Split responsibilities cleanly across the process boundary:

- **`outpost mcp` (thin stdio shim — one per AI host):**
  - Owns `stdin` / `stdout` JSON-RPC 2.0 framing exclusively. Never dies when `outpost-daemon` restarts or upgrades.
  - Handles MCP `initialize` locally (or caches the negotiated `protocolVersion`, `clientInfo`, `capabilities`, and active party/board subscriptions in memory).
  - Translates JSON-RPC requests into **compact binary IPC frames** over the Unix socket to `outpost-daemon`, and translates binary daemon push events into MCP notifications (e.g., `notifications/resources/updated` or tool-pollable state).
  - **On daemon disconnect (`EOF` / `EPIPE` / `ECONNRESET`):**
    1. Immediately enters `Reconnecting` state (does **not** exit and does **not** close `stdout`).
    2. Runs the connect-or-spawn state machine (Section 5.1) with bounded jittered backoff (e.g., 25ms, 50ms, 100ms, 250ms, up to 3s).
    3. Replays its binary `AttachClient` + `RestoreSubscriptions(last_seen_epoch, last_seen_seq)` frames once connected to the new daemon.
    4. **In-flight request semantics:**
       - Idempotent reads (`status`, `list_parties`, `read_board`, `read_chat`) that failed on transport EOF before receiving a reply are automatically retried once after reconnect.
       - Non-idempotent mutations (`send_chat`, `post_board`, `join_party`) carry a client-generated `idempotency_key: u128` (or return a clean JSON-RPC error `-32001` `"sidecar_restarting_retry"` if outcome is indeterminate) so messages are never silently duplicated or lost.

### 3.3 Why `SCM_RIGHTS` FD-Passing Fails for `MP1` WebSocket + `iroh` v1.5.0 QUIC

`SCM_RIGHTS` (and `systemd` `FDSTORE=1`) works well for **listening TCP/Unix sockets** or **cleartext local Unix client sockets**, because the kernel holds the TCP/Unix state machine. It fails for `multiplayer_outpost`'s upstream network connections:

1. **QUIC / `iroh` v1.5.0 breaks UDP FD handoff:**
   - As documented by Cloudflare (`udpgrm`, Marek Majkowski), NGINX (`quic_bpf` reload regressions causing 50%–75% handshake blackholes), HAProxy (HTX QUIC termination), and Envoy (`--hot-restart`): UDP is connectionless in the kernel. QUIC sessions live entirely in **userspace** — TLS 1.3 Mutual RPK keys, AEAD packet-number spaces, QUIC Connection IDs (CIDs), congestion controllers, stream buffers, and `iroh`'s home-relay HTTPS/WebSocket tunnel + NAT hole-punching state (`Endpoint`).
   - Passing the raw UDP socket FD via `SCM_RIGHTS` transfers zero userspace QUIC state; incoming encrypted UDP datagrams for existing CIDs cannot be decrypted by the new process without serializing the entire `quinn`/TLS/iroh internal state machine (which `iroh` does not expose and which breaks across binary upgrades anyway).
   - Moreover, `multiplayer_outpost` explicitly disables 0-RTT (`0-RTT off`, `AGENTS.md` Constraint #1), so there is no 0-RTT session ticket shortcut to preserve across processes.
2. **TLS 1.3 WebSocket (`MP1`) has the same userspace state barrier:**
   - Passing a connected TCP FD carrying an active TLS 1.3 + WebSocket session requires exporting and importing TLS cipher states, sequence numbers, and partial WebSocket frame buffers across processes — fragile, non-portable, and incompatible with version upgrades.
3. **Why clean drain + fast reconnect wins:**
   - In `multiplayer_outpost`, restarts happen only on **binary upgrade** or **crash recovery** (rare events).
   - `outpost-daemon` performs a bounded graceful close (`conn.close(0, b"restarting")` + `endpoint.close().await` + WebSocket Close frame `1001 Going Away`), releases `daemon.lock`, and exits in <500ms.
   - The new daemon binds the socket in <20ms, reconnects `MP1` WebSocket (~100–300ms), re-publishes its `EndpointDescriptor`, and re-dials active party peers over `iroh` (relay-first while hole-punching upgrades to direct UDP).
   - Meanwhile, the thin `outpost mcp` shim absorbs the ~0.5–1s hiccup completely invisibly to Claude Code, Codex, and Antigravity.

---

## 4. Security, Isolation, and Multi-Profile Layout on macOS & Linux

### 4.1 Symlink- and TOCTOU-Safe Private Runtime Directory

Never place Unix sockets directly inside world-writable `/tmp` (`1777`), where local attackers can pre-create symlinks or hijack paths.

#### Canonical Runtime Base & `sun_path` Budget (< 104 bytes on macOS)

| Platform | Selection Order | Typical Path Example | Byte Length |
| :--- | :--- | :--- | :--- |
| **Linux** | 1. `$OUTPOST_RUNTIME_DIR` (explicit override)<br>2. `$XDG_RUNTIME_DIR/mpo`<br>3. `/tmp/mpo-<uid>` (only if `XDG_RUNTIME_DIR` unset, verified `0700` owned by `geteuid()`) | `/run/user/1000/mpo/p1a2b3c4/d.sock` | **34 bytes** (74 bytes headroom) |
| **macOS** | 1. `$OUTPOST_RUNTIME_DIR` (explicit override)<br>2. `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `mpo` (shortened leaf)<br>3. Fallback if total path >= 100 bytes: `/tmp/mpo-<uid>` (verified `0700` owned by `geteuid()`) | `/var/folders/h8/rh8crjd90y958tn9gmmd2h8m0000gp/T/mpo/p1a2b3c4/d.sock` | **68 bytes** (36 bytes headroom under 104-byte `sun_path` limit) |

- **Crucial macOS invariant:** Always query `confstr(_CS_DARWIN_USER_TEMP_DIR)` directly instead of trusting `$TMPDIR`, because different shells/IDEs (e.g., tmux, VS Code, Claude Code subprocesses) sometimes scrub or override `$TMPDIR` to `/tmp`, which would otherwise cause split-brain daemons! Verify `socket_path.len() < 103` before `bind()`/`connect()`.

#### Exact Symlink-Safe Creation & Verification Sequence

Every daemon and client runs the identical directory-open routine before touching `daemon.lock` or `d.sock`:

1. Call `mkdir(dir_path, 0o700)`. Ignore `EEXIST`; fail on any other error.
2. Call `dirfd = open(dir_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`.
   - `O_NOFOLLOW` fails with `ELOOP` if an attacker swapped the final component for a symlink.
   - `O_DIRECTORY` fails with `ENOTDIR` if it is not a directory.
3. Call `fstat(dirfd, &st)` on the open FD (eliminating path-based `stat()` -> `open()` TOCTOU):
   - Require `S_ISDIR(st.st_mode)`.
   - Require `st.st_uid == geteuid()`.
   - Require `(st.st_mode & 0o777) == 0o700` (if broader, refuse to use it — do not blindly `chmod` an untrusted path).
4. Perform lockfile operations via `openat(dirfd, "daemon.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)`.
5. Set socket file mode to `0o600` (via `umask` guard during single-threaded pre-spawn or `fchmod` / parent `0700` containment; note `0700` parent directory already blocks traversal by all other non-root UIDs).

### 4.2 Kernel-Enforced Peer Authentication

Directory permissions are defense layer 1; kernel peer credential verification on every `accept(2)` is defense layer 2.

| OS | Syscall / Socket Option | Returned Kernel Struct | Authorization Rule | TOCTOU / PID-Reuse Properties |
| :--- | :--- | :--- | :--- | :--- |
| **Linux** | `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len)` | `struct ucred { pid, uid, gid }` | Reject immediately if `ucred.uid != geteuid()` | Credentials are stamped by kernel at `connect(2)` time; immune to post-connect `execve`. |
| **Linux 6.5+** | `getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len)` | `int pidfd` | Use `pidfd` for diagnostics & race-free `pidfd_send_signal` | Reference-counted kernel process handle; completely immune to PID reuse. |
| **macOS / Darwin** | `getpeereid(fd, &euid, &egid)` (wraps `SOL_LOCAL`, `LOCAL_PEERCRED` -> `struct xucred`) | `uid_t euid, gid_t egid` | Reject immediately if `euid != geteuid()` | Kernel-verified effective UID/GID of peer. |
| **macOS / Darwin** | `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len)` | `audit_token_t` | Optional audit/code-sign inspection | Immutable audit token; unlike raw `LOCAL_PEERPID`, resists `POSIX_SPAWN_SETEXEC` PID-swap TOCTOU. |

**Hard rule:** Authenticate on **`peer_uid == geteuid()`**, never on raw PIDs (`LOCAL_PEERPID` / `ucred.pid`). Raw PIDs are strictly for logging and diagnostics.

### 4.3 Multi-Profile & Multi-Account Isolation

- Each profile corresponds to one `(account_id: u64, device_id: u64)` keypair stored in the user's config/state directory (`~/.config/multiplayer_outpost/` or platform app-data dir).
- Derive the runtime subdirectory name from a fixed 8-hex-char (32-bit) or 16-hex-char (64-bit) digest of the canonical `device_id: u64` (e.g., `d<16-hex-of-device_id>` — 17 bytes, strictly integer-keyed per `BLACKBIRD.md` Tenet #6, never keyed by mutable username/handle strings).
- Result: two different `device_id` profiles run completely isolated daemons (`d<idA>/d.sock` and `d<idB>/d.sock`) with zero interference, while all CLI commands and MCP hosts sharing the same `device_id` converge deterministically on the exact same single daemon.

---

## 5. Concrete Reference State Machines for `multiplayer_outpost`

### 5.1 Files Inside `<runtime_base>/mpo/d<device_id_hex>/` (mode `0700`)

| File | Mode | Role | Lifecycle |
| :--- | :--- | :--- | :--- |
| `startup.lock` | `0600` | Serializes spawn and version-skew respawn across concurrent clients | Never unlinked; held via `flock(LOCK_EX)` only during spawn/respawn (~50–500ms) |
| `daemon.lock` | `0600` | Proves exclusive ownership by one live `outpost-daemon` | Never unlinked; held via `flock(LOCK_EX)` for the daemon's entire lifetime |
| `d.sock` | `0600` | Active `AF_UNIX` `SOCK_STREAM` IPC endpoint | Bound to `d.sock.tmp.<nonce>`, `listen()` called, then atomically `rename(2)`d to `d.sock` while holding `daemon.lock` |
| `daemon.log` | `0600` | Rotating stderr diagnostic log for detached daemon | Bounded size (e.g., 2 x 4 MiB); never written to caller's `stdout` |

*(Why bind-temp + `listen()` + `rename()`? Even if a client calls `connect("d.sock")` concurrently with daemon startup, `d.sock` never exists in a bound-but-not-yet-listening state. Clients see either the old socket or a ready listening socket atomically.)*

### 5.2 Connect, Spawn, and Version-Skew Respawn Flow

```
Client (CLI or MCP shim):
1. Verify/open runtime dirfd (0700, O_NOFOLLOW, fstat uid == geteuid()).
2. Fast path: connect("d.sock").
   - If connected:
     a. Send binary Hello { ipc_schema_version, build_digest, client_kind }.
     b. Read HelloAck { ipc_schema_version, build_digest, daemon_epoch, device_id } within HELLO_TIMEOUT (1500ms).
     c. If build_digest == LOCAL_BUILD_DIGEST && ipc_schema_version == LOCAL_SCHEMA:
        -> READY. Proceed with binary RPC / subscription stream.
     d. If mismatch OR HELLO_TIMEOUT:
        -> Fall through to Slow Path (step 3) with reason = VersionMismatch | Unresponsive.
   - If ENOENT or ECONNREFUSED:
     -> Fall through to Slow Path (step 3) with reason = NotRunning.

3. Slow path (serialized):
   a. Open startup.lock via openat(dirfd, ...); acquire flock(LOCK_EX) (bounded wait 10s).
   b. DOUBLE-CHECK: Retry step 2 (connect + Hello).
      - If now matching and healthy -> release startup.lock, return READY.
   c. If mismatch:
      - Send binary DrainAndShutdown { reason: VersionSkew } on existing socket (or if wedged, signal peer via verified pidfd / peer PID).
      - Wait for daemon.lock to become acquirable (poll/blocking flock(LOCK_EX) with DRAIN_GRACE = 2000ms timeout; escalate SIGTERM -> SIGKILL if wedged).
      - Release daemon.lock probe immediately before spawning.
   d. Create an anonymous readiness pipe (pipe_r, pipe_w) where pipe_r is FD_CLOEXEC and pipe_w is inherited by the child.
   e. Spawn `<self_exe> __daemon --device-id <u64> --ready-fd <pipe_w>` with:
      - setsid() in child
      - stdin -> /dev/null, stdout -> /dev/null, stderr -> daemon.log
      - All other FDs FD_CLOEXEC
   f. Daemon child:
      - Acquires flock(LOCK_EX | LOCK_NB) on daemon.lock (exits 0 immediately if another daemon somehow holds it).
      - Binds d.sock.tmp.<rand>, calls listen(backlog=128), atomically rename("d.sock.tmp.<rand>", "d.sock").
      - Writes 1-byte READY status + daemon_epoch to pipe_w and closes pipe_w.
   g. Client reads READY from pipe_r (timeout 3000ms), closes pipe_r, connects to d.sock, completes Hello, releases startup.lock.
```

### 5.3 Idle Auto-Shutdown (OpenSSH `ControlPersist` Pattern)

`outpost-daemon` maintains two atomic counters:
- `connected_clients: usize` (active IPC connections: CLI commands + MCP shims)
- `active_parties: usize` (joined parties where P2P state is live, if configured to persist while in a party, OR strictly tied to `connected_clients > 0` for pure zero-orphan behavior — recommend configurable `idle_timeout`, default `5m` after `connected_clients == 0 && active_parties == 0`, and `30s` if `connected_clients == 0` with no joined party).

**Race-free shutdown invariant:** When the idle timer expires, the daemon MUST acquire `flock(LOCK_EX | LOCK_NB)` on `startup.lock` (or pause `accept()` while checking pending connections):
1. Acquire `startup.lock` (`LOCK_EX | LOCK_NB`). If a client currently holds `startup.lock` (meaning a client is in the middle of connecting/spawning), abort shutdown and reset the idle timer.
2. Re-check `connected_clients == 0` and drain any already-queued socket from `accept(NONBLOCK)`. If a client arrived, release `startup.lock` and resume serving.
3. Unlink `d.sock` while holding both `startup.lock` and `daemon.lock`.
4. Release `startup.lock`.
5. Gracefully close `MP1` WebSocket (`1000 Normal Closure`) and call `iroh::Endpoint::close().await` (bounded timeout 2s).
6. Exit `0` (kernel releases `daemon.lock`).

*Why step 1–3 matters:* Without holding `startup.lock` while unlinking `d.sock`, a client could `connect()` to `d.sock` 1 microsecond before the daemon stops accepting, causing spurious `ECONNRESET` during idle exit.

### 5.4 Oracle-Grade Verification Plan (Per `BLACKBIRD.md` Tiers 4–7)

When `multiplayer_outpost` moves to implementation, verify the daemon lifecycle with error-raising fault-injection tests (never "no crash" demos):
1. **Thundering-herd property test (Tier 5):** Spawn 32 concurrent client processes against an empty runtime dir -> assert `exactly 1` daemon PID ever acquires `daemon.lock`, `exactly 1` `MP1` connect occurs, all 32 clients succeed and observe identical `daemon_epoch`.
2. **`SIGKILL` crash-recovery oracle (Tier 7):** `kill -9` the live daemon mid-session while 2 MCP shims hold active stdio streams -> assert `d.sock` stale node is recovered automatically, both MCP shims emit zero broken JSON-RPC lines on `stdout`, both transparently reconnect to a strictly greater/new `daemon_epoch`, and `outpost` resumes delivering party messages.
3. **Version-skew drain-and-respawn oracle (Tier 7):** Start daemon with synthetic `BUILD_DIGEST = [1; 32]`; connect client with `BUILD_DIGEST = [2; 32]` -> assert old daemon exits cleanly within `DRAIN_GRACE`, new daemon binds `d.sock` with `[2; 32]`, and an attached MCP shim survives without closing `stdout`.
4. **Wedged-daemon watchdog & escalation oracle (Tier 7):** Send `SIGSTOP` to daemon (simulating total event-loop deadlock while holding `flock` and listening socket) -> assert client hits `HELLO_TIMEOUT`, escalates `SIGTERM` -> `SIGKILL`, spawns replacement daemon, and succeeds within 5s.
5. **Symlink & permission attack oracle (Tier 7):** Pre-plant a symlink at runtime dir path and a `0755` directory -> assert both daemon and client fail closed with explicit security error without creating or unlinking any target outside the runtime dir.
6. **Idle shutdown race oracle (Tier 5):** Hammer `connect()` at the exact microsecond of idle-timer expiry across 200 iterations -> assert zero unrecovered `ECONNRESET`/`ENOENT` failures.
7. **macOS `sun_path` length oracle (Tier 7):** Verify under realistic 60-byte `/var/folders/.../T/` prefix that every generated socket path (including `d.sock.tmp.<nonce>`) is strictly `<= 103` bytes.

---

## 6. Verified Primary Sources & References

1. **Bazel Client-Server Architecture & `blaze.cc`:** `bazelbuild/bazel`, `src/main/cpp/blaze.cc` (`install_base`, `server.pid.txt`, `command_port`, `request_cookie`, `response_cookie`, `flock` server locking, version/startup-option skew restart); `bazel.build` Client/Server documentation.
2. **Buck2 Daemon Architecture:** `facebook/buck2`, `app/buck2_client_ctx` (`buckd.info`, `buckd.lifecycle`, `DaemonConstraints`, isolation directories); `buck2.build` daemon documentation.
3. **`tmux` Client/Server Startup Synchronization:** `tmux/tmux`, `client.c` / `server.c` (`ECONNREFUSED`/`ENOENT` trigger -> `flock(LOCK_EX)` on `<socket>.lock` -> double-check `connect()` -> `unlink()` + `bind()` + fork).
4. **OpenSSH Multiplexing:** OpenBSD `ssh_config(5)` (`ControlMaster`, `ControlPath`, `ControlPersist`) and OpenSSH `mux.c` (`muxserver_listen` temporary socket + atomic replacement, idle auto-exit, `-O check`/`-O exit`, parallel-start collision history).
5. **`systemd` Socket Activation & File Descriptor Store:** Lennart Poettering, *"systemd for Developers I / Socket Activation"* (`0pointer.de/blog/projects/socket-activation.html`); `systemd.io/FILE_DESCRIPTOR_STORE/`; `sd_listen_fds(3)`, `sd_pid_notify_with_fds(3)` (`FDSTORE=1`, `FileDescriptorStoreMax=`).
6. **macOS `launchd` Socket Activation & Domains:** Apple Developer Documentation `launch_activate_socket(3)`, `launchd.plist(5)` (`Sockets`, `SockPathName`, `SockPathMode`, `SecureSocketWithKey`, `LimitLoadToSessionType=Background`); `launchctl bootstrap` `gui/<uid>` vs `user/<uid>` SSH session domain behavior.
7. **Chromium Single-Instance Pattern:** Chromium `ProcessSingleton` (`SingletonLock`, `SingletonSocket`, `SingletonCookie` symlink/cookie architecture and hostname/crash lock failure modes).
8. **QUIC / UDP Zero-Downtime Reload Limitations:** Marek Majkowski, *"QUIC restarts, slow problems: udpgrm to the rescue"* (`blog.cloudflare.com`); NGINX `quic_bpf` / `SO_REUSEPORT` reload failure reports (`nginx.org`); HAProxy HTX QUIC termination docs (`haproxy.org`); Envoy hot-restart `SCM_RIGHTS` architecture.
9. **`iroh` Endpoint Lifecycle:** `n0-computer/iroh` (`Endpoint`, home relay, simultaneous UDP hole-punching, path migration, async `Endpoint::close().await` and `conn.close()`).
10. **Model Context Protocol (MCP) Stdio Transport:** `modelcontextprotocol.io` Specification — Transports (`stdio`) & Lifecycle (`initialize`, `notifications/initialized`, strict `stdout` JSON-RPC 2.0 newline-delimited framing, `stderr` logging, `stdin` EOF shutdown).
11. **Unix Syscalls, Locking, Peer Credentials & Runtime Directories:**
    - Linux man-pages (`man7.org`): `unix(7)` (`SO_PEERCRED`, `SO_PEERPIDFD` Linux 6.5+, `SCM_PIDFD`), `flock(2)`, `fcntl(2)` (`F_SETLK` vs `F_OFD_SETLK`), `openat(2)` (`O_NOFOLLOW`, `O_DIRECTORY`), `prctl(2)` (`PR_SET_PDEATHSIG`).
    - Apple Darwin / XNU headers & man-pages: `<sys/un.h>` (`sun_path[104]`, `SOL_LOCAL`, `LOCAL_PEERCRED`, `LOCAL_PEERPID`, `LOCAL_PEERTOKEN`), `getpeereid(3)`, `kqueue(2)` (`EVFILT_PROC`, `NOTE_EXIT`), `confstr(3)` (`_CS_DARWIN_USER_TEMP_DIR`).
    - Freedesktop XDG Base Directory Specification (`XDG_RUNTIME_DIR` `0700` & logout lifecycle) vs macOS `DARWIN_USER_TEMP_DIR` 3-day periodic cleanup.
    - Executable identity & in-place replacement: Linux `/proc/<pid>/exe` `(deleted)` & ELF `.note.gnu.build-id`; Apple Mach-O `LC_UUID`.
    - `rust-analyzer` / `proc-macro-srv` ABI version skew; `git-fsmonitor--daemon` and `gpg-agent` stale dotlock / `.ipc` failure modes.
