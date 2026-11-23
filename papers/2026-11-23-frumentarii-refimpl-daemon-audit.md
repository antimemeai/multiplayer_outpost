# Frumentarii Reference Implementation Audit: Local Daemon Lifecycle & MCP Stdio Transport

- **Date:** 2026-11-23
- **Role:** Frumentarius 2 (Reference Implementation Acquisition & Source Audit)
- **Target:** `multiplayer_outpost` (standalone local Outpost daemon + CLI + MCP stdio sidecar)
- **Corpora Audited:** Five stripped reference snapshots in gitignored `quarantine/` (exact commits and hashes tracked in [QUARANTINE.md](../QUARANTINE.md)).

---

## 1. Executive Synthesis for `multiplayer_outpost`

Auditing five battle-tested local daemons (`tmux`, `buck2`, `tailscale`, `openssh-portable`) and the official Rust MCP SDK (`rmcp`) surfaces a cohesive blueprint for Outpost's local sidecar architecture without guessing or inventing fragile conventions:

1. **Zero Startup Races (Combine `buck2` + `openssh-portable`):**
   - Hold a persistent, **never-unlinked** client lifecycle `flock` file (`outpost.lifecycle`) during kill/start transitions (`buck2` `client.rs:104-161`, `daemon_lifecycle.md:37-39`), avoiding `tmux`'s `unlink(lockfile)` race (`tmux` `server.c:239-243`).
   - Always double-check `connect()` **after** acquiring the lifecycle lock (`tmux` `client.c:149-157`; `buck2` `connect.rs:1341-1354`) so racing clients attach to the winner instead of restarting it.
   - Publish the Unix listening socket atomically by calling `bind()` + `listen()` on a sibling temp path under `umask(0177)`, then `link(tmp, final)` + `unlink(tmp)` (`openssh-portable` `mux.c:1355-1410`). Clients never observe a half-initialized `bind()`-before-`listen()` socket, and `link()` fails with `EEXIST` instead of clobbering a live socket.
2. **Zero Daemon Version Drift (Adopt `buck2`'s Pattern in Binary Format):**
   - Every client connection executes a mandatory handshake / `status` probe returning the daemon's build ID (`version`), binary/protocol version, and startup config digest (`buck2` `connect.rs:213-285`, `858-877`).
   - On mismatch, the client acquires the lifecycle lock, re-checks, sends a graceful shutdown RPC, waits with a bounded grace period, escalates to `SIGKILL` **only after validating `(pid, pid_start_time)`** to defeat PID reuse (`buck2` `daemon.rs:197-212`, `connect.rs:1741-1760`, `kill.rs:142-257`), cleans the daemon dir while preserving the lock file, spawns the new daemon, and re-verifies constraints after reconnect (`buck2` `connect.rs:1564-1571`).
   - Pair this with a dedicated OS watchdog thread in the daemon (`buck2` `daemon.rs:638-696`) that periodically checks its own `daemon.pid` / lifetime lock so a replaced daemon self-exits even if its Tokio runtime is jammed, plus a kernel-held `UnidaemonLifetimeLock` (`buck2` `daemon.rs:782-791`) that vanishes immediately on `SIGKILL` to distinguish a live daemon from stale metadata.
   - *Blackbird Doctrine adaptation:* `buck2` serializes `buckd.info` as JSON (`daemon.rs:170`); `multiplayer_outpost` must write internal daemon state/metadata and local IPC in a **native binary format** (`AGENTS.md` constraint #4), keeping JSON strictly at external MCP stdio and REST boundaries.
3. **Socket Security & Peer Authentication (`tmux` + `tailscale` + `openssh-portable`):**
   - Create the daemon directory `0700` and bind the socket under `umask(0177)` -> `0600` (`tmux` `server.c:126-137`, `openssh-portable` `mux.c:1372-1375`) rather than `tailscale`'s `net.Listen` + post-hoc `os.Chmod` (`tailscale` `safesocket/unixsocket.go:65-69`), which leaves a brief umask race window.
   - Verify OS peer credentials on every accepted Unix socket connection (`SO_PEERCRED` / `LOCAL_PEERCRED` / `getpeereid`, as in `tmux` `proc.c:331-334` and `tailscale` `ipnauth_unix_creds.go:18-31`) requiring `peer_uid == geteuid()` (plus root if desired), rejecting any other UID immediately.
4. **Idle Exit & Clean Teardown (`tmux` + `buck2` + `openssh-portable`):**
   - Track active MCP/CLI client connections and active party sessions (`tmux` `server.c:291-315`); exit cleanly after an idle grace period when zero clients and zero active P2P parties remain (or immediately on explicit `outpost stop` / `SIGTERM` / `SIGINT`), flushing pending writes and unlinking the socket only if it still refers to our own inode/PID.
   - Install a panic hook calling `_exit(1)` (`buck2` `daemon.rs:218-229`) so a panicked background task never leaves a half-dead zombie daemon holding the socket.
5. **MCP Stdio Transport (`rmcp` Audit Verdict: Own Minimal JSON-RPC 2.0 Stdio):**
   - Do **not** adopt `rmcp` as a dependency. Even minimal `server` + `transport-io` pulls `schemars`, `pastey`, `uuid`, `chrono`, `indexmap`, `sha2`, `unicode-*`, `tokio-util/codec`, and ties Outpost to 315 files of rapidly churning draft SEPs (`2026-07-28`, HTTP/SSE, OAuth2/JWT, skills-fs).
   - Build an owned ~400-LOC JSON-RPC 2.0 stdio transport in Outpost that directly incorporates all six hard-won invariants discovered in `rmcp`'s source: cancellation-safe `fill_buf`/`consume` bounded line reading (16 MiB cap), single-writer stdout serialization for concurrent responses + async push notifications, parse-error storm suppression, UTF-8 BOM + `\r\n` normalization, graceful EOF response draining, and the `tokio::io::stdin()` blocking-thread shutdown trap mitigation.

---

## 2. Audit 1: `tmux` (`quarantine/tmux/`, commit `6a32033bfc47a8a860799e661bc2733e78761149`)

### 2.1 Startup Lock via `flock` & Double-Checked `connect()`
- `client_get_lock()` (`quarantine/tmux/client.c:77-101`) opens `<socket_path>.lock` with `O_WRONLY|O_CREAT`, mode `0600` (line 84), then attempts non-blocking `flock(lockfd, LOCK_EX|LOCK_NB)` (line 89).
- If `errno == EAGAIN` (another client is currently starting the server), it blocks in `while (flock(lockfd, LOCK_EX) == -1 && errno == EINTR)` (lines 93-94), closes the fd, and returns `-2` (lines 95-96).
- In `client_connect()` (`quarantine/tmux/client.c:105-181`):
  - Tries `connect()` first without any lock (line 126). Only `ECONNREFUSED` and `ENOENT` trigger auto-start when `CLIENT_STARTSERVER` is set and `CLIENT_NOSTARTSERVER` is clear (lines 128-133).
  - If `client_get_lock()` returns `-2` (waited on a peer), it jumps back to `retry:` (`lines 144-145`) to connect to the server the peer just started.
  - **Critical invariant (lines 149-157):** Even when `client_get_lock()` *succeeds*, `client_connect()` sets `locked = 1` and executes `goto retry;` to attempt `connect()` **one more time while holding the lock**, preventing a race where another client took the lock, started the server, and released the lock between our initial `connect()` and `flock()`.
  - If the second `connect()` still fails under the lock, the client unlinks any stale socket (`unlink(path)`, line 159) and calls `server_start(..., lockfd, lockfile)` (line 164).
- **Subtle flaw to avoid in Outpost:** Inside the newly forked server, `server_start()` executes `unlink(lockfile); close(lockfd);` (`quarantine/tmux/server.c:239-243`). As `buck2` explicitly documents (`daemon_lifecycle.md:37-39`), unlinking a file while another process is waiting on `flock()` allows a third client to `open(..., O_CREAT)` a *brand-new inode* at `<socket_path>.lock` and acquire a concurrent lock on a different inode. Outpost must **never** unlink its lifecycle lock file.

### 2.2 Socket Creation, Permissions & Instant `socketpair()` Handoff
- `proc_fork_and_daemon()` (`quarantine/tmux/proc.c:375-396`) creates a pre-connected `socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair)` (line 380) **before** `fork()` + `daemon(1, 0)` (lines 382-390). The parent (spawning client) immediately returns `pair[0]` as its live client fd—zero polling, zero retry loop needed for the spawning client!
- `server_create_socket()` (`quarantine/tmux/server.c:107-155`):
  - Enforces `sizeof sa.sun_path` bounds check (`ENAMETOOLONG`, lines 116-120).
  - Calls `unlink(sa.sun_path)` (line 121), creates `AF_UNIX`/`SOCK_STREAM` (line 123), brackets `bind()` with `umask(S_IXUSR|S_IRWXG|S_IRWXO)` (`0600`, or `0660` for default socket, lines 126-137) so the socket is born with restrictive permissions and zero chmod race window, calls `listen(fd, 128)` (line 139), and sets non-blocking mode (line 145).
- `server_accept()` (`quarantine/tmux/server.c:379-412`):
  - Handles transient `EAGAIN | EINTR | ECONNABORTED` silently (line 392).
  - Handles `ENFILE | EMFILE` (fd exhaustion) by re-arming accept as a **1-second timer backoff** (`server_add_accept(1)`, lines 394-398, `419-438`) instead of spinning at 100% CPU or crashing.
  - Checks peer UID/GID via `getpeereid(fd, &peer->uid, &peer->gid)` inside `proc_add_peer()` (`quarantine/tmux/proc.c:331-334`) and enforces `server_acl_join(c)` (`quarantine/tmux/server.c:407-411`, `server-acl.c:222-232`).
- `SIGUSR1` (`quarantine/tmux/server.c:456-469`) recreates the listening socket if someone accidentally deleted `/tmp/tmux-*/default`.

### 2.3 `PROTOCOL_VERSION` Check & `MSG_IDENTIFY_*` Handshake
- Every `imsg` frame embeds `PROTOCOL_VERSION` (`8`, defined in `quarantine/tmux/tmux-protocol.h:23`) in `imsg.hdr.peerid` via `imsg_compose(ibuf, type, PROTOCOL_VERSION, ...)` (`quarantine/tmux/proc.c:177`).
- On every inbound frame, `proc_event_cb()` calls `peer_check_version()` (`quarantine/tmux/proc.c:100-103`, `134-148`): if `imsg->hdr.type != MSG_VERSION && (imsg->hdr.peerid & 0xff) != PROTOCOL_VERSION`, the receiver queues a zero-byte `MSG_VERSION` reply carrying its own `PROTOCOL_VERSION` in `hdr.peerid` and sets `PEER_BAD` (draining the write buffer before closing, lines 117-120).
- On the client (`quarantine/tmux/client.c:660-669`), receiving `MSG_VERSION` prints `protocol version mismatch (client %d, server %u)` and exits with status `1`. `tmux` does **not** auto-restart a mismatched server (appropriate for terminal sessions holding user shells, whereas Outpost's stateless sidecar/P2P daemon should follow `buck2`'s auto-restart or clean handoff).
- After connecting, `client_send_identify()` (`quarantine/tmux/client.c:444-489`) streams a batch of typed `MSG_IDENTIFY_*` messages (`LONGFLAGS`, `TERM`, `FEATURES`, `TTYNAME`, `CWD`, `STDIN`/`STDOUT` via `SCM_RIGHTS`, `CLIENTPID`, `ENVIRON`) terminated by `MSG_IDENTIFY_DONE` (line 488). The server refuses to execute client commands until `CLIENT_IDENTIFIED` is set on `MSG_IDENTIFY_DONE` (`quarantine/tmux/server-client.c:3022-3122`; `server.c:282-283`).

### 2.4 Auto-Exit When Last Client/Session Ends
- `server_loop()` (`quarantine/tmux/server.c:272-316`) runs after each `event_loop(EVLOOP_ONCE)` (`proc.c:227-229`). It returns `1` (causing `proc_loop` to exit, kill jobs, and call `exit(0)`, `server.c:262-267`) only when:
  1. `exit-empty` is enabled OR `server_exit` (`SIGINT`/`SIGTERM`) was requested (line 291);
  2. Either `exit-unattached` is enabled OR `sessions` RB-tree is empty (lines 294-297);
  3. No client has an attached `c->session != NULL` (lines 299-302);
  4. `cmd_wait_for_flush()` completes and `clients` tailq is empty (lines 308-310);
  5. No background job is still running (`!job_still_running()`, lines 312-313).

---

## 3. Audit 2: `buck2` (`quarantine/buck2/`, commit `7f0d35cc8e9aa1d308629806693a916a9f7c7631`)

Buck2's Rust daemon lifecycle (`app/buck2_daemon/`, `app/buck2_client_ctx/src/daemon/`, `app/buck2_common/src/daemon_dir.rs`) is the strongest direct blueprint for Outpost.

### 3.1 Daemon Directory Layout & `buckd.info` Durability
- `DaemonDir` (`quarantine/buck2/app/buck2_common/src/daemon_dir.rs:17-45`) centralizes five per-instance files: `buckd.info`, `buckd.pid`, `buckd.stdout`, `buckd.stderr`, `buckd.error.log` (plus `buckd.lifecycle` in `client.rs:135`).
- `DaemonCommand::run()` (`quarantine/buck2/app/buck2_daemon/src/daemon.rs:358-397`):
  1. Creates `buckd.stdout` and `buckd.stderr` **before** binding the listener (lines 364-375) to avoid a race where clients connect before log files exist.
  2. Binds the listener (`init_listener()`, line 375) **before** `daemonize()` (line 377).
  3. Performs a classic POSIX double-fork (`fork` -> `setsid` -> `umask(0o022)` -> `fork` -> `dup2` stdio to `/dev/null` or log files, `quarantine/buck2/app/buck2_daemon/src/daemonize.rs:122-204`), with the launcher parent exiting via `libc::_exit(0)` (line 124).
  4. Writes `buckd.pid` (line 380) and `DaemonProcessInfo` (`pid`, `endpoint`, `version`, `auth_token`, `pid_start_time`) into `buckd.info` and calls `file.sync_all()?` (`write_process_info`, lines 165-175) so clients never read a zero-length/unflushed descriptor after a crash.
  5. Generates a 20-char random per-daemon `auth_token` (`gen_auth_token`, lines 214-216) checked via gRPC metadata interceptor (`connect.rs:366-394`) — essential when using TCP loopback.

### 3.2 Eliminating Version & Config Drift (`DaemonConstraints`)
- The daemon builds `DaemonConstraints` (`quarantine/buck2/app/buck2_client_ctx/src/daemon_constraints.rs:32-47`) containing:
  - `version`: binary build unique ID (`BuckVersion::get_unique_id()`),
  - `user_version`: CI/job isolation identifier,
  - `daemon_id`: fresh UUID assigned by launcher (`connect.rs:502`),
  - `daemon_startup_config`: serialized startup options/settings,
  - `extra`: runtime state flags (`trace_io_enabled`, `materializer_state_identity`).
- Every client upgrades a raw transport channel into `BootstrapBuckdClient` by calling `status()` RPC (`quarantine/buck2/app/buck2_client_ctx/src/daemon/client/connect.rs:858-877`, `1791-1827`) and validating `DaemonConstraintsRequest::satisfied()` (`connect.rs:213-285`), which returns a structured `ConstraintUnsatisfiedReason` (`Version`, `UserVersion`, `StartupConfig`, `BuckSettings`, `RejectDaemonId`, `TraceIo`, `SqliteIdentity`, `connect.rs:123-138`).
- **Guarantee (`daemon_lifecycle.md:129-130`, `144`):** A client **never** uses a daemon whose constraints do not match. Even after spawning a brand-new daemon, the client re-checks `constraints.satisfied(&client.constraints)` (`connect.rs:1564-1571`) and aborts with `BuckDaemonConstraintWrongAfterStart` if it still mismatches.

### 3.3 Eliminating Startup Races & Automatic Stale-Daemon Restart
`establish_connection_inner()` (`quarantine/buck2/app/buck2_client_ctx/src/daemon/client/connect.rs:1312-1580`) executes a clean 2-phase protocol under an overall `StartupDeadline` (default 90s, connect 10s, launcher 30s, `connect.rs:396-435`):
1. **Lock-free fast path (lines 1321-1331, `1622-1642`):** Reads `buckd.info`, connects, fetches `status()`, checks `constraints.satisfied()`. If satisfied, returns immediately with zero locking overhead.
2. **Exclusive `BuckdLifecycleLock` (lines 1335-1339; `quarantine/buck2/app/buck2_client_ctx/src/daemon/client.rs:104-161`):** Opens `buckd.lifecycle` and retries non-blocking `File::try_lock()` every 5–100ms up to deadline (`client.rs:139-148`). The lock file is **never unlinked** during cleanup (`client.rs:180-183`, `daemon_lifecycle.md:37-39`), and is unlocked on `Drop` (`client.rs:207-213`).
3. **Re-probe under lock (lines 1345-1495):** Reloads `buckd.info` and attempts connection again in case a racing client just started a matching daemon.
   - Connected & constraints match -> returns immediately (line 1352).
   - Connected & constraints mismatch -> calls `client.kill_for_constraints_mismatch()` (lines 1412-1417): sends `KillRequest` RPC with 4s grace (`quarantine/buck2/app/buck2_client_ctx/src/daemon/client/kill.rs:39`, `142-200`), polls `kill::process_exists(pid)` every 100ms, and escalates to `hard_kill_impl()` (10s force timeout, `kill.rs:42`, `220-257`) if it refuses to exit.
   - Connect failed -> checks `process_exists(pid)` (`connect.rs:1662-1669`) and calls `hard_kill_until(&buckd_info.info, &deadline.half()?)` (`connect.rs:1459-1465`).
4. **PID-reuse safety (`daemon.rs:197-212`, `connect.rs:1741-1760`, `kill.rs:96`):** Records OS process start time (`pid_start_time`) in `buckd.info`. Before hard-killing an unreachable daemon on transport error, `recorded_daemon_is_running()` verifies both `pid_start_time != 0` and `process_start_time(Some(pid)) == Some(info.pid_start_time)` so a recycled PID belonging to an unrelated process is never killed.
5. **Clean dir + launch + fast-fail reconnect (`connect.rs:1518-1607`):**
   - `clean_daemon_dir(true)` (`client.rs:165-200`) moves old metadata/logs into `prev/` for post-mortem debugging while preserving `buckd.lifecycle`.
   - `start_server_unix()` (`connect.rs:625-793`) spawns the daemon launcher with piped stdout/stderr and waits for the launcher (parent of double-fork) to exit within `buckd_launch_timeout`, killing the launcher on timeout and distinguishing client-inflicted `SIGKILL` from external `SIGKILL` (`connect.rs:763-774`, `811-815`).
   - `connect_to_started_daemon()` (`connect.rs:1586-1607`) retries `load_and_create_channel` every 5–100ms, **short-circuiting immediately if `buckd.error.log` exists** (line 1601) — written by the daemon on any startup error (`daemon.rs:794-800`) — so startup failures surface in milliseconds instead of burning the 90s deadline!

### 3.4 Watchdog Self-Exit, Kernel Lifetime Lock & Panic Hygiene
- **Dedicated OS watchdog thread (`daemon.rs:177-192`, `598-605`, `638-696`):** Runs outside Tokio (`thread_spawn("check-daemon-dirs", ...)`), sleeping `checker_interval_seconds` (default 60s) and verifying that `buckd.pid` still equals `process::id()` and `project_root` metadata is still readable. On mismatch, sends on `hard_shutdown_sender`, breaking the main `select!` (`daemon.rs:607-616`) even if the async worker runtime is wedged.
- **Kernel-enforced lifetime lock (`daemon_lifecycle.md:31-39`, `daemon.rs:782-791`):** Shared daemons acquire `UnidaemonLifetimeLock` and call `std::mem::forget(...)` so the OS holds the exclusive file lock until process death (including `SIGKILL`). Clients probe it (`UnidaemonLifetimeLock::is_held` / `wait_until_free`, `connect.rs:1208-1218`, `1427`) to know with certainty whether a daemon is alive without racing stale PID files.
- **Panic & test self-destruct:** `terminate_on_panic()` (`daemon.rs:218-229`) overrides the panic hook to call `libc::_exit(1)` immediately (preventing half-alive zombies). `maybe_schedule_termination()` (`quarantine/buck2/app/buck2_daemon/src/schedule_termination.rs:33-79`) implements a `BUCK2_TERMINATE_AFTER` hard TTL thread for test isolation. (Note: Buck2's production inactivity timeout lives in `buck2_server`, referenced at `daemon.rs:803-804`, outside our sparse checkout.)

---

## 4. Audit 3: `tailscale` (`quarantine/tailscale/`, commit `66e3d823c754fd4dd87b95785568c76869e5a786`)

### 4.1 Unix Socket Creation, Permissions & Stale-Socket Probing
- `safesocket/unixsocket.go:24-71` implements dial-before-unlink stale socket recovery:
  - Calls `net.Dial("unix", path)` (line 35). If dial succeeds, closes the probe connection and refuses to start with `address already in use` (lines 36-42).
  - If dial fails, calls `os.Remove(path)` (line 43), creates parent dir (`0755`), calls `net.Listen("unix", path)` (line 65), and applies `os.Chmod(path, perm)` (line 69).
  - The authors explicitly warn (`lines 31-34`) that dial-then-remove-then-listen has a TOCTOU race without an external lock/pidfile.
- **Permission split (`safesocket/unixsocket.go:85-91`, `safesocket/safesocket.go:146-161`):** Because `tailscaled` runs as root and permits non-root read-only queries (`tailscale status`), it sets socket mode `0666` on platforms with kernel peer credentials (`linux`, `darwin`, `freebsd`, `solaris`, `illumos`) and `0600` otherwise. For `multiplayer_outpost` (a per-user sidecar), **both** restrictive `0600` (via `umask(0177)` before `bind()`) **and** peercred verification (`uid == geteuid()`) should be enforced as defense-in-depth.
- **Client startup retry (`safesocket/safesocket.go:43-78`):** `ConnectContext()` polls every 250ms for the first 2 seconds (up to 5s if a `tailscaled` process exists), smoothing over `daemon & client` startup races.

### 4.2 Peer Credential Auth & macOS Sandbox Fallback
- `ipn/ipnserver/server.go:533-538` extracts peer credentials once per accepted connection via `http.Server.ConnContext` -> `ipnauth.GetConnIdentity()` (`quarantine/tailscale/ipn/ipnauth/ipnauth_unix_creds.go:18-31`), which calls `peercred.Get(c)` (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` + `LOCAL_PEERPID` on Darwin/BSD) and captures `(UserID, PID)`.
- `ConnIdentity.IsReadonlyConn()` (`quarantine/tailscale/ipn/ipnauth/ipnauth.go:166-208`) grants read/write access when `uid == "0"`, `selfUID != 0 && uid == strconv.Itoa(selfUID)` (same non-root user as daemon, lines 191-194), configured `operatorUID`, or macOS `admin` group (lines 210-225). Unknown/missing peercreds fail closed to read-only (lines 178-186).
- On macOS App Store sandbox where Unix sockets cannot cross app group boundaries, `safesocket/safesocket_darwin.go:107-361` binds `127.0.0.1:0`, generates an 80-bit `crypto/rand` token (`sameUserProofTokenLength = 10` bytes hex, lines 31, 191-205), publishes it via a permission-gated `sameuserproof-*` file (lines 215-268), and validates BasicAuth with `subtle.ConstantTimeCompare` (`ipn/localapi/localapi.go:260-272`).

### 4.3 Local API Defense-in-Depth & Version/Capability Negotiation
- **Anti-CSRF / Anti-DNS-Rebinding (`quarantine/tailscale/ipn/localapi/localapi.go:250-254`, `286-307`):** Rejects any request with a non-empty `Referer` or `Origin` header, or a `Host` header other than `""` / `"local-tailscaled.sock"` (unless loopback + `RequiredPassword` is set). (Irrelevant over raw binary UDS, essential if Outpost ever exposes HTTP.)
- **Version & Capability Headers (`localapi.go:255-256`; `client/local/local.go:170`, `189-191`, `266-273`):**
  - Client sends `Tailscale-Cap: <int>` (monotonic integer capability version) on every request (`local.go:170`).
  - Server echoes `Tailscale-Version: <long-version>` and `Tailscale-Cap: <int>` on every response (`localapi.go:255-256`).
  - Client compares `Tailscale-Version` against `envknob.IPCVersion()` (`local.go:189-191`) and invokes `onVersionMismatch(clientVer, serverVer)` — passive warning rather than Buck2's active restart.

---

## 5. Audit 4: `openssh-portable` (`quarantine/openssh-portable/`, commit `fa4b2a82be7df9768272cfabc2d78e4a12c2b3c0`)

### 5.1 Atomic Socket Bind via Temp Path + `listen()` + `link()`
`muxserver_listen()` (`quarantine/openssh-portable/mux.c:1341-1421`) solves the Unix socket `bind()`-vs-`listen()` race cleanly without external locks:
1. Generates a 16-character alphanumeric suffix with `arc4random_uniform(62)` and constructs `<control_path>.<rand16>` (`mux.c:1361-1370`).
2. Brackets `unix_listener(tmp, 64, 0)` (which executes `socket()` + `bind()` + `listen()`) inside `old_umask = umask(0177); ... umask(old_umask);` (`mux.c:1372-1375`), guaranteeing mode `0600` at creation.
3. Publishes the already-listening socket atomically with `link(tmp, orig_control_path)` (`mux.c:1397-1407`), followed by `unlink(tmp)` (`mux.c:1408`).
   - **Why `link()` instead of `rename()`?** `rename()` silently overwrites an existing live socket, stranding an active master. `link()` atomically fails with `EEXIST` if another master won the race, causing the loser to clean up `tmp` and disable master mode (`mux.c:1398-1406`).
   - **Why temp path before `listen()`?** No client probing `orig_control_path` can ever race into the window between `bind()` and `listen()` and mistakenly conclude the socket is stale (`mux.c:1355-1360`).

### 5.2 `muxclient` Probing, Stale-Socket Recovery & Versioned `HELLO`
- `muxclient()` (`quarantine/openssh-portable/mux.c:2389-2510`):
  - Enforces `sizeof(addr.sun_path)` bounds (`lines 2417-2420`) and calls `connect()` (`line 2425`).
  - On `connect() == -1`: if `errno == ECONNREFUSED && options.control_master != SSHCTL_MASTER_NO`, logs `"Stale control socket ... unlinking"` and calls `unlink(path)` (`lines 2434-2438`), returning `-1` so the caller proceeds to launch a new master.
  - On `connect()` success: sets non-blocking (`line 2447`) and performs `mux_client_hello_exchange(sock, timeout_ms)` (`lines 2453-2457`, `1662-1725`) with a bounded initial timeout.
- **Binary framed handshake (`mux.c:269-314`, `1227-1246`, `1662-1725`):**
  - Both sides exchange 4-byte length-prefixed `MUX_MSG_HELLO` carrying `u32 SSHMUX_VER` plus zero or more `(cstring name, string value)` extension pairs (e.g., `"info"`).
  - Unknown extensions are ignored (`lines 306-309`, `1715-1717`); major version mismatch aborts immediately (`lines 286-290`, `1696-1700`).
  - Master rejects any message before `state->hello_rcvd` (`lines 1263-1267`).
  - Master replies to `MUX_C_ALIVE_CHECK` with `MUX_S_ALIVE` containing its own `getpid()` (`lines 499-513`).

### 5.3 `ControlPersist` Background Detach & Socket Cleanup
- In `ssh_session2()` (`quarantine/openssh-portable/ssh.c:2288-2319`), the process calls `muxserver_listen(ssh)` **before** detaching.
- When `control_persist` is enabled, `control_persist_detach()` (`quarantine/openssh-portable/ssh.c:1864-1902`) calls `fork()`:
  - **Parent** closes `muxserver_sock`, sets `control_master = SSHCTL_MASTER_NO`, and calls `muxclient(options.control_path)` (`lines 1891-1896`) to become a normal foreground client of the newly detached master!
  - **Child** redirects stdio to `/dev/null`, calls `daemon(1, 1)`, sets process title `"%s [mux]"`, and continues the event loop (`lines 1898-1901`).
- On clean exit, `ssh.c:1854-1855` unlinks `options.control_path` if `muxserver_sock != -1`. (Note: the `ControlPersist` idle timer countdown itself resides in `clientloop.c`, which was outside this sparse checkout; the lifecycle pattern is identical to `tmux`'s zero-active-sessions check plus a monotonic idle timer.)

---

## 6. Audit 5: `rmcp` (`quarantine/rmcp/`, commit `86c65108c9b358cfff5954e55502d2ee826baf8c`, v3.11.0)

### 6.1 Dependency & Complexity Footprint vs. Owned Implementation
Auditing `quarantine/rmcp/crates/rmcp/Cargo.toml` (549 lines) and the crate tree (`315` files, `5.1M`):
- **Unconditional dependencies (`Cargo.toml:49-76`, `125-139`):** `serde` (`derive`, `rc`), `serde_json`, `thiserror`, `tokio` (`sync`, `macros`, `rt`, `time`), `futures`, `indexmap`, `tracing`, `tokio-util`, `pin-project-lite`, `percent-encoding`, `unicode-general-category`, `unicode-normalization`, `sha2`, `chrono`, `libc` (unix).
- **Mandatory `server` feature (`Cargo.toml:148`, `196-197`):** Forces `schemars` (JSON Schema codegen + `chrono04`), `pastey`, `uuid`, `tokio/io-util`, `tokio-util/codec`; `default` also pulls `base64` and `rmcp-macros` (proc-macro crate).
- **Protocol/code surface:** `service.rs` (2,011 LOC) + `service/server.rs` (1,428 LOC) + `transport/async_rw.rs` (1,044 LOC) + `transport/io.rs` (390 LOC) carry substantial complexity for Streamable HTTP, SSE stream association (SEP-2260 `OriginatingRequestId` / `InboundStreamOrigin`), multi-round MRTR, experimental `2026-07-28` `server/discover` + `subscriptions/listen`, sampling, elicitation, OAuth2/JWT, and `skills-fs`.
- **Verdict for `multiplayer_outpost`:** Per `AGENTS.md` ("Default to implementing and owning the required machinery"), **do NOT adopt `rmcp`**. Outpost's MCP surface is narrow (stdio JSON-RPC 2.0 server exposing a fixed set of party/board tools, optional resources, and async notifications). An owned implementation takes ~350–500 LOC on top of `serde_json` + `tokio` (which Outpost already needs for REST + `iroh`), avoids proc-macro/schemars/chrono bloat, and isolates Outpost from upstream SDK breaking churn (`rmcp` is already on `3.11.0`).

### 6.2 Six Stdio Invariants to Steal Directly from `rmcp`'s Source
Even without depending on `rmcp`, its battle-tested stdio code reveals six subtle bugs that naive Rust MCP stdio implementations hit in production:

1. **`tokio::io::stdin()` Blocking-Thread Shutdown Hang (`quarantine/rmcp/crates/rmcp/src/transport/io.rs:17-22`, `43-127`):**
   - `tokio::io::stdin()` executes `read(0, ...)` on Tokio's blocking thread pool; cancelling the future does **not** interrupt the blocked OS thread, so Tokio runtime drop hangs waiting for stdin input or EOF (`io.rs:17-19`).
   - On Linux, `stdio_pipes()` (`io.rs:43-117`) solves this by reopening `/proc/self/fd/0` and `/proc/self/fd/1` with `O_NONBLOCK` (`reopen_nonblocking`, lines 92-99), verifying `is_fifo()` (lines 120-127), and wrapping them in `tokio::net::unix::pipe::{Receiver, Sender}` (lines 103-117). Reopening via `/proc/self/fd` creates a **separate open file description**, so `O_NONBLOCK` does not leak onto inherited fds of child processes!
   - On macOS (`io.rs:35-37`, `56-63`), `/proc/self/fd` doesn't exist so `rmcp` falls back to blocking `tokio::io::stdin()`. For Outpost (primary macOS + Linux dev hosts), either: (a) exit naturally on stdin EOF (the standard MCP host shutdown signal), (b) use `kqueue`/non-blocking `AsyncFd` on a `dup()` or dedicated OS reader thread for stdin that does not block Tokio runtime teardown, or (c) call `runtime.shutdown_background()` when exiting due to a signal before stdin closes.

2. **Cancellation-Safe, Memory-Bounded Line Framing (`quarantine/rmcp/crates/rmcp/src/transport/async_rw.rs:51-58`, `121-193`, `272-297`):**
   - Do **not** use `BufReader::read_line()` inside `tokio::select!`: (a) it allocates unboundedly until `\n` (OOM DoS), and (b) clearing a temporary buffer on each `select!` re-poll drops partial lines whenever an outbound write branch wakes first (`async_rw.rs:272-280`, citing issue #947).
   - `rmcp` keeps `line_buf: Vec<u8>` + `discarding: bool` on the transport struct and loops on `fill_buf().await` -> synchronous copy + `consume(n)` with `DEFAULT_MAX_LINE_LENGTH = 16 MiB` (`async_rw.rs:58`, `134-193`), discarding oversized lines cleanly through the next `\n`.

3. **UTF-8 BOM, CRLF, and Parse-Error Storm Suppression (`quarantine/rmcp/crates/rmcp/src/transport/async_rw.rs:301-338`, `385-391`, `437-492`):**
   - Strips trailing `\r` (`without_carriage_return`, line 385) and leading UTF-8 BOM `\xEF\xBB\xBF` (lines 390, 464); skips blank lines (lines 305-308).
   - On `serde_json::Error`: if `e.classify()` is `Syntax | Eof`, logs and **silently ignores** without replying (`lines 317-324`, preventing error echo storms); if `Data | Io` (valid JSON, wrong MCP schema), queues a single `-32600 Invalid Request` error response with `id: null` (`lines 254-271`, `325-331`).
   - Ignores unrecognized `notifications/*` without `id` for forward compatibility (`lines 437-476`).

4. **Serialized Stdout Writes for Concurrent Responses & Async Push Notifications (`quarantine/rmcp/crates/rmcp/src/service.rs:760-796`, `1425-1622`; `async_rw.rs:68`, `234-250`, `613-617`):**
   - `serve_inner()` (`service.rs:1411-1895`) multiplexes inbound requests (`transport.receive()`), handler replies (`sink_proxy_rx`), and unsolicited server-to-client notifications (`peer_rx`, driven by `Peer::send_notification`) in one `tokio::select!` loop.
   - `AsyncRwTransport` serializes all writes through `Arc<Mutex<Option<FramedWrite<...>>>>` (`async_rw.rs:68`, `234-250`), writing compact single-line JSON + `\n` (`lines 613-617`) and flushing. This guarantees async party-chat notifications pushed from the daemon never interleave mid-line with tool responses.
   - Note: Outpost should **never** write logs to stdout (`stderr` or daemon log file only).

5. **Graceful EOF & Cancellation Draining (`quarantine/rmcp/crates/rmcp/src/service.rs:1485-1525`, `1650-1727`, `1829-1886`):**
   - Tracks per-request child `CancellationToken`s in `local_ct_pool` (`lines 1437`, `1650-1652`); inbound `notifications/cancelled` cancels the matching in-flight request token and removes it so late responses are dropped (`lines 1568-1571`, `1720-1726`).
   - When `transport.receive()` returns `None` (stdin EOF -> `QuitReason::Closed`, lines 1485-1492) or `serve_loop_ct` fires (`QuitReason::Cancelled`, lines 1521-1524), `serve_inner` drops `sink_proxy_tx` and drains in-flight responses for **5 seconds** on EOF or **2 seconds** on cancellation (`lines 1834-1875`), then cancels remaining handlers (`line 1879`) and closes the transport (`line 1881`).

6. **Lenient `initialize` / `notifications/initialized` Ordering (`quarantine/rmcp/crates/rmcp/src/service/server.rs:570-735`):**
   - Responds to `ping` before `initialize` (`lines 573-588`).
   - Negotiates `protocolVersion` by echoing the client's requested version if supported, otherwise falling back to the server's newest supported handshake version (`negotiate_protocol_version`, lines 478-509).
   - Enters the main dispatch loop immediately after sending `InitializeResult` without hard-gating on `notifications/initialized` (`lines 721-727`), matching TypeScript SDK interoperability.

---

## 7. Cross-Reference Matrix

| Pattern | `tmux` | `buck2` | `tailscale` | `openssh-portable` | Recommended for `multiplayer_outpost` |
| --- | --- | --- | --- | --- | --- |
| **Startup race lock** | `flock` on `<sock>.lock` (bug: unlinks lock) | `try_lock` on `buckd.lifecycle` (never unlinked) | None (documented TOCTOU) | `link(tmp, final)` fails `EEXIST` | **Never-unlinked `outpost.lifecycle` `flock` + double-checked `connect()`** |
| **Atomic socket publish** | `unlink` + `umask` + `bind` + `listen` (under lock) | TCP/UDS bound before double-fork + `fsync` `buckd.info` | Dial-probe + `Remove` + `Listen` + `Chmod` | `umask(0177)` + `bind` + `listen` on temp, then `link()` + `unlink(tmp)` | **`umask(0177)` + temp `bind`/`listen` + `link()` + `unlink(tmp)` (under lifecycle lock)** |
| **Peer auth** | `getpeereid()` + ACL | Random 20-char `auth_token` in `buckd.info` | `peercred.Get()` (`SO_PEERCRED`/`LOCAL_PEERCRED`) | `0600` socket perms (`umask(0177)`) | **`0700` dir + `0600` socket + `peercred` `uid == geteuid()` check** |
| **Version drift** | `PROTOCOL_VERSION` in `imsg` header -> reject client | `DaemonConstraints` via `status()` RPC -> auto-kill + restart | `Tailscale-Version` header -> client warning callback | `SSHMUX_VER` in `HELLO` -> abort | **Binary `Hello`/`Status` with build ID + protocol ver -> auto-drain/kill & restart (`buck2` model)** |
| **PID-reuse guard** | N/A (never kills server) | `(pid, pid_start_time)` verified before hard kill | N/A | N/A | **Store `(pid, pid_start_time)` in binary daemon info + kernel-held `alive` `flock`** |
| **Stuck/replaced self-exit** | `SIGTERM`/`SIGINT` | Dedicated OS watchdog thread (60s) + panic `_exit(1)` | Context cancel / `Shutdown` event | `MUX_C_TERMINATE` / `quit_pending` | **Dedicated OS watchdog thread + kernel `alive` lock + panic `_exit(1)`** |
| **Idle exit** | Zero sessions & clients & jobs (`server_loop`) | Inactivity timeout + `BUCK2_TERMINATE_AFTER` | Always-on system daemon | `ControlPersist` idle timer | **Zero active clients & zero active parties -> grace timer -> clean exit** |
| **Fast startup failure** | `socketpair` error reply before exit | `buckd.error.log` short-circuits client retry loop | 2–5s dial retry loop | Launcher exit / `ECONNREFUSED` | **Write binary/stderr startup error file + short-circuit client retry loop** |
