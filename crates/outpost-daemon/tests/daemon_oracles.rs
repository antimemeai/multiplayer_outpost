//! All 7 Real-OS Daemon Fault-Injection Oracles (`BLACKBIRD.md` Tiers 4–7).
//!
//! Runs with `harness = false` so the exact same compiled test binary doubles as
//! the single-threaded detached daemon worker (`OUTPOST_ORACLE_DAEMON_MODE=1`)
//! BEFORE any threads or Tokio runtimes are created — guaranteeing 100% safe
//! `setsid()` + double-`fork()` on both macOS and Linux.

use std::collections::HashSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use outpost_core::ipc_wire::{ClientKind, HelloPayload, IPC_SCHEMA_VER, IpcOpcode};
use outpost_core::storage_codec::{DaemonInfoRecord, decode_daemon_info, encode_daemon_info};
use outpost_daemon::{
    CancellationToken, ClientConfig, DAEMON_INFO_NAME, DAEMON_LOCK_NAME, DAEMON_LOG_NAME,
    DaemonClient, DaemonConfig, DaemonError, DaemonExitReason, DaemonHandler, DaemonServer,
    DrainMode, FlockGuard, ForceStopOutcome, READY_FD, SOCKET_FILE_NAME, SpawnCommand, StateLock,
    VerifiedDir, atomic_write_in_dir, current_process_start_token, daemonize_in_child,
    force_stop_daemon, format_device_dir_name, install_daemon_process_hygiene,
    open_or_create_private_dir, process_start_token, publish_unix_listener, read_file_in_dir,
    resolve_runtime_dir, validate_sun_path_budget_with_limit,
};
use tokio::sync::Barrier;

const ENV_DAEMON_MODE: &str = "OUTPOST_ORACLE_DAEMON_MODE";
const ENV_DEVICE_ID: &str = "OUTPOST_ORACLE_DEVICE_ID";
const ENV_RUNTIME_OVERRIDE: &str = "OUTPOST_ORACLE_RUNTIME_OVERRIDE";
const ENV_IDLE_MS: &str = "OUTPOST_ORACLE_IDLE_MS";
const ENV_WATCHDOG_MS: &str = "OUTPOST_ORACLE_WATCHDOG_MS";
const ENV_BUILD_ORDER: &str = "OUTPOST_ORACLE_BUILD_ORDER";
const ENV_BUILD_DIGEST_BYTE: &str = "OUTPOST_ORACLE_BUILD_DIGEST_BYTE";
const ENV_SCHEMA_VER: &str = "OUTPOST_ORACLE_SCHEMA_VER";

struct TestHandler;

impl DaemonHandler for TestHandler {
    async fn handle_request(
        &self,
        _conn_id: u64,
        opcode: IpcOpcode,
        _request_id: u64,
        payload: Vec<u8>,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>, (u16, bool, String)> {
        match opcode {
            IpcOpcode::GetStatus => {
                let mut out = Vec::with_capacity(4 + payload.len());
                out.extend_from_slice(&std::process::id().to_le_bytes());
                out.extend_from_slice(&payload);
                Ok(out)
            }
            IpcOpcode::PartyWait => {
                tokio::select! {
                    _ = cancel.cancelled() => Err((499, false, "cancelled".to_string())),
                    _ = tokio::time::sleep(Duration::from_secs(30)) => Ok(b"timed_out".to_vec()),
                }
            }
            _ => Ok(payload),
        }
    }

    fn active_party_id(&self) -> u64 {
        0
    }
}

fn run_daemon_worker() -> ! {
    // 1. Single-threaded double-fork BEFORE any Tokio threads exist!
    if let Err(err) = daemonize_in_child() {
        eprintln!("daemonize_in_child failed: {err}");
        unsafe {
            libc::_exit(10);
        }
    }
    // 2. Single-threaded process hygiene (umask 0077, SIGPIPE ignore, lock-free panic hook).
    install_daemon_process_hygiene(libc::STDERR_FILENO);

    let device_id: u64 = std::env::var(ENV_DEVICE_ID)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let runtime_override = std::env::var(ENV_RUNTIME_OVERRIDE).ok().map(PathBuf::from);
    let idle_ms: u64 = std::env::var(ENV_IDLE_MS)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30_000);
    let watchdog_ms: u64 = std::env::var(ENV_WATCHDOG_MS)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let build_order: u64 = std::env::var(ENV_BUILD_ORDER)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let digest_byte: u8 = std::env::var(ENV_BUILD_DIGEST_BYTE)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xAA);
    let schema_ver: u32 = std::env::var(ENV_SCHEMA_VER)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(IPC_SCHEMA_VER);

    let mut cfg = DaemonConfig::new(device_id, build_order, [digest_byte; 32]);
    cfg.runtime_dir_override = runtime_override;
    cfg.ipc_schema_ver = schema_ver;
    cfg.idle_timeout = if idle_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(idle_ms))
    };
    cfg.watchdog_interval = Duration::from_millis(watchdog_ms);
    cfg.ready_fd = Some(READY_FD);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("tokio runtime build failed: {err}");
            unsafe {
                libc::_exit(11);
            }
        }
    };

    let res = rt.block_on(DaemonServer::run(cfg, Arc::new(TestHandler)));
    drop(rt);
    match res {
        Ok(_) => std::process::exit(0),
        Err(err) => {
            eprintln!("daemon server error: {err}");
            std::process::exit(12);
        }
    }
}

#[derive(Clone)]
struct WorkerSpec {
    device_id: u64,
    runtime_base: PathBuf,
    idle_ms: u64,
    watchdog_ms: u64,
    build_order: u64,
    digest_byte: u8,
    schema_ver: u32,
}

impl WorkerSpec {
    fn new(device_id: u64, runtime_base: PathBuf) -> Self {
        Self {
            device_id,
            runtime_base,
            idle_ms: 30_000,
            watchdog_ms: 250,
            build_order: 100,
            digest_byte: 0xAA,
            schema_ver: IPC_SCHEMA_VER,
        }
    }

    fn spawn_command(&self) -> SpawnCommand {
        let exe = std::env::current_exe().expect("current_exe");
        SpawnCommand {
            exe_path: exe,
            args: Vec::new(),
            env: vec![
                (ENV_DAEMON_MODE.to_string(), "1".to_string()),
                (ENV_DEVICE_ID.to_string(), self.device_id.to_string()),
                (
                    ENV_RUNTIME_OVERRIDE.to_string(),
                    self.runtime_base.to_string_lossy().into_owned(),
                ),
                (ENV_IDLE_MS.to_string(), self.idle_ms.to_string()),
                (ENV_WATCHDOG_MS.to_string(), self.watchdog_ms.to_string()),
                (ENV_BUILD_ORDER.to_string(), self.build_order.to_string()),
                (
                    ENV_BUILD_DIGEST_BYTE.to_string(),
                    self.digest_byte.to_string(),
                ),
                (ENV_SCHEMA_VER.to_string(), self.schema_ver.to_string()),
            ],
        }
    }

    fn client_config(
        &self,
        client_kind: ClientKind,
        schema_ver: u32,
        build_order: u64,
        digest_byte: u8,
        read_only_cli: bool,
    ) -> ClientConfig {
        let mut cfg = ClientConfig::new(
            self.device_id,
            HelloPayload {
                ipc_schema_ver: schema_ver,
                build_order,
                build_digest: [digest_byte; 32],
                client_kind,
                client_pid: std::process::id(),
            },
        );
        cfg.runtime_dir_override = Some(self.runtime_base.clone());
        cfg.read_only_cli = read_only_cli;
        cfg.spawn_command = Some(self.spawn_command());
        cfg
    }
}

fn make_short_tempdir() -> tempfile::TempDir {
    // Keep temp paths well within macOS 103-byte sun_path budget.
    tempfile::Builder::new()
        .prefix("mpo_")
        .tempdir()
        .expect("create tempdir")
}

async fn wait_until_daemon_exits(dir: &VerifiedDir, pid: u32, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        let lock_free = FlockGuard::probe_lock_free(dir, DAEMON_LOCK_NAME).unwrap_or(false);
        let proc_gone = process_start_token(pid).ok().flatten().is_none();
        if lock_free && proc_gone {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn shutdown_cleanly(client: &mut DaemonClient, dir: &VerifiedDir) {
    let pid = client.ack().daemon_pid;
    let _ = client.send_drain_and_shutdown(DrainMode::StopDetach).await;
    assert!(
        wait_until_daemon_exits(dir, pid, Duration::from_secs(5)).await,
        "daemon pid {pid} did not exit cleanly after DrainAndShutdown"
    );
}

/// Oracle 1: 32-way concurrent thundering herd on empty runtime dir ->
/// exactly 1 daemon PID acquires `daemon.lock`, all 32 clients succeed and observe
/// identical `daemon_epoch` and `daemon_pid`.
async fn oracle_1_thundering_herd_32_way() {
    let tmp = make_short_tempdir();
    let device_id = 1001;
    let spec = WorkerSpec::new(device_id, tmp.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(32));

    let mut handles = Vec::with_capacity(32);
    for idx in 0u32..32 {
        let b = Arc::clone(&barrier);
        let cfg = spec.client_config(ClientKind::Mcp, IPC_SCHEMA_VER, 100, 0xAA, false);
        handles.push(tokio::spawn(async move {
            b.wait().await;
            let mut client = DaemonClient::connect_or_spawn(&cfg)
                .await
                .unwrap_or_else(|e| panic!("client {idx} failed thundering herd: {e}"));
            let ack = client.ack().clone();
            assert_eq!(client.peer_pid(), ack.daemon_pid);
            let tag = idx.to_le_bytes().to_vec();
            let resp = client
                .request(IpcOpcode::GetStatus, tag.clone())
                .await
                .unwrap_or_else(|e| panic!("client {idx} GetStatus failed: {e}"));
            assert_eq!(resp.len(), 8);
            assert_eq!(&resp[0..4], &ack.daemon_pid.to_le_bytes());
            assert_eq!(&resp[4..8], &tag[..]);
            (ack.daemon_pid, ack.daemon_epoch, client)
        }));
    }

    let mut pids = HashSet::new();
    let mut epochs = HashSet::new();
    let mut clients = Vec::with_capacity(32);
    for h in handles {
        let (pid, epoch, client) = h.await.expect("client task panicked");
        pids.insert(pid);
        epochs.insert(epoch);
        clients.push(client);
    }

    assert_eq!(pids.len(), 1, "expected exactly 1 daemon PID, got {pids:?}");
    assert_eq!(
        epochs.len(),
        1,
        "expected exactly 1 daemon_epoch across all 32 clients, got {epochs:?}"
    );
    let only_pid = *pids.iter().next().expect("pid");
    let only_epoch = *epochs.iter().next().expect("epoch");

    let rdir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve dir");
    let vdir = open_or_create_private_dir(&rdir_path).expect("open verified dir");
    let raw_info = read_file_in_dir(vdir.as_raw_fd(), DAEMON_INFO_NAME, 8192)
        .expect("read daemon.info")
        .expect("daemon.info exists");
    let info = decode_daemon_info(&raw_info).expect("decode daemon.info");
    assert_eq!(info.pid, only_pid);
    assert_eq!(info.daemon_epoch, only_epoch);
    assert_eq!(
        process_start_token(only_pid).expect("start token"),
        Some(info.native_start_token)
    );

    // Drop 31 clients and cleanly drain with the last one.
    let mut last = clients.pop().expect("at least one client");
    drop(clients);
    shutdown_cleanly(&mut last, &vdir).await;
}

/// Oracle 2: A/B/A mixed-build coexistence ->
/// - Client with different `build_digest` at same `IPC_SCHEMA_VER` coexists (zero kills!).
/// - `mcp` client with mismatched schema returns `IncompatibleSchema` without killing daemon!
/// - Read-only CLI with mismatched schema returns `IncompatibleSchema` without killing daemon!
async fn oracle_2_aba_mixed_build_coexistence() {
    let tmp = make_short_tempdir();
    let device_id = 1002;
    let spec = WorkerSpec::new(device_id, tmp.path().to_path_buf());
    let rdir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve dir");

    // Boot Daemon A (schema=1, build_order=100, digest=0xAA).
    let cfg_a = spec.client_config(ClientKind::Cli, IPC_SCHEMA_VER, 100, 0xAA, false);
    let client_a = DaemonClient::connect_or_spawn(&cfg_a)
        .await
        .expect("boot daemon A");
    let pid_a = client_a.ack().daemon_pid;
    let epoch_a = client_a.ack().daemon_epoch;
    assert!(!client_a.upgrade_available());
    drop(client_a);

    // Client B: different build_digest (0xBB) and build_order (200), SAME schema=1 -> MUST coexist!
    let cfg_b = spec.client_config(ClientKind::Cli, IPC_SCHEMA_VER, 200, 0xBB, false);
    let client_b = DaemonClient::connect_or_spawn(&cfg_b)
        .await
        .expect("mixed-build client B must coexist");
    assert_eq!(client_b.ack().daemon_pid, pid_a, "daemon A was killed!");
    assert_eq!(client_b.ack().daemon_epoch, epoch_a, "daemon A respawned!");
    assert!(
        client_b.upgrade_available(),
        "upgrade_available should report build difference diagnostically"
    );
    drop(client_b);

    // MCP client with incompatible schema=2 -> MUST fail with IncompatibleSchema and NOT kill daemon A!
    let cfg_mcp_mismatch = spec.client_config(ClientKind::Mcp, IPC_SCHEMA_VER + 1, 300, 0xCC, false);
    match DaemonClient::connect_or_spawn(&cfg_mcp_mismatch).await {
        Err(DaemonError::IncompatibleSchema {
            local_schema,
            daemon_schema,
            ..
        }) => {
            assert_eq!(local_schema, IPC_SCHEMA_VER + 1);
            assert_eq!(daemon_schema, IPC_SCHEMA_VER);
        }
        other => panic!("expected IncompatibleSchema for MCP mismatch, got {other:?}"),
    }

    // Read-only CLI with incompatible schema=2 -> MUST also NOT kill daemon A!
    let cfg_ro_mismatch = spec.client_config(ClientKind::Cli, IPC_SCHEMA_VER + 1, 300, 0xCC, true);
    match DaemonClient::connect_or_spawn(&cfg_ro_mismatch).await {
        Err(DaemonError::IncompatibleSchema { .. }) => {}
        other => panic!("expected IncompatibleSchema for read-only CLI, got {other:?}"),
    }

    // Confirm Daemon A is still untouched with exact same (pid_a, epoch_a)!
    let mut verify_a = DaemonClient::connect_or_spawn(&cfg_a)
        .await
        .expect("daemon A must still be alive");
    assert_eq!(verify_a.ack().daemon_pid, pid_a);
    assert_eq!(verify_a.ack().daemon_epoch, epoch_a);

    let vdir = open_or_create_private_dir(&rdir_path).expect("open dir");
    shutdown_cleanly(&mut verify_a, &vdir).await;
}

/// Oracle 3: `SIGKILL` crash recovery ->
/// `kill -9` live daemon -> stale `d.sock` remains on disk -> next client auto-recovers
/// and spawns fresh daemon with new `daemon_epoch` and `daemon_pid`.
async fn oracle_3_sigkill_crash_recovery() {
    let tmp = make_short_tempdir();
    let device_id = 1003;
    let spec = WorkerSpec::new(device_id, tmp.path().to_path_buf());
    let cfg = spec.client_config(ClientKind::Cli, IPC_SCHEMA_VER, 100, 0xAA, false);

    let mut c1 = DaemonClient::connect_or_spawn(&cfg)
        .await
        .expect("boot daemon 1");
    let pid1 = c1.ack().daemon_pid;
    let epoch1 = c1.ack().daemon_epoch;
    let _ = c1
        .request(IpcOpcode::GetStatus, b"alive1".to_vec())
        .await
        .expect("status 1");
    drop(c1);

    let rdir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve dir");
    let vdir = open_or_create_private_dir(&rdir_path).expect("open dir");
    assert!(
        vdir.stat_entry(SOCKET_FILE_NAME).expect("stat").is_some(),
        "d.sock must exist before SIGKILL"
    );

    // Hard crash daemon 1 with SIGKILL!
    let rc = unsafe { libc::kill(pid1 as libc::pid_t, libc::SIGKILL) };
    assert_eq!(rc, 0, "SIGKILL failed: {}", io::Error::last_os_error());
    assert!(
        wait_until_daemon_exits(&vdir, pid1, Duration::from_secs(3)).await,
        "daemon 1 did not die after SIGKILL"
    );
    // Stale socket file is still on disk because SIGKILL bypassed cleanup!
    assert!(
        vdir.stat_entry(SOCKET_FILE_NAME).expect("stat").is_some(),
        "stale d.sock should still exist after SIGKILL"
    );

    // Next client MUST recover automatically and spawn a fresh daemon!
    let mut c2 = DaemonClient::connect_or_spawn(&cfg)
        .await
        .expect("auto-recover after SIGKILL");
    let pid2 = c2.ack().daemon_pid;
    let epoch2 = c2.ack().daemon_epoch;
    assert_ne!(pid2, pid1, "must spawn fresh PID");
    assert_ne!(epoch2, epoch1, "must observe new daemon_epoch");
    let resp = c2
        .request(IpcOpcode::GetStatus, b"alive2".to_vec())
        .await
        .expect("status 2");
    assert_eq!(&resp[4..], b"alive2");

    shutdown_cleanly(&mut c2, &vdir).await;
}

/// Oracle 4: Inode self-fence ->
/// Unlink `d.sock` while daemon is running -> OS watchdog detects `(dev, ino)` mismatch
/// and daemon transitions to `Draining` and exits cleanly!
async fn oracle_4_inode_self_fence() {
    let tmp = make_short_tempdir();
    let device_id = 1004;
    let mut spec = WorkerSpec::new(device_id, tmp.path().to_path_buf());
    spec.watchdog_ms = 100;
    spec.idle_ms = 60_000;
    let cfg = spec.client_config(ClientKind::Cli, IPC_SCHEMA_VER, 100, 0xAA, false);

    let client = DaemonClient::connect_or_spawn(&cfg)
        .await
        .expect("boot daemon for inode self-fence");
    let pid = client.ack().daemon_pid;
    drop(client);

    let rdir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve dir");
    let vdir = open_or_create_private_dir(&rdir_path).expect("open dir");

    // Simulate macOS dirhelper / tmpfiles.d removing d.sock out from under the daemon!
    std::fs::remove_file(rdir_path.join(SOCKET_FILE_NAME)).expect("unlink d.sock");

    assert!(
        wait_until_daemon_exits(&vdir, pid, Duration::from_secs(3)).await,
        "watchdog failed to self-fence and exit after d.sock was unlinked"
    );
}

/// Oracle 5: Idle-exit vs `connect()` race hammer ->
/// 40 rapid cycles hammering `connect_or_spawn()` right around a short 120ms idle timeout:
/// ZERO unrecovered `ECONNRESET`/`ENOENT` failures, and multiple `daemon_epoch`s observed.
async fn oracle_5_idle_exit_connect_race_hammer() {
    let tmp = make_short_tempdir();
    let device_id = 1005;
    let mut spec = WorkerSpec::new(device_id, tmp.path().to_path_buf());
    spec.idle_ms = 120;
    spec.watchdog_ms = 100;

    let mut observed_epochs = HashSet::new();
    let cycles = 40usize;
    for cycle in 0..cycles {
        // Sweep delays right across the 120ms idle-exit race window (95ms..155ms).
        let delay_ms = 95 + ((cycle as u64 * 17) % 65);
        if cycle > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let cfg1 = spec.client_config(ClientKind::Mcp, IPC_SCHEMA_VER, 100, 0xAA, false);
        let cfg2 = spec.client_config(ClientKind::Cli, IPC_SCHEMA_VER, 100, 0xAA, false);
        let (r1, r2) = tokio::join!(
            async {
                let mut c = DaemonClient::connect_or_spawn(&cfg1).await?;
                let epoch = c.ack().daemon_epoch;
                let resp = c.request(IpcOpcode::GetStatus, b"r1".to_vec()).await?;
                assert_eq!(&resp[4..], b"r1");
                Ok::<u64, DaemonError>(epoch)
            },
            async {
                let mut c = DaemonClient::connect_or_spawn(&cfg2).await?;
                let epoch = c.ack().daemon_epoch;
                let resp = c.request(IpcOpcode::GetStatus, b"r2".to_vec()).await?;
                assert_eq!(&resp[4..], b"r2");
                Ok::<u64, DaemonError>(epoch)
            }
        );

        let e1 = r1.unwrap_or_else(|e| panic!("cycle {cycle} client 1 failed: {e}"));
        let e2 = r2.unwrap_or_else(|e| panic!("cycle {cycle} client 2 failed: {e}"));
        observed_epochs.insert(e1);
        observed_epochs.insert(e2);
    }

    assert!(
        observed_epochs.len() >= 2,
        "expected idle auto-exit to trigger across 40 race cycles (got only {} epoch(s))",
        observed_epochs.len()
    );

    // Wait for final daemon to idle-exit on its own!
    let rdir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve dir");
    let vdir = open_or_create_private_dir(&rdir_path).expect("open dir");
    let start = Instant::now();
    loop {
        if FlockGuard::probe_lock_free(&vdir, DAEMON_LOCK_NAME).expect("probe lock") {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "final daemon failed to idle-exit after race hammer"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Oracle 6: Symlink & `0755` dir attack + macOS 60-byte `sun_path` budget +
/// real APFS/Linux atomic `link()` socket publish + atomic `StateLock` / `atomic_write_in_dir`.
async fn oracle_6_security_sun_path_and_atomic_publish() {
    let tmp = make_short_tempdir();
    let device_id = 1006;
    let leaf = format_device_dir_name(device_id).expect("leaf");

    // 6a. Leaf symlink attack: must fail closed without touching victim!
    let victim = tmp.path().join("victim_dir");
    std::fs::create_dir(&victim).expect("mkdir victim");
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).expect("chmod 0700");

    let attack_leaf_base = tmp.path().join("atk_leaf");
    std::fs::create_dir(&attack_leaf_base).expect("mkdir atk_leaf");
    std::fs::set_permissions(&attack_leaf_base, std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700");
    let leaf_symlink = attack_leaf_base.join(&leaf);
    std::os::unix::fs::symlink(&victim, &leaf_symlink).expect("symlink leaf");

    match open_or_create_private_dir(&leaf_symlink) {
        Err(DaemonError::SymlinkRejected { .. }) => {}
        other => panic!("expected SymlinkRejected on leaf symlink, got {other:?}"),
    }
    assert!(
        std::fs::read_dir(&victim).expect("read victim").next().is_none(),
        "victim directory must remain completely untouched"
    );

    // 6b. Parent symlink attack: must fail closed!
    let parent_symlink = tmp.path().join("atk_parent");
    std::os::unix::fs::symlink(&victim, &parent_symlink).expect("symlink parent");
    match open_or_create_private_dir(&parent_symlink.join(&leaf)) {
        Err(DaemonError::SymlinkRejected { .. }) => {}
        other => panic!("expected SymlinkRejected on parent symlink, got {other:?}"),
    }

    // 6c. Overly broad `0755` directory attack: must fail closed!
    let broad_dir = tmp.path().join("broad_0755").join(&leaf);
    std::fs::create_dir_all(&broad_dir).expect("mkdir broad");
    std::fs::set_permissions(&broad_dir, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 0755");
    match open_or_create_private_dir(&broad_dir) {
        Err(DaemonError::InsecureDirectory { .. }) => {}
        other => panic!("expected InsecureDirectory on 0755 dir, got {other:?}"),
    }

    // 6d. macOS 60-byte prefix + `mpo/d<13hex>/t.<8hex>` <= 103 B budget!
    // Exact 60-byte Darwin prefix:
    let macos_60b_prefix = "/var/folders/ab/cdefghijklmnopqrstuvwxyz0123456789abcdef/T";
    assert_eq!(macos_60b_prefix.len(), 58);
    let macos_exact_60b = format!("{macos_60b_prefix}01");
    assert_eq!(macos_exact_60b.len(), 60);
    let darwin_dir = PathBuf::from(&macos_exact_60b).join("mpo").join(&leaf);
    let temp_sample = darwin_dir.join("t.00000000");
    assert!(
        temp_sample.to_string_lossy().len() <= 103,
        "expected <= 103 bytes, got {}",
        temp_sample.to_string_lossy().len()
    );
    validate_sun_path_budget_with_limit(&darwin_dir, 103).expect("60B prefix must fit 103B");

    // 104-byte temp path MUST be rejected under macOS 103B budget!
    let too_long_dir = PathBuf::from(format!("/{}", "a".repeat(92)));
    assert_eq!(too_long_dir.join("t.00000000").to_string_lossy().len(), 104);
    match validate_sun_path_budget_with_limit(&too_long_dir, 103) {
        Err(DaemonError::SunPathTooLong { len: 104, max: 103, .. }) => {}
        other => panic!("expected SunPathTooLong for 104B path, got {other:?}"),
    }

    // Default OS runtime dir never uses /tmp!
    let default_dir = resolve_runtime_dir(device_id, None).expect("resolve default OS runtime dir");
    assert!(
        !default_dir.starts_with(Path::new("/tmp")),
        "default runtime dir must NEVER be under /tmp: {}",
        default_dir.display()
    );

    // 6e. Real APFS/Linux atomic `link()` socket publish + 0600 mode + connect + no `t.*` leftovers.
    let pub_dir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve pub dir");
    let vdir = open_or_create_private_dir(&pub_dir_path).expect("open pub dir");
    // Plant a stale `t.deadbeef` file to verify cleanup under daemon.lock.
    atomic_write_in_dir(vdir.as_raw_fd(), "t.deadbeef", b"stale").expect("plant stale temp");
    let dlock = FlockGuard::try_lock_exclusive(&vdir, DAEMON_LOCK_NAME)
        .expect("lock")
        .expect("acquire daemon.lock");
    let published = publish_unix_listener(&vdir, &dlock).expect("publish unix listener");
    assert!(
        published.used_atomic_link,
        "expected atomic linkat(t.<8hex>, d.sock) to succeed on APFS/Linux"
    );
    let sock_st = vdir
        .stat_entry(SOCKET_FILE_NAME)
        .expect("stat d.sock")
        .expect("d.sock exists");
    assert_eq!(sock_st.st_mode & 0o777, 0o600, "d.sock must be 0600");
    assert!(
        vdir.stat_entry("t.deadbeef").expect("stat stale").is_none(),
        "stale t.* files must be cleaned"
    );
    // Verify a real connect succeeds!
    let _stream = StdUnixStream::connect(vdir.path().join(SOCKET_FILE_NAME))
        .expect("connect to atomically published d.sock");
    drop(published);
    drop(dlock);

    // 6f. Verify `StateLock` + `atomic_write_in_dir` + `read_file_in_dir`.
    let state_dir_path = tmp.path().join("state_0700");
    let sdir = open_or_create_private_dir(&state_dir_path).expect("open state dir");
    let slock = StateLock::lock(&sdir, Duration::from_secs(2)).expect("acquire StateLock");
    assert!(
        StateLock::try_lock(&sdir).expect("contended try_lock").is_none(),
        "StateLock must be exclusive"
    );
    atomic_write_in_dir(sdir.as_raw_fd(), "state.bin", b"payload-v1").expect("atomic write 1");
    atomic_write_in_dir(sdir.as_raw_fd(), "state.bin", b"payload-v2").expect("atomic write 2");
    let loaded = read_file_in_dir(sdir.as_raw_fd(), "state.bin", 1024)
        .expect("read state.bin")
        .expect("state.bin exists");
    assert_eq!(loaded, b"payload-v2");
    drop(slock);
}

/// Oracle 7: Zero leaked non-`CLOEXEC` FDs + zero zombies + `SIGSTOP` verified `force_stop_daemon`
/// + recycled-PID start-token refusal + live IPC `Cancel`.
async fn oracle_7_no_fd_leak_no_zombies_and_sigstop_force_stop() {
    let tmp = make_short_tempdir();
    let device_id = 1007;
    let spec = WorkerSpec::new(device_id, tmp.path().to_path_buf());
    let cfg = spec.client_config(ClientKind::Mcp, IPC_SCHEMA_VER, 100, 0xAA, false);

    // 7a. Create a pipe with FD_CLOEXEC EXPLICITLY CLEARED on the write end!
    let mut fds = [-1 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let leak_r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let leak_w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    assert_eq!(
        unsafe { libc::fcntl(leak_w.as_raw_fd(), libc::F_SETFD, 0) },
        0,
        "clearing FD_CLOEXEC failed"
    );

    // Spawn daemon while parent holds the non-CLOEXEC `leak_w` FD open!
    let client = DaemonClient::connect_or_spawn(&cfg)
        .await
        .expect("spawn daemon with extra non-CLOEXEC pipe open");
    let daemon_pid = client.ack().daemon_pid;

    // Close parent's write end. If the daemon inherited `leak_w`, `leak_r` will NOT hit EOF!
    drop(leak_w);

    let mut pfd = libc::pollfd {
        fd: leak_r.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let prc = unsafe { libc::poll(&mut pfd, 1, 500) };
    assert!(
        prc > 0,
        "non-CLOEXEC pipe did NOT hit EOF immediately — daemon leaked host FD!"
    );
    let mut byte = [0u8; 1];
    let n = unsafe { libc::read(leak_r.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
    assert_eq!(
        n, 0,
        "expected immediate EOF (0 bytes) on leak_r, proving zero leaked FDs"
    );
    drop(leak_r);

    // 7b. Verify ZERO zombies from launcher double-fork!
    let mut wstatus: libc::c_int = 0;
    let wrc = unsafe { libc::waitpid(-1, &mut wstatus, libc::WNOHANG) };
    assert!(
        wrc <= 0,
        "found unreaped zombie child PID {wrc} after detached spawn!"
    );

    // Quick verification of IPC Cancel on in-flight PartyWait while daemon is live.
    let (mut stream, _ack, _upg, _pid) = client.into_parts();
    outpost_daemon::write_ipc_frame(
        &mut stream,
        &outpost_core::ipc_wire::IpcFrame {
            opcode: IpcOpcode::PartyWait,
            request_id: 77,
            payload: Vec::new(),
        },
    )
    .await
    .expect("write PartyWait");
    outpost_daemon::write_ipc_frame(
        &mut stream,
        &outpost_core::ipc_wire::IpcFrame {
            opcode: IpcOpcode::Cancel,
            request_id: 78,
            payload: outpost_daemon::encode_cancel_payload(77).expect("encode cancel"),
        },
    )
    .await
    .expect("write Cancel");
    let cancel_reply = tokio::time::timeout(
        Duration::from_secs(2),
        outpost_daemon::read_ipc_frame(&mut stream),
    )
    .await
    .expect("PartyWait should cancel promptly")
    .expect("read reply")
    .expect("frame present");
    assert_eq!(cancel_reply.opcode, IpcOpcode::Error);
    assert_eq!(cancel_reply.request_id, 77);
    let (code, _retryable, msg) =
        outpost_daemon::decode_error_payload(&cancel_reply.payload).expect("decode error");
    assert_eq!(code, 499);
    assert_eq!(msg, "cancelled");
    drop(stream);

    let rdir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve dir");
    let vdir = open_or_create_private_dir(&rdir_path).expect("open dir");

    // 7c. Freeze the live daemon with `SIGSTOP`!
    assert_eq!(
        unsafe { libc::kill(daemon_pid as libc::pid_t, libc::SIGSTOP) },
        0,
        "SIGSTOP failed"
    );

    // Verify a client hitting Hello timeout does NOT auto-kill the stopped daemon!
    let mut wedged_cfg = cfg.clone();
    wedged_cfg.hello_timeout = Duration::from_millis(200);
    wedged_cfg.exit_wait_timeout = Duration::from_millis(300);
    wedged_cfg.slow_path_timeout = Duration::from_secs(2);
    match DaemonClient::connect_or_spawn(&wedged_cfg).await {
        Err(DaemonError::DaemonWedged { .. }) => {}
        other => panic!("expected DaemonWedged against SIGSTOPped daemon, got {other:?}"),
    }
    assert!(
        process_start_token(daemon_pid).expect("token").is_some(),
        "connect_or_spawn must NEVER kill a SIGSTOPped daemon automatically!"
    );

    // 7d. Verify recycled-PID protection: if daemon.info has a bogus start_token for our own PID,
    // `force_stop_daemon` MUST refuse without signaling our process!
    let bogus_dir = open_or_create_private_dir(&tmp.path().join("bogus_recycled")).expect("dir");
    let _held_lock = FlockGuard::try_lock_exclusive(&bogus_dir, DAEMON_LOCK_NAME)
        .expect("lock")
        .expect("acquire");
    let my_pid = std::process::id();
    let my_token = current_process_start_token().expect("my start token");
    let bogus_info = DaemonInfoRecord {
        pid: my_pid,
        native_start_token: my_token.wrapping_add(999_999),
        daemon_epoch: 42,
        ipc_schema_ver: IPC_SCHEMA_VER,
        build_order: 1,
        build_digest: [0x11; 32],
        device_id,
        exe_path: "test".to_string(),
    };
    atomic_write_in_dir(
        bogus_dir.as_raw_fd(),
        DAEMON_INFO_NAME,
        &encode_daemon_info(&bogus_info).expect("encode"),
    )
    .expect("write bogus info");
    match force_stop_daemon(
        &bogus_dir,
        device_id,
        Duration::from_millis(100),
        Duration::from_millis(100),
    ) {
        Err(DaemonError::ProcessVerificationFailed { pid, .. }) => assert_eq!(pid, my_pid),
        other => panic!("expected ProcessVerificationFailed on recycled PID, got {other:?}"),
    }
    drop(_held_lock);

    // 7e. Now call `force_stop_daemon` on the REAL SIGSTOPped daemon:
    // SIGTERM is queued while stopped -> escalates to verified SIGKILL!
    let outcome = force_stop_daemon(
        &vdir,
        device_id,
        Duration::from_millis(250),
        Duration::from_secs(2),
    )
    .expect("force_stop_daemon must kill SIGSTOPped daemon cleanly");
    assert_eq!(
        outcome,
        ForceStopOutcome::KilledBySigkill { pid: daemon_pid }
    );
    assert!(
        wait_until_daemon_exits(&vdir, daemon_pid, Duration::from_secs(2)).await,
        "daemon must be gone and daemon.lock free after force_stop_daemon"
    );

    // Fresh client can immediately spawn a new daemon!
    let mut fresh = DaemonClient::connect_or_spawn(&cfg)
        .await
        .expect("spawn fresh daemon after force_stop");
    assert_ne!(fresh.ack().daemon_pid, daemon_pid);
    shutdown_cleanly(&mut fresh, &vdir).await;
}

struct InstrumentedHandler {
    started_epoch: std::sync::atomic::AtomicU64,
    health_ticks: std::sync::atomic::AtomicU64,
    client_counts: std::sync::Mutex<Vec<usize>>,
    drain_modes: std::sync::Mutex<Vec<DrainMode>>,
    oversized_reply_bytes: usize,
}

impl InstrumentedHandler {
    fn new(oversized_reply_bytes: usize) -> Self {
        Self {
            started_epoch: std::sync::atomic::AtomicU64::new(0),
            health_ticks: std::sync::atomic::AtomicU64::new(0),
            client_counts: std::sync::Mutex::new(Vec::new()),
            drain_modes: std::sync::Mutex::new(Vec::new()),
            oversized_reply_bytes,
        }
    }
}

impl DaemonHandler for InstrumentedHandler {
    async fn handle_request(
        &self,
        _conn_id: u64,
        opcode: IpcOpcode,
        _request_id: u64,
        payload: Vec<u8>,
        _cancel: CancellationToken,
    ) -> Result<Vec<u8>, (u16, bool, String)> {
        if opcode == IpcOpcode::PartyPoll && self.oversized_reply_bytes > 0 {
            return Ok(vec![0x5A; self.oversized_reply_bytes]);
        }
        Ok(payload)
    }

    fn active_party_id(&self) -> u64 {
        0
    }

    fn on_daemon_started(&self, daemon_epoch: u64) {
        self.started_epoch
            .store(daemon_epoch, std::sync::atomic::Ordering::SeqCst);
    }

    fn on_client_count_changed(&self, count: usize) {
        if let Ok(mut guard) = self.client_counts.lock() {
            guard.push(count);
        }
    }

    async fn health_tick(&self) {
        self.health_ticks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    async fn on_drain(&self, mode: DrainMode) {
        if let Ok(mut guard) = self.drain_modes.lock() {
            guard.push(mode);
        }
    }
}

/// Oracle 8 (Gate #1 Regressions):
/// - `on_daemon_started(epoch)` fires before connect with exact authoritative `daemon_epoch`
/// - `on_client_count_changed` tracks `0 -> 1 -> 2 -> 1 -> 0` reliably
/// - Watchdog `health_tick()` runs directly on coordinator loop with zero false kills
/// - `DrainMode::StopLeaveParty` is NEVER lost or downgraded under concurrent drain triggers
/// - Per-client outbound byte cap tears down connection cleanly instead of dropping frames
async fn oracle_8_gate1_lifecycle_watchdog_drain_and_backpressure() {
    use std::sync::atomic::Ordering;

    // 8a. Callbacks + Watchdog health_tick + outbound byte-cap teardown.
    {
        let tmp = make_short_tempdir();
        let device_id = 1008;
        let handler = Arc::new(InstrumentedHandler::new(2048));
        let mut cfg = DaemonConfig::new(device_id, 100, [0xAA; 32]);
        cfg.runtime_dir_override = Some(tmp.path().to_path_buf());
        cfg.idle_timeout = None;
        cfg.watchdog_interval = Duration::from_millis(35);
        cfg.watchdog_stall_timeout = Duration::from_millis(1000);
        cfg.max_outbound_bytes_per_client = 1024;

        let shutdown = CancellationToken::new();
        let server_task = tokio::spawn(DaemonServer::run_with_shutdown(
            cfg,
            Arc::clone(&handler),
            Some(shutdown.clone()),
        ));

        let mut client_cfg = ClientConfig::new(
            device_id,
            HelloPayload {
                ipc_schema_ver: IPC_SCHEMA_VER,
                build_order: 100,
                build_digest: [0xAA; 32],
                client_kind: ClientKind::Cli,
                client_pid: std::process::id(),
            },
        );
        client_cfg.runtime_dir_override = Some(tmp.path().to_path_buf());
        client_cfg.spawn_command = None;
        client_cfg.exit_wait_timeout = Duration::from_millis(25);

        // Wait until in-process server publishes d.sock.
        let mut c1 = loop {
            match DaemonClient::connect_or_spawn(&client_cfg).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(Duration::from_millis(15)).await,
            }
        };

        let started_epoch = handler.started_epoch.load(Ordering::SeqCst);
        assert_ne!(started_epoch, 0, "on_daemon_started must fire before accept");
        assert_eq!(
            c1.ack().daemon_epoch,
            started_epoch,
            "HelloAck.daemon_epoch must match on_daemon_started(epoch)"
        );

        let c2 = DaemonClient::connect_or_spawn(&client_cfg)
            .await
            .expect("second client connect");

        // Wait for >= 3 coordinator watchdog health ticks on healthy server.
        let tick_deadline = Instant::now() + Duration::from_secs(2);
        while handler.health_ticks.load(Ordering::SeqCst) < 3 {
            assert!(
                Instant::now() < tick_deadline,
                "watchdog health_tick did not advance on coordinator loop"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Trigger outbound byte-cap breach on c1 (2048 > 1024): connection MUST tear down!
        let oversized_res = tokio::time::timeout(
            Duration::from_secs(2),
            c1.request(IpcOpcode::PartyPoll, Vec::new()),
        )
        .await
        .expect("oversized reply must tear down connection promptly, not hang");
        assert!(
            oversized_res.is_err(),
            "expected connection teardown on outbound byte-cap breach, got {oversized_res:?}"
        );
        drop(c1);
        drop(c2);

        // Wait until client count transitions back down to 0.
        let zero_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let last = handler
                .client_counts
                .lock()
                .expect("lock counts")
                .last()
                .copied();
            if last == Some(0) {
                break;
            }
            assert!(
                Instant::now() < zero_deadline,
                "on_client_count_changed never returned to 0"
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        let counts = handler.client_counts.lock().expect("lock counts").clone();
        assert!(
            counts.contains(&1) && counts.contains(&2) && counts.last() == Some(&0),
            "unexpected client count sequence: {counts:?}"
        );

        shutdown.cancel();
        let exit = server_task
            .await
            .expect("server join")
            .expect("server exit ok");
        assert_eq!(exit, DaemonExitReason::ExternalShutdown);
    }

    // 8b. Concurrent drain race: `StopLeaveParty` must NEVER be lost or downgraded to `StopDetach`!
    for round in 0u64..15 {
        let tmp = make_short_tempdir();
        let device_id = 1100 + round;
        let handler = Arc::new(InstrumentedHandler::new(0));
        let mut cfg = DaemonConfig::new(device_id, 100, [0xAA; 32]);
        cfg.runtime_dir_override = Some(tmp.path().to_path_buf());
        cfg.idle_timeout = Some(Duration::from_millis(25));
        cfg.watchdog_interval = Duration::from_millis(50);

        let shutdown = CancellationToken::new();
        let server_task = tokio::spawn(DaemonServer::run_with_shutdown(
            cfg,
            Arc::clone(&handler),
            Some(shutdown.clone()),
        ));

        let mut client_cfg = ClientConfig::new(
            device_id,
            HelloPayload {
                ipc_schema_ver: IPC_SCHEMA_VER,
                build_order: 100,
                build_digest: [0xAA; 32],
                client_kind: ClientKind::Cli,
                client_pid: std::process::id(),
            },
        );
        client_cfg.runtime_dir_override = Some(tmp.path().to_path_buf());
        client_cfg.spawn_command = None;
        client_cfg.exit_wait_timeout = Duration::from_millis(25);

        let mut c_leave = loop {
            match DaemonClient::connect_or_spawn(&client_cfg).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        let mut c_detach = DaemonClient::connect_or_spawn(&client_cfg)
            .await
            .expect("connect second client");

        // Send StopLeaveParty, and the instant the server commits & ACKs it, race both
        // external_shutdown AND a second StopDetach request!
        c_leave
            .send_drain_and_shutdown(DrainMode::StopLeaveParty)
            .await
            .expect("send StopLeaveParty");
        shutdown.cancel();
        let _ = c_detach.send_drain_and_shutdown(DrainMode::StopDetach).await;

        let exit = server_task
            .await
            .expect("server join")
            .expect("server exit");
        assert_eq!(
            exit,
            DaemonExitReason::DrainRequested(DrainMode::StopLeaveParty),
            "round {round}: StopLeaveParty was lost or downgraded to {exit:?}"
        );
        let modes = handler.drain_modes.lock().expect("drain modes").clone();
        assert_eq!(
            modes,
            vec![DrainMode::StopLeaveParty],
            "round {round}: on_drain received wrong mode: {modes:?}"
        );
    }
}

/// Oracle 9 (Gate #1 Regressions):
/// - Component-wise `open_or_create_private_dir` rejects nested non-root intermediate symlinks
///   and non-directory components while succeeding through root-owned macOS `/var -> private/var`
/// - `daemon.log` rotates atomically to `daemon.log.1` on spawn when `> 4 MiB`
async fn oracle_9_gate1_component_walk_and_log_rotation() {
    let tmp = make_short_tempdir();
    let device_id = 1009;

    // 9a. Nested non-root intermediate symlink MUST be rejected even with deep descendants.
    let target = tmp.path().join("real_target");
    std::fs::create_dir(&target).expect("mkdir target");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let mid_link = tmp.path().join("nonroot_mid");
    std::os::unix::fs::symlink(&target, &mid_link).expect("symlink mid");
    let deep_through_link = mid_link.join("nested").join("leaf");
    match open_or_create_private_dir(&deep_through_link) {
        Err(DaemonError::SymlinkRejected { .. }) => {}
        other => panic!("expected SymlinkRejected on nested non-root symlink, got {other:?}"),
    }

    // Regular file as intermediate component MUST fail closed with InsecureDirectory.
    let reg_file = tmp.path().join("not_a_dir");
    std::fs::write(&reg_file, b"hello").expect("write regular file");
    match open_or_create_private_dir(&reg_file.join("child")) {
        Err(DaemonError::InsecureDirectory { .. }) => {}
        other => panic!("expected InsecureDirectory on regular file component, got {other:?}"),
    }

    // On macOS, verify paths traversing root-owned `/var -> private/var` succeed cleanly!
    #[cfg(target_os = "macos")]
    {
        assert!(
            tmp.path().starts_with(Path::new("/var/folders")),
            "expected macOS tempdir under /var/folders (through /var -> private/var), got {}",
            tmp.path().display()
        );
        let mac_dir = tmp.path().join("var_walk_ok").join("leaf");
        let vdir = open_or_create_private_dir(&mac_dir)
            .expect("open_or_create_private_dir must succeed through root-owned /var symlink");
        assert!(vdir.path_matches_inode().expect("inode match"));
    }

    // 9b. `daemon.log` rotation on spawn when > 4 MiB.
    let rdir_path = resolve_runtime_dir(device_id, Some(tmp.path())).expect("resolve dir");
    let vdir = open_or_create_private_dir(&rdir_path).expect("open runtime dir");
    let oversized_len = (4 * 1024 * 1024) + 1024;
    let log_path = rdir_path.join(DAEMON_LOG_NAME);
    std::fs::write(&log_path, vec![b'X'; oversized_len]).expect("write >4MiB daemon.log");
    std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600)).expect("chmod log");

    let spec = WorkerSpec::new(device_id, tmp.path().to_path_buf());
    let cfg = spec.client_config(ClientKind::Cli, IPC_SCHEMA_VER, 100, 0xAA, false);
    let mut client = DaemonClient::connect_or_spawn(&cfg)
        .await
        .expect("spawn daemon with oversized daemon.log");

    let rotated_st = vdir
        .stat_entry(outpost_daemon::os_unix::DAEMON_LOG_OLD_NAME)
        .expect("stat daemon.log.1")
        .expect("daemon.log.1 must exist after rotation");
    assert_eq!(
        rotated_st.st_size as usize, oversized_len,
        "rotated daemon.log.1 must preserve previous >4MiB log"
    );
    let cur_st = vdir
        .stat_entry(DAEMON_LOG_NAME)
        .expect("stat daemon.log")
        .expect("new daemon.log must exist");
    assert!(
        (cur_st.st_size as usize) < 4 * 1024 * 1024,
        "new daemon.log must be fresh after rotation (got {} bytes)",
        cur_st.st_size
    );

    shutdown_cleanly(&mut client, &vdir).await;
}

fn main() -> ExitCode {
    if std::env::var(ENV_DAEMON_MODE).as_deref() == Ok("1") {
        run_daemon_worker();
    }

    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build oracle test runtime");

    type OracleFn = fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;
    let oracles: &[(&str, OracleFn)] = &[
        (
            "oracle_1_thundering_herd_32_way",
            || Box::pin(oracle_1_thundering_herd_32_way()),
        ),
        (
            "oracle_2_aba_mixed_build_coexistence",
            || Box::pin(oracle_2_aba_mixed_build_coexistence()),
        ),
        (
            "oracle_3_sigkill_crash_recovery",
            || Box::pin(oracle_3_sigkill_crash_recovery()),
        ),
        (
            "oracle_4_inode_self_fence",
            || Box::pin(oracle_4_inode_self_fence()),
        ),
        (
            "oracle_5_idle_exit_connect_race_hammer",
            || Box::pin(oracle_5_idle_exit_connect_race_hammer()),
        ),
        (
            "oracle_6_security_sun_path_and_atomic_publish",
            || Box::pin(oracle_6_security_sun_path_and_atomic_publish()),
        ),
        (
            "oracle_7_no_fd_leak_no_zombies_and_sigstop_force_stop",
            || Box::pin(oracle_7_no_fd_leak_no_zombies_and_sigstop_force_stop()),
        ),
        (
            "oracle_8_gate1_lifecycle_watchdog_drain_and_backpressure",
            || Box::pin(oracle_8_gate1_lifecycle_watchdog_drain_and_backpressure()),
        ),
        (
            "oracle_9_gate1_component_walk_and_log_rotation",
            || Box::pin(oracle_9_gate1_component_walk_and_log_rotation()),
        ),
    ];

    let mut passed = 0usize;
    let mut filtered_out = 0usize;

    for &(name, func) in oracles {
        if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
            filtered_out += 1;
            continue;
        }
        let started = Instant::now();
        rt.block_on(func());
        println!("test {name} ... ok ({:.0?})", started.elapsed());
        passed += 1;
    }

    println!(
        "\ntest result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; {filtered_out} filtered out"
    );
    ExitCode::SUCCESS
}
