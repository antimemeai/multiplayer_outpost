//! Local daemon IPC server:
//! - Atomic `Serving -> Draining -> Exited` lifecycle state machine
//! - Mandatory 5s `Hello` deadline + mutual peercred verification + RAII client tracking
//! - Dedicated OS watchdog thread (inode self-fence + atime touch + coordinator progress tick)
//! - Race-free `ControlPersist` idle auto-exit holding `startup.lock` until after `daemon.lock`

use std::collections::HashMap;
use std::future::Future;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::{Duration, Instant};

use outpost_core::ipc_wire::{HelloAckPayload, IPC_SCHEMA_VER, IpcFrame, IpcOpcode};
use outpost_core::storage_codec::{DaemonInfoRecord, encode_daemon_info};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, mpsc};

use crate::cancel::CancellationToken;
use crate::error::DaemonError;
use crate::ipc_codec::{
    DrainMode, decode_cancel_payload, decode_drain_payload, decode_hello, encode_error_payload,
    encode_hello_ack, read_ipc_frame, write_ipc_frame,
};
use crate::os_unix::{
    DAEMON_INFO_NAME, DAEMON_LOCK_NAME, FlockGuard, STARTUP_LOCK_NAME, current_process_start_token,
    generate_daemon_epoch, monotonic_boottime_ms, publish_unix_listener, send_ready_reply_and_close,
    verify_peer_same_uid, write_log_lock_free,
};
use crate::runtime_dir::{
    SOCKET_FILE_NAME, VerifiedDir, open_or_create_private_dir, resolve_runtime_dir, stat_dev_ino,
};
use crate::state_io::atomic_write_in_dir;

/// Application request handler implemented by the daemon engine.
pub trait DaemonHandler: Send + Sync + 'static {
    fn handle_request(
        &self,
        conn_id: u64,
        opcode: IpcOpcode,
        request_id: u64,
        payload: Vec<u8>,
        cancel: CancellationToken,
    ) -> impl Future<Output = Result<Vec<u8>, (u16, bool, String)>> + Send;

    fn active_party_id(&self) -> u64;

    /// Called once after the authoritative `daemon_epoch` is generated and before
    /// the Unix socket is published or readiness is signaled.
    fn on_daemon_started(&self, _daemon_epoch: u64) {}

    /// Called whenever the authenticated client count changes (on connect and disconnect).
    fn on_client_count_changed(&self, _count: usize) {}

    /// Called directly from the coordinator loop when answering OS watchdog heartbeats.
    fn health_tick(&self) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn on_drain(&self, _mode: DrainMode) -> impl Future<Output = ()> + Send {
        async {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleState {
    Serving = 0,
    Draining = 1,
    Exited = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonExitReason {
    AlreadyRunning,
    IdleTimeout,
    DrainRequested(DrainMode),
    WatchdogInodeMismatch,
    Signal,
    ExternalShutdown,
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub device_id: u64,
    pub runtime_dir_override: Option<PathBuf>,
    pub ipc_schema_ver: u32,
    pub build_order: u64,
    pub build_digest: [u8; 32],
    pub exe_path: String,
    pub hello_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub watchdog_interval: Duration,
    pub watchdog_stall_timeout: Duration,
    pub max_clients: usize,
    pub max_inflight_per_client: usize,
    pub max_outbound_frames_per_client: usize,
    pub max_outbound_bytes_per_client: usize,
    pub drain_timeout: Duration,
    pub ready_fd: Option<RawFd>,
}

impl DaemonConfig {
    pub fn new(device_id: u64, build_order: u64, build_digest: [u8; 32]) -> Self {
        let exe_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_else(|| "mp-outpost".to_string());
        Self {
            device_id,
            runtime_dir_override: None,
            ipc_schema_ver: IPC_SCHEMA_VER,
            build_order,
            build_digest,
            exe_path,
            hello_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(300)),
            watchdog_interval: Duration::from_secs(5),
            watchdog_stall_timeout: Duration::from_secs(20),
            max_clients: 32,
            max_inflight_per_client: 16,
            max_outbound_frames_per_client: 64,
            max_outbound_bytes_per_client: 4 * 1024 * 1024,
            drain_timeout: Duration::from_millis(2000),
            ready_fd: None,
        }
    }
}

struct SharedState {
    lifecycle: AtomicU8,
    connected_clients: AtomicUsize,
    pending_handshakes: AtomicUsize,
    next_conn_id: AtomicU64,
    idle_notify: Notify,
    drain_notify: Notify,
    drain_reason: StdMutex<Option<DaemonExitReason>>,
    config: DaemonConfig,
    daemon_epoch: u64,
    daemon_pid: u32,
}

impl SharedState {
    fn state(&self) -> LifecycleState {
        match self.lifecycle.load(Ordering::SeqCst) {
            0 => LifecycleState::Serving,
            1 => LifecycleState::Draining,
            _ => LifecycleState::Exited,
        }
    }

    fn lock_drain_reason(&self) -> StdMutexGuard<'_, Option<DaemonExitReason>> {
        match self.drain_reason.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn drain_reason_or(&self, fallback: DaemonExitReason) -> DaemonExitReason {
        let guard = self.lock_drain_reason();
        guard.unwrap_or(fallback)
    }

    fn try_begin_draining(&self) -> bool {
        self.lifecycle
            .compare_exchange(
                LifecycleState::Serving as u8,
                LifecycleState::Draining as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    fn revert_draining_to_serving(&self) {
        let _ = self.lifecycle.compare_exchange(
            LifecycleState::Draining as u8,
            LifecycleState::Serving as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    fn mark_exited(&self) {
        self.lifecycle
            .store(LifecycleState::Exited as u8, Ordering::SeqCst);
    }

    /// Atomically records `reason` and transitions `Serving -> Draining` under the
    /// synchronous `drain_reason` lock so no caller can ever observe `Draining` before
    /// `drain_reason` is populated.
    fn trigger_drain(&self, reason: DaemonExitReason) -> bool {
        let mut guard = self.lock_drain_reason();
        if self.state() != LifecycleState::Serving {
            return false;
        }
        *guard = Some(reason);
        let transitioned = self.try_begin_draining();
        drop(guard);
        if transitioned {
            self.drain_notify.notify_waiters();
        }
        transitioned
    }

    /// Atomically transitions `Serving -> Draining` for autonomous idle exit if and
    /// only if `is_still_idle()` holds while serialized with `trigger_drain`.
    fn try_begin_idle_drain<F>(&self, is_still_idle: F) -> Result<bool, DaemonExitReason>
    where
        F: FnOnce() -> bool,
    {
        let mut guard = self.lock_drain_reason();
        if self.state() != LifecycleState::Serving {
            return Err(guard.unwrap_or(DaemonExitReason::ExternalShutdown));
        }
        if !self.try_begin_draining() {
            return Err(guard.unwrap_or(DaemonExitReason::ExternalShutdown));
        }
        if is_still_idle() {
            *guard = Some(DaemonExitReason::IdleTimeout);
            Ok(true)
        } else {
            self.revert_draining_to_serving();
            Ok(false)
        }
    }
}

struct ClientGuard<H: DaemonHandler> {
    shared: Arc<SharedState>,
    handler: Arc<H>,
}

impl<H: DaemonHandler> Drop for ClientGuard<H> {
    fn drop(&mut self) {
        let prev = self.shared.connected_clients.fetch_sub(1, Ordering::SeqCst);
        let now = prev.saturating_sub(1);
        self.handler.on_client_count_changed(now);
        if now == 0 {
            self.shared.idle_notify.notify_waiters();
        }
    }
}

struct PendingHandshakeGuard {
    shared: Arc<SharedState>,
    active: bool,
}

impl PendingHandshakeGuard {
    fn new(shared: Arc<SharedState>) -> Self {
        shared.pending_handshakes.fetch_add(1, Ordering::SeqCst);
        Self {
            shared,
            active: true,
        }
    }

    fn complete(mut self) {
        if self.active {
            self.active = false;
            self.shared.pending_handshakes.fetch_sub(1, Ordering::SeqCst);
            self.shared.idle_notify.notify_waiters();
        }
    }
}

impl Drop for PendingHandshakeGuard {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.shared.pending_handshakes.fetch_sub(1, Ordering::SeqCst);
            self.shared.idle_notify.notify_waiters();
        }
    }
}

pub struct DaemonServer;

impl DaemonServer {
    /// Runs the local daemon IPC server until idle exit, `DrainAndShutdown`,
    /// signal, or watchdog inode self-fence.
    pub async fn run<H: DaemonHandler>(
        config: DaemonConfig,
        handler: Arc<H>,
    ) -> Result<DaemonExitReason, DaemonError> {
        Self::run_with_shutdown(config, handler, None).await
    }

    /// Runs the local daemon IPC server with an optional external shutdown token.
    pub async fn run_with_shutdown<H: DaemonHandler>(
        mut config: DaemonConfig,
        handler: Arc<H>,
        external_shutdown: Option<CancellationToken>,
    ) -> Result<DaemonExitReason, DaemonError> {
        // Take `ready_fd` strictly once here so `send_ready_reply_and_close` is
        // guaranteed to be called at most once across all success & error paths.
        let mut ready_fd = config.ready_fd.take();
        let res = Self::run_inner(config, handler, external_shutdown, &mut ready_fd).await;
        if let Err(ref err) = res
            && let Some(fd) = ready_fd.take()
        {
            send_ready_reply_and_close(
                fd,
                &outpost_core::ipc_wire::ReadyReply::Err(err.to_string()),
            );
        }
        res
    }

    async fn run_inner<H: DaemonHandler>(
        config: DaemonConfig,
        handler: Arc<H>,
        external_shutdown: Option<CancellationToken>,
        ready_fd: &mut Option<RawFd>,
    ) -> Result<DaemonExitReason, DaemonError> {
        let runtime_path =
            resolve_runtime_dir(config.device_id, config.runtime_dir_override.as_deref())?;
        let dir = Arc::new(open_or_create_private_dir(&runtime_path)?);

        // Hold `startup_lock` ONLY if acquired during autonomous idle teardown;
        // declare it BEFORE `daemon_lock` so Rust drops `daemon_lock` strictly first!
        let mut idle_startup_lock: Option<FlockGuard> = None;

        let Some(daemon_lock) = FlockGuard::try_lock_exclusive(&dir, DAEMON_LOCK_NAME)? else {
            if let Some(fd) = ready_fd.take() {
                send_ready_reply_and_close(
                    fd,
                    &outpost_core::ipc_wire::ReadyReply::AlreadyRunning,
                );
            }
            return Ok(DaemonExitReason::AlreadyRunning);
        };
        let daemon_lock = Arc::new(daemon_lock);

        let daemon_epoch = generate_daemon_epoch()?;
        let daemon_pid = std::process::id();
        let start_token = current_process_start_token()?;

        // Notify handler of authoritative daemon_epoch BEFORE publishing d.sock / readiness.
        handler.on_daemon_started(daemon_epoch);

        let published = publish_unix_listener(&dir, &daemon_lock)?;
        let sock_dev = published.sock_dev;
        let sock_ino = published.sock_ino;
        let lock_dev = published.lock_dev;
        let lock_ino = published.lock_ino;

        let info = DaemonInfoRecord {
            pid: daemon_pid,
            native_start_token: start_token,
            daemon_epoch,
            ipc_schema_ver: config.ipc_schema_ver,
            build_order: config.build_order,
            build_digest: config.build_digest,
            device_id: config.device_id,
            exe_path: config.exe_path.clone(),
        };
        let info_bytes = encode_daemon_info(&info)?;
        atomic_write_in_dir(dir.as_raw_fd(), DAEMON_INFO_NAME, &info_bytes)?;

        let listener = UnixListener::from_std(published.listener)
            .map_err(|e| DaemonError::io("tokio UnixListener::from_std", e))?;

        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| DaemonError::io("register SIGTERM", e))?;
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|e| DaemonError::io("register SIGINT", e))?;

        let shared = Arc::new(SharedState {
            lifecycle: AtomicU8::new(LifecycleState::Serving as u8),
            connected_clients: AtomicUsize::new(0),
            pending_handshakes: AtomicUsize::new(0),
            next_conn_id: AtomicU64::new(1),
            idle_notify: Notify::new(),
            drain_notify: Notify::new(),
            drain_reason: StdMutex::new(None),
            config: config.clone(),
            daemon_epoch,
            daemon_pid,
        });

        // Coordinator heartbeat channel: directly probed by the main select! loop + handler.health_tick().
        let (hb_tx, mut hb_rx) = mpsc::channel::<u64>(4);
        let last_hb_ack_seq = Arc::new(AtomicU64::new(0));

        // Dedicated OS watchdog thread outside Tokio.
        let watchdog_stop = Arc::new(AtomicBool::new(false));
        let watchdog_handle = spawn_watchdog_thread(
            Arc::clone(&dir),
            Arc::clone(&daemon_lock),
            Arc::clone(&shared),
            Arc::clone(&watchdog_stop),
            hb_tx,
            Arc::clone(&last_hb_ack_seq),
            WatchdogInodes {
                lock_dev,
                lock_ino,
                sock_dev,
                sock_ino,
            },
        )?;

        // Signal readiness to spawning parent over FD 3 and close FD 3!
        if let Some(fd) = ready_fd.take() {
            send_ready_reply_and_close(
                fd,
                &outpost_core::ipc_wire::ReadyReply::Ok { daemon_epoch },
            );
        }

        let mut idle_since_ms: Option<u64> = None;
        let idle_poll_interval = config
            .idle_timeout
            .map(|d| (d / 4).clamp(Duration::from_millis(20), Duration::from_secs(1)))
            .unwrap_or_else(|| Duration::from_secs(60));

        let exit_reason = loop {
            if shared.state() != LifecycleState::Serving {
                break shared.drain_reason_or(DaemonExitReason::ExternalShutdown);
            }

            // Update sleep-aware idle timestamp.
            let is_idle = shared.connected_clients.load(Ordering::SeqCst) == 0
                && shared.pending_handshakes.load(Ordering::SeqCst) == 0
                && handler.active_party_id() == 0;
            if is_idle {
                let now = monotonic_boottime_ms();
                let since = *idle_since_ms.get_or_insert(now);
                if let Some(idle_limit) = config.idle_timeout {
                    let limit_ms = idle_limit.as_millis() as u64;
                    if now.saturating_sub(since) >= limit_ms {
                        // Race-free ControlPersist idle teardown:
                        // 1. Try startup.lock (LOCK_EX | LOCK_NB).
                        match FlockGuard::try_lock_exclusive(&dir, STARTUP_LOCK_NAME)? {
                            None => {
                                // A client is actively spawning/connecting; abort teardown.
                                idle_since_ms = Some(monotonic_boottime_ms());
                            }
                            Some(startup_guard) => {
                                // 2. Atomically transition Serving -> Draining and re-check idle invariants.
                                match shared.try_begin_idle_drain(|| {
                                    shared.connected_clients.load(Ordering::SeqCst) == 0
                                        && shared.pending_handshakes.load(Ordering::SeqCst) == 0
                                        && handler.active_party_id() == 0
                                }) {
                                    Ok(true) => {
                                        idle_startup_lock = Some(startup_guard);
                                        break DaemonExitReason::IdleTimeout;
                                    }
                                    Ok(false) => {
                                        // A client arrived just before Draining; revert & resume.
                                        drop(startup_guard);
                                        idle_since_ms = None;
                                    }
                                    Err(existing_reason) => {
                                        drop(startup_guard);
                                        break existing_reason;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                idle_since_ms = None;
            }

            let drain_wait = shared.drain_notify.notified();
            let idle_wait = shared.idle_notify.notified();

            tokio::select! {
                biased;

                _ = drain_wait => {
                    if shared.state() != LifecycleState::Serving {
                        break shared.drain_reason_or(DaemonExitReason::ExternalShutdown);
                    }
                }
                _ = sigterm.recv() => {
                    let _ = shared.trigger_drain(DaemonExitReason::Signal);
                    break shared.drain_reason_or(DaemonExitReason::Signal);
                }
                _ = sigint.recv() => {
                    let _ = shared.trigger_drain(DaemonExitReason::Signal);
                    break shared.drain_reason_or(DaemonExitReason::Signal);
                }
                _ = async {
                    if let Some(ref tok) = external_shutdown {
                        tok.cancelled().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    let _ = shared.trigger_drain(DaemonExitReason::ExternalShutdown);
                    break shared.drain_reason_or(DaemonExitReason::ExternalShutdown);
                }
                Some(seq) = hb_rx.recv() => {
                    handler.health_tick().await;
                    last_hb_ack_seq.store(seq, Ordering::Release);
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _addr)) => {
                            if shared.state() != LifecycleState::Serving {
                                drop(stream);
                                continue;
                            }
                            let current_total = shared.connected_clients.load(Ordering::SeqCst)
                                + shared.pending_handshakes.load(Ordering::SeqCst);
                            if current_total >= config.max_clients {
                                drop(stream);
                                continue;
                            }
                            idle_since_ms = None;
                            let pending = PendingHandshakeGuard::new(Arc::clone(&shared));
                            let conn_id = shared.next_conn_id.fetch_add(1, Ordering::Relaxed);
                            let shared_c = Arc::clone(&shared);
                            let handler_c = Arc::clone(&handler);
                            tokio::spawn(async move {
                                handle_connection(stream, conn_id, shared_c, handler_c, pending).await;
                            });
                        }
                        Err(err) => {
                            let raw = err.raw_os_error();
                            if raw == Some(libc::EMFILE) || raw == Some(libc::ENFILE) {
                                write_log_lock_free(b"outpost-daemon: EMFILE/ENFILE on accept, backing off 1s\n");
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            } else {
                                tokio::time::sleep(Duration::from_millis(25)).await;
                            }
                        }
                    }
                }
                _ = idle_wait => {}
                _ = tokio::time::sleep(idle_poll_interval) => {}
            }
        };

        // Ensure state is Draining, stop accepting, unlink verified `d.sock`.
        let _ = shared.trigger_drain(exit_reason);
        drop(listener);
        let _ = dir.unlink_if_matches(SOCKET_FILE_NAME, sock_dev, sock_ino);

        let drain_mode = match exit_reason {
            DaemonExitReason::DrainRequested(mode) => mode,
            _ => DrainMode::StopDetach,
        };
        let _ = tokio::time::timeout(config.drain_timeout, handler.on_drain(drain_mode)).await;

        shared.mark_exited();
        watchdog_stop.store(true, Ordering::SeqCst);
        let _ = watchdog_handle.join();

        // Explicitly drop `daemon_lock` BEFORE `idle_startup_lock` so no client can
        // acquire `startup.lock` while `daemon.lock` is still held!
        drop(daemon_lock);
        drop(idle_startup_lock);

        Ok(exit_reason)
    }
}

struct WatchdogInodes {
    lock_dev: u64,
    lock_ino: u64,
    sock_dev: u64,
    sock_ino: u64,
}

fn spawn_watchdog_thread(
    dir: Arc<VerifiedDir>,
    daemon_lock: Arc<FlockGuard>,
    shared: Arc<SharedState>,
    stop: Arc<AtomicBool>,
    hb_tx: mpsc::Sender<u64>,
    last_hb_ack_seq: Arc<AtomicU64>,
    inodes: WatchdogInodes,
) -> Result<std::thread::JoinHandle<()>, DaemonError> {
    let interval = shared.config.watchdog_interval.max(Duration::from_millis(1));
    let stall_timeout = shared.config.watchdog_stall_timeout;
    let drain_hard_deadline = shared
        .config
        .drain_timeout
        .saturating_add(Duration::from_secs(5));
    let sleep_step = interval.min(Duration::from_millis(50));

    std::thread::Builder::new()
        .name("outpost-watchdog".to_string())
        .spawn(move || {
            let mut seq = 1u64;
            let mut last_check = Instant::now();
            let mut pending_ping: Option<(u64, Instant)> = None;
            let mut drain_started_at: Option<Instant> = None;

            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(sleep_step);
                if stop.load(Ordering::Acquire) {
                    break;
                }
                if last_check.elapsed() < interval {
                    continue;
                }
                last_check = Instant::now();

                match shared.state() {
                    LifecycleState::Exited => break,
                    LifecycleState::Draining => {
                        let started = drain_started_at.get_or_insert_with(Instant::now);
                        if started.elapsed() > drain_hard_deadline {
                            write_log_lock_free(
                                b"outpost-daemon watchdog: drain stalled past hard deadline, calling _exit(2)\n",
                            );
                            unsafe {
                                libc::_exit(2);
                            }
                        }
                        continue;
                    }
                    LifecycleState::Serving => {
                        drain_started_at = None;
                    }
                }

                // 1. Inode self-fence: verify dir, daemon.lock, and d.sock all match.
                let dir_ok = dir.path_matches_inode().unwrap_or(false);
                let lock_ok = dir
                    .stat_entry(DAEMON_LOCK_NAME)
                    .ok()
                    .flatten()
                    .is_some_and(|st| {
                        let (dev, ino) = stat_dev_ino(&st);
                        dev == inodes.lock_dev && ino == inodes.lock_ino
                    });
                let sock_ok = dir
                    .stat_entry(SOCKET_FILE_NAME)
                    .ok()
                    .flatten()
                    .is_some_and(|st| {
                        let (dev, ino) = stat_dev_ino(&st);
                        dev == inodes.sock_dev && ino == inodes.sock_ino
                    });

                if !dir_ok || !lock_ok || !sock_ok {
                    write_log_lock_free(
                        b"outpost-daemon watchdog: inode self-fence triggered, draining cleanly\n",
                    );
                    let _ = shared.trigger_drain(DaemonExitReason::WatchdogInodeMismatch);
                    drain_started_at.get_or_insert_with(Instant::now);
                    continue;
                }

                // Touch atime on lock files to protect against macOS dirhelper / tmpfiles.d.
                daemon_lock.touch_atime();
                unsafe {
                    let _ = libc::utimensat(
                        dir.as_raw_fd(),
                        c"startup.lock".as_ptr(),
                        std::ptr::null(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    );
                }

                // 2. Coordinator event-loop heartbeat progress check on awake-only Instant.
                if let Some((sent_seq, sent_at)) = pending_ping {
                    if last_hb_ack_seq.load(Ordering::Acquire) >= sent_seq {
                        pending_ping = None;
                    } else if sent_at.elapsed() > stall_timeout {
                        write_log_lock_free(
                            b"outpost-daemon watchdog: coordinator stalled past timeout, calling _exit(2)\n",
                        );
                        unsafe {
                            libc::_exit(2);
                        }
                    }
                }

                if pending_ping.is_none() {
                    match hb_tx.try_send(seq) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {
                            pending_ping = Some((seq, Instant::now()));
                            seq = seq.saturating_add(1);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {}
                    }
                }
            }
        })
        .map_err(|e| DaemonError::io("spawn watchdog thread", e))
}

async fn handle_connection<H: DaemonHandler>(
    stream: UnixStream,
    conn_id: u64,
    shared: Arc<SharedState>,
    handler: Arc<H>,
    pending_guard: PendingHandshakeGuard,
) {
    // Mutual peercred verification: peer_uid MUST equal geteuid().
    if verify_peer_same_uid(stream.as_raw_fd()).is_err() {
        return;
    }

    let (mut reader, mut writer) = stream.into_split();

    // Mandatory 5s Hello deadline.
    let hello_frame = match tokio::time::timeout(
        shared.config.hello_timeout,
        read_ipc_frame(&mut reader),
    )
    .await
    {
        Ok(Ok(Some(frame))) => frame,
        _ => return,
    };

    if hello_frame.opcode != IpcOpcode::Hello {
        return;
    }
    if decode_hello(&hello_frame.payload).is_err() {
        return;
    }

    // Reject late Hello if daemon already transitioned to Draining.
    if shared.state() != LifecycleState::Serving {
        let err_frame = IpcFrame {
            opcode: IpcOpcode::Error,
            request_id: hello_frame.request_id,
            payload: encode_error_payload(503, true, "daemon_draining"),
        };
        let _ = write_ipc_frame(&mut writer, &err_frame).await;
        return;
    }

    // Atomically increment `connected_clients` BEFORE completing pending handshake
    // so there is zero gap where both counters are 0 while a client is authenticating!
    let prev_clients = shared.connected_clients.fetch_add(1, Ordering::SeqCst);
    let _client_guard = ClientGuard {
        shared: Arc::clone(&shared),
        handler: Arc::clone(&handler),
    };
    handler.on_client_count_changed(prev_clients.saturating_add(1));
    pending_guard.complete();

    // Double-check state after incrementing connected_clients in case idle exit raced.
    if shared.state() != LifecycleState::Serving {
        let err_frame = IpcFrame {
            opcode: IpcOpcode::Error,
            request_id: hello_frame.request_id,
            payload: encode_error_payload(503, true, "daemon_draining"),
        };
        let _ = write_ipc_frame(&mut writer, &err_frame).await;
        return;
    }

    let ack = HelloAckPayload {
        ipc_schema_ver: shared.config.ipc_schema_ver,
        build_order: shared.config.build_order,
        build_digest: shared.config.build_digest,
        daemon_epoch: shared.daemon_epoch,
        daemon_pid: shared.daemon_pid,
        device_id: shared.config.device_id,
        active_party_id: handler.active_party_id(),
        exe_path: shared.config.exe_path.clone(),
    };
    let Ok(ack_payload) = encode_hello_ack(&ack) else {
        return;
    };
    let ack_frame = IpcFrame {
        opcode: IpcOpcode::HelloAck,
        request_id: hello_frame.request_id,
        payload: ack_payload,
    };
    if write_ipc_frame(&mut writer, &ack_frame).await.is_err() {
        return;
    }

    // Bounded outbound frame & byte queue per connection.
    let (out_tx, mut out_rx) =
        mpsc::channel::<IpcFrame>(shared.config.max_outbound_frames_per_client);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let queued_bytes_w = Arc::clone(&queued_bytes);
    let max_out_bytes = shared.config.max_outbound_bytes_per_client;
    let conn_close = CancellationToken::new();
    let conn_close_w = conn_close.clone();

    let writer_task = tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                biased;
                _ = conn_close_w.cancelled() => break,
                maybe_frame = out_rx.recv() => match maybe_frame {
                    Some(f) => f,
                    None => break,
                }
            };
            let sz = frame.payload.len();
            queued_bytes_w.fetch_sub(sz, Ordering::AcqRel);
            if write_ipc_frame(&mut writer, &frame).await.is_err() {
                conn_close_w.cancel();
                break;
            }
        }
    });

    let inflight: Arc<Mutex<HashMap<u64, CancellationToken>>> =
        Arc::new(Mutex::new(HashMap::new()));

    loop {
        let frame = tokio::select! {
            biased;
            _ = conn_close.cancelled() => break,
            res = read_ipc_frame(&mut reader) => match res {
                Ok(Some(f)) => f,
                _ => break,
            }
        };

        if frame.opcode == IpcOpcode::Cancel {
            let Ok(target_id) = decode_cancel_payload(&frame.payload) else {
                break;
            };
            let map = inflight.lock().await;
            if let Some(tok) = map.get(&target_id) {
                tok.cancel();
            }
            continue;
        }

        if frame.opcode == IpcOpcode::DrainAndShutdown {
            let Ok(mode) = decode_drain_payload(&frame.payload) else {
                break;
            };
            let _ = shared.trigger_drain(DaemonExitReason::DrainRequested(mode));
            let reply = IpcFrame {
                opcode: IpcOpcode::DrainAndShutdown,
                request_id: frame.request_id,
                payload: Vec::new(),
            };
            let _ = tokio::time::timeout(Duration::from_millis(200), out_tx.send(reply)).await;
            break;
        }

        if frame.opcode == IpcOpcode::Hello || frame.opcode == IpcOpcode::HelloAck {
            // Protocol violation: Hello is only valid as the first frame.
            break;
        }

        if frame.request_id == 0 {
            break;
        }

        if shared.state() != LifecycleState::Serving {
            let err_frame = IpcFrame {
                opcode: IpcOpcode::Error,
                request_id: frame.request_id,
                payload: encode_error_payload(503, true, "daemon_draining"),
            };
            if !send_bounded(&out_tx, &queued_bytes, max_out_bytes, &conn_close, err_frame).await {
                conn_close.cancel();
                break;
            }
            continue;
        }

        let cancel = CancellationToken::new();
        {
            let mut map = inflight.lock().await;
            if map.contains_key(&frame.request_id) {
                // Spec §4.1: duplicate active request_id immediately closes connection.
                break;
            }
            if map.len() >= shared.config.max_inflight_per_client {
                drop(map);
                let err_frame = IpcFrame {
                    opcode: IpcOpcode::Error,
                    request_id: frame.request_id,
                    payload: encode_error_payload(429, true, "too_many_inflight_requests"),
                };
                if !send_bounded(&out_tx, &queued_bytes, max_out_bytes, &conn_close, err_frame)
                    .await
                {
                    conn_close.cancel();
                    break;
                }
                continue;
            }
            map.insert(frame.request_id, cancel.clone());
        }

        let handler_c = Arc::clone(&handler);
        let inflight_c = Arc::clone(&inflight);
        let out_tx_c = out_tx.clone();
        let queued_bytes_c = Arc::clone(&queued_bytes);
        let conn_close_c = conn_close.clone();
        let req_id = frame.request_id;
        let op = frame.opcode;
        let payload = frame.payload;

        tokio::spawn(async move {
            let res = handler_c
                .handle_request(conn_id, op, req_id, payload, cancel)
                .await;
            {
                let mut map = inflight_c.lock().await;
                map.remove(&req_id);
            }
            let reply = match res {
                Ok(resp_payload) => IpcFrame {
                    opcode: op,
                    request_id: req_id,
                    payload: resp_payload,
                },
                Err((code, retryable, msg)) => IpcFrame {
                    opcode: IpcOpcode::Error,
                    request_id: req_id,
                    payload: encode_error_payload(code, retryable, &msg),
                },
            };
            if !send_bounded(&out_tx_c, &queued_bytes_c, max_out_bytes, &conn_close_c, reply).await
            {
                conn_close_c.cancel();
            }
        });
    }

    // Cancel all in-flight requests owned by this dropped connection.
    {
        let map = inflight.lock().await;
        for tok in map.values() {
            tok.cancel();
        }
    }
    drop(out_tx);
    let _ = writer_task.await;
}

async fn send_bounded(
    tx: &mpsc::Sender<IpcFrame>,
    queued_bytes: &AtomicUsize,
    max_bytes: usize,
    conn_close: &CancellationToken,
    frame: IpcFrame,
) -> bool {
    let sz = frame.payload.len();
    let mut cur = queued_bytes.load(Ordering::Acquire);
    loop {
        let Some(next) = cur.checked_add(sz) else {
            return false;
        };
        if next > max_bytes {
            return false;
        }
        match queued_bytes.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
    let sent = tokio::select! {
        biased;
        _ = conn_close.cancelled() => false,
        res = tx.send(frame) => res.is_ok(),
    };
    if !sent {
        queued_bytes.fetch_sub(sz, Ordering::AcqRel);
        return false;
    }
    true
}
