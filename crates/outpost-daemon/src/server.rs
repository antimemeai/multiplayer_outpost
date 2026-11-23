//! Local daemon IPC server:
//! - Atomic `Serving -> Draining -> Exited` lifecycle state machine
//! - Mandatory 5s `Hello` deadline + mutual peercred verification + RAII client tracking
//! - Dedicated OS watchdog thread (inode self-fence + atime touch + coordinator progress tick)
//! - Race-free `ControlPersist` idle auto-exit holding `startup.lock` until after `daemon.lock`

use std::collections::HashMap;
use std::future::Future;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

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
    drain_reason: Mutex<Option<DaemonExitReason>>,
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

    async fn trigger_drain(&self, reason: DaemonExitReason) {
        if self.try_begin_draining() {
            let mut guard = self.drain_reason.lock().await;
            if guard.is_none() {
                *guard = Some(reason);
            }
            self.drain_notify.notify_waiters();
        }
    }
}

struct ClientGuard {
    shared: Arc<SharedState>,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        let prev = self.shared.connected_clients.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
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
        config: DaemonConfig,
        handler: Arc<H>,
        external_shutdown: Option<CancellationToken>,
    ) -> Result<DaemonExitReason, DaemonError> {
        let ready_fd = config.ready_fd;
        let res = Self::run_inner(config, handler, external_shutdown).await;
        if let Err(ref err) = res
            && let Some(fd) = ready_fd
        {
            send_ready_reply_and_close(
                fd,
                &outpost_core::ipc_wire::ReadyReply::Err(err.to_string()),
            );
        }
        res
    }

    async fn run_inner<H: DaemonHandler>(
        mut config: DaemonConfig,
        handler: Arc<H>,
        external_shutdown: Option<CancellationToken>,
    ) -> Result<DaemonExitReason, DaemonError> {
        let ready_fd = config.ready_fd.take();
        let runtime_path =
            resolve_runtime_dir(config.device_id, config.runtime_dir_override.as_deref())?;
        let dir = Arc::new(open_or_create_private_dir(&runtime_path)?);

        // Hold `startup_lock` ONLY if acquired during autonomous idle teardown;
        // declare it BEFORE `daemon_lock` so Rust drops `daemon_lock` strictly first!
        let mut idle_startup_lock: Option<FlockGuard> = None;

        let Some(daemon_lock) = FlockGuard::try_lock_exclusive(&dir, DAEMON_LOCK_NAME)? else {
            if let Some(fd) = ready_fd {
                send_ready_reply_and_close(
                    fd,
                    &outpost_core::ipc_wire::ReadyReply::AlreadyRunning,
                );
            }
            return Ok(DaemonExitReason::AlreadyRunning);
        };
        let daemon_lock = Arc::new(daemon_lock);

        let daemon_epoch = generate_daemon_epoch();
        let daemon_pid = std::process::id();
        let start_token = current_process_start_token()?;

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

        let shared = Arc::new(SharedState {
            lifecycle: AtomicU8::new(LifecycleState::Serving as u8),
            connected_clients: AtomicUsize::new(0),
            pending_handshakes: AtomicUsize::new(0),
            next_conn_id: AtomicU64::new(1),
            idle_notify: Notify::new(),
            drain_notify: Notify::new(),
            drain_reason: Mutex::new(None),
            config: config.clone(),
            daemon_epoch,
            daemon_pid,
        });

        // Coordinator heartbeat channel: proves the main Tokio runtime is making progress.
        let (hb_tx, mut hb_rx) = mpsc::channel::<u64>(4);
        let last_hb_ack_ms = Arc::new(AtomicU64::new(monotonic_boottime_ms()));
        let hb_ack_clone = Arc::clone(&last_hb_ack_ms);
        let hb_task = tokio::spawn(async move {
            while let Some(_seq) = hb_rx.recv().await {
                hb_ack_clone.store(monotonic_boottime_ms(), Ordering::Release);
            }
        });

        // Dedicated OS watchdog thread outside Tokio.
        let watchdog_stop = Arc::new(AtomicBool::new(false));
        let watchdog_handle = spawn_watchdog_thread(
            Arc::clone(&dir),
            Arc::clone(&daemon_lock),
            Arc::clone(&shared),
            Arc::clone(&watchdog_stop),
            hb_tx,
            last_hb_ack_ms,
            WatchdogInodes {
                lock_dev,
                lock_ino,
                sock_dev,
                sock_ino,
            },
        )?;

        // Signal readiness to spawning parent over FD 3 and close FD 3!
        if let Some(fd) = ready_fd {
            send_ready_reply_and_close(
                fd,
                &outpost_core::ipc_wire::ReadyReply::Ok { daemon_epoch },
            );
        }

        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| DaemonError::io("register SIGTERM", e))?;
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|e| DaemonError::io("register SIGINT", e))?;

        let mut idle_since_ms: Option<u64> = None;
        let idle_poll_interval = config
            .idle_timeout
            .map(|d| (d / 4).clamp(Duration::from_millis(20), Duration::from_secs(1)))
            .unwrap_or_else(|| Duration::from_secs(60));

        let exit_reason = loop {
            if shared.state() != LifecycleState::Serving {
                let guard = shared.drain_reason.lock().await;
                break guard.unwrap_or(DaemonExitReason::ExternalShutdown);
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
                                // 2. Atomically transition Serving -> Draining.
                                if shared.try_begin_draining() {
                                    // 3. Re-check idle invariants under startup.lock!
                                    let still_idle =
                                        shared.connected_clients.load(Ordering::SeqCst) == 0
                                            && shared.pending_handshakes.load(Ordering::SeqCst)
                                                == 0
                                            && handler.active_party_id() == 0;
                                    if still_idle {
                                        idle_startup_lock = Some(startup_guard);
                                        break DaemonExitReason::IdleTimeout;
                                    }
                                    // A client arrived just before Draining; revert & resume.
                                    shared.revert_draining_to_serving();
                                    drop(startup_guard);
                                    idle_since_ms = None;
                                } else {
                                    drop(startup_guard);
                                    let guard = shared.drain_reason.lock().await;
                                    break guard.unwrap_or(DaemonExitReason::ExternalShutdown);
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
                        let guard = shared.drain_reason.lock().await;
                        break guard.unwrap_or(DaemonExitReason::ExternalShutdown);
                    }
                }
                _ = sigterm.recv() => {
                    shared.trigger_drain(DaemonExitReason::Signal).await;
                    break DaemonExitReason::Signal;
                }
                _ = sigint.recv() => {
                    shared.trigger_drain(DaemonExitReason::Signal).await;
                    break DaemonExitReason::Signal;
                }
                _ = async {
                    if let Some(ref tok) = external_shutdown {
                        tok.cancelled().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    shared.trigger_drain(DaemonExitReason::ExternalShutdown).await;
                    break DaemonExitReason::ExternalShutdown;
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
        let _ = shared.try_begin_draining();
        drop(listener);
        let _ = dir.unlink_if_matches(SOCKET_FILE_NAME, sock_dev, sock_ino);

        let drain_mode = match exit_reason {
            DaemonExitReason::DrainRequested(mode) => mode,
            _ => DrainMode::StopDetach,
        };
        let _ = tokio::time::timeout(config.drain_timeout, handler.on_drain(drain_mode)).await;

        shared.mark_exited();
        watchdog_stop.store(true, Ordering::SeqCst);
        hb_task.abort();
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
    last_hb_ack_ms: Arc<AtomicU64>,
    inodes: WatchdogInodes,
) -> Result<std::thread::JoinHandle<()>, DaemonError> {
    let interval = shared.config.watchdog_interval;
    let stall_timeout_ms = shared.config.watchdog_stall_timeout.as_millis() as u64;
    let sleep_step = interval.min(Duration::from_millis(50));

    std::thread::Builder::new()
        .name("outpost-watchdog".to_string())
        .spawn(move || {
            let mut seq = 1u64;
            let mut last_check_ms = monotonic_boottime_ms();
            let interval_ms = interval.as_millis().max(1) as u64;

            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(sleep_step);
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let now_ms = monotonic_boottime_ms();
                if now_ms.saturating_sub(last_check_ms) < interval_ms {
                    continue;
                }
                last_check_ms = now_ms;

                if shared.state() != LifecycleState::Serving {
                    break;
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
                    if shared.try_begin_draining() {
                        if let Ok(mut guard) = shared.drain_reason.try_lock() {
                            *guard = Some(DaemonExitReason::WatchdogInodeMismatch);
                        }
                        shared.drain_notify.notify_waiters();
                    }
                    break;
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

                // 2. Coordinator event-loop heartbeat progress check.
                let _ = hb_tx.try_send(seq);
                seq = seq.wrapping_add(1);
                let ack_ms = last_hb_ack_ms.load(Ordering::Acquire);
                if now_ms.saturating_sub(ack_ms) > stall_timeout_ms {
                    write_log_lock_free(
                        b"outpost-daemon watchdog: coordinator stalled past timeout, calling _exit(2)\n",
                    );
                    unsafe {
                        libc::_exit(2);
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
    shared.connected_clients.fetch_add(1, Ordering::SeqCst);
    let _client_guard = ClientGuard {
        shared: Arc::clone(&shared),
    };
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

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let sz = frame.payload.len();
            queued_bytes_w.fetch_sub(sz, Ordering::AcqRel);
            if write_ipc_frame(&mut writer, &frame).await.is_err() {
                break;
            }
        }
    });

    let inflight: Arc<Mutex<HashMap<u64, CancellationToken>>> =
        Arc::new(Mutex::new(HashMap::new()));

    loop {
        let frame = match read_ipc_frame(&mut reader).await {
            Ok(Some(f)) => f,
            _ => break,
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
            let reply = IpcFrame {
                opcode: IpcOpcode::DrainAndShutdown,
                request_id: frame.request_id,
                payload: Vec::new(),
            };
            let _ = out_tx.send(reply).await;
            shared.trigger_drain(DaemonExitReason::DrainRequested(mode)).await;
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
            let _ = send_bounded(&out_tx, &queued_bytes, max_out_bytes, err_frame).await;
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
                if !send_bounded(&out_tx, &queued_bytes, max_out_bytes, err_frame).await {
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
            let _ = send_bounded(&out_tx_c, &queued_bytes_c, max_out_bytes, reply).await;
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
    frame: IpcFrame,
) -> bool {
    let sz = frame.payload.len();
    let prev = queued_bytes.fetch_add(sz, Ordering::AcqRel);
    if prev.saturating_add(sz) > max_bytes {
        queued_bytes.fetch_sub(sz, Ordering::AcqRel);
        return false;
    }
    if tx.send(frame).await.is_err() {
        queued_bytes.fetch_sub(sz, Ordering::AcqRel);
        return false;
    }
    true
}
