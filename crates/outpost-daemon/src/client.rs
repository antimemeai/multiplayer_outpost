//! Binary IPC client with lock-free Fast Path, serialized `startup.lock` Slow Path,
//! zero-ping-pong schema compatibility, and verified `force_stop_daemon`.

use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mp_protocol::MAX_SAFE_ID;
use outpost_core::ipc_wire::{
    HelloAckPayload, HelloCompatAction, HelloPayload, IpcFrame, IpcOpcode, ReadyReply,
    evaluate_hello_compat,
};
use tokio::net::UnixStream;

use crate::error::DaemonError;
use crate::ipc_codec::{
    DrainMode, decode_error_payload, decode_hello_ack, encode_cancel_payload, encode_drain_payload,
    encode_hello, read_ipc_frame, write_ipc_frame,
};
use crate::os_unix::{
    DAEMON_LOCK_NAME, FlockGuard, STARTUP_LOCK_NAME, SpawnCommand, spawn_detached_daemon,
    verify_peer_same_uid,
};
use crate::runtime_dir::{
    SOCKET_FILE_NAME, VerifiedDir, open_or_create_private_dir, resolve_runtime_dir,
};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub device_id: u64,
    pub runtime_dir_override: Option<PathBuf>,
    pub hello: HelloPayload,
    pub read_only_cli: bool,
    pub on_disk_exe_matches_local: bool,
    pub spawn_command: Option<SpawnCommand>,
    pub connect_timeout: Duration,
    pub hello_timeout: Duration,
    pub slow_path_timeout: Duration,
    pub exit_wait_timeout: Duration,
    pub ready_timeout: Duration,
}

impl ClientConfig {
    pub fn new(device_id: u64, hello: HelloPayload) -> Self {
        Self {
            device_id,
            runtime_dir_override: None,
            hello,
            read_only_cli: false,
            on_disk_exe_matches_local: false,
            spawn_command: None,
            connect_timeout: Duration::from_millis(3000),
            hello_timeout: Duration::from_millis(5000),
            slow_path_timeout: Duration::from_millis(15_000),
            exit_wait_timeout: Duration::from_millis(4000),
            ready_timeout: Duration::from_millis(3000),
        }
    }
}

#[derive(Debug)]
pub struct DaemonClient {
    stream: UnixStream,
    ack: HelloAckPayload,
    upgrade_available: bool,
    peer_pid: u32,
    next_request_id: AtomicU64,
}

enum FastAttempt {
    Connected(DaemonClient),
    DrainAndUpgrade(UnixStream, HelloAckPayload),
    HardError(DaemonError),
    FallbackSlowPath,
}

impl DaemonClient {
    /// Connects to a healthy compatible daemon on the Fast Path, or serializes under
    /// `startup.lock` on the Slow Path to double-check, wait for draining owners,
    /// and cleanly spawn a detached daemon.
    ///
    /// Invariants:
    /// - NEVER kills a healthy compatible daemon.
    /// - `ClientKind::Mcp` NEVER kills or drains a daemon.
    /// - NEVER signals/kills a daemon on `Hello` timeout alone.
    pub async fn connect_or_spawn(config: &ClientConfig) -> Result<Self, DaemonError> {
        let runtime_path =
            resolve_runtime_dir(config.device_id, config.runtime_dir_override.as_deref())?;
        let dir = open_or_create_private_dir(&runtime_path)?;

        // 1. Fast Path (lock-free).
        match try_connect_and_hello(&dir, config, true).await {
            FastAttempt::Connected(client) => return Ok(client),
            FastAttempt::HardError(err) => return Err(err),
            FastAttempt::DrainAndUpgrade(stream, _ack) => {
                drop(stream);
                // Fall through to serialized Slow Path to drain under startup.lock.
            }
            FastAttempt::FallbackSlowPath => {}
        }

        // 2. Slow Path (serialized under `startup.lock`).
        let slow_start = Instant::now();
        let dir_path = dir.path().to_path_buf();
        let lock_timeout = config.slow_path_timeout;
        let startup_lock = tokio::task::spawn_blocking(move || -> Result<FlockGuard, DaemonError> {
            let vdir = open_or_create_private_dir(&dir_path)?;
            FlockGuard::lock_exclusive_with_deadline(&vdir, STARTUP_LOCK_NAME, lock_timeout)
        })
        .await
        .map_err(|e| DaemonError::Protocol(format!("startup.lock task panicked: {e}")))??;

        // Double-check under `startup.lock`!
        let mut requested_drain = false;
        match try_connect_and_hello(&dir, config, false).await {
            FastAttempt::Connected(client) => {
                drop(startup_lock);
                return Ok(client);
            }
            FastAttempt::HardError(err) => {
                drop(startup_lock);
                return Err(err);
            }
            FastAttempt::DrainAndUpgrade(mut stream, _ack) => {
                // Mutating CLI upgrading strictly newer schema under `startup.lock`.
                let frame = IpcFrame {
                    opcode: IpcOpcode::DrainAndShutdown,
                    request_id: 2,
                    payload: encode_drain_payload(DrainMode::RestartKeepParty),
                };
                let _ = write_ipc_frame(&mut stream, &frame).await;
                let _ = tokio::time::timeout(Duration::from_millis(500), read_ipc_frame(&mut stream))
                    .await;
                drop(stream);
                requested_drain = true;
            }
            FastAttempt::FallbackSlowPath => {}
        }

        // Wait for any exiting daemon to release `daemon.lock`.
        let wait_cap = config
            .exit_wait_timeout
            .min(config.slow_path_timeout.saturating_sub(slow_start.elapsed()));
        let exit_start = Instant::now();
        loop {
            if FlockGuard::probe_lock_free(&dir, DAEMON_LOCK_NAME)? {
                break;
            }
            if exit_start.elapsed() >= wait_cap {
                // One final check in case a slow-waking daemon became responsive.
                if !requested_drain
                    && let FastAttempt::Connected(client) =
                        try_connect_and_hello(&dir, config, false).await
                {
                    drop(startup_lock);
                    return Ok(client);
                }
                drop(startup_lock);
                return Err(DaemonError::DaemonWedged {
                    reason: "daemon.lock held past wait deadline and d.sock unresponsive",
                });
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let Some(spawn_cmd) = config.spawn_command.clone() else {
            drop(startup_lock);
            return Err(DaemonError::DaemonNotRunning);
        };

        let ready_timeout = config
            .ready_timeout
            .min(config.slow_path_timeout.saturating_sub(slow_start.elapsed()));
        let dir_path = dir.path().to_path_buf();
        let ready = tokio::task::spawn_blocking(move || -> Result<ReadyReply, DaemonError> {
            let vdir = open_or_create_private_dir(&dir_path)?;
            spawn_detached_daemon(&vdir, &spawn_cmd, ready_timeout)
        })
        .await
        .map_err(|e| DaemonError::Protocol(format!("spawn task panicked: {e}")))??;

        let expected_epoch = match ready {
            ReadyReply::Ok { daemon_epoch } => Some(daemon_epoch),
            ReadyReply::Err(msg) => {
                drop(startup_lock);
                return Err(DaemonError::SpawnFailed(msg));
            }
            ReadyReply::AlreadyRunning => None,
        };

        // Connect to newly spawned daemon and verify `HelloAck.daemon_epoch == ready_epoch`.
        let connect_deadline = Instant::now() + Duration::from_millis(1500);
        let client = loop {
            match try_connect_and_hello(&dir, config, false).await {
                FastAttempt::Connected(client) => break client,
                FastAttempt::HardError(err) => {
                    drop(startup_lock);
                    return Err(err);
                }
                FastAttempt::DrainAndUpgrade(_, _) => {
                    drop(startup_lock);
                    return Err(DaemonError::Protocol(
                        "newly spawned daemon reported incompatible schema".to_string(),
                    ));
                }
                FastAttempt::FallbackSlowPath => {
                    if Instant::now() >= connect_deadline {
                        drop(startup_lock);
                        return Err(DaemonError::Timeout(
                            "connect to newly spawned daemon",
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(15)).await;
                }
            }
        };

        if let Some(expected) = expected_epoch
            && client.ack.daemon_epoch != expected
        {
            drop(startup_lock);
            return Err(DaemonError::EpochMismatch {
                expected,
                actual: client.ack.daemon_epoch,
            });
        }

        drop(startup_lock);
        Ok(client)
    }

    pub fn ack(&self) -> &HelloAckPayload {
        &self.ack
    }

    pub fn upgrade_available(&self) -> bool {
        self.upgrade_available
    }

    pub fn peer_pid(&self) -> u32 {
        self.peer_pid
    }

    fn alloc_request_id(&self) -> u64 {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id > MAX_SAFE_ID {
            self.next_request_id.store(2, Ordering::Relaxed);
            return 2;
        }
        id
    }

    /// Sends an IPC request and awaits its matching response frame.
    pub async fn request(
        &mut self,
        opcode: IpcOpcode,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, DaemonError> {
        let request_id = self.alloc_request_id();
        let frame = IpcFrame {
            opcode,
            request_id,
            payload,
        };
        write_ipc_frame(&mut self.stream, &frame).await?;
        let Some(resp) = read_ipc_frame(&mut self.stream).await? else {
            return Err(DaemonError::Protocol(
                "daemon closed connection before replying".to_string(),
            ));
        };
        if resp.request_id != request_id {
            return Err(DaemonError::Protocol(format!(
                "response request_id mismatch: expected {request_id}, got {}",
                resp.request_id
            )));
        }
        if resp.opcode == IpcOpcode::Error {
            let (code, retryable, message) = decode_error_payload(&resp.payload)?;
            return Err(DaemonError::RemoteError {
                code,
                retryable,
                message,
            });
        }
        if resp.opcode != opcode {
            return Err(DaemonError::Protocol(format!(
                "unexpected response opcode {:?} for request {:?}",
                resp.opcode, opcode
            )));
        }
        Ok(resp.payload)
    }

    /// Sends a `Cancel` frame targeting an in-flight `request_id` on this connection.
    pub async fn send_cancel(&mut self, target_request_id: u64) -> Result<(), DaemonError> {
        let request_id = self.alloc_request_id();
        let frame = IpcFrame {
            opcode: IpcOpcode::Cancel,
            request_id,
            payload: encode_cancel_payload(target_request_id)?,
        };
        write_ipc_frame(&mut self.stream, &frame).await
    }

    /// Sends a `DrainAndShutdown` request to the connected daemon.
    pub async fn send_drain_and_shutdown(&mut self, mode: DrainMode) -> Result<(), DaemonError> {
        let _ = self
            .request(IpcOpcode::DrainAndShutdown, encode_drain_payload(mode))
            .await?;
        Ok(())
    }

    /// Splits into raw underlying Tokio `UnixStream` for multiplexed callers.
    pub fn into_parts(self) -> (UnixStream, HelloAckPayload, bool, u32) {
        (
            self.stream,
            self.ack,
            self.upgrade_available,
            self.peer_pid,
        )
    }
}

async fn try_connect_and_hello(
    dir: &VerifiedDir,
    config: &ClientConfig,
    retry_refused: bool,
) -> FastAttempt {
    let sock_path = dir.path().join(SOCKET_FILE_NAME);
    let connect_deadline = Instant::now() + config.connect_timeout;
    let refused_deadline = Instant::now() + Duration::from_millis(100);

    let mut stream = loop {
        let remaining = connect_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return FastAttempt::FallbackSlowPath;
        }
        match tokio::time::timeout(remaining, UnixStream::connect(&sock_path)).await {
            Ok(Ok(s)) => break s,
            Ok(Err(err)) => {
                if retry_refused
                    && err.kind() == std::io::ErrorKind::ConnectionRefused
                    && Instant::now() < refused_deadline
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                return FastAttempt::FallbackSlowPath;
            }
            Err(_) => return FastAttempt::FallbackSlowPath,
        }
    };

    let peer_pid = match verify_peer_same_uid(stream.as_raw_fd()) {
        Ok(pid) => pid,
        Err(err @ DaemonError::PeerCredMismatch { .. }) => return FastAttempt::HardError(err),
        Err(_) => return FastAttempt::FallbackSlowPath,
    };

    let hello_frame = IpcFrame {
        opcode: IpcOpcode::Hello,
        request_id: 1,
        payload: encode_hello(&config.hello),
    };

    let ack_frame = match tokio::time::timeout(config.hello_timeout, async {
        write_ipc_frame(&mut stream, &hello_frame).await?;
        read_ipc_frame(&mut stream).await
    })
    .await
    {
        Ok(Ok(Some(frame))) => frame,
        // Never kill a daemon on Hello timeout or reset/EOF — fall through to Slow Path.
        _ => return FastAttempt::FallbackSlowPath,
    };

    if ack_frame.opcode == IpcOpcode::Error {
        if let Ok((_code, retryable, _msg)) = decode_error_payload(&ack_frame.payload)
            && retryable
        {
            return FastAttempt::FallbackSlowPath;
        }
        return FastAttempt::FallbackSlowPath;
    }

    if ack_frame.opcode != IpcOpcode::HelloAck || ack_frame.request_id != 1 {
        return FastAttempt::FallbackSlowPath;
    }

    let ack = match decode_hello_ack(&ack_frame.payload) {
        Ok(a) => a,
        Err(err) => return FastAttempt::HardError(DaemonError::IpcWire(err)),
    };

    if ack.device_id != config.device_id {
        return FastAttempt::HardError(DaemonError::DeviceIdMismatch {
            expected: config.device_id,
            actual: ack.device_id,
        });
    }

    match evaluate_hello_compat(
        &config.hello,
        ack.ipc_schema_ver,
        ack.build_order,
        ack.build_digest,
        config.read_only_cli,
        config.on_disk_exe_matches_local,
    ) {
        HelloCompatAction::Coexist { upgrade_available } => FastAttempt::Connected(DaemonClient {
            stream,
            ack,
            upgrade_available,
            peer_pid,
            next_request_id: AtomicU64::new(2),
        }),
        HelloCompatAction::DrainAndUpgrade => FastAttempt::DrainAndUpgrade(stream, ack),
        HelloCompatAction::ErrorIncompatibleSchema { daemon_schema } => {
            FastAttempt::HardError(DaemonError::IncompatibleSchema {
                local_schema: config.hello.ipc_schema_ver,
                daemon_schema,
                daemon_exe_path: ack.exe_path,
            })
        }
    }
}
