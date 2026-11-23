//! Error types for the local daemon runtime, OS primitives, and binary IPC.

use core::fmt;
use std::io;
use std::path::PathBuf;

use outpost_core::ipc_wire::IpcWireError;
use outpost_core::storage_codec::StorageCodecError;

#[derive(Debug)]
pub enum DaemonError {
    Io {
        context: &'static str,
        source: io::Error,
    },
    InvalidDeviceId(u64),
    InvalidPath {
        path: PathBuf,
        reason: &'static str,
    },
    SunPathTooLong {
        path: PathBuf,
        len: usize,
        max: usize,
    },
    InsecureDirectory {
        path: PathBuf,
        reason: &'static str,
    },
    SymlinkRejected {
        path: PathBuf,
    },
    LockTimeout {
        lock_name: &'static str,
    },
    PeerCredMismatch {
        expected_uid: u32,
        actual_uid: u32,
    },
    DeviceIdMismatch {
        expected: u64,
        actual: u64,
    },
    EpochMismatch {
        expected: u64,
        actual: u64,
    },
    IncompatibleSchema {
        local_schema: u32,
        daemon_schema: u32,
        daemon_exe_path: String,
    },
    DaemonNotRunning,
    DaemonWedged {
        reason: &'static str,
    },
    SpawnFailed(String),
    ReadinessTimeout,
    ReadinessProtocol(String),
    ProcessVerificationFailed {
        pid: u32,
        reason: &'static str,
    },
    IpcWire(IpcWireError),
    StorageCodec(StorageCodecError),
    Protocol(String),
    RemoteError {
        code: u16,
        retryable: bool,
        message: String,
    },
    Timeout(&'static str),
}

impl DaemonError {
    pub fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::InvalidDeviceId(id) => write!(f, "invalid device_id: {id}"),
            Self::InvalidPath { path, reason } => {
                write!(f, "invalid path '{}': {reason}", path.display())
            }
            Self::SunPathTooLong { path, len, max } => write!(
                f,
                "unix socket path '{}' is {len} bytes (exceeds limit of {max} bytes)",
                path.display()
            ),
            Self::InsecureDirectory { path, reason } => {
                write!(f, "insecure directory '{}': {reason}", path.display())
            }
            Self::SymlinkRejected { path } => {
                write!(f, "symlink rejected at '{}'", path.display())
            }
            Self::LockTimeout { lock_name } => {
                write!(f, "timed out acquiring lock '{lock_name}'")
            }
            Self::PeerCredMismatch {
                expected_uid,
                actual_uid,
            } => write!(
                f,
                "peer credential UID mismatch: expected {expected_uid}, got {actual_uid}"
            ),
            Self::DeviceIdMismatch { expected, actual } => write!(
                f,
                "daemon device_id mismatch: expected {expected}, got {actual}"
            ),
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "daemon epoch mismatch: expected {expected}, got {actual}"
            ),
            Self::IncompatibleSchema {
                local_schema,
                daemon_schema,
                daemon_exe_path,
            } => write!(
                f,
                "daemon_schema_mismatch_restart_mcp: local schema {local_schema}, running daemon schema {daemon_schema} ({daemon_exe_path})"
            ),
            Self::DaemonNotRunning => write!(f, "daemon is not running and auto-spawn is disabled"),
            Self::DaemonWedged { reason } => {
                write!(f, "daemon_wedged_run_force_stop: {reason}")
            }
            Self::SpawnFailed(msg) => write!(f, "daemon spawn failed: {msg}"),
            Self::ReadinessTimeout => write!(f, "timed out waiting for daemon readiness pipe"),
            Self::ReadinessProtocol(msg) => write!(f, "daemon readiness protocol error: {msg}"),
            Self::ProcessVerificationFailed { pid, reason } => {
                write!(f, "process verification failed for pid {pid}: {reason}")
            }
            Self::IpcWire(err) => write!(f, "IPC wire error: {err}"),
            Self::StorageCodec(err) => write!(f, "storage codec error: {err}"),
            Self::Protocol(msg) => write!(f, "IPC protocol error: {msg}"),
            Self::RemoteError {
                code,
                retryable,
                message,
            } => write!(
                f,
                "daemon error (code={code}, retryable={retryable}): {message}"
            ),
            Self::Timeout(what) => write!(f, "timed out: {what}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::IpcWire(err) => Some(err),
            Self::StorageCodec(err) => Some(err),
            _ => None,
        }
    }
}

impl From<IpcWireError> for DaemonError {
    fn from(value: IpcWireError) -> Self {
        Self::IpcWire(value)
    }
}

impl From<StorageCodecError> for DaemonError {
    fn from(value: StorageCodecError) -> Self {
        Self::StorageCodec(value)
    }
}
