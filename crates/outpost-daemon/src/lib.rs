//! Non-sucky OS local sidecar daemon runtime, locking, atomic socket publish,
//! double-fork zero-zombie spawning, watchdog inode self-fencing, and binary IPC.

#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

pub mod cancel;
pub mod client;
pub mod error;
pub mod ipc_codec;
pub mod os_unix;
pub mod runtime_dir;
pub mod server;
pub mod state_io;

pub use cancel::CancellationToken;
pub use client::{ClientConfig, DaemonClient};
pub use error::DaemonError;
pub use ipc_codec::{
    DrainMode, decode_cancel_payload, decode_drain_payload, decode_error_payload, decode_hello,
    decode_hello_ack, encode_cancel_payload, encode_drain_payload, encode_error_payload,
    encode_hello, encode_hello_ack, read_ipc_frame, write_ipc_frame,
};
pub use os_unix::{
    CACHEDIR_TAG_CONTENT, DAEMON_INFO_NAME, DAEMON_LOCK_NAME, DAEMON_LOG_NAME, FlockGuard,
    ForceStopOutcome, MACOS_BACKUP_EXCLUDE_BPLIST, MACOS_BACKUP_EXCLUDE_XATTR, PeerCreds,
    PublishedListener, READY_FD, STARTUP_LOCK_NAME, SpawnCommand, current_process_start_token,
    daemonize_in_child, exclude_dir_from_backup, fill_random, force_stop_daemon,
    generate_daemon_epoch, install_daemon_process_hygiene, monotonic_boottime_ms,
    open_rotating_log, process_start_token, publish_unix_listener, send_ready_reply_and_close,
    spawn_detached_daemon, verify_peer_creds, verify_peer_same_uid, write_log_lock_free,
};
pub use runtime_dir::{
    MAX_SUN_PATH_BYTES, SOCKET_FILE_NAME, TEMP_SOCKET_SAMPLE_NAME, VerifiedDir,
    format_device_dir_name, open_or_create_private_dir, resolve_runtime_dir, resolve_state_dir,
    validate_path_hygiene, validate_sun_path_budget, validate_sun_path_budget_with_limit,
};
pub use server::{DaemonConfig, DaemonExitReason, DaemonHandler, DaemonServer, LifecycleState};
pub use state_io::{
    STATE_LOCK_NAME, StateLock, atomic_write_in_dir, atomic_write_in_dir_no_replace,
    open_dir_nofollow, read_file_in_dir, read_regular_file_bounded_nofollow,
};
