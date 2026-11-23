//! OS-level daemon primitives for macOS & Linux:
//! - Never-unlinked `flock(2)` guards (`startup.lock`, `daemon.lock`)
//! - Mutual kernel peer credentials (`SO_PEERCRED`+`SO_PEERPIDFD` / `getpeereid`+`LOCAL_PEERPID`)
//! - Native process start tokens (same OS API on both daemon & verifier)
//! - Sleep-aware monotonic clock (`mach_continuous_time` / `CLOCK_BOOTTIME`)
//! - Atomic Unix socket publish (`bind -> chmod(0600) -> listen(128) -> link -> unlink`)
//! - Rotating `daemon.log` + lock-free `libc::write` panic/watchdog logging
//! - Zero-FD-leak, zero-zombie detached spawning (`posix_spawn` / `close_range` + double-fork)
//! - Verified `force_stop_daemon` (`SIGTERM` -> `SIGKILL` escalation)

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use mp_protocol::MAX_SAFE_ID;
use outpost_core::ipc_wire::{
    MAX_READY_ERR_BYTES, ReadyReply, decode_ready_reply, encode_ready_reply,
};
use outpost_core::storage_codec::decode_daemon_info;

use crate::error::DaemonError;
use crate::runtime_dir::{
    SOCKET_FILE_NAME, VerifiedDir, fstat_fd, leaf_name_to_cstring, path_to_cstring, stat_dev_ino,
    validate_sun_path_budget,
};
use crate::state_io::read_file_in_dir;

pub const STARTUP_LOCK_NAME: &str = "startup.lock";
pub const DAEMON_LOCK_NAME: &str = "daemon.lock";
pub const DAEMON_INFO_NAME: &str = "daemon.info";
pub const DAEMON_LOG_NAME: &str = "daemon.log";
pub const DAEMON_LOG_OLD_NAME: &str = "daemon.log.1";
pub const READY_FD: RawFd = 3;
pub const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

static DAEMON_LOG_FD: AtomicI32 = AtomicI32::new(-1);

/// Sleep-aware monotonic timestamp in milliseconds:
/// - macOS: `mach_continuous_time()` (advances during laptop sleep)
/// - Linux: `CLOCK_BOOTTIME` (advances during system suspend)
pub fn monotonic_boottime_ms() -> u64 {
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        struct MachTimebaseInfo {
            numer: u32,
            denom: u32,
        }
        unsafe extern "C" {
            fn mach_continuous_time() -> u64;
            fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
        }
        let mut info = MachTimebaseInfo { numer: 1, denom: 1 };
        let _ = unsafe { mach_timebase_info(&mut info) };
        let ticks = unsafe { mach_continuous_time() };
        let denom = u128::from(info.denom.max(1));
        let nanos = u128::from(ticks).saturating_mul(u128::from(info.numer)) / denom;
        (nanos / 1_000_000) as u64
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
        if rc != 0 {
            let _ = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        }
        let secs = ts.tv_sec.max(0) as u64;
        let millis = (ts.tv_nsec.max(0) as u64) / 1_000_000;
        secs.saturating_mul(1000).saturating_add(millis)
    }
}

/// Fills `buf` with OS CSPRNG bytes.
pub fn fill_random(buf: &mut [u8]) {
    #[cfg(target_os = "macos")]
    {
        unsafe {
            libc::arc4random_buf(buf.as_mut_ptr().cast(), buf.len());
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut offset = 0usize;
        while offset < buf.len() {
            let Some(dst) = buf.get_mut(offset..) else {
                break;
            };
            let n = unsafe { libc::getrandom(dst.as_mut_ptr().cast(), dst.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            offset = offset.saturating_add(n as usize);
        }
        if offset < buf.len() {
            // Fallback to /dev/urandom if getrandom ever failed unexpectedly.
            if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                use std::io::Read;
                if let Some(dst) = buf.get_mut(offset..) {
                    let _ = f.read_exact(dst);
                }
            }
        }
    }
}

pub fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    fill_random(&mut b);
    u32::from_le_bytes(b)
}

pub fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    fill_random(&mut b);
    u64::from_le_bytes(b)
}

/// Generates a non-zero CSPRNG `daemon_epoch` strictly within `1..=MAX_SAFE_ID`.
pub fn generate_daemon_epoch() -> u64 {
    (random_u64() % MAX_SAFE_ID).saturating_add(1)
}

/// Lock-free write to the daemon log file descriptor (safe in panic hooks & watchdog).
pub fn write_log_lock_free(msg: &[u8]) {
    let fd = DAEMON_LOG_FD.load(Ordering::Acquire);
    let target_fd = if fd >= 0 { fd } else { libc::STDERR_FILENO };
    let mut remaining = msg;
    while !remaining.is_empty() {
        let n = unsafe { libc::write(target_fd, remaining.as_ptr().cast(), remaining.len()) };
        if n <= 0 {
            break;
        }
        remaining = remaining.get(n as usize..).unwrap_or_default();
    }
}

/// Opens rotating `daemon.log` (`2 x 4 MiB`, `0600`) inside `dir`.
pub fn open_rotating_log(dir: &VerifiedDir) -> Result<OwnedFd, DaemonError> {
    if let Some(st) = dir.stat_entry(DAEMON_LOG_NAME)?
        && st.st_size >= 0
        && (st.st_size as u64) >= MAX_LOG_BYTES
    {
        let cur_c = leaf_name_to_cstring(DAEMON_LOG_NAME)?;
        let old_c = leaf_name_to_cstring(DAEMON_LOG_OLD_NAME)?;
        unsafe {
            let _ = libc::renameat(
                dir.as_raw_fd(),
                cur_c.as_ptr(),
                dir.as_raw_fd(),
                old_c.as_ptr(),
            );
        }
    }
    let cname = leaf_name_to_cstring(DAEMON_LOG_NAME)?;
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(DaemonError::io(
            "openat daemon.log",
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Installs single-threaded daemon process hygiene BEFORE starting Tokio:
/// `umask(0077)`, `SIGPIPE = SIG_IGN`, stores raw log FD, and installs a lock-free
/// panic hook (`libc::write(log_fd)` + `libc::_exit(1)`).
pub fn install_daemon_process_hygiene(log_fd: RawFd) {
    unsafe {
        libc::umask(0o077);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    DAEMON_LOG_FD.store(log_fd, Ordering::Release);
    std::panic::set_hook(Box::new(|info| {
        write_log_lock_free(b"outpost-daemon FATAL PANIC: ");
        if let Some(loc) = info.location() {
            write_log_lock_free(loc.file().as_bytes());
            write_log_lock_free(b"\n");
        } else {
            write_log_lock_free(b"(unknown location)\n");
        }
        unsafe {
            libc::_exit(1);
        }
    }));
}

/// Never-unlinked `flock(2)` guard on a lock file inside a `VerifiedDir`.
#[derive(Debug)]
pub struct FlockGuard {
    fd: OwnedFd,
    dev: u64,
    ino: u64,
}

impl FlockGuard {
    /// Opens (creating if needed) a never-unlinked lock file and tries `LOCK_EX | LOCK_NB`.
    pub fn try_lock_exclusive(
        dir: &VerifiedDir,
        name: &'static str,
    ) -> Result<Option<Self>, DaemonError> {
        let (fd, dev, ino) = open_lock_file(dir, name)?;
        let rc = loop {
            let r = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if r == 0 {
                break 0;
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(DaemonError::io("flock(LOCK_EX | LOCK_NB)", err));
        };
        let _ = rc;
        Ok(Some(Self { fd, dev, ino }))
    }

    /// Acquires `flock(LOCK_EX)` with bounded polling until `deadline`.
    pub fn lock_exclusive_with_deadline(
        dir: &VerifiedDir,
        name: &'static str,
        deadline: Duration,
    ) -> Result<Self, DaemonError> {
        let start = Instant::now();
        let mut sleep_ms = 5u64;
        loop {
            if let Some(guard) = Self::try_lock_exclusive(dir, name)? {
                return Ok(guard);
            }
            let elapsed = start.elapsed();
            if elapsed >= deadline {
                return Err(DaemonError::LockTimeout { lock_name: name });
            }
            let remaining = deadline.saturating_sub(elapsed);
            let nap = Duration::from_millis(sleep_ms).min(remaining);
            std::thread::sleep(nap);
            sleep_ms = (sleep_ms.saturating_mul(2)).min(50);
        }
    }

    /// Probes whether the lock file is currently unheld without keeping it locked.
    pub fn probe_lock_free(dir: &VerifiedDir, name: &'static str) -> Result<bool, DaemonError> {
        Ok(Self::try_lock_exclusive(dir, name)?.is_some())
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn dev(&self) -> u64 {
        self.dev
    }

    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// Touches atime/mtime on the open lock file to prevent macOS `dirhelper` / `tmpfiles.d` purging.
    pub fn touch_atime(&self) {
        unsafe {
            let _ = libc::futimens(self.fd.as_raw_fd(), std::ptr::null());
        }
    }
}

fn open_lock_file(dir: &VerifiedDir, name: &str) -> Result<(OwnedFd, u64, u64), DaemonError> {
    let cname = leaf_name_to_cstring(name)?;
    let raw_fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw_fd < 0 {
        return Err(DaemonError::io("openat lock file", io::Error::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let st = fstat_fd(fd.as_raw_fd())?;
    let euid = unsafe { libc::geteuid() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_uid != euid {
        return Err(DaemonError::InsecureDirectory {
            path: dir.path().join(name),
            reason: "lock file is not a regular file owned by current UID",
        });
    }
    let (dev, ino) = stat_dev_ino(&st);
    Ok((fd, dev, ino))
}

/// Kernel-verified Unix domain socket peer credentials.
#[derive(Debug)]
pub struct PeerCreds {
    pub uid: u32,
    pub pid: u32,
    pub pidfd: Option<OwnedFd>,
}

/// Verifies that the connected Unix socket peer has `peer_uid == geteuid()` and
/// returns the kernel-verified peer PID.
pub fn verify_peer_same_uid(fd: RawFd) -> Result<u32, DaemonError> {
    Ok(verify_peer_creds(fd)?.pid)
}

/// Full peer credential inspection (including optional Linux `SO_PEERPIDFD`).
pub fn verify_peer_creds(fd: RawFd) -> Result<PeerCreds, DaemonError> {
    let expected_uid = unsafe { libc::geteuid() };

    #[cfg(target_os = "macos")]
    {
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };
        if rc != 0 {
            return Err(DaemonError::io("getpeereid", io::Error::last_os_error()));
        }
        if euid != expected_uid {
            return Err(DaemonError::PeerCredMismatch {
                expected_uid,
                actual_uid: euid,
            });
        }
        const SOL_LOCAL: libc::c_int = 0;
        const LOCAL_PEERPID: libc::c_int = 0x002;
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(DaemonError::io(
                "getsockopt(LOCAL_PEERPID)",
                io::Error::last_os_error(),
            ));
        }
        if pid <= 0 {
            return Err(DaemonError::Protocol(format!(
                "kernel reported invalid LOCAL_PEERPID {pid}"
            )));
        }
        Ok(PeerCreds {
            uid: euid,
            pid: pid as u32,
            pidfd: None,
        })
    }

    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(DaemonError::io(
                "getsockopt(SO_PEERCRED)",
                io::Error::last_os_error(),
            ));
        }
        if cred.uid != expected_uid {
            return Err(DaemonError::PeerCredMismatch {
                expected_uid,
                actual_uid: cred.uid,
            });
        }
        if cred.pid <= 0 {
            return Err(DaemonError::Protocol(format!(
                "kernel reported invalid SO_PEERCRED pid {}",
                cred.pid
            )));
        }
        // Best-effort SO_PEERPIDFD (Linux 6.5+, constant 77 on x86_64/aarch64).
        const SO_PEERPIDFD: libc::c_int = 77;
        let mut raw_pidfd: libc::c_int = -1;
        let mut pidfd_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let pidfd = if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&mut raw_pidfd as *mut libc::c_int).cast(),
                &mut pidfd_len,
            )
        } == 0
            && raw_pidfd >= 0
        {
            Some(unsafe { OwnedFd::from_raw_fd(raw_pidfd) })
        } else {
            None
        };
        Ok(PeerCreds {
            uid: cred.uid,
            pid: cred.pid as u32,
            pidfd,
        })
    }
}

/// Returns the current process's native OS start token using the exact same OS API
/// as `process_start_token(pid)` (zero wall-clock cross-conversion!).
pub fn current_process_start_token() -> Result<u64, DaemonError> {
    let pid = std::process::id();
    process_start_token(pid)?.ok_or(DaemonError::ProcessVerificationFailed {
        pid,
        reason: "current process start token unavailable",
    })
}

/// Queries the native OS start token for `pid`:
/// - macOS: `proc_pidinfo(PROC_PIDTBSDINFO)` microsecond start time (`tvsec * 1_000_000 + tvusec`)
/// - Linux: raw `/proc/<pid>/stat` field 22 ticks
///
/// Returns `Ok(None)` if `pid` does not exist (`ESRCH` / `ENOENT`).
pub fn process_start_token(pid: u32) -> Result<Option<u64>, DaemonError> {
    if pid == 0 {
        return Ok(None);
    }

    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let expected_size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let rc = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                expected_size,
            )
        };
        if rc <= 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            // proc_pidinfo returns 0 with errno == 0 when a process just vanished.
            if rc == 0 && err.raw_os_error() == Some(0) {
                return Ok(None);
            }
            return Err(DaemonError::io("proc_pidinfo(PROC_PIDTBSDINFO)", err));
        }
        if rc < expected_size {
            return Ok(None);
        }
        let token = info
            .pbi_start_tvsec
            .wrapping_mul(1_000_000)
            .wrapping_add(info.pbi_start_tvusec);
        Ok(Some(token))
    }

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/stat");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err)
                if err.kind() == io::ErrorKind::NotFound
                    || err.raw_os_error() == Some(libc::ESRCH) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(DaemonError::io("read /proc/<pid>/stat", err)),
        };
        let Some(rparen) = content.rfind(')') else {
            return Err(DaemonError::ProcessVerificationFailed {
                pid,
                reason: "malformed /proc/<pid>/stat (missing ')')",
            });
        };
        let after = content.get(rparen + 1..).unwrap_or_default();
        // Field 3 (state) is index 0 after ')'; field 22 (starttime) is index 19.
        let Some(field22) = after.split_whitespace().nth(19) else {
            return Err(DaemonError::ProcessVerificationFailed {
                pid,
                reason: "malformed /proc/<pid>/stat (missing field 22)",
            });
        };
        let ticks = field22
            .parse::<u64>()
            .map_err(|_| DaemonError::ProcessVerificationFailed {
                pid,
                reason: "invalid starttime ticks in /proc/<pid>/stat",
            })?;
        Ok(Some(ticks))
    }
}

/// Result of atomically publishing `d.sock` under `daemon.lock`.
#[derive(Debug)]
pub struct PublishedListener {
    pub listener: StdUnixListener,
    pub dir_dev: u64,
    pub dir_ino: u64,
    pub lock_dev: u64,
    pub lock_ino: u64,
    pub sock_dev: u64,
    pub sock_ino: u64,
    pub used_atomic_link: bool,
}

/// Publishes `d.sock` atomically while holding `daemon.lock`:
/// 1. Unlinks stale `d.sock` and any leftover `t.*` entries in `dir`.
/// 2. Binds `t.<8hex>`, `chmod(0600)`, `listen(128)`.
/// 3. `linkat(t.<8hex>, d.sock)` + `unlinkat(t.<8hex>)` (falling back to direct
///    `bind("d.sock")` + `chmod(0600)` + `listen(128)` only on `EOPNOTSUPP`/`EPERM`).
/// 4. Records `(dir_dev, dir_ino, lock_dev, lock_ino, sock_dev, sock_ino)`.
pub fn publish_unix_listener(
    dir: &VerifiedDir,
    daemon_lock: &FlockGuard,
) -> Result<PublishedListener, DaemonError> {
    validate_sun_path_budget(dir.path())?;

    // 1. Clean stale `d.sock` and any leftover `t.*` entries under `daemon.lock`.
    unlink_stale_socket_files(dir)?;

    let tmp_name = format!("t.{:08x}", random_u32());
    let tmp_path = dir.path().join(&tmp_name);
    let final_path = dir.path().join(SOCKET_FILE_NAME);
    let tmp_c = leaf_name_to_cstring(&tmp_name)?;
    let final_c = leaf_name_to_cstring(SOCKET_FILE_NAME)?;

    // 2. Bind `t.<8hex>`, `chmod(0600)`, `listen(128)`.
    let sock_fd = bind_chmod_listen_unix(&tmp_path, dir.as_raw_fd(), &tmp_c)?;

    // 3. Atomic publish via `linkat` + `unlinkat`.
    let link_rc = unsafe {
        libc::linkat(
            dir.as_raw_fd(),
            tmp_c.as_ptr(),
            dir.as_raw_fd(),
            final_c.as_ptr(),
            0,
        )
    };
    let (listener_fd, used_atomic_link) = if link_rc == 0 {
        unsafe {
            let _ = libc::unlinkat(dir.as_raw_fd(), tmp_c.as_ptr(), 0);
        }
        (sock_fd, true)
    } else {
        let link_err = io::Error::last_os_error();
        let raw = link_err.raw_os_error();
        // Clean up temp socket before fallback or error.
        drop(sock_fd);
        unsafe {
            let _ = libc::unlinkat(dir.as_raw_fd(), tmp_c.as_ptr(), 0);
        }
        if raw == Some(libc::EOPNOTSUPP) || raw == Some(libc::EPERM) {
            let direct_fd = bind_chmod_listen_unix(&final_path, dir.as_raw_fd(), &final_c)?;
            (direct_fd, false)
        } else {
            return Err(DaemonError::io("linkat unix socket", link_err));
        }
    };

    // 4. Record `(sock_dev, sock_ino)` and verify `d.sock` is a socket.
    let sock_st = dir
        .stat_entry(SOCKET_FILE_NAME)?
        .ok_or_else(|| DaemonError::Protocol("published d.sock vanished immediately".to_string()))?;
    if (sock_st.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
        return Err(DaemonError::Protocol(
            "published d.sock is not a Unix domain socket".to_string(),
        ));
    }

    let listener = unsafe { StdUnixListener::from_raw_fd(listener_fd.into_raw_fd()) };
    listener
        .set_nonblocking(true)
        .map_err(|e| DaemonError::io("set_nonblocking listener", e))?;

    let (sock_dev, sock_ino) = stat_dev_ino(&sock_st);
    Ok(PublishedListener {
        listener,
        dir_dev: dir.dev(),
        dir_ino: dir.ino(),
        lock_dev: daemon_lock.dev(),
        lock_ino: daemon_lock.ino(),
        sock_dev,
        sock_ino,
        used_atomic_link,
    })
}

fn unlink_stale_socket_files(dir: &VerifiedDir) -> Result<(), DaemonError> {
    let sock_c = leaf_name_to_cstring(SOCKET_FILE_NAME)?;
    unsafe {
        let _ = libc::unlinkat(dir.as_raw_fd(), sock_c.as_ptr(), 0);
    }
    let entries = std::fs::read_dir(dir.path())
        .map_err(|e| DaemonError::io("read_dir cleanup stale t.*", e))?;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let fname = entry.file_name();
        let bytes = fname.as_bytes();
        if bytes.starts_with(b"t.")
            && let Ok(name_str) = std::str::from_utf8(bytes)
            && let Ok(cname) = leaf_name_to_cstring(name_str)
        {
            unsafe {
                let _ = libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0);
            }
        }
    }
    Ok(())
}

fn bind_chmod_listen_unix(
    abs_path: &Path,
    dirfd: RawFd,
    leaf_c: &CString,
) -> Result<OwnedFd, DaemonError> {
    let path_bytes = abs_path.as_os_str().as_bytes();
    let max_sun = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path)
        - 1;
    if path_bytes.len() > max_sun {
        return Err(DaemonError::SunPathTooLong {
            path: abs_path.to_path_buf(),
            len: path_bytes.len(),
            max: max_sun,
        });
    }

    #[cfg(target_os = "linux")]
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let raw_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };

    if raw_fd < 0 {
        return Err(DaemonError::io("socket(AF_UNIX)", io::Error::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    set_cloexec(fd.as_raw_fd())?;

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            path_bytes.as_ptr(),
            addr.sun_path.as_mut_ptr().cast::<u8>(),
            path_bytes.len(),
        );
    }
    let addr_len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path_bytes.len() + 1)
        as libc::socklen_t;
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = addr_len as u8;
    }

    let bind_rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if bind_rc != 0 {
        return Err(DaemonError::io("bind unix socket", io::Error::last_os_error()));
    }

    let chmod_rc = unsafe { libc::fchmodat(dirfd, leaf_c.as_ptr(), 0o600, 0) };
    if chmod_rc != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            let _ = libc::unlinkat(dirfd, leaf_c.as_ptr(), 0);
        }
        return Err(DaemonError::io("fchmodat(0600) unix socket", err));
    }

    let listen_rc = unsafe { libc::listen(fd.as_raw_fd(), 128) };
    if listen_rc != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            let _ = libc::unlinkat(dirfd, leaf_c.as_ptr(), 0);
        }
        return Err(DaemonError::io("listen(128) unix socket", err));
    }

    Ok(fd)
}

fn set_cloexec(fd: RawFd) -> Result<(), DaemonError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(DaemonError::io("fcntl(F_GETFD)", io::Error::last_os_error()));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(DaemonError::io("fcntl(F_SETFD)", io::Error::last_os_error()));
    }
    Ok(())
}

/// Duplicates `fd` onto an FD `>= min_fd` with `FD_CLOEXEC` set so `dup2(..., 0..=3)`
/// can never collide with its own source descriptors.
fn dup_above_cloexec(fd: RawFd, min_fd: RawFd) -> Result<OwnedFd, DaemonError> {
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min_fd) };
    if new_fd < 0 {
        return Err(DaemonError::io(
            "fcntl(F_DUPFD_CLOEXEC)",
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

fn create_cloexec_pipe() -> Result<(OwnedFd, OwnedFd), DaemonError> {
    let mut fds = [-1 as libc::c_int; 2];
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(DaemonError::io("pipe2", io::Error::last_os_error()));
        }
        let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok((r, w))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(DaemonError::io("pipe", io::Error::last_os_error()));
        }
        let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        set_cloexec(r.as_raw_fd())?;
        set_cloexec(w.as_raw_fd())?;
        Ok((r, w))
    }
}

/// Command specification for spawning a detached daemon binary.
#[derive(Debug, Clone)]
pub struct SpawnCommand {
    pub exe_path: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Double-forks the launcher child into a detached session grandchild (`setsid()` +
/// second `fork()` + launcher parent `_exit(0)` immediately reaped by the caller).
///
/// MUST be called single-threaded BEFORE starting Tokio!
pub fn daemonize_in_child() -> Result<(), DaemonError> {
    let sid = unsafe { libc::setsid() };
    if sid < 0 {
        return Err(DaemonError::io("setsid", io::Error::last_os_error()));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(DaemonError::io("second fork", io::Error::last_os_error()));
    }
    if pid > 0 {
        // Launcher parent exits immediately without running destructors or touching fd 3.
        unsafe {
            libc::_exit(0);
        }
    }
    Ok(())
}

/// Writes a unified binary `ReadyReply` to `fd` (normally fd 3) and closes it.
pub fn send_ready_reply_and_close(fd: RawFd, reply: &ReadyReply) {
    if fd < 0 {
        return;
    }
    if let Ok(encoded) = encode_ready_reply(reply) {
        let mut rem = encoded.as_slice();
        while !rem.is_empty() {
            let n = unsafe { libc::write(fd, rem.as_ptr().cast(), rem.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if n == 0 {
                break;
            }
            rem = rem.get(n as usize..).unwrap_or_default();
        }
    }
    unsafe {
        let _ = libc::close(fd);
    }
}

/// Spawns a detached daemon process with:
/// - `O_CLOEXEC` readiness pipe dup'd to FD 3 in the child
/// - `stdin` / `stdout` redirected to `/dev/null`
/// - `stderr` redirected to rotating `daemon.log`
/// - ZERO leaked host FDs `>= 4` (`POSIX_SPAWN_CLOEXEC_DEFAULT` on macOS;
///   async-signal-safe `close_range(4, u32::MAX, 0)` + fallback on Linux)
/// - Immediate reaping of the double-fork launcher child (zero zombies!)
/// - Bounded read of unified binary `ReadyReply` under `ready_timeout`.
pub fn spawn_detached_daemon(
    dir: &VerifiedDir,
    cmd: &SpawnCommand,
    ready_timeout: Duration,
) -> Result<ReadyReply, DaemonError> {
    let (pipe_r, pipe_w_raw) = create_cloexec_pipe()?;
    let log_fd_raw = open_rotating_log(dir)?;
    let devnull_raw = {
        let raw = unsafe {
            libc::open(
                c"/dev/null".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(DaemonError::io("open /dev/null", io::Error::last_os_error()));
        }
        unsafe { OwnedFd::from_raw_fd(raw) }
    };

    // Move all source FDs to >= 4 so dup2(..., 0..=3) can never collide with sources.
    let pipe_w = dup_above_cloexec(pipe_w_raw.as_raw_fd(), 4)?;
    let log_fd = dup_above_cloexec(log_fd_raw.as_raw_fd(), 4)?;
    let devnull_fd = dup_above_cloexec(devnull_raw.as_raw_fd(), 4)?;
    drop(pipe_w_raw);
    drop(log_fd_raw);
    drop(devnull_raw);

    let launcher_pid = spawn_launcher_process(
        cmd,
        devnull_fd.as_raw_fd(),
        log_fd.as_raw_fd(),
        pipe_w.as_raw_fd(),
    )?;

    // Drop parent's copy of write end immediately so EOF is observed if child dies!
    drop(pipe_w);
    drop(log_fd);
    drop(devnull_fd);

    let reply_res = read_ready_reply_with_timeout(pipe_r.as_raw_fd(), ready_timeout);

    // Always reap the launcher child (double-fork exits immediately -> zero zombies).
    reap_launcher_child(launcher_pid, Duration::from_secs(2));

    reply_res
}

fn reap_launcher_child(pid: libc::pid_t, timeout: Duration) {
    let start = Instant::now();
    let mut status: libc::c_int = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid || rc < 0 {
            return;
        }
        if start.elapsed() >= timeout {
            // Launcher should have _exit(0)'d immediately; kill if wedged and reap.
            unsafe {
                let _ = libc::kill(pid, libc::SIGKILL);
                let _ = libc::waitpid(pid, &mut status, 0);
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn read_ready_reply_with_timeout(
    pipe_r: RawFd,
    timeout: Duration,
) -> Result<ReadyReply, DaemonError> {
    let start = Instant::now();
    let mut buf = Vec::with_capacity(64);
    let max_frame = 3 + MAX_READY_ERR_BYTES;
    let mut chunk = [0u8; 256];

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(DaemonError::ReadinessTimeout);
        }
        let rem_ms = timeout
            .saturating_sub(elapsed)
            .as_millis()
            .min(i32::MAX as u128) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd: pipe_r,
            events: libc::POLLIN,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
        if prc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(DaemonError::io("poll readiness pipe", err));
        }
        if prc == 0 {
            return Err(DaemonError::ReadinessTimeout);
        }
        let n = unsafe { libc::read(pipe_r, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(DaemonError::io("read readiness pipe", err));
        }
        if n == 0 {
            break;
        }
        let n_usize = n as usize;
        if buf.len().saturating_add(n_usize) > max_frame {
            return Err(DaemonError::ReadinessProtocol(
                "readiness frame exceeded max size".to_string(),
            ));
        }
        if let Some(slice) = chunk.get(..n_usize) {
            buf.extend_from_slice(slice);
        }
        // Check if we already received a complete frame (even before pipe EOF).
        if is_complete_ready_frame(&buf) {
            break;
        }
    }

    if buf.is_empty() {
        return Err(DaemonError::ReadinessProtocol(
            "daemon closed readiness pipe without sending status (check daemon.log)".to_string(),
        ));
    }
    decode_ready_reply(&buf).map_err(|e| DaemonError::ReadinessProtocol(e.to_string()))
}

fn is_complete_ready_frame(buf: &[u8]) -> bool {
    match buf.first().copied() {
        Some(0x00) => buf.len() >= 9,
        Some(0x02) => !buf.is_empty(),
        Some(0x01) => {
            if let Some(len_bytes) = buf.get(1..3)
                && let Ok(arr) = <[u8; 2]>::try_from(len_bytes)
            {
                let len = usize::from(u16::from_le_bytes(arr));
                buf.len() >= 3usize.saturating_add(len)
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn spawn_launcher_process(
    cmd: &SpawnCommand,
    devnull_fd: RawFd,
    log_fd: RawFd,
    pipe_w: RawFd,
) -> Result<libc::pid_t, DaemonError> {
    const POSIX_SPAWN_CLOEXEC_DEFAULT: libc::c_short = 0x4000;

    let exe_c = path_to_cstring(&cmd.exe_path)?;
    let mut argv_c = Vec::with_capacity(cmd.args.len() + 1);
    argv_c.push(exe_c.clone());
    for arg in &cmd.args {
        argv_c.push(
            CString::new(arg.as_bytes()).map_err(|_| {
                DaemonError::SpawnFailed("spawn argument contains NUL byte".to_string())
            })?,
        );
    }
    let mut argv_ptrs: Vec<*mut libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .collect();
    argv_ptrs.push(std::ptr::null_mut());

    let env_c = build_env_cstrings(&cmd.env)?;
    let mut env_ptrs: Vec<*mut libc::c_char> = env_c
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .collect();
    env_ptrs.push(std::ptr::null_mut());

    let mut attr: libc::posix_spawnattr_t = std::ptr::null_mut();
    let rc = unsafe { libc::posix_spawnattr_init(&mut attr) };
    if rc != 0 {
        return Err(DaemonError::io(
            "posix_spawnattr_init",
            io::Error::from_raw_os_error(rc),
        ));
    }
    struct AttrGuard(libc::posix_spawnattr_t);
    impl Drop for AttrGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::posix_spawnattr_destroy(&mut self.0);
            }
        }
    }
    let mut attr_guard = AttrGuard(attr);

    let rc = unsafe {
        libc::posix_spawnattr_setflags(&mut attr_guard.0, POSIX_SPAWN_CLOEXEC_DEFAULT)
    };
    if rc != 0 {
        return Err(DaemonError::io(
            "posix_spawnattr_setflags(POSIX_SPAWN_CLOEXEC_DEFAULT)",
            io::Error::from_raw_os_error(rc),
        ));
    }

    let mut actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
    let rc = unsafe { libc::posix_spawn_file_actions_init(&mut actions) };
    if rc != 0 {
        return Err(DaemonError::io(
            "posix_spawn_file_actions_init",
            io::Error::from_raw_os_error(rc),
        ));
    }
    struct ActionsGuard(libc::posix_spawn_file_actions_t);
    impl Drop for ActionsGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::posix_spawn_file_actions_destroy(&mut self.0);
            }
        }
    }
    let mut actions_guard = ActionsGuard(actions);

    for &(src, dst) in &[
        (devnull_fd, libc::STDIN_FILENO),
        (devnull_fd, libc::STDOUT_FILENO),
        (log_fd, libc::STDERR_FILENO),
        (pipe_w, READY_FD),
    ] {
        let rc = unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut actions_guard.0, src, dst)
        };
        if rc != 0 {
            return Err(DaemonError::io(
                "posix_spawn_file_actions_adddup2",
                io::Error::from_raw_os_error(rc),
            ));
        }
    }

    let mut pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid,
            exe_c.as_ptr(),
            &actions_guard.0,
            &attr_guard.0,
            argv_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(DaemonError::io(
            "posix_spawn",
            io::Error::from_raw_os_error(rc),
        ));
    }
    Ok(pid)
}

#[cfg(target_os = "macos")]
fn build_env_cstrings(overrides: &[(String, String)]) -> Result<Vec<CString>, DaemonError> {
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    let mut map: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for (k, v) in overrides {
        map.insert(OsString::from(k), OsString::from(v));
    }
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let mut bytes = Vec::with_capacity(k.as_bytes().len() + 1 + v.as_bytes().len());
        bytes.extend_from_slice(k.as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(v.as_bytes());
        if let Ok(c) = CString::new(bytes) {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn spawn_launcher_process(
    cmd: &SpawnCommand,
    devnull_fd: RawFd,
    log_fd: RawFd,
    pipe_w: RawFd,
) -> Result<libc::pid_t, DaemonError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let mut command = Command::new(&cmd.exe_path);
    command.args(&cmd.args);
    for (k, v) in &cmd.env {
        command.env(k, v);
    }

    // Async-signal-safe pre_exec: dup2 0/1/2/3 (clears CLOEXEC on targets) and
    // close every descriptor >= 4 via close_range(4, u32::MAX, 0) with fallback.
    unsafe {
        command.pre_exec(move || {
            for &(src, dst) in &[
                (devnull_fd, libc::STDIN_FILENO),
                (devnull_fd, libc::STDOUT_FILENO),
                (log_fd, libc::STDERR_FILENO),
                (pipe_w, READY_FD),
            ] {
                if libc::dup2(src, dst) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            close_fds_from(4);
            Ok(())
        });
    }

    let child = command
        .spawn()
        .map_err(|e| DaemonError::io("spawn launcher", e))?;
    Ok(child.id() as libc::pid_t)
}

#[cfg(target_os = "linux")]
unsafe fn close_fds_from(first_fd: u32) {
    // SYS_close_range is 436 on both x86_64 and aarch64 Linux.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first_fd, u32::MAX, 0u32) };
    if rc == 0 {
        return;
    }
    // Async-signal-safe fallback: close up to RLIMIT_NOFILE (bounded to 65536).
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let max_fd = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        (rl.rlim_cur as u64).min(65536) as i32
    } else {
        4096
    };
    let mut fd = first_fd as i32;
    while fd < max_fd {
        unsafe {
            let _ = libc::close(fd);
        }
        fd += 1;
    }
}

/// Outcome of an explicit `force_stop_daemon` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceStopOutcome {
    AlreadyStopped,
    TerminatedBySigterm { pid: u32 },
    KilledBySigkill { pid: u32 },
}

/// Explicitly stops a wedged or running daemon (e.g. `daemon stop --force`):
/// - Holds `startup.lock` exclusively during verification & signaling.
/// - Verifies `(pid, native_start_token)` from `daemon.info` (and optional Linux
///   `SO_PEERPIDFD`) against the live OS kernel — NEVER signals a recycled PID!
/// - Sends `SIGTERM` -> waits `sigterm_timeout` -> re-verifies start token ->
///   escalates to `SIGKILL` -> waits `sigkill_timeout` for `daemon.lock` release.
pub fn force_stop_daemon(
    dir: &VerifiedDir,
    device_id: u64,
    sigterm_timeout: Duration,
    sigkill_timeout: Duration,
) -> Result<ForceStopOutcome, DaemonError> {
    let lock_deadline = sigterm_timeout
        .saturating_add(sigkill_timeout)
        .max(Duration::from_secs(5));
    let _startup_lock =
        FlockGuard::lock_exclusive_with_deadline(dir, STARTUP_LOCK_NAME, lock_deadline)?;

    if FlockGuard::probe_lock_free(dir, DAEMON_LOCK_NAME)? {
        return Ok(ForceStopOutcome::AlreadyStopped);
    }

    // Best-effort peer pidfd probe on Linux if socket accepts quickly.
    let peer_pidfd = probe_peer_pidfd(dir);

    let Some(raw_info) = read_file_in_dir(dir.as_raw_fd(), DAEMON_INFO_NAME, 16 * 1024)? else {
        return Err(DaemonError::ProcessVerificationFailed {
            pid: 0,
            reason: "daemon.lock is held but daemon.info is missing",
        });
    };
    let info = decode_daemon_info(&raw_info)?;
    if info.device_id != device_id {
        return Err(DaemonError::DeviceIdMismatch {
            expected: device_id,
            actual: info.device_id,
        });
    }
    if info.pid <= 1 {
        return Err(DaemonError::ProcessVerificationFailed {
            pid: info.pid,
            reason: "refusing to signal pid <= 1",
        });
    }

    let Some(live_token) = process_start_token(info.pid)? else {
        if FlockGuard::probe_lock_free(dir, DAEMON_LOCK_NAME)? {
            return Ok(ForceStopOutcome::AlreadyStopped);
        }
        return Err(DaemonError::ProcessVerificationFailed {
            pid: info.pid,
            reason: "daemon.info pid no longer exists",
        });
    };
    if live_token != info.native_start_token {
        return Err(DaemonError::ProcessVerificationFailed {
            pid: info.pid,
            reason: "PID start token mismatch (PID was recycled)",
        });
    }

    send_verified_signal(info.pid, info.native_start_token, peer_pidfd.as_ref(), libc::SIGTERM)?;
    if wait_for_daemon_lock_release(dir, sigterm_timeout)? {
        cleanup_dead_socket(dir);
        return Ok(ForceStopOutcome::TerminatedBySigterm { pid: info.pid });
    }

    // Re-verify start token right before SIGKILL escalation!
    match process_start_token(info.pid)? {
        Some(tok) if tok == info.native_start_token => {
            send_verified_signal(
                info.pid,
                info.native_start_token,
                peer_pidfd.as_ref(),
                libc::SIGKILL,
            )?;
        }
        None => {
            if wait_for_daemon_lock_release(dir, sigkill_timeout)? {
                cleanup_dead_socket(dir);
                return Ok(ForceStopOutcome::TerminatedBySigterm { pid: info.pid });
            }
        }
        Some(_) => {
            return Err(DaemonError::ProcessVerificationFailed {
                pid: info.pid,
                reason: "PID start token changed before SIGKILL escalation",
            });
        }
    }

    if wait_for_daemon_lock_release(dir, sigkill_timeout)? {
        cleanup_dead_socket(dir);
        return Ok(ForceStopOutcome::KilledBySigkill { pid: info.pid });
    }

    Err(DaemonError::DaemonWedged {
        reason: "daemon.lock remained held after SIGKILL",
    })
}

fn probe_peer_pidfd(dir: &VerifiedDir) -> Option<OwnedFd> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::net::UnixStream;
        let sock = dir.path().join(SOCKET_FILE_NAME);
        let stream = UnixStream::connect(sock).ok()?;
        let creds = verify_peer_creds(stream.as_raw_fd()).ok()?;
        creds.pidfd
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dir;
        None
    }
}

fn send_verified_signal(
    pid: u32,
    expected_token: u64,
    pidfd: Option<&OwnedFd>,
    sig: libc::c_int,
) -> Result<(), DaemonError> {
    #[cfg(target_os = "linux")]
    if let Some(pfd) = pidfd {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pfd.as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
    }
    let _ = pidfd;

    let Some(tok) = process_start_token(pid)? else {
        return Ok(());
    };
    if tok != expected_token {
        return Err(DaemonError::ProcessVerificationFailed {
            pid,
            reason: "PID start token mismatch immediately before kill(2)",
        });
    }
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(DaemonError::io("kill", err));
        }
    }
    Ok(())
}

fn wait_for_daemon_lock_release(
    dir: &VerifiedDir,
    timeout: Duration,
) -> Result<bool, DaemonError> {
    let start = Instant::now();
    loop {
        if FlockGuard::probe_lock_free(dir, DAEMON_LOCK_NAME)? {
            return Ok(true);
        }
        if start.elapsed() >= timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(15));
    }
}

fn cleanup_dead_socket(dir: &VerifiedDir) {
    if let Ok(cname) = leaf_name_to_cstring(SOCKET_FILE_NAME) {
        unsafe {
            let _ = libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0);
        }
    }
}

/// Helper to expose the raw OsStr check when building paths.
#[allow(dead_code)]
pub(crate) fn os_str_len(s: &OsStr) -> usize {
    s.as_bytes().len()
}
