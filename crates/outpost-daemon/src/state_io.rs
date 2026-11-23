//! Atomic binary file storage helpers (`StateLock` + `atomic_write_in_dir`).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use crate::error::DaemonError;
use crate::os_unix::{FlockGuard, random_u32};
use crate::runtime_dir::{VerifiedDir, fstat_fd, leaf_name_to_cstring};

pub const STATE_LOCK_NAME: &str = "state.lock";

/// Serialization lock (`flock(LOCK_EX)`) on never-unlinked `<state_dir>/state.lock`.
#[derive(Debug)]
pub struct StateLock {
    guard: FlockGuard,
}

impl StateLock {
    /// Acquires `state.lock` exclusively with a bounded wait deadline.
    pub fn lock(state_dir: &VerifiedDir, deadline: Duration) -> Result<Self, DaemonError> {
        let guard = FlockGuard::lock_exclusive_with_deadline(state_dir, STATE_LOCK_NAME, deadline)?;
        Ok(Self { guard })
    }

    /// Attempts a non-blocking exclusive lock on `state.lock`.
    pub fn try_lock(state_dir: &VerifiedDir) -> Result<Option<Self>, DaemonError> {
        let guard = FlockGuard::try_lock_exclusive(state_dir, STATE_LOCK_NAME)?;
        Ok(guard.map(|g| Self { guard: g }))
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.guard.as_raw_fd()
    }
}

/// Atomically writes `bytes` to `name` inside `dirfd`:
/// `openat(O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, 0o600)` -> `write_all` ->
/// `fsync(file)` -> `renameat` -> `fsync(dirfd)`.
pub fn atomic_write_in_dir(dirfd: RawFd, name: &str, bytes: &[u8]) -> Result<(), DaemonError> {
    let target_c = leaf_name_to_cstring(name)?;

    let mut tmp_name = String::new();
    let mut tmp_c = None;
    let mut file_fd: Option<OwnedFd> = None;

    for _ in 0..16 {
        let suffix = random_u32()?;
        tmp_name = format!(".{name}.tmp.{suffix:08x}");
        let candidate_c = leaf_name_to_cstring(&tmp_name)?;
        let raw_fd = unsafe {
            libc::openat(
                dirfd,
                candidate_c.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if raw_fd >= 0 {
            file_fd = Some(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            tmp_c = Some(candidate_c);
            break;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::AlreadyExists {
            continue;
        }
        return Err(DaemonError::io("openat temp file", err));
    }

    let (Some(fd), Some(tmp_c)) = (file_fd, tmp_c) else {
        return Err(DaemonError::io(
            "allocate unique temp filename",
            io::Error::new(io::ErrorKind::AlreadyExists, tmp_name),
        ));
    };

    let write_res = (|| -> Result<(), DaemonError> {
        write_all_fd(fd.as_raw_fd(), bytes)?;
        fsync_fd(fd.as_raw_fd())?;
        Ok(())
    })();

    // Always close the file descriptor before rename / cleanup.
    drop(fd);

    if let Err(err) = write_res {
        unsafe {
            let _ = libc::unlinkat(dirfd, tmp_c.as_ptr(), 0);
        }
        return Err(err);
    }

    let rc = unsafe { libc::renameat(dirfd, tmp_c.as_ptr(), dirfd, target_c.as_ptr()) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            let _ = libc::unlinkat(dirfd, tmp_c.as_ptr(), 0);
        }
        return Err(DaemonError::io("renameat atomic file", err));
    }

    fsync_fd(dirfd)?;
    Ok(())
}

/// Reads a regular file `name` inside `dirfd` with `O_NOFOLLOW | O_CLOEXEC`,
/// returning `Ok(None)` if `ENOENT` and failing closed if larger than `max_bytes`.
pub fn read_file_in_dir(
    dirfd: RawFd,
    name: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, DaemonError> {
    let cname = leaf_name_to_cstring(name)?;
    let raw_fd = unsafe {
        libc::openat(
            dirfd,
            cname.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(DaemonError::io("openat read file", err));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let st = fstat_fd(fd.as_raw_fd())?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(DaemonError::Protocol(format!(
            "expected regular file for '{name}'"
        )));
    }
    if st.st_size < 0 || (st.st_size as u64) > (max_bytes as u64) {
        return Err(DaemonError::Protocol(format!(
            "file '{name}' exceeds max allowed size ({max_bytes} bytes)"
        )));
    }

    let mut out = Vec::with_capacity(st.st_size as usize);
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(DaemonError::io("read file in dir", err));
        }
        if n == 0 {
            break;
        }
        let n_usize = n as usize;
        if out.len().saturating_add(n_usize) > max_bytes {
            return Err(DaemonError::Protocol(format!(
                "file '{name}' grew beyond max allowed size ({max_bytes} bytes)"
            )));
        }
        if let Some(slice) = buf.get(..n_usize) {
            out.extend_from_slice(slice);
        }
    }
    Ok(Some(out))
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) -> Result<(), DaemonError> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(DaemonError::io("write atomic temp file", err));
        }
        let written = n as usize;
        if written == 0 {
            return Err(DaemonError::io(
                "write atomic temp file",
                io::Error::new(io::ErrorKind::WriteZero, "short zero write"),
            ));
        }
        data = data.get(written..).unwrap_or_default();
    }
    Ok(())
}

fn fsync_fd(fd: RawFd) -> Result<(), DaemonError> {
    #[cfg(target_os = "macos")]
    {
        loop {
            let rc = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) };
            if rc == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            let raw = err.raw_os_error();
            if raw == Some(libc::ENOTSUP)
                || raw == Some(libc::EINVAL)
                || raw == Some(libc::ENOTTY)
            {
                break;
            }
            return Err(DaemonError::io("fcntl(F_FULLFSYNC)", err));
        }
    }

    loop {
        let rc = unsafe { libc::fsync(fd) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(DaemonError::io("fsync", err));
    }
}
