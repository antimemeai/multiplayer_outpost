//! Atomic binary file storage helpers (`StateLock`, `atomic_write_in_dir`,
//! `atomic_write_in_dir_no_replace`, `open_dir_nofollow`, and
//! `read_regular_file_bounded_nofollow`).

use std::ffi::CString;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
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

/// Atomically writes `bytes` to `target_name` inside `dirfd` WITHOUT replacing an
/// existing file or symlink:
/// `openat(O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, mode)` -> `write_all` ->
/// `fsync(file)` -> `close` -> `linkat(dirfd, tmp, dirfd, target, 0)` ->
/// `unlinkat(dirfd, tmp)` (always) -> `fsync(dirfd)` (on success).
///
/// Fails closed with `DaemonError::Io` (`io::ErrorKind::AlreadyExists`) if
/// `target_name` already exists as a regular file, symlink (including dangling),
/// or directory, without modifying the existing entry.
pub fn atomic_write_in_dir_no_replace(
    dirfd: RawFd,
    target_name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), DaemonError> {
    let target_c = leaf_name_to_cstring(target_name)?;
    let safe_mode = (mode & 0o777) as libc::c_uint;

    let mut tmp_name = String::new();
    let mut tmp_c = None;
    let mut file_fd: Option<OwnedFd> = None;

    for _ in 0..16 {
        let suffix = random_u32()?;
        tmp_name = format!(".{target_name}.tmp.{suffix:08x}");
        let candidate_c = leaf_name_to_cstring(&tmp_name)?;
        let raw_fd = unsafe {
            libc::openat(
                dirfd,
                candidate_c.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                safe_mode,
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

    // Always close the file descriptor before link / cleanup.
    drop(fd);

    if let Err(err) = write_res {
        unsafe {
            let _ = libc::unlinkat(dirfd, tmp_c.as_ptr(), 0);
        }
        return Err(err);
    }

    let rc = unsafe { libc::linkat(dirfd, tmp_c.as_ptr(), dirfd, target_c.as_ptr(), 0) };
    let link_err = if rc != 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };

    // Always remove the temporary directory entry in both success and failure paths.
    unsafe {
        let _ = libc::unlinkat(dirfd, tmp_c.as_ptr(), 0);
    }

    if let Some(err) = link_err {
        return Err(DaemonError::io("linkat atomic file", err));
    }

    fsync_fd(dirfd)?;
    Ok(())
}

/// Opens an existing directory `path` with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`,
/// rejecting a symlink at the target directory component while permitting OS root aliases
/// such as macOS `/var -> /private/var`.
pub fn open_dir_nofollow(path: &Path) -> Result<OwnedFd, DaemonError> {
    let raw_bytes = path.as_os_str().as_bytes();
    if raw_bytes.is_empty() {
        return Err(DaemonError::InvalidPath {
            path: path.to_path_buf(),
            reason: "directory path must not be empty",
        });
    }
    // Strip trailing slashes (unless path is "/") so a trailing slash on a symlink
    // cannot bypass `O_NOFOLLOW`.
    let mut trimmed = raw_bytes;
    while trimmed.len() > 1 && trimmed.ends_with(b"/") {
        if let Some(prefix) = trimmed.strip_suffix(b"/") {
            trimmed = prefix;
        } else {
            break;
        }
    }
    let cpath = CString::new(trimmed).map_err(|_| DaemonError::InvalidPath {
        path: path.to_path_buf(),
        reason: "directory path contains NUL byte",
    })?;
    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let err = io::Error::last_os_error();
        let raw_errno = err.raw_os_error();
        if raw_errno == Some(libc::ELOOP) {
            return Err(DaemonError::SymlinkRejected {
                path: path.to_path_buf(),
            });
        }
        // On macOS/BSD, `O_DIRECTORY | O_NOFOLLOW` on a symlink can return `ENOTDIR`
        // instead of `ELOOP`; classify symlink rejections consistently via `lstat`.
        if raw_errno == Some(libc::ENOTDIR) {
            let mut lst: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::lstat(cpath.as_ptr(), &mut lst) } == 0
                && (lst.st_mode & libc::S_IFMT) == libc::S_IFLNK
            {
                return Err(DaemonError::SymlinkRejected {
                    path: path.to_path_buf(),
                });
            }
        }
        return Err(DaemonError::io("open_dir_nofollow", err));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let st = fstat_fd(fd.as_raw_fd())?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(DaemonError::InvalidPath {
            path: path.to_path_buf(),
            reason: "target path is not a directory",
        });
    }
    Ok(fd)
}

/// Opens `path` with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, verifies via
/// `fstat` that it is a regular file (`S_IFREG`) with `0 <= st_size <= max_bytes`,
/// and reads at most `max_bytes` bytes (failing closed if the file exceeds `max_bytes`).
pub fn read_regular_file_bounded_nofollow(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, DaemonError> {
    let raw_bytes = path.as_os_str().as_bytes();
    if raw_bytes.is_empty() {
        return Err(DaemonError::InvalidPath {
            path: path.to_path_buf(),
            reason: "file path must not be empty",
        });
    }
    let cpath = CString::new(raw_bytes).map_err(|_| DaemonError::InvalidPath {
        path: path.to_path_buf(),
        reason: "file path contains NUL byte",
    })?;

    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let err = io::Error::last_os_error();
        return Err(DaemonError::io("open regular file", err));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let st = fstat_fd(fd.as_raw_fd())?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(DaemonError::Protocol(format!(
            "expected regular file at '{}'",
            path.display()
        )));
    }
    if st.st_size < 0 || (st.st_size as u64) > (max_bytes as u64) {
        return Err(DaemonError::Protocol(format!(
            "file '{}' exceeds max allowed size ({max_bytes} bytes)",
            path.display()
        )));
    }

    let initial_cap = usize::try_from(st.st_size).unwrap_or(0).min(64 * 1024);
    let mut out = Vec::with_capacity(initial_cap);
    let mut file = std::fs::File::from(fd);
    let limit = (max_bytes as u64).saturating_add(1);
    file.by_ref()
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| DaemonError::io("read regular file", e))?;
    if out.len() > max_bytes {
        return Err(DaemonError::Protocol(format!(
            "file '{}' grew beyond max allowed size ({max_bytes} bytes)",
            path.display()
        )));
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    #[test]
    fn atomic_write_no_replace_creates_0600_and_refuses_existing_file_or_symlink()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let dir_fd = open_dir_nofollow(tmp.path())?;

        // 1. Creates new file with 0600 permissions and leaves no temp file behind.
        atomic_write_in_dir_no_replace(dir_fd.as_raw_fd(), "backup.mpkey", b"secret-v1", 0o600)?;
        let target_path = tmp.path().join("backup.mpkey");
        let meta = fs::symlink_metadata(&target_path)?;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&target_path)?, b"secret-v1");

        // 2. Refuses to overwrite existing regular file with AlreadyExists and preserves content.
        let err_existing =
            atomic_write_in_dir_no_replace(dir_fd.as_raw_fd(), "backup.mpkey", b"secret-v2", 0o600);
        match err_existing {
            Err(DaemonError::Io { source, .. }) => {
                assert_eq!(source.kind(), io::ErrorKind::AlreadyExists);
            }
            other => return Err(format!("expected AlreadyExists, got {other:?}").into()),
        }
        assert_eq!(fs::read(&target_path)?, b"secret-v1");

        // 3. Refuses to overwrite existing symlink (including dangling symlink) without modifying target.
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, b"do-not-touch")?;
        let link_path = tmp.path().join("link.mpkey");
        symlink(&victim, &link_path)?;
        let err_link =
            atomic_write_in_dir_no_replace(dir_fd.as_raw_fd(), "link.mpkey", b"pwned", 0o600);
        match err_link {
            Err(DaemonError::Io { source, .. }) => {
                assert_eq!(source.kind(), io::ErrorKind::AlreadyExists);
            }
            other => return Err(format!("expected AlreadyExists on symlink, got {other:?}").into()),
        }
        assert!(fs::symlink_metadata(&link_path)?.file_type().is_symlink());
        assert_eq!(fs::read(&victim)?, b"do-not-touch");

        // Dangling symlink must also fail with AlreadyExists.
        let dangling = tmp.path().join("dangling.mpkey");
        symlink(tmp.path().join("nonexistent-target"), &dangling)?;
        let err_dangling =
            atomic_write_in_dir_no_replace(dir_fd.as_raw_fd(), "dangling.mpkey", b"data", 0o600);
        match err_dangling {
            Err(DaemonError::Io { source, .. }) => {
                assert_eq!(source.kind(), io::ErrorKind::AlreadyExists);
            }
            other => {
                return Err(
                    format!("expected AlreadyExists on dangling symlink, got {other:?}").into(),
                );
            }
        }
        assert!(!tmp.path().join("nonexistent-target").exists());

        // 4. Verify zero stray `.tmp.*` files remain in the directory!
        let mut entries = Vec::new();
        for entry in fs::read_dir(tmp.path())? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            assert!(
                !name.contains(".tmp."),
                "stray temp file left behind: {name}"
            );
            entries.push(name);
        }
        assert_eq!(entries.len(), 4);
        Ok(())
    }

    #[test]
    fn open_dir_nofollow_accepts_real_dir_and_rejects_symlink_dir()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir)?;
        let fd = open_dir_nofollow(&real_dir)?;
        let st = fstat_fd(fd.as_raw_fd())?;
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFDIR);
        assert_eq!(st.st_ino, fs::metadata(&real_dir)?.ino());

        let sym_dir = tmp.path().join("sym");
        symlink(&real_dir, &sym_dir)?;
        assert!(matches!(
            open_dir_nofollow(&sym_dir),
            Err(DaemonError::SymlinkRejected { .. })
        ));
        // Even with a trailing slash, symlink directory must be rejected!
        let sym_dir_slash = Path::new(&format!("{}/", sym_dir.display())).to_path_buf();
        assert!(matches!(
            open_dir_nofollow(&sym_dir_slash),
            Err(DaemonError::SymlinkRejected { .. })
        ));
        Ok(())
    }

    #[test]
    fn read_regular_file_bounded_nofollow_enforces_type_symlink_and_size()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;

        // 1. Reads valid regular file within bound.
        let ok_file = tmp.path().join("key.mpkey");
        fs::write(&ok_file, b"hello-world")?;
        let got = read_regular_file_bounded_nofollow(&ok_file, 11)?;
        assert_eq!(got, b"hello-world");

        // 2. Rejects file exceeding max_bytes.
        let err_big = read_regular_file_bounded_nofollow(&ok_file, 10);
        assert!(matches!(err_big, Err(DaemonError::Protocol(_))));

        // 3. Rejects symlink with ELOOP.
        let sym_file = tmp.path().join("key-link.mpkey");
        symlink(&ok_file, &sym_file)?;
        match read_regular_file_bounded_nofollow(&sym_file, 64) {
            Err(DaemonError::Io { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::ELOOP));
            }
            other => return Err(format!("expected ELOOP on symlink, got {other:?}").into()),
        }

        // 4. Rejects non-regular device node (/dev/zero) without hanging!
        let err_dev = read_regular_file_bounded_nofollow(Path::new("/dev/zero"), 1024);
        assert!(matches!(err_dev, Err(DaemonError::Protocol(_))));

        // 5. Rejects directory.
        let err_dir = read_regular_file_bounded_nofollow(tmp.path(), 1024);
        assert!(matches!(err_dir, Err(DaemonError::Protocol(_))));

        Ok(())
    }
}
