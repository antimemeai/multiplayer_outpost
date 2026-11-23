//! UID-only runtime directory resolution, `sun_path` budget enforcement,
//! and fail-closed `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` directory verification.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use mp_protocol::MAX_SAFE_ID;

use crate::error::DaemonError;

/// Maximum `sun_path` byte length excluding the trailing NUL terminator:
/// - macOS: `sizeof(sockaddr_un.sun_path) == 104` -> 103 bytes + NUL
/// - Linux: `sizeof(sockaddr_un.sun_path) == 108` -> 107 bytes + NUL
#[cfg(target_os = "macos")]
pub const MAX_SUN_PATH_BYTES: usize = 103;
#[cfg(not(target_os = "macos"))]
pub const MAX_SUN_PATH_BYTES: usize = 107;

/// Longest temporary socket leaf name (`t.<8hex>`, 10 bytes).
pub const TEMP_SOCKET_SAMPLE_NAME: &str = "t.00000000";

/// Final published Unix domain socket leaf name (`d.sock`, 6 bytes).
pub const SOCKET_FILE_NAME: &str = "d.sock";

/// Formats the deterministic per-device directory leaf name (`d<13hex>`).
pub fn format_device_dir_name(device_id: u64) -> Result<String, DaemonError> {
    if device_id == 0 || device_id > MAX_SAFE_ID {
        return Err(DaemonError::InvalidDeviceId(device_id));
    }
    Ok(format!("d{device_id:013x}"))
}

/// Validates a path override string (absolute, valid UTF-8, no `..`, no NUL/C0/C1/BiDi).
pub fn validate_path_hygiene(path: &Path) -> Result<(), DaemonError> {
    if !path.is_absolute() {
        return Err(DaemonError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path must be absolute",
        });
    }
    let Some(s) = path.to_str() else {
        return Err(DaemonError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path must be valid UTF-8",
        });
    };
    for ch in s.chars() {
        if ch == '\0'
            || ch.is_control()
            || matches!(
                ch,
                '\u{200E}'
                    | '\u{200F}'
                    | '\u{061C}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            )
        {
            return Err(DaemonError::InvalidPath {
                path: path.to_path_buf(),
                reason: "path contains forbidden control or BiDi scalar",
            });
        }
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(DaemonError::InvalidPath {
                path: path.to_path_buf(),
                reason: "path must not contain '..'",
            });
        }
    }
    Ok(())
}

/// Validates that `<dir>/t.00000000` fits within the given `sun_path` byte limit (excluding NUL).
pub fn validate_sun_path_budget_with_limit(dir: &Path, max_bytes: usize) -> Result<(), DaemonError> {
    let sample = dir.join(TEMP_SOCKET_SAMPLE_NAME);
    let len = sample.as_os_str().as_bytes().len();
    if len > max_bytes {
        return Err(DaemonError::SunPathTooLong {
            path: sample,
            len,
            max: max_bytes,
        });
    }
    Ok(())
}

/// Validates that `<dir>/t.00000000` fits strictly within the platform `sun_path` limit.
pub fn validate_sun_path_budget(dir: &Path) -> Result<(), DaemonError> {
    validate_sun_path_budget_with_limit(dir, MAX_SUN_PATH_BYTES)
}

/// Resolves the deterministic UID-only runtime directory for `device_id`,
/// never deriving from `$TMPDIR` or `$XDG_RUNTIME_DIR`.
pub fn resolve_runtime_dir(
    device_id: u64,
    explicit_override: Option<&Path>,
) -> Result<PathBuf, DaemonError> {
    let dev_leaf = format_device_dir_name(device_id)?;
    let dir = if let Some(override_dir) = explicit_override {
        validate_path_hygiene(override_dir)?;
        override_dir.join(&dev_leaf)
    } else {
        platform_runtime_base()?.join("mpo").join(&dev_leaf)
    };
    validate_sun_path_budget(&dir)?;
    Ok(dir)
}

/// Resolves the state directory (`<state_dir>`) per §2.1.
pub fn resolve_state_dir(explicit_override: Option<&Path>) -> Result<PathBuf, DaemonError> {
    if let Some(override_dir) = explicit_override {
        validate_path_hygiene(override_dir)?;
        return Ok(override_dir.to_path_buf());
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| DaemonError::InvalidPath {
            path: PathBuf::new(),
            reason: "HOME environment variable is unset",
        })?;
        let dir = PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("mp-outpost");
        validate_path_hygiene(&dir)?;
        Ok(dir)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = if let Some(xdg) = std::env::var_os("XDG_STATE_HOME")
            && !xdg.is_empty()
        {
            PathBuf::from(xdg)
        } else {
            let home = std::env::var_os("HOME").ok_or_else(|| DaemonError::InvalidPath {
                path: PathBuf::new(),
                reason: "HOME environment variable is unset",
            })?;
            PathBuf::from(home).join(".local").join("state")
        };
        let dir = base.join("mp-outpost");
        validate_path_hygiene(&dir)?;
        Ok(dir)
    }
}

#[cfg(target_os = "macos")]
fn platform_runtime_base() -> Result<PathBuf, DaemonError> {
    // Query Darwin per-user temp dir directly from the kernel/libc (NEVER `$TMPDIR`!).
    let needed = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if needed == 0 {
        return Err(DaemonError::io(
            "confstr(_CS_DARWIN_USER_TEMP_DIR)",
            io::Error::last_os_error(),
        ));
    }
    let mut buf = vec![0u8; needed];
    let written = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
        )
    };
    if written == 0 || written > buf.len() {
        return Err(DaemonError::io(
            "confstr(_CS_DARWIN_USER_TEMP_DIR) read",
            io::Error::last_os_error(),
        ));
    }
    let raw_len = buf.iter().position(|&b| b == 0).unwrap_or(written);
    let trimmed = buf
        .get(..raw_len)
        .unwrap_or_default()
        .strip_suffix(b"/")
        .unwrap_or_else(|| buf.get(..raw_len).unwrap_or_default());
    let path = PathBuf::from(OsStr::from_bytes(trimmed));
    validate_path_hygiene(&path)?;
    Ok(path)
}

#[cfg(not(target_os = "macos"))]
fn platform_runtime_base() -> Result<PathBuf, DaemonError> {
    let euid = unsafe { libc::geteuid() };
    let run_user = PathBuf::from(format!("/run/user/{euid}"));
    if is_verified_private_dir(&run_user, euid) {
        return Ok(run_user);
    }
    let home = std::env::var_os("HOME").ok_or_else(|| DaemonError::InvalidPath {
        path: PathBuf::new(),
        reason: "HOME environment variable is unset and /run/user/<uid> unavailable",
    })?;
    let cache = PathBuf::from(home).join(".cache");
    validate_path_hygiene(&cache)?;
    Ok(cache)
}

#[cfg(not(target_os = "macos"))]
fn is_verified_private_dir(path: &Path, expected_uid: u32) -> bool {
    let Ok(cpath) = path_to_cstring(path) else {
        return false;
    };
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let Ok(st) = fstat_fd(owned.as_raw_fd()) else {
        return false;
    };
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let mode = st.st_mode & 0o777;
    is_dir && st.st_uid == expected_uid && mode == 0o700
}

/// An open, verified `0700` directory owned by `geteuid()`, opened with
/// `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
#[derive(Debug)]
pub struct VerifiedDir {
    fd: OwnedFd,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl VerifiedDir {
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn dev(&self) -> u64 {
        self.dev
    }

    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// Checks whether the filesystem path still resolves to the exact `(dev, ino)`
    /// of this open directory handle (defeating `dirhelper` / `tmpfiles.d` wipes).
    pub fn path_matches_inode(&self) -> Result<bool, DaemonError> {
        let cpath = path_to_cstring(&self.path)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::lstat(cpath.as_ptr(), &mut st) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(DaemonError::io("lstat verified dir", err));
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let (dev, ino) = stat_dev_ino(&st);
        Ok(is_dir && dev == self.dev && ino == self.ino)
    }

    /// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` returning `Ok(None)` on `ENOENT`.
    pub fn stat_entry(&self, name: &str) -> Result<Option<libc::stat>, DaemonError> {
        let cname = leaf_name_to_cstring(name)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                cname.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(DaemonError::io("fstatat entry", err));
        }
        Ok(Some(st))
    }

    /// Unlinks `name` inside this directory ONLY if its current `(st_dev, st_ino)` matches.
    pub fn unlink_if_matches(
        &self,
        name: &str,
        expected_dev: u64,
        expected_ino: u64,
    ) -> Result<bool, DaemonError> {
        let Some(st) = self.stat_entry(name)? else {
            return Ok(false);
        };
        let (dev, ino) = stat_dev_ino(&st);
        if dev != expected_dev || ino != expected_ino {
            return Ok(false);
        }
        let cname = leaf_name_to_cstring(name)?;
        let rc = unsafe { libc::unlinkat(self.fd.as_raw_fd(), cname.as_ptr(), 0) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(DaemonError::io("unlinkat verified entry", err));
        }
        Ok(true)
    }
}

/// Walks every path component from `/` via `openat(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`
/// and `mkdirat(..., 0o700)` to create missing directories without path-based TOCTOU,
/// and verifies the final leaf FD via `fstat` that `S_ISDIR`, `st_uid == geteuid()`,
/// and `(st_mode & 0o777) == 0o700`.
///
/// Rejects ALL leaf symlinks, ALL non-root intermediate symlinks (regardless of UID),
/// and overly broad permissions (e.g. `0755`) fail-closed! Root-owned OS alias symlinks
/// on non-leaf components (e.g. macOS `/var -> private/var`) are permitted.
pub fn open_or_create_private_dir(path: &Path) -> Result<VerifiedDir, DaemonError> {
    validate_path_hygiene(path)?;
    let euid = unsafe { libc::geteuid() };

    let comps: Vec<&OsStr> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name),
            Component::RootDir | Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                None
            }
        })
        .collect();
    if comps.is_empty() {
        return Err(DaemonError::InsecureDirectory {
            path: path.to_path_buf(),
            reason: "root directory cannot be used as a private directory",
        });
    }

    let root_raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_raw < 0 {
        return Err(DaemonError::io("open root dir", io::Error::last_os_error()));
    }
    let mut cur_fd = unsafe { OwnedFd::from_raw_fd(root_raw) };
    let mut cur_path = PathBuf::from("/");
    let total = comps.len();

    for (idx, comp) in comps.into_iter().enumerate() {
        cur_path.push(comp);
        let is_leaf = idx + 1 == total;
        let cname = CString::new(comp.as_bytes()).map_err(|_| DaemonError::InvalidPath {
            path: cur_path.clone(),
            reason: "path component contains interior NUL byte",
        })?;

        let next_fd = open_or_create_component(cur_fd.as_raw_fd(), &cname, &cur_path, is_leaf)?;
        cur_fd = next_fd;
    }

    let st = fstat_fd(cur_fd.as_raw_fd())?;

    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(DaemonError::InsecureDirectory {
            path: path.to_path_buf(),
            reason: "target is not a directory",
        });
    }
    if st.st_uid != euid {
        return Err(DaemonError::InsecureDirectory {
            path: path.to_path_buf(),
            reason: "directory is not owned by current effective UID",
        });
    }
    let perm = st.st_mode & 0o777;
    if perm != 0o700 {
        return Err(DaemonError::InsecureDirectory {
            path: path.to_path_buf(),
            reason: "directory permissions are not strictly 0700",
        });
    }

    let (dev, ino) = stat_dev_ino(&st);
    Ok(VerifiedDir {
        fd: cur_fd,
        path: path.to_path_buf(),
        dev,
        ino,
    })
}

fn open_or_create_component(
    parent_fd: RawFd,
    cname: &CString,
    cur_path: &Path,
    is_leaf: bool,
) -> Result<OwnedFd, DaemonError> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let raw = unsafe { libc::openat(parent_fd, cname.as_ptr(), flags) };
    if raw >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
    }
    let mut err = io::Error::last_os_error();

    if err.kind() == io::ErrorKind::NotFound {
        let mrc = unsafe { libc::mkdirat(parent_fd, cname.as_ptr(), 0o700) };
        if mrc != 0 {
            let merr = io::Error::last_os_error();
            if merr.kind() != io::ErrorKind::AlreadyExists {
                return Err(DaemonError::io("mkdirat 0700", merr));
            }
        }
        let retry = unsafe { libc::openat(parent_fd, cname.as_ptr(), flags) };
        if retry >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(retry) });
        }
        err = io::Error::last_os_error();
    }

    let raw_err = err.raw_os_error();
    if raw_err == Some(libc::ELOOP) || raw_err == Some(libc::ENOTDIR) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let frc = unsafe {
            libc::fstatat(
                parent_fd,
                cname.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if frc != 0 {
            return Err(DaemonError::io(
                "fstatat directory component",
                io::Error::last_os_error(),
            ));
        }
        let is_symlink = (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;
        if is_symlink {
            if is_leaf || st.st_uid != 0 {
                return Err(DaemonError::SymlinkRejected {
                    path: cur_path.to_path_buf(),
                });
            }
            // Non-leaf root-owned OS alias symlink (e.g. `/var -> private/var`, `/tmp -> private/tmp`).
            let follow_fd = unsafe {
                libc::openat(
                    parent_fd,
                    cname.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if follow_fd < 0 {
                return Err(DaemonError::io(
                    "openat root-owned symlink dir",
                    io::Error::last_os_error(),
                ));
            }
            return Ok(unsafe { OwnedFd::from_raw_fd(follow_fd) });
        }
        return Err(DaemonError::InsecureDirectory {
            path: cur_path.to_path_buf(),
            reason: "path component is not a directory",
        });
    }

    Err(DaemonError::io("openat private dir component", err))
}

pub(crate) fn path_to_cstring(path: &Path) -> Result<CString, DaemonError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| DaemonError::InvalidPath {
        path: path.to_path_buf(),
        reason: "path contains interior NUL byte",
    })
}

pub(crate) fn leaf_name_to_cstring(name: &str) -> Result<CString, DaemonError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(DaemonError::InvalidPath {
            path: PathBuf::from(name),
            reason: "invalid directory entry name",
        });
    }
    CString::new(name.as_bytes()).map_err(|_| DaemonError::InvalidPath {
        path: PathBuf::from(name),
        reason: "entry name contains interior NUL byte",
    })
}

pub(crate) fn fstat_fd(fd: RawFd) -> Result<libc::stat, DaemonError> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return Err(DaemonError::io("fstat", io::Error::last_os_error()));
    }
    Ok(st)
}

#[allow(clippy::unnecessary_cast)]
pub(crate) fn stat_dev_ino(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}
