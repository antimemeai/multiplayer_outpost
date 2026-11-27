//! Binary persistence helpers under `StateLock` and TLS 1.3 control-plane config builder.

#[cfg(any(test, feature = "test-tls-overrides"))]
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(any(test, feature = "test-tls-overrides"))]
use base64::Engine as _;
#[cfg(any(test, feature = "test-tls-overrides"))]
use base64::engine::general_purpose::STANDARD as B64;
use mp_mls::MP_GROUP_ID_LEN;
use mp_protocol::{MAX_SAFE_ID, sha256};
#[cfg(any(test, feature = "test-tls-overrides"))]
use outpost_control::build_tls13_client_config_with_roots;
use outpost_control::{ControlClientConfig, ControlError};
use outpost_core::mls_store::{
    MLS_STORE_MAX_FILE_BYTES, MlsRoomSnapshotPlain, decrypt_mls_snapshot, derive_mls_store_key,
    encrypt_mls_snapshot_random,
};
use outpost_core::storage_codec::{
    DefaultDeviceRecord, DeviceRecord, EpochsStoreRecord, PeersStoreRecord, PendingDeviceRecord,
    PendingRegRecord, decode_default_device, decode_device_record, decode_epochs_store,
    decode_peers_store, decode_pending_device, decode_pending_reg, encode_default_device,
    encode_device_record, encode_epochs_store, encode_peers_store, encode_pending_device,
    encode_pending_reg,
};
use outpost_daemon::{
    DaemonError, StateLock, VerifiedDir, atomic_write_in_dir, exclude_dir_from_backup,
    format_device_dir_name, open_or_create_private_dir, read_file_in_dir, resolve_state_dir,
};
#[cfg(any(test, feature = "test-tls-overrides"))]
use rustls::pki_types::CertificateDer;

use crate::build_info::encode_hex;

pub const DEFAULT_DEVICE_FILE: &str = "default_device.bin";
pub const PENDING_DEV_FILE: &str = "pending_dev.bin";
pub const PENDING_REG_FILE: &str = "pending_reg.bin";
pub const PENDING_REG_CWT_FILE: &str = "pending_reg.cwt";
pub const PEERS_FILE: &str = "peers.bin";
pub const EPOCHS_FILE: &str = "epochs.bin";
pub const DEVICES_SUBDIR: &str = "devices";
pub const MLS_SUBDIR: &str = "mls";
pub const DEFAULT_RELAY_URL: &str = "https://relay.multiplayer.tech";

pub const STATE_LOCK_DEADLINE: Duration = Duration::from_secs(5);
const MAX_SMALL_STATE_BYTES: usize = 64 * 1024;
const MAX_PEERS_FILE_BYTES: usize = 2 * 1024 * 1024;

pub fn device_filename(device_id: u64) -> Result<String, DaemonError> {
    let prefix = format_device_dir_name(device_id)?;
    Ok(format!("{prefix}.dev.bin"))
}

pub fn resolve_effective_state_dir(cli_override: Option<&Path>) -> Result<PathBuf, String> {
    let env_override = std::env::var_os("OUTPOST_STATE_DIR")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let chosen = cli_override.or(env_override.as_deref());
    resolve_state_dir(chosen).map_err(|e| e.to_string())
}

pub fn resolve_effective_runtime_override(cli_override: Option<&Path>) -> Option<PathBuf> {
    cli_override.map(Path::to_path_buf).or_else(|| {
        std::env::var_os("OUTPOST_RUNTIME_DIR")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    })
}

pub fn open_state_dir(state_dir_path: &Path) -> Result<VerifiedDir, String> {
    open_or_create_private_dir(state_dir_path).map_err(|e| e.to_string())
}

pub fn open_devices_dir(state_dir_path: &Path) -> Result<VerifiedDir, String> {
    let _ = open_state_dir(state_dir_path)?;
    open_or_create_private_dir(&state_dir_path.join(DEVICES_SUBDIR)).map_err(|e| e.to_string())
}

/// Opens (creating if needed) the backup-excluded private MLS directory
/// `<state_dir>/mls/d<13hex>/` (`0700` + macOS `fsetxattr` / Linux `.nobackup` + `CACHEDIR.TAG`).
pub fn open_mls_device_dir(state_dir_path: &Path, device_id: u64) -> Result<VerifiedDir, String> {
    let _ = open_state_dir(state_dir_path)?;
    let mls_root = open_or_create_private_dir(&state_dir_path.join(MLS_SUBDIR))
        .map_err(|e| e.to_string())?;
    exclude_dir_from_backup(&mls_root).map_err(|e| e.to_string())?;
    let dev_leaf = format_device_dir_name(device_id).map_err(|e| e.to_string())?;
    let dev_dir = open_or_create_private_dir(&state_dir_path.join(MLS_SUBDIR).join(dev_leaf))
        .map_err(|e| e.to_string())?;
    exclude_dir_from_backup(&dev_dir).map_err(|e| e.to_string())?;
    Ok(dev_dir)
}

pub fn mls_room_filename(party_id: u64) -> Result<String, String> {
    if party_id == 0 || party_id > MAX_SAFE_ID {
        return Err(format!("invalid party_id {party_id}"));
    }
    Ok(format!("p{party_id:013x}.mls.bin"))
}

/// Atomically writes already-encrypted `MPM1` MLS snapshot bytes into `<state_dir>/mls/d<13hex>/`
/// under `StateLock` BEFORE any WebSocket transmit.
pub fn save_mls_room_bytes(
    state_dir_path: &Path,
    _lock: &StateLock,
    device_id: u64,
    party_id: u64,
    encrypted_bytes: &[u8],
) -> Result<(), String> {
    let mls_dir = open_mls_device_dir(state_dir_path, device_id)?;
    let fname = mls_room_filename(party_id)?;
    atomic_write_in_dir(mls_dir.as_raw_fd(), &fname, encrypted_bytes).map_err(|e| e.to_string())
}

/// Encrypts `snapshot` with AES-256-GCM and writes it atomically into `<state_dir>/mls/d<13hex>/`
/// under `StateLock`.
#[allow(dead_code)]
pub fn save_mls_room_snapshot(
    state_dir_path: &Path,
    lock: &StateLock,
    device_secret: &[u8; 32],
    device_id: u64,
    party_id: u64,
    group_id: &[u8; MP_GROUP_ID_LEN],
    snapshot: &MlsRoomSnapshotPlain,
) -> Result<(), String> {
    let key = derive_mls_store_key(device_secret, device_id);
    let encrypted = encrypt_mls_snapshot_random(&key, device_id, party_id, group_id, snapshot)
        .map_err(|e| format!("encrypt MLS room snapshot failed: {e}"))?;
    save_mls_room_bytes(state_dir_path, lock, device_id, party_id, &encrypted)
}

/// Loads and decrypts an `MPM1` MLS room snapshot from `<state_dir>/mls/d<13hex>/`, failing closed
/// on any CRC, AAD binding, or AES-256-GCM authentication failure.
#[allow(dead_code)]
pub fn load_mls_room_snapshot(
    state_dir_path: &Path,
    device_secret: &[u8; 32],
    device_id: u64,
    party_id: u64,
    group_id: &[u8; MP_GROUP_ID_LEN],
) -> Result<Option<MlsRoomSnapshotPlain>, String> {
    let mls_dir = open_mls_device_dir(state_dir_path, device_id)?;
    let fname = mls_room_filename(party_id)?;
    let Some(raw) = read_file_in_dir(mls_dir.as_raw_fd(), &fname, MLS_STORE_MAX_FILE_BYTES)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let key = derive_mls_store_key(device_secret, device_id);
    let plain = decrypt_mls_snapshot(&key, device_id, party_id, group_id, &raw)
        .map_err(|e| format!("corrupt or mismatched MLS snapshot '{fname}': {e}"))?;
    Ok(Some(plain))
}

pub fn remove_mls_room_snapshot(
    state_dir_path: &Path,
    _lock: &StateLock,
    device_id: u64,
    party_id: u64,
) {
    if let Ok(mls_dir) = open_mls_device_dir(state_dir_path, device_id)
        && let Ok(fname) = mls_room_filename(party_id)
    {
        let _ = std::fs::remove_file(mls_dir.path().join(fname));
    }
}

pub fn lock_state(state_dir: &VerifiedDir) -> Result<StateLock, String> {
    StateLock::lock(state_dir, STATE_LOCK_DEADLINE).map_err(|e| e.to_string())
}

pub fn load_device_record(state_dir_path: &Path, device_id: u64) -> Result<DeviceRecord, String> {
    let dev_dir = open_devices_dir(state_dir_path)?;
    let fname = device_filename(device_id).map_err(|e| e.to_string())?;
    let raw = read_file_in_dir(dev_dir.as_raw_fd(), &fname, MAX_SMALL_STATE_BYTES)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("enrolled device record not found for device_id={device_id}"))?;
    decode_device_record(&raw).map_err(|e| format!("corrupt device record '{fname}': {e}"))
}

pub fn save_device_record(
    state_dir_path: &Path,
    _lock: &StateLock,
    rec: &DeviceRecord,
) -> Result<(), String> {
    let dev_dir = open_devices_dir(state_dir_path)?;
    let fname = device_filename(rec.device_id).map_err(|e| e.to_string())?;
    let bytes = encode_device_record(rec).map_err(|e| e.to_string())?;
    atomic_write_in_dir(dev_dir.as_raw_fd(), &fname, &bytes).map_err(|e| e.to_string())
}

pub fn load_default_device_id(state_dir: &VerifiedDir) -> Result<Option<u64>, String> {
    let Some(raw) = read_file_in_dir(state_dir.as_raw_fd(), DEFAULT_DEVICE_FILE, 1024)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let rec =
        decode_default_device(&raw).map_err(|e| format!("corrupt default_device.bin: {e}"))?;
    Ok(Some(rec.device_id))
}

pub fn save_default_device_id(
    state_dir: &VerifiedDir,
    _lock: &StateLock,
    device_id: u64,
) -> Result<(), String> {
    let bytes = encode_default_device(&DefaultDeviceRecord { device_id })
        .map_err(|e| e.to_string())?;
    atomic_write_in_dir(state_dir.as_raw_fd(), DEFAULT_DEVICE_FILE, &bytes)
        .map_err(|e| e.to_string())
}

/// Scans `<state_dir>/devices/d<13hex>.dev.bin` and returns all valid enrolled device IDs sorted.
pub fn list_enrolled_device_ids(state_dir_path: &Path) -> Vec<u64> {
    let dev_path = state_dir_path.join(DEVICES_SUBDIR);
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dev_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(s) = name.to_str()
                && let Some(hex) = s.strip_prefix('d').and_then(|r| r.strip_suffix(".dev.bin"))
                && hex.len() == 13
                && let Ok(id) = u64::from_str_radix(hex, 16)
                && id > 0
                && id <= MAX_SAFE_ID
            {
                found.push(id);
            }
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

pub fn resolve_active_device_id(
    state_dir_path: &Path,
    cli_device_id: Option<u64>,
) -> Result<u64, String> {
    if let Some(id) = cli_device_id {
        if id == 0 || id > MAX_SAFE_ID {
            return Err(format!("invalid device_id {id}"));
        }
        return Ok(id);
    }
    if let Ok(raw) = std::env::var("OUTPOST_DEVICE_ID")
        && !raw.trim().is_empty()
    {
        let id = raw
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid OUTPOST_DEVICE_ID '{raw}'"))?;
        if id == 0 || id > MAX_SAFE_ID {
            return Err(format!("invalid OUTPOST_DEVICE_ID {id}"));
        }
        return Ok(id);
    }
    let state_dir = open_state_dir(state_dir_path)?;
    if let Some(id) = load_default_device_id(&state_dir)? {
        return Ok(id);
    }
    // Fallback: if exactly one `d<13hex>.dev.bin` exists, use it.
    let found = list_enrolled_device_ids(state_dir_path);
    if found.len() == 1
        && let Some(&only) = found.first()
    {
        return Ok(only);
    }
    Err("no enrolled device found; run `mp-outpost device init` or pass --device-id".to_string())
}

pub fn load_peers_store(state_dir: &VerifiedDir) -> Result<PeersStoreRecord, String> {
    let Some(raw) = read_file_in_dir(state_dir.as_raw_fd(), PEERS_FILE, MAX_PEERS_FILE_BYTES)
        .map_err(|e| e.to_string())?
    else {
        return Ok(PeersStoreRecord::default());
    };
    decode_peers_store(&raw).map_err(|e| format!("corrupt peers.bin (failing closed): {e}"))
}

pub fn save_peers_store(
    state_dir: &VerifiedDir,
    _lock: &StateLock,
    store: &PeersStoreRecord,
) -> Result<(), String> {
    let bytes = encode_peers_store(store).map_err(|e| e.to_string())?;
    atomic_write_in_dir(state_dir.as_raw_fd(), PEERS_FILE, &bytes).map_err(|e| e.to_string())
}

pub fn load_epochs_store(state_dir: &VerifiedDir) -> Result<EpochsStoreRecord, String> {
    let Some(raw) = read_file_in_dir(state_dir.as_raw_fd(), EPOCHS_FILE, MAX_SMALL_STATE_BYTES)
        .map_err(|e| e.to_string())?
    else {
        return Ok(EpochsStoreRecord::default());
    };
    decode_epochs_store(&raw).map_err(|e| format!("corrupt epochs.bin (failing closed): {e}"))
}

pub fn save_epochs_store(
    state_dir: &VerifiedDir,
    _lock: &StateLock,
    store: &EpochsStoreRecord,
) -> Result<(), String> {
    let bytes = encode_epochs_store(store).map_err(|e| e.to_string())?;
    atomic_write_in_dir(state_dir.as_raw_fd(), EPOCHS_FILE, &bytes).map_err(|e| e.to_string())
}

pub fn load_pending_device(state_dir: &VerifiedDir) -> Result<Option<PendingDeviceRecord>, String> {
    let Some(raw) = read_file_in_dir(state_dir.as_raw_fd(), PENDING_DEV_FILE, MAX_SMALL_STATE_BYTES)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let rec =
        decode_pending_device(&raw).map_err(|e| format!("corrupt pending_dev.bin: {e}"))?;
    Ok(Some(rec))
}

pub fn save_pending_device(
    state_dir: &VerifiedDir,
    _lock: &StateLock,
    rec: &PendingDeviceRecord,
) -> Result<(), String> {
    let bytes = encode_pending_device(rec).map_err(|e| e.to_string())?;
    atomic_write_in_dir(state_dir.as_raw_fd(), PENDING_DEV_FILE, &bytes).map_err(|e| e.to_string())
}

pub fn remove_state_file(state_dir: &VerifiedDir, _lock: &StateLock, name: &str) {
    let _ = std::fs::remove_file(state_dir.path().join(name));
}

pub fn load_pending_reg(state_dir: &VerifiedDir) -> Result<Option<PendingRegRecord>, String> {
    let Some(raw) = read_file_in_dir(state_dir.as_raw_fd(), PENDING_REG_FILE, MAX_SMALL_STATE_BYTES)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let rec = decode_pending_reg(&raw).map_err(|e| format!("corrupt pending_reg.bin: {e}"))?;
    Ok(Some(rec))
}

pub fn save_pending_reg(
    state_dir: &VerifiedDir,
    _lock: &StateLock,
    rec: &PendingRegRecord,
) -> Result<(), String> {
    let bytes = encode_pending_reg(rec).map_err(|e| e.to_string())?;
    atomic_write_in_dir(state_dir.as_raw_fd(), PENDING_REG_FILE, &bytes).map_err(|e| e.to_string())
}

pub fn load_pending_reg_cwt(state_dir: &VerifiedDir) -> Result<Option<Vec<u8>>, String> {
    read_file_in_dir(state_dir.as_raw_fd(), PENDING_REG_CWT_FILE, 1024).map_err(|e| e.to_string())
}

pub fn save_pending_reg_cwt(
    state_dir: &VerifiedDir,
    _lock: &StateLock,
    cwt: &[u8],
) -> Result<(), String> {
    atomic_write_in_dir(state_dir.as_raw_fd(), PENDING_REG_CWT_FILE, cwt).map_err(|e| e.to_string())
}

pub fn pubkey_fingerprint_hex(root_pubkey: &[u8; 32]) -> String {
    encode_hex(&sha256(root_pubkey))
}

/// Builds a TLS 1.3-only `ControlClientConfig` for `authority`.
///
/// Production/default builds NEVER honor `OUTPOST_TEST_CONNECT_ADDR` or `OUTPOST_TEST_CA_PEM`.
/// Those test overrides are compiled in ONLY under `#[cfg(any(test, feature = "test-tls-overrides"))]`.
pub fn build_control_client_config(authority: &str) -> Result<ControlClientConfig, ControlError> {
    #[cfg(not(any(test, feature = "test-tls-overrides")))]
    {
        ControlClientConfig::new(authority)
    }

    #[cfg(any(test, feature = "test-tls-overrides"))]
    {
        let mut cfg = ControlClientConfig::new(authority)?;

        if let Ok(raw_addr) = std::env::var("OUTPOST_TEST_CONNECT_ADDR") {
            let trimmed = raw_addr.trim();
            if !trimmed.is_empty() {
                let addr = trimmed.parse::<SocketAddr>().map_err(|e| {
                    ControlError::InvalidRequest(format!("invalid OUTPOST_TEST_CONNECT_ADDR: {e}"))
                })?;
                cfg = cfg.with_connect_addr(addr);
            }
        }

        if let Ok(raw_ca) = std::env::var("OUTPOST_TEST_CA_PEM") {
            let trimmed = raw_ca.trim();
            if !trimmed.is_empty() {
                let pem_text = if trimmed.contains("-----BEGIN CERTIFICATE-----") {
                    trimmed.to_string()
                } else {
                    std::fs::read_to_string(trimmed).map_err(|e| {
                        ControlError::TlsConfig(format!(
                            "failed to read OUTPOST_TEST_CA_PEM file '{trimmed}': {e}"
                        ))
                    })?
                };
                let ders = parse_pem_certificates(&pem_text)?;
                if ders.is_empty() {
                    return Err(ControlError::TlsConfig(
                        "OUTPOST_TEST_CA_PEM contained no certificates".to_string(),
                    ));
                }
                let mut roots = rustls::RootCertStore::empty();
                for der in ders {
                    roots
                        .add(der)
                        .map_err(|e| ControlError::TlsConfig(format!("invalid CA cert: {e}")))?;
                }
                let tls_cfg = build_tls13_client_config_with_roots(roots)?;
                cfg = cfg.with_tls_config(tls_cfg);
            }
        }

        Ok(cfg)
    }
}

/// Owned minimal PEM certificate parser (zero external crate dependencies).
#[cfg(any(test, feature = "test-tls-overrides"))]
fn parse_pem_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, ControlError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64_buf = String::new();

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == BEGIN {
            in_cert = true;
            b64_buf.clear();
            continue;
        }
        if trimmed == END {
            if in_cert {
                let der = B64
                    .decode(b64_buf.as_bytes())
                    .map_err(|e| ControlError::TlsConfig(format!("invalid PEM base64: {e}")))?;
                certs.push(CertificateDer::from(der));
                b64_buf.clear();
                in_cert = false;
            }
            continue;
        }
        if in_cert {
            b64_buf.push_str(trimmed);
        }
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use outpost_core::mls_store::{
        MlsDedupEntry, MlsRoomSnapshotPlain, PersistedOutboxEntry, PersistedPinnedRoot,
    };

    use super::{
        load_mls_room_snapshot, lock_state, open_mls_device_dir, open_state_dir,
        remove_mls_room_snapshot, save_mls_room_snapshot,
    };

    #[test]
    fn backup_excluded_encrypted_mls_storage_roundtrip_under_state_lock() -> Result<(), String> {
        let base = std::env::temp_dir().join(format!(
            "outpost-cli-mls-store-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let state_dir = open_state_dir(&base)?;
        let lock = lock_state(&state_dir)?;
        let device_secret = [0x5Au8; 32];
        let device_id = 2001u64;
        let party_id = 7701u64;
        let group_id = [0x33u8; 24];

        let mls_dir = open_mls_device_dir(&base, device_id)?;
        #[cfg(target_os = "macos")]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt as _;
            let p = CString::new(mls_dir.path().as_os_str().as_bytes())
                .map_err(|e| e.to_string())?;
            let attr = CString::new(outpost_daemon::MACOS_BACKUP_EXCLUDE_XATTR)
                .map_err(|e| e.to_string())?;
            let mut buf = [0u8; 128];
            #[allow(unsafe_code)]
            let rc = unsafe {
                libc::getxattr(
                    p.as_ptr(),
                    attr.as_ptr(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    0,
                    0,
                )
            };
            assert!(rc > 0, "macOS backup exclusion xattr missing on MLS device dir");
            assert_eq!(
                buf.get(..rc as usize),
                Some(outpost_daemon::MACOS_BACKUP_EXCLUDE_BPLIST.as_slice())
            );
        }
        #[cfg(target_os = "linux")]
        {
            assert!(mls_dir.path().join(".nobackup").exists());
            assert!(mls_dir.path().join("CACHEDIR.TAG").exists());
        }

        let snap = MlsRoomSnapshotPlain {
            mls_storage_blob: vec![9, 8, 7, 6],
            epoch: 3,
            device_epoch_seq: 12,
            total_sent_frames_in_epoch: 5,
            cloned_device_key_suspected: false,
            local_cache_wiped: false,
            inviter_unconfirmed: false,
            outbox: vec![PersistedOutboxEntry {
                inner_msg_id: [0x11; 16],
                client_msg_id: "mp2-2001-9".to_string(),
                msg_class: 1,
                target_selector: "@all".to_string(),
                plaintext: b"persist before send".to_vec(),
                sent_epoch: 3,
                device_epoch_seq: 12,
                wire_bytes: vec![0xAB; 32],
            }],
            dedup_ring: vec![MlsDedupEntry {
                group_id,
                auth_device_id: 2002,
                inner_msg_id: [0x22; 16],
            }],
            pinned_roots: vec![PersistedPinnedRoot {
                account_id: 1002,
                root_pubkey: [0x44; 32],
                root_gen: 1,
                custody_mode: 1,
                verified_oob: true,
                pending_oob_reverify: false,
            }],
            pending_key_packages: Vec::new(),
            device_binding_236b: vec![0x55; 236],
            device_list_blob: vec![0x66; 64],
            welcome_receipt: None,
        };

        save_mls_room_snapshot(
            &base,
            &lock,
            &device_secret,
            device_id,
            party_id,
            &group_id,
            &snap,
        )?;
        let loaded = load_mls_room_snapshot(&base, &device_secret, device_id, party_id, &group_id)?;
        assert_eq!(loaded, Some(snap));

        remove_mls_room_snapshot(&base, &lock, device_id, party_id);
        let after_rm =
            load_mls_room_snapshot(&base, &device_secret, device_id, party_id, &group_id)?;
        assert_eq!(after_rm, None);

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }
}
