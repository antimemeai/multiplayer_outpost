//! Binary persistence helpers under `StateLock` and TLS 1.3 control-plane config builder.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mp_protocol::{MAX_SAFE_ID, sha256};
use outpost_control::{
    ControlClientConfig, ControlError, build_tls13_client_config_with_roots,
};
use outpost_core::storage_codec::{
    DefaultDeviceRecord, DeviceRecord, EpochsStoreRecord, PeersStoreRecord, PendingDeviceRecord,
    PendingRegRecord, decode_default_device, decode_device_record, decode_epochs_store,
    decode_peers_store, decode_pending_device, decode_pending_reg, encode_default_device,
    encode_device_record, encode_epochs_store, encode_peers_store, encode_pending_device,
    encode_pending_reg,
};
use outpost_daemon::{
    DaemonError, StateLock, VerifiedDir, atomic_write_in_dir, format_device_dir_name,
    open_or_create_private_dir, read_file_in_dir, resolve_state_dir,
};
use rustls::pki_types::CertificateDer;

use crate::build_info::encode_hex;

pub const DEFAULT_DEVICE_FILE: &str = "default_device.bin";
pub const PENDING_DEV_FILE: &str = "pending_dev.bin";
pub const PENDING_REG_FILE: &str = "pending_reg.bin";
pub const PEERS_FILE: &str = "peers.bin";
pub const EPOCHS_FILE: &str = "epochs.bin";
pub const DEVICES_SUBDIR: &str = "devices";
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
    let dev_path = state_dir_path.join(DEVICES_SUBDIR);
    if let Ok(entries) = std::fs::read_dir(&dev_path) {
        let mut found = Vec::new();
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
        if found.len() == 1
            && let Some(&only) = found.first()
        {
            return Ok(only);
        }
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

pub fn pubkey_fingerprint_hex(root_pubkey: &[u8; 32]) -> String {
    encode_hex(&sha256(root_pubkey))
}

/// Builds a TLS 1.3-only `ControlClientConfig` for `authority`, honoring explicit
/// `OUTPOST_TEST_CONNECT_ADDR` and `OUTPOST_TEST_CA_PEM` env overrides ONLY when set
/// (while strictly preserving SNI, `Host`, and RFC 9421 `@authority`).
pub fn build_control_client_config(authority: &str) -> Result<ControlClientConfig, ControlError> {
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

/// Owned minimal PEM certificate parser (zero external crate dependencies).
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
