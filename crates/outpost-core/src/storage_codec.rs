//! Versioned binary persistence codecs (zero JSON internally, CRC32C protected).
//!
//! File magics:
//! - `MPD1`: Hot enrolled device record (`d<13hex>.dev.bin`)
//! - `MPX1`: Default active device selector (`default_device.bin`)
//! - `MPN1`: Staged pre-ID `device init` record (`pending_dev.bin`)
//! - `MPR2`: Crash-safe `account register` journal (`pending_reg.bin`)
//! - `MPP1`: Known peers TOFU store (`peers.bin`)
//! - `MPE1`: Durable party epoch floor LRU (`epochs.bin`)
//! - `MPI1`: Runtime daemon descriptor (`daemon.info`)

use core::fmt;

use mp_protocol::{MAX_CWT_BYTES, MAX_SAFE_ID, RelayPolicy};

use crate::crc32c::crc32c;

pub const STORAGE_FORMAT_VER: u16 = 1;
pub const MAX_PEERS_RECORDS: usize = 4096;
pub const MAX_EPOCH_ENTRIES: usize = 64;
pub const MAX_STRING_FIELD: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustState {
    Unpinned = 0,
    PinnedTrusted = 1,
    RevokedBlocked = 2,
}

impl TrustState {
    pub const fn from_persisted_u8(v: u8) -> Result<Self, StorageCodecError> {
        match v {
            1 => Ok(Self::PinnedTrusted),
            2 => Ok(Self::RevokedBlocked),
            _ => Err(StorageCodecError::InvalidEnum),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub account_id: u64,
    pub device_id: u64,
    pub root_pubkey: [u8; 32],
    pub device_secret: [u8; 32],
    pub device_pubkey: [u8; 32],
    pub device_cwt: Vec<u8>,
    pub local_relay_policy: RelayPolicy,
    pub api_authority: String,
    pub default_relay_url: String,
    pub device_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultDeviceRecord {
    pub device_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDeviceRecord {
    pub device_secret: [u8; 32],
    pub device_pubkey: [u8; 32],
    pub device_label: String,
    pub local_relay_policy: RelayPolicy,
    pub api_authority: String,
    pub default_relay_url: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRegRecord {
    pub idempotency_key: [u8; 32],
    pub root_pubkey: [u8; 32],
    pub device_secret: [u8; 32],
    pub device_pubkey: [u8; 32],
    pub handle: String,
    pub device_label: String,
    pub api_authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub api_authority_hash: [u8; 8],
    pub account_id: u64,
    pub root_pubkey: [u8; 32],
    pub trust_state: TrustState,
    pub pinned_at_ms: u64,
    pub handle_prop: String,
    pub handle_fetched_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeersStoreRecord {
    pub peers: Vec<PeerRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochFloorEntry {
    pub api_authority_hash: [u8; 8],
    pub party_id: u64,
    pub highest_party_epoch: u64,
    pub terminal_disbanded: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpochsStoreRecord {
    pub entries: Vec<EpochFloorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonInfoRecord {
    pub pid: u32,
    pub native_start_token: u64,
    pub daemon_epoch: u64,
    pub ipc_schema_ver: u32,
    pub build_order: u64,
    pub build_digest: [u8; 32],
    pub device_id: u64,
    pub exe_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageCodecError {
    Truncated,
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    NonZeroFlags,
    CrcMismatch,
    InvalidId,
    InvalidEnum,
    FieldTooLarge,
    InvalidUtf8,
    TooManyEntries,
}

impl fmt::Display for StorageCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StorageCodecError {}

fn check_safe_id(id: u64) -> Result<u64, StorageCodecError> {
    if id == 0 || id > MAX_SAFE_ID {
        return Err(StorageCodecError::InvalidId);
    }
    Ok(id)
}

fn begin_envelope(magic: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&magic);
    out.extend_from_slice(&STORAGE_FORMAT_VER.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn finish_envelope(mut out: Vec<u8>) -> Vec<u8> {
    let sum = crc32c(&out);
    out.extend_from_slice(&sum.to_le_bytes());
    out
}

fn write_str_u16(out: &mut Vec<u8>, s: &str, max_len: usize) -> Result<(), StorageCodecError> {
    if s.len() > max_len || s.len() > usize::from(u16::MAX) {
        return Err(StorageCodecError::FieldTooLarge);
    }
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn write_bytes_u16(out: &mut Vec<u8>, b: &[u8], max_len: usize) -> Result<(), StorageCodecError> {
    if b.len() > max_len || b.len() > usize::from(u16::MAX) {
        return Err(StorageCodecError::FieldTooLarge);
    }
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
    Ok(())
}

struct BinReader<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> BinReader<'a> {
    fn open(bytes: &'a [u8], expected_magic: [u8; 4]) -> Result<Self, StorageCodecError> {
        if bytes.len() < 12 {
            return Err(StorageCodecError::Truncated);
        }
        let body_len = bytes.len().checked_sub(4).ok_or(StorageCodecError::Truncated)?;
        let (content, crc_slice) = bytes.split_at(body_len);
        let expected_crc_arr: [u8; 4] = crc_slice
            .try_into()
            .map_err(|_| StorageCodecError::Truncated)?;
        if crc32c(content) != u32::from_le_bytes(expected_crc_arr) {
            return Err(StorageCodecError::CrcMismatch);
        }
        let magic = content.get(0..4).ok_or(StorageCodecError::Truncated)?;
        if magic != expected_magic {
            return Err(StorageCodecError::BadMagic);
        }
        let ver_arr: [u8; 2] = content
            .get(4..6)
            .ok_or(StorageCodecError::Truncated)?
            .try_into()
            .map_err(|_| StorageCodecError::Truncated)?;
        if u16::from_le_bytes(ver_arr) != STORAGE_FORMAT_VER {
            return Err(StorageCodecError::UnsupportedVersion);
        }
        let flags_arr: [u8; 2] = content
            .get(6..8)
            .ok_or(StorageCodecError::Truncated)?
            .try_into()
            .map_err(|_| StorageCodecError::Truncated)?;
        if u16::from_le_bytes(flags_arr) != 0 {
            return Err(StorageCodecError::NonZeroFlags);
        }
        Ok(Self {
            body: content.get(8..).ok_or(StorageCodecError::Truncated)?,
            pos: 0,
        })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StorageCodecError> {
        let end = self.pos.checked_add(n).ok_or(StorageCodecError::Truncated)?;
        let s = self
            .body
            .get(self.pos..end)
            .ok_or(StorageCodecError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn read_u8(&mut self) -> Result<u8, StorageCodecError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(StorageCodecError::Truncated)
    }

    fn read_u16(&mut self) -> Result<u16, StorageCodecError> {
        let arr: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| StorageCodecError::Truncated)?;
        Ok(u16::from_le_bytes(arr))
    }

    fn read_u32(&mut self) -> Result<u32, StorageCodecError> {
        let arr: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| StorageCodecError::Truncated)?;
        Ok(u32::from_le_bytes(arr))
    }

    fn read_u64(&mut self) -> Result<u64, StorageCodecError> {
        let arr: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| StorageCodecError::Truncated)?;
        Ok(u64::from_le_bytes(arr))
    }

    fn read_arr<const N: usize>(&mut self) -> Result<[u8; N], StorageCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageCodecError::Truncated)
    }

    fn read_bytes_u16(&mut self, max_len: usize) -> Result<Vec<u8>, StorageCodecError> {
        let len = usize::from(self.read_u16()?);
        if len > max_len {
            return Err(StorageCodecError::FieldTooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn read_str_u16(&mut self, max_len: usize) -> Result<String, StorageCodecError> {
        let raw = self.read_bytes_u16(max_len)?;
        let s = core::str::from_utf8(&raw).map_err(|_| StorageCodecError::InvalidUtf8)?;
        Ok(s.to_string())
    }

    fn finish(self) -> Result<(), StorageCodecError> {
        if self.pos != self.body.len() {
            return Err(StorageCodecError::TrailingBytes);
        }
        Ok(())
    }
}

pub fn encode_device_record(r: &DeviceRecord) -> Result<Vec<u8>, StorageCodecError> {
    check_safe_id(r.account_id)?;
    check_safe_id(r.device_id)?;
    let mut out = begin_envelope(*b"MPD1");
    out.extend_from_slice(&r.account_id.to_le_bytes());
    out.extend_from_slice(&r.device_id.to_le_bytes());
    out.extend_from_slice(&r.root_pubkey);
    out.extend_from_slice(&r.device_secret);
    out.extend_from_slice(&r.device_pubkey);
    write_bytes_u16(&mut out, &r.device_cwt, MAX_CWT_BYTES)?;
    out.push(r.local_relay_policy as u8);
    write_str_u16(&mut out, &r.api_authority, 256)?;
    write_str_u16(&mut out, &r.default_relay_url, 256)?;
    write_str_u16(&mut out, &r.device_label, 64)?;
    Ok(finish_envelope(out))
}

pub fn decode_device_record(bytes: &[u8]) -> Result<DeviceRecord, StorageCodecError> {
    let mut r = BinReader::open(bytes, *b"MPD1")?;
    let account_id = check_safe_id(r.read_u64()?)?;
    let device_id = check_safe_id(r.read_u64()?)?;
    let root_pubkey = r.read_arr::<32>()?;
    let device_secret = r.read_arr::<32>()?;
    let device_pubkey = r.read_arr::<32>()?;
    let device_cwt = r.read_bytes_u16(MAX_CWT_BYTES)?;
    let local_relay_policy =
        RelayPolicy::from_u8(r.read_u8()?).map_err(|_| StorageCodecError::InvalidEnum)?;
    let api_authority = r.read_str_u16(256)?;
    let default_relay_url = r.read_str_u16(256)?;
    let device_label = r.read_str_u16(64)?;
    r.finish()?;
    Ok(DeviceRecord {
        account_id,
        device_id,
        root_pubkey,
        device_secret,
        device_pubkey,
        device_cwt,
        local_relay_policy,
        api_authority,
        default_relay_url,
        device_label,
    })
}

pub fn encode_default_device(r: &DefaultDeviceRecord) -> Result<Vec<u8>, StorageCodecError> {
    check_safe_id(r.device_id)?;
    let mut out = begin_envelope(*b"MPX1");
    out.extend_from_slice(&r.device_id.to_le_bytes());
    Ok(finish_envelope(out))
}

pub fn decode_default_device(bytes: &[u8]) -> Result<DefaultDeviceRecord, StorageCodecError> {
    let mut r = BinReader::open(bytes, *b"MPX1")?;
    let device_id = check_safe_id(r.read_u64()?)?;
    r.finish()?;
    Ok(DefaultDeviceRecord { device_id })
}

pub fn encode_pending_device(r: &PendingDeviceRecord) -> Result<Vec<u8>, StorageCodecError> {
    let mut out = begin_envelope(*b"MPN1");
    out.extend_from_slice(&r.device_secret);
    out.extend_from_slice(&r.device_pubkey);
    write_str_u16(&mut out, &r.device_label, 64)?;
    out.push(r.local_relay_policy as u8);
    write_str_u16(&mut out, &r.api_authority, 256)?;
    write_str_u16(&mut out, &r.default_relay_url, 256)?;
    out.extend_from_slice(&r.created_at_ms.to_le_bytes());
    Ok(finish_envelope(out))
}

pub fn decode_pending_device(bytes: &[u8]) -> Result<PendingDeviceRecord, StorageCodecError> {
    let mut r = BinReader::open(bytes, *b"MPN1")?;
    let device_secret = r.read_arr::<32>()?;
    let device_pubkey = r.read_arr::<32>()?;
    let device_label = r.read_str_u16(64)?;
    let local_relay_policy =
        RelayPolicy::from_u8(r.read_u8()?).map_err(|_| StorageCodecError::InvalidEnum)?;
    let api_authority = r.read_str_u16(256)?;
    let default_relay_url = r.read_str_u16(256)?;
    let created_at_ms = r.read_u64()?;
    r.finish()?;
    Ok(PendingDeviceRecord {
        device_secret,
        device_pubkey,
        device_label,
        local_relay_policy,
        api_authority,
        default_relay_url,
        created_at_ms,
    })
}

pub fn encode_pending_reg(r: &PendingRegRecord) -> Result<Vec<u8>, StorageCodecError> {
    let mut out = begin_envelope(*b"MPR2");
    out.extend_from_slice(&r.idempotency_key);
    out.extend_from_slice(&r.root_pubkey);
    out.extend_from_slice(&r.device_secret);
    out.extend_from_slice(&r.device_pubkey);
    write_str_u16(&mut out, &r.handle, 64)?;
    write_str_u16(&mut out, &r.device_label, 64)?;
    write_str_u16(&mut out, &r.api_authority, 256)?;
    Ok(finish_envelope(out))
}

pub fn decode_pending_reg(bytes: &[u8]) -> Result<PendingRegRecord, StorageCodecError> {
    let mut r = BinReader::open(bytes, *b"MPR2")?;
    let idempotency_key = r.read_arr::<32>()?;
    let root_pubkey = r.read_arr::<32>()?;
    let device_secret = r.read_arr::<32>()?;
    let device_pubkey = r.read_arr::<32>()?;
    let handle = r.read_str_u16(64)?;
    let device_label = r.read_str_u16(64)?;
    let api_authority = r.read_str_u16(256)?;
    r.finish()?;
    Ok(PendingRegRecord {
        idempotency_key,
        root_pubkey,
        device_secret,
        device_pubkey,
        handle,
        device_label,
        api_authority,
    })
}

pub fn encode_peers_store(store: &PeersStoreRecord) -> Result<Vec<u8>, StorageCodecError> {
    if store.peers.len() > MAX_PEERS_RECORDS {
        return Err(StorageCodecError::TooManyEntries);
    }
    let mut out = begin_envelope(*b"MPP1");
    out.extend_from_slice(&(store.peers.len() as u32).to_le_bytes());
    for p in &store.peers {
        check_safe_id(p.account_id)?;
        if p.trust_state == TrustState::Unpinned {
            return Err(StorageCodecError::InvalidEnum);
        }
        out.extend_from_slice(&p.api_authority_hash);
        out.extend_from_slice(&p.account_id.to_le_bytes());
        out.extend_from_slice(&p.root_pubkey);
        out.push(p.trust_state as u8);
        out.extend_from_slice(&p.pinned_at_ms.to_le_bytes());
        write_str_u16(&mut out, &p.handle_prop, 64)?;
        out.extend_from_slice(&p.handle_fetched_ms.to_le_bytes());
    }
    Ok(finish_envelope(out))
}

pub fn decode_peers_store(bytes: &[u8]) -> Result<PeersStoreRecord, StorageCodecError> {
    let mut r = BinReader::open(bytes, *b"MPP1")?;
    let count = r.read_u32()? as usize;
    if count > MAX_PEERS_RECORDS {
        return Err(StorageCodecError::TooManyEntries);
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        let api_authority_hash = r.read_arr::<8>()?;
        let account_id = check_safe_id(r.read_u64()?)?;
        let root_pubkey = r.read_arr::<32>()?;
        let trust_state = TrustState::from_persisted_u8(r.read_u8()?)?;
        let pinned_at_ms = r.read_u64()?;
        let handle_prop = r.read_str_u16(64)?;
        let handle_fetched_ms = r.read_u64()?;
        peers.push(PeerRecord {
            api_authority_hash,
            account_id,
            root_pubkey,
            trust_state,
            pinned_at_ms,
            handle_prop,
            handle_fetched_ms,
        });
    }
    r.finish()?;
    Ok(PeersStoreRecord { peers })
}

pub fn encode_epochs_store(store: &EpochsStoreRecord) -> Result<Vec<u8>, StorageCodecError> {
    if store.entries.len() > MAX_EPOCH_ENTRIES {
        return Err(StorageCodecError::TooManyEntries);
    }
    let mut out = begin_envelope(*b"MPE1");
    out.extend_from_slice(&(store.entries.len() as u16).to_le_bytes());
    for e in &store.entries {
        check_safe_id(e.party_id)?;
        out.extend_from_slice(&e.api_authority_hash);
        out.extend_from_slice(&e.party_id.to_le_bytes());
        out.extend_from_slice(&e.highest_party_epoch.to_le_bytes());
        out.push(u8::from(e.terminal_disbanded));
        out.extend_from_slice(&e.updated_at_ms.to_le_bytes());
    }
    Ok(finish_envelope(out))
}

pub fn decode_epochs_store(bytes: &[u8]) -> Result<EpochsStoreRecord, StorageCodecError> {
    let mut r = BinReader::open(bytes, *b"MPE1")?;
    let count = usize::from(r.read_u16()?);
    if count > MAX_EPOCH_ENTRIES {
        return Err(StorageCodecError::TooManyEntries);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let api_authority_hash = r.read_arr::<8>()?;
        let party_id = check_safe_id(r.read_u64()?)?;
        let highest_party_epoch = r.read_u64()?;
        let term = r.read_u8()?;
        if term > 1 {
            return Err(StorageCodecError::InvalidEnum);
        }
        let updated_at_ms = r.read_u64()?;
        entries.push(EpochFloorEntry {
            api_authority_hash,
            party_id,
            highest_party_epoch,
            terminal_disbanded: term == 1,
            updated_at_ms,
        });
    }
    r.finish()?;
    Ok(EpochsStoreRecord { entries })
}

pub fn encode_daemon_info(info: &DaemonInfoRecord) -> Result<Vec<u8>, StorageCodecError> {
    check_safe_id(info.device_id)?;
    check_safe_id(info.daemon_epoch)?;
    let mut out = begin_envelope(*b"MPI1");
    out.extend_from_slice(&info.pid.to_le_bytes());
    out.extend_from_slice(&info.native_start_token.to_le_bytes());
    out.extend_from_slice(&info.daemon_epoch.to_le_bytes());
    out.extend_from_slice(&info.ipc_schema_ver.to_le_bytes());
    out.extend_from_slice(&info.build_order.to_le_bytes());
    out.extend_from_slice(&info.build_digest);
    out.extend_from_slice(&info.device_id.to_le_bytes());
    write_str_u16(&mut out, &info.exe_path, MAX_STRING_FIELD)?;
    Ok(finish_envelope(out))
}

pub fn decode_daemon_info(bytes: &[u8]) -> Result<DaemonInfoRecord, StorageCodecError> {
    let mut r = BinReader::open(bytes, *b"MPI1")?;
    let pid = r.read_u32()?;
    let native_start_token = r.read_u64()?;
    let daemon_epoch = check_safe_id(r.read_u64()?)?;
    let ipc_schema_ver = r.read_u32()?;
    let build_order = r.read_u64()?;
    let build_digest = r.read_arr::<32>()?;
    let device_id = check_safe_id(r.read_u64()?)?;
    let exe_path = r.read_str_u16(MAX_STRING_FIELD)?;
    r.finish()?;
    Ok(DaemonInfoRecord {
        pid,
        native_start_token,
        daemon_epoch,
        ipc_schema_ver,
        build_order,
        build_digest,
        device_id,
        exe_path,
    })
}
