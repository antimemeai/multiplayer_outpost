//! Binary IPC payload codecs and async frame reader/writer over Unix sockets.

use mp_protocol::MAX_SAFE_ID;
use outpost_core::ipc_wire::{
    ClientKind, HelloAckPayload, HelloPayload, IPC_HEADER_BYTES, IpcFrame, IpcWireError,
    decode_ipc_header, encode_ipc_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::DaemonError;

const MAX_EXE_PATH_BYTES: usize = 1024;
const MAX_ERROR_MSG_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DrainMode {
    RestartKeepParty = 0,
    StopDetach = 1,
    StopLeaveParty = 2,
}

impl DrainMode {
    pub const fn from_u8(v: u8) -> Result<Self, IpcWireError> {
        match v {
            0 => Ok(Self::RestartKeepParty),
            1 => Ok(Self::StopDetach),
            2 => Ok(Self::StopLeaveParty),
            _ => Err(IpcWireError::InvalidEnum),
        }
    }
}

pub fn encode_hello(p: &HelloPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 + 32 + 1 + 4);
    out.extend_from_slice(&p.ipc_schema_ver.to_le_bytes());
    out.extend_from_slice(&p.build_order.to_le_bytes());
    out.extend_from_slice(&p.build_digest);
    out.push(p.client_kind as u8);
    out.extend_from_slice(&p.client_pid.to_le_bytes());
    out
}

pub fn decode_hello(bytes: &[u8]) -> Result<HelloPayload, IpcWireError> {
    if bytes.len() < 49 {
        return Err(IpcWireError::Truncated);
    }
    if bytes.len() > 49 {
        return Err(IpcWireError::TrailingBytes);
    }
    let schema_arr: [u8; 4] = bytes
        .get(0..4)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let order_arr: [u8; 8] = bytes
        .get(4..12)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let digest_arr: [u8; 32] = bytes
        .get(12..44)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let kind_byte = bytes.get(44).copied().ok_or(IpcWireError::Truncated)?;
    let pid_arr: [u8; 4] = bytes
        .get(45..49)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;

    Ok(HelloPayload {
        ipc_schema_ver: u32::from_le_bytes(schema_arr),
        build_order: u64::from_le_bytes(order_arr),
        build_digest: digest_arr,
        client_kind: ClientKind::from_u8(kind_byte)?,
        client_pid: u32::from_le_bytes(pid_arr),
    })
}

pub fn encode_hello_ack(p: &HelloAckPayload) -> Result<Vec<u8>, IpcWireError> {
    if p.daemon_epoch == 0 || p.daemon_epoch > MAX_SAFE_ID {
        return Err(IpcWireError::InvalidId);
    }
    if p.device_id == 0 || p.device_id > MAX_SAFE_ID {
        return Err(IpcWireError::InvalidId);
    }
    if p.active_party_id > MAX_SAFE_ID {
        return Err(IpcWireError::InvalidId);
    }
    if p.exe_path.len() > MAX_EXE_PATH_BYTES {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut out = Vec::with_capacity(4 + 8 + 32 + 8 + 4 + 8 + 8 + 2 + p.exe_path.len());
    out.extend_from_slice(&p.ipc_schema_ver.to_le_bytes());
    out.extend_from_slice(&p.build_order.to_le_bytes());
    out.extend_from_slice(&p.build_digest);
    out.extend_from_slice(&p.daemon_epoch.to_le_bytes());
    out.extend_from_slice(&p.daemon_pid.to_le_bytes());
    out.extend_from_slice(&p.device_id.to_le_bytes());
    out.extend_from_slice(&p.active_party_id.to_le_bytes());
    out.extend_from_slice(&(p.exe_path.len() as u16).to_le_bytes());
    out.extend_from_slice(p.exe_path.as_bytes());
    Ok(out)
}

pub fn decode_hello_ack(bytes: &[u8]) -> Result<HelloAckPayload, IpcWireError> {
    if bytes.len() < 74 {
        return Err(IpcWireError::Truncated);
    }
    let schema_arr: [u8; 4] = bytes
        .get(0..4)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let order_arr: [u8; 8] = bytes
        .get(4..12)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let digest_arr: [u8; 32] = bytes
        .get(12..44)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let epoch_arr: [u8; 8] = bytes
        .get(44..52)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let pid_arr: [u8; 4] = bytes
        .get(52..56)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let dev_arr: [u8; 8] = bytes
        .get(56..64)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let party_arr: [u8; 8] = bytes
        .get(64..72)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let path_len_arr: [u8; 2] = bytes
        .get(72..74)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;

    let daemon_epoch = u64::from_le_bytes(epoch_arr);
    let device_id = u64::from_le_bytes(dev_arr);
    let active_party_id = u64::from_le_bytes(party_arr);
    if daemon_epoch == 0
        || daemon_epoch > MAX_SAFE_ID
        || device_id == 0
        || device_id > MAX_SAFE_ID
        || active_party_id > MAX_SAFE_ID
    {
        return Err(IpcWireError::InvalidId);
    }

    let path_len = usize::from(u16::from_le_bytes(path_len_arr));
    if path_len > MAX_EXE_PATH_BYTES {
        return Err(IpcWireError::BodyTooLarge);
    }
    let rest = bytes.get(74..).ok_or(IpcWireError::Truncated)?;
    if rest.len() < path_len {
        return Err(IpcWireError::Truncated);
    }
    if rest.len() > path_len {
        return Err(IpcWireError::TrailingBytes);
    }
    let exe_path = core::str::from_utf8(rest)
        .map_err(|_| IpcWireError::InvalidUtf8)?
        .to_string();

    Ok(HelloAckPayload {
        ipc_schema_ver: u32::from_le_bytes(schema_arr),
        build_order: u64::from_le_bytes(order_arr),
        build_digest: digest_arr,
        daemon_epoch,
        daemon_pid: u32::from_le_bytes(pid_arr),
        device_id,
        active_party_id,
        exe_path,
    })
}

pub fn encode_error_payload(code: u16, retryable: bool, message: &str) -> Vec<u8> {
    let cut = message.floor_char_boundary(MAX_ERROR_MSG_BYTES);
    let trimmed = message.as_bytes().get(..cut).unwrap_or_default();
    let mut out = Vec::with_capacity(5 + trimmed.len());
    out.extend_from_slice(&code.to_le_bytes());
    out.push(u8::from(retryable));
    out.extend_from_slice(&(trimmed.len() as u16).to_le_bytes());
    out.extend_from_slice(trimmed);
    out
}

pub fn decode_error_payload(bytes: &[u8]) -> Result<(u16, bool, String), IpcWireError> {
    if bytes.len() < 5 {
        return Err(IpcWireError::Truncated);
    }
    let code_arr: [u8; 2] = bytes
        .get(0..2)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let retry_byte = bytes.get(2).copied().ok_or(IpcWireError::Truncated)?;
    if retry_byte > 1 {
        return Err(IpcWireError::InvalidEnum);
    }
    let len_arr: [u8; 2] = bytes
        .get(3..5)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let msg_len = usize::from(u16::from_le_bytes(len_arr));
    if msg_len > MAX_ERROR_MSG_BYTES {
        return Err(IpcWireError::BodyTooLarge);
    }
    let rest = bytes.get(5..).ok_or(IpcWireError::Truncated)?;
    if rest.len() < msg_len {
        return Err(IpcWireError::Truncated);
    }
    if rest.len() > msg_len {
        return Err(IpcWireError::TrailingBytes);
    }
    let msg = core::str::from_utf8(rest)
        .map_err(|_| IpcWireError::InvalidUtf8)?
        .to_string();
    Ok((u16::from_le_bytes(code_arr), retry_byte == 1, msg))
}

pub fn encode_cancel_payload(target_request_id: u64) -> Result<Vec<u8>, IpcWireError> {
    if target_request_id == 0 || target_request_id > MAX_SAFE_ID {
        return Err(IpcWireError::InvalidRequestId);
    }
    Ok(target_request_id.to_le_bytes().to_vec())
}

pub fn decode_cancel_payload(bytes: &[u8]) -> Result<u64, IpcWireError> {
    if bytes.len() < 8 {
        return Err(IpcWireError::Truncated);
    }
    if bytes.len() > 8 {
        return Err(IpcWireError::TrailingBytes);
    }
    let arr: [u8; 8] = bytes.try_into().map_err(|_| IpcWireError::Truncated)?;
    let id = u64::from_le_bytes(arr);
    if id == 0 || id > MAX_SAFE_ID {
        return Err(IpcWireError::InvalidRequestId);
    }
    Ok(id)
}

pub fn encode_drain_payload(mode: DrainMode) -> Vec<u8> {
    vec![mode as u8]
}

pub fn decode_drain_payload(bytes: &[u8]) -> Result<DrainMode, IpcWireError> {
    if bytes.is_empty() {
        return Err(IpcWireError::Truncated);
    }
    if bytes.len() > 1 {
        return Err(IpcWireError::TrailingBytes);
    }
    let b = bytes.first().copied().ok_or(IpcWireError::Truncated)?;
    DrainMode::from_u8(b)
}

/// Reads a single binary IPC frame from an async reader, returning `Ok(None)` on clean EOF.
pub async fn read_ipc_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<IpcFrame>, DaemonError> {
    let mut header = [0u8; IPC_HEADER_BYTES];
    let mut read = 0usize;
    while read < IPC_HEADER_BYTES {
        let Some(dst) = header.get_mut(read..) else {
            break;
        };
        let n = reader
            .read(dst)
            .await
            .map_err(|e| DaemonError::io("read ipc frame header", e))?;
        if n == 0 {
            if read == 0 {
                return Ok(None);
            }
            return Err(DaemonError::IpcWire(IpcWireError::Truncated));
        }
        read = read.saturating_add(n);
    }

    let (body_len, opcode, request_id) = decode_ipc_header(&header)?;
    let mut payload = vec![0u8; body_len];
    if body_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| DaemonError::io("read ipc frame body", e))?;
    }
    Ok(Some(IpcFrame {
        opcode,
        request_id,
        payload,
    }))
}

/// Writes a single binary IPC frame to an async writer and flushes it.
pub async fn write_ipc_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &IpcFrame,
) -> Result<(), DaemonError> {
    let encoded = encode_ipc_frame(frame)?;
    writer
        .write_all(&encoded)
        .await
        .map_err(|e| DaemonError::io("write ipc frame", e))?;
    writer
        .flush()
        .await
        .map_err(|e| DaemonError::io("flush ipc frame", e))?;
    Ok(())
}
