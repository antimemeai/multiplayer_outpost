//! Binary local IPC (`d.sock`, 16-byte LE header, 2 MiB body cap), unified binary
//! readiness pipe codec, and schema-versioned daemon coexistence policy.

use core::fmt;

use mp_protocol::MAX_SAFE_ID;

pub const IPC_SCHEMA_VER: u32 = 4;
pub const IPC_WIRE_VER: u16 = 1;
pub const IPC_HEADER_BYTES: usize = 16;
pub const MAX_IPC_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_READY_ERR_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientKind {
    Cli = 1,
    Mcp = 2,
}

impl ClientKind {
    pub const fn from_u8(v: u8) -> Result<Self, IpcWireError> {
        match v {
            1 => Ok(Self::Cli),
            2 => Ok(Self::Mcp),
            _ => Err(IpcWireError::InvalidEnum),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IpcOpcode {
    Hello = 0x0001,
    HelloAck = 0x0002,
    Error = 0x0003,
    Cancel = 0x0004,
    DrainAndShutdown = 0x0005,
    ReloadDevice = 0x0006,
    GetStatus = 0x0010,
    PartyList = 0x0020,
    PartyMembers = 0x0021,
    PartySendChat = 0x0022,
    PartyPostBoard = 0x0023,
    PartyPoll = 0x0024,
    PartyWait = 0x0025,
    PartySendControlNotice = 0x0026,
    FriendsList = 0x0027,
    PartyCreate = 0x0030,
    PartyJoin = 0x0031,
    PartyLeave = 0x0032,
    PartyDisband = 0x0033,
    PartyKick = 0x0034,
    PartyPromote = 0x0035,
    PartyInviteMint = 0x0036,
    PartyInviteRevoke = 0x0037,
    PartyRequestsList = 0x0038,
    PartyRequestApprove = 0x0039,
    PartyRequestReject = 0x003A,
    FriendRequest = 0x003B,
    FriendRemove = 0x003C,
    FriendBlock = 0x003D,
    ResolveHandle = 0x003E,
    RoomInvite = 0x0040,
    RoomEnter = 0x0041,
    RoomLeave = 0x0042,
    FriendsLive = 0x0043,
}

impl IpcOpcode {
    pub const fn from_u16(v: u16) -> Result<Self, IpcWireError> {
        match v {
            0x0001 => Ok(Self::Hello),
            0x0002 => Ok(Self::HelloAck),
            0x0003 => Ok(Self::Error),
            0x0004 => Ok(Self::Cancel),
            0x0005 => Ok(Self::DrainAndShutdown),
            0x0006 => Ok(Self::ReloadDevice),
            0x0010 => Ok(Self::GetStatus),
            0x0020 => Ok(Self::PartyList),
            0x0021 => Ok(Self::PartyMembers),
            0x0022 => Ok(Self::PartySendChat),
            0x0023 => Ok(Self::PartyPostBoard),
            0x0024 => Ok(Self::PartyPoll),
            0x0025 => Ok(Self::PartyWait),
            0x0026 => Ok(Self::PartySendControlNotice),
            0x0027 => Ok(Self::FriendsList),
            0x0030 => Ok(Self::PartyCreate),
            0x0031 => Ok(Self::PartyJoin),
            0x0032 => Ok(Self::PartyLeave),
            0x0033 => Ok(Self::PartyDisband),
            0x0034 => Ok(Self::PartyKick),
            0x0035 => Ok(Self::PartyPromote),
            0x0036 => Ok(Self::PartyInviteMint),
            0x0037 => Ok(Self::PartyInviteRevoke),
            0x0038 => Ok(Self::PartyRequestsList),
            0x0039 => Ok(Self::PartyRequestApprove),
            0x003A => Ok(Self::PartyRequestReject),
            0x003B => Ok(Self::FriendRequest),
            0x003C => Ok(Self::FriendRemove),
            0x003D => Ok(Self::FriendBlock),
            0x003E => Ok(Self::ResolveHandle),
            0x0040 => Ok(Self::RoomInvite),
            0x0041 => Ok(Self::RoomEnter),
            0x0042 => Ok(Self::RoomLeave),
            0x0043 => Ok(Self::FriendsLive),
            _ => Err(IpcWireError::UnknownOpcode),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcFrame {
    pub opcode: IpcOpcode,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPayload {
    pub ipc_schema_ver: u32,
    pub build_order: u64,
    pub build_digest: [u8; 32],
    pub client_kind: ClientKind,
    pub client_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAckPayload {
    pub ipc_schema_ver: u32,
    pub build_order: u64,
    pub build_digest: [u8; 32],
    pub daemon_epoch: u64,
    pub daemon_pid: u32,
    pub device_id: u64,
    pub active_party_id: u64,
    pub exe_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloCompatAction {
    Coexist { upgrade_available: bool },
    DrainAndUpgrade,
    ErrorIncompatibleSchema { daemon_schema: u32 },
}

/// Evaluates client <-> daemon compatibility without ever causing A/B/A respawn wars:
/// - Compatible schema: ALWAYS coexist (never kill a healthy compatible daemon).
/// - `ClientKind::Mcp`: NEVER drains/kills a daemon.
/// - Read-only CLI (`daemon status`, `daemon logs`): NEVER drains/kills a daemon.
/// - Mutating CLI: drains ONLY on strictly newer schema (`local > daemon`) AND verified
///   on-disk executable digest match (`on_disk_exe_matches_local == true`).
pub const fn evaluate_hello_compat(
    local: &HelloPayload,
    daemon_schema_ver: u32,
    daemon_build_order: u64,
    daemon_build_digest: [u8; 32],
    read_only_cli: bool,
    on_disk_exe_matches_local: bool,
) -> HelloCompatAction {
    if local.ipc_schema_ver == daemon_schema_ver {
        let same_digest = const_eq_32(&local.build_digest, &daemon_build_digest);
        return HelloCompatAction::Coexist {
            upgrade_available: !same_digest && local.build_order != daemon_build_order,
        };
    }
    if matches!(local.client_kind, ClientKind::Mcp) || read_only_cli {
        return HelloCompatAction::ErrorIncompatibleSchema {
            daemon_schema: daemon_schema_ver,
        };
    }
    if local.ipc_schema_ver > daemon_schema_ver && on_disk_exe_matches_local {
        HelloCompatAction::DrainAndUpgrade
    } else {
        HelloCompatAction::ErrorIncompatibleSchema {
            daemon_schema: daemon_schema_ver,
        }
    }
}

#[allow(clippy::indexing_slicing)]
const fn const_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut i = 0usize;
    let mut diff = 0u8;
    while i < 32 {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadyReply {
    Ok { daemon_epoch: u64 },
    Err(String),
    AlreadyRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcWireError {
    Truncated,
    TrailingBytes,
    UnsupportedVersion,
    UnknownOpcode,
    BodyTooLarge,
    InvalidRequestId,
    InvalidId,
    InvalidEnum,
    InvalidUtf8,
}

impl fmt::Display for IpcWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for IpcWireError {}

pub fn encode_ipc_frame(frame: &IpcFrame) -> Result<Vec<u8>, IpcWireError> {
    if frame.payload.len() > MAX_IPC_BODY_BYTES {
        return Err(IpcWireError::BodyTooLarge);
    }
    if frame.request_id == 0 || frame.request_id > MAX_SAFE_ID {
        return Err(IpcWireError::InvalidRequestId);
    }
    let mut out = Vec::with_capacity(IPC_HEADER_BYTES + frame.payload.len());
    out.extend_from_slice(&(frame.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&IPC_WIRE_VER.to_le_bytes());
    out.extend_from_slice(&(frame.opcode as u16).to_le_bytes());
    out.extend_from_slice(&frame.request_id.to_le_bytes());
    out.extend_from_slice(&frame.payload);
    Ok(out)
}

pub fn decode_ipc_header(header: &[u8; IPC_HEADER_BYTES]) -> Result<(usize, IpcOpcode, u64), IpcWireError> {
    let len_arr: [u8; 4] = header
        .get(0..4)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let ver_arr: [u8; 2] = header
        .get(4..6)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let op_arr: [u8; 2] = header
        .get(6..8)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let req_arr: [u8; 8] = header
        .get(8..16)
        .ok_or(IpcWireError::Truncated)?
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;

    let body_len = u32::from_le_bytes(len_arr) as usize;
    if body_len > MAX_IPC_BODY_BYTES {
        return Err(IpcWireError::BodyTooLarge);
    }
    if u16::from_le_bytes(ver_arr) != IPC_WIRE_VER {
        return Err(IpcWireError::UnsupportedVersion);
    }
    let opcode = IpcOpcode::from_u16(u16::from_le_bytes(op_arr))?;
    let request_id = u64::from_le_bytes(req_arr);
    if request_id == 0 || request_id > MAX_SAFE_ID {
        return Err(IpcWireError::InvalidRequestId);
    }
    Ok((body_len, opcode, request_id))
}

pub fn decode_ipc_frame(bytes: &[u8]) -> Result<IpcFrame, IpcWireError> {
    let hdr_slice = bytes.get(0..IPC_HEADER_BYTES).ok_or(IpcWireError::Truncated)?;
    let hdr_arr: [u8; IPC_HEADER_BYTES] = hdr_slice
        .try_into()
        .map_err(|_| IpcWireError::Truncated)?;
    let (body_len, opcode, request_id) = decode_ipc_header(&hdr_arr)?;
    let body = bytes.get(IPC_HEADER_BYTES..).ok_or(IpcWireError::Truncated)?;
    if body.len() < body_len {
        return Err(IpcWireError::Truncated);
    }
    if body.len() > body_len {
        return Err(IpcWireError::TrailingBytes);
    }
    Ok(IpcFrame {
        opcode,
        request_id,
        payload: body.to_vec(),
    })
}

pub fn encode_ready_reply(reply: &ReadyReply) -> Result<Vec<u8>, IpcWireError> {
    match reply {
        ReadyReply::Ok { daemon_epoch } => {
            if *daemon_epoch == 0 || *daemon_epoch > MAX_SAFE_ID {
                return Err(IpcWireError::InvalidId);
            }
            let mut out = Vec::with_capacity(9);
            out.push(0x00);
            out.extend_from_slice(&daemon_epoch.to_le_bytes());
            Ok(out)
        }
        ReadyReply::Err(msg) => {
            let cut = msg.floor_char_boundary(MAX_READY_ERR_BYTES);
            let trimmed = msg.as_bytes().get(..cut).unwrap_or_default();
            let mut out = Vec::with_capacity(3 + trimmed.len());
            out.push(0x01);
            out.extend_from_slice(&(trimmed.len() as u16).to_le_bytes());
            out.extend_from_slice(trimmed);
            Ok(out)
        }
        ReadyReply::AlreadyRunning => Ok(vec![0x02]),
    }
}

pub fn decode_ready_reply(bytes: &[u8]) -> Result<ReadyReply, IpcWireError> {
    let tag = bytes.first().copied().ok_or(IpcWireError::Truncated)?;
    match tag {
        0x00 => {
            if bytes.len() < 9 {
                return Err(IpcWireError::Truncated);
            }
            if bytes.len() > 9 {
                return Err(IpcWireError::TrailingBytes);
            }
            let arr: [u8; 8] = bytes
                .get(1..9)
                .ok_or(IpcWireError::Truncated)?
                .try_into()
                .map_err(|_| IpcWireError::Truncated)?;
            let daemon_epoch = u64::from_le_bytes(arr);
            if daemon_epoch == 0 || daemon_epoch > MAX_SAFE_ID {
                return Err(IpcWireError::InvalidId);
            }
            Ok(ReadyReply::Ok { daemon_epoch })
        }
        0x01 => {
            let len_arr: [u8; 2] = bytes
                .get(1..3)
                .ok_or(IpcWireError::Truncated)?
                .try_into()
                .map_err(|_| IpcWireError::Truncated)?;
            let len = usize::from(u16::from_le_bytes(len_arr));
            if len > MAX_READY_ERR_BYTES {
                return Err(IpcWireError::BodyTooLarge);
            }
            let rest = bytes.get(3..).ok_or(IpcWireError::Truncated)?;
            if rest.len() < len {
                return Err(IpcWireError::Truncated);
            }
            if rest.len() > len {
                return Err(IpcWireError::TrailingBytes);
            }
            let msg = core::str::from_utf8(rest).map_err(|_| IpcWireError::InvalidUtf8)?;
            Ok(ReadyReply::Err(msg.to_string()))
        }
        0x02 => {
            if bytes.len() != 1 {
                return Err(IpcWireError::TrailingBytes);
            }
            Ok(ReadyReply::AlreadyRunning)
        }
        _ => Err(IpcWireError::InvalidEnum),
    }
}
