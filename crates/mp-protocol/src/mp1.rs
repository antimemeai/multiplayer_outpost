//! Compact 16-byte-header `MP1` binary control-plane WebSocket wire codec.
//! Zero JSON internals, exact bounds, `<= 8192 B` hard cap, non-zero flags/reserved rejected.

use core::fmt;

use crate::crypto::Ed25519PubKey;
use crate::cwt::MAX_CWT_BYTES;
use crate::endpoint::{
    EndpointDescriptor, EndpointError, MAX_RELAY_URL_BYTES, RelayPolicy, validate_pinned_relay_url,
};
use crate::ids::{AccountId, DeviceId, IdError, MAX_SAFE_ID, PartyId, PartyInviteId, RequestId, SessionId};
use std::collections::BTreeSet;

pub const MP1_VERSION: u8 = 1;
pub const MP1_HEADER_BYTES: usize = 16;
pub const MAX_MP1_FRAME_BYTES: usize = 8192;
pub const MAX_PARTY_MEMBERS: usize = 12;
pub const MAX_PRESENCE_ENTRIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Opcode {
    HelloAck = 0x0001,
    Error = 0x0002,
    PresenceSet = 0x0101,
    PresenceSnapshot = 0x0102,
    PresenceDelta = 0x0103,
    SocialEvent = 0x0104,
    PartyInviteNotify = 0x0105,
    InboxNotify = 0x0106,
    InboxAcked = 0x0107,
    PartySnapshot = 0x0201,
    PartyMemberJoined = 0x0202,
    PartyEndpointUpdate = 0x0203,
    PartyMemberUpdated = 0x0204,
    PartyMemberLeft = 0x0205,
    PartyLeaderChanged = 0x0206,
    PartyJoinRequestEvent = 0x0207,
    PartyDisbanded = 0x0208,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketRole {
    Account = 1,
    Party = 2,
}

impl SocketRole {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            1 => Ok(Self::Account),
            2 => Ok(Self::Party),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

impl Opcode {
    pub const fn is_allowed_from_client(self, role: SocketRole) -> bool {
        match role {
            SocketRole::Account => matches!(self, Self::PresenceSet),
            SocketRole::Party => matches!(self, Self::PartyEndpointUpdate),
        }
    }

    pub const fn from_u16(v: u16) -> Result<Self, Mp1Error> {
        match v {
            0x0001 => Ok(Self::HelloAck),
            0x0002 => Ok(Self::Error),
            0x0101 => Ok(Self::PresenceSet),
            0x0102 => Ok(Self::PresenceSnapshot),
            0x0103 => Ok(Self::PresenceDelta),
            0x0104 => Ok(Self::SocialEvent),
            0x0105 => Ok(Self::PartyInviteNotify),
            0x0106 => Ok(Self::InboxNotify),
            0x0107 => Ok(Self::InboxAcked),
            0x0201 => Ok(Self::PartySnapshot),
            0x0202 => Ok(Self::PartyMemberJoined),
            0x0203 => Ok(Self::PartyEndpointUpdate),
            0x0204 => Ok(Self::PartyMemberUpdated),
            0x0205 => Ok(Self::PartyMemberLeft),
            0x0206 => Ok(Self::PartyLeaderChanged),
            0x0207 => Ok(Self::PartyJoinRequestEvent),
            0x0208 => Ok(Self::PartyDisbanded),
            _ => Err(Mp1Error::UnknownOpcode(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PresenceVisibility {
    Invisible = 0,
    Online = 1,
    Idle = 2,
    Busy = 3,
}

impl PresenceVisibility {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            0 => Ok(Self::Invisible),
            1 => Ok(Self::Online),
            2 => Ok(Self::Idle),
            3 => Ok(Self::Busy),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocialEventKind {
    FriendRequest = 1,
    FriendAccepted = 2,
    Unfriended = 3,
}

impl SocialEventKind {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            1 => Ok(Self::FriendRequest),
            2 => Ok(Self::FriendAccepted),
            3 => Ok(Self::Unfriended),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PartyVisibility {
    Private = 0,
    Friends = 1,
}

impl PartyVisibility {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            0 => Ok(Self::Private),
            1 => Ok(Self::Friends),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PartyJoinMode {
    InviteOnly = 0,
    ApprovalRequired = 1,
}

impl PartyJoinMode {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            0 => Ok(Self::InviteOnly),
            1 => Ok(Self::ApprovalRequired),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemberLeaveReason {
    Left = 0,
    Kicked = 1,
    DisconnectedTimeout = 2,
    DeviceRevoked = 3,
    ConnectTimeout = 4,
}

impl MemberLeaveReason {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            0 => Ok(Self::Left),
            1 => Ok(Self::Kicked),
            2 => Ok(Self::DisconnectedTimeout),
            3 => Ok(Self::DeviceRevoked),
            4 => Ok(Self::ConnectTimeout),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PartyLeaderChangeReason {
    Promoted = 0,
    AutoMigrated = 1,
}

impl PartyLeaderChangeReason {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            0 => Ok(Self::Promoted),
            1 => Ok(Self::AutoMigrated),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PartyDisbandReason {
    LeaderDisbanded = 0,
    EmptyTimeout = 1,
}

impl PartyDisbandReason {
    pub const fn from_u8(v: u8) -> Result<Self, Mp1Error> {
        match v {
            0 => Ok(Self::LeaderDisbanded),
            1 => Ok(Self::EmptyTimeout),
            _ => Err(Mp1Error::InvalidEnumValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub opcode: Opcode,
    pub seq: u32,
    pub payload_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorFrame {
    pub ref_seq: u32,
    pub code: u16,
    pub retry_after_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceEntry {
    pub account_id: AccountId,
    pub status: PresenceVisibility,
    pub joinable_party_id: Option<PartyId>,
    pub updated_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyMemberRecord {
    pub device_id: DeviceId,
    pub account_id: AccountId,
    pub root_pubkey: Ed25519PubKey,
    pub device_pubkey: Ed25519PubKey,
    pub device_cwt: Vec<u8>,
    pub endpoint: EndpointDescriptor,
    pub joined_seq: u64,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartySnapshot {
    pub party_id: PartyId,
    pub party_epoch: u64,
    pub leader_account_id: AccountId,
    pub leader_device_id: DeviceId,
    pub visibility: PartyVisibility,
    pub join_mode: PartyJoinMode,
    pub relay_policy: RelayPolicy,
    pub max_members: u8,
    pub pinned_relay_url: String,
    pub members: Vec<PartyMemberRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mp1Message {
    HelloAck {
        session_id: SessionId,
        server_now_ms: u64,
        ping_interval_ms: u32,
    },
    Error(ErrorFrame),
    PresenceSet {
        visibility: PresenceVisibility,
        share_party: bool,
    },
    PresenceSnapshot {
        entries: Vec<PresenceEntry>,
    },
    PresenceDelta(PresenceEntry),
    SocialEvent {
        kind: SocialEventKind,
        peer_account_id: AccountId,
    },
    PartyInviteNotify {
        party_invite_id: PartyInviteId,
        party_id: PartyId,
        from_account_id: AccountId,
        expires_at_ms: u64,
    },
    InboxNotify {
        drop_id: u64,
        sender_account_id: AccountId,
        created_at_ms: u64,
        expires_at_ms: u64,
        ciphertext_len: u32,
    },
    InboxAcked {
        drop_id: u64,
        device_id: DeviceId,
    },
    PartySnapshot(PartySnapshot),
    PartyMemberJoined {
        party_epoch: u64,
        member: PartyMemberRecord,
    },
    PartyEndpointUpdate {
        endpoint: EndpointDescriptor,
    },
    PartyMemberUpdated {
        party_epoch: u64,
        device_id: DeviceId,
        connected: bool,
        device_cwt: Vec<u8>,
        endpoint: EndpointDescriptor,
    },
    PartyMemberLeft {
        party_epoch: u64,
        device_id: DeviceId,
        account_id: AccountId,
        reason: MemberLeaveReason,
    },
    PartyLeaderChanged {
        party_epoch: u64,
        new_leader_account_id: AccountId,
        new_leader_device_id: DeviceId,
        reason: PartyLeaderChangeReason,
    },
    PartyJoinRequestEvent {
        request_id: RequestId,
        account_id: AccountId,
        device_id: DeviceId,
        root_pubkey: Ed25519PubKey,
        device_pubkey: Ed25519PubKey,
    },
    PartyDisbanded {
        party_epoch: u64,
        reason: PartyDisbandReason,
    },
}

impl Mp1Message {
    pub const fn opcode(&self) -> Opcode {
        match self {
            Self::HelloAck { .. } => Opcode::HelloAck,
            Self::Error(_) => Opcode::Error,
            Self::PresenceSet { .. } => Opcode::PresenceSet,
            Self::PresenceSnapshot { .. } => Opcode::PresenceSnapshot,
            Self::PresenceDelta(_) => Opcode::PresenceDelta,
            Self::SocialEvent { .. } => Opcode::SocialEvent,
            Self::PartyInviteNotify { .. } => Opcode::PartyInviteNotify,
            Self::InboxNotify { .. } => Opcode::InboxNotify,
            Self::InboxAcked { .. } => Opcode::InboxAcked,
            Self::PartySnapshot(_) => Opcode::PartySnapshot,
            Self::PartyMemberJoined { .. } => Opcode::PartyMemberJoined,
            Self::PartyEndpointUpdate { .. } => Opcode::PartyEndpointUpdate,
            Self::PartyMemberUpdated { .. } => Opcode::PartyMemberUpdated,
            Self::PartyMemberLeft { .. } => Opcode::PartyMemberLeft,
            Self::PartyLeaderChanged { .. } => Opcode::PartyLeaderChanged,
            Self::PartyJoinRequestEvent { .. } => Opcode::PartyJoinRequestEvent,
            Self::PartyDisbanded { .. } => Opcode::PartyDisbanded,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mp1Error {
    FrameTooLarge,
    Truncated,
    TrailingBytes,
    UnsupportedVersion(u8),
    NonZeroFlags(u8),
    NonZeroReserved(u32),
    UnknownOpcode(u16),
    LengthMismatch,
    InvalidEnumValue,
    InvalidBool,
    InvalidCount,
    SafeIntExceeded,
    InvalidId(IdError),
    InvalidCwtLength,
    Endpoint(EndpointError),
}

impl fmt::Display for Mp1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Mp1Error {}

impl From<IdError> for Mp1Error {
    fn from(e: IdError) -> Self {
        Self::InvalidId(e)
    }
}

impl From<EndpointError> for Mp1Error {
    fn from(e: EndpointError) -> Self {
        Self::Endpoint(e)
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Mp1Error> {
        let end = self.pos.checked_add(n).ok_or(Mp1Error::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Mp1Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, Mp1Error> {
        let b = self.take(1)?;
        b.first().copied().ok_or(Mp1Error::Truncated)
    }

    fn read_bool(&mut self) -> Result<bool, Mp1Error> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Mp1Error::InvalidBool),
        }
    }

    fn read_u16(&mut self) -> Result<u16, Mp1Error> {
        let s = self.take(2)?;
        let arr: [u8; 2] = s.try_into().map_err(|_| Mp1Error::Truncated)?;
        Ok(u16::from_le_bytes(arr))
    }

    fn read_u32(&mut self) -> Result<u32, Mp1Error> {
        let s = self.take(4)?;
        let arr: [u8; 4] = s.try_into().map_err(|_| Mp1Error::Truncated)?;
        Ok(u32::from_le_bytes(arr))
    }

    fn read_u64_safe(&mut self) -> Result<u64, Mp1Error> {
        let s = self.take(8)?;
        let arr: [u8; 8] = s.try_into().map_err(|_| Mp1Error::Truncated)?;
        let v = u64::from_le_bytes(arr);
        if v > MAX_SAFE_ID {
            return Err(Mp1Error::SafeIntExceeded);
        }
        Ok(v)
    }

    fn read_pubkey(&mut self) -> Result<Ed25519PubKey, Mp1Error> {
        let s = self.take(32)?;
        s.try_into().map_err(|_| Mp1Error::Truncated)
    }

    fn read_bytes_u16(&mut self, max_len: usize) -> Result<Vec<u8>, Mp1Error> {
        let len = usize::from(self.read_u16()?);
        if len > max_len {
            return Err(Mp1Error::InvalidCount);
        }
        Ok(self.take(len)?.to_vec())
    }

    const fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn check_safe_u64(v: u64) -> Result<u64, Mp1Error> {
    if v > MAX_SAFE_ID {
        return Err(Mp1Error::SafeIntExceeded);
    }
    Ok(v)
}

fn write_presence_entry(out: &mut Vec<u8>, e: &PresenceEntry) -> Result<(), Mp1Error> {
    out.extend_from_slice(&e.account_id.to_le_bytes());
    out.push(e.status as u8);
    let party_raw = e.joinable_party_id.map_or(0u64, PartyId::get);
    out.extend_from_slice(&party_raw.to_le_bytes());
    out.extend_from_slice(&check_safe_u64(e.updated_ms)?.to_le_bytes());
    Ok(())
}

fn read_presence_entry(r: &mut Reader<'_>) -> Result<PresenceEntry, Mp1Error> {
    let account_id = AccountId::new(r.read_u64_safe()?)?;
    let status = PresenceVisibility::from_u8(r.read_u8()?)?;
    let party_raw = r.read_u64_safe()?;
    let joinable_party_id = if party_raw == 0 {
        None
    } else {
        Some(PartyId::new(party_raw)?)
    };
    let updated_ms = r.read_u64_safe()?;
    Ok(PresenceEntry {
        account_id,
        status,
        joinable_party_id,
        updated_ms,
    })
}

fn check_positive_safe_u64(v: u64) -> Result<u64, Mp1Error> {
    if v == 0 {
        return Err(Mp1Error::InvalidId(IdError::Zero));
    }
    if v > MAX_SAFE_ID {
        return Err(Mp1Error::InvalidId(IdError::ExceedsSafeInt(v)));
    }
    Ok(v)
}

fn validate_party_snapshot(s: &PartySnapshot) -> Result<(), Mp1Error> {
    if s.max_members < 2 || usize::from(s.max_members) > MAX_PARTY_MEMBERS {
        return Err(Mp1Error::InvalidCount);
    }
    if s.members.len() > usize::from(s.max_members) {
        return Err(Mp1Error::InvalidCount);
    }
    let _ = check_positive_safe_u64(s.party_epoch)?;
    validate_pinned_relay_url(s.relay_policy, &s.pinned_relay_url)?;
    let mut seen_devices = BTreeSet::new();
    for m in &s.members {
        let _ = check_positive_safe_u64(m.joined_seq)?;
        if !seen_devices.insert(m.device_id) {
            return Err(Mp1Error::InvalidCount);
        }
        m.endpoint
            .validate_against_policy(s.relay_policy, &s.pinned_relay_url)?;
    }
    Ok(())
}

fn write_member_record(out: &mut Vec<u8>, m: &PartyMemberRecord) -> Result<(), Mp1Error> {
    if m.device_cwt.is_empty() || m.device_cwt.len() > MAX_CWT_BYTES {
        return Err(Mp1Error::InvalidCwtLength);
    }
    let ep_bytes = m.endpoint.encode()?;
    out.extend_from_slice(&m.device_id.to_le_bytes());
    out.extend_from_slice(&m.account_id.to_le_bytes());
    out.extend_from_slice(&m.root_pubkey);
    out.extend_from_slice(&m.device_pubkey);
    let cwt_len = u16::try_from(m.device_cwt.len()).map_err(|_| Mp1Error::InvalidCwtLength)?;
    out.extend_from_slice(&cwt_len.to_le_bytes());
    out.extend_from_slice(&m.device_cwt);
    let ep_len = u16::try_from(ep_bytes.len()).map_err(|_| Mp1Error::FrameTooLarge)?;
    out.extend_from_slice(&ep_len.to_le_bytes());
    out.extend_from_slice(&ep_bytes);
    out.extend_from_slice(&check_positive_safe_u64(m.joined_seq)?.to_le_bytes());
    out.push(u8::from(m.connected));
    Ok(())
}

fn read_member_record(r: &mut Reader<'_>) -> Result<PartyMemberRecord, Mp1Error> {
    let device_id = DeviceId::new(r.read_u64_safe()?)?;
    let account_id = AccountId::new(r.read_u64_safe()?)?;
    let root_pubkey = r.read_pubkey()?;
    let device_pubkey = r.read_pubkey()?;
    let device_cwt = r.read_bytes_u16(MAX_CWT_BYTES)?;
    if device_cwt.is_empty() {
        return Err(Mp1Error::InvalidCwtLength);
    }
    let ep_bytes = r.read_bytes_u16(crate::endpoint::MAX_ENDPOINT_DESCRIPTOR_BYTES)?;
    let endpoint = EndpointDescriptor::decode(&ep_bytes)?;
    let joined_seq = r.read_u64_safe()?;
    let connected = r.read_bool()?;
    Ok(PartyMemberRecord {
        device_id,
        account_id,
        root_pubkey,
        device_pubkey,
        device_cwt,
        endpoint,
        joined_seq,
        connected,
    })
}

pub fn encode_frame(seq: u32, msg: &Mp1Message) -> Result<Vec<u8>, Mp1Error> {
    let mut payload = Vec::with_capacity(256);
    match msg {
        Mp1Message::HelloAck {
            session_id,
            server_now_ms,
            ping_interval_ms,
        } => {
            payload.extend_from_slice(&session_id.to_le_bytes());
            payload.extend_from_slice(&check_safe_u64(*server_now_ms)?.to_le_bytes());
            payload.extend_from_slice(&ping_interval_ms.to_le_bytes());
        }
        Mp1Message::Error(e) => {
            payload.extend_from_slice(&e.ref_seq.to_le_bytes());
            payload.extend_from_slice(&e.code.to_le_bytes());
            payload.extend_from_slice(&e.retry_after_ms.to_le_bytes());
        }
        Mp1Message::PresenceSet {
            visibility,
            share_party,
        } => {
            payload.push(*visibility as u8);
            payload.push(u8::from(*share_party));
        }
        Mp1Message::PresenceSnapshot { entries } => {
            if entries.len() > MAX_PRESENCE_ENTRIES {
                return Err(Mp1Error::InvalidCount);
            }
            let count = u16::try_from(entries.len()).map_err(|_| Mp1Error::InvalidCount)?;
            payload.extend_from_slice(&count.to_le_bytes());
            for e in entries {
                write_presence_entry(&mut payload, e)?;
            }
        }
        Mp1Message::PresenceDelta(e) => {
            write_presence_entry(&mut payload, e)?;
        }
        Mp1Message::SocialEvent {
            kind,
            peer_account_id,
        } => {
            payload.push(*kind as u8);
            payload.extend_from_slice(&peer_account_id.to_le_bytes());
        }
        Mp1Message::PartyInviteNotify {
            party_invite_id,
            party_id,
            from_account_id,
            expires_at_ms,
        } => {
            payload.extend_from_slice(&party_invite_id.to_le_bytes());
            payload.extend_from_slice(&party_id.to_le_bytes());
            payload.extend_from_slice(&from_account_id.to_le_bytes());
            payload.extend_from_slice(&check_safe_u64(*expires_at_ms)?.to_le_bytes());
        }
        Mp1Message::InboxNotify {
            drop_id,
            sender_account_id,
            created_at_ms,
            expires_at_ms,
            ciphertext_len,
        } => {
            payload.extend_from_slice(&check_positive_safe_u64(*drop_id)?.to_le_bytes());
            payload.extend_from_slice(&sender_account_id.to_le_bytes());
            payload.extend_from_slice(&check_safe_u64(*created_at_ms)?.to_le_bytes());
            payload.extend_from_slice(&check_safe_u64(*expires_at_ms)?.to_le_bytes());
            payload.extend_from_slice(&ciphertext_len.to_le_bytes());
        }
        Mp1Message::InboxAcked { drop_id, device_id } => {
            payload.extend_from_slice(&check_positive_safe_u64(*drop_id)?.to_le_bytes());
            payload.extend_from_slice(&device_id.to_le_bytes());
        }
        Mp1Message::PartySnapshot(s) => {
            validate_party_snapshot(s)?;
            payload.extend_from_slice(&s.party_id.to_le_bytes());
            payload.extend_from_slice(&check_positive_safe_u64(s.party_epoch)?.to_le_bytes());
            payload.extend_from_slice(&s.leader_account_id.to_le_bytes());
            payload.extend_from_slice(&s.leader_device_id.to_le_bytes());
            payload.push(s.visibility as u8);
            payload.push(s.join_mode as u8);
            payload.push(s.relay_policy as u8);
            payload.push(s.max_members);
            let url_bytes = s.pinned_relay_url.as_bytes();
            let url_len = u16::try_from(url_bytes.len()).map_err(|_| Mp1Error::InvalidCount)?;
            payload.extend_from_slice(&url_len.to_le_bytes());
            payload.extend_from_slice(url_bytes);
            let mcount = u8::try_from(s.members.len()).map_err(|_| Mp1Error::InvalidCount)?;
            payload.push(mcount);
            for m in &s.members {
                write_member_record(&mut payload, m)?;
            }
        }
        Mp1Message::PartyMemberJoined {
            party_epoch,
            member,
        } => {
            payload.extend_from_slice(&check_positive_safe_u64(*party_epoch)?.to_le_bytes());
            let _ = check_positive_safe_u64(member.joined_seq)?;
            write_member_record(&mut payload, member)?;
        }
        Mp1Message::PartyEndpointUpdate { endpoint } => {
            let ep = endpoint.encode()?;
            payload.extend_from_slice(&ep);
        }
        Mp1Message::PartyMemberUpdated {
            party_epoch,
            device_id,
            connected,
            device_cwt,
            endpoint,
        } => {
            if device_cwt.is_empty() || device_cwt.len() > MAX_CWT_BYTES {
                return Err(Mp1Error::InvalidCwtLength);
            }
            let ep = endpoint.encode()?;
            payload.extend_from_slice(&check_positive_safe_u64(*party_epoch)?.to_le_bytes());
            payload.extend_from_slice(&device_id.to_le_bytes());
            payload.push(u8::from(*connected));
            let cwt_len = u16::try_from(device_cwt.len()).map_err(|_| Mp1Error::InvalidCwtLength)?;
            payload.extend_from_slice(&cwt_len.to_le_bytes());
            payload.extend_from_slice(device_cwt);
            let ep_len = u16::try_from(ep.len()).map_err(|_| Mp1Error::FrameTooLarge)?;
            payload.extend_from_slice(&ep_len.to_le_bytes());
            payload.extend_from_slice(&ep);
        }
        Mp1Message::PartyMemberLeft {
            party_epoch,
            device_id,
            account_id,
            reason,
        } => {
            payload.extend_from_slice(&check_positive_safe_u64(*party_epoch)?.to_le_bytes());
            payload.extend_from_slice(&device_id.to_le_bytes());
            payload.extend_from_slice(&account_id.to_le_bytes());
            payload.push(*reason as u8);
        }
        Mp1Message::PartyLeaderChanged {
            party_epoch,
            new_leader_account_id,
            new_leader_device_id,
            reason,
        } => {
            payload.extend_from_slice(&check_positive_safe_u64(*party_epoch)?.to_le_bytes());
            payload.extend_from_slice(&new_leader_account_id.to_le_bytes());
            payload.extend_from_slice(&new_leader_device_id.to_le_bytes());
            payload.push(*reason as u8);
        }
        Mp1Message::PartyJoinRequestEvent {
            request_id,
            account_id,
            device_id,
            root_pubkey,
            device_pubkey,
        } => {
            payload.extend_from_slice(&request_id.to_le_bytes());
            payload.extend_from_slice(&account_id.to_le_bytes());
            payload.extend_from_slice(&device_id.to_le_bytes());
            payload.extend_from_slice(root_pubkey);
            payload.extend_from_slice(device_pubkey);
        }
        Mp1Message::PartyDisbanded {
            party_epoch,
            reason,
        } => {
            payload.extend_from_slice(&check_positive_safe_u64(*party_epoch)?.to_le_bytes());
            payload.push(*reason as u8);
        }
    }

    let total_len = MP1_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(Mp1Error::FrameTooLarge)?;
    if total_len > MAX_MP1_FRAME_BYTES {
        return Err(Mp1Error::FrameTooLarge);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| Mp1Error::FrameTooLarge)?;

    let mut frame = Vec::with_capacity(total_len);
    frame.push(MP1_VERSION);
    frame.push(0u8); // flags
    frame.extend_from_slice(&(msg.opcode() as u16).to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes()); // reserved
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame(bytes: &[u8]) -> Result<(FrameHeader, Mp1Message), Mp1Error> {
    if bytes.len() > MAX_MP1_FRAME_BYTES {
        return Err(Mp1Error::FrameTooLarge);
    }
    if bytes.len() < MP1_HEADER_BYTES {
        return Err(Mp1Error::Truncated);
    }

    let mut r = Reader::new(bytes);
    let version = r.read_u8()?;
    if version != MP1_VERSION {
        return Err(Mp1Error::UnsupportedVersion(version));
    }
    let flags = r.read_u8()?;
    if flags != 0 {
        return Err(Mp1Error::NonZeroFlags(flags));
    }
    let opcode = Opcode::from_u16(r.read_u16()?)?;
    let reserved = r.read_u32()?;
    if reserved != 0 {
        return Err(Mp1Error::NonZeroReserved(reserved));
    }
    let seq = r.read_u32()?;
    let payload_len = r.read_u32()?;
    let expected_total = MP1_HEADER_BYTES
        .checked_add(usize::try_from(payload_len).map_err(|_| Mp1Error::FrameTooLarge)?)
        .ok_or(Mp1Error::FrameTooLarge)?;
    if expected_total != bytes.len() {
        return Err(Mp1Error::LengthMismatch);
    }

    let msg = match opcode {
        Opcode::HelloAck => {
            let session_id = SessionId::new(r.read_u64_safe()?)?;
            let server_now_ms = r.read_u64_safe()?;
            let ping_interval_ms = r.read_u32()?;
            Mp1Message::HelloAck {
                session_id,
                server_now_ms,
                ping_interval_ms,
            }
        }
        Opcode::Error => {
            let ref_seq = r.read_u32()?;
            let code = r.read_u16()?;
            let retry_after_ms = r.read_u32()?;
            Mp1Message::Error(ErrorFrame {
                ref_seq,
                code,
                retry_after_ms,
            })
        }
        Opcode::PresenceSet => {
            let visibility = PresenceVisibility::from_u8(r.read_u8()?)?;
            let share_party = r.read_bool()?;
            Mp1Message::PresenceSet {
                visibility,
                share_party,
            }
        }
        Opcode::PresenceSnapshot => {
            let count = usize::from(r.read_u16()?);
            if count > MAX_PRESENCE_ENTRIES {
                return Err(Mp1Error::InvalidCount);
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                entries.push(read_presence_entry(&mut r)?);
            }
            Mp1Message::PresenceSnapshot { entries }
        }
        Opcode::PresenceDelta => Mp1Message::PresenceDelta(read_presence_entry(&mut r)?),
        Opcode::SocialEvent => {
            let kind = SocialEventKind::from_u8(r.read_u8()?)?;
            let peer_account_id = AccountId::new(r.read_u64_safe()?)?;
            Mp1Message::SocialEvent {
                kind,
                peer_account_id,
            }
        }
        Opcode::PartyInviteNotify => {
            let party_invite_id = PartyInviteId::new(r.read_u64_safe()?)?;
            let party_id = PartyId::new(r.read_u64_safe()?)?;
            let from_account_id = AccountId::new(r.read_u64_safe()?)?;
            let expires_at_ms = r.read_u64_safe()?;
            Mp1Message::PartyInviteNotify {
                party_invite_id,
                party_id,
                from_account_id,
                expires_at_ms,
            }
        }
        Opcode::InboxNotify => {
            let drop_id = check_positive_safe_u64(r.read_u64_safe()?)?;
            let sender_account_id = AccountId::new(r.read_u64_safe()?)?;
            let created_at_ms = r.read_u64_safe()?;
            let expires_at_ms = r.read_u64_safe()?;
            let ciphertext_len = r.read_u32()?;
            Mp1Message::InboxNotify {
                drop_id,
                sender_account_id,
                created_at_ms,
                expires_at_ms,
                ciphertext_len,
            }
        }
        Opcode::InboxAcked => {
            let drop_id = check_positive_safe_u64(r.read_u64_safe()?)?;
            let device_id = DeviceId::new(r.read_u64_safe()?)?;
            Mp1Message::InboxAcked { drop_id, device_id }
        }
        Opcode::PartySnapshot => {
            let party_id = PartyId::new(r.read_u64_safe()?)?;
            let party_epoch = check_positive_safe_u64(r.read_u64_safe()?)?;
            let leader_account_id = AccountId::new(r.read_u64_safe()?)?;
            let leader_device_id = DeviceId::new(r.read_u64_safe()?)?;
            let visibility = PartyVisibility::from_u8(r.read_u8()?)?;
            let join_mode = PartyJoinMode::from_u8(r.read_u8()?)?;
            let relay_policy = RelayPolicy::from_u8(r.read_u8()?)?;
            let max_members = r.read_u8()?;
            if max_members < 2 || usize::from(max_members) > MAX_PARTY_MEMBERS {
                return Err(Mp1Error::InvalidCount);
            }
            let url_bytes = r.read_bytes_u16(MAX_RELAY_URL_BYTES)?;
            let pinned_relay_url = std::str::from_utf8(&url_bytes)
                .map_err(|_| EndpointError::InvalidRelayUrl)?
                .to_owned();
            let mcount = usize::from(r.read_u8()?);
            if mcount > usize::from(max_members) {
                return Err(Mp1Error::InvalidCount);
            }
            let mut members = Vec::with_capacity(mcount);
            for _ in 0..mcount {
                members.push(read_member_record(&mut r)?);
            }
            let snap = PartySnapshot {
                party_id,
                party_epoch,
                leader_account_id,
                leader_device_id,
                visibility,
                join_mode,
                relay_policy,
                max_members,
                pinned_relay_url,
                members,
            };
            validate_party_snapshot(&snap)?;
            Mp1Message::PartySnapshot(snap)
        }
        Opcode::PartyMemberJoined => {
            let party_epoch = check_positive_safe_u64(r.read_u64_safe()?)?;
            let member = read_member_record(&mut r)?;
            let _ = check_positive_safe_u64(member.joined_seq)?;
            Mp1Message::PartyMemberJoined {
                party_epoch,
                member,
            }
        }
        Opcode::PartyEndpointUpdate => {
            let rest = r.take(usize::try_from(payload_len).map_err(|_| Mp1Error::FrameTooLarge)?)?;
            let endpoint = EndpointDescriptor::decode(rest)?;
            Mp1Message::PartyEndpointUpdate { endpoint }
        }
        Opcode::PartyMemberUpdated => {
            let party_epoch = check_positive_safe_u64(r.read_u64_safe()?)?;
            let device_id = DeviceId::new(r.read_u64_safe()?)?;
            let connected = r.read_bool()?;
            let device_cwt = r.read_bytes_u16(MAX_CWT_BYTES)?;
            if device_cwt.is_empty() {
                return Err(Mp1Error::InvalidCwtLength);
            }
            let ep_bytes = r.read_bytes_u16(crate::endpoint::MAX_ENDPOINT_DESCRIPTOR_BYTES)?;
            let endpoint = EndpointDescriptor::decode(&ep_bytes)?;
            Mp1Message::PartyMemberUpdated {
                party_epoch,
                device_id,
                connected,
                device_cwt,
                endpoint,
            }
        }
        Opcode::PartyMemberLeft => {
            let party_epoch = check_positive_safe_u64(r.read_u64_safe()?)?;
            let device_id = DeviceId::new(r.read_u64_safe()?)?;
            let account_id = AccountId::new(r.read_u64_safe()?)?;
            let reason = MemberLeaveReason::from_u8(r.read_u8()?)?;
            Mp1Message::PartyMemberLeft {
                party_epoch,
                device_id,
                account_id,
                reason,
            }
        }
        Opcode::PartyLeaderChanged => {
            let party_epoch = check_positive_safe_u64(r.read_u64_safe()?)?;
            let new_leader_account_id = AccountId::new(r.read_u64_safe()?)?;
            let new_leader_device_id = DeviceId::new(r.read_u64_safe()?)?;
            let reason = PartyLeaderChangeReason::from_u8(r.read_u8()?)?;
            Mp1Message::PartyLeaderChanged {
                party_epoch,
                new_leader_account_id,
                new_leader_device_id,
                reason,
            }
        }
        Opcode::PartyJoinRequestEvent => {
            let request_id = RequestId::new(r.read_u64_safe()?)?;
            let account_id = AccountId::new(r.read_u64_safe()?)?;
            let device_id = DeviceId::new(r.read_u64_safe()?)?;
            let root_pubkey = r.read_pubkey()?;
            let device_pubkey = r.read_pubkey()?;
            Mp1Message::PartyJoinRequestEvent {
                request_id,
                account_id,
                device_id,
                root_pubkey,
                device_pubkey,
            }
        }
        Opcode::PartyDisbanded => {
            let party_epoch = check_positive_safe_u64(r.read_u64_safe()?)?;
            let reason = PartyDisbandReason::from_u8(r.read_u8()?)?;
            Mp1Message::PartyDisbanded {
                party_epoch,
                reason,
            }
        }
    };

    if !r.is_empty() {
        return Err(Mp1Error::TrailingBytes);
    }

    Ok((
        FrameHeader {
            opcode,
            seq,
            payload_len,
        },
        msg,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn inbox_notify_and_acked_round_trip_and_server_only() {
        assert!(!Opcode::InboxNotify.is_allowed_from_client(SocketRole::Account));
        assert!(!Opcode::InboxNotify.is_allowed_from_client(SocketRole::Party));
        assert!(!Opcode::InboxAcked.is_allowed_from_client(SocketRole::Account));
        assert!(!Opcode::InboxAcked.is_allowed_from_client(SocketRole::Party));

        let notify = Mp1Message::InboxNotify {
            drop_id: 987_654_321,
            sender_account_id: AccountId::new(42).unwrap(),
            created_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_086_400_000,
            ciphertext_len: 4096,
        };
        let frame = encode_frame(0, &notify).unwrap();
        assert_eq!(frame.len(), MP1_HEADER_BYTES + 36);
        let (hdr, decoded) = decode_frame(&frame).unwrap();
        assert_eq!(hdr.opcode, Opcode::InboxNotify);
        assert_eq!(hdr.payload_len, 36);
        assert_eq!(decoded, notify);

        let acked = Mp1Message::InboxAcked {
            drop_id: 987_654_321,
            device_id: DeviceId::new(77).unwrap(),
        };
        let ack_frame = encode_frame(0, &acked).unwrap();
        assert_eq!(ack_frame.len(), MP1_HEADER_BYTES + 16);
        let (ahdr, adec) = decode_frame(&ack_frame).unwrap();
        assert_eq!(ahdr.opcode, Opcode::InboxAcked);
        assert_eq!(ahdr.payload_len, 16);
        assert_eq!(adec, acked);
    }
}
