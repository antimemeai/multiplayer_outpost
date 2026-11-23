//! Bit-exact Blackbird Wave 11B P2P Party Data-Plane Application Wire v1 codec
//! (ALPN `"blackbird-mp/1"`, cross-verified against `../blackbird/include/blackbird/p2p_party_session.hpp`).

use core::fmt;

pub const P2P_PARTY_FRAME_VERSION: u8 = 0x01;
pub const MAX_ROOM_SCOPE_BYTES: usize = 128;
pub const MAX_TARGET_SELECTOR_BYTES: usize = 64;
pub const MAX_SENDER_HANDLE_BYTES: usize = 64;
pub const MAX_CHAT_BODY_BYTES: usize = 256 * 1024;
pub const MAX_BRIDGE_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_CONTROL_NOTICE_BYTES: usize = 4096;
pub const MAX_EPHEMERAL_STATUS_BYTES: usize = 256;

pub const MAX_CONTROL_LANE_BYTES: usize = 64 * 1024;
pub const MAX_CAUSAL_LANE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EPHEMERAL_LANE_BYTES: usize = 1200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum P2pLane {
    Control = 0,
    Causal = 1,
    Ephemeral = 2,
}

impl P2pLane {
    pub const fn max_frame_bytes(self) -> usize {
        match self {
            Self::Control => MAX_CONTROL_LANE_BYTES,
            Self::Causal => MAX_CAUSAL_LANE_BYTES,
            Self::Ephemeral => MAX_EPHEMERAL_LANE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum P2pControlNoticeKind {
    SyncAck = 0,
    ScopeChanged = 1,
    Status = 2,
}

impl P2pControlNoticeKind {
    pub const fn from_u8(v: u8) -> Result<Self, P2pWireError> {
        match v {
            0 => Ok(Self::SyncAck),
            1 => Ok(Self::ScopeChanged),
            2 => Ok(Self::Status),
            _ => Err(P2pWireError::InvalidEnum),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum P2pActivityState {
    Offline = 0,
    Online = 1,
    Working = 2,
    Idle = 3,
    Typing = 4,
}

impl P2pActivityState {
    pub const fn from_u8(v: u8) -> Result<Self, P2pWireError> {
        match v {
            0 => Ok(Self::Offline),
            1 => Ok(Self::Online),
            2 => Ok(Self::Working),
            3 => Ok(Self::Idle),
            4 => Ok(Self::Typing),
            _ => Err(P2pWireError::InvalidEnum),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pChatMessage {
    pub room_scope: String,
    pub target_selector: String,
    pub sender_handle: String,
    pub timestamp_ns: i64,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pBridgeEnvelope {
    pub room_scope: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pControlNotice {
    pub kind: P2pControlNoticeKind,
    pub party_epoch: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pEphemeralPulse {
    pub activity_state: P2pActivityState,
    pub timestamp_ns: i64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pPartyFrame {
    ChatMessage(P2pChatMessage),
    BridgeEnvelope(P2pBridgeEnvelope),
    ControlNotice(P2pControlNotice),
    EphemeralPulse(P2pEphemeralPulse),
}

impl P2pPartyFrame {
    pub const fn lane(&self) -> P2pLane {
        match self {
            Self::ChatMessage(_) | Self::BridgeEnvelope(_) => P2pLane::Causal,
            Self::ControlNotice(_) => P2pLane::Control,
            Self::EphemeralPulse(_) => P2pLane::Ephemeral,
        }
    }

    pub const fn kind_byte(&self) -> u8 {
        match self {
            Self::ChatMessage(_) => 1,
            Self::BridgeEnvelope(_) => 2,
            Self::ControlNotice(_) => 3,
            Self::EphemeralPulse(_) => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pWireError {
    Truncated,
    TrailingBytes,
    UnsupportedVersion,
    UnknownKind,
    LaneMismatch,
    FieldTooLarge,
    InvalidUtf8,
    InvalidEnum,
    NonZeroReserved,
    FrameOversized,
}

impl fmt::Display for P2pWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for P2pWireError {}

fn append_text_u16(out: &mut Vec<u8>, text: &str, max_len: usize) -> Result<(), P2pWireError> {
    if text.len() > max_len || text.len() > usize::from(u16::MAX) {
        return Err(P2pWireError::FieldTooLarge);
    }
    out.extend_from_slice(&(text.len() as u16).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn append_bytes_u32(out: &mut Vec<u8>, bytes: &[u8], max_len: usize) -> Result<(), P2pWireError> {
    if bytes.len() > max_len || bytes.len() > u32::MAX as usize {
        return Err(P2pWireError::FieldTooLarge);
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub fn encode_p2p_party_frame(frame: &P2pPartyFrame) -> Result<Vec<u8>, P2pWireError> {
    let mut out = Vec::with_capacity(64);
    out.push(P2P_PARTY_FRAME_VERSION);
    out.push(frame.kind_byte());
    out.push(0); // flags
    out.push(0); // reserved

    match frame {
        P2pPartyFrame::ChatMessage(m) => {
            out.extend_from_slice(&m.timestamp_ns.to_le_bytes());
            append_text_u16(&mut out, &m.room_scope, MAX_ROOM_SCOPE_BYTES)?;
            append_text_u16(&mut out, &m.target_selector, MAX_TARGET_SELECTOR_BYTES)?;
            append_text_u16(&mut out, &m.sender_handle, MAX_SENDER_HANDLE_BYTES)?;
            append_bytes_u32(&mut out, m.body.as_bytes(), MAX_CHAT_BODY_BYTES)?;
        }
        P2pPartyFrame::BridgeEnvelope(b) => {
            append_text_u16(&mut out, &b.room_scope, MAX_ROOM_SCOPE_BYTES)?;
            append_bytes_u32(&mut out, &b.payload, MAX_BRIDGE_PAYLOAD_BYTES)?;
        }
        P2pPartyFrame::ControlNotice(n) => {
            out.push(n.kind as u8);
            out.push(0); // reserved
            out.extend_from_slice(&n.party_epoch.to_le_bytes());
            append_text_u16(&mut out, &n.text, MAX_CONTROL_NOTICE_BYTES)?;
        }
        P2pPartyFrame::EphemeralPulse(p) => {
            out.push(p.activity_state as u8);
            out.push(0); // reserved
            out.extend_from_slice(&p.timestamp_ns.to_le_bytes());
            append_text_u16(&mut out, &p.status, MAX_EPHEMERAL_STATUS_BYTES)?;
        }
    }

    if out.len() > frame.lane().max_frame_bytes() {
        return Err(P2pWireError::FrameOversized);
    }
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], P2pWireError> {
        let end = self.pos.checked_add(n).ok_or(P2pWireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(P2pWireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, P2pWireError> {
        let s = self.take(1)?;
        s.first().copied().ok_or(P2pWireError::Truncated)
    }

    fn read_u16(&mut self) -> Result<u16, P2pWireError> {
        let s = self.take(2)?;
        let arr: [u8; 2] = s.try_into().map_err(|_| P2pWireError::Truncated)?;
        Ok(u16::from_le_bytes(arr))
    }

    fn read_u32(&mut self) -> Result<u32, P2pWireError> {
        let s = self.take(4)?;
        let arr: [u8; 4] = s.try_into().map_err(|_| P2pWireError::Truncated)?;
        Ok(u32::from_le_bytes(arr))
    }

    fn read_u64(&mut self) -> Result<u64, P2pWireError> {
        let s = self.take(8)?;
        let arr: [u8; 8] = s.try_into().map_err(|_| P2pWireError::Truncated)?;
        Ok(u64::from_le_bytes(arr))
    }

    fn read_i64(&mut self) -> Result<i64, P2pWireError> {
        let s = self.take(8)?;
        let arr: [u8; 8] = s.try_into().map_err(|_| P2pWireError::Truncated)?;
        Ok(i64::from_le_bytes(arr))
    }

    fn read_text_u16(&mut self, max_len: usize) -> Result<String, P2pWireError> {
        let len = usize::from(self.read_u16()?);
        if len > max_len {
            return Err(P2pWireError::FieldTooLarge);
        }
        let raw = self.take(len)?;
        let s = core::str::from_utf8(raw).map_err(|_| P2pWireError::InvalidUtf8)?;
        Ok(s.to_string())
    }

    fn read_text_u32(&mut self, max_len: usize) -> Result<String, P2pWireError> {
        let len = self.read_u32()? as usize;
        if len > max_len {
            return Err(P2pWireError::FieldTooLarge);
        }
        let raw = self.take(len)?;
        let s = core::str::from_utf8(raw).map_err(|_| P2pWireError::InvalidUtf8)?;
        Ok(s.to_string())
    }

    fn read_bytes_u32(&mut self, max_len: usize) -> Result<Vec<u8>, P2pWireError> {
        let len = self.read_u32()? as usize;
        if len > max_len {
            return Err(P2pWireError::FieldTooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    const fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

pub fn decode_p2p_party_frame(
    expected_lane: P2pLane,
    bytes: &[u8],
) -> Result<P2pPartyFrame, P2pWireError> {
    if bytes.len() > expected_lane.max_frame_bytes() {
        return Err(P2pWireError::FrameOversized);
    }
    let mut r = Reader::new(bytes);
    let version = r.read_u8()?;
    if version != P2P_PARTY_FRAME_VERSION {
        return Err(P2pWireError::UnsupportedVersion);
    }
    let kind = r.read_u8()?;
    let flags = r.read_u8()?;
    let reserved = r.read_u8()?;
    if flags != 0 || reserved != 0 {
        return Err(P2pWireError::NonZeroReserved);
    }

    let frame = match kind {
        1 => {
            if expected_lane != P2pLane::Causal {
                return Err(P2pWireError::LaneMismatch);
            }
            let timestamp_ns = r.read_i64()?;
            let room_scope = r.read_text_u16(MAX_ROOM_SCOPE_BYTES)?;
            let target_selector = r.read_text_u16(MAX_TARGET_SELECTOR_BYTES)?;
            let sender_handle = r.read_text_u16(MAX_SENDER_HANDLE_BYTES)?;
            let body = r.read_text_u32(MAX_CHAT_BODY_BYTES)?;
            P2pPartyFrame::ChatMessage(P2pChatMessage {
                room_scope,
                target_selector,
                sender_handle,
                timestamp_ns,
                body,
            })
        }
        2 => {
            if expected_lane != P2pLane::Causal {
                return Err(P2pWireError::LaneMismatch);
            }
            let room_scope = r.read_text_u16(MAX_ROOM_SCOPE_BYTES)?;
            let payload = r.read_bytes_u32(MAX_BRIDGE_PAYLOAD_BYTES)?;
            P2pPartyFrame::BridgeEnvelope(P2pBridgeEnvelope {
                room_scope,
                payload,
            })
        }
        3 => {
            if expected_lane != P2pLane::Control {
                return Err(P2pWireError::LaneMismatch);
            }
            let notice_kind = P2pControlNoticeKind::from_u8(r.read_u8()?)?;
            let inner_rsv = r.read_u8()?;
            if inner_rsv != 0 {
                return Err(P2pWireError::NonZeroReserved);
            }
            let party_epoch = r.read_u64()?;
            let text = r.read_text_u16(MAX_CONTROL_NOTICE_BYTES)?;
            P2pPartyFrame::ControlNotice(P2pControlNotice {
                kind: notice_kind,
                party_epoch,
                text,
            })
        }
        4 => {
            if expected_lane != P2pLane::Ephemeral {
                return Err(P2pWireError::LaneMismatch);
            }
            let activity_state = P2pActivityState::from_u8(r.read_u8()?)?;
            let inner_rsv = r.read_u8()?;
            if inner_rsv != 0 {
                return Err(P2pWireError::NonZeroReserved);
            }
            let timestamp_ns = r.read_i64()?;
            let status = r.read_text_u16(MAX_EPHEMERAL_STATUS_BYTES)?;
            P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
                activity_state,
                timestamp_ns,
                status,
            })
        }
        _ => return Err(P2pWireError::UnknownKind),
    };

    if !r.at_end() {
        return Err(P2pWireError::TrailingBytes);
    }
    Ok(frame)
}
