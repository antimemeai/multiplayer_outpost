//! Strictly binary little-endian local IPC payloads for `d.sock` (ZERO JSON!).

use outpost_core::fence::SecretMatchKind;
use outpost_core::ipc_wire::IpcWireError;
use outpost_core::storage_codec::TrustState;
use outpost_mcp::{
    BoardEnvelopeEvent, McpPartyEvent, McpPartyEventKind, PartyPollResp, PeerProvenance,
};

pub const ERR_INVALID_PARAMS: u16 = 4000;
pub const ERR_NOT_FOUND: u16 = 4040;
pub const ERR_CONFLICT: u16 = 4090;
pub const ERR_IDEMPOTENCY_CONFLICT: u16 = 4091;
pub const ERR_CANCELLED: u16 = 4990;
pub const ERR_INTERNAL: u16 = 5000;
pub const ERR_CONTROL_PLANE: u16 = 5020;

pub const ERR_SECRET_OWN_DEVICE_SECRET: u16 = 4030;
pub const ERR_SECRET_OWN_DEVICE_CWT: u16 = 4031;
pub const ERR_SECRET_INVITE_TOKEN: u16 = 4032;
pub const ERR_SECRET_PRIVATE_KEY_PEM: u16 = 4033;
pub const ERR_SECRET_RECOVERY_KEY: u16 = 4205;
pub const ERR_SECRET_DEVICE_LINK_TOKEN: u16 = 4206;
pub const ERR_SECRET_RECOVERY_FILE: u16 = 4207;

pub const fn secret_kind_to_error_code(kind: SecretMatchKind) -> u16 {
    match kind {
        SecretMatchKind::OwnDeviceSecret => ERR_SECRET_OWN_DEVICE_SECRET,
        SecretMatchKind::OwnDeviceCwt => ERR_SECRET_OWN_DEVICE_CWT,
        SecretMatchKind::InviteToken => ERR_SECRET_INVITE_TOKEN,
        SecretMatchKind::PrivateKeyPem => ERR_SECRET_PRIVATE_KEY_PEM,
        SecretMatchKind::RecoveryKey => ERR_SECRET_RECOVERY_KEY,
        SecretMatchKind::DeviceLinkToken => ERR_SECRET_DEVICE_LINK_TOKEN,
        SecretMatchKind::RecoveryFile => ERR_SECRET_RECOVERY_FILE,
    }
}

pub const fn error_code_to_secret_kind(code: u16) -> Option<SecretMatchKind> {
    match code {
        ERR_SECRET_OWN_DEVICE_SECRET => Some(SecretMatchKind::OwnDeviceSecret),
        ERR_SECRET_OWN_DEVICE_CWT => Some(SecretMatchKind::OwnDeviceCwt),
        ERR_SECRET_INVITE_TOKEN => Some(SecretMatchKind::InviteToken),
        ERR_SECRET_PRIVATE_KEY_PEM => Some(SecretMatchKind::PrivateKeyPem),
        ERR_SECRET_RECOVERY_KEY => Some(SecretMatchKind::RecoveryKey),
        ERR_SECRET_DEVICE_LINK_TOKEN => Some(SecretMatchKind::DeviceLinkToken),
        ERR_SECRET_RECOVERY_FILE => Some(SecretMatchKind::RecoveryFile),
        _ => None,
    }
}

const MAX_STR_SMALL: usize = 4096;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_LIST_ITEMS: usize = 1024;
pub const MAX_POLL_LIMIT: u16 = 100;
pub const MAX_POLL_MAX_BYTES: u32 = outpost_core::party_state::MAX_POLL_MAX_BYTES as u32;

// ---------------------------------------------------------------------------
// Binary primitives
// ---------------------------------------------------------------------------

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(128),
        }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn fixed<const N: usize>(&mut self, b: &[u8; N]) {
        self.buf.extend_from_slice(b);
    }

    fn opt_u64(&mut self, v: Option<u64>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u64(x);
            }
            None => self.u8(0),
        }
    }

    fn opt_u32(&mut self, v: Option<u32>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u32(x);
            }
            None => self.u8(0),
        }
    }

    fn opt_u8(&mut self, v: Option<u8>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u8(x);
            }
            None => self.u8(0),
        }
    }

    fn str_u16(&mut self, s: &str) -> Result<(), IpcWireError> {
        let len = u16::try_from(s.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
        self.u16(len);
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }

    fn opt_str_u16(&mut self, s: Option<&str>) -> Result<(), IpcWireError> {
        match s {
            Some(text) => {
                self.u8(1);
                self.str_u16(text)?;
            }
            None => self.u8(0),
        }
        Ok(())
    }

    fn bytes_u32(&mut self, b: &[u8]) -> Result<(), IpcWireError> {
        let len = u32::try_from(b.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
        self.u32(len);
        self.buf.extend_from_slice(b);
        Ok(())
    }

    fn str_u32(&mut self, s: &str) -> Result<(), IpcWireError> {
        self.bytes_u32(s.as_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.buf
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

    fn take(&mut self, n: usize) -> Result<&'a [u8], IpcWireError> {
        let end = self.pos.checked_add(n).ok_or(IpcWireError::Truncated)?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(IpcWireError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, IpcWireError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(IpcWireError::Truncated)
    }

    fn bool(&mut self) -> Result<bool, IpcWireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(IpcWireError::InvalidEnum),
        }
    }

    fn u16(&mut self) -> Result<u16, IpcWireError> {
        let arr: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| IpcWireError::Truncated)?;
        Ok(u16::from_le_bytes(arr))
    }

    fn u32(&mut self) -> Result<u32, IpcWireError> {
        let arr: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| IpcWireError::Truncated)?;
        Ok(u32::from_le_bytes(arr))
    }

    fn u64(&mut self) -> Result<u64, IpcWireError> {
        let arr: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| IpcWireError::Truncated)?;
        Ok(u64::from_le_bytes(arr))
    }

    fn i64(&mut self) -> Result<i64, IpcWireError> {
        let arr: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| IpcWireError::Truncated)?;
        Ok(i64::from_le_bytes(arr))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], IpcWireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| IpcWireError::Truncated)
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, IpcWireError> {
        if self.bool()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    fn opt_u32(&mut self) -> Result<Option<u32>, IpcWireError> {
        if self.bool()? {
            Ok(Some(self.u32()?))
        } else {
            Ok(None)
        }
    }

    fn opt_u8(&mut self) -> Result<Option<u8>, IpcWireError> {
        if self.bool()? {
            Ok(Some(self.u8()?))
        } else {
            Ok(None)
        }
    }

    fn str_u16(&mut self, max_len: usize) -> Result<String, IpcWireError> {
        let len = usize::from(self.u16()?);
        if len > max_len {
            return Err(IpcWireError::BodyTooLarge);
        }
        let raw = self.take(len)?;
        let s = core::str::from_utf8(raw).map_err(|_| IpcWireError::InvalidUtf8)?;
        Ok(s.to_string())
    }

    fn opt_str_u16(&mut self, max_len: usize) -> Result<Option<String>, IpcWireError> {
        if self.bool()? {
            Ok(Some(self.str_u16(max_len)?))
        } else {
            Ok(None)
        }
    }

    fn bytes_u32(&mut self, max_len: usize) -> Result<Vec<u8>, IpcWireError> {
        let len = self.u32()? as usize;
        if len > max_len {
            return Err(IpcWireError::BodyTooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn str_u32(&mut self, max_len: usize) -> Result<String, IpcWireError> {
        let raw = self.bytes_u32(max_len)?;
        String::from_utf8(raw).map_err(|_| IpcWireError::InvalidUtf8)
    }

    fn finish(self) -> Result<(), IpcWireError> {
        if self.pos != self.buf.len() {
            return Err(IpcWireError::TrailingBytes);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePartySummary {
    pub party_id: u64,
    pub party_epoch: u64,
    pub leader_account_id: u64,
    pub leader_device_id: u64,
    pub visibility: u8,
    pub join_mode: u8,
    pub relay_policy: u8,
    pub effective_relay_policy: u8,
    pub pinned_relay_url: String,
    pub max_members: u8,
    pub member_count: u8,
    pub next_seq: u64,
    pub daemon_epoch: u64,
    pub room_code: String,
    pub room_name: String,
    pub share_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpinnedPeerAlert {
    pub account_id: u64,
    pub root_pubkey: [u8; 32],
    pub safety_number: String,
    pub server_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMismatchAlert {
    pub account_id: u64,
    pub expected_root_pubkey: [u8; 32],
    pub observed_root_pubkey: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResp {
    pub account_id: u64,
    pub device_id: u64,
    pub handle: String,
    pub api_authority: String,
    pub local_relay_policy: u8,
    pub cwt_expires_ms: u64,
    pub daemon_epoch: u64,
    pub daemon_pid: u32,
    pub build_order: u64,
    pub build_digest: [u8; 32],
    pub exe_path: String,
    pub control_ws_connected: bool,
    pub dual_host_churn_alert: bool,
    pub active_party: Option<ActivePartySummary>,
    pub unpinned_alerts: Vec<UnpinnedPeerAlert>,
    pub key_mismatch_alerts: Vec<KeyMismatchAlert>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadDeviceResp {
    pub reloaded: bool,
    pub device_id: u64,
    pub active_party_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyListResp {
    pub daemon_epoch: u64,
    pub parties: Vec<ActivePartySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub device_id: u64,
    pub account_id: u64,
    pub server_handle: String,
    pub root_pubkey: [u8; 32],
    pub trust_state: u8,
    pub safety_number: String,
    pub connected_mp1: bool,
    pub connected_p2p: bool,
    pub joined_seq: u64,
    pub key_mismatch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyMembersResp {
    pub party_id: u64,
    pub party_epoch: u64,
    pub members: Vec<MemberInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartySendChatReq {
    pub party_id: u64,
    pub client_msg_id: u64,
    pub room_scope: String,
    pub target_device_id: Option<u64>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyPostBoardReq {
    pub party_id: u64,
    pub client_msg_id: u64,
    pub room_scope: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyControlNoticeReq {
    pub party_id: u64,
    pub notice_kind: u8,
    pub party_epoch: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendResultResp {
    pub party_id: u64,
    pub client_msg_id: u64,
    pub delivered_to: Vec<u64>,
    pub withheld_unpinned: Vec<u64>,
    pub disconnected: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyPollIpcReq {
    pub party_id: u64,
    pub cursor_epoch: u64,
    pub after_seq: u64,
    pub limit: u16,
    pub max_bytes: u32,
    pub board_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyWaitIpcReq {
    pub party_id: u64,
    pub cursor_epoch: u64,
    pub after_seq: u64,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcProvenance {
    pub sender_account_id: u64,
    pub sender_device_id: u64,
    pub sender_handle: String,
    pub root_pubkey_fingerprint: String,
    pub safety_number: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcPartyEventKind {
    Chat {
        provenance: IpcProvenance,
        room_scope: String,
        target_selector: String,
        timestamp_ns: i64,
        body: String,
    },
    ControlNotice {
        provenance: IpcProvenance,
        notice_kind: u8,
        party_epoch: u64,
        text: String,
    },
    MembershipChanged {
        party_epoch: u64,
        summary: String,
    },
    BridgeEnvelope {
        provenance: IpcProvenance,
        room_scope: String,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcPartyEvent {
    pub event_seq: u64,
    pub party_id: u64,
    pub party_epoch: u64,
    pub kind: IpcPartyEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyPollIpcResp {
    pub party_id: u64,
    pub daemon_epoch: u64,
    pub next_seq: u64,
    pub dropped_before_seq: u64,
    pub cursor_reset: bool,
    pub gap_possible: bool,
    pub timed_out: bool,
    pub events: Vec<IpcPartyEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendItem {
    pub account_id: u64,
    pub state: u8,
    pub updated_at_ms: u64,
    pub presence_status: u8,
    pub joinable_party_id: Option<u64>,
    pub handle: String,
    pub safety_number: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendsListResp {
    pub friends: Vec<FriendItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyCreateReq {
    pub visibility: u8,
    pub join_mode: u8,
    pub relay_policy: u8,
    pub max_members: u8,
    pub relay_url: String,
    pub org_id: Option<u64>,
    pub group_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyCreateResp {
    pub party_id: u64,
    pub party_epoch: u64,
    pub pinned_relay_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyJoinReq {
    pub party_id: u64,
    pub relay_policy_override: Option<u8>,
    pub invite_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyJoinResp {
    /// 0 = joined, 1 = pending_approval
    pub status: u8,
    pub party_epoch: u64,
    pub request_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyEpochResp {
    pub ok: bool,
    pub party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyEpochOpReq {
    pub party_id: u64,
    pub expected_party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyKickReq {
    pub party_id: u64,
    pub target_account_id: u64,
    pub expected_party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyPromoteReq {
    pub party_id: u64,
    pub target_device_id: u64,
    pub expected_party_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyInviteMintReq {
    pub party_id: u64,
    pub target_account_id: Option<u64>,
    pub max_uses: Option<u8>,
    pub ttl_sec: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyInviteMintResp {
    pub party_invite_id: u64,
    pub expires_at_ms: u64,
    pub invite_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyInviteRevokeReq {
    pub party_id: u64,
    pub party_invite_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRequestsListReq {
    pub party_id: u64,
    pub cursor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequestItem {
    pub request_id: u64,
    pub account_id: u64,
    pub device_id: u64,
    pub root_pubkey_b64: String,
    pub device_pubkey_b64: String,
    pub requested_at_ms: u64,
    pub reserved_until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRequestsListResp {
    pub requests: Vec<JoinRequestItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRequestApproveReq {
    pub party_id: u64,
    pub request_id: u64,
    pub expected_party_epoch: u64,
    pub account_id: u64,
    pub device_id: u64,
    pub device_pubkey_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRequestApproveResp {
    pub approved: bool,
    pub reserved_until_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRequestRejectReq {
    pub party_id: u64,
    pub request_id: u64,
    pub expected_party_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendEdgeResp {
    pub target_account_id: u64,
    pub state: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveHandleResp {
    pub account_id: u64,
    pub handle: String,
    pub root_pubkey: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoomInviteIpcReq {
    pub handle: Option<String>,
    pub party_id: Option<u64>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomInviteIpcResp {
    pub party_id: u64,
    pub room_code: String,
    pub share_url: String,
    pub handle_url: String,
    pub ws_path: String,
    pub invited_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoomEnterIpcReq {
    pub target: String,
    pub agent_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomMemberIpc {
    pub account_id: u64,
    pub handle: String,
    pub client: String,
    pub agent_name: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomEnterIpcResp {
    pub party_id: u64,
    pub room_code: String,
    pub name: String,
    pub share_url: String,
    pub ws_path: String,
    pub members: Vec<RoomMemberIpc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoomLeaveIpcReq {
    pub party_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomLeaveIpcResp {
    pub left: bool,
    pub party_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveFriendIpc {
    pub account_id: u64,
    pub handle: String,
    pub state: String,
    pub presence: String,
    pub client: Option<String>,
    pub party_room_code: Option<String>,
    pub joinable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInviteIpc {
    pub party_id: u64,
    pub room_code: String,
    pub from_handle: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FriendsLiveIpcResp {
    pub friends: Vec<LiveFriendIpc>,
    pub pending_invites: Vec<PendingInviteIpc>,
}

// ---------------------------------------------------------------------------
// Encoders / Decoders
// ---------------------------------------------------------------------------

fn write_party_summary(w: &mut Writer, p: &ActivePartySummary) -> Result<(), IpcWireError> {
    w.u64(p.party_id);
    w.u64(p.party_epoch);
    w.u64(p.leader_account_id);
    w.u64(p.leader_device_id);
    w.u8(p.visibility);
    w.u8(p.join_mode);
    w.u8(p.relay_policy);
    w.u8(p.effective_relay_policy);
    w.str_u16(&p.pinned_relay_url)?;
    w.u8(p.max_members);
    w.u8(p.member_count);
    w.u64(p.next_seq);
    w.u64(p.daemon_epoch);
    w.str_u16(&p.room_code)?;
    w.str_u16(&p.room_name)?;
    w.str_u16(&p.share_url)?;
    Ok(())
}

fn read_party_summary(r: &mut Reader<'_>) -> Result<ActivePartySummary, IpcWireError> {
    Ok(ActivePartySummary {
        party_id: r.u64()?,
        party_epoch: r.u64()?,
        leader_account_id: r.u64()?,
        leader_device_id: r.u64()?,
        visibility: r.u8()?,
        join_mode: r.u8()?,
        relay_policy: r.u8()?,
        effective_relay_policy: r.u8()?,
        pinned_relay_url: r.str_u16(256)?,
        max_members: r.u8()?,
        member_count: r.u8()?,
        next_seq: r.u64()?,
        daemon_epoch: r.u64()?,
        room_code: r.str_u16(32)?,
        room_name: r.str_u16(128)?,
        share_url: r.str_u16(512)?,
    })
}

pub fn encode_u64_req(id: u64) -> Vec<u8> {
    id.to_le_bytes().to_vec()
}

pub fn decode_u64_req(bytes: &[u8]) -> Result<u64, IpcWireError> {
    let mut r = Reader::new(bytes);
    let v = r.u64()?;
    r.finish()?;
    Ok(v)
}

pub fn encode_bool_resp(ok: bool) -> Vec<u8> {
    vec![u8::from(ok)]
}

pub fn decode_bool_resp(bytes: &[u8]) -> Result<bool, IpcWireError> {
    let mut r = Reader::new(bytes);
    let v = r.bool()?;
    r.finish()?;
    Ok(v)
}

pub fn encode_status_resp(s: &StatusResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(s.account_id);
    w.u64(s.device_id);
    w.str_u16(&s.handle)?;
    w.str_u16(&s.api_authority)?;
    w.u8(s.local_relay_policy);
    w.u64(s.cwt_expires_ms);
    w.u64(s.daemon_epoch);
    w.u32(s.daemon_pid);
    w.u64(s.build_order);
    w.fixed(&s.build_digest);
    w.str_u16(&s.exe_path)?;
    w.bool(s.control_ws_connected);
    w.bool(s.dual_host_churn_alert);
    match &s.active_party {
        Some(p) => {
            w.bool(true);
            write_party_summary(&mut w, p)?;
        }
        None => w.bool(false),
    }
    let unpinned_len = u16::try_from(s.unpinned_alerts.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(unpinned_len);
    for a in &s.unpinned_alerts {
        w.u64(a.account_id);
        w.fixed(&a.root_pubkey);
        w.str_u16(&a.safety_number)?;
        w.str_u16(&a.server_handle)?;
    }
    let mm_len = u16::try_from(s.key_mismatch_alerts.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(mm_len);
    for m in &s.key_mismatch_alerts {
        w.u64(m.account_id);
        w.fixed(&m.expected_root_pubkey);
        w.fixed(&m.observed_root_pubkey);
    }
    Ok(w.finish())
}

pub fn decode_status_resp(bytes: &[u8]) -> Result<StatusResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let account_id = r.u64()?;
    let device_id = r.u64()?;
    let handle = r.str_u16(128)?;
    let api_authority = r.str_u16(256)?;
    let local_relay_policy = r.u8()?;
    let cwt_expires_ms = r.u64()?;
    let daemon_epoch = r.u64()?;
    let daemon_pid = r.u32()?;
    let build_order = r.u64()?;
    let build_digest = r.fixed::<32>()?;
    let exe_path = r.str_u16(MAX_STR_SMALL)?;
    let control_ws_connected = r.bool()?;
    let dual_host_churn_alert = r.bool()?;
    let active_party = if r.bool()? {
        Some(read_party_summary(&mut r)?)
    } else {
        None
    };
    let unpinned_count = usize::from(r.u16()?);
    if unpinned_count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut unpinned_alerts = Vec::with_capacity(unpinned_count);
    for _ in 0..unpinned_count {
        unpinned_alerts.push(UnpinnedPeerAlert {
            account_id: r.u64()?,
            root_pubkey: r.fixed::<32>()?,
            safety_number: r.str_u16(64)?,
            server_handle: r.str_u16(128)?,
        });
    }
    let mm_count = usize::from(r.u16()?);
    if mm_count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut key_mismatch_alerts = Vec::with_capacity(mm_count);
    for _ in 0..mm_count {
        key_mismatch_alerts.push(KeyMismatchAlert {
            account_id: r.u64()?,
            expected_root_pubkey: r.fixed::<32>()?,
            observed_root_pubkey: r.fixed::<32>()?,
        });
    }
    r.finish()?;
    Ok(StatusResp {
        account_id,
        device_id,
        handle,
        api_authority,
        local_relay_policy,
        cwt_expires_ms,
        daemon_epoch,
        daemon_pid,
        build_order,
        build_digest,
        exe_path,
        control_ws_connected,
        dual_host_churn_alert,
        active_party,
        unpinned_alerts,
        key_mismatch_alerts,
    })
}

pub fn encode_reload_resp(resp: &ReloadDeviceResp) -> Vec<u8> {
    let mut w = Writer::new();
    w.bool(resp.reloaded);
    w.u64(resp.device_id);
    w.u64(resp.active_party_id);
    w.finish()
}

pub fn decode_reload_resp(bytes: &[u8]) -> Result<ReloadDeviceResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let reloaded = r.bool()?;
    let device_id = r.u64()?;
    let active_party_id = r.u64()?;
    r.finish()?;
    Ok(ReloadDeviceResp {
        reloaded,
        device_id,
        active_party_id,
    })
}

pub fn encode_party_list_resp(resp: &PartyListResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.daemon_epoch);
    let len = u16::try_from(resp.parties.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(len);
    for p in &resp.parties {
        write_party_summary(&mut w, p)?;
    }
    Ok(w.finish())
}

pub fn decode_party_list_resp(bytes: &[u8]) -> Result<PartyListResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let daemon_epoch = r.u64()?;
    let count = usize::from(r.u16()?);
    if count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut parties = Vec::with_capacity(count);
    for _ in 0..count {
        parties.push(read_party_summary(&mut r)?);
    }
    r.finish()?;
    Ok(PartyListResp {
        daemon_epoch,
        parties,
    })
}

pub fn encode_party_members_resp(resp: &PartyMembersResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.party_id);
    w.u64(resp.party_epoch);
    let len = u16::try_from(resp.members.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(len);
    for m in &resp.members {
        w.u64(m.device_id);
        w.u64(m.account_id);
        w.str_u16(&m.server_handle)?;
        w.fixed(&m.root_pubkey);
        w.u8(m.trust_state);
        w.str_u16(&m.safety_number)?;
        w.bool(m.connected_mp1);
        w.bool(m.connected_p2p);
        w.u64(m.joined_seq);
        w.bool(m.key_mismatch);
    }
    Ok(w.finish())
}

pub fn decode_party_members_resp(bytes: &[u8]) -> Result<PartyMembersResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let party_epoch = r.u64()?;
    let count = usize::from(r.u16()?);
    if count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        members.push(MemberInfo {
            device_id: r.u64()?,
            account_id: r.u64()?,
            server_handle: r.str_u16(128)?,
            root_pubkey: r.fixed::<32>()?,
            trust_state: r.u8()?,
            safety_number: r.str_u16(64)?,
            connected_mp1: r.bool()?,
            connected_p2p: r.bool()?,
            joined_seq: r.u64()?,
            key_mismatch: r.bool()?,
        });
    }
    r.finish()?;
    Ok(PartyMembersResp {
        party_id,
        party_epoch,
        members,
    })
}

pub fn encode_party_send_chat_req(req: &PartySendChatReq) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.client_msg_id);
    w.str_u16(&req.room_scope)?;
    w.opt_u64(req.target_device_id);
    w.str_u32(&req.body)?;
    Ok(w.finish())
}

pub fn decode_party_send_chat_req(bytes: &[u8]) -> Result<PartySendChatReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let client_msg_id = r.u64()?;
    let room_scope = r.str_u16(128)?;
    let target_device_id = r.opt_u64()?;
    let body = r.str_u32(256 * 1024)?;
    r.finish()?;
    Ok(PartySendChatReq {
        party_id,
        client_msg_id,
        room_scope,
        target_device_id,
        body,
    })
}

pub fn encode_party_post_board_req(req: &PartyPostBoardReq) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.client_msg_id);
    w.str_u16(&req.room_scope)?;
    w.bytes_u32(&req.payload)?;
    Ok(w.finish())
}

pub fn decode_party_post_board_req(bytes: &[u8]) -> Result<PartyPostBoardReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let client_msg_id = r.u64()?;
    let room_scope = r.str_u16(128)?;
    let payload = r.bytes_u32(MAX_BODY_BYTES)?;
    r.finish()?;
    Ok(PartyPostBoardReq {
        party_id,
        client_msg_id,
        room_scope,
        payload,
    })
}

pub fn encode_control_notice_req(req: &PartyControlNoticeReq) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u8(req.notice_kind);
    w.u64(req.party_epoch);
    w.str_u16(&req.text)?;
    Ok(w.finish())
}

pub fn decode_control_notice_req(bytes: &[u8]) -> Result<PartyControlNoticeReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let notice_kind = r.u8()?;
    let party_epoch = r.u64()?;
    let text = r.str_u16(MAX_STR_SMALL)?;
    r.finish()?;
    Ok(PartyControlNoticeReq {
        party_id,
        notice_kind,
        party_epoch,
        text,
    })
}

pub fn encode_send_result_resp(resp: &SendResultResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.party_id);
    w.u64(resp.client_msg_id);
    let d_len = u16::try_from(resp.delivered_to.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(d_len);
    for &id in &resp.delivered_to {
        w.u64(id);
    }
    let w_len = u16::try_from(resp.withheld_unpinned.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(w_len);
    for &id in &resp.withheld_unpinned {
        w.u64(id);
    }
    let c_len = u16::try_from(resp.disconnected.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(c_len);
    for &id in &resp.disconnected {
        w.u64(id);
    }
    Ok(w.finish())
}

pub fn decode_send_result_resp(bytes: &[u8]) -> Result<SendResultResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let client_msg_id = r.u64()?;
    let d_len = usize::from(r.u16()?);
    if d_len > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut delivered_to = Vec::with_capacity(d_len);
    for _ in 0..d_len {
        delivered_to.push(r.u64()?);
    }
    let w_len = usize::from(r.u16()?);
    if w_len > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut withheld_unpinned = Vec::with_capacity(w_len);
    for _ in 0..w_len {
        withheld_unpinned.push(r.u64()?);
    }
    let c_len = usize::from(r.u16()?);
    if c_len > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut disconnected = Vec::with_capacity(c_len);
    for _ in 0..c_len {
        disconnected.push(r.u64()?);
    }
    r.finish()?;
    Ok(SendResultResp {
        party_id,
        client_msg_id,
        delivered_to,
        withheld_unpinned,
        disconnected,
    })
}

pub fn encode_party_poll_req(req: &PartyPollIpcReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.cursor_epoch);
    w.u64(req.after_seq);
    w.u16(req.limit);
    w.u32(req.max_bytes);
    w.bool(req.board_only);
    w.finish()
}

pub fn decode_party_poll_req(bytes: &[u8]) -> Result<PartyPollIpcReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let mut req = PartyPollIpcReq {
        party_id: r.u64()?,
        cursor_epoch: r.u64()?,
        after_seq: r.u64()?,
        limit: r.u16()?,
        max_bytes: r.u32()?,
        board_only: r.bool()?,
    };
    r.finish()?;
    if req.limit > MAX_POLL_LIMIT || req.max_bytes > MAX_POLL_MAX_BYTES {
        return Err(IpcWireError::BodyTooLarge);
    }
    if req.limit == 0 {
        req.limit = 1;
    }
    if req.max_bytes == 0 {
        req.max_bytes = MAX_POLL_MAX_BYTES;
    }
    Ok(req)
}

pub fn encode_party_wait_req(req: &PartyWaitIpcReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.cursor_epoch);
    w.u64(req.after_seq);
    w.u32(req.timeout_ms);
    w.finish()
}

pub fn decode_party_wait_req(bytes: &[u8]) -> Result<PartyWaitIpcReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyWaitIpcReq {
        party_id: r.u64()?,
        cursor_epoch: r.u64()?,
        after_seq: r.u64()?,
        timeout_ms: r.u32()?,
    };
    r.finish()?;
    Ok(req)
}

fn write_provenance(w: &mut Writer, p: &IpcProvenance) -> Result<(), IpcWireError> {
    w.u64(p.sender_account_id);
    w.u64(p.sender_device_id);
    w.str_u16(&p.sender_handle)?;
    w.str_u16(&p.root_pubkey_fingerprint)?;
    w.str_u16(&p.safety_number)?;
    Ok(())
}

fn read_provenance(r: &mut Reader<'_>) -> Result<IpcProvenance, IpcWireError> {
    Ok(IpcProvenance {
        sender_account_id: r.u64()?,
        sender_device_id: r.u64()?,
        sender_handle: r.str_u16(128)?,
        root_pubkey_fingerprint: r.str_u16(128)?,
        safety_number: r.str_u16(64)?,
    })
}

pub fn encode_party_poll_resp(resp: &PartyPollIpcResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.party_id);
    w.u64(resp.daemon_epoch);
    w.u64(resp.next_seq);
    w.u64(resp.dropped_before_seq);
    w.bool(resp.cursor_reset);
    w.bool(resp.gap_possible);
    w.bool(resp.timed_out);
    let len = u16::try_from(resp.events.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(len);
    for ev in &resp.events {
        w.u64(ev.event_seq);
        w.u64(ev.party_id);
        w.u64(ev.party_epoch);
        match &ev.kind {
            IpcPartyEventKind::Chat {
                provenance,
                room_scope,
                target_selector,
                timestamp_ns,
                body,
            } => {
                w.u8(1);
                write_provenance(&mut w, provenance)?;
                w.str_u16(room_scope)?;
                w.str_u16(target_selector)?;
                w.i64(*timestamp_ns);
                w.str_u32(body)?;
            }
            IpcPartyEventKind::ControlNotice {
                provenance,
                notice_kind,
                party_epoch,
                text,
            } => {
                w.u8(2);
                write_provenance(&mut w, provenance)?;
                w.u8(*notice_kind);
                w.u64(*party_epoch);
                w.str_u16(text)?;
            }
            IpcPartyEventKind::MembershipChanged {
                party_epoch,
                summary,
            } => {
                w.u8(3);
                w.u64(*party_epoch);
                w.str_u16(summary)?;
            }
            IpcPartyEventKind::BridgeEnvelope {
                provenance,
                room_scope,
                payload,
            } => {
                w.u8(4);
                write_provenance(&mut w, provenance)?;
                w.str_u16(room_scope)?;
                w.bytes_u32(payload)?;
            }
        }
    }
    Ok(w.finish())
}

pub fn decode_party_poll_resp(bytes: &[u8]) -> Result<PartyPollIpcResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let daemon_epoch = r.u64()?;
    let next_seq = r.u64()?;
    let dropped_before_seq = r.u64()?;
    let cursor_reset = r.bool()?;
    let gap_possible = r.bool()?;
    let timed_out = r.bool()?;
    let count = usize::from(r.u16()?);
    if count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        let event_seq = r.u64()?;
        let ev_party_id = r.u64()?;
        let party_epoch = r.u64()?;
        let tag = r.u8()?;
        let kind = match tag {
            1 => IpcPartyEventKind::Chat {
                provenance: read_provenance(&mut r)?,
                room_scope: r.str_u16(128)?,
                target_selector: r.str_u16(64)?,
                timestamp_ns: r.i64()?,
                body: r.str_u32(256 * 1024)?,
            },
            2 => IpcPartyEventKind::ControlNotice {
                provenance: read_provenance(&mut r)?,
                notice_kind: r.u8()?,
                party_epoch: r.u64()?,
                text: r.str_u16(MAX_STR_SMALL)?,
            },
            3 => IpcPartyEventKind::MembershipChanged {
                party_epoch: r.u64()?,
                summary: r.str_u16(MAX_STR_SMALL)?,
            },
            4 => IpcPartyEventKind::BridgeEnvelope {
                provenance: read_provenance(&mut r)?,
                room_scope: r.str_u16(128)?,
                payload: r.bytes_u32(MAX_BODY_BYTES)?,
            },
            _ => return Err(IpcWireError::InvalidEnum),
        };
        events.push(IpcPartyEvent {
            event_seq,
            party_id: ev_party_id,
            party_epoch,
            kind,
        });
    }
    r.finish()?;
    Ok(PartyPollIpcResp {
        party_id,
        daemon_epoch,
        next_seq,
        dropped_before_seq,
        cursor_reset,
        gap_possible,
        timed_out,
        events,
    })
}

pub fn encode_friends_list_resp(resp: &FriendsListResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    let len = u16::try_from(resp.friends.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(len);
    for f in &resp.friends {
        w.u64(f.account_id);
        w.u8(f.state);
        w.u64(f.updated_at_ms);
        w.u8(f.presence_status);
        w.opt_u64(f.joinable_party_id);
        w.str_u16(&f.handle)?;
        w.str_u16(&f.safety_number)?;
    }
    Ok(w.finish())
}

pub fn decode_friends_list_resp(bytes: &[u8]) -> Result<FriendsListResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let count = usize::from(r.u16()?);
    if count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut friends = Vec::with_capacity(count);
    for _ in 0..count {
        friends.push(FriendItem {
            account_id: r.u64()?,
            state: r.u8()?,
            updated_at_ms: r.u64()?,
            presence_status: r.u8()?,
            joinable_party_id: r.opt_u64()?,
            handle: r.str_u16(128)?,
            safety_number: r.str_u16(64)?,
        });
    }
    r.finish()?;
    Ok(FriendsListResp { friends })
}

pub fn encode_party_create_req(req: &PartyCreateReq) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u8(req.visibility);
    w.u8(req.join_mode);
    w.u8(req.relay_policy);
    w.u8(req.max_members);
    w.str_u16(&req.relay_url)?;
    w.opt_u64(req.org_id);
    w.opt_u64(req.group_id);
    Ok(w.finish())
}

pub fn decode_party_create_req(bytes: &[u8]) -> Result<PartyCreateReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyCreateReq {
        visibility: r.u8()?,
        join_mode: r.u8()?,
        relay_policy: r.u8()?,
        max_members: r.u8()?,
        relay_url: r.str_u16(256)?,
        org_id: r.opt_u64()?,
        group_id: r.opt_u64()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_create_resp(resp: &PartyCreateResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.party_id);
    w.u64(resp.party_epoch);
    w.str_u16(&resp.pinned_relay_url)?;
    Ok(w.finish())
}

pub fn decode_party_create_resp(bytes: &[u8]) -> Result<PartyCreateResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let resp = PartyCreateResp {
        party_id: r.u64()?,
        party_epoch: r.u64()?,
        pinned_relay_url: r.str_u16(256)?,
    };
    r.finish()?;
    Ok(resp)
}

pub fn encode_party_join_req(req: &PartyJoinReq) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.opt_u8(req.relay_policy_override);
    w.opt_str_u16(req.invite_link.as_deref())?;
    Ok(w.finish())
}

pub fn decode_party_join_req(bytes: &[u8]) -> Result<PartyJoinReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyJoinReq {
        party_id: r.u64()?,
        relay_policy_override: r.opt_u8()?,
        invite_link: r.opt_str_u16(256)?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_join_resp(resp: &PartyJoinResp) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(resp.status);
    w.u64(resp.party_epoch);
    w.u64(resp.request_id);
    w.finish()
}

pub fn decode_party_join_resp(bytes: &[u8]) -> Result<PartyJoinResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let resp = PartyJoinResp {
        status: r.u8()?,
        party_epoch: r.u64()?,
        request_id: r.u64()?,
    };
    r.finish()?;
    Ok(resp)
}

pub fn encode_party_epoch_resp(resp: &PartyEpochResp) -> Vec<u8> {
    let mut w = Writer::new();
    w.bool(resp.ok);
    w.u64(resp.party_epoch);
    w.finish()
}

pub fn decode_party_epoch_resp(bytes: &[u8]) -> Result<PartyEpochResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let resp = PartyEpochResp {
        ok: r.bool()?,
        party_epoch: r.u64()?,
    };
    r.finish()?;
    Ok(resp)
}

pub fn encode_party_epoch_op_req(req: &PartyEpochOpReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.expected_party_epoch);
    w.finish()
}

pub fn decode_party_epoch_op_req(bytes: &[u8]) -> Result<PartyEpochOpReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyEpochOpReq {
        party_id: r.u64()?,
        expected_party_epoch: r.u64()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_kick_req(req: &PartyKickReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.target_account_id);
    w.u64(req.expected_party_epoch);
    w.finish()
}

pub fn decode_party_kick_req(bytes: &[u8]) -> Result<PartyKickReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyKickReq {
        party_id: r.u64()?,
        target_account_id: r.u64()?,
        expected_party_epoch: r.u64()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_promote_req(req: &PartyPromoteReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.target_device_id);
    w.u64(req.expected_party_epoch);
    w.finish()
}

pub fn decode_party_promote_req(bytes: &[u8]) -> Result<PartyPromoteReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyPromoteReq {
        party_id: r.u64()?,
        target_device_id: r.u64()?,
        expected_party_epoch: r.u64()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_invite_mint_req(req: &PartyInviteMintReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.opt_u64(req.target_account_id);
    w.opt_u8(req.max_uses);
    w.opt_u32(req.ttl_sec);
    w.finish()
}

pub fn decode_party_invite_mint_req(bytes: &[u8]) -> Result<PartyInviteMintReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyInviteMintReq {
        party_id: r.u64()?,
        target_account_id: r.opt_u64()?,
        max_uses: r.opt_u8()?,
        ttl_sec: r.opt_u32()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_invite_mint_resp(resp: &PartyInviteMintResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.party_invite_id);
    w.u64(resp.expires_at_ms);
    w.opt_str_u16(resp.invite_link.as_deref())?;
    Ok(w.finish())
}

pub fn decode_party_invite_mint_resp(bytes: &[u8]) -> Result<PartyInviteMintResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let resp = PartyInviteMintResp {
        party_invite_id: r.u64()?,
        expires_at_ms: r.u64()?,
        invite_link: r.opt_str_u16(256)?,
    };
    r.finish()?;
    Ok(resp)
}

pub fn encode_party_invite_revoke_req(req: &PartyInviteRevokeReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.party_invite_id);
    w.finish()
}

pub fn decode_party_invite_revoke_req(bytes: &[u8]) -> Result<PartyInviteRevokeReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyInviteRevokeReq {
        party_id: r.u64()?,
        party_invite_id: r.u64()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_requests_list_req(req: &PartyRequestsListReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.opt_u64(req.cursor);
    w.finish()
}

pub fn decode_party_requests_list_req(bytes: &[u8]) -> Result<PartyRequestsListReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyRequestsListReq {
        party_id: r.u64()?,
        cursor: r.opt_u64()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_requests_list_resp(
    resp: &PartyRequestsListResp,
) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    let len = u16::try_from(resp.requests.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(len);
    for req in &resp.requests {
        w.u64(req.request_id);
        w.u64(req.account_id);
        w.u64(req.device_id);
        w.str_u16(&req.root_pubkey_b64)?;
        w.str_u16(&req.device_pubkey_b64)?;
        w.u64(req.requested_at_ms);
        w.opt_u64(req.reserved_until_ms);
    }
    Ok(w.finish())
}

pub fn decode_party_requests_list_resp(
    bytes: &[u8],
) -> Result<PartyRequestsListResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let count = usize::from(r.u16()?);
    if count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        requests.push(JoinRequestItem {
            request_id: r.u64()?,
            account_id: r.u64()?,
            device_id: r.u64()?,
            root_pubkey_b64: r.str_u16(128)?,
            device_pubkey_b64: r.str_u16(128)?,
            requested_at_ms: r.u64()?,
            reserved_until_ms: r.opt_u64()?,
        });
    }
    r.finish()?;
    Ok(PartyRequestsListResp { requests })
}

pub fn encode_party_request_approve_req(req: &PartyRequestApproveReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.request_id);
    w.u64(req.expected_party_epoch);
    w.u64(req.account_id);
    w.u64(req.device_id);
    w.fixed(&req.device_pubkey_sha256);
    w.finish()
}

pub fn decode_party_request_approve_req(
    bytes: &[u8],
) -> Result<PartyRequestApproveReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyRequestApproveReq {
        party_id: r.u64()?,
        request_id: r.u64()?,
        expected_party_epoch: r.u64()?,
        account_id: r.u64()?,
        device_id: r.u64()?,
        device_pubkey_sha256: r.fixed::<32>()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_party_request_approve_resp(resp: &PartyRequestApproveResp) -> Vec<u8> {
    let mut w = Writer::new();
    w.bool(resp.approved);
    w.u64(resp.reserved_until_ms);
    w.finish()
}

pub fn decode_party_request_approve_resp(
    bytes: &[u8],
) -> Result<PartyRequestApproveResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let resp = PartyRequestApproveResp {
        approved: r.bool()?,
        reserved_until_ms: r.u64()?,
    };
    r.finish()?;
    Ok(resp)
}

pub fn encode_party_request_reject_req(req: &PartyRequestRejectReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(req.party_id);
    w.u64(req.request_id);
    w.opt_u64(req.expected_party_epoch);
    w.finish()
}

pub fn decode_party_request_reject_req(
    bytes: &[u8],
) -> Result<PartyRequestRejectReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let req = PartyRequestRejectReq {
        party_id: r.u64()?,
        request_id: r.u64()?,
        expected_party_epoch: r.opt_u64()?,
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_friend_edge_resp(resp: &FriendEdgeResp) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(resp.target_account_id);
    w.u8(resp.state);
    w.finish()
}

pub fn decode_friend_edge_resp(bytes: &[u8]) -> Result<FriendEdgeResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let resp = FriendEdgeResp {
        target_account_id: r.u64()?,
        state: r.u8()?,
    };
    r.finish()?;
    Ok(resp)
}

pub fn encode_resolve_handle_req(handle: &str) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.str_u16(handle)?;
    Ok(w.finish())
}

pub fn decode_resolve_handle_req(bytes: &[u8]) -> Result<String, IpcWireError> {
    let mut r = Reader::new(bytes);
    let h = r.str_u16(128)?;
    r.finish()?;
    Ok(h)
}

pub fn encode_resolve_handle_resp(resp: &ResolveHandleResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.account_id);
    w.str_u16(&resp.handle)?;
    w.fixed(&resp.root_pubkey);
    Ok(w.finish())
}

pub fn decode_resolve_handle_resp(bytes: &[u8]) -> Result<ResolveHandleResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let resp = ResolveHandleResp {
        account_id: r.u64()?,
        handle: r.str_u16(128)?,
        root_pubkey: r.fixed::<32>()?,
    };
    r.finish()?;
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Conversion helpers for MCP & JSON boundary rendering
// ---------------------------------------------------------------------------

pub const fn relay_policy_name(v: u8) -> &'static str {
    match v {
        0 => "allow_relays",
        1 => "force_relays",
        2 => "no_relays",
        _ => "unknown",
    }
}

pub const fn trust_state_name(v: u8) -> &'static str {
    match v {
        0 => "unpinned",
        1 => "pinned_trusted",
        2 => "revoked_blocked",
        _ => "unknown",
    }
}

pub const fn trust_state_to_u8(t: TrustState) -> u8 {
    t as u8
}

impl From<IpcProvenance> for PeerProvenance {
    fn from(p: IpcProvenance) -> Self {
        Self {
            sender_account_id: p.sender_account_id,
            sender_device_id: p.sender_device_id,
            sender_handle: p.sender_handle,
            root_pubkey_fingerprint: p.root_pubkey_fingerprint,
            safety_number: p.safety_number,
        }
    }
}

impl From<IpcPartyEvent> for McpPartyEvent {
    fn from(ev: IpcPartyEvent) -> Self {
        let kind = match ev.kind {
            IpcPartyEventKind::Chat {
                provenance,
                room_scope,
                target_selector,
                timestamp_ns,
                body,
            } => McpPartyEventKind::Chat {
                provenance: provenance.into(),
                room_scope,
                target_selector,
                timestamp_ns,
                body,
            },
            IpcPartyEventKind::ControlNotice {
                provenance,
                notice_kind,
                party_epoch,
                text,
            } => McpPartyEventKind::ControlNotice {
                provenance: provenance.into(),
                notice_kind,
                party_epoch,
                text,
            },
            IpcPartyEventKind::MembershipChanged {
                party_epoch,
                summary,
            } => McpPartyEventKind::MembershipChanged {
                party_epoch,
                summary,
            },
            IpcPartyEventKind::BridgeEnvelope {
                provenance,
                room_scope,
                payload,
            } => McpPartyEventKind::BridgeEnvelope {
                provenance: provenance.into(),
                room_scope,
                payload,
            },
        };
        Self {
            event_seq: ev.event_seq,
            party_id: ev.party_id,
            party_epoch: ev.party_epoch,
            kind,
        }
    }
}

impl From<PartyPollIpcResp> for PartyPollResp {
    fn from(r: PartyPollIpcResp) -> Self {
        Self {
            party_id: r.party_id,
            daemon_epoch: r.daemon_epoch,
            next_seq: r.next_seq,
            dropped_before_seq: r.dropped_before_seq,
            cursor_reset: r.cursor_reset,
            gap_possible: r.gap_possible,
            timed_out: r.timed_out,
            self_account_id: None,
            self_handle: None,
            events: r.events.into_iter().map(McpPartyEvent::from).collect(),
        }
    }
}

pub fn poll_resp_to_board_events(r: PartyPollIpcResp) -> outpost_mcp::BoardReadResp {
    let mut events = Vec::new();
    for ev in r.events {
        if let IpcPartyEventKind::BridgeEnvelope {
            provenance,
            room_scope,
            payload,
        } = ev.kind
        {
            events.push(BoardEnvelopeEvent {
                event_seq: ev.event_seq,
                party_id: ev.party_id,
                party_epoch: ev.party_epoch,
                provenance: provenance.into(),
                room_scope,
                payload,
            });
        }
    }
    outpost_mcp::BoardReadResp {
        party_id: r.party_id,
        daemon_epoch: r.daemon_epoch,
        next_seq: r.next_seq,
        dropped_before_seq: r.dropped_before_seq,
        cursor_reset: r.cursor_reset,
        gap_possible: r.gap_possible,
        events,
    }
}

pub fn encode_room_invite_req(req: &RoomInviteIpcReq) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.opt_str_u16(req.handle.as_deref())?;
    w.opt_u64(req.party_id);
    w.opt_str_u16(req.name.as_deref())?;
    Ok(w.finish())
}

pub fn decode_room_invite_req(bytes: &[u8]) -> Result<RoomInviteIpcReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let handle = r.opt_str_u16(128)?;
    let party_id = r.opt_u64()?;
    let name = r.opt_str_u16(128)?;
    r.finish()?;
    Ok(RoomInviteIpcReq {
        handle,
        party_id,
        name,
    })
}

pub fn encode_room_invite_resp(resp: &RoomInviteIpcResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.party_id);
    w.str_u16(&resp.room_code)?;
    w.str_u16(&resp.share_url)?;
    w.str_u16(&resp.handle_url)?;
    w.str_u16(&resp.ws_path)?;
    w.opt_str_u16(resp.invited_handle.as_deref())?;
    Ok(w.finish())
}

pub fn decode_room_invite_resp(bytes: &[u8]) -> Result<RoomInviteIpcResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let room_code = r.str_u16(32)?;
    let share_url = r.str_u16(512)?;
    let handle_url = r.str_u16(512)?;
    let ws_path = r.str_u16(256)?;
    let invited_handle = r.opt_str_u16(128)?;
    r.finish()?;
    Ok(RoomInviteIpcResp {
        party_id,
        room_code,
        share_url,
        handle_url,
        ws_path,
        invited_handle,
    })
}

pub fn encode_room_enter_req(req: &RoomEnterIpcReq) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.str_u16(&req.target)?;
    w.opt_str_u16(req.agent_name.as_deref())?;
    Ok(w.finish())
}

pub fn decode_room_enter_req(bytes: &[u8]) -> Result<RoomEnterIpcReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let target = r.str_u16(512)?;
    let agent_name = r.opt_str_u16(128)?;
    r.finish()?;
    Ok(RoomEnterIpcReq { target, agent_name })
}

pub fn encode_room_enter_resp(resp: &RoomEnterIpcResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    w.u64(resp.party_id);
    w.str_u16(&resp.room_code)?;
    w.str_u16(&resp.name)?;
    w.str_u16(&resp.share_url)?;
    w.str_u16(&resp.ws_path)?;
    let len = u16::try_from(resp.members.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(len);
    for m in &resp.members {
        w.u64(m.account_id);
        w.str_u16(&m.handle)?;
        w.str_u16(&m.client)?;
        w.opt_str_u16(m.agent_name.as_deref())?;
        w.str_u16(&m.status)?;
    }
    Ok(w.finish())
}

pub fn decode_room_enter_resp(bytes: &[u8]) -> Result<RoomEnterIpcResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.u64()?;
    let room_code = r.str_u16(32)?;
    let name = r.str_u16(128)?;
    let share_url = r.str_u16(512)?;
    let ws_path = r.str_u16(256)?;
    let count = usize::from(r.u16()?);
    if count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        members.push(RoomMemberIpc {
            account_id: r.u64()?,
            handle: r.str_u16(128)?,
            client: r.str_u16(64)?,
            agent_name: r.opt_str_u16(128)?,
            status: r.str_u16(64)?,
        });
    }
    r.finish()?;
    Ok(RoomEnterIpcResp {
        party_id,
        room_code,
        name,
        share_url,
        ws_path,
        members,
    })
}

pub fn encode_room_leave_req(req: &RoomLeaveIpcReq) -> Vec<u8> {
    let mut w = Writer::new();
    w.opt_u64(req.party_id);
    w.finish()
}

pub fn decode_room_leave_req(bytes: &[u8]) -> Result<RoomLeaveIpcReq, IpcWireError> {
    let mut r = Reader::new(bytes);
    let party_id = r.opt_u64()?;
    r.finish()?;
    Ok(RoomLeaveIpcReq { party_id })
}

pub fn encode_room_leave_resp(resp: &RoomLeaveIpcResp) -> Vec<u8> {
    let mut w = Writer::new();
    w.bool(resp.left);
    w.u64(resp.party_id);
    w.finish()
}

pub fn decode_room_leave_resp(bytes: &[u8]) -> Result<RoomLeaveIpcResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let left = r.bool()?;
    let party_id = r.u64()?;
    r.finish()?;
    Ok(RoomLeaveIpcResp { left, party_id })
}

pub fn encode_friends_live_resp(resp: &FriendsLiveIpcResp) -> Result<Vec<u8>, IpcWireError> {
    let mut w = Writer::new();
    let f_len = u16::try_from(resp.friends.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(f_len);
    for f in &resp.friends {
        w.u64(f.account_id);
        w.str_u16(&f.handle)?;
        w.str_u16(&f.state)?;
        w.str_u16(&f.presence)?;
        w.opt_str_u16(f.client.as_deref())?;
        w.opt_str_u16(f.party_room_code.as_deref())?;
        w.bool(f.joinable);
    }
    let i_len = u16::try_from(resp.pending_invites.len()).map_err(|_| IpcWireError::BodyTooLarge)?;
    w.u16(i_len);
    for inv in &resp.pending_invites {
        w.u64(inv.party_id);
        w.str_u16(&inv.room_code)?;
        w.str_u16(&inv.from_handle)?;
        w.u64(inv.created_at_ms);
    }
    Ok(w.finish())
}

pub fn decode_friends_live_resp(bytes: &[u8]) -> Result<FriendsLiveIpcResp, IpcWireError> {
    let mut r = Reader::new(bytes);
    let f_count = usize::from(r.u16()?);
    if f_count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut friends = Vec::with_capacity(f_count);
    for _ in 0..f_count {
        friends.push(LiveFriendIpc {
            account_id: r.u64()?,
            handle: r.str_u16(128)?,
            state: r.str_u16(64)?,
            presence: r.str_u16(64)?,
            client: r.opt_str_u16(64)?,
            party_room_code: r.opt_str_u16(32)?,
            joinable: r.bool()?,
        });
    }
    let i_count = usize::from(r.u16()?);
    if i_count > MAX_LIST_ITEMS {
        return Err(IpcWireError::BodyTooLarge);
    }
    let mut pending_invites = Vec::with_capacity(i_count);
    for _ in 0..i_count {
        pending_invites.push(PendingInviteIpc {
            party_id: r.u64()?,
            room_code: r.str_u16(32)?,
            from_handle: r.str_u16(128)?,
            created_at_ms: r.u64()?,
        });
    }
    r.finish()?;
    Ok(FriendsLiveIpcResp {
        friends,
        pending_invites,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_POLL_LIMIT, MAX_POLL_MAX_BYTES, PartyPollIpcReq, StatusResp, decode_party_poll_req,
        decode_status_resp, encode_party_poll_req, encode_status_resp,
    };
    use outpost_core::ipc_wire::IpcWireError;

    #[test]
    fn party_poll_req_rejects_oversized_limit_and_max_bytes() {
        let valid = PartyPollIpcReq {
            party_id: 100,
            cursor_epoch: 1,
            after_seq: 0,
            limit: MAX_POLL_LIMIT,
            max_bytes: MAX_POLL_MAX_BYTES,
            board_only: false,
        };
        let encoded = encode_party_poll_req(&valid);
        assert_eq!(decode_party_poll_req(&encoded), Ok(valid.clone()));

        let over_limit = PartyPollIpcReq {
            limit: MAX_POLL_LIMIT + 1,
            ..valid.clone()
        };
        assert_eq!(
            decode_party_poll_req(&encode_party_poll_req(&over_limit)),
            Err(IpcWireError::BodyTooLarge)
        );

        let over_bytes = PartyPollIpcReq {
            max_bytes: MAX_POLL_MAX_BYTES + 1,
            ..valid
        };
        assert_eq!(
            decode_party_poll_req(&encode_party_poll_req(&over_bytes)),
            Err(IpcWireError::BodyTooLarge)
        );
    }

    #[test]
    fn status_resp_supports_long_exe_path_up_to_4096() {
        let long_path = "/".to_string() + &"a".repeat(3000);
        let resp = StatusResp {
            account_id: 1,
            device_id: 2,
            handle: "alice".to_string(),
            api_authority: "api.multiplayer.tech".to_string(),
            local_relay_policy: 0,
            cwt_expires_ms: 123_456,
            daemon_epoch: 7,
            daemon_pid: 42,
            build_order: 1000,
            build_digest: [0xAB; 32],
            exe_path: long_path.clone(),
            control_ws_connected: true,
            dual_host_churn_alert: false,
            active_party: None,
            unpinned_alerts: Vec::new(),
            key_mismatch_alerts: Vec::new(),
        };
        let bytes = match encode_status_resp(&resp) {
            Ok(b) => b,
            Err(e) => {
                assert_eq!(e, IpcWireError::Truncated);
                return;
            }
        };
        let decoded = decode_status_resp(&bytes);
        assert_eq!(decoded.map(|s| s.exe_path), Ok(long_path));
    }

    #[test]
    fn schema_v3_friends_and_scoped_party_create_roundtrip() {
        let friends = super::FriendsListResp {
            friends: vec![
                super::FriendItem {
                    account_id: 1002,
                    state: 0,
                    updated_at_ms: 1_730_000_000_000,
                    presence_status: 1,
                    joinable_party_id: Some(77),
                    handle: "bob".to_string(),
                    safety_number: "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0000-1111".to_string(),
                },
                super::FriendItem {
                    account_id: 1003,
                    state: 2,
                    updated_at_ms: 1_730_000_000_500,
                    presence_status: 0,
                    joinable_party_id: None,
                    handle: String::new(),
                    safety_number: String::new(),
                },
            ],
        };
        let encoded_friends = super::encode_friends_list_resp(&friends);
        assert!(encoded_friends.is_ok());
        if let Ok(bytes) = encoded_friends {
            assert_eq!(super::decode_friends_list_resp(&bytes), Ok(friends));
        }

        let create_req = super::PartyCreateReq {
            visibility: 0,
            join_mode: 1,
            relay_policy: 1,
            max_members: 8,
            relay_url: "https://relay.multiplayer.tech".to_string(),
            org_id: Some(42),
            group_id: Some(99),
        };
        let encoded_req = super::encode_party_create_req(&create_req);
        assert!(encoded_req.is_ok());
        if let Ok(bytes) = encoded_req {
            assert_eq!(super::decode_party_create_req(&bytes), Ok(create_req));
        }

        let unscoped_req = super::PartyCreateReq {
            visibility: 1,
            join_mode: 0,
            relay_policy: 0,
            max_members: 4,
            relay_url: String::new(),
            org_id: None,
            group_id: None,
        };
        let encoded_unscoped = super::encode_party_create_req(&unscoped_req);
        assert!(encoded_unscoped.is_ok());
        if let Ok(bytes) = encoded_unscoped {
            assert_eq!(super::decode_party_create_req(&bytes), Ok(unscoped_req));
        }
    }
}
