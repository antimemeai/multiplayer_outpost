//! Application message AAD (`MpAppAadV1`, exact 40 bytes) and canonical
//! length-prefixed zero-padded `MpAppPayloadV1` (Spec v3.1 §7.1) targeting exact
//! final serialized `MLSMessage` wire lengths (`512`, `2048`, `8192`, `24000` bytes)
//! with OpenMLS `padding_size = 0`.

use crate::error::MpMlsError;
use crate::identity::{check_safe_counter, check_safe_id};
use crate::policy::MP_GROUP_ID_LEN;

pub const MP_APP_AAD_MAGIC: &[u8; 4] = b"MP2A";
pub const MP_APP_AAD_LEN: usize = 40;

/// RFC 9420 §2.1.2 maximum MLS variable-length vector byte length (`2^30 - 1`).
pub const MAX_MLS_VECTOR_LEN: usize = (1usize << 30) - 1;

/// Exact final serialized `MLSMessage` wire bucket lengths (§7.1).
pub const WIRE_BUCKETS: [usize; 4] = [512, 2048, 8192, 24_000];

/// `MpAppPayloadV1` fixed framing overhead (Spec v3.1 §7.1):
/// `version(1) || msg_class(1) || inner_msg_id(16) || body_len(4) || ... || pad_len(4) = 26 bytes`.
pub const APP_PAYLOAD_OVERHEAD_LEN: usize = 1 + 1 + 16 + 4 + 4;
const APP_PAYLOAD_PREFIX_LEN: usize = 1 + 1 + 16 + 4;

/// Ciphersuite `0x0001` Ed25519 signature TLS-serialized length (`2-byte varint len=64 + 64 = 66 B`).
const CIPHERSUITE_0001_SIG_TLS_LEN: usize = 2 + 64;
/// AES-128-GCM tag length (16 B).
const AEAD_TAG_LEN: usize = 16;
/// Encrypted `MlsSenderData` (`leaf_index(4) + generation(4) + reuse_guard(4) + tag(16) = 28 B`)
/// plus its 1-byte TLS varint length prefix (`28 < 64`).
const ENCRYPTED_SENDER_DATA_TLS_LEN: usize = 1 + 12 + AEAD_TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgClass {
    DurableChat = 1,
    DurableAgentCard = 2,
    EphemeralStatus = 3,
    InviteControl = 4,
}

impl MsgClass {
    pub fn from_u8(v: u8) -> Result<Self, MpMlsError> {
        match v {
            1 => Ok(Self::DurableChat),
            2 => Ok(Self::DurableAgentCard),
            3 => Ok(Self::EphemeralStatus),
            4 => Ok(Self::InviteControl),
            other => Err(MpMlsError::InvalidEnumValue {
                field: "msg_class",
                value: u64::from(other),
            }),
        }
    }

    pub fn from_u32(v: u32) -> Result<Self, MpMlsError> {
        match v {
            1 => Ok(Self::DurableChat),
            2 => Ok(Self::DurableAgentCard),
            3 => Ok(Self::EphemeralStatus),
            4 => Ok(Self::InviteControl),
            other => Err(MpMlsError::InvalidEnumValue {
                field: "msg_class",
                value: u64::from(other),
            }),
        }
    }
}

/// Exact 40-byte `PrivateMessage.authenticated_data` (§7.1):
/// `"MP2A"(4) || party_id_be64(8) || mls_epoch_be64(8) || sender_device_id_be64(8) || device_epoch_seq_be64(8) || msg_class_be32(4)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpAppAadV1 {
    pub party_id: u64,
    pub mls_epoch: u64,
    pub sender_device_id: u64,
    pub device_epoch_seq: u64,
    pub msg_class: MsgClass,
}

impl MpAppAadV1 {
    pub fn encode(&self) -> Result<[u8; MP_APP_AAD_LEN], MpMlsError> {
        check_safe_id(self.party_id)?;
        check_safe_counter(self.mls_epoch)?;
        check_safe_id(self.sender_device_id)?;
        check_safe_counter(self.device_epoch_seq)?;

        let mut out = [0u8; MP_APP_AAD_LEN];
        out[0..4].copy_from_slice(MP_APP_AAD_MAGIC);
        out[4..12].copy_from_slice(&self.party_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.mls_epoch.to_be_bytes());
        out[20..28].copy_from_slice(&self.sender_device_id.to_be_bytes());
        out[28..36].copy_from_slice(&self.device_epoch_seq.to_be_bytes());
        out[36..40].copy_from_slice(&u32::from(self.msg_class as u8).to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != MP_APP_AAD_LEN || &bytes[0..4] != MP_APP_AAD_MAGIC {
            return Err(MpMlsError::InvalidAppAad);
        }
        let party_id = u64::from_be_bytes(
            bytes[4..12]
                .try_into()
                .map_err(|_| MpMlsError::InvalidAppAad)?,
        );
        let mls_epoch = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| MpMlsError::InvalidAppAad)?,
        );
        let sender_device_id = u64::from_be_bytes(
            bytes[20..28]
                .try_into()
                .map_err(|_| MpMlsError::InvalidAppAad)?,
        );
        let device_epoch_seq = u64::from_be_bytes(
            bytes[28..36]
                .try_into()
                .map_err(|_| MpMlsError::InvalidAppAad)?,
        );
        let msg_class_raw = u32::from_be_bytes(
            bytes[36..40]
                .try_into()
                .map_err(|_| MpMlsError::InvalidAppAad)?,
        );
        check_safe_id(party_id)?;
        check_safe_counter(mls_epoch)?;
        check_safe_id(sender_device_id)?;
        check_safe_counter(device_epoch_seq)?;
        let msg_class = MsgClass::from_u32(msg_class_raw)?;
        Ok(Self {
            party_id,
            mls_epoch,
            sender_device_id,
            device_epoch_seq,
            msg_class,
        })
    }
}

/// RFC 9420 §2.1.2 variable-length integer prefix size in bytes, bounded by `2^30 - 1`.
const fn tls_vl_prefix_len(len: usize) -> Option<usize> {
    if len < 64 {
        Some(1)
    } else if len < 16_384 {
        Some(2)
    } else if len <= MAX_MLS_VECTOR_LEN {
        Some(4)
    } else {
        None
    }
}

/// Computes the exact plaintext `application_data` length required so that the final
/// serialized `MLSMessage(PrivateMessage)` for ciphersuite `0x0001` (`padding_size = 0`,
/// `group_id_len = 24`, `aad_len = 40`) equals `target_wire_len`.
/// Returns `None` if `target_wire_len` is unrepresentable or exceeds the RFC 9420 `2^30 - 1` vector bound.
pub const fn app_payload_len_for_wire_bucket(target_wire_len: usize) -> Option<usize> {
    // MLSMessage header:
    // version(2) + wire_format(2) + group_id_vl(1 + 24) + epoch(8) + content_type(1)
    // + aad_vl(1 + 40) + encrypted_sender_data_vl(1 + 28) = 108 bytes.
    const FIXED_HEADER: usize = 2
        + 2
        + (1 + MP_GROUP_ID_LEN)
        + 8
        + 1
        + (1 + MP_APP_AAD_LEN)
        + ENCRYPTED_SENDER_DATA_TLS_LEN;

    if target_wire_len <= FIXED_HEADER {
        return None;
    }
    let rem_for_ct_vl = target_wire_len - FIXED_HEADER;

    let ct_len = if rem_for_ct_vl > 4 && matches!(tls_vl_prefix_len(rem_for_ct_vl - 4), Some(4)) {
        rem_for_ct_vl - 4
    } else if rem_for_ct_vl > 2 && matches!(tls_vl_prefix_len(rem_for_ct_vl - 2), Some(2)) {
        rem_for_ct_vl - 2
    } else if rem_for_ct_vl > 1 && matches!(tls_vl_prefix_len(rem_for_ct_vl - 1), Some(1)) {
        rem_for_ct_vl - 1
    } else {
        return None;
    };

    const INNER_OVERHEAD: usize = CIPHERSUITE_0001_SIG_TLS_LEN + AEAD_TAG_LEN;
    if ct_len <= INNER_OVERHEAD {
        return None;
    }
    let rem_for_app_vl = ct_len - INNER_OVERHEAD;
    let app_len = if rem_for_app_vl > 4 && matches!(tls_vl_prefix_len(rem_for_app_vl - 4), Some(4))
    {
        rem_for_app_vl - 4
    } else if rem_for_app_vl > 2 && matches!(tls_vl_prefix_len(rem_for_app_vl - 2), Some(2)) {
        rem_for_app_vl - 2
    } else if rem_for_app_vl > 1 && matches!(tls_vl_prefix_len(rem_for_app_vl - 1), Some(1)) {
        rem_for_app_vl - 1
    } else {
        return None;
    };
    Some(app_len)
}

/// Exact `MpAppPayloadV1` plaintext lengths corresponding to `[512, 2048, 8192, 24000]`.
pub const BUCKET_APP_LENS: [usize; 4] = [
    match app_payload_len_for_wire_bucket(WIRE_BUCKETS[0]) {
        Some(v) => v,
        None => unreachable!(),
    },
    match app_payload_len_for_wire_bucket(WIRE_BUCKETS[1]) {
        Some(v) => v,
        None => unreachable!(),
    },
    match app_payload_len_for_wire_bucket(WIRE_BUCKETS[2]) {
        Some(v) => v,
        None => unreachable!(),
    },
    match app_payload_len_for_wire_bucket(WIRE_BUCKETS[3]) {
        Some(v) => v,
        None => unreachable!(),
    },
];

/// Maximum raw body bytes that fit inside the largest (`24,000 B`) wire bucket (`23,776 B`).
pub const MAX_APP_BODY_BYTES: usize = BUCKET_APP_LENS[3] - APP_PAYLOAD_OVERHEAD_LEN;

/// Canonical padded application payload (`MpAppPayloadV1`, Spec v3.1 §7.1):
/// `version(u8=1) || msg_class(u8: 1..4) || inner_msg_id[16] || body_len(u32 BE) || body[body_len] || pad_len(u32 BE) || zeros[pad_len]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpAppPayloadV1 {
    pub msg_class: MsgClass,
    pub inner_msg_id: [u8; 16],
    pub body: Vec<u8>,
}

impl MpAppPayloadV1 {
    /// Encodes a borrowed `body` directly into the smallest fitting wire bucket
    /// (`512`, `2048`, `8192`, `24000`) without copying oversize payloads.
    pub fn encode_padded_slice(
        msg_class: MsgClass,
        inner_msg_id: [u8; 16],
        body: &[u8],
    ) -> Result<(Vec<u8>, usize), MpMlsError> {
        if body.len() > MAX_APP_BODY_BYTES {
            return Err(MpMlsError::PayloadExceedsMaxBucket);
        }
        let needed = APP_PAYLOAD_OVERHEAD_LEN
            .checked_add(body.len())
            .ok_or(MpMlsError::PayloadExceedsMaxBucket)?;

        let mut chosen: Option<(usize, usize)> = None;
        for i in 0..WIRE_BUCKETS.len() {
            if needed <= BUCKET_APP_LENS[i] {
                chosen = Some((BUCKET_APP_LENS[i], WIRE_BUCKETS[i]));
                break;
            }
        }
        let Some((app_len, wire_bucket)) = chosen else {
            return Err(MpMlsError::PayloadExceedsMaxBucket);
        };

        let body_len_u32 =
            u32::try_from(body.len()).map_err(|_| MpMlsError::PayloadExceedsMaxBucket)?;
        let pad_len = app_len - needed;
        let pad_len_u32 =
            u32::try_from(pad_len).map_err(|_| MpMlsError::PayloadExceedsMaxBucket)?;

        let mut buf = vec![0u8; app_len];
        buf[0] = 1;
        buf[1] = msg_class as u8;
        buf[2..18].copy_from_slice(&inner_msg_id);
        buf[18..22].copy_from_slice(&body_len_u32.to_be_bytes());
        let body_end = APP_PAYLOAD_PREFIX_LEN + body.len();
        buf[APP_PAYLOAD_PREFIX_LEN..body_end].copy_from_slice(body);
        buf[body_end..body_end + 4].copy_from_slice(&pad_len_u32.to_be_bytes());
        Ok((buf, wire_bucket))
    }

    /// Selects the smallest wire bucket (`512`, `2048`, `8192`, `24000`) that fits `self`
    /// and returns `(padded_payload_bytes, expected_final_mls_message_len)`.
    pub fn encode_padded(&self) -> Result<(Vec<u8>, usize), MpMlsError> {
        Self::encode_padded_slice(self.msg_class, self.inner_msg_id, &self.body)
    }

    /// Decodes a canonical zero-padded `MpAppPayloadV1`, verifying exact bucket size,
    /// `version == 1`, valid `msg_class`, exact `pad_len`, and all-zero padding bytes.
    pub fn decode_padded(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if !BUCKET_APP_LENS.contains(&bytes.len()) {
            return Err(MpMlsError::InvalidAppPayload(
                "plaintext length does not match any canonical bucket",
            ));
        }
        if bytes[0] != 1 {
            return Err(MpMlsError::UnsupportedVersion(bytes[0]));
        }
        let msg_class = MsgClass::from_u8(bytes[1])?;
        let inner_msg_id: [u8; 16] = bytes[2..18]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let body_len = u32::from_be_bytes(
            bytes[18..22]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        ) as usize;
        let body_end = APP_PAYLOAD_PREFIX_LEN
            .checked_add(body_len)
            .ok_or(MpMlsError::InvalidAppPayload("body_len overflow"))?;
        let pad_hdr_end = body_end
            .checked_add(4)
            .ok_or(MpMlsError::InvalidAppPayload("pad_len header overflow"))?;
        if pad_hdr_end > bytes.len() {
            return Err(MpMlsError::InvalidAppPayload(
                "body_len exceeds padded bucket size",
            ));
        }
        let pad_len = u32::from_be_bytes(
            bytes[body_end..pad_hdr_end]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        ) as usize;
        let total_end = pad_hdr_end
            .checked_add(pad_len)
            .ok_or(MpMlsError::InvalidAppPayload("pad_len overflow"))?;
        if total_end != bytes.len() {
            return Err(MpMlsError::InvalidAppPayload(
                "pad_len does not match remaining bucket bytes",
            ));
        }
        if bytes[pad_hdr_end..total_end].iter().any(|&b| b != 0) {
            return Err(MpMlsError::InvalidAppPayload("non-zero padding byte"));
        }
        Ok(Self {
            msg_class,
            inner_msg_id,
            body: bytes[APP_PAYLOAD_PREFIX_LEN..body_end].to_vec(),
        })
    }
}
