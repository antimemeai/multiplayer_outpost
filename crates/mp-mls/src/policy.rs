//! Group ID codec, `MpRoomPolicyExtV1` (`Extension::Unknown(0xFF01)`), `MpLeafDeviceListExtV1`
//! (`Extension::Unknown(0xFF02)`), RFC 9420 §7.2-compliant `Capabilities`, deterministic
//! Commit/Proposal/Welcome validation, wall-clock admission checks, and local policy evaluation
//! (Spec v3.1).

use std::collections::{BTreeMap, HashMap, HashSet};

use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialType, Extension, ExtensionType,
    Extensions, ExternalSender, GroupContext, GroupId, KeyPackage, LeafNode, Proposal,
    ProtocolVersion, PublicGroup, RequiredCapabilitiesExtension, Sender, SignaturePublicKey,
    StagedCommit, StagedWelcome, UnknownExtension,
};
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize, VLBytes};

use crate::crypto::{validate_ed25519_pubkey_strict, Ed25519PubKey};
use crate::error::MpMlsError;
use crate::identity::{
    check_safe_counter, check_safe_id, AccountDeviceListV1, AccountRootPinStore, ClientClass,
    CustodyMode, DeviceListTracker, MpMlsLeafCredV1, MAX_DEVICES_PER_ACCOUNT, MAX_SAFE_ID,
};
use crate::invite::{
    validate_policy_bits, POLICY_BIT_DISALLOW_BROWSER_DEVICES, POLICY_BIT_REQUIRE_SELF_CUSTODY,
};

pub const MP_GROUP_ID_PREFIX: &[u8; 8] = b"MP2MLS2\0";
pub const MP_GROUP_ID_LEN: usize = 24;
pub const MP_ROOM_POLICY_EXT_TYPE: u16 = 0xFF01;
pub const MP_LEAF_DEVICE_LIST_EXT_TYPE: u16 = 0xFF02;
pub const MP_DS_CRED_PREFIX: &[u8; 9] = b"mp-ds-v1:";

pub const MP_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub const MAX_ACCOUNTS_PER_ROOM: usize = 12;
pub const MAX_LEAVES_PER_ROOM: usize = 96;
pub const MAX_HOST_ACCOUNTS: usize = 12;
pub const MAX_BANNED_ACCOUNTS: usize = 128;

/// Catch-up-safe OpenMLS KeyPackage `Lifetime` bounds (1970-01-01..2100-01-01, zero `now + t` overflow,
/// zero wall-clock fork on historical Add replay; real 7d/30d expiry enforced on `MpMlsDeviceBindingV1`
/// and `AccountDeviceListV1` at admission time and in `evaluate_local_policy`).
pub const CATCHUP_SAFE_LIFETIME_NOT_BEFORE: u64 = 0;
pub const CATCHUP_SAFE_LIFETIME_NOT_AFTER: u64 = 4_102_444_800;

/// Extracts the raw HPKE public key bytes from a `LeafNode`'s `EncryptionKey`
/// (in OpenMLS 0.9.2 `EncryptionKey::as_slice()` is `pub(crate)`, while `TlsSerialize` encodes `VLBytes`).
pub(crate) fn leaf_encryption_key_bytes(leaf: &LeafNode) -> Result<Vec<u8>, MpMlsError> {
    let encoded = leaf
        .encryption_key()
        .tls_serialize_detached()
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
    let vl = VLBytes::tls_deserialize_exact_bytes(&encoded)
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
    Ok(vl.as_slice().to_vec())
}

/// Structured 24-byte `group_id`: `"MP2MLS2\0"(8) || party_id_be64(8) || incarnation_nonce(8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MpGroupId {
    pub party_id: u64,
    pub incarnation_nonce: [u8; 8],
}

impl MpGroupId {
    pub fn new(party_id: u64, incarnation_nonce: [u8; 8]) -> Result<Self, MpMlsError> {
        check_safe_id(party_id)?;
        Ok(Self {
            party_id,
            incarnation_nonce,
        })
    }

    pub fn encode(&self) -> [u8; MP_GROUP_ID_LEN] {
        let mut out = [0u8; MP_GROUP_ID_LEN];
        out[0..8].copy_from_slice(MP_GROUP_ID_PREFIX);
        out[8..16].copy_from_slice(&self.party_id.to_be_bytes());
        out[16..24].copy_from_slice(&self.incarnation_nonce);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != MP_GROUP_ID_LEN || &bytes[0..8] != MP_GROUP_ID_PREFIX {
            return Err(MpMlsError::InvalidGroupId);
        }
        let party_id = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| MpMlsError::InvalidGroupId)?,
        );
        check_safe_id(party_id).map_err(|_| MpMlsError::InvalidGroupId)?;
        let incarnation_nonce: [u8; 8] = bytes[16..24]
            .try_into()
            .map_err(|_| MpMlsError::InvalidGroupId)?;
        Ok(Self {
            party_id,
            incarnation_nonce,
        })
    }

    pub fn to_openmls(&self) -> GroupId {
        GroupId::from_slice(&self.encode())
    }
}

/// Builds the canonical `BasicCredential` for the single room DS `ExternalSender`:
/// `"mp-ds-v1:" || party_id_be64`.
pub fn ds_external_sender_credential(party_id: u64) -> Result<BasicCredential, MpMlsError> {
    check_safe_id(party_id)?;
    let mut ident = Vec::with_capacity(MP_DS_CRED_PREFIX.len() + 8);
    ident.extend_from_slice(MP_DS_CRED_PREFIX);
    ident.extend_from_slice(&party_id.to_be_bytes());
    Ok(BasicCredential::new(ident))
}

/// Builds the canonical `ExternalSender` for the room Delivery Service (`PartyDO`).
pub fn build_ds_external_sender(
    party_id: u64,
    ds_pubkey: &Ed25519PubKey,
) -> Result<ExternalSender, MpMlsError> {
    validate_ed25519_pubkey_strict(ds_pubkey)?;
    let cred = ds_external_sender_credential(party_id)?;
    Ok(ExternalSender::new(
        SignaturePublicKey::from(ds_pubkey.to_vec()),
        cred.into(),
    ))
}

/// Canonical `RequiredCapabilitiesExtension` listing ONLY our non-default private extensions
/// `0xFF01` (`MpRoomPolicyExtV1`) and `0xFF02` (`MpLeafDeviceListExtV1`) + `CredentialType::Basic`
/// (RFC 9420 §11.1 / Astra §3).
pub fn required_capabilities_extension() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(
        &[
            ExtensionType::Unknown(MP_ROOM_POLICY_EXT_TYPE),
            ExtensionType::Unknown(MP_LEAF_DEVICE_LIST_EXT_TYPE),
        ],
        &[],
        &[CredentialType::Basic],
    )
}

/// RFC 9420 §7.2-compliant `Capabilities` advertised by every `mp-mls` `LeafNode`:
/// omits ALL default MLS extension types and default proposal types, advertising ONLY our
/// non-default private extensions (`0xFF01`, `0xFF02`) and `CredentialType::Basic` (Astra §3).
pub fn leaf_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[MP_CIPHERSUITE]),
        Some(&[
            ExtensionType::Unknown(MP_ROOM_POLICY_EXT_TYPE),
            ExtensionType::Unknown(MP_LEAF_DEVICE_LIST_EXT_TYPE),
        ]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

/// Builds the mandatory `LeafNode` extension set carrying `0xFF02` `MpLeafDeviceListExtV1`.
pub fn leaf_device_list_extensions(
    device_list: &AccountDeviceListV1,
) -> Result<Extensions<LeafNode>, MpMlsError> {
    let raw = device_list.encode()?;
    Extensions::single(Extension::Unknown(
        MP_LEAF_DEVICE_LIST_EXT_TYPE,
        UnknownExtension(raw),
    ))
    .map_err(|e| MpMlsError::OpenMls(format!("build 0xFF02 LeafNode extension failed: {e}")))
}

/// Canonical binary `MpRoomPolicyExtV1` carried in `Extension::Unknown(0xFF01, ...)` (Spec v3.1 §4.1):
/// `version(1) || party_id(8) || e2ee_mode(1) || require_self_custody(1) || allow_browser_devices(1) || org_id(8) || host_count(2) || hosts[8*h] || banned_count(2) || banned[8*b] || invite_epoch(8)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpRoomPolicyExtV1 {
    pub version: u8,
    pub party_id: u64,
    pub e2ee_mode: u8,
    pub require_self_custody: bool,
    pub allow_browser_devices: bool,
    pub org_id: u64,
    pub host_account_ids: Vec<u64>,
    pub banned_account_ids: Vec<u64>,
    pub invite_epoch: u64,
}

fn validate_sorted_unique_ids(
    ids: &[u64],
    min_len: usize,
    max_len: usize,
    err_msg: &'static str,
) -> Result<(), MpMlsError> {
    if ids.len() < min_len || ids.len() > max_len {
        return Err(MpMlsError::InvalidRoomPolicy(err_msg));
    }
    let mut prev: Option<u64> = None;
    for &id in ids {
        check_safe_id(id)?;
        if let Some(p) = prev
            && id <= p
        {
            return Err(MpMlsError::InvalidRoomPolicy(err_msg));
        }
        prev = Some(id);
    }
    Ok(())
}

impl MpRoomPolicyExtV1 {
    pub fn validate(&self) -> Result<(), MpMlsError> {
        if self.version != 1 {
            return Err(MpMlsError::UnsupportedVersion(self.version));
        }
        check_safe_id(self.party_id)?;
        if self.e2ee_mode != 1 {
            return Err(MpMlsError::InvalidRoomPolicy("e2ee_mode must be 1"));
        }
        if self.org_id > MAX_SAFE_ID {
            return Err(MpMlsError::InvalidSafeId(self.org_id));
        }
        validate_sorted_unique_ids(
            &self.host_account_ids,
            1,
            MAX_HOST_ACCOUNTS,
            "host_account_ids must be 1..=12 sorted unique safe IDs",
        )?;
        validate_sorted_unique_ids(
            &self.banned_account_ids,
            0,
            MAX_BANNED_ACCOUNTS,
            "banned_account_ids must be 0..=128 sorted unique safe IDs",
        )?;
        check_safe_counter(self.invite_epoch)?;
        Ok(())
    }

    pub fn policy_bits(&self) -> u8 {
        let mut bits = 0u8;
        if self.require_self_custody {
            bits |= POLICY_BIT_REQUIRE_SELF_CUSTODY;
        }
        if !self.allow_browser_devices {
            bits |= POLICY_BIT_DISALLOW_BROWSER_DEVICES;
        }
        bits
    }

    pub fn satisfies_policy_bits(&self, required_bits: u8) -> Result<bool, MpMlsError> {
        validate_policy_bits(required_bits)?;
        if (required_bits & POLICY_BIT_REQUIRE_SELF_CUSTODY) != 0 && !self.require_self_custody {
            return Ok(false);
        }
        if (required_bits & POLICY_BIT_DISALLOW_BROWSER_DEVICES) != 0 && self.allow_browser_devices {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn add_banned_account(&mut self, account_id: u64) -> Result<(), MpMlsError> {
        check_safe_id(account_id)?;
        if let Err(pos) = self.banned_account_ids.binary_search(&account_id) {
            if self.banned_account_ids.len() >= MAX_BANNED_ACCOUNTS {
                return Err(MpMlsError::InvalidRoomPolicy("banned_account_ids full"));
            }
            self.banned_account_ids.insert(pos, account_id);
        }
        Ok(())
    }

    /// Returns a cloned policy with `invite_epoch` incremented by 1 (checked safe counter).
    pub fn with_bumped_invite_epoch(&self) -> Result<Self, MpMlsError> {
        let next_epoch = self
            .invite_epoch
            .checked_add(1)
            .ok_or(MpMlsError::InvalidSafeCounter(u64::MAX))?;
        check_safe_counter(next_epoch)?;
        let mut next = self.clone();
        next.invite_epoch = next_epoch;
        Ok(next)
    }

    pub fn encode(&self) -> Result<Vec<u8>, MpMlsError> {
        self.validate()?;
        let cap = 1
            + 8
            + 1
            + 1
            + 1
            + 8
            + 2
            + self.host_account_ids.len() * 8
            + 2
            + self.banned_account_ids.len() * 8
            + 8;
        let mut out = Vec::with_capacity(cap);
        out.push(self.version);
        out.extend_from_slice(&self.party_id.to_be_bytes());
        out.push(self.e2ee_mode);
        out.push(u8::from(self.require_self_custody));
        out.push(u8::from(self.allow_browser_devices));
        out.extend_from_slice(&self.org_id.to_be_bytes());
        out.extend_from_slice(&(self.host_account_ids.len() as u16).to_be_bytes());
        for &id in &self.host_account_ids {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&(self.banned_account_ids.len() as u16).to_be_bytes());
        for &id in &self.banned_account_ids {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&self.invite_epoch.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        let mut cursor = bytes;
        let read_u8 = |c: &mut &[u8]| -> Result<u8, MpMlsError> {
            if c.is_empty() {
                return Err(MpMlsError::TruncatedInput);
            }
            let v = c[0];
            *c = &c[1..];
            Ok(v)
        };
        let read_u16 = |c: &mut &[u8]| -> Result<u16, MpMlsError> {
            if c.len() < 2 {
                return Err(MpMlsError::TruncatedInput);
            }
            let v = u16::from_be_bytes([c[0], c[1]]);
            *c = &c[2..];
            Ok(v)
        };
        let read_u64 = |c: &mut &[u8]| -> Result<u64, MpMlsError> {
            if c.len() < 8 {
                return Err(MpMlsError::TruncatedInput);
            }
            let v = u64::from_be_bytes(
                c[0..8]
                    .try_into()
                    .map_err(|_| MpMlsError::TruncatedInput)?,
            );
            *c = &c[8..];
            Ok(v)
        };
        let read_bool = |c: &mut &[u8], field: &'static str| -> Result<bool, MpMlsError> {
            match read_u8(c)? {
                0 => Ok(false),
                1 => Ok(true),
                other => Err(MpMlsError::InvalidEnumValue {
                    field,
                    value: u64::from(other),
                }),
            }
        };

        let version = read_u8(&mut cursor)?;
        let party_id = read_u64(&mut cursor)?;
        let e2ee_mode = read_u8(&mut cursor)?;
        let require_self_custody = read_bool(&mut cursor, "require_self_custody")?;
        let allow_browser_devices = read_bool(&mut cursor, "allow_browser_devices")?;
        let org_id = read_u64(&mut cursor)?;

        let host_count = usize::from(read_u16(&mut cursor)?);
        if host_count == 0 || host_count > MAX_HOST_ACCOUNTS || host_count > cursor.len() / 8 {
            return Err(MpMlsError::InvalidRoomPolicy("invalid host_account_count"));
        }
        let mut host_account_ids = Vec::with_capacity(host_count);
        for _ in 0..host_count {
            host_account_ids.push(read_u64(&mut cursor)?);
        }

        let banned_count = usize::from(read_u16(&mut cursor)?);
        if banned_count > MAX_BANNED_ACCOUNTS || banned_count > cursor.len() / 8 {
            return Err(MpMlsError::InvalidRoomPolicy(
                "invalid banned_account_count",
            ));
        }
        let mut banned_account_ids = Vec::with_capacity(banned_count);
        for _ in 0..banned_count {
            banned_account_ids.push(read_u64(&mut cursor)?);
        }

        let invite_epoch = read_u64(&mut cursor)?;

        if !cursor.is_empty() {
            return Err(MpMlsError::TrailingBytes);
        }

        let policy = Self {
            version,
            party_id,
            e2ee_mode,
            require_self_custody,
            allow_browser_devices,
            org_id,
            host_account_ids,
            banned_account_ids,
            invite_epoch,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_extension(&self) -> Result<Extension, MpMlsError> {
        Ok(Extension::Unknown(
            MP_ROOM_POLICY_EXT_TYPE,
            UnknownExtension(self.encode()?),
        ))
    }

    pub fn from_group_context(ctx: &GroupContext) -> Result<Self, MpMlsError> {
        Self::from_extensions(ctx.extensions())
    }

    pub fn from_extensions(exts: &Extensions<GroupContext>) -> Result<Self, MpMlsError> {
        let raw = exts
            .unknown(MP_ROOM_POLICY_EXT_TYPE)
            .ok_or(MpMlsError::MissingRoomPolicyExtension)?;
        Self::decode(&raw.0)
    }

    /// Validates an `MpRoomPolicyExtV1` transition (Spec v3.1 §4.1):
    /// - `party_id`, `e2ee_mode`, `org_id` are strictly immutable.
    /// - On any Remove Commit (`has_remove == true`): `invite_epoch` MUST equal `prev.invite_epoch + 1`.
    /// - On a non-Remove Commit (`has_remove == false`): `invite_epoch` MUST equal `prev.invite_epoch`.
    /// - If `!is_host`: ONLY the `invite_epoch + 1` bump (when `has_remove == true`) is permitted;
    ///   all other fields (`require_self_custody`, `allow_browser_devices`, `host_account_ids`,
    ///   `banned_account_ids`) MUST remain identical to `prev`.
    /// - If `is_host`: `require_self_custody` (`0 -> 1`) and `allow_browser_devices` (`1 -> 0`) are
    ///   tighten-only, and `banned_account_ids` is append-only (monotonic ban list).
    pub fn validate_transition(
        prev: &Self,
        next: &Self,
        is_host: bool,
        has_remove: bool,
    ) -> Result<(), MpMlsError> {
        next.validate()?;
        if prev.party_id != next.party_id {
            return Err(MpMlsError::ExtensionPolicyViolation(
                "party_id is immutable",
            ));
        }
        if prev.e2ee_mode != next.e2ee_mode {
            return Err(MpMlsError::ExtensionPolicyViolation(
                "e2ee_mode is immutable",
            ));
        }
        if prev.org_id != next.org_id {
            return Err(MpMlsError::ExtensionPolicyViolation("org_id is immutable"));
        }

        if has_remove {
            if prev.invite_epoch.checked_add(1) != Some(next.invite_epoch) {
                return Err(MpMlsError::ExtensionPolicyViolation(
                    "Remove Commit must increment invite_epoch by exactly 1",
                ));
            }
        } else if next.invite_epoch != prev.invite_epoch {
            return Err(MpMlsError::ExtensionPolicyViolation(
                "invite_epoch may only increment on a Remove Commit",
            ));
        }

        if !is_host {
            if prev.require_self_custody != next.require_self_custody
                || prev.allow_browser_devices != next.allow_browser_devices
                || prev.host_account_ids != next.host_account_ids
                || prev.banned_account_ids != next.banned_account_ids
            {
                return Err(MpMlsError::ForbiddenProposal(
                    "non-host committer may only bump invite_epoch alongside a Remove",
                ));
            }
            return Ok(());
        }

        if prev.require_self_custody && !next.require_self_custody {
            return Err(MpMlsError::ExtensionPolicyViolation(
                "require_self_custody is tighten-only (cannot relax 1 -> 0)",
            ));
        }
        if !prev.allow_browser_devices && next.allow_browser_devices {
            return Err(MpMlsError::ExtensionPolicyViolation(
                "allow_browser_devices is tighten-only (cannot relax 0 -> 1)",
            ));
        }
        // Ban list is append-only (cannot silently unban accounts without a new incarnation).
        if prev
            .banned_account_ids
            .iter()
            .any(|id| next.banned_account_ids.binary_search(id).is_err())
        {
            return Err(MpMlsError::ExtensionPolicyViolation(
                "banned_account_ids is append-only (cannot remove existing bans)",
            ));
        }
        Ok(())
    }

    /// Checks whether a leaf credential satisfies this room's custody/class policy.
    pub fn check_leaf_allowed(&self, cred: &MpMlsLeafCredV1) -> Result<(), MpMlsError> {
        if self.require_self_custody && cred.binding.body.custody_mode != CustodyMode::SelfCustody {
            return Err(MpMlsError::RoomPolicyViolation(
                "room requires self-custody (custody_mode = 1)",
            ));
        }
        if !self.allow_browser_devices && cred.binding.body.client_class == ClientClass::Browser {
            return Err(MpMlsError::RoomPolicyViolation(
                "room disallows browser devices (client_class = 3)",
            ));
        }
        Ok(())
    }

    /// Checks that `account_id` is not in `banned_account_ids`.
    pub fn check_not_banned(&self, account_id: u64) -> Result<(), MpMlsError> {
        if self.banned_account_ids.binary_search(&account_id).is_ok() {
            return Err(MpMlsError::RoomPolicyViolation(
                "account_id is on room banned_account_ids list",
            ));
        }
        Ok(())
    }

    pub fn is_host(&self, account_id: u64) -> bool {
        self.host_account_ids.binary_search(&account_id).is_ok()
    }
}

/// Snapshot of an occupied leaf in the ratchet tree for deterministic validation,
/// carrying BOTH its verified `MpMlsLeafCredV1` AND its verified `0xFF02` `AccountDeviceListV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeLeafInfo {
    pub cred: MpMlsLeafCredV1,
    pub device_list: AccountDeviceListV1,
    pub signature_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

/// Decodes and validates a `LeafNode`'s `MpMlsLeafCredV1` AND mandatory `0xFF02`
/// `AccountDeviceListV1` (time-independent, strict Ed25519, Spec v3.1 §3.2 / §3.3):
/// 1. Decodes 276-byte `MpMlsLeafCredV1` and verifies `root_sig` + `device_pop_sig`.
/// 2. Verifies `LeafNode.signature_key == mls_sig_pubkey`.
/// 3. Extracts mandatory `Extension::Unknown(0xFF02)` and decodes `AccountDeviceListV1`.
/// 4. Verifies `list.account_id == cred.account_id`, `list.root_gen == cred.root_gen`,
///    `list.list_version == cred.list_version`, strict `list.verify(&cred.root_pubkey)`,
///    `SHA-256(list) == cred.list_hash`, and `list.authorizes_leaf(&cred.binding.body)`.
pub fn validate_leaf_node_credential(
    leaf: &LeafNode,
) -> Result<(MpMlsLeafCredV1, AccountDeviceListV1), MpMlsError> {
    let cred = MpMlsLeafCredV1::from_openmls_credential(leaf.credential())?;
    if leaf.signature_key().as_slice() != cred.binding.body.mls_sig_pubkey {
        return Err(MpMlsError::LeafSignatureKeyMismatch);
    }

    let raw_ext = leaf
        .extensions()
        .unknown(MP_LEAF_DEVICE_LIST_EXT_TYPE)
        .ok_or(MpMlsError::MissingLeafDeviceListExtension)?;
    let device_list = AccountDeviceListV1::decode(&raw_ext.0)?;

    let body = &cred.binding.body;
    if device_list.account_id != body.account_id {
        return Err(MpMlsError::InvalidLeafDeviceList(
            "0xFF02 device_list.account_id mismatch",
        ));
    }
    if device_list.root_gen != body.root_gen {
        return Err(MpMlsError::InvalidLeafDeviceList(
            "0xFF02 device_list.root_gen mismatch",
        ));
    }
    if device_list.list_version != cred.list_version {
        return Err(MpMlsError::InvalidLeafDeviceList(
            "0xFF02 device_list.list_version does not match credential list_version",
        ));
    }
    device_list.verify(&body.root_pubkey)?;
    if device_list.list_hash()? != cred.list_hash {
        return Err(MpMlsError::InvalidLeafDeviceList(
            "0xFF02 SHA-256(device_list) does not match credential list_hash",
        ));
    }
    if !device_list.authorizes_leaf(body) {
        return Err(MpMlsError::InvalidLeafDeviceList(
            "leaf (device_id, device_gen, mls_sig_pubkey) not authorized by 0xFF02 device list",
        ));
    }

    Ok((cred, device_list))
}

/// Extracts and validates EVERY occupied leaf in a `PublicGroup` (including `0xFF02` device list).
pub fn extract_public_group_leaves(
    pg: &PublicGroup,
) -> Result<BTreeMap<u32, TreeLeafInfo>, MpMlsError> {
    let mut leaves = BTreeMap::new();
    for m in pg.members() {
        let leaf = pg
            .leaf(m.index)
            .ok_or(MpMlsError::TreeInvariantViolation("member leaf missing"))?;
        let (cred, device_list) = validate_leaf_node_credential(leaf)?;
        leaves.insert(
            m.index.u32(),
            TreeLeafInfo {
                cred,
                device_list,
                signature_key: m.signature_key,
                encryption_key: m.encryption_key,
            },
        );
    }
    Ok(leaves)
}

/// Validates identity continuity when a leaf is replaced via `Update` or `UpdatePath` (§3.3).
pub fn validate_leaf_identity_continuity(
    prev: &MpMlsLeafCredV1,
    next: &MpMlsLeafCredV1,
) -> Result<(), MpMlsError> {
    let p = &prev.binding.body;
    let n = &next.binding.body;
    if p.account_id != n.account_id {
        return Err(MpMlsError::IdentityContinuityViolation(
            "account_id cannot change on leaf update",
        ));
    }
    if p.device_id != n.device_id {
        return Err(MpMlsError::IdentityContinuityViolation(
            "device_id cannot change on leaf update",
        ));
    }
    if p.root_pubkey != n.root_pubkey {
        return Err(MpMlsError::IdentityContinuityViolation(
            "root_pubkey cannot change on leaf update",
        ));
    }
    if p.root_gen != n.root_gen {
        return Err(MpMlsError::IdentityContinuityViolation(
            "root_gen cannot change on leaf update",
        ));
    }
    if p.custody_mode != n.custody_mode {
        return Err(MpMlsError::IdentityContinuityViolation(
            "custody_mode cannot change on leaf update",
        ));
    }
    if n.device_gen < p.device_gen {
        return Err(MpMlsError::IdentityContinuityViolation(
            "device_gen cannot regress on leaf update",
        ));
    }
    if next.list_version < prev.list_version {
        return Err(MpMlsError::IdentityContinuityViolation(
            "list_version cannot regress on leaf update",
        ));
    }
    Ok(())
}

/// Validates tree uniqueness, capacity, policy, and ban exclusion invariants (§3.3 / §4.1):
/// - No duplicate `device_id`, `signature_key`, or `encryption_key` across all occupied leaves.
/// - `<= 12` distinct `account_id`s, `<= 8` devices per account, `<= 96` occupied leaves.
/// - Every occupied leaf satisfies `policy` AND is NOT in `policy.banned_account_ids`!
pub fn validate_tree_invariants(
    leaves: &[TreeLeafInfo],
    policy: &MpRoomPolicyExtV1,
) -> Result<(), MpMlsError> {
    if leaves.len() > MAX_LEAVES_PER_ROOM {
        return Err(MpMlsError::TreeInvariantViolation(
            "occupied leaves exceed MAX_LEAVES_PER_ROOM (96)",
        ));
    }
    let mut seen_devices: HashSet<u64> = HashSet::with_capacity(leaves.len());
    let mut seen_sig_keys: HashSet<&[u8]> = HashSet::with_capacity(leaves.len());
    let mut seen_enc_keys: HashSet<&[u8]> = HashSet::with_capacity(leaves.len());
    let mut acct_counts: HashMap<u64, usize> = HashMap::new();

    for leaf in leaves {
        policy.check_leaf_allowed(&leaf.cred)?;
        policy.check_not_banned(leaf.cred.binding.body.account_id)?;
        if !seen_devices.insert(leaf.cred.binding.body.device_id) {
            return Err(MpMlsError::TreeInvariantViolation(
                "duplicate device_id in ratchet tree",
            ));
        }
        if !seen_sig_keys.insert(leaf.signature_key.as_slice()) {
            return Err(MpMlsError::TreeInvariantViolation(
                "duplicate signature_key in ratchet tree",
            ));
        }
        if !seen_enc_keys.insert(leaf.encryption_key.as_slice()) {
            return Err(MpMlsError::TreeInvariantViolation(
                "duplicate encryption_key in ratchet tree",
            ));
        }
        let count = acct_counts
            .entry(leaf.cred.binding.body.account_id)
            .or_insert(0);
        *count += 1;
        if *count > MAX_DEVICES_PER_ACCOUNT {
            return Err(MpMlsError::TreeInvariantViolation(
                "devices per account exceeds MAX_DEVICES_PER_ACCOUNT (8)",
            ));
        }
    }
    if acct_counts.len() > MAX_ACCOUNTS_PER_ROOM {
        return Err(MpMlsError::TreeInvariantViolation(
            "distinct accounts exceed MAX_ACCOUNTS_PER_ROOM (12)",
        ));
    }
    Ok(())
}

/// Wall-clock KeyPackage admission check (runs ONLY at admission time in DS and committing member, Spec v3.1 §3.3 / §4.2):
/// - Verifies ciphersuite `0x0001`, no `LastResort`, `init_key != leaf.encryption_key`.
/// - Verifies catch-up-safe `Lifetime` profile (`not_before == 0, not_after == 4_102_444_800`) so
///   historical Commit replay inside the 2,000-epoch catch-up horizon can never fail on wall clock.
/// - Verifies `MpMlsLeafCredV1` AND `0xFF02` `AccountDeviceListV1`.
/// - Enforces wall-clock `iat_s <= now_s < exp_s` on BOTH `MpMlsDeviceBindingV1` AND `AccountDeviceListV1`.
/// - Enforces room policy (`require_self_custody`, `allow_browser_devices`, `banned_account_ids`).
/// - Checks local pins and device-list revocation/equivocation if provided.
pub fn validate_key_package_admission(
    kp: &KeyPackage,
    now_s: u64,
    policy: &MpRoomPolicyExtV1,
    pins: Option<&AccountRootPinStore>,
    device_lists: Option<&DeviceListTracker>,
) -> Result<(MpMlsLeafCredV1, AccountDeviceListV1), MpMlsError> {
    check_safe_counter(now_s)?;
    if kp.ciphersuite() != MP_CIPHERSUITE {
        return Err(MpMlsError::KeyPackageAdmissionRejected(
            "unsupported ciphersuite",
        ));
    }
    if kp.last_resort() {
        return Err(MpMlsError::KeyPackageAdmissionRejected(
            "last-resort extension is forbidden",
        ));
    }
    let lt = kp.life_time();
    if lt.not_before() != CATCHUP_SAFE_LIFETIME_NOT_BEFORE
        || lt.not_after() != CATCHUP_SAFE_LIFETIME_NOT_AFTER
    {
        return Err(MpMlsError::KeyPackageAdmissionRejected(
            "KeyPackage lifetime does not match catch-up-safe profile (0..4_102_444_800)",
        ));
    }
    let leaf_enc = leaf_encryption_key_bytes(kp.leaf_node())?;
    if kp.hpke_init_key().as_slice() == leaf_enc.as_slice() {
        return Err(MpMlsError::KeyPackageAdmissionRejected(
            "init_key must differ from leaf encryption_key",
        ));
    }
    let (cred, device_list) = validate_leaf_node_credential(kp.leaf_node())?;
    cred.binding.verify_at_admission(now_s)?;
    device_list.verify_at_admission(&cred.binding.body.root_pubkey, now_s)?;
    policy.check_leaf_allowed(&cred)?;
    policy.check_not_banned(cred.binding.body.account_id)?;

    if let Some(pin_store) = pins {
        pin_store.check(
            cred.binding.body.account_id,
            &cred.binding.body.root_pubkey,
            cred.binding.body.root_gen,
            cred.binding.body.custody_mode,
        )?;
    }
    if let Some(dl) = device_lists {
        if dl.check_leaf_equivocation(&cred) {
            return Err(MpMlsError::DeviceListEquivocation {
                version: cred.list_version,
            });
        }
        if dl.is_leaf_revoked(&cred) {
            return Err(MpMlsError::KeyPackageAdmissionRejected(
                "device is revoked in AccountDeviceListV1",
            ));
        }
    }
    Ok((cred, device_list))
}

/// Checks if any verified `AccountDeviceListV1` in `evidence` (for the target's `account_id`
/// and verified under the target's `root_pubkey` for same `root_gen`) proves `target` was revoked
/// (strictly higher `list_version` omitting the leaf).
fn has_newer_revocation_evidence(
    target: &MpMlsLeafCredV1,
    evidence: &[(&crate::crypto::Ed25519PubKey, &AccountDeviceListV1)],
) -> bool {
    let tb = &target.binding.body;
    evidence.iter().any(|(root_pk, list)| {
        list.account_id == tb.account_id
            && *root_pk == &tb.root_pubkey
            && list.root_gen == tb.root_gen
            && list.list_version > target.list_version
            && !list.authorizes_leaf(tb)
    })
}

/// Validates a `GroupContextExtensions` proposal against the current `GroupContext` (Spec v3.1 §4.1).
fn validate_gce_extensions(
    prev_ctx: &GroupContext,
    next_exts: &Extensions<GroupContext>,
    prev_policy: &MpRoomPolicyExtV1,
    is_host: bool,
    has_remove: bool,
) -> Result<MpRoomPolicyExtV1, MpMlsError> {
    if prev_ctx.extensions().external_senders() != next_exts.external_senders() {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "ExternalSenders extension is immutable",
        ));
    }
    if prev_ctx.extensions().required_capabilities() != next_exts.required_capabilities() {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "RequiredCapabilities extension is immutable",
        ));
    }
    let next_policy = MpRoomPolicyExtV1::from_extensions(next_exts)?;
    MpRoomPolicyExtV1::validate_transition(prev_policy, &next_policy, is_host, has_remove)?;
    Ok(next_policy)
}

fn validate_proposal_inner(
    sender: &Sender,
    proposal: &Proposal,
    current_ctx: &GroupContext,
    current_leaves: &BTreeMap<u32, TreeLeafInfo>,
    extra_evidence: &[(&Ed25519PubKey, &AccountDeviceListV1)],
    commit_has_remove: Option<bool>,
) -> Result<(), MpMlsError> {
    let policy = MpRoomPolicyExtV1::from_group_context(current_ctx)?;

    match sender {
        Sender::NewMemberProposal => {
            return Err(MpMlsError::ForbiddenProposal(
                "Sender::NewMemberProposal is unconditionally rejected",
            ));
        }
        Sender::NewMemberCommit => {
            return Err(MpMlsError::ForbiddenProposal(
                "Sender::NewMemberCommit is unconditionally rejected",
            ));
        }
        Sender::External(ext_idx) => {
            if *ext_idx != openmls::prelude::SenderExtensionIndex::new(0) {
                return Err(MpMlsError::ForbiddenProposal(
                    "only ExternalSender index 0 (PartyDO DS) is authorized",
                ));
            }
            match proposal {
                Proposal::Remove(rem) => {
                    if !current_leaves.contains_key(&rem.removed().u32()) {
                        return Err(MpMlsError::ForbiddenProposal(
                            "External Remove targets non-existent leaf",
                        ));
                    }
                    return Ok(());
                }
                _ => {
                    return Err(MpMlsError::ForbiddenProposal(
                        "Sender::External may ONLY issue ProposalType::Remove",
                    ));
                }
            }
        }
        Sender::Member(_) => {}
    }

    let Sender::Member(sender_leaf_idx) = sender else {
        unreachable!();
    };
    let sender_info = current_leaves
        .get(&sender_leaf_idx.u32())
        .ok_or(MpMlsError::ForbiddenProposal("proposal sender not in tree"))?;

    match proposal {
        Proposal::Add(add) => {
            if add.key_package().last_resort() {
                return Err(MpMlsError::ForbiddenProposal(
                    "Add KeyPackage must not carry LastResort extension",
                ));
            }
            let (cred, _device_list) = validate_leaf_node_credential(add.key_package().leaf_node())?;
            policy.check_leaf_allowed(&cred)?;
            policy.check_not_banned(cred.binding.body.account_id)?;
            Ok(())
        }
        Proposal::Update(upd) => {
            let (next_cred, _device_list) = validate_leaf_node_credential(upd.leaf_node())?;
            validate_leaf_identity_continuity(&sender_info.cred, &next_cred)?;
            policy.check_leaf_allowed(&next_cred)?;
            Ok(())
        }
        Proposal::Remove(rem) => {
            let target = current_leaves
                .get(&rem.removed().u32())
                .ok_or(MpMlsError::ForbiddenProposal(
                    "Remove proposal targets non-existent leaf",
                ))?;
            let sender_acct = sender_info.cred.binding.body.account_id;
            let target_acct = target.cred.binding.body.account_id;

            // Host removing non-host is always deterministically permitted.
            if policy.is_host(sender_acct) && !policy.is_host(target_acct) {
                return Ok(());
            }

            // Otherwise (including same-account sibling revocation), Spec v3.1 §4.1 requires
            // a newer verified `AccountDeviceListV1` carried in the group/commit proving the
            // target leaf is absent from that account's authorized devices!
            let mut all_evidence: Vec<(&Ed25519PubKey, &AccountDeviceListV1)> = current_leaves
                .values()
                .map(|l| (&l.cred.binding.body.root_pubkey, &l.device_list))
                .collect();
            all_evidence.extend_from_slice(extra_evidence);
            if has_newer_revocation_evidence(&target.cred, &all_evidence) {
                Ok(())
            } else {
                Err(MpMlsError::ForbiddenProposal(
                    "inline member Remove requires host (for non-host) or newer verified AccountDeviceListV1 excluding target leaf",
                ))
            }
        }
        Proposal::GroupContextExtensions(gce) => {
            let is_host = policy.is_host(sender_info.cred.binding.body.account_id);
            match commit_has_remove {
                Some(has_remove) => {
                    let _ = validate_gce_extensions(
                        current_ctx,
                        gce.extensions(),
                        &policy,
                        is_host,
                        has_remove,
                    )?;
                    Ok(())
                }
                None => {
                    // Standalone proposal check before Commit: accept either a non-Remove GCE
                    // (host-only) OR a Remove-paired `invite_epoch + 1` GCE (host or non-host).
                    let ok_no_rem =
                        validate_gce_extensions(current_ctx, gce.extensions(), &policy, is_host, false)
                            .is_ok();
                    let ok_with_rem =
                        validate_gce_extensions(current_ctx, gce.extensions(), &policy, is_host, true)
                            .is_ok();
                    if ok_no_rem || ok_with_rem {
                        Ok(())
                    } else {
                        Err(MpMlsError::ExtensionPolicyViolation(
                            "GroupContextExtensions proposal violates room policy transition rules",
                        ))
                    }
                }
            }
        }
        Proposal::PreSharedKey(_) => Err(MpMlsError::ForbiddenProposal(
            "PreSharedKey proposals are forbidden in Spec v3.1 (use WelcomeAuthV1)",
        )),
        Proposal::ReInit(_) => Err(MpMlsError::ForbiddenProposal(
            "ProposalType::ReInit is unconditionally rejected",
        )),
        Proposal::ExternalInit(_) => Err(MpMlsError::ForbiddenProposal(
            "ProposalType::ExternalInit is unconditionally rejected",
        )),
        Proposal::SelfRemove => Err(MpMlsError::ForbiddenProposal(
            "ProposalType::SelfRemove is rejected",
        )),
        Proposal::Custom(_) => Err(MpMlsError::ForbiddenProposal(
            "Custom proposals are rejected",
        )),
    }
}

/// Pure, deterministic, wall-clock-free, cache-free proposal validator (Spec v3.1 §3.3 / §4.1).
pub fn validate_proposal_deterministic(
    sender: &Sender,
    proposal: &Proposal,
    current_ctx: &GroupContext,
    current_leaves: &BTreeMap<u32, TreeLeafInfo>,
) -> Result<(), MpMlsError> {
    validate_proposal_inner(sender, proposal, current_ctx, current_leaves, &[], None)
}

/// Pure, 100% deterministic, wall-clock-free, cache-free Commit validation (Spec v3.1 §3.3 / §4.1).
/// Depends ONLY on `(sender, staged_commit, prev_ctx, prev_leaves)` so DS, committer, and all
/// recipients reach identical accept/reject consensus with zero risk of consensus forks.
///
/// Returns `(resulting_policy, resulting_leaves_map)`.
pub fn validate_commit_deterministic(
    sender: &Sender,
    staged: &StagedCommit,
    prev_ctx: &GroupContext,
    prev_leaves: &BTreeMap<u32, TreeLeafInfo>,
) -> Result<(MpRoomPolicyExtV1, BTreeMap<u32, TreeLeafInfo>), MpMlsError> {
    let Sender::Member(committer_leaf_idx) = sender else {
        return Err(MpMlsError::ForbiddenProposal(
            "Commit sender MUST be Sender::Member (External / NewMemberCommit rejected)",
        ));
    };
    let committer_prev = prev_leaves
        .get(&committer_leaf_idx.u32())
        .ok_or(MpMlsError::ForbiddenProposal("committer not in prior tree"))?;

    // Mandatory UpdatePath on EVERY Commit (§4.1).
    let path_leaf = staged
        .update_path_leaf_node()
        .ok_or(MpMlsError::MissingUpdatePath)?;
    let (path_cred, path_device_list) = validate_leaf_node_credential(path_leaf)?;
    validate_leaf_identity_continuity(&committer_prev.cred, &path_cred)?;

    let prev_policy = MpRoomPolicyExtV1::from_group_context(prev_ctx)?;
    let is_host = prev_policy.is_host(committer_prev.cred.binding.body.account_id);
    let has_remove = staged.remove_proposals().next().is_some();

    // Collect verified `0xFF02` device lists from path_leaf and Update proposals in this Commit
    // so a sibling device can atomically refresh its own list and remove a revoked sibling leaf.
    let mut update_lists: Vec<(Ed25519PubKey, AccountDeviceListV1)> = Vec::new();
    update_lists.push((path_cred.binding.body.root_pubkey, path_device_list.clone()));
    for upd in staged.update_proposals() {
        let (u_cred, u_list) = validate_leaf_node_credential(upd.update_proposal().leaf_node())?;
        update_lists.push((u_cred.binding.body.root_pubkey, u_list));
    }
    let extra_evidence: Vec<(&Ed25519PubKey, &AccountDeviceListV1)> = update_lists
        .iter()
        .map(|(pk, list)| (pk, list))
        .collect();

    let mut next_policy = prev_policy.clone();
    let mut gce_count: usize = 0;

    // Validate every proposal in the staged Commit deterministically.
    for qp in staged.queued_proposals() {
        validate_proposal_inner(
            qp.sender(),
            qp.proposal(),
            prev_ctx,
            prev_leaves,
            &extra_evidence,
            Some(has_remove),
        )?;
        if let Proposal::GroupContextExtensions(gce) = qp.proposal() {
            gce_count += 1;
            if gce_count > 1 {
                return Err(MpMlsError::ExtensionPolicyViolation(
                    "multiple GroupContextExtensions proposals in a single Commit are forbidden",
                ));
            }
            let prop_is_host = match qp.sender() {
                Sender::Member(idx) => prev_leaves
                    .get(&idx.u32())
                    .is_some_and(|l| prev_policy.is_host(l.cred.binding.body.account_id)),
                _ => false,
            };
            next_policy = validate_gce_extensions(
                prev_ctx,
                gce.extensions(),
                &prev_policy,
                prop_is_host,
                has_remove,
            )?;
        }
    }

    // Spec v3.1 §4.1: EVERY Remove Commit MUST increment `invite_epoch = prev.invite_epoch + 1`!
    if has_remove {
        if gce_count == 0 {
            return Err(MpMlsError::ExtensionPolicyViolation(
                "Remove Commit must include GroupContextExtensions incrementing invite_epoch",
            ));
        }
        MpRoomPolicyExtV1::validate_transition(&prev_policy, &next_policy, is_host, true)?;
    }

    // Verify the resulting GroupContext itself matches our expected policy and immutable extensions.
    let staged_ctx = staged.group_context();
    if staged_ctx.group_id() != prev_ctx.group_id()
        || staged_ctx.ciphersuite() != MP_CIPHERSUITE
        || staged_ctx.protocol_version() != ProtocolVersion::Mls10
    {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "GroupContext identity/ciphersuite/version mutated",
        ));
    }
    if staged_ctx.extensions().external_senders() != prev_ctx.extensions().external_senders() {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "ExternalSenders extension is immutable",
        ));
    }
    if staged_ctx.extensions().required_capabilities()
        != prev_ctx.extensions().required_capabilities()
    {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "RequiredCapabilities extension is immutable",
        ));
    }
    let staged_policy = MpRoomPolicyExtV1::from_group_context(staged_ctx)?;
    if staged_policy != next_policy {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "staged GroupContext policy disagrees with validated proposals",
        ));
    }

    // Simulate resulting leaf map to verify Remove+Update exclusion, tree uniqueness, capacity,
    // and post-transition policy (including banned_account_ids exclusion across ALL occupied leaves).
    let mut next_leaves = prev_leaves.clone();
    let mut removed_indices: HashSet<u32> = HashSet::new();

    // 1. Apply Removes first (per RFC 9420 §12.4.2).
    for rem in staged.remove_proposals() {
        let idx = rem.remove_proposal().removed().u32();
        if idx == committer_leaf_idx.u32() {
            return Err(MpMlsError::ForbiddenProposal(
                "committer cannot remove self",
            ));
        }
        removed_indices.insert(idx);
        next_leaves.remove(&idx);
    }

    // 2. Apply Updates — explicitly forbid Remove + Update targeting the same leaf (Fable Low)!
    for upd in staged.update_proposals() {
        let Sender::Member(idx) = upd.sender() else {
            return Err(MpMlsError::ForbiddenProposal(
                "Update proposal from non-member",
            ));
        };
        if removed_indices.contains(&idx.u32()) {
            return Err(MpMlsError::ForbiddenProposal(
                "cannot both Remove and Update the same leaf in one Commit",
            ));
        }
        let leaf = upd.update_proposal().leaf_node();
        let (cred, device_list) = validate_leaf_node_credential(leaf)?;
        next_leaves.insert(
            idx.u32(),
            TreeLeafInfo {
                cred,
                device_list,
                signature_key: leaf.signature_key().as_slice().to_vec(),
                encryption_key: leaf_encryption_key_bytes(leaf)?,
            },
        );
    }

    // 3. Apply Adds (filling leftmost free leaf index or appending).
    for add in staged.add_proposals() {
        let leaf = add.add_proposal().key_package().leaf_node();
        let (cred, device_list) = validate_leaf_node_credential(leaf)?;
        next_policy.check_not_banned(cred.binding.body.account_id)?;
        let mut free_idx = 0u32;
        while next_leaves.contains_key(&free_idx) {
            free_idx += 1;
        }
        next_leaves.insert(
            free_idx,
            TreeLeafInfo {
                cred,
                device_list,
                signature_key: leaf.signature_key().as_slice().to_vec(),
                encryption_key: leaf_encryption_key_bytes(leaf)?,
            },
        );
    }

    // 4. Apply committer's UpdatePath leaf replacement.
    next_leaves.insert(
        committer_leaf_idx.u32(),
        TreeLeafInfo {
            cred: path_cred,
            device_list: path_device_list,
            signature_key: path_leaf.signature_key().as_slice().to_vec(),
            encryption_key: leaf_encryption_key_bytes(path_leaf)?,
        },
    );

    let leaves_vec: Vec<TreeLeafInfo> = next_leaves.values().cloned().collect();
    validate_tree_invariants(&leaves_vec, &next_policy)?;

    Ok((next_policy, next_leaves))
}

/// Validates a decrypted `StagedWelcome`'s `GroupContext`, DS `ExternalSender`, `RequiredCapabilities`
/// (`0xFF01` + `0xFF02`), `MpRoomPolicyExtV1` (`policy_bits` + `invite_epoch >= pinned_invite_epoch`),
/// and `welcome_sender` leaf (`0xFF02` included).
///
/// Returns `(policy, inviter_unconfirmed)` where `inviter_unconfirmed == true` iff the Welcome
/// was signed by a delegated room member rather than a leaf chaining to `expected_inviter_root_pk`
/// (Spec v3.1 §4.2.4: install in send-blocked Tier 0 until inviter confirms).
#[allow(clippy::too_many_arguments)]
pub fn validate_staged_welcome(
    staged: &StagedWelcome,
    expected_group_id: &[u8; MP_GROUP_ID_LEN],
    expected_party_id: u64,
    expected_ds_pubkey: &Ed25519PubKey,
    required_policy_bits: u8,
    pinned_invite_epoch: u64,
    expected_inviter_root_pk: &Ed25519PubKey,
) -> Result<(MpRoomPolicyExtV1, bool), MpMlsError> {
    check_safe_counter(pinned_invite_epoch)?;
    let ctx = staged.group_context();
    if ctx.group_id().as_slice() != expected_group_id {
        return Err(MpMlsError::InvalidGroupId);
    }
    let parsed_gid = MpGroupId::parse(ctx.group_id().as_slice())?;
    if parsed_gid.party_id != expected_party_id {
        return Err(MpMlsError::InvalidGroupId);
    }
    if ctx.ciphersuite() != MP_CIPHERSUITE || ctx.protocol_version() != ProtocolVersion::Mls10 {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "Welcome ciphersuite or protocol version mismatch",
        ));
    }

    // Verify exact ExternalSendersExtension (single entry = PartyDO DS).
    let expected_ds_sender = build_ds_external_sender(expected_party_id, expected_ds_pubkey)?;
    let ext_senders = ctx
        .extensions()
        .external_senders()
        .ok_or(MpMlsError::ExtensionPolicyViolation(
            "missing ExternalSendersExtension in Welcome",
        ))?;
    if ext_senders.len() != 1 || ext_senders[0] != expected_ds_sender {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "ExternalSendersExtension does not match pinned room DS pubkey",
        ));
    }

    // Verify RequiredCapabilitiesExtension includes BOTH 0xFF01 and 0xFF02.
    let req_caps = ctx.extensions().required_capabilities().ok_or(
        MpMlsError::ExtensionPolicyViolation("missing RequiredCapabilitiesExtension in Welcome"),
    )?;
    if !req_caps
        .extension_types()
        .contains(&ExtensionType::Unknown(MP_ROOM_POLICY_EXT_TYPE))
    {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "RequiredCapabilitiesExtension missing 0xFF01",
        ));
    }
    if !req_caps
        .extension_types()
        .contains(&ExtensionType::Unknown(MP_LEAF_DEVICE_LIST_EXT_TYPE))
    {
        return Err(MpMlsError::ExtensionPolicyViolation(
            "RequiredCapabilitiesExtension missing 0xFF02",
        ));
    }

    // Verify MpRoomPolicyExtV1 matches party_id, pinned policy_bits, and invite_epoch floor.
    let policy = MpRoomPolicyExtV1::from_group_context(ctx)?;
    if policy.party_id != expected_party_id {
        return Err(MpMlsError::InvalidRoomPolicy(
            "policy party_id does not match group_id",
        ));
    }
    if !policy.satisfies_policy_bits(required_policy_bits)? {
        return Err(MpMlsError::RoomPolicyViolation(
            "Welcome room policy violates pinned invite policy_bits",
        ));
    }
    if policy.invite_epoch < pinned_invite_epoch {
        return Err(MpMlsError::RoomPolicyViolation(
            "Welcome invite_epoch is below pinned invite_epoch floor",
        ));
    }

    // Validate Welcome GroupInfo signer leaf (including 0xFF02).
    // If signer root != pinned inviter_root_pk, flag `inviter_unconfirmed = true` (Tier 0 send-blocked).
    let signer_leaf = staged
        .welcome_sender()
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
    let (signer_cred, _signer_list) = validate_leaf_node_credential(signer_leaf)?;
    let inviter_unconfirmed = &signer_cred.binding.body.root_pubkey != expected_inviter_root_pk;

    Ok((policy, inviter_unconfirmed))
}

/// Validates EVERY leaf (including `0xFF02` `AccountDeviceListV1`) and all tree invariants on
/// a Welcome-installed `PublicGroup` BEFORE committing the isolated storage snapshot.
pub fn validate_welcome_public_group_leaves(
    pg: &PublicGroup,
    policy: &MpRoomPolicyExtV1,
) -> Result<BTreeMap<u32, TreeLeafInfo>, MpMlsError> {
    let leaves_map = extract_public_group_leaves(pg)?;
    let leaves_vec: Vec<TreeLeafInfo> = leaves_map.values().cloned().collect();
    validate_tree_invariants(&leaves_vec, policy)?;
    Ok(leaves_map)
}

/// Output of client-local policy evaluation (separated from deterministic Commit consensus,
/// Spec v3.1 §3.3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalPolicyReport {
    /// Leaf indices whose `(device_id, device_gen, mls_sig_pubkey)` are absent from a newer-or-equal
    /// verified `AccountDeviceListV1` -> client MUST block outbound sends until removed.
    pub pending_removal_leaves: Vec<u32>,
    /// Leaf indices whose `(account_id, root_pubkey, root_gen, custody_mode)` violated local
    /// `AccountRootPinStore` (e.g., custody mode flip under same root or unexpected root rotation).
    pub pin_violations: Vec<(u32, u64)>,
    /// Leaf indices whose `MpMlsDeviceBindingV1` is outside `[iat_s, exp_s)` at `now_s`.
    pub expired_binding_leaves: Vec<u32>,
    /// Leaf indices whose `0xFF02` `AccountDeviceListV1` is outside `[iat_s, exp_s)` at `now_s`.
    pub expired_list_leaves: Vec<u32>,
    /// Leaf indices whose `(root_gen, list_version)` conflicts in `list_hash` with a tracked list.
    pub equivocation_leaves: Vec<u32>,
}

impl LocalPolicyReport {
    /// Returns `true` iff ANY local trust/expiry/revocation/equivocation violation requires
    /// blocking outbound application sends (Spec v3.1 §3.3.4).
    pub fn should_block_send(&self) -> bool {
        !self.pending_removal_leaves.is_empty()
            || !self.pin_violations.is_empty()
            || !self.expired_binding_leaves.is_empty()
            || !self.expired_list_leaves.is_empty()
            || !self.equivocation_leaves.is_empty()
    }
}

/// Evaluates local pin, device-list revocation/equivocation, and wall-clock binding/list expiry
/// state against the authenticated tree WITHOUT causing consensus forks on historical Commits.
pub fn evaluate_local_policy(
    leaves: &BTreeMap<u32, TreeLeafInfo>,
    pins: &AccountRootPinStore,
    device_lists: &DeviceListTracker,
    now_s: Option<u64>,
) -> LocalPolicyReport {
    let mut report = LocalPolicyReport::default();
    for (&leaf_idx, info) in leaves {
        let body = &info.cred.binding.body;
        if pins
            .check(
                body.account_id,
                &body.root_pubkey,
                body.root_gen,
                body.custody_mode,
            )
            .is_err()
        {
            report.pin_violations.push((leaf_idx, body.account_id));
        }
        if device_lists.check_leaf_equivocation(&info.cred) {
            report.equivocation_leaves.push(leaf_idx);
        }
        if device_lists.is_leaf_revoked(&info.cred) {
            report.pending_removal_leaves.push(leaf_idx);
        }
        if let Some(now) = now_s {
            if now < body.iat_s || now >= body.exp_s {
                report.expired_binding_leaves.push(leaf_idx);
            }
            if now < info.device_list.iat_s || now >= info.device_list.exp_s {
                report.expired_list_leaves.push(leaf_idx);
            }
        }
    }
    report
}
