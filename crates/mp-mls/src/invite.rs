//! Split-secret invite derivation (HKDF-SHA256), `invite_epoch`-bound `InviteFragmentV2` (114 B),
//! `InviteRecordV1` (93 B), HMAC-SHA256 `join_proof`, and fixed-length 177-byte `WelcomeAuthV1` MAC
//! with secret-redacting `Debug` and constant-time equality (Spec v3.1 §4.2).

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{
    ct_eq_bytes, sha256, validate_ed25519_pubkey_strict, Ed25519PubKey, Sha256Digest,
};
use crate::error::MpMlsError;
use crate::identity::{check_safe_counter, check_safe_id};
use crate::policy::MP_GROUP_ID_LEN;

pub const INVITE_SERVER_INFO: &[u8] = b"mp-mls-invite-server-v1";
pub const INVITE_MAC_INFO: &[u8] = b"mp-mls-invite-mac-v1";
pub const JOIN_PROOF_DOMAIN: &[u8] = b"mp-mls-join-v2:";
pub const WELCOME_AUTH_DOMAIN: &[u8] = b"mp-mls-welcome-auth-v1:";

/// Exact length of `InviteFragmentV2` (Spec v3.1 §4.2):
/// `v=2(1) || group_id(24) || invite_id(8) || invite_epoch(8) || expires_at_s(8) || policy_bits(1) || inviter_root_pk(32) || invite_seed(32) = 114`.
pub const INVITE_FRAGMENT_V2_LEN: usize = 1 + MP_GROUP_ID_LEN + 8 + 8 + 8 + 1 + 32 + 32;

/// Exact length of `InviteRecordV1` (Spec v3.1 §4.2):
/// `version(1) || invite_id(8) || invite_epoch(8) || max_uses(4) || expires_at_s(8) || inviter_root_pk(32) || member_join_mac_key(32) = 93`.
pub const INVITE_RECORD_V1_LEN: usize = 1 + 8 + 8 + 4 + 8 + 32 + 32;

/// Exact length of `WelcomeAuthV1` (Spec v3.1 §4.2):
/// `version(1) || group_id(24) || target_epoch(8) || invite_id(8) || invite_epoch(8) || joiner_kp_ref(32) || tree_hash(32) || confirmation_tag(32) || welcome_mac(32) = 177`.
pub const WELCOME_AUTH_V1_LEN: usize = 1 + MP_GROUP_ID_LEN + 8 + 8 + 8 + 32 + 32 + 32 + 32;

/// Policy bit flags carried in `InviteFragmentV2.policy_bits`.
pub const POLICY_BIT_REQUIRE_SELF_CUSTODY: u8 = 0x01;
pub const POLICY_BIT_DISALLOW_BROWSER_DEVICES: u8 = 0x02;
pub const VALID_POLICY_BITS_MASK: u8 =
    POLICY_BIT_REQUIRE_SELF_CUSTODY | POLICY_BIT_DISALLOW_BROWSER_DEVICES;

type HmacSha256 = Hmac<Sha256>;

/// Validates that no unknown/reserved `policy_bits` are set.
pub fn validate_policy_bits(bits: u8) -> Result<(), MpMlsError> {
    if (bits & !VALID_POLICY_BITS_MASK) != 0 {
        return Err(MpMlsError::InvalidPolicyBits(bits));
    }
    Ok(())
}

/// Client-derived split secrets for an E2EE room invite.
/// Raw `invite_seed` and `member_join_mac_key` MUST NEVER be sent to `PartyDO`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InviteSecrets {
    pub server_invite_token: [u8; 32],
    pub server_token_hash: Sha256Digest,
    pub member_join_mac_key: [u8; 32],
}

impl fmt::Debug for InviteSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteSecrets")
            .field("server_invite_token", &"[REDACTED]")
            .field("server_token_hash", &self.server_token_hash)
            .field("member_join_mac_key", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for InviteSecrets {
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(&self.server_invite_token, &other.server_invite_token)
            & ct_eq_bytes(&self.server_token_hash, &other.server_token_hash)
            & ct_eq_bytes(&self.member_join_mac_key, &other.member_join_mac_key)
    }
}

impl Eq for InviteSecrets {}

impl InviteSecrets {
    /// Derives split secrets via HKDF-Extract(salt = group_id, ikm = invite_seed) + HKDF-Expand.
    pub fn derive(
        group_id: &[u8; MP_GROUP_ID_LEN],
        invite_seed: &[u8; 32],
    ) -> Result<Self, MpMlsError> {
        let hk = Hkdf::<Sha256>::new(Some(group_id.as_slice()), invite_seed.as_slice());

        let mut server_invite_token = [0u8; 32];
        hk.expand(INVITE_SERVER_INFO, &mut server_invite_token)
            .map_err(|_| MpMlsError::HkdfError)?;

        let mut member_join_mac_key = [0u8; 32];
        hk.expand(INVITE_MAC_INFO, &mut member_join_mac_key)
            .map_err(|_| MpMlsError::HkdfError)?;

        let server_token_hash = sha256(&server_invite_token);

        Ok(Self {
            server_invite_token,
            server_token_hash,
            member_join_mac_key,
        })
    }
}

/// Computes `join_proof = HMAC-SHA256(member_join_mac_key, "mp-mls-join-v2:" || group_id || invite_id_be64 || invite_epoch_be64 || expires_at_s_be64 || account_id_be64 || device_id_be64 || kp_ref)`.
#[allow(clippy::too_many_arguments)]
pub fn compute_join_proof(
    member_join_mac_key: &[u8; 32],
    group_id: &[u8; MP_GROUP_ID_LEN],
    invite_id: u64,
    invite_epoch: u64,
    expires_at_s: u64,
    account_id: u64,
    device_id: u64,
    kp_ref: &[u8],
) -> Result<[u8; 32], MpMlsError> {
    check_safe_id(invite_id)?;
    check_safe_counter(invite_epoch)?;
    check_safe_counter(expires_at_s)?;
    check_safe_id(account_id)?;
    check_safe_id(device_id)?;
    let mut mac =
        HmacSha256::new_from_slice(member_join_mac_key).map_err(|_| MpMlsError::InvalidMac)?;
    mac.update(JOIN_PROOF_DOMAIN);
    mac.update(group_id);
    mac.update(&invite_id.to_be_bytes());
    mac.update(&invite_epoch.to_be_bytes());
    mac.update(&expires_at_s.to_be_bytes());
    mac.update(&account_id.to_be_bytes());
    mac.update(&device_id.to_be_bytes());
    mac.update(kp_ref);
    let result: [u8; 32] = mac.finalize().into_bytes().into();
    Ok(result)
}

/// Constant-time verification of `join_proof`.
#[allow(clippy::too_many_arguments)]
pub fn verify_join_proof(
    member_join_mac_key: &[u8; 32],
    group_id: &[u8; MP_GROUP_ID_LEN],
    invite_id: u64,
    invite_epoch: u64,
    expires_at_s: u64,
    account_id: u64,
    device_id: u64,
    kp_ref: &[u8],
    join_proof: &[u8; 32],
) -> Result<(), MpMlsError> {
    check_safe_id(invite_id)?;
    check_safe_counter(invite_epoch)?;
    check_safe_counter(expires_at_s)?;
    check_safe_id(account_id)?;
    check_safe_id(device_id)?;
    let mut mac =
        HmacSha256::new_from_slice(member_join_mac_key).map_err(|_| MpMlsError::InvalidMac)?;
    mac.update(JOIN_PROOF_DOMAIN);
    mac.update(group_id);
    mac.update(&invite_id.to_be_bytes());
    mac.update(&invite_epoch.to_be_bytes());
    mac.update(&expires_at_s.to_be_bytes());
    mac.update(&account_id.to_be_bytes());
    mac.update(&device_id.to_be_bytes());
    mac.update(kp_ref);
    mac.verify_slice(join_proof)
        .map_err(|_| MpMlsError::InvalidMac)
}

/// Fixed 177-byte invite-keyed Welcome authentication tag (`WelcomeAuthV1`, Spec v3.1 §4.2):
/// binds `(group_id[24], target_epoch[8], invite_id[8], invite_epoch[8], joiner_kp_ref[32], tree_hash[32], confirmation_tag[32])`
/// to `member_join_mac_key`, defeating a lone malicious DS forging a fake-group Welcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WelcomeAuthV1 {
    pub group_id: [u8; MP_GROUP_ID_LEN],
    pub target_epoch: u64,
    pub invite_id: u64,
    pub invite_epoch: u64,
    pub joiner_kp_ref: [u8; 32],
    pub tree_hash: [u8; 32],
    pub confirmation_tag: [u8; 32],
    pub welcome_mac: [u8; 32],
}

impl WelcomeAuthV1 {
    #[allow(clippy::too_many_arguments)]
    fn compute_mac(
        member_join_mac_key: &[u8; 32],
        group_id: &[u8; MP_GROUP_ID_LEN],
        target_epoch: u64,
        invite_id: u64,
        invite_epoch: u64,
        joiner_kp_ref: &[u8; 32],
        tree_hash: &[u8; 32],
        confirmation_tag: &[u8; 32],
    ) -> Result<[u8; 32], MpMlsError> {
        check_safe_counter(target_epoch)?;
        check_safe_id(invite_id)?;
        check_safe_counter(invite_epoch)?;
        let mut mac =
            HmacSha256::new_from_slice(member_join_mac_key).map_err(|_| MpMlsError::InvalidMac)?;
        mac.update(WELCOME_AUTH_DOMAIN);
        mac.update(group_id);
        mac.update(&target_epoch.to_be_bytes());
        mac.update(&invite_id.to_be_bytes());
        mac.update(&invite_epoch.to_be_bytes());
        mac.update(joiner_kp_ref);
        mac.update(tree_hash);
        mac.update(confirmation_tag);
        Ok(mac.finalize().into_bytes().into())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        member_join_mac_key: &[u8; 32],
        group_id: [u8; MP_GROUP_ID_LEN],
        target_epoch: u64,
        invite_id: u64,
        invite_epoch: u64,
        joiner_kp_ref: [u8; 32],
        tree_hash: [u8; 32],
        confirmation_tag: [u8; 32],
    ) -> Result<Self, MpMlsError> {
        let welcome_mac = Self::compute_mac(
            member_join_mac_key,
            &group_id,
            target_epoch,
            invite_id,
            invite_epoch,
            &joiner_kp_ref,
            &tree_hash,
            &confirmation_tag,
        )?;
        Ok(Self {
            group_id,
            target_epoch,
            invite_id,
            invite_epoch,
            joiner_kp_ref,
            tree_hash,
            confirmation_tag,
            welcome_mac,
        })
    }

    pub fn verify(&self, member_join_mac_key: &[u8; 32]) -> Result<(), MpMlsError> {
        check_safe_counter(self.target_epoch)?;
        check_safe_id(self.invite_id)?;
        check_safe_counter(self.invite_epoch)?;
        let mut mac =
            HmacSha256::new_from_slice(member_join_mac_key).map_err(|_| MpMlsError::InvalidMac)?;
        mac.update(WELCOME_AUTH_DOMAIN);
        mac.update(&self.group_id);
        mac.update(&self.target_epoch.to_be_bytes());
        mac.update(&self.invite_id.to_be_bytes());
        mac.update(&self.invite_epoch.to_be_bytes());
        mac.update(&self.joiner_kp_ref);
        mac.update(&self.tree_hash);
        mac.update(&self.confirmation_tag);
        mac.verify_slice(&self.welcome_mac)
            .map_err(|_| MpMlsError::InvalidMac)
    }

    pub fn encode(&self) -> Result<[u8; WELCOME_AUTH_V1_LEN], MpMlsError> {
        check_safe_counter(self.target_epoch)?;
        check_safe_id(self.invite_id)?;
        check_safe_counter(self.invite_epoch)?;
        let mut out = [0u8; WELCOME_AUTH_V1_LEN];
        out[0] = 1;
        out[1..25].copy_from_slice(&self.group_id);
        out[25..33].copy_from_slice(&self.target_epoch.to_be_bytes());
        out[33..41].copy_from_slice(&self.invite_id.to_be_bytes());
        out[41..49].copy_from_slice(&self.invite_epoch.to_be_bytes());
        out[49..81].copy_from_slice(&self.joiner_kp_ref);
        out[81..113].copy_from_slice(&self.tree_hash);
        out[113..145].copy_from_slice(&self.confirmation_tag);
        out[145..177].copy_from_slice(&self.welcome_mac);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != WELCOME_AUTH_V1_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: WELCOME_AUTH_V1_LEN,
                got: bytes.len(),
            });
        }
        if bytes[0] != 1 {
            return Err(MpMlsError::UnsupportedVersion(bytes[0]));
        }
        let group_id: [u8; MP_GROUP_ID_LEN] = bytes[1..25]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let target_epoch = u64::from_be_bytes(
            bytes[25..33]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let invite_id = u64::from_be_bytes(
            bytes[33..41]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let invite_epoch = u64::from_be_bytes(
            bytes[41..49]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        check_safe_counter(target_epoch)?;
        check_safe_id(invite_id)?;
        check_safe_counter(invite_epoch)?;
        let joiner_kp_ref: [u8; 32] = bytes[49..81]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let tree_hash: [u8; 32] = bytes[81..113]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let confirmation_tag: [u8; 32] = bytes[113..145]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let welcome_mac: [u8; 32] = bytes[145..177]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        Ok(Self {
            group_id,
            target_epoch,
            invite_id,
            invite_epoch,
            joiner_kp_ref,
            tree_hash,
            confirmation_tag,
            welcome_mac,
        })
    }
}

/// Canonical 114-byte `v=2` invite URL fragment payload (Spec v3.1 §4.2):
/// `v=2(1) || group_id(24) || invite_id_be64(8) || invite_epoch_be64(8) || expires_at_s_be64(8) || policy_bits(1) || inviter_root_pk(32) || invite_seed(32)`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InviteFragmentV2 {
    pub group_id: [u8; MP_GROUP_ID_LEN],
    pub invite_id: u64,
    pub invite_epoch: u64,
    pub expires_at_s: u64,
    pub policy_bits: u8,
    pub inviter_root_pk: Ed25519PubKey,
    pub invite_seed: [u8; 32],
}

impl fmt::Debug for InviteFragmentV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteFragmentV2")
            .field("group_id", &self.group_id)
            .field("invite_id", &self.invite_id)
            .field("invite_epoch", &self.invite_epoch)
            .field("expires_at_s", &self.expires_at_s)
            .field("policy_bits", &self.policy_bits)
            .field("inviter_root_pk", &self.inviter_root_pk)
            .field("invite_seed", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for InviteFragmentV2 {
    fn eq(&self, other: &Self) -> bool {
        (self.group_id == other.group_id)
            & (self.invite_id == other.invite_id)
            & (self.invite_epoch == other.invite_epoch)
            & (self.expires_at_s == other.expires_at_s)
            & (self.policy_bits == other.policy_bits)
            & (self.inviter_root_pk == other.inviter_root_pk)
            & ct_eq_bytes(&self.invite_seed, &other.invite_seed)
    }
}

impl Eq for InviteFragmentV2 {}

impl InviteFragmentV2 {
    pub fn encode(&self) -> Result<[u8; INVITE_FRAGMENT_V2_LEN], MpMlsError> {
        check_safe_id(self.invite_id)?;
        check_safe_counter(self.invite_epoch)?;
        check_safe_counter(self.expires_at_s)?;
        validate_policy_bits(self.policy_bits)?;
        validate_ed25519_pubkey_strict(&self.inviter_root_pk)?;
        let mut out = [0u8; INVITE_FRAGMENT_V2_LEN];
        out[0] = 2;
        out[1..25].copy_from_slice(&self.group_id);
        out[25..33].copy_from_slice(&self.invite_id.to_be_bytes());
        out[33..41].copy_from_slice(&self.invite_epoch.to_be_bytes());
        out[41..49].copy_from_slice(&self.expires_at_s.to_be_bytes());
        out[49] = self.policy_bits;
        out[50..82].copy_from_slice(&self.inviter_root_pk);
        out[82..114].copy_from_slice(&self.invite_seed);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != INVITE_FRAGMENT_V2_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: INVITE_FRAGMENT_V2_LEN,
                got: bytes.len(),
            });
        }
        if bytes[0] != 2 {
            return Err(MpMlsError::UnsupportedVersion(bytes[0]));
        }
        let group_id: [u8; MP_GROUP_ID_LEN] = bytes[1..25]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let invite_id = u64::from_be_bytes(
            bytes[25..33]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let invite_epoch = u64::from_be_bytes(
            bytes[33..41]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let expires_at_s = u64::from_be_bytes(
            bytes[41..49]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        check_safe_id(invite_id)?;
        check_safe_counter(invite_epoch)?;
        check_safe_counter(expires_at_s)?;
        let policy_bits = bytes[49];
        validate_policy_bits(policy_bits)?;
        let inviter_root_pk: Ed25519PubKey = bytes[50..82]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        validate_ed25519_pubkey_strict(&inviter_root_pk)?;
        let invite_seed: [u8; 32] = bytes[82..114]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        Ok(Self {
            group_id,
            invite_id,
            invite_epoch,
            expires_at_s,
            policy_bits,
            inviter_root_pk,
            invite_seed,
        })
    }

    pub fn encode_b64url(&self) -> Result<String, MpMlsError> {
        let raw = self.encode()?;
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    pub fn decode_b64url(s: &str) -> Result<Self, MpMlsError> {
        let raw = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| MpMlsError::InvalidBase64)?;
        Self::decode(&raw)
    }

    pub fn derive_secrets(&self) -> Result<InviteSecrets, MpMlsError> {
        InviteSecrets::derive(&self.group_id, &self.invite_seed)
    }
}

/// Encrypted 93-byte in-group invite record synchronized between honest room members (Spec v3.1 §4.2).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InviteRecordV1 {
    pub invite_id: u64,
    pub invite_epoch: u64,
    pub max_uses: u32,
    pub expires_at_s: u64,
    pub inviter_root_pk: Ed25519PubKey,
    pub member_join_mac_key: [u8; 32],
}

impl fmt::Debug for InviteRecordV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteRecordV1")
            .field("invite_id", &self.invite_id)
            .field("invite_epoch", &self.invite_epoch)
            .field("max_uses", &self.max_uses)
            .field("expires_at_s", &self.expires_at_s)
            .field("inviter_root_pk", &self.inviter_root_pk)
            .field("member_join_mac_key", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for InviteRecordV1 {
    fn eq(&self, other: &Self) -> bool {
        (self.invite_id == other.invite_id)
            & (self.invite_epoch == other.invite_epoch)
            & (self.max_uses == other.max_uses)
            & (self.expires_at_s == other.expires_at_s)
            & (self.inviter_root_pk == other.inviter_root_pk)
            & ct_eq_bytes(&self.member_join_mac_key, &other.member_join_mac_key)
    }
}

impl Eq for InviteRecordV1 {}

impl InviteRecordV1 {
    pub fn encode(&self) -> Result<[u8; INVITE_RECORD_V1_LEN], MpMlsError> {
        check_safe_id(self.invite_id)?;
        check_safe_counter(self.invite_epoch)?;
        check_safe_counter(self.expires_at_s)?;
        validate_ed25519_pubkey_strict(&self.inviter_root_pk)?;
        let mut out = [0u8; INVITE_RECORD_V1_LEN];
        out[0] = 1;
        out[1..9].copy_from_slice(&self.invite_id.to_be_bytes());
        out[9..17].copy_from_slice(&self.invite_epoch.to_be_bytes());
        out[17..21].copy_from_slice(&self.max_uses.to_be_bytes());
        out[21..29].copy_from_slice(&self.expires_at_s.to_be_bytes());
        out[29..61].copy_from_slice(&self.inviter_root_pk);
        out[61..93].copy_from_slice(&self.member_join_mac_key);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != INVITE_RECORD_V1_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: INVITE_RECORD_V1_LEN,
                got: bytes.len(),
            });
        }
        if bytes[0] != 1 {
            return Err(MpMlsError::UnsupportedVersion(bytes[0]));
        }
        let invite_id = u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let invite_epoch = u64::from_be_bytes(
            bytes[9..17]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        check_safe_id(invite_id)?;
        check_safe_counter(invite_epoch)?;
        let max_uses = u32::from_be_bytes(
            bytes[17..21]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let expires_at_s = u64::from_be_bytes(
            bytes[21..29]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        check_safe_counter(expires_at_s)?;
        let inviter_root_pk: Ed25519PubKey = bytes[29..61]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        validate_ed25519_pubkey_strict(&inviter_root_pk)?;
        let member_join_mac_key: [u8; 32] = bytes[61..93]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        Ok(Self {
            invite_id,
            invite_epoch,
            max_uses,
            expires_at_s,
            inviter_root_pk,
            member_join_mac_key,
        })
    }
}
