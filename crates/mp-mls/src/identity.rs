//! Authentication Service (AS) canonical binary codecs, strict Ed25519 verifiers,
//! account device list monotonicity/equivocation tracking bound to pinned roots,
//! canonical 219-byte `RootRotationStmtV1`, leaf credentials, Safety Number v2,
//! and honest client-computed Room Trust Tiers (Spec v3.1).

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use openmls::prelude::{BasicCredential, Credential};

use crate::crypto::{
    encode_crockford_grouped_4, sha256, sign_ed25519, validate_ed25519_pubkey_strict,
    verify_ed25519_strict, Ed25519PubKey, Ed25519Sig, Sha256Digest,
};
use crate::error::MpMlsError;

/// Maximum safe integer shared across Rust (`u64`), SQLite (`i64`), and JS/TS (`Number`, `2^53 - 1`).
pub const MAX_SAFE_ID: u64 = 9_007_199_254_740_991;

/// Exact byte lengths per Spec v3.1 §3.2:
/// `1 + 8 + 4 + 8 + 4 + 1 + 1 + 1 + 8 + 8 + 32 + 32 = 108` bytes.
pub const DEVICE_BINDING_BODY_LEN: usize = 108;
/// `108 + 64 + 64 = 236` bytes.
pub const DEVICE_BINDING_LEN: usize = 236;
/// `8 + 4 + 32 = 44` bytes.
pub const ACTIVE_DEVICE_ENTRY_LEN: usize = 44;
/// `236 + 8 + 32 = 276` bytes carried in MLS `BasicCredential`.
pub const LEAF_CRED_LEN: usize = 276;
/// Spec v3.1 §3.2.1 `RootRotationStmtV1` prefix:
/// `1 + 8 + 4 + 4 + 1 + 1 + 32 + 32 + 8 = 91` bytes.
pub const ROOT_ROTATION_BODY_LEN: usize = 91;
/// Exact `RootRotationStmtV1` wire length: `91 + 64 + 64 = 219` bytes.
pub const ROOT_ROTATION_LEN: usize = 219;

pub const MAX_BROWSER_BINDING_TTL_S: u64 = 7 * 86_400;
pub const MAX_NATIVE_BINDING_TTL_S: u64 = 30 * 86_400;
pub const MAX_DEVICE_LIST_TTL_S: u64 = 30 * 86_400;
pub const MAX_DEVICES_PER_ACCOUNT: usize = 8;

pub const DEV_BIND_DOMAIN_SEP: &[u8] = b"mp-mls-dev-bind-v1:";
pub const DEV_POP_DOMAIN_SEP: &[u8] = b"mp-mls-dev-pop-v1:";
pub const DEV_LIST_DOMAIN_SEP: &[u8] = b"mp-mls-dev-list-v1:";
pub const ROOT_ROT_DOMAIN_SEP: &[u8] = b"mp-mls-root-rot-v1:";
pub const SAFETY_NUMBER_V2_DOMAIN_SEP: &[u8] = b"mp-safety-v2:";

pub fn check_safe_id(id: u64) -> Result<(), MpMlsError> {
    if id == 0 || id > MAX_SAFE_ID {
        return Err(MpMlsError::InvalidSafeId(id));
    }
    Ok(())
}

pub fn check_safe_counter(n: u64) -> Result<(), MpMlsError> {
    if n > MAX_SAFE_ID {
        return Err(MpMlsError::InvalidSafeCounter(n));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ClientClass {
    Blackbird = 1,
    Outpost = 2,
    Browser = 3,
}

impl ClientClass {
    pub fn from_u8(v: u8) -> Result<Self, MpMlsError> {
        match v {
            1 => Ok(Self::Blackbird),
            2 => Ok(Self::Outpost),
            3 => Ok(Self::Browser),
            other => Err(MpMlsError::InvalidEnumValue {
                field: "client_class",
                value: u64::from(other),
            }),
        }
    }

    pub fn max_binding_ttl_s(self) -> u64 {
        match self {
            Self::Browser => MAX_BROWSER_BINDING_TTL_S,
            Self::Blackbird | Self::Outpost => MAX_NATIVE_BINDING_TTL_S,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CustodyMode {
    CloudManaged = 0,
    SelfCustody = 1,
}

impl CustodyMode {
    pub fn from_u8(v: u8) -> Result<Self, MpMlsError> {
        match v {
            0 => Ok(Self::CloudManaged),
            1 => Ok(Self::SelfCustody),
            other => Err(MpMlsError::InvalidEnumValue {
                field: "custody_mode",
                value: u64::from(other),
            }),
        }
    }
}

/// Honest room trust tier computed client-side over the authenticated ratchet tree (Spec v3.1 §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomTrustTier {
    Tier0UnverifiedPostWipe,
    Tier1CloudOrBrowserPresent,
    Tier2SelfCustodyNativeUnverified,
    Tier3SelfCustodyNativeAllVerified,
}

/// Fixed 108-byte canonical body of `MpMlsDeviceBindingV1` (Spec v3.1 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpMlsDeviceBindingBodyV1 {
    pub version: u8,
    pub account_id: u64,
    pub root_gen: u32,
    pub device_id: u64,
    pub device_gen: u32,
    pub client_class: ClientClass,
    pub agent_capable: bool,
    pub custody_mode: CustodyMode,
    pub iat_s: u64,
    pub exp_s: u64,
    pub root_pubkey: Ed25519PubKey,
    pub mls_sig_pubkey: Ed25519PubKey,
}

impl MpMlsDeviceBindingBodyV1 {
    pub fn validate_fields(&self) -> Result<(), MpMlsError> {
        if self.version != 1 {
            return Err(MpMlsError::UnsupportedVersion(self.version));
        }
        check_safe_id(self.account_id)?;
        if self.root_gen == 0 {
            return Err(MpMlsError::InvalidGeneration { field: "root_gen" });
        }
        check_safe_id(self.device_id)?;
        if self.device_gen == 0 {
            return Err(MpMlsError::InvalidGeneration {
                field: "device_gen",
            });
        }
        check_safe_counter(self.iat_s)?;
        check_safe_counter(self.exp_s)?;
        if self.iat_s >= self.exp_s {
            return Err(MpMlsError::InvalidTimestampWindow {
                iat_s: self.iat_s,
                exp_s: self.exp_s,
            });
        }
        let ttl_s = self.exp_s - self.iat_s;
        let max_ttl_s = self.client_class.max_binding_ttl_s();
        if ttl_s > max_ttl_s {
            return Err(MpMlsError::TtlExceeded { ttl_s, max_ttl_s });
        }
        validate_ed25519_pubkey_strict(&self.root_pubkey)?;
        validate_ed25519_pubkey_strict(&self.mls_sig_pubkey)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; DEVICE_BINDING_BODY_LEN], MpMlsError> {
        self.validate_fields()?;
        let mut buf = [0u8; DEVICE_BINDING_BODY_LEN];
        buf[0] = self.version;
        buf[1..9].copy_from_slice(&self.account_id.to_be_bytes());
        buf[9..13].copy_from_slice(&self.root_gen.to_be_bytes());
        buf[13..21].copy_from_slice(&self.device_id.to_be_bytes());
        buf[21..25].copy_from_slice(&self.device_gen.to_be_bytes());
        buf[25] = self.client_class as u8;
        buf[26] = u8::from(self.agent_capable);
        buf[27] = self.custody_mode as u8;
        buf[28..36].copy_from_slice(&self.iat_s.to_be_bytes());
        buf[36..44].copy_from_slice(&self.exp_s.to_be_bytes());
        buf[44..76].copy_from_slice(&self.root_pubkey);
        buf[76..108].copy_from_slice(&self.mls_sig_pubkey);
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != DEVICE_BINDING_BODY_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: DEVICE_BINDING_BODY_LEN,
                got: bytes.len(),
            });
        }
        let version = bytes[0];
        let account_id = u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let root_gen = u32::from_be_bytes(
            bytes[9..13]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let device_id = u64::from_be_bytes(
            bytes[13..21]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let device_gen = u32::from_be_bytes(
            bytes[21..25]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let client_class = ClientClass::from_u8(bytes[25])?;
        let agent_capable = match bytes[26] {
            0 => false,
            1 => true,
            other => {
                return Err(MpMlsError::InvalidEnumValue {
                    field: "agent_capable",
                    value: u64::from(other),
                });
            }
        };
        let custody_mode = CustodyMode::from_u8(bytes[27])?;
        let iat_s = u64::from_be_bytes(
            bytes[28..36]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let exp_s = u64::from_be_bytes(
            bytes[36..44]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let root_pubkey: Ed25519PubKey = bytes[44..76]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let mls_sig_pubkey: Ed25519PubKey = bytes[76..108]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;

        let body = Self {
            version,
            account_id,
            root_gen,
            device_id,
            device_gen,
            client_class,
            agent_capable,
            custody_mode,
            iat_s,
            exp_s,
            root_pubkey,
            mls_sig_pubkey,
        };
        body.validate_fields()?;
        Ok(body)
    }
}

/// Fixed 236-byte canonical device binding (`MpMlsDeviceBindingV1`, Spec v3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpMlsDeviceBindingV1 {
    pub body: MpMlsDeviceBindingBodyV1,
    pub root_sig: Ed25519Sig,
    pub device_pop_sig: Ed25519Sig,
}

impl MpMlsDeviceBindingV1 {
    /// Signs a valid `MpMlsDeviceBindingBodyV1` with both the account root key and device MLS signing key.
    pub fn sign(
        body: MpMlsDeviceBindingBodyV1,
        root_sk: &SigningKey,
        device_sk: &SigningKey,
    ) -> Result<Self, MpMlsError> {
        let body_bytes = body.encode()?;
        if root_sk.verifying_key().to_bytes() != body.root_pubkey
            || device_sk.verifying_key().to_bytes() != body.mls_sig_pubkey
        {
            return Err(MpMlsError::InvalidPublicKey);
        }

        let mut bind_msg = Vec::with_capacity(DEV_BIND_DOMAIN_SEP.len() + DEVICE_BINDING_BODY_LEN);
        bind_msg.extend_from_slice(DEV_BIND_DOMAIN_SEP);
        bind_msg.extend_from_slice(&body_bytes);
        let root_sig = sign_ed25519(root_sk, &bind_msg);

        let mut pop_hash_input = Vec::with_capacity(DEVICE_BINDING_BODY_LEN + 64);
        pop_hash_input.extend_from_slice(&body_bytes);
        pop_hash_input.extend_from_slice(&root_sig);
        let pop_digest = sha256(&pop_hash_input);

        let mut pop_msg = Vec::with_capacity(DEV_POP_DOMAIN_SEP.len() + 32);
        pop_msg.extend_from_slice(DEV_POP_DOMAIN_SEP);
        pop_msg.extend_from_slice(&pop_digest);
        let device_pop_sig = sign_ed25519(device_sk, &pop_msg);

        Ok(Self {
            body,
            root_sig,
            device_pop_sig,
        })
    }

    pub fn encode(&self) -> Result<[u8; DEVICE_BINDING_LEN], MpMlsError> {
        let body_bytes = self.body.encode()?;
        let mut out = [0u8; DEVICE_BINDING_LEN];
        out[0..DEVICE_BINDING_BODY_LEN].copy_from_slice(&body_bytes);
        out[DEVICE_BINDING_BODY_LEN..DEVICE_BINDING_BODY_LEN + 64].copy_from_slice(&self.root_sig);
        out[DEVICE_BINDING_BODY_LEN + 64..DEVICE_BINDING_LEN].copy_from_slice(&self.device_pop_sig);
        Ok(out)
    }

    /// Decodes canonical 236-byte binding WITHOUT running signature verification yet.
    pub fn decode_unverified(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != DEVICE_BINDING_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: DEVICE_BINDING_LEN,
                got: bytes.len(),
            });
        }
        let body = MpMlsDeviceBindingBodyV1::decode(&bytes[0..DEVICE_BINDING_BODY_LEN])?;
        let root_sig: Ed25519Sig = bytes[DEVICE_BINDING_BODY_LEN..DEVICE_BINDING_BODY_LEN + 64]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let device_pop_sig: Ed25519Sig = bytes[DEVICE_BINDING_BODY_LEN + 64..DEVICE_BINDING_LEN]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        Ok(Self {
            body,
            root_sig,
            device_pop_sig,
        })
    }

    /// Time-independent deterministic verification of fields + strict Ed25519 signatures.
    /// Used during Commit / Welcome processing so offline catch-up never forks on wall clock.
    pub fn verify_structural(&self) -> Result<(), MpMlsError> {
        let body_bytes = self.body.encode()?;

        let mut bind_msg = Vec::with_capacity(DEV_BIND_DOMAIN_SEP.len() + DEVICE_BINDING_BODY_LEN);
        bind_msg.extend_from_slice(DEV_BIND_DOMAIN_SEP);
        bind_msg.extend_from_slice(&body_bytes);
        verify_ed25519_strict(&self.body.root_pubkey, &bind_msg, &self.root_sig)?;

        let mut pop_hash_input = Vec::with_capacity(DEVICE_BINDING_BODY_LEN + 64);
        pop_hash_input.extend_from_slice(&body_bytes);
        pop_hash_input.extend_from_slice(&self.root_sig);
        let pop_digest = sha256(&pop_hash_input);

        let mut pop_msg = Vec::with_capacity(DEV_POP_DOMAIN_SEP.len() + 32);
        pop_msg.extend_from_slice(DEV_POP_DOMAIN_SEP);
        pop_msg.extend_from_slice(&pop_digest);
        verify_ed25519_strict(&self.body.mls_sig_pubkey, &pop_msg, &self.device_pop_sig)?;

        Ok(())
    }

    /// Decodes and runs time-independent strict verification.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, MpMlsError> {
        let binding = Self::decode_unverified(bytes)?;
        binding.verify_structural()?;
        Ok(binding)
    }

    /// Wall-clock verification run ONLY at KeyPackage / Update admission time (§3.3).
    pub fn verify_at_admission(&self, now_s: u64) -> Result<(), MpMlsError> {
        check_safe_counter(now_s)?;
        self.verify_structural()?;
        if now_s < self.body.iat_s || now_s >= self.body.exp_s {
            return Err(MpMlsError::NotValidAtAdmissionTime { now_s });
        }
        Ok(())
    }
}

/// Fixed 44-byte entry in `AccountDeviceListV1` (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveDeviceEntryV1 {
    pub device_id: u64,
    pub device_gen: u32,
    pub mls_sig_pubkey: Ed25519PubKey,
}

impl ActiveDeviceEntryV1 {
    pub fn encode(&self) -> Result<[u8; ACTIVE_DEVICE_ENTRY_LEN], MpMlsError> {
        check_safe_id(self.device_id)?;
        if self.device_gen == 0 {
            return Err(MpMlsError::InvalidGeneration {
                field: "device_gen",
            });
        }
        validate_ed25519_pubkey_strict(&self.mls_sig_pubkey)?;
        let mut out = [0u8; ACTIVE_DEVICE_ENTRY_LEN];
        out[0..8].copy_from_slice(&self.device_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.device_gen.to_be_bytes());
        out[12..44].copy_from_slice(&self.mls_sig_pubkey);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != ACTIVE_DEVICE_ENTRY_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: ACTIVE_DEVICE_ENTRY_LEN,
                got: bytes.len(),
            });
        }
        let device_id = u64::from_be_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let device_gen = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let mls_sig_pubkey: Ed25519PubKey = bytes[12..44]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        check_safe_id(device_id)?;
        if device_gen == 0 {
            return Err(MpMlsError::InvalidGeneration {
                field: "device_gen",
            });
        }
        validate_ed25519_pubkey_strict(&mls_sig_pubkey)?;
        Ok(Self {
            device_id,
            device_gen,
            mls_sig_pubkey,
        })
    }
}

/// Canonical root-signed account device list (`AccountDeviceListV1`, §3.2).
/// Carried directly on every MLS `LeafNode` inside private extension `0xFF02`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDeviceListV1 {
    pub version: u8,
    pub account_id: u64,
    pub root_gen: u32,
    pub list_version: u64,
    pub iat_s: u64,
    pub exp_s: u64,
    pub entries: Vec<ActiveDeviceEntryV1>,
    pub root_sig: Ed25519Sig,
}

impl AccountDeviceListV1 {
    fn encode_prefix(&self) -> Result<Vec<u8>, MpMlsError> {
        if self.version != 1 {
            return Err(MpMlsError::UnsupportedVersion(self.version));
        }
        check_safe_id(self.account_id)?;
        if self.root_gen == 0 {
            return Err(MpMlsError::InvalidGeneration { field: "root_gen" });
        }
        check_safe_id(self.list_version)?;
        check_safe_counter(self.iat_s)?;
        check_safe_counter(self.exp_s)?;
        if self.iat_s >= self.exp_s {
            return Err(MpMlsError::InvalidTimestampWindow {
                iat_s: self.iat_s,
                exp_s: self.exp_s,
            });
        }
        let ttl_s = self.exp_s - self.iat_s;
        if ttl_s > MAX_DEVICE_LIST_TTL_S {
            return Err(MpMlsError::TtlExceeded {
                ttl_s,
                max_ttl_s: MAX_DEVICE_LIST_TTL_S,
            });
        }
        if self.entries.len() > MAX_DEVICES_PER_ACCOUNT {
            return Err(MpMlsError::TooManyDevicesInList {
                count: self.entries.len(),
                max: MAX_DEVICES_PER_ACCOUNT,
            });
        }

        let mut prev_dev_id: Option<u64> = None;
        for entry in &self.entries {
            if let Some(prev) = prev_dev_id
                && entry.device_id <= prev
            {
                return Err(MpMlsError::UnsortedOrDuplicateDeviceList);
            }
            prev_dev_id = Some(entry.device_id);
        }

        let prefix_len = 1 + 8 + 4 + 8 + 8 + 8 + 2 + self.entries.len() * ACTIVE_DEVICE_ENTRY_LEN;
        let mut out = Vec::with_capacity(prefix_len);
        out.push(self.version);
        out.extend_from_slice(&self.account_id.to_be_bytes());
        out.extend_from_slice(&self.root_gen.to_be_bytes());
        out.extend_from_slice(&self.list_version.to_be_bytes());
        out.extend_from_slice(&self.iat_s.to_be_bytes());
        out.extend_from_slice(&self.exp_s.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.encode()?);
        }
        Ok(out)
    }

    pub fn sign(
        account_id: u64,
        root_gen: u32,
        list_version: u64,
        iat_s: u64,
        exp_s: u64,
        mut entries: Vec<ActiveDeviceEntryV1>,
        root_sk: &SigningKey,
    ) -> Result<Self, MpMlsError> {
        entries.sort_by_key(|e| e.device_id);
        let mut list = Self {
            version: 1,
            account_id,
            root_gen,
            list_version,
            iat_s,
            exp_s,
            entries,
            root_sig: [0u8; 64],
        };
        let prefix = list.encode_prefix()?;
        let mut msg = Vec::with_capacity(DEV_LIST_DOMAIN_SEP.len() + prefix.len());
        msg.extend_from_slice(DEV_LIST_DOMAIN_SEP);
        msg.extend_from_slice(&prefix);
        list.root_sig = sign_ed25519(root_sk, &msg);
        Ok(list)
    }

    pub fn encode(&self) -> Result<Vec<u8>, MpMlsError> {
        let mut out = self.encode_prefix()?;
        out.extend_from_slice(&self.root_sig);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MpMlsError> {
        const HEADER_LEN: usize = 1 + 8 + 4 + 8 + 8 + 8 + 2;
        if bytes.len() < HEADER_LEN + 64 {
            return Err(MpMlsError::TruncatedInput);
        }
        let version = bytes[0];
        let account_id = u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let root_gen = u32::from_be_bytes(
            bytes[9..13]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let list_version = u64::from_be_bytes(
            bytes[13..21]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let iat_s = u64::from_be_bytes(
            bytes[21..29]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let exp_s = u64::from_be_bytes(
            bytes[29..37]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let device_count = u16::from_be_bytes(
            bytes[37..39]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        ) as usize;

        if device_count > MAX_DEVICES_PER_ACCOUNT {
            return Err(MpMlsError::TooManyDevicesInList {
                count: device_count,
                max: MAX_DEVICES_PER_ACCOUNT,
            });
        }
        let expected_len = HEADER_LEN + device_count * ACTIVE_DEVICE_ENTRY_LEN + 64;
        if bytes.len() < expected_len {
            return Err(MpMlsError::TruncatedInput);
        }
        if bytes.len() > expected_len {
            return Err(MpMlsError::TrailingBytes);
        }

        let mut entries = Vec::with_capacity(device_count);
        let mut offset = HEADER_LEN;
        for _ in 0..device_count {
            entries.push(ActiveDeviceEntryV1::decode(
                &bytes[offset..offset + ACTIVE_DEVICE_ENTRY_LEN],
            )?);
            offset += ACTIVE_DEVICE_ENTRY_LEN;
        }
        let root_sig: Ed25519Sig = bytes[offset..offset + 64]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;

        let list = Self {
            version,
            account_id,
            root_gen,
            list_version,
            iat_s,
            exp_s,
            entries,
            root_sig,
        };
        let _ = list.encode_prefix()?;
        Ok(list)
    }

    pub fn verify(&self, expected_root_pubkey: &Ed25519PubKey) -> Result<(), MpMlsError> {
        let prefix = self.encode_prefix()?;
        let mut msg = Vec::with_capacity(DEV_LIST_DOMAIN_SEP.len() + prefix.len());
        msg.extend_from_slice(DEV_LIST_DOMAIN_SEP);
        msg.extend_from_slice(&prefix);
        verify_ed25519_strict(expected_root_pubkey, &msg, &self.root_sig)
    }

    /// Wall-clock validity check for `AccountDeviceListV1` at admission time (§3.3.2).
    pub fn verify_at_admission(
        &self,
        expected_root_pubkey: &Ed25519PubKey,
        now_s: u64,
    ) -> Result<(), MpMlsError> {
        check_safe_counter(now_s)?;
        self.verify(expected_root_pubkey)?;
        if now_s < self.iat_s || now_s >= self.exp_s {
            return Err(MpMlsError::NotValidAtAdmissionTime { now_s });
        }
        Ok(())
    }

    pub fn list_hash(&self) -> Result<Sha256Digest, MpMlsError> {
        let encoded = self.encode()?;
        Ok(sha256(&encoded))
    }

    /// Returns true iff `(device_id, device_gen, mls_sig_pubkey)` matches an active entry
    /// in this list exactly (exact `device_id`, exact `device_gen`, exact `mls_sig_pubkey`).
    pub fn authorizes_leaf(&self, binding: &MpMlsDeviceBindingBodyV1) -> bool {
        self.entries.iter().any(|e| {
            e.device_id == binding.device_id
                && e.mls_sig_pubkey == binding.mls_sig_pubkey
                && e.device_gen == binding.device_gen
        })
    }
}

/// Persisted per-account `AccountDeviceListV1` freshness & equivocation tracker (§3.3, Fable H2).
#[derive(Debug, Default, Clone)]
pub struct DeviceListTracker {
    seen: HashMap<u64, (u64, Sha256Digest, AccountDeviceListV1)>,
}

impl DeviceListTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes a candidate `AccountDeviceListV1`, binding verification strictly to the account's
    /// pinned root in `pins` (`root_pubkey` and `root_gen`), optionally enforcing wall-clock
    /// validity (`now_s`), rejecting `root_gen` regression, stale `list_version`, and equal-version
    /// hash equivocation.
    ///
    /// Returns `Ok(true)` if the tracked list advanced, `Ok(false)` if identical.
    pub fn observe(
        &mut self,
        list: AccountDeviceListV1,
        pins: &AccountRootPinStore,
        now_s: Option<u64>,
    ) -> Result<bool, MpMlsError> {
        let pin = pins
            .get(list.account_id)
            .ok_or(MpMlsError::PinnedRootMismatch)?;
        if list.root_gen != pin.root_gen {
            return Err(MpMlsError::RootGenMismatch);
        }
        if let Some(now) = now_s {
            list.verify_at_admission(&pin.root_pubkey, now)?;
        } else {
            list.verify(&pin.root_pubkey)?;
        }
        let hash = list.list_hash()?;

        if let Some((seen_ver, seen_hash, seen_list)) = self.seen.get(&list.account_id) {
            if list.root_gen < seen_list.root_gen {
                return Err(MpMlsError::RootGenMismatch);
            }
            if list.root_gen == seen_list.root_gen {
                if list.list_version < *seen_ver {
                    return Err(MpMlsError::StaleDeviceList {
                        got: list.list_version,
                        seen: *seen_ver,
                    });
                }
                if list.list_version == *seen_ver {
                    if hash != *seen_hash {
                        return Err(MpMlsError::DeviceListEquivocation {
                            version: list.list_version,
                        });
                    }
                    return Ok(false);
                }
            }
        }

        self.seen
            .insert(list.account_id, (list.list_version, hash, list));
        Ok(true)
    }

    pub fn latest(&self, account_id: u64) -> Option<&AccountDeviceListV1> {
        self.seen.get(&account_id).map(|(_, _, l)| l)
    }

    pub fn seen_version_and_hash(&self, account_id: u64) -> Option<(u64, Sha256Digest)> {
        self.seen.get(&account_id).map(|(v, h, _)| (*v, *h))
    }

    /// Returns `true` iff the leaf carries an equal `(root_gen, list_version)` to our tracked
    /// list for its account with a conflicting `list_hash` (equivocation attack).
    pub fn check_leaf_equivocation(&self, cred: &MpMlsLeafCredV1) -> bool {
        let Some((seen_ver, seen_hash, seen_list)) = self.seen.get(&cred.binding.body.account_id)
        else {
            return false;
        };
        seen_list.root_gen == cred.binding.body.root_gen
            && *seen_ver == cred.list_version
            && *seen_hash != cred.list_hash
    }

    /// Checks whether a leaf is revoked/absent according to a newer-or-equal verified
    /// `AccountDeviceListV1` for its account.
    /// An older cached list (`latest.list_version < cred.list_version`) NEVER revokes a newer leaf!
    pub fn is_leaf_revoked(&self, cred: &MpMlsLeafCredV1) -> bool {
        let Some(latest) = self.latest(cred.binding.body.account_id) else {
            return false;
        };
        if latest.root_gen > cred.binding.body.root_gen {
            return true;
        }
        if latest.root_gen < cred.binding.body.root_gen {
            return false;
        }
        if latest.list_version < cred.list_version {
            return false;
        }
        !latest.authorizes_leaf(&cred.binding.body)
    }
}

/// Canonical 219-byte root rotation / "Take Custody" statement (`RootRotationStmtV1`, Spec v3.1 §3.2.1):
/// `version(1) || account_id(8) || old_root_gen(4) || new_root_gen(4) || old_custody_mode(1) || new_custody_mode(1) || old_root_pubkey(32) || new_root_pubkey(32) || rotated_at_s(8) || old_root_sig(64) || new_root_sig(64)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootRotationStmtV1 {
    pub version: u8,
    pub account_id: u64,
    pub old_root_gen: u32,
    pub new_root_gen: u32,
    pub old_custody_mode: CustodyMode,
    pub new_custody_mode: CustodyMode,
    pub old_root_pubkey: Ed25519PubKey,
    pub new_root_pubkey: Ed25519PubKey,
    pub rotated_at_s: u64,
    pub old_root_sig: Ed25519Sig,
    pub new_root_sig: Ed25519Sig,
}

impl RootRotationStmtV1 {
    fn encode_body(&self) -> Result<[u8; ROOT_ROTATION_BODY_LEN], MpMlsError> {
        if self.version != 1 {
            return Err(MpMlsError::UnsupportedVersion(self.version));
        }
        check_safe_id(self.account_id)?;
        if self.old_root_gen == 0 || self.old_root_gen.checked_add(1) != Some(self.new_root_gen) {
            return Err(MpMlsError::InvalidRootRotation(
                "new_root_gen must equal old_root_gen + 1 with old_root_gen >= 1",
            ));
        }
        if self.old_root_pubkey == self.new_root_pubkey {
            return Err(MpMlsError::InvalidRootRotation(
                "new_root_pubkey must differ from old_root_pubkey",
            ));
        }
        check_safe_counter(self.rotated_at_s)?;
        validate_ed25519_pubkey_strict(&self.old_root_pubkey)?;
        validate_ed25519_pubkey_strict(&self.new_root_pubkey)?;

        let mut out = [0u8; ROOT_ROTATION_BODY_LEN];
        out[0] = self.version;
        out[1..9].copy_from_slice(&self.account_id.to_be_bytes());
        out[9..13].copy_from_slice(&self.old_root_gen.to_be_bytes());
        out[13..17].copy_from_slice(&self.new_root_gen.to_be_bytes());
        out[17] = self.old_custody_mode as u8;
        out[18] = self.new_custody_mode as u8;
        out[19..51].copy_from_slice(&self.old_root_pubkey);
        out[51..83].copy_from_slice(&self.new_root_pubkey);
        out[83..91].copy_from_slice(&self.rotated_at_s.to_be_bytes());
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        account_id: u64,
        old_root_gen: u32,
        new_root_gen: u32,
        old_custody_mode: CustodyMode,
        new_custody_mode: CustodyMode,
        rotated_at_s: u64,
        old_root_sk: &SigningKey,
        new_root_sk: &SigningKey,
    ) -> Result<Self, MpMlsError> {
        let mut stmt = Self {
            version: 1,
            account_id,
            old_root_gen,
            new_root_gen,
            old_custody_mode,
            new_custody_mode,
            old_root_pubkey: old_root_sk.verifying_key().to_bytes(),
            new_root_pubkey: new_root_sk.verifying_key().to_bytes(),
            rotated_at_s,
            old_root_sig: [0u8; 64],
            new_root_sig: [0u8; 64],
        };
        let body = stmt.encode_body()?;
        let mut msg = Vec::with_capacity(ROOT_ROT_DOMAIN_SEP.len() + ROOT_ROTATION_BODY_LEN);
        msg.extend_from_slice(ROOT_ROT_DOMAIN_SEP);
        msg.extend_from_slice(&body);
        stmt.old_root_sig = sign_ed25519(old_root_sk, &msg);
        stmt.new_root_sig = sign_ed25519(new_root_sk, &msg);
        Ok(stmt)
    }

    pub fn encode(&self) -> Result<[u8; ROOT_ROTATION_LEN], MpMlsError> {
        let body = self.encode_body()?;
        let mut out = [0u8; ROOT_ROTATION_LEN];
        out[0..ROOT_ROTATION_BODY_LEN].copy_from_slice(&body);
        out[ROOT_ROTATION_BODY_LEN..ROOT_ROTATION_BODY_LEN + 64]
            .copy_from_slice(&self.old_root_sig);
        out[ROOT_ROTATION_BODY_LEN + 64..ROOT_ROTATION_LEN].copy_from_slice(&self.new_root_sig);
        Ok(out)
    }

    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != ROOT_ROTATION_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: ROOT_ROTATION_LEN,
                got: bytes.len(),
            });
        }
        let version = bytes[0];
        let account_id = u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let old_root_gen = u32::from_be_bytes(
            bytes[9..13]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let new_root_gen = u32::from_be_bytes(
            bytes[13..17]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let old_custody_mode = CustodyMode::from_u8(bytes[17])?;
        let new_custody_mode = CustodyMode::from_u8(bytes[18])?;
        let old_root_pubkey: Ed25519PubKey = bytes[19..51]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let new_root_pubkey: Ed25519PubKey = bytes[51..83]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let rotated_at_s = u64::from_be_bytes(
            bytes[83..91]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        let old_root_sig: Ed25519Sig = bytes[91..155]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let new_root_sig: Ed25519Sig = bytes[155..219]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;

        let stmt = Self {
            version,
            account_id,
            old_root_gen,
            new_root_gen,
            old_custody_mode,
            new_custody_mode,
            old_root_pubkey,
            new_root_pubkey,
            rotated_at_s,
            old_root_sig,
            new_root_sig,
        };
        stmt.verify()?;
        Ok(stmt)
    }

    pub fn verify(&self) -> Result<(), MpMlsError> {
        let body = self.encode_body()?;
        let mut msg = Vec::with_capacity(ROOT_ROT_DOMAIN_SEP.len() + ROOT_ROTATION_BODY_LEN);
        msg.extend_from_slice(ROOT_ROT_DOMAIN_SEP);
        msg.extend_from_slice(&body);
        verify_ed25519_strict(&self.old_root_pubkey, &msg, &self.old_root_sig)?;
        verify_ed25519_strict(&self.new_root_pubkey, &msg, &self.new_root_sig)?;
        Ok(())
    }
}

/// Locally pinned root identity for an account (Spec v3.1 §3.3 / §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedAccountRoot {
    pub account_id: u64,
    pub root_pubkey: Ed25519PubKey,
    pub root_gen: u32,
    pub custody_mode: CustodyMode,
    pub verified_oob: bool,
    /// `true` after a `0 -> 1` ("Take Custody") `RootRotationStmtV1` until the new root is
    /// verified out-of-band (keeps room at Tier 0 per Spec v3.1 §3.3.4 / §3.4).
    pub pending_oob_reverify: bool,
}

/// Local per-account root pin store enforcing custody-mode immutability under a given `root_pubkey`.
#[derive(Debug, Default, Clone)]
pub struct AccountRootPinStore {
    pins: HashMap<u64, PinnedAccountRoot>,
}

impl AccountRootPinStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, account_id: u64) -> Option<&PinnedAccountRoot> {
        self.pins.get(&account_id)
    }

    /// Verifies `(account_id, root_pubkey, root_gen, custody_mode)` against existing pin without mutating.
    /// Hard invariant: a `custody_mode` flip under the SAME `root_pubkey` is ALWAYS rejected!
    pub fn check(
        &self,
        account_id: u64,
        root_pubkey: &Ed25519PubKey,
        root_gen: u32,
        custody_mode: CustodyMode,
    ) -> Result<(), MpMlsError> {
        if let Some(pinned) = self.pins.get(&account_id) {
            if &pinned.root_pubkey == root_pubkey {
                if pinned.custody_mode != custody_mode {
                    return Err(MpMlsError::CustodyModeFlipUnderSameRoot);
                }
                if pinned.root_gen != root_gen {
                    return Err(MpMlsError::RootGenMismatch);
                }
            } else {
                return Err(MpMlsError::PinnedRootMismatch);
            }
        }
        Ok(())
    }

    /// Checks against existing pin, or TOFU-pins if unseen (`verified_oob = false`).
    pub fn check_or_pin(
        &mut self,
        account_id: u64,
        root_pubkey: Ed25519PubKey,
        root_gen: u32,
        custody_mode: CustodyMode,
    ) -> Result<(), MpMlsError> {
        check_safe_id(account_id)?;
        validate_ed25519_pubkey_strict(&root_pubkey)?;
        self.check(account_id, &root_pubkey, root_gen, custody_mode)?;
        self.pins.entry(account_id).or_insert(PinnedAccountRoot {
            account_id,
            root_pubkey,
            root_gen,
            custody_mode,
            verified_oob: false,
            pending_oob_reverify: false,
        });
        Ok(())
    }

    /// Marks a pinned account root as out-of-band Safety-Number-verified and clears `pending_oob_reverify`.
    pub fn mark_verified_oob(&mut self, account_id: u64) -> Result<(), MpMlsError> {
        let pin = self
            .pins
            .get_mut(&account_id)
            .ok_or(MpMlsError::PinnedRootMismatch)?;
        pin.verified_oob = true;
        pin.pending_oob_reverify = false;
        Ok(())
    }

    /// Applies a verified 219-byte `RootRotationStmtV1` ("Take Custody" or key rotation).
    /// Requires fresh `new_root_pubkey`, exact `old_root_gen + 1`, matching `old_custody_mode`,
    /// resets `verified_oob = false`, and sets `pending_oob_reverify = true` on `0 -> 1` transitions.
    pub fn apply_root_rotation(&mut self, stmt: &RootRotationStmtV1) -> Result<(), MpMlsError> {
        stmt.verify()?;
        let pinned = self
            .pins
            .get_mut(&stmt.account_id)
            .ok_or(MpMlsError::PinnedRootMismatch)?;
        if pinned.root_pubkey != stmt.old_root_pubkey {
            return Err(MpMlsError::PinnedRootMismatch);
        }
        if pinned.root_gen != stmt.old_root_gen {
            return Err(MpMlsError::RootGenMismatch);
        }
        if pinned.custody_mode != stmt.old_custody_mode {
            return Err(MpMlsError::InvalidRootRotation(
                "old_custody_mode does not match pinned account root",
            ));
        }
        let is_cloud_to_self_upgrade = stmt.old_custody_mode == CustodyMode::CloudManaged
            && stmt.new_custody_mode == CustodyMode::SelfCustody;
        pinned.root_pubkey = stmt.new_root_pubkey;
        pinned.root_gen = stmt.new_root_gen;
        pinned.custody_mode = stmt.new_custody_mode;
        pinned.verified_oob = false;
        pinned.pending_oob_reverify = is_cloud_to_self_upgrade;
        Ok(())
    }
}

/// Exact 276-byte MLS `BasicCredential.identity` (`MpMlsLeafCredV1`, Spec v3.1):
/// `MpMlsDeviceBindingV1 (236B) || list_version_be64 (8B) || list_hash (32B)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpMlsLeafCredV1 {
    pub binding: MpMlsDeviceBindingV1,
    pub list_version: u64,
    pub list_hash: Sha256Digest,
}

impl MpMlsLeafCredV1 {
    pub fn new(
        binding: MpMlsDeviceBindingV1,
        list_version: u64,
        list_hash: Sha256Digest,
    ) -> Result<Self, MpMlsError> {
        check_safe_id(list_version)?;
        binding.verify_structural()?;
        Ok(Self {
            binding,
            list_version,
            list_hash,
        })
    }

    pub fn encode(&self) -> Result<[u8; LEAF_CRED_LEN], MpMlsError> {
        check_safe_id(self.list_version)?;
        let binding_bytes = self.binding.encode()?;
        let mut out = [0u8; LEAF_CRED_LEN];
        out[0..DEVICE_BINDING_LEN].copy_from_slice(&binding_bytes);
        out[DEVICE_BINDING_LEN..DEVICE_BINDING_LEN + 8]
            .copy_from_slice(&self.list_version.to_be_bytes());
        out[DEVICE_BINDING_LEN + 8..LEAF_CRED_LEN].copy_from_slice(&self.list_hash);
        Ok(out)
    }

    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, MpMlsError> {
        if bytes.len() != LEAF_CRED_LEN {
            return Err(MpMlsError::InvalidLength {
                expected: LEAF_CRED_LEN,
                got: bytes.len(),
            });
        }
        let binding = MpMlsDeviceBindingV1::decode_and_verify(&bytes[0..DEVICE_BINDING_LEN])?;
        let list_version = u64::from_be_bytes(
            bytes[DEVICE_BINDING_LEN..DEVICE_BINDING_LEN + 8]
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?,
        );
        check_safe_id(list_version)?;
        let list_hash: Sha256Digest = bytes[DEVICE_BINDING_LEN + 8..LEAF_CRED_LEN]
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        Ok(Self {
            binding,
            list_version,
            list_hash,
        })
    }

    pub fn to_basic_credential(&self) -> Result<BasicCredential, MpMlsError> {
        let bytes = self.encode()?;
        Ok(BasicCredential::new(bytes.to_vec()))
    }

    pub fn from_openmls_credential(cred: &Credential) -> Result<Self, MpMlsError> {
        let basic = BasicCredential::try_from(cred.clone())
            .map_err(|_| MpMlsError::InvalidRoomPolicy("non-BasicCredential rejected"))?;
        Self::decode_and_verify(basic.identity())
    }
}

/// Computes canonical Safety Number v2 (§3.3.4):
/// `SHA-256("mp-safety-v2:" || account_id_be64 || root_pubkey[32] || custody_mode_u8)`
/// formatted as 32 Crockford Base32 chars grouped as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (39 chars).
pub fn compute_safety_number_v2(
    account_id: u64,
    root_pubkey: &Ed25519PubKey,
    custody_mode: CustodyMode,
) -> String {
    let mut input = Vec::with_capacity(SAFETY_NUMBER_V2_DOMAIN_SEP.len() + 8 + 32 + 1);
    input.extend_from_slice(SAFETY_NUMBER_V2_DOMAIN_SEP);
    input.extend_from_slice(&account_id.to_be_bytes());
    input.extend_from_slice(root_pubkey);
    input.push(custody_mode as u8);
    let digest = sha256(&input);
    encode_crockford_grouped_4(&digest[0..20])
}

/// Formats RFC 9420 §8.7 `epoch_authenticator` (first 15 bytes = 120 bits = 24 Crockford Base32 chars)
/// as `6x4` groups (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, 29 chars) per §3.4.
pub fn format_epoch_authenticator(auth: &[u8]) -> Result<String, MpMlsError> {
    if auth.len() < 15 {
        return Err(MpMlsError::InvalidLength {
            expected: 15,
            got: auth.len(),
        });
    }
    Ok(encode_crockford_grouped_4(&auth[0..15]))
}

/// Computes honest client-side Room Trust Tier and orthogonal AI Agent badge (Spec v3.1 §3.4).
/// Enforces pin + root + custody verification uniformly across ALL leaves, including own account (Fable M5).
pub fn compute_room_trust_tier(
    leaves: &[MpMlsLeafCredV1],
    pins: &AccountRootPinStore,
    local_cache_wiped: bool,
    inviter_unconfirmed: bool,
) -> (RoomTrustTier, bool) {
    let has_agent = leaves.iter().any(|l| l.binding.body.agent_capable);
    let any_pending_oob_reverify = leaves.iter().any(|l| {
        pins.get(l.binding.body.account_id)
            .is_some_and(|p| p.pending_oob_reverify)
    });
    if local_cache_wiped || inviter_unconfirmed || any_pending_oob_reverify {
        return (RoomTrustTier::Tier0UnverifiedPostWipe, has_agent);
    }
    let any_cloud_or_browser = leaves.iter().any(|l| {
        l.binding.body.custody_mode == CustodyMode::CloudManaged
            || l.binding.body.client_class == ClientClass::Browser
    });
    if any_cloud_or_browser {
        return (RoomTrustTier::Tier1CloudOrBrowserPresent, has_agent);
    }
    let all_verified = leaves.iter().all(|l| {
        let b = &l.binding.body;
        pins.get(b.account_id).is_some_and(|p| {
            p.verified_oob
                && !p.pending_oob_reverify
                && p.root_pubkey == b.root_pubkey
                && p.root_gen == b.root_gen
                && p.custody_mode == b.custody_mode
        })
    });
    if all_verified {
        (RoomTrustTier::Tier3SelfCustodyNativeAllVerified, has_agent)
    } else {
        (RoomTrustTier::Tier2SelfCustodyNativeUnverified, has_agent)
    }
}
