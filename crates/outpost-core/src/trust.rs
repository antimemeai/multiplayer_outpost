//! Canonical `mp-safety-v1` Crockford Base32 Safety Numbers, 5-link P2P admission
//! verification (`TLS RPK -> snapshot -> CWT.cnf -> CWT.iss -> PINNED root_pubkey`),
//! and symmetric relay policy compatibility.

use core::fmt;

use mp_protocol::{
    AccountId, CwtError, DeviceId, Ed25519PubKey, PartyMemberRecord, RelayPolicy, sha256,
    verify_device_cwt,
};

const SAFETY_DOMAIN_SEP: &[u8] = b"mp-safety-v1:";
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn api_authority_hash(authority: &str) -> [u8; 8] {
    let lower = authority.to_ascii_lowercase();
    let digest = sha256(lower.as_bytes());
    let mut out = [0u8; 8];
    if let Some(first8) = digest.get(0..8) {
        out.copy_from_slice(first8);
    }
    out
}

/// Computes canonical `mp-safety-v1` Safety Number:
/// first 20 bytes of `SHA-256("mp-safety-v1:" || account_id_le64 || root_pubkey[32])`
/// encoded as 32 uppercase Crockford Base32 chars grouped as `8 x 4` (`XXXX-XXXX-...`).
pub fn compute_safety_number(account_id: u64, root_pubkey: &[u8; 32]) -> String {
    let mut input = [0u8; 13 + 8 + 32];
    if let Some(s) = input.get_mut(0..13) {
        s.copy_from_slice(SAFETY_DOMAIN_SEP);
    }
    if let Some(s) = input.get_mut(13..21) {
        s.copy_from_slice(&account_id.to_le_bytes());
    }
    if let Some(s) = input.get_mut(21..53) {
        s.copy_from_slice(root_pubkey);
    }
    let digest = sha256(&input);

    let mut out = String::with_capacity(39);
    for group in 0..32usize {
        if group > 0 && group % 4 == 0 {
            out.push('-');
        }
        let bit_pos = group * 5;
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos % 8;
        let b0 = u16::from(digest.get(byte_idx).copied().unwrap_or(0));
        let b1 = u16::from(digest.get(byte_idx + 1).copied().unwrap_or(0));
        let pair = (b0 << 8) | b1;
        let shift = 11 - bit_off;
        let val = ((pair >> shift) & 0x1F) as usize;
        let ch = CROCKFORD_ALPHABET.get(val).copied().unwrap_or(b'0');
        out.push(char::from(ch));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyNumberError {
    InvalidLength,
    InvalidCharacter,
}

impl fmt::Display for SafetyNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SafetyNumberError {}

pub fn normalize_safety_number(input: &str) -> Result<[u8; 32], SafetyNumberError> {
    let mut out = [0u8; 32];
    let mut count = 0usize;
    for b in input.bytes() {
        if b == b'-' || b.is_ascii_whitespace() {
            continue;
        }
        let mapped = match b.to_ascii_uppercase() {
            b'I' | b'L' => b'1',
            b'O' => b'0',
            c if CROCKFORD_ALPHABET.contains(&c) => c,
            _ => return Err(SafetyNumberError::InvalidCharacter),
        };
        let slot = out.get_mut(count).ok_or(SafetyNumberError::InvalidLength)?;
        *slot = mapped;
        count += 1;
    }
    if count != 32 {
        return Err(SafetyNumberError::InvalidLength);
    }
    Ok(out)
}

pub fn verify_safety_number(account_id: u64, root_pubkey: &[u8; 32], candidate: &str) -> bool {
    let expected_str = compute_safety_number(account_id, root_pubkey);
    let Ok(expected) = normalize_safety_number(&expected_str) else {
        return false;
    };
    let Ok(actual) = normalize_safety_number(candidate) else {
        return false;
    };
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(actual.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrustLookup {
    PinnedTrusted { root_pubkey: Ed25519PubKey },
    Revoked,
    Unpinned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    Admitted {
        account_id: AccountId,
        device_id: DeviceId,
        cwt_exp_s: i64,
    },
    UnpinnedFirstContact {
        account_id: AccountId,
        root_pubkey: Ed25519PubKey,
        safety_number: String,
        cwt_exp_s: i64,
    },
    KeyMismatch {
        account_id: AccountId,
        expected_root: Ed25519PubKey,
        observed_root: Ed25519PubKey,
    },
    RejectRevoked,
    RejectTlsRpkMismatch,
    RejectCwtInvalid(CwtError),
}

/// Enforces the exact 5-link admission chain using ONLY the local system clock (`now_local_s`):
/// `TLS 1.3 RPK == snapshot.device_pubkey == CWT.cnf.x` AND
/// `CWT.iss == hex(sha256(PINNED_root_pubkey))` verified under `PINNED_root_pubkey`.
pub fn evaluate_peer_admission(
    tls_rpk: &Ed25519PubKey,
    member: &PartyMemberRecord,
    trust: &PeerTrustLookup,
    now_local_s: i64,
) -> AdmissionDecision {
    // Link 1: TLS 1.3 Mutual RPK must equal snapshot device_pubkey
    if tls_rpk != &member.device_pubkey {
        return AdmissionDecision::RejectTlsRpkMismatch;
    }

    match trust {
        PeerTrustLookup::Revoked => AdmissionDecision::RejectRevoked,
        PeerTrustLookup::PinnedTrusted {
            root_pubkey: pinned_root,
        } => {
            // Link 5: snapshot root_pubkey must match pinned root_pubkey
            if &member.root_pubkey != pinned_root {
                return AdmissionDecision::KeyMismatch {
                    account_id: member.account_id,
                    expected_root: *pinned_root,
                    observed_root: member.root_pubkey,
                };
            }
            // Links 2, 3 & 4: verify CWT signature + iss + exp + cnf.x == tls_rpk strictly under PINNED root_pubkey
            let claims = match verify_device_cwt(
                &member.device_cwt,
                pinned_root,
                Some(tls_rpk),
                now_local_s,
            ) {
                Ok(c) => c,
                Err(e) => return AdmissionDecision::RejectCwtInvalid(e),
            };
            if &claims.device_pubkey != tls_rpk {
                return AdmissionDecision::RejectCwtInvalid(CwtError::DeviceKeyMismatch);
            }
            AdmissionDecision::Admitted {
                account_id: member.account_id,
                device_id: member.device_id,
                cwt_exp_s: claims.exp,
            }
        }
        PeerTrustLookup::Unpinned => {
            let claims = match verify_device_cwt(
                &member.device_cwt,
                &member.root_pubkey,
                Some(tls_rpk),
                now_local_s,
            ) {
                Ok(c) => c,
                Err(e) => return AdmissionDecision::RejectCwtInvalid(e),
            };
            if &claims.device_pubkey != tls_rpk {
                return AdmissionDecision::RejectCwtInvalid(CwtError::DeviceKeyMismatch);
            }
            let safety_number =
                compute_safety_number(member.account_id.get(), &member.root_pubkey);
            AdmissionDecision::UnpinnedFirstContact {
                account_id: member.account_id,
                root_pubkey: member.root_pubkey,
                safety_number,
                cwt_exp_s: claims.exp,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPolicyCompatError {
    ForceConflictsWithNoRelays,
}

impl fmt::Display for RelayPolicyCompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RelayPolicyCompatError {}

/// Symmetric join-time relay policy matrix: `local_policy` is a non-downgradeable floor,
/// and `ForceRelays <-> NoRelays` is refused in BOTH directions.
pub const fn effective_relay_policy(
    local_policy: RelayPolicy,
    party_policy: RelayPolicy,
) -> Result<RelayPolicy, RelayPolicyCompatError> {
    match (local_policy, party_policy) {
        (RelayPolicy::ForceRelays, RelayPolicy::NoRelays)
        | (RelayPolicy::NoRelays, RelayPolicy::ForceRelays) => {
            Err(RelayPolicyCompatError::ForceConflictsWithNoRelays)
        }
        (RelayPolicy::ForceRelays, _) | (_, RelayPolicy::ForceRelays) => {
            Ok(RelayPolicy::ForceRelays)
        }
        (RelayPolicy::NoRelays, _) | (_, RelayPolicy::NoRelays) => Ok(RelayPolicy::NoRelays),
        (RelayPolicy::AllowRelays, RelayPolicy::AllowRelays) => Ok(RelayPolicy::AllowRelays),
    }
}
