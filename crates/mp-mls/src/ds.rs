//! Delivery Service (`PartyDO`) OpenMLS `PublicGroup` engine (`MpMlsPublicDs`, Spec v3.1 §5):
//! - Epoch-0 bootstrap from creator's signed `GroupInfo` (accepting RFC 9420 empty 0-byte
//!   `confirmed_transcript_hash`, requiring exact 32-byte `confirmation_tag`, `0xFF01`, `0xFF02`).
//! - Signing key custody kept strictly outside `MpMlsPublicDs` and snapshots (`ds_privkey` passed
//!   ONLY into `create_external_remove` and verified against `ds_pubkey`).
//! - Synchronous External `Remove` proposal signing (`SenderExtensionIndex(0)`) that immediately
//!   aborts any in-flight tentative commit and bumps `roster_rev`.
//! - Tentative Commit staging with wall-clock admission checks on every `Add`, `Update`, and
//!   changed `UpdatePath` leaf, surviving-electorate computation, and Spec v3.1 `"mp-mls-ack-v1:"`
//!   account-scoped Quorum Ack collection.
//! - Pre-finalization `roster_rev` and pending-removal exclusion recheck, timeout promotion when
//!   `>= 1` matching `OK` arrived with zero `REJECT`s, and 2,000-epoch catch-up horizon pruning.
//! - Bounded-allocation binary snapshot export/import persisting tentative commit state & votes.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use openmls::prelude::{
    ConfirmationTag, ExtensionType, ExternalProposal, GroupId, LeafNodeIndex, MlsMessageBodyIn,
    MlsMessageIn, ProcessedMessageContent, ProposalStore, ProtocolMessage, PublicGroup, Sender,
    SenderExtensionIndex, StagedCommit,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{types::SignatureScheme, OpenMlsProvider};
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize, VLBytes};

use crate::crypto::{
    sha256, sign_ed25519, validate_ed25519_pubkey_strict, verify_ed25519_strict, Ed25519PubKey,
    Ed25519Sig, MpCryptoProvider, Sha256Digest,
};
use crate::error::MpMlsError;
use crate::identity::{check_safe_counter, check_safe_id};
use crate::policy::{
    build_ds_external_sender, extract_public_group_leaves, validate_commit_deterministic,
    validate_key_package_admission, validate_leaf_node_credential, validate_tree_invariants,
    MpGroupId, MpRoomPolicyExtV1, TreeLeafInfo, MP_CIPHERSUITE, MP_GROUP_ID_LEN,
    MP_LEAF_DEVICE_LIST_EXT_TYPE, MP_ROOM_POLICY_EXT_TYPE,
};

/// Spec v3.1 §5.2 exact ACK signature domain separator.
pub const COMMIT_ACK_DOMAIN_SEP: &[u8] = b"mp-mls-ack-v1:";
/// Spec v3.1 §5.2 exact epoch_authenticator hash domain separator.
pub const ACK_AUTH_HASH_DOMAIN_SEP: &[u8] = b"mp-mls-ack-auth-v1:";
/// Maximum catch-up epoch horizon retained in `commit_log` and `proposal_log` (Spec v3.1 §5.1).
pub const MAX_MLS_CATCHUP_EPOCHS: u64 = 2_000;
/// Maximum catch-up commits returned per page (Spec v3.1 §5.1).
pub const MAX_CATCHUP_PAGE_LIMIT: usize = 32;

const SNAPSHOT_VERSION: u8 = 2;

/// Extracts exact 32-byte MAC from an OpenMLS `ConfirmationTag` (suite `0x0001` HMAC-SHA256).
pub(crate) fn confirmation_tag_32(tag: &ConfirmationTag) -> Result<[u8; 32], MpMlsError> {
    let encoded = tag
        .tls_serialize_detached()
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
    let vl = VLBytes::tls_deserialize_exact_bytes(&encoded)
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
    vl.as_slice()
        .try_into()
        .map_err(|_| MpMlsError::InvalidLength {
            expected: 32,
            got: vl.as_slice().len(),
        })
}

/// Hashes RFC 9420 `epoch_authenticator` before sending in `CommitAckV1` so the DS
/// never observes raw `epoch_authenticator` bytes (Spec v3.1 §5.2).
pub fn hash_epoch_authenticator_for_ack(epoch_authenticator: &[u8]) -> Sha256Digest {
    let mut input = Vec::with_capacity(ACK_AUTH_HASH_DOMAIN_SEP.len() + epoch_authenticator.len());
    input.extend_from_slice(ACK_AUTH_HASH_DOMAIN_SEP);
    input.extend_from_slice(epoch_authenticator);
    sha256(&input)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AckStatus {
    Ok = 1,
    Reject = 2,
}

impl AckStatus {
    pub fn from_u8(v: u8) -> Result<Self, MpMlsError> {
        match v {
            1 => Ok(Self::Ok),
            2 => Ok(Self::Reject),
            other => Err(MpMlsError::InvalidEnumValue {
                field: "ack_status",
                value: u64::from(other),
            }),
        }
    }
}

/// Member-signed tentative Commit ack (Spec v3.1 §5.2):
/// Signed bytes: `"mp-mls-ack-v1:" || group_id(24) || parent_epoch(8) || target_epoch(8) || commit_sha256(32) || status(1) || ack_auth_hash(32)`
/// (`ack_auth_hash = [0u8; 32]` on `Reject`, or `SHA-256("mp-mls-ack-auth-v1:" || epoch_authenticator)` on `Ok`).
/// `account_id` and `device_id` are routing identifiers authenticated against the active leaf in `PublicGroup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitAckV1 {
    pub group_id: [u8; MP_GROUP_ID_LEN],
    pub parent_epoch: u64,
    pub target_epoch: u64,
    pub commit_sha256: Sha256Digest,
    pub account_id: u64,
    pub device_id: u64,
    pub status: AckStatus,
    pub epoch_auth_hash: Option<Sha256Digest>,
    pub ack_sig: Ed25519Sig,
}

impl CommitAckV1 {
    fn signed_message(&self) -> Result<Vec<u8>, MpMlsError> {
        check_safe_counter(self.parent_epoch)?;
        check_safe_counter(self.target_epoch)?;
        check_safe_id(self.account_id)?;
        check_safe_id(self.device_id)?;
        if self.parent_epoch.checked_add(1) != Some(self.target_epoch) {
            return Err(MpMlsError::InvalidCommitAck(
                "target_epoch must equal parent_epoch + 1",
            ));
        }
        let auth_bytes: [u8; 32] = match (&self.status, &self.epoch_auth_hash) {
            (AckStatus::Ok, Some(h)) => *h,
            (AckStatus::Ok, None) => {
                return Err(MpMlsError::InvalidCommitAck(
                    "OK ack must carry 32-byte epoch_auth_hash",
                ));
            }
            (AckStatus::Reject, None) => [0u8; 32],
            (AckStatus::Reject, Some(_)) => {
                return Err(MpMlsError::InvalidCommitAck(
                    "REJECT ack must not carry epoch_auth_hash",
                ));
            }
        };
        let mut msg = Vec::with_capacity(COMMIT_ACK_DOMAIN_SEP.len() + 24 + 8 + 8 + 32 + 1 + 32);
        msg.extend_from_slice(COMMIT_ACK_DOMAIN_SEP);
        msg.extend_from_slice(&self.group_id);
        msg.extend_from_slice(&self.parent_epoch.to_be_bytes());
        msg.extend_from_slice(&self.target_epoch.to_be_bytes());
        msg.extend_from_slice(&self.commit_sha256);
        msg.push(self.status as u8);
        msg.extend_from_slice(&auth_bytes);
        Ok(msg)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        group_id: [u8; MP_GROUP_ID_LEN],
        parent_epoch: u64,
        target_epoch: u64,
        commit_sha256: Sha256Digest,
        account_id: u64,
        device_id: u64,
        status: AckStatus,
        epoch_auth_hash: Option<Sha256Digest>,
        device_sk: &SigningKey,
    ) -> Result<Self, MpMlsError> {
        let mut ack = Self {
            group_id,
            parent_epoch,
            target_epoch,
            commit_sha256,
            account_id,
            device_id,
            status,
            epoch_auth_hash,
            ack_sig: [0u8; 64],
        };
        let msg = ack.signed_message()?;
        ack.ack_sig = sign_ed25519(device_sk, &msg);
        Ok(ack)
    }

    pub fn verify(&self, expected_device_sig_pk: &Ed25519PubKey) -> Result<(), MpMlsError> {
        let msg = self.signed_message()?;
        verify_ed25519_strict(expected_device_sig_pk, &msg, &self.ack_sig)
    }
}

/// Computes RFC 9420 §8.2 `interim_transcript_hash`:
/// `SHA-256(confirmed_transcript_hash || VLBytes(confirmation_tag))`.
pub fn compute_interim_transcript_hash(
    confirmed_transcript_hash: &[u8],
    confirmation_tag: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(confirmed_transcript_hash.len() + 1 + 32);
    input.extend_from_slice(confirmed_transcript_hash);
    input.push(32u8); // TLS varint for 32 (< 64)
    input.extend_from_slice(confirmation_tag);
    sha256(&input)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProposalRecord {
    pub epoch: u64,
    pub proposal_ref: Vec<u8>,
    pub target_leaf_index: Option<u32>,
    pub proposal_blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedCommitRecord {
    pub epoch: u64,
    pub committer_device_id: u64,
    pub commit_sha256: Sha256Digest,
    pub confirmed_transcript_hash: Vec<u8>,
    pub interim_transcript_hash: [u8; 32],
    pub commit_blob: Vec<u8>,
    pub referenced_proposal_refs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchupCommitBundle {
    pub epoch: u64,
    pub commit_blob: Vec<u8>,
    pub referenced_proposals: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumOutcome {
    Pending {
        acked_accounts: usize,
        eligible_online_accounts: usize,
    },
    Finalized {
        new_epoch: u64,
        confirmed_transcript_hash: Vec<u8>,
        interim_transcript_hash: [u8; 32],
    },
    /// Rejected, conflicting auth hash, concurrent revocation, or timeout with 0 OKs:
    /// tentative commit is discarded and committer re-election is triggered WITHOUT auto-removing
    /// the committer (Spec v3.1 §5.2).
    Discarded {
        committer_device_id: u64,
        reason: &'static str,
    },
}

struct TentativeCommitState {
    parent_epoch: u64,
    target_epoch: u64,
    committer_account_id: u64,
    committer_device_id: u64,
    roster_rev: u64,
    removed_leaf_indices: BTreeSet<u32>,
    /// Leaf indices present in the resulting tree after this Commit.
    next_leaf_indices: BTreeSet<u32>,
    /// Surviving `(account_id, device_id)` pairs eligible to vote on this Commit
    /// (present in BOTH parent epoch and resulting tree, excluding committer's account).
    surviving_voter_devices: BTreeSet<(u64, u64)>,
    /// Distinct online surviving accounts expected to vote before early finalization.
    eligible_online_accounts: BTreeSet<u64>,
    commit_sha256: Sha256Digest,
    commit_blob: Vec<u8>,
    referenced_proposal_refs: Vec<Vec<u8>>,
    staged_commit: StagedCommit,
    staged_confirmed_hash: Vec<u8>,
    staged_interim_hash: [u8; 32],
    deadline_s: u64,
    /// Map of `account_id -> epoch_auth_hash` for verified `OK` acks (sorted for canonical snapshot).
    ok_acks_by_account: BTreeMap<u64, Sha256Digest>,
}

/// Delivery Service (`PartyDO`) `PublicGroup` oracle and state machine.
/// Holds ONLY public state (`ds_pubkey`, NEVER `ds_privkey`!).
pub struct MpMlsPublicDs {
    party_id: u64,
    group_id: [u8; MP_GROUP_ID_LEN],
    ds_pubkey: Ed25519PubKey,
    provider: MpCryptoProvider,
    public_group: PublicGroup,
    interim_transcript_hash: [u8; 32],
    roster_rev: u64,
    mls_rekey_required: bool,
    pending_removal_leaves: BTreeSet<u32>,
    /// Proposal log (`proposal_ref -> record`) retained across the 2,000-epoch catch-up horizon.
    proposal_log: BTreeMap<Vec<u8>, StoredProposalRecord>,
    /// Finalized commit log keyed by resulting epoch (`1, 2, ...`), bounded to 2,000 epochs.
    commit_log: BTreeMap<u64, FinalizedCommitRecord>,
    tentative: Option<TentativeCommitState>,
}

impl MpMlsPublicDs {
    fn current_leaves_map(&self) -> Result<BTreeMap<u32, TreeLeafInfo>, MpMlsError> {
        extract_public_group_leaves(&self.public_group)
    }

    /// Epoch-0 bootstrap from creator's signed `GroupInfo` (with inline `RatchetTreeExtension`).
    /// Explicitly accepts RFC 9420 empty 0-byte `confirmed_transcript_hash` at epoch 0, requires
    /// exact 32-byte `confirmation_tag`, `0xFF01`, `0xFF02`, and valid creator leaf `0xFF02` (§5.1).
    pub fn bootstrap_epoch0(
        party_id: u64,
        expected_group_id: [u8; MP_GROUP_ID_LEN],
        ds_pubkey: Ed25519PubKey,
        group_info_bytes: &[u8],
    ) -> Result<Self, MpMlsError> {
        check_safe_id(party_id)?;
        validate_ed25519_pubkey_strict(&ds_pubkey)?;
        let parsed_gid = MpGroupId::parse(&expected_group_id)?;
        if parsed_gid.party_id != party_id {
            return Err(MpMlsError::InvalidGroupId);
        }

        let mls_msg = MlsMessageIn::tls_deserialize_exact_bytes(group_info_bytes)
            .map_err(|e| MpMlsError::OpenMls(format!("GroupInfo decode failed: {e}")))?;
        let verifiable_gi = match mls_msg.extract() {
            MlsMessageBodyIn::GroupInfo(gi) => gi,
            _ => {
                return Err(MpMlsError::InvalidBootstrap(
                    "expected MlsMessageBodyIn::GroupInfo",
                ));
            }
        };

        let ctx = verifiable_gi.group_context();
        if ctx.group_id().as_slice() != expected_group_id {
            return Err(MpMlsError::InvalidGroupId);
        }
        if ctx.epoch().as_u64() != 0 {
            return Err(MpMlsError::InvalidBootstrap("bootstrap epoch must be 0"));
        }
        // RFC 9420 §8.2: epoch-0 confirmed_transcript_hash is empty (0 bytes).
        if !ctx.confirmed_transcript_hash().is_empty() {
            return Err(MpMlsError::InvalidBootstrap(
                "epoch-0 confirmed_transcript_hash must be 0 bytes",
            ));
        }
        if ctx.ciphersuite() != MP_CIPHERSUITE {
            return Err(MpMlsError::InvalidBootstrap("unsupported ciphersuite"));
        }

        let expected_ds_sender = build_ds_external_sender(party_id, &ds_pubkey)?;
        let ext_senders = ctx
            .extensions()
            .external_senders()
            .ok_or(MpMlsError::InvalidBootstrap(
                "missing ExternalSendersExtension",
            ))?;
        if ext_senders.len() != 1 || ext_senders[0] != expected_ds_sender {
            return Err(MpMlsError::InvalidBootstrap(
                "ExternalSendersExtension must contain exact single PartyDO DS key",
            ));
        }

        let req_caps =
            ctx.extensions()
                .required_capabilities()
                .ok_or(MpMlsError::InvalidBootstrap(
                    "missing RequiredCapabilitiesExtension",
                ))?;
        if !req_caps
            .extension_types()
            .contains(&ExtensionType::Unknown(MP_ROOM_POLICY_EXT_TYPE))
            || !req_caps
                .extension_types()
                .contains(&ExtensionType::Unknown(MP_LEAF_DEVICE_LIST_EXT_TYPE))
        {
            return Err(MpMlsError::InvalidBootstrap(
                "RequiredCapabilitiesExtension must include both 0xFF01 and 0xFF02",
            ));
        }

        let policy = MpRoomPolicyExtV1::from_group_context(ctx)?;
        if policy.party_id != party_id {
            return Err(MpMlsError::InvalidBootstrap("policy party_id mismatch"));
        }

        let ratchet_tree = verifiable_gi
            .extensions()
            .ratchet_tree()
            .ok_or(MpMlsError::InvalidBootstrap(
                "epoch-0 GroupInfo must embed RatchetTreeExtension",
            ))?
            .ratchet_tree()
            .clone();

        let provider = MpCryptoProvider::new();
        let (public_group, _verified_gi) = PublicGroup::from_external(
            provider.crypto(),
            provider.storage(),
            ratchet_tree,
            verifiable_gi,
            ProposalStore::new(),
        )
        .map_err(|e| MpMlsError::OpenMls(format!("PublicGroup::from_external failed: {e}")))?;

        let leaves_map = extract_public_group_leaves(&public_group)?;
        let leaves: Vec<TreeLeafInfo> = leaves_map.values().cloned().collect();
        if leaves.len() != 1 {
            return Err(MpMlsError::InvalidBootstrap(
                "epoch-0 bootstrap must have exactly 1 creator leaf",
            ));
        }
        if !policy.is_host(leaves[0].cred.binding.body.account_id) {
            return Err(MpMlsError::InvalidBootstrap(
                "creator account must be in host_account_ids",
            ));
        }
        validate_tree_invariants(&leaves, &policy)?;

        // Enforce exact 32-byte confirmation_tag at epoch-0 bootstrap (Astra §5).
        let gi_tag = confirmation_tag_32(public_group.confirmation_tag())?;
        let interim_transcript_hash = compute_interim_transcript_hash(
            public_group.group_context().confirmed_transcript_hash(),
            &gi_tag,
        );

        Ok(Self {
            party_id,
            group_id: expected_group_id,
            ds_pubkey,
            provider,
            public_group,
            interim_transcript_hash,
            roster_rev: 0,
            mls_rekey_required: false,
            pending_removal_leaves: BTreeSet::new(),
            proposal_log: BTreeMap::new(),
            commit_log: BTreeMap::new(),
            tentative: None,
        })
    }

    pub fn party_id(&self) -> u64 {
        self.party_id
    }

    pub fn group_id(&self) -> [u8; MP_GROUP_ID_LEN] {
        self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.public_group.group_context().epoch().as_u64()
    }

    pub fn roster_rev(&self) -> u64 {
        self.roster_rev
    }

    pub fn confirmed_transcript_hash(&self) -> &[u8] {
        self.public_group.group_context().confirmed_transcript_hash()
    }

    pub fn interim_transcript_hash(&self) -> [u8; 32] {
        self.interim_transcript_hash
    }

    pub fn mls_rekey_required(&self) -> bool {
        self.mls_rekey_required
    }

    pub fn has_tentative_commit(&self) -> bool {
        self.tentative.is_some()
    }

    pub fn public_group(&self) -> &PublicGroup {
        &self.public_group
    }

    pub fn room_policy(&self) -> Result<MpRoomPolicyExtV1, MpMlsError> {
        MpRoomPolicyExtV1::from_group_context(self.public_group.group_context())
    }

    pub fn proposal_count(&self) -> usize {
        self.proposal_log.len()
    }

    pub fn commit_log_len(&self) -> usize {
        self.commit_log.len()
    }

    pub fn ds_pubkey(&self) -> Ed25519PubKey {
        self.ds_pubkey
    }

    /// Synchronously signs an RFC 9420 `PublicMessage` External `Remove` proposal using
    /// caller-supplied `ds_privkey` (kept out of `MpMlsPublicDs` snapshots!), aborts any in-flight
    /// tentative commit, increments `roster_rev`, ingests the proposal into `PublicGroup`, appends
    /// to `proposal_log`, and raises `mls_rekey_required` (Spec v3.1 §5.2 / §6.3, Fable H6).
    pub fn create_external_remove(
        &mut self,
        target_leaf: LeafNodeIndex,
        ds_privkey: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>), MpMlsError> {
        let derived_pk = SigningKey::from_bytes(ds_privkey).verifying_key().to_bytes();
        if derived_pk != self.ds_pubkey {
            return Err(MpMlsError::InvalidPublicKey);
        }
        if self.public_group.leaf(target_leaf).is_none() {
            return Err(MpMlsError::ForbiddenProposal(
                "External Remove target leaf does not exist",
            ));
        }

        // Spec v3.1 §6.3 / Fable H6: abort any in-flight tentative commit and bump roster_rev!
        self.tentative = None;
        self.roster_rev = self.roster_rev.saturating_add(1);

        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            ds_privkey.to_vec(),
            self.ds_pubkey.to_vec(),
        );
        let epoch = self.public_group.group_context().epoch();
        let msg_out = ExternalProposal::new_remove::<MpCryptoProvider>(
            target_leaf,
            self.public_group.group_id().clone(),
            epoch,
            &signer,
            SenderExtensionIndex::new(0),
        )
        .map_err(|e| MpMlsError::OpenMls(format!("ExternalProposal::new_remove failed: {e}")))?;

        let proposal_blob = msg_out
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(format!("serialize proposal failed: {e}")))?;

        // Process through PublicGroup to verify signature & compute canonical ProposalRef.
        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(&proposal_blob)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        let proto_msg: ProtocolMessage = msg_in
            .try_into_protocol_message()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        let processed = self
            .public_group
            .process_message(self.provider.crypto(), proto_msg)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        let queued = match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(qp) => *qp,
            _ => {
                return Err(MpMlsError::OpenMls(
                    "expected ProposalMessage from External Remove".into(),
                ));
            }
        };

        let proposal_ref = queued
            .proposal_reference_ref()
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        self.public_group
            .add_proposal(self.provider.storage(), queued)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        self.proposal_log.insert(
            proposal_ref.clone(),
            StoredProposalRecord {
                epoch: epoch.as_u64(),
                proposal_ref: proposal_ref.clone(),
                target_leaf_index: Some(target_leaf.u32()),
                proposal_blob: proposal_blob.clone(),
            },
        );
        self.pending_removal_leaves.insert(target_leaf.u32());
        self.mls_rekey_required = true;

        Ok((proposal_ref, proposal_blob))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_tentative_state(
        &self,
        commit_bytes: &[u8],
        committer_device_id: u64,
        online_surviving_accounts: &[u64],
        now_s: Option<u64>,
        deadline_s: u64,
        roster_rev: u64,
        ok_acks_by_account: BTreeMap<u64, Sha256Digest>,
    ) -> Result<TentativeCommitState, MpMlsError> {
        check_safe_id(committer_device_id)?;
        let prev_leaves = self.current_leaves_map()?;
        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(commit_bytes)
            .map_err(|e| MpMlsError::OpenMls(format!("commit decode failed: {e}")))?;
        let proto_msg: ProtocolMessage = msg_in
            .try_into_protocol_message()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        // `PublicGroup::process_message` takes `&self` and does NOT mutate live state.
        let processed = self
            .public_group
            .process_message(self.provider.crypto(), proto_msg)
            .map_err(|e| {
                MpMlsError::OpenMls(format!("PublicGroup::process_message failed: {e}"))
            })?;

        let sender = processed.sender().clone();
        let staged_commit = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(sc) => *sc,
            _ => {
                return Err(MpMlsError::TentativeCommitError(
                    "expected StagedCommitMessage",
                ));
            }
        };

        let target_epoch = staged_commit.epoch().as_u64();
        check_safe_counter(target_epoch)?;

        // Run shared 100% deterministic commit validator (§3.3 & §4.1).
        let (next_policy, next_leaves) = validate_commit_deterministic(
            &sender,
            &staged_commit,
            self.public_group.group_context(),
            &prev_leaves,
        )?;

        let Sender::Member(committer_leaf_idx) = sender else {
            return Err(MpMlsError::ForbiddenProposal("non-member committer"));
        };
        let committer_info = prev_leaves
            .get(&committer_leaf_idx.u32())
            .ok_or(MpMlsError::ForbiddenProposal("committer leaf missing"))?;
        if committer_info.cred.binding.body.device_id != committer_device_id {
            return Err(MpMlsError::ForbiddenProposal(
                "committer_device_id does not match authenticated MLS commit sender",
            ));
        }

        // Wall-clock admission checks at staging time (Spec v3.1 §3.3.2 / Fable H1):
        // check EVERY Add KeyPackage AND EVERY Update/UpdatePath leaf whose binding or list changed!
        if let Some(now) = now_s {
            check_safe_counter(now)?;
            for add in staged_commit.add_proposals() {
                validate_key_package_admission(
                    add.add_proposal().key_package(),
                    now,
                    &next_policy,
                    None,
                    None,
                )?;
            }
            for upd in staged_commit.update_proposals() {
                let Sender::Member(idx) = upd.sender() else {
                    continue;
                };
                let (next_cred, next_list) =
                    validate_leaf_node_credential(upd.update_proposal().leaf_node())?;
                let changed = prev_leaves.get(&idx.u32()).is_none_or(|p| {
                    p.cred != next_cred || p.device_list != next_list
                });
                if changed {
                    next_cred.binding.verify_at_admission(now)?;
                    next_list.verify_at_admission(&next_cred.binding.body.root_pubkey, now)?;
                }
            }
            if let Some(path_leaf) = staged_commit.update_path_leaf_node() {
                let (path_cred, path_list) = validate_leaf_node_credential(path_leaf)?;
                let changed = path_cred != committer_info.cred
                    || path_list != committer_info.device_list;
                if changed {
                    path_cred.binding.verify_at_admission(now)?;
                    path_list.verify_at_admission(&path_cred.binding.body.root_pubkey, now)?;
                }
            }
        }

        // Collect removed leaves and resulting tree leaf indices; verify NO pending removal survives!
        let mut removed_leaf_indices = BTreeSet::new();
        for rem in staged_commit.remove_proposals() {
            removed_leaf_indices.insert(rem.remove_proposal().removed().u32());
        }
        let next_leaf_indices: BTreeSet<u32> = next_leaves.keys().copied().collect();
        for pending_leaf in &self.pending_removal_leaves {
            if next_leaf_indices.contains(pending_leaf)
                || !removed_leaf_indices.contains(pending_leaf)
            {
                return Err(MpMlsError::TentativeCommitError(
                    "commit failed to exclude all pending DS removal leaves",
                ));
            }
        }

        // Compute surviving electorate: devices present in BOTH parent epoch AND resulting tree,
        // excluding committer's account (removing 1 device preserves surviving sibling devices!).
        let committer_account_id = committer_info.cred.binding.body.account_id;
        let mut surviving_voter_devices = BTreeSet::new();
        let mut all_surviving_accounts = BTreeSet::new();
        for (&idx, prev_leaf) in &prev_leaves {
            if removed_leaf_indices.contains(&idx) {
                continue;
            }
            let acct = prev_leaf.cred.binding.body.account_id;
            if acct == committer_account_id {
                continue;
            }
            if next_leaves.contains_key(&idx) {
                surviving_voter_devices.insert((acct, prev_leaf.cred.binding.body.device_id));
                all_surviving_accounts.insert(acct);
            }
        }
        let mut eligible_online_accounts = BTreeSet::new();
        for &acct in online_surviving_accounts {
            if all_surviving_accounts.contains(&acct) {
                eligible_online_accounts.insert(acct);
            }
        }

        // Collect referenced proposal refs present in our proposal log.
        let mut referenced_proposal_refs = Vec::new();
        for qp in staged_commit.queued_proposals() {
            let pref = qp
                .proposal_reference_ref()
                .tls_serialize_detached()
                .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
            if self.proposal_log.contains_key(&pref) {
                referenced_proposal_refs.push(pref);
            }
        }

        let staged_confirmed_hash = staged_commit
            .group_context()
            .confirmed_transcript_hash()
            .to_vec();
        let confirmation_tag = extract_commit_confirmation_tag(commit_bytes)?;
        let staged_interim_hash =
            compute_interim_transcript_hash(&staged_confirmed_hash, &confirmation_tag);

        Ok(TentativeCommitState {
            parent_epoch: self.epoch(),
            target_epoch,
            committer_account_id,
            committer_device_id,
            roster_rev,
            removed_leaf_indices,
            next_leaf_indices,
            surviving_voter_devices,
            eligible_online_accounts,
            commit_sha256: sha256(commit_bytes),
            commit_blob: commit_bytes.to_vec(),
            referenced_proposal_refs,
            staged_commit,
            staged_confirmed_hash,
            staged_interim_hash,
            deadline_s,
            ok_acks_by_account,
        })
    }

    /// Validates an incoming `Commit` (including wall-clock admission on Adds & changed Updates)
    /// and enters tentative stage, computing the surviving electorate from the actual resulting tree.
    /// Immediately finalizes ONLY if zero other surviving accounts are online (`eligible_online_accounts.is_empty()`).
    pub fn stage_tentative_commit(
        &mut self,
        commit_bytes: &[u8],
        committer_device_id: u64,
        online_surviving_accounts: &[u64],
        now_s: u64,
        timeout_s: u64,
    ) -> Result<QuorumOutcome, MpMlsError> {
        check_safe_counter(now_s)?;
        if self.tentative.is_some() {
            return Err(MpMlsError::TentativeCommitError(
                "a tentative commit is already in flight",
            ));
        }
        let deadline_s = now_s.saturating_add(timeout_s);
        let state = self.build_tentative_state(
            commit_bytes,
            committer_device_id,
            online_surviving_accounts,
            Some(now_s),
            deadline_s,
            self.roster_rev,
            BTreeMap::new(),
        )?;

        let eligible_count = state.eligible_online_accounts.len();
        self.tentative = Some(state);

        if eligible_count == 0 {
            self.finalize_tentative()
        } else {
            Ok(QuorumOutcome::Pending {
                acked_accounts: 0,
                eligible_online_accounts: eligible_count,
            })
        }
    }

    /// Records a member's signed `CommitAckV1` (`"mp-mls-ack-v1:"`).
    /// - Aggregates per distinct surviving account (excluding committer & fully-removed accounts;
    ///   surviving sibling devices of a partially-removed account remain eligible voters!).
    /// - Waits until ALL `eligible_online_accounts` have voted OR `deadline_s` elapses.
    /// - Any device `REJECT` or `epoch_auth_hash` disagreement immediately discards without
    ///   auto-removing the committer!
    /// - On timeout (`now_s > deadline_s`), promotes to `Finalized` if `>= 1` matching `OK` arrived
    ///   with zero `REJECT`s; otherwise discards (Spec v3.1 §5.2).
    pub fn record_commit_ack(
        &mut self,
        ack: &CommitAckV1,
        now_s: u64,
    ) -> Result<QuorumOutcome, MpMlsError> {
        check_safe_counter(now_s)?;
        let Some(ref tentative) = self.tentative else {
            return Err(MpMlsError::TentativeCommitError(
                "no tentative commit in flight",
            ));
        };

        if now_s > tentative.deadline_s {
            return self.resolve_overdue_tentative();
        }

        if ack.group_id != self.group_id
            || ack.parent_epoch != tentative.parent_epoch
            || ack.target_epoch != tentative.target_epoch
            || ack.commit_sha256 != tentative.commit_sha256
        {
            return Err(MpMlsError::InvalidCommitAck(
                "ack binding mismatch (group_id/parent_epoch/target_epoch/commit_sha256)",
            ));
        }

        if ack.account_id == tentative.committer_account_id {
            return Err(MpMlsError::InvalidCommitAck(
                "committer's account cannot vote in commit quorum",
            ));
        }
        if !tentative
            .surviving_voter_devices
            .contains(&(ack.account_id, ack.device_id))
        {
            return Err(MpMlsError::InvalidCommitAck(
                "ack signer is not a surviving member device eligible to vote on this commit",
            ));
        }

        // Authenticate signer device signature against current `PublicGroup` leaves.
        let leaves = self.current_leaves_map()?;
        let signer_leaf = leaves
            .values()
            .find(|l| {
                l.cred.binding.body.device_id == ack.device_id
                    && l.cred.binding.body.account_id == ack.account_id
            })
            .ok_or(MpMlsError::InvalidCommitAck(
                "ack signer is not an active member device in current epoch",
            ))?;
        ack.verify(&signer_leaf.cred.binding.body.mls_sig_pubkey)?;

        match ack.status {
            AckStatus::Reject => {
                let bad_dev = tentative.committer_device_id;
                self.tentative = None;
                Ok(QuorumOutcome::Discarded {
                    committer_device_id: bad_dev,
                    reason: "rejected by surviving non-committer member",
                })
            }
            AckStatus::Ok => {
                let auth_hash = ack
                    .epoch_auth_hash
                    .ok_or(MpMlsError::InvalidCommitAck("missing epoch_auth_hash"))?;

                let tentative_mut = self
                    .tentative
                    .as_mut()
                    .ok_or(MpMlsError::TentativeCommitError("missing tentative commit"))?;

                // Any mismatch within an account or across accounts discards cleanly!
                if let Some(existing) = tentative_mut.ok_acks_by_account.get(&ack.account_id) {
                    if *existing != auth_hash {
                        let bad_dev = tentative_mut.committer_device_id;
                        self.tentative = None;
                        return Ok(QuorumOutcome::Discarded {
                            committer_device_id: bad_dev,
                            reason: "conflicting epoch_auth_hash across devices of same account",
                        });
                    }
                } else {
                    if tentative_mut
                        .ok_acks_by_account
                        .values()
                        .any(|other| *other != auth_hash)
                    {
                        let bad_dev = tentative_mut.committer_device_id;
                        self.tentative = None;
                        return Ok(QuorumOutcome::Discarded {
                            committer_device_id: bad_dev,
                            reason: "conflicting epoch_auth_hash across accounts",
                        });
                    }
                    tentative_mut
                        .ok_acks_by_account
                        .insert(ack.account_id, auth_hash);
                }

                // Wait until ALL distinct eligible online accounts have voted!
                let all_online_voted = tentative_mut
                    .eligible_online_accounts
                    .iter()
                    .all(|acct| tentative_mut.ok_acks_by_account.contains_key(acct));
                let acked_accounts = tentative_mut.ok_acks_by_account.len();
                let eligible_online = tentative_mut.eligible_online_accounts.len();

                if all_online_voted && acked_accounts >= 1 {
                    self.finalize_tentative()
                } else {
                    Ok(QuorumOutcome::Pending {
                        acked_accounts,
                        eligible_online_accounts: eligible_online,
                    })
                }
            }
        }
    }

    /// Resolves a timed-out tentative commit per Spec v3.1 §5.2:
    /// - If `>= 1` surviving account submitted a matching `OK` and zero `REJECT`s arrived -> PROMOTE to `Finalized`.
    /// - If `0 OK`s arrived while surviving accounts were online -> DISCARD (without auto-removing committer).
    pub fn expire_tentative_if_overdue(
        &mut self,
        now_s: u64,
    ) -> Result<Option<QuorumOutcome>, MpMlsError> {
        check_safe_counter(now_s)?;
        if let Some(ref t) = self.tentative
            && now_s > t.deadline_s
        {
            return self.resolve_overdue_tentative().map(Some);
        }
        Ok(None)
    }

    fn resolve_overdue_tentative(&mut self) -> Result<QuorumOutcome, MpMlsError> {
        let Some(ref t) = self.tentative else {
            return Err(MpMlsError::TentativeCommitError(
                "no tentative commit in flight",
            ));
        };
        if !t.ok_acks_by_account.is_empty() {
            self.finalize_tentative()
        } else {
            let bad_dev = t.committer_device_id;
            self.tentative = None;
            Ok(QuorumOutcome::Discarded {
                committer_device_id: bad_dev,
                reason: "tentative commit deadline expired with 0 OK acks",
            })
        }
    }

    fn finalize_tentative(&mut self) -> Result<QuorumOutcome, MpMlsError> {
        let tentative = self
            .tentative
            .take()
            .ok_or(MpMlsError::TentativeCommitError("no tentative commit"))?;

        // Spec v3.1 §5.2 pre-finalization exclusion recheck:
        // verify roster_rev has not advanced AND resulting tree excludes every pending removal leaf!
        if tentative.roster_rev != self.roster_rev
            || self
                .pending_removal_leaves
                .iter()
                .any(|leaf| tentative.next_leaf_indices.contains(leaf))
        {
            self.mls_rekey_required = true;
            return Ok(QuorumOutcome::Discarded {
                committer_device_id: tentative.committer_device_id,
                reason: "aborted before finalization due to concurrent revocation or uncovered pending removal",
            });
        }

        self.public_group
            .merge_commit(self.provider.storage(), tentative.staged_commit)
            .map_err(|e| MpMlsError::OpenMls(format!("PublicGroup::merge_commit failed: {e}")))?;

        for removed in &tentative.removed_leaf_indices {
            self.pending_removal_leaves.remove(removed);
        }
        if self.pending_removal_leaves.is_empty() {
            self.mls_rekey_required = false;
        }
        self.interim_transcript_hash = tentative.staged_interim_hash;

        self.commit_log.insert(
            tentative.target_epoch,
            FinalizedCommitRecord {
                epoch: tentative.target_epoch,
                committer_device_id: tentative.committer_device_id,
                commit_sha256: tentative.commit_sha256,
                confirmed_transcript_hash: tentative.staged_confirmed_hash.clone(),
                interim_transcript_hash: tentative.staged_interim_hash,
                commit_blob: tentative.commit_blob,
                referenced_proposal_refs: tentative.referenced_proposal_refs,
            },
        );

        // Enforce 2,000-epoch catch-up horizon pruning on commit_log and proposal_log (§5.1).
        if tentative.target_epoch > MAX_MLS_CATCHUP_EPOCHS {
            let min_keep_epoch = tentative.target_epoch - MAX_MLS_CATCHUP_EPOCHS;
            self.commit_log.retain(|&ep, _| ep >= min_keep_epoch);
            let mut still_referenced: BTreeSet<&[u8]> = BTreeSet::new();
            for rec in self.commit_log.values() {
                for pref in &rec.referenced_proposal_refs {
                    still_referenced.insert(pref.as_slice());
                }
            }
            let cur_epoch = tentative.target_epoch;
            let keep_refs: BTreeSet<Vec<u8>> = self
                .proposal_log
                .iter()
                .filter(|(k, v)| {
                    v.epoch >= min_keep_epoch
                        || v.epoch == cur_epoch
                        || still_referenced.contains(k.as_slice())
                })
                .map(|(k, _)| k.clone())
                .collect();
            self.proposal_log.retain(|k, _| keep_refs.contains(k));
        }

        Ok(QuorumOutcome::Finalized {
            new_epoch: tentative.target_epoch,
            confirmed_transcript_hash: tentative.staged_confirmed_hash,
            interim_transcript_hash: tentative.staged_interim_hash,
        })
    }

    /// Returns finalized commits from `from_epoch` (inclusive) up to `limit` (`1..=32`),
    /// each paired with the exact full bytes of every referenced proposal from `proposal_log` (§5.1).
    pub fn get_catchup_commits(
        &self,
        from_epoch: u64,
        limit: usize,
    ) -> Result<Vec<CatchupCommitBundle>, MpMlsError> {
        if limit == 0 || limit > MAX_CATCHUP_PAGE_LIMIT {
            return Err(MpMlsError::InvalidCatchupLimit(limit));
        }
        let mut out = Vec::new();
        for (&epoch, rec) in self.commit_log.range(from_epoch..).take(limit) {
            let mut props = Vec::with_capacity(rec.referenced_proposal_refs.len());
            for pref in &rec.referenced_proposal_refs {
                let stored = self.proposal_log.get(pref).ok_or(MpMlsError::OpenMls(
                    "referenced proposal missing from proposal_log".into(),
                ))?;
                props.push(stored.proposal_blob.clone());
            }
            out.push(CatchupCommitBundle {
                epoch,
                commit_blob: rec.commit_blob.clone(),
                referenced_proposals: props,
            });
        }
        Ok(out)
    }

    /// Exports the full `MpMlsPublicDs` durable public state (NO `ds_privkey`!) as a canonical
    /// binary blob (version = 2), including `roster_rev` and any in-flight tentative commit + votes.
    pub fn export_snapshot(&self) -> Result<Vec<u8>, MpMlsError> {
        let storage_blob = self.provider.export_storage_binary()?;
        let mut out = Vec::new();
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&self.party_id.to_be_bytes());
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.ds_pubkey);
        out.extend_from_slice(&self.interim_transcript_hash);
        out.extend_from_slice(&self.roster_rev.to_be_bytes());
        out.push(u8::from(self.mls_rekey_required));

        // pending_removal_leaves (sorted ascending)
        out.extend_from_slice(&(self.pending_removal_leaves.len() as u32).to_be_bytes());
        for &idx in &self.pending_removal_leaves {
            out.extend_from_slice(&idx.to_be_bytes());
        }

        // proposal_log (sorted ascending by proposal_ref)
        out.extend_from_slice(&(self.proposal_log.len() as u32).to_be_bytes());
        for rec in self.proposal_log.values() {
            out.extend_from_slice(&rec.epoch.to_be_bytes());
            out.extend_from_slice(&(rec.proposal_ref.len() as u32).to_be_bytes());
            out.extend_from_slice(&rec.proposal_ref);
            match rec.target_leaf_index {
                Some(idx) => {
                    out.push(1);
                    out.extend_from_slice(&idx.to_be_bytes());
                }
                None => out.push(0),
            }
            out.extend_from_slice(&(rec.proposal_blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&rec.proposal_blob);
        }

        // commit_log (sorted ascending by epoch)
        out.extend_from_slice(&(self.commit_log.len() as u32).to_be_bytes());
        for rec in self.commit_log.values() {
            out.extend_from_slice(&rec.epoch.to_be_bytes());
            out.extend_from_slice(&rec.committer_device_id.to_be_bytes());
            out.extend_from_slice(&rec.commit_sha256);
            out.extend_from_slice(&(rec.confirmed_transcript_hash.len() as u32).to_be_bytes());
            out.extend_from_slice(&rec.confirmed_transcript_hash);
            out.extend_from_slice(&rec.interim_transcript_hash);
            out.extend_from_slice(&(rec.commit_blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&rec.commit_blob);
            out.extend_from_slice(&(rec.referenced_proposal_refs.len() as u32).to_be_bytes());
            for pref in &rec.referenced_proposal_refs {
                out.extend_from_slice(&(pref.len() as u32).to_be_bytes());
                out.extend_from_slice(pref);
            }
        }

        // Optional in-flight tentative commit state (preserves votes & deadline across DO restarts!)
        match &self.tentative {
            None => out.push(0),
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.committer_device_id.to_be_bytes());
                out.extend_from_slice(&t.roster_rev.to_be_bytes());
                out.extend_from_slice(&t.deadline_s.to_be_bytes());
                out.extend_from_slice(&(t.eligible_online_accounts.len() as u32).to_be_bytes());
                for &acct in &t.eligible_online_accounts {
                    out.extend_from_slice(&acct.to_be_bytes());
                }
                out.extend_from_slice(&(t.ok_acks_by_account.len() as u32).to_be_bytes());
                for (&acct, hash) in &t.ok_acks_by_account {
                    out.extend_from_slice(&acct.to_be_bytes());
                    out.extend_from_slice(hash);
                }
                out.extend_from_slice(&(t.commit_blob.len() as u32).to_be_bytes());
                out.extend_from_slice(&t.commit_blob);
            }
        }

        // OpenMLS storage blob
        out.extend_from_slice(&(storage_blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&storage_blob);
        Ok(out)
    }

    /// Restores `MpMlsPublicDs` from a binary snapshot produced by `export_snapshot`.
    /// Caps ALL preallocations by remaining input bytes before allocating and rejects duplicate/unsorted
    /// keys (Astra #2 / Fable H7).
    pub fn import_snapshot(bytes: &[u8]) -> Result<Self, MpMlsError> {
        let mut c = bytes;
        let read_u8 = |c: &mut &[u8]| -> Result<u8, MpMlsError> {
            if c.is_empty() {
                return Err(MpMlsError::TruncatedInput);
            }
            let v = c[0];
            *c = &c[1..];
            Ok(v)
        };
        let read_u32 = |c: &mut &[u8]| -> Result<u32, MpMlsError> {
            if c.len() < 4 {
                return Err(MpMlsError::TruncatedInput);
            }
            let v = u32::from_be_bytes(
                c[0..4]
                    .try_into()
                    .map_err(|_| MpMlsError::TruncatedInput)?,
            );
            *c = &c[4..];
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
        let read_vec = |c: &mut &[u8]| -> Result<Vec<u8>, MpMlsError> {
            let len = read_u32(c)? as usize;
            if c.len() < len {
                return Err(MpMlsError::TruncatedInput);
            }
            let v = c[..len].to_vec();
            *c = &c[len..];
            Ok(v)
        };
        let read_exact = |c: &mut &[u8], n: usize| -> Result<Vec<u8>, MpMlsError> {
            if c.len() < n {
                return Err(MpMlsError::TruncatedInput);
            }
            let v = c[..n].to_vec();
            *c = &c[n..];
            Ok(v)
        };

        let ver = read_u8(&mut c)?;
        if ver != SNAPSHOT_VERSION {
            return Err(MpMlsError::UnsupportedVersion(ver));
        }
        let party_id = read_u64(&mut c)?;
        check_safe_id(party_id)?;
        let group_id: [u8; MP_GROUP_ID_LEN] = read_exact(&mut c, MP_GROUP_ID_LEN)?
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let parsed_gid = MpGroupId::parse(&group_id)?;
        if parsed_gid.party_id != party_id {
            return Err(MpMlsError::InvalidGroupId);
        }
        let ds_pubkey: [u8; 32] = read_exact(&mut c, 32)?
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        validate_ed25519_pubkey_strict(&ds_pubkey)?;
        let interim_transcript_hash: [u8; 32] = read_exact(&mut c, 32)?
            .try_into()
            .map_err(|_| MpMlsError::TruncatedInput)?;
        let roster_rev = read_u64(&mut c)?;
        let mls_rekey_required = match read_u8(&mut c)? {
            0 => false,
            1 => true,
            other => {
                return Err(MpMlsError::InvalidEnumValue {
                    field: "mls_rekey_required",
                    value: u64::from(other),
                });
            }
        };

        // pending_removal_leaves (min 4 bytes/entry, strictly ascending)
        let rem_count = read_u32(&mut c)? as usize;
        if rem_count > c.len() / 4 {
            return Err(MpMlsError::TruncatedInput);
        }
        let mut pending_removal_leaves = BTreeSet::new();
        let mut prev_rem: Option<u32> = None;
        for _ in 0..rem_count {
            let idx = read_u32(&mut c)?;
            if let Some(p) = prev_rem
                && idx <= p
            {
                return Err(MpMlsError::SnapshotCorrupted(
                    "duplicate or unsorted pending_removal_leaves",
                ));
            }
            prev_rem = Some(idx);
            pending_removal_leaves.insert(idx);
        }

        // proposal_log (min 8 + 4 + 1 + 4 = 17 bytes/entry, strictly ascending proposal_ref)
        let prop_count = read_u32(&mut c)? as usize;
        if prop_count > c.len() / 17 {
            return Err(MpMlsError::TruncatedInput);
        }
        let mut proposal_log = BTreeMap::new();
        let mut prev_prop_ref: Option<Vec<u8>> = None;
        for _ in 0..prop_count {
            let epoch = read_u64(&mut c)?;
            check_safe_counter(epoch)?;
            let proposal_ref = read_vec(&mut c)?;
            if let Some(ref p) = prev_prop_ref
                && proposal_ref <= *p
            {
                return Err(MpMlsError::SnapshotCorrupted(
                    "duplicate or unsorted proposal_log key",
                ));
            }
            prev_prop_ref = Some(proposal_ref.clone());
            let target_leaf_index = match read_u8(&mut c)? {
                0 => None,
                1 => Some(read_u32(&mut c)?),
                other => {
                    return Err(MpMlsError::InvalidEnumValue {
                        field: "target_leaf_index_tag",
                        value: u64::from(other),
                    });
                }
            };
            let proposal_blob = read_vec(&mut c)?;
            proposal_log.insert(
                proposal_ref.clone(),
                StoredProposalRecord {
                    epoch,
                    proposal_ref,
                    target_leaf_index,
                    proposal_blob,
                },
            );
        }

        // commit_log (min 8 + 8 + 32 + 4 + 32 + 4 + 4 = 92 bytes/entry, strictly ascending epoch)
        let commit_count = read_u32(&mut c)? as usize;
        if commit_count > c.len() / 92 {
            return Err(MpMlsError::TruncatedInput);
        }
        let mut commit_log = BTreeMap::new();
        let mut prev_commit_epoch: Option<u64> = None;
        for _ in 0..commit_count {
            let epoch = read_u64(&mut c)?;
            check_safe_counter(epoch)?;
            if let Some(p) = prev_commit_epoch
                && epoch <= p
            {
                return Err(MpMlsError::SnapshotCorrupted(
                    "duplicate or unsorted commit_log epoch",
                ));
            }
            prev_commit_epoch = Some(epoch);
            let committer_device_id = read_u64(&mut c)?;
            check_safe_id(committer_device_id)?;
            let commit_sha256: [u8; 32] = read_exact(&mut c, 32)?
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?;
            let confirmed_transcript_hash = read_vec(&mut c)?;
            let rec_interim: [u8; 32] = read_exact(&mut c, 32)?
                .try_into()
                .map_err(|_| MpMlsError::TruncatedInput)?;
            let commit_blob = read_vec(&mut c)?;
            let pref_count = read_u32(&mut c)? as usize;
            if pref_count > c.len() / 4 {
                return Err(MpMlsError::TruncatedInput);
            }
            let mut referenced_proposal_refs = Vec::with_capacity(pref_count);
            for _ in 0..pref_count {
                referenced_proposal_refs.push(read_vec(&mut c)?);
            }
            commit_log.insert(
                epoch,
                FinalizedCommitRecord {
                    epoch,
                    committer_device_id,
                    commit_sha256,
                    confirmed_transcript_hash,
                    interim_transcript_hash: rec_interim,
                    commit_blob,
                    referenced_proposal_refs,
                },
            );
        }

        // Optional tentative commit data
        let tentative_raw = match read_u8(&mut c)? {
            0 => None,
            1 => {
                let committer_device_id = read_u64(&mut c)?;
                let t_roster_rev = read_u64(&mut c)?;
                let deadline_s = read_u64(&mut c)?;
                let online_count = read_u32(&mut c)? as usize;
                if online_count > c.len() / 8 {
                    return Err(MpMlsError::TruncatedInput);
                }
                let mut online_accts = Vec::with_capacity(online_count);
                let mut prev_acct: Option<u64> = None;
                for _ in 0..online_count {
                    let acct = read_u64(&mut c)?;
                    if let Some(p) = prev_acct
                        && acct <= p
                    {
                        return Err(MpMlsError::SnapshotCorrupted(
                            "duplicate or unsorted eligible_online_accounts",
                        ));
                    }
                    prev_acct = Some(acct);
                    online_accts.push(acct);
                }
                let ack_count = read_u32(&mut c)? as usize;
                if ack_count > c.len() / 40 {
                    return Err(MpMlsError::TruncatedInput);
                }
                let mut ok_acks = BTreeMap::new();
                let mut prev_ack_acct: Option<u64> = None;
                for _ in 0..ack_count {
                    let acct = read_u64(&mut c)?;
                    if let Some(p) = prev_ack_acct
                        && acct <= p
                    {
                        return Err(MpMlsError::SnapshotCorrupted(
                            "duplicate or unsorted ok_acks_by_account",
                        ));
                    }
                    prev_ack_acct = Some(acct);
                    let hash: [u8; 32] = read_exact(&mut c, 32)?
                        .try_into()
                        .map_err(|_| MpMlsError::TruncatedInput)?;
                    ok_acks.insert(acct, hash);
                }
                let commit_blob = read_vec(&mut c)?;
                Some((
                    committer_device_id,
                    t_roster_rev,
                    deadline_s,
                    online_accts,
                    ok_acks,
                    commit_blob,
                ))
            }
            other => {
                return Err(MpMlsError::InvalidEnumValue {
                    field: "has_tentative",
                    value: u64::from(other),
                });
            }
        };

        let storage_blob = read_vec(&mut c)?;
        if !c.is_empty() {
            return Err(MpMlsError::TrailingBytes);
        }

        let provider = MpCryptoProvider::import_storage_binary(&storage_blob)?;
        let public_group = PublicGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
            .ok_or_else(|| MpMlsError::OpenMls("PublicGroup missing in snapshot".into()))?;

        let mut ds = Self {
            party_id,
            group_id,
            ds_pubkey,
            provider,
            public_group,
            interim_transcript_hash,
            roster_rev,
            mls_rekey_required,
            pending_removal_leaves,
            proposal_log,
            commit_log,
            tentative: None,
        };

        if let Some((
            committer_device_id,
            t_roster_rev,
            deadline_s,
            online_accts,
            ok_acks,
            commit_blob,
        )) = tentative_raw
        {
            let restored = ds.build_tentative_state(
                &commit_blob,
                committer_device_id,
                &online_accts,
                None,
                deadline_s,
                t_roster_rev,
                ok_acks,
            )?;
            ds.tentative = Some(restored);
        }

        Ok(ds)
    }
}

/// Extracts the exact 32-byte `confirmation_tag` from a serialized `MLSMessage(PublicMessage(Commit))`.
pub fn extract_commit_confirmation_tag(commit_bytes: &[u8]) -> Result<[u8; 32], MpMlsError> {
    let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(commit_bytes)
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
    match msg_in.extract() {
        MlsMessageBodyIn::PublicMessage(pm) => pm
            .confirmation_tag()
            .ok_or(MpMlsError::OpenMls(
                "Commit PublicMessage missing confirmation_tag".into(),
            ))
            .and_then(confirmation_tag_32),
        _ => Err(MpMlsError::OpenMls(
            "expected PublicMessage Commit wire format".into(),
        )),
    }
}
