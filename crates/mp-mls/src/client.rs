//! High-level `MpMlsClient` wrapping `openmls = "=0.9.2"` `MlsGroup` with all Spec v3.1 invariants:
//! - Ciphersuite `0x0001`, `max_past_epochs = 2` + explicit 120-second `prune_past_epochs(now_s)`,
//!   `out_of_order_tolerance = 64`, `maximum_forward_distance = 1024`, `use_ratchet_tree_extension = true`,
//!   `padding_size = 0`, `PURE_PLAINTEXT_WIRE_FORMAT_POLICY`.
//! - RFC 9420 §7.2-compliant `LeafNode.capabilities` (zero default extensions/proposals) and
//!   mandatory self-contained `0xFF02` `MpLeafDeviceListExtV1` on every generated LeafNode/KeyPackage.
//! - Catch-up-safe `Lifetime::init(0, 4_102_444_800)` on OpenMLS leaves/KeyPackages so historical
//!   Commit catch-up never forks; real `7d`/`30d` expiry enforced on `MpMlsDeviceBindingV1` and
//!   `AccountDeviceListV1` at admission time and in `evaluate_local_policy`.
//! - Atomic snapshot Welcome join binding `Welcome.secrets()` to `expected_joiner_kp_ref`, verifying
//!   `WelcomeAuthV1`, validating ALL leaves (`0xFF02`) and root pins BEFORE committing storage,
//!   and entering Tier-0 send-blocked `Inviter Unconfirmed` mode for delegated Warm Welcomes.
//! - Isolated snapshot staging for encryption (zero ratchet advancement on any error), decryption,
//!   proposals, and Commits; identical deterministic Commit validation for authors and recipients.
//! - 500-frame advisory PCS self-Update threshold + 900-frame hard send stop per epoch;
//!   honest own-leaf Commit clone detection (never frozen by unverified `OwnPrivateMessage` echoes).

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use ed25519_dalek::SigningKey;
use openmls::prelude::{
    CredentialWithKey, Extension, Extensions, GroupId, KeyPackage, KeyPackageIn, LeafNodeIndex,
    LeafNodeParameters, Lifetime, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, PastEpochDeletion, ProcessMessageError,
    ProcessedMessageContent, Proposal, ProtocolMessage, ProtocolVersion, Sender,
    SenderRatchetConfiguration, StageCommitError, StagedWelcome, ValidationError,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{types::SignatureScheme, OpenMlsProvider};
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize};

use crate::crypto::{sha256, Ed25519PubKey, MpCryptoProvider, Sha256Digest};
use crate::ds::{
    confirmation_tag_32, extract_commit_confirmation_tag, hash_epoch_authenticator_for_ack,
    AckStatus, CommitAckV1,
};
use crate::error::MpMlsError;
use crate::framing::{MpAppAadV1, MpAppPayloadV1, MsgClass, MAX_APP_BODY_BYTES, WIRE_BUCKETS};
use crate::identity::{
    check_safe_counter, compute_room_trust_tier, format_epoch_authenticator, AccountDeviceListV1,
    AccountRootPinStore, DeviceListTracker, MpMlsLeafCredV1, RoomTrustTier, RootRotationStmtV1,
};
use crate::invite::{validate_policy_bits, verify_join_proof, InviteRecordV1, WelcomeAuthV1};
use crate::policy::{
    build_ds_external_sender, evaluate_local_policy, extract_public_group_leaves,
    leaf_capabilities, leaf_device_list_extensions, required_capabilities_extension,
    validate_commit_deterministic, validate_key_package_admission,
    validate_leaf_identity_continuity, validate_leaf_node_credential,
    validate_proposal_deterministic, validate_staged_welcome, validate_welcome_public_group_leaves,
    LocalPolicyReport, MpGroupId, MpRoomPolicyExtV1, TreeLeafInfo,
    CATCHUP_SAFE_LIFETIME_NOT_AFTER, CATCHUP_SAFE_LIFETIME_NOT_BEFORE, MP_CIPHERSUITE,
    MP_GROUP_ID_LEN,
};

pub const MP_MAX_PAST_EPOCHS: usize = 2;
pub const MP_OUT_OF_ORDER_TOLERANCE: u32 = 64;
pub const MP_MAX_FORWARD_DISTANCE: u32 = 1024;
pub const MP_PCS_UPDATE_FRAME_THRESHOLD: u64 = 500;
/// Hard per-epoch frame stop (`900 < 1024`) guaranteeing ephemeral frames can never exhaust
/// `maximum_forward_distance = 1024` (Spec v3.1 §7.2).
pub const MP_MAX_FRAMES_PER_EPOCH: u64 = 900;
/// Maximum retention window for past-epoch decryption secrets in seconds (Spec v3.1 §7.2).
pub const MP_PAST_EPOCH_RETENTION_SECS: u64 = 120;

/// Catch-up-safe OpenMLS KeyPackage lifetime (1970..2100 via `Lifetime::init`, zero `now + t` overflow
/// and zero `SystemTime::now()` call) so OpenMLS never rejects historical Add Commits during offline
/// catch-up; real 7d/30d expiry is enforced on `MpMlsDeviceBindingV1` and `AccountDeviceListV1`.
pub fn unbounded_mls_lifetime() -> Lifetime {
    Lifetime::init(
        CATCHUP_SAFE_LIFETIME_NOT_BEFORE,
        CATCHUP_SAFE_LIFETIME_NOT_AFTER,
    )
}

/// Canonical `MlsGroupJoinConfig` shared by room creators and joiners.
pub fn mp_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .padding_size(0)
        .max_past_epochs(MP_MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            MP_OUT_OF_ORDER_TOLERANCE,
            MP_MAX_FORWARD_DISTANCE,
        ))
        .build()
}

/// Device signing identity bundle held locally by an `MpMlsClient`, pairing the verified
/// `MpMlsLeafCredV1` (276 B) with its matching root-signed `AccountDeviceListV1` (for `0xFF02`).
#[derive(Clone)]
pub struct DeviceIdentity {
    pub cred: MpMlsLeafCredV1,
    pub device_list: AccountDeviceListV1,
    pub device_sk: SigningKey,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("account_id", &self.cred.binding.body.account_id)
            .field("device_id", &self.cred.binding.body.device_id)
            .field("device_gen", &self.cred.binding.body.device_gen)
            .field("list_version", &self.cred.list_version)
            .field("device_sk", &"[REDACTED]")
            .finish()
    }
}

impl DeviceIdentity {
    /// Validates cryptographic binding between `cred`, `device_list` (`0xFF02`), and `device_sk`.
    pub fn new(
        cred: MpMlsLeafCredV1,
        device_list: AccountDeviceListV1,
        device_sk: SigningKey,
    ) -> Result<Self, MpMlsError> {
        cred.binding.verify_structural()?;
        let body = &cred.binding.body;
        if device_sk.verifying_key().to_bytes() != body.mls_sig_pubkey {
            return Err(MpMlsError::LeafSignatureKeyMismatch);
        }
        if device_list.account_id != body.account_id {
            return Err(MpMlsError::InvalidLeafDeviceList(
                "device_list.account_id mismatch",
            ));
        }
        if device_list.root_gen != body.root_gen {
            return Err(MpMlsError::InvalidLeafDeviceList(
                "device_list.root_gen mismatch",
            ));
        }
        if device_list.list_version != cred.list_version {
            return Err(MpMlsError::InvalidLeafDeviceList(
                "device_list.list_version mismatch",
            ));
        }
        device_list.verify(&body.root_pubkey)?;
        if device_list.list_hash()? != cred.list_hash {
            return Err(MpMlsError::InvalidLeafDeviceList(
                "SHA-256(device_list) does not match cred.list_hash",
            ));
        }
        if !device_list.authorizes_leaf(body) {
            return Err(MpMlsError::InvalidLeafDeviceList(
                "device_list does not authorize this leaf",
            ));
        }
        Ok(Self {
            cred,
            device_list,
            device_sk,
        })
    }

    pub fn openmls_signer(&self) -> SignatureKeyPair {
        SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            self.device_sk.as_bytes().to_vec(),
            self.cred.binding.body.mls_sig_pubkey.to_vec(),
        )
    }

    pub fn credential_with_key(&self) -> Result<CredentialWithKey, MpMlsError> {
        Ok(CredentialWithKey {
            credential: self.cred.to_basic_credential()?.into(),
            signature_key: self.cred.binding.body.mls_sig_pubkey.to_vec().into(),
        })
    }

    pub fn account_id(&self) -> u64 {
        self.cred.binding.body.account_id
    }

    pub fn device_id(&self) -> u64 {
        self.cred.binding.body.device_id
    }
}

/// Generates a single-use RFC 9420 `KeyPackage` (NO last-resort extension, catch-up-safe lifetime,
/// RFC 9420 §7.2 `Capabilities`, and mandatory `0xFF02` `MpLeafDeviceListExtV1` extension)
/// and persists its private keys inside `provider`. Returns `(kp_wire_bytes, kp_ref_32B)`.
pub fn generate_single_use_key_package(
    identity: &DeviceIdentity,
    provider: &MpCryptoProvider,
) -> Result<(Vec<u8>, [u8; 32]), MpMlsError> {
    let signer = identity.openmls_signer();
    let cred_with_key = identity.credential_with_key()?;
    let leaf_exts = leaf_device_list_extensions(&identity.device_list)?;
    let kp_bundle = KeyPackage::builder()
        .leaf_node_capabilities(leaf_capabilities())
        .leaf_node_extensions(leaf_exts)
        .key_package_lifetime(unbounded_mls_lifetime())
        .build(MP_CIPHERSUITE, provider, &signer, cred_with_key)
        .map_err(|e| MpMlsError::OpenMls(format!("KeyPackage::build failed: {e}")))?;

    let kp_ref_bytes = kp_bundle
        .key_package()
        .hash_ref(provider.crypto())
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
        .as_slice()
        .to_vec();
    let kp_ref: [u8; 32] = kp_ref_bytes.try_into().map_err(|v: Vec<u8>| {
        MpMlsError::InvalidLength {
            expected: 32,
            got: v.len(),
        }
    })?;
    let kp_msg = MlsMessageOut::from(kp_bundle.key_package().clone());
    let kp_bytes = kp_msg
        .tls_serialize_detached()
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
    Ok((kp_bytes, kp_ref))
}

/// Pending local outbox record for persist-before-send & epoch-stale requeue (§7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOutboxEntry {
    pub inner_msg_id: [u8; 16],
    pub msg_class: MsgClass,
    pub plaintext: Vec<u8>,
    pub sent_epoch: u64,
    pub device_epoch_seq: u64,
    pub wire_bytes: Vec<u8>,
}

/// Verified and decrypted application message returned to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedAppMessage {
    pub epoch: u64,
    pub auth_account_id: u64,
    pub auth_device_id: u64,
    pub device_epoch_seq: u64,
    pub msg_class: MsgClass,
    pub inner_msg_id: [u8; 16],
    pub body: Vec<u8>,
    /// `true` iff `(auth_device_id, inner_msg_id)` was already delivered previously
    /// (e.g., epoch-stale requeue deduplication per §7.1 / §7.2).
    pub is_duplicate: bool,
}

/// Output of `MpMlsClient::commit_add_member_with_invite`.
#[derive(Debug, Clone)]
pub struct AddMemberCommitOutput {
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Vec<u8>,
    pub welcome_auth: WelcomeAuthV1,
}

#[derive(Clone, PartialEq, Eq)]
struct ActiveInviteState {
    record: InviteRecordV1,
    uses_seen: u32,
}

impl fmt::Debug for ActiveInviteState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveInviteState")
            .field("record", &self.record)
            .field("uses_seen", &self.uses_seen)
            .finish()
    }
}

/// Deferred local mutations bound to a pending Commit — applied ONLY when that Commit merges,
/// and rolled back cleanly on `discard_pending_commit` or a lost commit race (Fable H5, M2).
#[derive(Clone)]
struct PendingCommitMeta {
    commit_sha256: Sha256Digest,
    consumed_kp_ref: Option<[u8; 32]>,
    invite_id_used: Option<u64>,
    updated_identity: Option<DeviceIdentity>,
}

/// Production `mp-mls` client state machine wrapping `openmls = "=0.9.2"` `MlsGroup`.
pub struct MpMlsClient {
    party_id: u64,
    group_id: [u8; MP_GROUP_ID_LEN],
    identity: DeviceIdentity,
    provider: MpCryptoProvider,
    group: MlsGroup,
    pins: AccountRootPinStore,
    device_lists: DeviceListTracker,
    active_invites: HashMap<u64, ActiveInviteState>,
    /// Consumed KeyPackageRefs tagged with the epoch in which they were committed (pruned on rollover).
    consumed_kp_refs: HashMap<[u8; 32], u64>,
    /// Deduplication map `(auth_device_id, inner_msg_id) -> first_seen_epoch` (pruned to active window).
    seen_inner_msg_ids: HashMap<(u64, [u8; 16]), u64>,
    pending_commit_meta: Option<PendingCommitMeta>,
    device_epoch_seq: u64,
    total_sent_frames_in_epoch: u64,
    cloned_device_key_suspected: bool,
    local_cache_wiped: bool,
    /// `true` when joined via a delegated Welcome whose GroupInfo signer did not chain to
    /// `pinned_inviter_root_pk` (Tier 0, blocks outbound sends until inviter confirms in `epoch >= join_epoch`).
    inviter_unconfirmed: bool,
    pinned_inviter_root_pk: Option<Ed25519PubKey>,
    join_epoch: u64,
    /// Retired past epochs mapped to the wall-clock `now_s` when the group advanced past them,
    /// driving deterministic 120-second `prune_past_epochs(now_s)` purging (Spec v3.1 §7.2).
    epoch_retired_at_s: BTreeMap<u64, u64>,
}

impl MpMlsClient {
    /// Creates a new epoch-0 room with `self` as creator, `0xFF02` leaf extension, and single DS `ExternalSender`.
    /// Returns `(client, epoch0_group_info_bytes)` so `PartyDO` can bootstrap `MpMlsPublicDs`.
    pub fn create_room(
        party_id: u64,
        incarnation_nonce: [u8; 8],
        ds_pubkey: &Ed25519PubKey,
        policy: MpRoomPolicyExtV1,
        identity: DeviceIdentity,
    ) -> Result<(Self, Vec<u8>), MpMlsError> {
        let mp_gid = MpGroupId::new(party_id, incarnation_nonce)?;
        let group_id = mp_gid.encode();
        policy.validate()?;
        if policy.party_id != party_id {
            return Err(MpMlsError::InvalidRoomPolicy("policy party_id mismatch"));
        }
        if !policy.is_host(identity.account_id()) {
            return Err(MpMlsError::InvalidRoomPolicy(
                "creator account must be in host_account_ids",
            ));
        }
        policy.check_leaf_allowed(&identity.cred)?;
        policy.check_not_banned(identity.account_id())?;

        let ds_sender = build_ds_external_sender(party_id, ds_pubkey)?;
        let gc_exts = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(required_capabilities_extension()),
            Extension::ExternalSenders(vec![ds_sender]),
            policy.to_extension()?,
        ])
        .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        let leaf_exts = leaf_device_list_extensions(&identity.device_list)?;

        let create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(MP_CIPHERSUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .padding_size(0)
            .max_past_epochs(MP_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                MP_OUT_OF_ORDER_TOLERANCE,
                MP_MAX_FORWARD_DISTANCE,
            ))
            .capabilities(leaf_capabilities())
            .lifetime(unbounded_mls_lifetime())
            .with_group_context_extensions(gc_exts)
            .with_leaf_node_extensions(leaf_exts)
            .map_err(|e| MpMlsError::OpenMls(format!("with_leaf_node_extensions failed: {e}")))?
            .build();

        let provider = MpCryptoProvider::new();
        let signer = identity.openmls_signer();
        let cred_with_key = identity.credential_with_key()?;

        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &create_config,
            mp_gid.to_openmls(),
            cred_with_key,
        )
        .map_err(|e| MpMlsError::OpenMls(format!("MlsGroup::new_with_group_id failed: {e}")))?;

        let gi_msg = group
            .export_group_info(provider.crypto(), &signer, true)
            .map_err(|e| MpMlsError::OpenMls(format!("export_group_info failed: {e}")))?;
        let gi_bytes = gi_msg
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        let mut pins = AccountRootPinStore::new();
        let b = &identity.cred.binding.body;
        pins.check_or_pin(b.account_id, b.root_pubkey, b.root_gen, b.custody_mode)?;
        pins.mark_verified_oob(b.account_id)?;

        let mut device_lists = DeviceListTracker::new();
        let _ = device_lists.observe(identity.device_list.clone(), &pins, None)?;

        let client = Self {
            party_id,
            group_id,
            identity,
            provider,
            group,
            pins,
            device_lists,
            active_invites: HashMap::new(),
            consumed_kp_refs: HashMap::new(),
            seen_inner_msg_ids: HashMap::new(),
            pending_commit_meta: None,
            device_epoch_seq: 0,
            total_sent_frames_in_epoch: 0,
            cloned_device_key_suspected: false,
            local_cache_wiped: false,
            inviter_unconfirmed: false,
            pinned_inviter_root_pk: None,
            join_epoch: 0,
            epoch_retired_at_s: BTreeMap::new(),
        };
        Ok((client, gi_bytes))
    }

    /// Joins a room from a `Welcome` + `WelcomeAuthV1` using **fully atomic isolated snapshot staging**
    /// (Spec v3.1 §4.2.4, Fable H4/M6, Astra §4):
    /// 1. Verifies `WelcomeAuthV1` MAC, `pinned_invite_epoch` floor, and `policy_bits` BEFORE touching OpenMLS.
    /// 2. Verifies `Welcome.secrets()` explicitly targets `expected_joiner_kp_ref` BEFORE staging.
    /// 3. Forks isolated storage, stages & installs `MlsGroup` inside the isolated snapshot.
    /// 4. Verifies `GroupContext`, `0xFF01`, `0xFF02` on EVERY tree leaf, exact 32-byte `confirmation_tag`,
    ///    own leaf identity, AND builds `AccountRootPinStore` (own identity first, then all peers)
    ///    **ALL BEFORE** committing isolated storage!
    /// 5. On success, moves ownership of the single live `provider` into `MpMlsClient` via `std::mem::take`
    ///    so the caller retains ZERO stale copy of join-epoch secrets. On ANY error, `provider` is untouched!
    /// 6. If the Welcome signer does not chain to `pinned_inviter_root_pk` (delegated committer),
    ///    installs in send-blocked Tier 0 (`inviter_unconfirmed = true`) until the inviter confirms.
    #[allow(clippy::too_many_arguments)]
    pub fn join_from_welcome(
        welcome_bytes: &[u8],
        welcome_auth: &WelcomeAuthV1,
        member_join_mac_key: &[u8; 32],
        expected_joiner_kp_ref: &[u8; 32],
        pinned_group_id: [u8; MP_GROUP_ID_LEN],
        expected_party_id: u64,
        expected_ds_pubkey: &Ed25519PubKey,
        required_policy_bits: u8,
        pinned_invite_epoch: u64,
        pinned_inviter_root_pk: &Ed25519PubKey,
        identity: DeviceIdentity,
        provider: &mut MpCryptoProvider,
    ) -> Result<Self, MpMlsError> {
        check_safe_counter(pinned_invite_epoch)?;
        validate_policy_bits(required_policy_bits)?;

        // Step 1: Verify invite-keyed `WelcomeAuthV1` MAC and pinned fields BEFORE touching storage!
        if welcome_auth.group_id != pinned_group_id
            || &welcome_auth.joiner_kp_ref != expected_joiner_kp_ref
            || welcome_auth.invite_epoch < pinned_invite_epoch
        {
            return Err(MpMlsError::InvalidMac);
        }
        welcome_auth.verify(member_join_mac_key)?;

        // Step 2: Decode Welcome and verify it explicitly targets `expected_joiner_kp_ref` (Fable M6)!
        let mls_msg = MlsMessageIn::tls_deserialize_exact_bytes(welcome_bytes)
            .map_err(|e| MpMlsError::OpenMls(format!("Welcome decode failed: {e}")))?;
        let welcome = match mls_msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                return Err(MpMlsError::OpenMls(
                    "expected MlsMessageBodyIn::Welcome".into(),
                ));
            }
        };
        let targets_expected_kp = welcome
            .secrets()
            .iter()
            .any(|egs| egs.new_member().as_slice() == expected_joiner_kp_ref);
        if !targets_expected_kp {
            return Err(MpMlsError::WelcomeKeyPackageMismatch);
        }

        // Step 3: Fork isolated storage snapshot so ANY failure leaves caller's `provider` untouched!
        let isolated = provider.fork_isolated()?;

        let join_cfg = mp_join_config();
        let staged = StagedWelcome::build_from_welcome(&isolated, &join_cfg, welcome)
            .map_err(|e| MpMlsError::OpenMls(format!("build_from_welcome failed: {e}")))?
            .skip_lifetime_validation()
            .build()
            .map_err(|e| MpMlsError::OpenMls(format!("StagedWelcome::build failed: {e}")))?;

        // Step 4: Deterministic Welcome policy, DS ExternalSender, RequiredCapabilities (0xFF01+0xFF02),
        // invite_epoch floor, and Welcome signer check.
        let (policy, inviter_unconfirmed) = validate_staged_welcome(
            &staged,
            &pinned_group_id,
            expected_party_id,
            expected_ds_pubkey,
            required_policy_bits,
            pinned_invite_epoch,
            pinned_inviter_root_pk,
        )?;

        // Step 5: Verify our own leaf matches our credential AND 0xFF02 device list.
        let own_leaf = staged
            .own_leaf_node()
            .ok_or_else(|| MpMlsError::OpenMls("own leaf missing in Welcome".into()))?;
        let (own_cred, own_list) = validate_leaf_node_credential(own_leaf)?;
        if own_cred != identity.cred || own_list != identity.device_list {
            return Err(MpMlsError::LeafSignatureKeyMismatch);
        }

        // Step 6: Convert to MlsGroup inside the ISOLATED snapshot so we can inspect EVERY leaf's
        // 0xFF02 extension AND the verified 32-byte `confirmation_tag` BEFORE committing storage!
        let group = staged
            .into_group(&isolated)
            .map_err(|e| MpMlsError::OpenMls(format!("StagedWelcome::into_group failed: {e}")))?;

        let ctx = group.public_group().group_context();
        let gi_confirmation_tag = confirmation_tag_32(group.confirmation_tag())?;
        if ctx.group_id().as_slice() != welcome_auth.group_id
            || ctx.epoch().as_u64() != welcome_auth.target_epoch
            || ctx.tree_hash() != welcome_auth.tree_hash
            || gi_confirmation_tag != welcome_auth.confirmation_tag
        {
            return Err(MpMlsError::InvalidMac);
        }

        // Step 7: Validate EVERY leaf in the installed ratchet tree (including 0xFF02!) & tree invariants.
        let leaves_map = validate_welcome_public_group_leaves(group.public_group(), &policy)?;

        // Step 8: Build AccountRootPinStore (own identity FIRST!) and DeviceListTracker BEFORE
        // touching live storage — if any account has conflicting roots or equivocation, abort cleanly!
        let mut pins = AccountRootPinStore::new();
        let own_b = &identity.cred.binding.body;
        pins.check_or_pin(
            own_b.account_id,
            own_b.root_pubkey,
            own_b.root_gen,
            own_b.custody_mode,
        )?;
        pins.mark_verified_oob(own_b.account_id)?;

        for info in leaves_map.values() {
            let b = &info.cred.binding.body;
            pins.check_or_pin(b.account_id, b.root_pubkey, b.root_gen, b.custody_mode)?;
        }

        let mut device_lists = DeviceListTracker::new();
        let _ = device_lists.observe(identity.device_list.clone(), &pins, None)?;
        for info in leaves_map.values() {
            match device_lists.observe(info.device_list.clone(), &pins, None) {
                Ok(_) | Err(MpMlsError::StaleDeviceList { .. }) => {}
                Err(e) => return Err(e),
            }
        }

        // Step 9: Atomically commit isolated storage and hand the single live provider to the client
        // (caller's `provider` is cleared to an empty default so no stale epoch secrets linger!).
        provider.commit_from_isolated(isolated)?;
        let owned_provider = std::mem::take(provider);
        let join_epoch = group.epoch().as_u64();

        Ok(Self {
            party_id: expected_party_id,
            group_id: pinned_group_id,
            identity,
            provider: owned_provider,
            group,
            pins,
            device_lists,
            active_invites: HashMap::new(),
            consumed_kp_refs: HashMap::new(),
            seen_inner_msg_ids: HashMap::new(),
            pending_commit_meta: None,
            device_epoch_seq: 0,
            total_sent_frames_in_epoch: 0,
            cloned_device_key_suspected: false,
            local_cache_wiped: false,
            inviter_unconfirmed,
            pinned_inviter_root_pk: Some(*pinned_inviter_root_pk),
            join_epoch,
            epoch_retired_at_s: BTreeMap::new(),
        })
    }

    pub fn party_id(&self) -> u64 {
        self.party_id
    }

    pub fn group_id(&self) -> [u8; MP_GROUP_ID_LEN] {
        self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn confirmed_transcript_hash(&self) -> &[u8] {
        self.group.public_group().group_context().confirmed_transcript_hash()
    }

    pub fn own_leaf_index(&self) -> LeafNodeIndex {
        self.group.own_leaf_index()
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    pub fn is_active(&self) -> bool {
        self.group.is_active()
    }

    pub fn cloned_device_key_suspected(&self) -> bool {
        self.cloned_device_key_suspected
    }

    pub fn inviter_unconfirmed(&self) -> bool {
        self.inviter_unconfirmed
    }

    pub fn total_sent_frames_in_epoch(&self) -> u64 {
        self.total_sent_frames_in_epoch
    }

    /// Spec v3.1 §7.2: trigger mandatory PCS self-Update at 500 total sent frames (advisory),
    /// with a hard send stop at 900 total sent frames.
    pub fn needs_pcs_self_update(&self) -> bool {
        self.total_sent_frames_in_epoch >= MP_PCS_UPDATE_FRAME_THRESHOLD
    }

    pub fn epoch_authenticator(&self) -> Vec<u8> {
        self.group.epoch_authenticator().as_slice().to_vec()
    }

    pub fn epoch_authenticator_code(&self) -> Result<String, MpMlsError> {
        format_epoch_authenticator(self.group.epoch_authenticator().as_slice())
    }

    pub fn room_policy(&self) -> Result<MpRoomPolicyExtV1, MpMlsError> {
        MpRoomPolicyExtV1::from_group_context(self.group.public_group().group_context())
    }

    pub fn pins(&self) -> &AccountRootPinStore {
        &self.pins
    }

    pub fn pins_mut(&mut self) -> &mut AccountRootPinStore {
        &mut self.pins
    }

    pub fn device_lists(&self) -> &DeviceListTracker {
        &self.device_lists
    }

    /// Observes a candidate `AccountDeviceListV1` strictly bound to `self.pins` (Fable H2).
    pub fn observe_device_list(
        &mut self,
        list: AccountDeviceListV1,
        now_s: Option<u64>,
    ) -> Result<bool, MpMlsError> {
        self.device_lists.observe(list, &self.pins, now_s)
    }

    pub fn apply_root_rotation(&mut self, stmt: &RootRotationStmtV1) -> Result<(), MpMlsError> {
        self.pins.apply_root_rotation(stmt)
    }

    pub fn register_active_invite(&mut self, record: InviteRecordV1) {
        self.active_invites.insert(
            record.invite_id,
            ActiveInviteState {
                record,
                uses_seen: 0,
            },
        );
    }

    pub fn active_invite_count(&self) -> usize {
        self.active_invites.len()
    }

    /// Returns map of current authenticated tree leaves (with verified `0xFF02` device lists).
    pub fn current_leaves_map(&self) -> Result<BTreeMap<u32, TreeLeafInfo>, MpMlsError> {
        extract_public_group_leaves(self.group.public_group())
    }

    /// Evaluates local pin, device-list revocation/equivocation, and wall-clock binding/list expiry
    /// state against the current tree (Spec v3.1 §3.3.4).
    pub fn evaluate_local_policy(
        &self,
        now_s: Option<u64>,
    ) -> Result<LocalPolicyReport, MpMlsError> {
        let leaves = self.current_leaves_map()?;
        Ok(evaluate_local_policy(
            &leaves,
            &self.pins,
            &self.device_lists,
            now_s,
        ))
    }

    /// Computes honest client-side Room Trust Tier and orthogonal AI Agent badge (Spec v3.1 §3.4).
    pub fn room_trust_tier(&self) -> Result<(RoomTrustTier, bool), MpMlsError> {
        let leaves: Vec<MpMlsLeafCredV1> = self
            .current_leaves_map()?
            .into_values()
            .map(|l| l.cred)
            .collect();
        Ok(compute_room_trust_tier(
            &leaves,
            &self.pins,
            self.local_cache_wiped,
            self.inviter_unconfirmed,
        ))
    }

    /// Purges OpenMLS past-epoch decryption secrets older than `120 s` (`MP_PAST_EPOCH_RETENTION_SECS`)
    /// relative to explicit `now_s` (Spec v3.1 §7.2 / Astra §6). Returns count of epochs pruned.
    pub fn prune_past_epochs(&mut self, now_s: u64) -> Result<usize, MpMlsError> {
        check_safe_counter(now_s)?;
        let before = self.epoch_retired_at_s.len();
        self.epoch_retired_at_s
            .retain(|_, &mut retired_at| now_s.saturating_sub(retired_at) < MP_PAST_EPOCH_RETENTION_SECS);
        let keep = self.epoch_retired_at_s.len().min(MP_MAX_PAST_EPOCHS);
        let policy = if keep == 0 {
            PastEpochDeletion::delete_all()
        } else {
            PastEpochDeletion::delete_all_without_timestamps().max_past_epochs(keep)
        };
        self.group
            .delete_past_epoch_secrets(&self.provider, policy)
            .map_err(|e| MpMlsError::OpenMls(format!("delete_past_epoch_secrets failed: {e}")))?;
        Ok(before.saturating_sub(self.epoch_retired_at_s.len()))
    }

    /// Validates an invitee's `join_proof` and `KeyPackage` at wall-clock `now_s`,
    /// builds a path-bearing `Add` Commit (with inline `ratchet_tree` Welcome, NO External PSK),
    /// and computes the invite-keyed `WelcomeAuthV1` MAC (Spec v3.1 §4.2).
    ///
    /// - Enforces `record.invite_epoch == current_policy.invite_epoch`.
    /// - Unless `allow_delegated == true`, refuses to commit if `record.inviter_root_pk` differs
    ///   from this client's `root_pubkey` (prevents ghost leaves; delegated adds produce Tier-0
    ///   `Inviter Unconfirmed` Welcomes per §4.2.4).
    /// - Defers `consumed_kp_refs` and `uses_seen` updates until `apply_finalized_commit` merges!
    pub fn commit_add_member_with_invite(
        &mut self,
        kp_bytes: &[u8],
        invite_id: u64,
        join_proof: &[u8; 32],
        now_s: u64,
        allow_delegated: bool,
    ) -> Result<AddMemberCommitOutput, MpMlsError> {
        check_safe_counter(now_s)?;
        let invite_state = self
            .active_invites
            .get(&invite_id)
            .ok_or(MpMlsError::UnknownOrRevokedInvite(invite_id))?
            .clone();

        if now_s >= invite_state.record.expires_at_s
            || invite_state.uses_seen >= invite_state.record.max_uses
        {
            return Err(MpMlsError::InviteExhaustedOrExpired);
        }

        let policy = self.room_policy()?;
        if invite_state.record.invite_epoch != policy.invite_epoch {
            return Err(MpMlsError::UnknownOrRevokedInvite(invite_id));
        }

        if !allow_delegated
            && invite_state.record.inviter_root_pk != self.identity.cred.binding.body.root_pubkey
        {
            return Err(MpMlsError::PinnedRootMismatch);
        }

        // Parse & validate KeyPackage via OpenMLS + our wall-clock & 0xFF02 admission check.
        let kp_msg = MlsMessageIn::tls_deserialize_exact_bytes(kp_bytes)
            .map_err(|e| MpMlsError::OpenMls(format!("KeyPackage decode failed: {e}")))?;
        let kp_in: KeyPackageIn = match kp_msg.extract() {
            MlsMessageBodyIn::KeyPackage(kp) => kp,
            _ => {
                return Err(MpMlsError::KeyPackageAdmissionRejected(
                    "expected MlsMessageBodyIn::KeyPackage",
                ));
            }
        };
        let kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| MpMlsError::OpenMls(format!("KeyPackage validation failed: {e}")))?;

        let kp_ref: [u8; 32] = kp
            .hash_ref(self.provider.crypto())
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
            .as_slice()
            .try_into()
            .map_err(|_| MpMlsError::KeyPackageAdmissionRejected("invalid kp_ref length"))?;

        if self.consumed_kp_refs.contains_key(&kp_ref) {
            return Err(MpMlsError::KeyPackageAdmissionRejected(
                "KeyPackage kp_ref already consumed (replay rejected)",
            ));
        }

        let (joiner_cred, _joiner_list) = validate_key_package_admission(
            &kp,
            now_s,
            &policy,
            Some(&self.pins),
            Some(&self.device_lists),
        )?;

        // Verify `join_proof` MAC under `member_join_mac_key` bound to `invite_epoch`!
        verify_join_proof(
            &invite_state.record.member_join_mac_key,
            &self.group_id,
            invite_id,
            invite_state.record.invite_epoch,
            invite_state.record.expires_at_s,
            joiner_cred.binding.body.account_id,
            joiner_cred.binding.body.device_id,
            &kp_ref,
            join_proof,
        )?;

        let signer = self.identity.openmls_signer();
        // Do NOT consume unrelated queued proposals during an invite Add commit so no
        // unvetted queued Add proposal can bypass invite-proof and wall-clock admission checks.
        let bundle = self
            .group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds([kp])
            .force_self_update(true)
            .load_psks(self.provider.storage())
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
            .use_ratchet_tree_extension(true)
            .build(self.provider.rand(), self.provider.crypto(), &signer, |_| true)
            .map_err(|e| MpMlsError::OpenMls(format!("CommitBuilder::build failed: {e}")))?
            .stage_commit(&self.provider)
            .map_err(|e| MpMlsError::OpenMls(format!("stage_commit failed: {e}")))?;

        let (commit_msg, welcome_opt, group_info_opt) = bundle.into_contents();
        let welcome = welcome_opt
            .ok_or_else(|| MpMlsError::OpenMls("Add commit did not produce Welcome".into()))?;
        let group_info = group_info_opt
            .ok_or_else(|| MpMlsError::OpenMls("Add commit did not produce GroupInfo".into()))?;

        let commit_bytes = commit_msg
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        let welcome_msg = MlsMessageOut::from_welcome(welcome, ProtocolVersion::Mls10);
        let welcome_bytes = welcome_msg
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        let tree_hash: [u8; 32] = group_info
            .group_context()
            .tree_hash()
            .try_into()
            .map_err(|_| MpMlsError::OpenMls("unexpected tree_hash length".into()))?;
        let confirmation_tag = extract_commit_confirmation_tag(&commit_bytes)?;

        let welcome_auth = WelcomeAuthV1::new(
            &invite_state.record.member_join_mac_key,
            self.group_id,
            group_info.group_context().epoch().as_u64(),
            invite_id,
            invite_state.record.invite_epoch,
            kp_ref,
            tree_hash,
            confirmation_tag,
        )?;

        self.pending_commit_meta = Some(PendingCommitMeta {
            commit_sha256: sha256(&commit_bytes),
            consumed_kp_ref: Some(kp_ref),
            invite_id_used: Some(invite_id),
            updated_identity: None,
        });

        Ok(AddMemberCommitOutput {
            commit_bytes,
            welcome_bytes,
            welcome_auth,
        })
    }

    /// Processes and validates a standalone `PublicMessage` proposal (e.g. DS External `Remove`)
    /// on an isolated snapshot before storing in `MlsGroup`'s proposal store.
    pub fn apply_proposal(&mut self, proposal_bytes: &[u8]) -> Result<(), MpMlsError> {
        let prev_leaves = self.current_leaves_map()?;
        let isolated = self.provider.fork_isolated()?;
        let mut iso_group =
            MlsGroup::load(isolated.storage(), &GroupId::from_slice(&self.group_id))
                .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
                .ok_or_else(|| MpMlsError::OpenMls("group missing in isolated snapshot".into()))?;

        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(proposal_bytes)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        let proto_msg: ProtocolMessage = msg_in
            .try_into_protocol_message()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        let processed = iso_group
            .process_message(&isolated, proto_msg)
            .map_err(|e| MpMlsError::OpenMls(format!("process proposal failed: {e}")))?;

        let sender = processed.sender().clone();
        let queued = match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(qp) => *qp,
            ProcessedMessageContent::ExternalJoinProposalMessage(qp) => *qp,
            _ => {
                return Err(MpMlsError::ForbiddenProposal("expected ProposalMessage"));
            }
        };

        validate_proposal_deterministic(
            &sender,
            queued.proposal(),
            iso_group.public_group().group_context(),
            &prev_leaves,
        )?;

        iso_group
            .store_pending_proposal(isolated.storage(), queued)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        self.provider.commit_from_isolated(isolated)?;
        self.group = iso_group;
        Ok(())
    }

    /// Commits pending queued proposals (e.g. DS External `Remove`) with mandatory `UpdatePath`,
    /// automatically emitting the mandatory `invite_epoch + 1` `GroupContextExtensions` bump
    /// whenever pending proposals contain a `Remove` (works for BOTH host and non-host committers!).
    pub fn commit_pending_proposals(
        &mut self,
        updated_policy: Option<MpRoomPolicyExtV1>,
    ) -> Result<Vec<u8>, MpMlsError> {
        let cur_ctx = self.group.public_group().group_context();
        let cur_policy = MpRoomPolicyExtV1::from_group_context(cur_ctx)?;
        let is_host = cur_policy.is_host(self.identity.account_id());
        let has_remove = self
            .group
            .pending_proposals()
            .any(|qp| matches!(qp.proposal(), Proposal::Remove(_)));

        let resolved_policy = match (updated_policy, has_remove) {
            (Some(new_policy), _) => {
                MpRoomPolicyExtV1::validate_transition(&cur_policy, &new_policy, is_host, has_remove)?;
                Some(new_policy)
            }
            (None, true) => Some(cur_policy.with_bumped_invite_epoch()?),
            (None, false) => None,
        };

        let next_exts_opt = if let Some(new_policy) = resolved_policy {
            let mut next_exts = cur_ctx.extensions().clone();
            next_exts
                .add_or_replace(new_policy.to_extension()?)
                .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
            Some(next_exts)
        } else {
            None
        };

        let signer = self.identity.openmls_signer();
        let mut builder = self
            .group
            .commit_builder()
            .consume_proposal_store(true)
            .force_self_update(true);

        if let Some(next_exts) = next_exts_opt {
            builder = builder
                .propose_group_context_extensions(next_exts)
                .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        }

        // Never blindly include unvetted queued Add proposals.
        let bundle = builder
            .load_psks(self.provider.storage())
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &signer,
                |qp| !matches!(qp.proposal(), Proposal::Add(_)),
            )
            .map_err(|e| MpMlsError::OpenMls(format!("commit_pending_proposals failed: {e}")))?
            .stage_commit(&self.provider)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        let commit_bytes = bundle
            .into_commit()
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        self.pending_commit_meta = Some(PendingCommitMeta {
            commit_sha256: sha256(&commit_bytes),
            consumed_kp_ref: None,
            invite_id_used: None,
            updated_identity: None,
        });
        Ok(commit_bytes)
    }

    /// Performs a path-bearing PCS self-Update Commit (optionally refreshing `DeviceIdentity`
    /// with a higher `device_gen` / `iat_s` / `exp_s` and updated `0xFF02` `AccountDeviceListV1`).
    /// Validates continuity & key match up front and defers updating `self.identity` until merge (Fable H5)!
    pub fn commit_self_update(
        &mut self,
        updated_identity: Option<DeviceIdentity>,
    ) -> Result<Vec<u8>, MpMlsError> {
        let mut deferred_identity: Option<DeviceIdentity> = None;

        let signer = self.identity.openmls_signer();
        let mut builder = self
            .group
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true);

        if let Some(new_id) = updated_identity {
            validate_leaf_identity_continuity(&self.identity.cred, &new_id.cred)?;
            let cred_with_key = new_id.credential_with_key()?;
            let leaf_exts = leaf_device_list_extensions(&new_id.device_list)?;
            let params = LeafNodeParameters::builder()
                .with_credential_with_key(cred_with_key)
                .with_capabilities(leaf_capabilities())
                .with_extensions(leaf_exts)
                .build();
            builder = builder.leaf_node_parameters(params);
            deferred_identity = Some(new_id);
        } else {
            let leaf_exts = leaf_device_list_extensions(&self.identity.device_list)?;
            let params = LeafNodeParameters::builder()
                .with_capabilities(leaf_capabilities())
                .with_extensions(leaf_exts)
                .build();
            builder = builder.leaf_node_parameters(params);
        }

        let bundle = builder
            .load_psks(self.provider.storage())
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
            .build(self.provider.rand(), self.provider.crypto(), &signer, |_| true)
            .map_err(|e| MpMlsError::OpenMls(format!("commit_self_update failed: {e}")))?
            .stage_commit(&self.provider)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        let commit_bytes = bundle
            .into_commit()
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        self.pending_commit_meta = Some(PendingCommitMeta {
            commit_sha256: sha256(&commit_bytes),
            consumed_kp_ref: None,
            invite_id_used: None,
            updated_identity: deferred_identity,
        });
        Ok(commit_bytes)
    }

    /// Host-only `GroupContextExtensions` policy update Commit with mandatory `UpdatePath`.
    pub fn commit_policy_update(
        &mut self,
        new_policy: MpRoomPolicyExtV1,
    ) -> Result<Vec<u8>, MpMlsError> {
        self.commit_pending_proposals(Some(new_policy))
    }

    /// Discards any locally staged pending Commit and rolls back all deferred metadata
    /// (`consumed_kp_ref`, invite use counter, self-update `DeviceIdentity`).
    pub fn discard_pending_commit(&mut self) -> Result<(), MpMlsError> {
        self.group
            .clear_pending_commit(self.provider.storage())
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        self.pending_commit_meta = None;
        Ok(())
    }

    /// Validates an incoming tentative `Commit` on an **isolated snapshot** (zero live state mutation!)
    /// and emits a signed `CommitAckV1` (`"mp-mls-ack-v1:"`):
    /// - Returns `Err(MpMlsError::CannotEvaluateTentativeCommit(_))` (DOES NOT sign `REJECT`!) on
    ///   decode errors, group/epoch mismatch, or missing referenced proposals (Fable M3!).
    /// - Emits `AckStatus::Ok` with `SHA-256("mp-mls-ack-auth-v1:" || epoch_authenticator)` on valid Commit.
    /// - Emits `AckStatus::Reject` ONLY on genuine cryptographic/path/confirmation_tag or deterministic policy failures!
    pub fn validate_tentative_commit_and_sign_ack(
        &self,
        commit_bytes: &[u8],
    ) -> Result<CommitAckV1, MpMlsError> {
        // Pre-check wire framing, group_id, and epoch BEFORE signing any REJECT!
        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(commit_bytes)
            .map_err(|_| MpMlsError::CannotEvaluateTentativeCommit("commit decode failed"))?;
        let proto_msg: ProtocolMessage = msg_in
            .try_into_protocol_message()
            .map_err(|_| MpMlsError::CannotEvaluateTentativeCommit("not a ProtocolMessage"))?;
        if proto_msg.group_id().as_slice() != self.group_id {
            return Err(MpMlsError::CannotEvaluateTentativeCommit(
                "group_id mismatch",
            ));
        }
        let parent_epoch = self.epoch();
        if proto_msg.epoch().as_u64() != parent_epoch {
            return Err(MpMlsError::CannotEvaluateTentativeCommit(
                "epoch mismatch (client not at commit parent_epoch)",
            ));
        }

        let target_epoch = parent_epoch
            .checked_add(1)
            .ok_or(MpMlsError::InvalidSafeCounter(u64::MAX))?;
        let commit_sha256 = sha256(commit_bytes);

        match self.stage_incoming_commit_isolated(commit_bytes) {
            Ok((_iso_provider, _iso_group, staged, _sender)) => {
                let auth_hash = staged
                    .epoch_authenticator()
                    .map(|a| hash_epoch_authenticator_for_ack(a.as_slice()));
                CommitAckV1::sign(
                    self.group_id,
                    parent_epoch,
                    target_epoch,
                    commit_sha256,
                    self.identity.account_id(),
                    self.identity.device_id(),
                    AckStatus::Ok,
                    auth_hash,
                    &self.identity.device_sk,
                )
            }
            Err(MpMlsError::CannotEvaluateTentativeCommit(reason)) => {
                Err(MpMlsError::CannotEvaluateTentativeCommit(reason))
            }
            Err(_) => CommitAckV1::sign(
                self.group_id,
                parent_epoch,
                target_epoch,
                commit_sha256,
                self.identity.account_id(),
                self.identity.device_id(),
                AckStatus::Reject,
                None,
                &self.identity.device_sk,
            ),
        }
    }

    fn stage_incoming_commit_isolated(
        &self,
        commit_bytes: &[u8],
    ) -> Result<
        (
            MpCryptoProvider,
            MlsGroup,
            openmls::prelude::StagedCommit,
            Sender,
        ),
        MpMlsError,
    > {
        let prev_leaves = self.current_leaves_map()?;
        let isolated = self.provider.fork_isolated()?;
        let mut iso_group =
            MlsGroup::load(isolated.storage(), &GroupId::from_slice(&self.group_id))
                .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
                .ok_or_else(|| MpMlsError::OpenMls("group missing in snapshot".into()))?;

        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(commit_bytes)
            .map_err(|_| MpMlsError::CannotEvaluateTentativeCommit("commit decode failed"))?;
        let proto_msg: ProtocolMessage = msg_in
            .try_into_protocol_message()
            .map_err(|_| MpMlsError::CannotEvaluateTentativeCommit("not a ProtocolMessage"))?;

        let processed = iso_group.process_message(&isolated, proto_msg).map_err(|e| {
            match e {
                ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => {
                    MpMlsError::CannotEvaluateTentativeCommit("wrong epoch")
                }
                ProcessMessageError::ValidationError(ValidationError::WrongGroupId) => {
                    MpMlsError::CannotEvaluateTentativeCommit("wrong group_id")
                }
                ProcessMessageError::InvalidCommit(StageCommitError::MissingProposal) => {
                    MpMlsError::CannotEvaluateTentativeCommit(
                        "referenced proposal has not arrived yet",
                    )
                }
                other => MpMlsError::OpenMls(format!("process_message(Commit) failed: {other}")),
            }
        })?;

        let sender = processed.sender().clone();
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(sc) => *sc,
            _ => {
                return Err(MpMlsError::ForbiddenProposal(
                    "expected StagedCommitMessage",
                ));
            }
        };

        // Pure deterministic validation (zero wall-clock / cache dependency!).
        let _ = validate_commit_deterministic(
            &sender,
            &staged,
            iso_group.public_group().group_context(),
            &prev_leaves,
        )?;

        Ok((isolated, iso_group, staged, sender))
    }

    /// Applies a finalized `Commit` to live state at explicit wall-clock `now_s` (for 120s past-epoch
    /// retirement tracking).
    /// - If `commit_bytes` matches our own pending Commit, runs the EXACT same deterministic
    ///   validator (`validate_commit_deterministic`) as recipients before merging, then applies
    ///   deferred `PendingCommitMeta` (`consumed_kp_ref`, `uses_seen`, `updated_identity`).
    /// - Otherwise checks own-leaf sender BEFORE OpenMLS staging (ensuring reliable clone detection
    ///   even when OpenMLS would return `OwnCommitMismatch`, Fable H3 / Astra §6), stages on
    ///   isolated snapshot, validates deterministically, and commits atomically.
    /// - Clears all locally cached `InviteRecordV1`s on ANY `Remove` Commit (§4.2).
    /// - Prunes bounded per-epoch caches (`seen_inner_msg_ids`, `consumed_kp_refs`).
    pub fn apply_finalized_commit(
        &mut self,
        commit_bytes: &[u8],
        now_s: u64,
    ) -> Result<LocalPolicyReport, MpMlsError> {
        check_safe_counter(now_s)?;
        let prev_epoch = self.epoch();
        let commit_hash = sha256(commit_bytes);

        if self
            .pending_commit_meta
            .as_ref()
            .is_some_and(|m| m.commit_sha256 == commit_hash)
        {
            // Enforce IDENTICAL deterministic commit validation for authors and recipients (Astra §3)!
            let prev_leaves = self.current_leaves_map()?;
            let pending_staged = self
                .group
                .pending_commit()
                .ok_or_else(|| MpMlsError::OpenMls("pending commit missing".into()))?;
            let own_sender = Sender::Member(self.group.own_leaf_index());
            let _ = validate_commit_deterministic(
                &own_sender,
                pending_staged,
                self.group.public_group().group_context(),
                &prev_leaves,
            )?;
            let had_remove = pending_staged.remove_proposals().next().is_some();

            self.group
                .merge_pending_commit(&self.provider)
                .map_err(|e| MpMlsError::OpenMls(format!("merge_pending_commit failed: {e}")))?;

            let new_epoch = self.epoch();
            if let Some(meta) = self.pending_commit_meta.take() {
                if let Some(kp_ref) = meta.consumed_kp_ref {
                    self.consumed_kp_refs.insert(kp_ref, new_epoch);
                }
                if let Some(inv_id) = meta.invite_id_used
                    && let Some(st) = self.active_invites.get_mut(&inv_id)
                {
                    st.uses_seen = st.uses_seen.saturating_add(1);
                }
                if let Some(new_id) = meta.updated_identity {
                    self.identity = new_id;
                    let _ = self
                        .device_lists
                        .observe(self.identity.device_list.clone(), &self.pins, None);
                }
            }

            self.on_epoch_advanced(prev_epoch, new_epoch, now_s, had_remove);
            return self.post_commit_local_update(Some(now_s));
        }

        // Clone detection BEFORE calling OpenMLS `process_message` (Fable H3 / Astra §6):
        // OpenMLS rejects an unauthored Commit from our own leaf with `OwnCommitMismatch`, so we
        // MUST inspect the wire sender first to raise `ClonedDeviceKeySuspected` reliably!
        if let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact_bytes(commit_bytes)
            && let MlsMessageBodyIn::PublicMessage(pm) = msg_in.extract()
            && pm.group_id().as_slice() == self.group_id
            && pm.epoch().as_u64() == prev_epoch
            && pm.sender() == &Sender::Member(self.group.own_leaf_index())
        {
            self.cloned_device_key_suspected = true;
            return Err(MpMlsError::ClonedDeviceKeySuspected);
        }

        let prev_leaves = self.current_leaves_map()?;
        let (isolated, mut iso_group, staged, sender) =
            self.stage_incoming_commit_isolated(commit_bytes)?;

        // If this commit was authored by our pinned inviter in `epoch >= join_epoch`, clear `inviter_unconfirmed`!
        let inviter_confirmed_by_commit = if self.inviter_unconfirmed
            && let (Some(pinned_inv), Sender::Member(committer_idx)) =
                (self.pinned_inviter_root_pk, &sender)
            && let Some(committer_leaf) = prev_leaves.get(&committer_idx.u32())
        {
            committer_leaf.cred.binding.body.root_pubkey == pinned_inv
                && staged.epoch().as_u64() >= self.join_epoch
        } else {
            false
        };

        let had_remove = staged.remove_proposals().next().is_some();
        iso_group
            .merge_staged_commit(&isolated, staged)
            .map_err(|e| MpMlsError::OpenMls(format!("merge_staged_commit failed: {e}")))?;

        self.provider.commit_from_isolated(isolated)?;
        self.group = iso_group;
        self.pending_commit_meta = None;
        if inviter_confirmed_by_commit {
            self.inviter_unconfirmed = false;
        }

        let new_epoch = self.epoch();
        self.on_epoch_advanced(prev_epoch, new_epoch, now_s, had_remove);
        self.post_commit_local_update(Some(now_s))
    }

    fn on_epoch_advanced(&mut self, prev_epoch: u64, new_epoch: u64, now_s: u64, had_remove: bool) {
        self.device_epoch_seq = 0;
        self.total_sent_frames_in_epoch = 0;
        if had_remove {
            self.active_invites.clear();
        }
        self.epoch_retired_at_s.insert(prev_epoch, now_s);
        while self.epoch_retired_at_s.len() > MP_MAX_PAST_EPOCHS {
            if let Some(&oldest) = self.epoch_retired_at_s.keys().next() {
                self.epoch_retired_at_s.remove(&oldest);
            }
        }
        let min_keep = new_epoch.saturating_sub(MP_MAX_PAST_EPOCHS as u64);
        self.seen_inner_msg_ids.retain(|_, &mut ep| ep >= min_keep);
        self.consumed_kp_refs.retain(|_, &mut ep| ep >= min_keep);
    }

    fn post_commit_local_update(
        &mut self,
        now_s: Option<u64>,
    ) -> Result<LocalPolicyReport, MpMlsError> {
        let leaves = self.current_leaves_map()?;
        // First evaluate against existing pins & device lists BEFORE auto-pinning unseen accounts.
        let report = evaluate_local_policy(&leaves, &self.pins, &self.device_lists, now_s);
        for info in leaves.values() {
            let b = &info.cred.binding.body;
            if self.pins.get(b.account_id).is_none() {
                let _ = self
                    .pins
                    .check_or_pin(b.account_id, b.root_pubkey, b.root_gen, b.custody_mode);
            }
            // Advance tracked device list if the leaf carries a newer valid list under its pinned root.
            let _ = self
                .device_lists
                .observe(info.device_list.clone(), &self.pins, None);
        }
        Ok(report)
    }

    /// Encrypts an application message into an exact-bucket (`512`, `2048`, `8192`, `24000` B)
    /// `MLSMessage(PrivateMessage)` with strict `MpAppAadV1` and canonical `MpAppPayloadV1`.
    ///
    /// Hard safety invariants:
    /// - Rejects `plaintext.len() > MAX_APP_BODY_BYTES` BEFORE copying plaintext or touching state!
    /// - Blocks sends if `cloned_device_key_suspected`, `inviter_unconfirmed` (Tier 0 delegated join),
    ///   `total_sent_frames_in_epoch >= 900` (`MP_MAX_FRAMES_PER_EPOCH`), OR `evaluate_local_policy(Some(now_s)).should_block_send()`.
    /// - Stages `create_message` on an **isolated storage snapshot** and commits back ONLY AFTER
    ///   exact wire bucket length verification succeeds (zero ratchet advancement on any error!).
    pub fn encrypt_app_message(
        &mut self,
        inner_msg_id: [u8; 16],
        msg_class: MsgClass,
        plaintext: &[u8],
        now_s: u64,
    ) -> Result<PendingOutboxEntry, MpMlsError> {
        if plaintext.len() > MAX_APP_BODY_BYTES {
            return Err(MpMlsError::PayloadExceedsMaxBucket);
        }
        check_safe_counter(now_s)?;
        if self.cloned_device_key_suspected {
            return Err(MpMlsError::ClonedDeviceKeySuspected);
        }
        if self.inviter_unconfirmed {
            return Err(MpMlsError::SendBlockedByLocalPolicy(
                "delegated Welcome is Tier-0 Inviter Unconfirmed until inviter sends a message or Commit",
            ));
        }
        if self.total_sent_frames_in_epoch >= MP_MAX_FRAMES_PER_EPOCH {
            return Err(MpMlsError::FrameLimitExceeded {
                sent: self.total_sent_frames_in_epoch,
                max: MP_MAX_FRAMES_PER_EPOCH,
            });
        }
        let local_report = self.evaluate_local_policy(Some(now_s))?;
        if local_report.should_block_send() {
            return Err(MpMlsError::SendBlockedByLocalPolicy(
                "local policy report flagged pending removal, pin violation, equivocation, or expired leaf",
            ));
        }

        // Encode & pad directly from slice BEFORE touching OpenMLS ratchet state!
        let (padded_bytes, expected_wire_len) =
            MpAppPayloadV1::encode_padded_slice(msg_class, inner_msg_id, plaintext)?;

        let epoch = self.epoch();
        let seq = self.device_epoch_seq;
        let aad = MpAppAadV1 {
            party_id: self.party_id,
            mls_epoch: epoch,
            sender_device_id: self.identity.device_id(),
            device_epoch_seq: seq,
            msg_class,
        };
        let aad_bytes = aad.encode()?;

        // Stage encryption on an isolated storage snapshot so ANY error (including wire bucket
        // mismatch) leaves the live OpenMLS sender ratchet 100% unadvanced (Astra §6)!
        let isolated = self.provider.fork_isolated()?;
        let mut iso_group =
            MlsGroup::load(isolated.storage(), &GroupId::from_slice(&self.group_id))
                .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
                .ok_or_else(|| MpMlsError::OpenMls("group missing in snapshot".into()))?;

        let signer = self.identity.openmls_signer();
        iso_group.set_aad(aad_bytes.to_vec());
        let msg_out = iso_group
            .create_message(&isolated, &signer, &padded_bytes)
            .map_err(|e| MpMlsError::OpenMls(format!("create_message failed: {e}")))?;

        let wire_bytes = msg_out
            .tls_serialize_detached()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        if wire_bytes.len() != expected_wire_len || !WIRE_BUCKETS.contains(&wire_bytes.len()) {
            return Err(MpMlsError::WireBucketSizeMismatch {
                expected: expected_wire_len,
                got: wire_bytes.len(),
            });
        }

        // Commit isolated ratchet state atomically now that all checks passed!
        self.provider.commit_from_isolated(isolated)?;
        self.group = iso_group;
        self.device_epoch_seq = self.device_epoch_seq.saturating_add(1);
        self.total_sent_frames_in_epoch = self.total_sent_frames_in_epoch.saturating_add(1);

        Ok(PendingOutboxEntry {
            inner_msg_id,
            msg_class,
            plaintext: plaintext.to_vec(),
            sent_epoch: epoch,
            device_epoch_seq: seq,
            wire_bytes,
        })
    }

    /// Re-encrypts an unacknowledged outbox message in the current (advanced) epoch,
    /// preserving the exact same `inner_msg_id` for receiver deduplication (§7.2).
    pub fn requeue_stale_outbox_entry(
        &mut self,
        stale_entry: &PendingOutboxEntry,
        now_s: u64,
    ) -> Result<PendingOutboxEntry, MpMlsError> {
        self.encrypt_app_message(
            stale_entry.inner_msg_id,
            stale_entry.msg_class,
            &stale_entry.plaintext,
            now_s,
        )
    }

    /// Decrypts and verifies an inbound `MLSMessage(PrivateMessage)` on an **isolated snapshot**
    /// before committing ratchet state atomically (Spec v3.1 §7.1):
    /// - Returns `Err(MpMlsError::OwnPrivateMessageEcho)` WITHOUT setting `cloned_device_key_suspected`
    ///   when OpenMLS reports `OwnPrivateMessage` (OpenMLS cannot verify sender signatures on own
    ///   messages, so treating an unverified echo as a clone alert would allow a DS DoS; Astra §6).
    /// - Clears `inviter_unconfirmed` if a verified `PrivateMessage` in `epoch >= join_epoch` comes
    ///   from a leaf chaining to `pinned_inviter_root_pk` (§4.2.4).
    pub fn decrypt_app_message(
        &mut self,
        wire_bytes: &[u8],
    ) -> Result<DecryptedAppMessage, MpMlsError> {
        if !WIRE_BUCKETS.contains(&wire_bytes.len()) {
            return Err(MpMlsError::InvalidAppPayload(
                "wire MLSMessage length does not match any canonical bucket",
            ));
        }

        let isolated = self.provider.fork_isolated()?;
        let mut iso_group =
            MlsGroup::load(isolated.storage(), &GroupId::from_slice(&self.group_id))
                .map_err(|e| MpMlsError::OpenMls(e.to_string()))?
                .ok_or_else(|| MpMlsError::OpenMls("group missing in snapshot".into()))?;

        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(wire_bytes)
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;
        let proto_msg: ProtocolMessage = msg_in
            .try_into_protocol_message()
            .map_err(|e| MpMlsError::OpenMls(e.to_string()))?;

        let processed = iso_group
            .process_message(&isolated, proto_msg)
            .map_err(|e| MpMlsError::OpenMls(format!("decrypt PrivateMessage failed: {e}")))?;

        let msg_epoch = processed.epoch().as_u64();
        let aad_raw = processed.aad().to_vec();
        let sender_cred_raw = processed.credential().clone();

        let app_bytes = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => app.into_bytes(),
            ProcessedMessageContent::OwnPrivateMessage => {
                // Spec v3.1 §7.2 / Astra §6: OpenMLS returns OwnPrivateMessage before verifying
                // signature; NEVER suspend an honest sender on an unverified echo!
                return Err(MpMlsError::OwnPrivateMessageEcho);
            }
            _ => {
                return Err(MpMlsError::OpenMls(
                    "expected ApplicationMessage in PrivateMessage".into(),
                ));
            }
        };

        // Authenticate sender credential from MLS leaf at `msg_epoch`.
        let sender_cred = MpMlsLeafCredV1::from_openmls_credential(&sender_cred_raw)?;
        let auth_account_id = sender_cred.binding.body.account_id;
        let auth_device_id = sender_cred.binding.body.device_id;

        if auth_device_id == self.identity.device_id() {
            self.cloned_device_key_suspected = true;
            return Err(MpMlsError::ClonedDeviceKeySuspected);
        }

        // Strict AAD verification against authenticated MLS metadata.
        let aad = MpAppAadV1::decode(&aad_raw)?;
        if aad.party_id != self.party_id {
            return Err(MpMlsError::AadMismatch("aad.party_id mismatch"));
        }
        if aad.mls_epoch != msg_epoch {
            return Err(MpMlsError::AadMismatch("aad.mls_epoch mismatch"));
        }
        if aad.sender_device_id != auth_device_id {
            return Err(MpMlsError::AadMismatch(
                "aad.sender_device_id does not match authenticated MLS sender leaf",
            ));
        }

        // Canonical padded payload decode + cross-check `payload.msg_class == aad.msg_class`.
        let payload = MpAppPayloadV1::decode_padded(&app_bytes)?;
        if payload.msg_class != aad.msg_class {
            return Err(MpMlsError::AadMismatch(
                "MpAppPayloadV1.msg_class does not match MpAppAadV1.msg_class",
            ));
        }

        // Commit isolated OpenMLS ratchet state atomically now that all verification passed!
        self.provider.commit_from_isolated(isolated)?;
        self.group = iso_group;

        // If joined via delegated Welcome, clear `inviter_unconfirmed` once inviter speaks in `epoch >= join_epoch`!
        if self.inviter_unconfirmed
            && msg_epoch >= self.join_epoch
            && self
                .pinned_inviter_root_pk
                .is_some_and(|pk| pk == sender_cred.binding.body.root_pubkey)
        {
            self.inviter_unconfirmed = false;
        }

        let is_duplicate = self
            .seen_inner_msg_ids
            .contains_key(&(auth_device_id, payload.inner_msg_id));
        if !is_duplicate {
            self.seen_inner_msg_ids
                .insert((auth_device_id, payload.inner_msg_id), msg_epoch);
        }

        Ok(DecryptedAppMessage {
            epoch: msg_epoch,
            auth_account_id,
            auth_device_id,
            device_epoch_seq: aad.device_epoch_seq,
            msg_class: payload.msg_class,
            inner_msg_id: payload.inner_msg_id,
            body: payload.body,
            is_duplicate,
        })
    }

    /// Direct mutable access to underlying OpenMLS `MlsGroup` + `MpCryptoProvider`
    /// ONLY for adversarial negative-vector test construction.
    pub fn raw_group_and_provider_mut(&mut self) -> (&mut MlsGroup, &MpCryptoProvider) {
        (&mut self.group, &self.provider)
    }
}
