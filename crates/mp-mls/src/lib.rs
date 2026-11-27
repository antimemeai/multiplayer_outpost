#![forbid(unsafe_code)]

//! Phase 0 `mp-mls` crate implementing `mp2` E2EE over RFC 9420 MLS (`openmls = "=0.9.2"`, Spec v3.1).
//!
//! Zero `unsafe` code, zero JSON in our production codecs (canonical big-endian binary codecs only),
//! compiled for both native targets and `wasm32-unknown-unknown` (`--features wasm`).

pub mod client;
pub mod crypto;
pub mod ds;
pub mod error;
pub mod framing;
pub mod identity;
pub mod invite;
pub mod policy;

pub use client::{
    generate_single_use_key_package, mp_join_config, unbounded_mls_lifetime, AddMemberCommitOutput,
    DecryptedAppMessage, DeviceIdentity, MpMlsClient, PendingOutboxEntry, MP_MAX_FORWARD_DISTANCE,
    MP_MAX_FRAMES_PER_EPOCH, MP_MAX_PAST_EPOCHS, MP_OUT_OF_ORDER_TOLERANCE,
    MP_PAST_EPOCH_RETENTION_SECS, MP_PCS_UPDATE_FRAME_THRESHOLD,
};
pub use crypto::{
    ct_eq_bytes, encode_crockford_grouped_4, is_canonical_ed25519_scalar, sha256, sign_ed25519,
    validate_ed25519_pubkey_strict, verify_ed25519_strict, Ed25519PubKey, Ed25519Sig,
    MpCryptoProvider, MpStrictCrypto, Sha256Digest,
};
pub use ds::{
    compute_interim_transcript_hash, extract_commit_confirmation_tag,
    hash_epoch_authenticator_for_ack, AckStatus, CatchupCommitBundle, CommitAckV1,
    FinalizedCommitRecord, MpMlsPublicDs, QuorumOutcome, StoredProposalRecord,
    ACK_AUTH_HASH_DOMAIN_SEP, COMMIT_ACK_DOMAIN_SEP, MAX_CATCHUP_PAGE_LIMIT,
    MAX_MLS_CATCHUP_EPOCHS,
};
pub use error::MpMlsError;
pub use framing::{
    app_payload_len_for_wire_bucket, MpAppAadV1, MpAppPayloadV1, MsgClass,
    APP_PAYLOAD_OVERHEAD_LEN, BUCKET_APP_LENS, MAX_APP_BODY_BYTES, MAX_MLS_VECTOR_LEN,
    MP_APP_AAD_LEN, MP_APP_AAD_MAGIC, WIRE_BUCKETS,
};
pub use identity::{
    check_safe_counter, check_safe_id, compute_room_trust_tier, compute_safety_number_v2,
    format_epoch_authenticator, AccountDeviceListV1, AccountRootPinStore, ActiveDeviceEntryV1,
    ClientClass, CustodyMode, DeviceListTracker, MpMlsDeviceBindingBodyV1, MpMlsDeviceBindingV1,
    MpMlsLeafCredV1, PinnedAccountRoot, RoomTrustTier, RootRotationStmtV1,
    ACTIVE_DEVICE_ENTRY_LEN, DEVICE_BINDING_BODY_LEN, DEVICE_BINDING_LEN, LEAF_CRED_LEN,
    MAX_BROWSER_BINDING_TTL_S, MAX_DEVICES_PER_ACCOUNT, MAX_DEVICE_LIST_TTL_S,
    MAX_NATIVE_BINDING_TTL_S, MAX_SAFE_ID, ROOT_ROTATION_BODY_LEN, ROOT_ROTATION_LEN,
};
pub use invite::{
    compute_join_proof, validate_policy_bits, verify_join_proof, InviteFragmentV2, InviteRecordV1,
    InviteSecrets, WelcomeAuthV1, INVITE_FRAGMENT_V2_LEN, INVITE_RECORD_V1_LEN,
    POLICY_BIT_DISALLOW_BROWSER_DEVICES, POLICY_BIT_REQUIRE_SELF_CUSTODY, VALID_POLICY_BITS_MASK,
    WELCOME_AUTH_V1_LEN,
};
pub use policy::{
    build_ds_external_sender, ds_external_sender_credential, evaluate_local_policy,
    extract_public_group_leaves, leaf_capabilities, leaf_device_list_extensions,
    required_capabilities_extension, validate_commit_deterministic, validate_key_package_admission,
    validate_leaf_identity_continuity, validate_leaf_node_credential,
    validate_proposal_deterministic, validate_staged_welcome, validate_tree_invariants,
    validate_welcome_public_group_leaves, LocalPolicyReport, MpGroupId, MpRoomPolicyExtV1,
    TreeLeafInfo, CATCHUP_SAFE_LIFETIME_NOT_AFTER, CATCHUP_SAFE_LIFETIME_NOT_BEFORE,
    MAX_ACCOUNTS_PER_ROOM, MAX_BANNED_ACCOUNTS, MAX_HOST_ACCOUNTS, MAX_LEAVES_PER_ROOM,
    MP_CIPHERSUITE, MP_DS_CRED_PREFIX, MP_GROUP_ID_LEN, MP_GROUP_ID_PREFIX,
    MP_LEAF_DEVICE_LIST_EXT_TYPE, MP_ROOM_POLICY_EXT_TYPE,
};
