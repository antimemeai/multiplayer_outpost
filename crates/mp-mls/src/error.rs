use thiserror::Error;

/// Unified error type for `mp-mls` protocol, identity, policy, framing, client, and DS logic.
#[derive(Debug, Error)]
pub enum MpMlsError {
    // --- Codec & integer range errors ---
    #[error("invalid binary length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("truncated binary input")]
    TruncatedInput,

    #[error("trailing bytes in canonical binary input")]
    TrailingBytes,

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("identifier out of safe range (1..=MAX_SAFE_ID): {0}")]
    InvalidSafeId(u64),

    #[error("counter out of safe range (0..=MAX_SAFE_ID): {0}")]
    InvalidSafeCounter(u64),

    #[error("invalid enum value for {field}: {value}")]
    InvalidEnumValue { field: &'static str, value: u64 },

    #[error("invalid base64url encoding")]
    InvalidBase64,

    #[error("unknown or reserved policy_bits set: 0x{0:02x}")]
    InvalidPolicyBits(u8),

    #[error("duplicate or unsorted key in binary storage snapshot")]
    DuplicateOrUnsortedStorageKey,

    #[error("corrupted binary snapshot: {0}")]
    SnapshotCorrupted(&'static str),

    // --- Strict Ed25519 / crypto errors ---
    #[error("invalid or non-canonical Ed25519 public key")]
    InvalidPublicKey,

    #[error("weak, small-order, or mixed-order Ed25519 point rejected")]
    WeakOrTorsionPoint,

    #[error("strict Ed25519 signature verification failed")]
    InvalidSignature,

    #[error("HMAC verification failed")]
    InvalidMac,

    #[error("HKDF derivation failed")]
    HkdfError,

    // --- Identity / AS errors ---
    #[error("invalid binding generation: {field} must be >= 1")]
    InvalidGeneration { field: &'static str },

    #[error("invalid timestamp window (iat_s={iat_s}, exp_s={exp_s})")]
    InvalidTimestampWindow { iat_s: u64, exp_s: u64 },

    #[error("binding or device list TTL exceeds policy maximum ({ttl_s}s > {max_ttl_s}s)")]
    TtlExceeded { ttl_s: u64, max_ttl_s: u64 },

    #[error("binding, device list, or key package not valid at admission time {now_s}")]
    NotValidAtAdmissionTime { now_s: u64 },

    #[error("device list entries must be strictly ascending and unique by device_id")]
    UnsortedOrDuplicateDeviceList,

    #[error("device list exceeds max devices per account ({count} > {max})")]
    TooManyDevicesInList { count: usize, max: usize },

    #[error("stale AccountDeviceListV1: version {got} < seen {seen}")]
    StaleDeviceList { got: u64, seen: u64 },

    #[error("AccountDeviceListV1 equivocation detected at version {version}")]
    DeviceListEquivocation { version: u64 },

    #[error("custody_mode flip under the same root_pubkey is forbidden")]
    CustodyModeFlipUnderSameRoot,

    #[error("root_pubkey does not match pinned account root")]
    PinnedRootMismatch,

    #[error("root_gen does not match pinned account root")]
    RootGenMismatch,

    #[error("invalid root rotation statement: {0}")]
    InvalidRootRotation(&'static str),

    #[error("leaf signature_key does not match binding mls_sig_pubkey")]
    LeafSignatureKeyMismatch,

    #[error("leaf node missing required 0xFF02 MpLeafDeviceListExtV1 extension")]
    MissingLeafDeviceListExtension,

    #[error("invalid 0xFF02 MpLeafDeviceListExtV1 extension: {0}")]
    InvalidLeafDeviceList(&'static str),

    // --- Policy / GroupContext / Proposal errors ---
    #[error("invalid group_id format or party_id mismatch")]
    InvalidGroupId,

    #[error("missing required MpRoomPolicyExt (0xFF01)")]
    MissingRoomPolicyExtension,

    #[error("invalid room policy extension: {0}")]
    InvalidRoomPolicy(&'static str),

    #[error("forbidden proposal sender or proposal type: {0}")]
    ForbiddenProposal(&'static str),

    #[error("group context extension policy violation: {0}")]
    ExtensionPolicyViolation(&'static str),

    #[error("leaf identity continuity violation: {0}")]
    IdentityContinuityViolation(&'static str),

    #[error("room policy violation: {0}")]
    RoomPolicyViolation(&'static str),

    #[error("tree uniqueness or capacity violation: {0}")]
    TreeInvariantViolation(&'static str),

    #[error("commit missing mandatory UpdatePath")]
    MissingUpdatePath,

    #[error("key package rejected at admission: {0}")]
    KeyPackageAdmissionRejected(&'static str),

    // --- Invite / Welcome errors ---
    #[error("invite expired or usage limit exhausted")]
    InviteExhaustedOrExpired,

    #[error("invite revoked or unknown: {0}")]
    UnknownOrRevokedInvite(u64),

    #[error("welcome does not target expected KeyPackageRef")]
    WelcomeKeyPackageMismatch,

    // --- Framing / Padding / AAD / Client guards ---
    #[error("invalid MpAppAadV1 encoding or magic")]
    InvalidAppAad,

    #[error("authenticated AAD mismatch: {0}")]
    AadMismatch(&'static str),

    #[error("application payload exceeds maximum 24,000 B wire bucket")]
    PayloadExceedsMaxBucket,

    #[error("invalid padded application payload: {0}")]
    InvalidAppPayload(&'static str),

    #[error("exact wire bucket size invariant violated: expected {expected}, got {got}")]
    WireBucketSizeMismatch { expected: usize, got: usize },

    #[error("per-epoch hard frame limit reached ({sent} >= {max}); self-Update Commit required")]
    FrameLimitExceeded { sent: u64, max: u64 },

    #[error("outbound send blocked by local trust/policy state: {0}")]
    SendBlockedByLocalPolicy(&'static str),

    #[error("cloned device key suspected (received unauthored Commit from own device_id)")]
    ClonedDeviceKeySuspected,

    #[error("received unverified own echoed PrivateMessage (ignored without clone alert)")]
    OwnPrivateMessageEcho,

    // --- DS / Quorum errors ---
    #[error("epoch-0 bootstrap violation: {0}")]
    InvalidBootstrap(&'static str),

    #[error("tentative commit state error: {0}")]
    TentativeCommitError(&'static str),

    #[error("cannot evaluate tentative commit (do not sign REJECT): {0}")]
    CannotEvaluateTentativeCommit(&'static str),

    #[error("invalid commit ack: {0}")]
    InvalidCommitAck(&'static str),

    #[error("invalid catch-up page limit (must be 1..=32): {0}")]
    InvalidCatchupLimit(usize),

    // --- OpenMLS engine errors ---
    #[error("openmls error: {0}")]
    OpenMls(String),
}
