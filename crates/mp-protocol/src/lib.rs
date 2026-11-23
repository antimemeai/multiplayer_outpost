#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

pub mod crypto;
pub mod cwt;
pub mod endpoint;
pub mod ids;
pub mod mp1;
pub mod rfc9421;

pub use crypto::{
    CryptoError, DEVICE_FP_DOMAIN_SEP, ENC_SUBKEY_CERT_BODY_BYTES, ENC_SUBKEY_CERT_BYTES,
    ENC_SUBKEY_CERT_DOMAIN_SEP, Ed25519PubKey, Ed25519Sig, EncSubkeyCertClaims, Handle,
    IROH_RELAY_CHALLENGE_DOMAIN_SEP, RECOVERY_KEY_DOMAIN_SEP, RECOVERY_KEY_PREFIX,
    SAFETY_NUMBER_DOMAIN_SEP, Sha256Digest, compute_device_fingerprint, compute_safety_number,
    decode_recovery_key, encode_recovery_key, hash_account_invite_secret, hash_party_invite_secret,
    sha256, validate_ed25519_pubkey_strict, validate_x25519_pubkey_strict, verify_ed25519_strict,
    verify_enc_subkey_cert, verify_iroh_relay_challenge,
};
pub use cwt::{CwtClaims, CwtError, MAX_CWT_BYTES, MAX_CWT_TTL_SECS, encode_device_cwt, verify_device_cwt};
pub use endpoint::{
    DirectAddr, EndpointDescriptor, EndpointError, MAX_DIRECT_ADDRS, MAX_ENDPOINT_DESCRIPTOR_BYTES,
    MAX_RELAY_URL_BYTES, RelayPolicy, TransportKind, validate_corporate_relay_url,
    validate_pinned_relay_url, validate_relay_url,
};
pub use ids::{
    AccountId, DeviceId, IdError, InviteId, MAX_SAFE_ID, PartyId, PartyInviteId, RequestId,
    SessionId,
};
pub use mp1::{
    ErrorFrame, FrameHeader, MAX_MP1_FRAME_BYTES, MAX_PARTY_MEMBERS, MP1_HEADER_BYTES, MP1_VERSION,
    MemberLeaveReason, Mp1Error, Mp1Message, Opcode, PartyDisbandReason, PartyJoinMode,
    PartyLeaderChangeReason, PartyMemberRecord, PartySnapshot, PartyVisibility, PresenceEntry,
    PresenceVisibility, SocialEventKind, SocketRole, decode_frame, encode_frame,
};
pub use rfc9421::{
    HttpMethod, KeyId, MAX_CLOCK_SKEW_SECS, MAX_SIGNATURE_WINDOW_SECS, ParsedSignatureInput,
    Rfc9421Error, Rfc9421Request, VerifiedSignature, build_signature_base, compute_content_digest,
    parse_signature_input, validate_path_and_query, verify_rfc9421_request,
};
