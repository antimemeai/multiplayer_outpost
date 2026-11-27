//! Specification & Security Oracles for `outpost-core` MLS E2EE Store and Session (`v0.7.0`, Spec v3.1).
//!
//! Proves end-to-end:
//! 1. Encrypted `MPM1` local MLS store round-trip, wrong-key/CRC/AAD-transplant rejection,
//!    `(group_id, auth_device_id, inner_msg_id)` dedup ring bounds, and `PinnedAccountRoot`
//!    (including `pending_oob_reverify`) / `KeyPackage` / `WelcomeReceipt` persistence.
//! 2. Atomic persist-before-send invariant (failed persist aborts without leaking unpersisted
//!    outbox entries) + two-Outpost MLS exchange of padded `chat`, `agent_card`, and
//!    `ephemeral_status` across exact `{512, 2048, 8192, 24000}` byte buckets + Tier 0..=3 trust.
//! 3. Strict rejection of plaintext `utf8` frames in `e2ee_mode == 1`, same-epoch exact-byte
//!    idempotent retry, and `409 mls_epoch_stale` requeue preserving `inner_msg_id[16]` dedup.
//! 4. Tentative Commit isolated staging + signed `CommitAckV1` (`OK` & `REJECT`) verified against
//!    `MpMlsPublicDs` + post-removal Forward Secrecy (DS External `Remove` -> failover Commit with
//!    automatic `invite_epoch + 1` bump -> removed member cannot decrypt post-removal traffic) +
//!    deterministic `prune_past_epochs(now_s)` 120s retention purge.
//! 5. `500`-frame PCS self-Update trigger, `900`-frame single-epoch hard cap, and clone detection
//!    send suspension.

#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use mp_mls::{
    AccountDeviceListV1, AckStatus, ActiveDeviceEntryV1, ClientClass, CustodyMode, DeviceIdentity,
    InviteRecordV1, InviteSecrets, MP_GROUP_ID_LEN, MP_PCS_UPDATE_FRAME_THRESHOLD,
    MpCryptoProvider, MpMlsClient, MpMlsDeviceBindingBodyV1, MpMlsDeviceBindingV1,
    MpMlsLeafCredV1, MpMlsPublicDs, MpRoomPolicyExtV1, MsgClass, QuorumOutcome, WIRE_BUCKETS,
    compute_join_proof, generate_single_use_key_package,
};
use openmls::prelude::LeafNodeIndex;
use outpost_core::mls_session::{
    DecryptedInboundPayload, InnerEphemeralStatus, MP_HARD_CAP_FRAMES_PER_EPOCH, MlsRoomSession,
    MlsSessionError,
};
use outpost_core::mls_store::{
    MAX_MLS_DEDUP_ENTRIES, MlsDedupEntry, MlsDedupRing, MlsRoomSnapshotPlain, MlsStoreError,
    PersistedKeyPackage, PersistedOutboxEntry, PersistedPinnedRoot, PersistedWelcomeReceipt,
    decrypt_mls_snapshot, derive_mls_store_key, encrypt_mls_snapshot, encrypt_mls_snapshot_random,
};

const NOW_S: u64 = 1_760_000_000;
const PARTY_ID: u64 = 42_001;

fn make_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn make_identity(
    account_id: u64,
    device_id: u64,
    root_seed: u8,
    device_seed: u8,
    client_class: ClientClass,
    agent_capable: bool,
    custody_mode: CustodyMode,
) -> (SigningKey, DeviceIdentity) {
    let root_sk = make_signing_key(root_seed);
    let dev_sk = make_signing_key(device_seed);
    let ttl_s = match client_class {
        ClientClass::Browser => 7 * 86_400,
        ClientClass::Blackbird | ClientClass::Outpost => 30 * 86_400,
    };
    let iat_s = NOW_S.saturating_sub(60);
    let exp_s = NOW_S.saturating_add(ttl_s - 60);
    let body = MpMlsDeviceBindingBodyV1 {
        version: 1,
        account_id,
        root_gen: 1,
        device_id,
        device_gen: 1,
        client_class,
        agent_capable,
        custody_mode,
        iat_s,
        exp_s,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        mls_sig_pubkey: dev_sk.verifying_key().to_bytes(),
    };
    let Ok(binding) = MpMlsDeviceBindingV1::sign(body, &root_sk, &dev_sk) else {
        unreachable!("sign device binding");
    };
    let Ok(device_list) = AccountDeviceListV1::sign(
        account_id,
        1,
        1,
        iat_s,
        exp_s,
        vec![ActiveDeviceEntryV1 {
            device_id,
            device_gen: 1,
            mls_sig_pubkey: dev_sk.verifying_key().to_bytes(),
        }],
        &root_sk,
    ) else {
        unreachable!("sign account device list");
    };
    let Ok(list_hash) = device_list.list_hash() else {
        unreachable!("hash device list");
    };
    let cred = MpMlsLeafCredV1 {
        binding,
        list_version: device_list.list_version,
        list_hash,
    };
    let Ok(identity) = DeviceIdentity::new(cred, device_list, dev_sk) else {
        unreachable!("create device identity");
    };
    (root_sk, identity)
}

fn make_policy(
    host_account_id: u64,
    require_self_custody: bool,
    allow_browser: bool,
) -> MpRoomPolicyExtV1 {
    MpRoomPolicyExtV1 {
        version: 1,
        party_id: PARTY_ID,
        e2ee_mode: 1,
        require_self_custody,
        allow_browser_devices: allow_browser,
        org_id: 0,
        invite_epoch: 0,
        host_account_ids: vec![host_account_id],
        banned_account_ids: Vec::new(),
    }
}

struct RoomFixture {
    ds: MpMlsPublicDs,
    ds_sk: [u8; 32],
    ds_pk: [u8; 32],
    alice_root_pk: [u8; 32],
    alice: MlsRoomSession,
    bob: MlsRoomSession,
}

fn bootstrap_two_outpost_room() -> RoomFixture {
    let ds_sk_obj = make_signing_key(0xD5);
    let ds_sk = ds_sk_obj.to_bytes();
    let ds_pk = ds_sk_obj.verifying_key().to_bytes();

    let (alice_root_sk, alice_id) = make_identity(
        1001,
        2001,
        0x11,
        0x21,
        ClientClass::Outpost,
        true,
        CustodyMode::SelfCustody,
    );
    let alice_root_pk = alice_root_sk.verifying_key().to_bytes();
    let policy = make_policy(1001, false, true);

    let Ok((alice_client, gi_bytes)) =
        MpMlsClient::create_room(PARTY_ID, [7u8; 8], &ds_pk, policy, alice_id)
    else {
        unreachable!("create_room failed");
    };
    let gid = alice_client.group_id();
    let Ok(mut ds) = MpMlsPublicDs::bootstrap_epoch0(PARTY_ID, gid, ds_pk, &gi_bytes) else {
        unreachable!("bootstrap_epoch0 failed");
    };

    let alice_key = derive_mls_store_key(&[0xA1; 32], 2001);
    let mut alice = MlsRoomSession::new(alice_client, *alice_key);

    // Bob joins via invite-authenticated Add + Welcome + WelcomeAuthV1.
    let (_bob_root_sk, bob_id) = make_identity(
        1002,
        2002,
        0x12,
        0x22,
        ClientClass::Outpost,
        false,
        CustodyMode::SelfCustody,
    );
    let invite_id = 9001u64;
    let invite_epoch = 0u64;
    let expires_at_s = NOW_S + 3600;
    let Ok(secrets) = InviteSecrets::derive(&gid, &[0x55; 32]) else {
        unreachable!("derive invite secrets");
    };
    alice.client_mut().register_active_invite(InviteRecordV1 {
        invite_id,
        invite_epoch,
        max_uses: 4,
        expires_at_s,
        inviter_root_pk: alice_root_pk,
        member_join_mac_key: secrets.member_join_mac_key,
    });

    let mut bob_provider = MpCryptoProvider::new();
    let Ok((bob_kp_bytes, bob_kp_ref)) = generate_single_use_key_package(&bob_id, &bob_provider)
    else {
        unreachable!("generate bob kp");
    };
    let Ok(join_proof) = compute_join_proof(
        &secrets.member_join_mac_key,
        &gid,
        invite_id,
        invite_epoch,
        expires_at_s,
        1002,
        2002,
        &bob_kp_ref,
    ) else {
        unreachable!("compute join proof");
    };

    let Ok(add_out) =
        alice.build_add_member_commit(&bob_kp_bytes, invite_id, &join_proof, NOW_S, false)
    else {
        unreachable!("build add member commit");
    };
    // Solo creator at epoch 0 -> only Alice (committer) is surviving online, so quorum = 0 -> finalized!
    let Ok(outcome) = ds.stage_tentative_commit(&add_out.commit_bytes, 2001, &[1001], NOW_S, 30)
    else {
        unreachable!("stage add commit");
    };
    assert!(matches!(outcome, QuorumOutcome::Finalized { new_epoch: 1, .. }));

    assert!(
        alice
            .handle_finalized_commit(&[], &add_out.commit_bytes, NOW_S)
            .is_ok()
    );

    let Ok(bob_client) = MpMlsClient::join_from_welcome(
        &add_out.welcome_bytes,
        &add_out.welcome_auth,
        &secrets.member_join_mac_key,
        &bob_kp_ref,
        gid,
        PARTY_ID,
        &ds_pk,
        0,
        invite_epoch,
        &alice_root_pk,
        bob_id,
        &mut bob_provider,
    ) else {
        unreachable!("bob join_from_welcome failed");
    };
    let bob_key = derive_mls_store_key(&[0xB2; 32], 2002);
    let bob = MlsRoomSession::new(bob_client, *bob_key);

    RoomFixture {
        ds,
        ds_sk,
        ds_pk,
        alice_root_pk,
        alice,
        bob,
    }
}

#[test]
fn oracle_1_encrypted_mls_store_roundtrip_aad_binding_crc_and_dedup_ring() {
    let secret = [0x42u8; 32];
    let key_a = derive_mls_store_key(&secret, 2001);
    let key_b = derive_mls_store_key(&secret, 2002);
    assert_ne!(key_a, key_b, "device_id must domain-separate store keys");

    let gid = [0x99u8; MP_GROUP_ID_LEN];
    let snap = MlsRoomSnapshotPlain {
        mls_storage_blob: vec![1, 2, 3, 4, 5, 6, 7, 8],
        epoch: 11,
        device_epoch_seq: 42,
        total_sent_frames_in_epoch: 17,
        cloned_device_key_suspected: false,
        local_cache_wiped: false,
        inviter_unconfirmed: true,
        outbox: vec![PersistedOutboxEntry {
            inner_msg_id: [0xAB; 16],
            client_msg_id: "mp2-2001-1".to_string(),
            msg_class: MsgClass::DurableChat as u8,
            target_selector: "@bob".to_string(),
            plaintext: b"hello encrypted world".to_vec(),
            sent_epoch: 11,
            device_epoch_seq: 42,
            wire_bytes: vec![0xEE; 64],
        }],
        dedup_ring: vec![MlsDedupEntry {
            group_id: gid,
            auth_device_id: 2002,
            inner_msg_id: [0xCD; 16],
        }],
        pinned_roots: vec![PersistedPinnedRoot {
            account_id: 1002,
            root_pubkey: [0x33; 32],
            root_gen: 2,
            custody_mode: 1,
            verified_oob: true,
            pending_oob_reverify: true,
        }],
        pending_key_packages: vec![PersistedKeyPackage {
            kp_ref: [0x44; 32],
            kp_wire_bytes: vec![0x55; 48],
            provider_blob: vec![0x61; 32],
            created_at_s: NOW_S,
        }],
        device_binding_236b: vec![0x66; 236],
        device_list_blob: vec![0x77; 128],
        welcome_receipt: Some(PersistedWelcomeReceipt {
            party_id: PARTY_ID,
            group_id: gid,
            target_epoch: 1,
            kp_ref: [0x44; 32],
            acked: false,
        }),
    };

    let nonce = [0x13u8; 12];
    let Ok(sealed) = encrypt_mls_snapshot(&key_a, 2001, PARTY_ID, &gid, &snap, nonce) else {
        unreachable!("encrypt_mls_snapshot failed");
    };
    let Ok(opened) = decrypt_mls_snapshot(&key_a, 2001, PARTY_ID, &gid, &sealed) else {
        unreachable!("decrypt_mls_snapshot failed");
    };
    assert_eq!(opened, snap);

    // Wrong key MUST fail closed with DecryptionFailed!
    assert_eq!(
        decrypt_mls_snapshot(&key_b, 2001, PARTY_ID, &gid, &sealed),
        Err(MlsStoreError::DecryptionFailed)
    );
    // Transplant across device_id, party_id, or group_id MUST fail closed!
    assert_eq!(
        decrypt_mls_snapshot(&key_a, 9999, PARTY_ID, &gid, &sealed),
        Err(MlsStoreError::AadBindingMismatch)
    );
    assert_eq!(
        decrypt_mls_snapshot(&key_a, 2001, PARTY_ID + 1, &gid, &sealed),
        Err(MlsStoreError::AadBindingMismatch)
    );
    let mut other_gid = gid;
    if let Some(b) = other_gid.first_mut() {
        *b ^= 0x01;
    }
    assert_eq!(
        decrypt_mls_snapshot(&key_a, 2001, PARTY_ID, &other_gid, &sealed),
        Err(MlsStoreError::AadBindingMismatch)
    );

    // Single-bit flip in ciphertext MUST fail closed (CRC32C mismatch)!
    let mut flipped = sealed.clone();
    if let Some(b) = flipped.get_mut(sealed.len().saturating_sub(10)) {
        *b ^= 0x80;
    }
    assert_eq!(
        decrypt_mls_snapshot(&key_a, 2001, PARTY_ID, &gid, &flipped),
        Err(MlsStoreError::CrcMismatch)
    );

    // Randomized nonce produces distinct ciphertexts that both decrypt cleanly.
    let Ok(r1) = encrypt_mls_snapshot_random(&key_a, 2001, PARTY_ID, &gid, &snap) else {
        unreachable!("random encrypt 1");
    };
    let Ok(r2) = encrypt_mls_snapshot_random(&key_a, 2001, PARTY_ID, &gid, &snap) else {
        unreachable!("random encrypt 2");
    };
    assert_ne!(r1, r2);
    assert_eq!(
        decrypt_mls_snapshot(&key_a, 2001, PARTY_ID, &gid, &r1),
        Ok(snap.clone())
    );
    assert_eq!(
        decrypt_mls_snapshot(&key_a, 2001, PARTY_ID, &gid, &r2),
        Ok(snap)
    );

    // Dedup ring strictly enforces FIFO cap (MAX_MLS_DEDUP_ENTRIES) and deduplicates on (group_id, auth_device_id, inner_msg_id).
    let mut ring = MlsDedupRing::new();
    let id0 = [0u8; 16];
    assert!(!ring.check_and_insert(gid, 2002, id0));
    assert!(ring.check_and_insert(gid, 2002, id0));
    assert!(!ring.check_and_insert(gid, 2003, id0)); // different device_id is distinct!
    for i in 1..=(MAX_MLS_DEDUP_ENTRIES + 10) {
        let mut id = [0u8; 16];
        if let Some(dst) = id.get_mut(0..8) {
            dst.copy_from_slice(&(i as u64).to_be_bytes());
        }
        assert!(!ring.check_and_insert(gid, 2002, id));
    }
    assert_eq!(ring.len(), MAX_MLS_DEDUP_ENTRIES);
    assert!(!ring.contains(gid, 2002, id0));
}

#[test]
fn oracle_2_persist_before_send_two_outpost_padded_exchange_and_trust_tiers() {
    let mut fx = bootstrap_two_outpost_room();

    // Verify matching 6x4 Crockford Base32 epoch authenticator, Tier 2 (before OOB pin verify), and has_declared_agent=true.
    let st_a = fx.alice.status_snapshot();
    let st_b = fx.bob.status_snapshot();
    assert_eq!(st_a.e2ee_mode, 1);
    assert_eq!(st_a.mls_epoch, 1);
    assert_eq!(st_b.mls_epoch, 1);
    assert_eq!(st_a.epoch_authenticator_b32, st_b.epoch_authenticator_b32);
    assert_eq!(st_a.epoch_authenticator_b32.len(), 29); // 6 groups of 4 + 5 dashes
    assert!(st_a.has_declared_agent);
    assert!(st_b.has_declared_agent);
    assert_eq!(st_a.trust_tier, 2);
    assert_eq!(st_b.trust_tier, 2);
    assert!(!st_a.clone_detected);

    // OOB verify each other's pinned roots -> upgrades to Tier 3!
    assert!(fx.alice.client_mut().pins_mut().mark_verified_oob(1002).is_ok());
    assert!(fx.bob.client_mut().pins_mut().mark_verified_oob(1001).is_ok());
    assert_eq!(fx.alice.status_snapshot().trust_tier, 3);
    assert_eq!(fx.bob.status_snapshot().trust_tier, 3);

    // Persist-before-send oracle: if persist_fn fails, send aborts and outbox does NOT retain entry!
    let failed = fx
        .alice
        .prepare_outbound_chat("cid-fail", "@bob", "never sent", NOW_S, |_| {
            Err("simulated disk full".to_string())
        });
    assert!(matches!(failed, Err(MlsSessionError::PersistFailed(_))));
    assert!(
        fx.alice.outbox_entries().is_empty(),
        "failed persist MUST roll back outbox entry"
    );

    // 1. Exchange padded `chat` preserving encrypted inner `target_selector` across buckets!
    let mut persisted_blobs: Vec<Vec<u8>> = Vec::new();
    let short_chat = "hello bob, E2EE works!";
    let Ok(prep_chat) = fx.alice.prepare_outbound_chat(
        "cid-chat-1",
        "@bob:agent",
        short_chat,
        NOW_S,
        |enc| {
            persisted_blobs.push(enc.to_vec());
            Ok(())
        },
    ) else {
        unreachable!("prepare_outbound_chat failed");
    };
    assert_eq!(persisted_blobs.len(), 1);
    // Verify persisted snapshot decrypts and contains the outbox entry BEFORE WS transmit!
    let alice_key = derive_mls_store_key(&[0xA1; 32], 2001);
    let gid = fx.alice.group_id();
    let Some(last_blob) = persisted_blobs.last() else {
        unreachable!("expected persisted blob");
    };
    let Ok(restored_snap) = decrypt_mls_snapshot(&alice_key, 2001, PARTY_ID, &gid, last_blob) else {
        unreachable!("decrypt persisted snapshot");
    };
    assert_eq!(restored_snap.outbox.len(), 1);
    assert_eq!(
        restored_snap.outbox.first().map(|e| e.client_msg_id.as_str()),
        Some("cid-chat-1")
    );

    // Bob decrypts chat -> verifies authenticated sender + inner target + exact plaintext!
    let Ok(dec_chat) = fx
        .bob
        .decrypt_inbound_mp2("opaque_b64", &prep_chat.body_b64, false)
    else {
        unreachable!("bob decrypt chat failed");
    };
    assert_eq!(dec_chat.auth_account_id, 1001);
    assert_eq!(dec_chat.auth_device_id, 2001);
    assert!(!dec_chat.sender_is_browser);
    assert!(dec_chat.sender_agent_capable);
    assert!(!dec_chat.is_duplicate);
    assert_eq!(
        dec_chat.payload,
        DecryptedInboundPayload::Chat {
            target_selector: "@bob:agent".to_string(),
            body: short_chat.to_string(),
        }
    );

    // 2. Exchange padded `agent_card` across 2048 B, 8192 B, and 24000 B wire buckets!
    let medium_card = vec![b'C'; 900];
    let Ok(prep_card_med) = fx
        .alice
        .prepare_outbound_agent_card("cid-card-med", &medium_card, NOW_S, |_| Ok(()))
    else {
        unreachable!("prepare medium card");
    };
    let large_card = vec![b'L'; 3_500];
    let Ok(prep_card_lg) = fx
        .alice
        .prepare_outbound_agent_card("cid-card-lg", &large_card, NOW_S, |_| Ok(()))
    else {
        unreachable!("prepare large card");
    };
    let xlarge_card = vec![b'X'; 12_000];
    let Ok(prep_card_xl) = fx
        .alice
        .prepare_outbound_agent_card("cid-card-xl", &xlarge_card, NOW_S, |_| Ok(()))
    else {
        unreachable!("prepare xlarge card");
    };
    // Verify exact final serialized MLSMessage wire lengths match {512, 2048, 8192, 24000} B buckets!
    assert_eq!(WIRE_BUCKETS, [512, 2048, 8192, 24_000]);
    assert_eq!(prep_chat.wire_bytes.len(), 512);
    assert_eq!(prep_card_med.wire_bytes.len(), 2048);
    assert_eq!(prep_card_lg.wire_bytes.len(), 8192);
    assert_eq!(prep_card_xl.wire_bytes.len(), 24_000);

    for (prep, expected) in [
        (&prep_card_med, medium_card),
        (&prep_card_lg, large_card),
        (&prep_card_xl, xlarge_card),
    ] {
        let Ok(dec) = fx.bob.decrypt_inbound_mp2("opaque_b64", &prep.body_b64, false) else {
            unreachable!("bob decrypt card failed");
        };
        assert_eq!(
            dec.payload,
            DecryptedInboundPayload::AgentCard { payload: expected }
        );
    }

    // 3. Exchange encrypted `ephemeral_status`!
    let Ok(prep_eph) = fx.alice.prepare_outbound_ephemeral_status(
        "cid-eph-1",
        "Claude Code",
        "thinking",
        Some("verifying MLS buckets"),
        NOW_S,
        |_| Ok(()),
    ) else {
        unreachable!("prepare ephemeral status");
    };
    assert_eq!(prep_eph.wire_bytes.len(), 512);
    let Ok(dec_eph) = fx
        .bob
        .decrypt_inbound_mp2("opaque_b64", &prep_eph.body_b64, false)
    else {
        unreachable!("bob decrypt ephemeral status");
    };
    assert_eq!(
        dec_eph.payload,
        DecryptedInboundPayload::EphemeralStatus(InnerEphemeralStatus {
            agent_name: "Claude Code".to_string(),
            agent_state: "thinking".to_string(),
            agent_summary: Some("verifying MLS buckets".to_string()),
        })
    );
}

#[test]
fn oracle_3_reject_plaintext_utf8_and_epoch_stale_requeue_dedup() {
    let mut fx = bootstrap_two_outpost_room();

    // Plaintext utf8 MUST be strictly rejected in e2ee_mode == 1!
    let rejected = fx
        .bob
        .decrypt_inbound_mp2("utf8", "plaintext injection attempt", false);
    assert!(matches!(
        rejected,
        Err(MlsSessionError::PlaintextRejectedInE2eeRoom)
    ));

    // Send chat at epoch 1 and verify same-epoch retry returns EXACT stored wire bytes (zero ratchet advance)!
    let Ok(first) = fx.alice.prepare_outbound_chat(
        "cid-retry-1",
        "@all",
        "idempotent message",
        NOW_S,
        |_| Ok(()),
    ) else {
        unreachable!("first send");
    };
    let sent_count_after_first = fx.alice.total_sent_frames_in_epoch();
    let Ok(retry) = fx.alice.prepare_outbound_chat(
        "cid-retry-1",
        "@all",
        "idempotent message",
        NOW_S,
        |_| Ok(()),
    ) else {
        unreachable!("same-epoch retry");
    };
    assert_eq!(first.wire_bytes, retry.wire_bytes);
    assert_eq!(first.inner_msg_id, retry.inner_msg_id);
    assert_eq!(fx.alice.total_sent_frames_in_epoch(), sent_count_after_first);

    // Advance epoch via PCS self-Update (simulating `409 mls_epoch_stale` on Alice's unacked outbox entry).
    let Ok(pcs_commit) = fx.alice.build_pcs_self_update_commit() else {
        unreachable!("pcs commit");
    };
    // Only Alice online -> quorum = 0 -> immediate finalize
    assert!(
        fx.ds
            .stage_tentative_commit(&pcs_commit, 2001, &[1001], NOW_S + 1, 30)
            .is_ok()
    );
    assert!(
        fx.alice
            .handle_finalized_commit(&[], &pcs_commit, NOW_S + 1)
            .is_ok()
    );
    assert!(
        fx.bob
            .handle_finalized_commit(&[], &pcs_commit, NOW_S + 1)
            .is_ok()
    );
    assert_eq!(fx.alice.epoch(), 2);
    assert_eq!(fx.bob.epoch(), 2);

    // Stale outbox entry is detected and re-encrypted in epoch 2 keeping EXACT inner_msg_id[16]!
    assert_eq!(
        fx.alice.stale_outbox_client_msg_ids(),
        vec!["cid-retry-1".to_string()]
    );
    let Ok(requeued) = fx
        .alice
        .requeue_stale_outbox_entry("cid-retry-1", NOW_S + 1, |_| Ok(()))
    else {
        unreachable!("requeue stale outbox");
    };
    assert_eq!(requeued.mls_epoch, 2);
    assert_eq!(requeued.inner_msg_id, first.inner_msg_id);
    assert_ne!(requeued.wire_bytes, first.wire_bytes);

    // Bob receives epoch-1 frame (past-epoch window = 2) AND epoch-2 requeued frame:
    // second MUST be flagged `is_duplicate == true` via (group_id, auth_device_id, inner_msg_id)!
    let Ok(dec1) = fx.bob.decrypt_inbound_mp2("opaque_b64", &first.body_b64, false) else {
        unreachable!("bob decrypt epoch-1 frame");
    };
    assert!(!dec1.is_duplicate);
    let Ok(dec2) = fx
        .bob
        .decrypt_inbound_mp2("opaque_b64", &requeued.body_b64, false)
    else {
        unreachable!("bob decrypt epoch-2 requeued frame");
    };
    assert!(
        dec2.is_duplicate,
        "requeued epoch-stale frame with identical inner_msg_id MUST be deduplicated"
    );

    // Ack clears outbox and persists!
    let Ok(removed) = fx.alice.ack_outbox("cid-retry-1", |_| Ok(())) else {
        unreachable!("ack outbox");
    };
    assert!(removed);
    assert!(fx.alice.outbox_entries().is_empty());
}

#[test]
fn oracle_4_tentative_commit_ack_and_post_removal_forward_secrecy() {
    let mut fx = bootstrap_two_outpost_room();

    // Add Charlie (device 2003, account 1003) so we have 3 members & can test quorum ack + post-removal FS!
    let (_charlie_root_sk, charlie_id) = make_identity(
        1003,
        2003,
        0x13,
        0x23,
        ClientClass::Outpost,
        false,
        CustodyMode::SelfCustody,
    );
    let gid = fx.alice.group_id();
    let invite_id = 9002u64;
    let invite_epoch = 0u64;
    let expires_at_s = NOW_S + 3600;
    let Ok(secrets) = InviteSecrets::derive(&gid, &[0x66; 32]) else {
        unreachable!("derive invite 2");
    };
    fx.alice.client_mut().register_active_invite(InviteRecordV1 {
        invite_id,
        invite_epoch,
        max_uses: 2,
        expires_at_s,
        inviter_root_pk: fx.alice_root_pk,
        member_join_mac_key: secrets.member_join_mac_key,
    });
    let mut charlie_provider = MpCryptoProvider::new();
    let Ok((charlie_kp, charlie_kp_ref)) =
        generate_single_use_key_package(&charlie_id, &charlie_provider)
    else {
        unreachable!("charlie kp");
    };
    let Ok(join_proof) = compute_join_proof(
        &secrets.member_join_mac_key,
        &gid,
        invite_id,
        invite_epoch,
        expires_at_s,
        1003,
        2003,
        &charlie_kp_ref,
    ) else {
        unreachable!("charlie join proof");
    };
    let Ok(add_charlie) = fx.alice.build_add_member_commit(
        &charlie_kp,
        invite_id,
        &join_proof,
        NOW_S,
        false,
    ) else {
        unreachable!("add charlie commit");
    };

    // DS stages tentative commit with online surviving accounts [1001, 1002] -> Bob (1002) must ack!
    let Ok(pending) = fx.ds.stage_tentative_commit(
        &add_charlie.commit_bytes,
        2001,
        &[1001, 1002],
        NOW_S + 2,
        30,
    ) else {
        unreachable!("stage tentative add charlie");
    };
    assert!(matches!(
        pending,
        QuorumOutcome::Pending {
            acked_accounts: 0,
            eligible_online_accounts: 1,
            ..
        }
    ));

    // Bob validates a CORRUPTED commit tentatively -> returns REJECT without mutating Bob's epoch!
    let mut bad_commit = add_charlie.commit_bytes.clone();
    if let Some(last) = bad_commit.last_mut() {
        *last ^= 0xFF;
    }
    let Ok(reject_ack) = fx.bob.handle_tentative_commit(&[], &bad_commit) else {
        unreachable!("corrupted tentative commit should produce REJECT ack");
    };
    assert_eq!(reject_ack.status, AckStatus::Reject);
    assert_eq!(fx.bob.epoch(), 1);

    // Bob validates the REAL tentative commit -> signed OK CommitAckV1 with epoch_auth_hash!
    let Ok(ok_ack) = fx.bob.handle_tentative_commit(&[], &add_charlie.commit_bytes) else {
        unreachable!("bob tentative commit ok");
    };
    assert_eq!(ok_ack.status, AckStatus::Ok);
    assert!(ok_ack.epoch_auth_hash.is_some());
    assert_eq!(fx.bob.epoch(), 1, "tentative staging MUST NOT mutate live epoch");

    let Ok(finalized) = fx.ds.record_commit_ack(&ok_ack, NOW_S + 3) else {
        unreachable!("ds record_commit_ack");
    };
    assert!(matches!(
        finalized,
        QuorumOutcome::Finalized { new_epoch: 2, .. }
    ));

    // Alice & Bob merge finalized commit; Charlie joins from Welcome.
    assert!(
        fx.alice
            .handle_finalized_commit(&[], &add_charlie.commit_bytes, NOW_S + 3)
            .is_ok()
    );
    assert!(
        fx.bob
            .handle_finalized_commit(&[], &add_charlie.commit_bytes, NOW_S + 3)
            .is_ok()
    );
    let Ok(charlie_client) = MpMlsClient::join_from_welcome(
        &add_charlie.welcome_bytes,
        &add_charlie.welcome_auth,
        &secrets.member_join_mac_key,
        &charlie_kp_ref,
        gid,
        PARTY_ID,
        &fx.ds_pk,
        0,
        invite_epoch,
        &fx.alice_root_pk,
        charlie_id,
        &mut charlie_provider,
    ) else {
        unreachable!("charlie join_from_welcome");
    };
    let mut charlie =
        MlsRoomSession::new(charlie_client, *derive_mls_store_key(&[0xC3; 32], 2003));
    assert_eq!(charlie.epoch(), 2);

    // Find Charlie's leaf index and issue DS External Remove!
    let leaves = fx.alice.client().current_leaves_map().unwrap_or_default();
    let Some((&charlie_leaf_u32, _)) = leaves
        .iter()
        .find(|(_, info)| info.cred.binding.body.device_id == 2003)
    else {
        unreachable!("charlie leaf not found");
    };
    let Ok((_prop_ref, remove_prop_blob)) = fx
        .ds
        .create_external_remove(LeafNodeIndex::new(charlie_leaf_u32), &fx.ds_sk)
    else {
        unreachable!("create_external_remove");
    };

    // Alice receives MlsRekeyNeeded -> outbound sends are SUSPENDED!
    fx.alice
        .handle_rekey_needed(std::slice::from_ref(&remove_prop_blob));
    assert!(fx.alice.mls_rekey_required());
    assert!(matches!(
        fx.alice.prepare_outbound_chat(
            "blocked-during-rekey",
            "@all",
            "nope",
            NOW_S + 4,
            |_| Ok(()),
        ),
        Err(MlsSessionError::SendBlockedRekeyRequired)
    ));

    // Alice builds failover rekey Commit covering the DS External Remove (auto-bumping invite_epoch)!
    let Ok(remove_commit) = fx.alice.build_failover_rekey_commit(None) else {
        unreachable!("build_failover_rekey_commit");
    };
    let Ok(rem_pending) = fx.ds.stage_tentative_commit(
        &remove_commit,
        2001,
        &[1001, 1002],
        NOW_S + 4,
        30,
    ) else {
        unreachable!("stage remove commit");
    };
    assert!(matches!(rem_pending, QuorumOutcome::Pending { .. }));
    let Ok(bob_rem_ack) = fx
        .bob
        .handle_tentative_commit(std::slice::from_ref(&remove_prop_blob), &remove_commit)
    else {
        unreachable!("bob ack remove commit");
    };
    assert_eq!(bob_rem_ack.status, AckStatus::Ok);
    let Ok(rem_fin) = fx.ds.record_commit_ack(&bob_rem_ack, NOW_S + 5) else {
        unreachable!("finalize remove commit");
    };
    assert!(matches!(
        rem_fin,
        QuorumOutcome::Finalized { new_epoch: 3, .. }
    ));

    assert!(
        fx.alice
            .handle_finalized_commit(&[], &remove_commit, NOW_S + 5)
            .is_ok()
    );
    assert!(
        fx.bob
            .handle_finalized_commit(&[], &remove_commit, NOW_S + 5)
            .is_ok()
    );
    assert!(!fx.alice.mls_rekey_required());
    assert_eq!(fx.alice.epoch(), 3);
    assert_eq!(fx.bob.epoch(), 3);
    assert_eq!(
        fx.alice.client().room_policy().ok().map(|p| p.invite_epoch),
        Some(1),
        "removal commit MUST bump invite_epoch to 1"
    );

    // Post-Removal Forward Secrecy: Alice sends epoch-3 secret -> Bob decrypts, Charlie FAILS!
    let Ok(post_rem) = fx.alice.prepare_outbound_chat(
        "post-remove-1",
        "@bob",
        "top secret after removal",
        NOW_S + 5,
        |_| Ok(()),
    ) else {
        unreachable!("post-removal chat send");
    };
    let Ok(bob_dec) = fx
        .bob
        .decrypt_inbound_mp2("opaque_b64", &post_rem.body_b64, false)
    else {
        unreachable!("bob decrypt post-removal chat");
    };
    assert_eq!(
        bob_dec.payload,
        DecryptedInboundPayload::Chat {
            target_selector: "@bob".to_string(),
            body: "top secret after removal".to_string(),
        }
    );
    assert!(
        charlie
            .decrypt_inbound_mp2("opaque_b64", &post_rem.body_b64, false)
            .is_err(),
        "removed member MUST NOT decrypt post-removal epoch-3 message"
    );

    // Deterministic 120-second PastEpochDeletion sweep purges retired epochs after 120s!
    assert_eq!(fx.alice.prune_past_epochs(NOW_S + 10).ok(), Some(0));
    let Ok(pruned) = fx.alice.prune_past_epochs(NOW_S + 200) else {
        unreachable!("prune_past_epochs after 120s");
    };
    assert!(pruned >= 1, "expected retired past epochs purged after 120s");
    assert!(fx.bob.prune_past_epochs(NOW_S + 200).is_ok());

    assert!(B64.decode(post_rem.body_b64.as_bytes()).is_ok());
}

#[test]
fn oracle_5_pcs_500_threshold_900_hard_cap_and_clone_detection_freeze() {
    let mut fx = bootstrap_two_outpost_room();

    // Send 499 ephemeral frames: below 500 PCS trigger.
    for i in 1..MP_PCS_UPDATE_FRAME_THRESHOLD {
        let cid = format!("eph-{i}");
        let Ok(prep) = fx.alice.prepare_outbound_ephemeral_status(
            &cid,
            "Outpost",
            "working",
            None,
            NOW_S,
            |_| Ok(()),
        ) else {
            unreachable!("send ephemeral {i}");
        };
        assert!(!prep.needs_pcs_self_update);
    }

    // Frame 500 MUST raise needs_pcs_self_update == true!
    let Ok(frame_500) = fx.alice.prepare_outbound_ephemeral_status(
        "eph-500",
        "Outpost",
        "working",
        None,
        NOW_S,
        |_| Ok(()),
    ) else {
        unreachable!("send frame 500");
    };
    assert!(frame_500.needs_pcs_self_update);
    assert!(fx.alice.needs_pcs_self_update());

    // Continue to 900 (hard cap): frame 900 succeeds, frame 901 fails closed with EpochFrameCapReached!
    for i in (MP_PCS_UPDATE_FRAME_THRESHOLD + 1)..=MP_HARD_CAP_FRAMES_PER_EPOCH {
        let cid = format!("eph-{i}");
        assert!(
            fx.alice
                .prepare_outbound_ephemeral_status(&cid, "Outpost", "working", None, NOW_S, |_| {
                    Ok(())
                })
                .is_ok()
        );
    }
    let over_cap = fx
        .alice
        .prepare_outbound_chat("chat-901", "@all", "over hard cap", NOW_S, |_| Ok(()));
    assert!(matches!(
        over_cap,
        Err(MlsSessionError::EpochFrameCapReached {
            count: 900,
            cap: 900
        })
    ));

    // PCS self-Update Commit resets the epoch counter and unblocks sending!
    let Ok(pcs_commit) = fx.alice.build_pcs_self_update_commit() else {
        unreachable!("pcs commit");
    };
    assert!(
        fx.ds
            .stage_tentative_commit(&pcs_commit, 2001, &[1001], NOW_S + 10, 30)
            .is_ok()
    );
    assert!(
        fx.alice
            .handle_finalized_commit(&[], &pcs_commit, NOW_S + 10)
            .is_ok()
    );
    assert_eq!(fx.alice.total_sent_frames_in_epoch(), 0);
    assert!(
        fx.alice
            .prepare_outbound_chat("chat-after-pcs", "@all", "unblocked!", NOW_S + 10, |_| {
                Ok(())
            })
            .is_ok()
    );

    // Clone detection (`409 device_seq_rollback` or own-device decryption) suspends all outbound sends!
    fx.alice.mark_clone_detected();
    assert!(fx.alice.status_snapshot().clone_detected);
    assert!(matches!(
        fx.alice.prepare_outbound_chat(
            "chat-after-clone",
            "@all",
            "blocked!",
            NOW_S + 10,
            |_| Ok(()),
        ),
        Err(MlsSessionError::SendBlockedCloneDetected)
    ));
}
