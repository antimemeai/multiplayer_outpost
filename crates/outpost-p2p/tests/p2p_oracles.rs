//! Tier 7 Real Dual-Endpoint Loopback QUIC Oracles for `outpost-p2p`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use iroh::endpoint::{ConnectionError, presets};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey, TransportAddr};
use mp_protocol::{DirectAddr, EndpointDescriptor, RelayPolicy, TransportKind};
use outpost_core::lan_protocol::{
    LanHandshakeMessage, LanHelloMessage, LanJoinMessage, encode_lan_handshake_frame,
};
use outpost_core::p2p_wire::{
    P2pActivityState, P2pBridgeEnvelope, P2pChatMessage, P2pControlNotice, P2pControlNoticeKind,
    P2pEphemeralPulse, P2pLane, P2pPartyFrame,
};
use outpost_p2p::{
    ALPN, CLOSE_PEER_REVOKED, CLOSE_PROTOCOL_VIOLATION, CLOSE_SUPERSEDED, CLOSE_UNAUTHORIZED,
    LanTransportConfig, MAX_PENDING_LAN_PEERS, P2pError, P2pTransportEvent, PartyP2pConfig,
    PartyP2pTransport, PeerDialTarget, STREAM_INIT_MARKER,
};

async fn spawn_no_relays(device_id: u64, seed_byte: u8) -> Result<PartyP2pTransport, P2pError> {
    PartyP2pTransport::spawn(PartyP2pConfig {
        local_device_id: device_id,
        device_secret: [seed_byte; 32],
        effective_relay_policy: RelayPolicy::NoRelays,
        pinned_relay_url: None,
    })
    .await
}

async fn recv_within(
    transport: &mut PartyP2pTransport,
    timeout: Duration,
) -> Option<P2pTransportEvent> {
    tokio::time::timeout(timeout, transport.recv_event())
        .await
        .unwrap_or_default()
}

async fn wait_for_connected(transport: &mut PartyP2pTransport, expected_peer: [u8; 32]) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(ev) = recv_within(transport, Duration::from_millis(500)).await
            && ev
                == (P2pTransportEvent::PeerConnected {
                    peer_pubkey: expected_peer,
                })
        {
            return true;
        }
    }
    false
}

async fn wait_for_frame(
    transport: &mut PartyP2pTransport,
    expected_peer: [u8; 32],
    expected_lane: P2pLane,
) -> Option<P2pPartyFrame> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(P2pTransportEvent::FrameReceived {
            peer_pubkey,
            lane,
            frame,
        }) = recv_within(transport, Duration::from_millis(500)).await
            && peer_pubkey == expected_peer
            && lane == expected_lane
        {
            return Some(frame);
        }
    }
    None
}

async fn wait_for_disconnect(
    transport: &mut PartyP2pTransport,
    expected_peer: [u8; 32],
) -> Option<u32> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(P2pTransportEvent::PeerDisconnected {
            peer_pubkey,
            reason_code,
        }) = recv_within(transport, Duration::from_millis(500)).await
            && peer_pubkey == expected_peer
        {
            return Some(reason_code);
        }
    }
    None
}

fn descriptor_to_transport_addrs(desc: &EndpointDescriptor) -> Vec<TransportAddr> {
    desc.direct_addrs
        .iter()
        .map(|a| match *a {
            DirectAddr::V4 { ip, port } => {
                TransportAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
            }
            DirectAddr::V6 { ip, port } => {
                TransportAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
            }
        })
        .collect()
}

/// Oracle 1: Two real `PartyP2pTransport` instances (`NoRelays` localhost UDP) exchange all 4
/// `P2pPartyFrame` kinds (`ChatMessage`, `BridgeEnvelope`, `ControlNotice`, `EphemeralPulse`)
/// across Streams 0, 4, and Datagrams with verified `peer_pubkey` attribution.
#[tokio::test]
async fn oracle1_dual_endpoint_all_four_frame_kinds_over_three_lanes() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = spawn_no_relays(101, 0x11).await?;
    let mut bob = spawn_no_relays(202, 0x22).await?;

    let alice_pk = alice.local_pubkey();
    let bob_pk = bob.local_pubkey();
    assert_ne!(alice_pk, bob_pk);

    alice.set_allowed_peers(HashSet::from([bob_pk]));
    bob.set_allowed_peers(HashSet::from([alice_pk]));

    let bob_desc = bob.local_endpoint_descriptor();
    assert!(bob_desc.relay_url.is_empty());
    assert!(!bob_desc.direct_addrs.is_empty());

    alice
        .connect_peer(PeerDialTarget {
            device_id: 202,
            device_pubkey: bob_pk,
            remote_relay_policy: RelayPolicy::NoRelays,
            endpoint: bob_desc,
        })
        .await?;

    assert!(wait_for_connected(&mut alice, bob_pk).await);
    assert!(wait_for_connected(&mut bob, alice_pk).await);

    let chat = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "party/main".into(),
        target_selector: "@all".into(),
        sender_handle: "alice".into(),
        timestamp_ns: 1_732_350_000_000_000_000,
        body: "hello from outpost over stream 4".into(),
    });
    let bridge = P2pPartyFrame::BridgeEnvelope(P2pBridgeEnvelope {
        room_scope: "party/ops".into(),
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42, 0x99],
    });
    let notice = P2pPartyFrame::ControlNotice(P2pControlNotice {
        kind: P2pControlNoticeKind::SyncAck,
        party_epoch: 7,
        text: "ok-epoch-7".into(),
    });
    let pulse = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
        activity_state: P2pActivityState::Working,
        timestamp_ns: 1_732_350_001_000_000_000,
        status: "compiling".into(),
    });

    // Alice -> Bob across all 4 frame kinds (Streams 0, 4, and RFC 9221 Datagram).
    alice.send_frame(bob_pk, &notice).await?;
    assert_eq!(
        wait_for_frame(&mut bob, alice_pk, P2pLane::Control).await,
        Some(notice.clone())
    );

    alice.send_frame(bob_pk, &chat).await?;
    assert_eq!(
        wait_for_frame(&mut bob, alice_pk, P2pLane::Causal).await,
        Some(chat.clone())
    );

    alice.send_frame(bob_pk, &bridge).await?;
    assert_eq!(
        wait_for_frame(&mut bob, alice_pk, P2pLane::Causal).await,
        Some(bridge.clone())
    );

    alice.send_frame(bob_pk, &pulse).await?;
    assert_eq!(
        wait_for_frame(&mut bob, alice_pk, P2pLane::Ephemeral).await,
        Some(pulse.clone())
    );

    // Bob -> Alice reverse direction across all 3 lanes as well.
    let bob_notice = P2pPartyFrame::ControlNotice(P2pControlNotice {
        kind: P2pControlNoticeKind::Status,
        party_epoch: 8,
        text: "bob-ready".into(),
    });
    let bob_chat = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "party/main".into(),
        target_selector: "@alice".into(),
        sender_handle: "bob".into(),
        timestamp_ns: 1_732_350_002_000_000_000,
        body: "ack from bob".into(),
    });
    let bob_pulse = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
        activity_state: P2pActivityState::Idle,
        timestamp_ns: 1_732_350_003_000_000_000,
        status: "standing-by".into(),
    });

    bob.send_frame(alice_pk, &bob_notice).await?;
    assert_eq!(
        wait_for_frame(&mut alice, bob_pk, P2pLane::Control).await,
        Some(bob_notice)
    );

    bob.send_frame(alice_pk, &bob_chat).await?;
    assert_eq!(
        wait_for_frame(&mut alice, bob_pk, P2pLane::Causal).await,
        Some(bob_chat)
    );

    bob.send_frame(alice_pk, &bob_pulse).await?;
    assert_eq!(
        wait_for_frame(&mut alice, bob_pk, P2pLane::Ephemeral).await,
        Some(bob_pulse)
    );

    alice.close().await;
    bob.close().await;
    Ok(())
}

/// Oracle 2: Unlisted peer rejected at `EndpointHooks::after_handshake` before any
/// application bytes can be exchanged.
#[tokio::test]
async fn oracle2_unlisted_peer_rejected_at_after_handshake() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = spawn_no_relays(101, 0x31).await?;
    let mallory = spawn_no_relays(666, 0x66).await?;

    let alice_pk = alice.local_pubkey();
    let mallory_pk = mallory.local_pubkey();

    // Mallory allows Alice so Mallory can attempt to dial, but Alice does NOT allow Mallory.
    mallory.set_allowed_peers(HashSet::from([alice_pk]));

    let alice_desc = alice.local_endpoint_descriptor();
    let res = mallory
        .connect_peer(PeerDialTarget {
            device_id: 101,
            device_pubkey: alice_pk,
            remote_relay_policy: RelayPolicy::NoRelays,
            endpoint: alice_desc.clone(),
        })
        .await;
    assert_eq!(res, Err(P2pError::PeerNotAllowed));

    // Also verify with a raw iroh dialer that Alice rejects at after_handshake with 4401
    // before any application stream bytes are accepted.
    let raw_sk = SecretKey::from_bytes(&[0x77; 32]);
    let raw_ep = Endpoint::builder(presets::Minimal)
        .secret_key(raw_sk)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;

    let alice_id = PublicKey::from_bytes(&alice_pk)?;
    let alice_addr = EndpointAddr::from_parts(alice_id, descriptor_to_transport_addrs(&alice_desc));
    match raw_ep.connect(alice_addr, ALPN).await {
        Err(_) => {
            // Rejected during handshake before connection returned.
        }
        Ok(conn) => {
            let err = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await?;
            match err {
                ConnectionError::ApplicationClosed(app) => {
                    assert_eq!(app.error_code.into_inner(), u64::from(CLOSE_UNAUTHORIZED));
                }
                other => {
                    return Err(format!("expected 4401 ApplicationClosed, got {other:?}").into());
                }
            }
        }
    }

    // Alice must never have emitted PeerConnected or FrameReceived for Mallory or raw peer.
    assert!(recv_within(&mut alice, Duration::from_millis(200)).await.is_none());
    assert!(!alice.is_peer_connected(&mallory_pk));

    raw_ep.close().await;
    mallory.close().await;
    alice.close().await;
    Ok(())
}

/// Oracle 3: `revoke_peer(pk, 4403)` immediately tears down active QUIC connection and emits
/// `PeerDisconnected`.
#[tokio::test]
async fn oracle3_revoke_peer_tears_down_quic_and_emits_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = spawn_no_relays(101, 0x41).await?;
    let mut bob = spawn_no_relays(202, 0x42).await?;

    let alice_pk = alice.local_pubkey();
    let bob_pk = bob.local_pubkey();

    alice.set_allowed_peers(HashSet::from([bob_pk]));
    bob.set_allowed_peers(HashSet::from([alice_pk]));

    alice
        .connect_peer(PeerDialTarget {
            device_id: 202,
            device_pubkey: bob_pk,
            remote_relay_policy: RelayPolicy::NoRelays,
            endpoint: bob.local_endpoint_descriptor(),
        })
        .await?;

    assert!(wait_for_connected(&mut alice, bob_pk).await);
    assert!(wait_for_connected(&mut bob, alice_pk).await);

    // Alice revokes Bob with 4403 (CLOSE_PEER_REVOKED).
    alice.revoke_peer(bob_pk, CLOSE_PEER_REVOKED);

    // Local side immediately emits PeerDisconnected(4403) and rejects further sends.
    assert_eq!(
        wait_for_disconnect(&mut alice, bob_pk).await,
        Some(CLOSE_PEER_REVOKED)
    );
    assert!(!alice.is_peer_connected(&bob_pk));
    let send_after = alice
        .send_frame(
            bob_pk,
            &P2pPartyFrame::ControlNotice(P2pControlNotice {
                kind: P2pControlNoticeKind::Status,
                party_epoch: 1,
                text: "must-fail".into(),
            }),
        )
        .await;
    assert_eq!(send_after, Err(P2pError::PeerNotAllowed));

    // Remote side (Bob) observes immediate QUIC teardown with 4403.
    assert_eq!(
        wait_for_disconnect(&mut bob, alice_pk).await,
        Some(CLOSE_PEER_REVOKED)
    );
    assert!(!bob.is_peer_connected(&alice_pk));

    alice.close().await;
    bob.close().await;
    Ok(())
}

/// Oracle 4: `ForceRelays` endpoint returns `direct_addrs.is_empty()` and refuses `NoRelays`
/// targets (and rejects missing/non-https relay URLs).
#[tokio::test]
async fn oracle4_force_relays_zero_direct_addrs_and_refuses_no_relays() -> Result<(), Box<dyn std::error::Error>> {
    // Missing relay URL under ForceRelays fails closed.
    let missing_url = PartyP2pTransport::spawn(PartyP2pConfig {
        local_device_id: 1,
        device_secret: [0x51; 32],
        effective_relay_policy: RelayPolicy::ForceRelays,
        pinned_relay_url: None,
    })
    .await;
    assert!(matches!(missing_url, Err(P2pError::PolicyViolation(_))));

    // Non-HTTPS relay URL under ForceRelays fails closed.
    let http_url = PartyP2pTransport::spawn(PartyP2pConfig {
        local_device_id: 1,
        device_secret: [0x51; 32],
        effective_relay_policy: RelayPolicy::ForceRelays,
        pinned_relay_url: Some("http://relay.multiplayer.tech".into()),
    })
    .await;
    assert!(matches!(http_url, Err(P2pError::InvalidRelayUrl(_))));

    // Valid ForceRelays endpoint exposes ZERO direct UDP addresses.
    let forced = PartyP2pTransport::spawn(PartyP2pConfig {
        local_device_id: 10,
        device_secret: [0x52; 32],
        effective_relay_policy: RelayPolicy::ForceRelays,
        pinned_relay_url: Some("https://relay.multiplayer.tech".into()),
    })
    .await?;

    let desc = forced.local_endpoint_descriptor();
    assert!(
        desc.direct_addrs.is_empty(),
        "ForceRelays endpoint must expose zero direct addresses"
    );
    assert_eq!(desc.relay_url, "https://relay.multiplayer.tech");
    assert_eq!(desc.transport_kind, TransportKind::IrohQuic);

    let bob = spawn_no_relays(20, 0x53).await?;
    let bob_pk = bob.local_pubkey();
    forced.set_allowed_peers(HashSet::from([bob_pk]));

    // Refuses NoRelays target.
    let dial_no_relays = forced
        .connect_peer(PeerDialTarget {
            device_id: 20,
            device_pubkey: bob_pk,
            remote_relay_policy: RelayPolicy::NoRelays,
            endpoint: bob.local_endpoint_descriptor(),
        })
        .await;
    assert!(matches!(dial_no_relays, Err(P2pError::PolicyViolation(_))));

    // Also refuses direct IP addresses even if remote claims AllowRelays.
    let dial_with_ips = forced
        .connect_peer(PeerDialTarget {
            device_id: 20,
            device_pubkey: bob_pk,
            remote_relay_policy: RelayPolicy::AllowRelays,
            endpoint: EndpointDescriptor {
                transport_kind: TransportKind::IrohQuic,
                relay_url: "https://relay.multiplayer.tech".into(),
                direct_addrs: vec![DirectAddr::V4 {
                    ip: [127, 0, 0, 1],
                    port: 4433,
                }],
            },
        })
        .await;
    assert!(matches!(dial_with_ips, Err(P2pError::PolicyViolation(_))));

    // Conversely, NoRelays endpoint refuses ForceRelays target.
    bob.set_allowed_peers(HashSet::from([forced.local_pubkey()]));
    let reverse_dial = bob
        .connect_peer(PeerDialTarget {
            device_id: 10,
            device_pubkey: forced.local_pubkey(),
            remote_relay_policy: RelayPolicy::ForceRelays,
            endpoint: desc,
        })
        .await;
    assert!(matches!(reverse_dial, Err(P2pError::PolicyViolation(_))));

    bob.close().await;
    forced.close().await;
    Ok(())
}

/// Oracle 5: `4409` superseded reconnect replaces stale connection cleanly and delivers
/// subsequent frames.
#[tokio::test]
async fn oracle5_superseded_4409_reconnect_replaces_stale_conn_and_delivers_frames() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = spawn_no_relays(101, 0x81).await?;
    let mut bob = spawn_no_relays(202, 0x82).await?;

    let alice_pk = alice.local_pubkey();
    let bob_pk = bob.local_pubkey();

    alice.set_allowed_peers(HashSet::from([bob_pk]));
    bob.set_allowed_peers(HashSet::from([alice_pk]));

    // Part A: Establish a raw connection using Bob's secret key to Alice, then supersede it
    // from the real `bob` PartyP2pTransport and verify the stale connection receives 4409.
    let stale_ep = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x82; 32]))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let alice_id = PublicKey::from_bytes(&alice_pk)?;
    let alice_desc = alice.local_endpoint_descriptor();
    let alice_addr = EndpointAddr::from_parts(alice_id, descriptor_to_transport_addrs(&alice_desc));

    let stale_conn = stale_ep.connect(alice_addr, ALPN).await?;
    let (mut s0_send, mut s0_recv) = stale_conn.open_bi().await?;
    s0_send.write_all(&STREAM_INIT_MARKER.to_le_bytes()).await?;
    let (mut s4_send, _s4_recv) = stale_conn.open_bi().await?;
    s4_send.write_all(&STREAM_INIT_MARKER.to_le_bytes()).await?;
    let mut ack = [0u8; 4];
    s0_recv.read_exact(&mut ack).await?;
    assert_eq!(u32::from_le_bytes(ack), STREAM_INIT_MARKER);
    assert!(wait_for_connected(&mut alice, bob_pk).await);

    // Real Bob connects to Alice -> Alice MUST close stale_conn with 4409 (CLOSE_SUPERSEDED)!
    let bob_target = PeerDialTarget {
        device_id: 101,
        device_pubkey: alice_pk,
        remote_relay_policy: RelayPolicy::NoRelays,
        endpoint: alice_desc.clone(),
    };
    if let Err(err) = bob.connect_peer(bob_target.clone()).await {
        if matches!(err, P2pError::Timeout) {
            tokio::time::sleep(Duration::from_millis(150)).await;
            bob.connect_peer(bob_target)
                .await
                .map_err(|e| format!("partA bob.connect_peer retry failed: {e}"))?;
        } else {
            return Err(format!("partA bob.connect_peer failed: {err}").into());
        }
    }

    let stale_close = tokio::time::timeout(Duration::from_secs(15), stale_conn.closed()).await?;
    match stale_close {
        ConnectionError::ApplicationClosed(app) => {
            assert_eq!(app.error_code.into_inner(), u64::from(CLOSE_SUPERSEDED));
        }
        other => {
            return Err(format!("expected 4409 CLOSE_SUPERSEDED, got {other:?}").into());
        }
    }
    // Close the duplicate-EndpointId raw socket immediately so it cannot intercept
    // Alice's subsequent Part C dial back to Bob's real endpoint on macOS CI.
    stale_ep.close().await;

    assert!(wait_for_connected(&mut bob, alice_pk).await);
    assert!(wait_for_connected(&mut alice, bob_pk).await);

    // Part B: Verify subsequent frames flow cleanly in BOTH directions on the replacement conn.
    let msg1 = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "party/main".into(),
        target_selector: "@all".into(),
        sender_handle: "bob".into(),
        timestamp_ns: 1001,
        body: "post-4409-from-bob".into(),
    });
    bob.send_frame(alice_pk, &msg1).await?;
    assert_eq!(
        wait_for_frame(&mut alice, bob_pk, P2pLane::Causal).await,
        Some(msg1)
    );

    // Part C: Reconnect a second time from Alice -> Bob via PartyP2pTransport::connect_peer
    // (superseding Bob's initiated connection cleanly), and exchange frames on all lanes.
    let alice_target = PeerDialTarget {
        device_id: 202,
        device_pubkey: bob_pk,
        remote_relay_policy: RelayPolicy::NoRelays,
        endpoint: bob.local_endpoint_descriptor(),
    };
    if let Err(err) = alice.connect_peer(alice_target.clone()).await {
        if matches!(err, P2pError::Timeout) {
            tokio::time::sleep(Duration::from_millis(150)).await;
            alice
                .connect_peer(alice_target)
                .await
                .map_err(|e| format!("partC alice.connect_peer retry failed: {e}"))?;
        } else {
            return Err(format!("partC alice.connect_peer failed: {err}").into());
        }
    }

    assert!(wait_for_connected(&mut alice, bob_pk).await);
    assert!(wait_for_connected(&mut bob, alice_pk).await);

    let msg2 = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "party/main".into(),
        target_selector: "@bob".into(),
        sender_handle: "alice".into(),
        timestamp_ns: 1002,
        body: "post-second-supersede-from-alice".into(),
    });
    alice.send_frame(bob_pk, &msg2).await?;
    assert_eq!(
        wait_for_frame(&mut bob, alice_pk, P2pLane::Causal).await,
        Some(msg2)
    );

    let ctrl = P2pPartyFrame::ControlNotice(P2pControlNotice {
        kind: P2pControlNoticeKind::ScopeChanged,
        party_epoch: 12,
        text: "superseded-ok".into(),
    });
    bob.send_frame(alice_pk, &ctrl).await?;
    assert_eq!(
        wait_for_frame(&mut alice, bob_pk, P2pLane::Control).await,
        Some(ctrl)
    );

    alice.close().await;
    bob.close().await;
    Ok(())
}

/// Oracle 6: Simultaneous mutual dial glare resolves deterministically (smaller EndpointId
/// initiator wins) with one surviving live connection, zero double-close, and clean
/// bidirectional frame exchange on all 3 lanes.
#[tokio::test]
async fn oracle6_simultaneous_mutual_dial_glare_resolves_deterministically() -> Result<(), Box<dyn std::error::Error>> {
    for (seed_a, seed_b) in [(0x91u8, 0x92u8), (0x93u8, 0x94u8), (0xA1u8, 0xA2u8)] {
        let mut alice = spawn_no_relays(101, seed_a).await?;
        let mut bob = spawn_no_relays(202, seed_b).await?;

        let alice_pk = alice.local_pubkey();
        let bob_pk = bob.local_pubkey();

        alice.set_allowed_peers(HashSet::from([bob_pk]));
        bob.set_allowed_peers(HashSet::from([alice_pk]));

        let alice_desc = alice.local_endpoint_descriptor();
        let bob_desc = bob.local_endpoint_descriptor();

        let target_bob = PeerDialTarget {
            device_id: 202,
            device_pubkey: bob_pk,
            remote_relay_policy: RelayPolicy::NoRelays,
            endpoint: bob_desc,
        };
        let target_alice = PeerDialTarget {
            device_id: 101,
            device_pubkey: alice_pk,
            remote_relay_policy: RelayPolicy::NoRelays,
            endpoint: alice_desc,
        };

        let (res_a, res_b) = tokio::join!(
            alice.connect_peer(target_bob),
            bob.connect_peer(target_alice),
        );
        // At least the winning side must succeed; if the losing side raced with 4409 before
        // its incoming winner registered, wait briefly for convergence and verify both are live.
        assert!(
            res_a.is_ok() || res_b.is_ok(),
            "at least one dial must succeed: a={res_a:?}, b={res_b:?}"
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if alice.is_peer_connected(&bob_pk) && bob.is_peer_connected(&alice_pk) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(alice.is_peer_connected(&bob_pk), "alice must hold live peer");
        assert!(bob.is_peer_connected(&alice_pk), "bob must hold live peer");

        // Give any superseded losing connection time to settle and confirm neither side drops!
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            alice.is_peer_connected(&bob_pk),
            "alice connection must survive glare settlement"
        );
        assert!(
            bob.is_peer_connected(&alice_pk),
            "bob connection must survive glare settlement"
        );

        let msg_ab = P2pPartyFrame::ChatMessage(P2pChatMessage {
            room_scope: "party/glare".into(),
            target_selector: "@bob".into(),
            sender_handle: "alice".into(),
            timestamp_ns: 2001,
            body: "glare-survived-a-to-b".into(),
        });
        let msg_ba = P2pPartyFrame::ControlNotice(P2pControlNotice {
            kind: P2pControlNoticeKind::SyncAck,
            party_epoch: 9,
            text: "glare-survived-b-to-a".into(),
        });

        alice.send_frame(bob_pk, &msg_ab).await?;
        assert_eq!(
            wait_for_frame(&mut bob, alice_pk, P2pLane::Causal).await,
            Some(msg_ab)
        );
        bob.send_frame(alice_pk, &msg_ba).await?;
        assert_eq!(
            wait_for_frame(&mut alice, bob_pk, P2pLane::Control).await,
            Some(msg_ba)
        );

        alice.close().await;
        bob.close().await;
    }
    Ok(())
}

/// Oracle 7: Malformed / invalid Lane 2 datagrams are dropped cleanly without closing the
/// QUIC connection or disrupting Lane 0/1 streams.
#[tokio::test]
async fn oracle7_invalid_lane2_datagram_dropped_without_killing_lane0_or_lane1() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = spawn_no_relays(101, 0xB1).await?;
    let alice_pk = alice.local_pubkey();
    let alice_desc = alice.local_endpoint_descriptor();

    let raw_sk = SecretKey::from_bytes(&[0xB2; 32]);
    let raw_pk = *raw_sk.public().as_bytes();
    alice.set_allowed_peers(HashSet::from([raw_pk]));

    let transport_cfg = iroh::endpoint::QuicTransportConfig::builder()
        .datagram_receive_buffer_size(Some(65_536))
        .datagram_send_buffer_size(65_536)
        .build();
    let raw_ep = Endpoint::builder(presets::Minimal)
        .secret_key(raw_sk)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .transport_config(transport_cfg)
        .bind()
        .await?;

    let alice_id = PublicKey::from_bytes(&alice_pk)?;
    let alice_addr = EndpointAddr::from_parts(alice_id, descriptor_to_transport_addrs(&alice_desc));
    let conn = raw_ep.connect(alice_addr, ALPN).await?;

    let (mut s0_send, mut s0_recv) = conn.open_bi().await?;
    s0_send.write_all(&STREAM_INIT_MARKER.to_le_bytes()).await?;
    let (mut s4_send, _s4_recv) = conn.open_bi().await?;
    s4_send.write_all(&STREAM_INIT_MARKER.to_le_bytes()).await?;
    let mut ack = [0u8; 4];
    s0_recv.read_exact(&mut ack).await?;
    assert_eq!(u32::from_le_bytes(ack), STREAM_INIT_MARKER);
    assert!(wait_for_connected(&mut alice, raw_pk).await);

    // Send malformed Lane 2 datagrams (garbage bytes + wrong frame kind for Lane 2).
    conn.send_datagram(bytes::Bytes::from_static(&[0xFF, 0x00, 0xDE, 0xAD]))?;
    conn.send_datagram(bytes::Bytes::from_static(&[0x01, 0x02]))?;

    // Wait briefly and confirm QUIC connection is STILL alive!
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(conn.close_reason().is_none());
    assert!(alice.is_peer_connected(&raw_pk));

    // Send valid Lane 0 ControlNotice and Lane 1 ChatMessage over Streams 0 and 4.
    let notice = P2pPartyFrame::ControlNotice(P2pControlNotice {
        kind: P2pControlNoticeKind::Status,
        party_epoch: 3,
        text: "still-alive-after-bad-dgram".into(),
    });
    let enc_notice = outpost_core::p2p_wire::encode_p2p_party_frame(&notice)?;
    let notice_len = u32::try_from(enc_notice.len())?;
    s0_send.write_all(&notice_len.to_le_bytes()).await?;
    s0_send.write_all(&enc_notice).await?;

    let chat = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "party/main".into(),
        target_selector: "@all".into(),
        sender_handle: "raw".into(),
        timestamp_ns: 3001,
        body: "lane1-still-works".into(),
    });
    let enc_chat = outpost_core::p2p_wire::encode_p2p_party_frame(&chat)?;
    let chat_len = u32::try_from(enc_chat.len())?;
    s4_send.write_all(&chat_len.to_le_bytes()).await?;
    s4_send.write_all(&enc_chat).await?;

    // Send valid Lane 2 EphemeralPulse datagram too.
    let pulse = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
        activity_state: P2pActivityState::Working,
        timestamp_ns: 3002,
        status: "valid-pulse".into(),
    });
    let enc_pulse = outpost_core::p2p_wire::encode_p2p_party_frame(&pulse)?;
    conn.send_datagram(bytes::Bytes::from(enc_pulse))?;

    assert_eq!(
        wait_for_frame(&mut alice, raw_pk, P2pLane::Control).await,
        Some(notice)
    );
    assert_eq!(
        wait_for_frame(&mut alice, raw_pk, P2pLane::Causal).await,
        Some(chat)
    );
    assert_eq!(
        wait_for_frame(&mut alice, raw_pk, P2pLane::Ephemeral).await,
        Some(pulse)
    );

    raw_ep.close().await;
    alice.close().await;
    Ok(())
}

/// Oracle 8: `set_allowed_peers_with_close_code(..., CLOSE_UNAUTHORIZED)` closes removed
/// peers with exact code `4401`, and `split()` enables concurrent send + revoke + close
/// without deadlock.
#[tokio::test]
async fn oracle8_allowlist_close_code_4401_and_split_concurrent_send_revoke() -> Result<(), Box<dyn std::error::Error>> {
    // Part A: `set_allowed_peers_with_close_code(..., 4401)`
    {
        let mut alice = spawn_no_relays(101, 0xC1).await?;
        let mut bob = spawn_no_relays(202, 0xC2).await?;
        let alice_pk = alice.local_pubkey();
        let bob_pk = bob.local_pubkey();

        alice.set_allowed_peers(HashSet::from([bob_pk]));
        bob.set_allowed_peers(HashSet::from([alice_pk]));
        alice
            .connect_peer(PeerDialTarget {
                device_id: 202,
                device_pubkey: bob_pk,
                remote_relay_policy: RelayPolicy::NoRelays,
                endpoint: bob.local_endpoint_descriptor(),
            })
            .await?;

        assert!(wait_for_connected(&mut alice, bob_pk).await);
        assert!(wait_for_connected(&mut bob, alice_pk).await);

        // Suspend allowlist with 4401 (CLOSE_UNAUTHORIZED) instead of 4403!
        alice.set_allowed_peers_with_close_code(HashSet::new(), CLOSE_UNAUTHORIZED);

        assert_eq!(
            wait_for_disconnect(&mut alice, bob_pk).await,
            Some(CLOSE_UNAUTHORIZED)
        );
        assert_eq!(
            wait_for_disconnect(&mut bob, alice_pk).await,
            Some(CLOSE_UNAUTHORIZED)
        );

        alice.close().await;
        bob.close().await;
    }

    // Part B: `split()` concurrent send + revoke + wait_online + watch_addr + close without deadlock
    {
        let alice = spawn_no_relays(101, 0xC3).await?;
        let mut bob = spawn_no_relays(202, 0xC4).await?;

        let (alice_handle, mut alice_events) = alice.split();
        let alice_pk = alice_handle.local_pubkey();
        let bob_pk = bob.local_pubkey();

        // `wait_online` is an immediate no-op under NoRelays and `watch_addr` returns a live watcher.
        alice_handle.wait_online(Duration::from_millis(50)).await;
        let _addr_watcher = alice_handle.watch_addr();

        alice_handle.set_allowed_peers(HashSet::from([bob_pk]));
        bob.set_allowed_peers(HashSet::from([alice_pk]));

        let event_task = tokio::spawn(async move {
            let mut connected = false;
            let mut disconnected_code = None;
            while let Some(ev) = alice_events.recv_event().await {
                match ev {
                    P2pTransportEvent::PeerConnected { peer_pubkey } if peer_pubkey == bob_pk => {
                        connected = true;
                    }
                    P2pTransportEvent::PeerDisconnected {
                        peer_pubkey,
                        reason_code,
                    } if peer_pubkey == bob_pk => {
                        disconnected_code = Some(reason_code);
                    }
                    _ => {}
                }
            }
            (connected, disconnected_code)
        });

        alice_handle
            .connect_peer(PeerDialTarget {
                device_id: 202,
                device_pubkey: bob_pk,
                remote_relay_policy: RelayPolicy::NoRelays,
                endpoint: bob.local_endpoint_descriptor(),
            })
            .await?;
        assert!(wait_for_connected(&mut bob, alice_pk).await);

        // Concurrent sends from two Arc<PartyP2pHandle> clones while event_task drains events.
        let h1 = std::sync::Arc::clone(&alice_handle);
        let h2 = std::sync::Arc::clone(&alice_handle);
        let send1 = tokio::spawn(async move {
            let msg = P2pPartyFrame::ChatMessage(P2pChatMessage {
                room_scope: "party/split".into(),
                target_selector: "@bob".into(),
                sender_handle: "alice".into(),
                timestamp_ns: 4001,
                body: "concurrent-send-1".into(),
            });
            h1.send_frame(bob_pk, &msg).await
        });
        let send2 = tokio::spawn(async move {
            let ctrl = P2pPartyFrame::ControlNotice(P2pControlNotice {
                kind: P2pControlNoticeKind::SyncAck,
                party_epoch: 1,
                text: "concurrent-send-2".into(),
            });
            h2.send_frame(bob_pk, &ctrl).await
        });
        send1.await??;
        send2.await??;

        assert!(wait_for_frame(&mut bob, alice_pk, P2pLane::Control).await.is_some());
        assert!(wait_for_frame(&mut bob, alice_pk, P2pLane::Causal).await.is_some());

        // Revoke concurrently while event_task is running.
        alice_handle.revoke_peer(bob_pk, CLOSE_PEER_REVOKED);
        assert_eq!(
            wait_for_disconnect(&mut bob, alice_pk).await,
            Some(CLOSE_PEER_REVOKED)
        );

        // Closing the handle wakes `alice_events.recv_event()` -> `None` even while `alice_handle` is still in scope.
        alice_handle.close().await;
        let (connected, disconnected_code) =
            tokio::time::timeout(Duration::from_secs(3), event_task).await??;
        assert!(connected);
        assert_eq!(disconnected_code, Some(CLOSE_PEER_REVOKED));

        bob.close().await;
    }
    Ok(())
}

async fn spawn_lan(
    device_id: u64,
    seed_byte: u8,
    open_admission: bool,
    bind_port: Option<u16>,
) -> Result<PartyP2pTransport, P2pError> {
    PartyP2pTransport::spawn_with_lan(
        PartyP2pConfig {
            local_device_id: device_id,
            device_secret: [seed_byte; 32],
            effective_relay_policy: RelayPolicy::NoRelays,
            pinned_relay_url: None,
        },
        Some(LanTransportConfig {
            no_relays: true,
            lan_open_admission: open_admission,
            lan_bind_port: bind_port,
        }),
    )
    .await
}

/// Oracle 9: Opt-in LAN `NoRelays` + `lan_open_admission` fails closed on invalid/online
/// configurations without opening sockets, and supports explicit `lan_bind_port`.
#[tokio::test]
async fn oracle9_lan_config_and_open_admission_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    // 1. lan_open_admission == true without no_relays == true -> InvalidConfig
    let bad_open = PartyP2pTransport::spawn_with_lan(
        PartyP2pConfig {
            local_device_id: 1,
            device_secret: [0xD1; 32],
            effective_relay_policy: RelayPolicy::NoRelays,
            pinned_relay_url: None,
        },
        Some(LanTransportConfig {
            no_relays: false,
            lan_open_admission: true,
            lan_bind_port: None,
        }),
    )
    .await;
    assert!(matches!(bad_open, Err(P2pError::InvalidConfig(_))));

    // 2. ForceRelays + no_relays == true -> InvalidConfig
    let bad_force = PartyP2pTransport::spawn_with_lan(
        PartyP2pConfig {
            local_device_id: 2,
            device_secret: [0xD2; 32],
            effective_relay_policy: RelayPolicy::ForceRelays,
            pinned_relay_url: Some("https://relay.multiplayer.tech".into()),
        },
        Some(LanTransportConfig {
            no_relays: true,
            lan_open_admission: true,
            lan_bind_port: None,
        }),
    )
    .await;
    assert!(matches!(bad_force, Err(P2pError::InvalidConfig(_))));

    // 3. ForceRelays + no_relays == true (even with lan_open_admission == false) -> InvalidConfig
    let bad_force_closed = PartyP2pTransport::spawn_with_lan(
        PartyP2pConfig {
            local_device_id: 3,
            device_secret: [0xD3; 32],
            effective_relay_policy: RelayPolicy::ForceRelays,
            pinned_relay_url: Some("https://relay.multiplayer.tech".into()),
        },
        Some(LanTransportConfig {
            no_relays: true,
            lan_open_admission: false,
            lan_bind_port: None,
        }),
    )
    .await;
    assert!(matches!(bad_force_closed, Err(P2pError::InvalidConfig(_))));

    // 4. AllowRelays + no_relays == true -> InvalidConfig
    let bad_allow = PartyP2pTransport::spawn_with_lan(
        PartyP2pConfig {
            local_device_id: 4,
            device_secret: [0xD4; 32],
            effective_relay_policy: RelayPolicy::AllowRelays,
            pinned_relay_url: None,
        },
        Some(LanTransportConfig {
            no_relays: true,
            lan_open_admission: false,
            lan_bind_port: None,
        }),
    )
    .await;
    assert!(matches!(bad_allow, Err(P2pError::InvalidConfig(_))));

    // 5. lan_bind_port without no_relays == true -> InvalidConfig
    let bad_port = PartyP2pTransport::spawn_with_lan(
        PartyP2pConfig {
            local_device_id: 5,
            device_secret: [0xD5; 32],
            effective_relay_policy: RelayPolicy::AllowRelays,
            pinned_relay_url: None,
        },
        Some(LanTransportConfig {
            no_relays: false,
            lan_open_admission: false,
            lan_bind_port: Some(45678),
        }),
    )
    .await;
    assert!(matches!(bad_port, Err(P2pError::InvalidConfig(_))));

    // 6. NoRelays LAN mode + pinned_relay_url -> InvalidConfig
    let bad_relay_url = PartyP2pTransport::spawn_with_lan(
        PartyP2pConfig {
            local_device_id: 6,
            device_secret: [0xD6; 32],
            effective_relay_policy: RelayPolicy::NoRelays,
            pinned_relay_url: Some("https://relay.multiplayer.tech".into()),
        },
        Some(LanTransportConfig {
            no_relays: true,
            lan_open_admission: true,
            lan_bind_port: None,
        }),
    )
    .await;
    assert!(matches!(bad_relay_url, Err(P2pError::InvalidConfig(_))));

    // 7. Online ForceRelays endpoint ignores set_lan_open_admission(true), has zero direct addrs,
    //    and rejects connect_direct with PolicyViolation.
    let forced = PartyP2pTransport::spawn(PartyP2pConfig {
        local_device_id: 7,
        device_secret: [0xD7; 32],
        effective_relay_policy: RelayPolicy::ForceRelays,
        pinned_relay_url: Some("https://relay.multiplayer.tech".into()),
    })
    .await?;
    forced.set_lan_open_admission(true).await;
    assert!(!forced.is_lan_open_admission());
    assert!(forced.local_direct_addrs().is_empty());
    let peer_pk = *SecretKey::from_bytes(&[0xD8; 32]).public().as_bytes();
    forced.allow_peer(peer_pk).await?;
    let direct_err = forced
        .connect_direct(
            peer_pk,
            &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433)],
        )
        .await;
    assert!(matches!(direct_err, Err(P2pError::PolicyViolation(_))));
    forced.close().await;

    // 8. Online AllowRelays endpoint ignores set_lan_open_admission(true).
    let allow_ep = PartyP2pTransport::spawn(PartyP2pConfig {
        local_device_id: 8,
        device_secret: [0xD9; 32],
        effective_relay_policy: RelayPolicy::AllowRelays,
        pinned_relay_url: None,
    })
    .await?;
    allow_ep.set_lan_open_admission(true).await;
    assert!(!allow_ep.is_lan_open_admission());
    allow_ep.close().await;

    // 9. Explicit lan_bind_port binds that exact UDP port cleanly.
    let probe = std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    let chosen_port = probe.local_addr()?.port();
    drop(probe);
    let fixed = spawn_lan(9, 0xDA, false, Some(chosen_port)).await?;
    let addrs = fixed.local_direct_addrs();
    assert!(
        addrs.iter().any(|a| a.port() == chosen_port),
        "expected bound port {chosen_port} in {addrs:?}"
    );
    fixed.close().await;

    Ok(())
}

/// Oracle 10: Real dual-endpoint `NoRelays` LAN open admission over 127.0.0.1 (`blackbird-mp/1`):
/// - Pending joiner dials directly via `connect_direct`
/// - Lane 0 Control handshake succeeds before `allow_peer`; Lane 1 Causal & Lane 2 Ephemeral
///   from pending peers are blocked & disconnected (`4400`), never delivered to application
/// - `peer_remote_addr` reports loopback `SocketAddr` for rate limiting
/// - `allow_peer` promotes the live QUIC connection; bidirectional Lane 1 + Lane 2 succeed
/// - `set_lan_open_admission(false)` disconnects remaining pending peers and rejects new unknowns
#[tokio::test]
async fn oracle10_lan_open_admission_pending_isolation_promotion_and_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let mut host = spawn_lan(100, 0xE1, true, None).await?;
    let mut joiner_a = spawn_lan(101, 0xE2, false, None).await?;
    let mut rogue_b = spawn_lan(102, 0xE3, false, None).await?;
    let mut rogue_c = spawn_lan(103, 0xE4, false, None).await?;
    let mut pending_d = spawn_lan(104, 0xE5, false, None).await?;
    let unknown_e = spawn_lan(105, 0xE6, false, None).await?;

    let host_pk = host.local_pubkey();
    let joiner_a_pk = joiner_a.local_pubkey();
    let rogue_b_pk = rogue_b.local_pubkey();
    let rogue_c_pk = rogue_c.local_pubkey();
    let pending_d_pk = pending_d.local_pubkey();

    assert!(host.is_lan_open_admission());
    let host_addrs: Vec<SocketAddr> = host
        .local_direct_addrs()
        .into_iter()
        .filter(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .collect();
    assert!(
        !host_addrs.is_empty(),
        "LAN host must expose 127.0.0.1 direct socket"
    );

    // Joiners explicitly allow the host before dialing directly.
    for ep in [&joiner_a, &rogue_b, &rogue_c, &pending_d, &unknown_e] {
        ep.allow_peer(host_pk).await?;
    }

    // 1. Joiner A dials host directly (un-allowlisted on host -> admitted as pending).
    joiner_a.connect_direct(host_pk, &host_addrs).await?;
    assert!(wait_for_connected(&mut host, joiner_a_pk).await);
    assert!(wait_for_connected(&mut joiner_a, host_pk).await);

    // Host observes Joiner A's loopback remote SocketAddr for per-IP PIN rate limiting.
    let remote_addr = host.peer_remote_addr(joiner_a_pk).await;
    let Some(sock) = remote_addr else {
        return Err("expected Some(SocketAddr) for pending LAN joiner".into());
    };
    assert_eq!(sock.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(sock.port(), 0);

    // Before allow_peer: host CANNOT send Lane 1 or Lane 2 to pending Joiner A.
    let blocked_chat = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "lan/main".into(),
        target_selector: "@all".into(),
        sender_handle: "host".into(),
        timestamp_ns: 1,
        body: "blocked-before-allow".into(),
    });
    let blocked_pulse = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
        activity_state: P2pActivityState::Idle,
        timestamp_ns: 2,
        status: "blocked".into(),
    });
    assert_eq!(
        host.send_frame(joiner_a_pk, &blocked_chat).await,
        Err(P2pError::PeerNotAllowed)
    );
    assert_eq!(
        host.send_frame(joiner_a_pk, &blocked_pulse).await,
        Err(P2pError::PeerNotAllowed)
    );

    // Before allow_peer: bidirectional Lane 0 LAN handshake (`mp1-lan/1`) succeeds cleanly!
    let lan_hello = LanHandshakeMessage::Hello(LanHelloMessage {
        lan_party_id: "0123456789abcdef".into(),
        lobby_name: "Test LAN".into(),
        host_name: "host".into(),
        host_account_id: 100,
        host_pubkey: host_pk,
        require_pin: true,
        host_nonce: [0xAB; 32],
        max_members: 4,
    });
    host.send_lan_handshake(joiner_a_pk, &lan_hello).await?;
    let mut got_hello = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(P2pTransportEvent::LanHandshakeReceived {
            peer_pubkey,
            message,
        }) = recv_within(&mut joiner_a, Duration::from_millis(500)).await
            && peer_pubkey == host_pk
        {
            got_hello = Some(message);
            break;
        }
    }
    assert_eq!(got_hello, Some(lan_hello));

    let lan_join = LanHandshakeMessage::Join(LanJoinMessage {
        lan_party_id: "0123456789abcdef".into(),
        display_name: "joiner-a".into(),
        account_id: 101,
        pin_proof: Some([0xCD; 32]),
    });
    joiner_a.send_lan_handshake(host_pk, &lan_join).await?;
    let mut got_join = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(P2pTransportEvent::LanHandshakeReceived {
            peer_pubkey,
            message,
        }) = recv_within(&mut host, Duration::from_millis(500)).await
            && peer_pubkey == joiner_a_pk
        {
            got_join = Some(message);
            break;
        }
    }
    assert_eq!(got_join, Some(lan_join));

    // 2. Rogue pending Joiner B sends Lane 1 Causal before allow_peer -> strictly blocked
    //    (NEVER delivered to application) and disconnected with CLOSE_PROTOCOL_VIOLATION (4400).
    rogue_b.connect_direct(host_pk, &host_addrs).await?;
    assert!(wait_for_connected(&mut host, rogue_b_pk).await);
    let rogue_chat = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "lan/main".into(),
        target_selector: "@all".into(),
        sender_handle: "rogue-b".into(),
        timestamp_ns: 10,
        body: "must-never-arrive".into(),
    });
    rogue_b.send_frame(host_pk, &rogue_chat).await?;
    let mut rogue_b_disconnected = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(ev) = recv_within(&mut host, Duration::from_millis(500)).await {
            match ev {
                P2pTransportEvent::FrameReceived { peer_pubkey, .. }
                    if peer_pubkey == rogue_b_pk =>
                {
                    return Err("pending peer Lane 1 frame leaked to host application!".into());
                }
                P2pTransportEvent::PeerDisconnected {
                    peer_pubkey,
                    reason_code,
                } if peer_pubkey == rogue_b_pk => {
                    rogue_b_disconnected = Some(reason_code);
                    break;
                }
                _ => {}
            }
        }
    }
    assert_eq!(rogue_b_disconnected, Some(CLOSE_PROTOCOL_VIOLATION));
    assert_eq!(
        wait_for_disconnect(&mut rogue_b, host_pk).await,
        Some(CLOSE_PROTOCOL_VIOLATION)
    );

    // 3. Rogue pending Joiner C sends Lane 2 Ephemeral datagram before allow_peer -> strictly
    //    blocked (NEVER delivered to application) and disconnected with CLOSE_PROTOCOL_VIOLATION.
    rogue_c.connect_direct(host_pk, &host_addrs).await?;
    assert!(wait_for_connected(&mut host, rogue_c_pk).await);
    let rogue_pulse = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
        activity_state: P2pActivityState::Working,
        timestamp_ns: 20,
        status: "must-never-arrive".into(),
    });
    rogue_c.send_frame(host_pk, &rogue_pulse).await?;
    let mut rogue_c_disconnected = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(ev) = recv_within(&mut host, Duration::from_millis(500)).await {
            match ev {
                P2pTransportEvent::FrameReceived { peer_pubkey, .. }
                    if peer_pubkey == rogue_c_pk =>
                {
                    return Err("pending peer Lane 2 datagram leaked to host application!".into());
                }
                P2pTransportEvent::PeerDisconnected {
                    peer_pubkey,
                    reason_code,
                } if peer_pubkey == rogue_c_pk => {
                    rogue_c_disconnected = Some(reason_code);
                    break;
                }
                _ => {}
            }
        }
    }
    assert_eq!(rogue_c_disconnected, Some(CLOSE_PROTOCOL_VIOLATION));
    assert_eq!(
        wait_for_disconnect(&mut rogue_c, host_pk).await,
        Some(CLOSE_PROTOCOL_VIOLATION)
    );

    // 4. Host promotes Joiner A via allow_peer (idempotent) without dropping live QUIC conn.
    host.allow_peer(joiner_a_pk).await?;
    host.allow_peer(joiner_a_pk).await?;

    // Bidirectional Lane 1 Causal chat + Lane 2 Ephemeral datagrams succeed immediately!
    let chat_a2h = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "lan/main".into(),
        target_selector: "@all".into(),
        sender_handle: "joiner-a".into(),
        timestamp_ns: 30,
        body: "promoted-chat-a-to-host".into(),
    });
    let chat_h2a = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "lan/main".into(),
        target_selector: "@joiner-a".into(),
        sender_handle: "host".into(),
        timestamp_ns: 31,
        body: "promoted-chat-host-to-a".into(),
    });
    let pulse_a2h = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
        activity_state: P2pActivityState::Working,
        timestamp_ns: 32,
        status: "lan-fast".into(),
    });
    let pulse_h2a = P2pPartyFrame::EphemeralPulse(P2pEphemeralPulse {
        activity_state: P2pActivityState::Idle,
        timestamp_ns: 33,
        status: "host-ack".into(),
    });

    joiner_a.send_frame(host_pk, &chat_a2h).await?;
    assert_eq!(
        wait_for_frame(&mut host, joiner_a_pk, P2pLane::Causal).await,
        Some(chat_a2h)
    );
    host.send_frame(joiner_a_pk, &chat_h2a).await?;
    assert_eq!(
        wait_for_frame(&mut joiner_a, host_pk, P2pLane::Causal).await,
        Some(chat_h2a)
    );
    joiner_a.send_frame(host_pk, &pulse_a2h).await?;
    assert_eq!(
        wait_for_frame(&mut host, joiner_a_pk, P2pLane::Ephemeral).await,
        Some(pulse_a2h)
    );
    host.send_frame(joiner_a_pk, &pulse_h2a).await?;
    assert_eq!(
        wait_for_frame(&mut joiner_a, host_pk, P2pLane::Ephemeral).await,
        Some(pulse_h2a)
    );

    // 5. Connect pending peer D, then lock lobby via set_lan_open_admission(false):
    //    - Pending peer D is immediately disconnected (CLOSE_UNAUTHORIZED)
    //    - Unknown peer E dialing host is rejected (PeerNotAllowed)
    //    - Promoted Joiner A stays connected and exchanges frames cleanly!
    pending_d.connect_direct(host_pk, &host_addrs).await?;
    assert!(wait_for_connected(&mut host, pending_d_pk).await);

    host.set_lan_open_admission(false).await;
    assert!(!host.is_lan_open_admission());

    assert_eq!(
        wait_for_disconnect(&mut host, pending_d_pk).await,
        Some(CLOSE_UNAUTHORIZED)
    );
    assert_eq!(
        wait_for_disconnect(&mut pending_d, host_pk).await,
        Some(CLOSE_UNAUTHORIZED)
    );
    assert!(host.peer_remote_addr(pending_d_pk).await.is_none());

    let reject_e = unknown_e.connect_direct(host_pk, &host_addrs).await;
    assert_eq!(reject_e, Err(P2pError::PeerNotAllowed));

    let post_lock_chat = P2pPartyFrame::ChatMessage(P2pChatMessage {
        room_scope: "lan/main".into(),
        target_selector: "@all".into(),
        sender_handle: "joiner-a".into(),
        timestamp_ns: 40,
        body: "still-connected-after-lock".into(),
    });
    joiner_a.send_frame(host_pk, &post_lock_chat).await?;
    assert_eq!(
        wait_for_frame(&mut host, joiner_a_pk, P2pLane::Causal).await,
        Some(post_lock_chat)
    );

    unknown_e.close().await;
    pending_d.close().await;
    rogue_c.close().await;
    rogue_b.close().await;
    joiner_a.close().await;
    host.close().await;
    Ok(())
}

/// Oracle 11: `MAX_PENDING_LAN_PEERS` (16) cap is strictly enforced while already-allowlisted
/// VIP peers can still connect, and promoting 1 pending peer frees a slot.
#[tokio::test]
async fn oracle11_lan_open_admission_enforces_16_pending_peer_cap()
-> Result<(), Box<dyn std::error::Error>> {
    let mut host = spawn_lan(200, 0xF0, true, None).await?;
    let host_pk = host.local_pubkey();
    let host_addrs: Vec<SocketAddr> = host
        .local_direct_addrs()
        .into_iter()
        .filter(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .collect();
    assert!(!host_addrs.is_empty());

    let mut pending = Vec::with_capacity(MAX_PENDING_LAN_PEERS);
    for idx in 0..MAX_PENDING_LAN_PEERS {
        let seed_byte = u8::try_from(0x10 + idx)?;
        let ep = spawn_lan(300 + u64::try_from(idx)?, seed_byte, false, None).await?;
        let pk = ep.local_pubkey();
        ep.allow_peer(host_pk).await?;
        ep.connect_direct(host_pk, &host_addrs).await?;
        assert!(wait_for_connected(&mut host, pk).await);
        pending.push((ep, pk));
    }

    // 17th unknown peer MUST be rejected!
    let overflow = spawn_lan(400, 0xF1, false, None).await?;
    let overflow_pk = overflow.local_pubkey();
    overflow.allow_peer(host_pk).await?;
    assert_eq!(
        overflow.connect_direct(host_pk, &host_addrs).await,
        Err(P2pError::PeerNotAllowed)
    );

    // Already-allowlisted VIP peer MUST still connect even while all 16 pending slots are full!
    let vip = spawn_lan(401, 0xF2, false, None).await?;
    let vip_pk = vip.local_pubkey();
    host.allow_peer(vip_pk).await?;
    vip.allow_peer(host_pk).await?;
    vip.connect_direct(host_pk, &host_addrs).await?;
    assert!(wait_for_connected(&mut host, vip_pk).await);

    // Promoting 1 pending peer frees 1 slot so overflow can now connect!
    let Some(first_pending_pk) = pending.first().map(|(_, pk)| *pk) else {
        return Err("expected at least one pending peer".into());
    };
    host.allow_peer(first_pending_pk).await?;
    overflow.connect_direct(host_pk, &host_addrs).await?;
    assert!(wait_for_connected(&mut host, overflow_pk).await);

    overflow.close().await;
    vip.close().await;
    for (ep, _) in pending {
        ep.close().await;
    }
    host.close().await;
    Ok(())
}

/// Oracle 12 (Gate #3 G3-L2-2): `PartyP2pConfig` `Debug` implementation strictly redacts
/// `device_secret` and never leaks secret key bytes in formatted output.
#[test]
fn oracle12_party_p2p_config_debug_redacts_device_secret() {
    let cfg = PartyP2pConfig {
        local_device_id: 42,
        device_secret: [0x5A; 32],
        effective_relay_policy: RelayPolicy::ForceRelays,
        pinned_relay_url: Some("https://relay.multiplayer.tech".into()),
    };
    let compact = format!("{cfg:?}");
    let pretty = format!("{cfg:#?}");
    assert!(compact.contains("[REDACTED]"), "compact debug: {compact}");
    assert!(pretty.contains("[REDACTED]"), "pretty debug: {pretty}");
    assert!(
        !compact.contains("90, 90, 90"),
        "device_secret bytes leaked in compact debug: {compact}"
    );
    assert!(
        !pretty.contains("90,\n"),
        "device_secret bytes leaked in pretty debug: {pretty}"
    );
    assert!(compact.contains("42"));
    assert!(compact.contains("relay.multiplayer.tech"));
}

/// Oracle 13 (Gate #3 G3-L2-1): An online `NoRelays` endpoint (spawned via `spawn`, NOT
/// `spawn_with_lan` with `no_relays: true`) refuses `set_lan_open_admission(true)`, refuses
/// `send_lan_handshake`, and NEVER emits `LanHandshakeReceived` for inbound LAN handshake frames.
#[tokio::test]
async fn oracle13_online_no_relays_rejects_lan_admission_and_handshake()
-> Result<(), Box<dyn std::error::Error>> {
    let mut online_host = spawn_no_relays(500, 0x71).await?;
    let mut peer = spawn_no_relays(501, 0x72).await?;

    let host_pk = online_host.local_pubkey();
    let peer_pk = peer.local_pubkey();

    // Online NoRelays must ignore set_lan_open_admission(true).
    online_host.set_lan_open_admission(true).await;
    assert!(
        !online_host.is_lan_open_admission(),
        "online NoRelays endpoint must NEVER enter LAN open admission"
    );

    online_host.allow_peer(peer_pk).await?;
    peer.allow_peer(host_pk).await?;

    let host_desc = online_host.local_endpoint_descriptor();
    peer.connect_peer(PeerDialTarget {
        device_id: 500,
        device_pubkey: host_pk,
        remote_relay_policy: RelayPolicy::NoRelays,
        endpoint: host_desc.clone(),
    })
    .await?;
    assert!(wait_for_connected(&mut online_host, peer_pk).await);
    assert!(wait_for_connected(&mut peer, host_pk).await);

    let lan_hello = LanHandshakeMessage::Hello(LanHelloMessage {
        lan_party_id: "0123456789abcdef".into(),
        lobby_name: "Online Spoof".into(),
        host_name: "host".into(),
        host_account_id: 500,
        host_pubkey: host_pk,
        require_pin: false,
        host_nonce: [0x11; 32],
        max_members: 4,
    });
    assert!(matches!(
        online_host.send_lan_handshake(peer_pk, &lan_hello).await,
        Err(P2pError::PolicyViolation(_))
    ));

    // Even if a raw peer injects a valid mp1-lan/1 Lane-0 frame into an online NoRelays endpoint,
    // it MUST NOT decode as LanHandshakeReceived and MUST close with CLOSE_PROTOCOL_VIOLATION.
    let raw_sk = SecretKey::from_bytes(&[0x73; 32]);
    let raw_pk = *raw_sk.public().as_bytes();
    online_host.allow_peer(raw_pk).await?;
    let raw_ep = Endpoint::builder(presets::Minimal)
        .secret_key(raw_sk)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let host_id = PublicKey::from_bytes(&host_pk)?;
    let host_addr = EndpointAddr::from_parts(host_id, descriptor_to_transport_addrs(&host_desc));
    let raw_conn = raw_ep.connect(host_addr, ALPN).await?;
    let (mut s0_send, mut s0_recv) = raw_conn.open_bi().await?;
    s0_send.write_all(&STREAM_INIT_MARKER.to_le_bytes()).await?;
    let (mut s4_send, _s4_recv) = raw_conn.open_bi().await?;
    s4_send.write_all(&STREAM_INIT_MARKER.to_le_bytes()).await?;
    let mut ack = [0u8; 4];
    s0_recv.read_exact(&mut ack).await?;
    assert_eq!(u32::from_le_bytes(ack), STREAM_INIT_MARKER);
    assert!(wait_for_connected(&mut online_host, raw_pk).await);

    let encoded_handshake = encode_lan_handshake_frame(&lan_hello)?;
    let frame_len = u32::try_from(encoded_handshake.len())?;
    s0_send.write_all(&frame_len.to_le_bytes()).await?;
    s0_send.write_all(&encoded_handshake).await?;

    let mut disconnected_code = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(ev) = recv_within(&mut online_host, Duration::from_millis(500)).await {
            match ev {
                P2pTransportEvent::LanHandshakeReceived { .. } => {
                    return Err("online NoRelays endpoint emitted LanHandshakeReceived!".into());
                }
                P2pTransportEvent::PeerDisconnected {
                    peer_pubkey,
                    reason_code,
                } if peer_pubkey == raw_pk => {
                    disconnected_code = Some(reason_code);
                    break;
                }
                _ => {}
            }
        }
    }
    assert_eq!(disconnected_code, Some(CLOSE_PROTOCOL_VIOLATION));

    raw_ep.close().await;
    peer.close().await;
    online_host.close().await;
    Ok(())
}

/// Oracle 14 (Gate #3 G3-L2-1): A pending (un-allowlisted) LAN peer sending a non-handshake
/// Lane-0 `ControlNotice` frame MUST be rejected immediately at the transport boundary with
/// `CLOSE_PROTOCOL_VIOLATION (4400)` and NEVER emitted as `FrameReceived`.
#[tokio::test]
async fn oracle14_pending_lan_peer_non_handshake_lane0_rejected_with_4400()
-> Result<(), Box<dyn std::error::Error>> {
    let mut host = spawn_lan(600, 0x61, true, None).await?;
    let mut rogue = spawn_lan(601, 0x62, false, None).await?;

    let host_pk = host.local_pubkey();
    let rogue_pk = rogue.local_pubkey();
    let host_addrs: Vec<SocketAddr> = host
        .local_direct_addrs()
        .into_iter()
        .filter(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .collect();
    assert!(!host_addrs.is_empty());

    rogue.allow_peer(host_pk).await?;
    rogue.connect_direct(host_pk, &host_addrs).await?;
    assert!(wait_for_connected(&mut host, rogue_pk).await);
    assert!(wait_for_connected(&mut rogue, host_pk).await);

    // Rogue pending peer sends a non-handshake Lane-0 ControlNotice.
    let spoofed_notice = P2pPartyFrame::ControlNotice(P2pControlNotice {
        kind: P2pControlNoticeKind::ScopeChanged,
        party_epoch: 99,
        text: "unauthenticated-control-notice".into(),
    });
    rogue.send_frame(host_pk, &spoofed_notice).await?;

    let mut disconnected_code = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(ev) = recv_within(&mut host, Duration::from_millis(500)).await {
            match ev {
                P2pTransportEvent::FrameReceived { peer_pubkey, .. }
                    if peer_pubkey == rogue_pk =>
                {
                    return Err("pending peer non-handshake Lane-0 ControlNotice leaked!".into());
                }
                P2pTransportEvent::PeerDisconnected {
                    peer_pubkey,
                    reason_code,
                } if peer_pubkey == rogue_pk => {
                    disconnected_code = Some(reason_code);
                    break;
                }
                _ => {}
            }
        }
    }
    assert_eq!(disconnected_code, Some(CLOSE_PROTOCOL_VIOLATION));
    assert_eq!(
        wait_for_disconnect(&mut rogue, host_pk).await,
        Some(CLOSE_PROTOCOL_VIOLATION)
    );

    rogue.close().await;
    host.close().await;
    Ok(())
}

/// Oracle 15 (Gate #3 G3-L2-1): Strict `<= 16` (`MAX_PENDING_LAN_PEERS`) cap accounts for
/// both active pending peers AND in-flight pending handshakes, enforcing max 1 in-flight
/// handshake per `EndpointId` and rejecting same-key reconnects when 16 slots are occupied.
#[tokio::test]
async fn oracle15_strict_16_pending_cap_includes_in_flight_and_same_key_connections()
-> Result<(), Box<dyn std::error::Error>> {
    let mut host = spawn_lan(700, 0xA5, true, None).await?;
    let host_pk = host.local_pubkey();
    let host_id = PublicKey::from_bytes(&host_pk)?;
    let host_addrs: Vec<SocketAddr> = host
        .local_direct_addrs()
        .into_iter()
        .filter(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .collect();
    assert!(!host_addrs.is_empty());
    let host_transport_addrs: Vec<TransportAddr> =
        host_addrs.iter().copied().map(TransportAddr::Ip).collect();

    // Fill 15 active pending slots.
    let mut pending = Vec::with_capacity(MAX_PENDING_LAN_PEERS);
    for idx in 0..(MAX_PENDING_LAN_PEERS - 1) {
        let seed_byte = u8::try_from(0x20 + idx)?;
        let ep = spawn_lan(710 + u64::try_from(idx)?, seed_byte, false, None).await?;
        let pk = ep.local_pubkey();
        ep.allow_peer(host_pk).await?;
        ep.connect_direct(host_pk, &host_addrs).await?;
        assert!(wait_for_connected(&mut host, pk).await);
        pending.push((ep, pk));
    }

    // 16th peer starts an IN-FLIGHT handshake (QUIC connects, does NOT open Streams 0 & 4 yet).
    let inflight_seed = [0x9A; 32];
    let raw_inflight_ep = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&inflight_seed))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let inflight_conn = raw_inflight_ep
        .connect(
            EndpointAddr::from_parts(host_id, host_transport_addrs.clone()),
            ALPN,
        )
        .await?;
    // Allow host's accept_loop to reserve the 16th in-flight pending slot.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        inflight_conn.close_reason().is_none(),
        "16th in-flight pending peer should hold the 16th slot"
    );

    // While 15 active + 1 in-flight == 16:
    // (a) A 17th distinct unknown peer MUST be rejected!
    let extra_unknown = spawn_lan(790, 0x9B, false, None).await?;
    extra_unknown.allow_peer(host_pk).await?;
    assert_eq!(
        extra_unknown.connect_direct(host_pk, &host_addrs).await,
        Err(P2pError::PeerNotAllowed)
    );

    // (b) A second concurrent connection using the SAME key as the in-flight peer MUST be rejected!
    let dup_inflight_ep = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&inflight_seed))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let dup_res = dup_inflight_ep
        .connect(
            EndpointAddr::from_parts(host_id, host_transport_addrs.clone()),
            ALPN,
        )
        .await;
    match dup_res {
        Err(_) => {}
        Ok(conn) => {
            let err = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await?;
            match err {
                ConnectionError::ApplicationClosed(app) => {
                    assert_eq!(app.error_code.into_inner(), u64::from(CLOSE_UNAUTHORIZED));
                }
                other => {
                    return Err(format!("expected 4401 on duplicate in-flight key, got {other:?}").into());
                }
            }
        }
    }

    // (c) An ALREADY-ACTIVE pending peer (same key as slot #0) attempting a second connection
    //     while 15 active + 1 in-flight == 16 MUST ALSO be rejected (never 17)!
    let same_key_active_ep = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x20; 32]))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let same_key_res = same_key_active_ep
        .connect(
            EndpointAddr::from_parts(host_id, host_transport_addrs),
            ALPN,
        )
        .await;
    match same_key_res {
        Err(_) => {}
        Ok(conn) => {
            let err = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await?;
            match err {
                ConnectionError::ApplicationClosed(app) => {
                    assert_eq!(app.error_code.into_inner(), u64::from(CLOSE_UNAUTHORIZED));
                }
                other => {
                    return Err(
                        format!("expected 4401 on same-key overflow at cap 16, got {other:?}")
                            .into(),
                    );
                }
            }
        }
    }

    drop(inflight_conn);
    same_key_active_ep.close().await;
    dup_inflight_ep.close().await;
    raw_inflight_ep.close().await;
    extra_unknown.close().await;
    for (ep, _) in pending {
        ep.close().await;
    }
    host.close().await;
    Ok(())
}
