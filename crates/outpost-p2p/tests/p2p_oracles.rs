//! Tier 7 Real Dual-Endpoint Loopback QUIC Oracles for `outpost-p2p`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use iroh::endpoint::{ConnectionError, presets};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey, TransportAddr};
use mp_protocol::{DirectAddr, EndpointDescriptor, RelayPolicy, TransportKind};
use outpost_core::p2p_wire::{
    P2pActivityState, P2pBridgeEnvelope, P2pChatMessage, P2pControlNotice, P2pControlNoticeKind,
    P2pEphemeralPulse, P2pLane, P2pPartyFrame,
};
use outpost_p2p::{
    ALPN, CLOSE_PEER_REVOKED, CLOSE_SUPERSEDED, CLOSE_UNAUTHORIZED, P2pError, P2pTransportEvent,
    PartyP2pConfig, PartyP2pTransport, PeerDialTarget, STREAM_INIT_MARKER,
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
    bob.connect_peer(PeerDialTarget {
        device_id: 101,
        device_pubkey: alice_pk,
        remote_relay_policy: RelayPolicy::NoRelays,
        endpoint: alice_desc.clone(),
    })
    .await?;

    let stale_close = tokio::time::timeout(Duration::from_secs(5), stale_conn.closed()).await?;
    match stale_close {
        ConnectionError::ApplicationClosed(app) => {
            assert_eq!(app.error_code.into_inner(), u64::from(CLOSE_SUPERSEDED));
        }
        other => {
            return Err(format!("expected 4409 CLOSE_SUPERSEDED, got {other:?}").into());
        }
    }

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

    stale_ep.close().await;
    alice.close().await;
    bob.close().await;
    Ok(())
}
