//! Specification Oracles for `outpost-control` MLS Wire & HTTPS Control Plane (`v0.7.0`).
//!
//! Proves:
//! 1. `mp2` E2EE wire parser (`Hello` E2EE fields + all 5 MLS/ephemeral server events) and
//!    outbound builders enforcing `target == "*"` & `body_encoding == "opaque_b64"`.
//! 2. Real local TLS 1.3 mock HTTPS server verifying signed RFC 9421 requests across all 13
//!    `/v1/devices/{reserve,binding,list}` and `/v1/parties/:id/mls/*` routes, exact 236-byte
//!    device binding validation, and `<= 256 KiB` control budget enforcement.
//! 3. Real local TLS 1.3 mock `mp2` WebSocket verifying fail-closed plaintext refusal and clear
//!    `send_status` suppression when `e2ee_mode == 1`.

#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use ed25519_dalek::SigningKey;
use mp_protocol::{
    AccountId, DeviceId, HttpMethod, PartyId, Rfc9421Request, sha256, verify_rfc9421_request,
};
use outpost_control::{
    ControlClient, ControlClientConfig, ControlError, MAX_MLS_CONTROL_BODY_BYTES,
    MLS_DEVICE_BINDING_BYTES, MlsCommitAckRequest, MlsCommitRequest, MlsCreateInviteRequest,
    MlsInitRequest, MlsJoinRequest, MlsWelcomeAckRequest, Mp2EventKind, Mp2RoomEvent, Mp2WsError,
    PutDeviceBindingRequest, PutDeviceListRequest, RequestSigner, ReserveDeviceRequest,
    build_e2ee_app_frame_json, build_e2ee_ephemeral_frame_json,
    build_tls13_client_config_with_roots, parse_mp2_server_text, wall_now_secs,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const TEST_AUTHORITY: &str = "api.multiplayer.tech";

struct TestPki {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    client_tls13: Arc<rustls::ClientConfig>,
}

fn generate_test_pki() -> TestPki {
    let Ok(certified) = rcgen::generate_simple_self_signed(vec![TEST_AUTHORITY.to_owned()]) else {
        unreachable!("rcgen cert generation");
    };
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));
    let mut roots = rustls::RootCertStore::empty();
    assert!(roots.add(cert_der.clone()).is_ok());
    let Ok(client_tls13) = build_tls13_client_config_with_roots(roots) else {
        unreachable!("build TLS 1.3 client config");
    };
    TestPki {
        cert_der,
        key_der,
        client_tls13,
    }
}

fn make_server_acceptor(pki: &TestPki) -> TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let Ok(builder) = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
    else {
        unreachable!("TLS 1.3 server builder");
    };
    let Ok(mut cfg) = builder
        .with_no_client_auth()
        .with_single_cert(vec![pki.cert_der.clone()], pki.key_der.clone_key())
    else {
        unreachable!("server single cert");
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(cfg))
}

fn make_client_config(pki: &TestPki, addr: SocketAddr) -> ControlClientConfig {
    let Ok(cfg) = ControlClientConfig::new(TEST_AUTHORITY) else {
        unreachable!("valid authority");
    };
    cfg.with_tls_config(Arc::clone(&pki.client_tls13))
        .with_connect_addr(addr)
        .with_request_timeout(Duration::from_secs(5))
}

struct ParsedHttpReq {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_http_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> ParsedHttpReq {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let Ok(n) = stream.read(&mut tmp).await else {
            unreachable!("read request");
        };
        assert!(n > 0, "unexpected EOF while reading HTTP request");
        if let Some(chunk) = tmp.get(..n) {
            raw.extend_from_slice(chunk);
        }
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let head_slice = raw.get(..header_end).unwrap_or_default();
    let Ok(head_str) = std::str::from_utf8(head_slice) else {
        unreachable!("valid utf8 headers");
    };
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().unwrap_or_default();
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), format!("?{q}")),
        None => (target.clone(), "?".to_owned()),
    };

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    let content_len = headers
        .get("content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = raw.get(header_end + 4..).unwrap_or_default().to_vec();
    while body.len() < content_len {
        let Ok(n) = stream.read(&mut tmp).await else {
            unreachable!("read body");
        };
        assert!(n > 0, "unexpected EOF while reading HTTP body");
        if let Some(chunk) = tmp.get(..n) {
            body.extend_from_slice(chunk);
        }
    }
    body.truncate(content_len);

    ParsedHttpReq {
        method,
        path,
        query,
        headers,
        body,
    }
}

fn verify_req_signature(
    req: &ParsedHttpReq,
    root_pk: &[u8; 32],
    dev_pk: &[u8; 32],
) {
    let method = match req.method.as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        other => unreachable!("unexpected HTTP method {other}"),
    };
    let sig_input = req.headers.get("signature-input").map(String::as_str).unwrap_or_default();
    let sig = req.headers.get("signature").map(String::as_str).unwrap_or_default();
    let ct = req.headers.get("content-type").map(String::as_str);
    let cd = req.headers.get("content-digest").map(String::as_str);
    let rfc_req = Rfc9421Request {
        method,
        authority: TEST_AUTHORITY,
        path: &req.path,
        query: &req.query,
        content_type: ct,
        content_digest: cd,
        has_content_encoding: req.headers.contains_key("content-encoding"),
        body: &req.body,
        signature_input: sig_input,
        signature: sig,
    };
    let now_s = wall_now_secs();
    let is_root = sig_input.contains(".root\"");
    let expected_pk = if is_root { root_pk } else { dev_pk };
    let res = verify_rfc9421_request(&rfc_req, TEST_AUTHORITY, expected_pk, now_s);
    assert!(
        res.is_ok(),
        "RFC 9421 verification failed for {} {}{}: {res:?}",
        req.method,
        req.path,
        req.query
    );
}

#[test]
fn oracle_1_mp2_e2ee_frame_parsers_and_builders() {
    // 1. Hello with full E2EE metadata
    let hello_json = serde_json::json!({
        "v": 2,
        "t": "hello",
        "party_id": 7701,
        "room_code": "E2EE",
        "name": "Secure Room",
        "self": { "account_id": 1001, "handle": "alice", "role": "host" },
        "latest_seq": 5,
        "e2ee_mode": 1,
        "mls_epoch": 3,
        "min_allowed_mls_epoch": 2,
        "mls_rekey_required": true,
        "group_id_b64": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY",
        "members": [],
        "history": []
    })
    .to_string();
    let Ok(Mp2RoomEvent::Hello(hello)) = parse_mp2_server_text(&hello_json) else {
        unreachable!("expected Hello");
    };
    assert_eq!(hello.e2ee_mode, 1);
    assert_eq!(hello.mls_epoch, 3);
    assert_eq!(hello.min_allowed_mls_epoch, 2);
    assert!(hello.mls_rekey_required);
    assert_eq!(
        hello.group_id_b64.as_deref(),
        Some("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY")
    );

    // 2. All 5 MLS / ephemeral server events
    let tentative_json = serde_json::json!({
        "v": 2,
        "t": "mls_commit_tentative",
        "party_id": 7701,
        "group_id_b64": "GID",
        "parent_epoch": 3,
        "target_epoch": 4,
        "commit_sha256_b64": "SHA",
        "committer_account_id": 1001,
        "committer_device_id": 2001,
        "commit_b64": "Q09NTUlU",
        "proposal_blobs_b64": ["UFJPUA=="],
        "deadline_ms": 1_760_000_030_000u64
    })
    .to_string();
    assert!(matches!(
        parse_mp2_server_text(&tentative_json),
        Ok(Mp2RoomEvent::MlsCommitTentative {
            parent_epoch: 3,
            target_epoch: 4,
            committer_device_id: 2001,
            ..
        })
    ));

    let finalized_json = serde_json::json!({
        "v": 2,
        "t": "mls_commit_finalized",
        "party_id": 7701,
        "group_id_b64": "GID",
        "epoch": 4,
        "commit_sha256_b64": "SHA",
        "commit_b64": "Q09NTUlU",
        "proposal_blobs_b64": [],
        "confirmed_transcript_hash_b64": "Q1RI"
    })
    .to_string();
    assert!(matches!(
        parse_mp2_server_text(&finalized_json),
        Ok(Mp2RoomEvent::MlsCommitFinalized { epoch: 4, .. })
    ));

    let rekey_json = serde_json::json!({
        "v": 2,
        "t": "mls_rekey_needed",
        "party_id": 7701,
        "group_id_b64": "GID",
        "mls_epoch": 4,
        "min_allowed_mls_epoch": 5,
        "reason": "member_kicked",
        "proposal_blobs_b64": ["UkVNT1ZF"],
        "elected_committer_device_id": 2002
    })
    .to_string();
    assert!(matches!(
        parse_mp2_server_text(&rekey_json),
        Ok(Mp2RoomEvent::MlsRekeyNeeded {
            mls_epoch: 4,
            min_allowed_mls_epoch: 5,
            elected_committer_device_id: Some(2002),
            ..
        })
    ));

    let welcome_json = serde_json::json!({
        "v": 2,
        "t": "mls_welcome_ready",
        "party_id": 7701,
        "group_id_b64": "GID",
        "target_epoch": 5,
        "welcome_id": 88
    })
    .to_string();
    assert!(matches!(
        parse_mp2_server_text(&welcome_json),
        Ok(Mp2RoomEvent::MlsWelcomeReady {
            target_epoch: 5,
            welcome_id: Some(88),
            ..
        })
    ));

    let eph_json = serde_json::json!({
        "v": 2,
        "t": "ephemeral_event",
        "ts_ms": 1_760_000_000_000u64,
        "sender": { "account_id": 1002, "handle": "bob", "client": "outpost", "device_id": 2002 },
        "mls_epoch": 4,
        "target": "*",
        "kind": "e2ee_ephemeral",
        "body_encoding": "opaque_b64",
        "body": "Q0lQSEVSVEVYVA=="
    })
    .to_string();
    assert!(matches!(
        parse_mp2_server_text(&eph_json),
        Ok(Mp2RoomEvent::EphemeralEvent {
            mls_epoch: Some(4),
            kind: Mp2EventKind::E2eeEphemeral,
            ..
        })
    ));

    // 3. Outbound E2EE builders enforce target == "*" & body_encoding == "opaque_b64"
    let Ok(app_frame) = build_e2ee_app_frame_json("cid-1", 4, "QUJDRA==") else {
        unreachable!("build_e2ee_app_frame_json");
    };
    let Ok(app_val): Result<serde_json::Value, _> = serde_json::from_str(&app_frame) else {
        unreachable!("parse app frame JSON");
    };
    assert_eq!(app_val.get("t").and_then(serde_json::Value::as_str), Some("send"));
    assert_eq!(app_val.get("kind").and_then(serde_json::Value::as_str), Some("e2ee_app"));
    assert_eq!(app_val.get("target").and_then(serde_json::Value::as_str), Some("*"));
    assert_eq!(
        app_val.get("body_encoding").and_then(serde_json::Value::as_str),
        Some("opaque_b64")
    );
    assert_eq!(app_val.get("mls_epoch").and_then(serde_json::Value::as_u64), Some(4));

    let Ok(eph_frame) = build_e2ee_ephemeral_frame_json("cid-2", 4, "QUJDRA==") else {
        unreachable!("build_e2ee_ephemeral_frame_json");
    };
    let Ok(eph_val): Result<serde_json::Value, _> = serde_json::from_str(&eph_frame) else {
        unreachable!("parse eph frame JSON");
    };
    assert_eq!(
        eph_val.get("kind").and_then(serde_json::Value::as_str),
        Some("e2ee_ephemeral")
    );
    assert_eq!(eph_val.get("target").and_then(serde_json::Value::as_str), Some("*"));
    assert_eq!(
        eph_val.get("body_encoding").and_then(serde_json::Value::as_str),
        Some("opaque_b64")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_2_signed_rfc9421_mls_https_control_plane_and_256kib_budget() {
    let pki = generate_test_pki();
    let acceptor = make_server_acceptor(&pki);
    let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
        unreachable!("bind loopback");
    };
    let Ok(addr) = listener.local_addr() else {
        unreachable!("local addr");
    };

    let root_sk = SigningKey::from_bytes(&[0x11; 32]);
    let dev_sk = SigningKey::from_bytes(&[0x22; 32]);
    let root_pk = root_sk.verifying_key().to_bytes();
    let dev_pk = dev_sk.verifying_key().to_bytes();
    let Ok(acc_id) = AccountId::new(1001) else {
        unreachable!("account id");
    };
    let Ok(dev_id) = DeviceId::new(2001) else {
        unreachable!("device id");
    };
    let Ok(pid) = PartyId::new(7701) else {
        unreachable!("party id");
    };

    let root_signer = RequestSigner::root(acc_id, root_sk.to_bytes());
    let dev_signer = RequestSigner::device(acc_id, dev_id, dev_sk.to_bytes());
    let client = ControlClient::with_device_signer(make_client_config(&pki, addr), dev_signer);

    let seen_routes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_routes_srv = Arc::clone(&seen_routes);

    let srv = tokio::spawn(async move {
        for _ in 0..13 {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                break;
            };
            let req = read_http_request(&mut tls).await;
            verify_req_signature(&req, &root_pk, &dev_pk);
            let key = format!("{} {}{}", req.method, req.path, req.query);
            if let Ok(mut g) = seen_routes_srv.lock() {
                g.push(key.clone());
            }

            let resp_body = match (req.method.as_str(), req.path.as_str()) {
                ("POST", "/v1/devices/reserve") => {
                    serde_json::json!({ "device_id": 2001, "root_gen": 1, "device_gen": 1 })
                }
                ("PUT", "/v1/devices/binding") => {
                    serde_json::json!({ "device_id": 2001, "device_gen": 1, "ok": true })
                }
                ("PUT", "/v1/devices/list") => {
                    serde_json::json!({ "ok": true, "list_version": 3, "list_hash_b64": "SEFTSA==" })
                }
                ("GET", "/v1/devices/list") => {
                    serde_json::json!({ "account_id": 1001, "list_version": 3, "device_list_b64": "TElTVA==" })
                }
                ("POST", "/v1/parties/7701/mls/init") => {
                    serde_json::json!({ "ok": true, "group_id_b64": "GID", "mls_epoch": 0, "party_ds_pubkey_b64": "RFNQSw==" })
                }
                ("POST", "/v1/parties/7701/mls/invites") => {
                    serde_json::json!({ "invite_id": 9001, "invite_epoch": 0, "expires_at_ms": 1_760_003_600_000u64 })
                }
                ("POST", "/v1/parties/7701/mls/join") => {
                    serde_json::json!({ "status": "queued", "mls_epoch": 0 })
                }
                ("POST", "/v1/parties/7701/mls/commit") => {
                    serde_json::json!({ "status": "tentative", "target_epoch": 1, "commit_sha256_b64": "SHA", "finalized": false })
                }
                ("POST", "/v1/parties/7701/mls/ack") => {
                    serde_json::json!({ "ok": true, "finalized": true, "discarded": false, "new_epoch": 1 })
                }
                ("GET", "/v1/parties/7701/mls/commits") => {
                    serde_json::json!({
                        "group_id_b64": "GID",
                        "head_epoch": 1,
                        "commits": [{ "epoch": 1, "commit_b64": "Q09NTUlU", "proposal_blobs_b64": [] }]
                    })
                }
                ("GET", "/v1/parties/7701/mls/welcome") => {
                    serde_json::json!({
                        "pending": true,
                        "group_id_b64": "GID",
                        "target_epoch": 1,
                        "welcome_b64": "V0VMQ09NRQ==",
                        "welcome_auth_b64": "QVVUSA==",
                        "party_ds_pubkey_b64": "RFNQSw=="
                    })
                }
                ("POST", "/v1/parties/7701/mls/welcome/ack") => {
                    serde_json::json!({ "ok": true })
                }
                ("GET", "/v1/parties/7701/mls/device-lists") => {
                    serde_json::json!({
                        "device_lists": [{ "account_id": 1001, "list_version": 3, "device_list_b64": "TElTVA==" }]
                    })
                }
                other => unreachable!("unexpected route: {other:?}"),
            };

            let body_bytes = resp_body.to_string().into_bytes();
            let http_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_bytes.len()
            );
            assert!(tls.write_all(http_resp.as_bytes()).await.is_ok());
            assert!(tls.write_all(&body_bytes).await.is_ok());
            assert!(tls.flush().await.is_ok());
        }
    });

    // Local validation checks BEFORE hitting network:
    // 1. Non-236 byte device binding rejected locally!
    let bad_binding = client
        .put_device_binding(
            &root_signer,
            &PutDeviceBindingRequest {
                device_binding_b64: B64_STD.encode([0xAAu8; MLS_DEVICE_BINDING_BYTES - 1]),
                device_label: Some("MacBook".to_owned()),
            },
        )
        .await;
    assert!(matches!(bad_binding, Err(ControlError::InvalidRequest(_))));

    // 2. Oversized > 256 KiB MLS control request rejected locally!
    let huge = "A".repeat(MAX_MLS_CONTROL_BODY_BYTES + 128);
    let oversized = client
        .mls_submit_commit(
            pid,
            &MlsCommitRequest {
                parent_epoch: 0,
                commit_b64: huge,
                welcome_b64: None,
                welcome_auth_b64: None,
                joiner_device_id: None,
                welcomes: Vec::new(),
            },
        )
        .await;
    assert!(matches!(oversized, Err(ControlError::InvalidRequest(_))));

    // Now exercise all 13 signed RFC 9421 endpoints end-to-end!
    let Ok(r_res) = client
        .reserve_device_id(
            &root_signer,
            &ReserveDeviceRequest {
                client_class: 2,
                device_label: "Outpost".to_owned(),
            },
        )
        .await
    else {
        unreachable!("reserve_device_id");
    };
    assert_eq!(r_res.device_id, 2001);

    let Ok(r_bind) = client
        .put_device_binding(
            &root_signer,
            &PutDeviceBindingRequest {
                device_binding_b64: B64_STD.encode([0xBBu8; MLS_DEVICE_BINDING_BYTES]),
                device_label: Some("Outpost".to_owned()),
            },
        )
        .await
    else {
        unreachable!("put_device_binding");
    };
    assert!(r_bind.ok);

    let Ok(r_put_list) = client
        .put_device_list(
            &root_signer,
            &PutDeviceListRequest {
                device_list_b64: B64_STD.encode(b"list-bytes"),
            },
        )
        .await
    else {
        unreachable!("put_device_list");
    };
    assert_eq!(r_put_list.list_version, 3);

    let Ok(r_get_list) = client.get_device_list().await else {
        unreachable!("get_device_list");
    };
    assert_eq!(r_get_list.account_id, 1001);

    let Ok(r_init) = client
        .mls_init_group(
            pid,
            &MlsInitRequest {
                group_id_b64: "GID".to_owned(),
                group_info_b64: "R0lORk8=".to_owned(),
            },
        )
        .await
    else {
        unreachable!("mls_init_group");
    };
    assert!(r_init.ok);

    let Ok(r_inv) = client
        .mls_create_invite(
            pid,
            &MlsCreateInviteRequest {
                server_token_hash_b64: "SEFTSA==".to_owned(),
                max_uses: 4,
                expires_at_ms: 1_760_003_600_000,
                invite_epoch: Some(0),
            },
        )
        .await
    else {
        unreachable!("mls_create_invite");
    };
    assert_eq!(r_inv.invite_id, 9001);

    let Ok(r_join) = client
        .mls_submit_join(
            pid,
            &MlsJoinRequest {
                invite_id: Some(9001),
                server_invite_token_b64: Some("VE9LRU4=".to_owned()),
                kp_ref_b64: "S1BSRUY=".to_owned(),
                kp_blob_b64: "S1A=".to_owned(),
                join_proof_b64: Some("UFJPT0Y=".to_owned()),
            },
        )
        .await
    else {
        unreachable!("mls_submit_join");
    };
    assert_eq!(r_join.status, "queued");

    let Ok(r_com) = client
        .mls_submit_commit(
            pid,
            &MlsCommitRequest {
                parent_epoch: 0,
                commit_b64: "Q09NTUlU".to_owned(),
                welcome_b64: None,
                welcome_auth_b64: None,
                joiner_device_id: None,
                welcomes: Vec::new(),
            },
        )
        .await
    else {
        unreachable!("mls_submit_commit");
    };
    assert_eq!(r_com.target_epoch, 1);

    let Ok(r_ack) = client
        .mls_submit_ack(
            pid,
            &MlsCommitAckRequest {
                group_id_b64: "GID".to_owned(),
                parent_epoch: 0,
                target_epoch: 1,
                commit_sha256_b64: "SHA".to_owned(),
                status: 1,
                epoch_auth_hash_b64: Some("QVVUSA==".to_owned()),
                ack_sig_b64: "U0lH".to_owned(),
            },
        )
        .await
    else {
        unreachable!("mls_submit_ack");
    };
    assert!(r_ack.finalized);

    let Ok(r_commits) = client.mls_fetch_commits(pid, 1, 16).await else {
        unreachable!("mls_fetch_commits");
    };
    assert_eq!(r_commits.commits.len(), 1);

    let Ok(r_wel) = client.mls_fetch_welcome(pid).await else {
        unreachable!("mls_fetch_welcome");
    };
    assert!(r_wel.pending);

    let Ok(r_wack) = client
        .mls_ack_welcome(
            pid,
            &MlsWelcomeAckRequest {
                group_id_b64: "GID".to_owned(),
                target_epoch: 1,
                kp_ref_b64: "S1BSRUY=".to_owned(),
                welcome_id: None,
            },
        )
        .await
    else {
        unreachable!("mls_ack_welcome");
    };
    assert!(r_wack.ok);

    let Ok(r_dls) = client.mls_fetch_device_lists(pid).await else {
        unreachable!("mls_fetch_device_lists");
    };
    assert_eq!(r_dls.device_lists.len(), 1);

    assert!(srv.await.is_ok());
    let routes = seen_routes.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(routes.len(), 13);
    assert!(routes.contains(&"GET /v1/parties/7701/mls/commits?from_epoch=1&limit=16".to_owned()));
}

fn ws_accept_key(sec_ws_key: &str) -> String {
    let mut input = Vec::with_capacity(sec_ws_key.len() + 36);
    input.extend_from_slice(sec_ws_key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = sha256(&input);
    // Wait: RFC 6455 uses SHA-1! Use sha1_digest inline (20-byte minimal RFC 3174).
    let _ = digest;
    B64_STD.encode(sha1_rfc6455(&input))
}

/// Minimal owned RFC 3174 SHA-1 for RFC 6455 `Sec-WebSocket-Accept` in mock WS server tests.
fn sha1_rfc6455(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let b0 = chunk.get(i * 4).copied().unwrap_or(0);
            let b1 = chunk.get(i * 4 + 1).copied().unwrap_or(0);
            let b2 = chunk.get(i * 4 + 2).copied().unwrap_or(0);
            let b3 = chunk.get(i * 4 + 3).copied().unwrap_or(0);
            if let Some(slot) = w.get_mut(i) {
                *slot = u32::from_be_bytes([b0, b1, b2, b3]);
            }
        }
        for i in 16..80 {
            let v = w.get(i - 3).copied().unwrap_or(0)
                ^ w.get(i - 8).copied().unwrap_or(0)
                ^ w.get(i - 14).copied().unwrap_or(0)
                ^ w.get(i - 16).copied().unwrap_or(0);
            if let Some(slot) = w.get_mut(i) {
                *slot = v.rotate_left(1);
            }
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A82_7999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9_EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC_u32)
            } else {
                (b ^ c ^ d, 0xCA62_C1D6u32)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    if let Some(s) = out.get_mut(0..4) {
        s.copy_from_slice(&h0.to_be_bytes());
    }
    if let Some(s) = out.get_mut(4..8) {
        s.copy_from_slice(&h1.to_be_bytes());
    }
    if let Some(s) = out.get_mut(8..12) {
        s.copy_from_slice(&h2.to_be_bytes());
    }
    if let Some(s) = out.get_mut(12..16) {
        s.copy_from_slice(&h3.to_be_bytes());
    }
    if let Some(s) = out.get_mut(16..20) {
        s.copy_from_slice(&h4.to_be_bytes());
    }
    out
}

async fn send_ws_server_text<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, text: &str) {
    let payload = text.as_bytes();
    let mut frame = Vec::with_capacity(10 + payload.len());
    frame.push(0x81); // FIN + Text
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    assert!(stream.write_all(&frame).await.is_ok());
    assert!(stream.flush().await.is_ok());
}

async fn read_ws_client_text<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut hdr = [0u8; 2];
    assert!(stream.read_exact(&mut hdr).await.is_ok());
    let b1 = hdr.get(1).copied().unwrap_or(0);
    let masked = (b1 & 0x80) != 0;
    assert!(masked, "client WS frames must be masked");
    let len_byte = b1 & 0x7F;
    let payload_len: usize = if len_byte < 126 {
        usize::from(len_byte)
    } else {
        let mut ext = [0u8; 2];
        assert!(stream.read_exact(&mut ext).await.is_ok());
        usize::from(u16::from_be_bytes(ext))
    };
    let mut mask = [0u8; 4];
    assert!(stream.read_exact(&mut mask).await.is_ok());
    let mut payload = vec![0u8; payload_len];
    assert!(stream.read_exact(&mut payload).await.is_ok());
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask.get(i % 4).copied().unwrap_or(0);
    }
    String::from_utf8(payload).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_3_mp2_ws_e2ee_mode_suppresses_clear_status_and_blocks_plaintext() {
    let pki = generate_test_pki();
    let acceptor = make_server_acceptor(&pki);
    let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
        unreachable!("bind ws loopback");
    };
    let Ok(addr) = listener.local_addr() else {
        unreachable!("ws local addr");
    };

    let dev_sk = SigningKey::from_bytes(&[0x33; 32]);
    let Ok(acc_id) = AccountId::new(1001) else {
        unreachable!("acc");
    };
    let Ok(dev_id) = DeviceId::new(2001) else {
        unreachable!("dev");
    };
    let Ok(pid) = PartyId::new(7701) else {
        unreachable!("pid");
    };
    let signer = RequestSigner::device(acc_id, dev_id, dev_sk.to_bytes());
    let client = ControlClient::with_device_signer(make_client_config(&pki, addr), signer);

    let srv = tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            unreachable!("accept ws");
        };
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            unreachable!("tls accept ws");
        };
        let req = read_http_request(&mut tls).await;
        let ws_key = req
            .headers
            .get("sec-websocket-key")
            .cloned()
            .unwrap_or_default();
        let accept = ws_accept_key(&ws_key);
        let upgrade = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: mp2\r\n\r\n"
        );
        assert!(tls.write_all(upgrade.as_bytes()).await.is_ok());
        assert!(tls.flush().await.is_ok());

        // Send Hello with e2ee_mode = 1
        let hello = serde_json::json!({
            "v": 2,
            "t": "hello",
            "party_id": 7701,
            "room_code": "E2EE",
            "name": "Locked Room",
            "self": { "account_id": 1001, "handle": "alice", "role": "host" },
            "latest_seq": 0,
            "e2ee_mode": 1,
            "mls_epoch": 2,
            "min_allowed_mls_epoch": 2,
            "mls_rekey_required": false,
            "members": [],
            "history": []
        })
        .to_string();
        send_ws_server_text(&mut tls, &hello).await;

        // First client frame received MUST be `e2ee_app` (clear `status` and plaintext `chat` were suppressed/refused!)
        let frame1 = read_ws_client_text(&mut tls).await;
        let frame2 = read_ws_client_text(&mut tls).await;
        (frame1, frame2)
    });

    let Ok(mut ws) = client.connect_mp2_room(pid).await else {
        unreachable!("connect_mp2_room");
    };
    let Ok(Some(Mp2RoomEvent::Hello(hello))) = ws.next_event().await else {
        unreachable!("receive hello");
    };
    assert_eq!(hello.e2ee_mode, 1);
    ws.set_e2ee_mode(hello.e2ee_mode);
    assert_eq!(ws.e2ee_mode(), 1);

    // Clear send_status MUST be silently suppressed (zero bytes transmitted)!
    assert!(ws.send_status("outpost", "Outpost", "idle", None).await.is_ok());

    // Plaintext send_event MUST fail closed locally with Mp2WsError::InvalidJson!
    let bad_plain = ws
        .send_event("cid-plain", Mp2EventKind::Chat, "@all", "utf8", "leaked secret")
        .await;
    assert!(matches!(bad_plain, Err(Mp2WsError::InvalidJson(_))));

    // E2EE app & ephemeral frames succeed cleanly!
    assert!(ws.send_e2ee_app("cid-e2ee-1", 2, "Q0lQSEVSMQ==").await.is_ok());
    assert!(
        ws.send_e2ee_ephemeral("cid-eph-1", 2, "Q0lQSEVSMg==")
            .await
            .is_ok()
    );

    let Ok((f1, f2)) = srv.await else {
        unreachable!("ws server join");
    };
    assert!(f1.contains("\"kind\":\"e2ee_app\""));
    assert!(f1.contains("\"target\":\"*\""));
    assert!(f1.contains("\"body_encoding\":\"opaque_b64\""));
    assert!(!f1.contains("leaked secret"));
    assert!(f2.contains("\"kind\":\"e2ee_ephemeral\""));
    assert!(f2.contains("\"target\":\"*\""));
}
