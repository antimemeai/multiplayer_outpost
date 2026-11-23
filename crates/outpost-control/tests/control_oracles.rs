//! Tier 7 Specification Oracles for `outpost-control`.
//!
//! Exercises real local TLS 1.3 (and TLS 1.2 negative) mock servers on `127.0.0.1`
//! with `rcgen` certificates for `api.multiplayer.tech`, verifying:
//! 1. TLS 1.2 server is rejected fail-closed (TLS 1.3 only).
//! 2. `Transfer-Encoding: chunked` REST response, `> 16 KiB` body rejection, zero redirects.
//! 3. RFC 9421 `clock_skew` auto-retry preserves exact `Idempotency-Key` & body while
//!    generating a fresh nonce, and clamps `clock_offset_ms` to `±600_000 ms`.
//! 4. Real WS `101` upgrade verifying `Sec-WebSocket-Protocol: mp1`, coalesced post-`101`
//!    `HELLO_ACK` & `PARTY_SNAPSHOT` frames, `"MP1:PING"`/`"MP1:PONG"`, fragmented WS message
//!    with interleaved RFC 6455 Ping, rejecting `> 8,192 B` reassembled WS frame, and rejecting
//!    missing `mp1` subprotocol / `permessage-deflate`.
//! 5. HTTP `404`/`403` WS upgrade -> `WsConnectError::Terminal(status)`;
//!    `EvictionChurnDetector` at 3 rapid changing sessions; `EndpointUpdateCoalescer`
//!    30s throttling, `retry_after_ms`, and `ForceRelays` suppression;
//!    plus typed REST endpoint contract coverage across all `/v1/*` routes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use ed25519_dalek::SigningKey;
use mp_protocol::{
    AccountId, DeviceId, DirectAddr, EndpointDescriptor, HttpMethod, MAX_MP1_FRAME_BYTES,
    MemberLeaveReason, Mp1Message, PartyId, PartyInviteId, PartyJoinMode, PartyMemberRecord,
    PartySnapshot, PartyVisibility, RelayPolicy, RequestId, Rfc9421Error, Rfc9421Request,
    SessionId, TransportKind, encode_device_cwt, encode_frame, sha256, verify_rfc9421_request,
};
use outpost_control::{
    ApprovePartyRequest, ChurnStatus, ControlClient, ControlClientConfig, ControlError,
    CreatePartyRequest, DeviceLinkApproveRequest, DeviceLinkInspectResponse,
    DeviceLinkPollResponse, EndpointUpdateCoalescer, EnrollDeviceRequest, EvictionChurnDetector,
    JoinPartyRequest, JoinPartyResponse, MAX_CLOCK_OFFSET_MS, MAX_RESPONSE_BODY_BYTES,
    MP1_PING_TEXT, MP1_PONG_TEXT, MintPartyInviteRequest, Mp1WsEvent, Mp1WsTarget,
    RegisterAccountRequest, RequestSigner, WsConnectError, WsError,
    build_tls13_client_config_with_roots, wall_now_ms, wall_now_secs,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const TEST_AUTHORITY: &str = "api.multiplayer.tech";
const TEST_RELAY_URL: &str = "https://relay.multiplayer.tech";

struct TestPki {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    client_tls13: Arc<rustls::ClientConfig>,
}

fn generate_test_pki() -> TestPki {
    let certified = rcgen::generate_simple_self_signed(vec![TEST_AUTHORITY.to_owned()])
        .expect("rcgen cert generation");
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add test root cert");
    let client_tls13 =
        build_tls13_client_config_with_roots(roots).expect("build TLS 1.3 client config");

    TestPki {
        cert_der,
        key_der,
        client_tls13,
    }
}

fn make_server_acceptor(
    pki: &TestPki,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![pki.cert_der.clone()], pki.key_der.clone_key())
        .expect("server cert");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(cfg))
}

fn make_client_config(pki: &TestPki, addr: SocketAddr) -> ControlClientConfig {
    ControlClientConfig::new(TEST_AUTHORITY)
        .expect("valid authority")
        .with_tls_config(Arc::clone(&pki.client_tls13))
        .with_connect_addr(addr)
        .with_request_timeout(Duration::from_secs(5))
}

#[derive(Debug, Clone)]
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
        let n = stream.read(&mut tmp).await.expect("read request");
        assert!(n > 0, "unexpected EOF while reading HTTP request");
        raw.extend_from_slice(&tmp[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let head_str = std::str::from_utf8(&raw[..header_end]).expect("valid utf8 headers");
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().expect("request line");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().expect("method").to_owned();
    let target = parts.next().expect("target").to_owned();
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

    let mut body = raw[header_end + 4..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp).await.expect("read body");
        assert!(n > 0, "unexpected EOF while reading HTTP body");
        body.extend_from_slice(&tmp[..n]);
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

/// Pure RFC 3174 SHA-1 for computing `Sec-WebSocket-Accept` in the local mock server.
fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let (chunks, _) = msg.as_chunks::<64>();
    for chunk in chunks {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
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
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn ws_accept_value(client_key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut buf = Vec::with_capacity(client_key.len() + GUID.len());
    buf.extend_from_slice(client_key.as_bytes());
    buf.extend_from_slice(GUID.as_bytes());
    B64_STD.encode(sha1_digest(&buf))
}

fn encode_server_ws_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.push((if fin { 0x80 } else { 0x00 }) | (opcode & 0x0f));
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

async fn read_masked_client_ws_frame<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> (u8, Vec<u8>) {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.expect("ws frame hdr");
    let opcode = hdr[0] & 0x0f;
    let masked = (hdr[1] & 0x80) != 0;
    assert!(masked, "RFC 6455 requires client frames to be masked");
    let mut len = usize::from(hdr[1] & 0x7f);
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await.expect("ws len16");
        len = usize::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await.expect("ws len64");
        len = u64::from_be_bytes(ext) as usize;
    }
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).await.expect("ws mask");
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.expect("ws payload");
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    (opcode, payload)
}

fn make_cwt(root_secret: [u8; 32], dev_pubkey: [u8; 32]) -> Vec<u8> {
    let root = SigningKey::from_bytes(&root_secret);
    let now = wall_now_secs();
    encode_device_cwt(&root, &dev_pubkey, now - 5, now + 86_400).expect("encode cwt")
}

fn make_relay_only_endpoint() -> EndpointDescriptor {
    EndpointDescriptor {
        transport_kind: TransportKind::IrohQuic,
        relay_url: TEST_RELAY_URL.to_owned(),
        direct_addrs: vec![],
    }
}

fn make_direct_endpoint(port: u16) -> EndpointDescriptor {
    EndpointDescriptor {
        transport_kind: TransportKind::IrohQuic,
        relay_url: TEST_RELAY_URL.to_owned(),
        direct_addrs: vec![DirectAddr::V4 {
            ip: [203, 0, 113, 10],
            port,
        }],
    }
}

// ===========================================================================
// Oracle 1: TLS 1.2 Server Rejected Fail-Closed (Both REST & WS)
// ===========================================================================

#[tokio::test]
async fn oracle_tls12_server_is_rejected_fail_closed() {
    let pki = generate_test_pki();
    let tls12_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS12]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let srv = tokio::spawn(async move {
        for _ in 0..2 {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = tls12_acceptor.accept(tcp).await;
            }
        }
    });

    let signer = RequestSigner::device(
        AccountId::new(100).expect("acct"),
        DeviceId::new(200).expect("dev"),
        [7u8; 32],
    );
    let client = ControlClient::with_device_signer(make_client_config(&pki, addr), signer);

    // 1. REST call against TLS 1.2 server must fail closed!
    let rest_err = client
        .health()
        .await
        .expect_err("TLS 1.2 REST server MUST be rejected");
    assert!(
        matches!(rest_err, ControlError::Io(_)),
        "expected TLS handshake Io error, got: {rest_err:?}"
    );

    // 2. WebSocket connect against TLS 1.2 server must also fail closed!
    let ws_err = client
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect_err("TLS 1.2 WS server MUST be rejected");
    assert!(
        matches!(ws_err, WsConnectError::Transport(ControlError::Io(_))),
        "expected TLS handshake transport error, got: {ws_err:?}"
    );

    srv.await.expect("server task");
}

// ===========================================================================
// Oracle 2: Chunked REST Response, > 16 KiB Body Rejection, & Zero Redirects
// ===========================================================================

#[tokio::test]
async fn oracle_chunked_rest_response_oversized_body_and_zero_redirects() {
    let pki = generate_test_pki();
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let srv = tokio::spawn(async move {
        // Request 1: Valid multi-chunk Transfer-Encoding: chunked JSON response
        {
            let (tcp, _) = listener.accept().await.expect("accept 1");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls 1");
            let req = read_http_request(&mut tls).await;
            assert_eq!(req.method, "GET");
            assert_eq!(req.path, "/v1/health");
            assert_eq!(req.headers.get("host").map(String::as_str), Some(TEST_AUTHORITY));

            let part1 = r#"{"ok":true,"#;
            let part2 = r#""server_now_ms":1730000123456}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                part1.len(),
                part1,
                part2.len(),
                part2
            );
            tls.write_all(resp.as_bytes()).await.expect("write chunked");
            tls.shutdown().await.expect("shutdown 1");
        }

        // Request 2: Chunked body exceeding 16 KiB (16_385 bytes)
        {
            let (tcp, _) = listener.accept().await.expect("accept 2");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls 2");
            let _req = read_http_request(&mut tls).await;
            let chunk_a = vec![b'a'; 8192];
            let chunk_b = vec![b'b'; 8193]; // total = 16_385 > 16_384!
            let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            resp.extend_from_slice(format!("{:x}\r\n", chunk_a.len()).as_bytes());
            resp.extend_from_slice(&chunk_a);
            resp.extend_from_slice(b"\r\n");
            resp.extend_from_slice(format!("{:x}\r\n", chunk_b.len()).as_bytes());
            resp.extend_from_slice(&chunk_b);
            resp.extend_from_slice(b"\r\n0\r\n\r\n");
            let _ = tls.write_all(&resp).await;
            let _ = tls.shutdown().await;
        }

        // Request 3: Content-Length exceeding 16 KiB
        {
            let (tcp, _) = listener.accept().await.expect("accept 3");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls 3");
            let _req = read_http_request(&mut tls).await;
            let oversized = MAX_RESPONSE_BODY_BYTES + 1;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {oversized}\r\n\r\n"
            );
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.shutdown().await;
        }

        // Request 4: 302 Redirect must NEVER be followed
        {
            let (tcp, _) = listener.accept().await.expect("accept 4");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls 4");
            let _req = read_http_request(&mut tls).await;
            let resp = "HTTP/1.1 302 Found\r\nLocation: https://evil.example/v1/health\r\nContent-Length: 0\r\n\r\n";
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });

    let client = ControlClient::new(make_client_config(&pki, addr));

    let health = client.health().await.expect("chunked health must succeed");
    assert!(health.ok);
    assert_eq!(health.server_now_ms, 1_730_000_123_456);

    let err_chunked = client
        .health()
        .await
        .expect_err(">16 KiB chunked body must fail");
    assert!(
        matches!(err_chunked, ControlError::ResponseTooLarge),
        "expected ResponseTooLarge, got {err_chunked:?}"
    );

    let err_cl = client
        .health()
        .await
        .expect_err(">16 KiB Content-Length must fail");
    assert!(
        matches!(err_cl, ControlError::ResponseTooLarge),
        "expected ResponseTooLarge, got {err_cl:?}"
    );

    let err_redir = client
        .health()
        .await
        .expect_err("302 redirect must be refused");
    assert!(
        matches!(err_redir, ControlError::UnexpectedRedirect { status: 302 }),
        "expected UnexpectedRedirect(302), got {err_redir:?}"
    );

    srv.await.expect("server task");
}

// ===========================================================================
// Oracle 3: RFC 9421 `clock_skew` Auto-Retry + Idempotency-Key Preservation
//           + Fresh Nonce + `±600_000 ms` Clamp
// ===========================================================================

#[tokio::test]
async fn oracle_clock_skew_retry_preserves_idempotency_key_and_refreshes_nonce() {
    let pki = generate_test_pki();
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let root_secret = [11u8; 32];
    let root_signing = SigningKey::from_bytes(&root_secret);
    let root_pubkey = root_signing.verifying_key().to_bytes();
    let dev_signing = SigningKey::from_bytes(&[22u8; 32]);
    let dev_pubkey = dev_signing.verifying_key().to_bytes();
    let cwt = make_cwt(root_secret, dev_pubkey);
    let idem_key = "reg_idem_key_0123456789abcdef";

    // Simulate a server clock shifted +180 seconds ahead of local wall clock.
    let skew_ms: i64 = 180_000;
    let observed = Arc::new(Mutex::new(Vec::<(String, String, Vec<u8>)>::new()));
    let observed_srv = Arc::clone(&observed);

    let srv = tokio::spawn(async move {
        for attempt in 0..2u8 {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls accept");
            let req = read_http_request(&mut tls).await;
            assert_eq!(req.method, "POST");
            assert_eq!(req.path, "/v1/accounts/register");

            let sig_input = req
                .headers
                .get("signature-input")
                .expect("signature-input")
                .clone();
            let sig = req.headers.get("signature").expect("signature").clone();
            let idem = req
                .headers
                .get("idempotency-key")
                .expect("idempotency-key")
                .clone();

            let parsed_si =
                mp_protocol::parse_signature_input(&sig_input).expect("valid signature-input");
            observed_srv
                .lock()
                .expect("lock")
                .push((parsed_si.nonce.clone(), idem, req.body.clone()));

            let server_now_ms = (wall_now_ms() as i64 + skew_ms) as u64;
            let server_now_s = (server_now_ms / 1000) as i64;

            let verify_res = verify_rfc9421_request(
                &Rfc9421Request {
                    method: HttpMethod::Post,
                    authority: req.headers.get("host").map(String::as_str).unwrap_or(""),
                    path: &req.path,
                    query: &req.query,
                    content_type: req.headers.get("content-type").map(String::as_str),
                    content_digest: req.headers.get("content-digest").map(String::as_str),
                    has_content_encoding: req.headers.contains_key("content-encoding"),
                    body: &req.body,
                    signature_input: &sig_input,
                    signature: &sig,
                },
                TEST_AUTHORITY,
                &root_pubkey,
                server_now_s,
            );

            let (status_line, body_json) = if attempt == 0 {
                assert_eq!(
                    verify_res.expect_err("attempt 0 must hit ClockSkew"),
                    Rfc9421Error::ClockSkew
                );
                (
                    "HTTP/1.1 401 Unauthorized",
                    format!(r#"{{"error":"clock_skew","server_now_ms":{server_now_ms}}}"#),
                )
            } else {
                let verified = verify_res.expect("attempt 1 must pass RFC 9421 verification");
                assert_eq!(
                    verified.keyid.format(),
                    RequestSigner::registration(root_secret).key_id().format()
                );
                (
                    "HTTP/1.1 201 Created",
                    r#"{"account_id":1001,"device_id":2002,"handle":"alice"}"#.to_owned(),
                )
            };

            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body_json.len(),
                body_json
            );
            tls.write_all(resp.as_bytes()).await.expect("write resp");
            tls.shutdown().await.expect("shutdown");
        }
    });

    let client = ControlClient::new(make_client_config(&pki, addr));
    let reg = client
        .register_account(
            root_secret,
            idem_key,
            &RegisterAccountRequest {
                invite_secret: "mpinv1_test_invite_token_value".to_owned(),
                handle: "alice".to_owned(),
                device_pubkey: dev_pubkey,
                device_label: "macbook".to_owned(),
                device_cwt: cwt,
            },
        )
        .await
        .expect("register_account must succeed after clock_skew auto-retry");

    assert_eq!(reg.account_id, 1001);
    assert_eq!(reg.device_id, 2002);
    assert_eq!(reg.handle, "alice");

    srv.await.expect("server task");

    {
        let recorded = observed.lock().expect("lock");
        assert_eq!(recorded.len(), 2, "expected exactly 2 attempts");
        assert_ne!(
            recorded[0].0, recorded[1].0,
            "retry MUST generate a fresh RFC 9421 nonce"
        );
        assert_eq!(
            recorded[0].1, idem_key,
            "attempt 1 Idempotency-Key must match"
        );
        assert_eq!(
            recorded[1].1, idem_key,
            "retry MUST preserve exact Idempotency-Key"
        );
        assert_eq!(
            recorded[0].2, recorded[1].2,
            "retry MUST preserve exact body bytes"
        );
    }

    let learned_offset = client.clock_offset_ms();
    assert!(
        (learned_offset - skew_ms).abs() < 5_000,
        "expected offset near {skew_ms}, got {learned_offset}"
    );

    // Verify strict ±600_000 ms (±10 min) clamping on extreme server timestamps!
    let now = wall_now_ms();
    assert_eq!(
        client.record_server_clock_ms(now + 3_600_000),
        MAX_CLOCK_OFFSET_MS
    );
    assert_eq!(
        client.record_server_clock_ms(now.saturating_sub(3_600_000)),
        -MAX_CLOCK_OFFSET_MS
    );
}

// ===========================================================================
// Oracle 4: Real WS 101 + Coalesced HELLO_ACK & PARTY_SNAPSHOT + MP1:PING/PONG
//           + Fragmented Frame with Interleaved Ping + > 8,192 B Rejection
//           + Subprotocol / Extension Rejection
// ===========================================================================

#[tokio::test]
async fn oracle_ws_101_coalesced_frames_ping_pong_fragmented_interleaved_and_oversized_rejection() {
    let pki = generate_test_pki();
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acct_id = AccountId::new(1001).expect("acct");
    let dev_id = DeviceId::new(2002).expect("dev");
    let party_id = PartyId::new(777).expect("party");
    let dev_secret = [33u8; 32];
    let dev_pubkey = SigningKey::from_bytes(&dev_secret)
        .verifying_key()
        .to_bytes();
    let root_secret = [44u8; 32];
    let root_pubkey = SigningKey::from_bytes(&root_secret)
        .verifying_key()
        .to_bytes();
    let cwt = make_cwt(root_secret, dev_pubkey);
    let ep = make_relay_only_endpoint();

    let hello_msg = Mp1Message::HelloAck {
        session_id: SessionId::new(9999).expect("sid"),
        server_now_ms: wall_now_ms(),
        ping_interval_ms: 20_000,
    };
    let snap_msg = Mp1Message::PartySnapshot(PartySnapshot {
        party_id,
        party_epoch: 5,
        leader_account_id: acct_id,
        leader_device_id: dev_id,
        visibility: PartyVisibility::Friends,
        join_mode: PartyJoinMode::InviteOnly,
        relay_policy: RelayPolicy::ForceRelays,
        max_members: 4,
        pinned_relay_url: TEST_RELAY_URL.to_owned(),
        members: vec![PartyMemberRecord {
            device_id: dev_id,
            account_id: acct_id,
            root_pubkey,
            device_pubkey: dev_pubkey,
            device_cwt: cwt.clone(),
            endpoint: ep.clone(),
            joined_seq: 1,
            connected: true,
        }],
    });
    let left_msg = Mp1Message::PartyMemberLeft {
        party_epoch: 6,
        device_id: DeviceId::new(3003).expect("dev3"),
        account_id: AccountId::new(1002).expect("acct2"),
        reason: MemberLeaveReason::Kicked,
    };

    let hello_bytes = encode_frame(1, &hello_msg).expect("encode hello");
    let snap_bytes = encode_frame(2, &snap_msg).expect("encode snap");
    let left_bytes = encode_frame(3, &left_msg).expect("encode left");

    let srv_hello = hello_bytes.clone();
    let srv_snap = snap_bytes.clone();
    let srv_left = left_bytes.clone();

    let srv = tokio::spawn(async move {
        // Connection 1: Full valid WS lifecycle + coalesced frames + ping/pong + fragmented + interleaved ping + >8192B
        {
            let (tcp, _) = listener.accept().await.expect("accept ws 1");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls ws 1");
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );

            let req = read_http_request(&mut tls).await;
            assert_eq!(req.method, "GET");
            assert_eq!(req.path, "/v1/parties/777/ws");
            assert_eq!(req.headers.get("host").map(String::as_str), Some(TEST_AUTHORITY));
            assert_eq!(
                req.headers.get("sec-websocket-protocol").map(String::as_str),
                Some("mp1")
            );
            assert!(
                !req.headers.contains_key("sec-websocket-extensions"),
                "client must not request permessage-deflate"
            );

            // Verify real RFC 9421 signature on WS upgrade!
            verify_rfc9421_request(
                &Rfc9421Request {
                    method: HttpMethod::Get,
                    authority: req.headers.get("host").map(String::as_str).unwrap_or(""),
                    path: &req.path,
                    query: &req.query,
                    content_type: None,
                    content_digest: None,
                    has_content_encoding: false,
                    body: &[],
                    signature_input: req.headers.get("signature-input").expect("sig-in"),
                    signature: req.headers.get("signature").expect("sig"),
                },
                TEST_AUTHORITY,
                &dev_pubkey,
                wall_now_secs(),
            )
            .expect("WS upgrade RFC 9421 signature must verify");

            let ws_key = req
                .headers
                .get("sec-websocket-key")
                .expect("sec-websocket-key");
            let accept = ws_accept_value(ws_key);

            // Coalesce HTTP 101 + HELLO_ACK + PARTY_SNAPSHOT into ONE single TLS write!
            let mut coalesced = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: mp1\r\n\r\n"
            )
            .into_bytes();
            coalesced.extend_from_slice(&encode_server_ws_frame(true, 0x2, &srv_hello));
            coalesced.extend_from_slice(&encode_server_ws_frame(true, 0x2, &srv_snap));
            tls.write_all(&coalesced).await.expect("write coalesced 101");
            tls.flush().await.expect("flush 101");

            // Read client "MP1:PING" text frame, reply "MP1:PONG"
            let (op_ping, pay_ping) = read_masked_client_ws_frame(&mut tls).await;
            assert_eq!(op_ping, 0x1, "expected text frame for MP1:PING");
            assert_eq!(pay_ping, MP1_PING_TEXT.as_bytes());
            tls.write_all(&encode_server_ws_frame(true, 0x1, MP1_PONG_TEXT.as_bytes()))
                .await
                .expect("write MP1:PONG");
            tls.flush().await.expect("flush pong");

            // Read client binary PARTY_ENDPOINT_UPDATE frame
            let (op_ep, pay_ep) = read_masked_client_ws_frame(&mut tls).await;
            assert_eq!(op_ep, 0x2, "expected binary frame for PARTY_ENDPOINT_UPDATE");
            let (_hdr, decoded_ep) =
                mp_protocol::decode_frame(&pay_ep).expect("decode client endpoint update");
            assert!(matches!(decoded_ep, Mp1Message::PartyEndpointUpdate { .. }));

            // Send fragmented binary message (PartyMemberLeft) with interleaved RFC 6455 Ping!
            let split = srv_left.len() / 2;
            let mut frag_seq = Vec::new();
            frag_seq.extend_from_slice(&encode_server_ws_frame(false, 0x2, &srv_left[..split]));
            frag_seq.extend_from_slice(&encode_server_ws_frame(true, 0x9, b"ping-check"));
            frag_seq.extend_from_slice(&encode_server_ws_frame(true, 0x0, &srv_left[split..]));
            tls.write_all(&frag_seq).await.expect("write fragmented");
            tls.flush().await.expect("flush fragmented");

            // Verify client answered the interleaved RFC 6455 Ping with a masked Pong!
            let (op_pong, pay_pong) = read_masked_client_ws_frame(&mut tls).await;
            assert_eq!(op_pong, 0xA, "expected RFC 6455 Pong reply to interleaved Ping");
            assert_eq!(pay_pong, b"ping-check");

            // Send fragmented binary message totaling 8,193 B (> 8,192 B cap!)
            let frag1 = vec![0xAAu8; 4096];
            let frag2 = vec![0xBBu8; 4097];
            let mut too_big = Vec::new();
            too_big.extend_from_slice(&encode_server_ws_frame(false, 0x2, &frag1));
            too_big.extend_from_slice(&encode_server_ws_frame(true, 0x0, &frag2));
            let _ = tls.write_all(&too_big).await;
            let _ = tls.flush().await;
        }

        // Connection 2: 101 missing Sec-WebSocket-Protocol: mp1 -> must reject!
        {
            let (tcp, _) = listener.accept().await.expect("accept ws 2");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls ws 2");
            let req = read_http_request(&mut tls).await;
            let accept = ws_accept_value(req.headers.get("sec-websocket-key").expect("key"));
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.flush().await;
        }

        // Connection 3: 101 with forbidden permessage-deflate -> must reject!
        {
            let (tcp, _) = listener.accept().await.expect("accept ws 3");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls ws 3");
            let req = read_http_request(&mut tls).await;
            let accept = ws_accept_value(req.headers.get("sec-websocket-key").expect("key"));
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: mp1\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
            );
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.flush().await;
        }
    });

    let signer = RequestSigner::device(acct_id, dev_id, dev_secret);
    let client = ControlClient::with_device_signer(make_client_config(&pki, addr), signer);

    let mut ws = client
        .connect_ws(Mp1WsTarget::Party(party_id))
        .await
        .expect("WS 101 connect must succeed");

    // 1. Coalesced HELLO_ACK
    let ev1 = ws.next_event().await.expect("ev1").expect("some ev1");
    assert_eq!(
        ev1,
        Mp1WsEvent::Frame {
            header: mp_protocol::FrameHeader {
                opcode: mp_protocol::Opcode::HelloAck,
                seq: 1,
                payload_len: (hello_bytes.len() - mp_protocol::MP1_HEADER_BYTES) as u32,
            },
            message: hello_msg,
        }
    );

    // 2. Coalesced PARTY_SNAPSHOT
    let ev2 = ws.next_event().await.expect("ev2").expect("some ev2");
    assert!(matches!(
        ev2,
        Mp1WsEvent::Frame {
            message: Mp1Message::PartySnapshot(ref s),
            ..
        } if s.party_id == party_id && s.party_epoch == 5 && s.members.len() == 1
    ));

    // 3. MP1:PING -> MP1:PONG updates sleep-aware last_pong_ms
    let before_pong = ws.last_pong_ms();
    ws.send_ping().await.expect("send MP1:PING");
    let ev3 = ws.next_event().await.expect("ev3").expect("some ev3");
    assert_eq!(ev3, Mp1WsEvent::Pong);
    assert!(ws.last_pong_ms() >= before_pong);

    // 4. Send binary PARTY_ENDPOINT_UPDATE
    let seq = ws
        .send_party_endpoint_update(ep)
        .await
        .expect("send endpoint update");
    assert_eq!(seq, 1);

    // 5. Fragmented binary MP1 message with interleaved RFC 6455 Ping
    let ev4 = ws.next_event().await.expect("ev4").expect("some ev4");
    assert!(matches!(
        ev4,
        Mp1WsEvent::Frame {
            message: Mp1Message::PartyMemberLeft {
                party_epoch: 6,
                reason: MemberLeaveReason::Kicked,
                ..
            },
            ..
        }
    ));

    // 6. > 8,192 B reassembled binary WS message MUST be rejected!
    let err_big = ws
        .next_event()
        .await
        .expect_err("8,193 B reassembled WS frame must fail");
    assert!(
        matches!(
            err_big,
            WsError::FrameTooLarge {
                max_len,
                ..
            } if max_len == MAX_MP1_FRAME_BYTES
        ),
        "expected FrameTooLarge(max_len=8192), got {err_big:?}"
    );
    drop(ws);

    // 7. Missing Sec-WebSocket-Protocol: mp1 rejected
    let err_proto = client
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect_err("missing mp1 subprotocol must fail");
    assert!(
        matches!(err_proto, WsConnectError::MissingMp1Subprotocol),
        "expected MissingMp1Subprotocol, got {err_proto:?}"
    );

    // 8. Forbidden permessage-deflate rejected
    let err_ext = client
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect_err("permessage-deflate must fail");
    assert!(
        matches!(err_ext, WsConnectError::ForbiddenExtension),
        "expected ForbiddenExtension, got {err_ext:?}"
    );

    srv.await.expect("server task");
}

// ===========================================================================
// Oracle 5: Terminal 404/403 WS Upgrade + EvictionChurnDetector +
//           EndpointUpdateCoalescer
// ===========================================================================

#[tokio::test]
async fn oracle_ws_terminal_404_403_churn_detector_and_endpoint_coalescer() {
    let pki = generate_test_pki();
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let srv = tokio::spawn(async move {
        for (status_line, body) in [
            ("HTTP/1.1 404 Not Found", r#"{"error":"not_found"}"#),
            ("HTTP/1.1 403 Forbidden", r#"{"error":"device_revoked"}"#),
        ] {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls");
            let _req = read_http_request(&mut tls).await;
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });

    let signer = RequestSigner::device(
        AccountId::new(100).expect("acct"),
        DeviceId::new(200).expect("dev"),
        [55u8; 32],
    );
    let client = ControlClient::with_device_signer(make_client_config(&pki, addr), signer);
    let party_id = PartyId::new(42).expect("party");

    let err_404 = client
        .connect_ws(Mp1WsTarget::Party(party_id))
        .await
        .expect_err("404 must fail");
    assert!(
        matches!(err_404, WsConnectError::Terminal(404)),
        "expected Terminal(404), got {err_404:?}"
    );

    let err_403 = client
        .connect_ws(Mp1WsTarget::Party(party_id))
        .await
        .expect_err("403 must fail");
    assert!(
        matches!(err_403, WsConnectError::Terminal(403)),
        "expected Terminal(403), got {err_403:?}"
    );

    srv.await.expect("server task");

    // --- EvictionChurnDetector oracle ---
    let mut churn = EvictionChurnDetector::new();
    let s1 = SessionId::new(1).expect("s1");
    let s2 = SessionId::new(2).expect("s2");
    let s3 = SessionId::new(3).expect("s3");
    let s4 = SessionId::new(4).expect("s4");
    let s5 = SessionId::new(5).expect("s5");

    // Initial clean connect
    assert_eq!(churn.record_hello_ack_at(s1, false, 10_000), ChurnStatus::Ok);
    // Same session_id reconnect does NOT count as a changing-session replacement
    assert_eq!(churn.record_hello_ack_at(s1, true, 15_000), ChurnStatus::Ok);
    assert_eq!(churn.replacements_in_window(), 0);
    // 1st unexpected changing session
    assert_eq!(churn.record_hello_ack_at(s2, true, 20_000), ChurnStatus::Ok);
    // 2nd unexpected changing session
    assert_eq!(churn.record_hello_ack_at(s3, true, 40_000), ChurnStatus::Ok);
    // 3rd unexpected changing session within 60_000 ms -> DualHostChurnDetected!
    assert_eq!(
        churn.record_hello_ack_at(s4, true, 75_000),
        ChurnStatus::DualHostChurnDetected {
            replacements_in_window: 3
        }
    );
    // After window advances past oldest entries (t = 140_000 => cutoff 80_000), count drops back!
    assert_eq!(churn.record_hello_ack_at(s5, true, 140_000), ChurnStatus::Ok);
    assert_eq!(churn.replacements_in_window(), 1);

    // --- EndpointUpdateCoalescer oracle ---
    let ep1 = make_direct_endpoint(40001);
    let ep2 = make_direct_endpoint(40002);
    let ep3 = make_direct_endpoint(40003);
    let ep4 = make_direct_endpoint(40004);

    let mut coalescer = EndpointUpdateCoalescer::new(RelayPolicy::AllowRelays);
    // First submit emits immediately
    assert_eq!(coalescer.submit_at(ep1.clone(), 1_000), Some(ep1));
    // Rapid roaming within 30s throttled & coalesced to latest (ep3)
    assert_eq!(coalescer.submit_at(ep2, 5_000), None);
    assert_eq!(coalescer.submit_at(ep3.clone(), 12_000), None);
    assert_eq!(coalescer.poll_ready_at(30_999), None);
    assert_eq!(coalescer.poll_ready_at(31_000), Some(ep3));
    assert!(!coalescer.has_pending());

    // Server ERROR.retry_after_ms overrides the 30s interval when longer
    coalescer.record_retry_after_at(45_000, 35_000); // blocked until 80_000
    assert_eq!(coalescer.submit_at(ep4.clone(), 62_000), None);
    assert_eq!(coalescer.poll_ready_at(79_999), None);
    assert_eq!(coalescer.poll_ready_at(80_000), Some(ep4));

    // ForceRelays MUST suppress ALL updates unconditionally!
    let mut forced = EndpointUpdateCoalescer::new(RelayPolicy::ForceRelays);
    assert_eq!(forced.submit_at(make_relay_only_endpoint(), 1_000), None);
    assert_eq!(forced.submit_at(make_direct_endpoint(41000), 100_000), None);
    assert_eq!(forced.poll_ready_at(200_000), None);
    assert!(!forced.has_pending());
}

// ===========================================================================
// Oracle 6: Typed REST Endpoint Surface Coverage (All `/v1/*` Routes)
// ===========================================================================

#[tokio::test]
async fn oracle_typed_rest_endpoints_match_exact_server_contract() {
    let pki = generate_test_pki();
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acct_id = AccountId::new(1001).expect("acct");
    let bob_id = AccountId::new(1002).expect("bob");
    let dev_id = DeviceId::new(2002).expect("dev");
    let dev2_id = DeviceId::new(2003).expect("dev2");
    let party_id = PartyId::new(5005).expect("party");
    let inv_id = PartyInviteId::new(6006).expect("inv");
    let req_id = RequestId::new(7007).expect("req");

    let root_secret = [61u8; 32];
    let root_pubkey = SigningKey::from_bytes(&root_secret)
        .verifying_key()
        .to_bytes();
    let dev_secret = [62u8; 32];
    let dev_pubkey = SigningKey::from_bytes(&dev_secret)
        .verifying_key()
        .to_bytes();
    let dev2_pubkey = SigningKey::from_bytes(&[63u8; 32])
        .verifying_key()
        .to_bytes();
    let cwt = make_cwt(root_secret, dev2_pubkey);

    let root_signer = RequestSigner::root(acct_id, root_secret);
    let dev_signer = RequestSigner::device(acct_id, dev_id, dev_secret);

    let srv = tokio::spawn(async move {
        let total_calls = 24usize;
        for _ in 0..total_calls {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls");
            let req = read_http_request(&mut tls).await;
            let method = HttpMethod::parse(&req.method).expect("method");
            let sig_input = req.headers.get("signature-input").expect("sig-in");
            let sig = req.headers.get("signature").expect("sig");
            let parsed_si = mp_protocol::parse_signature_input(sig_input).expect("parse si");
            let verify_pk = match parsed_si.keyid {
                mp_protocol::KeyId::Root { .. } => &root_pubkey,
                mp_protocol::KeyId::Device { .. } => &dev_pubkey,
                mp_protocol::KeyId::Registration { .. }
                | mp_protocol::KeyId::Recovery { .. }
                | mp_protocol::KeyId::DeviceLink { .. } => panic!("unexpected special keyid"),
            };

            verify_rfc9421_request(
                &Rfc9421Request {
                    method,
                    authority: req.headers.get("host").map(String::as_str).unwrap_or(""),
                    path: &req.path,
                    query: &req.query,
                    content_type: req.headers.get("content-type").map(String::as_str),
                    content_digest: req.headers.get("content-digest").map(String::as_str),
                    has_content_encoding: req.headers.contains_key("content-encoding"),
                    body: &req.body,
                    signature_input: sig_input,
                    signature: sig,
                },
                TEST_AUTHORITY,
                verify_pk,
                wall_now_secs(),
            )
            .expect("RFC 9421 verification must pass for every REST route");

            let (status, json) = match (req.method.as_str(), req.path.as_str(), req.query.as_str()) {
                ("GET", "/v1/accounts/me", "?") => (
                    "200 OK",
                    format!(
                        r#"{{"account_id":1001,"handle":"alice","root_pubkey_b64":"{}","devices":[{{"device_id":2002,"pubkey_b64":"{}","label":"laptop","cwt_expires_ms":1900000000000,"generation":1,"pop_verified":true,"created_at_ms":1700000000000,"revoked_at_ms":null}}],"active_party_ids":[5005]}}"#,
                        B64_STD.encode(root_pubkey),
                        B64_STD.encode(dev_pubkey)
                    ),
                ),
                ("GET", "/v1/accounts/1002", "?") => (
                    "200 OK",
                    format!(
                        r#"{{"account_id":1002,"handle":"bob","root_pubkey_b64":"{}","devices":[{{"device_id":2003,"pubkey_b64":"{}","cwt_b64":"{}"}}]}}"#,
                        B64_STD.encode(root_pubkey),
                        B64_STD.encode(dev2_pubkey),
                        B64_STD.encode(&cwt)
                    ),
                ),
                ("GET", "/v1/accounts/resolve", "?handle=bob") => (
                    "200 OK",
                    format!(
                        r#"{{"account_id":1002,"handle":"bob","root_pubkey_b64":"{}"}}"#,
                        B64_STD.encode(root_pubkey)
                    ),
                ),
                ("PATCH", "/v1/accounts/me/handle", "?") => {
                    assert!(matches!(parsed_si.keyid, mp_protocol::KeyId::Root { .. }));
                    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
                    assert_eq!(v["handle"], "alice_prime");
                    (
                        "200 OK",
                        r#"{"account_id":1001,"handle":"alice_prime"}"#.to_owned(),
                    )
                }
                ("POST", "/v1/devices", "?") => {
                    assert!(matches!(parsed_si.keyid, mp_protocol::KeyId::Root { .. }));
                    (
                        "201 Created",
                        r#"{"device_id":2003,"cwt_expires_ms":1900000000000}"#.to_owned(),
                    )
                }
                ("PUT", "/v1/devices/2003/cwt", "?") => {
                    assert!(matches!(parsed_si.keyid, mp_protocol::KeyId::Root { .. }));
                    (
                        "200 OK",
                        r#"{"device_id":2003,"cwt_expires_ms":1950000000000}"#.to_owned(),
                    )
                }
                ("DELETE", "/v1/devices/2003", "?") => {
                    assert!(matches!(parsed_si.keyid, mp_protocol::KeyId::Root { .. }));
                    (
                        "200 OK",
                        r#"{"revoked":true,"evicted_parties":[5005],"pending_retries":0}"#
                            .to_owned(),
                    )
                }
                ("GET", "/v1/friends", "?") => (
                    "200 OK",
                    r#"{"friends":[{"peer_account_id":1002,"state":2,"updated_at_ms":1700000000001}]}"#
                        .to_owned(),
                ),
                ("POST", "/v1/friends/requests", "?") => (
                    "202 Accepted",
                    r#"{"target_account_id":1002,"state":1}"#.to_owned(),
                ),
                ("DELETE", "/v1/friends/1002", "?") => {
                    ("200 OK", r#"{"removed":true}"#.to_owned())
                }
                ("POST", "/v1/friends/1002/block", "?") => (
                    "200 OK",
                    r#"{"target_account_id":1002,"state":3}"#.to_owned(),
                ),
                ("POST", "/v1/parties", "?") => (
                    "201 Created",
                    format!(
                        r#"{{"party_id":5005,"party_epoch":1,"pinned_relay_url":"{TEST_RELAY_URL}"}}"#
                    ),
                ),
                ("GET", "/v1/parties/5005", "?") => (
                    "200 OK",
                    format!(
                        r#"{{"party_id":5005,"party_epoch":1,"leader_account_id":1001,"leader_device_id":2002,"visibility":1,"join_mode":0,"relay_policy":1,"pinned_relay_url":"{TEST_RELAY_URL}","max_members":4,"member_count":1}}"#
                    ),
                ),
                ("POST", "/v1/parties/5005/join", "?") => {
                    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
                    if v.get("invite_link").is_some() {
                        (
                            "202 Accepted",
                            r#"{"status":"pending_approval","request_id":7007}"#.to_owned(),
                        )
                    } else {
                        ("200 OK", r#"{"status":"joined","party_epoch":2}"#.to_owned())
                    }
                }
                ("POST", "/v1/parties/5005/leave", "?") => {
                    ("200 OK", r#"{"left":true,"party_epoch":3}"#.to_owned())
                }
                ("POST", "/v1/parties/5005/disband", "?") => {
                    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
                    assert_eq!(v["expected_party_epoch"], 3);
                    ("200 OK", r#"{"disbanded":true,"party_epoch":4}"#.to_owned())
                }
                ("POST", "/v1/parties/5005/kick", "?") => {
                    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
                    assert_eq!(v["target_account_id"], 1002);
                    assert_eq!(v["expected_party_epoch"], 4);
                    ("200 OK", r#"{"kicked":true,"party_epoch":5}"#.to_owned())
                }
                ("POST", "/v1/parties/5005/promote", "?") => {
                    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
                    assert_eq!(v["target_device_id"], 2003);
                    assert_eq!(v["expected_party_epoch"], 5);
                    ("200 OK", r#"{"promoted":true,"party_epoch":6}"#.to_owned())
                }
                ("POST", "/v1/parties/5005/invites", "?") => (
                    "201 Created",
                    r#"{"party_invite_id":6006,"expires_at_ms":1900000000000,"invite_link":"mppi1_5005_abc"}"#
                        .to_owned(),
                ),
                ("DELETE", "/v1/parties/5005/invites/6006", "?") => {
                    ("200 OK", r#"{"revoked":true}"#.to_owned())
                }
                ("GET", "/v1/parties/5005/requests", "?cursor=10") => (
                    "200 OK",
                    format!(
                        r#"{{"requests":[{{"request_id":7007,"account_id":1002,"device_id":2003,"root_pubkey_b64":"{}","device_pubkey_b64":"{}","requested_at_ms":1700000000100,"reserved_until_ms":null}}]}}"#,
                        B64_STD.encode(root_pubkey),
                        B64_STD.encode(dev2_pubkey)
                    ),
                ),
                ("POST", "/v1/parties/5005/requests/7007/approve", "?") => {
                    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
                    assert_eq!(v["expected_party_epoch"], 6);
                    assert_eq!(v["account_id"], 1002);
                    assert_eq!(v["device_id"], 2003);
                    let expected_hex: String = sha256(&dev2_pubkey)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    assert_eq!(v["device_pubkey_sha256_hex"], expected_hex);
                    (
                        "200 OK",
                        r#"{"approved":true,"reserved_until_ms":1700000060100}"#.to_owned(),
                    )
                }
                ("POST", "/v1/parties/5005/requests/7007/reject", "?") => {
                    let v: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
                    assert_eq!(v["expected_party_epoch"], 6);
                    ("200 OK", r#"{"rejected":true}"#.to_owned())
                }
                other => panic!("unexpected request: {other:?}"),
            };

            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json.len(),
                json
            );
            tls.write_all(resp.as_bytes()).await.expect("write");
            tls.shutdown().await.expect("shutdown");
        }
    });

    let client = ControlClient::with_device_signer(make_client_config(&pki, addr), dev_signer);
    let ep = make_relay_only_endpoint();
    let cwt_for_calls = make_cwt(root_secret, dev2_pubkey);

    let me = client.get_me().await.expect("get_me");
    assert_eq!(me.account_id, 1001);
    assert_eq!(me.devices.len(), 1);
    assert!(me.devices[0].pop_verified);

    let acct = client.get_account(bob_id).await.expect("get_account");
    assert_eq!(acct.handle, "bob");
    assert_eq!(acct.devices.as_ref().map(Vec::len), Some(1));

    let resolved = client.resolve_handle("bob").await.expect("resolve_handle");
    assert_eq!(resolved.account_id, 1002);

    let renamed = client
        .rename_handle(&root_signer, "alice_prime")
        .await
        .expect("rename_handle");
    assert_eq!(renamed.handle, "alice_prime");

    let enrolled = client
        .enroll_device(
            &root_signer,
            &EnrollDeviceRequest {
                device_pubkey: dev2_pubkey,
                device_label: "wintermute".to_owned(),
                device_cwt: cwt_for_calls.clone(),
            },
        )
        .await
        .expect("enroll_device");
    assert_eq!(enrolled.device_id, 2003);

    let renewed = client
        .renew_device_cwt(&root_signer, dev2_id, &cwt_for_calls)
        .await
        .expect("renew_device_cwt");
    assert_eq!(renewed.cwt_expires_ms, 1_950_000_000_000);

    let revoked = client
        .revoke_device(&root_signer, dev2_id)
        .await
        .expect("revoke_device");
    assert!(revoked.revoked);
    assert_eq!(revoked.evicted_parties, vec![5005]);

    let friends = client.list_friends().await.expect("list_friends");
    assert_eq!(friends.friends.len(), 1);

    let fr = client
        .send_friend_request(bob_id)
        .await
        .expect("send_friend_request");
    assert_eq!(fr.state, 1);

    assert!(client.remove_friend(bob_id).await.expect("remove_friend").removed);
    assert_eq!(
        client.block_account(bob_id).await.expect("block_account").state,
        3
    );

    let created = client
        .create_party(&CreatePartyRequest {
            visibility: PartyVisibility::Friends,
            join_mode: PartyJoinMode::InviteOnly,
            relay_policy: RelayPolicy::ForceRelays,
            max_members: 4,
            endpoint: ep.clone(),
            relay_url: Some(TEST_RELAY_URL.to_owned()),
        })
        .await
        .expect("create_party");
    assert_eq!(created.party_id, 5005);

    let summary = client.get_party(party_id).await.expect("get_party");
    assert_eq!(summary.party_epoch, 1);
    assert_eq!(summary.member_count, 1);

    let j1 = client
        .join_party(
            party_id,
            &JoinPartyRequest {
                endpoint: ep.clone(),
                invite_link: None,
            },
        )
        .await
        .expect("join_party joined");
    assert_eq!(j1, JoinPartyResponse::Joined { party_epoch: 2 });

    let j2 = client
        .join_party(
            party_id,
            &JoinPartyRequest {
                endpoint: ep,
                invite_link: Some("mppi1_5005_secret".to_owned()),
            },
        )
        .await
        .expect("join_party pending");
    assert_eq!(j2, JoinPartyResponse::PendingApproval { request_id: 7007 });

    assert_eq!(client.leave_party(party_id).await.expect("leave").party_epoch, 3);
    assert_eq!(
        client
            .disband_party(party_id, 3)
            .await
            .expect("disband")
            .party_epoch,
        4
    );
    assert_eq!(
        client
            .kick_member(party_id, bob_id, 4)
            .await
            .expect("kick")
            .party_epoch,
        5
    );
    assert_eq!(
        client
            .promote_member(party_id, dev2_id, 5)
            .await
            .expect("promote")
            .party_epoch,
        6
    );

    let minted = client
        .mint_party_invite(
            party_id,
            &MintPartyInviteRequest {
                target_account_id: None,
                max_uses: Some(2),
                ttl_sec: Some(3600),
            },
        )
        .await
        .expect("mint_party_invite");
    assert_eq!(minted.party_invite_id, 6006);

    assert!(
        client
            .revoke_party_invite(party_id, inv_id)
            .await
            .expect("revoke_party_invite")
            .revoked
    );

    let reqs = client
        .list_party_requests(party_id, Some(10))
        .await
        .expect("list_party_requests");
    assert_eq!(reqs.requests.len(), 1);
    assert_eq!(reqs.requests[0].request_id, 7007);

    let approved = client
        .approve_party_request(
            party_id,
            req_id,
            &ApprovePartyRequest::for_device_pubkey(6, bob_id, dev2_id, &dev2_pubkey),
        )
        .await
        .expect("approve_party_request");
    assert!(approved.approved);

    let rejected = client
        .reject_party_request(party_id, req_id, Some(6))
        .await
        .expect("reject_party_request");
    assert!(rejected.rejected);

    srv.await.expect("server task");
}

// ===========================================================================
// Oracle 7: Gate #1 Hardening Regressions (Authority Canonicalization, Strict
//           ALPN, Bounded WS Upgrade Headers, Safe Sec-WebSocket-Accept,
//           WS 401 clock_skew Auto-Retry)
// ===========================================================================

fn make_server_acceptor_with_alpn(
    pki: &TestPki,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn_protocols: Vec<Vec<u8>>,
) -> TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![pki.cert_der.clone()], pki.key_der.clone_key())
        .expect("server cert");
    cfg.alpn_protocols = alpn_protocols;
    TlsAcceptor::from(Arc::new(cfg))
}

#[tokio::test]
async fn oracle_authority_canonicalization_and_strict_alpn_enforcement() {
    // 1. Canonicalization unit checks
    let cfg_default_port =
        ControlClientConfig::new("API.MULTIPLAYER.TECH:443").expect("canonical default port");
    assert_eq!(cfg_default_port.authority, "api.multiplayer.tech");

    let cfg_custom_port =
        ControlClientConfig::new("API.MULTIPLAYER.TECH:8443").expect("canonical custom port");
    assert_eq!(cfg_custom_port.authority, "api.multiplayer.tech:8443");

    assert!(matches!(
        ControlClientConfig::new("api.multiplayer.tech:0443"),
        Err(ControlError::InvalidAuthority(_))
    ));
    assert!(matches!(
        ControlClientConfig::new("api.multiplayer.tech:0"),
        Err(ControlError::InvalidAuthority(_))
    ));

    let pki = generate_test_pki();

    // 2. Server with NO ALPN negotiated must be rejected on both REST and WS!
    let no_alpn_acceptor =
        make_server_acceptor_with_alpn(&pki, &[&rustls::version::TLS13], vec![]);
    let listener_no_alpn = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr_no_alpn = listener_no_alpn.local_addr().expect("local_addr");

    let srv_no_alpn = tokio::spawn(async move {
        for _ in 0..2 {
            if let Ok((tcp, _)) = listener_no_alpn.accept().await {
                let _ = no_alpn_acceptor.accept(tcp).await;
            }
        }
    });

    let signer = RequestSigner::device(
        AccountId::new(1001).expect("acct"),
        DeviceId::new(2002).expect("dev"),
        [71u8; 32],
    );
    let client_no_alpn = ControlClient::with_device_signer(
        ControlClientConfig::new("API.MULTIPLAYER.TECH:443")
            .expect("canonical")
            .with_tls_config(Arc::clone(&pki.client_tls13))
            .with_connect_addr(addr_no_alpn)
            .with_request_timeout(Duration::from_secs(5)),
        signer.clone(),
    );

    let rest_err = client_no_alpn
        .health()
        .await
        .expect_err("missing ALPN must fail REST");
    assert!(
        matches!(rest_err, ControlError::TlsPolicyViolation(_)),
        "expected TlsPolicyViolation on missing ALPN, got {rest_err:?}"
    );

    let ws_err = client_no_alpn
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect_err("missing ALPN must fail WS");
    assert!(
        matches!(
            ws_err,
            WsConnectError::Transport(ControlError::TlsPolicyViolation(_))
        ),
        "expected TlsPolicyViolation on missing ALPN WS, got {ws_err:?}"
    );
    srv_no_alpn.await.expect("srv_no_alpn");

    // 3. Uppercase + `:443` authority works end-to-end with lowercase Host & RFC 9421 @authority
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener_ok = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr_ok = listener_ok.local_addr().expect("local_addr");
    let dev_pubkey = signer.verifying_pubkey();

    let srv_ok = tokio::spawn(async move {
        let (tcp, _) = listener_ok.accept().await.expect("accept");
        let mut tls = tls13_acceptor.accept(tcp).await.expect("tls");
        let req = read_http_request(&mut tls).await;
        assert_eq!(
            req.headers.get("host").map(String::as_str),
            Some("api.multiplayer.tech")
        );
        verify_rfc9421_request(
            &Rfc9421Request {
                method: HttpMethod::Get,
                authority: req.headers.get("host").map(String::as_str).unwrap_or(""),
                path: &req.path,
                query: &req.query,
                content_type: None,
                content_digest: None,
                has_content_encoding: false,
                body: &[],
                signature_input: req.headers.get("signature-input").expect("sig-in"),
                signature: req.headers.get("signature").expect("sig"),
            },
            "api.multiplayer.tech",
            &dev_pubkey,
            wall_now_secs(),
        )
        .expect("canonical authority RFC 9421 verification must pass");
        let body = r#"{"friends":[]}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        tls.write_all(resp.as_bytes()).await.expect("write");
        tls.shutdown().await.expect("shutdown");
    });

    let client_ok = ControlClient::with_device_signer(
        ControlClientConfig::new("API.MULTIPLAYER.TECH:443")
            .expect("canonical")
            .with_tls_config(Arc::clone(&pki.client_tls13))
            .with_connect_addr(addr_ok)
            .with_request_timeout(Duration::from_secs(5)),
        signer,
    );
    let friends = client_ok
        .list_friends()
        .await
        .expect("canonicalized authority call must succeed");
    assert!(friends.friends.is_empty());
    srv_ok.await.expect("srv_ok");
}

#[tokio::test]
async fn oracle_ws_upgrade_bounded_headers_hostile_accept_and_401_clock_skew_retry() {
    let pki = generate_test_pki();
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acct_id = AccountId::new(1001).expect("acct");
    let dev_id = DeviceId::new(2002).expect("dev");
    let dev_secret = [72u8; 32];
    let dev_pubkey = SigningKey::from_bytes(&dev_secret)
        .verifying_key()
        .to_bytes();

    let hello_msg = Mp1Message::HelloAck {
        session_id: SessionId::new(4242).expect("sid"),
        server_now_ms: wall_now_ms() + 180_000,
        ping_interval_ms: 20_000,
    };
    let hello_bytes = encode_frame(1, &hello_msg).expect("encode hello");
    let skew_ms: i64 = 180_000;
    let nonces = Arc::new(Mutex::new(Vec::<String>::new()));
    let nonces_srv = Arc::clone(&nonces);

    let srv = tokio::spawn(async move {
        // Connection 1: Oversized > 8 KiB WS upgrade headers (16 KiB without \r\n\r\n)
        {
            let (tcp, _) = listener.accept().await.expect("accept 1");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls 1");
            let _req = read_http_request(&mut tls).await;
            let mut big = b"HTTP/1.1 101 Switching Protocols\r\nX-Pad: ".to_vec();
            big.extend(std::iter::repeat_n(b'A', 16 * 1024));
            big.extend_from_slice(b"\r\n\r\n");
            let _ = tls.write_all(&big).await;
            let _ = tls.shutdown().await;
        }

        // Connection 2: Hostile oversized non-base64 Sec-WebSocket-Accept (must NOT panic!)
        {
            let (tcp, _) = listener.accept().await.expect("accept 2");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls 2");
            let _req = read_http_request(&mut tls).await;
            let hostile_accept = "!".repeat(256);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {hostile_accept}\r\nSec-WebSocket-Protocol: mp1\r\n\r\n"
            );
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.shutdown().await;
        }

        // Connection 3: Wrong valid-base64 Sec-WebSocket-Accept (must reject cleanly)
        {
            let (tcp, _) = listener.accept().await.expect("accept 3");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls 3");
            let _req = read_http_request(&mut tls).await;
            let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: mp1\r\n\r\n";
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.shutdown().await;
        }

        // Connections 4 & 5: WS 401 clock_skew on attempt 0 -> auto-retry succeeds on attempt 1!
        for attempt in 0..2u8 {
            let (tcp, _) = listener.accept().await.expect("accept skew");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls skew");
            let req = read_http_request(&mut tls).await;
            assert_eq!(req.method, "GET");
            assert_eq!(req.path, "/v1/ws");

            let sig_input = req.headers.get("signature-input").expect("sig-in");
            let sig = req.headers.get("signature").expect("sig");
            let parsed_si =
                mp_protocol::parse_signature_input(sig_input).expect("parse signature-input");
            nonces_srv.lock().expect("lock").push(parsed_si.nonce);

            let server_now_ms = (wall_now_ms() as i64 + skew_ms) as u64;
            let server_now_s = (server_now_ms / 1000) as i64;
            let verify_res = verify_rfc9421_request(
                &Rfc9421Request {
                    method: HttpMethod::Get,
                    authority: req.headers.get("host").map(String::as_str).unwrap_or(""),
                    path: &req.path,
                    query: &req.query,
                    content_type: None,
                    content_digest: None,
                    has_content_encoding: false,
                    body: &[],
                    signature_input: sig_input,
                    signature: sig,
                },
                TEST_AUTHORITY,
                &dev_pubkey,
                server_now_s,
            );

            if attempt == 0 {
                assert_eq!(
                    verify_res.expect_err("attempt 0 must hit ClockSkew"),
                    Rfc9421Error::ClockSkew
                );
                let body = format!(r#"{{"error":"clock_skew","server_now_ms":{server_now_ms}}}"#);
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                tls.write_all(resp.as_bytes()).await.expect("write 401");
                tls.shutdown().await.expect("shutdown 401");
            } else {
                verify_res.expect("attempt 1 must pass RFC 9421 verification after clock sync");
                let accept = ws_accept_value(req.headers.get("sec-websocket-key").expect("key"));
                let mut coalesced = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: mp1\r\n\r\n"
                )
                .into_bytes();
                coalesced.extend_from_slice(&encode_server_ws_frame(true, 0x2, &hello_bytes));
                tls.write_all(&coalesced).await.expect("write 101");
                tls.flush().await.expect("flush 101");
            }
        }
    });

    let signer = RequestSigner::device(acct_id, dev_id, dev_secret);
    let client = ControlClient::with_device_signer(make_client_config(&pki, addr), signer);

    // 1. Oversized > 8 KiB upgrade headers rejected without buffering
    let err_hdrs = client
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect_err("oversized headers must fail");
    assert!(
        matches!(err_hdrs, WsConnectError::ResponseHeadersTooLarge),
        "expected ResponseHeadersTooLarge, got {err_hdrs:?}"
    );

    // 2. Hostile oversized non-base64 Sec-WebSocket-Accept rejected cleanly (no panic!)
    let err_hostile = client
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect_err("hostile Sec-WebSocket-Accept must fail");
    assert!(
        matches!(err_hostile, WsConnectError::InvalidUpgradeResponse(_)),
        "expected InvalidUpgradeResponse, got {err_hostile:?}"
    );

    // 3. Mismatched valid-base64 Sec-WebSocket-Accept rejected cleanly
    let err_mismatch = client
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect_err("mismatched Sec-WebSocket-Accept must fail");
    assert!(
        matches!(err_mismatch, WsConnectError::InvalidUpgradeResponse(_)),
        "expected InvalidUpgradeResponse, got {err_mismatch:?}"
    );

    // 4. WS 401 clock_skew auto-retry updates offset, refreshes nonce, and connects!
    let mut ws = client
        .connect_ws(Mp1WsTarget::Account)
        .await
        .expect("WS connect must succeed after 401 clock_skew auto-retry");

    let ev = ws.next_event().await.expect("ev").expect("hello frame");
    assert!(matches!(
        ev,
        Mp1WsEvent::Frame {
            message: Mp1Message::HelloAck { .. },
            ..
        }
    ));

    let learned_offset = client.clock_offset_ms();
    assert!(
        (learned_offset - skew_ms).abs() < 5_000,
        "expected WS clock offset near {skew_ms}, got {learned_offset}"
    );

    srv.await.expect("server task");
    let recorded = nonces.lock().expect("lock");
    assert_eq!(recorded.len(), 2);
    assert_ne!(
        recorded[0], recorded[1],
        "WS clock_skew retry MUST generate a fresh RFC 9421 nonce"
    );
}

// ===========================================================================
// Oracle 8: Identity Portability, Web Portal, & TLS 1.3 Relay Ping Endpoints
// ===========================================================================

fn generate_test_pki_for(authority: &str) -> TestPki {
    let certified = rcgen::generate_simple_self_signed(vec![authority.to_owned()])
        .expect("rcgen cert generation");
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add test root cert");
    let client_tls13 =
        build_tls13_client_config_with_roots(roots).expect("build TLS 1.3 client config");

    TestPki {
        cert_der,
        key_der,
        client_tls13,
    }
}

#[tokio::test]
async fn oracle_identity_portability_and_web_portal_endpoints() {
    let pki = generate_test_pki();
    let tls13_acceptor = make_server_acceptor(&pki, &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acct_id = AccountId::new(1001).expect("acct");
    let dev_id = DeviceId::new(2002).expect("dev");

    let root_secret = [81u8; 32];
    let root_pubkey = SigningKey::from_bytes(&root_secret)
        .verifying_key()
        .to_bytes();
    let dev_secret = [82u8; 32];
    let dev_pubkey = SigningKey::from_bytes(&dev_secret)
        .verifying_key()
        .to_bytes();
    let new_dev_secret = [83u8; 32];
    let new_dev_pubkey = SigningKey::from_bytes(&new_dev_secret)
        .verifying_key()
        .to_bytes();
    let new_dev_cwt = make_cwt(root_secret, new_dev_pubkey);

    let root_signer = RequestSigner::root(acct_id, root_secret);
    let dev_signer = RequestSigner::device(acct_id, dev_id, dev_secret);
    let rec_signer = RequestSigner::recovery(root_secret);
    let link_signer = RequestSigner::device_link(new_dev_secret);

    assert!(
        rec_signer.key_id().format().starts_with("rec.")
            && rec_signer.key_id().format().len() == 36
    );
    assert!(
        link_signer.key_id().format().starts_with("link.")
            && link_signer.key_id().format().len() == 37
    );

    let expected_rec_keyid = rec_signer.key_id().format();
    let expected_link_keyid = link_signer.key_id().format();
    let expected_cwt_b64 = B64_STD.encode(&new_dev_cwt);
    let srv_cwt_b64 = expected_cwt_b64.clone();
    let poll_nonces = Arc::new(Mutex::new(Vec::<String>::new()));
    let poll_nonces_srv = Arc::clone(&poll_nonces);

    let srv = tokio::spawn(async move {
        // 13 live TLS 1.3 requests covering all 8 new endpoints + both branches of inspect/poll/web-sessions
        let mut create_calls = 0u8;
        let mut inspect_calls = 0u8;
        let mut poll_calls = 0u8;

        for _ in 0..13 {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = tls13_acceptor.accept(tcp).await.expect("tls");
            let req = read_http_request(&mut tls).await;
            let method = HttpMethod::parse(&req.method).expect("method");
            let sig_input = req.headers.get("signature-input").expect("sig-in");
            let sig = req.headers.get("signature").expect("sig");
            let parsed_si = mp_protocol::parse_signature_input(sig_input).expect("parse si");

            let verify_pk = match parsed_si.keyid {
                mp_protocol::KeyId::Root { .. } | mp_protocol::KeyId::Recovery { .. } => {
                    &root_pubkey
                }
                mp_protocol::KeyId::Device { .. } => &dev_pubkey,
                mp_protocol::KeyId::DeviceLink { .. } => &new_dev_pubkey,
                mp_protocol::KeyId::Registration { .. } => panic!("unexpected reg keyid"),
            };

            let verified = verify_rfc9421_request(
                &Rfc9421Request {
                    method,
                    authority: req.headers.get("host").map(String::as_str).unwrap_or(""),
                    path: &req.path,
                    query: &req.query,
                    content_type: req.headers.get("content-type").map(String::as_str),
                    content_digest: req.headers.get("content-digest").map(String::as_str),
                    has_content_encoding: req.headers.contains_key("content-encoding"),
                    body: &req.body,
                    signature_input: sig_input,
                    signature: sig,
                },
                TEST_AUTHORITY,
                verify_pk,
                wall_now_secs(),
            )
            .expect("RFC 9421 verification must pass for all identity portability endpoints");

            let body_val: serde_json::Value =
                serde_json::from_slice(&req.body).expect("valid json body");

            let (status, json) = match (req.method.as_str(), req.path.as_str(), req.query.as_str())
            {
                ("POST", "/v1/accounts/recover-lookup", "?") => {
                    assert_eq!(verified.keyid.format(), expected_rec_keyid);
                    let obj = body_val.as_object().expect("json object");
                    assert_eq!(obj.len(), 1);
                    assert_eq!(
                        obj.get("root_pubkey_b64").and_then(serde_json::Value::as_str),
                        Some(B64_STD.encode(root_pubkey).as_str())
                    );
                    (
                        "200 OK",
                        format!(
                            r#"{{"account_id":1001,"handle":"alice","root_pubkey_b64":"{}","safety_number":"SP44-BGDF-SWJH-YXTV-ZWXT-MNGX-P342-B0TV","devices":[{{"device_id":2002,"pubkey_b64":"{}","label":"laptop","cwt_expires_ms":1900000000000,"generation":1,"pop_verified":true,"created_at_ms":1700000000000,"revoked_at_ms":null}}]}}"#,
                            B64_STD.encode(root_pubkey),
                            B64_STD.encode(dev_pubkey)
                        ),
                    )
                }
                ("POST", "/v1/web-sessions/inspect", "?") => {
                    assert!(matches!(
                        verified.keyid,
                        mp_protocol::KeyId::Device { .. } | mp_protocol::KeyId::Root { .. }
                    ));
                    assert_eq!(body_val["user_code"], "W4K9-M2P7");
                    (
                        "200 OK",
                        r#"{"pending":true,"scope":"web_account_portal","browser_fingerprint":"a1b2c3d4","requester_country":"US","requester_client":"Chrome/130","created_at_ms":1795453800000,"expires_at_ms":1795454100000}"#
                            .to_owned(),
                    )
                }
                ("POST", "/v1/web-sessions/approve", "?") => {
                    assert_eq!(body_val["user_code"], "W4K9-M2P7");
                    let is_root = matches!(verified.keyid, mp_protocol::KeyId::Root { .. });
                    let dev_field = if is_root { "null" } else { "2002" };
                    (
                        "200 OK",
                        format!(
                            r#"{{"approved":true,"scope":"web_account_portal","account_id":1001,"approved_device_id":{dev_field},"approved_by_root":{is_root},"browser_fingerprint":"a1b2c3d4","requester_country":"US","requester_client":"Chrome/130"}}"#
                        ),
                    )
                }
                ("POST", "/v1/device-links/create", "?") => {
                    assert!(matches!(verified.keyid, mp_protocol::KeyId::Root { .. }));
                    let obj = body_val.as_object().expect("json object");
                    create_calls += 1;
                    if create_calls == 1 {
                        assert!(
                            obj.is_empty(),
                            "None device_label must serialize to {{}}, got {obj:?}"
                        );
                    } else {
                        assert_eq!(obj.len(), 1);
                        assert_eq!(
                            obj.get("device_label").and_then(serde_json::Value::as_str),
                            Some("wintermute")
                        );
                    }
                    (
                        "201 Created",
                        r#"{"link_code":"W4K9-M2P7","expires_at_ms":1795454100000}"#.to_owned(),
                    )
                }
                ("POST", "/v1/device-links/claim", "?") => {
                    assert_eq!(verified.keyid.format(), expected_link_keyid);
                    let obj = body_val.as_object().expect("json object");
                    assert_eq!(obj.len(), 3);
                    assert_eq!(body_val["link_code"], "W4K9-M2P7");
                    assert_eq!(body_val["device_pubkey_b64"], B64_STD.encode(new_dev_pubkey));
                    assert_eq!(body_val["device_label"], "wintermute");
                    (
                        "200 OK",
                        r#"{"poll_token":"mpdl1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","device_fingerprint":"ad1a8375-03ecc659-ad64922d-16cf6eb6","expires_at_ms":1795454100000}"#
                            .to_owned(),
                    )
                }
                ("POST", "/v1/device-links/inspect", "?") => {
                    assert!(matches!(verified.keyid, mp_protocol::KeyId::Root { .. }));
                    assert_eq!(body_val["link_code"], "W4K9-M2P7");
                    inspect_calls += 1;
                    if inspect_calls == 1 {
                        (
                            "200 OK",
                            r#"{"state":"waiting_for_device","suggested_label":"wintermute","created_at_ms":1795453800000,"expires_at_ms":1795454100000}"#
                                .to_owned(),
                        )
                    } else {
                        (
                            "200 OK",
                            format!(
                                r#"{{"state":"pending_approval","device_pubkey_b64":"{}","device_fingerprint":"ad1a8375-03ecc659-ad64922d-16cf6eb6","device_label":"wintermute","requester_country":"US","created_at_ms":1795453800000,"expires_at_ms":1795454100000}}"#,
                                B64_STD.encode(new_dev_pubkey)
                            ),
                        )
                    }
                }
                ("POST", "/v1/device-links/approve", "?") => {
                    assert!(matches!(verified.keyid, mp_protocol::KeyId::Root { .. }));
                    let obj = body_val.as_object().expect("json object");
                    assert_eq!(obj.len(), 3, "None device_label must be omitted");
                    assert_eq!(body_val["link_code"], "W4K9-M2P7");
                    assert_eq!(body_val["device_pubkey_b64"], B64_STD.encode(new_dev_pubkey));
                    assert_eq!(body_val["device_cwt_b64"], srv_cwt_b64);
                    (
                        "200 OK",
                        r#"{"approved":true,"account_id":1001,"device_id":2004,"device_label":"wintermute","device_fingerprint":"ad1a8375-03ecc659-ad64922d-16cf6eb6","cwt_expires_ms":1900000000000}"#
                            .to_owned(),
                    )
                }
                ("POST", "/v1/device-links/poll", "?") => {
                    assert_eq!(verified.keyid.format(), expected_link_keyid);
                    assert_eq!(body_val["link_code"], "W4K9-M2P7");
                    assert_eq!(
                        body_val["poll_token"],
                        "mpdl1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    );
                    assert_eq!(body_val["device_pubkey_b64"], B64_STD.encode(new_dev_pubkey));
                    poll_nonces_srv
                        .lock()
                        .expect("lock")
                        .push(verified.nonce.clone());
                    poll_calls += 1;
                    if poll_calls == 1 {
                        (
                            "202 Accepted",
                            r#"{"status":"pending","expires_at_ms":1795454100000}"#.to_owned(),
                        )
                    } else {
                        (
                            "200 OK",
                            format!(
                                r#"{{"status":"approved","account_id":1001,"handle":"alice","device_id":2004,"root_pubkey_b64":"{}","device_cwt_b64":"{}","cwt_expires_ms":1900000000000,"safety_number":"SP44-BGDF-SWJH-YXTV-ZWXT-MNGX-P342-B0TV"}}"#,
                                B64_STD.encode(root_pubkey),
                                srv_cwt_b64
                            ),
                        )
                    }
                }
                other => panic!("unexpected request: {other:?}"),
            };

            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json.len(),
                json
            );
            tls.write_all(resp.as_bytes()).await.expect("write");
            tls.shutdown().await.expect("shutdown");
        }
    });

    let client =
        ControlClient::with_device_signer(make_client_config(&pki, addr), dev_signer.clone());

    // Local fail-closed signer guards: .root-only routes MUST reject device, rec., and link. signers!
    for bad_signer in [&dev_signer, &rec_signer, &link_signer] {
        assert!(matches!(
            client.device_link_create(bad_signer, None).await,
            Err(ControlError::InvalidRequest(_))
        ));
        assert!(matches!(
            client.device_link_inspect(bad_signer, "W4K9-M2P7").await,
            Err(ControlError::InvalidRequest(_))
        ));
        assert!(matches!(
            client
                .device_link_approve(
                    bad_signer,
                    &DeviceLinkApproveRequest {
                        link_code: "W4K9-M2P7".to_owned(),
                        device_pubkey: new_dev_pubkey,
                        device_cwt: new_dev_cwt.clone(),
                        device_label: None,
                    }
                )
                .await,
            Err(ControlError::InvalidRequest(_))
        ));
    }
    // Web sessions MUST reject rec. and link. signers locally!
    for bad_signer in [&rec_signer, &link_signer] {
        assert!(matches!(
            client
                .web_session_inspect_with_signer(bad_signer, "W4K9-M2P7")
                .await,
            Err(ControlError::InvalidRequest(_))
        ));
        assert!(matches!(
            client
                .web_session_approve_with_signer(bad_signer, "W4K9-M2P7")
                .await,
            Err(ControlError::InvalidRequest(_))
        ));
    }

    // 1. POST /v1/accounts/recover-lookup (rec.<32hex>)
    let recovered = client
        .recover_lookup(root_secret)
        .await
        .expect("recover_lookup");
    assert_eq!(recovered.account_id, 1001);
    assert_eq!(recovered.handle, "alice");
    assert_eq!(recovered.root_pubkey_b64, B64_STD.encode(root_pubkey));
    assert_eq!(
        recovered.safety_number,
        "SP44-BGDF-SWJH-YXTV-ZWXT-MNGX-P342-B0TV"
    );
    assert_eq!(recovered.devices.len(), 1);
    assert_eq!(recovered.devices[0].device_id, 2002);

    // 2 & 3. POST /v1/web-sessions/inspect & approve (device signer + .root signer)
    let web_insp = client
        .web_session_inspect("W4K9-M2P7")
        .await
        .expect("web_session_inspect");
    assert!(web_insp.pending);
    assert_eq!(web_insp.scope, "web_account_portal");
    assert_eq!(web_insp.browser_fingerprint, "a1b2c3d4");
    assert_eq!(web_insp.requester_country, "US");
    assert_eq!(web_insp.requester_client, "Chrome/130");

    let web_appr_dev = client
        .web_session_approve("W4K9-M2P7")
        .await
        .expect("web_session_approve device");
    assert!(web_appr_dev.approved);
    assert_eq!(web_appr_dev.account_id, 1001);
    assert_eq!(web_appr_dev.approved_device_id, Some(2002));
    assert!(!web_appr_dev.approved_by_root);

    let web_insp_root = client
        .web_session_inspect_with_signer(&root_signer, "W4K9-M2P7")
        .await
        .expect("web_session_inspect root");
    assert!(web_insp_root.pending);

    let web_appr_root = client
        .web_session_approve_with_signer(&root_signer, "W4K9-M2P7")
        .await
        .expect("web_session_approve root");
    assert!(web_appr_root.approved);
    assert_eq!(web_appr_root.approved_device_id, None);
    assert!(web_appr_root.approved_by_root);

    // 4. POST /v1/device-links/create (.root) with None and Some(label)
    let link_none = client
        .device_link_create(&root_signer, None)
        .await
        .expect("device_link_create None");
    assert_eq!(link_none.link_code, "W4K9-M2P7");
    let link_some = client
        .device_link_create(&root_signer, Some("wintermute"))
        .await
        .expect("device_link_create Some");
    assert_eq!(link_some.expires_at_ms, 1_795_454_100_000);

    // 5. POST /v1/device-links/inspect (.root) -> WaitingForDevice
    let insp_wait = client
        .device_link_inspect(&root_signer, "W4K9-M2P7")
        .await
        .expect("device_link_inspect waiting");
    assert_eq!(
        insp_wait,
        DeviceLinkInspectResponse::WaitingForDevice {
            suggested_label: "wintermute".to_owned(),
            created_at_ms: 1_795_453_800_000,
            expires_at_ms: 1_795_454_100_000,
        }
    );

    // 6. POST /v1/device-links/claim (link.<32hex>)
    let claimed = client
        .device_link_claim(new_dev_secret, "W4K9-M2P7", Some("wintermute"))
        .await
        .expect("device_link_claim");
    assert_eq!(
        claimed.poll_token,
        "mpdl1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        claimed.device_fingerprint,
        "ad1a8375-03ecc659-ad64922d-16cf6eb6"
    );

    // 7. POST /v1/device-links/inspect (.root) -> PendingApproval
    let insp_pending = client
        .device_link_inspect(&root_signer, "W4K9-M2P7")
        .await
        .expect("device_link_inspect pending");
    assert_eq!(
        insp_pending,
        DeviceLinkInspectResponse::PendingApproval {
            device_pubkey_b64: B64_STD.encode(new_dev_pubkey),
            device_fingerprint: "ad1a8375-03ecc659-ad64922d-16cf6eb6".to_owned(),
            device_label: "wintermute".to_owned(),
            requester_country: "US".to_owned(),
            created_at_ms: 1_795_453_800_000,
            expires_at_ms: 1_795_454_100_000,
        }
    );

    // 8a. POST /v1/device-links/poll (link.<32hex>) -> 202 Pending
    let poll_pending = client
        .device_link_poll(new_dev_secret, "W4K9-M2P7", &claimed.poll_token)
        .await
        .expect("device_link_poll 202");
    assert_eq!(
        poll_pending,
        DeviceLinkPollResponse::Pending {
            expires_at_ms: 1_795_454_100_000
        }
    );

    // 9. POST /v1/device-links/approve (.root)
    let approved = client
        .device_link_approve(
            &root_signer,
            &DeviceLinkApproveRequest {
                link_code: "W4K9-M2P7".to_owned(),
                device_pubkey: new_dev_pubkey,
                device_cwt: new_dev_cwt,
                device_label: None,
            },
        )
        .await
        .expect("device_link_approve");
    assert!(approved.approved);
    assert_eq!(approved.account_id, 1001);
    assert_eq!(approved.device_id, 2004);
    assert_eq!(approved.device_label, "wintermute");

    // 8b. POST /v1/device-links/poll (link.<32hex>) -> 200 Approved
    let poll_approved = client
        .device_link_poll(new_dev_secret, "W4K9-M2P7", &claimed.poll_token)
        .await
        .expect("device_link_poll 200");
    assert_eq!(
        poll_approved,
        DeviceLinkPollResponse::Approved {
            account_id: 1001,
            handle: "alice".to_owned(),
            device_id: 2004,
            root_pubkey_b64: B64_STD.encode(root_pubkey),
            device_cwt_b64: expected_cwt_b64,
            cwt_expires_ms: 1_900_000_000_000,
            safety_number: "SP44-BGDF-SWJH-YXTV-ZWXT-MNGX-P342-B0TV".to_owned(),
        }
    );

    srv.await.expect("server task");
    {
        let nonces = poll_nonces.lock().expect("lock");
        assert_eq!(nonces.len(), 2);
        assert_ne!(
            nonces[0], nonces[1],
            "each device_link_poll MUST use a fresh RFC 9421 nonce"
        );
    }

    // 10. TLS 1.3 relay /ping probe helper
    let relay_pki = generate_test_pki_for("relay.multiplayer.tech");
    let relay_acceptor = make_server_acceptor(&relay_pki, &[&rustls::version::TLS13]);
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let relay_srv = tokio::spawn(async move {
        let (tcp, _) = relay_listener.accept().await.expect("accept relay");
        let mut tls = relay_acceptor.accept(tcp).await.expect("tls relay");
        let req = read_http_request(&mut tls).await;
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/ping");
        assert_eq!(
            req.headers.get("host").map(String::as_str),
            Some("relay.multiplayer.tech")
        );
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        tls.write_all(resp.as_bytes()).await.expect("write ping");
        tls.shutdown().await.expect("shutdown relay");
    });

    let relay_client = ControlClient::new(
        ControlClientConfig::new("relay.multiplayer.tech")
            .expect("relay cfg")
            .with_tls_config(Arc::clone(&relay_pki.client_tls13))
            .with_connect_addr(relay_addr)
            .with_request_timeout(Duration::from_secs(5)),
    );
    assert!(matches!(
        relay_client
            .probe_relay_ping("http://relay.multiplayer.tech")
            .await,
        Err(ControlError::InvalidRequest(_))
    ));
    let rtt = relay_client
        .probe_relay_ping(TEST_RELAY_URL)
        .await
        .expect("probe_relay_ping must succeed over TLS 1.3");
    assert!(rtt < Duration::from_secs(5));
    relay_srv.await.expect("relay srv");
}
