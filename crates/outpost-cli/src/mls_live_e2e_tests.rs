//! Live End-to-End MLS (`e2ee_mode = 1`) Integration Tests for `mp-outpost` (`v0.7.1`).
//!
//! Spins up a real in-process TLS 1.3 HTTP/1.1 + `mp2` WebSocket Delivery Service backed by
//! the real `mp_mls::MpMlsPublicDs` state machine, and drives multiple real `AppDaemon`
//! instances end-to-end across:
//! 1. Cloud-managed (`custody_mode = 0`) automatic `POST /v1/accounts/me/mls/cloud-bind`
//!    bootstrap (with client-side `device_pop_sig` completion + encrypted 0600 persistence).
//! 2. Creator `op_room_invite` -> epoch-0 `MpMlsClient::create_room` -> `POST /mls/init`
//!    -> `InviteFragmentV2` share URL minting -> encrypted `MPM1` snapshot persistence.
//! 3. Same-account multi-device sibling fleet (Machine A `1001/2001` + Machine B `1001/2002`
//!    under `@alice`): bare `op_room_enter` -> single-use `KeyPackage` -> `POST /mls/join`
//!    -> live WS `mls_join_request` -> sibling Add Commit + sibling `WelcomeAuthV1`
//!    -> `GET /mls/welcome` -> `join_from_welcome_sibling` -> bidirectional encrypted
//!    `e2ee_app` chat, IRC `{"mp_irc":1,...}` action, and agent card!
//! 4. Cross-account invite join (`@bob` `1002/2003` via `#<InviteFragmentV2_b64u>`): proves
//!    `invite_seed` NEVER touches `/v1/rooms/enter`, proves split-secret `join_proof` +
//!    `WelcomeAuthV1`, and proves bidirectional encrypted chat across Alice A, Alice B, Bob.
//! 5. Multi-account quorum `CommitAckV1` (`mp-mls-ack-v1:`): `@charlie` (`1003/2004`) joins
//!    while Alice + Bob are online -> DS stages **tentative** commit -> Bob's live WS pump
//!    verifies deterministically, signs `CommitAckV1`, submits `POST /mls/ack` -> DS reaches
//!    quorum and finalizes epoch 3 -> Charlie joins & exchanges encrypted chat at epoch 3!
//! 6. Fail-closed plaintext refusal when `e2ee_mode == 1 && mls_session.is_none()`.
//! 7. DS-signed `ExternalRemove` (`mls_rekey_needed`) evicting Charlie -> epoch 4 quorum
//!    finalization -> post-eviction secrecy (Bob decrypts epoch 4; Charlie cannot!).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use mp_mls::LeafNodeIndex;
use mp_mls::crypto::{sha256, sign_ed25519};
use mp_mls::ds::{AckStatus, CommitAckV1, MpMlsPublicDs, QuorumOutcome};
use mp_mls::framing::WIRE_BUCKETS;
use mp_mls::identity::{
    AccountDeviceListV1, ActiveDeviceEntryV1, ClientClass, CustodyMode, DEV_BIND_DOMAIN_SEP,
    MAX_NATIVE_BINDING_TTL_S, MpMlsDeviceBindingBodyV1, MpMlsDeviceBindingV1,
};
use mp_mls::invite::InviteFragmentV2;
use mp_mls::policy::{MP_GROUP_ID_LEN, extract_public_group_leaves};
use mp_protocol::{AccountId, DeviceId, RelayPolicy, encode_device_cwt};
use outpost_control::{
    ControlClient, ControlClientConfig, MP2_PING_TEXT, MP2_PONG_TEXT, MP2_SUBPROTOCOL,
    RequestSigner, build_tls13_client_config_with_roots, wall_now_ms, wall_now_secs,
};
use outpost_core::storage_codec::DeviceRecord;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

use super::AppDaemon;
use crate::ipc_payloads::{
    ERR_CONFLICT, IpcPartyEventKind, PartyPollIpcReq, PartyPostBoardReq, PartySendChatReq,
    RoomEnterIpcReq, RoomInviteIpcReq, decode_party_poll_resp, decode_room_enter_resp,
    decode_room_invite_resp, encode_party_poll_req, encode_party_post_board_req,
    encode_party_send_chat_req, encode_room_enter_req, encode_room_invite_req,
};
use crate::storage::{lock_state, open_state_dir, save_device_record};

const TEST_AUTHORITY: &str = "api.multiplayer.tech";
const TEST_PARTY_ID: u64 = 77_001;
const TEST_ROOM_CODE: &str = "E2EE";

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

#[derive(Clone)]
struct AccountRecord {
    account_id: u64,
    handle: String,
    root_secret: [u8; 32],
    devices: Vec<ActiveDeviceEntryV1>,
    list_version: u64,
    device_list_b64: String,
}

#[derive(Clone)]
struct StoredWelcome {
    welcome_id: u64,
    target_device_id: u64,
    target_epoch: u64,
    group_id_b64: String,
    welcome_b64: String,
    welcome_auth_b64: String,
    kp_ref_b64: String,
    acked: bool,
}

#[derive(Clone)]
struct RecordedWsSend {
    sender_account_id: u64,
    sender_device_id: u64,
    kind: String,
    target: String,
    body_encoding: String,
    body: String,
    mls_epoch: Option<u64>,
}

#[derive(Clone)]
struct StoredPendingKp {
    kp_id: u64,
    account_id: u64,
    device_id: u64,
    invite_id: Option<u64>,
    kp_ref_b64: String,
    kp_blob_b64: String,
    join_proof_b64: Option<String>,
}

struct MockDsState {
    ds_secret: [u8; 32],
    ds_pubkey: [u8; 32],
    accounts: HashMap<u64, AccountRecord>,
    /// `(account_id, device_id)` currently online on `mp2` WS.
    online_ws_devices: HashSet<(u64, u64)>,
    /// All devices currently members of the room.
    room_members: HashMap<u64, (u64, String)>,
    ds: Option<MpMlsPublicDs>,
    group_id: Option<[u8; MP_GROUP_ID_LEN]>,
    next_invite_id: u64,
    next_welcome_id: u64,
    next_kp_id: u64,
    next_event_seq: u64,
    pending_kps: Vec<StoredPendingKp>,
    pending_welcomes: Vec<StoredWelcome>,
    /// Stored tentative proposal blobs for current tentative commit.
    pending_proposals_b64: Vec<String>,
    tentative_commit_b64: Option<String>,
    tentative_proposals_b64: Vec<String>,
    /// Recorded `/v1/rooms/enter` targets (proves `#fragment` never hits server!).
    recorded_enter_targets: Vec<String>,
    /// Recorded `POST /v1/parties/:id/mls/ack` voters `(account_id, device_id, target_epoch)`.
    recorded_quorum_acks: Vec<(u64, u64, u64)>,
    /// Recorded `POST /v1/accounts/me/mls/cloud-bind` calls `(account_id, device_id)`.
    recorded_cloud_binds: Vec<(u64, u64)>,
    /// Recorded outbound WS send frames (for wire secrecy & bucket-size assertions!).
    recorded_ws_sends: Vec<RecordedWsSend>,
    ws_broadcast: broadcast::Sender<String>,
}

impl MockDsState {
    fn new(ds_secret: [u8; 32]) -> Self {
        let ds_pubkey = SigningKey::from_bytes(&ds_secret).verifying_key().to_bytes();
        let (ws_broadcast, _) = broadcast::channel(256);
        Self {
            ds_secret,
            ds_pubkey,
            accounts: HashMap::new(),
            online_ws_devices: HashSet::new(),
            room_members: HashMap::new(),
            ds: None,
            group_id: None,
            next_invite_id: 100,
            next_welcome_id: 500,
            next_kp_id: 1,
            next_event_seq: 0,
            pending_kps: Vec::new(),
            pending_welcomes: Vec::new(),
            pending_proposals_b64: Vec::new(),
            tentative_commit_b64: None,
            tentative_proposals_b64: Vec::new(),
            recorded_enter_targets: Vec::new(),
            recorded_quorum_acks: Vec::new(),
            recorded_cloud_binds: Vec::new(),
            recorded_ws_sends: Vec::new(),
            ws_broadcast,
        }
    }

    fn register_account(&mut self, account_id: u64, handle: &str, root_secret: [u8; 32]) {
        self.accounts.insert(
            account_id,
            AccountRecord {
                account_id,
                handle: handle.to_string(),
                root_secret,
                devices: Vec::new(),
                list_version: 0,
                device_list_b64: String::new(),
            },
        );
    }

    fn online_accounts(&self) -> Vec<u64> {
        let mut set: HashSet<u64> = HashSet::new();
        for &(acc, _) in &self.online_ws_devices {
            set.insert(acc);
        }
        let mut v: Vec<u64> = set.into_iter().collect();
        v.sort_unstable();
        v
    }

    fn members_json(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for (&did, (acc, handle)) in &self.room_members {
            out.push(json!({
                "account_id": acc.to_string(),
                "device_id": did.to_string(),
                "handle": handle,
                "client": "outpost",
                "is_guest": false,
                "is_browser": false,
                "status": "live",
            }));
        }
        out
    }

    fn is_mls_member(&self, device_id: u64) -> bool {
        let Some(ref ds) = self.ds else {
            return true;
        };
        extract_public_group_leaves(ds.public_group())
            .map(|leaves| {
                leaves
                    .values()
                    .any(|l| l.cred.binding.body.device_id == device_id)
            })
            .unwrap_or(false)
    }

    fn broadcast_json(&self, frame: Value) {
        let _ = self.ws_broadcast.send(frame.to_string());
    }
}

/// Extracts `(account_id, device_id)` from the RFC 9421 `Signature-Input` header `keyid="d<hex13>"`
/// or `keyid="a<acc_hex>.d<dev_hex>"` / `X-MP-Device-Id` style keyid emitted by `RequestSigner::device`.
fn parse_signer_ids(headers: &HashMap<String, String>) -> Option<(u64, u64)> {
    let sig_input = headers.get("signature-input")?;
    let parsed = mp_protocol::parse_signature_input(sig_input).ok()?;
    match parsed.keyid {
        mp_protocol::KeyId::Device {
            account_id,
            device_id,
        } => Some((account_id.get(), device_id.get())),
        _ => None,
    }
}

struct ParsedHttpReq {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_http_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Option<ParsedHttpReq> {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(chunk) = tmp.get(..n) {
            raw.extend_from_slice(chunk);
        }
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let head_str = std::str::from_utf8(raw.get(..header_end)?).ok()?;
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (target, String::new()),
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
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(chunk) = tmp.get(..n) {
            body.extend_from_slice(chunk);
        }
    }
    body.truncate(content_len);

    Some(ParsedHttpReq {
        method,
        path,
        query,
        headers,
        body,
    })
}

async fn write_json_response<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    body: &Value,
) {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let bytes = body.to_string().into_bytes();
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.write_all(&bytes).await;
    let _ = stream.flush().await;
}

fn compute_ws_accept(sec_key: &str) -> String {
    let mut sha1 = sha1_digest(format!(
        "{sec_key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    ).as_bytes());
    let _ = &mut sha1;
    B64.encode(sha1)
}

/// Minimal RFC 3174 SHA-1 strictly for RFC 6455 `Sec-WebSocket-Accept` in the local mock server.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let off = i * 4;
            if let (Some(b0), Some(b1), Some(b2), Some(b3)) = (
                chunk.get(off),
                chunk.get(off + 1),
                chunk.get(off + 2),
                chunk.get(off + 3),
            ) && let Some(slot) = w.get_mut(i)
            {
                *slot = u32::from_be_bytes([*b0, *b1, *b2, *b3]);
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
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
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
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        if let Some(slice) = out.get_mut(i * 4..i * 4 + 4) {
            slice.copy_from_slice(&word.to_be_bytes());
        }
    }
    out
}

async fn ws_write_text<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    text: &str,
) -> std::io::Result<()> {
    let payload = text.as_bytes();
    let mut hdr = Vec::with_capacity(10);
    hdr.push(0x81u8); // FIN + Text
    let len = payload.len();
    if len < 126 {
        hdr.push(u8::try_from(len).unwrap_or(0));
    } else if len <= usize::from(u16::MAX) {
        hdr.push(126u8);
        hdr.extend_from_slice(&u16::try_from(len).unwrap_or(0).to_be_bytes());
    } else {
        hdr.push(127u8);
        hdr.extend_from_slice(&(len as u64).to_be_bytes());
    }
    w.write_all(&hdr).await?;
    w.write_all(payload).await?;
    w.flush().await
}

async fn ws_read_client_frame<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> Option<(u8, Vec<u8>)> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b).await.ok()?;
    let opcode = b[0] & 0x0F;
    let masked = (b[1] & 0x80) != 0;
    let len7 = b[1] & 0x7F;
    let payload_len: usize = if len7 < 126 {
        usize::from(len7)
    } else if len7 == 126 {
        let mut ext = [0u8; 2];
        r.read_exact(&mut ext).await.ok()?;
        usize::from(u16::from_be_bytes(ext))
    } else {
        let mut ext = [0u8; 8];
        r.read_exact(&mut ext).await.ok()?;
        usize::try_from(u64::from_be_bytes(ext)).ok()?
    };
    let mask = if masked {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).await.ok()?;
        Some(m)
    } else {
        None
    };
    let mut data = vec![0u8; payload_len];
    r.read_exact(&mut data).await.ok()?;
    if let Some(m) = mask {
        for (i, byte) in data.iter_mut().enumerate() {
            if let Some(&k) = m.get(i % 4) {
                *byte ^= k;
            }
        }
    }
    Some((opcode, data))
}

async fn spawn_mock_ds_server(
    pki: &TestPki,
    state: Arc<Mutex<MockDsState>>,
) -> SocketAddr {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
        unreachable!("bind loopback");
    };
    let Ok(addr) = listener.local_addr() else {
        unreachable!("local_addr");
    };
    let acceptor = make_server_acceptor(pki);

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Some(req) = read_http_request(&mut tls).await else {
                    return;
                };
                let (caller_acc, caller_dev) = parse_signer_ids(&req.headers).unwrap_or((0, 0));

                // WebSocket upgrade for `/v1/parties/77001/ws`
                if req.method == "GET"
                    && req.path == format!("/v1/parties/{TEST_PARTY_ID}/ws")
                    && req
                        .headers
                        .get("upgrade")
                        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
                {
                    let (allowed, hello_frame, mut rx) = {
                        let Ok(mut st) = state.lock() else {
                            return;
                        };
                        if !st.is_mls_member(caller_dev) {
                            (false, Value::Null, st.ws_broadcast.subscribe())
                        } else {
                            st.online_ws_devices.insert((caller_acc, caller_dev));
                            let handle = st
                                .accounts
                                .get(&caller_acc)
                                .map(|a| a.handle.clone())
                                .unwrap_or_default();
                            st.room_members
                                .insert(caller_dev, (caller_acc, handle.clone()));
                            let mls_epoch = st.ds.as_ref().map_or(0, MpMlsPublicDs::epoch);
                            let gid_b64 = st.group_id.map(|g| B64.encode(g));
                            let ds_pk_b64 = B64.encode(st.ds_pubkey);
                            let members = st.members_json();
                            let hello = json!({
                                "v": 2,
                                "t": "hello",
                                "party_id": TEST_PARTY_ID.to_string(),
                                "room_code": TEST_ROOM_CODE,
                                "name": "Live MLS Room",
                                "self": {
                                    "account_id": caller_acc.to_string(),
                                    "device_id": caller_dev.to_string(),
                                    "handle": handle,
                                    "client": "outpost",
                                    "is_guest": false,
                                    "is_browser": false,
                                },
                                "latest_seq": st.next_event_seq,
                                "members": members,
                                "history": [],
                                "e2ee_mode": 1,
                                "mls_epoch": mls_epoch,
                                "min_allowed_mls_epoch": mls_epoch.saturating_sub(2),
                                "mls_rekey_required": st.ds.as_ref().is_some_and(MpMlsPublicDs::mls_rekey_required),
                                "group_id_b64": gid_b64,
                                "party_ds_pubkey_b64": ds_pk_b64,
                                "mls_invite_epoch": 0,
                            });
                            let rx = st.ws_broadcast.subscribe();
                            (true, hello, rx)
                        }
                    };
                    if !allowed {
                        write_json_response(
                            &mut tls,
                            404,
                            &json!({"error": "not_mls_member", "message": "not an MLS member"}),
                        )
                        .await;
                        return;
                    }
                    let sec_key = req
                        .headers
                        .get("sec-websocket-key")
                        .cloned()
                        .unwrap_or_default();
                    let accept = compute_ws_accept(&sec_key);
                    let upgrade_resp = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {MP2_SUBPROTOCOL}\r\n\r\n"
                    );
                    if tls.write_all(upgrade_resp.as_bytes()).await.is_err()
                        || tls.flush().await.is_err()
                    {
                        return;
                    }

                    let (mut ws_read, mut ws_write) = tokio::io::split(tls);
                    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                    let _ = out_tx.send(hello_frame.to_string());

                    // Dedicated writer task (never cancels `ws_read_client_frame`!).
                    let writer_task = tokio::spawn(async move {
                        while let Some(txt) = out_rx.recv().await {
                            if ws_write_text(&mut ws_write, &txt).await.is_err() {
                                break;
                            }
                        }
                    });

                    // Dedicated broadcast forwarder task (forwards room broadcasts to writer channel).
                    let bcast_tx = out_tx.clone();
                    let bcast_task = tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Ok(txt) => {
                                    if bcast_tx.send(txt).is_err() {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {}
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    });

                    // Exclusive cancel-safe reader loop owning `ws_read`!
                    while let Some((opcode, data)) = ws_read_client_frame(&mut ws_read).await {
                        match opcode {
                            0x1 => {
                                let Ok(text) = std::str::from_utf8(&data) else {
                                    continue;
                                };
                                if text == MP2_PING_TEXT {
                                    let _ = out_tx.send(MP2_PONG_TEXT.to_string());
                                    continue;
                                }
                                let Ok(val) = serde_json::from_str::<Value>(text) else {
                                    continue;
                                };
                                let t = val.get("t").and_then(Value::as_str).unwrap_or_default();
                                if t == "send" {
                                    let cid = val.get("client_msg_id").and_then(Value::as_str).unwrap_or_default().to_string();
                                    let kind = val.get("kind").and_then(Value::as_str).unwrap_or_default().to_string();
                                    let target = val.get("target").and_then(Value::as_str).unwrap_or_default().to_string();
                                    let body_encoding = val.get("body_encoding").and_then(Value::as_str).unwrap_or_default().to_string();
                                    let body = val.get("body").and_then(Value::as_str).unwrap_or_default().to_string();
                                    let mls_epoch = val.get("mls_epoch").and_then(Value::as_u64);
                                    let now_ms = wall_now_ms();
                                    let (seq, ev_frame) = {
                                        let Ok(mut st) = state.lock() else {
                                            break;
                                        };
                                        st.recorded_ws_sends.push(RecordedWsSend {
                                            sender_account_id: caller_acc,
                                            sender_device_id: caller_dev,
                                            kind: kind.clone(),
                                            target: target.clone(),
                                            body_encoding: body_encoding.clone(),
                                            body: body.clone(),
                                            mls_epoch,
                                        });
                                        st.next_event_seq = st.next_event_seq.saturating_add(1);
                                        let seq = st.next_event_seq;
                                        let handle = st
                                            .accounts
                                            .get(&caller_acc)
                                            .map(|a| a.handle.clone())
                                            .unwrap_or_default();
                                        let ev = json!({
                                            "v": 2,
                                            "t": "event",
                                            "seq": seq,
                                            "ts_ms": now_ms,
                                            "client_msg_id": cid,
                                            "sender": {
                                                "account_id": caller_acc.to_string(),
                                                "device_id": caller_dev.to_string(),
                                                "handle": handle,
                                                "client": "outpost",
                                                "is_guest": false,
                                                "is_browser": false,
                                            },
                                            "target": target,
                                            "kind": kind,
                                            "body_encoding": body_encoding,
                                            "body": body,
                                            "mls_epoch": mls_epoch,
                                            "e2ee_mode": 1,
                                        });
                                        (seq, ev)
                                    };
                                    let ack = json!({
                                        "v": 2,
                                        "t": "ack",
                                        "client_msg_id": cid,
                                        "seq": seq,
                                        "ts_ms": now_ms,
                                    });
                                    let _ = out_tx.send(ack.to_string());
                                    if let Ok(st) = state.lock() {
                                        st.broadcast_json(ev_frame);
                                    }
                                }
                            }
                            0x8 => break,
                            _ => {}
                        }
                    }
                    drop(out_tx);
                    bcast_task.abort();
                    writer_task.abort();
                    if let Ok(mut st) = state.lock() {
                        st.online_ws_devices.remove(&(caller_acc, caller_dev));
                    }
                    return;
                }

                // HTTP REST API routes
                let (status, resp_json) =
                    handle_mock_http(&state, &req, caller_acc, caller_dev);
                write_json_response(&mut tls, status, &resp_json).await;
            });
        }
    });

    addr
}

fn handle_mock_http(
    state: &Arc<Mutex<MockDsState>>,
    req: &ParsedHttpReq,
    caller_acc: u64,
    caller_dev: u64,
) -> (u16, Value) {
    let body_json: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let Ok(mut st) = state.lock() else {
        return (500, json!({"error": "lock_poisoned"}));
    };
    let party_prefix = format!("/v1/parties/{TEST_PARTY_ID}");

    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/v1/accounts/me/mls/cloud-bind") => {
            let mls_sig_pk_b64 = body_json
                .get("mls_sig_pubkey_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Ok(mls_sig_raw) = B64.decode(mls_sig_pk_b64.as_bytes()) else {
                return (400, json!({"error": "invalid_mls_sig_pubkey"}));
            };
            let Ok(mls_sig_pk): Result<[u8; 32], _> = mls_sig_raw.try_into() else {
                return (400, json!({"error": "invalid_mls_sig_pubkey_len"}));
            };
            let iat_s = body_json
                .get("iat_s")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| u64::try_from(wall_now_secs()).unwrap_or(0));
            let exp_s = body_json
                .get("exp_s")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| iat_s.saturating_add(MAX_NATIVE_BINDING_TTL_S));
            let Some(acc) = st.accounts.get_mut(&caller_acc) else {
                return (404, json!({"error": "unknown_account"}));
            };
            let root_sk = SigningKey::from_bytes(&acc.root_secret);
            let root_pk = root_sk.verifying_key().to_bytes();

            let binding_body = MpMlsDeviceBindingBodyV1 {
                version: 1,
                account_id: caller_acc,
                root_gen: 1,
                device_id: caller_dev,
                device_gen: 1,
                client_class: ClientClass::Outpost,
                agent_capable: true,
                custody_mode: CustodyMode::CloudManaged,
                iat_s,
                exp_s,
                root_pubkey: root_pk,
                mls_sig_pubkey: mls_sig_pk,
            };
            let Ok(body_bytes) = binding_body.encode() else {
                return (400, json!({"error": "invalid_binding_body"}));
            };
            let mut bind_msg = Vec::with_capacity(DEV_BIND_DOMAIN_SEP.len() + body_bytes.len());
            bind_msg.extend_from_slice(DEV_BIND_DOMAIN_SEP);
            bind_msg.extend_from_slice(&body_bytes);
            let root_sig = sign_ed25519(&root_sk, &bind_msg);

            let mut pop_hash_in = Vec::with_capacity(body_bytes.len() + 64);
            pop_hash_in.extend_from_slice(&body_bytes);
            pop_hash_in.extend_from_slice(&root_sig);
            let pop_digest = sha256(&pop_hash_in);
            let mut pop_message =
                Vec::with_capacity(mp_mls::identity::DEV_POP_DOMAIN_SEP.len() + 32);
            pop_message.extend_from_slice(mp_mls::identity::DEV_POP_DOMAIN_SEP);
            pop_message.extend_from_slice(&pop_digest);

            let device_sig_b64_opt = body_json
                .get("device_sig_b64")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());

            let Some(device_sig_b64) = device_sig_b64_opt else {
                // Step 1: return deterministic `body_b64`, `root_sig_b64`, and `pop_message_b64`!
                return (
                    200,
                    json!({
                        "ok": true,
                        "step": "sign_pop",
                        "account_id": caller_acc.to_string(),
                        "device_id": caller_dev.to_string(),
                        "device_gen": 1,
                        "root_gen": 1,
                        "root_pubkey_b64": B64.encode(root_pk),
                        "custody_mode": 0,
                        "iat_s": iat_s,
                        "exp_s": exp_s,
                        "body_b64": B64.encode(body_bytes),
                        "root_sig_b64": B64.encode(root_sig),
                        "pop_message_b64": B64.encode(&pop_message),
                    }),
                );
            };

            // Step 2: verify `device_sig_b64`, assemble canonical 236B `MpMlsDeviceBindingV1`,
            // update monotonic `AccountDeviceListV1`, and return finalized bundle!
            let Ok(dev_sig_raw) = B64.decode(device_sig_b64.as_bytes()) else {
                return (400, json!({"error": "invalid_device_sig_b64"}));
            };
            let Ok(device_pop_sig): Result<[u8; 64], _> = dev_sig_raw.try_into() else {
                return (400, json!({"error": "invalid_device_sig_len"}));
            };
            let full_binding = MpMlsDeviceBindingV1 {
                body: binding_body,
                root_sig,
                device_pop_sig,
            };
            if full_binding.verify_structural().is_err() {
                return (400, json!({"error": "invalid_device_pop_sig"}));
            }
            let Ok(binding_bytes) = full_binding.encode() else {
                return (500, json!({"error": "encode_binding_failed"}));
            };

            // Update monotonic AccountDeviceListV1 for this account (keeps sibling devices!)
            if !acc.devices.iter().any(|d| d.device_id == caller_dev) {
                acc.devices.push(ActiveDeviceEntryV1 {
                    device_id: caller_dev,
                    device_gen: 1,
                    mls_sig_pubkey: mls_sig_pk,
                });
                acc.devices.sort_by_key(|d| d.device_id);
            }
            acc.list_version = acc.list_version.saturating_add(1);
            let Ok(list) = AccountDeviceListV1::sign(
                caller_acc,
                1,
                acc.list_version,
                iat_s,
                exp_s,
                acc.devices.clone(),
                &root_sk,
            ) else {
                return (500, json!({"error": "sign_device_list_failed"}));
            };
            let Ok(list_bytes) = list.encode() else {
                return (500, json!({"error": "encode_device_list_failed"}));
            };
            let Ok(list_hash) = list.list_hash() else {
                return (500, json!({"error": "hash_device_list_failed"}));
            };
            acc.device_list_b64 = B64.encode(&list_bytes);
            let list_version = acc.list_version;
            let list_b64 = acc.device_list_b64.clone();
            st.recorded_cloud_binds.push((caller_acc, caller_dev));
            (
                200,
                json!({
                    "ok": true,
                    "account_id": caller_acc.to_string(),
                    "device_id": caller_dev.to_string(),
                    "device_gen": 1,
                    "root_gen": 1,
                    "root_pubkey_b64": B64.encode(root_pk),
                    "custody_mode": 0,
                    "binding_b64": B64.encode(binding_bytes),
                    "device_list_b64": list_b64,
                    "list_version": list_version,
                    "list_hash_b64": B64.encode(list_hash),
                    "exp_s": exp_s,
                }),
            )
        }
        ("POST", "/v1/devices/binding") => (
            200,
            json!({
                "ok": true,
                "device_id": caller_dev.to_string(),
                "binding_sha256_b64": B64.encode([0u8; 32]),
            }),
        ),
        ("GET", "/v1/accounts/me/device-list") => {
            if let Some(acc) = st.accounts.get(&caller_acc)
                && !acc.device_list_b64.is_empty()
            {
                (
                    200,
                    json!({
                        "account_id": caller_acc.to_string(),
                        "list_version": acc.list_version,
                        "device_list_b64": acc.device_list_b64,
                    }),
                )
            } else {
                (404, json!({"error": "not_found"}))
            }
        }
        ("POST", "/v1/rooms/invite") => {
            let handle = st
                .accounts
                .get(&caller_acc)
                .map(|a| a.handle.clone())
                .unwrap_or_default();
            st.room_members.insert(caller_dev, (caller_acc, handle));
            let is_creator = st.ds.is_none();
            (
                200,
                json!({
                    "party_id": TEST_PARTY_ID.to_string(),
                    "room_code": TEST_ROOM_CODE,
                    "share_url": format!("https://clank.party/{TEST_ROOM_CODE}"),
                    "handle_url": "https://clank.party/@alice",
                    "ws_path": format!("/v1/parties/{TEST_PARTY_ID}/ws"),
                    "e2ee_mode": 1,
                    "party_ds_pubkey_b64": B64.encode(st.ds_pubkey),
                    "group_id_b64": st.group_id.map(|g| B64.encode(g)),
                    "is_creator": is_creator,
                }),
            )
        }
        ("POST", "/v1/rooms/enter") => {
            let target = body_json
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            st.recorded_enter_targets.push(target);
            let handle = st
                .accounts
                .get(&caller_acc)
                .map(|a| a.handle.clone())
                .unwrap_or_default();
            st.room_members.insert(caller_dev, (caller_acc, handle));
            let members = st.members_json();
            (
                200,
                json!({
                    "party_id": TEST_PARTY_ID.to_string(),
                    "room_code": TEST_ROOM_CODE,
                    "name": "Live MLS Room",
                    "share_url": format!("https://clank.party/{TEST_ROOM_CODE}"),
                    "ws_path": format!("/v1/parties/{TEST_PARTY_ID}/ws"),
                    "e2ee_mode": 1,
                    "party_ds_pubkey_b64": B64.encode(st.ds_pubkey),
                    "group_id_b64": st.group_id.map(|g| B64.encode(g)),
                    "members": members,
                }),
            )
        }
        ("POST", p) if p == format!("{party_prefix}/mls/init") => {
            if st.ds.is_some() {
                return (409, json!({"error": "mls_already_initialized"}));
            }
            let gid_b64 = body_json
                .get("group_id_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let gi_b64 = body_json
                .get("group_info_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Ok(gid_raw) = B64.decode(gid_b64.as_bytes()) else {
                return (400, json!({"error": "bad_group_id"}));
            };
            let Ok(gid): Result<[u8; MP_GROUP_ID_LEN], _> = gid_raw.try_into() else {
                return (400, json!({"error": "bad_group_id_len"}));
            };
            let Ok(gi_bytes) = B64.decode(gi_b64.as_bytes()) else {
                return (400, json!({"error": "bad_group_info"}));
            };
            match MpMlsPublicDs::bootstrap_epoch0(TEST_PARTY_ID, gid, st.ds_pubkey, &gi_bytes) {
                Ok(ds) => {
                    st.ds = Some(ds);
                    st.group_id = Some(gid);
                    (
                        201,
                        json!({
                            "ok": true,
                            "group_id_b64": gid_b64,
                            "mls_epoch": 0,
                        }),
                    )
                }
                Err(e) => (400, json!({"error": format!("bootstrap_failed: {e}")})),
            }
        }
        ("POST", p) if p == format!("{party_prefix}/mls/invites") => {
            st.next_invite_id = st.next_invite_id.saturating_add(1);
            let inv_id = st.next_invite_id;
            let exp_ms = body_json
                .get("expires_at_ms")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| wall_now_ms().saturating_add(3_600_000));
            (
                201,
                json!({
                    "invite_id": inv_id,
                    "invite_epoch": 0,
                    "expires_at_ms": exp_ms,
                }),
            )
        }
        ("POST", p) if p == format!("{party_prefix}/mls/join") => {
            let kp_blob_b64 = body_json
                .get("kp_blob_b64")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let kp_ref_b64 = body_json
                .get("kp_ref_b64")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let invite_id = body_json.get("invite_id").and_then(Value::as_u64);
            let join_proof_b64 = body_json
                .get("join_proof_b64")
                .and_then(Value::as_str)
                .map(str::to_string);
            let kp_id = st.next_kp_id;
            st.next_kp_id = st.next_kp_id.saturating_add(1);
            st.pending_kps.push(StoredPendingKp {
                kp_id,
                account_id: caller_acc,
                device_id: caller_dev,
                invite_id,
                kp_ref_b64: kp_ref_b64.clone(),
                kp_blob_b64: kp_blob_b64.clone(),
                join_proof_b64: join_proof_b64.clone(),
            });
            // Broadcast `mls_join_request` to all online MLS members!
            st.broadcast_json(json!({
                "v": 2,
                "t": "mls_join_request",
                "party_id": TEST_PARTY_ID.to_string(),
                "account_id": caller_acc.to_string(),
                "device_id": caller_dev.to_string(),
                "invite_id": invite_id,
                "kp_ref_b64": kp_ref_b64,
                "kp_blob_b64": kp_blob_b64,
                "join_proof_b64": join_proof_b64,
            }));
            (
                202,
                json!({
                    "queued": true,
                    "kp_id": kp_id,
                }),
            )
        }
        ("POST", p) if p == format!("{party_prefix}/mls/commit") => {
            let commit_b64 = body_json
                .get("commit_b64")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let Ok(commit_bytes) = B64.decode(commit_b64.as_bytes()) else {
                return (400, json!({"error": "bad_commit_b64"}));
            };
            let online = st.online_accounts();
            let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
            let Some(ref mut ds) = st.ds else {
                return (409, json!({"error": "mls_not_initialized"}));
            };
            let parent_epoch = ds.epoch();
            let commit_sha = sha256(&commit_bytes);
            let outcome =
                match ds.stage_tentative_commit(&commit_bytes, caller_dev, &online, now_s, 15) {
                    Ok(o) => o,
                    Err(e) => {
                        return (409, json!({"error": format!("commit_rejected: {e}")}));
                    }
                };
            let target_epoch = parent_epoch.saturating_add(1);
            let gid_b64 = B64.encode(ds.group_id());

            // Store any attached Welcome(s)
            if let Some(arr) = body_json.get("welcomes").and_then(Value::as_array) {
                for w in arr {
                    let target_dev = w
                        .get("target_device_id")
                        .and_then(Value::as_u64)
                        .or_else(|| {
                            w.get("target_device_id")
                                .and_then(Value::as_str)
                                .and_then(|s| s.parse().ok())
                        })
                        .unwrap_or(0);
                    let welcome_b64 = w
                        .get("welcome_blob_b64")
                        .or_else(|| w.get("welcome_b64"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let welcome_auth_b64 = w
                        .get("welcome_auth_blob_b64")
                        .or_else(|| w.get("welcome_auth_b64"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let kp_ref_b64 = w
                        .get("kp_ref_b64")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    if target_dev > 0 && !welcome_b64.is_empty() {
                        st.pending_kps.retain(|k| k.kp_ref_b64 != kp_ref_b64);
                        st.next_welcome_id = st.next_welcome_id.saturating_add(1);
                        let wid = st.next_welcome_id;
                        st.pending_welcomes.push(StoredWelcome {
                            welcome_id: wid,
                            target_device_id: target_dev,
                            target_epoch,
                            group_id_b64: gid_b64.clone(),
                            welcome_b64,
                            welcome_auth_b64,
                            kp_ref_b64,
                            acked: false,
                        });
                    }
                }
            }

            let proposals_b64 = st.pending_proposals_b64.clone();
            match outcome {
                QuorumOutcome::Finalized { new_epoch, .. } => {
                    st.pending_proposals_b64.clear();
                    st.tentative_commit_b64 = None;
                    st.tentative_proposals_b64.clear();
                    st.broadcast_json(json!({
                        "v": 2,
                        "t": "mls_commit_finalized",
                        "party_id": TEST_PARTY_ID.to_string(),
                        "group_id_b64": gid_b64,
                        "epoch": new_epoch,
                        "commit_sha256_b64": B64.encode(commit_sha),
                        "commit_blob_b64": commit_b64,
                        "proposals_b64": proposals_b64,
                    }));
                    (
                        200,
                        json!({
                            "finalized": true,
                            "outcome": "finalized",
                            "target_epoch": new_epoch,
                            "commit_sha256_b64": B64.encode(commit_sha),
                        }),
                    )
                }
                QuorumOutcome::Pending { .. } => {
                    st.tentative_commit_b64 = Some(commit_b64.clone());
                    st.tentative_proposals_b64 = proposals_b64.clone();
                    st.broadcast_json(json!({
                        "v": 2,
                        "t": "mls_commit_tentative",
                        "party_id": TEST_PARTY_ID.to_string(),
                        "group_id_b64": gid_b64,
                        "parent_epoch": parent_epoch,
                        "target_epoch": target_epoch,
                        "commit_sha256_b64": B64.encode(commit_sha),
                        "committer_account_id": caller_acc.to_string(),
                        "committer_device_id": caller_dev.to_string(),
                        "commit_blob_b64": commit_b64,
                        "proposals_b64": proposals_b64,
                        "deadline_ms": wall_now_ms().saturating_add(15_000),
                    }));
                    (
                        202,
                        json!({
                            "finalized": false,
                            "outcome": "tentative",
                            "target_epoch": target_epoch,
                            "commit_sha256_b64": B64.encode(commit_sha),
                        }),
                    )
                }
                QuorumOutcome::Discarded { reason, .. } => {
                    (409, json!({"error": format!("commit_discarded: {reason}")}))
                }
            }
        }
        ("POST", p) if p == format!("{party_prefix}/mls/ack") => {
            let group_id_b64 = body_json
                .get("group_id_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let parent_epoch = body_json
                .get("parent_epoch")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let target_epoch = body_json
                .get("target_epoch")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let commit_sha_b64 = body_json
                .get("commit_sha256_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let status_u8 = body_json.get("status").and_then(Value::as_u64).unwrap_or(0) as u8;
            let auth_hash_b64 = body_json
                .get("epoch_auth_hash_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let ack_sig_b64 = body_json
                .get("ack_sig_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();

            let Ok(gid_raw) = B64.decode(group_id_b64.as_bytes()) else {
                return (400, json!({"error": "bad_gid"}));
            };
            let Ok(gid): Result<[u8; MP_GROUP_ID_LEN], _> = gid_raw.try_into() else {
                return (400, json!({"error": "bad_gid_len"}));
            };
            let Ok(csha): Result<[u8; 32], _> = B64
                .decode(commit_sha_b64.as_bytes())
                .unwrap_or_default()
                .try_into()
            else {
                return (400, json!({"error": "bad_commit_sha"}));
            };
            let Ok(ahash): Result<[u8; 32], _> = B64
                .decode(auth_hash_b64.as_bytes())
                .unwrap_or_default()
                .try_into()
            else {
                return (400, json!({"error": "bad_auth_hash"}));
            };
            let Ok(sig): Result<[u8; 64], _> = B64
                .decode(ack_sig_b64.as_bytes())
                .unwrap_or_default()
                .try_into()
            else {
                return (400, json!({"error": "bad_ack_sig"}));
            };
            let Ok(status) = AckStatus::from_u8(status_u8) else {
                return (400, json!({"error": "bad_ack_status"}));
            };

            let ack = CommitAckV1 {
                group_id: gid,
                parent_epoch,
                target_epoch,
                commit_sha256: csha,
                account_id: caller_acc,
                device_id: caller_dev,
                status,
                epoch_auth_hash: Some(ahash),
                ack_sig: sig,
            };
            let now_s = u64::try_from(wall_now_secs()).unwrap_or(0);
            let Some(ref mut ds) = st.ds else {
                return (409, json!({"error": "mls_not_initialized"}));
            };
            match ds.record_commit_ack(&ack, now_s) {
                Ok(QuorumOutcome::Finalized { new_epoch, .. }) => {
                    let commit_b64 = st.tentative_commit_b64.take().unwrap_or_default();
                    let proposals_b64 = std::mem::take(&mut st.tentative_proposals_b64);
                    st.pending_proposals_b64.clear();
                    st.recorded_quorum_acks
                        .push((caller_acc, caller_dev, new_epoch));
                    st.broadcast_json(json!({
                        "v": 2,
                        "t": "mls_commit_finalized",
                        "party_id": TEST_PARTY_ID.to_string(),
                        "group_id_b64": group_id_b64,
                        "epoch": new_epoch,
                        "commit_sha256_b64": commit_sha_b64,
                        "commit_blob_b64": commit_b64,
                        "proposals_b64": proposals_b64,
                    }));
                    (
                        200,
                        json!({
                            "finalized": true,
                            "outcome": "finalized",
                            "discarded": false,
                            "current_epoch": new_epoch,
                        }),
                    )
                }
                Ok(QuorumOutcome::Pending { .. }) => {
                    st.recorded_quorum_acks
                        .push((caller_acc, caller_dev, target_epoch));
                    (
                        200,
                        json!({
                            "finalized": false,
                            "outcome": "pending",
                            "discarded": false,
                            "current_epoch": parent_epoch,
                        }),
                    )
                }
                Ok(QuorumOutcome::Discarded { .. }) => {
                    st.tentative_commit_b64 = None;
                    st.tentative_proposals_b64.clear();
                    st.broadcast_json(json!({
                        "v": 2,
                        "t": "mls_commit_discarded",
                        "party_id": TEST_PARTY_ID.to_string(),
                        "reason": "rejected",
                    }));
                    (
                        200,
                        json!({
                            "finalized": false,
                            "outcome": "discarded",
                            "discarded": true,
                            "current_epoch": parent_epoch,
                        }),
                    )
                }
                Err(e) => (409, json!({"error": format!("ack_failed: {e}")})),
            }
        }
        ("GET", p) if p == format!("{party_prefix}/mls/welcome") => {
            let ds_pk_b64 = B64.encode(st.ds_pubkey);
            let current_epoch = st.ds.as_ref().map_or(0, MpMlsPublicDs::epoch);
            // Only release a Welcome once its target_epoch has been FINALIZED on DS!
            if let Some(w) = st
                .pending_welcomes
                .iter()
                .find(|w| {
                    w.target_device_id == caller_dev
                        && !w.acked
                        && w.target_epoch <= current_epoch
                })
                .cloned()
            {
                (
                    200,
                    json!({
                        "party_ds_pubkey_b64": ds_pk_b64,
                        "group_id_b64": w.group_id_b64,
                        "welcome": {
                            "welcome_id": w.welcome_id,
                            "mls_epoch": w.target_epoch,
                            "group_id_b64": w.group_id_b64,
                            "kp_ref_b64": w.kp_ref_b64,
                            "welcome_b64": w.welcome_b64,
                            "welcome_auth_b64": w.welcome_auth_b64,
                        }
                    }),
                )
            } else {
                (
                    200,
                    json!({
                        "party_ds_pubkey_b64": ds_pk_b64,
                        "group_id_b64": st.group_id.map(|g| B64.encode(g)),
                        "welcome": null,
                    }),
                )
            }
        }
        ("POST", p) if p == format!("{party_prefix}/mls/welcome/ack") => {
            let wid = body_json.get("welcome_id").and_then(Value::as_u64);
            for w in &mut st.pending_welcomes {
                if w.target_device_id == caller_dev
                    && (wid.is_none() || wid == Some(w.welcome_id))
                {
                    w.acked = true;
                }
            }
            (200, json!({"ok": true, "acked": true}))
        }
        ("GET", p) if p == format!("{party_prefix}/mls/commits") => {
            let from_epoch = req
                .query
                .split('&')
                .find_map(|kv| kv.strip_prefix("from_epoch="))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1);
            let Some(ref ds) = st.ds else {
                return (200, json!({"commits": [], "current_epoch": 0}));
            };
            let bundles = ds.get_catchup_commits(from_epoch, 32).unwrap_or_default();
            let commits: Vec<Value> = bundles
                .into_iter()
                .map(|b| {
                    let props: Vec<String> =
                        b.referenced_proposals.iter().map(|p| B64.encode(p)).collect();
                    json!({
                        "mls_epoch": b.epoch,
                        "commit_blob_b64": B64.encode(&b.commit_blob),
                        "proposals_b64": props,
                    })
                })
                .collect();
            (
                200,
                json!({
                    "current_epoch": ds.epoch(),
                    "commits": commits,
                }),
            )
        }
        ("GET", p) if p == format!("{party_prefix}/mls/device-lists") => {
            let lists: Vec<Value> = st
                .accounts
                .values()
                .filter(|a| !a.device_list_b64.is_empty())
                .map(|a| {
                    json!({
                        "account_id": a.account_id.to_string(),
                        "list_version": a.list_version,
                        "list_b64": a.device_list_b64,
                    })
                })
                .collect();
            (200, json!({"device_lists": lists}))
        }
        ("GET", p) if p == format!("{party_prefix}/mls/proposals/pending") => {
            let mls_epoch = st.ds.as_ref().map_or(0, MpMlsPublicDs::epoch);
            let rekey = st
                .ds
                .as_ref()
                .is_some_and(MpMlsPublicDs::mls_rekey_required);
            (
                200,
                json!({
                    "mls_epoch": mls_epoch,
                    "min_allowed_mls_epoch": mls_epoch.saturating_sub(2),
                    "mls_rekey_required": rekey,
                    "proposals_b64": st.pending_proposals_b64,
                }),
            )
        }
        ("GET", p) if p == format!("{party_prefix}/mls/key-packages") => {
            let items: Vec<Value> = st
                .pending_kps
                .iter()
                .map(|k| {
                    json!({
                        "kp_id": k.kp_id,
                        "account_id": k.account_id.to_string(),
                        "device_id": k.device_id.to_string(),
                        "invite_id": k.invite_id,
                        "kp_ref_b64": k.kp_ref_b64,
                        "kp_blob_b64": k.kp_blob_b64,
                        "join_proof_b64": k.join_proof_b64,
                    })
                })
                .collect();
            (200, json!({"key_packages": items}))
        }
        _ => (404, json!({"error": "not_found", "path": req.path})),
    }
}

async fn make_test_daemon(
    pki: &TestPki,
    addr: SocketAddr,
    account_id: u64,
    device_id: u64,
    handle: &str,
    root_secret: [u8; 32],
    device_secret: [u8; 32],
) -> Result<(tempfile::TempDir, Arc<AppDaemon>), String> {
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let state_path = tmp.path().join("state");
    let root_sk = SigningKey::from_bytes(&root_secret);
    let dev_sk = SigningKey::from_bytes(&device_secret);
    let root_pk = root_sk.verifying_key().to_bytes();
    let dev_pk = dev_sk.verifying_key().to_bytes();
    let now = wall_now_secs();
    let cwt = encode_device_cwt(&root_sk, &dev_pk, now, now + 86_400)
        .map_err(|e| format!("encode cwt: {e}"))?;

    let rec = DeviceRecord {
        account_id,
        device_id,
        root_pubkey: root_pk,
        device_secret,
        device_pubkey: dev_pk,
        device_cwt: cwt,
        local_relay_policy: RelayPolicy::AllowRelays,
        api_authority: TEST_AUTHORITY.to_string(),
        default_relay_url: "https://relay.multiplayer.tech".to_string(),
        device_label: format!("{handle}-{device_id}"),
    };
    {
        let sd = open_state_dir(&state_path)?;
        let lock = lock_state(&sd)?;
        save_device_record(&state_path, &lock, &rec)?;
    }

    let daemon = AppDaemon::load_with_options(state_path, None, device_id, false)?;
    let cfg = ControlClientConfig::new(TEST_AUTHORITY)
        .map_err(|e| e.to_string())?
        .with_tls_config(Arc::clone(&pki.client_tls13))
        .with_connect_addr(addr)
        .with_request_timeout(Duration::from_secs(5));
    let signer = RequestSigner::device(
        AccountId::new(account_id).map_err(|e| e.to_string())?,
        DeviceId::new(device_id).map_err(|e| e.to_string())?,
        device_secret,
    );
    let control = ControlClient::with_device_signer(cfg, signer);
    {
        let mut st = daemon.inner.lock().await;
        st.control = control;
        st.own_handle = handle.to_string();
    }
    Ok((tmp, daemon))
}

async fn wait_until<F, Fut>(timeout: Duration, mut pred: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if pred().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn daemon_mls_epoch_and_connected(d: &AppDaemon) -> Option<(u64, bool)> {
    let st = d.inner.lock().await;
    let sess = st.active_party.as_ref()?;
    let mls = sess.mls_session.as_ref()?;
    Some((mls.epoch(), sess.mp2_connected))
}

async fn poll_all_events(d: &AppDaemon, party_id: u64) -> Vec<IpcPartyEventKind> {
    let req = encode_party_poll_req(&PartyPollIpcReq {
        party_id,
        cursor_epoch: 0,
        after_seq: 0,
        limit: 100,
        max_bytes: 262_144,
        board_only: false,
    });
    let Ok(raw) = d.op_party_poll(&req).await else {
        return Vec::new();
    };
    let Ok(resp) = decode_party_poll_resp(&raw) else {
        return Vec::new();
    };
    resp.events.into_iter().map(|e| e.kind).collect()
}

#[tokio::test]
async fn live_mls_e2ee_same_account_sibling_cross_account_quorum_ack_and_cloud_bind()
-> Result<(), String> {
    let pki = generate_test_pki();
    let ds_secret = [0x99u8; 32];
    let ds_state = Arc::new(Mutex::new(MockDsState::new(ds_secret)));

    let alice_root = [0x11u8; 32];
    let bob_root = [0x22u8; 32];
    let charlie_root = [0x33u8; 32];
    {
        let mut st = ds_state.lock().map_err(|_| "lock poisoned".to_string())?;
        st.register_account(1001, "alice", alice_root);
        st.register_account(1002, "bob", bob_root);
        st.register_account(1003, "charlie", charlie_root);
    }

    let addr = spawn_mock_ds_server(&pki, Arc::clone(&ds_state)).await;

    // 4 real AppDaemons with NO pre-populated `identity.mls.bin` (tests automatic cloud-bind!):
    // - Machine A (`1001/2001`, `@alice`)
    // - Machine B (`1001/2002`, `@alice` — SAME ACCOUNT sibling device!)
    // - Bob       (`1002/2003`, `@bob`)
    // - Charlie   (`1003/2004`, `@charlie`)
    let (_tmp_a, alice_a) =
        make_test_daemon(&pki, addr, 1001, 2001, "alice", alice_root, [0xA1; 32]).await?;
    let (_tmp_b, alice_b) =
        make_test_daemon(&pki, addr, 1001, 2002, "alice", alice_root, [0xA2; 32]).await?;
    let (_tmp_bob, bob) =
        make_test_daemon(&pki, addr, 1002, 2003, "bob", bob_root, [0xB1; 32]).await?;
    let (_tmp_charlie, charlie) =
        make_test_daemon(&pki, addr, 1003, 2004, "charlie", charlie_root, [0xC1; 32]).await?;

    // =========================================================================
    // 1. Machine A creates an `e2ee_mode = 1` room via `op_room_invite`!
    //    Verifies automatic `cloud-bind`, epoch-0 OpenMLS bootstrap, encrypted
    //    snapshot persistence (0600), and `#<InviteFragmentV2_b64u>` minting.
    // =========================================================================
    let inv_req = encode_room_invite_req(&RoomInviteIpcReq {
        handle: None,
        party_id: None,
        name: Some("Live MLS Room".to_string()),
    })
    .map_err(|e| e.to_string())?;
    let inv_raw = alice_a
        .op_room_invite(&inv_req)
        .await
        .map_err(|e| format!("alice_a op_room_invite failed: {}", e.2))?;
    let inv_resp = decode_room_invite_resp(&inv_raw).map_err(|e| e.to_string())?;
    assert_eq!(inv_resp.party_id, TEST_PARTY_ID);

    // Share URL MUST embed a valid 114-byte InviteFragmentV2 after `#`!
    let (_base_url, frag_b64u) = inv_resp
        .share_url
        .split_once('#')
        .ok_or_else(|| format!("expected #InviteFragmentV2 in share_url: {}", inv_resp.share_url))?;
    let parsed_frag = InviteFragmentV2::decode_b64url(frag_b64u)
        .map_err(|e| format!("invalid InviteFragmentV2: {e}"))?;
    assert_eq!(parsed_frag.invite_id, 101);

    // Wait for Machine A to connect `mp2` WS at epoch 0 (both client and server-side registered)!
    assert!(
        wait_until(Duration::from_secs(25), || async {
            let on_server = ds_state
                .lock()
                .is_ok_and(|st| st.online_ws_devices.contains(&(1001, 2001)));
            on_server && daemon_mls_epoch_and_connected(&alice_a).await == Some((0, true))
        })
        .await,
        "Machine A should be connected to mp2 WS at MLS epoch 0"
    );

    // Verify encrypted identity + room snapshot files exist on disk with mode 0600!
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mls_dir = alice_a
            .state_dir_path
            .join("mls")
            .join(format!("d{:013x}", 2001u64));
        let id_meta = std::fs::metadata(mls_dir.join("identity.mls.bin"))
            .map_err(|e| format!("missing identity.mls.bin: {e}"))?;
        assert_eq!(id_meta.permissions().mode() & 0o777, 0o600);
        let snap_meta = std::fs::metadata(mls_dir.join(format!("p{:013x}.mls.bin", TEST_PARTY_ID)))
            .map_err(|e| format!("missing room snapshot: {e}"))?;
        assert_eq!(snap_meta.permissions().mode() & 0o777, 0o600);
    }

    // =========================================================================
    // 2. FAIL-CLOSED PLAINTEXT REFUSAL ORACLE:
    //    Before Machine B finishes MLS Welcome join, sending MUST fail closed
    //    and NEVER downgrade to plaintext `kind: "chat"`!
    // =========================================================================
    let enter_b_req = encode_room_enter_req(&RoomEnterIpcReq {
        target: TEST_PARTY_ID.to_string(),
        agent_name: None,
    })
    .map_err(|e| e.to_string())?;
    let enter_b_raw = alice_b
        .op_room_enter(&enter_b_req)
        .await
        .map_err(|e| format!("alice_b op_room_enter failed: {}", e.2))?;
    let enter_b_resp = decode_room_enter_resp(&enter_b_raw).map_err(|e| e.to_string())?;
    assert_eq!(enter_b_resp.party_id, TEST_PARTY_ID);

    // Verify fail-closed refusal while `mls_session` is None (test via a fresh temporary state check)
    {
        let mut st = alice_b.inner.lock().await;
        if let Some(ref sess) = st.active_party
            && sess.mls_session.is_none()
        {
            drop(st);
            let early_req = encode_party_send_chat_req(&PartySendChatReq {
                party_id: TEST_PARTY_ID,
                client_msg_id: 9001,
                room_scope: "party/main".to_string(),
                target_device_id: None,
                body: "MUST_NEVER_SEND_PLAINTEXT".to_string(),
            })
            .map_err(|e| e.to_string())?;
            let err = alice_b.op_party_send_chat(1, &early_req).await;
            assert!(
                matches!(err, Err((code, _, _)) if code == ERR_CONFLICT),
                "send before MLS Welcome join MUST fail closed with ERR_CONFLICT"
            );
        } else {
            let _ = &mut st;
        }
    }

    // =========================================================================
    // 3. SAME-ACCOUNT MULTI-DEVICE SIBLING JOIN (Machine A + Machine B under `@alice`)!
    //    Machine B submits KP via `POST /mls/join` (NO invite link!) -> Machine A
    //    auto-commits sibling Add + sibling `WelcomeAuthV1` -> Machine B installs
    //    Welcome and connects `mp2` WS at epoch 1!
    // =========================================================================
    let epoch1_ok = wait_until(Duration::from_secs(25), || async {
        daemon_mls_epoch_and_connected(&alice_a).await == Some((1, true))
            && daemon_mls_epoch_and_connected(&alice_b).await == Some((1, true))
    })
    .await;
    if !epoch1_ok {
        let a_st = daemon_mls_epoch_and_connected(&alice_a).await;
        let b_st = daemon_mls_epoch_and_connected(&alice_b).await;
        let (ds_ep, kps, wels) = ds_state
            .lock()
            .map(|st| {
                (
                    st.ds.as_ref().map(MpMlsPublicDs::epoch),
                    st.pending_kps.len(),
                    st.pending_welcomes.len(),
                )
            })
            .unwrap_or((None, 0, 0));
        return Err(format!(
            "Machine A and sibling Machine B failed to reach MLS epoch 1 (a={a_st:?}, b={b_st:?}, ds_epoch={ds_ep:?}, pending_kps={kps}, pending_welcomes={wels})"
        ));
    }

    // Bidirectional encrypted `e2ee_app` chat + IRC action + agent card between Machine A & B!
    let msg_a_to_b = encode_party_send_chat_req(&PartySendChatReq {
        party_id: TEST_PARTY_ID,
        client_msg_id: 1001,
        room_scope: "party/main".to_string(),
        target_device_id: None,
        body: "hello sibling from laptop".to_string(),
    })
    .map_err(|e| e.to_string())?;
    alice_a
        .op_party_send_chat(1, &msg_a_to_b)
        .await
        .map_err(|e| format!("alice_a send chat failed: {}", e.2))?;

    let irc_me_a = encode_party_send_chat_req(&PartySendChatReq {
        party_id: TEST_PARTY_ID,
        client_msg_id: 1002,
        room_scope: "party/main".to_string(),
        target_device_id: None,
        body: r#"{"mp_irc":1,"t":"me","text":"deploys build-01"}"#.to_string(),
    })
    .map_err(|e| e.to_string())?;
    alice_a
        .op_party_send_chat(1, &irc_me_a)
        .await
        .map_err(|e| format!("alice_a send irc action failed: {}", e.2))?;

    let card_a = encode_party_post_board_req(&PartyPostBoardReq {
        party_id: TEST_PARTY_ID,
        client_msg_id: 1003,
        room_scope: "party/main".to_string(),
        payload: br#"{"title":"Lane C E2EE","summary":"MLS live pump green","status":"done"}"#
            .to_vec(),
    })
    .map_err(|e| e.to_string())?;
    alice_a
        .op_party_post_board(1, &card_a)
        .await
        .map_err(|e| format!("alice_a post card failed: {}", e.2))?;

    let msg_b_to_a = encode_party_send_chat_req(&PartySendChatReq {
        party_id: TEST_PARTY_ID,
        client_msg_id: 2001,
        room_scope: "party/main".to_string(),
        target_device_id: None,
        body: "ack from build-01".to_string(),
    })
    .map_err(|e| e.to_string())?;
    alice_b
        .op_party_send_chat(1, &msg_b_to_a)
        .await
        .map_err(|e| format!("alice_b send chat failed: {}", e.2))?;

    // Verify Machine B received & decrypted Machine A's chat, IRC action, AND agent card!
    assert!(
        wait_until(Duration::from_secs(25), || async {
            let evs = poll_all_events(&alice_b, TEST_PARTY_ID).await;
            let got_chat = evs.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::Chat { provenance, body, .. }
                        if provenance.sender_account_id == 1001
                            && provenance.sender_device_id == 2001
                            && body == "hello sibling from laptop"
                )
            });
            let got_irc = evs.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::Chat { body, .. }
                        if body == r#"{"mp_irc":1,"t":"me","text":"deploys build-01"}"#
                )
            });
            let got_card = evs.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::BridgeEnvelope { provenance, payload, .. }
                        if provenance.sender_device_id == 2001
                            && core::str::from_utf8(payload)
                                .is_ok_and(|s| s.contains("Lane C E2EE"))
                )
            });
            got_chat && got_irc && got_card
        })
        .await,
        "Sibling Machine B must decrypt Machine A's chat, encrypted IRC action, and agent card"
    );

    // Verify Machine A received & decrypted Machine B's reply!
    assert!(
        wait_until(Duration::from_secs(25), || async {
            let evs = poll_all_events(&alice_a, TEST_PARTY_ID).await;
            evs.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::Chat { provenance, body, .. }
                        if provenance.sender_account_id == 1001
                            && provenance.sender_device_id == 2002
                            && body == "ack from build-01"
                )
            })
        })
        .await,
        "Machine A must decrypt sibling Machine B's reply"
    );

    // =========================================================================
    // 4. CROSS-ACCOUNT INVITE JOIN (`@bob` `1002/2003` via `#<InviteFragmentV2_b64u>`)
    //    Proves fragment seed NEVER hits `/v1/rooms/enter`, proves split-secret
    //    `join_proof` + `WelcomeAuthV1`, advances to epoch 2!
    // =========================================================================
    let enter_bob_req = encode_room_enter_req(&RoomEnterIpcReq {
        target: inv_resp.share_url.clone(),
        agent_name: None,
    })
    .map_err(|e| e.to_string())?;
    bob.op_room_enter(&enter_bob_req)
        .await
        .map_err(|e| format!("bob op_room_enter failed: {}", e.2))?;

    assert!(
        wait_until(Duration::from_secs(25), || async {
            daemon_mls_epoch_and_connected(&alice_a).await == Some((2, true))
                && daemon_mls_epoch_and_connected(&alice_b).await == Some((2, true))
                && daemon_mls_epoch_and_connected(&bob).await == Some((2, true))
        })
        .await,
        "Alice A, Alice B, and Bob should all reach MLS epoch 2"
    );

    // Fragment privacy oracle: `#` / `frag_b64u` MUST NEVER appear in `/v1/rooms/enter`!
    {
        let st = ds_state.lock().map_err(|_| "lock poisoned".to_string())?;
        for t in &st.recorded_enter_targets {
            assert!(
                !t.contains('#') && !t.contains(frag_b64u),
                "invite_seed fragment leaked to /v1/rooms/enter: {t}"
            );
        }
    }

    let msg_bob = encode_party_send_chat_req(&PartySendChatReq {
        party_id: TEST_PARTY_ID,
        client_msg_id: 3001,
        room_scope: "party/main".to_string(),
        target_device_id: None,
        body: "hello from @bob".to_string(),
    })
    .map_err(|e| e.to_string())?;
    bob.op_party_send_chat(1, &msg_bob)
        .await
        .map_err(|e| format!("bob send chat failed: {}", e.2))?;

    assert!(
        wait_until(Duration::from_secs(25), || async {
            let ev_a = poll_all_events(&alice_a, TEST_PARTY_ID).await;
            let ev_b = poll_all_events(&alice_b, TEST_PARTY_ID).await;
            let ok_a = ev_a.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::Chat { provenance, body, .. }
                        if provenance.sender_account_id == 1002
                            && provenance.sender_device_id == 2003
                            && body == "hello from @bob"
                )
            });
            let ok_b = ev_b.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::Chat { provenance, body, .. }
                        if provenance.sender_account_id == 1002
                            && body == "hello from @bob"
                )
            });
            ok_a && ok_b
        })
        .await,
        "Both Machine A and Machine B must decrypt Bob's cross-account message"
    );

    // =========================================================================
    // 5. MULTI-ACCOUNT QUORUM `CommitAckV1` (`mp-mls-ack-v1:`):
    //    `@charlie` (`1003/2004`) joins while Alice (1001) AND Bob (1002) are online!
    //    Alice A commits -> DS holds TENTATIVE commit -> Bob signs `CommitAckV1`
    //    and submits `POST /mls/ack` -> DS finalizes epoch 3 -> Charlie joins!
    // =========================================================================
    let enter_charlie_req = encode_room_enter_req(&RoomEnterIpcReq {
        target: inv_resp.share_url.clone(),
        agent_name: None,
    })
    .map_err(|e| e.to_string())?;
    charlie
        .op_room_enter(&enter_charlie_req)
        .await
        .map_err(|e| format!("charlie op_room_enter failed: {}", e.2))?;

    assert!(
        wait_until(Duration::from_secs(25), || async {
            daemon_mls_epoch_and_connected(&alice_a).await == Some((3, true))
                && daemon_mls_epoch_and_connected(&alice_b).await == Some((3, true))
                && daemon_mls_epoch_and_connected(&bob).await == Some((3, true))
                && daemon_mls_epoch_and_connected(&charlie).await == Some((3, true))
        })
        .await,
        "All 4 devices across 3 accounts should reach MLS epoch 3 after Bob's quorum CommitAckV1"
    );

    // Verify Bob (`account_id = 1002, device_id = 2003`) actually signed & submitted `CommitAckV1`!
    {
        let st = ds_state.lock().map_err(|_| "lock poisoned".to_string())?;
        assert!(
            st.recorded_quorum_acks
                .iter()
                .any(|&(acc, dev, ep)| acc == 1002 && dev == 2003 && ep == 3),
            "expected verified CommitAckV1 from Bob (1002/2003) for epoch 3, got {:?}",
            st.recorded_quorum_acks
        );
        // Verify all 4 devices used automatic cloud-bind!
        assert_eq!(st.recorded_cloud_binds.len(), 4);
    }

    let msg_charlie = encode_party_send_chat_req(&PartySendChatReq {
        party_id: TEST_PARTY_ID,
        client_msg_id: 4001,
        room_scope: "party/main".to_string(),
        target_device_id: None,
        body: "charlie after quorum ack".to_string(),
    })
    .map_err(|e| e.to_string())?;
    charlie
        .op_party_send_chat(1, &msg_charlie)
        .await
        .map_err(|e| format!("charlie send chat failed: {}", e.2))?;

    assert!(
        wait_until(Duration::from_secs(25), || async {
            let ev_bob = poll_all_events(&bob, TEST_PARTY_ID).await;
            ev_bob.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::Chat { provenance, body, .. }
                        if provenance.sender_account_id == 1003
                            && body == "charlie after quorum ack"
                )
            })
        })
        .await,
        "Bob must decrypt Charlie's post-quorum message"
    );

    // =========================================================================
    // 6. EXTERNAL REMOVE PROPOSAL (`mls_rekey_needed`) & POST-EVICTION SECRECY!
    //    DS creates a signed RFC 9420 External Remove for Charlie's leaf ->
    //    elects Machine A (`2001`) -> Machine A commits removal -> Bob ACKs ->
    //    DS finalizes epoch 4 -> post-eviction chat decrypts on Bob, NOT Charlie!
    // =========================================================================
    {
        let mut st = ds_state.lock().map_err(|_| "lock poisoned".to_string())?;
        let ds_secret_copy = st.ds_secret;
        let ds = st
            .ds
            .as_mut()
            .ok_or_else(|| "missing ds".to_string())?;
        let leaves = extract_public_group_leaves(ds.public_group())
            .map_err(|e| format!("extract leaves: {e}"))?;
        let charlie_leaf_idx = leaves
            .iter()
            .find_map(|(&idx, info)| {
                (info.cred.binding.body.device_id == 2004).then_some(idx)
            })
            .ok_or_else(|| "charlie leaf not found".to_string())?;
        let (_prop_ref, prop_blob) = ds
            .create_external_remove(
                LeafNodeIndex::new(charlie_leaf_idx),
                &ds_secret_copy,
            )
            .map_err(|e| format!("create_external_remove: {e}"))?;
        let prop_b64 = B64.encode(&prop_blob);
        let mls_epoch = ds.epoch();
        let gid_b64 = B64.encode(ds.group_id());
        st.pending_proposals_b64.push(prop_b64.clone());
        st.broadcast_json(json!({
            "v": 2,
            "t": "mls_rekey_needed",
            "party_id": TEST_PARTY_ID.to_string(),
            "group_id_b64": gid_b64,
            "mls_epoch": mls_epoch,
            "min_allowed_mls_epoch": mls_epoch.saturating_add(1),
            "reason": "member_kicked",
            "proposals_b64": [prop_b64],
            "elected_committer_device_id": "2001",
        }));
    }

    assert!(
        wait_until(Duration::from_secs(25), || async {
            daemon_mls_epoch_and_connected(&alice_a).await == Some((4, true))
                && daemon_mls_epoch_and_connected(&bob).await == Some((4, true))
        })
        .await,
        "Alice A and Bob should finalize ExternalRemove eviction to MLS epoch 4"
    );

    let post_evict_msg = encode_party_send_chat_req(&PartySendChatReq {
        party_id: TEST_PARTY_ID,
        client_msg_id: 5001,
        room_scope: "party/main".to_string(),
        target_device_id: None,
        body: "TOP_SECRET_AFTER_CHARLIE_EVICTED".to_string(),
    })
    .map_err(|e| e.to_string())?;
    alice_a
        .op_party_send_chat(1, &post_evict_msg)
        .await
        .map_err(|e| format!("alice_a post-evict send failed: {}", e.2))?;

    assert!(
        wait_until(Duration::from_secs(25), || async {
            let ev_bob = poll_all_events(&bob, TEST_PARTY_ID).await;
            ev_bob.iter().any(|k| {
                matches!(
                    k,
                    IpcPartyEventKind::Chat { body, .. }
                        if body == "TOP_SECRET_AFTER_CHARLIE_EVICTED"
                )
            })
        })
        .await,
        "Bob must decrypt post-eviction epoch-4 message"
    );

    // Charlie MUST NOT be able to decrypt the post-eviction epoch-4 message!
    tokio::time::sleep(Duration::from_millis(150)).await;
    let charlie_evs = poll_all_events(&charlie, TEST_PARTY_ID).await;
    assert!(
        !charlie_evs.iter().any(|k| matches!(
            k,
            IpcPartyEventKind::Chat { body, .. } if body == "TOP_SECRET_AFTER_CHARLIE_EVICTED"
        )),
        "Evicted Charlie MUST NEVER decrypt post-eviction epoch-4 messages!"
    );

    // =========================================================================
    // 7. WIRE SECRECY & EXACT BUCKET SIZE ORACLE:
    //    Inspect EVERY outbound frame recorded by the server!
    // =========================================================================
    {
        let st = ds_state.lock().map_err(|_| "lock poisoned".to_string())?;
        assert!(
            st.recorded_ws_sends.len() >= 7,
            "expected at least 7 encrypted e2ee_app frames, got {}",
            st.recorded_ws_sends.len()
        );
        for frame in &st.recorded_ws_sends {
            assert!(frame.sender_account_id > 0 && frame.sender_device_id > 0);
            assert_eq!(frame.kind, "e2ee_app", "ONLY e2ee_app frames allowed in E2EE room");
            assert_eq!(frame.target, "*", "outer target MUST be '*' in E2EE room");
            assert_eq!(
                frame.body_encoding, "opaque_b64",
                "outer body_encoding MUST be 'opaque_b64'"
            );
            assert!(frame.mls_epoch.is_some(), "mls_epoch MUST be present");
            let wire_bytes = B64
                .decode(frame.body.as_bytes())
                .map_err(|_| "recorded body not valid base64".to_string())?;
            assert!(
                WIRE_BUCKETS.contains(&wire_bytes.len()),
                "wire frame length {} is NOT in exact WIRE_BUCKETS {:?}",
                wire_bytes.len(),
                WIRE_BUCKETS
            );
            for forbidden in [
                "hello sibling",
                "deploys build-01",
                "Lane C E2EE",
                "ack from build-01",
                "hello from @bob",
                "charlie after quorum ack",
                "TOP_SECRET_AFTER_CHARLIE_EVICTED",
                "MUST_NEVER_SEND_PLAINTEXT",
            ] {
                assert!(
                    !frame.body.contains(forbidden),
                    "plaintext secret '{forbidden}' leaked on wire!"
                );
            }
        }
    }

    // Cleanly shut down all 4 daemons so background tasks exit promptly.
    alice_a.shutdown.cancel();
    alice_b.shutdown.cancel();
    bob.shutdown.cancel();
    charlie.shutdown.cancel();
    Ok(())
}
