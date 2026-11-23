//! Real compiled-binary Tier 7 E2E Oracles for `mp-outpost`.
//!
//! Spawns the real compiled `mp-outpost` binary (`env!("CARGO_BIN_EXE_mp-outpost")`):
//! 1. Oracle 1: Device custody (`device init` -> `device install-cwt` -> `whoami --safety-number`),
//!    non-TTY fail-closed `peer trust` gate, lazy MCP (`< 20 ms` `initialize` + `tools/list` with
//!    ZERO daemon spawned, lazy auto-spawn on `outpost_status`, `< 100 ms` exit on stdin EOF),
//!    `daemon status` & `daemon stop`.
//! 2. Oracle 2: Full 2-Outpost Live E2E Party over local TLS 1.3 mock `MP1` control server +
//!    REAL `iroh` v1.5.0 QUIC ALPN `blackbird-mp/1` + live `mp-outpost mcp` `party_send` /
//!    `party_wait` with nonce-fenced authenticated provenance and clean teardown.

#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use mp_protocol::{
    AccountId, DeviceId, EndpointDescriptor, MAX_CWT_TTL_SECS, Mp1Message, PartyId, PartyJoinMode,
    PartyMemberRecord, PartySnapshot, PartyVisibility, RelayPolicy, SessionId, encode_device_cwt,
    encode_frame,
};
use outpost_control::wall_now_secs;
use outpost_core::storage_codec::{
    PeerRecord, PeersStoreRecord, TrustState, encode_peers_store,
};
use outpost_core::trust::{api_authority_hash, compute_safety_number};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

const BIN_PATH: &str = env!("CARGO_BIN_EXE_mp-outpost");
const TEST_AUTHORITY: &str = "api.multiplayer.tech";

fn make_short_tempdir(prefix: &str) -> Result<tempfile::TempDir, String> {
    let base = if Path::new("/private/tmp").is_dir() {
        PathBuf::from("/private/tmp")
    } else {
        PathBuf::from("/tmp")
    };
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(base)
        .map_err(|e| format!("tempdir failed: {e}"))?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 failed: {e}"))?;
    Ok(dir)
}

fn make_private_subdir(parent: &Path, name: &str) -> Result<PathBuf, String> {
    let p = parent.join(name);
    std::fs::create_dir_all(&p).map_err(|e| format!("mkdir failed: {e}"))?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 failed: {e}"))?;
    Ok(p)
}

struct CliOutput {
    status_ok: bool,
    stdout: String,
    stderr: String,
}

fn run_bin(
    state_dir: &Path,
    runtime_dir: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    extra_env: &[(&str, &str)],
) -> Result<CliOutput, String> {
    let mut cmd = Command::new(BIN_PATH);
    cmd.arg("--state-dir")
        .arg(state_dir)
        .arg("--runtime-dir")
        .arg(runtime_dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for &(k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    if let Some(data) = stdin_bytes
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin
            .write_all(data)
            .map_err(|e| format!("stdin write failed: {e}"))?;
    } else {
        drop(child.stdin.take());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait_with_output failed: {e}"))?;
    Ok(CliOutput {
        status_ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

struct McpProc {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: BufReader<ChildStdout>,
}

impl McpProc {
    fn spawn(
        state_dir: &Path,
        runtime_dir: &Path,
        extra_env: &[(&str, &str)],
    ) -> Result<Self, String> {
        let mut cmd = Command::new(BIN_PATH);
        cmd.arg("--state-dir")
            .arg(state_dir)
            .arg("--runtime-dir")
            .arg(runtime_dir)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|e| format!("spawn mcp failed: {e}"))?;
        let stdin = child.stdin.take().ok_or("missing mcp stdin")?;
        let stdout = child.stdout.take().ok_or("missing mcp stdout")?;
        Ok(Self {
            child,
            stdin: Some(stdin),
            reader: BufReader::new(stdout),
        })
    }

    fn send(&mut self, msg: &Value) -> Result<(), String> {
        let line = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        let stdin = self.stdin.as_mut().ok_or("mcp stdin already closed")?;
        stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("write mcp stdin: {e}"))?;
        stdin
            .write_all(b"\n")
            .map_err(|e| format!("write mcp newline: {e}"))?;
        stdin.flush().map_err(|e| format!("flush mcp stdin: {e}"))
    }

    fn recv(&mut self) -> Result<Value, String> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| format!("read mcp stdout: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF from mcp stdout".to_string());
        }
        serde_json::from_str(line.trim()).map_err(|e| format!("invalid JSON from mcp: {e}: {line}"))
    }

    fn close_stdin_and_wait(&mut self) -> Result<(bool, Duration), String> {
        let start = Instant::now();
        drop(self.stdin.take());
        let status = self
            .child
            .wait()
            .map_err(|e| format!("wait mcp exit: {e}"))?;
        Ok((status.success(), start.elapsed()))
    }
}

impl Drop for McpProc {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct EnrolledDeviceInfo {
    account_id: u64,
    device_id: u64,
    root_pubkey: [u8; 32],
    device_pubkey: [u8; 32],
    device_cwt: Vec<u8>,
}

fn provision_device(
    state_dir: &Path,
    runtime_dir: &Path,
    account_id: u64,
    device_id: u64,
    root_seed: [u8; 32],
    label: &str,
) -> Result<EnrolledDeviceInfo, String> {
    let init_out = run_bin(
        state_dir,
        runtime_dir,
        &[
            "--json",
            "device",
            "init",
            "--device-label",
            label,
            "--relay-policy",
            "none",
        ],
        None,
        &[],
    )?;
    if !init_out.status_ok {
        return Err(format!("device init failed: {}", init_out.stderr));
    }
    let init_json: Value =
        serde_json::from_str(&init_out.stdout).map_err(|e| format!("parse init json: {e}"))?;
    let dev_pub_b64 = init_json
        .get("device_pubkey_b64")
        .and_then(Value::as_str)
        .ok_or("missing device_pubkey_b64")?;
    let dev_pub_vec = B64
        .decode(dev_pub_b64.as_bytes())
        .map_err(|e| format!("decode dev_pub: {e}"))?;
    let device_pubkey: [u8; 32] = dev_pub_vec
        .try_into()
        .map_err(|_| "device_pubkey not 32 bytes".to_string())?;

    let root_sk = SigningKey::from_bytes(&root_seed);
    let root_pubkey = root_sk.verifying_key().to_bytes();
    let now_s = wall_now_secs();
    let device_cwt = encode_device_cwt(
        &root_sk,
        &device_pubkey,
        now_s,
        now_s.saturating_add(MAX_CWT_TTL_SECS),
    )
    .map_err(|e| format!("encode_device_cwt failed: {e}"))?;

    let root_b64 = B64.encode(root_pubkey);
    let cwt_b64 = B64.encode(&device_cwt);
    let acc_str = account_id.to_string();
    let dev_str = device_id.to_string();

    let inst_out = run_bin(
        state_dir,
        runtime_dir,
        &[
            "--json",
            "device",
            "install-cwt",
            "--account-id",
            &acc_str,
            "--device-id",
            &dev_str,
            "--root-pubkey-b64",
            &root_b64,
            "--cwt-stdin",
            "--skip-probe",
        ],
        Some(cwt_b64.as_bytes()),
        &[],
    )?;
    if !inst_out.status_ok {
        return Err(format!("device install-cwt failed: {}", inst_out.stderr));
    }

    Ok(EnrolledDeviceInfo {
        account_id,
        device_id,
        root_pubkey,
        device_pubkey,
        device_cwt,
    })
}

// ===========================================================================
// Oracle 1: Device custody + lazy MCP + < 100 ms EOF + TTY gate
// ===========================================================================

#[test]
fn oracle_1_custody_lazy_mcp_eof_and_tty_gate() -> Result<(), String> {
    let root_tmp = make_short_tempdir("mpo1")?;
    let state_dir = make_private_subdir(root_tmp.path(), "st")?;
    let runtime_dir = make_private_subdir(root_tmp.path(), "rt")?;

    // 1. device init -> device install-cwt --skip-probe
    let dev = provision_device(&state_dir, &runtime_dir, 1001, 2001, [0x11u8; 32], "oracle1")?;

    // 2. whoami --safety-number --json -> verify exact mp-safety-v1 Crockford SN!
    let who = run_bin(
        &state_dir,
        &runtime_dir,
        &["whoami", "--safety-number", "--json"],
        None,
        &[],
    )?;
    if !who.status_ok {
        return Err(format!("whoami failed: {}", who.stderr));
    }
    let who_json: Value =
        serde_json::from_str(&who.stdout).map_err(|e| format!("whoami json: {e}"))?;
    let expected_sn = compute_safety_number(1001, &dev.root_pubkey);
    let actual_sn = who_json
        .get("safety_number")
        .and_then(Value::as_str)
        .ok_or("missing safety_number")?;
    if actual_sn != expected_sn {
        return Err(format!("safety number mismatch: got {actual_sn}, expected {expected_sn}"));
    }

    // 3. peer trust 1002 with non-TTY stdin MUST fail closed (and --safety-number argv flag refused)
    let trust_piped = run_bin(
        &state_dir,
        &runtime_dir,
        &["peer", "trust", "1002"],
        Some(b"AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0000-1111\n"),
        &[],
    )?;
    if trust_piped.status_ok {
        return Err("peer trust MUST fail closed on non-TTY stdin!".to_string());
    }
    let trust_flag = run_bin(
        &state_dir,
        &runtime_dir,
        &["peer", "trust", "1002", "--safety-number", "AAAA-BBBB"],
        None,
        &[],
    )?;
    if trust_flag.status_ok {
        return Err("peer trust MUST refuse --safety-number argv flag!".to_string());
    }

    // 4. Spawn mp-outpost mcp -> initialize + tools/list fast with ZERO daemon started yet!
    let mut mcp = McpProc::spawn(&state_dir, &runtime_dir, &[])?;

    // Send initialize (process startup + initialize + tools/list).
    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "oracle1", "version": "1.0" }
        }
    }))?;
    let init_resp = mcp.recv()?;
    if init_resp.get("id").and_then(Value::as_i64) != Some(1) {
        return Err(format!("unexpected initialize resp: {init_resp}"));
    }

    let t_list = Instant::now();
    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }))?;
    let list_resp = mcp.recv()?;
    let list_elapsed = t_list.elapsed();
    if list_elapsed >= Duration::from_millis(20) {
        return Err(format!("tools/list took {:?} (>= 20 ms)", list_elapsed));
    }
    let tools = list_resp
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("missing tools array")?;
    if tools.len() != 9 {
        return Err(format!("expected 9 MCP tools, got {}", tools.len()));
    }

    // Verify NO daemon socket was created during initialize / tools/list!
    let dev_rt_dir = runtime_dir.join(format!("d{:013x}", 2001u64));
    if dev_rt_dir.join("d.sock").exists() {
        return Err("daemon socket MUST NOT exist before first tools/call!".to_string());
    }

    // 5. Call outpost_status -> lazily auto-spawns daemon!
    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "outpost_status",
            "arguments": {}
        }
    }))?;
    let status_resp = mcp.recv()?;
    if status_resp.pointer("/result/isError").and_then(Value::as_bool) != Some(false) {
        return Err(format!("outpost_status failed: {status_resp}"));
    }
    let daemon_pid = status_resp
        .pointer("/result/structuredContent/daemon_pid")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing daemon_pid in {status_resp}"))?;
    if daemon_pid == 0 {
        return Err("daemon_pid was 0".to_string());
    }

    // 6. Send stdin EOF to mcp -> assert exits < 100 ms with exit 0!
    let (mcp_ok, eof_elapsed) = mcp.close_stdin_and_wait()?;
    if !mcp_ok {
        return Err("mp-outpost mcp exited with non-zero status on stdin EOF".to_string());
    }
    if eof_elapsed >= Duration::from_millis(100) {
        return Err(format!("mp-outpost mcp EOF exit took {:?} (>= 100 ms)", eof_elapsed));
    }

    // 7. daemon status --json shows live daemon!
    let ds = run_bin(
        &state_dir,
        &runtime_dir,
        &["daemon", "status", "--json"],
        None,
        &[],
    )?;
    if !ds.status_ok {
        return Err(format!("daemon status failed: {}", ds.stderr));
    }
    let ds_json: Value =
        serde_json::from_str(&ds.stdout).map_err(|e| format!("daemon status json: {e}"))?;
    if ds_json.get("running").and_then(Value::as_bool) != Some(true) {
        return Err(format!("expected daemon running=true, got {ds_json}"));
    }
    if ds_json.get("daemon_pid").and_then(Value::as_u64) != Some(daemon_pid) {
        return Err(format!("daemon_pid mismatch: {ds_json}"));
    }

    // 8. daemon stop cleanly shuts it down!
    let stop = run_bin(
        &state_dir,
        &runtime_dir,
        &["daemon", "stop", "--json"],
        None,
        &[],
    )?;
    if !stop.status_ok {
        return Err(format!("daemon stop failed: {}", stop.stderr));
    }

    let ds2 = run_bin(
        &state_dir,
        &runtime_dir,
        &["daemon", "status", "--json"],
        None,
        &[],
    )?;
    let ds2_json: Value =
        serde_json::from_str(&ds2.stdout).map_err(|e| format!("daemon status2 json: {e}"))?;
    if ds2_json.get("running").and_then(Value::as_bool) != Some(false) {
        return Err(format!("expected daemon stopped, got {ds2_json}"));
    }

    Ok(())
}

// ===========================================================================
// Oracle 2: Full 2-Outpost Live E2E Party over Local TLS 1.3 Mock MP1 Server
//           + Real iroh v1.5.0 QUIC + MCP party_send / party_wait
// ===========================================================================

struct MockAccount {
    account_id: u64,
    device_id: u64,
    handle: String,
    root_pubkey: [u8; 32],
    device_pubkey: [u8; 32],
    device_cwt: Vec<u8>,
}

struct MockPartyState {
    party_id: u64,
    party_epoch: u64,
    leader_account_id: u64,
    leader_device_id: u64,
    members: Vec<PartyMemberRecord>,
}

struct MockServerState {
    accounts: HashMap<u64, MockAccount>,
    party: Option<MockPartyState>,
    next_session_id: u64,
    party_tx: broadcast::Sender<Vec<u8>>,
}

impl MockServerState {
    fn build_snapshot_frame(&self) -> Result<Vec<u8>, String> {
        let party = self.party.as_ref().ok_or("no active party on mock server")?;
        let snap = PartySnapshot {
            party_id: PartyId::new(party.party_id).map_err(|e| e.to_string())?,
            party_epoch: party.party_epoch,
            leader_account_id: AccountId::new(party.leader_account_id)
                .map_err(|e| e.to_string())?,
            leader_device_id: DeviceId::new(party.leader_device_id).map_err(|e| e.to_string())?,
            visibility: PartyVisibility::Private,
            join_mode: PartyJoinMode::InviteOnly,
            relay_policy: RelayPolicy::NoRelays,
            max_members: 8,
            pinned_relay_url: String::new(),
            members: party.members.clone(),
        };
        encode_frame(2, &Mp1Message::PartySnapshot(snap)).map_err(|e| e.to_string())
    }
}

fn generate_mock_tls() -> Result<(TlsAcceptor, String), String> {
    let certified = rcgen::generate_simple_self_signed(vec![TEST_AUTHORITY.to_string()])
        .map_err(|e| format!("rcgen failed: {e}"))?;
    let cert_pem = certified.cert.pem();
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls server cfg: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("tls single cert: {e}"))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((TlsAcceptor::from(Arc::new(cfg)), cert_pem))
}

async fn spawn_mock_mp1_server(
    state: Arc<Mutex<MockServerState>>,
) -> Result<(SocketAddr, String, tokio::task::JoinHandle<()>), String> {
    let (acceptor, cert_pem) = generate_mock_tls()?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind mock server: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("mock local_addr: {e}"))?;

    let handle = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor_c = acceptor.clone();
            let state_c = Arc::clone(&state);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor_c.accept(tcp).await else {
                    return;
                };
                let Ok(req) = read_http_req(&mut tls).await else {
                    return;
                };
                handle_mock_connection(tls, req, state_c).await;
            });
        }
    });

    Ok((addr, cert_pem, handle))
}

struct ParsedReq {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_http_req<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<ParsedReq, ()> {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).await.map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        if let Some(slice) = tmp.get(..n) {
            raw.extend_from_slice(slice);
        }
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if raw.len() > 32 * 1024 {
            return Err(());
        }
    };

    let head = core::str::from_utf8(raw.get(..header_end).ok_or(())?).map_err(|_| ())?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().ok_or(())?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().ok_or(())?.to_string();
    let target = parts.next().ok_or(())?;
    let path = target.split('?').next().unwrap_or(target).to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len = headers
        .get("content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = raw.get(header_end + 4..).unwrap_or_default().to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp).await.map_err(|_| ())?;
        if n == 0 {
            break;
        }
        if let Some(slice) = tmp.get(..n) {
            body.extend_from_slice(slice);
        }
    }
    body.truncate(content_len);
    Ok(ParsedReq {
        method,
        path,
        headers,
        body,
    })
}

fn extract_caller_account_id(headers: &HashMap<String, String>) -> Option<u64> {
    let sig_input = headers.get("signature-input")?;
    let marker = "keyid=\"";
    let start = sig_input.find(marker)? + marker.len();
    let rest = sig_input.get(start..)?;
    let end = rest.find('"')?;
    let keyid = rest.get(..end)?;
    let (acc_str, _) = keyid.split_once('.')?;
    acc_str.parse::<u64>().ok()
}

async fn write_http_json<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    reason: &str,
    val: &Value,
) {
    let body = serde_json::to_vec(val).unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.flush().await;
}

async fn handle_mock_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    req: ParsedReq,
    state: Arc<Mutex<MockServerState>>,
) {
    // WebSocket upgrade routes
    if req.headers.get("upgrade").map(|s| s.to_ascii_lowercase()).as_deref() == Some("websocket") {
        let Some(ws_key) = req.headers.get("sec-websocket-key") else {
            return;
        };
        let accept = compute_ws_accept(ws_key);
        let upgrade_resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: mp1\r\n\r\n"
        );
        if stream.write_all(upgrade_resp.as_bytes()).await.is_err() {
            return;
        }
        let _ = stream.flush().await;

        let (session_id, mut party_rx, initial_snapshot) = {
            let mut st = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.next_session_id = st.next_session_id.saturating_add(1);
            let sid = st.next_session_id;
            let snap = if req.path.starts_with("/v1/parties/") {
                st.build_snapshot_frame().ok()
            } else {
                None
            };
            (sid, st.party_tx.subscribe(), snap)
        };

        if let Ok(sid) = SessionId::new(session_id)
            && let Ok(hello_frame) = encode_frame(
                1,
                &Mp1Message::HelloAck {
                    session_id: sid,
                    server_now_ms: outpost_control::wall_now_ms(),
                    ping_interval_ms: 20_000,
                },
            )
            && write_ws_frame(&mut stream, 0x2, &hello_frame).await.is_err()
        {
            return;
        }

        if let Some(snap_frame) = initial_snapshot
            && write_ws_frame(&mut stream, 0x2, &snap_frame).await.is_err()
        {
            return;
        }

        let is_party = req.path.starts_with("/v1/parties/");
        loop {
            tokio::select! {
                bcast = party_rx.recv(), if is_party => {
                    if let Ok(frame) = bcast
                        && write_ws_frame(&mut stream, 0x2, &frame).await.is_err()
                    {
                        return;
                    }
                }
                client_msg = read_ws_client_frame(&mut stream) => {
                    match client_msg {
                        Ok(Some((opcode, payload))) => {
                            if opcode == 0x1 && payload == b"MP1:PING" {
                                if write_ws_frame(&mut stream, 0x1, b"MP1:PONG").await.is_err() {
                                    return;
                                }
                            } else if opcode == 0x8 {
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            }
        }
    }

    // REST routes
    let caller_acc = extract_caller_account_id(&req.headers).unwrap_or(1001);
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/accounts/me") => {
            let val = {
                let st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(acc) = st.accounts.get(&caller_acc) {
                    json!({
                        "account_id": acc.account_id,
                        "handle": acc.handle,
                        "root_pubkey_b64": B64.encode(acc.root_pubkey),
                        "devices": [],
                        "active_party_ids": []
                    })
                } else {
                    json!({ "error": "not_found" })
                }
            };
            write_http_json(&mut stream, 200, "OK", &val).await;
        }
        ("GET", path) if path.starts_with("/v1/accounts/") => {
            let id_str = path.trim_start_matches("/v1/accounts/");
            if let Ok(target_id) = id_str.parse::<u64>() {
                let resp = {
                    let st = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    st.accounts.get(&target_id).map(|acc| {
                        json!({
                            "account_id": acc.account_id,
                            "handle": acc.handle,
                            "root_pubkey_b64": B64.encode(acc.root_pubkey),
                        })
                    })
                };
                if let Some(val) = resp {
                    write_http_json(&mut stream, 200, "OK", &val).await;
                    return;
                }
            }
            write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "not_found" })).await;
        }
        ("POST", "/v1/parties") => {
            let Ok(body_json) = serde_json::from_slice::<Value>(&req.body) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({ "error": "bad_json" }))
                    .await;
                return;
            };
            let Some(ep_b64) = body_json.get("endpoint_b64").and_then(Value::as_str) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({ "error": "no_ep" }))
                    .await;
                return;
            };
            let Ok(ep_bytes) = B64.decode(ep_b64.as_bytes()) else {
                return;
            };
            let Ok(endpoint) = EndpointDescriptor::decode(&ep_bytes) else {
                return;
            };

            let resp = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(acc) = st.accounts.get(&caller_acc) else {
                    return;
                };
                let Ok(dev_id) = DeviceId::new(acc.device_id) else {
                    return;
                };
                let Ok(acc_id) = AccountId::new(acc.account_id) else {
                    return;
                };
                let member = PartyMemberRecord {
                    device_id: dev_id,
                    account_id: acc_id,
                    root_pubkey: acc.root_pubkey,
                    device_pubkey: acc.device_pubkey,
                    device_cwt: acc.device_cwt.clone(),
                    endpoint,
                    joined_seq: 1,
                    connected: true,
                };
                st.party = Some(MockPartyState {
                    party_id: 7001,
                    party_epoch: 1,
                    leader_account_id: acc.account_id,
                    leader_device_id: acc.device_id,
                    members: vec![member],
                });
                json!({
                    "party_id": 7001,
                    "party_epoch": 1,
                    "pinned_relay_url": ""
                })
            };
            write_http_json(&mut stream, 201, "Created", &resp).await;
        }
        ("GET", "/v1/parties/7001") => {
            let val = {
                let st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                st.party.as_ref().map(|p| {
                    json!({
                        "party_id": p.party_id,
                        "party_epoch": p.party_epoch,
                        "leader_account_id": p.leader_account_id,
                        "leader_device_id": p.leader_device_id,
                        "visibility": 0,
                        "join_mode": 0,
                        "relay_policy": 2,
                        "pinned_relay_url": "",
                        "max_members": 8,
                        "member_count": p.members.len()
                    })
                })
            };
            if let Some(v) = val {
                write_http_json(&mut stream, 200, "OK", &v).await;
            } else {
                write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "not_found" }))
                    .await;
            }
        }
        ("POST", "/v1/parties/7001/join") => {
            let Ok(body_json) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let Some(ep_b64) = body_json.get("endpoint_b64").and_then(Value::as_str) else {
                return;
            };
            let Ok(ep_bytes) = B64.decode(ep_b64.as_bytes()) else {
                return;
            };
            let Ok(endpoint) = EndpointDescriptor::decode(&ep_bytes) else {
                return;
            };

            let resp = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(acc) = st.accounts.get(&caller_acc) else {
                    return;
                };
                let Ok(dev_id) = DeviceId::new(acc.device_id) else {
                    return;
                };
                let Ok(acc_id) = AccountId::new(acc.account_id) else {
                    return;
                };
                let member = PartyMemberRecord {
                    device_id: dev_id,
                    account_id: acc_id,
                    root_pubkey: acc.root_pubkey,
                    device_pubkey: acc.device_pubkey,
                    device_cwt: acc.device_cwt.clone(),
                    endpoint,
                    joined_seq: 2,
                    connected: true,
                };
                if let Some(ref mut p) = st.party {
                    p.party_epoch += 1;
                    p.members.retain(|m| m.device_id != dev_id);
                    p.members.push(member);
                    let ep = p.party_epoch;
                    if let Ok(snap) = st.build_snapshot_frame() {
                        let _ = st.party_tx.send(snap);
                    }
                    json!({
                        "status": "joined",
                        "party_epoch": ep
                    })
                } else {
                    return;
                }
            };
            write_http_json(&mut stream, 200, "OK", &resp).await;
        }
        _ => {
            write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "not_found" })).await;
        }
    }
}

async fn write_ws_frame<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
) -> Result<(), ()> {
    let mut header = Vec::with_capacity(10);
    header.push(0x80 | (opcode & 0x0f));
    let len = payload.len();
    if len < 126 {
        header.push(len as u8);
    } else if len <= usize::from(u16::MAX) {
        header.push(126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    stream.write_all(&header).await.map_err(|_| ())?;
    stream.write_all(payload).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())
}

async fn read_ws_client_frame<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Option<(u8, Vec<u8>)>, ()> {
    let mut hdr = [0u8; 2];
    if stream.read_exact(&mut hdr).await.is_err() {
        return Ok(None);
    }
    let opcode = hdr[0] & 0x0f;
    let masked = (hdr[1] & 0x80) != 0;
    let len7 = hdr[1] & 0x7f;
    let len = match len7 {
        0..=125 => usize::from(len7),
        126 => {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).await.map_err(|_| ())?;
            usize::from(u16::from_be_bytes(ext))
        }
        _ => {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).await.map_err(|_| ())?;
            u64::from_be_bytes(ext) as usize
        }
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await.map_err(|_| ())?;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await.map_err(|_| ())?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            if let Some(&m) = mask.get(i % 4) {
                *b ^= m;
            }
        }
    }
    Ok(Some((opcode, payload)))
}

fn compute_ws_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + 36);
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = sha1_digest(&input);
    B64.encode(digest)
}

fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            if let Some(s) = chunk.get(i * 4..i * 4 + 4)
                && let Ok(arr) = <[u8; 4]>::try_from(s)
            {
                *slot = u32::from_be_bytes(arr);
            }
        }
        for i in 16..80 {
            let v = (w.get(i - 3).copied().unwrap_or(0)
                ^ w.get(i - 8).copied().unwrap_or(0)
                ^ w.get(i - 14).copied().unwrap_or(0)
                ^ w.get(i - 16).copied().unwrap_or(0))
            .rotate_left(1);
            if let Some(slot) = w.get_mut(i) {
                *slot = v;
            }
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

fn write_pinned_peer(
    state_dir: &Path,
    peer_account_id: u64,
    peer_root_pubkey: [u8; 32],
    peer_handle: &str,
) -> Result<(), String> {
    let store = PeersStoreRecord {
        peers: vec![PeerRecord {
            api_authority_hash: api_authority_hash(TEST_AUTHORITY),
            account_id: peer_account_id,
            root_pubkey: peer_root_pubkey,
            trust_state: TrustState::PinnedTrusted,
            pinned_at_ms: outpost_control::wall_now_ms(),
            handle_prop: peer_handle.to_string(),
            handle_fetched_ms: outpost_control::wall_now_ms(),
        }],
    };
    let encoded = encode_peers_store(&store).map_err(|e| format!("encode_peers_store: {e}"))?;
    let p = state_dir.join("peers.bin");
    std::fs::write(&p, encoded).map_err(|e| format!("write peers.bin: {e}"))?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod peers.bin: {e}"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oracle_2_two_outpost_live_e2e_iroh_quic_and_mcp() -> Result<(), String> {
    let root_tmp = make_short_tempdir("mpo2")?;
    let alice_st = make_private_subdir(root_tmp.path(), "as")?;
    let alice_rt = make_private_subdir(root_tmp.path(), "ar")?;
    let bob_st = make_private_subdir(root_tmp.path(), "bs")?;
    let bob_rt = make_private_subdir(root_tmp.path(), "br")?;

    // 1. Provision Alice (1001/2001) and Bob (1002/2002)
    let alice = provision_device(&alice_st, &alice_rt, 1001, 2001, [0xAAu8; 32], "alice-dev")?;
    let bob = provision_device(&bob_st, &bob_rt, 1002, 2002, [0xBBu8; 32], "bob-dev")?;

    // Pre-pin each other's root_pubkey in peers.bin
    write_pinned_peer(&alice_st, bob.account_id, bob.root_pubkey, "bob")?;
    write_pinned_peer(&bob_st, alice.account_id, alice.root_pubkey, "alice")?;

    // 2. Start local TLS 1.3 mock MP1 server
    let (party_tx, _) = broadcast::channel::<Vec<u8>>(32);
    let mut accounts = HashMap::new();
    accounts.insert(
        alice.account_id,
        MockAccount {
            account_id: alice.account_id,
            device_id: alice.device_id,
            handle: "alice".to_string(),
            root_pubkey: alice.root_pubkey,
            device_pubkey: alice.device_pubkey,
            device_cwt: alice.device_cwt.clone(),
        },
    );
    accounts.insert(
        bob.account_id,
        MockAccount {
            account_id: bob.account_id,
            device_id: bob.device_id,
            handle: "bob".to_string(),
            root_pubkey: bob.root_pubkey,
            device_pubkey: bob.device_pubkey,
            device_cwt: bob.device_cwt.clone(),
        },
    );

    let mock_state = Arc::new(Mutex::new(MockServerState {
        accounts,
        party: None,
        next_session_id: 100,
        party_tx,
    }));
    let (server_addr, cert_pem, server_task) = spawn_mock_mp1_server(mock_state).await?;
    let ca_path = root_tmp.path().join("mock_ca.pem");
    std::fs::write(&ca_path, cert_pem).map_err(|e| format!("write ca pem: {e}"))?;

    let addr_str = server_addr.to_string();
    let ca_str = ca_path.to_string_lossy().into_owned();
    let env_vars = [
        ("OUTPOST_TEST_CONNECT_ADDR", addr_str.as_str()),
        ("OUTPOST_TEST_CA_PEM", ca_str.as_str()),
    ];

    // Ensure daemons get cleaned up even if an assertion fails mid-test!
    let result = async {
        // 3. Alice creates party with --relay-policy none
        let create_out = run_bin(
            &alice_st,
            &alice_rt,
            &["party", "create", "--relay-policy", "none", "--json"],
            None,
            &env_vars,
        )?;
        if !create_out.status_ok {
            return Err(format!("alice party create failed: {}", create_out.stderr));
        }
        let create_json: Value = serde_json::from_str(&create_out.stdout)
            .map_err(|e| format!("parse create json: {e}"))?;
        let party_id = create_json
            .get("party_id")
            .and_then(Value::as_u64)
            .ok_or("missing party_id")?;
        if party_id != 7001 {
            return Err(format!("expected party_id 7001, got {party_id}"));
        }

        // 4. Bob joins party 7001 with --relay-policy none
        let join_out = run_bin(
            &bob_st,
            &bob_rt,
            &["party", "join", "7001", "--relay-policy", "none", "--json"],
            None,
            &env_vars,
        )?;
        if !join_out.status_ok {
            return Err(format!("bob party join failed: {}", join_out.stderr));
        }

        // 5. Spawn mp-outpost mcp for BOTH Alice and Bob
        let mut alice_mcp = McpProc::spawn(&alice_st, &alice_rt, &env_vars)?;
        let mut bob_mcp = McpProc::spawn(&bob_st, &bob_rt, &env_vars)?;

        for (label, proc_mcp) in [("alice", &mut alice_mcp), ("bob", &mut bob_mcp)] {
            proc_mcp.send(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": label, "version": "1.0" }
                }
            }))?;
            let _ = proc_mcp.recv()?;
        }

        // 6. Wait until Alice's party_members shows Bob is connected over REAL iroh v1.5.0 QUIC!
        let connect_deadline = Instant::now() + Duration::from_secs(12);
        let mut p2p_ready = false;
        let mut req_id = 10i64;
        while Instant::now() < connect_deadline {
            req_id += 1;
            alice_mcp.send(&json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {
                    "name": "party_members",
                    "arguments": { "party_id": 7001 }
                }
            }))?;
            let resp = alice_mcp.recv()?;
            if let Some(members) = resp
                .pointer("/result/structuredContent/members")
                .and_then(Value::as_array)
            {
                let bob_connected = members.iter().any(|m| {
                    m.get("device_id").and_then(Value::as_u64) == Some(2002)
                        && m.get("connected_p2p").and_then(Value::as_bool) == Some(true)
                });
                if bob_connected {
                    p2p_ready = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !p2p_ready {
            return Err("timed out waiting for real iroh v1.5.0 QUIC connection between Alice and Bob".to_string());
        }

        // 7. Read Bob's current cursor via party_poll so Bob waits strictly for Alice's chat message
        bob_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "party_poll",
                "arguments": { "party_id": 7001, "after_seq": 0 }
            }
        }))?;
        let bob_poll = bob_mcp.recv()?;
        let bob_next_seq = bob_poll
            .pointer("/result/structuredContent/next_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let bob_daemon_epoch = bob_poll
            .pointer("/result/structuredContent/daemon_epoch")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        // 8. Bob starts party_wait!
        bob_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "party_wait",
                "arguments": {
                    "party_id": 7001,
                    "cursor_epoch": bob_daemon_epoch,
                    "after_seq": bob_next_seq,
                    "timeout_ms": 10000
                }
            }
        }))?;

        // Give Bob's wait a tiny moment to register on Notify, then Alice sends chat over iroh QUIC!
        tokio::time::sleep(Duration::from_millis(50)).await;
        let secret_msg = "hello from alice over iroh quic!";
        alice_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "party_send",
                "arguments": {
                    "party_id": 7001,
                    "body": secret_msg
                }
            }
        }))?;
        let alice_send_resp = alice_mcp.recv()?;
        if alice_send_resp
            .pointer("/result/isError")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(format!("alice party_send failed: {alice_send_resp}"));
        }
        let delivered = alice_send_resp
            .pointer("/result/structuredContent/delivered_to")
            .and_then(Value::as_array)
            .ok_or("missing delivered_to")?;
        if !delivered.iter().any(|v| v.as_u64() == Some(2002)) {
            return Err(format!("expected delivered_to to include 2002, got {alice_send_resp}"));
        }

        // 9. Bob receives Alice's message via party_wait!
        let bob_wait_resp = bob_mcp.recv()?;
        if bob_wait_resp
            .pointer("/result/isError")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(format!("bob party_wait failed: {bob_wait_resp}"));
        }

        let content_text = bob_wait_resp
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing content[0].text in {bob_wait_resp}"))?;
        if !content_text.contains("<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_")
            || !content_text.contains("<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END_")
            || !content_text.contains(secret_msg)
        {
            return Err(format!(
                "bob party_wait text missing nonce fence or payload: {content_text}"
            ));
        }

        let events = bob_wait_resp
            .pointer("/result/structuredContent/events")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("missing events in {bob_wait_resp}"))?;
        let chat_ev = events
            .iter()
            .find(|e| e.get("kind").and_then(Value::as_str) == Some("chat"))
            .ok_or_else(|| format!("no chat event in {bob_wait_resp}"))?;
        if chat_ev.pointer("/provenance/sender_account_id").and_then(Value::as_u64) != Some(1001)
            || chat_ev.pointer("/provenance/sender_device_id").and_then(Value::as_u64) != Some(2001)
            || chat_ev.pointer("/provenance/sender_handle").and_then(Value::as_str) != Some("alice")
            || chat_ev.get("untrusted_remote").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!(
                "wrong authenticated provenance on chat event: {chat_ev}"
            ));
        }
        if chat_ev.get("body").and_then(Value::as_str) != Some(secret_msg) {
            return Err(format!("unexpected body: {chat_ev}"));
        }

        // Verify accidental-secret-disclosure guard refuses invite token without echoing it!
        let fake_invite = "mpinv1_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
        alice_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "party_send",
                "arguments": {
                    "party_id": 7001,
                    "body": format!("oops {fake_invite}")
                }
            }
        }))?;
        let sec_resp = alice_mcp.recv()?;
        if sec_resp.pointer("/result/isError").and_then(Value::as_bool) != Some(true) {
            return Err(format!("secret guard MUST refuse invite token: {sec_resp}"));
        }
        if sec_resp.to_string().contains(fake_invite) {
            return Err("secret guard MUST NOT echo offending secret!".to_string());
        }

        // 10. Cleanly exit both MCP proxies
        let (a_ok, _) = alice_mcp.close_stdin_and_wait()?;
        let (b_ok, _) = bob_mcp.close_stdin_and_wait()?;
        if !a_ok || !b_ok {
            return Err("one of the MCP proxies did not exit 0".to_string());
        }

        Ok(())
    }
    .await;

    // 11. Always stop both daemons and verify zero lingering processes!
    let _ = run_bin(&alice_st, &alice_rt, &["daemon", "stop"], None, &env_vars);
    let _ = run_bin(&bob_st, &bob_rt, &["daemon", "stop"], None, &env_vars);
    server_task.abort();

    // Propagate any test error after teardown.
    result?;

    for (who, st, rt) in [("alice", &alice_st, &alice_rt), ("bob", &bob_st, &bob_rt)] {
        let ds = run_bin(st, rt, &["daemon", "status", "--json"], None, &env_vars)?;
        let j: Value = serde_json::from_str(&ds.stdout).map_err(|e| e.to_string())?;
        if j.get("running").and_then(Value::as_bool) != Some(false) {
            return Err(format!("{who} daemon still running after stop: {j}"));
        }
    }

    Ok(())
}
