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

#[cfg(feature = "test-tls-overrides")]
use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Write as _};
#[cfg(feature = "test-tls-overrides")]
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
#[cfg(feature = "test-tls-overrides")]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use mp_protocol::{MAX_CWT_TTL_SECS, encode_device_cwt};
#[cfg(feature = "test-tls-overrides")]
use mp_protocol::{
    AccountId, DeviceId, EndpointDescriptor, Mp1Message, PartyId, PartyJoinMode, PartyMemberRecord,
    PartySnapshot, PartyVisibility, RelayPolicy, SessionId, encode_frame,
};
use outpost_control::wall_now_secs;
#[cfg(feature = "test-tls-overrides")]
use outpost_core::storage_codec::{PeerRecord, PeersStoreRecord, TrustState, encode_peers_store};
#[cfg(feature = "test-tls-overrides")]
use outpost_core::trust::api_authority_hash;
use outpost_core::trust::compute_safety_number;
#[cfg(feature = "test-tls-overrides")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
#[cfg(feature = "test-tls-overrides")]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
#[cfg(feature = "test-tls-overrides")]
use tokio::net::TcpListener;
#[cfg(feature = "test-tls-overrides")]
use tokio::sync::broadcast;
#[cfg(feature = "test-tls-overrides")]
use tokio_rustls::TlsAcceptor;

const BIN_PATH: &str = env!("CARGO_BIN_EXE_mp-outpost");
#[cfg(feature = "test-tls-overrides")]
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

#[allow(dead_code)]
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
    if tools.len() != 13 {
        return Err(format!("expected 13 MCP tools, got {}", tools.len()));
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

#[test]
fn oracle_4_mcp_setup_and_recovery_key_argv_rejection() -> Result<(), String> {
    let root_tmp = make_short_tempdir("mpo4")?;
    let state_dir = make_private_subdir(root_tmp.path(), "st")?;
    let runtime_dir = make_private_subdir(root_tmp.path(), "rt")?;

    // 1. `mcp setup --json` offline check for all clients
    let setup_all = run_bin(
        &state_dir,
        &runtime_dir,
        &["mcp", "setup", "--json"],
        None,
        &[],
    )?;
    if !setup_all.status_ok {
        return Err(format!("mcp setup --json failed: {}", setup_all.stderr));
    }
    let j: Value =
        serde_json::from_str(&setup_all.stdout).map_err(|e| format!("mcp setup json: {e}"))?;
    let configs = j
        .get("configs")
        .and_then(Value::as_object)
        .ok_or("missing configs object")?;
    for client in ["claude", "codex", "cursor", "antigravity"] {
        if !configs.contains_key(client) {
            return Err(format!("missing client '{client}' in mcp setup output"));
        }
    }

    // 2. Single client filter (`--client claude`)
    let setup_claude = run_bin(
        &state_dir,
        &runtime_dir,
        &["mcp", "setup", "--client", "claude"],
        None,
        &[],
    )?;
    if !setup_claude.status_ok || !setup_claude.stdout.contains("claude mcp add multiplayer") {
        return Err(format!(
            "mcp setup --client claude unexpected output: {}",
            setup_claude.stdout
        ));
    }

    // 3. Passing secrets anywhere on argv MUST be refused BEFORE `mcp` / CLI dispatch and NEVER echoed!
    let fake_rk = mp_protocol::encode_recovery_key(&[0x55u8; 32]);
    let rk_argv = run_bin(
        &state_dir,
        &runtime_dir,
        &["account", "recover", "--device-label", "test", &fake_rk],
        None,
        &[],
    )?;
    if rk_argv.status_ok {
        return Err("CLI MUST refuse mprk1_ recovery key on argv!".to_string());
    }

    // --passphrase=secret refused BEFORE mcp dispatch without echoing secret
    let pass_argv = run_bin(
        &state_dir,
        &runtime_dir,
        &["mcp", "--passphrase=do-not-echo-this-9876"],
        None,
        &[],
    )?;
    if pass_argv.status_ok || pass_argv.stderr.contains("do-not-echo-this-9876") {
        return Err(format!(
            "CLI MUST refuse --passphrase=... without echoing secret: ok={} stderr={}",
            pass_argv.status_ok, pass_argv.stderr
        ));
    }

    // .mpkey PEM on argv refused
    let pem_argv = run_bin(
        &state_dir,
        &runtime_dir,
        &["whoami", "-----BEGIN MULTIPLAYER RECOVERY KEY-----\nTVBLRVkxAA=="],
        None,
        &[],
    )?;
    if pem_argv.status_ok {
        return Err("CLI MUST refuse .mpkey PEM contents on argv!".to_string());
    }

    // Space-split unprefixed 55-char recovery key across multiple argv tokens refused
    let unprefixed = fake_rk.strip_prefix("mprk1_").unwrap_or(&fake_rk);
    let mut split_args: Vec<&str> = vec!["account", "recover", "--device-label", "test"];
    split_args.extend(unprefixed.split('-'));
    let split_argv = run_bin(&state_dir, &runtime_dir, &split_args, None, &[])?;
    if split_argv.status_ok {
        return Err("CLI MUST refuse space-split unprefixed recovery key on argv!".to_string());
    }

    // Unknown secret-like flag `--token=secret` MUST NOT echo secret value
    let tok_argv = run_bin(
        &state_dir,
        &runtime_dir,
        &["whoami", "--token=never-echo-token-777"],
        None,
        &[],
    )?;
    if tok_argv.status_ok || tok_argv.stderr.contains("never-echo-token-777") {
        return Err(format!(
            "unknown --token=... MUST be redacted in stderr: {}",
            tok_argv.stderr
        ));
    }

    // 4. `mcp setup --write` refuses `--client all`, preserves existing JSON keys + writes `.bak`,
    //    and idempotently upserts Codex TOML!
    let refuse_all = run_bin(
        &state_dir,
        &runtime_dir,
        &["mcp", "setup", "--client", "all", "--write"],
        None,
        &[],
    )?;
    if refuse_all.status_ok {
        return Err("mcp setup --client all --write MUST be refused!".to_string());
    }

    let claude_cfg = root_tmp.path().join("claude_mcp.json");
    let orig_claude = r#"{"custom":true,"mcpServers":{"existing":{"command":"foo","args":[]}}}"#;
    std::fs::write(&claude_cfg, orig_claude).map_err(|e| format!("write claude cfg: {e}"))?;
    let claude_cfg_str = claude_cfg.to_string_lossy().into_owned();
    let write_claude = run_bin(
        &state_dir,
        &runtime_dir,
        &[
            "--json",
            "mcp",
            "setup",
            "--client",
            "claude",
            "--write",
            "--config",
            &claude_cfg_str,
        ],
        None,
        &[],
    )?;
    if !write_claude.status_ok {
        return Err(format!("mcp setup --write claude failed: {}", write_claude.stderr));
    }
    let bak_claude = root_tmp.path().join("claude_mcp.json.bak");
    if std::fs::read_to_string(&bak_claude).map_err(|e| format!("read bak: {e}"))? != orig_claude {
        return Err("claude .bak did not preserve exact original config!".to_string());
    }
    let merged_claude: Value = serde_json::from_str(
        &std::fs::read_to_string(&claude_cfg).map_err(|e| format!("read merged: {e}"))?,
    )
    .map_err(|e| format!("parse merged json: {e}"))?;
    if merged_claude.get("custom").and_then(Value::as_bool) != Some(true)
        || merged_claude.pointer("/mcpServers/existing/command").and_then(Value::as_str)
            != Some("foo")
        || merged_claude
            .pointer("/mcpServers/multiplayer/args/0")
            .and_then(Value::as_str)
            != Some("mcp")
    {
        return Err(format!("merged claude json missing expected keys: {merged_claude}"));
    }

    let codex_cfg = root_tmp.path().join("codex_config.toml");
    let orig_codex = "[profile]\nname = \"dev\"\n\n[mcp_servers.multiplayer]\ncommand = \"/old/mp-outpost\"\nargs = [\"mcp\"]\n";
    std::fs::write(&codex_cfg, orig_codex).map_err(|e| format!("write codex cfg: {e}"))?;
    let codex_cfg_str = codex_cfg.to_string_lossy().into_owned();
    let write_codex1 = run_bin(
        &state_dir,
        &runtime_dir,
        &[
            "--json",
            "mcp",
            "setup",
            "--client",
            "codex",
            "--write",
            "--config",
            &codex_cfg_str,
        ],
        None,
        &[],
    )?;
    if !write_codex1.status_ok {
        return Err(format!("mcp setup --write codex failed: {}", write_codex1.stderr));
    }
    let first_toml =
        std::fs::read_to_string(&codex_cfg).map_err(|e| format!("read codex1: {e}"))?;
    if !first_toml.contains("[profile]")
        || !first_toml.contains("[mcp_servers.multiplayer]")
        || first_toml.contains("/old/mp-outpost")
    {
        return Err(format!("unexpected codex toml: {first_toml}"));
    }
    let write_codex2 = run_bin(
        &state_dir,
        &runtime_dir,
        &[
            "--json",
            "mcp",
            "setup",
            "--client",
            "codex",
            "--write",
            "--config",
            &codex_cfg_str,
        ],
        None,
        &[],
    )?;
    if !write_codex2.status_ok {
        return Err(format!("mcp setup --write codex2 failed: {}", write_codex2.stderr));
    }
    let second_toml =
        std::fs::read_to_string(&codex_cfg).map_err(|e| format!("read codex2: {e}"))?;
    if first_toml != second_toml {
        return Err("codex TOML upsert was not idempotent!".to_string());
    }

    Ok(())
}

// ===========================================================================
// Oracle 7: LAN Party! CLI Mandates, 2-Binary Encrypted QUIC Chat, & Relays
// ===========================================================================

struct LanChildProc {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: std::sync::mpsc::Receiver<String>,
    stderr_handle: Option<std::thread::JoinHandle<String>>,
}

impl LanChildProc {
    fn spawn(
        state_dir: &Path,
        runtime_dir: &Path,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Result<Self, String> {
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
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawn lan proc failed: {e}"))?;
        let stdin = child.stdin.take().ok_or("missing lan proc stdin")?;
        let stdout = child.stdout.take().ok_or("missing lan proc stdout")?;
        let stderr = child.stderr.take().ok_or("missing lan proc stderr")?;

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line.trim().to_string()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let stderr_handle = std::thread::spawn(move || {
            let mut buf = String::new();
            let mut reader = BufReader::new(stderr);
            let _ = std::io::Read::read_to_string(&mut reader, &mut buf);
            buf
        });

        Ok(Self {
            child,
            stdin: Some(stdin),
            rx,
            stderr_handle: Some(stderr_handle),
        })
    }

    fn send_line(&mut self, line: &str) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("lan proc stdin closed")?;
        stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("write lan stdin: {e}"))?;
        stdin
            .write_all(b"\n")
            .map_err(|e| format!("write lan newline: {e}"))?;
        stdin.flush().map_err(|e| format!("flush lan stdin: {e}"))
    }

    fn wait_for_event(&mut self, event_name: &str, timeout: Duration) -> Result<Value, String> {
        let deadline = Instant::now() + timeout;
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let rem = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(rem.min(Duration::from_millis(250))) {
                Ok(line) => {
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(val) = serde_json::from_str::<Value>(&line) {
                        if val.get("event").and_then(Value::as_str) == Some(event_name) {
                            return Ok(val);
                        }
                        seen.push(line);
                    } else {
                        seen.push(line);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let err_tail = self.finish_and_read_stderr();
        Err(format!(
            "timed out waiting for event '{event_name}' (seen={seen:?}, stderr={err_tail})"
        ))
    }

    fn finish_and_read_stderr(&mut self) -> String {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stderr_handle
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default()
    }

    fn wait_exit_clean(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return Ok(());
                    }
                    let stderr = self
                        .stderr_handle
                        .take()
                        .and_then(|h| h.join().ok())
                        .unwrap_or_default();
                    return Err(format!("lan proc exited with {status}: {stderr}"));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(format!("try_wait failed: {e}")),
            }
        }
        let stderr = self.finish_and_read_stderr();
        Err(format!("lan proc did not exit cleanly within {timeout:?}: {stderr}"))
    }
}

impl Drop for LanChildProc {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        if let (Some(&hi), Some(&lo)) = (
            HEX.get(usize::from(b >> 4)),
            HEX.get(usize::from(b & 0x0f)),
        ) {
            s.push(char::from(hi));
            s.push(char::from(lo));
        }
    }
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_7_lan_party_cli_mandates_and_regional_relays() -> Result<(), String> {
    let root_tmp = make_short_tempdir("mpo7")?;
    let host_st = make_private_subdir(root_tmp.path(), "hst")?;
    let host_rt = make_private_subdir(root_tmp.path(), "hrt")?;
    let host_lan = make_private_subdir(root_tmp.path(), "hlan")?;
    let join_st = make_private_subdir(root_tmp.path(), "jst")?;
    let join_rt = make_private_subdir(root_tmp.path(), "jrt")?;
    let join_lan = make_private_subdir(root_tmp.path(), "jlan")?;
    let xdg_dir = make_private_subdir(root_tmp.path(), "xdg")?;

    let host_lan_str = host_lan.to_string_lossy().into_owned();
    let join_lan_str = join_lan.to_string_lossy().into_owned();
    let xdg_str = xdg_dir.to_string_lossy().into_owned();
    let base_env = [("XDG_CONFIG_HOME", xdg_str.as_str())];

    // 1. `mp-outpost lan status --json --lan-dir <tmp>` reports `disabled: false` and opens zero sockets.
    let st_out = run_bin(
        &host_st,
        &host_rt,
        &["lan", "status", "--json", "--lan-dir", &host_lan_str],
        None,
        &base_env,
    )?;
    if !st_out.status_ok {
        return Err(format!("lan status failed: {}", st_out.stderr));
    }
    let st_json: Value =
        serde_json::from_str(&st_out.stdout).map_err(|e| format!("lan status json: {e}"))?;
    if st_json.pointer("/policy/disabled").and_then(Value::as_bool) != Some(false) {
        return Err(format!("expected lan status policy.disabled=false: {st_json}"));
    }

    // 2. `MP_DISABLE_LAN=1` fails closed immediately on both `lan host --no-mdns` and `lan scan`!
    let disabled_env = [
        ("XDG_CONFIG_HOME", xdg_str.as_str()),
        ("MP_DISABLE_LAN", "1"),
    ];
    let dis_host = run_bin(
        &host_st,
        &host_rt,
        &["lan", "host", "--no-mdns", "--lan-dir", &host_lan_str],
        None,
        &disabled_env,
    )?;
    if dis_host.status_ok {
        return Err("MP_DISABLE_LAN=1 lan host MUST fail closed!".to_string());
    }
    let dis_scan = run_bin(
        &host_st,
        &host_rt,
        &["lan", "scan", "--timeout", "1"],
        None,
        &disabled_env,
    )?;
    if dis_scan.status_ok {
        return Err("MP_DISABLE_LAN=1 lan scan MUST fail closed!".to_string());
    }

    // 3. Global argv secret guard rejects `--pin` and `--pin=` (case-insensitive) without echoing `424242`!
    for bad_args in [
        vec!["lan", "host", "--pin", "424242"],
        vec!["lan", "host", "--pin=424242"],
        vec!["lan", "join", "127.0.0.1:4433", "--PIN=424242"],
    ] {
        let pin_res = run_bin(&host_st, &host_rt, &bad_args, None, &base_env)?;
        if pin_res.status_ok
            || pin_res.stderr.contains("424242")
            || !pin_res.stderr.contains("PINs are forbidden on CLI argv")
        {
            return Err(format!(
                "expected argv PIN rejection without echoing secret for {bad_args:?}: ok={} stderr={}",
                pin_res.status_ok, pin_res.stderr
            ));
        }
    }

    // 4. Full 2-process compiled-binary encrypted QUIC LAN Party chat on loopback!
    // Pre-seed joiner's local identity.json (mode 0600) so we know joiner's canonical SN up front,
    // while letting host generate a fresh local identity on startup.
    let join_seed = [0x77u8; 32];
    let join_sk = SigningKey::from_bytes(&join_seed);
    let join_pk = join_sk.verifying_key().to_bytes();
    let join_sn = compute_safety_number(0, &join_pk);
    let join_id_path = join_lan.join("identity.json");
    let join_id_body = json!({
        "version": 1,
        "account_id": 0,
        "display_name": "outpost-joiner",
        "seed_hex": encode_hex_32(&join_seed),
        "public_key_hex": encode_hex_32(&join_pk),
    })
    .to_string();
    std::fs::write(&join_id_path, format!("{join_id_body}\n"))
        .map_err(|e| format!("write joiner identity.json: {e}"))?;
    std::fs::set_permissions(&join_id_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 joiner identity.json: {e}"))?;

    let mut host_proc = LanChildProc::spawn(
        &host_st,
        &host_rt,
        &[
            "--json",
            "lan",
            "host",
            "--no-mdns",
            "--require-pin",
            "--pin-stdin",
            "--lan-dir",
            &host_lan_str,
            "--display-name",
            "outpost-host",
            "--yes-safety-number",
            &join_sn,
        ],
        &base_env,
    )?;
    host_proc.send_line("424242")?;

    let ready_ev = host_proc.wait_for_event("lobby_ready", Duration::from_secs(15))?;
    let direct_addr = ready_ev
        .get("direct_addr")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing direct_addr in lobby_ready: {ready_ev}"))?
        .to_string();
    let host_pk_b64u = ready_ev
        .get("host_pk_b64u")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing host_pk_b64u in lobby_ready: {ready_ev}"))?
        .to_string();
    let host_sn = ready_ev
        .get("safety_number")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing safety_number in lobby_ready: {ready_ev}"))?
        .to_string();
    if ready_ev.get("require_pin").and_then(Value::as_bool) != Some(true)
        || ready_ev.get("mdns_enabled").and_then(Value::as_bool) != Some(false)
    {
        return Err(format!("unexpected lobby_ready flags: {ready_ev}"));
    }

    let mut join_proc = LanChildProc::spawn(
        &join_st,
        &join_rt,
        &[
            "--json",
            "lan",
            "join",
            &direct_addr,
            "--host-pk",
            &host_pk_b64u,
            "--pin-stdin",
            "--lan-dir",
            &join_lan_str,
            "--display-name",
            "outpost-joiner",
            "--yes-safety-number",
            &host_sn,
        ],
        &base_env,
    )?;
    join_proc.send_line("424242")?;

    let _join_ready = join_proc.wait_for_event("peer_joined", Duration::from_secs(15))?;
    let _host_saw_join = host_proc.wait_for_event("peer_joined", Duration::from_secs(15))?;

    join_proc.send_line("hello from outpost joiner")?;
    let host_chat = host_proc.wait_for_event("chat", Duration::from_secs(15))?;
    if host_chat.get("body").and_then(Value::as_str) != Some("hello from outpost joiner") {
        return Err(format!("unexpected host chat event: {host_chat}"));
    }

    host_proc.send_line("hello from outpost host")?;
    let join_chat = join_proc.wait_for_event("chat", Duration::from_secs(15))?;
    if join_chat.get("body").and_then(Value::as_str) != Some("hello from outpost host") {
        return Err(format!("unexpected joiner chat event: {join_chat}"));
    }

    let _ = join_proc.send_line("/quit");
    let _ = host_proc.send_line("/quit");
    join_proc.wait_exit_clean(Duration::from_secs(10))?;
    host_proc.wait_exit_clean(Duration::from_secs(10))?;

    // 5. Verify `mp-outpost relays --json` (and `--ping`) against a local TLS 1.3 mock server!
    #[cfg(feature = "test-tls-overrides")]
    live_e2e::verify_relays_cli_against_mock_tls13(root_tmp.path(), &host_st, &host_rt).await?;

    Ok(())
}

// ===========================================================================
// Oracle 3 (default production build): MUST ignore OUTPOST_TEST_* overrides
// ===========================================================================

#[cfg(not(feature = "test-tls-overrides"))]
#[test]
fn oracle_3_default_binary_ignores_test_tls_overrides() -> Result<(), String> {
    let root_tmp = make_short_tempdir("mpo3")?;
    let state_dir = make_private_subdir(root_tmp.path(), "st")?;
    let runtime_dir = make_private_subdir(root_tmp.path(), "rt")?;

    // Provision a device, then spawn the daemon with intentionally malformed
    // OUTPOST_TEST_CONNECT_ADDR and nonexistent OUTPOST_TEST_CA_PEM.
    // A production binary (without `test-tls-overrides`) MUST completely ignore both
    // env vars so `AppDaemon::load` -> `build_control_client_config` succeeds cleanly!
    let _dev = provision_device(&state_dir, &runtime_dir, 1003, 2003, [0x33u8; 32], "prod-check")?;

    let hostile_env = [
        ("OUTPOST_TEST_CONNECT_ADDR", "not-a-valid-socket-addr"),
        ("OUTPOST_TEST_CA_PEM", "/nonexistent/hostile/ca.pem"),
    ];

    let start_out = run_bin(
        &state_dir,
        &runtime_dir,
        &["daemon", "start", "--json"],
        None,
        &hostile_env,
    )?;
    let _ = run_bin(&state_dir, &runtime_dir, &["daemon", "stop"], None, &[]);

    if !start_out.status_ok {
        return Err(format!(
            "default binary honored OUTPOST_TEST_* env vars instead of ignoring them: stderr={}",
            start_out.stderr
        ));
    }
    if start_out.stderr.contains("OUTPOST_TEST_CONNECT_ADDR")
        || start_out.stderr.contains("OUTPOST_TEST_CA_PEM")
    {
        return Err(format!(
            "default binary parsed OUTPOST_TEST_* env vars: {}",
            start_out.stderr
        ));
    }

    // Also verify `device renew` refuses to renew an unknown device_id without `--device-pubkey-b64`.
    let root_key_path = root_tmp.path().join("root.key");
    std::fs::write(&root_key_path, B64.encode([0x33u8; 32]))
        .map_err(|e| format!("write root key: {e}"))?;
    let root_key_str = root_key_path.to_string_lossy().into_owned();
    let renew_out = run_bin(
        &state_dir,
        &runtime_dir,
        &[
            "device",
            "renew",
            "--device-id",
            "9999",
            "--account-id",
            "1003",
            "--root-key-file",
            &root_key_str,
        ],
        None,
        &hostile_env,
    )?;
    if renew_out.status_ok {
        return Err("device renew MUST refuse missing local device record without --device-pubkey-b64!".to_string());
    }
    if !renew_out.stderr.contains("--device-pubkey-b64") {
        return Err(format!(
            "expected device renew to require --device-pubkey-b64, got: {}",
            renew_out.stderr
        ));
    }

    Ok(())
}

// ===========================================================================
// Oracle 2: Full 2-Outpost Live E2E Party over Local TLS 1.3 Mock MP1 Server
//           + Real iroh v1.5.0 QUIC + MCP party_send / party_wait
// ===========================================================================

#[cfg(feature = "test-tls-overrides")]
mod live_e2e {
    use super::*;

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
    query: String,
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
    let (path_part, query_part) = target.split_once('?').unwrap_or((target, ""));
    let path = path_part.to_string();
    let query = query_part.to_string();

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
        query,
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

    let (chunks, _) = msg.as_chunks::<64>();
    for chunk in chunks {
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

// ===========================================================================
// Oracle 5 (v0.2.0 Identity Portability + Web Portal + Doctor E2E Oracle)
// ===========================================================================

struct MockLinkEntry {
    account_id: u64,
    link_code: String,
    suggested_label: String,
    claimed_pubkey: Option<[u8; 32]>,
    claimed_label: Option<String>,
    poll_token: Option<String>,
    approved_device_id: Option<u64>,
    approved_cwt_b64: Option<String>,
    approved_cwt_expires_ms: Option<u64>,
}

struct MockPortabilityState {
    next_account_id: u64,
    next_device_id: u64,
    accounts: HashMap<u64, MockPortabilityAccount>,
    links: HashMap<String, MockLinkEntry>,
    web_approved: bool,
    web_browser_fp: String,
    poll_429_remaining: u32,
    inspect_429_remaining: u32,
}

struct MockPortabilityAccount {
    account_id: u64,
    handle: String,
    root_pubkey: [u8; 32],
    devices: Vec<(u64, [u8; 32], String, u64)>,
}

async fn spawn_mock_portability_server(
    state: Arc<Mutex<MockPortabilityState>>,
) -> Result<(SocketAddr, String, tokio::task::JoinHandle<()>), String> {
    let (acceptor, cert_pem) = generate_mock_tls()?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind mock portability server: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("mock portability local_addr: {e}"))?;

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
                handle_portability_req(tls, req, state_c).await;
            });
        }
    });

    Ok((addr, cert_pem, handle))
}

async fn handle_portability_req<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    req: ParsedReq,
    state: Arc<Mutex<MockPortabilityState>>,
) {
    let now_ms = outpost_control::wall_now_ms();
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/health") => {
            write_http_json(
                &mut stream,
                200,
                "OK",
                &json!({ "ok": true, "server_now_ms": now_ms }),
            )
            .await;
        }
        ("GET", "/ping") => {
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
        ("POST", "/v1/accounts/register") => {
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({ "error": "bad_json" })).await;
                return;
            };
            let handle = body
                .get("handle")
                .and_then(Value::as_str)
                .unwrap_or("alice")
                .to_string();
            let label = body
                .get("device_label")
                .and_then(Value::as_str)
                .unwrap_or("primary")
                .to_string();
            let Some(root_pk_b64) = body.get("root_pubkey_b64").and_then(Value::as_str) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({ "error": "missing_root_pk" })).await;
                return;
            };
            let Some(dev_pk_b64) = body.get("device_pubkey_b64").and_then(Value::as_str) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({ "error": "missing_dev_pk" })).await;
                return;
            };
            let Ok(root_vec) = B64.decode(root_pk_b64.as_bytes()) else {
                return;
            };
            let Ok(dev_vec) = B64.decode(dev_pk_b64.as_bytes()) else {
                return;
            };
            let (Ok(root_pk), Ok(dev_pk)) = (
                <[u8; 32]>::try_from(root_vec),
                <[u8; 32]>::try_from(dev_vec),
            ) else {
                return;
            };

            let resp = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let aid = st.next_account_id;
                st.next_account_id += 1;
                let did = st.next_device_id;
                st.next_device_id += 1;
                st.accounts.insert(
                    aid,
                    MockPortabilityAccount {
                        account_id: aid,
                        handle: handle.clone(),
                        root_pubkey: root_pk,
                        devices: vec![(did, dev_pk, label, now_ms + 30 * 86_400_000)],
                    },
                );
                json!({
                    "account_id": aid,
                    "device_id": did,
                    "handle": handle,
                })
            };
            write_http_json(&mut stream, 201, "Created", &resp).await;
        }
        ("POST", "/v1/accounts/recover-lookup") => {
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({ "error": "bad_json" })).await;
                return;
            };
            let Some(root_pk_b64) = body.get("root_pubkey_b64").and_then(Value::as_str) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({ "error": "missing_root_pk" })).await;
                return;
            };
            let Ok(root_vec) = B64.decode(root_pk_b64.as_bytes()) else {
                return;
            };
            let Ok(root_pk) = <[u8; 32]>::try_from(root_vec) else {
                return;
            };

            let found = {
                let st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                st.accounts
                    .values()
                    .find(|a| a.root_pubkey == root_pk)
                    .map(|a| {
                        let sn = compute_safety_number(a.account_id, &a.root_pubkey);
                        let devs: Vec<Value> = a
                            .devices
                            .iter()
                            .map(|(did, dpk, lbl, exp_ms)| {
                                json!({
                                    "device_id": did,
                                    "pubkey_b64": B64.encode(dpk),
                                    "label": lbl,
                                    "cwt_expires_ms": exp_ms,
                                    "generation": 1,
                                    "pop_verified": true,
                                    "created_at_ms": now_ms,
                                    "revoked_at_ms": null,
                                })
                            })
                            .collect();
                        json!({
                            "account_id": a.account_id,
                            "handle": a.handle,
                            "root_pubkey_b64": B64.encode(a.root_pubkey),
                            "safety_number": sn,
                            "devices": devs,
                        })
                    })
            };
            if let Some(val) = found {
                write_http_json(&mut stream, 200, "OK", &val).await;
            } else {
                write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "not_found" })).await;
            }
        }
        ("POST", "/v1/devices") => {
            let caller_acc = extract_caller_account_id(&req.headers).unwrap_or(0);
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let label = body
                .get("device_label")
                .and_then(Value::as_str)
                .unwrap_or("recovered")
                .to_string();
            let Some(dev_pk_b64) = body.get("device_pubkey_b64").and_then(Value::as_str) else {
                return;
            };
            let Ok(dev_vec) = B64.decode(dev_pk_b64.as_bytes()) else {
                return;
            };
            let Ok(dev_pk) = <[u8; 32]>::try_from(dev_vec) else {
                return;
            };
            let exp_ms = now_ms + 30 * 86_400_000;
            let resp = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let did = st.next_device_id;
                st.next_device_id += 1;
                if let Some(acc) = st.accounts.get_mut(&caller_acc) {
                    acc.devices.push((did, dev_pk, label, exp_ms));
                }
                json!({
                    "device_id": did,
                    "cwt_expires_ms": exp_ms,
                })
            };
            write_http_json(&mut stream, 201, "Created", &resp).await;
        }
        ("POST", "/v1/device-links/create") => {
            let caller_acc = extract_caller_account_id(&req.headers).unwrap_or(0);
            let body = serde_json::from_slice::<Value>(&req.body).unwrap_or_default();
            let label = body
                .get("device_label")
                .and_then(Value::as_str)
                .unwrap_or("laptop")
                .to_string();
            let code = "W4K9-M2P7".to_string();
            let expires_at_ms = now_ms + 300_000;
            {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                st.links.insert(
                    code.clone(),
                    MockLinkEntry {
                        account_id: caller_acc,
                        link_code: code.clone(),
                        suggested_label: label,
                        claimed_pubkey: None,
                        claimed_label: None,
                        poll_token: None,
                        approved_device_id: None,
                        approved_cwt_b64: None,
                        approved_cwt_expires_ms: None,
                    },
                );
            }
            write_http_json(
                &mut stream,
                201,
                "Created",
                &json!({ "link_code": code, "expires_at_ms": expires_at_ms }),
            )
            .await;
        }
        ("POST", "/v1/device-links/claim") => {
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let code = body
                .get("link_code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let dev_pk_b64 = body
                .get("device_pubkey_b64")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let label = body
                .get("device_label")
                .and_then(Value::as_str)
                .unwrap_or("new-dev")
                .to_string();
            let Ok(dev_vec) = B64.decode(dev_pk_b64.as_bytes()) else {
                return;
            };
            let Ok(dev_pk) = <[u8; 32]>::try_from(dev_vec) else {
                return;
            };

            let resp = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(link) = st.links.get_mut(code) {
                    let tok = "mpdl1_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG".to_string();
                    link.claimed_pubkey = Some(dev_pk);
                    link.claimed_label = Some(label);
                    link.poll_token = Some(tok.clone());
                    Some(json!({
                        "poll_token": tok,
                        // Deliberately send a BOGUS server fingerprint to prove clients ignore it!
                        "device_fingerprint": "00000000-00000000-00000000-00000000",
                        "expires_at_ms": now_ms + 300_000,
                    }))
                } else {
                    None
                }
            };
            if let Some(v) = resp {
                write_http_json(&mut stream, 200, "OK", &v).await;
            } else {
                write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "invalid_or_expired_link" })).await;
            }
        }
        ("POST", "/v1/device-links/inspect") => {
            let send_429 = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if st.inspect_429_remaining > 0 {
                    st.inspect_429_remaining -= 1;
                    true
                } else {
                    false
                }
            };
            if send_429 {
                let body = r#"{"error":"rate_limited"}"#;
                let resp = format!(
                    "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                return;
            }
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let code = body
                .get("link_code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let resp = {
                let st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                st.links.get(code).map(|link| {
                    if let Some(dpk) = link.claimed_pubkey {
                        json!({
                            "state": "pending_approval",
                            "device_pubkey_b64": B64.encode(dpk),
                            // Deliberately BOGUS server fingerprint — primary MUST compute locally!
                            "device_fingerprint": "ffffffff-ffffffff-ffffffff-ffffffff",
                            "device_label": link.claimed_label.clone().unwrap_or_default(),
                            "requester_country": "US",
                            "created_at_ms": now_ms,
                            "expires_at_ms": now_ms + 300_000,
                        })
                    } else {
                        json!({
                            "state": "waiting_for_device",
                            "suggested_label": link.suggested_label,
                            "created_at_ms": now_ms,
                            "expires_at_ms": now_ms + 300_000,
                        })
                    }
                })
            };
            if let Some(v) = resp {
                write_http_json(&mut stream, 200, "OK", &v).await;
            } else {
                write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "invalid_or_expired_link" })).await;
            }
        }
        ("POST", "/v1/device-links/approve") => {
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let code = body
                .get("link_code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let cwt_b64 = body
                .get("device_cwt_b64")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let label_override = body
                .get("device_label")
                .and_then(Value::as_str)
                .map(str::to_string);

            let resp = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let did = st.next_device_id;
                st.next_device_id += 1;
                let exp_ms = now_ms + 30 * 86_400_000;
                if let Some(link) = st.links.get_mut(code) {
                    let aid = link.account_id;
                    let dpk = link.claimed_pubkey.unwrap_or([0u8; 32]);
                    let lbl = label_override
                        .or_else(|| link.claimed_label.clone())
                        .unwrap_or_else(|| link.suggested_label.clone());
                    let fp = mp_protocol::compute_device_fingerprint(&dpk);
                    link.approved_device_id = Some(did);
                    link.approved_cwt_b64 = Some(cwt_b64);
                    link.approved_cwt_expires_ms = Some(exp_ms);
                    let _ = &link.link_code;
                    if let Some(acc) = st.accounts.get_mut(&aid) {
                        acc.devices.push((did, dpk, lbl.clone(), exp_ms));
                    }
                    Some(json!({
                        "approved": true,
                        "account_id": aid,
                        "device_id": did,
                        "device_label": lbl,
                        "device_fingerprint": fp,
                        "cwt_expires_ms": exp_ms,
                    }))
                } else {
                    None
                }
            };
            if let Some(v) = resp {
                write_http_json(&mut stream, 200, "OK", &v).await;
            } else {
                write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "invalid_or_expired_link" })).await;
            }
        }
        ("POST", "/v1/device-links/poll") => {
            let send_429 = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if st.poll_429_remaining > 0 {
                    st.poll_429_remaining -= 1;
                    true
                } else {
                    false
                }
            };
            if send_429 {
                let body = r#"{"error":"rate_limited"}"#;
                let resp = format!(
                    "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                return;
            }
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let code = body
                .get("link_code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let poll_tok = body
                .get("poll_token")
                .and_then(Value::as_str)
                .unwrap_or_default();

            let (status, reason, val) = {
                let st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(link) = st.links.get(code)
                    && link.poll_token.as_deref() == Some(poll_tok)
                {
                    if let (Some(did), Some(cwt_b64), Some(exp_ms)) = (
                        link.approved_device_id,
                        link.approved_cwt_b64.as_ref(),
                        link.approved_cwt_expires_ms,
                    ) && let Some(acc) = st.accounts.get(&link.account_id)
                    {
                        let sn = compute_safety_number(acc.account_id, &acc.root_pubkey);
                        (
                            200u16,
                            "OK",
                            json!({
                                "status": "approved",
                                "account_id": acc.account_id,
                                "handle": acc.handle,
                                "device_id": did,
                                "root_pubkey_b64": B64.encode(acc.root_pubkey),
                                "device_cwt_b64": cwt_b64,
                                "cwt_expires_ms": exp_ms,
                                "safety_number": sn,
                            }),
                        )
                    } else {
                        (
                            202u16,
                            "Accepted",
                            json!({
                                "status": "pending",
                                "expires_at_ms": now_ms + 300_000,
                            }),
                        )
                    }
                } else {
                    (
                        404u16,
                        "Not Found",
                        json!({ "error": "invalid_or_expired_link" }),
                    )
                }
            };
            write_http_json(&mut stream, status, reason, &val).await;
        }
        ("POST", "/v1/web-sessions/inspect") => {
            let fp = {
                let st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                st.web_browser_fp.clone()
            };
            write_http_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "pending": true,
                    "scope": "account:read",
                    "browser_fingerprint": fp,
                    "requester_country": "US",
                    "requester_client": "Firefox 132 / macOS",
                    "created_at_ms": now_ms,
                    "expires_at_ms": now_ms + 300_000,
                }),
            )
            .await;
        }
        ("POST", "/v1/web-sessions/approve") => {
            let caller_acc = extract_caller_account_id(&req.headers).unwrap_or(1001);
            let fp = {
                let mut st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                st.web_approved = true;
                st.web_browser_fp.clone()
            };
            write_http_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "approved": true,
                    "scope": "account:read",
                    "account_id": caller_acc,
                    "approved_device_id": 2001,
                    "approved_by_root": false,
                    "browser_fingerprint": fp,
                    "requester_country": "US",
                    "requester_client": "Firefox 132 / macOS",
                }),
            )
            .await;
        }
        _ => {
            write_http_json(&mut stream, 404, "Not Found", &json!({ "error": "not_found" })).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oracle_5_identity_portability_device_link_web_approve_and_doctor() -> Result<(), String> {
    let root_tmp = make_short_tempdir("mpo5")?;
    let primary_st = make_private_subdir(root_tmp.path(), "ps")?;
    let primary_rt = make_private_subdir(root_tmp.path(), "pr")?;
    let recover_st = make_private_subdir(root_tmp.path(), "rs")?;
    let recover_rt = make_private_subdir(root_tmp.path(), "rr")?;
    let linked_st = make_private_subdir(root_tmp.path(), "ls")?;
    let linked_rt = make_private_subdir(root_tmp.path(), "lr")?;

    let mock_state = Arc::new(Mutex::new(MockPortabilityState {
        next_account_id: 5001,
        next_device_id: 6001,
        accounts: HashMap::new(),
        links: HashMap::new(),
        web_approved: false,
        web_browser_fp: "a1b2c3d4".to_string(),
        poll_429_remaining: 1,
        inspect_429_remaining: 1,
    }));
    let (server_addr, cert_pem, server_task) =
        spawn_mock_portability_server(Arc::clone(&mock_state)).await?;
    let ca_path = root_tmp.path().join("mock_ca.pem");
    std::fs::write(&ca_path, cert_pem).map_err(|e| format!("write ca pem: {e}"))?;

    let addr_str = server_addr.to_string();
    let ca_str = ca_path.to_string_lossy().into_owned();
    let env_vars = [
        ("OUTPOST_TEST_CONNECT_ADDR", addr_str.as_str()),
        ("OUTPOST_TEST_CA_PEM", ca_str.as_str()),
    ];

    let root_key_path = root_tmp.path().join("root.key");
    let root_key_str = root_key_path.to_string_lossy().into_owned();
    let rk_out_path = root_tmp.path().join("recovery.key");
    let rk_out_str = rk_out_path.to_string_lossy().into_owned();
    let rk_out2_path = root_tmp.path().join("recovery2.key");
    let rk_out2_str = rk_out2_path.to_string_lossy().into_owned();
    let mpkey_path = root_tmp.path().join("backup.mpkey");
    let mpkey_str = mpkey_path.to_string_lossy().into_owned();

    let result: Result<(), String> = async {
        // 1. `account register --json` MUST NEVER leak `mprk1_` on stdout; writes canonical `0600` `mprk1_` to files!
        let reg_out = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "account",
                "register",
                "--handle",
                "antimeme",
                "--device-label",
                "primary-box",
                "--root-key-out",
                &root_key_str,
                "--recovery-key-out",
                &rk_out_str,
                "--invite-stdin",
            ],
            Some(b"mpinv1_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG\n"),
            &env_vars,
        )?;
        if !reg_out.status_ok {
            return Err(format!("account register failed: {}", reg_out.stderr));
        }
        if reg_out.stdout.contains("mprk1_") {
            return Err(format!(
                "account register --json MUST NOT leak mprk1_ to stdout: {}",
                reg_out.stdout
            ));
        }
        let reg_json: Value =
            serde_json::from_str(&reg_out.stdout).map_err(|e| format!("reg json: {e}"))?;
        if reg_json.get("recovery_key").is_some() {
            return Err(format!("account register --json must not include recovery_key field: {reg_json}"));
        }
        let account_id = reg_json
            .get("account_id")
            .and_then(Value::as_u64)
            .ok_or("missing account_id")?;
        let reg_sn = reg_json
            .get("safety_number")
            .and_then(Value::as_str)
            .ok_or("missing safety_number")?
            .to_string();

        // Both root.key and recovery.key are mode 0600 canonical mprk1_ files with identical seed!
        for key_path in [&root_key_path, &rk_out_path] {
            let meta = std::fs::metadata(key_path).map_err(|e| format!("key stat: {e}"))?;
            if (meta.permissions().mode() & 0o777) != 0o600 {
                return Err(format!("{} must have mode 0600!", key_path.display()));
            }
        }
        let reg_rk = std::fs::read_to_string(&rk_out_path)
            .map_err(|e| format!("read rk_out: {e}"))?
            .trim()
            .to_string();
        let root_rk = std::fs::read_to_string(&root_key_path)
            .map_err(|e| format!("read root_key: {e}"))?
            .trim()
            .to_string();
        if !reg_rk.starts_with("mprk1_") || reg_rk != root_rk {
            return Err(format!(
                "expected identical canonical mprk1_ in root & recovery files: rk={reg_rk} root={root_rk}"
            ));
        }
        let decoded_seed = mp_protocol::decode_recovery_key(&reg_rk)
            .map_err(|e| format!("decode registered recovery_key: {e}"))?;

        // 2. `account recovery-key` refuses headless stdout without `--recovery-key-out`,
        //    and writes exact `0600` `mprk1_` file with `--recovery-key-out`!
        let rk_headless = run_bin(
            &primary_st,
            &primary_rt,
            &["account", "recovery-key", "--root-key-file", &root_key_str],
            None,
            &env_vars,
        )?;
        if rk_headless.status_ok || rk_headless.stdout.contains("mprk1_") {
            return Err(format!(
                "headless account recovery-key without --recovery-key-out MUST be refused: ok={} out={}",
                rk_headless.status_ok, rk_headless.stdout
            ));
        }
        let rk_json_headless = run_bin(
            &primary_st,
            &primary_rt,
            &["--json", "account", "recovery-key", "--root-key-file", &root_key_str],
            None,
            &env_vars,
        )?;
        if rk_json_headless.status_ok || rk_json_headless.stdout.contains("mprk1_") {
            return Err("account recovery-key --json without --recovery-key-out MUST be refused!".to_string());
        }
        let rk_file_out = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "account",
                "recovery-key",
                "--root-key-file",
                &root_key_str,
                "--recovery-key-out",
                &rk_out2_str,
            ],
            None,
            &env_vars,
        )?;
        if !rk_file_out.status_ok || rk_file_out.stdout.contains("mprk1_") {
            return Err(format!(
                "account recovery-key --recovery-key-out failed or leaked key: stderr={} out={}",
                rk_file_out.stderr, rk_file_out.stdout
            ));
        }
        let rk2_text = std::fs::read_to_string(&rk_out2_path)
            .map_err(|e| format!("read rk2: {e}"))?
            .trim()
            .to_string();
        if rk2_text != reg_rk {
            return Err("account recovery-key --recovery-key-out mismatch!".to_string());
        }

        // 3. `account export-mpkey` -> mode 0600 -> refuses overwrite without --force -> succeeds with --force!
        let pass = "correct-horse-battery-staple\n";
        let export_out = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "account",
                "export-mpkey",
                "--root-key-file",
                &root_key_str,
                "--out",
                &mpkey_str,
                "--account-id",
                &account_id.to_string(),
                "--handle",
                "antimeme",
                "--passphrase-stdin",
            ],
            Some(pass.as_bytes()),
            &env_vars,
        )?;
        if !export_out.status_ok {
            return Err(format!("account export-mpkey failed: {}", export_out.stderr));
        }
        let mpkey_meta =
            std::fs::metadata(&mpkey_path).map_err(|e| format!("mpkey stat: {e}"))?;
        if (mpkey_meta.permissions().mode() & 0o777) != 0o600 {
            return Err("exported .mpkey does not have mode 0600!".to_string());
        }

        // Second export without --force MUST fail closed!
        let export_noclobber = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "account",
                "export-mpkey",
                "--root-key-file",
                &root_key_str,
                "--out",
                &mpkey_str,
                "--passphrase-stdin",
            ],
            Some(pass.as_bytes()),
            &env_vars,
        )?;
        if export_noclobber.status_ok {
            return Err("account export-mpkey MUST refuse to overwrite existing .mpkey without --force!".to_string());
        }

        // With --force it succeeds cleanly!
        let export_force = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "account",
                "export-mpkey",
                "--root-key-file",
                &root_key_str,
                "--out",
                &mpkey_str,
                "--account-id",
                &account_id.to_string(),
                "--handle",
                "antimeme",
                "--passphrase-stdin",
                "--force",
            ],
            Some(pass.as_bytes()),
            &env_vars,
        )?;
        if !export_force.status_ok {
            return Err(format!("account export-mpkey --force failed: {}", export_force.stderr));
        }

        let rec_out = run_bin(
            &recover_st,
            &recover_rt,
            &[
                "--json",
                "account",
                "recover",
                "--mpkey",
                &mpkey_str,
                "--passphrase-stdin",
                "--device-label",
                "recovered-laptop",
                "--relay-policy",
                "no",
            ],
            Some(pass.as_bytes()),
            &env_vars,
        )?;
        if !rec_out.status_ok {
            return Err(format!("account recover failed: {}", rec_out.stderr));
        }
        let rec_json: Value =
            serde_json::from_str(&rec_out.stdout).map_err(|e| format!("recover json: {e}"))?;
        if rec_json.get("account_id").and_then(Value::as_u64) != Some(account_id)
            || rec_json.get("safety_number").and_then(Value::as_str) != Some(reg_sn.as_str())
        {
            return Err(format!("account recover mismatch: {rec_json}"));
        }
        let _ = decoded_seed;

        // 4. Full concurrent Device Link flow WITH simulated HTTP 429 + Retry-After: 1 on BOTH
        //    `device link join` poll AND `device link approve --wait` inspect!
        let create_out = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "device",
                "link",
                "create",
                "--root-key-file",
                &root_key_str,
                "--device-label",
                "wintermute",
            ],
            None,
            &env_vars,
        )?;
        if !create_out.status_ok {
            return Err(format!("device link create failed: {}", create_out.stderr));
        }
        let create_json: Value =
            serde_json::from_str(&create_out.stdout).map_err(|e| format!("create json: {e}"))?;
        let link_code = create_json
            .get("link_code")
            .and_then(Value::as_str)
            .ok_or("missing link_code")?
            .to_string();

        // Spawn `device link join` concurrently as a real child process!
        let mut join_cmd = Command::new(BIN_PATH);
        join_cmd
            .arg("--state-dir")
            .arg(&linked_st)
            .arg("--runtime-dir")
            .arg(&linked_rt)
            .arg("--json")
            .args([
                "device",
                "link",
                "join",
                &link_code,
                "--device-label",
                "wintermute",
                "--relay-policy",
                "no",
                "--timeout-secs",
                "20",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for &(k, v) in &env_vars {
            join_cmd.env(k, v);
        }
        let mut join_child = join_cmd
            .spawn()
            .map_err(|e| format!("spawn device link join: {e}"))?;
        let join_stderr = join_child.stderr.take().ok_or("missing join stderr")?;

        // Read the locally computed 128-bit fingerprint printed by the new machine!
        let join_fp = tokio::task::spawn_blocking(move || -> Result<String, String> {
            let mut reader = BufReader::new(join_stderr);
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader
                    .read_line(&mut line)
                    .map_err(|e| format!("read join stderr: {e}"))?;
                if n == 0 {
                    return Err("EOF before device fingerprint was printed".to_string());
                }
                if let Some(fp) = line
                    .trim()
                    .strip_prefix("Device fingerprint (verify on primary): ")
                {
                    return Ok(fp.trim().to_string());
                }
            }
        })
        .await
        .map_err(|e| format!("join stderr task: {e}"))??;

        // Primary refuses wrong fingerprint (passing --wait so inspect survives 429 retry)!
        let bad_approve = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "device",
                "link",
                "approve",
                &link_code,
                "--root-key-file",
                &root_key_str,
                "--wait",
                "--yes-fingerprint",
                "ffffffff-ffffffff-ffffffff-ffffffff",
            ],
            None,
            &env_vars,
        )?;
        if bad_approve.status_ok {
            return Err("device link approve MUST reject bogus server fingerprint!".to_string());
        }

        // Primary approves using the exact locally computed fingerprint (with --wait)!
        let approve_out = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "device",
                "link",
                "approve",
                &link_code,
                "--root-key-file",
                &root_key_str,
                "--wait",
                "--yes-fingerprint",
                &join_fp,
            ],
            None,
            &env_vars,
        )?;
        if !approve_out.status_ok {
            return Err(format!("device link approve failed: {}", approve_out.stderr));
        }

        // Wait for `device link join` to survive the 429 Retry-After, collect the verified CWT, and save!
        let join_output = tokio::task::spawn_blocking(move || join_child.wait_with_output())
            .await
            .map_err(|e| format!("wait join task: {e}"))?
            .map_err(|e| format!("wait join output: {e}"))?;
        if !join_output.status.success() {
            return Err(format!(
                "device link join failed: stdout={} stderr={}",
                String::from_utf8_lossy(&join_output.stdout),
                String::from_utf8_lossy(&join_output.stderr)
            ));
        }
        let join_json: Value = serde_json::from_slice(&join_output.stdout)
            .map_err(|e| format!("join json: {e}"))?;
        if join_json.get("linked").and_then(Value::as_bool) != Some(true)
            || join_json.get("account_id").and_then(Value::as_u64) != Some(account_id)
            || join_json.get("safety_number").and_then(Value::as_str) != Some(reg_sn.as_str())
        {
            return Err(format!("unexpected device link join result: {join_json}"));
        }

        // Verify linked device can immediately run offline `whoami --safety-number`!
        let linked_who = run_bin(
            &linked_st,
            &linked_rt,
            &["whoami", "--safety-number"],
            None,
            &env_vars,
        )?;
        if !linked_who.status_ok || linked_who.stdout.trim() != reg_sn {
            return Err(format!(
                "linked device whoami mismatch: ok={} out={}",
                linked_who.status_ok, linked_who.stdout
            ));
        }

        // 5. `web approve`:
        //    (a) headless `--yes-browser-fingerprint` WITHOUT `--root-key-file` MUST be refused!
        let headless_no_root = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "web",
                "approve",
                "ABCD-EFGH",
                "--yes-browser-fingerprint",
                "a1b2c3d4",
            ],
            None,
            &env_vars,
        )?;
        if headless_no_root.status_ok {
            return Err("headless web approve --yes-browser-fingerprint without --root-key-file MUST be refused!".to_string());
        }

        //    (b) malformed fingerprint MUST be refused!
        let bad_fmt_web = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "web",
                "approve",
                "ABCD-EFGH",
                "--root-key-file",
                &root_key_str,
                "--yes-browser-fingerprint",
                "not-8hex!",
            ],
            None,
            &env_vars,
        )?;
        if bad_fmt_web.status_ok {
            return Err("web approve MUST reject non-8-hex browser fingerprint!".to_string());
        }

        //    (c) mismatched valid 8-hex fingerprint MUST be refused!
        let bad_web = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "web",
                "approve",
                "ABCD-EFGH",
                "--root-key-file",
                &root_key_str,
                "--yes-browser-fingerprint",
                "00000000",
            ],
            None,
            &env_vars,
        )?;
        if bad_web.status_ok {
            return Err("web approve MUST reject mismatched browser fingerprint!".to_string());
        }

        //    (d) exact 8-hex fingerprint WITH `--root-key-file` succeeds!
        let ok_web = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "web",
                "approve",
                "ABCD-EFGH",
                "--root-key-file",
                &root_key_str,
                "--yes-browser-fingerprint",
                "a1b2c3d4",
            ],
            None,
            &env_vars,
        )?;
        if !ok_web.status_ok {
            return Err(format!("web approve failed: {}", ok_web.stderr));
        }
        let web_json: Value =
            serde_json::from_str(&ok_web.stdout).map_err(|e| format!("web json: {e}"))?;
        if web_json.get("approved").and_then(Value::as_bool) != Some(true) {
            return Err(format!("expected approved=true: {web_json}"));
        }

        // 6. `doctor --json` non-destructive health check against local TLS 1.3 mock server,
        //    plus independent relay probe when `--api-authority` is invalid!
        let doc_out = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "doctor",
                "--relay-url",
                "https://api.multiplayer.tech",
            ],
            None,
            &env_vars,
        )?;
        if !doc_out.status_ok {
            return Err(format!("doctor failed: {}", doc_out.stderr));
        }
        let doc_json: Value =
            serde_json::from_str(&doc_out.stdout).map_err(|e| format!("doctor json: {e}"))?;
        if doc_json.pointer("/device/enrolled").and_then(Value::as_bool) != Some(true)
            || doc_json.pointer("/device/cwt_valid").and_then(Value::as_bool) != Some(true)
            || doc_json.pointer("/control_plane/ok").and_then(Value::as_bool) != Some(true)
            || doc_json.pointer("/relay/ok").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!("unexpected doctor report: {doc_json}"));
        }

        let doc_indep = run_bin(
            &primary_st,
            &primary_rt,
            &[
                "--json",
                "doctor",
                "--api-authority",
                "bad authority with spaces",
                "--relay-url",
                "https://api.multiplayer.tech",
            ],
            None,
            &env_vars,
        )?;
        if !doc_indep.status_ok {
            return Err(format!("doctor independent probe failed: {}", doc_indep.stderr));
        }
        let doc_indep_json: Value =
            serde_json::from_str(&doc_indep.stdout).map_err(|e| format!("doctor indep json: {e}"))?;
        if doc_indep_json.pointer("/control_plane/ok").and_then(Value::as_bool) != Some(false)
            || doc_indep_json.pointer("/relay/ok").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!(
                "invalid api_authority must NOT suppress relay ping probe: {doc_indep_json}"
            ));
        }

        Ok(())
    }
    .await;

    server_task.abort();
    result
}

// ===========================================================================
// Oracle 6 (v0.3.0 Native Self-Upgrade over Real TLS 1.3 Mock Release Server)
// ===========================================================================

fn current_target_slug_test() -> Result<&'static str, String> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok("darwin-arm64")
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok("linux-x86_64")
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Ok("linux-arm64")
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        Err("unsupported platform for upgrade E2E test".to_string())
    }
}

fn hex_lower_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        if let (Some(&hi), Some(&lo)) = (
            HEX.get(usize::from(b >> 4)),
            HEX.get(usize::from(b & 0x0f)),
        ) {
            s.push(char::from(hi));
            s.push(char::from(lo));
        }
    }
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_6_tls13_self_upgrade_and_sha256_tamper_rejection() -> Result<(), String> {
    let target = current_target_slug_test()?;
    let root_tmp = make_short_tempdir("mpo6")?;
    let state_dir = make_private_subdir(root_tmp.path(), "st")?;
    let runtime_dir = make_private_subdir(root_tmp.path(), "rt")?;
    let pkg_stage = make_private_subdir(root_tmp.path(), "pkg")?;

    let version = "v9.9.9";
    let stem = format!("mp-outpost-{version}-{target}");
    let pkg_sub = pkg_stage.join(&stem);
    std::fs::create_dir(&pkg_sub).map_err(|e| format!("mkdir pkg_sub: {e}"))?;

    let stub_bin = pkg_sub.join("mp-outpost");
    std::fs::write(&stub_bin, "#!/bin/sh\necho \"mp-outpost 9.9.9 (tls-e2e)\"\n")
        .map_err(|e| format!("write stub: {e}"))?;
    std::fs::set_permissions(&stub_bin, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod stub: {e}"))?;

    let tarball_name = format!("{stem}.tar.gz");
    let tarball_path = root_tmp.path().join(&tarball_name);
    let tar_status = Command::new("tar")
        .arg("-C")
        .arg(&pkg_stage)
        .arg("-czf")
        .arg(&tarball_path)
        .arg(&stem)
        .status()
        .map_err(|e| format!("tar create: {e}"))?;
    if !tar_status.success() {
        return Err("tar create failed".to_string());
    }

    let tb_bytes = std::fs::read(&tarball_path).map_err(|e| format!("read tarball: {e}"))?;
    let tb_sha = hex_lower_32(&mp_protocol::sha256(&tb_bytes));
    let tb_size = tb_bytes.len() as u64;

    let sums_bytes = format!("{tb_sha}  {tarball_name}\n").into_bytes();
    let manifest_bytes = json!({
        "version": version,
        "commit": "deadbeefcafe",
        "assets": [{
            "target": target,
            "filename": tarball_name,
            "sha256": tb_sha,
            "size_bytes": tb_size,
        }]
    })
    .to_string()
    .into_bytes();

    let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::from([
        ("/release-manifest.json".to_string(), manifest_bytes),
        ("/SHA256SUMS.txt".to_string(), sums_bytes),
        (format!("/{tarball_name}"), tb_bytes.clone()),
    ])));

    let (acceptor, cert_pem) = generate_mock_tls()?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind release mock: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("release mock addr: {e}"))?;

    let files_srv = Arc::clone(&files);
    let server_task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor_c = acceptor.clone();
            let files_c = Arc::clone(&files_srv);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor_c.accept(tcp).await else {
                    return;
                };
                let Ok(req) = read_http_req(&mut tls).await else {
                    return;
                };
                let payload = {
                    let map = files_c
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    map.get(&req.path).cloned()
                };
                if let Some(body) = payload {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = tls.write_all(head.as_bytes()).await;
                    let _ = tls.write_all(&body).await;
                    let _ = tls.flush().await;
                } else {
                    let _ = tls
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    let _ = tls.flush().await;
                }
            });
        }
    });

    let ca_path = root_tmp.path().join("release_ca.pem");
    std::fs::write(&ca_path, cert_pem).map_err(|e| format!("write ca: {e}"))?;
    let addr_str = addr.to_string();
    let ca_str = ca_path.to_string_lossy().into_owned();
    let env_vars = [
        ("OUTPOST_TEST_CONNECT_ADDR", addr_str.as_str()),
        ("OUTPOST_TEST_CA_PEM", ca_str.as_str()),
    ];
    let base_url = format!("https://{TEST_AUTHORITY}");

    let install_dir = make_private_subdir(root_tmp.path(), "bin")?;
    let install_path = install_dir.join("mp-outpost");
    std::fs::write(&install_path, b"old-bin").map_err(|e| format!("seed old bin: {e}"))?;
    let install_str = install_path.to_string_lossy().into_owned();

    let result: Result<(), String> = (|| {
        // 1. `mp-outpost --json upgrade --check` over real TLS 1.3!
        let chk = run_bin(
            &state_dir,
            &runtime_dir,
            &["--json", "upgrade", "--check", "--base-url", &base_url],
            None,
            &env_vars,
        )?;
        if !chk.status_ok {
            return Err(format!("upgrade --check failed: {}", chk.stderr));
        }
        let chk_json: Value =
            serde_json::from_str(&chk.stdout).map_err(|e| format!("chk json: {e}"))?;
        if chk_json.get("update_available").and_then(Value::as_bool) != Some(true)
            || chk_json.get("latest_version").and_then(Value::as_str) != Some("v9.9.9")
        {
            return Err(format!("unexpected upgrade --check output: {chk_json}"));
        }

        // 2. Full `mp-outpost --json upgrade --yes` atomic 0755 install!
        let upg = run_bin(
            &state_dir,
            &runtime_dir,
            &[
                "--json",
                "upgrade",
                "--yes",
                "--base-url",
                &base_url,
                "--install-path",
                &install_str,
            ],
            None,
            &env_vars,
        )?;
        if !upg.status_ok {
            return Err(format!("upgrade --yes failed: {}", upg.stderr));
        }
        let meta = std::fs::metadata(&install_path).map_err(|e| format!("meta: {e}"))?;
        if (meta.permissions().mode() & 0o777) != 0o755 {
            return Err("upgraded binary must have mode 0755!".to_string());
        }
        let ver_out = Command::new(&install_path)
            .arg("--version")
            .output()
            .map_err(|e| format!("run upgraded bin: {e}"))?;
        if !ver_out.status.success()
            || !String::from_utf8_lossy(&ver_out.stdout).starts_with("mp-outpost 9.9.9")
        {
            return Err("upgraded binary did not pass --version check!".to_string());
        }

        // 3. Tamper tarball on server -> MUST reject with SHA-256 mismatch and leave binary intact!
        let mut tampered = tb_bytes.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xff;
        }
        {
            let mut map = files
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            map.insert(format!("/{tarball_name}"), tampered);
        }
        let bad = run_bin(
            &state_dir,
            &runtime_dir,
            &[
                "upgrade",
                "--yes",
                "--base-url",
                &base_url,
                "--install-path",
                &install_str,
            ],
            None,
            &env_vars,
        )?;
        if bad.status_ok || !bad.stderr.contains("SHA-256 mismatch") {
            return Err(format!(
                "tampered tarball MUST be rejected with SHA-256 mismatch: ok={} stderr={}",
                bad.status_ok, bad.stderr
            ));
        }

        Ok(())
    })();

    server_task.abort();
    result
}

pub(super) async fn verify_relays_cli_against_mock_tls13(
    root_tmp: &Path,
    state_dir: &Path,
    runtime_dir: &Path,
) -> Result<(), String> {
    let (acceptor, cert_pem) = generate_mock_tls()?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind relays mock: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("relays mock addr: {e}"))?;

    let relays_body = json!({
        "default_relay_url": format!("https://{TEST_AUTHORITY}"),
        "relays": [
            {
                "url": format!("https://{TEST_AUTHORITY}"),
                "region": "us-east",
                "label": "US East Primary",
                "default": true
            }
        ]
    })
    .to_string()
    .into_bytes();

    let server_task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor_c = acceptor.clone();
            let body_c = relays_body.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor_c.accept(tcp).await else {
                    return;
                };
                let Ok(req) = read_http_req(&mut tls).await else {
                    return;
                };
                if req.method == "GET" && req.path == "/v1/relays" {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body_c.len()
                    );
                    let _ = tls.write_all(head.as_bytes()).await;
                    let _ = tls.write_all(&body_c).await;
                    let _ = tls.flush().await;
                } else if req.method == "GET" && req.path == "/ping" {
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = tls.flush().await;
                } else {
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = tls.flush().await;
                }
            });
        }
    });

    let ca_path = root_tmp.join("relays_ca.pem");
    std::fs::write(&ca_path, cert_pem).map_err(|e| format!("write relays ca: {e}"))?;
    let addr_str = addr.to_string();
    let ca_str = ca_path.to_string_lossy().into_owned();
    let env_vars = [
        ("OUTPOST_TEST_CONNECT_ADDR", addr_str.as_str()),
        ("OUTPOST_TEST_CA_PEM", ca_str.as_str()),
    ];

    let result: Result<(), String> = (|| {
        let out = run_bin(
            state_dir,
            runtime_dir,
            &["--json", "relays", "--api-authority", TEST_AUTHORITY],
            None,
            &env_vars,
        )?;
        if !out.status_ok {
            return Err(format!("relays --json failed: {}", out.stderr));
        }
        let j: Value =
            serde_json::from_str(&out.stdout).map_err(|e| format!("parse relays json: {e}"))?;
        let expected_url = format!("https://{TEST_AUTHORITY}");
        if j.get("default_relay_url").and_then(Value::as_str) != Some(expected_url.as_str())
            || j.pointer("/relays/0/region").and_then(Value::as_str) != Some("us-east")
            || j.pointer("/relays/0/url").and_then(Value::as_str) != Some(expected_url.as_str())
        {
            return Err(format!("unexpected relays --json output: {j}"));
        }

        let ping_out = run_bin(
            state_dir,
            runtime_dir,
            &["--json", "relays", "--ping", "--api-authority", TEST_AUTHORITY],
            None,
            &env_vars,
        )?;
        if !ping_out.status_ok {
            return Err(format!("relays --ping --json failed: {}", ping_out.stderr));
        }
        let pj: Value = serde_json::from_str(&ping_out.stdout)
            .map_err(|e| format!("parse relays --ping json: {e}"))?;
        if pj.get("pinged").and_then(Value::as_bool) != Some(true)
            || pj.get("fastest_relay_url").and_then(Value::as_str) != Some(expected_url.as_str())
            || pj.pointer("/relays/0/ok").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!("unexpected relays --ping --json output: {pj}"));
        }

        Ok(())
    })();

    server_task.abort();
    result
}

// ===========================================================================
// Oracle 8: Xbox Live `mp2` WSS Room, Unpinned Chat/AgentCard, Cloud Login +
//           Silent CWT Auto-Renew, 1-Verb CLI Hygiene, New MCP Tools & --strict-pins
// ===========================================================================

struct Mp2MockAccount {
    account_id: u64,
    device_id: u64,
    handle: String,
    root_sk: SigningKey,
    device_pubkey: [u8; 32],
}

struct Mp2MockServerState {
    accounts: HashMap<u64, Mp2MockAccount>,
    flows: HashMap<String, (u64, String, [u8; 32], usize, i64)>, // flow_id -> (acc_id, handle, dev_pk, poll_count, cwt_ttl)
    next_login_idx: usize,
    renew_calls: usize,
    room_seq: u64,
    dedup: HashMap<String, u64>,
    room_members: Vec<Value>,
    pending_invite_for_bob: bool,
    room_tx: broadcast::Sender<String>,
}

async fn spawn_mock_mp2_server(
    state: Arc<Mutex<Mp2MockServerState>>,
) -> Result<(SocketAddr, String, tokio::task::JoinHandle<()>), String> {
    let certified = rcgen::generate_simple_self_signed(vec![TEST_AUTHORITY.to_string()])
        .map_err(|e| format!("rcgen failed: {e}"))?;
    let cert_pem = certified.cert.pem();
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut srv_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls13 server cfg: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("server cert: {e}"))?;
    srv_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(srv_cfg));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind mp2 mock: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acc = acceptor.clone();
            let st = Arc::clone(&state);
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else {
                    return;
                };
                let Ok(req) = read_http_req(&mut tls).await else {
                    return;
                };
                handle_mock_mp2_conn(tls, req, st).await;
            });
        }
    });
    Ok((addr, cert_pem, handle))
}

async fn handle_mock_mp2_conn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    req: ParsedReq,
    state: Arc<Mutex<Mp2MockServerState>>,
) {
    let caller_acc = extract_caller_account_id(&req.headers).unwrap_or(1001);

    // WebSocket upgrade routes
    if req
        .headers
        .get("upgrade")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
        == Some("websocket")
    {
        let Some(ws_key) = req.headers.get("sec-websocket-key") else {
            return;
        };
        let proto = req
            .headers
            .get("sec-websocket-protocol")
            .map(String::as_str)
            .unwrap_or("mp1");
        let accept = compute_ws_accept(ws_key);
        let upgrade_resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {proto}\r\n\r\n"
        );
        if stream.write_all(upgrade_resp.as_bytes()).await.is_err() {
            return;
        }
        let _ = stream.flush().await;

        if proto == "mp2" {
            let (self_handle, latest_seq, members, mut rx) = {
                let st = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let h = st
                    .accounts
                    .get(&caller_acc)
                    .map(|a| a.handle.clone())
                    .unwrap_or_else(|| format!("user{caller_acc}"));
                (h, st.room_seq, st.room_members.clone(), st.room_tx.subscribe())
            };
            let hello = json!({
                "v": 2,
                "t": "hello",
                "party_id": "8801",
                "room_code": "KAIH",
                "name": "Squad",
                "self": { "account_id": caller_acc.to_string(), "handle": self_handle, "client": "outpost" },
                "latest_seq": latest_seq,
                "members": members,
                "history": []
            })
            .to_string();
            if write_ws_frame(&mut stream, 0x1, hello.as_bytes())
                .await
                .is_err()
            {
                return;
            }

            loop {
                tokio::select! {
                    bcast = rx.recv() => {
                        if let Ok(text) = bcast
                            && write_ws_frame(&mut stream, 0x1, text.as_bytes()).await.is_err()
                        {
                            return;
                        }
                    }
                    client_msg = read_ws_client_frame(&mut stream) => {
                        match client_msg {
                            Ok(Some((0x1, payload))) => {
                                let Ok(text) = std::str::from_utf8(&payload) else {
                                    return;
                                };
                                if text == "MP2:PING" {
                                    if write_ws_frame(&mut stream, 0x1, b"MP2:PONG").await.is_err() {
                                        return;
                                    }
                                    continue;
                                }
                                let Ok(v) = serde_json::from_str::<Value>(text) else {
                                    continue;
                                };
                                if v.get("t").and_then(Value::as_str) == Some("send") {
                                    let cid = v.get("client_msg_id").and_then(Value::as_str).unwrap_or("").to_string();
                                    let kind = v.get("kind").and_then(Value::as_str).unwrap_or("chat").to_string();
                                    let target = v.get("target").and_then(Value::as_str).unwrap_or("@all").to_string();
                                    let body_encoding = v.get("body_encoding").and_then(Value::as_str).unwrap_or("utf8").to_string();
                                    let body = v.get("body").and_then(Value::as_str).unwrap_or("").to_string();
                                    let (assigned_seq, ts_ms) = {
                                        let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                        let ts = outpost_control::wall_now_ms();
                                        let s = if let Some(&prev) = st.dedup.get(&cid) {
                                            prev
                                        } else {
                                            st.room_seq += 1;
                                            let next_s = st.room_seq;
                                            st.dedup.insert(cid.clone(), next_s);
                                            let (sh, did) = st.accounts.get(&caller_acc).map_or_else(
                                                || (format!("user{caller_acc}"), caller_acc),
                                                |a| (a.handle.clone(), a.device_id),
                                            );
                                            let ev = json!({
                                                "v": 2,
                                                "t": "event",
                                                "seq": next_s,
                                                "ts_ms": ts,
                                                "client_msg_id": cid,
                                                "sender": {
                                                    "account_id": caller_acc.to_string(),
                                                    "device_id": did.to_string(),
                                                    "handle": sh,
                                                    "client": "outpost"
                                                },
                                                "target": target,
                                                "kind": kind,
                                                "body_encoding": body_encoding,
                                                "body": body
                                            })
                                            .to_string();
                                            let _ = st.room_tx.send(ev);
                                            next_s
                                        };
                                        (s, ts)
                                    };
                                    let ack = json!({
                                        "v": 2,
                                        "t": "ack",
                                        "client_msg_id": cid,
                                        "seq": assigned_seq,
                                        "ts_ms": ts_ms
                                    })
                                    .to_string();
                                    if write_ws_frame(&mut stream, 0x1, ack.as_bytes()).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Ok(Some((0x8, _))) | Ok(None) | Err(_) => return,
                            _ => {}
                        }
                    }
                }
            }
        } else {
            // Account `/v1/ws` (mp1): send HelloAck and keep alive
            if let Ok(sid) = SessionId::new(1)
                && let Ok(hello_frame) = encode_frame(
                    1,
                    &Mp1Message::HelloAck {
                        session_id: sid,
                        server_now_ms: outpost_control::wall_now_ms(),
                        ping_interval_ms: 20_000,
                    },
                )
            {
                let _ = write_ws_frame(&mut stream, 0x2, &hello_frame).await;
            }
            while let Ok(Some((op, payload))) = read_ws_client_frame(&mut stream).await {
                if op == 0x1 && payload == b"MP1:PING" {
                    if write_ws_frame(&mut stream, 0x1, b"MP1:PONG").await.is_err() {
                        return;
                    }
                } else if op == 0x8 {
                    return;
                }
            }
        }
        return;
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/v1/auth/session/start") => {
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
                write_http_json(&mut stream, 400, "Bad Request", &json!({"error":"bad_json"})).await;
                return;
            };
            let pk_b64 = v.get("device_pubkey_b64").and_then(Value::as_str).unwrap_or("");
            let Ok(pk_raw) = B64.decode(pk_b64.as_bytes()) else {
                return;
            };
            let Ok(dev_pk) = <[u8; 32]>::try_from(pk_raw) else {
                return;
            };
            let resp = {
                let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let idx = st.next_login_idx;
                st.next_login_idx += 1;
                let (acc_id, dev_id, handle, root_seed, cwt_ttl) = if idx == 0 {
                    (1001u64, 2001u64, "alice".to_string(), [0xA1u8; 32], 7 * 86_400i64)
                } else {
                    // Bob starts with a short 2-hour CWT (< 3d) to trigger silent background renew!
                    (1002u64, 2002u64, "bob".to_string(), [0xB2u8; 32], 7_200i64)
                };
                let root_sk = SigningKey::from_bytes(&root_seed);
                st.accounts.insert(
                    acc_id,
                    Mp2MockAccount {
                        account_id: acc_id,
                        device_id: dev_id,
                        handle: handle.clone(),
                        root_sk,
                        device_pubkey: dev_pk,
                    },
                );
                let flow_id = format!("flow_{idx}");
                st.flows.insert(flow_id.clone(), (acc_id, handle, dev_pk, 0, cwt_ttl));
                json!({
                    "flow_id": flow_id,
                    "poll_token": format!("poll_{idx}"),
                    "user_code": "XBOX-LIVE",
                    "verify_url": "https://multiplayer.tech/login?code=XBOX-LIVE",
                    "expires_at_ms": outpost_control::wall_now_ms() + 300_000
                })
            };
            write_http_json(&mut stream, 200, "OK", &resp).await;
        }
        ("POST", "/v1/auth/session/poll") => {
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let flow_id = v.get("flow_id").and_then(Value::as_str).unwrap_or("");
            let resp = {
                let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let info = st.flows.get_mut(flow_id).map(|entry| {
                    entry.3 += 1;
                    (entry.0, entry.1.clone(), entry.2, entry.3, entry.4)
                });
                match info {
                    Some((_, _, _, 1, _)) => json!({ "status": "pending" }),
                    Some((acc_id, handle, dev_pk, _, ttl)) => {
                        let Some(acc) = st.accounts.get(&acc_id) else {
                            return;
                        };
                        let now_s = outpost_control::wall_now_secs();
                        let exp_s = now_s + ttl;
                        let cwt = encode_device_cwt(&acc.root_sk, &dev_pk, now_s, exp_s)
                            .unwrap_or_default();
                        json!({
                            "status": "approved",
                            "account_id": acc.account_id,
                            "handle": handle,
                            "device_id": acc.device_id,
                            "root_pubkey_b64": B64.encode(acc.root_sk.verifying_key().to_bytes()),
                            "device_cwt_b64": B64.encode(cwt),
                            "cwt_expires_ms": (exp_s as u64) * 1000,
                            "session_token": "mpcs1_test"
                        })
                    }
                    None => json!({ "status": "expired" }),
                }
            };
            write_http_json(&mut stream, 200, "OK", &resp).await;
        }
        ("POST", "/v1/devices/me/renew") => {
            let resp = {
                let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                st.renew_calls += 1;
                st.accounts.get(&caller_acc).map(|acc| {
                    let now_s = outpost_control::wall_now_secs();
                    let exp_s = now_s + 7 * 86_400;
                    let cwt = encode_device_cwt(&acc.root_sk, &acc.device_pubkey, now_s, exp_s)
                        .unwrap_or_default();
                    json!({
                        "device_id": acc.device_id,
                        "device_cwt_b64": B64.encode(cwt),
                        "cwt_expires_ms": (exp_s as u64) * 1000
                    })
                })
            };
            if let Some(v) = resp {
                write_http_json(&mut stream, 200, "OK", &v).await;
            } else {
                write_http_json(&mut stream, 404, "Not Found", &json!({"error":"not_found"})).await;
            }
        }
        ("GET", "/v1/accounts/me") => {
            let resp = {
                let st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(acc) = st.accounts.get(&caller_acc) else {
                    return;
                };
                json!({
                    "account_id": acc.account_id,
                    "handle": acc.handle,
                    "root_pubkey_b64": B64.encode(acc.root_sk.verifying_key().to_bytes()),
                    "devices": [],
                    "active_party_ids": []
                })
            };
            write_http_json(&mut stream, 200, "OK", &resp).await;
        }
        ("GET", "/v1/accounts/resolve") => {
            let target_h = req.query.trim_start_matches("handle=");
            let resp = {
                let st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                st.accounts.values().find(|a| a.handle == target_h).map(|acc| {
                    json!({
                        "account_id": acc.account_id,
                        "handle": acc.handle,
                        "root_pubkey_b64": B64.encode(acc.root_sk.verifying_key().to_bytes())
                    })
                })
            };
            if let Some(v) = resp {
                write_http_json(&mut stream, 200, "OK", &v).await;
            } else {
                write_http_json(&mut stream, 404, "Not Found", &json!({"error":"not_found"})).await;
            }
        }
        ("POST", "/v1/friends/requests") => {
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let target = v.get("target_account_id").and_then(Value::as_u64).unwrap_or(0);
            write_http_json(
                &mut stream,
                200,
                "OK",
                &json!({ "target_account_id": target, "state": 0 }),
            )
            .await;
        }
        ("GET", "/v1/friends/live") => {
            let resp = {
                let st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let other_acc = if caller_acc == 1001 { 1002 } else { 1001 };
                let other_handle = st
                    .accounts
                    .get(&other_acc)
                    .map(|a| a.handle.clone())
                    .unwrap_or_else(|| "peer".to_string());
                let pending = if caller_acc == 1002 && st.pending_invite_for_bob {
                    vec![json!({
                        "party_id": 8801,
                        "room_code": "KAIH",
                        "from_handle": "alice",
                        "created_at_ms": outpost_control::wall_now_ms()
                    })]
                } else {
                    Vec::new()
                };
                json!({
                    "friends": [
                        {
                            "account_id": other_acc,
                            "handle": other_handle,
                            "state": "friend",
                            "presence": "in_party",
                            "client": "outpost",
                            "party_room_code": "KAIH",
                            "joinable": true
                        }
                    ],
                    "pending_invites": pending
                })
            };
            write_http_json(&mut stream, 200, "OK", &resp).await;
        }
        ("POST", "/v1/rooms/invite") => {
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
                return;
            };
            let invited_handle = v.get("handle").and_then(Value::as_str).map(str::to_string);
            let resp = {
                let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if invited_handle.as_deref() == Some("bob") {
                    st.pending_invite_for_bob = true;
                }
                let (h, did) = st.accounts.get(&caller_acc).map_or_else(
                    || ("alice".to_string(), 2001),
                    |a| (a.handle.clone(), a.device_id),
                );
                if !st
                    .room_members
                    .iter()
                    .any(|m| m.get("account_id").and_then(Value::as_u64) == Some(caller_acc))
                {
                    st.room_members.push(json!({
                        "account_id": caller_acc,
                        "device_id": did,
                        "handle": h,
                        "client": "outpost",
                        "status": "live"
                    }));
                }
                json!({
                    "party_id": 8801,
                    "room_code": "KAIH",
                    "share_url": "https://multiplayer.tech/p/KAIH",
                    "handle_url": format!("https://multiplayer.tech/@{h}"),
                    "ws_path": "/v1/parties/8801/ws",
                    "invited_handle": invited_handle
                })
            };
            write_http_json(&mut stream, 200, "OK", &resp).await;
        }
        ("POST", "/v1/rooms/enter") => {
            let resp = {
                let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let (h, did) = st.accounts.get(&caller_acc).map_or_else(
                    || ("bob".to_string(), 2002),
                    |a| (a.handle.clone(), a.device_id),
                );
                if !st
                    .room_members
                    .iter()
                    .any(|m| m.get("account_id").and_then(Value::as_u64) == Some(caller_acc))
                {
                    st.room_members.push(json!({
                        "account_id": caller_acc,
                        "device_id": did,
                        "handle": h,
                        "client": "outpost",
                        "status": "live"
                    }));
                }
                let pres = json!({
                    "v": 2,
                    "t": "presence",
                    "members": st.room_members
                })
                .to_string();
                let _ = st.room_tx.send(pres);
                json!({
                    "party_id": 8801,
                    "room_code": "KAIH",
                    "name": "Squad",
                    "share_url": "https://multiplayer.tech/p/KAIH",
                    "ws_path": "/v1/parties/8801/ws",
                    "members": st.room_members
                })
            };
            write_http_json(&mut stream, 200, "OK", &resp).await;
        }
        ("POST", "/v1/rooms/leave") => {
            write_http_json(&mut stream, 200, "OK", &json!({ "left": true, "party_id": 8801 }))
                .await;
        }
        _ => {
            write_http_json(&mut stream, 404, "Not Found", &json!({"error":"not_found"})).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oracle_8_xbox_live_mp2_unpinned_chat_login_renew_and_strict_pins() -> Result<(), String> {
    let root_tmp = make_short_tempdir("mpo8")?;
    let alice_st = make_private_subdir(root_tmp.path(), "as")?;
    let alice_rt = make_private_subdir(root_tmp.path(), "ar")?;
    let bob_st = make_private_subdir(root_tmp.path(), "bs")?;
    let bob_rt = make_private_subdir(root_tmp.path(), "br")?;
    let strict_rt = make_private_subdir(root_tmp.path(), "sr")?;

    let (room_tx, _) = broadcast::channel::<String>(32);
    let mock_state = Arc::new(Mutex::new(Mp2MockServerState {
        accounts: HashMap::new(),
        flows: HashMap::new(),
        next_login_idx: 0,
        renew_calls: 0,
        room_seq: 0,
        dedup: HashMap::new(),
        room_members: Vec::new(),
        pending_invite_for_bob: false,
        room_tx,
    }));
    let (server_addr, cert_pem, server_task) = spawn_mock_mp2_server(Arc::clone(&mock_state)).await?;
    let ca_path = root_tmp.path().join("mp2_ca.pem");
    std::fs::write(&ca_path, cert_pem).map_err(|e| format!("write ca: {e}"))?;
    let addr_str = server_addr.to_string();
    let ca_str = ca_path.to_string_lossy().into_owned();
    let env_vars = [
        ("OUTPOST_TEST_CONNECT_ADDR", addr_str.as_str()),
        ("OUTPOST_TEST_CA_PEM", ca_str.as_str()),
        ("OUTPOST_NO_BROWSER", "1"),
    ];

    let result = async {
        // 1. Alice and Bob sign in via `mp-outpost login` (ZERO root.seed, ZERO safety-number jargon!)
        let alice_login = run_bin(
            &alice_st,
            &alice_rt,
            &["login", "--no-open", "--poll-ms", "50"],
            None,
            &env_vars,
        )?;
        if !alice_login.status_ok || !alice_login.stdout.contains("Signed in as @alice") {
            return Err(format!(
                "alice login failed: stdout={} stderr={}",
                alice_login.stdout, alice_login.stderr
            ));
        }
        if alice_login.stdout.contains("relay_policy") || alice_login.stdout.contains("safety_number") {
            return Err(format!("login leaked jargon: {}", alice_login.stdout));
        }

        let bob_login = run_bin(
            &bob_st,
            &bob_rt,
            &["login", "--no-open", "--poll-ms", "50"],
            None,
            &env_vars,
        )?;
        if !bob_login.status_ok || !bob_login.stdout.contains("Signed in as @bob") {
            return Err(format!(
                "bob login failed: stdout={} stderr={}",
                bob_login.stdout, bob_login.stderr
            ));
        }

        // Verify `whoami` default human output hides safety_number, account_id, and relay_policy
        let whoami_human = run_bin(&alice_st, &alice_rt, &["whoami"], None, &env_vars)?;
        if !whoami_human.status_ok
            || whoami_human.stdout.contains("safety_number")
            || whoami_human.stdout.contains("relay_policy")
            || whoami_human.stdout.contains("account_id")
        {
            return Err(format!("whoami leaked internal fields: {}", whoami_human.stdout));
        }

        // 2. 1-verb `add`, `invite`, `friends`, bare `join` (accepts latest pending invite!)
        let add_out = run_bin(&alice_st, &alice_rt, &["add", "@bob"], None, &env_vars)?;
        if !add_out.status_ok || !add_out.stdout.contains("@bob") {
            return Err(format!("add @bob failed: {} {}", add_out.stdout, add_out.stderr));
        }

        let inv_out = run_bin(
            &alice_st,
            &alice_rt,
            &["invite", "@bob", "--name", "Squad"],
            None,
            &env_vars,
        )?;
        if !inv_out.status_ok
            || !inv_out.stdout.contains("KAIH")
            || !inv_out.stdout.contains("@bob")
            || inv_out.stdout.contains("8801")
        {
            return Err(format!(
                "invite @bob unexpected output: stdout={} stderr={}",
                inv_out.stdout, inv_out.stderr
            ));
        }

        let friends_out = run_bin(&bob_st, &bob_rt, &["friends"], None, &env_vars)?;
        if !friends_out.status_ok
            || !friends_out.stdout.contains("@alice")
            || !friends_out.stdout.contains("KAIH")
            || friends_out.stdout.contains("safety_number")
            || friends_out.stdout.contains("account_id")
        {
            return Err(format!(
                "friends unexpected output: stdout={} stderr={}",
                friends_out.stdout, friends_out.stderr
            ));
        }

        // Bare `mp-outpost join` accepts Bob's latest pending invite!
        let join_out = run_bin(&bob_st, &bob_rt, &["join"], None, &env_vars)?;
        if !join_out.status_ok
            || !join_out.stdout.contains("Joined Squad")
            || !join_out.stdout.contains("@alice")
        {
            return Err(format!(
                "bare join failed: stdout={} stderr={}",
                join_out.stdout, join_out.stderr
            ));
        }

        // Verify Bob's daemon silently renewed his short-lived CWT via `/v1/devices/me/renew`!
        let renew_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < renew_deadline {
            let count = mock_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .renew_calls;
            if count >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let renew_count = mock_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .renew_calls;
        if renew_count < 1 {
            return Err("expected silent background /v1/devices/me/renew call for Bob".to_string());
        }

        // 3. Unpinned peer chat & `board_post` (`agent_card`) over `mp2` WSS via MCP (ZERO safety-number pinning!)
        let mut alice_mcp = McpProc::spawn(&alice_st, &alice_rt, &env_vars)?;
        let mut bob_mcp = McpProc::spawn(&bob_st, &bob_rt, &env_vars)?;
        for (label, p) in [("alice", &mut alice_mcp), ("bob", &mut bob_mcp)] {
            p.send(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": label, "version": "1.0" }
                }
            }))?;
            let _ = p.recv()?;
        }

        // Wait briefly for both mp2 WS connections to complete `hello`
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Alice sends chat WITHOUT pinning Bob!
        alice_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "party_send",
                "arguments": { "party_id": 8801, "body": "yo unpinned mp2 chat!" }
            }
        }))?;
        let send_resp = alice_mcp.recv()?;
        if send_resp.pointer("/result/isError").and_then(Value::as_bool) != Some(false) {
            return Err(format!("unpinned party_send must succeed by default: {send_resp}"));
        }

        // Alice posts an `agent_card` via `board_post` WITHOUT pinning Bob!
        let card_json = r#"{"title":"Fixed auth test","summary":"2 files changed"}"#;
        alice_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "board_post",
                "arguments": {
                    "party_id": 8801,
                    "room_scope": "party/main",
                    "payload_b64": B64.encode(card_json.as_bytes())
                }
            }
        }))?;
        let card_resp = alice_mcp.recv()?;
        if card_resp.pointer("/result/isError").and_then(Value::as_bool) != Some(false) {
            return Err(format!("unpinned board_post must succeed by default: {card_resp}"));
        }

        // Bob polls and receives BOTH chat AND agent_card with real `@alice` provenance + nonce fences!
        let poll_deadline = Instant::now() + Duration::from_secs(5);
        let mut saw_chat = false;
        let mut saw_card = false;
        let mut rid = 20i64;
        while Instant::now() < poll_deadline && (!saw_chat || !saw_card) {
            rid += 1;
            bob_mcp.send(&json!({
                "jsonrpc": "2.0",
                "id": rid,
                "method": "tools/call",
                "params": {
                    "name": "party_poll",
                    "arguments": { "party_id": 8801, "after_seq": 0 }
                }
            }))?;
            let poll = bob_mcp.recv()?;
            if let Some(events) = poll
                .pointer("/result/structuredContent/events")
                .and_then(Value::as_array)
            {
                for ev in events {
                    if ev.get("kind").and_then(Value::as_str) == Some("chat")
                        && ev.get("body").and_then(Value::as_str) == Some("yo unpinned mp2 chat!")
                        && ev.pointer("/provenance/sender_handle").and_then(Value::as_str) == Some("alice")
                    {
                        saw_chat = true;
                    }
                    if ev.get("kind").and_then(Value::as_str) == Some("bridge_envelope")
                        && ev.pointer("/provenance/sender_handle").and_then(Value::as_str) == Some("alice")
                    {
                        saw_card = true;
                    }
                }
            }
            if !saw_chat || !saw_card {
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
        }
        if !saw_chat || !saw_card {
            return Err(format!(
                "Bob did not receive both unpinned mp2 events (saw_chat={saw_chat}, saw_card={saw_card})"
            ));
        }

        // 4. Test new MCP lifecycle tools (`party_leave`, `party_join`, `party_invite`, `friend_add`)
        bob_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": { "name": "party_leave", "arguments": {} }
        }))?;
        let leave_mcp = bob_mcp.recv()?;
        if leave_mcp.pointer("/result/structuredContent/left").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!("MCP party_leave failed: {leave_mcp}"));
        }

        bob_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": { "name": "party_join", "arguments": { "target": "KAIH" } }
        }))?;
        let join_mcp = bob_mcp.recv()?;
        if join_mcp.pointer("/result/structuredContent/room_code").and_then(Value::as_str)
            != Some("KAIH")
        {
            return Err(format!("MCP party_join failed: {join_mcp}"));
        }

        bob_mcp.send(&json!({
            "jsonrpc": "2.0",
            "id": 52,
            "method": "tools/call",
            "params": { "name": "friend_add", "arguments": { "handle": "@alice" } }
        }))?;
        let friend_mcp = bob_mcp.recv()?;
        if friend_mcp.pointer("/result/structuredContent/handle").and_then(Value::as_str)
            != Some("alice")
        {
            return Err(format!("MCP friend_add failed: {friend_mcp}"));
        }

        // 5. Verify opt-in `--strict-pins` blocks sending to unpinned peers!
        let strict_env = [
            ("OUTPOST_TEST_CONNECT_ADDR", addr_str.as_str()),
            ("OUTPOST_TEST_CA_PEM", ca_str.as_str()),
            ("OUTPOST_NO_BROWSER", "1"),
            ("OUTPOST_STRICT_PINS", "1"),
        ];
        let _ = run_bin(&bob_st, &strict_rt, &["join", "KAIH"], None, &strict_env)?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let strict_say = run_bin(
            &bob_st,
            &strict_rt,
            &["--strict-pins", "party", "say", "8801", "should block"],
            None,
            &strict_env,
        )?;
        if strict_say.status_ok {
            return Err("expected --strict-pins to block send to unpinned peer".to_string());
        }

        // 6. Clean `mp-outpost leave`
        let leave_cli = run_bin(&alice_st, &alice_rt, &["leave"], None, &env_vars)?;
        if !leave_cli.status_ok || !leave_cli.stdout.contains("Left party.") {
            return Err(format!("leave cli failed: {} {}", leave_cli.stdout, leave_cli.stderr));
        }

        let _ = alice_mcp.child.kill();
        let _ = bob_mcp.child.kill();
        Ok(())
    }
    .await;

    let _ = run_bin(&alice_st, &alice_rt, &["daemon", "stop", "--force"], None, &env_vars);
    let _ = run_bin(&bob_st, &bob_rt, &["daemon", "stop", "--force"], None, &env_vars);
    let _ = run_bin(&bob_st, &strict_rt, &["daemon", "stop", "--force"], None, &env_vars);
    server_task.abort();
    result
}
}
