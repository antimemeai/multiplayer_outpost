//! `mp-outpost` single static binary entrypoint:
//! - CLI (`mp-outpost <cmd>`)
//! - Stateless thin MCP stdio proxy (`mp-outpost mcp`)
//! - Detached local sidecar daemon (`mp-outpost __daemon`, daemonized single-threaded BEFORE Tokio!)

#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod app_daemon;
mod build_info;
mod chat;
mod cli;
mod ipc_payloads;
mod lan;
mod mcp_bridge;
mod mcp_setup;
mod mpkey;
mod storage;
mod upgrade;

use std::sync::Arc;
use std::time::Duration;

use outpost_control::sanitize_server_error;
use outpost_core::ipc_wire::ReadyReply;
use outpost_daemon::{
    DaemonConfig, DaemonServer, daemonize_in_child, install_daemon_process_hygiene,
    send_ready_reply_and_close,
};
use outpost_mcp::{McpServerConfig, run_stdio};

use crate::app_daemon::{AppDaemon, AppDaemonHandler};
use crate::build_info::{build_digest, build_order};
use crate::cli::{
    DaemonSubcommandArgs, GlobalOpts, parse_daemon_subcommand_if_present,
    parse_mcp_subcommand_if_present, reject_secrets_in_argv, run_cli_command,
};
use crate::mcp_bridge::DaemonMcpBridge;
use crate::storage::{resolve_effective_runtime_override, resolve_effective_state_dir};

fn print_sanitized_err(prefix: &str, err: &str) {
    let safe = sanitize_server_error(err);
    eprintln!("{prefix}: {safe}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // CRITICAL (G2-L3-3): Reject secrets anywhere on argv BEFORE `__daemon`, `mcp`, or CLI dispatch!
    if let Err(err) = reject_secrets_in_argv(&args) {
        print_sanitized_err("error", &err);
        std::process::exit(2);
    }

    // CRITICAL: Inspect argv for `__daemon` BEFORE creating any Tokio runtime or threads!
    match parse_daemon_subcommand_if_present(&args) {
        Ok(Some(daemon_args)) => run_daemon_entrypoint(daemon_args),
        Err(err) => {
            print_sanitized_err("error", &err);
            std::process::exit(2);
        }
        Ok(None) => {}
    }

    // Check `mcp` subcommand (fast < 20ms initialize/tools/list + < 50ms EOF exit).
    match parse_mcp_subcommand_if_present(&args) {
        Ok(Some(opts)) => run_mcp_entrypoint(opts),
        Err(err) => {
            print_sanitized_err("error", &err);
            std::process::exit(2);
        }
        Ok(None) => {}
    }

    // Standard CLI command execution.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            print_sanitized_err("error", &format!("failed to build Tokio runtime: {e}"));
            std::process::exit(1);
        }
    };

    if let Err(err) = rt.block_on(run_cli_command(&args)) {
        print_sanitized_err("error", &err);
        std::process::exit(1);
    }
}

fn run_daemon_entrypoint(daemon_args: DaemonSubcommandArgs) {
    // 1. Single-threaded daemonization (setsid + 2nd fork) BEFORE starting Tokio!
    if !daemon_args.foreground
        && let Err(e) = daemonize_in_child()
    {
        if let Some(fd) = daemon_args.ready_fd {
            send_ready_reply_and_close(fd, &ReadyReply::Err(format!("daemonize failed: {e}")));
        }
        eprintln!("error: daemonize failed: {e}");
        std::process::exit(1);
    }

    // 2. Single-threaded process hygiene (`umask(0077)`, `SIGPIPE=SIG_IGN`, lock-free panic hook).
    install_daemon_process_hygiene(libc::STDERR_FILENO);

    let state_dir_path = match resolve_effective_state_dir(daemon_args.state_dir.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            if let Some(fd) = daemon_args.ready_fd {
                send_ready_reply_and_close(fd, &ReadyReply::Err(e.clone()));
            }
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let runtime_override = resolve_effective_runtime_override(daemon_args.runtime_dir.as_deref());

    // 3. Load enrolled device, peers.bin, and epochs.bin BEFORE starting Tokio/publishing readiness.
    let app = match AppDaemon::load_with_options(
        state_dir_path,
        runtime_override.clone(),
        daemon_args.device_id,
        daemon_args.strict_pins,
    ) {
        Ok(a) => a,
        Err(e) => {
            if let Some(fd) = daemon_args.ready_fd {
                send_ready_reply_and_close(fd, &ReadyReply::Err(e.clone()));
            }
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("failed to build Tokio runtime: {e}");
            if let Some(fd) = daemon_args.ready_fd {
                send_ready_reply_and_close(fd, &ReadyReply::Err(msg.clone()));
            }
            eprintln!("error: {msg}");
            std::process::exit(1);
        }
    };

    let mut cfg = DaemonConfig::new(daemon_args.device_id, build_order(), build_digest());
    cfg.runtime_dir_override = runtime_override;
    cfg.ready_fd = daemon_args.ready_fd;
    if let Some(secs) = daemon_args.idle_timeout_secs {
        cfg.idle_timeout = if secs == 0 {
            None
        } else {
            Some(Duration::from_secs(secs))
        };
    }

    let exit_code = rt.block_on(async move {
        let handler = Arc::new(AppDaemonHandler::new(app));
        match DaemonServer::run(cfg, handler).await {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("daemon error: {e}");
                1
            }
        }
    });

    std::process::exit(exit_code);
}

fn run_mcp_entrypoint(opts: GlobalOpts) {
    let state_dir = match resolve_effective_state_dir(opts.state_dir.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let runtime_override = resolve_effective_runtime_override(opts.runtime_dir.as_deref());

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to build Tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    let res = rt.block_on(async move {
        let cfg = McpServerConfig::default();
        let shutdown = cfg.shutdown.clone();

        tokio::spawn(async move {
            let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
            let sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt());
            match (sigterm, sigint) {
                (Ok(mut t), Ok(mut i)) => {
                    tokio::select! {
                        _ = t.recv() => {}
                        _ = i.recv() => {}
                    }
                    shutdown.cancel();
                }
                _ => {
                    let _ = tokio::signal::ctrl_c().await;
                    shutdown.cancel();
                }
            }
        });

        let bridge = DaemonMcpBridge::new(state_dir, runtime_override, opts.device_id);
        run_stdio(bridge, cfg).await
    });

    // Exit immediately without joining the detached blocking stdin thread (< 50 ms EOF guarantee!).
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("mcp stdio error: {e}");
            std::process::exit(1);
        }
    }
}
