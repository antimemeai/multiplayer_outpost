//! Multi-host `mp-outpost mcp setup` generator and atomic `--write` config merger.
//!
//! Supported clients:
//! - `claude` (`.mcp.json` / `~/.claude.json`, JSON `mcpServers.multiplayer`)
//! - `codex` (`~/.codex/config.toml`, TOML `[mcp_servers.multiplayer]`)
//! - `cursor` (`.cursor/mcp.json` / `~/.cursor/mcp.json`, JSON `mcpServers.multiplayer`)
//! - `antigravity` (`~/.gemini/antigravity/mcp_config.json` & `~/.gemini/config/mcp_config.json`, JSON `mcpServers.multiplayer`)
//! - `hermes` (`~/.hermes/config.yaml`, YAML `mcp_servers.multiplayer`)
//! - `gemini` (`~/.gemini/settings.json`, JSON `mcpServers.multiplayer`)
//! - `opencode` (`~/.config/opencode/opencode.json`, JSON `mcp.multiplayer`)
//! - `zed` (`~/.config/zed/settings.json`, JSON `context_servers.multiplayer`)
//! - `all` (prints snippets/JSON for all 8 clients; refused for `--write`)

use std::io;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use outpost_daemon::{
    atomic_write_in_dir, open_dir_nofollow, read_regular_file_bounded_nofollow,
};
use serde_json::{Value, json};

use crate::cli::{
    GlobalOpts, next_val, print_json, redact_unknown_arg, shell_single_quote, toml_basic_string,
};

const MAX_MCP_CONFIG_BYTES: usize = 1024 * 1024;
const HERMES_TIMEOUT_SECS: u64 = 90;
const HERMES_CONNECT_TIMEOUT_SECS: u64 = 15;

pub const MCP_CLIENTS_USAGE: &str =
    "claude|codex|cursor|antigravity|hermes|gemini|opencode|zed|all";
const MCP_WRITE_CLIENTS_USAGE: &str =
    "claude|codex|cursor|antigravity|hermes|gemini|opencode|zed";

fn resolve_home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "HOME environment variable is not set; pass --config <path>".to_string())
}

fn path_entry_exists_nofollow(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn antigravity_default_paths_from_home(home: &Path) -> Vec<PathBuf> {
    let ide_dir = home.join(".gemini").join("antigravity");
    let cli_dir = home.join(".gemini").join("config");
    let ide_cfg = ide_dir.join("mcp_config.json");
    let cli_cfg = cli_dir.join("mcp_config.json");

    let ide_present = path_entry_exists_nofollow(&ide_cfg) || path_entry_exists_nofollow(&ide_dir);
    let cli_present = path_entry_exists_nofollow(&cli_cfg) || path_entry_exists_nofollow(&cli_dir);

    match (ide_present, cli_present) {
        (true, false) => vec![ide_cfg],
        (false, true) => vec![cli_cfg],
        _ => vec![ide_cfg, cli_cfg],
    }
}

fn default_mcp_config_paths_from_home(
    client: &str,
    global: bool,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let require_home = || -> Result<PathBuf, String> {
        match home {
            Some(h) => Ok(h.to_path_buf()),
            None => resolve_home_dir(),
        }
    };
    match client {
        "claude" => {
            if global {
                Ok(vec![require_home()?.join(".claude.json")])
            } else {
                Ok(vec![PathBuf::from(".mcp.json")])
            }
        }
        "cursor" => {
            if global {
                Ok(vec![require_home()?.join(".cursor").join("mcp.json")])
            } else {
                Ok(vec![PathBuf::from(".cursor").join("mcp.json")])
            }
        }
        "codex" => Ok(vec![require_home()?.join(".codex").join("config.toml")]),
        "antigravity" => Ok(antigravity_default_paths_from_home(&require_home()?)),
        "hermes" => Ok(vec![require_home()?.join(".hermes").join("config.yaml")]),
        "gemini" => Ok(vec![require_home()?.join(".gemini").join("settings.json")]),
        "opencode" => Ok(vec![
            require_home()?
                .join(".config")
                .join("opencode")
                .join("opencode.json"),
        ]),
        "zed" => Ok(vec![
            require_home()?
                .join(".config")
                .join("zed")
                .join("settings.json"),
        ]),
        other => Err(format!("cannot determine default config path for '{other}'")),
    }
}

fn is_codex_multiplayer_section_header(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.starts_with('[') || trimmed.starts_with("[[") {
        return false;
    }
    let Some(close_idx) = trimmed.find(']') else {
        return false;
    };
    let after = trimmed.get(close_idx + 1..).unwrap_or("").trim();
    if !after.is_empty() && !after.starts_with('#') {
        return false;
    }
    let inner = trimmed.get(1..close_idx).unwrap_or("").trim();
    inner == "mcp_servers.multiplayer"
}

fn is_toml_section_header(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('[') && trimmed.contains(']')
}

pub(crate) fn upsert_codex_mcp_toml(existing: &str, bin: &str) -> String {
    let block = format!(
        "[mcp_servers.multiplayer]\ncommand = {}\nargs = [\"mcp\"]",
        toml_basic_string(bin)
    );
    let mut out_lines: Vec<String> = Vec::new();
    let mut in_target = false;
    let mut replaced = false;

    for raw_line in existing.lines() {
        if is_toml_section_header(raw_line) {
            if is_codex_multiplayer_section_header(raw_line) {
                in_target = true;
                if !replaced {
                    out_lines.push(block.clone());
                    replaced = true;
                }
                continue;
            }
            in_target = false;
        }
        if !in_target {
            out_lines.push(raw_line.to_string());
        }
    }

    if !replaced {
        if !out_lines.is_empty() && !out_lines.last().is_some_and(|l| l.trim().is_empty()) {
            out_lines.push(String::new());
        }
        out_lines.push(block);
    }

    let mut rendered = out_lines.join("\n");
    rendered.push('\n');
    rendered
}

fn yaml_double_quoted_string(s: &str) -> Result<String, String> {
    // JSON double-quoted strings are strictly valid YAML 1.2 double-quoted scalars.
    serde_json::to_string(s).map_err(|e| format!("failed YAML-quoting string: {e}"))
}

fn render_hermes_multiplayer_entry(bin: &str, indent: usize) -> Result<Vec<String>, String> {
    let pad = " ".repeat(indent);
    let child = " ".repeat(indent + 2);
    let item = " ".repeat(indent + 4);
    let qbin = yaml_double_quoted_string(bin)?;
    Ok(vec![
        format!("{pad}multiplayer:"),
        format!("{child}command: {qbin}"),
        format!("{child}args:"),
        format!("{item}- \"mcp\""),
        format!("{child}timeout: {HERMES_TIMEOUT_SECS}"),
        format!("{child}connect_timeout: {HERMES_CONNECT_TIMEOUT_SECS}"),
    ])
}

fn render_hermes_snippet(bin: &str) -> Result<String, String> {
    let mut lines = vec!["mcp_servers:".to_string()];
    lines.extend(render_hermes_multiplayer_entry(bin, 2)?);
    Ok(lines.join("\n"))
}

fn strip_unquoted_yaml_comment(s: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double && ch == '\\' {
            escaped = true;
            continue;
        }
        if !in_double && ch == '\'' {
            in_single = !in_single;
            continue;
        }
        if !in_single && ch == '"' {
            in_double = !in_double;
            continue;
        }
        if !in_single && !in_double && ch == '#' {
            let prev_is_ws = idx == 0
                || s.get(..idx)
                    .and_then(|prefix| prefix.chars().last())
                    .is_some_and(char::is_whitespace);
            if prev_is_ws {
                return s.get(..idx).unwrap_or(s).trim();
            }
        }
    }
    s.trim()
}

fn leading_space_indent(line: &str) -> Result<usize, String> {
    let mut count = 0usize;
    for b in line.bytes() {
        match b {
            b' ' => count += 1,
            b'\t' => {
                return Err(
                    "refusing to modify YAML config containing tab indentation".to_string()
                );
            }
            _ => break,
        }
    }
    Ok(count)
}

fn matches_yaml_key<'a>(trimmed: &'a str, key: &str) -> Option<&'a str> {
    let rest = trimmed.strip_prefix(key)?;
    let after_colon = rest.strip_prefix(':')?;
    if after_colon.is_empty()
        || after_colon
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
    {
        Some(after_colon)
    } else {
        None
    }
}

/// Idempotently upserts `mcp_servers.multiplayer` inside a Hermes `config.yaml` file
/// while preserving all unrelated top-level sections, sibling MCP servers, and comments.
pub(crate) fn upsert_hermes_mcp_yaml(existing: &str, bin: &str) -> Result<String, String> {
    let lines: Vec<String> = existing
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
        .collect();

    let mut section_start: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_space_indent(line)?;
        if indent == 0 && matches_yaml_key(trimmed, "mcp_servers").is_some() {
            section_start = Some(idx);
            break;
        }
    }

    let Some(start_idx) = section_start else {
        let mut out = lines;
        if !out.is_empty() && !out.last().is_some_and(|l| l.trim().is_empty()) {
            out.push(String::new());
        }
        out.push("mcp_servers:".to_string());
        out.extend(render_hermes_multiplayer_entry(bin, 2)?);
        let mut rendered = out.join("\n");
        rendered.push('\n');
        return Ok(rendered);
    };

    let header_line = lines
        .get(start_idx)
        .map(String::as_str)
        .unwrap_or_default();
    let after_colon = matches_yaml_key(header_line.trim(), "mcp_servers").unwrap_or("");
    let header_value = strip_unquoted_yaml_comment(after_colon);
    let replace_inline_empty = if header_value.is_empty() {
        false
    } else if matches!(header_value, "{}" | "~" | "null" | "Null" | "NULL") {
        true
    } else {
        return Err(format!(
            "refusing to modify YAML config: existing 'mcp_servers' value '{header_value}' is not a block mapping"
        ));
    };

    // Determine end of `mcp_servers:` block (stop at the next non-blank, non-comment line at indent 0).
    let mut section_end = lines.len();
    for (idx, line) in lines.iter().enumerate().skip(start_idx + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_space_indent(line)?;
        if indent == 0 {
            section_end = idx;
            break;
        }
    }

    // Trim trailing blank lines and top-level comments (`#` at col 0) out of the section slice
    // so comments introducing the next top-level section remain attached to that section.
    let mut content_end = section_end;
    while content_end > start_idx + 1 {
        let prev = lines
            .get(content_end - 1)
            .map(String::as_str)
            .unwrap_or_default();
        let trimmed = prev.trim();
        if trimmed.is_empty() || prev.starts_with('#') {
            content_end -= 1;
        } else {
            break;
        }
    }

    // Detect child indentation and validate `mcp_servers` is a mapping (not a sequence).
    let mut child_indent: Option<usize> = None;
    for line in lines.get(start_idx + 1..content_end).unwrap_or_default() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_space_indent(line)?;
        if child_indent.is_none() {
            if trimmed == "-" || trimmed.starts_with("- ") {
                return Err(
                    "refusing to modify YAML config: existing 'mcp_servers' field is a YAML sequence, not a mapping"
                        .to_string(),
                );
            }
            child_indent = Some(indent);
        }
    }
    let child_indent = child_indent.unwrap_or(2);
    let entry_lines = render_hermes_multiplayer_entry(bin, child_indent)?;

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + entry_lines.len() + 2);
    out.extend(lines.get(..start_idx).unwrap_or_default().iter().cloned());
    if replace_inline_empty {
        out.push("mcp_servers:".to_string());
    } else {
        out.push(header_line.to_string());
    }

    let mut idx = start_idx + 1;
    let mut replaced = false;
    while idx < content_end {
        let line = lines.get(idx).map(String::as_str).unwrap_or_default();
        let trimmed = line.trim();
        let is_target_key = if !trimmed.is_empty() && !trimmed.starts_with('#') {
            let indent = leading_space_indent(line)?;
            indent == child_indent && matches_yaml_key(trimmed, "multiplayer").is_some()
        } else {
            false
        };

        if is_target_key {
            if !replaced {
                out.extend(entry_lines.iter().cloned());
                replaced = true;
            }
            idx += 1;
            // Skip entire existing `multiplayer:` subtree (strictly deeper indent or blank lines inside it).
            let mut sub_end = idx;
            while sub_end < content_end {
                let sub_line = lines.get(sub_end).map(String::as_str).unwrap_or_default();
                let sub_trimmed = sub_line.trim();
                if sub_trimmed.is_empty() {
                    sub_end += 1;
                    continue;
                }
                let sub_indent = leading_space_indent(sub_line)?;
                if sub_indent > child_indent {
                    sub_end += 1;
                } else {
                    break;
                }
            }
            // Preserve trailing blank lines that separate `multiplayer:` from the next sibling key.
            let mut kept_blanks = sub_end;
            while kept_blanks > idx
                && lines
                    .get(kept_blanks - 1)
                    .is_some_and(|l| l.trim().is_empty())
            {
                kept_blanks -= 1;
            }
            for blank_i in kept_blanks..sub_end {
                if let Some(bl) = lines.get(blank_i) {
                    out.push(bl.clone());
                }
            }
            idx = sub_end;
            continue;
        }

        out.push(line.to_string());
        idx += 1;
    }

    if !replaced {
        out.extend(entry_lines);
    }

    out.extend(lines.get(content_end..).unwrap_or_default().iter().cloned());
    let mut rendered = out.join("\n");
    rendered.push('\n');
    Ok(rendered)
}

fn upsert_json_client_config(
    client: &str,
    bin: &str,
    existing_bytes: Option<&[u8]>,
    target_path: &Path,
) -> Result<String, String> {
    let mut root_obj = match existing_bytes {
        Some(bytes) => {
            let text = core::str::from_utf8(bytes).map_err(|_| {
                format!(
                    "existing JSON config '{}' is not valid UTF-8",
                    target_path.display()
                )
            })?;
            if text.trim().is_empty() {
                serde_json::Map::new()
            } else {
                let parsed: Value = serde_json::from_str(text).map_err(|e| {
                    format!(
                        "refusing to modify invalid JSON config '{}': {e}",
                        target_path.display()
                    )
                })?;
                match parsed {
                    Value::Object(map) => map,
                    _ => {
                        return Err(format!(
                            "refusing to modify '{}': top-level JSON value must be an object",
                            target_path.display()
                        ));
                    }
                }
            }
        }
        None => serde_json::Map::new(),
    };

    let (section_key, server_value) = match client {
        "opencode" => (
            "mcp",
            json!({
                "type": "local",
                "command": [bin, "mcp"],
                "enabled": true,
            }),
        ),
        "zed" => (
            "context_servers",
            json!({
                "command": bin,
                "args": ["mcp"],
                "env": {},
            }),
        ),
        _ => (
            "mcpServers",
            json!({
                "command": bin,
                "args": ["mcp"],
            }),
        ),
    };

    let servers_entry = root_obj
        .entry(section_key.to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Value::Object(servers_map) = servers_entry else {
        return Err(format!(
            "refusing to modify '{}': existing '{section_key}' field is not a JSON object",
            target_path.display()
        ));
    };
    servers_map.insert("multiplayer".to_string(), server_value);

    let mut pretty = serde_json::to_string_pretty(&Value::Object(root_obj))
        .map_err(|e| format!("failed serializing JSON config: {e}"))?;
    pretty.push('\n');
    Ok(pretty)
}

fn ensure_not_symlink(path: &Path, label: &str) -> Result<Option<std::fs::Metadata>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "refusing to modify symlink {label} '{}'",
                    path.display()
                ));
            }
            Ok(Some(meta))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("failed inspecting {label} '{}': {e}", path.display())),
    }
}

pub(crate) fn write_mcp_client_config(
    client: &str,
    bin: &str,
    target_path: &Path,
) -> Result<Option<PathBuf>, String> {
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid config path '{}'", target_path.display()))?;
    let parent = match target_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    // Refuse symlinked parent or symlinked target (including dangling symlinks).
    if let Some(parent_meta) = ensure_not_symlink(parent, "config directory")? {
        if !parent_meta.file_type().is_dir() {
            return Err(format!(
                "refusing to write config: parent '{}' is not a directory",
                parent.display()
            ));
        }
    } else {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed creating config directory '{}': {e}",
                parent.display()
            )
        })?;
    }

    let dir_fd = open_dir_nofollow(parent)
        .map_err(|e| format!("failed opening config directory '{}': {e}", parent.display()))?;

    let existing_bytes: Option<Vec<u8>> = match ensure_not_symlink(target_path, "config path")? {
        Some(meta) => {
            if !meta.file_type().is_file() {
                return Err(format!(
                    "refusing to modify non-regular config path '{}'",
                    target_path.display()
                ));
            }
            Some(
                read_regular_file_bounded_nofollow(target_path, MAX_MCP_CONFIG_BYTES).map_err(
                    |e| {
                        format!(
                            "failed reading existing config '{}': {e}",
                            target_path.display()
                        )
                    },
                )?,
            )
        }
        None => None,
    };

    let new_contents = match client {
        "codex" => {
            let existing_str = match existing_bytes.as_deref() {
                Some(bytes) => core::str::from_utf8(bytes).map_err(|_| {
                    format!(
                        "existing TOML config '{}' is not valid UTF-8",
                        target_path.display()
                    )
                })?,
                None => "",
            };
            upsert_codex_mcp_toml(existing_str, bin)
        }
        "hermes" => {
            let existing_str = match existing_bytes.as_deref() {
                Some(bytes) => core::str::from_utf8(bytes).map_err(|_| {
                    format!(
                        "existing YAML config '{}' is not valid UTF-8",
                        target_path.display()
                    )
                })?,
                None => "",
            };
            upsert_hermes_mcp_yaml(existing_str, bin)?
        }
        _ => upsert_json_client_config(client, bin, existing_bytes.as_deref(), target_path)?,
    };

    let backup_path = if let Some(ref prev_bytes) = existing_bytes {
        let bak_name = format!("{file_name}.bak");
        let bak_full = parent.join(&bak_name);
        if let Some(bak_meta) = ensure_not_symlink(&bak_full, "backup path")?
            && !bak_meta.file_type().is_file()
        {
            return Err(format!(
                "refusing to overwrite non-regular backup path '{}'",
                bak_full.display()
            ));
        }
        atomic_write_in_dir(dir_fd.as_raw_fd(), &bak_name, prev_bytes)
            .map_err(|e| format!("failed writing backup '{bak_name}': {e}"))?;
        Some(bak_full)
    } else {
        None
    };

    atomic_write_in_dir(dir_fd.as_raw_fd(), file_name, new_contents.as_bytes()).map_err(|e| {
        format!(
            "failed atomically writing config '{}': {e}",
            target_path.display()
        )
    })?;

    Ok(backup_path)
}

pub(crate) fn cmd_mcp(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(format!(
            "usage: mp-outpost mcp setup [--client {MCP_CLIENTS_USAGE}] [--write] [--config <path>] [--global]"
        ));
    };
    if sub != "setup" {
        return Err(format!(
            "unknown mcp subcommand '{}'",
            redact_unknown_arg(sub)
        ));
    }
    let rest = args.get(1..).unwrap_or_default();
    let mut client = "all".to_string();
    let mut write_flag = false;
    let mut config_override: Option<PathBuf> = None;
    let mut global_flag = false;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--client" => client = next_val(rest, &mut i, "--client")?.to_ascii_lowercase(),
            "--write" => {
                write_flag = true;
                i += 1;
            }
            "--config" => {
                config_override = Some(PathBuf::from(next_val(rest, &mut i, "--config")?));
            }
            "--global" => {
                global_flag = true;
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown argument to `mcp setup`: {}",
                    redact_unknown_arg(other)
                ));
            }
        }
    }
    if !matches!(
        client.as_str(),
        "claude" | "codex" | "cursor" | "antigravity" | "hermes" | "gemini" | "opencode" | "zed" | "all"
    ) {
        return Err(format!(
            "invalid --client '{client}' (expected {MCP_CLIENTS_USAGE})"
        ));
    }
    if !write_flag && (config_override.is_some() || global_flag) {
        return Err("--config and --global require --write".to_string());
    }

    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "mp-outpost".to_string());

    if write_flag {
        if client == "all" {
            return Err(format!(
                "--write requires an explicit --client ({MCP_WRITE_CLIENTS_USAGE}); refusing --client all"
            ));
        }
        let target_paths = match config_override {
            Some(p) => vec![p],
            None => default_mcp_config_paths_from_home(&client, global_flag, None)?,
        };
        let mut results: Vec<(PathBuf, Option<PathBuf>)> = Vec::with_capacity(target_paths.len());
        for target_path in target_paths {
            let backup_path = write_mcp_client_config(&client, &bin, &target_path)?;
            results.push((target_path, backup_path));
        }

        if opts.json {
            let first_path = results
                .first()
                .map(|(p, _)| p.display().to_string())
                .unwrap_or_default();
            let first_bak = results
                .first()
                .and_then(|(_, b)| b.as_ref().map(|p| p.display().to_string()));
            let written_entries: Vec<Value> = results
                .iter()
                .map(|(p, b)| {
                    json!({
                        "path": p.display().to_string(),
                        "backup_path": b.as_ref().map(|bp| bp.display().to_string()),
                    })
                })
                .collect();
            let paths_list: Vec<String> = results
                .iter()
                .map(|(p, _)| p.display().to_string())
                .collect();
            print_json(&json!({
                "written": true,
                "client": client,
                "binary": bin,
                "path": first_path,
                "backup_path": first_bak,
                "paths": paths_list,
                "results": written_entries,
            }));
        } else {
            for (target_path, backup_path) in results {
                println!(
                    "Configured MCP server 'multiplayer' for {client} in '{}'.",
                    target_path.display()
                );
                if let Some(bak) = backup_path {
                    println!("Previous configuration backed up to '{}'.", bak.display());
                }
            }
            if client == "hermes" {
                println!("Reload MCP servers in an active Hermes session with `/reload-mcp`.");
            }
        }
        return Ok(());
    }

    let stdio_json = json!({
        "mcpServers": {
            "multiplayer": {
                "command": bin,
                "args": ["mcp"]
            }
        }
    });
    let opencode_json = json!({
        "mcp": {
            "multiplayer": {
                "type": "local",
                "command": [bin, "mcp"],
                "enabled": true
            }
        }
    });
    let zed_json = json!({
        "context_servers": {
            "multiplayer": {
                "command": bin,
                "args": ["mcp"],
                "env": {}
            }
        }
    });
    let quoted_bin = shell_single_quote(&bin);
    let claude_cmd = format!("claude mcp add multiplayer -- {quoted_bin} mcp");
    let codex_cmd = format!("codex mcp add multiplayer -- {quoted_bin} mcp");
    let codex_toml = format!(
        "[mcp_servers.multiplayer]\ncommand = {}\nargs = [\"mcp\"]",
        toml_basic_string(&bin)
    );
    let hermes_yaml = render_hermes_snippet(&bin)?;

    if opts.json {
        let mut configs = serde_json::Map::new();
        if client == "all" || client == "claude" {
            configs.insert(
                "claude".to_string(),
                json!({
                    "command": claude_cmd,
                    "mcp_json": stdio_json,
                }),
            );
        }
        if client == "all" || client == "codex" {
            configs.insert(
                "codex".to_string(),
                json!({
                    "command": codex_cmd,
                    "config_toml": codex_toml,
                }),
            );
        }
        if client == "all" || client == "cursor" {
            configs.insert(
                "cursor".to_string(),
                json!({
                    "config_path": ".cursor/mcp.json",
                    "mcp_json": stdio_json,
                }),
            );
        }
        if client == "all" || client == "antigravity" {
            configs.insert(
                "antigravity".to_string(),
                json!({
                    "config_paths": [
                        "~/.gemini/antigravity/mcp_config.json",
                        "~/.gemini/config/mcp_config.json"
                    ],
                    "mcp_json": stdio_json,
                }),
            );
        }
        if client == "all" || client == "hermes" {
            configs.insert(
                "hermes".to_string(),
                json!({
                    "config_path": "~/.hermes/config.yaml",
                    "config_yaml": hermes_yaml,
                }),
            );
        }
        if client == "all" || client == "gemini" {
            configs.insert(
                "gemini".to_string(),
                json!({
                    "config_path": "~/.gemini/settings.json",
                    "mcp_json": stdio_json,
                }),
            );
        }
        if client == "all" || client == "opencode" {
            configs.insert(
                "opencode".to_string(),
                json!({
                    "config_path": "~/.config/opencode/opencode.json",
                    "mcp_json": opencode_json,
                }),
            );
        }
        if client == "all" || client == "zed" {
            configs.insert(
                "zed".to_string(),
                json!({
                    "config_path": "~/.config/zed/settings.json",
                    "mcp_json": zed_json,
                }),
            );
        }
        print_json(&json!({
            "binary": bin,
            "client": client,
            "configs": Value::Object(configs),
        }));
        return Ok(());
    }

    let pretty_json = serde_json::to_string_pretty(&stdio_json).unwrap_or_default();
    let pretty_opencode = serde_json::to_string_pretty(&opencode_json).unwrap_or_default();
    let pretty_zed = serde_json::to_string_pretty(&zed_json).unwrap_or_default();
    if client == "all" || client == "claude" {
        println!("=== Claude Code ===");
        println!("Run:\n  {claude_cmd}\n");
        println!("Or add to .mcp.json (or pass `--client claude --write`):\n{pretty_json}\n");
    }
    if client == "all" || client == "codex" {
        println!("=== Codex CLI ===");
        println!("Run:\n  {codex_cmd}\n");
        println!(
            "Or add to ~/.codex/config.toml (or pass `--client codex --write`):\n{codex_toml}\n"
        );
    }
    if client == "all" || client == "cursor" {
        println!("=== Cursor ===");
        println!(
            "Add to .cursor/mcp.json or ~/.cursor/mcp.json (or pass `--client cursor --write`):\n{pretty_json}\n"
        );
    }
    if client == "all" || client == "antigravity" {
        println!("=== Antigravity ===");
        println!(
            "Add to ~/.gemini/antigravity/mcp_config.json (IDE) and/or ~/.gemini/config/mcp_config.json (Antigravity 2.0 / agy CLI) (or pass `--client antigravity --write`):\n{pretty_json}\n"
        );
    }
    if client == "all" || client == "hermes" {
        println!("=== Hermes Agent ===");
        println!(
            "Add to ~/.hermes/config.yaml (or pass `--client hermes --write`, then run `/reload-mcp`):\n{hermes_yaml}\n"
        );
    }
    if client == "all" || client == "gemini" {
        println!("=== Gemini CLI ===");
        println!(
            "Add to ~/.gemini/settings.json (or pass `--client gemini --write`):\n{pretty_json}\n"
        );
    }
    if client == "all" || client == "opencode" {
        println!("=== OpenCode ===");
        println!(
            "Add to ~/.config/opencode/opencode.json (or pass `--client opencode --write`):\n{pretty_opencode}\n"
        );
    }
    if client == "all" || client == "zed" {
        println!("=== Zed Editor ===");
        println!(
            "Add to ~/.config/zed/settings.json (or pass `--client zed --write`):\n{pretty_zed}\n"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    #[test]
    fn hermes_yaml_upsert_fresh_merge_replace_and_idempotency() -> Result<(), String> {
        let bin = "/usr/local/bin/mp-outpost";

        // 1. Fresh empty file
        let fresh = upsert_hermes_mcp_yaml("", bin)?;
        assert!(fresh.starts_with("mcp_servers:\n  multiplayer:\n"));
        assert!(fresh.contains("command: \"/usr/local/bin/mp-outpost\""));
        assert!(fresh.contains("timeout: 90"));
        assert!(fresh.contains("connect_timeout: 15"));
        assert_eq!(fresh, upsert_hermes_mcp_yaml(&fresh, bin)?);

        // 2. Existing config without mcp_servers preserves comments and unrelated keys
        let no_mcp = "# Hermes config\nmodel:\n  default: claude-sonnet\nagent:\n  max_turns: 40\n";
        let added = upsert_hermes_mcp_yaml(no_mcp, bin)?;
        assert!(added.contains("# Hermes config"));
        assert!(added.contains("model:\n  default: claude-sonnet"));
        assert!(added.contains("agent:\n  max_turns: 40"));
        assert!(added.contains("mcp_servers:\n  multiplayer:"));
        assert_eq!(added, upsert_hermes_mcp_yaml(&added, bin)?);

        // 3. Existing mcp_servers with sibling servers before & after + existing multiplayer block
        let existing_multi = "\
model:
  name: opus
# MCP block
mcp_servers:
  github:
    command: \"gh-mcp\"
    args: [\"serve\"]
  multiplayer:
    command: \"/old/mp-outpost\"
    args: [\"mcp\"]
    env:
      OLD: \"1\"
    timeout: 30
  linear:
    url: \"https://mcp.linear.app/mcp\"

# Tool costs
tool_costs:
  default: 1
";
        let updated = upsert_hermes_mcp_yaml(existing_multi, "/opt/bin/mp-outpost")?;
        assert!(updated.contains("github:\n    command: \"gh-mcp\""));
        assert!(updated.contains("linear:\n    url: \"https://mcp.linear.app/mcp\""));
        assert!(updated.contains("# Tool costs\ntool_costs:\n  default: 1"));
        assert!(updated.contains("command: \"/opt/bin/mp-outpost\""));
        assert!(updated.contains("timeout: 90"));
        assert!(updated.contains("connect_timeout: 15"));
        assert!(!updated.contains("/old/mp-outpost"));
        assert!(!updated.contains("OLD:"));
        assert_eq!(updated, upsert_hermes_mcp_yaml(&updated, "/opt/bin/mp-outpost")?);

        // 4. Empty inline mapping `mcp_servers: {}` and `mcp_servers: null`
        for empty_hdr in ["mcp_servers: {}\n", "mcp_servers: null # empty\n"] {
            let merged = upsert_hermes_mcp_yaml(empty_hdr, bin)?;
            assert!(merged.contains("mcp_servers:\n  multiplayer:\n"));
            assert!(!merged.contains("{}"));
            assert_eq!(merged, upsert_hermes_mcp_yaml(&merged, bin)?);
        }

        // 5. Fail closed on non-mapping or sequence `mcp_servers`
        assert!(upsert_hermes_mcp_yaml("mcp_servers: \"invalid\"\n", bin).is_err());
        assert!(upsert_hermes_mcp_yaml("mcp_servers: { foo: bar }\n", bin).is_err());
        assert!(upsert_hermes_mcp_yaml("mcp_servers:\n  - foo\n", bin).is_err());

        Ok(())
    }

    #[test]
    fn write_hermes_gemini_opencode_zed_preserves_keys_bak_and_0600() -> Result<(), String> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let bin = "/opt/homebrew/bin/mp-outpost";

        // Hermes YAML: 0600 permissions + .bak + unrelated keys preserved
        let hermes_path = tmp.path().join("hermes").join("config.yaml");
        std::fs::create_dir_all(tmp.path().join("hermes")).map_err(|e| e.to_string())?;
        let orig_hermes = "agent:\n  name: pilot\n";
        std::fs::write(&hermes_path, orig_hermes).map_err(|e| e.to_string())?;
        let bak = write_mcp_client_config("hermes", bin, &hermes_path)?;
        let bak_path = bak.ok_or("expected .bak for existing hermes config")?;
        assert_eq!(
            std::fs::read_to_string(&bak_path).map_err(|e| e.to_string())?,
            orig_hermes
        );
        let mode = std::fs::metadata(&hermes_path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let hermes_after = std::fs::read_to_string(&hermes_path).map_err(|e| e.to_string())?;
        assert!(hermes_after.contains("agent:\n  name: pilot"));
        assert!(hermes_after.contains("timeout: 90"));
        assert!(hermes_after.contains("connect_timeout: 15"));

        // Gemini JSON
        let gemini_path = tmp.path().join("gemini_settings.json");
        std::fs::write(
            &gemini_path,
            r#"{"theme":"dark","mcpServers":{"keep":{"command":"k","args":[]}}}"#,
        )
        .map_err(|e| e.to_string())?;
        write_mcp_client_config("gemini", bin, &gemini_path)?;
        let gem_val: Value = serde_json::from_str(
            &std::fs::read_to_string(&gemini_path).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(gem_val.pointer("/theme").and_then(Value::as_str), Some("dark"));
        assert_eq!(
            gem_val.pointer("/mcpServers/keep/command").and_then(Value::as_str),
            Some("k")
        );
        assert_eq!(
            gem_val
                .pointer("/mcpServers/multiplayer/command")
                .and_then(Value::as_str),
            Some(bin)
        );
        assert_eq!(
            gem_val
                .pointer("/mcpServers/multiplayer/args/0")
                .and_then(Value::as_str),
            Some("mcp")
        );

        // OpenCode JSON
        let oc_path = tmp.path().join("opencode.json");
        std::fs::write(
            &oc_path,
            r#"{"$schema":"https://opencode.ai/config.json","mcp":{"other":{"type":"remote","url":"https://example.test"}}}"#,
        )
        .map_err(|e| e.to_string())?;
        write_mcp_client_config("opencode", bin, &oc_path)?;
        let oc_val: Value = serde_json::from_str(
            &std::fs::read_to_string(&oc_path).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(
            oc_val.pointer("/mcp/other/type").and_then(Value::as_str),
            Some("remote")
        );
        assert_eq!(
            oc_val.pointer("/mcp/multiplayer/type").and_then(Value::as_str),
            Some("local")
        );
        assert_eq!(
            oc_val
                .pointer("/mcp/multiplayer/command/0")
                .and_then(Value::as_str),
            Some(bin)
        );
        assert_eq!(
            oc_val
                .pointer("/mcp/multiplayer/command/1")
                .and_then(Value::as_str),
            Some("mcp")
        );
        assert_eq!(
            oc_val
                .pointer("/mcp/multiplayer/enabled")
                .and_then(Value::as_bool),
            Some(true)
        );

        // Zed JSON
        let zed_path = tmp.path().join("zed_settings.json");
        std::fs::write(
            &zed_path,
            r#"{"buffer_font_size":14,"context_servers":{"existing":{"command":"x","args":[]}}}"#,
        )
        .map_err(|e| e.to_string())?;
        write_mcp_client_config("zed", bin, &zed_path)?;
        let zed_val: Value = serde_json::from_str(
            &std::fs::read_to_string(&zed_path).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(
            zed_val.pointer("/buffer_font_size").and_then(Value::as_i64),
            Some(14)
        );
        assert_eq!(
            zed_val
                .pointer("/context_servers/existing/command")
                .and_then(Value::as_str),
            Some("x")
        );
        assert_eq!(
            zed_val
                .pointer("/context_servers/multiplayer/command")
                .and_then(Value::as_str),
            Some(bin)
        );
        assert_eq!(
            zed_val
                .pointer("/context_servers/multiplayer/args/0")
                .and_then(Value::as_str),
            Some("mcp")
        );

        // Fail closed when target section is wrong JSON type
        let bad_oc = tmp.path().join("bad_opencode.json");
        std::fs::write(&bad_oc, r#"{"mcp":[]}"#).map_err(|e| e.to_string())?;
        assert!(write_mcp_client_config("opencode", bin, &bad_oc).is_err());

        let bad_zed = tmp.path().join("bad_zed.json");
        std::fs::write(&bad_zed, r#"{"context_servers":"oops"}"#).map_err(|e| e.to_string())?;
        assert!(write_mcp_client_config("zed", bin, &bad_zed).is_err());

        Ok(())
    }

    #[test]
    fn antigravity_default_path_resolution_handles_ide_cli_and_fresh_home() -> Result<(), String> {
        let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let home = tmp.path();
        let ide_cfg = home.join(".gemini").join("antigravity").join("mcp_config.json");
        let cli_cfg = home.join(".gemini").join("config").join("mcp_config.json");

        // Fresh HOME -> both IDE & CLI paths
        assert_eq!(
            antigravity_default_paths_from_home(home),
            vec![ide_cfg.clone(), cli_cfg.clone()]
        );

        // Only CLI directory exists -> CLI path only
        std::fs::create_dir_all(home.join(".gemini").join("config"))
            .map_err(|e| e.to_string())?;
        assert_eq!(
            antigravity_default_paths_from_home(home),
            vec![cli_cfg.clone()]
        );

        // Both exist -> both paths
        std::fs::create_dir_all(home.join(".gemini").join("antigravity"))
            .map_err(|e| e.to_string())?;
        assert_eq!(
            antigravity_default_paths_from_home(home),
            vec![ide_cfg.clone(), cli_cfg.clone()]
        );

        // Only IDE directory exists -> IDE path only
        std::fs::remove_dir_all(home.join(".gemini").join("config"))
            .map_err(|e| e.to_string())?;
        assert_eq!(antigravity_default_paths_from_home(home), vec![ide_cfg]);

        Ok(())
    }

    #[test]
    fn write_mcp_client_config_refuses_live_dangling_parent_and_bak_symlinks() -> Result<(), String>
    {
        let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let bin = "/usr/local/bin/mp-outpost";

        // 1. Live symlink target
        let real_file = tmp.path().join("real.json");
        std::fs::write(&real_file, r#"{"keep":1}"#).map_err(|e| e.to_string())?;
        let live_link = tmp.path().join("live_link.json");
        symlink(&real_file, &live_link).map_err(|e| e.to_string())?;
        assert!(write_mcp_client_config("gemini", bin, &live_link).is_err());
        assert_eq!(
            std::fs::read_to_string(&real_file).map_err(|e| e.to_string())?,
            r#"{"keep":1}"#
        );

        // 2. Dangling symlink target
        let dangling_link = tmp.path().join("dangling.yaml");
        symlink(tmp.path().join("does-not-exist.yaml"), &dangling_link)
            .map_err(|e| e.to_string())?;
        assert!(write_mcp_client_config("hermes", bin, &dangling_link).is_err());

        // 3. Symlink parent directory
        let real_dir = tmp.path().join("real_dir");
        std::fs::create_dir(&real_dir).map_err(|e| e.to_string())?;
        let link_dir = tmp.path().join("link_dir");
        symlink(&real_dir, &link_dir).map_err(|e| e.to_string())?;
        assert!(write_mcp_client_config("zed", bin, &link_dir.join("settings.json")).is_err());

        // 4. Symlink .bak file
        let target_cfg = tmp.path().join("opencode.json");
        std::fs::write(&target_cfg, r#"{}"#).map_err(|e| e.to_string())?;
        let bak_link = tmp.path().join("opencode.json.bak");
        symlink(&real_file, &bak_link).map_err(|e| e.to_string())?;
        assert!(write_mcp_client_config("opencode", bin, &target_cfg).is_err());
        assert_eq!(
            std::fs::read_to_string(&real_file).map_err(|e| e.to_string())?,
            r#"{"keep":1}"#
        );

        Ok(())
    }
}
