# multiplayer_outpost

Read [BLACKBIRD.md](BLACKBIRD.md) (workspace doctrine), [README.md](README.md), and [JOURNAL.md](JOURNAL.md).

## Mission

`multiplayer_outpost` is the third platoon in the multiplayer company alongside:
- `../blackbird` (`blackbird-leader`) — full Blackbird coding agent harness & C++23 client
- `../multiplayer_site` (`multiplayer-site`) — `multiplayer.tech` web home, Cloudflare `api.multiplayer.tech` control plane (`MP1`), and `multiplayer.tech/mcp`

Our mission: build a lightweight, standalone **Outpost / sidecar** (CLI + MCP stdio server over `mp-protocol` + `iroh` v1.5.0) containing only what is needed for non-Blackbird coding agents (Claude Code, Codex, Antigravity, etc.) to join `multiplayer.tech` parties and exchange P2P party chat / board messages without requiring the full Blackbird harness.

## Cross-Platoon Bridge

Coordinate with sibling platoons via the shared company board:
```sh
blackbird platoon read --board ~/projects/.blackbird/xplat-board
blackbird platoon post --board ~/projects/.blackbird/xplat-board --from multiplayer-outpost --to all --kind brief --text '...'
```

## Non-Negotiable Constraints

1. **Control-Plane vs. P2P Data-Plane Boundary:** `https://api.multiplayer.tech` handles only accounts, multi-device CWTs, friends/blocks, presence, party making/unmaking, and `EndpointDescriptor` rendezvous. All party payloads flow peer-to-peer over `iroh` v1.5.0 (QUIC RFC 9000 + TLS 1.3 Mutual RPK RFC 7250, 0-RTT off, ALPN `blackbird-mp/1`).
2. **Zero Homebrew Primitives, Zero Homebrew Protocols:** Standards-only crypto (TLS 1.3, RFC 9421 + RFC 9530 `tag="mp1"`, RFC 8392/8747 `COSE_Sign1` `alg = Ed25519 (-19)` exact protected header `h'A10132'`, strict RFC 8032 torsion-free Ed25519, `iroh` v1.5.0).
3. **Primary Keys Are Never Strings (`BLACKBIRD.md` Tenet #6):** All entity IDs are 52/53-bit positive integers (`1..=9007199254740991`). Handles, labels, and aliases are mutable properties.
4. **Binary Internals, JSON Only at External Boundaries:** Native values and binary wire/storage formats internally; JSON strictly at external REST and MCP JSON-RPC boundaries.
5. **No Code Before Research, Spec, Tribunals, and Plan:** Follow `BLACKBIRD.md` Pattern of Work (Frumentarii -> Deep Research & Spec -> Adversarial Tribunal -> Brutal Plan -> JSMNTL).
6. **Workspace Library Policy:** Discuss any third-party crate/library adoption with the operator before adopting it.
7. **Repo Hygiene:** Keep literature and research reports in `papers/`, reference implementations in gitignored `quarantine/` tracked by `QUARANTINE.md`, working scratch/logs in gitignored `context/`, and record every significant act in `JOURNAL.md`.
