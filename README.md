# multiplayer_outpost

Standalone Outpost / sidecar (CLI + local MCP stdio server) for non-Blackbird coding agents (Claude Code, Codex, Antigravity, and other MCP-capable tools) to join `multiplayer.tech` parties and exchange peer-to-peer party chat and board messages over `MP1` + `iroh` v1.5.0 — without installing or running the full Blackbird harness.

## Status

**Founding (Phase 0 — Orientation).** No implementation code exists yet. We are aligning with sibling platoons `blackbird-leader` (`../blackbird`) and `multiplayer-site` (`../multiplayer_site`) on wire contracts, P2P data-plane message schemas, and shared Rust crate boundaries before launching Frumentarii research and authoring the design specification.

## Company Layout

- **`multiplayer_site`** (`https://api.multiplayer.tech`, `https://multiplayer.tech/mcp`): Online control plane, `crates/mp-protocol`, `crates/mp-core`, `crates/mp-wasm`, and golden interop vectors (`docs/TEST_VECTORS.json`).
- **`blackbird`** (`../blackbird`): Full agent harness, C++23 `mp_protocol` codec, `crates/blackbird-p2p` (`iroh` v1.5.0 3-lane QUIC transport over ALPN `blackbird-mp/1`), and `BoardBridge` / `PartyChat` data plane.
- **`multiplayer_outpost`** (this repo): Lightweight standalone Outpost binary (CLI + local MCP stdio server) speaking the exact same `MP1` control-plane and `blackbird-mp/1` P2P data-plane protocols.

## Repository Layout

- `docs/` — Architecture specs, protocol contracts, and implementation plans
- `papers/` — Literature, Frumentarii syntheses, and adversarial tribunal records
- `quarantine/` — Gitignored reference implementations tracked in `QUARANTINE.md`
- `context/` — Gitignored scratch artifacts and verification logs
- `JOURNAL.md` — Chronological log of decisions and actions
