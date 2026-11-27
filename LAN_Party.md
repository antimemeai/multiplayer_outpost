# LAN Party! Mode (`mp1-lan/1`)

**Status:** Shipped in **Outpost (`mp-outpost`)** and **Blackbird** (`blackbird` ↔ `blackbird`, `mp-outpost` ↔ `mp-outpost`, and `blackbird` ↔ `mp-outpost`)  
**Scope:** Zero-server, zero-account, sub-millisecond encrypted local-network multiplayer that feels like a 1998 LAN lobby while keeping strict cryptographic and local-safety invariants.

> **Note on online vs. LAN modes:** Online parties on `multiplayer.tech` use `mp2` WebSockets with **MLS (RFC 9420)** end-to-end encryption (`openmls`). **LAN Party! mode (`mp1-lan/1`)** is a separate, strictly opt-in, zero-server local-network mode with zero calls to `api.multiplayer.tech`.

---

## 1. Operator Security & Safety Invariants (Non-Negotiable)

1. **Strictly opt-in — never active by default:** Neither Blackbird nor `mp-outpost` opens a LAN discovery socket or sends mDNS/UDP advertisements until you explicitly start a LAN host or scan.
2. **Hard kill-switch (configurably disabled):**
   - Permanently fail-closed via **config file** (`lan.disabled = true`) AND **environment variable** (`MP_DISABLE_LAN=1`; Blackbird also honors `BLACKBIRD_DISABLE_LAN=1`).
   - When disabled, any CLI/TUI/MCP attempt to host, scan, or join a LAN party fails closed immediately without opening any UDP/mDNS socket.
   - **MCP safety:** Local stdio MCP tools (`mp-outpost mcp`) NEVER start a LAN host or disable PIN/Safety Number checks autonomously; LAN host, join, and peer trust are human-initiated terminal/TUI actions only.
3. **Auto-timeout & shut off when idle:**
   - **Host beacon timeout (default: `300s` / 5 min, configurable via `--timeout <sec>`, hard cap `1800s`):** If no remote peer joins before the timer expires, the host stops mDNS advertising, closes its LAN discovery listener, and exits cleanly (`lan_host_timeout`). Once a lobby is locked or idle timeout fires, mDNS advertisements stop.
   - **Scan timeout (default: `15s`, configurable up to `60s`):** Scanning stops automatically and closes the multicast socket when the window expires.
4. **Configurably require a user-provided PIN:**
   - Supported via **config file** (`lan.require_pin = true`) and CLI/TUI flags (`--require-pin` / `--pin-stdin` / interactive hidden `/dev/tty` prompt).
   - **Zero secrets on argv:** PINs are read from `/dev/tty` hidden prompt or `--pin-stdin` — NEVER accepted via `--pin <value>` CLI arguments (keeping `ps` and shell history clean).
   - **Constant-time challenge-response inside TLS 1.3 (never plaintext on wire):**
     - PIN verification occurs *after* the local QUIC + TLS 1.3 Mutual Ed25519 RPK handshake completes (so passive Wi-Fi sniffers see nothing).
     - Host sends a fresh 32-byte random `host_nonce`.
     - Joiner responds with `proof = BLAKE3_keyed(key = BLAKE3_derive("mp1-lan-pin-v1", utf8_nfc(pin)), msg = "mp1-lan-join" || lan_party_id || host_pubkey || joiner_pubkey || host_nonce)` (32 bytes), verified in constant time.
     - **Brute-force lock:** Host enforces max **5 failed PIN attempts** per `(joiner_pubkey, source_ip)` and max **15 total failed attempts** per lobby before tearing down the lobby.
5. **No silent trust — Safety Number pinning stays mandatory:**
   - LAN discovery (mDNS/UDP) is **untrusted** (anyone on the same Wi-Fi can spoof advertisements).
   - Existing pinned peers (`~/.config/mp-outpost/lan_peers.json` / Blackbird peer store) are recognized automatically by their Ed25519 public key + Safety Number.
   - Unpinned peers require explicit interactive terminal/TUI confirmation of their canonical **Safety Number** (computed with the same `compute_safety_number` algorithm, using `account_id = 0` for local-only LAN identities).
6. **Unlocked-laptop & walk-up attack guard (`lan.require_local_auth` + system policy):**
   - Configurable **local OS presence verification** (`lan.require_local_auth = true`) before starting a LAN host, joining a LAN lobby, or pinning a new LAN peer:
     - **macOS:** Native `LocalAuthentication` (`LAContext` with `LAPolicy.deviceOwnerAuthentication` — Touch ID or macOS account password), falling back to `sudo -k && sudo -v` on headless SSH sessions.
     - **Linux:** PAM / `sudo -k && sudo -v` (`-k` always invalidates cached timestamps).
   - **Tamper-resistant system policy (optional):** Both clients check `/etc/multiplayer/lan.toml` (root-owned, if present) **before** user config and treat system-level `disabled = true`, `require_pin = true`, or `require_local_auth = true` as non-overridable lower bounds.

---

## 2. Works Completely Offline (No Account Required)

- **Registered `multiplayer.tech` user:** Can reuse an existing Ed25519 identity and Safety Number.
- **Unregistered / air-gapped user:** Generates or reuses a local-only `0600` Ed25519 LAN identity (`display_name` + local pubkey + Safety Number with `account_id = 0`) so anyone can run encrypted Blackbird ↔ Outpost LAN collaboration immediately on office Wi-Fi, a home lab, or a plane.

---

## 3. Discovery & Wire Interop Contract (`mp1-lan/1`)

### A. Discovery Layer (mDNS + Direct `ip:port` Fallback)
- **mDNS Service Type:** `_mp1-lan._udp.local.` (RFC 6762/6763).
- **Minimal TXT Record (zero secrets, bounded <= 256 B):**
  - `v=1` (protocol version)
  - `id=<16-hex random lan_party_id>`
  - `name=<1..32 printable ASCII lobby name>`
  - `host=<1..32 printable ASCII handle or display name>`
  - `pk=<base64url 32-byte Ed25519 host pubkey>`
  - `pin=<0|1>` (advertises whether host requires a PIN; never carries the PIN or a hash of it)
  - `alpn=blackbird-mp/1`
- **Direct IP Fallback (Tailscale / WireGuard / routed VLANs where multicast does not cross subnets):**
  - Host prints its direct LAN `ip:port` + `pk` fingerprint when started.
  - Joiner can bypass mDNS completely: `lan join <ip:port> [--host-pk <b64u>]`.

### B. Direct Local Encrypted Transport
- Uses local QUIC + TLS 1.3 Mutual Ed25519 RPK (`blackbird-mp/1`) with **relays disabled** (local LAN endpoints only) and zero calls to `api.multiplayer.tech`.
- Host acts as the in-memory coordinator for the LAN lobby (enforcing `max_members <= 12`, PIN challenge-response, kick/lock, and clean teardown on exit).

---

## 4. CLI & Config Reference

```sh
# Outpost (mp-outpost)
mp-outpost lan status
mp-outpost lan host [--name "quake-night"] [--require-pin] [--pin-stdin] [--timeout 300]
mp-outpost lan scan [--timeout 15]
mp-outpost lan join <lobby_id|ip:port> [--pin-stdin]

# Blackbird (CLI + TUI /lan)
blackbird lan status
blackbird lan host [--name "quake-night"] [--require-pin] [--pin-stdin] [--timeout 300]
blackbird lan scan [--timeout 15]
blackbird lan join <lobby_id|ip:port> [--pin-stdin]
```

**Config keys (`lan.toml`, both clients):**
```toml
[lan]
disabled = false            # true = hard kill-switch (also MP_DISABLE_LAN=1)
require_pin = false         # true = refuse to host without a user-provided room PIN
require_local_auth = false  # true = require fresh Touch ID / OS password (or sudo -k -v) before LAN host/join/pin
idle_timeout_sec = 300      # auto-stop hosting if 0 peers join (max 1800)
scan_timeout_sec = 15       # auto-stop scanning if 0 lobbies found (max 60)
# Optional root-owned /etc/multiplayer/lan.toml acts as a non-overridable policy floor.
```
