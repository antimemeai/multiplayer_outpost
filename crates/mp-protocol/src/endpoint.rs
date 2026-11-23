//! Strictly parsed, zero-opaque-blob P2P `EndpointDescriptor` binary codec (`<= 256 B` exact max).
//! Replaces opaque signaling payloads so PartyDO has ZERO covert party-content relay channel.

use core::fmt;

/// Exact grammar max: 1 (kind) + 2 (relay_url_len) + 100 (relay_url) + 1 (direct_count) + 8*19 (IPv6) = 256 B.
pub const MAX_ENDPOINT_DESCRIPTOR_BYTES: usize = 256;
pub const MAX_RELAY_URL_BYTES: usize = 100;
pub const MAX_DIRECT_ADDRS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportKind {
    IrohQuic = 1,
    DirectQuic = 2,
}

impl TransportKind {
    pub const fn from_u8(v: u8) -> Result<Self, EndpointError> {
        match v {
            1 => Ok(Self::IrohQuic),
            2 => Ok(Self::DirectQuic),
            _ => Err(EndpointError::InvalidTransportKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayPolicy {
    AllowRelays = 0,
    ForceRelays = 1,
    NoRelays = 2,
}

impl RelayPolicy {
    pub const fn from_u8(v: u8) -> Result<Self, EndpointError> {
        match v {
            0 => Ok(Self::AllowRelays),
            1 => Ok(Self::ForceRelays),
            2 => Ok(Self::NoRelays),
            _ => Err(EndpointError::InvalidRelayPolicy),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectAddr {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}

impl DirectAddr {
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::V4 { .. } => 1 + 4 + 2,
            Self::V6 { .. } => 1 + 16 + 2,
        }
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::V4 { port, .. } | Self::V6 { port, .. } => *port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDescriptor {
    pub transport_kind: TransportKind,
    pub relay_url: String,
    pub direct_addrs: Vec<DirectAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    TooLarge,
    Truncated,
    TrailingBytes,
    InvalidTransportKind,
    InvalidRelayPolicy,
    InvalidRelayUrl,
    TooManyDirectAddrs,
    InvalidAddrFamily,
    InvalidPort,
    DisallowedDirectAddr,
    ForceRelaysViolation,
    NoRelaysViolation,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EndpointError {}

/// Label-boundary denylist for private/internal/loopback/rebinding suffixes.
const DENIED_RELAY_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "arpa",
    "localdomain",
    "lan",
    "home",
    "corp",
    "intranet",
    "private",
    "invalid",
    "test",
    "example",
    "onion",
    "alt",
    "nip.io",
    "sslip.io",
    "xip.io",
    "localtest.me",
    "lvh.me",
];

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.')
}

/// Extracts and validates the host portion of an `https://<fqdn>[:port]` relay origin.
/// Strictly rejects:
/// - non-HTTPS schemes, paths, queries, fragments, userinfo, uppercase
/// - single-label hosts (`localhost`), IPv4 literals (`127.0.0.1`), integer/hex hosts (`2130706433`, `0x7f.1`)
/// - DNS labels > 63 bytes, starting/ending with `-`, `0x...`, or punycode `xn--` on ANY label
/// - non-alpha or single-char TLDs (requires `^[a-z]{2,63}$`)
/// - private/internal/rebinding DNS suffixes (`DENIED_RELAY_SUFFIXES`) on exact label boundaries
/// - explicit privileged ports `0..=1023` (including `:443`, `:80`, `:22`) or invalid ports
fn parse_and_validate_relay_host(url: &str) -> Result<&str, EndpointError> {
    if url.len() > MAX_RELAY_URL_BYTES {
        return Err(EndpointError::InvalidRelayUrl);
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or(EndpointError::InvalidRelayUrl)?;
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('@')
        || rest.contains('\\')
    {
        return Err(EndpointError::InvalidRelayUrl);
    }
    let (host, port_opt) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(EndpointError::InvalidRelayUrl);
    }

    // Require a valid multi-label FQDN (rejects localhost, numeric/IPv4/hex hosts, punycode, bad DNS labels).
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(EndpointError::InvalidRelayUrl);
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(EndpointError::InvalidRelayUrl);
    }
    for &label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || label.starts_with("0x")
            || label.starts_with("xn--")
        {
            return Err(EndpointError::InvalidRelayUrl);
        }
    }
    // TLD must be strictly `^[a-z]{2,63}$` (rejects numeric/IP-like/punycode/1-char TLDs).
    let tld = labels.last().copied().unwrap_or("");
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(EndpointError::InvalidRelayUrl);
    }

    // Exact label-boundary suffix denylist (prevents internal/LAN/rebinding SSRF).
    if DENIED_RELAY_SUFFIXES
        .iter()
        .any(|&suffix| host_matches_suffix(host, suffix))
    {
        return Err(EndpointError::InvalidRelayUrl);
    }

    if let Some(p) = port_opt {
        if p.is_empty() || p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EndpointError::InvalidRelayUrl);
        }
        let port: u16 = p.parse().map_err(|_| EndpointError::InvalidRelayUrl)?;
        // Reject privileged ports (< 1024, including :443 default port and :22/:80/:53).
        if port < 1024 {
            return Err(EndpointError::InvalidRelayUrl);
        }
    }
    Ok(host)
}

/// Validates an optional HTTPS relay URL origin (`https://<fqdn>[:port]`, <= 100 bytes).
pub fn validate_relay_url(url: &str) -> Result<(), EndpointError> {
    if url.is_empty() {
        return Ok(());
    }
    let _ = parse_and_validate_relay_host(url)?;
    Ok(())
}

/// Validates a non-empty customer self-hosted corporate relay URL origin.
/// Enforces all `validate_relay_url` SSRF invariants AND rejects `multiplayer.tech` / `*.multiplayer.tech`.
pub fn validate_corporate_relay_url(url: &str) -> Result<(), EndpointError> {
    if url.is_empty() {
        return Err(EndpointError::InvalidRelayUrl);
    }
    let host = parse_and_validate_relay_host(url)?;
    if host_matches_suffix(host, "multiplayer.tech") {
        return Err(EndpointError::InvalidRelayUrl);
    }
    Ok(())
}

/// Validates a party's `pinned_relay_url` against its `RelayPolicy`.
pub fn validate_pinned_relay_url(
    policy: RelayPolicy,
    pinned_relay_url: &str,
) -> Result<(), EndpointError> {
    validate_relay_url(pinned_relay_url)?;
    match policy {
        RelayPolicy::ForceRelays => {
            if pinned_relay_url.is_empty() {
                return Err(EndpointError::ForceRelaysViolation);
            }
        }
        RelayPolicy::NoRelays => {
            if !pinned_relay_url.is_empty() {
                return Err(EndpointError::NoRelaysViolation);
            }
        }
        RelayPolicy::AllowRelays => {}
    }
    Ok(())
}

fn is_always_disallowed_addr(addr: DirectAddr) -> bool {
    match addr {
        DirectAddr::V4 { ip, .. } => {
            let [a, b, c, d] = ip;
            // Unspecified (0.0.0.0/8), loopback (127.0.0.0/8), multicast (224.0.0.0/4), broadcast/reserved (240.0.0.0/4)
            a == 0 || a == 127 || a >= 224 || (a == 255 && b == 255 && c == 255 && d == 255)
        }
        DirectAddr::V6 { ip, .. } => {
            let is_unspec = ip.iter().all(|&b| b == 0);
            let is_loopback = ip.get(0..15).is_some_and(|s| s.iter().all(|&b| b == 0))
                && ip.get(15) == Some(&1);
            let is_multicast = ip.first() == Some(&0xff);
            // IPv4-mapped IPv6 (::ffff:0:0/96)
            let is_v4_mapped = ip.get(0..10).is_some_and(|s| s.iter().all(|&b| b == 0))
                && ip.get(10) == Some(&0xff)
                && ip.get(11) == Some(&0xff);
            is_unspec || is_loopback || is_multicast || is_v4_mapped
        }
    }
}

fn is_private_or_lan_addr(addr: DirectAddr) -> bool {
    match addr {
        DirectAddr::V4 { ip, .. } => {
            let [a, b, _, _] = ip;
            // RFC 1918 (10/8, 172.16/12, 192.168/16), CGNAT/Tailscale (100.64/10), link-local (169.254/16)
            a == 10
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
        }
        DirectAddr::V6 { ip, .. } => {
            let b0 = ip.first().copied().unwrap_or(0);
            let b1 = ip.get(1).copied().unwrap_or(0);
            // ULA (fc00::/7) or link-local (fe80::/10)
            (b0 & 0xfe) == 0xfc || (b0 == 0xfe && (b1 & 0xc0) == 0x80)
        }
    }
}

impl EndpointDescriptor {
    pub fn validate(&self) -> Result<(), EndpointError> {
        validate_relay_url(&self.relay_url)?;
        if self.direct_addrs.len() > MAX_DIRECT_ADDRS {
            return Err(EndpointError::TooManyDirectAddrs);
        }
        let mut total = 1usize + 2 + self.relay_url.len() + 1;
        for &addr in &self.direct_addrs {
            if addr.port() == 0 {
                return Err(EndpointError::InvalidPort);
            }
            if is_always_disallowed_addr(addr) {
                return Err(EndpointError::DisallowedDirectAddr);
            }
            total = total.saturating_add(addr.encoded_len());
        }
        if total > MAX_ENDPOINT_DESCRIPTOR_BYTES {
            return Err(EndpointError::TooLarge);
        }
        Ok(())
    }

    /// Enforces immutable party-level `relay_policy` & pinned `party_relay_url`.
    pub fn validate_against_policy(
        &self,
        policy: RelayPolicy,
        pinned_relay_url: &str,
    ) -> Result<(), EndpointError> {
        self.validate()?;
        validate_pinned_relay_url(policy, pinned_relay_url)?;
        match policy {
            RelayPolicy::ForceRelays => {
                if self.transport_kind != TransportKind::IrohQuic {
                    return Err(EndpointError::ForceRelaysViolation);
                }
                if !self.direct_addrs.is_empty() {
                    return Err(EndpointError::ForceRelaysViolation);
                }
                if self.relay_url != pinned_relay_url {
                    return Err(EndpointError::ForceRelaysViolation);
                }
            }
            RelayPolicy::NoRelays => {
                if !self.relay_url.is_empty() {
                    return Err(EndpointError::NoRelaysViolation);
                }
            }
            RelayPolicy::AllowRelays => {
                // Prevent remote peers from injecting RFC 1918 / link-local LAN addresses for UDP probing!
                // (LAN / Tailscale private addresses are permitted under NoRelays.)
                if self.direct_addrs.iter().any(|&a| is_private_or_lan_addr(a)) {
                    return Err(EndpointError::DisallowedDirectAddr);
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, EndpointError> {
        self.validate()?;
        let relay_bytes = self.relay_url.as_bytes();
        let relay_len = u16::try_from(relay_bytes.len()).map_err(|_| EndpointError::TooLarge)?;
        let direct_count =
            u8::try_from(self.direct_addrs.len()).map_err(|_| EndpointError::TooManyDirectAddrs)?;

        let mut out = Vec::with_capacity(MAX_ENDPOINT_DESCRIPTOR_BYTES);
        out.push(self.transport_kind as u8);
        out.extend_from_slice(&relay_len.to_le_bytes());
        out.extend_from_slice(relay_bytes);
        out.push(direct_count);
        for addr in &self.direct_addrs {
            match addr {
                DirectAddr::V4 { ip, port } => {
                    out.push(4);
                    out.extend_from_slice(ip);
                    out.extend_from_slice(&port.to_le_bytes());
                }
                DirectAddr::V6 { ip, port } => {
                    out.push(6);
                    out.extend_from_slice(ip);
                    out.extend_from_slice(&port.to_le_bytes());
                }
            }
        }
        if out.len() > MAX_ENDPOINT_DESCRIPTOR_BYTES {
            return Err(EndpointError::TooLarge);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EndpointError> {
        if bytes.len() > MAX_ENDPOINT_DESCRIPTOR_BYTES {
            return Err(EndpointError::TooLarge);
        }
        let kind_b = *bytes.first().ok_or(EndpointError::Truncated)?;
        let transport_kind = TransportKind::from_u8(kind_b)?;
        let len_slice = bytes.get(1..3).ok_or(EndpointError::Truncated)?;
        let len_arr: [u8; 2] = len_slice.try_into().map_err(|_| EndpointError::Truncated)?;
        let relay_len = usize::from(u16::from_le_bytes(len_arr));
        if relay_len > MAX_RELAY_URL_BYTES {
            return Err(EndpointError::InvalidRelayUrl);
        }
        let relay_end = 3usize.checked_add(relay_len).ok_or(EndpointError::Truncated)?;
        let relay_slice = bytes.get(3..relay_end).ok_or(EndpointError::Truncated)?;
        let relay_url =
            std::str::from_utf8(relay_slice).map_err(|_| EndpointError::InvalidRelayUrl)?.to_owned();
        validate_relay_url(&relay_url)?;

        let direct_count = usize::from(*bytes.get(relay_end).ok_or(EndpointError::Truncated)?);
        if direct_count > MAX_DIRECT_ADDRS {
            return Err(EndpointError::TooManyDirectAddrs);
        }
        let mut cursor = relay_end + 1;
        let mut direct_addrs = Vec::with_capacity(direct_count);
        for _ in 0..direct_count {
            let fam = *bytes.get(cursor).ok_or(EndpointError::Truncated)?;
            cursor += 1;
            match fam {
                4 => {
                    let ip_slice = bytes.get(cursor..cursor + 4).ok_or(EndpointError::Truncated)?;
                    let ip: [u8; 4] = ip_slice.try_into().map_err(|_| EndpointError::Truncated)?;
                    cursor += 4;
                    let port_slice = bytes.get(cursor..cursor + 2).ok_or(EndpointError::Truncated)?;
                    let port = u16::from_le_bytes(
                        port_slice.try_into().map_err(|_| EndpointError::Truncated)?,
                    );
                    cursor += 2;
                    if port == 0 {
                        return Err(EndpointError::InvalidPort);
                    }
                    direct_addrs.push(DirectAddr::V4 { ip, port });
                }
                6 => {
                    let ip_slice = bytes.get(cursor..cursor + 16).ok_or(EndpointError::Truncated)?;
                    let ip: [u8; 16] = ip_slice.try_into().map_err(|_| EndpointError::Truncated)?;
                    cursor += 16;
                    let port_slice = bytes.get(cursor..cursor + 2).ok_or(EndpointError::Truncated)?;
                    let port = u16::from_le_bytes(
                        port_slice.try_into().map_err(|_| EndpointError::Truncated)?,
                    );
                    cursor += 2;
                    if port == 0 {
                        return Err(EndpointError::InvalidPort);
                    }
                    direct_addrs.push(DirectAddr::V6 { ip, port });
                }
                _ => return Err(EndpointError::InvalidAddrFamily),
            }
        }
        if cursor != bytes.len() {
            return Err(EndpointError::TrailingBytes);
        }
        let ep = Self {
            transport_kind,
            relay_url,
            direct_addrs,
        };
        ep.validate()?;
        Ok(ep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_url_hardening_rejects_ssrf_punycode_and_privileged_ports() {
        // Valid public origins (default port omitted or unprivileged >= 1024)
        assert!(validate_relay_url("").is_ok());
        assert!(validate_relay_url("https://relay.multiplayer.tech").is_ok());
        assert!(validate_relay_url("https://relay-weur.multiplayer.tech").is_ok());
        assert!(validate_relay_url("https://relay.corp-team.com:8443").is_ok());
        assert!(validate_relay_url("https://relay.corp-team.com:1024").is_ok());

        // Corporate relay rejects empty & *.multiplayer.tech, accepts real customer domain
        assert!(validate_corporate_relay_url("https://relay.acme-eng.com").is_ok());
        assert!(validate_corporate_relay_url("https://relay.acme-eng.com:8443").is_ok());
        assert!(validate_corporate_relay_url("").is_err());
        assert!(validate_corporate_relay_url("https://multiplayer.tech").is_err());
        assert!(validate_corporate_relay_url("https://relay.multiplayer.tech").is_err());
        assert!(validate_corporate_relay_url("https://relay-wnam.multiplayer.tech").is_err());

        // Reject SSRF, private/rebinding suffixes, punycode on any label, bad TLDs, privileged ports
        for bad in [
            "http://relay.acme-eng.com",
            "https://localhost",
            "https://sub.localhost",
            "https://relay.local",
            "https://relay.internal",
            "https://1.0.0.127.in-addr.arpa",
            "https://relay.localdomain",
            "https://relay.lan",
            "https://relay.home",
            "https://relay.corp",
            "https://relay.intranet",
            "https://relay.private",
            "https://relay.invalid",
            "https://relay.test",
            "https://relay.example",
            "https://hidden.onion",
            "https://relay.alt",
            "https://127.0.0.1.nip.io",
            "https://10-0-0-1.sslip.io",
            "https://127.0.0.1.xip.io",
            "https://a.localtest.me",
            "https://a.lvh.me",
            "https://127.0.0.1",
            "https://169.254.169.254",
            "https://0x7f.1",
            "https://xn--bcher-kva.com",
            "https://relay.xn--p1ai",
            "https://relay.c",
            "https://relay.c0m",
            "https://relay.acme-eng.com:443",
            "https://relay.acme-eng.com:80",
            "https://relay.acme-eng.com:22",
            "https://relay.acme-eng.com:1023",
            "https://relay.acme-eng.com:0",
            "https://relay.acme-eng.com/path",
            "https://user@relay.acme-eng.com",
        ] {
            assert!(
                validate_relay_url(bad).is_err(),
                "validate_relay_url must reject {bad}"
            );
            assert!(
                validate_corporate_relay_url(bad).is_err(),
                "validate_corporate_relay_url must reject {bad}"
            );
        }
    }
}
