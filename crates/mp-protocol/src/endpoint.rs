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

/// Validates an optional HTTPS relay URL origin (`https://<fqdn>[:port]`, <= 100 bytes).
/// Strictly rejects:
/// - non-HTTPS schemes, paths, queries, fragments, userinfo, uppercase
/// - single-label hosts (`localhost`), IPv4 literals (`127.0.0.1`), integer/hex hosts (`2130706433`, `0x7f.1`)
/// - DNS labels > 63 bytes or starting/ending with `-`
/// - explicit default `:443` (canonical origin equality) or invalid ports
pub fn validate_relay_url(url: &str) -> Result<(), EndpointError> {
    if url.is_empty() {
        return Ok(());
    }
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

    // Require a valid multi-label FQDN (rejects localhost, numeric/IPv4/hex hosts, bad DNS labels).
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
        {
            return Err(EndpointError::InvalidRelayUrl);
        }
    }
    // TLD must contain at least one ASCII letter (rejects numeric/IPv4-like hosts).
    let tld = labels.last().copied().unwrap_or("");
    if !tld.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err(EndpointError::InvalidRelayUrl);
    }

    if let Some(p) = port_opt {
        if p.is_empty() || p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EndpointError::InvalidRelayUrl);
        }
        let port: u16 = p.parse().map_err(|_| EndpointError::InvalidRelayUrl)?;
        if port == 0 || port == 443 {
            return Err(EndpointError::InvalidRelayUrl);
        }
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
