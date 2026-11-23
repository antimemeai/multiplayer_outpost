//! Shared TLS 1.3-only, HTTP/1.1-ALPN-only transport connector.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::http::ControlError;

/// Default canonical `multiplayer.tech` control-plane origin authority.
pub const DEFAULT_API_AUTHORITY: &str = "api.multiplayer.tech";

/// Builds the default production `rustls::ClientConfig`:
/// - Strictly TLS 1.3 only (`&[&rustls::version::TLS13]`)
/// - `webpki-roots` trust anchors
/// - HTTP/1.1 ALPN only (`["http/1.1"]`)
/// - Zero 0-RTT early data (`enable_early_data = false`)
pub fn default_tls13_client_config() -> Result<Arc<rustls::ClientConfig>, ControlError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    build_tls13_client_config_with_roots(roots)
}

/// Builds a strictly TLS 1.3-only, HTTP/1.1-ALPN-only, zero-early-data `rustls::ClientConfig`
/// using the supplied `RootCertStore` (useful for tests with `rcgen` self-signed certs).
pub fn build_tls13_client_config_with_roots(
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, ControlError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ControlError::TlsConfig(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Parses, validates, and canonicalizes an HTTP authority (`host` or `host:port`),
/// returning `(canonical_authority, lowercase_host, port)`.
///
/// Canonicalization lowercases the ASCII hostname and strips the default `:443` port
/// (e.g. `API.MULTIPLAYER.TECH:443` -> `api.multiplayer.tech`).
/// Rejects userinfo, paths, queries, whitespace, non-ASCII bytes, leading-zero ports,
/// and invalid ports.
pub(crate) fn parse_authority(authority: &str) -> Result<(String, String, u16), ControlError> {
    if authority.is_empty()
        || authority.len() > 255
        || !authority.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.contains('\\')
    {
        return Err(ControlError::InvalidAuthority(authority.to_owned()));
    }

    let (host, port) = if let Some((host, port_str)) = authority.rsplit_once(':') {
        if host.is_empty()
            || host.contains(':')
            || port_str.is_empty()
            || port_str.starts_with('0')
            || !port_str.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(ControlError::InvalidAuthority(authority.to_owned()));
        }
        let port = port_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| ControlError::InvalidAuthority(authority.to_owned()))?;
        (host, port)
    } else {
        (authority, 443)
    };

    let host_lower = host.to_ascii_lowercase();
    let canonical = if port == 443 {
        host_lower.clone()
    } else {
        format!("{host_lower}:{port}")
    };
    Ok((canonical, host_lower, port))
}

/// Validates and returns the canonical authority string (lowercase host, default `:443` stripped).
pub(crate) fn canonicalize_authority(authority: &str) -> Result<String, ControlError> {
    let (canonical, _, _) = parse_authority(authority)?;
    Ok(canonical)
}

/// Establishes a TCP + TLS 1.3-only connection pinned to `authority` SNI.
///
/// When `connect_addr` is `Some(addr)`, TCP dials `addr` while TLS SNI remains pinned to
/// `authority`'s canonical lowercase hostname (allowing local TLS 1.3 mock-server testing
/// against `api.multiplayer.tech`).
pub(crate) async fn connect_tls13(
    authority: &str,
    connect_addr: Option<SocketAddr>,
    tls_config: &Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>, ControlError> {
    let (_, host, port) = parse_authority(authority)?;
    if tls_config.enable_early_data {
        return Err(ControlError::TlsConfig(
            "0-RTT early data must be disabled".to_owned(),
        ));
    }

    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| ControlError::InvalidAuthority(authority.to_owned()))?;

    let connector = TlsConnector::from(Arc::clone(tls_config));
    let tls = tokio::time::timeout(timeout, async {
        let tcp = match connect_addr {
            Some(addr) => TcpStream::connect(addr).await,
            None => TcpStream::connect((host.as_str(), port)).await,
        }?;
        let _ = tcp.set_nodelay(true);
        connector.connect(server_name, tcp).await
    })
    .await
    .map_err(|_| ControlError::Timeout)?
    .map_err(ControlError::Io)?;

    let (_, conn) = tls.get_ref();
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(ControlError::TlsPolicyViolation(
            "negotiated TLS version is not TLS 1.3".to_owned(),
        ));
    }
    if conn.alpn_protocol() != Some(b"http/1.1".as_slice()) {
        return Err(ControlError::TlsPolicyViolation(
            "negotiated ALPN is not http/1.1".to_owned(),
        ));
    }

    Ok(tls)
}
