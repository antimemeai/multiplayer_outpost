//! Deterministic compile-time build identity helpers.

pub const BUILD_DIGEST_HEX: &str = env!("OUTPOST_BUILD_DIGEST_HEX");
pub const BUILD_ORDER_STR: &str = env!("OUTPOST_BUILD_ORDER");
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn build_order() -> u64 {
    BUILD_ORDER_STR.parse::<u64>().unwrap_or(1)
}

pub fn build_digest() -> [u8; 32] {
    decode_hex_32(BUILD_DIGEST_HEX).unwrap_or([0u8; 32])
}

pub fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(*bytes.get(i * 2)?)?;
        let lo = hex_nibble(*bytes.get(i * 2 + 1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        if let (Some(&hi), Some(&lo)) = (
            HEX.get(usize::from(b >> 4)),
            HEX.get(usize::from(b & 0x0f)),
        ) {
            out.push(char::from(hi));
            out.push(char::from(lo));
        }
    }
    out
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Checks whether the on-disk binary at `current_exe()` still exists and is readable.
pub fn on_disk_exe_matches_local() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .is_some_and(|m| m.is_file())
}
