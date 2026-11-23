//! Deterministic compile-time build identity helpers.

pub const BUILD_DIGEST_HEX: &str = env!("OUTPOST_BUILD_DIGEST_HEX");
pub const BUILD_ORDER_STR: &str = env!("OUTPOST_BUILD_ORDER");
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Contiguous build-identity stamp embedded into the compiled binary so
/// `on_disk_exe_matches_local()` can verify the on-disk executable matches
/// the running binary's exact build digest and build order.
#[used]
static BUILD_STAMP_EMBED: &[u8] = concat!(
    "MPO_BUILD_STAMP_V1:",
    env!("OUTPOST_BUILD_DIGEST_HEX"),
    ":",
    env!("OUTPOST_BUILD_ORDER"),
    "\0"
)
.as_bytes();

const MAX_ON_DISK_EXE_BYTES: u64 = 256 * 1024 * 1024;

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

/// Constructs the expected embedded build stamp dynamically from compile-time constants.
pub fn expected_build_stamp() -> Vec<u8> {
    format!("MPO_BUILD_STAMP_V1:{BUILD_DIGEST_HEX}:{BUILD_ORDER_STR}\0").into_bytes()
}

/// Checks whether raw executable bytes contain the exact contiguous `expected_stamp`.
pub fn binary_matches_stamp(bytes: &[u8], expected_stamp: &[u8]) -> bool {
    if expected_stamp.is_empty() || bytes.len() < expected_stamp.len() {
        return false;
    }
    bytes
        .windows(expected_stamp.len())
        .any(|win| win == expected_stamp)
}

/// Checks whether the on-disk binary at `current_exe()` is a regular file containing
/// this exact build's embedded `MPO_BUILD_STAMP_V1:<digest>:<order>\0` stamp.
pub fn on_disk_exe_matches_local() -> bool {
    // Keep `BUILD_STAMP_EMBED` live under aggressive linker dead-stripping.
    let _ = std::hint::black_box(BUILD_STAMP_EMBED);
    let Ok(path) = std::env::current_exe() else {
        return false;
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return false;
    };
    if !meta.is_file() || meta.len() > MAX_ON_DISK_EXE_BYTES {
        return false;
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    let expected = expected_build_stamp();
    binary_matches_stamp(&bytes, &expected)
}

#[cfg(test)]
mod tests {
    use super::{
        BUILD_DIGEST_HEX, BUILD_ORDER_STR, binary_matches_stamp, expected_build_stamp,
        on_disk_exe_matches_local,
    };

    #[test]
    fn binary_stamp_matches_and_detects_tampering() {
        let stamp = expected_build_stamp();
        let mut fake_bin = b"\x7fELF...padding...".to_vec();
        fake_bin.extend_from_slice(&stamp);
        fake_bin.extend_from_slice(b"...tail...");
        assert!(binary_matches_stamp(&fake_bin, &stamp));

        // Tamper a single byte inside the embedded stamp.
        let mut tampered = fake_bin.clone();
        if let Some(pos) = tampered.windows(stamp.len()).position(|w| w == stamp.as_slice())
            && let Some(b) = tampered.get_mut(pos + 25)
        {
            *b ^= 0x01;
        }
        assert!(!binary_matches_stamp(&tampered, &stamp));

        // Different build order must fail.
        let other_order =
            format!("MPO_BUILD_STAMP_V1:{BUILD_DIGEST_HEX}:999999999\0").into_bytes();
        assert!(!binary_matches_stamp(&fake_bin, &other_order));

        // Empty inputs fail closed.
        assert!(!binary_matches_stamp(&[], &stamp));
        assert!(!binary_matches_stamp(&fake_bin, &[]));
        let _ = BUILD_ORDER_STR;
    }

    #[test]
    fn running_test_exe_matches_its_own_embedded_stamp() {
        assert!(on_disk_exe_matches_local());
    }
}
