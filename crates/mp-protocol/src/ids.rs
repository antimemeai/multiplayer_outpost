//! Strongly typed 53-bit safe positive integer primary keys.
//! Per BLACKBIRD.md Core Tenet #6: primary keys are NEVER strings.

use core::fmt;

/// Maximum lossless integer across Rust `u64`, C++23 `uint64_t`, SQLite `INTEGER`,
/// Cloudflare D1, and JS IEEE-754 `Number` (`Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_ID: u64 = (1u64 << 53) - 1;

/// Maximum 52-bit non-sequential random global identifier.
pub const MAX_RANDOM_GLOBAL_ID: u64 = (1u64 << 52) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    Zero,
    ExceedsSafeInt(u64),
    InvalidDecimal,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => write!(f, "identifier must be >= 1"),
            Self::ExceedsSafeInt(v) => write!(f, "identifier {v} exceeds MAX_SAFE_ID ({MAX_SAFE_ID})"),
            Self::InvalidDecimal => write!(f, "invalid decimal integer identifier"),
        }
    }
}

impl std::error::Error for IdError {}

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(raw: u64) -> Result<Self, IdError> {
                if raw == 0 {
                    return Err(IdError::Zero);
                }
                if raw > MAX_SAFE_ID {
                    return Err(IdError::ExceedsSafeInt(raw));
                }
                Ok(Self(raw))
            }

            pub const fn get(self) -> u64 {
                self.0
            }

            pub fn parse_decimal(s: &str) -> Result<Self, IdError> {
                if s.is_empty() || s.len() > 16 || s.starts_with('0') {
                    return Err(IdError::InvalidDecimal);
                }
                if !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(IdError::InvalidDecimal);
                }
                let raw = s.parse::<u64>().map_err(|_| IdError::InvalidDecimal)?;
                Self::new(raw)
            }

            pub const fn to_le_bytes(self) -> [u8; 8] {
                self.0.to_le_bytes()
            }

            pub const fn from_le_bytes(bytes: [u8; 8]) -> Result<Self, IdError> {
                Self::new(u64::from_le_bytes(bytes))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_id!(AccountId);
define_id!(DeviceId);
define_id!(PartyId);
define_id!(InviteId);
define_id!(PartyInviteId);
define_id!(SessionId);
define_id!(RequestId);
