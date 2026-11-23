//! Strict JSON parsing for MCP stdio frames:
//! - Rejects duplicate JSON object keys at any nesting depth (including Unicode-escaped aliases).
//! - Rejects embedded NUL (`\0`) bytes/characters in raw frames and decoded strings.
//! - Distinguishes malformed JSON syntax (`Syntax | Eof`, silently dropped to prevent error storms)
//!   from semantic/security violations (duplicate keys, embedded NUL, invalid request shape).

use core::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Classification of strict JSON line parse failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictJsonError {
    /// Malformed UTF-8 or malformed JSON syntax (`Syntax | Eof`) — silently drop to prevent echo storms.
    MalformedSyntax,
    /// Raw or decoded NUL byte detected.
    EmbeddedNul,
    /// Duplicate key detected in a JSON object.
    DuplicateKey,
    /// Excessive nesting or other data-layer rejection.
    InvalidData(String),
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSyntax => write!(f, "malformed JSON syntax"),
            Self::EmbeddedNul => write!(f, "embedded NUL byte is not allowed"),
            Self::DuplicateKey => write!(f, "duplicate JSON object key is not allowed"),
            Self::InvalidData(msg) => write!(f, "invalid JSON data: {msg}"),
        }
    }
}

impl std::error::Error for StrictJsonError {}

const DUPLICATE_KEY_MARKER: &str = "OUTPOST_DUP_KEY";
const EMBEDDED_NUL_MARKER: &str = "OUTPOST_EMBEDDED_NUL";

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor).map(Self)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a valid JSON value without duplicate object keys or NUL characters")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.contains('\0') {
            return Err(de::Error::custom(EMBEDDED_NUL_MARKER));
        }
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.contains('\0') {
            return Err(de::Error::custom(EMBEDDED_NUL_MARKER));
        }
        Ok(Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::new();
        while let Some(elem) = seq.next_element::<StrictValue>()? {
            out.push(elem.0);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.contains('\0') {
                return Err(de::Error::custom(EMBEDDED_NUL_MARKER));
            }
            if out.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            let val = map.next_value::<StrictValue>()?;
            out.insert(key, val.0);
        }
        Ok(Value::Object(out))
    }
}

/// Parses a single JSON-RPC line with strict hygiene:
/// - Rejects raw `0x00` bytes before parsing.
/// - Validates UTF-8 (invalid UTF-8 maps to `MalformedSyntax` so it is silently dropped).
/// - Rejects duplicate object keys and decoded `\u0000` NUL characters.
/// - Maps `serde_json` `Syntax | Eof` errors to `MalformedSyntax`.
pub fn parse_strict_json_line(raw: &[u8]) -> Result<Value, StrictJsonError> {
    if raw.contains(&0) {
        return Err(StrictJsonError::EmbeddedNul);
    }
    let text = core::str::from_utf8(raw).map_err(|_| StrictJsonError::MalformedSyntax)?;
    match serde_json::from_str::<StrictValue>(text) {
        Ok(StrictValue(v)) => Ok(v),
        Err(err) => {
            if err.is_syntax() || err.is_eof() {
                return Err(StrictJsonError::MalformedSyntax);
            }
            let msg = err.to_string();
            if msg.contains(DUPLICATE_KEY_MARKER) {
                Err(StrictJsonError::DuplicateKey)
            } else if msg.contains(EMBEDDED_NUL_MARKER) {
                Err(StrictJsonError::EmbeddedNul)
            } else {
                Err(StrictJsonError::InvalidData(msg))
            }
        }
    }
}
