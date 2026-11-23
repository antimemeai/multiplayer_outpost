#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

pub mod crc32c;
pub mod fence;
pub mod ipc_wire;
pub mod lan_protocol;
pub mod p2p_wire;
pub mod party_state;
pub mod storage_codec;
pub mod trust;
