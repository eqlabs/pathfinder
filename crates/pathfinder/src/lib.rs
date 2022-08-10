#![deny(rust_2018_idioms)]

pub mod cairo;
pub mod config;
pub mod consts;
pub mod core;
pub mod ethereum;
pub mod retry;
pub mod rpc;
pub mod sequencer;
pub mod state;
pub mod storage;
pub mod update;

/// Creates a [`stark_hash::StarkHash`] from an even hex string, resulting in compile-time error
/// when invalid.
macro_rules! starkhash {
    ($hex:expr) => {{
        let bytes = hex_literal::hex!($hex);
        match stark_hash::StarkHash::from_be_slice(bytes.as_slice()) {
            Ok(sh) => sh,
            Err(stark_hash::OverflowError) => panic!("Invalid constant: OverflowError"),
        }
    }};
}

/// Creates a [`stark_hash::StarkHash`] from a byte slice, resulting in compile-time error when
/// invalid.
#[cfg(test)]
macro_rules! starkhash_bytes {
    ($bytes:expr) => {{
        match stark_hash::StarkHash::from_be_slice($bytes) {
            Ok(sh) => sh,
            Err(stark_hash::OverflowError) => panic!("Invalid constant: OverflowError"),
        }
    }};
}

pub(crate) use starkhash;
#[cfg(test)]
pub(crate) use starkhash_bytes;
