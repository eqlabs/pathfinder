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

macro_rules! starkhash {
    ($hex:expr) => {{
        let bytes = hex_literal::hex!($hex);
        match stark_hash::StarkHash::from_be_slice(bytes.as_slice()) {
            Ok(sh) => sh,
            Err(stark_hash::OverflowError) => panic!("Invalid constant: OverflowError"),
        }
    }};
}

pub(crate) use starkhash;
