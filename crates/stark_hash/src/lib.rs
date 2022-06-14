#![deny(rust_2018_idioms)]

mod hash;
mod serde;

pub use hash::{stark_hash, HexParseError, OverflowError, StarkHash};
