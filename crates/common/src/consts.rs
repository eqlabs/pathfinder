//! Repeated constants used around pathfinder

use crate::macro_prelude::block_hash;
use crate::BlockHash;

/// Vergen string
pub const VERGEN_GIT_DESCRIBE: &str = env!("VERGEN_GIT_DESCRIBE");

/// User agent used in http clients
pub const USER_AGENT: &str = concat!("starknet-pathfinder/", env!("VERGEN_GIT_DESCRIBE"));

pub const MAINNET_GENESIS_HASH: BlockHash =
    block_hash!("047C3637B57C2B079B93C61539950C17E868A28F46CDEF28F88521067F21E943");

pub const SEPOLIA_TESTNET_GENESIS_HASH: BlockHash =
    block_hash!("5c627d4aeb51280058bed93c7889bce78114d63baad1be0f0aeb32496d5f19c");

pub const SEPOLIA_INTEGRATION_GENESIS_HASH: BlockHash =
    block_hash!("19f675d3fb226821493a6ab9a1955e384bba80f130de625621a418e9a7c0ca3");
