//! Repeated constants used around pathfinder

use stark_hash::StarkHash;

use crate::core::StarknetBlockHash;

/// User agent used in http clients
pub const USER_AGENT: &str = concat!(
    "starknet-pathfinder/",
    env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT")
);

lazy_static::lazy_static!(
    pub static ref GOERLI_GENESIS_HASH: StarknetBlockHash = StarknetBlockHash(
        StarkHash::from_hex_str(
            "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b",
        )
        .unwrap(),
    );

    pub static ref MAINNET_GENESIS_HASH: StarknetBlockHash = StarknetBlockHash(
        StarkHash::from_hex_str(
            "0x047C3637B57C2B079B93C61539950C17E868A28F46CDEF28F88521067F21E943",
        )
        .unwrap(),
    );
);
