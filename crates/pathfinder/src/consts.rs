//! Repeated constants used around pathfinder

/// User agent used in http clients
pub const USER_AGENT: &str = concat!(
    "starknet-pathfinder/",
    env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT")
);
