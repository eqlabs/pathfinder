//! Repeated constants used around pathfinder

/// User agent used in http clients
///
/// Resolves to "pathfinder/<version_info>"
pub const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT")
);
