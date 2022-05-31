//! Repeated constants used around pathfinder

pub fn version() -> String {
    option_env!("PATHFINDER_VERSION")
        .unwrap_or(env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT"))
        .to_string()
}

/// User agent used in http clients
pub fn user_agent() -> String {
    format!("starknet-pathfinder/{}", version())
}
