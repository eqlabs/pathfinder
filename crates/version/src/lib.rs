//! Version information for Pathfinder

/// Version string from git or environment
pub const VERSION: &str = env!("VERGEN_GIT_DESCRIBE");

/// User agent string used in HTTP clients
pub const USER_AGENT: &str = concat!("starknet-pathfinder/", env!("VERGEN_GIT_DESCRIBE"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::const_is_empty)]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn user_agent_contains_version() {
        assert!(USER_AGENT.contains(VERSION));
    }
}
