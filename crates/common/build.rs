//! Pathfinder build script.
//!
//! Just sets up `vergen` to query our git information for the build.

pub fn main() {
    let force_version_env_var_name = "PATHFINDER_FORCE_VERSION";

    println!("cargo:rerun-if-env-changed={force_version_env_var_name}");

    if let Ok(version) = std::env::var(force_version_env_var_name) {
        if !version.is_empty() {
            println!("cargo:rustc-env=VERGEN_GIT_SEMVER_LIGHTWEIGHT={version}");
            return;
        }
    }

    // at 7.0.0 default enables everything compiled in, selected with feature-flags
    let mut config = vergen::Config::default();
    *config.git_mut().semver_kind_mut() = vergen::SemverKind::Lightweight;
    *config.git_mut().semver_dirty_mut() = Some("-dirty");
    *config.git_mut().branch_mut() = false;
    *config.git_mut().commit_author_mut() = false;
    *config.git_mut().commit_count_mut() = false;
    *config.git_mut().commit_message_mut() = false;
    *config.git_mut().commit_timestamp_mut() = false;
    *config.git_mut().sha_mut() = false;
    vergen::vergen(config).expect("vergen failed; this is probably due to missing .git directory");
}
