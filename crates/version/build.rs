//! Pathfinder build script.
//!
//! Just sets up `vergen` to query our git information for the build.

pub fn main() {
    let force_version_env_var_name = "PATHFINDER_FORCE_VERSION";

    println!("cargo:rerun-if-env-changed={force_version_env_var_name}");

    if let Ok(version) = std::env::var(force_version_env_var_name) {
        if !version.is_empty() {
            println!("cargo:rustc-env=VERGEN_GIT_DESCRIBE={version}");
            return;
        }
    }

    // at 7.0.0 default enables everything compiled in, selected with feature-flags
    const ENABLE_DIRTY: bool = true;
    const ENABLE_TAGS: bool = true;
    vergen::EmitBuilder::builder()
        .fail_on_error()
        .git_describe(ENABLE_DIRTY, ENABLE_TAGS, None)
        .emit()
        .expect("vergen failed; this is probably due to missing .git directory");
}
