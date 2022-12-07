//! Pathfinder build script.
//!
//! Just sets up `vergen` to query our git information for the build.

pub fn main() {
    // at 7.0.0 default enables everything compiled in, selected with feature-flags
    let mut config = vergen::Config::default();
    *config.git_mut().semver_kind_mut() = vergen::SemverKind::Lightweight;
    *config.git_mut().semver_dirty_mut() = Some("-dirty");
    vergen::vergen(config).expect("vergen failed; this is probably due to missing .git directory");
}
