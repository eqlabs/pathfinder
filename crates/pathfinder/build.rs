//! Pathfinder build script.
//!
//! Just sets up `vergen` to query our git information for the build.

fn main() {
    // our Dockerfile is set up to a dependency only run, to cache a layer with all of the
    // dependencies downloaded. during that "DEPENDENCY_LAYER" environment variable is set,
    // and we shouldn't ask vergen to setup anything on that run to avoid this adding additional
    // cache-miss reasons.

    if std::env::var_os("DEPENDENCY_LAYER").is_some() {
        return;
    }

    {
        // at 7.0.0 default enables everything compiled in, selected with feature-flags
        let mut config = vergen::Config::default();
        *config.git_mut().semver_kind_mut() = vergen::SemverKind::Lightweight;
        *config.git_mut().semver_dirty_mut() = Some("-dirty");
        vergen::vergen(config)
            .expect("vergen failed; this is probably due to missing .git directory");
    }
}
