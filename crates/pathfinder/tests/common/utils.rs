//! Test utilities for Pathfinder integration tests.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context as _;
use tempfile::Builder;

use crate::common::pathfinder_instance::{Config, PathfinderInstance};

/// This function does a few things at the beginning of an integration test:
/// - sets up dumping stdout and stderr logs of Pathfinder instances to the
///   test's stdout if the environment variable
///   `PATHFINDER_CONSENSUS_TEST_DUMP_CHILD_LOGS_ON_FAIL` is set,
/// - creates temporary directory for test artifacts,
/// - verifies that the Pathfinder binary and fixtures directory exist,
/// - starts an [`std::time::Instant`] to measure test setup duration,
/// - returns configuration for the number of nodes specified and the instant.
pub fn setup(num_instances: usize) -> anyhow::Result<(Vec<Config>, Instant)> {
    PathfinderInstance::enable_log_dump(
        std::env::var_os("PATHFINDER_CONSENSUS_TEST_DUMP_CHILD_LOGS_ON_FAIL").is_some(),
    );

    let stopwatch = Instant::now();

    let pathfinder_bin = pathfinder_bin();
    anyhow::ensure!(pathfinder_bin.exists(), "Pathfinder binary not found");
    let fixture_dir = fixture_dir();
    anyhow::ensure!(fixture_dir.exists(), "Fixture directory not found");
    let test_dir = Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .context("Creating temporary directory for test artifacts")?;
    println!(
        "Test artifacts will be stored in {}",
        test_dir.path().display()
    );

    Ok((
        Config::for_set(
            num_instances,
            &pathfinder_bin,
            &fixture_dir,
            test_dir.path(),
        ),
        stopwatch,
    ))
}

/// Logs how many seconds have elapsed since `stopwatch` was created.
pub fn log_elapsed(stopwatch: Instant) {
    println!(
        "Test setup completed after {} s",
        stopwatch.elapsed().as_secs()
    );
}

fn pathfinder_bin() -> PathBuf {
    let mut path = manifest_dir_path();
    assert!(path.pop());
    assert!(path.pop());
    path.push("target");
    #[cfg(debug_assertions)]
    {
        path.push("debug");
    }
    #[cfg(not(debug_assertions))]
    {
        path.push("release");
    }
    path.push("pathfinder");
    path
}

fn fixture_dir() -> PathBuf {
    let mut path = manifest_dir_path();
    path.push("tests");
    path.push("fixtures");
    path
}

fn manifest_dir_path() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
}
