//! Integration testing helpers for the consensus task. These are only
//! active in debug builds when both the "p2p" and "consensus-integration-tests"
//! features are enabled.

use std::path::Path;

/// ## Important
/// This function does nothing in production builds.
///
/// ## Integration testing
/// Exits the process with error code of value `1` if the current height
/// matches. This function is only active in debug builds when both the
/// "p2p" and "consensus-integration-tests" features are enabled. A marker file
/// is created in the data directory to indicate that the failure has been
/// triggered. If the file already exists, it is removed instead. This allows
/// for easy detection of whether the failure has been triggered or not.
/// The file is named `fail_on_{prefix}_{height}`.
///
/// ## Panics
/// The function will panic if it fails to create the marker file or fails to
/// remove it when the file exists.
pub fn debug_fail_on(
    _current_height: u64,
    _config: Option<crate::config::integration_testing::FailureInjection>,
    _data_directory: &Path,
) {
    #[cfg(all(
        feature = "p2p",
        feature = "consensus-integration-tests",
        debug_assertions
    ))]
    debug_fail_on_impl(_current_height, _config, _data_directory);
}

#[cfg(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
))]
fn debug_fail_on_impl(
    current_height: u64,
    config: Option<crate::config::integration_testing::FailureInjection>,
    data_directory: &Path,
) {
    let Some(config) = config else {
        return;
    };

    if current_height != config.height() {
        return;
    }

    let failure_height = config.height();
    let prefix = config.prefix();
    let marker_file = data_directory.join(format!("fail_on_{prefix}_{failure_height}"));

    if marker_file.exists() {
        std::fs::remove_file(&marker_file)
            .unwrap_or_else(|_| panic!("Failed to remove marker file {}", marker_file.display()));
        tracing::trace!(
            marker_file=%marker_file.display(),
            "💥 ❌ Integration testing: removed",
        );
    } else {
        std::fs::File::create(&marker_file)
            .unwrap_or_else(|_| panic!("Failed to create marker file {}", marker_file.display()));
        tracing::trace!(
            marker_file=%marker_file.display(),
            "💥 ✅ Integration testing: created",
        );
        tracing::info!(
            "💥 💥 Integration testing: exiting process with error code 1 at height \
             {failure_height} on {prefix}, as configured"
        );
        std::process::exit(1);
    }
}
