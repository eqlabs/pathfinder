use std::path::Path;

/// ## Important
/// This function does nothing in production builds.
///
/// ## Integration testing
/// Creates a marker file in the data directory indicating that a specific port
/// has been assigned. This function is only active in debug builds. The file is
/// named `{pid}_{name}_port_{value}`.
///
/// ## Panics
/// The function will panic if it fails to create the marker file.
pub fn debug_create_port_marker_file(_name: &str, _value: u16, _data_directory: &Path) {
    #[cfg(debug_assertions)]
    {
        let marker_file =
            _data_directory.join(format!("pid_{}_{}_port", std::process::id(), _name));
        std::fs::write(&marker_file, _value.to_string())
            .unwrap_or_else(|_| panic!("Failed to create marker file {}", marker_file.display()));
    }
}
