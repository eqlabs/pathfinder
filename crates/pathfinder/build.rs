use std::{path::PathBuf, process::Command};

pub fn main() {
    set_casm_compiler_version();
}

#[derive(serde::Deserialize)]
struct CargoMetadata {
    pub packages: Vec<Package>,
}

#[derive(serde::Deserialize)]
struct Package {
    pub name: String,
    pub id: String,
}

fn set_casm_compiler_version() {
    let manifest_path = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR"))
            .unwrap(),
    )
    .join("Cargo.toml");

    let cargo_args = [
        "metadata",
        "--locked",
        "--format-version=1",
        "--manifest-path",
        manifest_path.to_str().unwrap(),
    ];
    let cargo_binary = std::env::var("CARGO").unwrap();
    let cargo_output = Command::new(cargo_binary)
        .args(cargo_args)
        .output()
        .unwrap();

    let metadata =
        serde_json::from_slice::<CargoMetadata>(&cargo_output.stdout).unwrap_or_else(|_| {
            panic!(
                "{}",
                std::str::from_utf8(&cargo_output.stderr)
                    .unwrap()
                    .to_string()
            )
        });

    let sierra_compiler_package = metadata
        .packages
        .iter()
        .find(|p| p.name == "cairo-lang-starknet")
        .expect("cairo-lang-starknet should be a dependency");

    // We use the `id` here because `version` might not be unique (for example when using the compiler
    // package from a Git repository).
    println!(
        "cargo:rustc-env=SIERRA_CASM_COMPILER_VERSION={}",
        sierra_compiler_package.id
    );
}
