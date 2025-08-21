use std::path::PathBuf;
use std::process::{Command, Output};

#[tokio::test]
async fn consensus_3_node_smoke_test() {
    let mut pathfinder_binary_path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    eprintln!("CARGO_MANIFEST_DIR: {}", pathfinder_binary_path.display());
    assert!(pathfinder_binary_path.pop());
    assert!(pathfinder_binary_path.pop());
    pathfinder_binary_path.push("target");
    pathfinder_binary_path.push("debug");
    pathfinder_binary_path.push("pathfinder");
    eprintln!("CARGO_MANIFEST_DIR: {}", pathfinder_binary_path.display());

    let output = Command::new(pathfinder_binary_path)
        .args(["--help"])
        .output()
        .unwrap();
    let Output {
        status,
        stdout,
        stderr,
    } = output;

    eprintln!("status: {status:?}");

    eprintln!("stdout: {}--END--", String::from_utf8(stdout).unwrap());

    eprintln!("stderr: {}--END--", String::from_utf8(stderr).unwrap());
}
