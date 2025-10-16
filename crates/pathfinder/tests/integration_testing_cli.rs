use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::Context as _;
use rstest::rstest;

/// Values passed with these CLI arguments will not cause errors in a debug
/// build built with features `p2p` and `integration-testing` enabled.
#[rstest]
#[case::inject_failure_on_proposal_rx("--integration-testing.inject-failure.on-proposal-rx", "=1")]
#[case::inject_failure_on_proposal_decided(
    "--integration-testing.inject-failure.on-proposal-decided",
    "=1"
)]
#[test]
fn pathfinder_release_doesnt_have_integration_testing_cli(
    #[case] cli_arg_name: &str,
    #[case] cli_arg_val: &str,
) -> anyhow::Result<()> {
    let mut command = Command::new(pathfinder_release_bin());
    let command = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("RUST_LOG", "pathfinder_lib=trace,pathfinder=trace")
        .args([
            "--ethereum.url=https://ethereum-sepolia-rpc.publicnode.com",
            format!("{cli_arg_name}{cli_arg_val}").as_str(),
        ]);
    let process = command.spawn().context("Spawning Pathfinder process")?;
    let output = process
        .wait_with_output()
        .context("Waiting for Pathfinder process to exit")?;
    let std_err = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        std_err.starts_with(format!("error: unexpected argument '{cli_arg_name}' found").as_str()),
        "Got:\n[STDERR_BEGIN]\n{}[STDERR_END]",
        std_err
    );

    Ok(())
}

pub fn pathfinder_release_bin() -> PathBuf {
    let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    assert!(path.pop());
    assert!(path.pop());
    path.push("target");
    path.push("release");
    path.push("pathfinder");
    path
}
