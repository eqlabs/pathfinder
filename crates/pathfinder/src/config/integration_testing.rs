#[cfg(not(all(feature = "p2p", feature = "integration-testing", debug_assertions)))]
pub use disabled::*;
#[cfg(all(feature = "p2p", feature = "integration-testing", debug_assertions))]
pub use enabled::*;

#[cfg(all(feature = "p2p", feature = "integration-testing", debug_assertions))]
mod enabled {
    use clap::builder::RangedU64ValueParser;

    #[derive(clap::Args)]
    pub struct IntegrationTestingCli {
        #[arg(
            long = "integration-testing.inject-failure.on-proposal-rx",
            action = clap::ArgAction::Set,
            value_parser = up_to_10_height_parser(),
        )]
        inject_failure_on_proposal_rx: Option<u64>,
        #[arg(
            long = "integration-testing.inject-failure.on-proposal-decided",
            action = clap::ArgAction::Set,
            value_parser = up_to_10_height_parser(),
        )]
        inject_failure_on_proposal_decided: Option<u64>,
    }

    fn up_to_10_height_parser() -> RangedU64ValueParser {
        (0..=10).into()
    }

    #[derive(Clone)]
    pub struct IntegrationTestingConfig {
        _inject_failure_on_proposal_rx: Option<u64>,
        _inject_failure_on_proposal_decided: Option<u64>,
    }

    impl IntegrationTestingConfig {
        pub fn parse(cli: IntegrationTestingCli) -> Self {
            Self {
                _inject_failure_on_proposal_rx: cli.inject_failure_on_proposal_rx,
                _inject_failure_on_proposal_decided: cli.inject_failure_on_proposal_decided,
            }
        }
    }
}

#[cfg(not(all(feature = "p2p", feature = "integration-testing", debug_assertions)))]
mod disabled {
    #[derive(Default)]
    pub struct IntegrationTestingCli;

    #[derive(Clone)]
    pub struct IntegrationTestingConfig;

    impl IntegrationTestingConfig {
        pub fn parse(_: IntegrationTestingCli) -> Self {
            Self
        }
    }
}
