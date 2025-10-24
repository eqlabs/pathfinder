#[cfg(not(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
)))]
pub use disabled::*;
#[cfg(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
))]
pub use enabled::*;

#[cfg(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
))]
mod enabled {
    use clap::builder::RangedU64ValueParser;

    #[derive(clap::Args)]
    pub struct IntegrationTestingCli {
        #[arg(
            long = "integration-tests.disable-db-verification",
            action = clap::ArgAction::Set,
            default_value = "false"
        )]
        disable_db_verification: bool,
        #[arg(
            long = "integration-tests.inject-failure.on-proposal-rx",
            action = clap::ArgAction::Set,
            value_parser = up_to_15_height_parser(),
        )]
        inject_failure_on_proposal_rx: Option<u64>,
        #[arg(
            long = "integration-tests.inject-failure.on-proposal-decided",
            action = clap::ArgAction::Set,
            value_parser = up_to_15_height_parser(),
        )]
        inject_failure_on_proposal_decided: Option<u64>,
    }

    fn up_to_15_height_parser() -> RangedU64ValueParser {
        (0..=15).into()
    }

    #[derive(Copy, Clone)]
    pub struct IntegrationTestingConfig {
        disable_db_verification: bool,
        inject_failure: InjectFailureConfig,
    }

    #[derive(Copy, Clone)]
    pub struct InjectFailureConfig {
        pub on_proposal_rx: Option<FailureInjection>,
        pub on_proposal_decided: Option<FailureInjection>,
    }

    #[derive(Copy, Clone)]
    pub struct FailureInjection {
        height: u64,
        prefix: &'static str,
    }

    impl FailureInjection {
        fn new(height: u64, prefix: &'static str) -> Self {
            Self { height, prefix }
        }

        pub fn height(&self) -> u64 {
            self.height
        }

        pub fn prefix(&self) -> &'static str {
            self.prefix
        }
    }

    impl IntegrationTestingConfig {
        pub fn parse(cli: IntegrationTestingCli) -> Self {
            Self {
                disable_db_verification: cli.disable_db_verification,
                inject_failure: InjectFailureConfig {
                    on_proposal_rx: cli
                        .inject_failure_on_proposal_rx
                        .map(|h| FailureInjection::new(h, "proposal_rx")),
                    on_proposal_decided: cli
                        .inject_failure_on_proposal_decided
                        .map(|h| FailureInjection::new(h, "proposal_decided")),
                },
            }
        }

        pub fn is_db_verification_disabled(&self) -> bool {
            self.disable_db_verification
        }

        pub fn inject_failure_config(&self) -> InjectFailureConfig {
            self.inject_failure
        }
    }
}

#[cfg(not(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
)))]
mod disabled {
    #[derive(Default)]
    pub struct IntegrationTestingCli;

    #[derive(Copy, Clone)]
    pub struct IntegrationTestingConfig;

    #[derive(Copy, Clone, Default)]
    pub struct InjectFailureConfig {
        pub on_proposal_rx: Option<FailureInjection>,
        pub on_proposal_decided: Option<FailureInjection>,
    }

    #[derive(Copy, Clone)]
    pub struct FailureInjection;

    impl IntegrationTestingConfig {
        pub fn parse(_: IntegrationTestingCli) -> Self {
            Self
        }

        pub fn is_db_verification_disabled(&self) -> bool {
            false
        }

        pub fn inject_failure_config(&self) -> InjectFailureConfig {
            InjectFailureConfig::default()
        }
    }
}
