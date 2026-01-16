use std::str::FromStr;

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

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum InjectFailureTrigger {
    ProposalInitRx,
    ProposalFinRx,
    BlockInfoRx,
    TransactionBatchRx,
    ExecutedTransactionCountRx,
    EntireProposalPersisted,
    PrevoteRx,
    PrecommitRx,
    ProposalDecided,
    ProposalCommitted,
    OutdatedVote,
}

impl InjectFailureTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            InjectFailureTrigger::ProposalInitRx => "proposal_init_rx",
            InjectFailureTrigger::ProposalFinRx => "proposal_fin_rx",
            InjectFailureTrigger::BlockInfoRx => "block_info_rx",
            InjectFailureTrigger::TransactionBatchRx => "txn_batch_rx",
            InjectFailureTrigger::ExecutedTransactionCountRx => "executed_txn_count_rx",
            InjectFailureTrigger::EntireProposalPersisted => "entire_proposal_persisted",
            InjectFailureTrigger::PrevoteRx => "prevote_rx",
            InjectFailureTrigger::PrecommitRx => "precommit_rx",
            InjectFailureTrigger::ProposalDecided => "proposal_decided",
            InjectFailureTrigger::ProposalCommitted => "proposal_committed",
            InjectFailureTrigger::OutdatedVote => "outdated_vote",
        }
    }
}

impl FromStr for InjectFailureTrigger {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "proposal_init_rx" => Ok(InjectFailureTrigger::ProposalInitRx),
            "proposal_fin_rx" => Ok(InjectFailureTrigger::ProposalFinRx),
            "block_info_rx" => Ok(InjectFailureTrigger::BlockInfoRx),
            "txn_batch_rx" => Ok(InjectFailureTrigger::TransactionBatchRx),
            "executed_txn_count_rx" => Ok(InjectFailureTrigger::ExecutedTransactionCountRx),
            "entire_proposal_persisted" => Ok(InjectFailureTrigger::EntireProposalPersisted),
            "prevote_rx" => Ok(InjectFailureTrigger::PrevoteRx),
            "precommit_rx" => Ok(InjectFailureTrigger::PrecommitRx),
            "proposal_decided" => Ok(InjectFailureTrigger::ProposalDecided),
            "proposal_committed" => Ok(InjectFailureTrigger::ProposalCommitted),
            "outdated_vote" => Ok(InjectFailureTrigger::OutdatedVote),
            _ => Err(format!("Unknown inject failure event: {s}")),
        }
    }
}

#[cfg(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
))]
mod enabled {
    #[derive(clap::Args)]
    pub struct IntegrationTestingCli {
        #[arg(
            long = "integration-tests.disable-db-verification",
            action = clap::ArgAction::Set,
            default_value = "false"
        )]
        disable_db_verification: bool,

        #[arg(
            long = "integration-tests.inject-failure",
            action = clap::ArgAction::Set,
            value_parser = parse_inject_failure,
        )]
        inject_failure: Option<InjectFailureConfig>,
    }

    #[derive(Copy, Clone)]
    pub struct InjectFailureConfig {
        pub height: u64,
        pub trigger: super::InjectFailureTrigger,
    }

    fn parse_inject_failure(s: &str) -> Result<InjectFailureConfig, String> {
        let mut items = s.split(',');
        let height: u64 = items
            .next()
            .ok_or_else(|| "Expected block height".to_string())?
            .parse()
            .map_err(|_| "Expected a number (u64)".to_string())?;
        if height > 15 {
            return Err("Expected range (0..=15)".to_string());
        }
        let trigger = items
            .next()
            .ok_or_else(|| "Expected inject failure trigger".to_string())?
            .parse()
            .map_err(|e| format!("Expected inject failure trigger: {e}"))?;

        Ok(InjectFailureConfig { height, trigger })
    }

    #[derive(Copy, Clone)]
    pub struct IntegrationTestingConfig {
        disable_db_verification: bool,
        inject_failure: Option<InjectFailureConfig>,
    }

    impl IntegrationTestingConfig {
        pub fn parse(cli: IntegrationTestingCli) -> Self {
            Self {
                disable_db_verification: cli.disable_db_verification,
                inject_failure: cli.inject_failure,
            }
        }

        pub fn is_db_verification_disabled(&self) -> bool {
            self.disable_db_verification
        }

        pub fn inject_failure_config(&self) -> Option<InjectFailureConfig> {
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

    #[derive(Copy, Clone)]
    pub struct InjectFailureConfig {
        pub height: u64,
        pub trigger: super::InjectFailureTrigger,
    }

    impl IntegrationTestingConfig {
        pub fn parse(_: IntegrationTestingCli) -> Self {
            Self
        }

        pub fn is_db_verification_disabled(&self) -> bool {
            false
        }

        pub fn inject_failure_config(&self) -> Option<InjectFailureConfig> {
            None
        }
    }
}
