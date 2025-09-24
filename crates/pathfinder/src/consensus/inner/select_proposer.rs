use pathfinder_common::ContractAddress;
use pathfinder_consensus::{RoundRobinProposerSelector, Validator, ValidatorSet};

use crate::config::ConsensusConfig;

/// A proposer selector that can be either fixed or round-robin.
#[derive(Clone)]
pub enum ProposerSelector {
    Fixed(FixedProposerSelector),
    RoundRobin(RoundRobinProposerSelector),
}

impl pathfinder_consensus::ProposerSelector<ContractAddress> for ProposerSelector {
    fn select_proposer<'a>(
        &self,
        validator_set: &'a ValidatorSet<ContractAddress>,
        height: u64,
        round: u32,
    ) -> &'a Validator<ContractAddress> {
        match self {
            ProposerSelector::Fixed(selector) => {
                selector.select_proposer(validator_set, height, round)
            }
            ProposerSelector::RoundRobin(selector) => {
                selector.select_proposer(validator_set, height, round)
            }
        }
    }
}

/// Get the proposer selector based on the consensus config.
///
/// If a proposer address is provided, use a fixed proposer selector,
/// otherwise, use a round-robin proposer selector.
pub fn get_proposer_selector(config: &ConsensusConfig) -> ProposerSelector {
    match config.proposer_address {
        Some(proposer_address) => {
            ProposerSelector::Fixed(FixedProposerSelector::new(proposer_address))
        }
        None => ProposerSelector::RoundRobin(RoundRobinProposerSelector),
    }
}

/// A proposer selector that always selects the same proposer.
/// Note that the proposer must be in the validator set!
#[derive(Clone)]
pub struct FixedProposerSelector {
    proposer_address: ContractAddress,
}

impl FixedProposerSelector {
    pub fn new(proposer_address: ContractAddress) -> Self {
        Self { proposer_address }
    }
}

impl pathfinder_consensus::ProposerSelector<ContractAddress> for FixedProposerSelector {
    fn select_proposer<'a>(
        &self,
        validator_set: &'a ValidatorSet<ContractAddress>,
        _height: u64,
        _round: u32,
    ) -> &'a Validator<ContractAddress> {
        validator_set
            .validators
            .iter()
            .find(|v| v.address == self.proposer_address)
            .expect("Fixed proposer must be in validator set")
    }
}
