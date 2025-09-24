use pathfinder_common::ContractAddress;
use pathfinder_consensus::{Validator, ValidatorSet};

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
