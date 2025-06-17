use super::{ConsensusValue, Height, MalachiteContext, Round, ValidatorAddress};

/// A proposal for a value in a round
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub height: Height,
    pub round: Round,
    pub value_id: ConsensusValue,
    pub pol_round: Round,
    pub proposer: ValidatorAddress,
}

impl malachite_types::Proposal<MalachiteContext> for Proposal {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &ConsensusValue {
        &self.value_id
    }

    fn take_value(self) -> ConsensusValue {
        self.value_id
    }

    fn pol_round(&self) -> Round {
        self.pol_round
    }

    fn validator_address(&self) -> &ValidatorAddress {
        &self.proposer
    }
}
