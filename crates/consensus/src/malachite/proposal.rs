use serde::{Deserialize, Serialize};

use super::{ConsensusValue, Height, MalachiteContext, Round, ValidatorAddress};

/// A proposal for a block value in a consensus round.
///
/// A proposal is created by the designated proposer for a given height and
/// round. It contains the proposed block value along with additional metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub height: Height,
    pub round: Round,
    pub value: ConsensusValue,
    pub pol_round: Round,
    pub proposer: ValidatorAddress,
}

impl std::fmt::Debug for Proposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "H:{} R:{} From:{} Val:{:?}",
            self.height, self.round, self.proposer, self.value
        )
    }
}

impl malachite_types::Proposal<MalachiteContext> for Proposal {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> malachite_types::Round {
        self.round.into_inner()
    }

    fn value(&self) -> &ConsensusValue {
        &self.value
    }

    fn take_value(self) -> ConsensusValue {
        self.value
    }

    fn pol_round(&self) -> malachite_types::Round {
        self.pol_round.into_inner()
    }

    fn validator_address(&self) -> &ValidatorAddress {
        &self.proposer
    }
}
