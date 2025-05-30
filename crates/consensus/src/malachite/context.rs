use malachite_signing_ed25519::Ed25519;
use malachite_types::{NilOrVal, Round, ValidatorSet as MalachiteValidatorSet, ValueId, VoteType};
use tracing::info;

use super::{
    ConsensusValue,
    Height,
    Proposal,
    ProposalPart,
    Validator,
    ValidatorAddress,
    ValidatorSet,
    Vote,
};

/// The malachite context for the consensus logic.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MyContext;

impl malachite_types::Context for MyContext {
    type Address = ValidatorAddress;
    type Height = Height;

    type ProposalPart = ProposalPart;
    type Proposal = Proposal;

    type Validator = Validator;
    type ValidatorSet = ValidatorSet;

    type Value = ConsensusValue;

    type Vote = Vote;

    type Extension = Vec<u8>;

    type SigningScheme = Ed25519;

    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        let round = round.as_u32().expect("round is not nil");
        let num_validators = validator_set.count() as u32;
        // Basic round robin proposer selection.
        let index = (round % num_validators) as usize;
        let proposer = validator_set
            .get_by_index(index)
            .expect("validator not found");
        info!(
            "✅ Selected proposer {:?} at height {:?} and round {:?}",
            proposer, height, round
        );
        proposer
    }

    fn new_proposal(
        &self,
        height: Self::Height,
        round: Round,
        value: Self::Value,
        pol_round: Round,
        address: Self::Address,
    ) -> Self::Proposal {
        info!(
            "📦 [{}] Proposing value {:?} at height {:?} and round {:?}",
            address, value, height, round
        );
        Proposal {
            height,
            round,
            value_id: value,
            proposer: address,
            pol_round,
        }
    }

    fn new_prevote(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        info!(
            "🗳️ [{}] Prevoting value {:?} at height {:?} and round {:?}",
            address, value_id, height, round
        );
        Vote {
            r#type: VoteType::Prevote,
            height,
            round,
            validator_address: address,
            value: value_id,
            extension: None,
        }
    }

    fn new_precommit(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        Vote {
            r#type: VoteType::Precommit,
            height,
            round,
            validator_address: address,
            value: value_id,
            extension: None,
        }
    }
}
