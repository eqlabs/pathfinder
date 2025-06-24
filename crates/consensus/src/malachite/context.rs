use malachite_signing_ed25519::Ed25519;
use malachite_types::{NilOrVal, Round, ValidatorSet as MalachiteValidatorSet, ValueId, VoteType};

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
pub struct MalachiteContext;

impl malachite_types::Context for MalachiteContext {
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
        let index = (round % num_validators) as usize;
        let proposer = validator_set
            .get_by_index(index)
            .expect("validator not found");

        tracing::debug!(
            proposer = ?proposer,
            height = ?height,
            round = ?round,
            "Selected proposer for round"
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
        tracing::debug!(
            validator = %address,
            value = ?value,
            height = %height,
            round = %round,
            pol_round = %pol_round,
            "Creating new proposal"
        );
        Proposal {
            height,
            round: round.into(),
            value_id: value,
            proposer: address,
            pol_round: pol_round.into(),
        }
    }

    fn new_prevote(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        tracing::debug!(
            validator = %address,
            value = ?value_id,
            height = %height,
            round = %round,
            "Creating new prevote"
        );
        Vote {
            r#type: VoteType::Prevote,
            height,
            round: round.into(),
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
        tracing::debug!(
            validator = %address,
            value = ?value_id,
            height = %height,
            round = %round,
            "Creating new precommit"
        );
        Vote {
            r#type: VoteType::Precommit,
            height,
            round: round.into(),
            validator_address: address,
            value: value_id,
            extension: None,
        }
    }
}
