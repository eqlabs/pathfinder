pub use malachite_types::VoteType;
use malachite_types::{Height as MalachiteHeight, NilOrVal, SignedExtension};
use p2p_proto::consensus as p2p_proto;

use super::{Height, MalachiteContext, Round, ValidatorAddress, ValueId};

/// A vote for a value in a round
///
/// This is not a wrapper around the `Vote` type from the `p2p_proto` crate
/// because we need to own that `NilOrVal` to satisfy the interface.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub r#type: VoteType,
    pub height: Height,
    pub round: Round,
    pub value: NilOrVal<ValueId>,
    pub validator_address: ValidatorAddress,
    pub extension: Option<SignedExtension<MalachiteContext>>,
}

impl From<p2p_proto::Vote> for Vote {
    fn from(vote: p2p_proto::Vote) -> Self {
        Self {
            r#type: match vote.vote_type {
                p2p_proto::VoteType::Prevote => VoteType::Prevote,
                p2p_proto::VoteType::Precommit => VoteType::Precommit,
            },
            height: Height::new(vote.height),
            round: Round::new(vote.round),
            value: match vote.block_hash {
                Some(v) => NilOrVal::Val(ValueId::from(v)),
                None => NilOrVal::Nil,
            },
            validator_address: ValidatorAddress::from(vote.voter),
            extension: None, // TODO: implement extension
        }
    }
}

impl From<Vote> for p2p_proto::Vote {
    fn from(vote: Vote) -> Self {
        p2p_proto::Vote {
            vote_type: match vote.r#type {
                VoteType::Prevote => p2p_proto::VoteType::Prevote,
                VoteType::Precommit => p2p_proto::VoteType::Precommit,
            },
            height: vote.height.as_u64(),
            round: vote.round.as_u32().expect("round is not nil"),
            block_hash: match &vote.value {
                NilOrVal::Val(value) => Some(value.clone().into_inner()),
                NilOrVal::Nil => None,
            },
            voter: vote.validator_address.into(),
            extension: vote.extension.map(|ext| ext.message.clone()),
        }
    }
}

impl malachite_types::Vote<MalachiteContext> for Vote {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &NilOrVal<ValueId> {
        &self.value
    }

    fn take_value(self) -> NilOrVal<ValueId> {
        self.value
    }

    fn vote_type(&self) -> VoteType {
        self.r#type
    }

    fn validator_address(&self) -> &ValidatorAddress {
        &self.validator_address
    }

    fn extension(&self) -> Option<&SignedExtension<MalachiteContext>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<SignedExtension<MalachiteContext>> {
        self.extension.take()
    }

    fn extend(self, extension: SignedExtension<MalachiteContext>) -> Self {
        Self {
            extension: Some(extension),
            ..self
        }
    }
}
