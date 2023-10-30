use crate::common::{Address, ConsensusSignature, Hash};
use crate::state::StateDiff;
use crate::transaction::Transactions;
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::{Dummy, Fake, Faker};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::consensus::Proposal")]
pub struct Proposal {
    block_number: u64,
    round: u32,
    pol: u32,
    block_header_hash: Hash,
    timestamp: SystemTime,
    signature: ConsensusSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::consensus::Vote")]
pub struct Vote {
    proposal: Proposal,
    validator_address: Address,
    validator_index: i32,
    signature: ConsensusSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum CreateBlock {
    Transactions(Transactions),
    StateDiff(StateDiff),
    Proposal(Proposal),
}

impl<T> Dummy<T> for Proposal {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Proposal {
            block_number: Faker.fake_with_rng(rng),
            round: Faker.fake_with_rng(rng),
            pol: Faker.fake_with_rng(rng),
            block_header_hash: Faker.fake_with_rng(rng),
            timestamp: SystemTime::now(),
            signature: Faker.fake_with_rng(rng),
        }
    }
}

impl ToProtobuf<proto::consensus::CreateBlock> for CreateBlock {
    fn to_protobuf(self) -> proto::consensus::CreateBlock {
        use proto::consensus::create_block::Messages::{Proposal, StateDiff, Transactions};
        proto::consensus::CreateBlock {
            messages: Some(match self {
                Self::Transactions(t) => Transactions(t.to_protobuf()),
                Self::StateDiff(s) => StateDiff(s.to_protobuf()),
                Self::Proposal(p) => Proposal(p.to_protobuf()),
            }),
        }
    }
}

impl TryFromProtobuf<proto::consensus::CreateBlock> for CreateBlock {
    fn try_from_protobuf(
        input: proto::consensus::CreateBlock,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::consensus::create_block::Messages::{Proposal, StateDiff, Transactions};
        let messages = input.messages.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: missing field `messages`", field_name),
            )
        })?;
        Ok(match messages {
            Transactions(t) => {
                Self::Transactions(TryFromProtobuf::try_from_protobuf(t, field_name)?)
            }
            StateDiff(s) => Self::StateDiff(TryFromProtobuf::try_from_protobuf(s, field_name)?),
            Proposal(p) => Self::Proposal(TryFromProtobuf::try_from_protobuf(p, field_name)?),
        })
    }
}
