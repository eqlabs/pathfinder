use crate::common::{Address, Hash};

use crate::{ToProtobuf, TryFromProtobuf};
use crate::proto;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum VoteType {
    Prevote,
    #[default]
    Precommit,
}

impl ToProtobuf<proto::consensus::vote::VoteType> for VoteType {
    fn to_protobuf(self) -> proto::consensus::vote::VoteType {
        match self {
            Self::Prevote => proto::consensus::vote::VoteType::Prevote,
            Self::Precommit => proto::consensus::vote::VoteType::Precommit,
        }
    }
}

impl TryFromProtobuf<i32> for VoteType {
    fn try_from_protobuf(input: i32, _: &'static str) -> Result<Self, std::io::Error> {
        match input {
            0 => Ok(Self::Prevote),
            1 => Ok(Self::Precommit),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid vote type")),
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::consensus::Vote")]
pub struct Vote {
    pub vote_type: VoteType,
    pub block_number: u64,
    pub round: u32,
    pub proposal_commitment: Option<Hash>,
    pub voter: Address,
}


impl TryFromProtobuf<Option<proto::common::Hash>> for Option<Hash> {
    fn try_from_protobuf(input: Option<proto::common::Hash>, _: &'static str) -> Result<Self, std::io::Error> {
        match input {
            Some(hash) => Ok(Some(Hash::try_from_protobuf(hash, "proposal_commitment")?)),
            None => Ok(None),
        }
    }
}



/*

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum StreamMessageBody<T> {
    Content(T),
    Fin,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct StreamMessage<T: IntoFromProto, StreamId: IntoFromProto + Clone> {
    pub message: StreamMessageBody<T>,
    pub stream_id: StreamId,
    pub message_id: u64,
}

/// This message must be sent first when proposing a new block.
#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, TaggedDebug)]
#[protobuf(name = "crate::proto::consensus::ProposalInit")]
pub struct ProposalInit {
    /// The height of the consensus (block number).
    pub height: BlockNumber,
    /// The current round of the consensus.
    pub round: u32,
    /// The last round that was valid.
    pub valid_round: Option<u32>,
    /// Address of the one who proposed the block.
    pub proposer: ContractAddress,
}

/// This struct differs from `BlockInfo` in `starknet_api` because we send L1 gas prices in ETH and
/// include the ETH to STRK conversion rate. This allows for more informative validations, as we can
/// distinguish whether an issue comes from the L1 price reading or the conversion rate instead of
/// comparing after multiplication.
#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, TaggedDebug)]
#[protobuf(name = "crate::proto::consensus::BlockInfo")]
pub struct ConsensusBlockInfo {
    pub height: BlockNumber,
    pub timestamp: u64,
    pub builder: ContractAddress,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub l2_gas_price_fri: u128,
    pub l1_gas_price_wei: u128,
    pub l1_data_gas_price_wei: u128,
    /// The value of 1 ETH in FRI.
    pub eth_to_fri_rate: u128,
}

impl ConsensusBlockInfo {
    pub fn wei_to_fri(wei: u128, eth_to_fri_rate: u128) -> u128 {
        // We use integer division since wei * eth_to_fri_rate is expected to be high enough to not
        // cause too much precision loss.
        wei.checked_mul(eth_to_fri_rate).expect("Gas price is too high.") / ETH_TO_WEI
    }
    pub fn fri_to_wei(fri: u128, eth_to_fri_rate: u128) -> u128 {
        fri.checked_mul(ETH_TO_WEI).expect("Gas price is too high") / eth_to_fri_rate
    }
}

/// A temporary constant to use as a validator ID. Zero is not a valid contract address.
// TODO(Matan): Remove this once we have a proper validator set.
pub const DEFAULT_VALIDATOR_ID: u64 = 100;

impl Default for ProposalInit {
    fn default() -> Self {
        ProposalInit {
            height: Default::default(),
            round: Default::default(),
            valid_round: Default::default(),
            proposer: ContractAddress::from(DEFAULT_VALIDATOR_ID),
        }
    }
}

/// There is one or more batches of transactions in a proposed block.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionBatch {
    /// The transactions in the batch.
    pub transactions: Vec<ConsensusTransaction>,
}

/// The proposal is done when receiving this fin message, which contains the block hash.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposalFin {
    /// The block hash of the proposed block.
    /// TODO(Matan): Consider changing the content ID to a signature.
    pub proposal_commitment: BlockHash,
}

/// A part of the proposal.
#[derive(Debug, Clone, PartialEq)]
pub enum ProposalPart {
    /// The initialization part of the proposal.
    Init(ProposalInit),
    /// Identifies the content of the proposal; contains `id(v)` in Tendermint terms.
    Fin(ProposalFin),
    /// The block info part of the proposal.
    BlockInfo(ConsensusBlockInfo),
    /// A part of the proposal that contains one or more transactions.
    Transactions(TransactionBatch),
}

impl TryInto<ProposalInit> for ProposalPart {
    type Error = ProtobufConversionError;

    fn try_into(self: ProposalPart) -> Result<ProposalInit, Self::Error> {
        match self {
            ProposalPart::Init(init) => Ok(init),
            _ => Err(ProtobufConversionError::WrongEnumVariant {
                type_description: "ProposalPart",
                expected: "Init",
                value_as_str: format!("{:?}", self),
            }),
        }
    }
}

impl From<ProposalInit> for ProposalPart {
    fn from(value: ProposalInit) -> Self {
        ProposalPart::Init(value)
    }
}

impl<T, StreamId> std::fmt::Display for StreamMessage<T, StreamId>
where
    T: Clone + IntoFromProto,
    StreamId: IntoFromProto + Clone + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let StreamMessageBody::Content(message) = &self.message {
            let message: Vec<u8> = message.clone().into();
            write!(
                f,
                "StreamMessage {{ stream_id: {}, message_id: {}, message_length: {}}}",
                self.stream_id,
                self.message_id,
                message.len(),
            )
        } else {
            write!(
                f,
                "StreamMessage {{ stream_id: {}, message_id: {}, message is fin }}",
                self.stream_id, self.message_id,
            )
        }
    }
}

/// HeighAndRound is a tuple struct used as the StreamId for consensus and context.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeightAndRound(pub u64, pub u32);

impl TryFrom<Vec<u8>> for HeightAndRound {
    type Error = ProtobufConversionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 12 {
            return Err(ProtobufConversionError::DecodeError(DecodeError::new("Invalid length")));
        }
        let mut bytes = value.as_slice();
        let height = bytes.get_u64();
        let round = bytes.get_u32();
        Ok(HeightAndRound(height, round))
    }
}

impl From<HeightAndRound> for Vec<u8> {
    fn from(value: HeightAndRound) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.put_u64(value.0);
        bytes.put_u32(value.1);
        bytes
    }
}

impl std::fmt::Display for HeightAndRound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(height: {}, round: {})", self.0, self.1)
    }
}

*/