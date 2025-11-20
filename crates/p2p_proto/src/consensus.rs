use fake::Dummy;
use pathfinder_crypto::Felt;
use prost::Message;
use proto::consensus::consensus as consensus_proto;

use crate::common::{Address, Hash, L1DataAvailabilityMode};
use crate::transaction::{DeclareV3WithClass, DeployAccountV3, InvokeV3, L1HandlerV0};
use crate::{proto, proto_field, ProtobufSerializable, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum TransactionVariant {
    DeclareV3(DeclareV3WithClass),
    DeployAccountV3(DeployAccountV3),
    InvokeV3(InvokeV3),
    L1HandlerV0(L1HandlerV0),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::ConsensusTransaction")]
pub struct Transaction {
    pub txn: TransactionVariant,
    pub transaction_hash: Hash,
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Dummy)]
pub enum VoteType {
    Prevote,
    #[default]
    Precommit,
}

#[derive(
    Debug, Default, Clone, Eq, PartialEq, PartialOrd, Ord, ToProtobuf, TryFromProtobuf, Dummy,
)]
#[protobuf(name = "consensus_proto::Vote")]
pub struct Vote {
    pub vote_type: VoteType,
    pub block_number: u64,
    pub round: u32,
    #[optional]
    pub proposal_commitment: Option<Hash>,
    pub voter: Address,
}

impl ProtobufSerializable for Vote {
    fn to_protobuf_bytes(&self) -> Vec<u8> {
        self.clone().to_protobuf().encode_to_vec()
    }

    fn from_protobuf_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let proto = proto::consensus::consensus::Vote::decode(bytes)?;
        Vote::try_from_protobuf(proto, "vote")
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum ProposalPart {
    Init(ProposalInit),
    Fin(ProposalFin),
    BlockInfo(BlockInfo),
    TransactionBatch(Vec<Transaction>),
    TransactionsFin(TransactionsFin),
    ProposalCommitment(ProposalCommitment),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::ProposalInit")]
pub struct ProposalInit {
    pub block_number: u64,
    pub round: u32,
    #[optional]
    pub valid_round: Option<u32>,
    pub proposer: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::ProposalFin")]
pub struct ProposalFin {
    pub proposal_commitment: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::TransactionBatch")]
pub struct TransactionBatch {
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::TransactionsFin")]
pub struct TransactionsFin {
    pub executed_transaction_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::BlockInfo")]
pub struct BlockInfo {
    pub block_number: u64,
    pub builder: Address,
    pub timestamp: u64,
    pub l2_gas_price_fri: u128,
    pub l1_gas_price_wei: u128,
    pub l1_data_gas_price_wei: u128,
    pub eth_to_strk_rate: u128,
    pub l1_da_mode: L1DataAvailabilityMode,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::ProposalCommitment")]
pub struct ProposalCommitment {
    pub block_number: u64,
    pub parent_commitment: Hash,
    pub builder: Address,
    pub timestamp: u64,
    pub protocol_version: String,
    pub old_state_root: Hash,
    pub version_constant_commitment: Hash,
    pub state_diff_commitment: Hash,
    pub transaction_commitment: Hash,
    pub event_commitment: Hash,
    pub receipt_commitment: Hash,
    pub concatenated_counts: Felt,
    pub l1_gas_price_fri: u128,
    pub l1_data_gas_price_fri: u128,
    pub l2_gas_price_fri: u128,
    pub l2_gas_used: u128,
    pub next_l2_gas_price_fri: u128,
    pub l1_da_mode: L1DataAvailabilityMode,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "consensus_proto::StreamMessage")]
pub struct StreamMessage {
    pub message: StreamMessageVariant,
    pub stream_id: Vec<u8>,
    pub sequence_number: u64,
}

impl StreamMessage {
    /// Creates a new StreamMessage containing a serialized ProposalPart
    pub fn with_proposal_part(
        proposal: ProposalPart,
        stream_id: Vec<u8>,
        sequence_number: u64,
    ) -> Self {
        let proposal_bytes = proposal.to_protobuf().encode_to_vec();
        Self {
            message: StreamMessageVariant::Content(proposal_bytes),
            stream_id,
            sequence_number,
        }
    }

    /// Attempts to extract a ProposalPart from the message content
    pub fn try_extract_proposal(&self) -> Option<Result<ProposalPart, std::io::Error>> {
        if let StreamMessageVariant::Content(content) = &self.message {
            consensus_proto::ProposalPart::decode(content.as_slice())
                .ok()
                .map(|proto| ProposalPart::try_from_protobuf(proto, "proposal"))
        } else {
            None
        }
    }

    pub fn try_from_protobuf_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let proto_message = consensus_proto::StreamMessage::decode(bytes)?;
        Self::try_from_protobuf(proto_message, "stream_message")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum StreamMessageVariant {
    Content(Vec<u8>),
    Fin,
}

impl ToProtobuf<consensus_proto::ProposalPart> for ProposalPart {
    fn to_protobuf(self) -> consensus_proto::ProposalPart {
        use consensus_proto::proposal_part::Messages::{
            BlockInfo,
            Commitment,
            Fin,
            Init,
            TransactionFin,
            Transactions,
        };
        let msg = match self {
            ProposalPart::Init(proposal_init) => Init(proposal_init.to_protobuf()),
            ProposalPart::Fin(proposal_fin) => Fin(proposal_fin.to_protobuf()),
            ProposalPart::BlockInfo(block_info) => BlockInfo(block_info.to_protobuf()),
            ProposalPart::TransactionBatch(transactions) => {
                Transactions(consensus_proto::TransactionBatch {
                    transactions: transactions
                        .into_iter()
                        .map(|txn| txn.to_protobuf())
                        .collect(),
                })
            }
            ProposalPart::TransactionsFin(transactions_fin) => {
                TransactionFin(transactions_fin.to_protobuf())
            }
            ProposalPart::ProposalCommitment(proposal_commitment) => {
                Commitment(proposal_commitment.to_protobuf())
            }
        };
        consensus_proto::ProposalPart {
            messages: Some(msg),
        }
    }
}

impl TryFromProtobuf<consensus_proto::ProposalPart> for ProposalPart {
    fn try_from_protobuf(
        input: consensus_proto::ProposalPart,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use consensus_proto::proposal_part::Messages::{
            BlockInfo,
            Commitment,
            Fin,
            Init,
            TransactionFin,
            Transactions,
        };
        match proto_field(input.messages, field_name)? {
            Init(init) => TryFromProtobuf::try_from_protobuf(init, field_name).map(Self::Init),
            BlockInfo(bi) => {
                TryFromProtobuf::try_from_protobuf(bi, field_name).map(Self::BlockInfo)
            }
            Transactions(transactions) => transactions
                .transactions
                .into_iter()
                .map(|txn| TryFromProtobuf::try_from_protobuf(txn, field_name))
                .collect::<Result<Vec<_>, _>>()
                .map(Self::TransactionBatch),
            Fin(fin) => TryFromProtobuf::try_from_protobuf(fin, field_name).map(Self::Fin),
            TransactionFin(transactions_fin) => {
                TryFromProtobuf::try_from_protobuf(transactions_fin, field_name)
                    .map(Self::TransactionsFin)
            }
            Commitment(proposal_commitment) => {
                TryFromProtobuf::try_from_protobuf(proposal_commitment, field_name)
                    .map(Self::ProposalCommitment)
            }
        }
    }
}

impl ProtobufSerializable for ProposalPart {
    fn to_protobuf_bytes(&self) -> Vec<u8> {
        self.clone().to_protobuf().encode_to_vec()
    }

    fn from_protobuf_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let proto = consensus_proto::ProposalPart::decode(bytes)?;
        ProposalPart::try_from_protobuf(proto, "proposal")
    }
}

impl ProposalPart {
    pub fn as_init(&self) -> Option<&ProposalInit> {
        if let Self::Init(init) = self {
            Some(init)
        } else {
            None
        }
    }

    pub fn as_init_mut(&mut self) -> Option<&mut ProposalInit> {
        if let Self::Init(init) = self {
            Some(init)
        } else {
            None
        }
    }

    pub fn as_fin(&self) -> Option<&ProposalFin> {
        if let Self::Fin(fin) = self {
            Some(fin)
        } else {
            None
        }
    }

    pub fn is_block_info(&self) -> bool {
        matches!(self, Self::BlockInfo(_))
    }
}

impl ToProtobuf<consensus_proto::consensus_transaction::Txn> for TransactionVariant {
    fn to_protobuf(self) -> consensus_proto::consensus_transaction::Txn {
        use proto::consensus::consensus::consensus_transaction::Txn::{
            DeclareV3,
            DeployAccountV3,
            InvokeV3,
            L1Handler,
        };
        match self {
            Self::DeclareV3(txn) => DeclareV3(txn.to_protobuf()),
            Self::DeployAccountV3(txn) => DeployAccountV3(txn.to_protobuf()),
            Self::InvokeV3(txn) => InvokeV3(txn.to_protobuf()),
            Self::L1HandlerV0(txn) => L1Handler(txn.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<consensus_proto::consensus_transaction::Txn> for TransactionVariant {
    fn try_from_protobuf(
        input: consensus_proto::consensus_transaction::Txn,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use consensus_proto::consensus_transaction::Txn::{
            DeclareV3,
            DeployAccountV3,
            InvokeV3,
            L1Handler,
        };
        match input {
            DeclareV3(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeclareV3),
            DeployAccountV3(t) => {
                TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeployAccountV3)
            }
            InvokeV3(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::InvokeV3),
            L1Handler(t) => {
                TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::L1HandlerV0)
            }
        }
    }
}

impl ToProtobuf<i32> for VoteType {
    fn to_protobuf(self) -> i32 {
        use consensus_proto::vote::VoteType::{Precommit, Prevote};
        match self {
            VoteType::Prevote => Prevote as i32,
            VoteType::Precommit => Precommit as i32,
        }
    }
}

impl TryFromProtobuf<i32> for VoteType {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        use consensus_proto::vote::VoteType::{Precommit, Prevote};
        Ok(
            match TryFrom::try_from(input).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid vote type field element {field_name} enum value: {e}"),
                )
            })? {
                Prevote => VoteType::Prevote,
                Precommit => VoteType::Precommit,
            },
        )
    }
}

impl ToProtobuf<consensus_proto::stream_message::Message> for StreamMessageVariant {
    fn to_protobuf(self) -> consensus_proto::stream_message::Message {
        use proto::consensus::consensus::stream_message::Message::{Content, Fin};
        match self {
            Self::Content(message) => Content(message),
            Self::Fin => Fin(proto::common::Fin {}),
        }
    }
}

impl TryFromProtobuf<consensus_proto::stream_message::Message> for StreamMessageVariant {
    fn try_from_protobuf(
        input: consensus_proto::stream_message::Message,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use consensus_proto::stream_message::Message::{Content, Fin};
        match input {
            Content(message) => {
                TryFromProtobuf::try_from_protobuf(message, field_name).map(Self::Content)
            }
            Fin(_) => Ok(Self::Fin),
        }
    }
}
