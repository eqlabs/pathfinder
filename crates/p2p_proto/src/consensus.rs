use fake::Dummy;

use crate::common::{Address, Hash, L1DataAvailabilityMode};
use crate::proto::consensus::ConsensusTransaction;
use crate::transaction::{DeclareV3WithClass, DeployAccountV3, InvokeV3, L1HandlerV0};
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum TransactionVariant {
    DeclareV3(DeclareV3WithClass),
    DeployAccountV3(DeployAccountV3),
    InvokeV3(InvokeV3),
    L1HandlerV0(L1HandlerV0),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::consensus::ConsensusTransaction")]
pub struct Transaction {
    pub txn: TransactionVariant,
    pub transaction_hash: Hash,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub enum VoteType {
    Prevote,
    Precommit,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::consensus::StreamMessage")]
pub struct StreamMessage {
    pub message: StreamMessageVariant,
    pub stream_id: Vec<u8>,
    pub message_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum StreamMessageVariant {
    Content(Vec<u8>),
    Fin,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::consensus::ProposalInit")]
pub struct ProposalInit {
    pub height: u64,
    pub round: u32,
    #[optional]
    pub valid_round: Option<u32>,
    pub proposer: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::consensus::BlockInfo")]
pub struct BlockInfo {
    pub height: u64,
    pub timestamp: u64,
    pub builder: Address,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub l2_gas_price_fri: u128,
    pub l1_gas_price_wei: u128,
    pub l1_data_gas_price_wei: u128,
    pub eth_to_fri_rate: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::consensus::ProposalFin")]
pub struct ProposalFin {
    pub proposal_commitment: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum ProposalPart {
    ProposalInit(ProposalInit),
    BlockInfo(BlockInfo),
    TransactionBatch(Vec<Transaction>),
    ProposalFin(ProposalFin),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransactionBatch {
    /// The transactions in the batch.
    pub transactions: Vec<ConsensusTransaction>,
}

impl ToProtobuf<proto::consensus::consensus_transaction::Txn> for TransactionVariant {
    fn to_protobuf(self) -> proto::consensus::consensus_transaction::Txn {
        use proto::consensus::consensus_transaction::Txn::{
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

impl TryFromProtobuf<proto::consensus::consensus_transaction::Txn> for TransactionVariant {
    fn try_from_protobuf(
        input: proto::consensus::consensus_transaction::Txn,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::consensus::consensus_transaction::Txn::{
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
        use proto::consensus::vote::VoteType::{Precommit, Prevote};
        match self {
            VoteType::Prevote => Prevote as i32,
            VoteType::Precommit => Precommit as i32,
        }
    }
}

impl TryFromProtobuf<i32> for VoteType {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        use proto::consensus::vote::VoteType::{Precommit, Prevote};
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

impl ToProtobuf<proto::consensus::stream_message::Message> for StreamMessageVariant {
    fn to_protobuf(self) -> proto::consensus::stream_message::Message {
        use proto::consensus::stream_message::Message::{Content, Fin};
        match self {
            Self::Content(message) => Content(message),
            Self::Fin => Fin(proto::common::Fin {}),
        }
    }
}

impl TryFromProtobuf<proto::consensus::stream_message::Message> for StreamMessageVariant {
    fn try_from_protobuf(
        input: proto::consensus::stream_message::Message,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::consensus::stream_message::Message::{Content, Fin};
        match input {
            Content(message) => {
                TryFromProtobuf::try_from_protobuf(message, field_name).map(Self::Content)
            }
            Fin(_) => Ok(Self::Fin),
        }
    }
}

impl ToProtobuf<proto::consensus::ProposalPart> for ProposalPart {
    fn to_protobuf(self) -> proto::consensus::ProposalPart {
        use proto::consensus::proposal_part::Message::{BlockInfo, Fin, Init, Transactions};
        use proto::consensus::TransactionBatch;
        proto::consensus::ProposalPart {
            message: Some(match self {
                Self::ProposalInit(init) => Init(init.to_protobuf()),
                Self::BlockInfo(bi) => BlockInfo(bi.to_protobuf()),
                Self::TransactionBatch(transactions) => Transactions(TransactionBatch {
                    transactions: transactions
                        .into_iter()
                        .map(|txn| txn.to_protobuf())
                        .collect(),
                }),
                Self::ProposalFin(fin) => Fin(fin.to_protobuf()),
            }),
        }
    }
}

impl TryFromProtobuf<proto::consensus::ProposalPart> for ProposalPart {
    fn try_from_protobuf(
        input: proto::consensus::ProposalPart,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::consensus::proposal_part::Message::{BlockInfo, Fin, Init, Transactions};
        match proto_field(input.message, field_name)? {
            Init(init) => {
                TryFromProtobuf::try_from_protobuf(init, field_name).map(Self::ProposalInit)
            }
            BlockInfo(bi) => {
                TryFromProtobuf::try_from_protobuf(bi, field_name).map(Self::BlockInfo)
            }
            Transactions(transactions) => transactions
                .transactions
                .into_iter()
                .map(|txn| TryFromProtobuf::try_from_protobuf(txn, field_name))
                .collect::<Result<Vec<_>, _>>()
                .map(Self::TransactionBatch),
            Fin(fin) => TryFromProtobuf::try_from_protobuf(fin, field_name).map(Self::ProposalFin),
        }
    }
}
