use fake::Dummy;
use prost::Message;

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
#[protobuf(name = "crate::proto::consensus::ConsensusTransaction")]
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
#[protobuf(name = "crate::proto::consensus::Vote")]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: u64,
    pub round: u32,
    #[optional]
    pub block_hash: Option<Hash>,
    pub voter: Address,
    #[optional]
    pub extension: Option<Vec<u8>>,
}

impl ProtobufSerializable for Vote {
    fn to_protobuf_bytes(&self) -> Vec<u8> {
        self.clone().to_protobuf().encode_to_vec()
    }

    fn from_protobuf_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let proto = proto::consensus::Vote::decode(bytes)?;
        Vote::try_from_protobuf(proto, "vote")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::consensus::StreamMessage")]
pub struct StreamMessage {
    pub message: StreamMessageVariant,
    pub stream_id: Vec<u8>,
    pub message_id: u64,
}

impl StreamMessage {
    /// Creates a new StreamMessage containing a serialized ProposalPart
    pub fn with_proposal_part(proposal: ProposalPart, stream_id: Vec<u8>, message_id: u64) -> Self {
        let proposal_bytes = proposal.to_protobuf().encode_to_vec();
        Self {
            message: StreamMessageVariant::Content(proposal_bytes),
            stream_id,
            message_id,
        }
    }

    /// Attempts to extract a ProposalPart from the message content
    pub fn try_extract_proposal(&self) -> Option<Result<ProposalPart, std::io::Error>> {
        if let StreamMessageVariant::Content(content) = &self.message {
            proto::consensus::ProposalPart::decode(content.as_slice())
                .ok()
                .map(|proto| ProposalPart::try_from_protobuf(proto, "proposal"))
        } else {
            None
        }
    }
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
    Init(ProposalInit),
    BlockInfo(BlockInfo),
    TransactionBatch(Vec<Transaction>),
    Fin(ProposalFin),
}

impl std::fmt::Display for ProposalPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(_) => write!(f, "Init"),
            Self::BlockInfo(_) => write!(f, "BlockInfo"),
            Self::TransactionBatch(_) => write!(f, "TransactionBatch"),
            Self::Fin(_) => write!(f, "Fin"),
        }
    }
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
                Self::Init(init) => Init(init.to_protobuf()),
                Self::BlockInfo(bi) => BlockInfo(bi.to_protobuf()),
                Self::TransactionBatch(transactions) => Transactions(TransactionBatch {
                    transactions: transactions
                        .into_iter()
                        .map(|txn| txn.to_protobuf())
                        .collect(),
                }),
                Self::Fin(fin) => Fin(fin.to_protobuf()),
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
        }
    }
}

impl ProtobufSerializable for ProposalPart {
    fn to_protobuf_bytes(&self) -> Vec<u8> {
        self.clone().to_protobuf().encode_to_vec()
    }

    fn from_protobuf_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let proto = proto::consensus::ProposalPart::decode(bytes)?;
        ProposalPart::try_from_protobuf(proto, "proposal")
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_crypto::Felt;

    use super::*;
    use crate::common::{Address, Hash, L1DataAvailabilityMode};

    #[test]
    fn test_stream_message_serialization() {
        // Test Content variant
        let content_message = StreamMessage {
            message: StreamMessageVariant::Content(vec![1, 2, 3, 4]),
            stream_id: vec![5, 6, 7, 8],
            message_id: 42,
        };

        // Serialize, deserialize, and verify
        let proto = content_message.clone().to_protobuf();
        let deserialized = StreamMessage::try_from_protobuf(proto, "").unwrap();
        assert_eq!(content_message, deserialized);

        // Test Fin variant
        let fin_message = StreamMessage {
            message: StreamMessageVariant::Fin,
            stream_id: vec![9, 10, 11, 12],
            message_id: 43,
        };

        // Serialize, deserialize, and verify
        let proto = fin_message.clone().to_protobuf();
        let deserialized = StreamMessage::try_from_protobuf(proto, "").unwrap();
        assert_eq!(fin_message, deserialized);
    }

    #[test]
    fn test_proposal_part_serialization() {
        // Test ProposalInit variant
        let init = ProposalInit {
            height: 100,
            round: 5,
            valid_round: Some(4),
            proposer: Address(Felt::from_hex_str("0x123").unwrap()),
        };
        let proposal_init = ProposalPart::Init(init.clone());

        // Serialize, deserialize, and verify
        let proto = proposal_init.clone().to_protobuf();
        let deserialized = ProposalPart::try_from_protobuf(proto, "test").unwrap();
        assert_eq!(proposal_init, deserialized);

        // Test BlockInfo variant
        let block_info = BlockInfo {
            height: 100,
            timestamp: 1234567890,
            builder: Address(Felt::from_hex_str("0x456").unwrap()),
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 1000,
            l1_gas_price_wei: 2000,
            l1_data_gas_price_wei: 3000,
            eth_to_fri_rate: 4000,
        };
        let proposal_part = ProposalPart::BlockInfo(block_info.clone());

        // Serialize, deserialize, and verify
        let proto = proposal_part.clone().to_protobuf();
        let deserialized = ProposalPart::try_from_protobuf(proto, "test").unwrap();
        assert_eq!(proposal_part, deserialized);

        // Test TransactionBatch variant
        let transactions = vec![Transaction {
            txn: TransactionVariant::L1HandlerV0(L1HandlerV0 {
                nonce: Felt::from_hex_str("0x1").unwrap(),
                calldata: vec![Felt::from_hex_str("0x2").unwrap()],
                address: Address(Felt::from_hex_str("0x3").unwrap()),
                entry_point_selector: Felt::from_hex_str("0x4").unwrap(),
            }),
            transaction_hash: Hash(Felt::from_hex_str("0xabc").unwrap()),
        }];
        let proposal_batch = ProposalPart::TransactionBatch(transactions.clone());

        // Serialize, deserialize, and verify
        let proto = proposal_batch.clone().to_protobuf();
        let deserialized = ProposalPart::try_from_protobuf(proto, "test").unwrap();
        assert_eq!(proposal_batch, deserialized);

        // Test ProposalFin variant
        let fin = ProposalFin {
            proposal_commitment: Hash(Felt::from_hex_str("0xdef").unwrap()),
        };
        let proposal_fin = ProposalPart::Fin(fin.clone());

        // Serialize, deserialize, and verify
        let proto = proposal_fin.clone().to_protobuf();
        let deserialized = ProposalPart::try_from_protobuf(proto, "test").unwrap();
        assert_eq!(proposal_fin, deserialized);
    }

    #[test]
    fn test_stream_message_with_proposal_part() {
        // Create a ProposalPart (using BlockInfo as an example)
        let block_info = BlockInfo {
            height: 100,
            timestamp: 1234567890,
            builder: Address(Felt::from_hex_str("0x456").unwrap()),
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 1000,
            l1_gas_price_wei: 2000,
            l1_data_gas_price_wei: 3000,
            eth_to_fri_rate: 4000,
        };
        let proposal_part = ProposalPart::BlockInfo(block_info);

        // Create StreamMessage with ProposalPart
        let stream_message =
            StreamMessage::with_proposal_part(proposal_part.clone(), vec![1, 2, 3, 4], 42);

        // Serialize and deserialize
        let proto = stream_message.clone().to_protobuf();
        let deserialized_stream = StreamMessage::try_from_protobuf(proto, "test").unwrap();
        assert_eq!(stream_message, deserialized_stream);

        // Extract and verify ProposalPart
        let deserialized_proposal = deserialized_stream
            .try_extract_proposal()
            .expect("Should contain proposal")
            .expect("Should deserialize successfully");
        assert_eq!(proposal_part, deserialized_proposal);
    }

    #[test]
    fn test_proposal_part_protobuf_serializable() {
        // Test ProposalInit variant
        let init = ProposalInit {
            height: 100,
            round: 5,
            valid_round: Some(4),
            proposer: Address(Felt::from_hex_str("0x123").unwrap()),
        };
        let proposal_init = ProposalPart::Init(init);

        // Test serialization and deserialization using ProtobufSerializable
        let bytes = proposal_init.to_protobuf_bytes();
        let deserialized = ProposalPart::from_protobuf_bytes(&bytes).unwrap();
        assert_eq!(proposal_init, deserialized);

        // Test BlockInfo variant
        let block_info = BlockInfo {
            height: 100,
            timestamp: 1234567890,
            builder: Address(Felt::from_hex_str("0x456").unwrap()),
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 1000,
            l1_gas_price_wei: 2000,
            l1_data_gas_price_wei: 3000,
            eth_to_fri_rate: 4000,
        };
        let proposal_block = ProposalPart::BlockInfo(block_info);

        // Test serialization and deserialization using ProtobufSerializable
        let bytes = proposal_block.to_protobuf_bytes();
        let deserialized = ProposalPart::from_protobuf_bytes(&bytes).unwrap();
        assert_eq!(proposal_block, deserialized);

        // Test TransactionBatch variant
        let transactions = vec![Transaction {
            txn: TransactionVariant::L1HandlerV0(L1HandlerV0 {
                nonce: Felt::from_hex_str("0x1").unwrap(),
                calldata: vec![Felt::from_hex_str("0x2").unwrap()],
                address: Address(Felt::from_hex_str("0x3").unwrap()),
                entry_point_selector: Felt::from_hex_str("0x4").unwrap(),
            }),
            transaction_hash: Hash(Felt::from_hex_str("0xabc").unwrap()),
        }];
        let proposal_batch = ProposalPart::TransactionBatch(transactions);

        // Test serialization and deserialization using ProtobufSerializable
        let bytes = proposal_batch.to_protobuf_bytes();
        let deserialized = ProposalPart::from_protobuf_bytes(&bytes).unwrap();
        assert_eq!(proposal_batch, deserialized);

        // Test ProposalFin variant
        let fin = ProposalFin {
            proposal_commitment: Hash(Felt::from_hex_str("0xdef").unwrap()),
        };
        let proposal_fin = ProposalPart::Fin(fin);

        // Test serialization and deserialization using ProtobufSerializable
        let bytes = proposal_fin.to_protobuf_bytes();
        let deserialized = ProposalPart::from_protobuf_bytes(&bytes).unwrap();
        assert_eq!(proposal_fin, deserialized);
    }

    #[test]
    fn test_vote_protobuf_serializable() {
        // Test Vote with Prevote type and no block hash
        let prevote = Vote {
            vote_type: VoteType::Prevote,
            height: 100,
            round: 5,
            block_hash: None,
            voter: Address(Felt::from_hex_str("0x123").unwrap()),
            extension: None,
        };

        // Test serialization and deserialization using ProtobufSerializable
        let bytes = prevote.to_protobuf_bytes();
        let deserialized = Vote::from_protobuf_bytes(&bytes).unwrap();
        assert_eq!(prevote, deserialized);

        // Test Vote with Precommit type and block hash
        let precommit = Vote {
            vote_type: VoteType::Precommit,
            height: 101,
            round: 6,
            block_hash: Some(Hash(Felt::from_hex_str("0x456").unwrap())),
            voter: Address(Felt::from_hex_str("0x789").unwrap()),
            extension: None,
        };

        // Test serialization and deserialization using ProtobufSerializable
        let bytes = precommit.to_protobuf_bytes();
        let deserialized = Vote::from_protobuf_bytes(&bytes).unwrap();
        assert_eq!(precommit, deserialized);
    }
}
