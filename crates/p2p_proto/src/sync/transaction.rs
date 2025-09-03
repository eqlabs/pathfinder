use fake::Dummy;
use pathfinder_crypto::Felt;

use crate::common::{Address, Hash};
use crate::sync::common::Iteration;
use crate::sync::receipt::Receipt;
use crate::transaction::*;
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::TransactionsRequest")]
pub struct TransactionsRequest {
    pub iteration: Iteration,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default, Clone, PartialEq, Eq, Dummy)]
pub enum TransactionsResponse {
    TransactionWithReceipt(TransactionWithReceipt),
    #[default]
    Fin,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::TransactionWithReceipt")]
pub struct TransactionWithReceipt {
    pub transaction: Transaction,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum TransactionVariant {
    DeclareV0(DeclareV0WithoutClass),
    DeclareV1(DeclareV1WithoutClass),
    DeclareV2(DeclareV2WithoutClass),
    DeclareV3(DeclareV3WithoutClass),
    Deploy(Deploy),
    DeployAccountV1(DeployAccountV1),
    DeployAccountV3(DeployAccountV3),
    InvokeV0(InvokeV0),
    InvokeV1(InvokeV1),
    InvokeV3(InvokeV3),
    L1HandlerV0(L1HandlerV0),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::TransactionInBlock")]
pub struct Transaction {
    pub txn: TransactionVariant,
    pub transaction_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::DeclareV0WithoutClass")]
pub struct DeclareV0WithoutClass {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::DeclareV1WithoutClass")]
pub struct DeclareV1WithoutClass {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::DeclareV2WithoutClass")]
pub struct DeclareV2WithoutClass {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
    pub compiled_class_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::DeclareV3WithoutClass")]
pub struct DeclareV3WithoutClass {
    pub common: DeclareV3Common,
    pub class_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::Deploy")]
pub struct Deploy {
    pub class_hash: Hash,
    pub address_salt: Felt,
    pub calldata: Vec<Felt>,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::DeployAccountV1")]
pub struct DeployAccountV1 {
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
    pub address_salt: Felt,
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::InvokeV0")]
pub struct InvokeV0 {
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub address: Address,
    pub entry_point_selector: Felt,
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum EntryPointType {
    External,
    L1Handler,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::transaction::transaction_in_block::InvokeV1")]
pub struct InvokeV1 {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    // FIXME incorrect field
    // pub class_hash: Hash,
    pub nonce: Felt,
    pub calldata: Vec<Felt>,
}

impl ToProtobuf<proto::sync::transaction::TransactionsResponse> for TransactionsResponse {
    fn to_protobuf(self) -> proto::sync::transaction::TransactionsResponse {
        use proto::sync::transaction::transactions_response::TransactionMessage::{
            Fin,
            TransactionWithReceipt,
        };
        proto::sync::transaction::TransactionsResponse {
            transaction_message: Some(match self {
                Self::TransactionWithReceipt(t) => TransactionWithReceipt(t.to_protobuf()),
                Self::Fin => Fin(proto::common::Fin {}),
            }),
        }
    }
}

impl TryFromProtobuf<proto::sync::transaction::TransactionsResponse> for TransactionsResponse {
    fn try_from_protobuf(
        input: proto::sync::transaction::TransactionsResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::sync::transaction::transactions_response::TransactionMessage::{
            Fin,
            TransactionWithReceipt,
        };
        Ok(match proto_field(input.transaction_message, field_name)? {
            TransactionWithReceipt(t) => {
                Self::TransactionWithReceipt(TryFromProtobuf::try_from_protobuf(t, field_name)?)
            }
            Fin(_) => Self::Fin,
        })
    }
}

impl TryFromProtobuf<proto::sync::transaction::transaction_in_block::Txn> for TransactionVariant {
    fn try_from_protobuf(
        input: proto::sync::transaction::transaction_in_block::Txn,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::sync::transaction::transaction_in_block::Txn::*;
        match input {
            DeclareV0(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::DeclareV0)
            }
            DeclareV1(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::DeclareV1)
            }
            DeclareV2(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::DeclareV2)
            }
            DeclareV3(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::DeclareV3)
            }
            Deploy(txn) => TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::Deploy),
            DeployAccountV1(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::DeployAccountV1)
            }
            DeployAccountV3(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::DeployAccountV3)
            }
            InvokeV0(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::InvokeV0)
            }
            InvokeV1(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::InvokeV1)
            }
            InvokeV3(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::InvokeV3)
            }
            L1Handler(txn) => {
                TryFromProtobuf::try_from_protobuf(txn, field_name).map(Self::L1HandlerV0)
            }
        }
    }
}

impl ToProtobuf<proto::sync::transaction::transaction_in_block::Txn> for TransactionVariant {
    fn to_protobuf(self) -> proto::sync::transaction::transaction_in_block::Txn {
        use proto::sync::transaction::transaction_in_block::Txn::*;
        match self {
            Self::DeclareV0(txn) => DeclareV0(txn.to_protobuf()),
            Self::DeclareV1(txn) => DeclareV1(txn.to_protobuf()),
            Self::DeclareV2(txn) => DeclareV2(txn.to_protobuf()),
            Self::DeclareV3(txn) => DeclareV3(txn.to_protobuf()),
            Self::Deploy(txn) => Deploy(txn.to_protobuf()),
            Self::DeployAccountV1(txn) => DeployAccountV1(txn.to_protobuf()),
            Self::DeployAccountV3(txn) => DeployAccountV3(txn.to_protobuf()),
            Self::InvokeV0(txn) => InvokeV0(txn.to_protobuf()),
            Self::InvokeV1(txn) => InvokeV1(txn.to_protobuf()),
            Self::InvokeV3(txn) => InvokeV3(txn.to_protobuf()),
            Self::L1HandlerV0(txn) => L1Handler(txn.to_protobuf()),
        }
    }
}
