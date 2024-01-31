use crate::common::{Address, Hash, Iteration};
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use pathfinder_crypto::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::ResourceLimits")]
pub struct ResourceLimits {
    pub max_amount: Felt,
    pub max_price_per_unit: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::ResourceBounds")]
pub struct ResourceBounds {
    pub l1_gas: ResourceLimits,
    pub l2_gas: ResourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::AccountSignature")]
pub struct AccountSignature {
    pub parts: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::DeclareV0")]
pub struct DeclareV0 {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::DeclareV1")]

pub struct DeclareV1 {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::DeclareV2")]
pub struct DeclareV2 {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
    pub compiled_class_hash: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::DeclareV3")]
pub struct DeclareV3 {
    pub sender: Address,
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
    pub compiled_class_hash: Felt,
    pub resource_bounds: ResourceBounds,
    pub tip: Felt,
    pub paymaster_data: Address,
    pub account_deployment_data: Address,
    pub nonce_domain: String,
    pub fee_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::Deploy")]
pub struct Deploy {
    pub class_hash: Hash,
    pub address_salt: Felt,
    pub calldata: Vec<Felt>,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::DeployAccountV1")]
pub struct DeployAccountV1 {
    pub max_fee: Felt,
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
    pub address_salt: Felt,
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::DeployAccountV3")]
pub struct DeployAccountV3 {
    pub signature: AccountSignature,
    pub class_hash: Hash,
    pub nonce: Felt,
    pub address_salt: Felt,
    pub calldata: Vec<Felt>,
    pub resource_bounds: ResourceBounds,
    pub tip: Felt,
    pub paymaster_data: Address,
    pub nonce_domain: String,
    pub fee_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::InvokeV0")]
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
#[protobuf(name = "crate::proto::transaction::transaction::InvokeV1")]
pub struct InvokeV1 {
    pub sender: Address,
    pub max_fee: Felt,
    pub signature: AccountSignature,
    // FIXME incorrect field
    // pub class_hash: Hash,
    pub nonce: Felt,
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::InvokeV3")]
pub struct InvokeV3 {
    pub sender: Address,
    pub signature: AccountSignature,
    pub calldata: Vec<Felt>,
    pub resource_bounds: ResourceBounds,
    pub tip: Felt,
    pub paymaster_data: Address,
    pub account_deployment_data: Address,
    pub nonce_domain: String,
    pub fee_domain: String,
    pub nonce: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::transaction::L1HandlerV0")]
pub struct L1HandlerV0 {
    pub nonce: Felt,
    pub address: Address,
    pub entry_point_selector: Felt,
    pub calldata: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum Transaction {
    DeclareV0(DeclareV0),
    DeclareV1(DeclareV1),
    DeclareV2(DeclareV2),
    DeclareV3(DeclareV3),
    Deploy(Deploy),
    DeployAccountV1(DeployAccountV1),
    DeployAccountV3(DeployAccountV3),
    InvokeV0(InvokeV0),
    InvokeV1(InvokeV1),
    InvokeV3(InvokeV3),
    L1HandlerV0(L1HandlerV0),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::transaction::TransactionsRequest")]
pub struct TransactionsRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum TransactionsResponse {
    Transaction(Transaction),
    Fin,
}

impl ToProtobuf<proto::transaction::Transaction> for Transaction {
    fn to_protobuf(self) -> proto::transaction::Transaction {
        use proto::transaction::transaction::Txn::{
            DeclareV0, DeclareV1, DeclareV2, DeclareV3, Deploy, DeployAccountV1, DeployAccountV3,
            InvokeV0, InvokeV1, InvokeV3, L1Handler,
        };
        proto::transaction::Transaction {
            txn: Some(match self {
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
            }),
        }
    }
}

impl TryFromProtobuf<proto::transaction::Transaction> for Transaction {
    fn try_from_protobuf(
        input: proto::transaction::Transaction,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::transaction::transaction::Txn::{
            DeclareV0, DeclareV1, DeclareV2, DeclareV3, Deploy, DeployAccountV1, DeployAccountV3,
            InvokeV0, InvokeV1, InvokeV3, L1Handler,
        };
        match proto_field(input.txn, field_name)? {
            DeclareV0(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeclareV0),
            DeclareV1(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeclareV1),
            DeclareV2(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeclareV2),
            DeclareV3(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeclareV3),
            Deploy(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::Deploy),
            DeployAccountV1(t) => {
                TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeployAccountV1)
            }
            DeployAccountV3(t) => {
                TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::DeployAccountV3)
            }
            InvokeV0(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::InvokeV0),
            InvokeV1(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::InvokeV1),
            InvokeV3(t) => TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::InvokeV3),
            L1Handler(t) => {
                TryFromProtobuf::try_from_protobuf(t, field_name).map(Self::L1HandlerV0)
            }
        }
    }
}

impl ToProtobuf<proto::transaction::TransactionsResponse> for TransactionsResponse {
    fn to_protobuf(self) -> proto::transaction::TransactionsResponse {
        use proto::transaction::transactions_response::TransactionMessage::{Fin, Transaction};
        proto::transaction::TransactionsResponse {
            transaction_message: Some(match self {
                Self::Transaction(t) => Transaction(t.to_protobuf()),
                Self::Fin => Fin(proto::common::Fin {}),
            }),
        }
    }
}

impl TryFromProtobuf<proto::transaction::TransactionsResponse> for TransactionsResponse {
    fn try_from_protobuf(
        input: proto::transaction::TransactionsResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::transaction::transactions_response::TransactionMessage::{Fin, Transaction};
        Ok(match proto_field(input.transaction_message, field_name)? {
            Transaction(t) => Self::Transaction(TryFromProtobuf::try_from_protobuf(t, field_name)?),
            Fin(_) => Self::Fin,
        })
    }
}
