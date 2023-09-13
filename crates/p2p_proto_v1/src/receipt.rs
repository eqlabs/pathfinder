use crate::{
    common::{Fin, Hash, Iteration},
    proto, ToProtobuf, TryFromProtobuf,
};
use fake::Dummy;
use primitive_types::H160;
use stark_hash::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::MessageToL1")]
pub struct MessageToL1 {
    pub from_address: Felt,
    pub payload: Vec<Felt>,
    pub to_address: EthereumAddress,
}

// Avoid pathfinder_common dependency
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EthereumAddress(pub H160);

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::MessageToL2")]
pub struct MessageToL2 {
    pub from_address: EthereumAddress,
    pub payload: Vec<Felt>,
    pub to_address: Felt,
    pub entry_point_selector: Felt,
    pub nonce: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::receipt::ExecutionResources")]
pub struct ExecutionResources {
    pub builtins: execution_resources::BuiltinCounter,
    pub steps: u32,
    pub memory_holes: u32,
}

pub mod execution_resources {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
    #[protobuf(name = "crate::proto::receipt::receipt::execution_resources::BuiltinCounter")]
    pub struct BuiltinCounter {
        pub bitwise: u32,
        pub ecdsa: u32,
        pub ec_op: u32,
        pub pedersen: u32,
        pub range_check: u32,
        pub poseidon: u32,
        pub keccak: u32,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::receipt::Common")]
pub struct ReceiptCommon {
    pub transaction_hash: Hash,
    pub actual_fee: Felt,
    pub messages_sent: Vec<MessageToL1>,
    pub execution_resources: ExecutionResources,
    pub revert_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::receipt::Invoke")]
pub struct InvokeTransactionReceipt {
    pub common: ReceiptCommon,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::receipt::L1Handler")]
pub struct L1HandlerTransactionReceipt {
    pub common: ReceiptCommon,
    pub msg_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::receipt::Declare")]
pub struct DeclareTransactionReceipt {
    pub common: ReceiptCommon,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::receipt::Deploy")]
pub struct DeployTransactionReceipt {
    pub common: ReceiptCommon,
    pub contract_address: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::receipt::DeployAccount")]
pub struct DeployAccountTransactionReceipt {
    pub common: ReceiptCommon,
    pub contract_address: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]

pub enum Receipt {
    Invoke(InvokeTransactionReceipt),
    Declare(DeclareTransactionReceipt),
    Deploy(DeployTransactionReceipt),
    DeployAccount(DeployAccountTransactionReceipt),
    L1Handler(L1HandlerTransactionReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::ReceiptsRequest")]
pub struct ReceiptsRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::Receipts")]
pub struct Receipts {
    pub items: Vec<Receipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::ReceiptsResponse")]
pub struct ReceiptsResponse {
    pub block_number: u64,
    pub block_hash: Hash,
    #[rename(responses)]
    pub kind: ReceiptsResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum ReceiptsResponseKind {
    Receipts(Receipts),
    Fin(Fin),
}

impl<T> Dummy<T> for EthereumAddress {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self(H160::random_using(rng))
    }
}

impl ToProtobuf<proto::receipt::EthereumAddress> for EthereumAddress {
    fn to_protobuf(self) -> proto::receipt::EthereumAddress {
        proto::receipt::EthereumAddress {
            elements: self.0.to_fixed_bytes().into(),
        }
    }
}

impl TryFromProtobuf<proto::receipt::EthereumAddress> for EthereumAddress {
    fn try_from_protobuf(
        input: proto::receipt::EthereumAddress,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        if input.elements.len() != primitive_types::H160::len_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length for Ethereum address {field_name}"),
            ));
        }

        // from_slice() panics if the input length is incorrect, but we've already checked that
        let address = primitive_types::H160::from_slice(&input.elements);
        Ok(Self(address))
    }
}

impl TryFromProtobuf<proto::receipt::Receipt> for Receipt {
    fn try_from_protobuf(
        input: proto::receipt::Receipt,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::receipt::receipt::Receipt::{
            Declare, DeployAccount, DeprecatedDeploy, Invoke, L1Handler,
        };

        match input.receipt {
            Some(receipt) => match receipt {
                Invoke(r) => Ok(Receipt::Invoke(TryFromProtobuf::try_from_protobuf(
                    r, field_name,
                )?)),
                L1Handler(r) => Ok(Receipt::L1Handler(TryFromProtobuf::try_from_protobuf(
                    r, field_name,
                )?)),
                Declare(r) => Ok(Receipt::Declare(TryFromProtobuf::try_from_protobuf(
                    r, field_name,
                )?)),
                DeprecatedDeploy(r) => Ok(Receipt::Deploy(TryFromProtobuf::try_from_protobuf(
                    r, field_name,
                )?)),
                DeployAccount(r) => Ok(Receipt::DeployAccount(TryFromProtobuf::try_from_protobuf(
                    r, field_name,
                )?)),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse {field_name}: missing receipt field"),
            )),
        }
    }
}

impl ToProtobuf<proto::receipt::Receipt> for Receipt {
    fn to_protobuf(self) -> proto::receipt::Receipt {
        use proto::receipt::receipt::Receipt::{
            Declare, DeployAccount, DeprecatedDeploy, Invoke, L1Handler,
        };

        let receipt = Some(match self {
            Receipt::Invoke(r) => Invoke(r.to_protobuf()),
            Receipt::Declare(r) => Declare(r.to_protobuf()),
            Receipt::Deploy(r) => DeprecatedDeploy(r.to_protobuf()),
            Receipt::DeployAccount(r) => DeployAccount(r.to_protobuf()),
            Receipt::L1Handler(r) => L1Handler(r.to_protobuf()),
        });
        proto::receipt::Receipt { receipt }
    }
}

impl ToProtobuf<proto::receipt::receipts_response::Responses> for ReceiptsResponseKind {
    fn to_protobuf(self) -> proto::receipt::receipts_response::Responses {
        use proto::receipt::receipts_response::Responses::{Fin, Receipts};
        match self {
            ReceiptsResponseKind::Receipts(r) => Receipts(r.to_protobuf()),
            ReceiptsResponseKind::Fin(f) => Fin(f.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::receipt::receipts_response::Responses> for ReceiptsResponseKind {
    fn try_from_protobuf(
        input: proto::receipt::receipts_response::Responses,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::receipt::receipts_response::Responses::{Fin, Receipts};
        match input {
            Receipts(r) => Ok(ReceiptsResponseKind::Receipts(
                TryFromProtobuf::try_from_protobuf(r, field_name)?,
            )),
            Fin(f) => Ok(ReceiptsResponseKind::Fin(
                TryFromProtobuf::try_from_protobuf(f, field_name)?,
            )),
        }
    }
}
