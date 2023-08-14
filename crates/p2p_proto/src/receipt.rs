use crate::{common::BlockId, proto, ToProtobuf, TryFromProtobuf};
use fake::{Dummy, Fake, Faker};
use primitive_types::H160;
use stark_hash::Felt;

// Avoid pathfinder_common dependency
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EthereumAddress(pub H160);

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

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::receipt::MessageToL1")]
pub struct MessageToL1 {
    pub from_address: Felt,
    pub payload: Vec<Felt>,
    pub to_address: EthereumAddress,
}

impl<T> Dummy<T> for MessageToL1 {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &T, rng: &mut R) -> Self {
        Self {
            from_address: Felt::dummy_with_rng(config, rng),
            payload: Faker.fake_with_rng(rng),
            to_address: EthereumAddress::dummy_with_rng(config, rng),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::receipt::MessageToL2")]
pub struct MessageToL2 {
    pub from_address: EthereumAddress,
    pub payload: Vec<Felt>,
    pub to_address: Felt,
    pub entry_point_selector: Felt,
    pub nonce: Felt,
}

impl<T> Dummy<T> for MessageToL2 {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &T, rng: &mut R) -> Self {
        Self {
            from_address: EthereumAddress::dummy_with_rng(config, rng),
            payload: Faker.fake_with_rng(rng),
            to_address: Faker.fake_with_rng(rng),
            entry_point_selector: Faker.fake_with_rng(rng),
            nonce: Faker.fake_with_rng(rng),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::ExecutionResources")]
pub struct ExecutionResources {
    pub builtin_instance_counter: execution_resources::BuiltinInstanceCounter,
    pub n_steps: u64,
    pub n_memory_holes: u64,
}

pub mod execution_resources {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
    #[protobuf(name = "crate::proto::receipt::execution_resources::BuiltinInstanceCounter")]
    pub struct BuiltinInstanceCounter {
        pub bitwise_builtin: u64,
        pub ecdsa_builtin: u64,
        pub ec_op_builtin: u64,
        pub output_builtin: u64,
        pub pedersen_builtin: u64,
        pub range_check_builtin: u64,
        pub keccak_builtin: u64,
        pub poseidon_builtin: u64,
        pub segment_arena_builtin: u64,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::CommonTransactionReceiptProperties")]
pub struct CommonTransactionReceiptProperties {
    pub transaction_hash: Felt,
    pub transaction_index: u32,
    pub actual_fee: Felt,
    pub messages_sent: Vec<MessageToL1>,
    #[optional]
    pub consumed_message: Option<MessageToL2>,
    pub execution_resources: ExecutionResources,
    pub execution_status: ExecutionStatus,
    pub revert_error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum ExecutionStatus {
    Succeeded,
    Reverted,
}

impl TryFromProtobuf<i32> for ExecutionStatus {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        let status = proto::receipt::ExecutionStatus::from_i32(input).ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to convert protobuf output for {field_name}: {input} did not match any known execution status"),
        ))?;

        match status {
            proto::receipt::ExecutionStatus::Succeeded => Ok(Self::Succeeded),
            proto::receipt::ExecutionStatus::Reverted => Ok(Self::Reverted),
        }
    }
}

impl ToProtobuf<proto::receipt::ExecutionStatus> for ExecutionStatus {
    fn to_protobuf(self) -> proto::receipt::ExecutionStatus {
        match self {
            ExecutionStatus::Succeeded => proto::receipt::ExecutionStatus::Succeeded,
            ExecutionStatus::Reverted => proto::receipt::ExecutionStatus::Reverted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::InvokeTransactionReceipt")]
pub struct InvokeTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::L1HandlerTransactionReceipt")]
pub struct L1HandlerTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::DeclareTransactionReceipt")]
pub struct DeclareTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::DeprecatedDeployTransactionReceipt")]
pub struct DeployTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,

    pub contract_address: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::DeployAccountTransactionReceipt")]
pub struct DeployAccountTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,

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
#[protobuf(name = "crate::proto::receipt::GetReceipts")]
pub struct GetReceipts {
    pub id: BlockId,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::receipt::Receipts")]
pub struct Receipts {
    pub receipts: Vec<Receipt>,
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
