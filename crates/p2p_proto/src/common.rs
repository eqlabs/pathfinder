#[cfg(feature = "test-utils")]
use fake::{Dummy, Fake, Faker};
use stark_hash::Felt;

use crate::{ToProtobuf, TryFromProtobuf};

use super::proto;

#[derive(Debug, Default, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::BlockHeader")]
pub struct BlockHeader {
    pub block_hash: Felt,
    pub parent_block_hash: Felt,
    pub block_number: u64,
    pub state_commitment: Felt,
    pub sequencer_address: Felt,
    pub block_timestamp: u64,
    pub gas_price: Felt,
    pub transaction_count: u32,
    pub transaction_commitment: Felt,
    pub event_count: u32,
    pub event_commitment: Felt,
    pub starknet_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::BlockBody")]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
    pub receipts: Vec<Receipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
pub enum Transaction {
    Invoke(InvokeTransaction),
    Declare(DeclareTransaction),
    Deploy(DeployTransaction),
    L1Handler(L1HandlerTransaction),
    DeployAccount(DeployAccountTransaction),
}

impl TryFromProtobuf<proto::common::Transaction> for Transaction {
    fn try_from_protobuf(
        input: proto::common::Transaction,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        match input.txn {
            Some(tx) => match tx {
                proto::common::transaction::Txn::Invoke(i) => Ok(Transaction::Invoke(
                    TryFromProtobuf::try_from_protobuf(i, "txn")?,
                )),
                proto::common::transaction::Txn::Declare(d) => Ok(Transaction::Declare(
                    TryFromProtobuf::try_from_protobuf(d, "txn")?,
                )),
                proto::common::transaction::Txn::Deploy(d) => Ok(Transaction::Deploy(
                    TryFromProtobuf::try_from_protobuf(d, "txn")?,
                )),
                proto::common::transaction::Txn::L1Handler(l1) => Ok(Transaction::L1Handler(
                    TryFromProtobuf::try_from_protobuf(l1, "txn")?,
                )),
                proto::common::transaction::Txn::DeployAccount(d) => Ok(
                    Transaction::DeployAccount(TryFromProtobuf::try_from_protobuf(d, "txn")?),
                ),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse {field_name}: missing txn field"),
            )),
        }
    }
}

impl ToProtobuf<proto::common::Transaction> for Transaction {
    fn to_protobuf(self) -> proto::common::Transaction {
        let txn = Some(match self {
            Transaction::Invoke(tx) => proto::common::transaction::Txn::Invoke(tx.to_protobuf()),
            Transaction::Declare(tx) => proto::common::transaction::Txn::Declare(tx.to_protobuf()),
            Transaction::Deploy(tx) => proto::common::transaction::Txn::Deploy(tx.to_protobuf()),
            Transaction::L1Handler(tx) => {
                proto::common::transaction::Txn::L1Handler(tx.to_protobuf())
            }
            Transaction::DeployAccount(tx) => {
                proto::common::transaction::Txn::DeployAccount(tx.to_protobuf())
            }
        });
        proto::common::Transaction { txn }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::InvokeTransaction")]
pub struct InvokeTransaction {
    pub contract_address: Felt,
    pub deprecated_entry_point_selector: Option<invoke_transaction::EntryPoint>,
    pub calldata: Vec<Felt>,
    pub signature: Vec<Felt>,
    pub max_fee: Felt,
    pub nonce: Felt,
    pub version: Felt,
}

impl TryFromProtobuf<crate::proto::common::InvokeTransaction> for InvokeTransaction {
    fn try_from_protobuf(
        input: crate::proto::common::InvokeTransaction,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            contract_address: TryFromProtobuf::try_from_protobuf(
                input.contract_address,
                field_name,
            )?,
            deprecated_entry_point_selector: match input.deprecated_entry_point_selector {
                Some(x) => Some(TryFromProtobuf::try_from_protobuf(x, field_name)?),
                None => None,
            },
            calldata: TryFromProtobuf::try_from_protobuf(input.calldata, field_name)?,
            signature: TryFromProtobuf::try_from_protobuf(input.signature, field_name)?,
            max_fee: TryFromProtobuf::try_from_protobuf(input.max_fee, field_name)?,
            nonce: TryFromProtobuf::try_from_protobuf(input.nonce, field_name)?,
            version: TryFromProtobuf::try_from_protobuf(input.version, field_name)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::L1HandlerTransaction")]
pub struct L1HandlerTransaction {
    pub contract_address: Felt,
    pub entry_point_selector: Felt,
    pub calldata: Vec<Felt>,
    pub nonce: Felt,
    pub version: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::DeclareTransaction")]
pub struct DeclareTransaction {
    pub contract_class_hash: Felt,
    pub sender_address: Felt,
    pub signature: Vec<Felt>,
    pub max_fee: Felt,
    pub nonce: Felt,
    pub version: Felt,
    pub compiled_class_hash: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::DeployAccountTransaction")]
pub struct DeployAccountTransaction {
    pub contract_address_salt: Felt,
    pub constructor_calldata: Vec<Felt>,
    pub class_hash: Felt,
    pub max_fee: Felt,
    pub signature: Vec<Felt>,
    pub nonce: Felt,
    pub version: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::DeprecatedDeployTransaction")]
pub struct DeployTransaction {
    pub contract_class_hash: Felt,
    pub contract_address_salt: Felt,
    pub constructor_calldata: Vec<Felt>,
    pub version: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::CompressedContractClass")]
pub struct CompressedContractClass {
    pub class: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::Event")]
pub struct Event {
    pub from_address: Felt,
    pub keys: Vec<Felt>,
    pub data: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::common::MessageToL1")]
pub struct MessageToL1 {
    pub from_address: Felt,
    pub payload: Vec<Felt>,
    pub to_address: primitive_types::H160,
}

#[cfg(feature = "test-utils")]
impl<T> Dummy<T> for MessageToL1 {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, _: &mut R) -> Self {
        Self {
            from_address: Faker.fake(),
            payload: Faker.fake(),
            to_address: primitive_types::H160::random(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::common::MessageToL2")]
pub struct MessageToL2 {
    pub from_address: primitive_types::H160,
    pub payload: Vec<Felt>,
    pub to_address: Felt,
    pub entry_point_selector: Felt,
    pub nonce: Felt,
}

#[cfg(feature = "test-utils")]
impl<T> Dummy<T> for MessageToL2 {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, _: &mut R) -> Self {
        Self {
            from_address: primitive_types::H160::random(),
            payload: Faker.fake(),
            to_address: Faker.fake(),
            entry_point_selector: Faker.fake(),
            nonce: Faker.fake(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::ExecutionResources")]
pub struct ExecutionResources {
    pub builtin_instance_counter: execution_resources::BuiltinInstanceCounter,
    pub n_steps: u64,
    pub n_memory_holes: u64,
}

pub mod execution_resources {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
    #[cfg_attr(feature = "test-utils", derive(Dummy))]
    #[protobuf(name = "crate::proto::common::execution_resources::BuiltinInstanceCounter")]
    pub struct BuiltinInstanceCounter {
        pub bitwise_builtin: u64,
        pub ecdsa_builtin: u64,
        pub ec_op_builtin: u64,
        pub output_builtin: u64,
        pub pedersen_builtin: u64,
        pub range_check_builtin: u64,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::CommonTransactionReceiptProperties")]
pub struct CommonTransactionReceiptProperties {
    pub transaction_hash: Felt,
    pub transaction_index: u32,
    pub actual_fee: Felt,
    pub messages_sent: Vec<MessageToL1>,
    pub events: Vec<Event>,
    pub consumed_message: Option<MessageToL2>,
    pub execution_resources: ExecutionResources,
}

impl TryFromProtobuf<crate::proto::common::CommonTransactionReceiptProperties>
    for CommonTransactionReceiptProperties
{
    fn try_from_protobuf(
        input: crate::proto::common::CommonTransactionReceiptProperties,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            transaction_hash: TryFromProtobuf::try_from_protobuf(
                input.transaction_hash,
                field_name,
            )?,
            transaction_index: TryFromProtobuf::try_from_protobuf(
                input.transaction_index,
                field_name,
            )?,
            actual_fee: TryFromProtobuf::try_from_protobuf(input.actual_fee, field_name)?,
            messages_sent: TryFromProtobuf::try_from_protobuf(input.messages_sent, field_name)?,
            events: TryFromProtobuf::try_from_protobuf(input.events, field_name)?,
            consumed_message: match input.consumed_message {
                Some(x) => Some(TryFromProtobuf::try_from_protobuf(x, field_name)?),
                None => None,
            },
            execution_resources: TryFromProtobuf::try_from_protobuf(
                input.execution_resources,
                field_name,
            )?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::InvokeTransactionReceipt")]
pub struct InvokeTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::L1HandlerTransactionReceipt")]
pub struct L1HandlerTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::DeclareTransactionReceipt")]
pub struct DeclareTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::DeprecatedDeployTransactionReceipt")]
pub struct DeployTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,

    pub contract_address: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::common::DeployAccountTransactionReceipt")]
pub struct DeployAccountTransactionReceipt {
    pub common: CommonTransactionReceiptProperties,

    pub contract_address: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]

pub enum Receipt {
    Invoke(InvokeTransactionReceipt),
    Declare(DeclareTransactionReceipt),
    Deploy(DeployTransactionReceipt),
    DeployAccount(DeployAccountTransactionReceipt),
    L1Handler(L1HandlerTransactionReceipt),
}

impl TryFromProtobuf<proto::common::Receipt> for Receipt {
    fn try_from_protobuf(
        input: proto::common::Receipt,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        match input.receipt {
            Some(receipt) => match receipt {
                proto::common::receipt::Receipt::Invoke(r) => Ok(Receipt::Invoke(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::common::receipt::Receipt::L1Handler(r) => Ok(Receipt::L1Handler(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::common::receipt::Receipt::Declare(r) => Ok(Receipt::Declare(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::common::receipt::Receipt::DeprecatedDeploy(r) => Ok(Receipt::Deploy(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::common::receipt::Receipt::DeployAccount(r) => Ok(Receipt::DeployAccount(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse {field_name}: missing receipt field"),
            )),
        }
    }
}

impl ToProtobuf<proto::common::Receipt> for Receipt {
    fn to_protobuf(self) -> proto::common::Receipt {
        let receipt = Some(match self {
            Receipt::Invoke(r) => proto::common::receipt::Receipt::Invoke(r.to_protobuf()),
            Receipt::Declare(r) => proto::common::receipt::Receipt::Declare(r.to_protobuf()),
            Receipt::Deploy(r) => {
                proto::common::receipt::Receipt::DeprecatedDeploy(r.to_protobuf())
            }
            Receipt::DeployAccount(r) => {
                proto::common::receipt::Receipt::DeployAccount(r.to_protobuf())
            }
            Receipt::L1Handler(r) => proto::common::receipt::Receipt::L1Handler(r.to_protobuf()),
        });
        proto::common::Receipt { receipt }
    }
}

pub mod invoke_transaction {
    use crate::proto;
    use crate::{ToProtobuf, TryFromProtobuf};
    #[cfg(feature = "test-utils")]
    use fake::Dummy;
    use stark_hash::Felt;

    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "test-utils", derive(Dummy))]
    pub enum EntryPoint {
        Unspecified(Felt),
        External(Felt),
        L1Handler(Felt),
    }

    impl TryFromProtobuf<proto::common::invoke_transaction::DeprecatedEntryPoint> for EntryPoint {
        fn try_from_protobuf(
            input: proto::common::invoke_transaction::DeprecatedEntryPoint,
            field_name: &'static str,
        ) -> Result<Self, std::io::Error> {
            match input.r#type {
                Some(r#type) => match r#type {
                    proto::common::invoke_transaction::deprecated_entry_point::Type::Unspecified(x) => Ok(
                        EntryPoint::Unspecified(TryFromProtobuf::try_from_protobuf(x, field_name)?),
                    ),
                    proto::common::invoke_transaction::deprecated_entry_point::Type::External(x) => Ok(
                        EntryPoint::External(TryFromProtobuf::try_from_protobuf(x, field_name)?),
                    ),
                    proto::common::invoke_transaction::deprecated_entry_point::Type::L1Handler(x) => Ok(
                        EntryPoint::L1Handler(TryFromProtobuf::try_from_protobuf(x, field_name)?),
                    ),
                },
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse {field_name}: missing type field"),
                )),
            }
        }
    }

    impl ToProtobuf<proto::common::invoke_transaction::DeprecatedEntryPoint> for EntryPoint {
        fn to_protobuf(self) -> proto::common::invoke_transaction::DeprecatedEntryPoint {
            let r#type = Some(match self {
                EntryPoint::Unspecified(e) => {
                    proto::common::invoke_transaction::deprecated_entry_point::Type::Unspecified(
                        e.to_protobuf(),
                    )
                }
                EntryPoint::External(e) => {
                    proto::common::invoke_transaction::deprecated_entry_point::Type::External(
                        e.to_protobuf(),
                    )
                }
                EntryPoint::L1Handler(e) => {
                    proto::common::invoke_transaction::deprecated_entry_point::Type::L1Handler(
                        e.to_protobuf(),
                    )
                }
            });
            proto::common::invoke_transaction::DeprecatedEntryPoint { r#type }
        }
    }
}
