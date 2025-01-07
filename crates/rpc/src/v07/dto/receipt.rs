use pathfinder_common::prelude::*;
use pathfinder_serde::h256_as_no_leading_zeros_hex_str;

use crate::types::receipt;
use crate::types::reply::BlockStatus;
use crate::PendingData;

type CommonTransaction = pathfinder_common::transaction::Transaction;
type CommonReceipt = pathfinder_common::receipt::Receipt;
type CommonEvent = pathfinder_common::event::Event;

pub struct BlockWithReceipts {
    status: BlockStatus,
    header: crate::v07::dto::header::Header,
    body: BlockBodyWithReceipts,
}

impl crate::dto::SerializeForVersion for BlockWithReceipts {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("status", &self.status)?;
        serializer.flatten(&self.header)?;
        serializer.flatten(&self.body)?;
        serializer.end()
    }
}

pub struct PendingBlockWithReceipts {
    header: crate::v07::dto::header::PendingHeader,
    body: BlockBodyWithReceipts,
}

impl From<PendingData> for PendingBlockWithReceipts {
    fn from(value: PendingData) -> Self {
        let body = value
            .block
            .transactions
            .iter()
            .zip(value.block.transaction_receipts.iter())
            .map(|(t, (r, e))| (t.clone(), r.clone(), e.clone()))
            .collect::<Vec<_>>();

        let body = BlockBodyWithReceipts::from_common(body, receipt::FinalityStatus::AcceptedOnL2);

        Self {
            header: value.header().into(),
            body,
        }
    }
}

impl crate::dto::SerializeForVersion for PendingBlockWithReceipts {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.flatten(&self.header)?;
        serializer.flatten(&self.body)?;
        serializer.end()
    }
}

struct BlockBodyWithReceipts {
    transactions: Vec<TransactionWithReceipt>,
}

impl BlockBodyWithReceipts {
    fn from_common(
        value: Vec<(CommonTransaction, CommonReceipt, Vec<CommonEvent>)>,
        finality_status: receipt::FinalityStatus,
    ) -> Self {
        let transactions = value
            .into_iter()
            .map(|(t, r, e)| TransactionWithReceipt::from_common(t, r, e, finality_status))
            .collect();

        Self { transactions }
    }
}

impl crate::dto::SerializeForVersion for BlockBodyWithReceipts {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_iter(
            "transactions",
            self.transactions.len(),
            &mut self.transactions.iter(),
        )?;
        serializer.end()
    }
}

// Inner type of block with receipts
struct TransactionWithReceipt {
    transaction: crate::types::transaction::TransactionWithHash,
    receipt: PendingTxnReceipt,
}

impl TransactionWithReceipt {
    fn from_common(
        transaction: CommonTransaction,
        receipt: CommonReceipt,
        events: Vec<CommonEvent>,
        finality_status: receipt::FinalityStatus,
    ) -> Self {
        let receipt =
            PendingTxnReceipt::from_common(&transaction, receipt, events, finality_status);

        Self {
            transaction: transaction.into(),
            receipt,
        }
    }
}

impl crate::dto::SerializeForVersion for &TransactionWithReceipt {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("transaction", &self.transaction)?;
        serializer.serialize_field("receipt", &self.receipt)?;
        serializer.end()
    }
}

#[allow(unused)]
pub enum TxnReceipt {
    Invoke {
        common: CommonReceiptProperties,
    },
    L1Handler {
        message_hash: primitive_types::H256,
        common: CommonReceiptProperties,
    },
    Declare {
        common: CommonReceiptProperties,
    },
    Deploy {
        contract_address: ContractAddress,
        common: CommonReceiptProperties,
    },
    DeployAccount {
        contract_address: ContractAddress,
        common: CommonReceiptProperties,
    },
}

impl crate::dto::SerializeForVersion for TxnReceipt {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        match self {
            Self::Invoke { common } => {
                serializer.serialize_field("type", &"INVOKE")?;
                serializer.flatten(common)?;
            }
            Self::L1Handler {
                message_hash,
                common,
            } => {
                serializer.serialize_field("type", &"L1_HANDLER")?;
                serializer.serialize_field(
                    "message_hash",
                    &h256_as_no_leading_zeros_hex_str(message_hash),
                )?;
                serializer.flatten(common)?;
            }
            Self::Declare { common } => {
                serializer.serialize_field("type", &"DECLARE")?;
                serializer.flatten(common)?;
            }
            Self::Deploy {
                contract_address,
                common,
            } => {
                serializer.serialize_field("type", &"DEPLOY")?;
                serializer.serialize_field("contract_address", &contract_address)?;
                serializer.flatten(common)?;
            }
            Self::DeployAccount {
                contract_address,
                common,
            } => {
                serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                serializer.serialize_field("contract_address", &contract_address)?;
                serializer.flatten(common)?;
            }
        }
        serializer.end()
    }
}

pub enum PendingTxnReceipt {
    Invoke {
        common: PendingCommonReceiptProperties,
    },
    L1Handler {
        message_hash: primitive_types::H256,
        common: PendingCommonReceiptProperties,
    },
    Declare {
        common: PendingCommonReceiptProperties,
    },
    Deploy {
        contract_address: ContractAddress,
        common: PendingCommonReceiptProperties,
    },
    DeployAccount {
        contract_address: ContractAddress,
        common: PendingCommonReceiptProperties,
    },
}

impl crate::dto::SerializeForVersion for PendingTxnReceipt {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        match self {
            Self::Invoke { common } => {
                serializer.serialize_field("type", &"INVOKE")?;
                serializer.flatten(common)?;
            }
            Self::L1Handler {
                message_hash,
                common,
            } => {
                serializer.serialize_field("type", &"L1_HANDLER")?;
                serializer.serialize_field(
                    "message_hash",
                    &h256_as_no_leading_zeros_hex_str(message_hash),
                )?;
                serializer.flatten(common)?;
            }
            Self::Declare { common } => {
                serializer.serialize_field("type", &"DECLARE")?;
                serializer.flatten(common)?;
            }
            Self::Deploy {
                contract_address,
                common,
            } => {
                serializer.serialize_field("type", &"DEPLOY")?;
                serializer.serialize_field("contract_address", &contract_address)?;
                serializer.flatten(common)?;
            }
            Self::DeployAccount {
                contract_address,
                common,
            } => {
                serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                serializer.serialize_field("contract_address", &contract_address)?;
                serializer.flatten(common)?;
            }
        }
        serializer.end()
    }
}

impl PendingTxnReceipt {
    pub fn from_common(
        transaction: &CommonTransaction,
        receipt: CommonReceipt,
        events: Vec<CommonEvent>,
        finality_status: receipt::FinalityStatus,
    ) -> Self {
        let common = PendingCommonReceiptProperties::from_common(
            transaction,
            receipt,
            events,
            finality_status,
        );

        use pathfinder_common::transaction::TransactionVariant;
        match &transaction.variant {
            TransactionVariant::DeclareV0(_) => Self::Declare { common },
            TransactionVariant::DeclareV1(_) => Self::Declare { common },
            TransactionVariant::DeclareV2(_) => Self::Declare { common },
            TransactionVariant::DeclareV3(_) => Self::Declare { common },
            TransactionVariant::DeployV0(tx) => Self::Deploy {
                contract_address: tx.contract_address,
                common,
            },
            TransactionVariant::DeployV1(tx) => Self::Deploy {
                contract_address: tx.contract_address,
                common,
            },
            TransactionVariant::DeployAccountV1(tx) => Self::DeployAccount {
                contract_address: tx.contract_address,
                common,
            },
            TransactionVariant::DeployAccountV3(tx) => Self::DeployAccount {
                contract_address: tx.contract_address,
                common,
            },
            TransactionVariant::InvokeV0(_) => Self::Invoke { common },
            TransactionVariant::InvokeV1(_) => Self::Invoke { common },
            TransactionVariant::InvokeV3(_) => Self::Invoke { common },
            TransactionVariant::L1Handler(tx) => Self::L1Handler {
                message_hash: tx.calculate_message_hash(),
                common,
            },
        }
    }
}

pub struct ComputationResources(receipt::ExecutionResourcesProperties);

impl From<pathfinder_common::receipt::ExecutionResources> for ComputationResources {
    fn from(value: pathfinder_common::receipt::ExecutionResources) -> Self {
        Self(receipt::ExecutionResourcesProperties {
            steps: value.n_steps,
            memory_holes: value.n_memory_holes,
            range_check_builtin_applications: value.builtins.range_check,
            pedersen_builtin_applications: value.builtins.pedersen,
            poseidon_builtin_applications: value.builtins.poseidon,
            ec_op_builtin_applications: value.builtins.ec_op,
            ecdsa_builtin_applications: value.builtins.ecdsa,
            bitwise_builtin_applications: value.builtins.bitwise,
            keccak_builtin_applications: value.builtins.keccak,
            segment_arena_builtin: value.builtins.segment_arena,
        })
    }
}

impl crate::dto::SerializeForVersion for ComputationResources {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        self.0.serialize(serializer)
    }
}

pub struct ExecutionResources {
    computation_resources: ComputationResources,
    data_availability: DataResources,
}

impl From<pathfinder_common::receipt::ExecutionResources> for ExecutionResources {
    fn from(value: pathfinder_common::receipt::ExecutionResources) -> Self {
        Self {
            data_availability: value.data_availability.clone().into(),
            computation_resources: value.into(),
        }
    }
}

impl crate::dto::SerializeForVersion for ExecutionResources {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.flatten(&self.computation_resources)?;
        serializer.serialize_field("data_availability", &self.data_availability)?;
        serializer.end()
    }
}

/// An object embedded within EXECUTION_RESOURCES.
struct DataResources {
    l1_gas: u128,
    l1_data_gas: u128,
}

impl From<pathfinder_common::receipt::L1Gas> for DataResources {
    fn from(value: pathfinder_common::receipt::L1Gas) -> Self {
        Self {
            l1_gas: value.l1_gas,
            l1_data_gas: value.l1_data_gas,
        }
    }
}

impl crate::dto::SerializeForVersion for DataResources {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("l1_gas", &self.l1_gas)?;
        serializer.serialize_field("l1_data_gas", &self.l1_data_gas)?;
        serializer.end()
    }
}

pub struct CommonReceiptProperties {
    transaction_hash: TransactionHash,
    actual_fee: FeePayment,
    block_hash: BlockHash,
    block_number: BlockNumber,
    messages_sent: Vec<receipt::MessageToL1>,
    events: Vec<receipt::Event>,
    revert_reason: Option<String>,
    execution_resources: ExecutionResources,
    execution_status: receipt::ExecutionStatus,
    finality_status: receipt::FinalityStatus,
}

impl crate::dto::SerializeForVersion for CommonReceiptProperties {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("transaction_hash", &self.transaction_hash)?;
        serializer.serialize_field("actual_fee", &self.actual_fee)?;
        serializer.serialize_field("block_hash", &self.block_hash)?;
        serializer.serialize_field("block_number", &self.block_number)?;
        serializer.serialize_iter(
            "messages_sent",
            self.messages_sent.len(),
            &mut self.messages_sent.iter().cloned(),
        )?;
        serializer.serialize_iter(
            "events",
            self.events.len(),
            &mut self.events.iter().cloned(),
        )?;
        serializer.serialize_optional("revert_reason", self.revert_reason.clone())?;
        serializer.serialize_field("execution_resources", &self.execution_resources)?;
        serializer.serialize_field("execution_status", &self.execution_status)?;
        serializer.serialize_field("finality_status", &self.finality_status)?;
        serializer.end()
    }
}

pub struct PendingCommonReceiptProperties {
    transaction_hash: TransactionHash,
    actual_fee: FeePayment,
    messages_sent: Vec<receipt::MessageToL1>,
    events: Vec<receipt::Event>,
    revert_reason: Option<String>,
    execution_status: receipt::ExecutionStatus,
    execution_resources: ExecutionResources,
    finality_status: receipt::FinalityStatus,
}

impl PendingCommonReceiptProperties {
    fn from_common(
        transaction: &CommonTransaction,
        receipt: CommonReceipt,
        events: Vec<CommonEvent>,
        finality_status: receipt::FinalityStatus,
    ) -> Self {
        let actual_fee = FeePayment {
            amount: receipt.actual_fee,
            unit: transaction.version().into(),
        };

        let revert_reason = receipt.revert_reason().map(ToOwned::to_owned);
        let messages_sent = receipt
            .l2_to_l1_messages
            .into_iter()
            .map(Into::into)
            .collect();
        let events = events.into_iter().map(Into::into).collect();
        let execution_status = receipt.execution_status.into();
        let execution_resources = receipt.execution_resources.into();

        Self {
            transaction_hash: transaction.hash,
            actual_fee,
            messages_sent,
            events,
            revert_reason,
            execution_status,
            execution_resources,
            finality_status,
        }
    }
}

impl crate::dto::SerializeForVersion for PendingCommonReceiptProperties {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("transaction_hash", &self.transaction_hash)?;
        serializer.serialize_field("actual_fee", &self.actual_fee)?;
        serializer.serialize_iter(
            "messages_sent",
            self.messages_sent.len(),
            &mut self.messages_sent.iter().cloned(),
        )?;
        serializer.serialize_iter(
            "events",
            self.events.len(),
            &mut self.events.iter().cloned(),
        )?;
        serializer.serialize_optional("revert_reason", self.revert_reason.clone())?;
        serializer.serialize_field("execution_resources", &self.execution_resources)?;
        serializer.serialize_field("execution_status", &self.execution_status)?;
        serializer.serialize_field("finality_status", &self.finality_status)?;
        serializer.end()
    }
}

struct FeePayment {
    amount: Fee,
    unit: PriceUnit,
}

impl crate::dto::SerializeForVersion for FeePayment {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("amount", &self.amount)?;
        serializer.serialize_field("unit", &self.unit)?;
        serializer.end()
    }
}

pub enum PriceUnit {
    Wei,
    Fri,
}

impl From<TransactionVersion> for PriceUnit {
    fn from(value: TransactionVersion) -> Self {
        match value {
            TransactionVersion::ZERO | TransactionVersion::ONE | TransactionVersion::TWO => {
                PriceUnit::Wei
            }
            _ => PriceUnit::Fri,
        }
    }
}

impl crate::dto::SerializeForVersion for PriceUnit {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_str(match self {
            Self::Wei => "WEI",
            Self::Fri => "FRI",
        })
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;

    use super::*;
    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[test]
    fn txn_receipt() {
        let expected = serde_json::json!({
            "transaction_hash": "0x1",
            "block_hash": "0x3",
            "actual_fee": {
                "amount": "0x123",
                "unit": "WEI",
            },
            "block_number": 4,
            "messages_sent": [],
            "events": [],
            "execution_resources": {
                "steps": 10,
                "data_availability": {
                    "l1_gas": 0,
                    "l1_data_gas": 0,
                }
            },
            "execution_status": "SUCCEEDED",
            "finality_status": "ACCEPTED_ON_L2",
            "type": "INVOKE",
        });

        let uut = TxnReceipt::Invoke {
            common: CommonReceiptProperties {
                transaction_hash: transaction_hash!("0x1"),
                actual_fee: FeePayment {
                    amount: fee!("0x123"),
                    unit: PriceUnit::Wei,
                },
                block_hash: block_hash!("0x3"),
                block_number: BlockNumber::new_or_panic(4),
                messages_sent: vec![],
                events: vec![],
                revert_reason: None,
                execution_resources: ExecutionResources {
                    computation_resources: ComputationResources(
                        receipt::ExecutionResourcesProperties {
                            steps: 10,
                            memory_holes: 0,
                            range_check_builtin_applications: 0,
                            pedersen_builtin_applications: 0,
                            poseidon_builtin_applications: 0,
                            ec_op_builtin_applications: 0,
                            ecdsa_builtin_applications: 0,
                            bitwise_builtin_applications: 0,
                            keccak_builtin_applications: 0,
                            segment_arena_builtin: 0,
                        },
                    ),
                    data_availability: DataResources {
                        l1_gas: 0,
                        l1_data_gas: 0,
                    },
                },
                execution_status: receipt::ExecutionStatus::Succeeded,
                finality_status: receipt::FinalityStatus::AcceptedOnL2,
            },
        };

        let encoded = uut
            .serialize(Serializer {
                version: RpcVersion::V07,
            })
            .unwrap();

        assert_eq!(encoded, expected);
    }
    #[test]
    fn pending_txn_receipt() {
        let expected = serde_json::json!({
            "transaction_hash": "0x1",
            "actual_fee": {
                "amount": "0x123",
                "unit": "WEI",
            },
            "messages_sent": [],
            "events": [],
            "execution_resources": {
                "steps": 10,
                "data_availability": {
                    "l1_gas": 0,
                    "l1_data_gas": 0,
                }
            },
            "execution_status": "SUCCEEDED",
            "finality_status": "ACCEPTED_ON_L2",
            "type": "INVOKE",
        });

        let uut = PendingTxnReceipt::Invoke {
            common: PendingCommonReceiptProperties {
                transaction_hash: transaction_hash!("0x1"),
                actual_fee: FeePayment {
                    amount: fee!("0x123"),
                    unit: PriceUnit::Wei,
                },
                messages_sent: vec![],
                events: vec![],
                revert_reason: None,
                execution_resources: ExecutionResources {
                    computation_resources: ComputationResources(
                        receipt::ExecutionResourcesProperties {
                            steps: 10,
                            memory_holes: 0,
                            range_check_builtin_applications: 0,
                            pedersen_builtin_applications: 0,
                            poseidon_builtin_applications: 0,
                            ec_op_builtin_applications: 0,
                            ecdsa_builtin_applications: 0,
                            bitwise_builtin_applications: 0,
                            keccak_builtin_applications: 0,
                            segment_arena_builtin: 0,
                        },
                    ),
                    data_availability: DataResources {
                        l1_gas: 0,
                        l1_data_gas: 0,
                    },
                },
                execution_status: receipt::ExecutionStatus::Succeeded,
                finality_status: receipt::FinalityStatus::AcceptedOnL2,
            },
        };

        let encoded = uut
            .serialize(Serializer {
                version: RpcVersion::V07,
            })
            .unwrap();
        assert_eq!(encoded, expected);
    }
}
