use pathfinder_common::prelude::*;
use pathfinder_serde::H256AsNoLeadingZerosHexStr;
use serde::Serialize;

use crate::v02::types::reply::BlockStatus;
use crate::v06::method::get_transaction_receipt::types as v06;
use crate::PendingData;

#[derive(Serialize)]
pub struct BlockWithReceipts {
    status: BlockStatus,
    #[serde(flatten)]
    header: crate::v07::dto::header::Header,
    #[serde(flatten)]
    body: BlockBodyWithReceipts,
}

#[derive(Serialize)]
pub struct PendingBlockWithReceipts {
    #[serde(flatten)]
    header: crate::v07::dto::header::PendingHeader,
    #[serde(flatten)]
    body: BlockBodyWithReceipts,
}

type CommonTransaction = pathfinder_common::transaction::Transaction;
type CommonReceipt = pathfinder_common::receipt::Receipt;
type CommonEvent = pathfinder_common::event::Event;

impl From<PendingData> for PendingBlockWithReceipts {
    fn from(value: PendingData) -> Self {
        let body = value
            .block
            .transactions
            .iter()
            .zip(value.block.transaction_receipts.iter())
            .map(|(t, (r, e))| (t.clone(), r.clone(), e.clone()))
            .collect::<Vec<_>>();

        let body = BlockBodyWithReceipts::from_common(body, v06::FinalityStatus::AcceptedOnL2);

        Self {
            header: value.header().into(),
            body,
        }
    }
}

#[derive(Serialize)]
struct BlockBodyWithReceipts {
    transactions: Vec<TransactionWithReceipt>,
}

impl BlockBodyWithReceipts {
    fn from_common(
        value: Vec<(CommonTransaction, CommonReceipt, Vec<CommonEvent>)>,
        finality_status: v06::FinalityStatus,
    ) -> Self {
        let transactions = value
            .into_iter()
            .map(|(t, r, e)| TransactionWithReceipt::from_common(t, r, e, finality_status))
            .collect();

        Self { transactions }
    }
}

#[derive(Serialize)]
// Inner type of block with receipts
struct TransactionWithReceipt {
    transaction: crate::v06::types::TransactionWithHash,
    receipt: PendingTxnReceipt,
}

impl TransactionWithReceipt {
    fn from_common(
        transaction: CommonTransaction,
        receipt: CommonReceipt,
        events: Vec<CommonEvent>,
        finality_status: v06::FinalityStatus,
    ) -> Self {
        let receipt =
            PendingTxnReceipt::from_common(&transaction, receipt, events, finality_status);

        Self {
            transaction: transaction.into(),
            receipt,
        }
    }
}

#[serde_with::serde_as]
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(unused)]
pub enum TxnReceipt {
    Invoke {
        #[serde(flatten)]
        common: CommonReceiptProperties,
    },
    L1Handler {
        #[serde_as(as = "H256AsNoLeadingZerosHexStr")]
        message_hash: primitive_types::H256,
        #[serde(flatten)]
        common: CommonReceiptProperties,
    },
    Declare {
        #[serde(flatten)]
        common: CommonReceiptProperties,
    },
    Deploy {
        contract_address: ContractAddress,
        #[serde(flatten)]
        common: CommonReceiptProperties,
    },
    DeployAccount {
        contract_address: ContractAddress,
        #[serde(flatten)]
        common: CommonReceiptProperties,
    },
}

#[serde_with::serde_as]
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PendingTxnReceipt {
    Invoke {
        #[serde(flatten)]
        common: PendingCommonReceiptProperties,
    },
    L1Handler {
        #[serde_as(as = "H256AsNoLeadingZerosHexStr")]
        message_hash: primitive_types::H256,
        #[serde(flatten)]
        common: PendingCommonReceiptProperties,
    },
    Declare {
        #[serde(flatten)]
        common: PendingCommonReceiptProperties,
    },
    Deploy {
        contract_address: ContractAddress,
        #[serde(flatten)]
        common: PendingCommonReceiptProperties,
    },
    DeployAccount {
        contract_address: ContractAddress,
        #[serde(flatten)]
        common: PendingCommonReceiptProperties,
    },
}

impl PendingTxnReceipt {
    pub fn from_common(
        transaction: &CommonTransaction,
        receipt: CommonReceipt,
        events: Vec<CommonEvent>,
        finality_status: v06::FinalityStatus,
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

#[derive(Serialize)]
pub struct ComputationResources(v06::ExecutionResourcesProperties);

impl From<pathfinder_common::receipt::ExecutionResources> for ComputationResources {
    fn from(value: pathfinder_common::receipt::ExecutionResources) -> Self {
        Self(v06::ExecutionResourcesProperties {
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

#[derive(Serialize)]
pub struct ExecutionResources {
    #[serde(flatten)]
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

#[derive(Serialize)]
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

#[derive(Serialize)]
pub struct CommonReceiptProperties {
    transaction_hash: TransactionHash,
    actual_fee: FeePayment,
    block_hash: BlockHash,
    block_number: BlockNumber,
    messages_sent: Vec<v06::MessageToL1>,
    events: Vec<v06::Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revert_reason: Option<String>,
    execution_resources: ExecutionResources,
    execution_status: v06::ExecutionStatus,
    finality_status: v06::FinalityStatus,
}

#[derive(Serialize)]
pub struct PendingCommonReceiptProperties {
    transaction_hash: TransactionHash,
    actual_fee: FeePayment,
    messages_sent: Vec<v06::MessageToL1>,
    events: Vec<v06::Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revert_reason: Option<String>,
    execution_status: v06::ExecutionStatus,
    execution_resources: ExecutionResources,
    finality_status: v06::FinalityStatus,
}

impl PendingCommonReceiptProperties {
    fn from_common(
        transaction: &CommonTransaction,
        receipt: CommonReceipt,
        events: Vec<CommonEvent>,
        finality_status: v06::FinalityStatus,
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

#[derive(Serialize)]
struct FeePayment {
    amount: Fee,
    unit: PriceUnit,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;

    use super::*;

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
                        v06::ExecutionResourcesProperties {
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
                execution_status: v06::ExecutionStatus::Succeeded,
                finality_status: v06::FinalityStatus::AcceptedOnL2,
            },
        };

        let encoded = serde_json::to_value(uut).unwrap();

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
                        v06::ExecutionResourcesProperties {
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
                execution_status: v06::ExecutionStatus::Succeeded,
                finality_status: v06::FinalityStatus::AcceptedOnL2,
            },
        };

        let encoded = serde_json::to_value(uut).unwrap();
        assert_eq!(encoded, expected);
    }
}
