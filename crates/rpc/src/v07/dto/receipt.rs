use pathfinder_serde::H256AsNoLeadingZerosHexStr;
use serde::Serialize;

use pathfinder_common::prelude::*;

use crate::v06::method::get_transaction_receipt::types as v06;

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
        common: CommonPendingReceiptProperties,
    },
    L1Handler {
        #[serde_as(as = "H256AsNoLeadingZerosHexStr")]
        message_hash: primitive_types::H256,
        #[serde(flatten)]
        common: CommonPendingReceiptProperties,
    },
    Declare {
        #[serde(flatten)]
        common: CommonPendingReceiptProperties,
    },
    Deploy {
        contract_address: ContractAddress,
        #[serde(flatten)]
        common: CommonPendingReceiptProperties,
    },
    DeployAccount {
        contract_address: ContractAddress,
        #[serde(flatten)]
        common: CommonPendingReceiptProperties,
    },
}

#[derive(Serialize)]
pub struct ComputationResources(v06::ExecutionResourcesPropertiesV06);

impl From<pathfinder_common::receipt::ExecutionResources> for ComputationResources {
    fn from(value: pathfinder_common::receipt::ExecutionResources) -> Self {
        Self(v06::ExecutionResourcesPropertiesV06 {
            steps: value.n_steps,
            memory_holes: value.n_memory_holes,
            range_check_builtin_applications: value.builtin_instance_counter.range_check_builtin,
            pedersen_builtin_applications: value.builtin_instance_counter.pedersen_builtin,
            poseidon_builtin_applications: value.builtin_instance_counter.poseidon_builtin,
            ec_op_builtin_applications: value.builtin_instance_counter.ec_op_builtin,
            ecdsa_builtin_applications: value.builtin_instance_counter.ecdsa_builtin,
            bitwise_builtin_applications: value.builtin_instance_counter.bitwise_builtin,
            keccak_builtin_applications: value.builtin_instance_counter.keccak_builtin,
            segment_arena_builtin: value.builtin_instance_counter.segment_arena_builtin,
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

impl From<pathfinder_common::receipt::ExecutionDataAvailability> for DataResources {
    fn from(value: pathfinder_common::receipt::ExecutionDataAvailability) -> Self {
        Self {
            l1_gas: value.l1_gas,
            l1_data_gas: value.l1_data_gas,
        }
    }
}

#[derive(Serialize)]
pub struct CommonReceiptProperties {
    pub transaction_hash: TransactionHash,
    pub actual_fee: FeePayment,
    pub block_hash: BlockHash,
    pub block_number: BlockNumber,
    pub messages_sent: Vec<v06::MessageToL1>,
    pub events: Vec<v06::Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    pub execution_resources: ExecutionResources,
    pub execution_status: v06::ExecutionStatus,
    pub finality_status: v06::FinalityStatus,
}

#[derive(Serialize)]
pub struct CommonPendingReceiptProperties {
    pub transaction_hash: TransactionHash,
    pub actual_fee: FeePayment,
    pub messages_sent: Vec<v06::MessageToL1>,
    pub events: Vec<v06::Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    pub execution_status: v06::ExecutionStatus,
    pub execution_resources: ExecutionResources,
    pub finality_status: v06::FinalityStatus,
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

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;

    use pretty_assertions_sorted::assert_eq;

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
                        v06::ExecutionResourcesPropertiesV06 {
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
            common: CommonPendingReceiptProperties {
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
                        v06::ExecutionResourcesPropertiesV06 {
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
