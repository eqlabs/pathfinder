use std::num::NonZeroU64;

use primitive_types::H256;

use crate::dto::serialize::SerializeForVersion;
use crate::{dto::*, RpcVersion};

use super::serialize;

pub struct TxnReceipt<'a> {
    pub receipt: &'a pathfinder_common::receipt::Receipt,
    pub transaction: &'a pathfinder_common::transaction::Transaction,
    pub finality: TxnFinalityStatus,
    pub block_hash: &'a pathfinder_common::BlockHash,
    pub block_number: pathfinder_common::BlockNumber,
}

pub struct PendingTxnReceipt<'a> {
    pub receipt: &'a pathfinder_common::receipt::Receipt,
    pub transaction: &'a pathfinder_common::transaction::Transaction,
}

struct CommonReceiptProperties<'a> {
    receipt: &'a pathfinder_common::receipt::Receipt,
    version: &'a pathfinder_common::TransactionVersion,
    finality: TxnFinalityStatus,
    block_hash: &'a pathfinder_common::BlockHash,
    block_number: pathfinder_common::BlockNumber,
}

struct PendingCommonReceiptProperties<'a> {
    receipt: &'a pathfinder_common::receipt::Receipt,
    version: &'a pathfinder_common::TransactionVersion,
}

struct FeePayment<'a> {
    amount: Option<&'a pathfinder_common::Fee>,
    version: &'a pathfinder_common::TransactionVersion,
}

struct PriceUnit<'a>(&'a pathfinder_common::TransactionVersion);

struct ExecutionResources<'a>(&'a pathfinder_common::receipt::ExecutionResources);
struct ComputationResources<'a>(&'a pathfinder_common::receipt::ExecutionResources);

#[derive(Copy, Clone)]
enum TxnExecutionStatus {
    Succeeded,
    Reverted,
}

#[derive(Copy, Clone)]
pub enum TxnFinalityStatus {
    AcceptedOnL2,
    AcceptedOnL1,
}

struct MsgToL1<'a>(pub &'a pathfinder_common::receipt::L2ToL1Message);

struct InvokeTxnReceipt<'a> {
    common: CommonReceiptProperties<'a>,
}

struct L1HandlerTxnReceipt<'a> {
    common: CommonReceiptProperties<'a>,
    message_hash: &'a H256,
}

struct DeclareTxnReceipt<'a> {
    common: CommonReceiptProperties<'a>,
}

struct DeployTxnReceipt<'a> {
    common: CommonReceiptProperties<'a>,
    contract_address: &'a pathfinder_common::ContractAddress,
}

struct DeployAccountTxnReceipt<'a> {
    common: CommonReceiptProperties<'a>,
    contract_address: &'a pathfinder_common::ContractAddress,
}

struct PendingInvokeTxnReceipt<'a> {
    common: PendingCommonReceiptProperties<'a>,
}

struct PendingL1HandlerTxnReceipt<'a> {
    common: PendingCommonReceiptProperties<'a>,
    message_hash: &'a H256,
}

struct PendingDeclareTxnReceipt<'a> {
    common: PendingCommonReceiptProperties<'a>,
}

struct PendingDeployAccountTxnReceipt<'a> {
    common: PendingCommonReceiptProperties<'a>,
    contract_address: &'a pathfinder_common::ContractAddress,
}

enum TxnType {
    Declare,
    Deploy,
    DeployAccount,
    Invoke,
    L1Handler,
}

impl SerializeForVersion for TxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let common = CommonReceiptProperties {
            receipt: self.receipt,
            finality: self.finality,
            block_hash: self.block_hash,
            block_number: self.block_number,
            version: &self.transaction.version(),
        };
        use pathfinder_common::transaction::TransactionVariant;
        match &self.transaction.variant {
            TransactionVariant::DeclareV0(_)
            | TransactionVariant::DeclareV1(_)
            | TransactionVariant::DeclareV2(_)
            | TransactionVariant::DeclareV3(_) => {
                DeclareTxnReceipt { common }.serialize(serializer)
            }
            TransactionVariant::Deploy(tx) => DeployTxnReceipt {
                common,
                contract_address: &tx.contract_address,
            }
            .serialize(serializer),
            TransactionVariant::DeployAccountV0V1(tx) => DeployAccountTxnReceipt {
                common,
                contract_address: &tx.contract_address,
            }
            .serialize(serializer),
            TransactionVariant::DeployAccountV3(tx) => DeployAccountTxnReceipt {
                common,
                contract_address: &tx.contract_address,
            }
            .serialize(serializer),
            TransactionVariant::InvokeV0(_)
            | TransactionVariant::InvokeV1(_)
            | TransactionVariant::InvokeV3(_) => InvokeTxnReceipt { common }.serialize(serializer),
            TransactionVariant::L1Handler(tx) => L1HandlerTxnReceipt {
                common,
                message_hash: &tx.calculate_message_hash(),
            }
            .serialize(serializer),
        }
    }
}

impl SerializeForVersion for PendingTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let common = PendingCommonReceiptProperties {
            receipt: self.receipt,
            version: &self.transaction.version(),
        };
        use pathfinder_common::transaction::TransactionVariant;
        match &self.transaction.variant {
            TransactionVariant::DeclareV0(_)
            | TransactionVariant::DeclareV1(_)
            | TransactionVariant::DeclareV2(_)
            | TransactionVariant::DeclareV3(_) => {
                PendingDeclareTxnReceipt { common }.serialize(serializer)
            }
            // This should no longer be possible to receive for a pending transaction.
            // These are legacy only transactions.
            TransactionVariant::Deploy(tx) => PendingDeployAccountTxnReceipt {
                common,
                contract_address: &tx.contract_address,
            }
            .serialize(serializer),
            TransactionVariant::DeployAccountV0V1(tx) => PendingDeployAccountTxnReceipt {
                common,
                contract_address: &tx.contract_address,
            }
            .serialize(serializer),
            TransactionVariant::DeployAccountV3(tx) => PendingDeployAccountTxnReceipt {
                common,
                contract_address: &tx.contract_address,
            }
            .serialize(serializer),
            TransactionVariant::InvokeV0(_)
            | TransactionVariant::InvokeV1(_)
            | TransactionVariant::InvokeV3(_) => {
                PendingInvokeTxnReceipt { common }.serialize(serializer)
            }
            TransactionVariant::L1Handler(tx) => PendingL1HandlerTxnReceipt {
                common,
                message_hash: &tx.calculate_message_hash(),
            }
            .serialize(serializer),
        }
    }
}

impl SerializeForVersion for InvokeTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"INVOKE")?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for PendingInvokeTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"INVOKE")?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for DeployTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"DEPLOY")?;
        serializer.serialize_field("contract_address", &Felt(self.contract_address.get()))?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for DeployAccountTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
        serializer.serialize_field("contract_address", &Felt(self.contract_address.get()))?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for PendingDeployAccountTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
        serializer.serialize_field("contract_address", &Felt(self.contract_address.get()))?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for L1HandlerTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"L1_HANDLER")?;
        serializer.serialize_field("message_hash", &NumAsHex::H256(&self.message_hash))?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for PendingL1HandlerTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"L1_HANDLER")?;
        serializer.serialize_field("message_hash", &NumAsHex::H256(&self.message_hash))?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for DeclareTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"DECLARE")?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for PendingDeclareTxnReceipt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("type", &"DECLARE")?;
        serializer.flatten(&self.common)?;
        serializer.end()
    }
}

impl SerializeForVersion for CommonReceiptProperties<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("transaction_hash", &TxnHash(&self.receipt.transaction_hash))?;
        serializer.serialize_field(
            "actual_fee",
            &FeePayment {
                amount: self.receipt.actual_fee.as_ref(),
                version: &self.version,
            },
        )?;
        serializer.serialize_field("finality_status", &self.finality)?;
        serializer.serialize_field("block_hash", &BlockHash(self.block_hash))?;
        serializer.serialize_field("block_number", &BlockNumber(self.block_number))?;
        serializer.serialize_iter(
            "messages_sent",
            self.receipt.l2_to_l1_messages.len(),
            &mut self.receipt.l2_to_l1_messages.iter().map(MsgToL1),
        )?;
        serializer.serialize_iter(
            "events",
            self.receipt.events.len(),
            &mut self.receipt.events.iter().map(Event),
        )?;
        serializer.serialize_field(
            "execution_resources",
            &ExecutionResources(&self.receipt.execution_resources),
        )?;

        if let Some(reason) = self.receipt.revert_reason() {
            serializer.serialize_field("execution_status", &TxnExecutionStatus::Reverted)?;
            serializer.serialize_field("revert_reason", &reason)?;
        } else {
            serializer.serialize_field("execution_status", &TxnExecutionStatus::Succeeded)?;
        }

        serializer.end()
    }
}

impl SerializeForVersion for PendingCommonReceiptProperties<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("transaction_hash", &TxnHash(&self.receipt.transaction_hash))?;
        serializer.serialize_field(
            "actual_fee",
            &FeePayment {
                amount: self.receipt.actual_fee.as_ref(),
                version: self.version,
            },
        )?;

        serializer.serialize_iter(
            "messages_sent",
            self.receipt.l2_to_l1_messages.len(),
            &mut self.receipt.l2_to_l1_messages.iter().map(MsgToL1),
        )?;
        serializer.serialize_iter(
            "events",
            self.receipt.events.len(),
            &mut self.receipt.events.iter().map(Event),
        )?;
        serializer.serialize_field("finality_status", &"ACCEPTED_ON_L2")?;
        serializer.serialize_field(
            "execution_resources",
            &ExecutionResources(&self.receipt.execution_resources),
        )?;

        if let Some(reason) = self.receipt.revert_reason() {
            serializer.serialize_field("execution_status", &TxnExecutionStatus::Reverted)?;
            serializer.serialize_field("revert_reason", &reason)?;
        } else {
            serializer.serialize_field("execution_status", &TxnExecutionStatus::Succeeded)?;
        }

        serializer.end()
    }
}

impl SerializeForVersion for TxnType {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnType::Declare => "DECLARE",
            TxnType::Deploy => "DEPLOY",
            TxnType::DeployAccount => "DEPLOY_ACCOUNT",
            TxnType::Invoke => "INVOKE",
            TxnType::L1Handler => "L1_HANDLER",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnExecutionStatus {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnExecutionStatus::Succeeded => "SUCCEEDED",
            TxnExecutionStatus::Reverted => "REVERTED",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnFinalityStatus {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnFinalityStatus::AcceptedOnL2 => "ACCEPTED_ON_L2",
            TxnFinalityStatus::AcceptedOnL1 => "ACCEPTED_ON_L1",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for MsgToL1<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("from_address", &Felt(self.0.from_address.get()))?;
        // The spec erroneously marks this as a Felt, but should be an ETH_ADDRESS.
        serializer.serialize_field(
            "to_address",
            // unwrap is safe as Ethereum address is 20 bytes and cannot overflow.
            &Felt(&pathfinder_crypto::Felt::from_be_slice(self.0.to_address.0.as_bytes()).unwrap()),
        )?;
        serializer.serialize_iter(
            "payload",
            self.0.payload.len(),
            &mut self.0.payload.iter().map(|x| Felt(&x.0)),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for ComputationResources<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut s = serializer.serialize_struct()?;

        s.serialize_field("steps", &self.0.n_steps)?;

        s.serialize_optional("memory_holes", NonZeroU64::new(self.0.n_memory_holes))?;
        s.serialize_optional(
            "range_check_builtin_applications",
            NonZeroU64::new(self.0.builtins.range_check),
        )?;
        s.serialize_optional(
            "pedersen_builtin_applications",
            NonZeroU64::new(self.0.builtins.pedersen),
        )?;
        s.serialize_optional(
            "poseidon_builtin_applications",
            NonZeroU64::new(self.0.builtins.poseidon),
        )?;
        s.serialize_optional(
            "ec_op_builtin_applications",
            NonZeroU64::new(self.0.builtins.ec_op),
        )?;
        s.serialize_optional(
            "ecdsa_builtin_applications",
            NonZeroU64::new(self.0.builtins.ecdsa),
        )?;
        s.serialize_optional(
            "bitwise_builtin_applications",
            NonZeroU64::new(self.0.builtins.bitwise),
        )?;
        s.serialize_optional(
            "keccak_builtin_applications",
            NonZeroU64::new(self.0.builtins.keccak),
        )?;
        s.serialize_optional(
            "segment_arena_builtin",
            NonZeroU64::new(self.0.builtins.segment_arena),
        )?;

        s.end()
    }
}

impl SerializeForVersion for ExecutionResources<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        // This object is defined inline in the spec.
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("l1_gas", &self.0.data_availability.l1_gas)?;
        s.serialize_field("l1_data_gas", &self.0.data_availability.l1_data_gas)?;
        let data_availability = s.end()?;

        let computation = serializer.serialize(&ComputationResources(self.0))?;

        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("data_availability", &data_availability)?;
        serializer.flatten(&computation)?;
        serializer.end()
    }
}

impl SerializeForVersion for FeePayment<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        if let Some(amount) = self.amount {
            serializer.serialize_field("amount", &Felt(&amount.0))?;
        } else {
            serializer.serialize_field("amount", &Felt(&Default::default()))?;
        }
        serializer.serialize_field("unit", &PriceUnit(&self.version))?;

        serializer.end()
    }
}

impl SerializeForVersion for PriceUnit<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        use pathfinder_common::TransactionVersion;
        match self.0 {
            &TransactionVersion::ZERO | &TransactionVersion::ONE | &TransactionVersion::TWO => {
                "WEI"
            }
            _ => "FRI",
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use crate::dto::serialize::Serializer;

    use super::*;
    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;
    use primitive_types::H160;
    use serde_json::json;

    #[test]
    fn msg_to_l1() {
        let s = Serializer::default();

        let to_address = felt!("0x5678");

        let message = pathfinder_common::receipt::L2ToL1Message {
            from_address: contract_address!("0x1234"),
            to_address: pathfinder_common::EthereumAddress(H160::from_slice(
                &to_address.to_be_bytes()[12..],
            )),
            payload: vec![
                l2_to_l1_message_payload_elem!("0x1"),
                l2_to_l1_message_payload_elem!("0x2"),
                l2_to_l1_message_payload_elem!("0x3"),
            ],
        };

        let expected = json!({
            "from_address": s.serialize(&Felt(message.from_address.get())).unwrap(),
            "to_address": s.serialize(&Felt(&to_address)).unwrap(),
            "payload": message.payload.iter().map(|x| Felt(&x.0).serialize(s).unwrap()).collect::<Vec<_>>(),
        });

        let encoded = MsgToL1(&message).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn txn_finality_status() {
        let s = Serializer::default();
        let l2 = s.serialize(&TxnFinalityStatus::AcceptedOnL2).unwrap();
        let l1 = s.serialize(&TxnFinalityStatus::AcceptedOnL1).unwrap();

        assert_eq!(l2, json!("ACCEPTED_ON_L2"));
        assert_eq!(l1, json!("ACCEPTED_ON_L1"));
    }

    #[test]
    fn txn_execution_status() {
        let s = Serializer::default();
        let succeeded = s.serialize(&TxnExecutionStatus::Succeeded).unwrap();
        let reverted = s.serialize(&TxnExecutionStatus::Reverted).unwrap();

        assert_eq!(succeeded, json!("SUCCEEDED"));
        assert_eq!(reverted, json!("REVERTED"));
    }

    #[test]
    fn txn_type() {
        let s = Serializer::default();

        let declare = s.serialize(&TxnType::Declare).unwrap();
        let deploy = s.serialize(&TxnType::Deploy).unwrap();
        let deploy_account = s.serialize(&TxnType::DeployAccount).unwrap();
        let invoke = s.serialize(&TxnType::Invoke).unwrap();
        let l1_handler = s.serialize(&TxnType::L1Handler).unwrap();

        assert_eq!(declare, json!("DECLARE"));
        assert_eq!(deploy, json!("DEPLOY"));
        assert_eq!(deploy_account, json!("DEPLOY_ACCOUNT"));
        assert_eq!(invoke, json!("INVOKE"));
        assert_eq!(l1_handler, json!("L1_HANDLER"));
    }

    mod computation_resources {
        use super::*;
        use pretty_assertions_sorted::assert_eq;

        #[test]
        fn zeros_are_skipped() {
            let resources = pathfinder_common::receipt::ExecutionResources {
                builtins: Default::default(),
                n_steps: 10,
                n_memory_holes: 0,
                data_availability: Default::default(),
            };

            let expected = json!({
               "steps": 10
            });

            let encoded = Serializer::default()
                .serialize(&ComputationResources(&resources))
                .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn non_zeros_are_present() {
            let resources = pathfinder_common::receipt::ExecutionResources {
                builtins: pathfinder_common::receipt::BuiltinCounters {
                    output: 1,
                    pedersen: 2,
                    range_check: 3,
                    ecdsa: 4,
                    bitwise: 5,
                    ec_op: 6,
                    keccak: 7,
                    poseidon: 8,
                    segment_arena: 9,
                },
                n_steps: 10,
                n_memory_holes: 11,
                data_availability: Default::default(),
            };

            let expected = json!({
               "steps": 10,
               "memory_holes": resources.n_memory_holes,
               "range_check_builtin_applications": resources.builtins.range_check,
               "pedersen_builtin_applications": resources.builtins.pedersen,
               "poseidon_builtin_applications": resources.builtins.poseidon,
               "ec_op_builtin_applications": resources.builtins.ec_op,
               "ecdsa_builtin_applications": resources.builtins.ecdsa,
               "bitwise_builtin_applications": resources.builtins.bitwise,
               "keccak_builtin_applications": resources.builtins.keccak,
               "segment_arena_builtin": resources.builtins.segment_arena,
            });

            let encoded = Serializer::default()
                .serialize(&ComputationResources(&resources))
                .unwrap();

            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn execution_resources() {
        let s = Serializer::default();

        let resources = pathfinder_common::receipt::ExecutionResources {
            n_steps: 10,
            data_availability: pathfinder_common::receipt::ExecutionDataAvailability {
                l1_gas: 101,
                l1_data_gas: 200,
            },
            n_memory_holes: Default::default(),
            builtins: Default::default(),
        };

        let expected_computation = s.serialize(&ComputationResources(&resources)).unwrap();
        let expected_data_availability = json!({
            "data_availability": {
                "l1_gas": resources.data_availability.l1_gas,
                "l1_data_gas": resources.data_availability.l1_data_gas,
            }
        });
        let expected = crate::dto::merge_json(expected_computation, expected_data_availability);

        let encoded = ExecutionResources(&resources).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn price_unit() {
        use pathfinder_common::TransactionVersion;

        let s = Serializer::default();
        let v0 = s.serialize(&PriceUnit(&TransactionVersion::ZERO)).unwrap();
        let v1 = s.serialize(&PriceUnit(&TransactionVersion::ONE)).unwrap();
        let v2 = s.serialize(&PriceUnit(&TransactionVersion::TWO)).unwrap();
        let v3 = s.serialize(&PriceUnit(&TransactionVersion::THREE)).unwrap();

        assert_eq!(v0, json!("WEI"));
        assert_eq!(v1, json!("WEI"));
        assert_eq!(v2, json!("WEI"));

        assert_eq!(v3, json!("FRI"));
    }

    #[test]
    fn fee_payment() {
        let s = Serializer::default();
        let amount = fee!("0x123");
        let version = pathfinder_common::TransactionVersion::ZERO;

        let expected = json!({
            "amount": s.serialize(&Felt(&amount.0)).unwrap(),
            "unit": s.serialize(&PriceUnit(&version)).unwrap(),
        });

        let encoded = FeePayment {
            amount: Some(&amount),
            version: &version,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }

    mod pending_common_receipt_properties {
        use super::*;
        use pretty_assertions_sorted::assert_eq;

        #[test]
        fn reverted() {
            let s = Serializer::default();
            let version = pathfinder_common::TransactionVersion::ZERO;
            let receipt = test_receipt();

            let expected = json!({
                "transaction_hash": s.serialize(&TxnHash(&receipt.transaction_hash)).unwrap(),
                "actual_fee": s.serialize(&FeePayment {
                    amount: receipt.actual_fee.as_ref(),
                    version: &version
                }).unwrap(),
                "messages_sent": receipt.l2_to_l1_messages.iter().map(|x| MsgToL1(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "events": receipt.events.iter().map(|x| Event(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "revert_reason": "revert reason",
                "finality_status": "ACCEPTED_ON_L2",
                "execution_status": s.serialize(&TxnExecutionStatus::Reverted).unwrap(),
                "execution_resources": s.serialize(&ExecutionResources(&receipt.execution_resources)).unwrap(),
            });

            let encoded = PendingCommonReceiptProperties {
                receipt: &receipt,
                version: &version,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn success() {
            let s = Serializer::default();
            let version = pathfinder_common::TransactionVersion::ZERO;
            let mut receipt = test_receipt();
            receipt.execution_status = pathfinder_common::receipt::ExecutionStatus::Succeeded;

            let expected = json!({
                "transaction_hash": s.serialize(&TxnHash(&receipt.transaction_hash)).unwrap(),
                "actual_fee": s.serialize(&FeePayment {
                    amount: receipt.actual_fee.as_ref(),
                    version: &version
                }).unwrap(),
                "messages_sent": receipt.l2_to_l1_messages.iter().map(|x| MsgToL1(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "events": receipt.events.iter().map(|x| Event(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "finality_status": "ACCEPTED_ON_L2",
                "execution_status": s.serialize(&TxnExecutionStatus::Succeeded).unwrap(),
                "execution_resources": s.serialize(&ExecutionResources(&receipt.execution_resources)).unwrap(),
            });

            let encoded = PendingCommonReceiptProperties {
                receipt: &receipt,
                version: &version,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        fn test_receipt() -> pathfinder_common::receipt::Receipt {
            let receipt = pathfinder_common::receipt::Receipt {
                actual_fee: None,
                events: vec![pathfinder_common::event::Event {
                    data: vec![],
                    from_address: contract_address!("0xABC"),
                    keys: vec![],
                }],
                execution_resources: pathfinder_common::receipt::ExecutionResources {
                    n_steps: 100,
                    ..Default::default()
                },
                l2_to_l1_messages: vec![pathfinder_common::receipt::L2ToL1Message {
                    from_address: contract_address!("0x999"),
                    payload: vec![],
                    to_address: pathfinder_common::EthereumAddress(Default::default()),
                }],
                execution_status: pathfinder_common::receipt::ExecutionStatus::Reverted {
                    reason: "revert reason".to_owned(),
                },
                transaction_hash: transaction_hash!("0x123"),
                transaction_index: Default::default(),
            };
            receipt
        }
    }

    mod common_receipt_properties {
        use super::*;
        use pretty_assertions_sorted::assert_eq;

        #[test]
        fn reverted() {
            let s = Serializer::default();
            let version = pathfinder_common::TransactionVersion::ZERO;
            let receipt = test_receipt();
            let block_hash = block_hash!("0x999");
            let block_number = pathfinder_common::BlockNumber::GENESIS + 10;

            let expected = json!({
                "transaction_hash": s.serialize(&TxnHash(&receipt.transaction_hash)).unwrap(),
                "actual_fee": s.serialize(&FeePayment {
                    amount: receipt.actual_fee.as_ref(),
                    version: &version
                }).unwrap(),
                "messages_sent": receipt.l2_to_l1_messages.iter().map(|x| MsgToL1(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "events": receipt.events.iter().map(|x| Event(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "revert_reason": "revert reason",
                "finality_status": "ACCEPTED_ON_L1",
                "execution_status": s.serialize(&TxnExecutionStatus::Reverted).unwrap(),
                "execution_resources": s.serialize(&ExecutionResources(&receipt.execution_resources)).unwrap(),
                "block_hash": s.serialize(&BlockHash(&block_hash)).unwrap(),
                "block_number": s.serialize(&BlockNumber(block_number)).unwrap(),
            });

            let encoded = CommonReceiptProperties {
                receipt: &receipt,
                version: &version,
                finality: TxnFinalityStatus::AcceptedOnL1,
                block_hash: &block_hash,
                block_number,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn success() {
            let s = Serializer::default();
            let version = pathfinder_common::TransactionVersion::ZERO;
            let mut receipt = test_receipt();
            receipt.execution_status = pathfinder_common::receipt::ExecutionStatus::Succeeded;
            let block_hash = block_hash!("0x999");
            let block_number = pathfinder_common::BlockNumber::GENESIS + 10;

            let expected = json!({
                "transaction_hash": s.serialize(&TxnHash(&receipt.transaction_hash)).unwrap(),
                "actual_fee": s.serialize(&FeePayment {
                    amount: receipt.actual_fee.as_ref(),
                    version: &version
                }).unwrap(),
                "messages_sent": receipt.l2_to_l1_messages.iter().map(|x| MsgToL1(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "events": receipt.events.iter().map(|x| Event(&x).serialize(s).unwrap()).collect::<Vec<_>>(),
                "finality_status": "ACCEPTED_ON_L1",
                "execution_status": s.serialize(&TxnExecutionStatus::Succeeded).unwrap(),
                "execution_resources": s.serialize(&ExecutionResources(&receipt.execution_resources)).unwrap(),
                "block_hash": s.serialize(&BlockHash(&block_hash)).unwrap(),
                "block_number": s.serialize(&BlockNumber(block_number)).unwrap(),
            });

            let encoded = CommonReceiptProperties {
                receipt: &receipt,
                version: &version,
                finality: TxnFinalityStatus::AcceptedOnL1,
                block_hash: &block_hash,
                block_number,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn pending_invoke_txn_receipt() {
        let s = Serializer::default();
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let common = PendingCommonReceiptProperties {
            receipt: &receipt,
            version: &version,
        };

        let expected = merge_json(json!({"type": "INVOKE"}), s.serialize(&common).unwrap());
        let encoded = PendingInvokeTxnReceipt { common }.serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn pending_l1_handler_txn_receipt() {
        let s = Serializer::default();
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let msg_hash = H256::from_low_u64_be(57);
        let common = PendingCommonReceiptProperties {
            receipt: &receipt,
            version: &version,
        };

        let expected = merge_json(
            json!({
                "type": "L1_HANDLER",
                "message_hash": s.serialize(&NumAsHex::H256(&msg_hash)).unwrap(),
            }),
            s.serialize(&common).unwrap(),
        );
        let encoded = PendingL1HandlerTxnReceipt {
            common,
            message_hash: &msg_hash,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn pending_declare_txn_receipt() {
        let s = Serializer::default();
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let common = PendingCommonReceiptProperties {
            receipt: &receipt,
            version: &version,
        };

        let expected = merge_json(
            json!({
                "type": "DECLARE"
            }),
            s.serialize(&common).unwrap(),
        );
        let encoded = PendingDeclareTxnReceipt { common }.serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn pending_deploy_txn_receipt() {
        let s = Serializer::default();
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let address = contract_address!("0x99123");
        let common = PendingCommonReceiptProperties {
            receipt: &receipt,
            version: &version,
        };

        let expected = merge_json(
            json!({
                "type": "DEPLOY_ACCOUNT",
                "contract_address": s.serialize(&Felt(&address.0)).unwrap(),
            }),
            s.serialize(&common).unwrap(),
        );
        let encoded = PendingDeployAccountTxnReceipt {
            common,
            contract_address: &address,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }

    mod pending_txn_receipt {
        use super::*;
        use pretty_assertions_sorted::assert_eq;

        #[test]
        fn invoke() {
            let s = Serializer::default();
            let receipt = test_receipt();
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::InvokeV0(
                    Default::default(),
                ),
            };

            let common = PendingCommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
            };
            let expected = PendingInvokeTxnReceipt { common }.serialize(s).unwrap();

            let encoded = PendingTxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn declare() {
            let s = Serializer::default();
            let receipt = test_receipt();
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::DeclareV0(
                    Default::default(),
                ),
            };

            let common = PendingCommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
            };
            let expected = PendingDeclareTxnReceipt { common }.serialize(s).unwrap();

            let encoded = PendingTxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn deploy_account() {
            let s = Serializer::default();
            let receipt = test_receipt();
            let variant = pathfinder_common::transaction::DeployAccountTransactionV3::default();
            let contract_address = variant.contract_address;
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::DeployAccountV3(
                    variant,
                ),
            };

            let common = PendingCommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
            };
            let expected = PendingDeployAccountTxnReceipt {
                common,
                contract_address: &contract_address,
            }
            .serialize(s)
            .unwrap();

            let encoded = PendingTxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn l1_handler() {
            let s = Serializer::default();
            let receipt = test_receipt();
            let variant = pathfinder_common::transaction::L1HandlerTransaction::default();
            let msg_hash = variant.calculate_message_hash();
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::L1Handler(variant),
            };

            let common = PendingCommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
            };
            let expected = PendingL1HandlerTxnReceipt {
                common,
                message_hash: &msg_hash,
            }
            .serialize(s)
            .unwrap();

            let encoded = PendingTxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn invoke_txn_receipt() {
        let s = Serializer::default();
        let finality = TxnFinalityStatus::AcceptedOnL1;
        let block_hash = block_hash!("0x12312");
        let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let common = CommonReceiptProperties {
            receipt: &receipt,
            version: &version,
            finality,
            block_hash: &block_hash,
            block_number,
        };

        let expected = merge_json(json!({"type": "INVOKE"}), s.serialize(&common).unwrap());
        let encoded = InvokeTxnReceipt { common }.serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn l1_handler_txn_receipt() {
        let s = Serializer::default();
        let finality = TxnFinalityStatus::AcceptedOnL1;
        let block_hash = block_hash!("0x12312");
        let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let msg_hash = H256::from_low_u64_be(57);
        let common = CommonReceiptProperties {
            receipt: &receipt,
            version: &version,
            finality,
            block_hash: &block_hash,
            block_number,
        };

        let expected = merge_json(
            json!({
                "type": "L1_HANDLER",
                "message_hash": s.serialize(&NumAsHex::H256(&msg_hash)).unwrap(),
            }),
            s.serialize(&common).unwrap(),
        );
        let encoded = L1HandlerTxnReceipt {
            common,
            message_hash: &msg_hash,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn declare_txn_receipt() {
        let s = Serializer::default();
        let finality = TxnFinalityStatus::AcceptedOnL1;
        let block_hash = block_hash!("0x12312");
        let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let common = CommonReceiptProperties {
            receipt: &receipt,
            version: &version,
            finality,
            block_hash: &block_hash,
            block_number,
        };

        let expected = merge_json(
            json!({
                "type": "DECLARE"
            }),
            s.serialize(&common).unwrap(),
        );
        let encoded = DeclareTxnReceipt { common }.serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn deploy_txn_receipt() {
        let s = Serializer::default();
        let finality = TxnFinalityStatus::AcceptedOnL1;
        let block_hash = block_hash!("0x12312");
        let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
        let receipt = test_receipt();
        let version = pathfinder_common::TransactionVersion::ZERO;
        let address = contract_address!("0x99123");
        let common = CommonReceiptProperties {
            receipt: &receipt,
            version: &version,
            finality,
            block_hash: &block_hash,
            block_number,
        };

        let expected = merge_json(
            json!({
                "type": "DEPLOY_ACCOUNT",
                "contract_address": s.serialize(&Felt(&address.0)).unwrap(),
            }),
            s.serialize(&common).unwrap(),
        );
        let encoded = DeployAccountTxnReceipt {
            common,
            contract_address: &address,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }

    mod txn_receipt {
        use super::*;
        use pretty_assertions_sorted::assert_eq;

        #[test]
        fn invoke() {
            let s = Serializer::default();
            let receipt = test_receipt();
            let finality = TxnFinalityStatus::AcceptedOnL1;
            let block_hash = block_hash!("0x12312");
            let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::InvokeV0(
                    Default::default(),
                ),
            };

            let common = CommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
                finality,
                block_hash: &block_hash,
                block_number,
            };
            let expected = InvokeTxnReceipt { common }.serialize(s).unwrap();

            let encoded = TxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
                finality,
                block_hash: &block_hash,
                block_number,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn declare() {
            let s = Serializer::default();
            let finality = TxnFinalityStatus::AcceptedOnL1;
            let block_hash = block_hash!("0x12312");
            let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
            let receipt = test_receipt();
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::DeclareV0(
                    Default::default(),
                ),
            };

            let common = CommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
                finality,
                block_hash: &block_hash,
                block_number,
            };
            let expected = DeclareTxnReceipt { common }.serialize(s).unwrap();

            let encoded = TxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
                finality,
                block_hash: &block_hash,
                block_number,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn deploy_account() {
            let s = Serializer::default();
            let finality = TxnFinalityStatus::AcceptedOnL1;
            let block_hash = block_hash!("0x12312");
            let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
            let receipt = test_receipt();
            let variant = pathfinder_common::transaction::DeployAccountTransactionV3::default();
            let contract_address = variant.contract_address;
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::DeployAccountV3(
                    variant,
                ),
            };

            let common = CommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
                finality,
                block_hash: &block_hash,
                block_number,
            };
            let expected = DeployAccountTxnReceipt {
                common,
                contract_address: &contract_address,
            }
            .serialize(s)
            .unwrap();

            let encoded = TxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
                finality,
                block_hash: &block_hash,
                block_number,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }

        #[test]
        fn l1_handler() {
            let s = Serializer::default();
            let finality = TxnFinalityStatus::AcceptedOnL1;
            let block_hash = block_hash!("0x12312");
            let block_number = pathfinder_common::BlockNumber::GENESIS + 132;
            let receipt = test_receipt();
            let variant = pathfinder_common::transaction::L1HandlerTransaction::default();
            let msg_hash = variant.calculate_message_hash();
            let transaction = pathfinder_common::transaction::Transaction {
                hash: receipt.transaction_hash,
                variant: pathfinder_common::transaction::TransactionVariant::L1Handler(variant),
            };

            let common = CommonReceiptProperties {
                receipt: &receipt,
                version: &transaction.version(),
                finality,
                block_hash: &block_hash,
                block_number,
            };
            let expected = L1HandlerTxnReceipt {
                common,
                message_hash: &msg_hash,
            }
            .serialize(s)
            .unwrap();

            let encoded = TxnReceipt {
                receipt: &receipt,
                transaction: &transaction,
                finality,
                block_hash: &block_hash,
                block_number,
            }
            .serialize(s)
            .unwrap();

            assert_eq!(encoded, expected);
        }
    }

    fn test_receipt() -> pathfinder_common::receipt::Receipt {
        let receipt = pathfinder_common::receipt::Receipt {
            actual_fee: None,
            events: vec![pathfinder_common::event::Event {
                data: vec![],
                from_address: contract_address!("0xABC"),
                keys: vec![],
            }],
            execution_resources: pathfinder_common::receipt::ExecutionResources {
                n_steps: 100,
                ..Default::default()
            },
            l2_to_l1_messages: vec![pathfinder_common::receipt::L2ToL1Message {
                from_address: contract_address!("0x999"),
                payload: vec![],
                to_address: pathfinder_common::EthereumAddress(Default::default()),
            }],
            execution_status: pathfinder_common::receipt::ExecutionStatus::Reverted {
                reason: "revert reason".to_owned(),
            },
            transaction_hash: transaction_hash!("0x123"),
            transaction_index: Default::default(),
        };
        receipt
    }
}
