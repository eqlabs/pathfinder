use primitive_types::H256;

use crate::dto::serialize::SerializeForVersion;
use crate::dto::*;

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
    finality: TxnFinalityStatus,
    block_hash: &'a pathfinder_common::BlockHash,
    block_number: pathfinder_common::BlockNumber,
}

struct PendingCommonReceiptProperties<'a> {
    receipt: &'a pathfinder_common::receipt::Receipt,
    transaction: &'a pathfinder_common::transaction::Transaction,
}

struct ExecutionResources<'a>(&'a pathfinder_common::receipt::ExecutionResources);

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

struct PendingDeployTxnReceipt<'a> {
    common: PendingCommonReceiptProperties<'a>,
    contract_address: &'a pathfinder_common::ContractAddress,
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
            transaction: self.transaction,
        };
        use pathfinder_common::transaction::TransactionVariant;
        match &self.transaction.variant {
            TransactionVariant::DeclareV0(_)
            | TransactionVariant::DeclareV1(_)
            | TransactionVariant::DeclareV2(_)
            | TransactionVariant::DeclareV3(_) => {
                PendingDeclareTxnReceipt { common }.serialize(serializer)
            }
            TransactionVariant::Deploy(tx) => PendingDeployTxnReceipt {
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

impl SerializeForVersion for PendingDeployTxnReceipt<'_> {
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
            &Felt(&self.receipt.actual_fee.unwrap_or_default().0),
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

        let txn_type = match &self.transaction.variant {
            pathfinder_common::transaction::TransactionVariant::DeclareV0(_) => TxnType::Declare,
            pathfinder_common::transaction::TransactionVariant::DeclareV1(_) => TxnType::Declare,
            pathfinder_common::transaction::TransactionVariant::DeclareV2(_) => TxnType::Declare,
            pathfinder_common::transaction::TransactionVariant::DeclareV3(_) => TxnType::Declare,
            pathfinder_common::transaction::TransactionVariant::Deploy(_) => TxnType::Deploy,
            pathfinder_common::transaction::TransactionVariant::DeployAccountV0V1(_) => {
                TxnType::DeployAccount
            }
            pathfinder_common::transaction::TransactionVariant::DeployAccountV3(_) => {
                TxnType::DeployAccount
            }
            pathfinder_common::transaction::TransactionVariant::InvokeV0(_) => TxnType::Invoke,
            pathfinder_common::transaction::TransactionVariant::InvokeV1(_) => TxnType::Invoke,
            pathfinder_common::transaction::TransactionVariant::InvokeV3(_) => TxnType::Invoke,
            pathfinder_common::transaction::TransactionVariant::L1Handler(_) => TxnType::L1Handler,
        };

        serializer.serialize_field("transaction_hash", &TxnHash(&self.receipt.transaction_hash))?;
        serializer.serialize_field(
            "actual_fee",
            &Felt(&self.receipt.actual_fee.unwrap_or_default().0),
        )?;
        serializer.serialize_field("type", &txn_type)?;
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
        serializer.serialize_field("to_address", &EthAddress(&self.0.to_address))?;
        serializer.serialize_field("payload", &PayloadDto(&self.0.payload))?;

        struct PayloadDto<'a>(&'a [pathfinder_common::L2ToL1MessagePayloadElem]);
        impl SerializeForVersion for PayloadDto<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_seq(Some(self.0.len()))?;

                for value in self.0 {
                    serializer.serialize_element(&Felt(&value.0))?;
                }

                serializer.end()
            }
        }

        serializer.end()
    }
}

impl SerializeForVersion for ExecutionResources<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("steps", &NumAsHex::U64(self.0.n_steps))?;
        serializer.serialize_field("memory_holes", &NumAsHex::U64(self.0.n_memory_holes))?;
        serializer.serialize_field(
            "range_check_builtin_applications",
            &NumAsHex::U64(self.0.builtins.range_check),
        )?;
        serializer.serialize_field(
            "pedersen_builtin_applications",
            &NumAsHex::U64(self.0.builtins.pedersen),
        )?;
        serializer.serialize_field("poseidon", &NumAsHex::U64(self.0.builtins.poseidon))?;
        serializer.serialize_field("ec_op", &NumAsHex::U64(self.0.builtins.ec_op))?;
        serializer.serialize_field("ecdsa", &NumAsHex::U64(self.0.builtins.ecdsa))?;
        serializer.serialize_field("bitwise", &NumAsHex::U64(self.0.builtins.bitwise))?;
        serializer.serialize_field("keccak", &NumAsHex::U64(self.0.builtins.keccak))?;

        serializer.end()
    }
}
