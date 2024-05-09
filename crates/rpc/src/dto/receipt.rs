use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::{Transaction, TransactionKind, TransactionVariant};
use pathfinder_common::{BlockHash, BlockNumber, TransactionHash, TransactionVersion};
use serde::ser::Error;

use super::serialize;
use crate::dto::serialize::{SerializeForVersion, Serializer};
use crate::{dto, RpcVersion};

#[derive(Copy, Clone)]
pub enum TxnStatus {
    Received,
    Rejected,
    AcceptedOnL2,
    AcceptedOnL1,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TxnExecutionStatus {
    Succeeded,
    Reverted,
}

impl From<&pathfinder_common::receipt::ExecutionStatus> for TxnExecutionStatus {
    fn from(value: &pathfinder_common::receipt::ExecutionStatus) -> Self {
        use pathfinder_common::receipt::ExecutionStatus;
        match value {
            ExecutionStatus::Succeeded => Self::Succeeded,
            ExecutionStatus::Reverted { .. } => Self::Reverted,
        }
    }
}

#[derive(Copy, Clone)]
pub enum TxnFinalityStatus {
    AcceptedOnL2,
    AcceptedOnL1,
}

pub struct TxnReceiptWithBlockInfo<'a> {
    pub block_hash: Option<&'a BlockHash>,
    pub block_number: Option<BlockNumber>,
    pub receipt: &'a Receipt,
    pub transaction: &'a Transaction,
    pub events: &'a [Event],
    pub finality: TxnFinalityStatus,
}

pub struct TxnReceipt<'a> {
    pub receipt: &'a Receipt,
    pub transaction: &'a Transaction,
    pub events: &'a [Event],
    pub finality: TxnFinalityStatus,
}

pub struct InvokeTxnReceipt<'a>(pub &'a TxnReceipt<'a>);
pub struct L1HandlerTxnReceipt<'a>(pub &'a TxnReceipt<'a>);
pub struct DeclareTxnReceipt<'a>(pub &'a TxnReceipt<'a>);
pub struct DeployTxnReceipt<'a>(pub &'a TxnReceipt<'a>);
pub struct DeployAccountTxnReceipt<'a>(pub &'a TxnReceipt<'a>);

pub struct CommonReceiptProperties<'a>(pub &'a TxnReceipt<'a>);

#[derive(Copy, Clone)]
pub struct PriceUnit<'a>(pub &'a TransactionVersion);

pub struct FeePayment<'a> {
    amount: &'a pathfinder_common::Fee,
    transaction_version: &'a TransactionVersion,
}
pub struct MsgToL1<'a>(pub &'a pathfinder_common::receipt::L2ToL1Message);
pub struct ExecutionResources<'a>(pub &'a pathfinder_common::receipt::ExecutionResources);
pub struct ComputationResources<'a>(pub &'a pathfinder_common::receipt::ExecutionResources);

impl SerializeForVersion for TxnStatus {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnStatus::Received => "RECEIVED",
            TxnStatus::Rejected => "REJECTED",
            TxnStatus::AcceptedOnL2 => "ACCEPTED_ON_L2",
            TxnStatus::AcceptedOnL1 => "ACCEPTED_ON_L1",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnExecutionStatus {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnExecutionStatus::Succeeded => "SUCCEEDED",
            TxnExecutionStatus::Reverted => "REVERTED",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnFinalityStatus {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnFinalityStatus::AcceptedOnL2 => "ACCEPTED_ON_L2",
            TxnFinalityStatus::AcceptedOnL1 => "ACCEPTED_ON_L1",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnReceiptWithBlockInfo<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let Self {
            block_hash,
            block_number,
            receipt,
            transaction,
            events,
            finality,
        } = self;

        let mut serializer = serializer.serialize_struct()?;

        serializer.flatten(&TxnReceipt {
            receipt,
            transaction,
            events,
            finality: *finality,
        })?;

        serializer.serialize_optional("block_hash", block_hash.map(dto::BlockHash))?;
        serializer.serialize_optional("block_number", block_number.map(dto::BlockNumber))?;

        serializer.end()
    }
}

impl SerializeForVersion for TxnReceipt<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        match self.transaction.variant.kind() {
            TransactionKind::Declare => serializer.serialize(&DeclareTxnReceipt(&self)),
            TransactionKind::Deploy => serializer.serialize(&DeployTxnReceipt(&self)),
            TransactionKind::DeployAccount => serializer.serialize(&DeployAccountTxnReceipt(&self)),
            TransactionKind::Invoke => serializer.serialize(&InvokeTxnReceipt(&self)),
            TransactionKind::L1Handler => serializer.serialize(&DeclareTxnReceipt(&self)),
        }
    }
}

impl SerializeForVersion for DeclareTxnReceipt<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        if self.0.transaction.variant.kind() != TransactionKind::Declare {
            return Err(serde_json::error::Error::custom(
                "expected Declare transaction",
            ));
        }

        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"DECLARE")?;
        serializer.flatten(&CommonReceiptProperties(self.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for DeployTxnReceipt<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let contract_address = match &self.0.transaction.variant {
            // Partial match here is safe since this variant is deprecated.
            // i.e. no risk of forgetting to handle a new variant.
            TransactionVariant::Deploy(tx) => &tx.contract_address,
            _ => {
                return Err(serde_json::error::Error::custom(
                    "expected Deploy transaction",
                ))
            }
        };

        let mut serializer = serializer.serialize_struct()?;

        serializer.flatten(&CommonReceiptProperties(self.0))?;
        serializer.serialize_field("type", &"DEPLOY")?;
        serializer.serialize_field("contract_address", &dto::Felt(&contract_address.0))?;

        serializer.end()
    }
}
impl SerializeForVersion for DeployAccountTxnReceipt<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let contract_address = match &self.0.transaction.variant {
            TransactionVariant::DeployAccountV1(tx) => &tx.contract_address,
            TransactionVariant::DeployAccountV3(tx) => &tx.contract_address,
            TransactionVariant::DeclareV0(_)
            | TransactionVariant::DeclareV1(_)
            | TransactionVariant::DeclareV2(_)
            | TransactionVariant::DeclareV3(_)
            | TransactionVariant::Deploy(_)
            | TransactionVariant::InvokeV0(_)
            | TransactionVariant::InvokeV1(_)
            | TransactionVariant::InvokeV3(_)
            | TransactionVariant::L1Handler(_) => {
                return Err(serde_json::error::Error::custom(
                    "expected Deploy transaction",
                ))
            }
        };

        let mut serializer = serializer.serialize_struct()?;

        serializer.flatten(&CommonReceiptProperties(self.0))?;
        serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
        serializer.serialize_field("contract_address", &dto::Felt(&contract_address.0))?;

        serializer.end()
    }
}
impl SerializeForVersion for InvokeTxnReceipt<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        if self.0.transaction.variant.kind() != TransactionKind::Invoke {
            return Err(serde_json::error::Error::custom(
                "expected Invoke transaction",
            ));
        }

        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"INVOKE")?;
        serializer.flatten(&CommonReceiptProperties(self.0))?;

        serializer.end()
    }
}
impl SerializeForVersion for L1HandlerTxnReceipt<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}
impl SerializeForVersion for CommonReceiptProperties<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("transaction_hash", &dto::TxnHash(&self.0.transaction.hash))?;
        serializer.serialize_field(
            "actual_fee",
            &FeePayment {
                amount: &self.0.receipt.actual_fee,
                transaction_version: &self.0.transaction.version(),
            },
        )?;
        serializer.serialize_field("finality_status", &self.0.finality)?;
        serializer.serialize_iter(
            "messages_sent",
            self.0.receipt.l2_to_l1_messages.len(),
            &mut self.0.receipt.l2_to_l1_messages.iter().map(MsgToL1),
        )?;
        serializer.serialize_iter(
            "events",
            self.0.events.len(),
            &mut self.0.events.iter().map(|e| dto::Event {
                address: &e.from_address,
                keys: &e.keys,
                data: &e.data,
            }),
        )?;
        serializer.serialize_field(
            "execution_resources",
            &ExecutionResources(&self.0.receipt.execution_resources),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for FeePayment<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("amount", &dto::Felt(&self.amount.0))?;
        serializer.serialize_field("unit", &PriceUnit(&self.transaction_version))?;

        serializer.end()
    }
}

impl SerializeForVersion for MsgToL1<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        // FIXME: This clone could be elided if either the specification is fixed to
        // represent this as an ETH_ADDRESS. Alternatively, we can amend dto::Felt to an
        // enum over [Felt, EthAddress] but that seems worse than the clone imo.
        let to_address = pathfinder_crypto::Felt::from_be_slice(&self.0.to_address.0.as_bytes())
            .expect("Ethereum address should fit in a felt");

        serializer.serialize_field("from_address", &dto::Felt(&self.0.from_address.0))?;
        serializer.serialize_field("to_address", &dto::Felt(&to_address))?;
        serializer.serialize_field("from_address", &dto::Felt(&self.0.from_address.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for ExecutionResources<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        struct DataAvailability<'a>(&'a pathfinder_common::receipt::ExecutionDataAvailability);

        impl SerializeForVersion for DataAvailability<'_> {
            fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field("l1_gas", &self.0.l1_gas)?;
                serializer.serialize_field("l1_data_gas", &self.0.l1_data_gas)?;

                serializer.end()
            }
        }

        let mut serializer = serializer.serialize_struct()?;

        serializer.flatten(&ComputationResources(&self.0))?;
        serializer.serialize_field(
            "data_availability",
            &DataAvailability(&self.0.data_availability),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for PriceUnit<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        match self.0 {
            &TransactionVersion::ZERO | &TransactionVersion::ONE | &TransactionVersion::TWO => {
                "WEI"
            }
            _ => "FRI",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for ComputationResources<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        use std::num::NonZeroU64;

        // All values are required to be non-zero. Steps MUST be non-zero as it is
        // required, however the rest are simply skipped if zero.
        let steps = NonZeroU64::new(self.0.n_steps)
            .ok_or_else(|| serde_json::error::Error::custom("steps was zero which is invalid"))?;
        let memory_holes = NonZeroU64::new(self.0.n_memory_holes);
        let range_check = NonZeroU64::new(self.0.builtins.range_check);
        let pedersen = NonZeroU64::new(self.0.builtins.pedersen);
        let poseidon = NonZeroU64::new(self.0.builtins.poseidon);
        let ec_op = NonZeroU64::new(self.0.builtins.ec_op);
        let edcsa = NonZeroU64::new(self.0.builtins.ecdsa);
        let bitwise = NonZeroU64::new(self.0.builtins.bitwise);
        let keccak = NonZeroU64::new(self.0.builtins.keccak);
        let segment_arena = NonZeroU64::new(self.0.builtins.segment_arena);

        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("steps", &steps)?;
        serializer.serialize_optional("memory_holes", memory_holes)?;
        serializer.serialize_optional("range_check_builtin_applications", range_check)?;
        serializer.serialize_optional("pedersen_builtin_applications", pedersen)?;
        serializer.serialize_optional("poseidon_builtin_applications", poseidon)?;
        serializer.serialize_optional("ec_op_builtin_applications", ec_op)?;
        serializer.serialize_optional("ecdsa_builtin_applications", edcsa)?;
        serializer.serialize_optional("bitwise_builtin_applications", bitwise)?;
        serializer.serialize_optional("keccak_builtin_applications", keccak)?;
        serializer.serialize_optional("segment_arena_builtin", segment_arena)?;

        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions_sorted::assert_eq;
    use rstest::rstest;
    use serde_json::json;

    use super::*;
    use crate::dto::serialize::Serializer;

    #[rstest]
    #[case::received(TxnStatus::Received, "RECEIVED")]
    #[case::rejected(TxnStatus::Rejected, "REJECTED")]
    #[case::accepted_on_l2(TxnStatus::AcceptedOnL2, "ACCEPTED_ON_L2")]
    #[case::accepted_on_l1(TxnStatus::AcceptedOnL1, "ACCEPTED_ON_L1")]
    fn txn_status(#[case] input: TxnStatus, #[case] expected: &str) {
        let expected = json!(expected);
        let encoded = input.serialize(Serializer::default()).unwrap();
        assert_eq!(encoded, expected);
    }

    #[rstest]
    #[case::accepted_on_l2(TxnFinalityStatus::AcceptedOnL2, "ACCEPTED_ON_L2")]
    #[case::accepted_on_l1(TxnFinalityStatus::AcceptedOnL1, "ACCEPTED_ON_L1")]
    fn txn_finality_status(#[case] input: TxnFinalityStatus, #[case] expected: &str) {
        let expected = json!(expected);
        let encoded = input.serialize(Serializer::default()).unwrap();
        assert_eq!(encoded, expected);
    }

    #[rstest]
    #[case::accepted_on_l2(TxnExecutionStatus::Succeeded, "SUCCEEDED")]
    #[case::accepted_on_l1(TxnExecutionStatus::Reverted, "REVERTED")]
    fn txn_execution_status(#[case] input: TxnExecutionStatus, #[case] expected: &str) {
        let expected = json!(expected);
        let encoded = input.serialize(Serializer::default()).unwrap();
        assert_eq!(encoded, expected);
    }
}
