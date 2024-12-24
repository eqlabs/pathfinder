use anyhow::anyhow;
use pathfinder_common::{ContractAddress, ContractNonce};
use serde::ser::Error;

use super::{FeeEstimate, SerializeStruct};
use crate::RpcVersion;

#[derive(Debug)]
pub struct TransactionTrace {
    pub trace: pathfinder_executor::types::TransactionTrace,
    pub include_state_diff: bool,
}

impl crate::dto::SerializeForVersion for TransactionTrace {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        match &self.trace {
            pathfinder_executor::types::TransactionTrace::Declare(trace) => {
                serializer.serialize_field("type", &"DECLARE")?;
                if let Some(fee_transfer_invocation) = &trace.fee_transfer_invocation {
                    serializer.serialize_field(
                        "fee_transfer_invocation",
                        &FunctionInvocation(fee_transfer_invocation),
                    )?;
                }
                if let Some(validate_invocation) = &trace.validate_invocation {
                    serializer.serialize_field(
                        "validate_invocation",
                        &FunctionInvocation(validate_invocation),
                    )?;
                }
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &StateDiff(&trace.state_diff))?;
                }
                serializer.serialize_field(
                    "execution_resources",
                    &ExecutionResources(&trace.execution_resources),
                )?;
            }
            pathfinder_executor::types::TransactionTrace::DeployAccount(trace) => {
                serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                serializer.serialize_field(
                    "constructor_invocation",
                    &FunctionInvocation(trace.constructor_invocation.as_ref().ok_or_else(
                        || {
                            serde_json::error::Error::custom(
                                "Missing constructor_invocation in trace",
                            )
                        },
                    )?),
                )?;
                if let Some(fee_transfer_invocation) = &trace.fee_transfer_invocation {
                    serializer.serialize_field(
                        "fee_transfer_invocation",
                        &FunctionInvocation(fee_transfer_invocation),
                    )?;
                }
                if let Some(validate_invocation) = &trace.validate_invocation {
                    serializer.serialize_field(
                        "validate_invocation",
                        &FunctionInvocation(validate_invocation),
                    )?;
                }
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &StateDiff(&trace.state_diff))?;
                }
                serializer.serialize_field(
                    "execution_resources",
                    &ExecutionResources(&trace.execution_resources),
                )?;
            }
            pathfinder_executor::types::TransactionTrace::Invoke(trace) => {
                serializer.serialize_field("type", &"INVOKE")?;
                serializer.serialize_field(
                    "execute_invocation",
                    &ExecuteInvocation(&trace.execute_invocation),
                )?;
                if let Some(fee_transfer_invocation) = &trace.fee_transfer_invocation {
                    serializer.serialize_field(
                        "fee_transfer_invocation",
                        &FunctionInvocation(fee_transfer_invocation),
                    )?;
                }
                if let Some(validate_invocation) = &trace.validate_invocation {
                    serializer.serialize_field(
                        "validate_invocation",
                        &FunctionInvocation(validate_invocation),
                    )?;
                }
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &StateDiff(&trace.state_diff))?;
                }
                serializer.serialize_field(
                    "execution_resources",
                    &ExecutionResources(&trace.execution_resources),
                )?;
            }
            pathfinder_executor::types::TransactionTrace::L1Handler(trace) => {
                serializer.serialize_field("type", &"L1_HANDLER")?;
                serializer.serialize_field(
                    "function_invocation",
                    &FunctionInvocation(trace.function_invocation.as_ref().ok_or_else(|| {
                        serde_json::error::Error::custom("Missing function_invocation in trace")
                    })?),
                )?;
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &StateDiff(&trace.state_diff))?;
                }
                serializer.serialize_field(
                    "execution_resources",
                    &ExecutionResources(&trace.execution_resources),
                )?;
            }
        }
        serializer.end()
    }
}

#[derive(Debug)]
pub(crate) struct FunctionInvocation<'a>(&'a pathfinder_executor::types::FunctionInvocation);

impl crate::dto::SerializeForVersion for FunctionInvocation<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field(
            "call_type",
            &match self.0.call_type {
                pathfinder_executor::types::CallType::Call => "CALL",
                pathfinder_executor::types::CallType::Delegate => "DELEGATE",
            },
        )?;
        serializer.serialize_field("caller_address", &crate::dto::Felt(&self.0.caller_address))?;
        serializer.serialize_iter(
            "calls",
            self.0.internal_calls.len(),
            &mut self.0.internal_calls.iter().map(FunctionInvocation),
        )?;
        if let Some(class_hash) = &self.0.class_hash {
            serializer.serialize_field("class_hash", &crate::dto::Felt(class_hash))?;
        }
        serializer.serialize_field(
            "entry_point_type",
            &match self.0.entry_point_type {
                pathfinder_executor::types::EntryPointType::Constructor => "CONSTRUCTOR",
                pathfinder_executor::types::EntryPointType::External => "EXTERNAL",
                pathfinder_executor::types::EntryPointType::L1Handler => "L1_HANDLER",
            },
        )?;
        serializer.serialize_iter(
            "events",
            self.0.events.len(),
            &mut self.0.events.iter().map(Event),
        )?;
        serializer.serialize_field(
            "contract_address",
            &crate::dto::Felt(&self.0.contract_address.0),
        )?;
        serializer.serialize_field("entry_point_selector", &crate::dto::Felt(&self.0.selector))?;
        serializer.serialize_iter(
            "calldata",
            self.0.calldata.len(),
            &mut self.0.calldata.iter().map(crate::dto::Felt),
        )?;
        serializer.serialize_iter(
            "messages",
            self.0.messages.len(),
            &mut self.0.messages.iter().map(MsgToL1),
        )?;
        serializer.serialize_iter(
            "result",
            self.0.result.len(),
            &mut self.0.result.iter().map(crate::dto::Felt),
        )?;
        match serializer.version {
            RpcVersion::V08 => serializer.serialize_field(
                "execution_resources",
                &InnerCallExecutionResources(&self.0.execution_resources),
            )?,
            _ => serializer.serialize_field(
                "execution_resources",
                &ComputationResources(&self.0.computation_resources),
            )?,
        }
        serializer.end()
    }
}

struct Event<'a>(&'a pathfinder_executor::types::Event);

impl crate::dto::SerializeForVersion for Event<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("order", &self.0.order)?;
        serializer.serialize_iter(
            "data",
            self.0.data.len(),
            &mut self.0.data.iter().map(crate::dto::Felt),
        )?;
        serializer.serialize_iter(
            "keys",
            self.0.keys.len(),
            &mut self.0.keys.iter().map(crate::dto::Felt),
        )?;
        serializer.end()
    }
}

struct MsgToL1<'a>(&'a pathfinder_executor::types::MsgToL1);

impl crate::dto::SerializeForVersion for MsgToL1<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("order", &self.0.order)?;
        serializer.serialize_iter(
            "payload",
            self.0.payload.len(),
            &mut self.0.payload.iter().map(crate::dto::Felt),
        )?;
        serializer.serialize_field("to_address", &crate::dto::Felt(&self.0.to_address))?;
        serializer.serialize_field("from_address", &crate::dto::Felt(&self.0.from_address))?;
        serializer.end()
    }
}

struct ComputationResources<'a>(&'a pathfinder_executor::types::ComputationResources);

impl crate::dto::SerializeForVersion for ComputationResources<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("steps", &self.0.steps)?;
        if self.0.memory_holes != 0 {
            serializer.serialize_field("memory_holes", &self.0.memory_holes)?;
        }
        if self.0.range_check_builtin_applications != 0 {
            serializer.serialize_field(
                "range_check_builtin_applications",
                &self.0.range_check_builtin_applications,
            )?;
        }
        if self.0.pedersen_builtin_applications != 0 {
            serializer.serialize_field(
                "pedersen_builtin_applications",
                &self.0.pedersen_builtin_applications,
            )?;
        }
        if self.0.poseidon_builtin_applications != 0 {
            serializer.serialize_field(
                "poseidon_builtin_applications",
                &self.0.poseidon_builtin_applications,
            )?;
        }
        if self.0.ec_op_builtin_applications != 0 {
            serializer.serialize_field(
                "ec_op_builtin_applications",
                &self.0.ec_op_builtin_applications,
            )?;
        }
        if self.0.ecdsa_builtin_applications != 0 {
            serializer.serialize_field(
                "ecdsa_builtin_applications",
                &self.0.ecdsa_builtin_applications,
            )?;
        }
        if self.0.bitwise_builtin_applications != 0 {
            serializer.serialize_field(
                "bitwise_builtin_applications",
                &self.0.bitwise_builtin_applications,
            )?;
        }
        if self.0.keccak_builtin_applications != 0 {
            serializer.serialize_field(
                "keccak_builtin_applications",
                &self.0.keccak_builtin_applications,
            )?;
        }
        if self.0.segment_arena_builtin != 0 {
            serializer.serialize_field("segment_arena_builtin", &self.0.segment_arena_builtin)?;
        }
        serializer.end()
    }
}

struct InnerCallExecutionResources<'a>(&'a pathfinder_executor::types::InnerCallExecutionResources);

impl crate::dto::SerializeForVersion for InnerCallExecutionResources<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("l1_gas", &self.0.l1_gas)?;
        serializer.serialize_field("l2_gas", &self.0.l2_gas)?;
        serializer.end()
    }
}

struct StateDiff<'a>(&'a pathfinder_executor::types::StateDiff);

impl crate::dto::SerializeForVersion for StateDiff<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_iter(
            "storage_diffs",
            self.0.storage_diffs.len(),
            &mut self.0.storage_diffs.iter().map(StorageDiff),
        )?;
        serializer.serialize_iter(
            "deprecated_declared_classes",
            self.0.deprecated_declared_classes.len(),
            &mut self
                .0
                .deprecated_declared_classes
                .iter()
                .map(|v| crate::dto::Felt(&v.0)),
        )?;
        serializer.serialize_iter(
            "declared_classes",
            self.0.declared_classes.len(),
            &mut self.0.declared_classes.iter().map(DeclaredSierraClass),
        )?;
        serializer.serialize_iter(
            "deployed_contracts",
            self.0.deployed_contracts.len(),
            &mut self.0.deployed_contracts.iter().map(DeployedContract),
        )?;
        serializer.serialize_iter(
            "replaced_classes",
            self.0.replaced_classes.len(),
            &mut self.0.replaced_classes.iter().map(ReplacedClass),
        )?;
        serializer.serialize_iter(
            "nonces",
            self.0.nonces.len(),
            &mut self.0.nonces.iter().map(Nonce),
        )?;
        serializer.end()
    }
}

struct StorageDiff<'a>(
    (
        &'a ContractAddress,
        &'a Vec<pathfinder_executor::types::StorageDiff>,
    ),
);

impl crate::dto::SerializeForVersion for StorageDiff<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("address", &crate::dto::Felt(&self.0 .0 .0))?;
        serializer.serialize_iter(
            "storage_entries",
            self.0 .1.len(),
            &mut self.0 .1.iter().map(StorageEntry),
        )?;
        serializer.end()
    }
}

struct StorageEntry<'a>(&'a pathfinder_executor::types::StorageDiff);

impl crate::dto::SerializeForVersion for StorageEntry<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("key", &crate::dto::Felt(&self.0.key.0))?;
        serializer.serialize_field("value", &crate::dto::Felt(&self.0.value.0))?;
        serializer.end()
    }
}

struct DeclaredSierraClass<'a>(&'a pathfinder_executor::types::DeclaredSierraClass);

impl crate::dto::SerializeForVersion for DeclaredSierraClass<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("class_hash", &crate::dto::Felt(&self.0.class_hash.0))?;
        serializer.serialize_field(
            "compiled_class_hash",
            &crate::dto::Felt(&self.0.compiled_class_hash.0),
        )?;
        serializer.end()
    }
}

struct DeployedContract<'a>(&'a pathfinder_executor::types::DeployedContract);

impl crate::dto::SerializeForVersion for DeployedContract<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("address", &crate::dto::Felt(&self.0.address.0))?;
        serializer.serialize_field("class_hash", &crate::dto::Felt(&self.0.class_hash.0))?;
        serializer.end()
    }
}

struct ReplacedClass<'a>(&'a pathfinder_executor::types::ReplacedClass);

impl crate::dto::SerializeForVersion for ReplacedClass<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field(
            "contract_address",
            &crate::dto::Felt(&self.0.contract_address.0),
        )?;
        serializer.serialize_field("class_hash", &crate::dto::Felt(&self.0.class_hash.0))?;
        serializer.end()
    }
}

struct Nonce<'a>((&'a ContractAddress, &'a ContractNonce));

impl crate::dto::SerializeForVersion for Nonce<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("contract_address", &crate::dto::Felt(&self.0 .0 .0))?;
        serializer.serialize_field("nonce", &crate::dto::Felt(&self.0 .1 .0))?;
        serializer.end()
    }
}

struct ExecutionResources<'a>(&'a pathfinder_executor::types::ExecutionResources);

impl crate::dto::SerializeForVersion for ExecutionResources<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match serializer.version {
            RpcVersion::V08 => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("l1_gas", &self.0.l1_gas)?;
                serializer.serialize_field("l1_data_gas", &self.0.l1_data_gas)?;
                serializer.serialize_field("l2_gas", &self.0.l2_gas)?;
                serializer.end()
            }
            _ => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.flatten(&ComputationResources(&self.0.computation_resources))?;
                serializer.serialize_field(
                    "data_availability",
                    &DataAvailabilityResources(&self.0.data_availability),
                )?;
                serializer.end()
            }
        }
    }
}

struct DataAvailabilityResources<'a>(&'a pathfinder_executor::types::DataAvailabilityResources);

impl crate::dto::SerializeForVersion for DataAvailabilityResources<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("l1_gas", &self.0.l1_gas)?;
        serializer.serialize_field("l1_data_gas", &self.0.l1_data_gas)?;
        serializer.end()
    }
}

struct ExecuteInvocation<'a>(&'a pathfinder_executor::types::ExecuteInvocation);

impl crate::dto::SerializeForVersion for ExecuteInvocation<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self.0 {
            pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(Some(invocation)) => {
                FunctionInvocation(invocation).serialize(serializer)
            }
            pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(None) => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.end()
            }
            pathfinder_executor::types::ExecuteInvocation::RevertedReason(reason) => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("revert_reason", reason)?;
                serializer.end()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallType {
    Call,
    _LibraryCall,
    Delegate,
}

impl From<pathfinder_executor::types::CallType> for CallType {
    fn from(value: pathfinder_executor::types::CallType) -> Self {
        use pathfinder_executor::types::CallType::*;
        match value {
            Call => Self::Call,
            Delegate => Self::Delegate,
        }
    }
}

impl crate::dto::SerializeForVersion for CallType {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            CallType::Call => serializer.serialize_str("CALL"),
            CallType::_LibraryCall => serializer.serialize_str("LIBRARY_CALL"),
            CallType::Delegate => serializer.serialize_str("DELEGATE"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SimulationFlags(pub Vec<SimulationFlag>);

#[derive(Debug, Eq, PartialEq)]
pub enum SimulationFlag {
    SkipFeeCharge,
    SkipValidate,
}

impl crate::dto::DeserializeForVersion for SimulationFlag {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        let value: String = value.deserialize()?;
        match value.as_str() {
            "SKIP_FEE_CHARGE" => Ok(Self::SkipFeeCharge),
            "SKIP_VALIDATE" => Ok(Self::SkipValidate),
            _ => Err(serde_json::Error::custom("Invalid simulation flag")),
        }
    }
}

impl crate::dto::DeserializeForVersion for SimulationFlags {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        let array = value.deserialize_array(SimulationFlag::deserialize)?;
        Ok(Self(array))
    }
}

pub(crate) struct SimulatedTransaction(pub pathfinder_executor::types::TransactionSimulation);

impl crate::dto::SerializeForVersion for SimulatedTransaction {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("fee_estimation", &FeeEstimate(&self.0.fee_estimation))?;
        serializer.serialize_field(
            "transaction_trace",
            &TransactionTrace {
                trace: self.0.trace.clone(),
                include_state_diff: false,
            },
        )?;
        serializer.end()
    }
}

#[cfg(test)]
mod tests {

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        felt,
        BlockHeader,
        BlockId,
        CallParam,
        ClassHash,
        ContractAddress,
        EntryPoint,
        StarknetVersion,
        StorageAddress,
        StorageValue,
        TransactionVersion,
    };
    use pathfinder_crypto::Felt;
    use pathfinder_storage::Storage;
    use starknet_gateway_test_fixtures::class_definitions::{
        DUMMY_ACCOUNT_CLASS_HASH,
        ERC20_CONTRACT_DEFINITION_CLASS_HASH,
    };

    use crate::context::RpcContext;
    use crate::dto::{
        CallType,
        ComputationResources,
        ExecutionResources,
        FeeEstimate,
        FunctionInvocation,
        SerializeForVersion,
        Serializer,
        SimulatedTransaction,
        TransactionTrace,
    };
    use crate::method::call::FunctionCall;
    use crate::method::get_state_update::types::{DeployedContract, Nonce, StateDiff};
    use crate::method::simulate_transactions::tests::fixtures;
    use crate::types::request::{
        BroadcastedDeclareTransaction,
        BroadcastedDeclareTransactionV1,
        BroadcastedTransaction,
    };
    use crate::types::ContractClass;
    use crate::RpcVersion;

    pub(crate) async fn setup_storage_with_starknet_version(
        version: StarknetVersion,
    ) -> (
        Storage,
        BlockHeader,
        ContractAddress,
        ContractAddress,
        StorageValue,
    ) {
        let test_storage_key = StorageAddress::from_name(b"my_storage_var");
        let test_storage_value = storage_value!("0x09");

        // set test storage variable
        let (storage, last_block_header, account_contract_address, universal_deployer_address) =
            crate::test_setup::test_storage(version, |state_update| {
                state_update.with_storage_update(
                    fixtures::DEPLOYED_CONTRACT_ADDRESS,
                    test_storage_key,
                    test_storage_value,
                )
            })
            .await;

        (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        )
    }
}
