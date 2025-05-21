use anyhow::anyhow;
use pathfinder_common::{ContractAddress, ContractNonce};
use serde::ser::Error;

use super::SerializeStruct;
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
                    serializer
                        .serialize_field("fee_transfer_invocation", &fee_transfer_invocation)?;
                }
                if let Some(validate_invocation) = &trace.validate_invocation {
                    serializer.serialize_field("validate_invocation", &validate_invocation)?;
                }
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &trace.state_diff)?;
                }
                if serializer.version > RpcVersion::V06 {
                    serializer
                        .serialize_field("execution_resources", &trace.execution_resources)?;
                }
            }
            pathfinder_executor::types::TransactionTrace::DeployAccount(trace) => {
                serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                serializer.serialize_field(
                    "constructor_invocation",
                    &trace.constructor_invocation.as_ref().ok_or_else(|| {
                        serde_json::error::Error::custom("Missing constructor_invocation in trace")
                    })?,
                )?;
                if let Some(fee_transfer_invocation) = &trace.fee_transfer_invocation {
                    serializer
                        .serialize_field("fee_transfer_invocation", &fee_transfer_invocation)?;
                }
                if let Some(validate_invocation) = &trace.validate_invocation {
                    serializer.serialize_field("validate_invocation", &validate_invocation)?;
                }
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &trace.state_diff)?;
                }
                if serializer.version > RpcVersion::V06 {
                    serializer
                        .serialize_field("execution_resources", &trace.execution_resources)?;
                }
            }
            pathfinder_executor::types::TransactionTrace::Invoke(trace) => {
                serializer.serialize_field("type", &"INVOKE")?;
                serializer.serialize_field("execute_invocation", &trace.execute_invocation)?;
                if let Some(fee_transfer_invocation) = &trace.fee_transfer_invocation {
                    serializer
                        .serialize_field("fee_transfer_invocation", &fee_transfer_invocation)?;
                }
                if let Some(validate_invocation) = &trace.validate_invocation {
                    serializer.serialize_field("validate_invocation", &validate_invocation)?;
                }
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &trace.state_diff)?;
                }
                if serializer.version > RpcVersion::V06 {
                    serializer
                        .serialize_field("execution_resources", &trace.execution_resources)?;
                }
            }
            pathfinder_executor::types::TransactionTrace::L1Handler(trace) => {
                serializer.serialize_field("type", &"L1_HANDLER")?;
                serializer.serialize_field(
                    "function_invocation",
                    &trace.function_invocation.as_ref().ok_or_else(|| {
                        serde_json::error::Error::custom("Missing function_invocation in trace")
                    })?,
                )?;
                if self.include_state_diff {
                    serializer.serialize_field("state_diff", &trace.state_diff)?;
                }
                if serializer.version > RpcVersion::V06 {
                    serializer
                        .serialize_field("execution_resources", &trace.execution_resources)?;
                }
            }
        }
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &pathfinder_executor::types::FunctionInvocation {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_optional(
            "call_type",
            self.call_type.as_ref().map(|call_type| match call_type {
                pathfinder_executor::types::CallType::Call => "CALL",
                pathfinder_executor::types::CallType::Delegate => "DELEGATE",
            }),
        )?;
        serializer.serialize_field("caller_address", &self.caller_address)?;
        serializer.serialize_iter(
            "calls",
            self.internal_calls.len(),
            &mut self.internal_calls.iter(),
        )?;
        if let Some(class_hash) = &self.class_hash {
            serializer.serialize_field("class_hash", &class_hash)?;
        }
        serializer.serialize_optional(
            "entry_point_type",
            self.entry_point_type
                .as_ref()
                .map(|entry_point_type| match entry_point_type {
                    pathfinder_executor::types::EntryPointType::Constructor => "CONSTRUCTOR",
                    pathfinder_executor::types::EntryPointType::External => "EXTERNAL",
                    pathfinder_executor::types::EntryPointType::L1Handler => "L1_HANDLER",
                }),
        )?;
        serializer.serialize_iter("events", self.events.len(), &mut self.events.iter())?;
        serializer.serialize_field("contract_address", &self.contract_address)?;
        serializer.serialize_optional("entry_point_selector", self.selector.as_ref())?;
        serializer.serialize_iter("calldata", self.calldata.len(), &mut self.calldata.iter())?;
        serializer.serialize_iter("messages", self.messages.len(), &mut self.messages.iter())?;
        serializer.serialize_iter("result", self.result.len(), &mut self.result.iter())?;
        match serializer.version {
            RpcVersion::V08 => {
                serializer.serialize_field(
                    "execution_resources",
                    &InnerCallExecutionResources(&self.execution_resources),
                )?;
                serializer.serialize_field("is_reverted", &self.is_reverted)?;
            }
            _ => serializer.serialize_field(
                "execution_resources",
                &ComputationResources(&self.computation_resources),
            )?,
        }
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &pathfinder_executor::types::Event {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("order", &self.order)?;
        serializer.serialize_iter("data", self.data.len(), &mut self.data.iter())?;
        serializer.serialize_iter("keys", self.keys.len(), &mut self.keys.iter())?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &pathfinder_executor::types::MsgToL1 {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("order", &self.order)?;
        serializer.serialize_iter("payload", self.payload.len(), &mut self.payload.iter())?;
        serializer.serialize_field("to_address", &self.to_address)?;
        serializer.serialize_field("from_address", &self.from_address)?;
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

impl crate::dto::SerializeForVersion
    for (
        &pathfinder_common::ContractAddress,
        &pathfinder_common::ContractNonce,
    )
{
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("contract_address", &self.0)?;
        serializer.serialize_field("nonce", self.1)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for pathfinder_executor::types::StateDiff {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_iter(
            "storage_diffs",
            self.storage_diffs.len(),
            &mut self.storage_diffs.iter().map(StorageDiff),
        )?;
        serializer.serialize_iter(
            "deprecated_declared_classes",
            self.deprecated_declared_classes.len(),
            &mut self.deprecated_declared_classes.iter(),
        )?;
        serializer.serialize_iter(
            "declared_classes",
            self.declared_classes.len(),
            &mut self.declared_classes.iter(),
        )?;
        serializer.serialize_iter(
            "deployed_contracts",
            self.deployed_contracts.len(),
            &mut self.deployed_contracts.iter(),
        )?;
        serializer.serialize_iter(
            "replaced_classes",
            self.replaced_classes.len(),
            &mut self.replaced_classes.iter(),
        )?;
        serializer.serialize_iter("nonces", self.nonces.len(), &mut self.nonces.iter())?;
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
        serializer.serialize_field("address", &self.0 .0)?;
        serializer.serialize_iter("storage_entries", self.0 .1.len(), &mut self.0 .1.iter())?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &pathfinder_executor::types::StorageDiff {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("key", &self.key)?;
        serializer.serialize_field("value", &self.value)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &pathfinder_executor::types::DeclaredSierraClass {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("class_hash", &self.class_hash)?;
        serializer.serialize_field("compiled_class_hash", &self.compiled_class_hash)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &pathfinder_executor::types::DeployedContract {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("address", &self.address)?;
        serializer.serialize_field("class_hash", &self.class_hash)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &pathfinder_executor::types::ReplacedClass {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("contract_address", &self.contract_address)?;
        serializer.serialize_field("class_hash", &self.class_hash)?;
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
        serializer.serialize_field("contract_address", &self.0 .0)?;
        serializer.serialize_field("nonce", self.0 .1)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for pathfinder_executor::types::ExecutionResources {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match serializer.version {
            RpcVersion::V08 => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("l1_gas", &self.l1_gas)?;
                serializer.serialize_field("l1_data_gas", &self.l1_data_gas)?;
                serializer.serialize_field("l2_gas", &self.l2_gas)?;
                serializer.end()
            }
            _ => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.flatten(&ComputationResources(&self.computation_resources))?;
                serializer.serialize_field("data_availability", &self.data_availability)?;
                serializer.end()
            }
        }
    }
}

impl crate::dto::SerializeForVersion for pathfinder_executor::types::DataAvailabilityResources {
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

impl crate::dto::SerializeForVersion for pathfinder_executor::types::ExecuteInvocation {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(Some(invocation)) => {
                invocation.serialize(serializer)
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

impl crate::dto::SerializeForVersion for pathfinder_executor::types::TransactionSimulation {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("fee_estimation", &self.fee_estimation)?;
        serializer.serialize_field(
            "transaction_trace",
            &TransactionTrace {
                trace: self.trace.clone(),
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
        SerializeForVersion,
        Serializer,
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
