use pathfinder_common::{CallParam, EntryPoint};
use pathfinder_crypto::Felt;
use pathfinder_executor::types::TransactionSimulation;
use serde::{Deserialize, Serialize};
use starknet_gateway_types::trace as gateway_trace;

pub mod dto {
    use serde_with::serde_as;

    use crate::felt::RpcFelt;
    use crate::v05::method::call::FunctionCall;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    // #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct FeeEstimate {
        /// The Ethereum gas cost of the transaction
        #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
        pub gas_consumed: primitive_types::U256,
        /// The gas price (in gwei) that was used in the cost estimation (input to fee estimation)
        #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
        pub gas_price: primitive_types::U256,
        /// The estimated fee for the transaction (in gwei), product of gas_consumed and gas_price
        #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
        pub overall_fee: primitive_types::U256,
    }

    impl From<pathfinder_executor::types::FeeEstimate> for FeeEstimate {
        fn from(value: pathfinder_executor::types::FeeEstimate) -> Self {
            Self {
                gas_consumed: value.gas_consumed,
                gas_price: value.gas_price,
                overall_fee: value.overall_fee,
            }
        }
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_FEE_CHARGE")]
        SkipFeeCharge,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub enum CallType {
        #[serde(rename = "CALL")]
        Call,
        #[serde(rename = "LIBRARY_CALL")]
        LibraryCall,
    }

    impl From<pathfinder_executor::types::CallType> for CallType {
        fn from(value: pathfinder_executor::types::CallType) -> Self {
            use pathfinder_executor::types::CallType::*;
            match value {
                Call => Self::Call,
                Delegate => Self::LibraryCall,
            }
        }
    }

    #[serde_with::serde_as]
    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct FunctionInvocation {
        #[serde(default)]
        pub call_type: CallType,
        #[serde(default)]
        #[serde_as(as = "RpcFelt")]
        pub caller_address: Felt,
        #[serde(default)]
        pub calls: Vec<FunctionInvocation>,
        #[serde(default)]
        #[serde_as(as = "Option<RpcFelt>")]
        pub class_hash: Option<Felt>,
        #[serde(default)]
        pub entry_point_type: EntryPointType,
        #[serde(default)]
        pub events: Vec<Event>,
        #[serde(flatten)]
        pub function_call: FunctionCall,
        #[serde(default)]
        pub messages: Vec<MsgToL1>,
        #[serde(default)]
        #[serde_as(as = "Vec<RpcFelt>")]
        pub result: Vec<Felt>,
    }

    impl From<pathfinder_executor::types::FunctionInvocation> for FunctionInvocation {
        fn from(fi: pathfinder_executor::types::FunctionInvocation) -> Self {
            Self {
                call_type: fi.call_type.into(),
                caller_address: fi.caller_address,
                calls: fi.internal_calls.into_iter().map(Into::into).collect(),
                class_hash: fi.class_hash,
                entry_point_type: fi.entry_point_type.into(),
                events: fi.events.into_iter().map(Into::into).collect(),
                function_call: FunctionCall {
                    contract_address: fi.contract_address,
                    entry_point_selector: EntryPoint(fi.selector),
                    calldata: fi.calldata.into_iter().map(CallParam).collect(),
                },
                messages: fi.messages.into_iter().map(Into::into).collect(),
                result: fi.result.into_iter().map(Into::into).collect(),
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub enum EntryPointType {
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    impl From<pathfinder_executor::types::EntryPointType> for EntryPointType {
        fn from(value: pathfinder_executor::types::EntryPointType) -> Self {
            use pathfinder_executor::types::EntryPointType::*;
            match value {
                Constructor => Self::Constructor,
                External => Self::External,
                L1Handler => Self::L1Handler,
            }
        }
    }

    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct MsgToL1 {
        #[serde_as(as = "Vec<RpcFelt>")]
        pub payload: Vec<Felt>,
        #[serde_as(as = "RpcFelt")]
        pub to_address: Felt,
        #[serde_as(as = "RpcFelt")]
        pub from_address: Felt,
    }

    impl From<pathfinder_executor::types::MsgToL1> for MsgToL1 {
        fn from(value: pathfinder_executor::types::MsgToL1) -> Self {
            Self {
                payload: value.payload,
                to_address: value.to_address,
                from_address: value.from_address,
            }
        }
    }

    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct Event {
        #[serde_as(as = "Vec<RpcFelt>")]
        pub data: Vec<Felt>,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub keys: Vec<Felt>,
    }

    impl From<pathfinder_executor::types::Event> for Event {
        fn from(value: pathfinder_executor::types::Event) -> Self {
            Self {
                data: value.data,
                keys: value.keys,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    #[serde(untagged)]
    pub enum TransactionTrace {
        Declare(DeclareTxnTrace),
        DeployAccount(DeployAccountTxnTrace),
        Invoke(InvokeTxnTrace),
        L1Handler(L1HandlerTxnTrace),
    }

    impl From<pathfinder_executor::types::TransactionTrace> for TransactionTrace {
        fn from(trace: pathfinder_executor::types::TransactionTrace) -> Self {
            use pathfinder_executor::types::TransactionTrace::*;
            match trace {
                Declare(t) => Self::Declare(t.into()),
                DeployAccount(t) => Self::DeployAccount(t.into()),
                Invoke(t) => Self::Invoke(t.into()),
                L1Handler(t) => Self::L1Handler(t.into()),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct DeclareTxnTrace {
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    impl From<pathfinder_executor::types::DeclareTransactionTrace> for DeclareTxnTrace {
        fn from(trace: pathfinder_executor::types::DeclareTransactionTrace) -> Self {
            Self {
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
                validate_invocation: trace.validate_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct DeployAccountTxnTrace {
        #[serde(default)]
        pub constructor_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    impl From<pathfinder_executor::types::DeployAccountTransactionTrace> for DeployAccountTxnTrace {
        fn from(trace: pathfinder_executor::types::DeployAccountTransactionTrace) -> Self {
            Self {
                constructor_invocation: trace.constructor_invocation.map(Into::into),
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
                validate_invocation: trace.validate_invocation.map(Into::into),
            }
        }
    }

    #[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
    #[serde(untagged)]
    pub enum ExecuteInvocation {
        #[default]
        Empty,
        FunctionInvocation(FunctionInvocation),
        RevertedReason {
            revert_reason: String,
        },
    }

    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        pub execute_invocation: ExecuteInvocation,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    impl From<pathfinder_executor::types::InvokeTransactionTrace> for InvokeTxnTrace {
        fn from(trace: pathfinder_executor::types::InvokeTransactionTrace) -> Self {
            Self {
                validate_invocation: trace.validate_invocation.map(Into::into),
                execute_invocation: match trace.execute_invocation {
                    pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(Some(
                        function_invocation,
                    )) => ExecuteInvocation::FunctionInvocation(function_invocation.into()),
                    pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(None) => {
                        ExecuteInvocation::Empty
                    }
                    pathfinder_executor::types::ExecuteInvocation::RevertedReason(
                        revert_reason,
                    ) => ExecuteInvocation::RevertedReason { revert_reason },
                },
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct L1HandlerTxnTrace {
        #[serde(default)]
        pub function_invocation: Option<FunctionInvocation>,
    }

    impl From<pathfinder_executor::types::L1HandlerTransactionTrace> for L1HandlerTxnTrace {
        fn from(trace: pathfinder_executor::types::L1HandlerTransactionTrace) -> Self {
            Self {
                function_invocation: trace.function_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct SimulatedTransaction {
        #[serde(default)]
        pub fee_estimation: FeeEstimate,
        #[serde(default)]
        pub transaction_trace: TransactionTrace,
    }

    impl From<TransactionSimulation> for SimulatedTransaction {
        fn from(tx: TransactionSimulation) -> Self {
            dto::SimulatedTransaction {
                fee_estimation: tx.fee_estimation.into(),
                transaction_trace: tx.trace.into(),
            }
        }
    }

    impl From<gateway_trace::CallType> for CallType {
        fn from(value: gateway_trace::CallType) -> Self {
            match value {
                gateway_trace::CallType::Call => Self::Call,
                gateway_trace::CallType::Delegate => Self::LibraryCall,
            }
        }
    }

    impl From<gateway_trace::EntryPointType> for EntryPointType {
        fn from(value: gateway_trace::EntryPointType) -> Self {
            match value {
                gateway_trace::EntryPointType::Constructor => Self::Constructor,
                gateway_trace::EntryPointType::External => Self::External,
                gateway_trace::EntryPointType::L1Handler => Self::L1Handler,
            }
        }
    }

    impl From<gateway_trace::Event> for Event {
        fn from(value: gateway_trace::Event) -> Self {
            Self {
                data: value.data,
                keys: value.keys,
            }
        }
    }

    impl From<gateway_trace::FunctionInvocation> for FunctionInvocation {
        fn from(value: starknet_gateway_types::trace::FunctionInvocation) -> Self {
            Self {
                call_type: value.call_type.map(Into::into).unwrap_or(CallType::Call),
                function_call: FunctionCall {
                    calldata: value.calldata.into_iter().map(CallParam).collect(),
                    contract_address: value.contract_address,
                    entry_point_selector: EntryPoint(value.selector.unwrap_or_default()),
                },
                caller_address: value.caller_address,
                calls: value.internal_calls.into_iter().map(Into::into).collect(),
                class_hash: value.class_hash,
                entry_point_type: value
                    .entry_point_type
                    .map(Into::into)
                    .unwrap_or(EntryPointType::External),
                events: value.events.into_iter().map(Into::into).collect(),
                messages: value
                    .messages
                    .into_iter()
                    .map(|message| MsgToL1 {
                        payload: message.payload,
                        to_address: message.to_address,
                        from_address: value.contract_address.0,
                    })
                    .collect(),
                result: value.result,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV2,
        BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1,
    };
    use crate::v02::types::ContractClass;
    use pathfinder_common::{macro_prelude::*, Fee};
    use pathfinder_common::{
        //felt,
        BlockHeader,
        ContractAddress,
        StorageAddress,
        StorageValue,
        TransactionVersion,
    };
    use pathfinder_storage::Storage;

    use super::*;

    pub(crate) mod fixtures {
        use pathfinder_common::{CasmHash, ClassHash, ContractAddress};

        use super::*;

        pub const SIERRA_DEFINITION: &[u8] =
            include_bytes!("../../../fixtures/contracts/storage_access.json");
        pub const SIERRA_HASH: ClassHash =
            class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
        pub const CASM_HASH: CasmHash =
            casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");
        pub const CASM_DEFINITION: &[u8] =
            include_bytes!("../../../fixtures/contracts/storage_access.casm");
        const MAX_FEE: Fee = Fee(Felt::from_u64(10_000_000));
        pub const DEPLOYED_CONTRACT_ADDRESS: ContractAddress =
            contract_address!("0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7");
        pub const UNIVERSAL_DEPLOYER_CLASS_HASH: ClassHash =
            class_hash!("0x06f38fb91ddbf325a0625533576bb6f6eafd9341868a9ec3faa4b01ce6c4f4dc");

        pub mod input {
            use crate::v02::types::request::BroadcastedTransaction;

            use super::*;

            pub fn declare(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                let contract_class = ContractClass::from_definition_bytes(SIERRA_DEFINITION)
                    .unwrap()
                    .as_sierra()
                    .unwrap();

                assert_eq!(contract_class.class_hash().unwrap().hash(), SIERRA_HASH);

                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(
                    BroadcastedDeclareTransactionV2 {
                        version: TransactionVersion::TWO,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        nonce: transaction_nonce!("0x0"),
                        contract_class,
                        sender_address: account_contract_address,
                        compiled_class_hash: CASM_HASH,
                    },
                ))
            }

            pub fn universal_deployer(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        nonce: transaction_nonce!("0x1"),
                        version: TransactionVersion::ONE,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        sender_address: account_contract_address,
                        calldata: vec![
                            CallParam(*universal_deployer_address.get()),
                            // Entry point selector for the called contract, i.e. AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                            call_param!("4"),
                            // classHash
                            CallParam(SIERRA_HASH.0),
                            // salt
                            call_param!("0x0"),
                            // unique
                            call_param!("0x0"),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                ))
            }

            pub fn invoke(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        nonce: transaction_nonce!("0x2"),
                        version: TransactionVersion::ONE,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        sender_address: account_contract_address,
                        calldata: vec![
                            CallParam(*DEPLOYED_CONTRACT_ADDRESS.get()),
                            // Entry point selector for the called contract, i.e. AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                            call_param!("0"),
                        ],
                    },
                ))
            }
        }
    }

    pub(crate) async fn setup_storage() -> (
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
            crate::test_setup::test_storage(|state_update| {
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
