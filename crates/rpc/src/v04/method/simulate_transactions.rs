use crate::{
    context::RpcContext, executor::ExecutionStateError, v02::types::request::BroadcastedTransaction,
};

use anyhow::Context;
use pathfinder_common::{BlockId, CallParam, EntryPoint};
use pathfinder_executor::{types::TransactionSimulation, CallError};
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

#[derive(Deserialize, Debug)]
pub struct SimulateTrasactionInput {
    block_id: BlockId,
    transactions: Vec<BroadcastedTransaction>,
    simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct SimulateTransactionOutput(pub Vec<dto::SimulatedTransaction>);

crate::error::generate_rpc_error_subset!(
    SimulateTransactionError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<CallError> for SimulateTransactionError {
    fn from(value: CallError) -> Self {
        use CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::ContractError,
            Reverted(revert_error) => {
                Self::Internal(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
            Internal(e) => Self::Internal(e),
        }
    }
}

impl From<ExecutionStateError> for SimulateTransactionError {
    fn from(error: ExecutionStateError) -> Self {
        match error {
            ExecutionStateError::BlockNotFound => Self::BlockNotFound,
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn simulate_transactions(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionOutput, SimulateTransactionError> {
    let chain_id = context.chain_id;

    let execution_state = crate::executor::execution_state(context, input.block_id, None).await?;

    let skip_validate = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipValidate);

    let skip_fee_charge = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipFeeCharge);

    let span = tracing::Span::current();

    let txs = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let transactions = input
            .transactions
            .iter()
            .map(|tx| crate::executor::map_broadcasted_transaction(tx, chain_id))
            .collect::<Result<Vec<_>, _>>()?;

        pathfinder_executor::simulate(
            execution_state,
            transactions,
            skip_validate,
            skip_fee_charge,
        )
    })
    .await
    .context("Simulating transaction")??;

    let txs = txs.into_iter().map(Into::into).collect();
    Ok(SimulateTransactionOutput(txs))
}

pub mod dto {
    use serde_with::serde_as;

    use crate::felt::RpcFelt;
    use crate::v02::method::call::FunctionCall;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[serde_as]
    #[derive(Debug, Serialize, PartialEq, Eq)]
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

    #[derive(Debug, Serialize, Eq, PartialEq)]
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
    #[derive(Debug, Serialize, Eq, PartialEq)]
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

    #[derive(Debug, Serialize, Eq, PartialEq)]
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
    #[derive(Debug, Serialize, Eq, PartialEq)]
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
    #[derive(Debug, Serialize, Eq, PartialEq)]
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

    #[derive(Debug, Serialize, Eq, PartialEq)]
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
    #[derive(Debug, Serialize, Eq, PartialEq)]
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
    #[derive(Debug, Serialize, Eq, PartialEq)]
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

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        pub execute_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    impl From<pathfinder_executor::types::InvokeTransactionTrace> for InvokeTxnTrace {
        fn from(trace: pathfinder_executor::types::InvokeTransactionTrace) -> Self {
            Self {
                validate_invocation: trace.validate_invocation.map(Into::into),
                execute_invocation: trace.execute_invocation.map(Into::into),
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            }
        }
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Serialize, Eq, PartialEq)]
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
    #[derive(Debug, Serialize, Eq, PartialEq)]
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
}

#[cfg(test)]
mod tests {
    use crate::v02::method::call::FunctionCall;
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV2,
        BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1,
    };
    use crate::v02::types::ContractClass;
    use pathfinder_common::{felt, StorageAddress, TransactionVersion};
    use pathfinder_common::{macro_prelude::*, Fee};
    use starknet_gateway_test_fixtures::class_definitions::{
        DUMMY_ACCOUNT_CLASS_HASH, ERC20_CONTRACT_DEFINITION_CLASS_HASH,
    };

    use super::*;

    #[tokio::test]
    async fn test_simulate_transaction_with_skip_fee_charge() {
        let (context, _, _, _) = crate::test_setup::test_context().await;

        let input_json = serde_json::json!({
            "block_id": {"block_number": 1},
            "transactions": [
                {
                    "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                    "max_fee": "0x0",
                    "signature": [],
                    "class_hash": DUMMY_ACCOUNT_CLASS_HASH,
                    "nonce": "0x0",
                    "version": TransactionVersion::ONE_WITH_QUERY_VERSION,
                    "constructor_calldata": [],
                    "type": "DEPLOY_ACCOUNT"
                }
            ],
            "simulation_flags": ["SKIP_FEE_CHARGE"]
        });
        let input = SimulateTrasactionInput::deserialize(&input_json).unwrap();

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            vec![
            SimulatedTransaction {
                fee_estimation:
                    FeeEstimate {
                        gas_consumed: 3097.into(),
                        gas_price: 1.into(),
                        overall_fee: 3097.into(),
                    }
                ,
                transaction_trace:
                    TransactionTrace::DeployAccount(
                        DeployAccountTxnTrace {
                            constructor_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::Constructor,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                },
                            ),
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(DUMMY_ACCOUNT_CLASS_HASH.0),
                                            call_param!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971"),
                                        ],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                },
                            ),
                            fee_transfer_invocation: None,
                        },
                    ),
            }]
        };

        let result = simulate_transactions(context, input).await.expect("result");
        pretty_assertions::assert_eq!(result.0, expected);
    }

    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class() {
        let test_storage_key = StorageAddress::from_name(b"my_storage_var");
        let test_storage_value = storage_value!("0x09");
        // address of the deployed test contract
        let deployed_contract_address =
            contract_address!("0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7");

        // set test storage variable
        let (storage, last_block_header, account_contract_address, universal_deployer_address) =
            crate::test_setup::test_storage(|state_update| {
                state_update.with_storage_update(
                    deployed_contract_address,
                    test_storage_key,
                    test_storage_value,
                )
            })
            .await;
        let context = RpcContext::for_tests().with_storage(storage);

        let universal_deployer_class_hash =
            class_hash!("0x06f38fb91ddbf325a0625533576bb6f6eafd9341868a9ec3faa4b01ce6c4f4dc");

        let sierra_definition = include_bytes!("../../../fixtures/contracts/storage_access.json");
        let sierra_hash =
            class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
        let casm_hash =
            casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");

        let contract_class = ContractClass::from_definition_bytes(sierra_definition)
            .unwrap()
            .as_sierra()
            .unwrap();

        assert_eq!(contract_class.class_hash().unwrap().hash(), sierra_hash);

        let max_fee = Fee(Felt::from_u64(10_000_000));

        // declare test class
        let declare_transaction = BroadcastedTransaction::Declare(
            BroadcastedDeclareTransaction::V2(BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee,
                signature: vec![],
                nonce: transaction_nonce!("0x0"),
                contract_class,
                sender_address: account_contract_address,
                compiled_class_hash: casm_hash,
            }),
        );
        // deploy with unversal deployer contract
        let universal_deployer_transaction = BroadcastedTransaction::Invoke(
            BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                nonce: transaction_nonce!("0x1"),
                version: TransactionVersion::ONE,
                max_fee,
                signature: vec![],
                sender_address: account_contract_address,
                calldata: vec![
                    CallParam(*universal_deployer_address.get()),
                    // Entry point selector for the called contract, i.e. AccountCallArray::selector
                    CallParam(EntryPoint::hashed(b"deployContract").0),
                    // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                    call_param!("4"),
                    // classHash
                    CallParam(sierra_hash.0),
                    // salt
                    call_param!("0x0"),
                    // unique
                    call_param!("0x0"),
                    // calldata_len
                    call_param!("0x0"),
                ],
            }),
        );

        // invoke deployed contract
        let invoke_transaction = BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
            BroadcastedInvokeTransactionV1 {
                nonce: transaction_nonce!("0x2"),
                version: TransactionVersion::ONE,
                max_fee,
                signature: vec![],
                sender_address: account_contract_address,
                calldata: vec![
                    CallParam(*deployed_contract_address.get()),
                    // Entry point selector for the called contract, i.e. AccountCallArray::selector
                    CallParam(EntryPoint::hashed(b"get_data").0),
                    // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                    call_param!("0"),
                ],
            },
        ));

        let input = SimulateTrasactionInput {
            transactions: vec![
                declare_transaction,
                universal_deployer_transaction,
                invoke_transaction,
            ],
            block_id: BlockId::Number(last_block_header.number),
            simulation_flags: dto::SimulationFlags(vec![]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        let expected_declare_output = {
            use dto::*;

            const GAS_CONSUMED: u64 = 3700;

            SimulatedTransaction {
                fee_estimation:
                    FeeEstimate {
                        gas_consumed: GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        overall_fee: GAS_CONSUMED.into(),
                    }
                ,
                transaction_trace:
                    TransactionTrace::Declare(
                        DeclareTxnTrace {
                            fee_transfer_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: *account_contract_address.get(),
                                    calls: vec![],
                                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![
                                        Event {
                                            data: vec![
                                                *account_contract_address.get(),
                                                last_block_header.sequencer_address.0,
                                                Felt::from_u64(GAS_CONSUMED),
                                                felt!("0x0"),
                                            ],
                                            keys: vec![
                                                felt!("0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"),
                                            ]
                                        }
                                    ],
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(last_block_header.sequencer_address.0),
                                            CallParam(Felt::from_u64(GAS_CONSUMED)),
                                            call_param!("0x0"),
                                        ],
                                        contract_address: pathfinder_executor::FEE_TOKEN_ADDRESS,
                                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                                    },
                                    messages: vec![],
                                    result: vec![
                                        felt!("0x1"),
                                    ],
                                },
                            ),
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        contract_address: account_contract_address,
                                        entry_point_selector: EntryPoint::hashed(b"__validate_declare__"),
                                        calldata: vec![
                                            CallParam(sierra_hash.0),
                                        ],
                                    },
                                    messages: vec![],
                                    result: vec![],
                                },
                            ),
                        },
                    ),
            }
        };

        let expected_universal_deployer_output = {
            use dto::*;

            const GAS_CONSUMED: u64 = 4337;

            SimulatedTransaction {
                fee_estimation:
                    FeeEstimate {
                        gas_consumed: GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        overall_fee: GAS_CONSUMED.into(),
                    }
                ,
                transaction_trace:
                    TransactionTrace::Invoke(
                        InvokeTxnTrace {
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        contract_address: account_contract_address,
                                        entry_point_selector: EntryPoint::hashed(b"__validate__"),
                                        calldata: vec![
                                            CallParam(universal_deployer_address.0),
                                            CallParam(EntryPoint::hashed(b"deployContract").0),
                                            // calldata_len
                                            call_param!("0x4"),
                                            // classHash
                                            CallParam(sierra_hash.0),
                                            // salt
                                            call_param!("0x0"),
                                            // unique
                                            call_param!("0x0"),
                                            // calldata_len
                                            call_param!("0x0"),
                                        ],
                                    },
                                    messages: vec![],
                                    result: vec![],
                                },
                            ),
                            execute_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![
                                        FunctionInvocation {
                                            call_type: CallType::Call,
                                            caller_address: *account_contract_address.get(),
                                            calls: vec![
                                                FunctionInvocation {
                                                    call_type: CallType::Call,
                                                    caller_address: *universal_deployer_address.get(),
                                                    calls: vec![],
                                                    class_hash: Some(sierra_hash.0),
                                                    entry_point_type: EntryPointType::Constructor,
                                                    events: vec![],
                                                    function_call: FunctionCall {
                                                        contract_address: deployed_contract_address,
                                                        entry_point_selector: EntryPoint::hashed(b"constructor"),
                                                        calldata: vec![],
                                                    },
                                                    messages: vec![],
                                                    result: vec![],
                                                },
                                            ],
                                            class_hash: Some(universal_deployer_class_hash.0),
                                            entry_point_type: EntryPointType::External,
                                            events: vec![
                                                Event {
                                                    data: vec![
                                                        *deployed_contract_address.get(),
                                                        *account_contract_address.get(),
                                                        felt!("0x0"),
                                                        sierra_hash.0,
                                                        felt!("0x0"),
                                                        felt!("0x0"),
                                                    ],
                                                    keys: vec![
                                                        felt!("0x026B160F10156DEA0639BEC90696772C640B9706A47F5B8C52EA1ABE5858B34D"),
                                                    ]
                                                },
                                            ],
                                            function_call: FunctionCall {
                                                contract_address: universal_deployer_address,
                                                entry_point_selector: EntryPoint::hashed(b"deployContract"),
                                                calldata: vec![
                                                    // classHash
                                                    CallParam(sierra_hash.0),
                                                    // salt
                                                    call_param!("0x0"),
                                                    // unique
                                                    call_param!("0x0"),
                                                    //  calldata_len
                                                    call_param!("0x0"),
                                                ],
                                            },
                                            messages: vec![],
                                            result: vec![
                                                *deployed_contract_address.get(),
                                            ],
                                        }
                                    ],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        contract_address: account_contract_address,
                                        entry_point_selector: EntryPoint::hashed(b"__execute__"),
                                        calldata: vec![
                                            CallParam(universal_deployer_address.0),
                                            CallParam(EntryPoint::hashed(b"deployContract").0),
                                            call_param!("0x4"),
                                            // classHash
                                            CallParam(sierra_hash.0),
                                            // salt
                                            call_param!("0x0"),
                                            // unique
                                            call_param!("0x0"),
                                            // calldata_len
                                            call_param!("0x0"),
                                        ],
                                    },
                                    messages: vec![],
                                    result: vec![
                                        *deployed_contract_address.get(),
                                    ],
                                },
                            ),
                            fee_transfer_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: *account_contract_address.get(),
                                    calls: vec![],
                                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![
                                        Event {
                                            data: vec![
                                                *account_contract_address.get(),
                                                last_block_header.sequencer_address.0,
                                                Felt::from_u64(GAS_CONSUMED),
                                                felt!("0x0"),
                                            ],
                                            keys: vec![
                                                felt!("0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"),
                                            ]
                                        }
                                    ],
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(last_block_header.sequencer_address.0),
                                            CallParam(Felt::from_u64(GAS_CONSUMED)),
                                            // calldata_len
                                            call_param!("0x0"),
                                        ],
                                        contract_address: pathfinder_executor::FEE_TOKEN_ADDRESS,
                                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                                    },
                                    messages: vec![],
                                    result: vec![
                                        felt!("0x1"),
                                    ],
                                },
                            ),
                        },
                    ),
            }
        };

        let expected_invoke_output = {
            use dto::*;

            const GAS_CONSUMED: u64 = 2491;

            SimulatedTransaction {
                fee_estimation:
                    FeeEstimate {
                        gas_consumed: GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        overall_fee: GAS_CONSUMED.into(),
                    }
                ,
                transaction_trace:
                    TransactionTrace::Invoke(
                        InvokeTxnTrace {
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        contract_address: account_contract_address,
                                        entry_point_selector: EntryPoint::hashed(b"__validate__"),
                                        calldata: vec![
                                            CallParam(deployed_contract_address.0),
                                            CallParam(EntryPoint::hashed(b"get_data").0),
                                            // calldata_len
                                            call_param!("0x0"),
                                        ],
                                    },
                                    messages: vec![],
                                    result: vec![],
                                },
                            ),
                            execute_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![
                                        FunctionInvocation {
                                            call_type: CallType::Call,
                                            caller_address: *account_contract_address.get(),
                                            calls: vec![],
                                            class_hash: Some(sierra_hash.0),
                                            entry_point_type: EntryPointType::External,
                                            events: vec![],
                                            function_call: FunctionCall {
                                                contract_address: deployed_contract_address,
                                                entry_point_selector: EntryPoint::hashed(b"get_data"),
                                                calldata: vec![],
                                            },
                                            messages: vec![],
                                            result: vec![
                                                test_storage_value.0,
                                            ],
                                        }
                                    ],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        contract_address: account_contract_address,
                                        entry_point_selector: EntryPoint::hashed(b"__execute__"),
                                        calldata: vec![
                                            CallParam(deployed_contract_address.0),
                                            CallParam(EntryPoint::hashed(b"get_data").0),
                                            // calldata_len
                                            call_param!("0x0"),
                                        ],
                                    },
                                    messages: vec![],
                                    result: vec![
                                        test_storage_value.0,
                                    ],
                                },
                            ),
                            fee_transfer_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: *account_contract_address.get(),
                                    calls: vec![],
                                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![
                                        Event {
                                            data: vec![
                                                *account_contract_address.get(),
                                                last_block_header.sequencer_address.0,
                                                Felt::from_u64(GAS_CONSUMED),
                                                felt!("0x0"),
                                            ],
                                            keys: vec![
                                                felt!("0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"),
                                            ]
                                        }
                                    ],
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(last_block_header.sequencer_address.0),
                                            CallParam(Felt::from_u64(GAS_CONSUMED)),
                                            call_param!("0x0"),
                                        ],
                                        contract_address: pathfinder_executor::FEE_TOKEN_ADDRESS,
                                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                                    },
                                    messages: vec![],
                                    result: vec![
                                        felt!("0x1"),
                                    ],
                                },
                            ),
                        },
                    ),
            }
        };

        pretty_assertions::assert_eq!(
            result,
            SimulateTransactionOutput(vec![
                expected_declare_output,
                expected_universal_deployer_output,
                expected_invoke_output,
            ])
        );
    }

    #[tokio::test]
    async fn test_skip_fee_charge_flag_returns_error() {
        let (context, _, _, _) = crate::test_setup::test_context().await;

        let input_json = serde_json::json!({
            "block_id": {"block_number": 1},
            "transactions": [],
            "simulation_flags": ["SKIP_FEE_CHARGE"]
        });
        let input = SimulateTrasactionInput::deserialize(&input_json).unwrap();
        let error = simulate_transactions(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, SimulateTransactionError::Internal(e) => { assert_eq!(e.to_string(), "Simulation flags are unsupported") });
    }

    #[tokio::test]
    async fn test_skip_validate_flag_returns_error() {
        let (context, _, _, _) = crate::test_setup::test_context().await;

        let input_json = serde_json::json!({
            "block_id": {"block_number": 1},
            "transactions": [],
            "simulation_flags": ["SKIP_VALIDATE"]
        });
        let input = SimulateTrasactionInput::deserialize(&input_json).unwrap();
        let error = simulate_transactions(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, SimulateTransactionError::Internal(e) => { assert_eq!(e.to_string(), "Simulation flags are unsupported") });
    }
}
