use crate::{context::RpcContext, v02::types::request::BroadcastedTransaction};

use anyhow::Context;
use pathfinder_common::{BlockId, CallParam, EntryPoint};
use pathfinder_crypto::Felt;
use pathfinder_executor::{types::TransactionSimulation, CallError};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SimulateTransactionInput {
    block_id: BlockId,
    // `transactions` used to be called `transaction` in the JSON-RPC 0.3.0 specification.
    #[serde(alias = "transaction")]
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
                Self::Custom(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
        }
    }
}

impl From<crate::executor::ExecutionStateError> for SimulateTransactionError {
    fn from(error: crate::executor::ExecutionStateError) -> Self {
        use crate::executor::ExecutionStateError::*;
        match error {
            BlockNotFound => Self::BlockNotFound,
            Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTransactionInput,
) -> Result<SimulateTransactionOutput, SimulateTransactionError> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let skip_validate = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &dto::SimulationFlag::SkipValidate);

        let mut db = context
            .storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let (header, pending) = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                (pending.header(), Some(pending.state_update.clone()))
            }
            other => {
                let block_id = other.try_into().expect("Only pending should fail");

                let header = db
                    .block_header(block_id)
                    .context("Fetching block header")?
                    .ok_or(SimulateTransactionError::BlockNotFound)?;

                (header, None)
            }
        };

        let state =
            pathfinder_executor::ExecutionState::simulation(&db, context.chain_id, header, pending);

        let transactions = input
            .transactions
            .iter()
            .map(|tx| crate::executor::map_broadcasted_transaction(tx, context.chain_id))
            .collect::<Result<Vec<_>, _>>()?;

        let txs = pathfinder_executor::simulate(state, transactions, skip_validate, false)?;
        let txs = txs.into_iter().map(Into::into).collect();
        Ok(SimulateTransactionOutput(txs))
    })
    .await
    .context("Simulating transaction")?
}

pub(crate) mod dto {
    use serde_with::serde_as;

    use crate::felt::RpcFelt;
    use crate::v05::method::call::FunctionCall;

    use super::*;

    #[serde_as]
    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
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

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
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
    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    pub struct FunctionInvocation {
        #[serde(default)]
        pub call_type: CallType,
        #[serde_as(as = "RpcFelt")]
        pub caller_address: Felt,
        #[serde(default)]
        pub calls: Vec<FunctionInvocation>,
        #[serde(default)]
        #[serde_as(as = "Option<RpcFelt>")]
        pub code_address: Option<Felt>,
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
                code_address: fi.class_hash,
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
    #[derive(Debug, Serialize, Eq, PartialEq)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub execute_invocation: ExecuteInvocation,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
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
        pub fee_estimation: FeeEstimate,
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
    use pathfinder_common::{felt, TransactionVersion};
    use pathfinder_common::{macro_prelude::*, StorageAddress};
    use starknet_gateway_test_fixtures::class_definitions::DUMMY_ACCOUNT_CLASS_HASH;

    use crate::v02::types::request::BroadcastedDeployAccountTransaction;
    use crate::v05::method::call::FunctionCall;

    use super::*;

    #[tokio::test]
    async fn test_simulate_transaction() {
        let transaction = BroadcastedDeployAccountTransaction {
            contract_address_salt: contract_address_salt!(
                "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971"
            ),
            max_fee: fee!("0x100000000000"),
            signature: vec![],
            class_hash: DUMMY_ACCOUNT_CLASS_HASH,
            nonce: transaction_nonce!("0x0"),
            version: TransactionVersion::ONE_WITH_QUERY_VERSION,
            constructor_calldata: vec![],
        };

        let deployed_contract_address = transaction.deployed_contract_address();
        let account_balance_key =
            StorageAddress::from_map_name_and_key(b"ERC20_balances", deployed_contract_address.0);

        let (storage, _, _, _) = crate::test_setup::test_storage(|state_update| {
            state_update.with_storage_update(
                pathfinder_executor::FEE_TOKEN_ADDRESS,
                account_balance_key,
                storage_value!("0x10000000000000000000000000000"),
            )
        })
        .await;

        let context = RpcContext::for_tests().with_storage(storage);

        let input_json = serde_json::json!({
            "block_id": {"block_number": 1},
            "transaction": [
                BroadcastedTransaction::DeployAccount(transaction),
            ],
            "simulation_flags": []
        });
        let input = SimulateTransactionInput::deserialize(&input_json).unwrap();

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            let transaction =
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
                                        code_address: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
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
                                        code_address: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
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
                                fee_transfer_invocation: Some(
                                    FunctionInvocation {
                                        call_type: CallType::Call,
                                        caller_address: felt!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        calls: vec![],
                                        code_address: Some(
                                            felt!("0x013DBE991273192B5573C526CDDC27A27DECB8525B44536CB0F57B5B2C089B51"),
                                        ),
                                        entry_point_type: EntryPointType::External,
                                        events: vec![
                                            Event {
                                                data: vec![
                                                    felt!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                                    felt!("0x01176A1BD84444C89232EC27754698E5D2E7E1A7F1539F12027F28B23EC9F3D8"),
                                                    felt!("0x0000000000000000000000000000000000000000000000000000000000000C19"),
                                                    felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                                                ],
                                                keys: vec![
                                                    felt!("0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"),
                                                ],
                                            },
                                        ],
                                        function_call: FunctionCall {
                                            contract_address: contract_address!("0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7"),
                                            entry_point_selector: entry_point!("0x0083AFD3F4CAEDC6EEBF44246FE54E38C95E3179A5EC9EA81740ECA5B482D12E"),
                                            calldata: vec![
                                                call_param!("0x01176A1BD84444C89232EC27754698E5D2E7E1A7F1539F12027F28B23EC9F3D8"),
                                                call_param!("0x0000000000000000000000000000000000000000000000000000000000000C19"),
                                                call_param!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                                            ],
                                        },
                                        messages: vec![],
                                        result: vec![
                                            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                                        ],
                                    },
                                ),
                            },
                        ),
                };
            vec![transaction]
        };

        let result = simulate_transaction(context, input).await.expect("result");
        pretty_assertions::assert_eq!(result.0, expected);
    }
}
