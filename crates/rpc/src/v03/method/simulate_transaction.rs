use crate::{
    cairo::ext_py::{
        types::{FeeEstimate, FunctionInvocation, TransactionSimulation, TransactionTrace},
        CallFailure,
    },
    context::RpcContext,
    v02::types::{reply, request::BroadcastedTransaction},
};

use anyhow::anyhow;
use pathfinder_common::BlockId;
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

use super::common::prepare_handle_and_block;

#[derive(Deserialize, Debug)]
pub struct SimulateTrasactionInput {
    block_id: BlockId,
    transactions: Vec<BroadcastedTransaction>,
    simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct SimulateTransactionResult(pub Vec<dto::SimulatedTransaction>);

crate::error::generate_rpc_error_subset!(
    SimulateTransactionError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<CallFailure> for SimulateTransactionError {
    fn from(value: CallFailure) -> Self {
        match value {
            CallFailure::NoSuchBlock => Self::BlockNotFound,
            CallFailure::NoSuchContract => Self::ContractNotFound,
            CallFailure::InvalidEntryPoint => Self::ContractError,
            CallFailure::ExecutionFailed(e) => Self::Internal(anyhow!("Execution failed: {e:?}")),
            CallFailure::Internal(e) => Self::Internal(anyhow!("Internal error: {e:?}")),
            CallFailure::Shutdown => Self::Internal(anyhow!("Internal error")),
        }
    }
}

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionResult, SimulateTransactionError> {
    let (handle, gas_price, at_block, pending_timestamp, pending_update) =
        prepare_handle_and_block(&context, input.block_id).await?;

    let skip_execute = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipExecute);
    let skip_validate = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipValidate);
    let txs = handle
        .simulate_transaction(
            at_block,
            gas_price,
            pending_update,
            pending_timestamp,
            input.transactions,
            (skip_execute, skip_validate),
        )
        .await
        .map_err(SimulateTransactionError::from)?;

    let txs: Result<Vec<dto::SimulatedTransaction>, SimulateTransactionError> =
        txs.into_iter().map(map_tx).collect();
    Ok(SimulateTransactionResult(txs?))
}

fn map_tx(
    tx: TransactionSimulation,
) -> Result<dto::SimulatedTransaction, SimulateTransactionError> {
    Ok(dto::SimulatedTransaction {
        fee_estimation: Some(map_fee(tx.fee_estimation)),
        transaction_trace: Some(map_trace(tx.trace)?),
    })
}

fn map_fee(fee: FeeEstimate) -> reply::FeeEstimate {
    reply::FeeEstimate {
        gas_consumed: fee.gas_consumed,
        gas_price: fee.gas_price,
        overall_fee: fee.overall_fee,
    }
}

fn map_function_invocation(mut fi: FunctionInvocation) -> dto::FunctionInvocation {
    dto::FunctionInvocation {
        call_type: fi.call_type,
        caller_address: fi.caller_address,
        calls: fi
            .internal_calls
            .take()
            .map(|calls| calls.into_iter().map(map_function_invocation).collect()),
        code_address: fi.class_hash,
        entry_point_type: fi.entry_point_type,
        events: fi.events,
        messages: fi.messages,
        function_call: dto::FunctionCall {
            calldata: fi.calldata,
            contract_address: fi.contract_address,
            entry_point_selector: fi.selector,
        },
        result: fi.result,
    }
}

fn map_trace(
    mut trace: TransactionTrace,
) -> Result<dto::TransactionTrace, SimulateTransactionError> {
    let invocations = (
        trace.validate_invocation.take(),
        trace.function_invocation.take(),
        trace.fee_transfer_invocation.take(),
    );
    match invocations {
        (Some(val), Some(fun), fee)
            if fun.entry_point_type == Some(dto::EntryPointType::Constructor) =>
        {
            Ok(dto::TransactionTrace::DeployAccount(
                dto::DeployAccountTxnTrace {
                    fee_transfer_invocation: fee.map(map_function_invocation),
                    validate_invocation: Some(map_function_invocation(val)),
                    constructor_invocation: Some(map_function_invocation(fun)),
                },
            ))
        }
        (Some(val), Some(fun), fee)
            if fun.entry_point_type == Some(dto::EntryPointType::External) =>
        {
            Ok(dto::TransactionTrace::Invoke(dto::InvokeTxnTrace {
                fee_transfer_invocation: fee.map(map_function_invocation),
                validate_invocation: Some(map_function_invocation(val)),
                execute_invocation: Some(map_function_invocation(fun)),
            }))
        }
        (Some(val), _, fee) => Ok(dto::TransactionTrace::Declare(dto::DeclareTxnTrace {
            fee_transfer_invocation: fee.map(map_function_invocation),
            validate_invocation: Some(map_function_invocation(val)),
        })),
        (_, Some(fun), _) => Ok(dto::TransactionTrace::L1Handler(dto::L1HandlerTxnTrace {
            function_invocation: Some(map_function_invocation(fun)),
        })),
        _ => Err(SimulateTransactionError::Internal(anyhow!(
            "Unmatched transaction trace: '{trace:?}'"
        ))),
    }
}

pub mod dto {
    use crate::v02::types::reply::FeeEstimate;

    use super::*;

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Signature(pub Vec<Felt>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Address(pub Felt);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct FunctionCall {
        pub calldata: Vec<Felt>,
        pub contract_address: Address,
        pub entry_point_selector: Felt,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum CallType {
        #[serde(rename = "CALL")]
        Call,
        #[serde(rename = "LIBRARY_CALL")]
        LibraryCall,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum EntryPointType {
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct FunctionInvocation {
        #[serde(default)]
        pub call_type: Option<CallType>,
        #[serde(default)]
        pub caller_address: Option<Felt>,
        #[serde(default)]
        pub calls: Option<Vec<FunctionInvocation>>,
        #[serde(default)]
        pub code_address: Option<Felt>,
        #[serde(default)]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        pub events: Option<Vec<Event>>,
        #[serde(flatten)]
        pub function_call: FunctionCall,
        #[serde(default)]
        pub messages: Option<Vec<MsgToL1>>,
        #[serde(default)]
        pub result: Option<Vec<Felt>>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct MsgToL1 {
        pub payload: Vec<Felt>,
        pub to_address: Felt,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Event {
        #[serde(flatten)]
        pub event_content: EventContent,
        pub from_address: Address,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct EventContent {
        pub data: Vec<Felt>,
        pub keys: Vec<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    #[serde(untagged)]
    pub enum TransactionTrace {
        Declare(DeclareTxnTrace),
        DeployAccount(DeployAccountTxnTrace),
        Invoke(InvokeTxnTrace),
        L1Handler(L1HandlerTxnTrace),
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct DeclareTxnTrace {
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct DeployAccountTxnTrace {
        #[serde(default)]
        pub constructor_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        pub execute_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct L1HandlerTxnTrace {
        #[serde(default)]
        pub function_invocation: Option<FunctionInvocation>,
    }

    #[serde_with::skip_serializing_none]
    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulatedTransaction {
        #[serde(default)]
        pub fee_estimation: Option<FeeEstimate>,
        #[serde(default)]
        pub transaction_trace: Option<TransactionTrace>,
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::{felt, Chain};
    use pathfinder_storage::{JournalMode, Storage};
    use tempfile::tempdir;

    use crate::v02::types::reply::FeeEstimate;

    use super::*;

    #[tokio::test]
    async fn test_simulate_transaction_deploy_balance_contract() {
        use starknet_gateway_test_fixtures::testnet::balance_contract::{
            CLASS_DEFINITION, CLASS_HASH,
        };

        let dir = tempdir().expect("tempdir");
        let mut db_path = dir.path().to_path_buf();
        db_path.push("db.sqlite");

        let storage = Storage::migrate(db_path, JournalMode::WAL).expect("storage");

        {
            let mut db = storage.connection().expect("db connection");
            let tx = db.transaction().expect("tx");
            tx.execute(
                "insert into class_definitions (hash, definition) values (?, ?)",
                [
                    hex::decode(CLASS_HASH).expect("class hash"),
                    hex::decode(CLASS_DEFINITION).expect("class def"),
                ],
            )
            .expect("insert class");
            tx.execute("insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address) values (?, 1, 1, ?, x'01', ?)", [
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
            ]).expect("insert block");
            tx.commit().expect("commit");
        }

        let (call_handle, _join_handle) = crate::cairo::ext_py::start(
            storage.path().into(),
            std::num::NonZeroUsize::try_from(1).unwrap(),
            futures::future::pending(),
            Chain::Testnet,
        )
        .await
        .unwrap();

        let rpc = RpcContext::for_tests()
            .with_storage(storage)
            .with_call_handling(call_handle);

        let input_json = r#"{
            "block_id": {"block_number": 1},
            "transactions": [
                {
                    "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                    "max_fee": "0x0",
                    "signature": [
                        "0x296ab4b0b7cb0c6929c4fb1e04b782511dffb049f72a90efe5d53f0515eab88",
                        "0x4e80d8bb98a9baf47f6f0459c2329a5401538576e76436acaf5f56c573c7d77"
                    ],
                    "class_hash": "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
                    "nonce": "0x0",
                    "version": "0x100000000000000000000000000000001",
                    "constructor_calldata": [
                        "0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
                    ],
                    "type": "DEPLOY_ACCOUNT"
                }
            ],
            "simulation_flags": []
        }"#;
        let input: SimulateTrasactionInput = serde_json::from_str(input_json).expect("input");

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            use ethers::types::H256;

            vec![
            SimulatedTransaction {
                fee_estimation: Some(
                    FeeEstimate {
                        gas_consumed: H256::from_low_u64_be(0x010e3),
                        gas_price: H256::from_low_u64_be(0x01),
                        overall_fee: H256::from_low_u64_be(0x010e3),
                    }
                ),
                transaction_trace: Some(
                    TransactionTrace::DeployAccount(
                        DeployAccountTxnTrace {
                            constructor_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: Some(felt!("0x0")),
                                    calls: Some(vec![]),
                                    code_address: Some(felt!("0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513")),
                                    entry_point_type: Some(EntryPointType::Constructor),
                                    events: Some(vec![]),
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            felt!("0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D"),
                                        ],
                                        contract_address: Address(felt!("0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415")),
                                        entry_point_selector: felt!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"),
                                    },
                                    messages: Some(vec![]),
                                    result: Some(vec![]),
                                },
                            ),
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: Some(felt!("0x0")),
                                    calls: Some(vec![]),
                                    code_address: Some(felt!("0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513")),
                                    entry_point_type: Some(EntryPointType::External),
                                    events: Some(vec![]),
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            felt!("0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513"),
                                            felt!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971"),
                                            felt!("0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D"),
                                        ],
                                        contract_address: Address(felt!("0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415")),
                                        entry_point_selector: felt!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895"),
                                    },
                                    messages: Some(vec![]),
                                    result: Some(vec![]),
                                },
                            ),
                            fee_transfer_invocation: None,
                        },
                    ),
                ),
            }]
        };

        let result = simulate_transaction(rpc, input).await.expect("result");
        assert_eq!(result.0, expected);
    }
}
