use crate::{
    cairo::ext_py::{CallFailure, GasPriceSource},
    context::RpcContext,
    error::RpcError,
    v02::{
        method::estimate_fee::base_block_and_pending_for_call,
        types::{
            reply::{FeeEstimation, FunctionInvocation, TransactionSimulation, TransactionTrace},
            request::BroadcastedTransaction,
        },
    },
};
use anyhow::anyhow;
use pathfinder_common::BlockId;
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionResult, SimulateTrasactionError> {
    let handle = context
        .call_handle
        .as_ref()
        .ok_or_else(|| SimulateTrasactionError::IllegalState)?;

    let gas_price = if matches!(input.block_id, BlockId::Pending | BlockId::Latest) {
        let gas_price = match context.eth_gas_price.as_ref() {
            Some(cached) => cached.get().await,
            None => None,
        };

        let gas_price =
            gas_price.ok_or_else(|| anyhow::anyhow!("Current eth_gasPrice is unavailable"))?;

        GasPriceSource::Current(gas_price)
    } else {
        GasPriceSource::PastBlock
    };

    let (at_block, pending_timestamp, pending_update) =
        base_block_and_pending_for_call(input.block_id, &context.pending_data).await?;

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
            &input.transactions,
            (skip_execute, skip_validate),
        )
        .await
        .map_err(SimulateTrasactionError::CallFailed)?;

    let txs: Result<Vec<dto::SimulatedTransaction>, SimulateTrasactionError> =
        txs.into_iter().map(map_tx).collect();
    Ok(SimulateTransactionResult(txs?))
}

fn map_tx(tx: TransactionSimulation) -> Result<dto::SimulatedTransaction, SimulateTrasactionError> {
    Ok(dto::SimulatedTransaction {
        fee_estimation: Some(map_fee(tx.fee_estimation)),
        transaction_trace: Some(map_trace(tx.trace)?),
    })
}

fn map_fee(fee: FeeEstimation) -> dto::FeeEstimate {
    dto::FeeEstimate {
        gas_consumed: Some(fee.gas_consumed),
        gas_price: Some(fee.gas_price),
        overall_fee: Some(fee.overall_fee),
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
        code_address: fi.code_address,
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
) -> Result<dto::TransactionTrace, SimulateTrasactionError> {
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
        _ => Err(SimulateTrasactionError::Custom(anyhow!(
            "Unmatched transaction trace!"
        ))),
    }
}

#[derive(Deserialize, Debug)]
pub struct SimulateTrasactionInput {
    block_id: BlockId,
    transactions: Vec<BroadcastedTransaction>,
    simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize)]
pub struct SimulateTransactionResult(pub Vec<dto::SimulatedTransaction>);

#[derive(Debug)]
pub enum SimulateTrasactionError {
    Custom(anyhow::Error),
    IllegalState,
    CallFailed(CallFailure),
}

impl From<SimulateTrasactionError> for RpcError {
    fn from(value: SimulateTrasactionError) -> Self {
        match value {
            SimulateTrasactionError::IllegalState | SimulateTrasactionError::CallFailed(_) => {
                RpcError::Internal(anyhow!("Internal error"))
            }
            SimulateTrasactionError::Custom(e) => RpcError::Internal(e),
        }
    }
}

impl From<anyhow::Error> for SimulateTrasactionError {
    fn from(err: anyhow::Error) -> Self {
        Self::Custom(err)
    }
}

pub mod dto {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Signature(pub Vec<Felt>);

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Address(pub Felt);

    #[derive(Debug, Deserialize, Serialize)]
    pub struct FunctionCall {
        pub calldata: Vec<Felt>,
        pub contract_address: Address,
        pub entry_point_selector: Felt,
    }

    #[derive(Debug, Deserialize, Serialize)]
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

    #[derive(Debug, Deserialize, Serialize)]
    pub struct FunctionInvocation {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub call_type: Option<CallType>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub caller_address: Option<Felt>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub calls: Option<Vec<FunctionInvocation>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code_address: Option<Felt>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub events: Option<Vec<Event>>,
        #[serde(flatten)]
        pub function_call: FunctionCall,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub messages: Option<Vec<MsgToL1>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub result: Option<Vec<Felt>>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct MsgToL1 {
        pub payload: Vec<Felt>,
        pub to_address: Felt,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Event {
        #[serde(flatten)]
        pub event_content: EventContent,
        pub from_address: Address,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct EventContent {
        pub data: Vec<Felt>,
        pub keys: Vec<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(untagged)]
    pub enum TransactionTrace {
        Declare(DeclareTxnTrace),
        DeployAccount(DeployAccountTxnTrace),
        Invoke(InvokeTxnTrace),
        L1Handler(L1HandlerTxnTrace),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeclareTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeployAccountTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub constructor_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub execute_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct L1HandlerTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub function_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SimulatedTransaction {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_estimation: Option<FeeEstimate>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transaction_trace: Option<TransactionTrace>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct FeeEstimate {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub gas_consumed: Option<NumAsHex>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub gas_price: Option<NumAsHex>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub overall_fee: Option<NumAsHex>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct NumAsHex(pub String);
}

// TODO!(SM): tests

/*

curl -H 'Content-type: application/json' -d'@sim.json' http://127.0.0.1:9545/rpc/v0.3 | jq . > res.json

>>>
{
    "jsonrpc": "2.0",
    "method": "starknet_simulateTransaction",
    "params": {
        "block_id": "latest",
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
    },
    "id": "42?"
}

<<<
{
  "jsonrpc": "2.0",
  "result": [
    {
      "fee_estimation": {
        "gas_consumed": "0x00000000000000000000000000000000000000000000000000000000000010e3",
        "gas_price": "0x0000000000000000000000000000000000000000000000000000001a8fddc9e5",
        "overall_fee": "0x0000000000000000000000000000000000000000000000000001c08b6e48560f"
      },
      "transaction_trace": {
        "constructor_invocation": {
          "call_type": "CALL",
          "caller_address": "0x0",
          "calls": [],
          "code_address": "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
          "entry_point_type": "CONSTRUCTOR",
          "events": [],
          "calldata": [
            "0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
          ],
          "contract_address": "0x332141f07b2081e840cd12f62fb161606a24d1d81d54549cd5fb2ed419db415",
          "entry_point_selector": "0x28ffe4ff0f226a9107253e17a904099aa4f63a02a5621de0576e5aa71bc5194",
          "messages": [],
          "result": []
        },
        "validate_invocation": {
          "call_type": "CALL",
          "caller_address": "0x0",
          "calls": [],
          "code_address": "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
          "entry_point_type": "EXTERNAL",
          "events": [],
          "calldata": [
            "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
            "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
            "0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
          ],
          "contract_address": "0x332141f07b2081e840cd12f62fb161606a24d1d81d54549cd5fb2ed419db415",
          "entry_point_selector": "0x36fcbf06cd96843058359e1a75928beacfac10727dab22a3972f0af8aa92895",
          "messages": [],
          "result": []
        }
      }
    }
  ],
  "id": "42?"
}

---

[crates/rpc/src/v03/method/simulate_transaction.rs:22] &input = SimulateTrasactionInput {
    block_id: Latest,
    transactions: [
        DeployAccount(
            BroadcastedDeployAccountTransaction {
                version: TransactionVersion(
                    0x0000000000000000000000000000000100000000000000000000000000000001,
                ),
                max_fee: Fee(
                    0x00000000000000000000000000000000,
                ),
                signature: [
                    TransactionSignatureElem(0x0296AB4B0B7CB0C6929C4FB1E04B782511DFFB049F72A90EFE5D53F0515EAB88),
                    TransactionSignatureElem(0x04E80D8BB98A9BAF47F6F0459C2329A5401538576E76436ACAF5F56C573C7D77),
                ],
                nonce: TransactionNonce(0x0000000000000000000000000000000000000000000000000000000000000000),
                contract_address_salt: ContractAddressSalt(0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971),
                constructor_calldata: [
                    CallParam(0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D),
                ],
                class_hash: ClassHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
            },
        ),
    ],
    simulation_flags: SimulationFlags(
        [],
    ),
}
[crates/rpc/src/cairo/ext_py/sub_process.rs:397] &sent_over = SimulateTx {
    common: CommonProperties {
        at_block: Latest,
        chain: Testnet,
        pending_updates: ContractUpdatesWrapper(
            None,
        ),
        pending_deployed: DeployedContractsWrapper(
            None,
        ),
        pending_nonces: NoncesWrapper(
            None,
        ),
        pending_timestamp: 0,
    },
    gas_price: 0x0000000000000000000000000000000000000000000000000000001a8fddc9e5,
    transactions: [
        DeployAccount(
            DeployAccount {
                version: TransactionVersion(
                    0x0000000000000000000000000000000100000000000000000000000000000001,
                ),
                max_fee: Fee(
                    0x00000000000000000000000000000000,
                ),
                signature: [
                    TransactionSignatureElem(0x0296AB4B0B7CB0C6929C4FB1E04B782511DFFB049F72A90EFE5D53F0515EAB88),
                    TransactionSignatureElem(0x04E80D8BB98A9BAF47F6F0459C2329A5401538576E76436ACAF5F56C573C7D77),
                ],
                nonce: TransactionNonce(0x0000000000000000000000000000000000000000000000000000000000000000),
                class_hash: ClassHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
                contract_address_salt: ContractAddressSalt(0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971),
                constructor_calldata: [
                    CallParam(0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D),
                ],
            },
        ),
    ],
}
[crates/rpc/src/v03/method/simulate_transaction.rs:69] &txs = [
    TransactionSimulation {
        trace: TransactionTrace {
            validate_invocation: Some(
                FunctionInvocation {
                    calldata: [
                        StarkHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
                        StarkHash(0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971),
                        StarkHash(0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D),
                    ],
                    contract_address: Address(
                        StarkHash(0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415),
                    ),
                    selector: StarkHash(0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895),
                    call_type: Some(
                        Call,
                    ),
                    caller_address: Some(
                        StarkHash(0x0000000000000000000000000000000000000000000000000000000000000000),
                    ),
                    internal_calls: Some(
                        [],
                    ),
                    code_address: Some(
                        StarkHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
                    ),
                    entry_point_type: Some(
                        External,
                    ),
                    events: Some(
                        [],
                    ),
                    messages: Some(
                        [],
                    ),
                    result: Some(
                        [],
                    ),
                },
            ),
            function_invocation: Some(
                FunctionInvocation {
                    calldata: [
                        StarkHash(0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D),
                    ],
                    contract_address: Address(
                        StarkHash(0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415),
                    ),
                    selector: StarkHash(0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194),
                    call_type: Some(
                        Call,
                    ),
                    caller_address: Some(
                        StarkHash(0x0000000000000000000000000000000000000000000000000000000000000000),
                    ),
                    internal_calls: Some(
                        [],
                    ),
                    code_address: Some(
                        StarkHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
                    ),
                    entry_point_type: Some(
                        Constructor,
                    ),
                    events: Some(
                        [],
                    ),
                    messages: Some(
                        [],
                    ),
                    result: Some(
                        [],
                    ),
                },
            ),
            fee_transfer_invocation: None,
            signature: [
                StarkHash(0x0296AB4B0B7CB0C6929C4FB1E04B782511DFFB049F72A90EFE5D53F0515EAB88),
                StarkHash(0x04E80D8BB98A9BAF47F6F0459C2329A5401538576E76436ACAF5F56C573C7D77),
            ],
        },
        fee_estimation: FeeEstimation {
            overall_fee: NumAsHex(
                "0x0000000000000000000000000000000000000000000000000001c08b6e48560f",
            ),
            gas_price: NumAsHex(
                "0x0000000000000000000000000000000000000000000000000000001a8fddc9e5",
            ),
            gas_usage: NumAsHex(
                "0x00000000000000000000000000000000000000000000000000000000000010e3",
            ),
            unit: "wei",
        },
    },
]
[crates/rpc/src/v03/method/simulate_transaction.rs:74] &txs = Ok(
    [
        SimulatedTransaction {
            fee_estimation: Some(
                FeeEstimate {
                    gas_consumed: Some(
                        NumAsHex(
                            "0x00000000000000000000000000000000000000000000000000000000000010e3",
                        ),
                    ),
                    gas_price: Some(
                        NumAsHex(
                            "0x0000000000000000000000000000000000000000000000000000001a8fddc9e5",
                        ),
                    ),
                    overall_fee: Some(
                        NumAsHex(
                            "0x0000000000000000000000000000000000000000000000000001c08b6e48560f",
                        ),
                    ),
                },
            ),
            transaction_trace: Some(
                DeployAccount(
                    DeployAccountTxnTrace {
                        constructor_invocation: Some(
                            FunctionInvocation {
                                call_type: Some(
                                    Call,
                                ),
                                caller_address: Some(
                                    StarkHash(0x0000000000000000000000000000000000000000000000000000000000000000),
                                ),
                                calls: Some(
                                    [],
                                ),
                                code_address: Some(
                                    StarkHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
                                ),
                                entry_point_type: Some(
                                    Constructor,
                                ),
                                events: Some(
                                    [],
                                ),
                                function_call: FunctionCall {
                                    calldata: [
                                        StarkHash(0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D),
                                    ],
                                    contract_address: Address(
                                        StarkHash(0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415),
                                    ),
                                    entry_point_selector: StarkHash(0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194),
                                },
                                messages: Some(
                                    [],
                                ),
                                result: Some(
                                    [],
                                ),
                            },
                        ),
                        fee_transfer_invocation: None,
                        validate_invocation: Some(
                            FunctionInvocation {
                                call_type: Some(
                                    Call,
                                ),
                                caller_address: Some(
                                    StarkHash(0x0000000000000000000000000000000000000000000000000000000000000000),
                                ),
                                calls: Some(
                                    [],
                                ),
                                code_address: Some(
                                    StarkHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
                                ),
                                entry_point_type: Some(
                                    External,
                                ),
                                events: Some(
                                    [],
                                ),
                                function_call: FunctionCall {
                                    calldata: [
                                        StarkHash(0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513),
                                        StarkHash(0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971),
                                        StarkHash(0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D),
                                    ],
                                    contract_address: Address(
                                        StarkHash(0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415),
                                    ),
                                    entry_point_selector: StarkHash(0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895),
                                },
                                messages: Some(
                                    [],
                                ),
                                result: Some(
                                    [],
                                ),
                            },
                        ),
                    },
                ),
            ),
        },
    ],
)

 */
