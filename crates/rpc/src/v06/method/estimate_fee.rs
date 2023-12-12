use anyhow::Context;
use pathfinder_executor::ExecutionState;
use serde_with::serde_as;

use crate::{
    context::RpcContext, error::ApplicationError, v02::types::request::BroadcastedTransaction,
    v06::types::PriceUnit,
};
use pathfinder_common::BlockId;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EstimateFeeInput {
    pub request: Vec<BroadcastedTransaction>,
    pub simulation_flags: SimulationFlags,
    pub block_id: BlockId,
}

#[derive(Debug, serde::Deserialize, Eq, PartialEq)]
pub struct SimulationFlags(pub Vec<SimulationFlag>);

#[derive(Debug, serde::Deserialize, Eq, PartialEq)]
pub enum SimulationFlag {
    #[serde(rename = "SKIP_VALIDATE")]
    SkipValidate,
}

#[derive(Debug)]
pub enum EstimateFeeError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    TransactionExecutionError {
        transaction_index: usize,
        error: String,
    },
}

impl From<anyhow::Error> for EstimateFeeError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<pathfinder_executor::TransactionExecutionError> for EstimateFeeError {
    fn from(value: pathfinder_executor::TransactionExecutionError) -> Self {
        use pathfinder_executor::TransactionExecutionError::*;
        match value {
            ExecutionError {
                transaction_index,
                error,
            } => Self::TransactionExecutionError {
                transaction_index,
                error,
            },
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
        }
    }
}

impl From<crate::executor::ExecutionStateError> for EstimateFeeError {
    fn from(error: crate::executor::ExecutionStateError) -> Self {
        use crate::executor::ExecutionStateError::*;
        match error {
            BlockNotFound => Self::BlockNotFound,
            Internal(e) => Self::Internal(e),
        }
    }
}

impl From<EstimateFeeError> for ApplicationError {
    fn from(value: EstimateFeeError) -> Self {
        match value {
            EstimateFeeError::BlockNotFound => ApplicationError::BlockNotFound,
            EstimateFeeError::TransactionExecutionError {
                transaction_index,
                error,
            } => ApplicationError::TransactionExecutionError {
                transaction_index,
                error,
            },
            EstimateFeeError::Internal(e) => ApplicationError::Internal(e),
            EstimateFeeError::Custom(e) => ApplicationError::Custom(e),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct FeeEstimate {
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_consumed: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_price: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub overall_fee: primitive_types::U256,
    pub unit: PriceUnit,
}

impl From<pathfinder_executor::types::FeeEstimate> for FeeEstimate {
    fn from(value: pathfinder_executor::types::FeeEstimate) -> Self {
        Self {
            gas_consumed: value.gas_consumed,
            gas_price: value.gas_price,
            overall_fee: value.overall_fee,
            unit: value.unit.into(),
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<Vec<FeeEstimate>, EstimateFeeError> {
    let span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
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
                let block_id = other.try_into().expect("Only pending cast should fail");
                let header = db
                    .block_header(block_id)
                    .context("Querying block header")?
                    .ok_or(EstimateFeeError::BlockNotFound)?;

                (header, None)
            }
        };

        let state = ExecutionState::simulation(&db, context.chain_id, header, pending);

        let skip_validate = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &SimulationFlag::SkipValidate);

        let transactions = input
            .request
            .iter()
            .map(|tx| crate::executor::map_broadcasted_transaction(tx, context.chain_id))
            .collect::<Result<Vec<_>, _>>()?;

        let result = pathfinder_executor::estimate(state, transactions, skip_validate)?;

        Ok::<_, EstimateFeeError>(result)
    })
    .await
    .context("Executing transaction")??;

    Ok(result.into_iter().map(Into::into).collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransaction;
    use pathfinder_common::{
        felt, BlockHash, CallParam, ContractAddress, Fee, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };

    mod parsing {
        use super::*;
        use serde_json::json;

        fn test_invoke_txn() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                crate::v02::types::request::BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(felt!("0x6")),
                    signature: vec![TransactionSignatureElem(felt!("0x7"))],
                    nonce: TransactionNonce(felt!("0x8")),
                    sender_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                    calldata: vec![CallParam(felt!("0xff"))],
                },
            ))
        }

        #[test]
        fn positional_args() {
            let positional = json!([
                [
                    {
                        "type": "INVOKE",
                        "version": "0x100000000000000000000000000000001",
                        "max_fee": "0x6",
                        "signature": [
                            "0x7"
                        ],
                        "nonce": "0x8",
                        "sender_address": "0xaaa",
                        "calldata": [
                            "0xff"
                        ]
                    }
                ],
                ["SKIP_VALIDATE"],
                { "block_hash": "0xabcde" }
            ]);

            let input = serde_json::from_value::<EstimateFeeInput>(positional).unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                simulation_flags: SimulationFlags(vec![SimulationFlag::SkipValidate]),
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named_args = json!({
                "request": [
                    {
                        "type": "INVOKE",
                        "version": "0x100000000000000000000000000000001",
                        "max_fee": "0x6",
                        "signature": [
                            "0x7"
                        ],
                        "nonce": "0x8",
                        "sender_address": "0xaaa",
                        "calldata": [
                            "0xff"
                        ]
                    }
                ],
                "simulation_flags": ["SKIP_VALIDATE"],
                "block_id": { "block_hash": "0xabcde" }
            });
            let input = serde_json::from_value::<EstimateFeeInput>(named_args).unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                simulation_flags: SimulationFlags(vec![SimulationFlag::SkipValidate]),
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    mod in_memory {

        use super::*;

        use pathfinder_common::{macro_prelude::*, EntryPoint, Tip};

        use pathfinder_common::felt;

        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV2,
            BroadcastedInvokeTransactionV0, BroadcastedInvokeTransactionV1,
            BroadcastedInvokeTransactionV3,
        };
        use crate::v02::types::{
            ContractClass, DataAvailabilityMode, ResourceBounds, SierraContractClass,
        };

        #[test_log::test(tokio::test)]
        async fn declare_deploy_and_invoke_sierra_class() {
            let (context, last_block_header, account_contract_address, universal_deployer_address) =
                crate::test_setup::test_context().await;

            let sierra_definition =
                include_bytes!("../../../fixtures/contracts/storage_access.json");
            let sierra_hash =
                class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
            let casm_hash =
                casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");

            let contract_class: SierraContractClass =
                ContractClass::from_definition_bytes(sierra_definition)
                    .unwrap()
                    .as_sierra()
                    .unwrap();

            assert_eq!(contract_class.class_hash().unwrap().hash(), sierra_hash);

            let max_fee = Fee::default();

            // declare test class
            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V2(BroadcastedDeclareTransactionV2 {
                    version: TransactionVersion::TWO,
                    max_fee,
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class,
                    sender_address: account_contract_address,
                    compiled_class_hash: casm_hash,
                }),
            );
            // deploy with unversal deployer contract
            let deploy_transaction = BroadcastedTransaction::Invoke(
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
            let invoke_transaction = BroadcastedTransaction::Invoke(
                BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                    nonce: transaction_nonce!("0x2"),
                    version: TransactionVersion::ONE,
                    max_fee,
                    signature: vec![],
                    sender_address: account_contract_address,
                    calldata: vec![
                        // address of the deployed test contract
                        CallParam(felt!(
                            "0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7"
                        )),
                        // Entry point selector for the called contract, i.e. AccountCallArray::selector
                        CallParam(EntryPoint::hashed(b"get_data").0),
                        // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                        call_param!("0"),
                    ],
                }),
            );

            // do the same invoke with a v0 transaction
            let invoke_v0_transaction = BroadcastedTransaction::Invoke(
                BroadcastedInvokeTransaction::V0(BroadcastedInvokeTransactionV0 {
                    version: TransactionVersion::ONE,
                    max_fee,
                    signature: vec![],
                    contract_address: contract_address!(
                        "0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7"
                    ),
                    entry_point_selector: EntryPoint::hashed(b"get_data"),
                    calldata: vec![],
                }),
            );

            // do the same invoke with a v3 transaction
            let invoke_v3_transaction = BroadcastedTransaction::Invoke(
                BroadcastedInvokeTransaction::V3(BroadcastedInvokeTransactionV3 {
                    version: TransactionVersion::THREE,
                    signature: vec![],
                    sender_address: account_contract_address,
                    calldata: vec![
                        // address of the deployed test contract
                        CallParam(felt!(
                            "0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7"
                        )),
                        // Entry point selector for the called contract, i.e. AccountCallArray::selector
                        CallParam(EntryPoint::hashed(b"get_data").0),
                        // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                        call_param!("0"),
                    ],
                    nonce: transaction_nonce!("0x3"),
                    resource_bounds: ResourceBounds::default(),
                    tip: Tip(0),
                    paymaster_data: vec![],
                    account_deployment_data: vec![],
                    nonce_data_availability_mode: DataAvailabilityMode::L1,
                    fee_data_availability_mode: DataAvailabilityMode::L1,
                }),
            );

            let input = EstimateFeeInput {
                request: vec![
                    declare_transaction,
                    deploy_transaction,
                    invoke_transaction,
                    invoke_v0_transaction,
                    invoke_v3_transaction,
                ],
                simulation_flags: SimulationFlags(vec![]),
                block_id: BlockId::Number(last_block_header.number),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let declare_expected = FeeEstimate {
                gas_consumed: 3700.into(),
                gas_price: 1.into(),
                overall_fee: 3700.into(),
                unit: PriceUnit::Wei,
            };
            let deploy_expected = FeeEstimate {
                gas_consumed: 4337.into(),
                gas_price: 1.into(),
                overall_fee: 4337.into(),
                unit: PriceUnit::Wei,
            };
            let invoke_expected = FeeEstimate {
                gas_consumed: 2491.into(),
                gas_price: 1.into(),
                overall_fee: 2491.into(),
                unit: PriceUnit::Wei,
            };
            let invoke_v0_expected = FeeEstimate {
                gas_consumed: 1260.into(),
                gas_price: 1.into(),
                overall_fee: 1260.into(),
                unit: PriceUnit::Wei,
            };
            let invoke_v3_expected = FeeEstimate {
                gas_consumed: 2491.into(),
                // STRK gas price is 2
                gas_price: 2.into(),
                overall_fee: 4982.into(),
                unit: PriceUnit::Fri,
            };
            assert_eq!(
                result,
                vec![
                    declare_expected,
                    deploy_expected,
                    invoke_expected,
                    invoke_v0_expected,
                    invoke_v3_expected,
                ]
            );
        }
    }
}
