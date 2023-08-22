use anyhow::Context;
use serde_with::serde_as;

use crate::{context::RpcContext, v02::types::request::BroadcastedTransaction};
use pathfinder_common::BlockId;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EstimateFeeInput {
    request: Vec<BroadcastedTransaction>,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<pathfinder_executor::CallError> for EstimateFeeError {
    fn from(value: pathfinder_executor::CallError) -> Self {
        use pathfinder_executor::CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::Internal(anyhow::anyhow!("Invalid message selector")),
            Reverted(revert_error) => {
                Self::Internal(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
            Internal(e) => Self::Internal(e),
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

#[serde_as]
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct FeeEstimate {
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_consumed: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_price: primitive_types::U256,
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

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<Vec<FeeEstimate>, EstimateFeeError> {
    let chain_id = context.chain_id;

    let execution_state = crate::executor::execution_state(context, input.block_id, None).await?;

    let span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let transactions = input
            .request
            .iter()
            .map(|tx| crate::executor::map_broadcasted_transaction(tx, chain_id))
            .collect::<Result<Vec<_>, _>>()?;

        let result = pathfinder_executor::estimate(execution_state, transactions)?;

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
    use stark_hash::Felt;

    mod parsing {
        use super::*;

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
            use jsonrpsee::types::Params;

            let positional = r#"[
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
                { "block_hash": "0xabcde" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named_args = r#"{
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
                "block_id": { "block_hash": "0xabcde" }
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    mod in_memory {

        use super::*;

        use pathfinder_common::{macro_prelude::*, EntryPoint};

        use pathfinder_common::felt;

        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV2,
            BroadcastedInvokeTransactionV1,
        };
        use crate::v02::types::{ContractClass, SierraContractClass};

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

            let max_fee = Fee(Felt::from_u64(10_000_000));

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

            let input = EstimateFeeInput {
                request: vec![declare_transaction, deploy_transaction, invoke_transaction],
                block_id: BlockId::Number(last_block_header.number),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let declare_expected = FeeEstimate {
                gas_consumed: 3700.into(),
                gas_price: 1.into(),
                overall_fee: 3700.into(),
            };
            let deploy_expected = FeeEstimate {
                gas_consumed: 4337.into(),
                gas_price: 1.into(),
                overall_fee: 4337.into(),
            };
            let invoke_expected = FeeEstimate {
                gas_consumed: 2491.into(),
                gas_price: 1.into(),
                overall_fee: 2491.into(),
            };
            assert_eq!(
                result,
                vec![declare_expected, deploy_expected, invoke_expected]
            );
        }
    }
}
