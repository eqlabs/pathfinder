use std::sync::Arc;

use serde::Serialize;
use serde_with::serde_as;

use crate::{
    cairo::ext_py::{BlockHashNumberOrLatest, GasPriceSource},
    core::{BlockId, TransactionVersion},
    rpc::v02::types::request::BroadcastedTransaction,
    rpc::v02::{types::request::BroadcastedInvokeTransaction, RpcContext},
    state::PendingData,
};

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateFeeInput {
    request: BroadcastedTransaction,
    block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError,
    InvalidMessageSelector,
    InvalidCallData
);

impl From<crate::cairo::ext_py::CallFailure> for EstimateFeeError {
    fn from(c: crate::cairo::ext_py::CallFailure) -> Self {
        use crate::cairo::ext_py::CallFailure::*;
        match c {
            NoSuchBlock => Self::BlockNotFound,
            NoSuchContract => Self::ContractNotFound,
            InvalidEntryPoint => Self::InvalidMessageSelector,
            ExecutionFailed(e) => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
            // Intentionally hide the message under Internal
            Internal(_) | Shutdown => Self::Internal(anyhow::anyhow!("Internal error")),
        }
    }
}

impl TryInto<crate::rpc::v01::types::request::Call> for BroadcastedTransaction {
    type Error = EstimateFeeError;

    fn try_into(self) -> Result<crate::rpc::v01::types::request::Call, Self::Error> {
        match self {
            BroadcastedTransaction::Declare(_) | BroadcastedTransaction::Deploy(_) => {
                Err(EstimateFeeError::Internal(anyhow::anyhow!(
                    "Internal error: Only invoke transactions are supported."
                )))
            }
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(tx)) => {
                Ok(crate::rpc::v01::types::request::Call {
                    contract_address: tx.contract_address,
                    calldata: tx.calldata,
                    entry_point_selector: Some(tx.entry_point_selector),
                    signature: tx
                        .signature
                        .into_iter()
                        .map(|x| crate::core::CallSignatureElem(x.0))
                        .collect(),
                    max_fee: tx.max_fee,
                    version: TransactionVersion::ZERO,
                    nonce: tx.nonce,
                })
            }
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(tx)) => {
                Ok(crate::rpc::v01::types::request::Call {
                    contract_address: tx.sender_address,
                    calldata: tx.calldata,
                    entry_point_selector: None,
                    signature: tx
                        .signature
                        .into_iter()
                        .map(|x| crate::core::CallSignatureElem(x.0))
                        .collect(),
                    max_fee: tx.max_fee,
                    version: TransactionVersion::ONE,
                    nonce: tx.nonce,
                })
            }
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<FeeEstimate, EstimateFeeError> {
    let handle = context
        .call_handle
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Unsupported configuration"))?;

    // discussed during estimateFee work: when user is requesting using block_hash use the
    // gasPrice from the starknet_blocks::gas_price column, otherwise (tags) get the latest
    // eth_gasPrice.
    //
    // the fact that [`base_block_and_pending_for_call`] transforms pending cases to use
    // actual parent blocks by hash is an internal transformation we do for correctness,
    // unrelated to this consideration.
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

    let (when, pending_update) =
        base_block_and_pending_for_call(input.block_id, &context.pending_data).await?;

    let call: crate::rpc::v01::types::request::Call = input.request.try_into()?;

    let result = handle
        .estimate_fee(call, when, gas_price, pending_update)
        .await?;

    Ok(result.into())
}

/// Transforms the request to call or estimate fee at some point in time to the type expected
/// by [`crate::cairo::ext_py`] with the optional, latest pending data.
async fn base_block_and_pending_for_call(
    at_block: BlockId,
    pending_data: &Option<PendingData>,
) -> Result<
    (
        BlockHashNumberOrLatest,
        Option<Arc<crate::sequencer::reply::StateUpdate>>,
    ),
    anyhow::Error,
> {
    use crate::cairo::ext_py::Pending;

    match BlockHashNumberOrLatest::try_from(at_block) {
        Ok(when) => Ok((when, None)),
        Err(Pending) => {
            // we must have pending_data configured for pending requests, otherwise we fail
            // fast.
            match pending_data {
                Some(pending) => {
                    // call on this particular parent block hash; if it's not found at query time over
                    // at python, it should fall back to latest and **disregard** the pending data.
                    let pending_on_top_of_a_block = pending
                        .state_update_on_parent_block()
                        .await
                        .map(|(parent_block, data)| (parent_block.into(), Some(data)));

                    // if there is no pending data available, just execute on whatever latest.
                    Ok(
                        pending_on_top_of_a_block
                            .unwrap_or((BlockHashNumberOrLatest::Latest, None)),
                    )
                }
                None => Err(anyhow::anyhow!(
                    "Pending data not supported in this configuration"
                )),
            }
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
#[serde(deny_unknown_fields)]
pub struct FeeEstimate {
    /// The Ethereum gas cost of the transaction
    #[serde_as(as = "crate::rpc::serde::H256AsHexStr")]
    pub gas_consumed: web3::types::H256,
    /// The gas price (in gwei) that was used in the cost estimation (input to fee estimation)
    #[serde_as(as = "crate::rpc::serde::H256AsHexStr")]
    pub gas_price: web3::types::H256,
    /// The estimated fee for the transaction (in gwei), product of gas_consumed and gas_price
    #[serde_as(as = "crate::rpc::serde::H256AsHexStr")]
    pub overall_fee: web3::types::H256,
}

impl From<crate::rpc::v01::types::reply::FeeEstimate> for FeeEstimate {
    fn from(v01: crate::rpc::v01::types::reply::FeeEstimate) -> Self {
        Self {
            gas_consumed: v01.consumed,
            gas_price: v01.gas_price,
            overall_fee: v01.fee,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod parsing {
        use super::*;

        use crate::core::{
            CallParam, ContractAddress, EntryPoint, Fee, StarknetBlockHash, TransactionNonce,
            TransactionSignatureElem,
        };
        use crate::starkhash;

        fn test_invoke_txn() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                crate::rpc::v02::types::request::BroadcastedInvokeTransactionV0 {
                    max_fee: Fee(web3::types::H128::from_low_u64_be(0x6)),
                    signature: vec![TransactionSignatureElem(starkhash!("07"))],
                    nonce: TransactionNonce(starkhash!("08")),
                    contract_address: ContractAddress::new_or_panic(starkhash!("0aaa")),
                    entry_point_selector: EntryPoint(starkhash!("0e")),
                    calldata: vec![CallParam(starkhash!("ff"))],
                },
            ))
        }

        #[test]
        fn positional_args() {
            use jsonrpsee::types::Params;

            let positional = r#"[
                {
                    "type": "INVOKE",
                    "version": "0x0",
                    "max_fee": "0x6",
                    "signature": [
                        "0x7"
                    ],
                    "nonce": "0x8",
                    "contract_address": "0xaaa",
                    "entry_point_selector": "0xe",
                    "calldata": [
                        "0xff"
                    ]
                },
                { "block_hash": "0xabcde" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: test_invoke_txn(),
                block_id: BlockId::Hash(StarknetBlockHash(starkhash!("0abcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named_args = r#"{
                "request": {
                    "type": "INVOKE",
                    "version": "0x0",
                    "max_fee": "0x6",
                    "signature": [
                        "0x7"
                    ],
                    "nonce": "0x8",
                    "contract_address": "0xaaa",
                    "entry_point_selector": "0xe",
                    "calldata": [
                        "0xff"
                    ]
                },
                "block_id": { "block_hash": "0xabcde" }
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: test_invoke_txn(),
                block_id: BlockId::Hash(StarknetBlockHash(starkhash!("0abcde"))),
            };
            assert_eq!(input, expected);
        }
    }
}
