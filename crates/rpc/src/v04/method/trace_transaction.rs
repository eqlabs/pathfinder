use serde::{Deserialize, Serialize};
use starknet_api::transaction::TransactionHash;

use crate::context::RpcContext;

use super::simulate_transactions::dto::TransactionTrace;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceTrasactionInput {
    transaction_hash: TransactionHash,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceTransactionOutput(TransactionTrace);

crate::error::generate_rpc_error_subset!(
    TraceTransactionError: InvalidTxnHash,
    NoTraceAvailable
);

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTrasactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    unimplemented!() // TODO(SM)
}
