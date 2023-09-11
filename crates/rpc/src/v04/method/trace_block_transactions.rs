use serde::{Deserialize, Serialize};
use starknet_api::{block::BlockHash, transaction::TransactionHash};

use crate::context::RpcContext;

use super::simulate_transactions::dto::TransactionTrace;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceBlockTrasactionsInput {
    block_hash: BlockHash,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct Trace {
    transaction_hash: TransactionHash,
    trace_root: TransactionTrace,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceBlockTransactionsOutput(Vec<Trace>);

crate::error::generate_rpc_error_subset!(
    TraceBlockTransactionsError: InvalidBlockHash
);

pub async fn trace_block_transactions(
    context: RpcContext,
    input: TraceBlockTrasactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    unimplemented!() // TODO(SM)
}
