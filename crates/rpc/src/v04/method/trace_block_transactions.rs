use pathfinder_common::{BlockHash, TransactionHash};
use serde::{Deserialize, Serialize};

use super::simulate_transactions::dto::TransactionTrace;

use crate::{context::RpcContext, v05::method::trace_block_transactions as v05};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceBlockTransactionsInput {
    block_hash: BlockHash,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct Trace {
    pub transaction_hash: TransactionHash,
    pub trace_root: TransactionTrace,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceBlockTransactionsOutput(pub Vec<Trace>);

crate::error::generate_rpc_error_subset!(
    TraceBlockTransactionsError: InvalidBlockHash
);

pub async fn trace_block_transactions(
    context: RpcContext,
    input: TraceBlockTransactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    let input = v05::TraceBlockTransactionsInput {
        block_id: input.block_hash.into(),
    };

    v05::trace_block_transactions(context, input)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

impl From<v05::TraceBlockTransactionsOutput> for TraceBlockTransactionsOutput {
    fn from(value: v05::TraceBlockTransactionsOutput) -> Self {
        Self(
            value
                .0
                .into_iter()
                .map(|t| Trace {
                    transaction_hash: t.transaction_hash,
                    trace_root: t.trace_root.into(),
                })
                .collect(),
        )
    }
}

impl From<v05::TraceBlockTransactionsError> for TraceBlockTransactionsError {
    fn from(value: v05::TraceBlockTransactionsError) -> Self {
        match value {
            v05::TraceBlockTransactionsError::Internal(x) => Self::Internal(x),
            v05::TraceBlockTransactionsError::Custom(x) => Self::Custom(x),
            v05::TraceBlockTransactionsError::BlockNotFound => Self::InvalidBlockHash,
            v05::TraceBlockTransactionsError::ContractErrorV05 { revert_error } => {
                Self::Custom(anyhow::anyhow!("Transaction reverted: {revert_error}"))
            }
        }
    }
}
