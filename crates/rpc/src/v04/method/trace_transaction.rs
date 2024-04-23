use pathfinder_common::TransactionHash;

use super::simulate_transactions::dto::TransactionTrace;
use crate::context::RpcContext;
use crate::error::TraceError;
use crate::v05::method::trace_transaction as v05;

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceTransactionInput {
    pub transaction_hash: TransactionHash,
}

#[derive(Debug, serde::Serialize, Eq, PartialEq)]
pub struct TraceTransactionOutput(pub TransactionTrace);

#[derive(Debug)]
pub enum TraceTransactionError {
    InvalidTxnHash,
    NoTraceAvailable(TraceError),
    Internal(anyhow::Error),
    Custom(anyhow::Error),
}

impl From<TraceTransactionError> for crate::error::ApplicationError {
    fn from(value: TraceTransactionError) -> Self {
        match value {
            TraceTransactionError::InvalidTxnHash => crate::error::ApplicationError::InvalidTxnHash,
            TraceTransactionError::NoTraceAvailable(e) => {
                crate::error::ApplicationError::NoTraceAvailable(e)
            }
            TraceTransactionError::Internal(e) => crate::error::ApplicationError::Internal(e),
            TraceTransactionError::Custom(e) => crate::error::ApplicationError::Custom(e),
        }
    }
}

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    let input = v05::TraceTransactionInput {
        transaction_hash: input.transaction_hash,
    };
    v05::trace_transaction(context, input)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

impl From<v05::TraceTransactionOutput> for TraceTransactionOutput {
    fn from(value: v05::TraceTransactionOutput) -> Self {
        Self(value.0.into())
    }
}

impl From<v05::TraceTransactionError> for TraceTransactionError {
    fn from(value: v05::TraceTransactionError) -> Self {
        match value {
            v05::TraceTransactionError::Internal(x) => Self::Internal(x),
            v05::TraceTransactionError::Custom(x) => Self::Custom(x),
            v05::TraceTransactionError::InvalidTxnHash => Self::InvalidTxnHash,
            v05::TraceTransactionError::NoTraceAvailable(x) => Self::NoTraceAvailable(x),
            v05::TraceTransactionError::ContractErrorV05 { revert_error } => {
                Self::Custom(anyhow::anyhow!("Transaction reverted: {revert_error}"))
            }
        }
    }
}
