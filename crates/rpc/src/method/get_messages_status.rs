use anyhow::Context;
use pathfinder_common::{L1TransactionHash, TransactionHash};
use pathfinder_ethereum::EthereumApi;
use serde::{Deserialize, Serialize};

use crate::context::RpcContext;
use crate::method::get_transaction_status;

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    transaction_hash: L1TransactionHash,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_hash: value
                    .deserialize("transaction_hash")
                    .map(L1TransactionHash::new)?,
            })
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FinalityStatus {
    Received,
    Rejected,
    AcceptedOnL2,
    AcceptedOnL1,
}

#[derive(Clone, Debug)]
pub struct L1HandlerTransactionStatus {
    transaction_hash: TransactionHash,
    finality_status: FinalityStatus,
    failure_reason: Option<String>,
}

#[derive(Debug)]
pub struct Output(Vec<L1HandlerTransactionStatus>);

crate::error::generate_rpc_error_subset!(Error: TxnHashNotFound);

pub async fn get_messages_status(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();

    let _g = span.enter();

    // Fetch the L1 handler transactions for the given transaction hash
    let ethereum = context.ethereum.clone();

    let l1_handler_txs = ethereum
        .get_l1_handler_txs(&context.core_contract_address, &input.transaction_hash)
        .await
        .context("Fetching L1 handler tx hashes")
        .map_err(|_| Error::TxnHashNotFound)?;

    let mut res = vec![];
    for tx in l1_handler_txs {
        let tx_hash = tx.calculate_hash(context.chain_id);

        let input = get_transaction_status::Input::new(tx_hash);
        let status = get_transaction_status(context.clone(), input)
            .await
            .map_err(|_| Error::TxnHashNotFound)?;

        use get_transaction_status::Output as TxStatus;
        let finality_status = match status {
            TxStatus::Received => FinalityStatus::Received,
            TxStatus::Rejected { .. } => FinalityStatus::Rejected,
            TxStatus::AcceptedOnL1(_) => FinalityStatus::AcceptedOnL1,
            TxStatus::AcceptedOnL2(_) => FinalityStatus::AcceptedOnL2,
        };

        let failure_reason = match status {
            TxStatus::Rejected { error_message, .. } => error_message,
            _ => None,
        };

        res.push(L1HandlerTransactionStatus {
            transaction_hash: tx.calculate_hash(context.chain_id),
            finality_status,
            failure_reason,
        });
    }

    Ok(Output(res))
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize_iter(self.0.len(), &mut self.0.clone().into_iter())
    }
}

impl crate::dto::serialize::SerializeForVersion for L1HandlerTransactionStatus {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("transaction_hash", &self.transaction_hash)?;
        serializer.serialize_field("finality_status", &self.finality_status)?;
        serializer.serialize_optional("failure_reason", self.failure_reason.as_deref())?;
        serializer.end()
    }
}
