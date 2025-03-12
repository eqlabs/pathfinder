use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockHeader, BlockId};

use crate::context::RpcContext;

crate::error::generate_rpc_error_subset!(Error: BlockNotFound);

pub struct Input {
    pub block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
            })
        })
    }
}

#[derive(Debug)]
pub enum Output {
    Pending {
        header: Arc<starknet_gateway_types::reply::PendingBlock>,
        transactions: Vec<Transaction>,
    },
    Full {
        header: Box<BlockHeader>,
        transactions: Vec<Transaction>,
        l1_accepted: bool,
    },
}

/// Get block information with full transactions given the block id
pub async fn get_block_with_txs(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();
    util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut connection = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&transaction)
                    .context("Querying pending data")?;

                let transactions = pending.block.transactions.to_vec();

                return Ok(Output::Pending {
                    header: pending.block,
                    transactions,
                });
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        let header = transaction
            .block_header(block_id)
            .context("Reading block from database")?
            .ok_or(Error::BlockNotFound)?;

        let l1_accepted = transaction.block_is_l1_accepted(header.number.into())?;

        let transactions = transaction
            .transactions_for_block(header.number.into())
            .context("Reading transactions from database")?
            .context("Transaction data missing")?
            .into_iter()
            .collect();

        Ok(Output::Full {
            header: Box::new(header),
            l1_accepted,
            transactions,
        })
    })
    .await
    .context("Joining blocking task")?
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            Output::Pending {
                header,
                transactions,
            } => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.flatten(header.as_ref())?;
                serializer.serialize_iter(
                    "transactions",
                    transactions.len(),
                    &mut transactions.iter().map(crate::dto::TransactionWithHash),
                )?;
                serializer.end()
            }
            Output::Full {
                header,
                transactions,
                l1_accepted,
            } => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.flatten(header.as_ref())?;
                serializer.serialize_iter(
                    "transactions",
                    transactions.len(),
                    &mut transactions.iter().map(crate::dto::TransactionWithHash),
                )?;
                serializer.serialize_field(
                    "status",
                    &if *l1_accepted {
                        "ACCEPTED_ON_L1"
                    } else {
                        "ACCEPTED_ON_L2"
                    },
                )?;
                serializer.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn pending(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;

        let input = Input {
            block_id: BlockId::Pending,
        };

        let output = get_block_with_txs(context, input).await.unwrap();
        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(output_json, version, "blocks/pending_with_txs.json");
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn latest(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;

        let input = Input {
            block_id: BlockId::Latest,
        };

        let output = get_block_with_txs(context, input).await.unwrap();
        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(output_json, version, "blocks/latest_with_txs.json");
    }
}
