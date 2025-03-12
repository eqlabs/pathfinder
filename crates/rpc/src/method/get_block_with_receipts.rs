use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::BlockId;
use starknet_gateway_types::reply::PendingBlock;

use crate::context::RpcContext;

pub enum Output {
    Full {
        header: Box<pathfinder_common::BlockHeader>,
        body: Vec<(
            pathfinder_common::transaction::Transaction,
            pathfinder_common::receipt::Receipt,
            Vec<pathfinder_common::event::Event>,
        )>,
        is_l1_accepted: bool,
    },
    Pending(Arc<PendingBlock>),
}

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

crate::error::generate_rpc_error_subset!(Error: BlockNotFound);

pub async fn get_block_with_receipts(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();
    util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Creating database connection")?;

        let db = db.transaction().context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                return Ok(Output::Pending(pending.block));
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        let header = db
            .block_header(block_id)
            .context("Fetching block header")?
            .ok_or(Error::BlockNotFound)?;

        let body = db
            .transaction_data_for_block(block_id)
            .context("Fetching transaction data")?
            .context("Transaction data missing")?;

        let is_l1_accepted = db
            .block_is_l1_accepted(block_id)
            .context("Fetching block finality")?;

        Ok(Output::Full {
            header: header.into(),
            body,
            is_l1_accepted,
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
        let mut serializer = serializer.serialize_struct()?;
        match self {
            Output::Full {
                header,
                body,
                is_l1_accepted,
            } => {
                let finality = if *is_l1_accepted {
                    crate::dto::TxnFinalityStatus::AcceptedOnL1
                } else {
                    crate::dto::TxnFinalityStatus::AcceptedOnL2
                };
                serializer.serialize_field(
                    "status",
                    &if *is_l1_accepted {
                        "ACCEPTED_ON_L1"
                    } else {
                        "ACCEPTED_ON_L2"
                    },
                )?;
                serializer.flatten(header.as_ref())?;
                serializer.serialize_iter(
                    "transactions",
                    body.len(),
                    &mut body
                        .iter()
                        .map(|(transaction, receipt, events)| TransactionWithReceipt {
                            transaction,
                            receipt,
                            events,
                            finality,
                        }),
                )?;
            }
            Output::Pending(block) => {
                serializer.flatten(block.as_ref())?;
                serializer.serialize_iter(
                    "transactions",
                    block.transactions.len(),
                    &mut block
                        .transactions
                        .iter()
                        .zip(block.transaction_receipts.iter())
                        .map(|(transaction, (receipt, events))| TransactionWithReceipt {
                            transaction,
                            receipt,
                            events,
                            finality: crate::dto::TxnFinalityStatus::AcceptedOnL2,
                        }),
                )?;
            }
        }
        serializer.end()
    }
}

struct TransactionWithReceipt<'a> {
    pub transaction: &'a pathfinder_common::transaction::Transaction,
    pub receipt: &'a pathfinder_common::receipt::Receipt,
    pub events: &'a [pathfinder_common::event::Event],
    pub finality: crate::dto::TxnFinalityStatus,
}

impl crate::dto::SerializeForVersion for TransactionWithReceipt<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        match serializer.version {
            crate::RpcVersion::V07 => {
                serializer.serialize_field(
                    "transaction",
                    &crate::dto::TransactionWithHash(self.transaction),
                )?;
            }
            _ => {
                serializer.serialize_field("transaction", &self.transaction)?;
            }
        }
        serializer.serialize_field(
            "receipt",
            &crate::dto::TxnReceipt {
                receipt: self.receipt,
                transaction: self.transaction,
                events: self.events,
                finality: self.finality,
            },
        )?;
        serializer.end()
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

        let output = get_block_with_receipts(context.clone(), input)
            .await
            .unwrap()
            .serialize(Serializer { version })
            .unwrap();

        crate::assert_json_matches_fixture!(output, version, "blocks/pending.json");
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

        let output = get_block_with_receipts(context.clone(), input)
            .await
            .unwrap()
            .serialize(Serializer { version })
            .unwrap();

        crate::assert_json_matches_fixture!(output, version, "blocks/latest.json");
    }
}
