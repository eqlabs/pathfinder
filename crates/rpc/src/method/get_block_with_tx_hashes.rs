use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{BlockHeader, TransactionHash};

use crate::context::RpcContext;
use crate::pending::{PendingBlocks, UnvalidatedOrId};
use crate::types::BlockId;
use crate::RpcVersion;

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
        block: Arc<PendingBlocks>,
        transactions: Vec<TransactionHash>,
    },
    Full {
        header: Box<BlockHeader>,
        transactions: Vec<TransactionHash>,
        l1_accepted: bool,
    },
}

/// Get block information with transaction hashes given the block id
pub async fn get_block_with_tx_hashes(
    context: RpcContext,
    input: Input,
    _rpc_version: RpcVersion,
) -> Result<Output, Error> {
    let span = tracing::Span::current();
    let pending_or_id = context.pending_data.resolve_or_id(input.block_id).await?;
    util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut connection = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;

        let block_id = match pending_or_id {
            UnvalidatedOrId::PreConfirmed(pending) => {
                let pending = pending.validate(&transaction)?;

                let transactions = pending
                    .pre_confirmed_transactions()
                    .iter()
                    .map(|t| t.hash)
                    .collect();

                return Ok(Output::Pending {
                    block: pending.pending_block(),
                    transactions,
                });
            }
            UnvalidatedOrId::Other(other) => other
                .to_common(&transaction)
                .map_err(|_| Error::BlockNotFound)?,
        };

        let header = transaction
            .block_header(block_id)
            .context("Reading block from database")?
            .ok_or(Error::BlockNotFound)?;

        let l1_accepted = transaction.block_is_l1_accepted(header.number.into())?;

        let transactions = transaction
            .transaction_hashes_for_block(header.number.into())
            .context("Reading transaction hashes")?
            .context("Transaction hashes missing")?;

        Ok(Output::Full {
            header: Box::new(header),
            transactions,
            l1_accepted,
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
                block,
                transactions,
            } => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.flatten(&block.pre_confirmed)?;
                serializer.serialize_iter(
                    "transactions",
                    transactions.len(),
                    &mut transactions.iter(),
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
                    &mut transactions.iter(),
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
    use std::time::Duration;

    use pathfinder_pending_data::PendingDataCache;

    use super::*;
    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    /// An unavailable pre-confirmed cache surfaces a client-visible reason —
    /// code -32603 with the reason in `data` — rather than a bare
    /// "Internal error".
    #[test]
    fn unavailable_maps_to_custom_with_reason() {
        use pathfinder_pending_data::ReadError;

        use crate::error::ApplicationError;

        let err: Error = ReadError::Unavailable("syncing").into();
        let app: ApplicationError = err.into();

        assert_eq!(app.code(RpcVersion::V09), -32603);
        let data = app
            .data(RpcVersion::V09)
            .expect("the reason is carried in `data`");
        assert!(
            data["error"].as_str().unwrap().contains("syncing"),
            "got: {data}"
        );
    }

    #[rstest::rstest]
    #[case::v09(RpcVersion::V09)]
    #[case::v10(RpcVersion::V10)]
    #[tokio::test]
    async fn pre_confirmed(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pre_confirmed().await;

        let input = Input {
            block_id: BlockId::PreConfirmed,
        };

        let output = get_block_with_tx_hashes(context, input, version)
            .await
            .unwrap();
        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "blocks/pre_confirmed_with_tx_hashes.json"
        );
    }

    #[rstest::rstest]
    #[case::v09(RpcVersion::V09)]
    #[case::v10(RpcVersion::V10)]
    #[tokio::test]
    async fn latest(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pre_confirmed().await;

        let input = Input {
            block_id: BlockId::Latest,
        };

        let output = get_block_with_tx_hashes(context, input, version)
            .await
            .unwrap();
        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "blocks/latest_with_tx_hashes.json"
        );
    }

    /// Prior to splitting `PendingDataCache::get[_optional]` into and async
    /// `resolve` and sync `validate` all the RPC methods that used preconfirmed
    /// data would hold the database connection in `spawn_blocking` for the
    /// entire duration of the cold start timeout that could happen in
    /// `PendingDataCache::get[_optional]` if the cache was cold and the
    /// gateway happened to be slow. Using an arbitrary single method is
    /// representative of all the other affected methods.
    #[tokio::test]
    async fn regression_waiting_for_pre_confirmed_data_does_not_hold_a_database_connection() {
        const COLD_START: Duration = Duration::from_millis(500);
        const LATEST_TIMEOUT: Duration = Duration::from_millis(300);

        let cache = Arc::new(PendingDataCache::new().with_cold_start_timeout(COLD_START));
        // Mark stale so that any readers will wait.
        cache.mark_stale();
        let context = RpcContext::for_tests().with_pending_data_cache(cache);

        let _waiting = tokio::spawn(get_block_with_tx_hashes(
            context.clone(),
            Input {
                block_id: BlockId::PreConfirmed,
            },
            RpcVersion::V09,
        ));

        // Make sure that the read hangs on waiting for preconfirmed data.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let latest = get_block_with_tx_hashes(
            context,
            Input {
                block_id: BlockId::Latest,
            },
            RpcVersion::V09,
        );

        // Latest should be served regardless of whether the preconfirmed reader
        // is still waiting.
        tokio::time::timeout(LATEST_TIMEOUT, latest)
            .await
            .unwrap()
            .unwrap();
    }
}
