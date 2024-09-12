use std::sync::Arc;

use axum::async_trait;
use pathfinder_common::{BlockId, BlockNumber};
use tokio::sync::mpsc;

use crate::context::RpcContext;
use crate::jsonrpc::{RpcError, RpcSubscriptionFlow};

pub struct SubscribeNewHeads;

#[derive(Debug)]
pub struct Request {
    block: BlockId,
}

impl crate::dto::DeserializeForVersion for Request {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block: value.deserialize_serde("block")?,
            })
        })
    }
}

#[derive(Debug)]
pub struct Message(Arc<pathfinder_common::BlockHeader>);

impl crate::dto::serialize::SerializeForVersion for Message {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        crate::dto::BlockHeader(&self.0).serialize(serializer)
    }
}

#[async_trait]
impl RpcSubscriptionFlow for SubscribeNewHeads {
    type Request = Request;
    type Notification = Message;

    fn subscription_name() -> &'static str {
        "starknet_subscriptionNewHeads"
    }

    fn starting_block(req: &Self::Request) -> BlockId {
        req.block
    }

    async fn catch_up(
        state: &RpcContext,
        _req: &Self::Request,
        from: BlockNumber,
        to: BlockNumber,
    ) -> Result<Vec<(Self::Notification, BlockNumber)>, RpcError> {
        let storage = state.storage.clone();
        let headers = tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
            let mut conn = storage.connection().map_err(RpcError::InternalError)?;
            let db = conn.transaction().map_err(RpcError::InternalError)?;
            db.block_range(from, to).map_err(RpcError::InternalError)
        })
        .await
        .map_err(|e| RpcError::InternalError(e.into()))??;
        Ok(headers
            .into_iter()
            .map(|header| {
                let block_number = header.number;
                (Message(header.into()), block_number)
            })
            .collect())
    }

    async fn subscribe(state: RpcContext, tx: mpsc::Sender<(Self::Notification, BlockNumber)>) {
        let mut rx = state.notifications.block_headers.subscribe();
        loop {
            match rx.recv().await {
                Ok(header) => {
                    let block_number = header.number;
                    if tx
                        .send((Message(header.into()), block_number))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        "Error receiving block header from notifications channel, node might be \
                         lagging: {:?}",
                        e
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO Remove this
    #![allow(dead_code)]

    use std::time::Duration;

    use pathfinder_common::{BlockHash, BlockHeader, BlockNumber, ChainId};
    use pathfinder_crypto::Felt;
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_client::Client;

    use crate::context::{RpcConfig, RpcContext};
    use crate::pending::PendingWatcher;
    use crate::v02::types::syncing::Syncing;
    use crate::{Notifications, SyncState};

    #[test]
    fn happy_path_with_historic_blocks() {}

    #[test]
    fn happy_path_with_historic_blocks_batching() {}

    #[test]
    fn happy_path_with_no_historic_blocks() {}

    #[test]
    fn race_condition_with_historic_blocks() {}

    #[test]
    fn unsubscribe() {}

    fn setup(num_blocks: u64) -> RpcContext {
        let storage = StorageBuilder::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let db = conn.transaction().unwrap();
        for i in 1..num_blocks {
            let header = sample_header(i);
            db.insert_block_header(&header).unwrap();
        }
        db.commit().unwrap();
        let (_, pending_data) = tokio::sync::watch::channel(Default::default());
        let notifications = Notifications::default();
        RpcContext {
            cache: Default::default(),
            storage,
            execution_storage: StorageBuilder::in_memory().unwrap(),
            pending_data: PendingWatcher::new(pending_data),
            sync_status: SyncState {
                status: Syncing::False(false).into(),
            }
            .into(),
            chain_id: ChainId::MAINNET,
            sequencer: Client::mainnet(Duration::from_secs(10)),
            websocket: None,
            notifications,
            config: RpcConfig {
                batch_concurrency_limit: 1.try_into().unwrap(),
                get_events_max_blocks_to_scan: 1.try_into().unwrap(),
                get_events_max_uncached_bloom_filters_to_load: 1.try_into().unwrap(),
                custom_versioned_constants: None,
            },
        }
    }

    fn sample_header(i: u64) -> BlockHeader {
        BlockHeader {
            hash: BlockHash(Felt::from_u64(i)),
            parent_hash: BlockHash::ZERO,
            number: BlockNumber::new_or_panic(i),
            ..Default::default()
        }
    }
}
