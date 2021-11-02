use web3::futures::{poll, Future, FutureExt, TryStreamExt};
use web3::types::{BlockId, BlockNumber};
use web3::{futures::StreamExt, transports::WebSocket};

use crate::storage::{Block, Storage};

use anyhow::Context;

pub struct StateSync {
    web_socket: WebSocket,
    storage: Storage,
}

impl StateSync {
    pub fn new(web_socket: WebSocket, storage: Storage) -> Self {
        Self {
            web_socket,
            storage,
        }
    }

    /// The goal is to update our local storage to be up-to-date
    /// with the current L1 chain.
    ///
    /// Once this is achieved, we can continue syncing by tracking
    /// new incoming blocks using a new block subscription.
    pub async fn sync_state(&mut self) -> anyhow::Result<()> {
        let ws = web3::Web3::new(self.web_socket.clone());

        // Track the head of the chain.
        //
        // This must be started before doing anything, so that we don't miss any events which
        // may change whats valid.
        //
        // An alternative may be to track only log events affecting the StarkNet contracts,
        // but I am unsure of how to avoid reorg race conditions.
        let mut heads = ws.eth_subscribe().subscribe_new_heads().await?;
        let mut latest_chain: Block = ws
            .eth()
            .block(BlockId::Number(BlockNumber::Latest))
            .await?
            .unwrap()
            .into();

        let mut latest_checked = self.storage.latest_block(0)?;

        // Builds the filter responsible for pulling in the Eth logs we are interested in.
        let filter_builder = web3::types::FilterBuilder::default()
        // .address(vec![MEMPAGE_ADDR, GPS_ADDR]) todo, once I've figured out what the values are now.
        ;

        // Start going through logs, from current till now. Keep an eye on new blocks.
        // Finished once we reach the latest block.
        while latest_checked.as_ref() != Some(&latest_chain) {
            // Update latest chain head if available
            if let Some(head) = heads.next().now_or_never() {
                match head {
                    Some(Ok(head)) => latest_chain = head.into(),
                    Some(Err(err)) => {
                        Err(err).with_context(|| "block subscription stream terminated")?
                    }
                    None => anyhow::bail!("New block head subscription stream terminated"),
                }
            }

            // Get next set of StarkNet logs.
            //
            // Must include the latest log we already have in storage, which will allow
            // us to check that storage wasn't invalidated by a reorg.
            let stride: u64 = 100_000;
            let latest_storage_block = self.storage.latest_block(0)?;
            let latest_storage = latest_storage_block.clone().map(|b| b.number).unwrap_or(0);
            let to_block = latest_storage + stride;
            let log_filter = filter_builder
                .clone()
                .from_block(BlockNumber::Number(latest_storage.into()))
                .to_block(BlockNumber::Number(to_block.into()))
                .limit(5000)
                .build();
            let logs = ws.eth().logs(log_filter).await.unwrap();
            // TODO: need to handle errors from L1, will require dynamic `stride` size
            //       to deal with max event sizes, rate-limiting etc.


            // Check storage for a reorg.
            //
            // If storage is still valid, then we expect the logs should
            // include the latest log that we have in storage (since we explicitly
            // included the latest block in storage).
            //
            // It is enough to check our latest block, since we only store blocks which
            // contain logs.
            let first_block = logs.first().map(|log| Block {
                number: log.block_number.unwrap().as_u64(),
                hash: log.block_hash.unwrap(),
            });
            if first_block != latest_storage_block {
                // Reorg invalidated our storage,
                todo!("Walk through storage, remove invalid blocks");
            }

            // Update our local state for the next round.
            latest_checked = Some(
                ws.eth()
                    .block(BlockId::Number(to_block.into()))
                    .await?
                    .unwrap() // todo: handle this case properly..
                    .into(),
            );

            // Interpret logs into a state updates..

            // Commit state updates to storage.
        }

        // We can now keep in sync by only tracking the heads subscription.
        // Which this function can now return for the next step in the process.

        Ok(())
    }
}
