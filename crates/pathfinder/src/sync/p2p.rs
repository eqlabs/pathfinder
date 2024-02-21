#![allow(dead_code, unused_variables)]
mod headers;

use anyhow::Context;
use pathfinder_common::{BlockHash, BlockNumber};
use pathfinder_ethereum::EthereumStateUpdate;
use pathfinder_storage::Storage;
use primitive_types::H160;
use tokio::task::spawn_blocking;

use p2p::client::peer_agnostic::Client as P2PClient;

/// Provides P2P sync capability for blocks secured by L1.
pub struct Sync {
    storage: Storage,
    p2p: P2PClient,
    // TODO: merge these two inside the client.
    eth_client: pathfinder_ethereum::EthereumClient,
    eth_address: H160,
}

impl Sync {
    pub fn new(
        storage: Storage,
        p2p: P2PClient,
        ethereum: (pathfinder_ethereum::EthereumClient, H160),
    ) -> Self {
        Self {
            storage,
            p2p,
            eth_client: ethereum.0,
            eth_address: ethereum.1,
        }
    }

    /// Syncs using p2p until the latest Ethereum checkpoint.
    pub async fn run(&self) -> anyhow::Result<()> {
        use pathfinder_ethereum::EthereumApi;
        let checkpoint = self
            .eth_client
            .get_starknet_state(&self.eth_address)
            .await
            .context("Fetching latest L1 checkpoint")?;

        let local_state = LocalState::from_db(self.storage.clone(), checkpoint.clone())
            .await
            .context("Querying local state")?;

        // Ensure our local state is consistent with the L1 checkpoint.
        CheckpointAnalysis::analyse(&local_state, &checkpoint)
            .handle(self.storage.clone())
            .await
            .context("Analysing local storage against L1 checkpoint")?;

        // Persist checkpoint as new L1 anchor. This must be done first to protect against an interrupted sync process.
        // Subsequent syncs will use this value to rollback against. Persisting it later would result in more data than
        // necessary being rolled back (potentially all data if the header sync process is frequently interrupted), so this
        // ensures sync will progress even under bad conditions.
        let anchor = checkpoint;
        persist_anchor(self.storage.clone(), anchor.clone())
            .await
            .context("Persisting new Ethereum anchor")?;

        // Sync missing headers in reverse chronological order, from the new anchor to genesis.
        self.sync_headers(anchor).await.context("Syncing headers")?;

        // Sync the rest of the data in chronological order.

        Ok(())
    }

    /// Syncs all headers in reverse chronological order, from the anchor point
    /// back to genesis. Fills in any gaps left by previous header syncs.
    ///
    /// As sync goes backwards from a known L1 anchor block, this method can
    /// guarantee that all sync'd headers are secured by L1.
    ///
    /// No guarantees are made about any headers newer than the anchor.
    async fn sync_headers(&self, anchor: EthereumStateUpdate) -> anyhow::Result<()> {
        while let Some(gap) =
            headers::next_gap(self.storage.clone(), anchor.block_number, anchor.block_hash)
                .await
                .context("Finding next gap in header chain")?
        {
            use futures::StreamExt;
            use futures::TryStreamExt;

            // TODO: create a tracing scope for this gap start, stop.

            tracing::info!("Syncing headers");

            // TODO: consider .inspect_ok(tracing::trace!) for each stage.
            let result = self
                .p2p
                .clone()
                // TODO: consider buffering in the client to reduce request latency.
                .header_stream(gap.head, gap.tail, true)
                .scan((gap.head, gap.head_hash, false), headers::check_continuity)
                // TODO: rayon scope this.
                .and_then(headers::verify)
                // chunk so that persisting to storage can be batched.
                .try_chunks(1024)
                // TODO: Pull out remaining data from try_chunks error.
                //       try_chunks::Error is a tuple of Err(data, error) so we
                //       should re-stream that as Ok(data), Err(error). Right now
                //       we just map to Err(error).
                .map_err(|e| e.1)
                .and_then(|x| headers::persist(x, self.storage.clone()))
                .inspect_ok(|x| tracing::info!(tail=%x.data.header.number, "Header chunk synced"))
                // Drive stream to completion.
                .try_fold((), |_state, _x| std::future::ready(Ok(())))
                .await;

            match result {
                Ok(()) => {
                    tracing::info!("Syncing headers complete");
                }
                Err(error) => {
                    if let Some(peer_data) = error.peer_id_and_data() {
                        // TODO: punish peer.
                        tracing::debug!(
                            peer=%peer_data.peer, block=%peer_data.data.header.number, %error,
                            "Error while streaming headers"
                        );
                    } else {
                        tracing::debug!(%error, "Error while streaming headers");
                    }
                }
            }
        }

        Ok(())
    }
}

/// Performs [analysis](Self::analyse) of the [LocalState] by comparing it with a given L1 checkpoint,
/// and [handles](Self::handle) the result.
enum CheckpointAnalysis {
    /// The checkpoint hash does not match the local L1 anchor, indicating an inconsistency with the Ethereum source
    /// with the one used by the previous sync.
    HashMismatchWithAnchor {
        block: BlockNumber,
        checkpoint: BlockHash,
        anchor: BlockHash,
    },
    /// The checkpoint is older than the local anchor, indicating an inconsistency in the Ethereum source between
    /// this sync and the previous sync.
    PredatesAnchor {
        checkpoint: BlockNumber,
        anchor: BlockNumber,
    },
    /// The checkpoint exceeds the local chain. As such, the local chain should be rolled back to its anchor as we
    /// cannot be confident in any of the local data not verified by L1.
    ExceedsLocalChain {
        local: BlockNumber,
        checkpoint: BlockNumber,
        anchor: Option<BlockNumber>,
    },
    /// The checkpoint hash does not match the local chain data. The local chain should be rolled back to its anchor.
    HashMismatchWithLocalChain {
        block: BlockNumber,
        local: BlockHash,
        checkpoint: BlockHash,
        anchor: Option<BlockNumber>,
    },
    /// Local data is consistent with the checkpoint, no action required.
    Consistent,
}

impl CheckpointAnalysis {
    /// Analyse [LocalState] by checking it for consistency against the given L1 checkpoint.
    ///
    /// For more information on the potential inconsistencies see the [CheckpointAnalysis] variants.
    fn analyse(local_state: &LocalState, checkpoint: &EthereumStateUpdate) -> CheckpointAnalysis {
        // Checkpoint is older than or inconsistent with our local L1 anchor.
        if let Some(anchor) = &local_state.anchor {
            if checkpoint.block_number < anchor.block_number {
                return CheckpointAnalysis::PredatesAnchor {
                    checkpoint: checkpoint.block_number,
                    anchor: anchor.block_number,
                };
            }
            if checkpoint.block_number == anchor.block_number
                && checkpoint.block_hash != anchor.block_hash
            {
                return CheckpointAnalysis::HashMismatchWithAnchor {
                    block: anchor.block_number,
                    checkpoint: checkpoint.block_hash,
                    anchor: anchor.block_hash,
                };
            }
        }

        // Is local data not secured by an anchor potentially invalid?
        if let Some(latest) = local_state.latest_header {
            if checkpoint.block_number > latest.0 {
                return CheckpointAnalysis::ExceedsLocalChain {
                    local: latest.0,
                    checkpoint: checkpoint.block_number,
                    anchor: local_state.anchor.as_ref().map(|x| x.block_number),
                };
            } else if let Some((_, hash)) = local_state.checkpoint {
                if hash != checkpoint.block_hash {
                    return CheckpointAnalysis::HashMismatchWithLocalChain {
                        block: checkpoint.block_number,
                        local: hash,
                        checkpoint: checkpoint.block_hash,
                        anchor: local_state.anchor.as_ref().map(|x| x.block_number),
                    };
                }
            }
        }

        CheckpointAnalysis::Consistent
    }

    /// Handles the [checkpoint analysis](Self::analyse) [result](Self).
    ///
    /// Returns an error for [PredatesAnchor](Self::PredatesAnchor) and
    /// [HashMismatchWithAnchor](Self::HashMismatchWithAnchor) since these indicate an inconsistency with the Ethereum
    /// source - making all data suspect.
    ///
    /// Rolls back local state to the anchor for [ExceedsLocalChain](Self::ExceedsLocalChain) and
    /// [HashMismatchWithLocalChain](Self::HashMismatchWithLocalChain) conditions.
    ///
    /// Does nothing for [Consistent](Self::Consistent). This leaves any insecure local data intact. Always rolling
    /// back to the L1 anchor would result in a poor user experience if restarting frequently as each restart would
    /// purge new data.
    async fn handle(self, storage: Storage) -> anyhow::Result<()> {
        match self {
            CheckpointAnalysis::HashMismatchWithAnchor {
                block,
                checkpoint,
                anchor,
            } => {
                tracing::error!(
                    %block, %checkpoint, %anchor,
                    "Ethereum checkpoint's hash did not match the local Ethereum anchor. This indicates a serious inconsistency in the Ethereum source used by this sync and the previous sync."
                );
                anyhow::bail!("Ethereum checkpoint hash did not match local anchor.");
            }
            CheckpointAnalysis::PredatesAnchor { checkpoint, anchor } => {
                // TODO: or consider this valid. If so, then we should continue sync but use the local anchor instead of the checkpoint.
                tracing::error!(
                    %checkpoint, %anchor,
                    "Ethereum checkpoint is older than the local anchor. This indicates a serious inconsistency in the Ethereum source used by this sync and the previous sync."
                );
                anyhow::bail!("Ethereum checkpoint hash did not match local anchor.");
            }
            CheckpointAnalysis::ExceedsLocalChain {
                local,
                checkpoint,
                anchor,
            } => {
                tracing::info!(
                    %local, anchor=%anchor.unwrap_or_default(), %checkpoint,
                    "Rolling back local chain to latest anchor point. Local data is potentially invalid as the Ethereum checkpoint is newer the local chain."
                );
                rollback_to_anchor(storage, anchor)
                    .await
                    .context("Rolling back chain state to L1 anchor")?;
            }
            CheckpointAnalysis::HashMismatchWithLocalChain {
                block,
                local,
                checkpoint,
                anchor,
            } => {
                tracing::info!(
                    %block, %local, %checkpoint, ?anchor,
                    "Rolling back local chain to latest anchor point. Local data is invalid as it did not match the Ethereum checkpoint's hash."
                );
                rollback_to_anchor(storage, anchor)
                    .await
                    .context("Rolling back chain state to L1 anchor")?;
            }
            CheckpointAnalysis::Consistent => {
                tracing::info!("Ethereum checkpoint is consistent with local data");
            }
        };

        Ok(())
    }
}

struct LocalState {
    latest_header: Option<(BlockNumber, BlockHash)>,
    anchor: Option<EthereumStateUpdate>,
    checkpoint: Option<(BlockNumber, BlockHash)>,
}

impl LocalState {
    async fn from_db(storage: Storage, checkpoint: EthereumStateUpdate) -> anyhow::Result<Self> {
        // TODO: this should include header gaps.
        spawn_blocking(move || {
            let mut db = storage
                .connection()
                .context("Creating database connection")?;
            let db = db.transaction().context("Creating database transaction")?;

            let latest_header = db
                .block_id(pathfinder_storage::BlockId::Latest)
                .context("Querying latest header")?;

            let checkpoint = db
                .block_id(checkpoint.block_number.into())
                .context("Querying checkpoint header")?;

            let anchor = db.latest_l1_state().context("Querying latest L1 anchor")?;

            Ok(LocalState {
                latest_header,
                checkpoint,
                anchor,
            })
        })
        .await
        .context("Joining blocking task")?
    }
}

/// Rolls back local chain-state until the given anchor point, making it the tip of the local chain. If this is ['None']
/// then all data will be rolled back.
async fn rollback_to_anchor(storage: Storage, anchor: Option<BlockNumber>) -> anyhow::Result<()> {
    spawn_blocking(move || {
        todo!("Rollback storage to anchor point");
    })
    .await
    .context("Joining blocking task")?
}

async fn persist_anchor(storage: Storage, anchor: EthereumStateUpdate) -> anyhow::Result<()> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        db.upsert_l1_state(&anchor).context("Inserting anchor")?;
        // TODO: this is a bit dodgy, but is used by the sync process. However it destroys
        //       some RPC assumptions which we should be aware of.
        db.update_l1_l2_pointer(Some(anchor.block_number))
            .context("Updating L1-L2 pointer")?;
        db.commit().context("Committing database transaction")?;
        Ok(())
    })
    .await
    .context("Joining blocking task")?
}
