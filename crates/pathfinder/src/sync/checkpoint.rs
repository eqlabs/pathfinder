#![allow(dead_code, unused_variables)]
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use futures::{pin_mut, StreamExt, TryStreamExt};
use p2p::client::conv::TryFromDto;
use p2p::client::peer_agnostic::{Class, Client as P2PClient, EventsForBlockByTransaction};
use p2p::PeerData;
use p2p_proto::common::{BlockNumberOrHash, Direction, Iteration};
use p2p_proto::transaction::{TransactionWithReceipt, TransactionsRequest, TransactionsResponse};
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{BlockHash, BlockHeader, BlockNumber, ClassHash, TransactionIndex};
use pathfinder_ethereum::EthereumStateUpdate;
use pathfinder_storage::Storage;
use primitive_types::H160;
use serde_json::de;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

use super::class_definitions::ClassWithLayout;
use crate::state::block_hash::{
    calculate_transaction_commitment,
    TransactionCommitmentFinalHashType,
};
use crate::sync::error::SyncError;
use crate::sync::{class_definitions, events, headers, state_updates, transactions};

/// Provides P2P sync capability for blocks secured by L1.
#[derive(Clone)]
pub struct Sync {
    pub storage: Storage,
    pub p2p: P2PClient,
    // TODO: merge these two inside the client.
    pub eth_client: pathfinder_ethereum::EthereumClient,
    pub eth_address: H160,
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

    /// Syncs using p2p until the given Ethereum checkpoint.
    pub async fn run(&self, checkpoint: EthereumStateUpdate) -> Result<(), SyncError> {
        use pathfinder_ethereum::EthereumApi;

        let local_state = LocalState::from_db(self.storage.clone(), checkpoint.clone())
            .await
            .context("Querying local state")?;

        // Ensure our local state is consistent with the L1 checkpoint.
        CheckpointAnalysis::analyse(&local_state, &checkpoint)
            .handle(self.storage.clone())
            .await
            .context("Analysing local storage against L1 checkpoint")?;

        // Persist checkpoint as new L1 anchor. This must be done first to protect
        // against an interrupted sync process. Subsequent syncs will use this
        // value to rollback against. Persisting it later would result in more data than
        // necessary being rolled back (potentially all data if the header sync process
        // is frequently interrupted), so this ensures sync will progress even
        // under bad conditions.
        let anchor = checkpoint;
        persist_anchor(self.storage.clone(), anchor.clone())
            .await
            .context("Persisting new Ethereum anchor")?;

        let head = anchor.block_number;

        // Sync missing headers in reverse chronological order, from the new anchor to
        // genesis.
        self.sync_headers(anchor).await?;

        // Sync the rest of the data in chronological order.
        self.sync_transactions()
            .await
            .context("Syncing transactions")?;
        self.sync_state_updates(head).await?;
        self.sync_class_definitions(head).await?;
        self.sync_events(head).await?;

        Ok(())
    }

    /// Syncs all headers in reverse chronological order, from the anchor point
    /// back to genesis. Fills in any gaps left by previous header syncs.
    ///
    /// As sync goes backwards from a known L1 anchor block, this method can
    /// guarantee that all sync'd headers are secured by L1.
    ///
    /// No guarantees are made about any headers newer than the anchor.
    async fn sync_headers(&self, anchor: EthereumStateUpdate) -> Result<(), SyncError> {
        while let Some(gap) =
            headers::next_gap(self.storage.clone(), anchor.block_number, anchor.block_hash)
                .await
                .context("Finding next gap in header chain")?
        {
            // TODO: create a tracing scope for this gap start, stop.

            tracing::info!("Syncing headers");

            // TODO: consider .inspect_ok(tracing::trace!) for each stage.
            self.p2p
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
                .await?;
        }

        Ok(())
    }

    async fn sync_transactions(&self) -> anyhow::Result<()> {
        let (first_block, last_block) = spawn_blocking({
            let storage = self.storage.clone();
            move || -> anyhow::Result<(Option<BlockNumber>, Option<BlockNumber>)> {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().context("Creating database transaction")?;
                let first_block = db
                    .first_block_without_transactions()
                    .context("Querying first block without transactions")?;
                let last_block = db
                    .block_id(pathfinder_storage::BlockId::Latest)
                    .context("Querying latest block without transactions")?
                    .map(|(block_number, _)| block_number);
                Ok((first_block, last_block))
            }
        })
        .await
        .context("Joining blocking task")??;

        let Some(first_block) = first_block else {
            return Ok(());
        };
        let last_block = last_block.context("Last block not found but first block found")?;

        let mut curr_block = headers::query(self.storage.clone(), first_block)
            .await?
            .ok_or_else(|| anyhow::anyhow!("First block not found"))?;

        // Loop which refreshes peer set once we exhaust it.
        loop {
            let peers = self
                .p2p
                .get_update_peers_with_transaction_sync_capability()
                .await;

            // Attempt each peer.
            'next_peer: for peer in peers {
                let request = TransactionsRequest {
                    iteration: Iteration {
                        start: BlockNumberOrHash::Number(curr_block.number.get()),
                        direction: Direction::Forward,
                        limit: last_block.get() - curr_block.number.get() + 1,
                        step: 1.into(),
                    },
                };

                let mut responses =
                    match self.p2p.send_transactions_sync_request(peer, request).await {
                        Ok(x) => x,
                        Err(error) => {
                            // Failed to establish connection, try next peer.
                            tracing::debug!(%peer, reason=%error, "Transactions request failed");
                            continue 'next_peer;
                        }
                    };

                let mut transactions = Vec::new();
                while let Some(transaction) = responses.next().await {
                    match transaction {
                        TransactionsResponse::TransactionWithReceipt(tx) => {
                            let TransactionWithReceipt {
                                transaction,
                                receipt,
                            } = tx;
                            match (
                                TransactionVariant::try_from_dto(transaction),
                                Receipt::try_from_dto((
                                    receipt,
                                    TransactionIndex::new_or_panic(
                                        transactions.len().try_into().expect("ptr size is 64bits"),
                                    ),
                                )),
                            ) {
                                (Ok(tx), Ok(rec))
                                    if transactions.len() < curr_block.transaction_count =>
                                {
                                    transactions.push((tx, rec))
                                }
                                (Ok(tx), Ok(rec)) => {
                                    let Some(checked) = check_transactions(
                                        &curr_block,
                                        std::mem::take(&mut transactions),
                                    )
                                    .await?
                                    else {
                                        tracing::debug!(
                                            "Invalid transactions for block {}, trying next peer",
                                            curr_block.number
                                        );
                                        continue 'next_peer;
                                    };

                                    transactions::persist(
                                        self.storage.clone(),
                                        curr_block.clone(),
                                        checked,
                                    )
                                    .await
                                    .context("Inserting transactions")?;
                                    if curr_block.number == last_block {
                                        return Ok(());
                                    }
                                    curr_block =
                                        headers::query(self.storage.clone(), curr_block.number + 1)
                                            .await?
                                            .ok_or_else(|| {
                                                anyhow::anyhow!("Next block not found")
                                            })?;
                                    transactions.push((tx, rec));
                                }
                                (Err(error), _) | (_, Err(error)) => {
                                    tracing::debug!(%peer, %error, "Transaction stream returned unexpected DTO");
                                    continue 'next_peer;
                                }
                            }
                        }
                        TransactionsResponse::Fin if curr_block.number == last_block => {
                            let Some(checked) =
                                check_transactions(&curr_block, std::mem::take(&mut transactions))
                                    .await?
                            else {
                                tracing::debug!(
                                    "Invalid transactions for block {}, trying next peer",
                                    curr_block.number
                                );
                                continue 'next_peer;
                            };

                            transactions::persist(self.storage.clone(), curr_block, checked)
                                .await
                                .context("Inserting transactions")?;
                            return Ok(());
                        }
                        TransactionsResponse::Fin => {
                            tracing::debug!(%peer, "Unexpected transaction stream Fin");
                            continue 'next_peer;
                        }
                    };
                }
            }
        }
    }

    async fn sync_state_updates(&self, stop: BlockNumber) -> Result<(), SyncError> {
        if let Some(start) = state_updates::next_missing(self.storage.clone(), stop)
            .await
            .context("Finding next missing state update")?
        {
            self.p2p
                .clone()
                .state_diff_stream(
                    start,
                    stop,
                    state_updates::contract_update_counts_stream(self.storage.clone(), start, stop),
                )
                .map_err(Into::into)
                .and_then(state_updates::verify_signature)
                .try_chunks(100)
                .map_err(|e| e.1)
                // Persist state updates (without: state commitments and declared classes)
                .and_then(|x| state_updates::persist(self.storage.clone(), x))
                .inspect_ok(|x| tracing::info!(tail=%x, "State update chunk synced"))
                // Drive stream to completion.
                .try_fold((), |_, _| std::future::ready(Ok(())))
                .await?;
        }

        Ok(())
    }

    async fn sync_class_definitions(&self, stop: BlockNumber) -> Result<(), SyncError> {
        let Some(start) = class_definitions::next_missing(self.storage.clone(), stop)
            .await
            .context("Finding next block with missing class definition(s)")?
        else {
            return Ok(());
        };

        let class_stream = self.p2p.clone().class_definitions_stream(
            start,
            stop,
            class_definitions::declared_class_counts_stream(self.storage.clone(), start, stop),
        );

        let declared_classes_stream =
            class_definitions::declared_classes_at_block_stream(self.storage.clone(), start, stop);

        handle_class_stream(class_stream, self.storage.clone(), declared_classes_stream).await?;

        Ok(())
    }

    async fn sync_events(&self, stop: BlockNumber) -> Result<(), SyncError> {
        let Some(start) = events::next_missing(self.storage.clone(), stop)
            .await
            .context("Finding next block with missing events")?
        else {
            return Ok(());
        };

        let event_stream = self.p2p.clone().events_stream(
            start,
            stop,
            events::counts_stream(self.storage.clone(), start, stop),
        );

        handle_event_stream(event_stream, self.storage.clone()).await?;

        Ok(())
    }
}

async fn handle_class_stream(
    class_stream: impl futures::Stream<Item = Result<PeerData<Class>, anyhow::Error>>,
    storage: Storage,
    declared_classes_at_block_stream: impl futures::Stream<
        Item = Result<(BlockNumber, HashSet<ClassHash>), SyncError>,
    >,
) -> Result<(), SyncError> {
    let a = class_stream
        .map_err(Into::into)
        .and_then(class_definitions::verify_layout);

    pin_mut!(a, declared_classes_at_block_stream);

    let b = class_definitions::verify_declared_at(declared_classes_at_block_stream, a);

    b.and_then(class_definitions::verify_hash)
        .try_chunks(10)
        .map_err(|e| e.1)
        .and_then(|x| class_definitions::persist(storage.clone(), x))
        .inspect_ok(|x| tracing::info!(tail=%x, "Class definitions chunk synced"))
        // Drive stream to completion.
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await?;
    Ok(())
}

async fn handle_event_stream(
    event_stream: impl futures::Stream<Item = anyhow::Result<PeerData<EventsForBlockByTransaction>>>,
    storage: Storage,
) -> Result<(), SyncError> {
    event_stream
        .map_err(Into::into)
        .and_then(|x| events::verify_commitment(x, storage.clone()))
        .try_chunks(100)
        .map_err(|e| e.1)
        .and_then(|x| events::persist(storage.clone(), x))
        .inspect_ok(|x| tracing::info!(tail=%x, "Events chunk synced"))
        // Drive stream to completion.
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await?;
    Ok(())
}

/// Takes ownership of transactions and returns them if verification passes.
async fn check_transactions(
    block: &BlockHeader,
    transactions: Vec<(TransactionVariant, Receipt)>,
) -> anyhow::Result<Option<Vec<(Transaction, Receipt)>>> {
    if transactions.len() != block.transaction_count {
        return Ok(None);
    }
    let (transaction_variants, receipts): (Vec<TransactionVariant>, Vec<Receipt>) =
        transactions.into_iter().unzip();
    let transaction_final_hash_type =
        TransactionCommitmentFinalHashType::for_version(&block.starknet_version);
    let (transaction_commitment, transactions) = spawn_blocking({
        move || {
            let mut transactions = Vec::new();

            rayon::scope(|s| {
                s.spawn(|_| {
                    use rayon::prelude::*;

                    transactions = transaction_variants
                        .into_par_iter()
                        .map(|variant| Transaction {
                            hash: todo!(), //variant.calculate_hash(chain_id, query_only),
                            variant,
                        })
                        .collect();
                })
            });

            calculate_transaction_commitment(&transactions, transaction_final_hash_type)
                .map_err(anyhow::Error::from)
                .map(|commitment| (commitment, transactions))
        }
    })
    .await
    .context("Joining blocking task")?
    .context("Calculating transaction commitment")?;
    Ok((transaction_commitment == block.transaction_commitment)
        .then_some(transactions.into_iter().zip(receipts).collect()))
}

/// Performs [analysis](Self::analyse) of the [LocalState] by comparing it with
/// a given L1 checkpoint, and [handles](Self::handle) the result.
enum CheckpointAnalysis {
    /// The checkpoint hash does not match the local L1 anchor, indicating an
    /// inconsistency with the Ethereum source with the one used by the
    /// previous sync.
    HashMismatchWithAnchor {
        block: BlockNumber,
        checkpoint: BlockHash,
        anchor: BlockHash,
    },
    /// The checkpoint is older than the local anchor, indicating an
    /// inconsistency in the Ethereum source between this sync and the
    /// previous sync.
    PredatesAnchor {
        checkpoint: BlockNumber,
        anchor: BlockNumber,
    },
    /// The checkpoint exceeds the local chain. As such, the local chain should
    /// be rolled back to its anchor as we cannot be confident in any of the
    /// local data not verified by L1.
    ExceedsLocalChain {
        local: BlockNumber,
        checkpoint: BlockNumber,
        anchor: Option<BlockNumber>,
    },
    /// The checkpoint hash does not match the local chain data. The local chain
    /// should be rolled back to its anchor.
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
    /// Analyse [LocalState] by checking it for consistency against the given L1
    /// checkpoint.
    ///
    /// For more information on the potential inconsistencies see the
    /// [CheckpointAnalysis] variants.
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
            }
            if let Some((_, hash)) = local_state.checkpoint {
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
    /// [HashMismatchWithAnchor](Self::HashMismatchWithAnchor) since these
    /// indicate an inconsistency with the Ethereum source - making all data
    /// suspect.
    ///
    /// Rolls back local state to the anchor for
    /// [ExceedsLocalChain](Self::ExceedsLocalChain) and
    /// [HashMismatchWithLocalChain](Self::HashMismatchWithLocalChain)
    /// conditions.
    ///
    /// Does nothing for [Consistent](Self::Consistent). This leaves any
    /// insecure local data intact. Always rolling back to the L1 anchor
    /// would result in a poor user experience if restarting frequently as each
    /// restart would purge new data.
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
                // TODO: or consider this valid. If so, then we should continue sync but use the
                // local anchor instead of the checkpoint.
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

/// Rolls back local chain-state until the given anchor point, making it the tip
/// of the local chain. If this is ['None'] then all data will be rolled back.
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
        // TODO: this is a bit dodgy, but is used by the sync process. However it
        // destroys       some RPC assumptions which we should be aware of.
        db.update_l1_l2_pointer(Some(anchor.block_number))
            .context("Updating L1-L2 pointer")?;
        db.commit().context("Committing database transaction")?;
        Ok(())
    })
    .await
    .context("Joining blocking task")?
}

#[cfg(test)]
mod tests {
    use super::*;

    mod handle_event_stream {
        use fake::{Fake, Faker};
        use futures::stream;
        use p2p::libp2p::PeerId;
        use pathfinder_common::event::Event;
        use pathfinder_common::transaction::TransactionVariant;
        use pathfinder_common::TransactionHash;
        use pathfinder_crypto::Felt;
        use pathfinder_storage::{fake as fake_storage, StorageBuilder};

        use super::super::handle_event_stream;
        use super::*;
        use crate::state::block_hash::calculate_event_commitment;

        struct Setup {
            pub streamed_events: Vec<anyhow::Result<PeerData<EventsForBlockByTransaction>>>,
            pub expected_events: Vec<Vec<(TransactionHash, Vec<Event>)>>,
            pub storage: Storage,
        }

        async fn setup(num_blocks: usize, compute_event_commitments: bool) -> Setup {
            tokio::task::spawn_blocking(move || {
                let mut blocks = fake_storage::init::with_n_blocks(num_blocks);
                let streamed_events = blocks
                    .iter()
                    .map(|block| {
                        anyhow::Result::Ok(PeerData::for_tests((
                            block.header.header.number,
                            block
                                .transaction_data
                                .iter()
                                .map(|x| x.2.clone())
                                .collect::<Vec<_>>(),
                        )))
                    })
                    .collect::<Vec<_>>();
                let expected_events = blocks
                    .iter()
                    .map(|block| {
                        block
                            .transaction_data
                            .iter()
                            .map(|x| (x.0.hash, x.2.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let storage = StorageBuilder::in_memory().unwrap();
                blocks.iter_mut().for_each(|block| {
                    if compute_event_commitments {
                        block.header.header.event_commitment = calculate_event_commitment(
                            &block
                                .transaction_data
                                .iter()
                                .flat_map(|(_, _, events)| events)
                                .collect::<Vec<_>>(),
                        )
                        .unwrap();
                    }
                    // Purge events
                    block
                        .transaction_data
                        .iter_mut()
                        .for_each(|(_, _, events)| events.clear());
                    block.cairo_defs.iter_mut().for_each(|(_, def)| def.clear());
                });
                fake_storage::fill(&storage, &blocks);
                Setup {
                    streamed_events,
                    expected_events,
                    storage,
                }
            })
            .await
            .unwrap()
        }

        #[tokio::test]
        async fn happy_path() {
            const NUM_BLOCKS: usize = 10;
            let Setup {
                streamed_events,
                expected_events,
                storage,
            } = setup(NUM_BLOCKS, true).await;

            handle_event_stream(stream::iter(streamed_events), storage.clone())
                .await
                .unwrap();

            let actual_events = tokio::task::spawn_blocking(move || {
                let mut conn = storage.connection().unwrap();
                let db_tx = conn.transaction().unwrap();
                (0..NUM_BLOCKS)
                    .map(|n| {
                        db_tx
                            .events_for_block(BlockNumber::new_or_panic(n as u64).into())
                            .unwrap()
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap();

            pretty_assertions_sorted::assert_eq!(expected_events, actual_events);
        }

        #[tokio::test]
        async fn commitment_mismatch() {
            const NUM_BLOCKS: usize = 1;
            let Setup {
                streamed_events,
                expected_events,
                storage,
            } = setup(NUM_BLOCKS, false).await;
            let expected_peer_id = streamed_events[0].as_ref().unwrap().peer;

            assert_matches::assert_matches!(
                handle_event_stream(stream::iter(streamed_events), storage.clone())
                    .await
                    .unwrap_err(),
                SyncError::EventCommitmentMismatch(x) => assert_eq!(x, expected_peer_id)
            );
        }

        #[tokio::test]
        async fn stream_failure() {
            assert_matches::assert_matches!(
                handle_event_stream(
                    stream::once(std::future::ready(Err(anyhow::anyhow!("")))),
                    StorageBuilder::in_memory().unwrap()
                )
                .await
                .unwrap_err(),
                SyncError::Other(_)
            );
        }

        #[tokio::test]
        async fn header_missing() {
            assert_matches::assert_matches!(
                handle_event_stream(
                    stream::once(std::future::ready(Ok(Faker.fake()))),
                    StorageBuilder::in_memory().unwrap()
                )
                .await
                .unwrap_err(),
                SyncError::Other(_)
            );
        }
    }

    mod handle_class_stream {
        use std::collections::HashMap;
        use std::future;

        use fake::{Dummy, Fake, Faker};
        use futures::{stream, SinkExt};
        use p2p::libp2p::PeerId;
        use pathfinder_common::event::Event;
        use pathfinder_common::transaction::TransactionVariant;
        use pathfinder_common::{felt, CasmHash, ClassHash, SierraHash, TransactionHash};
        use pathfinder_crypto::Felt;
        use pathfinder_storage::fake::{self as fake_storage, Block};
        use pathfinder_storage::StorageBuilder;
        use starknet_gateway_test_fixtures::class_definitions::{
            CAIRO_0_10_TUPLES_INTEGRATION,
            CAIRO_0_11_SIERRA,
        };

        use super::super::handle_class_stream;
        use super::*;
        use crate::state::block_hash::calculate_event_commitment;

        #[derive(Clone, Copy, Debug, Dummy)]
        struct DeclaredClass {
            pub block: BlockNumber,
            pub class: ClassHash,
        }

        #[derive(Clone, Debug)]
        struct DeclaredClasses(Vec<DeclaredClass>);

        impl DeclaredClasses {
            pub fn to_stream(
                &self,
            ) -> impl futures::Stream<Item = Result<(BlockNumber, HashSet<ClassHash>), SyncError>>
            {
                let mut all = HashMap::<_, HashSet<ClassHash>>::new();
                self.0
                    .iter()
                    .copied()
                    .for_each(|DeclaredClass { block, class }| {
                        all.entry(block).or_default().insert(class);
                    });
                stream::iter(all.into_iter().map(Ok))
            }
        }

        impl<T> Dummy<T> for DeclaredClasses {
            fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &T, rng: &mut R) -> Self {
                DeclaredClasses(fake::vec![DeclaredClass; 1..10])
            }
        }

        struct Setup {
            pub streamed_classes: Vec<anyhow::Result<PeerData<Class>>>,
            pub declared_classes: DeclaredClasses,
            pub expected_defs: Vec<(Vec<u8>, Option<Vec<u8>>)>,
            pub storage: Storage,
        }

        const ONE: BlockNumber = BlockNumber::new_or_panic(1);

        /// The genesis block contains no declared classes
        async fn setup(expect_correct_class_hashes: bool) -> Setup {
            tokio::task::spawn_blocking(move || {
                let mut blocks = fake_storage::init::with_n_blocks(2);

                blocks[0].state_update.declared_cairo_classes = Default::default();
                blocks[0].state_update.declared_sierra_classes = Default::default();
                blocks[0].cairo_defs = Default::default();
                blocks[0].sierra_defs = Default::default();

                let (cairo_hash, sierra_hash) = if expect_correct_class_hashes {
                    (
                        ClassHash(felt!(
                            "0x542460935cea188d21e752d8459d82d60497866aaad21f873cbb61621d34f7f"
                        )),
                        SierraHash(felt!(
                            "0x4e70b19333ae94bd958625f7b61ce9eec631653597e68645e13780061b2136c"
                        )),
                    )
                } else {
                    Default::default()
                };
                blocks[1].state_update.declared_cairo_classes = [cairo_hash].into();
                blocks[1].state_update.declared_sierra_classes =
                    [(sierra_hash, CasmHash::ZERO)].into();
                blocks[1].cairo_defs = vec![(cairo_hash, CAIRO_0_10_TUPLES_INTEGRATION.to_vec())];
                blocks[1].sierra_defs =
                    vec![(sierra_hash, CAIRO_0_11_SIERRA.to_vec(), b"casm".to_vec())];

                let streamed_classes = blocks[1]
                    .sierra_defs
                    .iter()
                    .cloned()
                    .map(|(sierra_hash, sierra_definition, casm_definition)| {
                        anyhow::Result::Ok(PeerData::for_tests(Class::Sierra {
                            block_number: blocks[1].header.header.number,
                            sierra_hash,
                            sierra_definition,
                            casm_definition,
                        }))
                    })
                    .chain(
                        blocks[1]
                            .cairo_defs
                            .iter()
                            .cloned()
                            .map(|(hash, definition)| {
                                anyhow::Result::Ok(PeerData::for_tests(Class::Cairo {
                                    block_number: blocks[1].header.header.number,
                                    hash,
                                    definition,
                                }))
                            }),
                    )
                    .collect::<Vec<_>>();
                let (declared_classes, expected_defs) = streamed_classes
                    .iter()
                    .map(|class| {
                        let class = &class.as_ref().unwrap().data;
                        (
                            DeclaredClass {
                                block: class.block_number(),
                                class: class.hash(),
                            },
                            (class.class_definition(), class.casm_definition()),
                        )
                    })
                    .unzip::<_, _, Vec<DeclaredClass>, Vec<(Vec<u8>, Option<Vec<u8>>)>>();
                let storage = StorageBuilder::in_memory().unwrap();
                fake_storage::fill(&storage, &blocks);
                Setup {
                    streamed_classes,
                    declared_classes: DeclaredClasses(declared_classes),
                    expected_defs,
                    storage,
                }
            })
            .await
            .unwrap()
        }

        #[tokio::test]
        async fn happy_path() {
            let Setup {
                streamed_classes,
                declared_classes,
                expected_defs,
                storage,
            } = setup(true).await;

            handle_class_stream(
                stream::iter(streamed_classes),
                storage.clone(),
                declared_classes.to_stream(),
            )
            .await
            .unwrap();

            let actual_defs = tokio::task::spawn_blocking(move || {
                let mut conn = storage.connection().unwrap();
                let db_tx = conn.transaction().unwrap();
                declared_classes
                    .0
                    .into_iter()
                    .map(|x| {
                        (
                            db_tx
                                .class_definition_at(x.block.into(), x.class)
                                .unwrap()
                                .unwrap(),
                            db_tx.casm_definition_at(x.block.into(), x.class).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap();

            pretty_assertions_sorted::assert_eq!(expected_defs, actual_defs);
        }

        #[rstest::rstest]
        #[case::cairo(Class::Cairo {
            block_number: ONE,
            hash: ClassHash::ZERO,
            definition: Default::default()
        })]
        #[case::sierra(Class::Sierra {
            block_number: ONE,
            sierra_hash: SierraHash::ZERO,
            sierra_definition: Default::default(),
            casm_definition: Default::default()
        })]
        #[tokio::test]
        async fn bad_layout(#[case] class: Class) {
            let storage = StorageBuilder::in_memory().unwrap();
            let data = PeerData::for_tests(class);
            let expected_peer_id = data.peer;

            assert_matches::assert_matches!(
                handle_class_stream(stream::once(std::future::ready(Ok(data))), storage, Faker.fake::<DeclaredClasses>().to_stream())
                    .await
                    .unwrap_err(),
                SyncError::BadClassLayout(x) => assert_eq!(x, expected_peer_id)
            );
        }

        #[tokio::test]
        async fn unexpected_class() {
            let Setup {
                mut streamed_classes,
                declared_classes,
                storage,
                ..
            } = setup(true).await;

            let peer_data = streamed_classes.last_mut().unwrap().as_mut().unwrap();
            match peer_data.data {
                Class::Cairo { ref mut hash, .. } => *hash = ClassHash::ZERO,
                _ => unreachable!(),
            }
            let expected_peer_id = peer_data.peer;

            assert_matches::assert_matches!(
                handle_class_stream(stream::iter(streamed_classes), storage, declared_classes.to_stream())
                    .await
                    .unwrap_err(),
                SyncError::UnexpectedClass(x) => assert_eq!(x, expected_peer_id)
            );
        }

        #[tokio::test]
        async fn class_hash_mismatch() {
            let Setup {
                streamed_classes,
                declared_classes,
                storage,
                ..
            } = setup(false).await;
            let expected_peer_id = streamed_classes[0].as_ref().unwrap().peer;

            assert_matches::assert_matches!(
                handle_class_stream(stream::iter(streamed_classes), storage.clone(), declared_classes.to_stream())
                    .await
                    .unwrap_err(),
                SyncError::BadClassHash(x) => assert_eq!(x, expected_peer_id)
            );
        }

        #[tokio::test]
        async fn stream_failure() {
            assert_matches::assert_matches!(
                handle_class_stream(
                    stream::once(std::future::ready(Err(anyhow::anyhow!("")))),
                    StorageBuilder::in_memory().unwrap(),
                    Faker.fake::<DeclaredClasses>().to_stream()
                )
                .await
                .unwrap_err(),
                SyncError::Other(_)
            );
        }
    }
}
