use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use anyhow::{anyhow, Context};
use futures::{StreamExt, TryStreamExt};
use pathfinder_common::state_update::{ContractClassUpdate, StateUpdateData};
use pathfinder_common::{
    BlockCommitmentSignature,
    BlockHash,
    BlockNumber,
    CasmHash,
    Chain,
    ChainId,
    ClassHash,
    EventCommitment,
    PublicKey,
    ReceiptCommitment,
    SierraHash,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    StateUpdate,
    TransactionCommitment,
};
use pathfinder_storage::Storage;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::reply::{Block, BlockSignature, Status};
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::state::block_hash::{
    calculate_event_commitment,
    calculate_receipt_commitment,
    calculate_transaction_commitment,
    verify_block_hash,
    BlockHeaderData,
};
use crate::state::sync::class::{download_class, DownloadedClass};
use crate::state::sync::SyncEvent;

#[derive(Default, Debug, Clone, Copy)]
pub struct Timings {
    pub block_download: Duration,
    pub class_declaration: Duration,
    pub signature_download: Duration,
}

/// A cache containing the last `N` blocks in the chain. Used to determine reorg
/// extents and ensure the integrity of new blocks.
pub struct BlockChain {
    /// The latest block in the chain.
    head: BlockNumber,
    /// The earliest block in the chain.
    tail: BlockNumber,

    map: HashMap<BlockNumber, (BlockHash, StateCommitment)>,
}

impl BlockChain {
    pub fn reset_to_genesis(&mut self) {
        self.map.drain();
        self.head = BlockNumber::default();
        self.tail = BlockNumber::default();
    }

    pub fn with_capacity(
        capacity: usize,
        blocks: Vec<(BlockNumber, BlockHash, StateCommitment)>,
    ) -> Self {
        let skip = blocks.len().saturating_sub(capacity);
        let blocks = &blocks[skip..];

        let head = blocks.last().map(|b| b.0).unwrap_or_default();
        let tail = blocks.first().map(|b| b.0).unwrap_or_default();

        let mut map = HashMap::with_capacity(capacity);
        map.extend(blocks.iter().cloned().map(|(a, b, c)| (a, (b, c))));

        Self { head, tail, map }
    }

    pub fn get<'a>(&'a self, block: &BlockNumber) -> Option<&'a (BlockHash, StateCommitment)> {
        self.map.get(block)
    }

    pub fn push(&mut self, number: BlockNumber, hash: BlockHash, commitment: StateCommitment) {
        for i in number.get()..=self.head.get() {
            self.map.remove(&BlockNumber::new_or_panic(i));
        }

        if self.map.capacity() == self.map.len() {
            self.map.remove(&self.tail);
            self.tail += 1;
        }
        self.map.insert(number, (hash, commitment));

        self.head = number;
    }
}

#[derive(Clone)]
pub struct L2SyncContext<GatewayClient> {
    pub sequencer: GatewayClient,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub block_validation_mode: BlockValidationMode,
    pub storage: Storage,
    pub sequencer_public_key: PublicKey,
    pub fetch_concurrency: std::num::NonZeroUsize,
    pub fetch_casm_from_fgw: bool,
}

pub async fn sync<GatewayClient>(
    tx_event: mpsc::Sender<SyncEvent>,
    context: L2SyncContext<GatewayClient>,
    mut head: Option<(BlockNumber, BlockHash, StateCommitment)>,
    mut blocks: BlockChain,
    mut latest: tokio::sync::watch::Receiver<(BlockNumber, BlockHash)>,
) -> anyhow::Result<()>
where
    GatewayClient: GatewayApi + Clone + Send + 'static,
{
    // Phase 1: catch up to the latest block
    let bulk_tail = latest.borrow().0;
    bulk_sync(
        tx_event.clone(),
        context.clone(),
        &mut blocks,
        &mut head,
        bulk_tail,
    )
    .await?;

    let L2SyncContext {
        sequencer,
        chain,
        chain_id,
        block_validation_mode,
        storage,
        sequencer_public_key,
        fetch_concurrency: _,
        fetch_casm_from_fgw,
    } = context;

    // Start polling head of chain
    'outer: loop {
        // Get the next block from L2.
        let (next, head_meta) = match &head {
            Some(head) => (head.0 + 1, Some(head)),
            None => (BlockNumber::GENESIS, None),
        };

        // We start downloading the signature for the block
        let signature_handle = tokio::spawn({
            let sequencer = sequencer.clone();
            async move {
                let t_signature = std::time::Instant::now();
                let result = sequencer.signature(next.into()).await;
                let t_signature = t_signature.elapsed();

                (result, t_signature)
            }
        });

        let t_block = std::time::Instant::now();

        let (block, commitments, state_update, state_diff_commitment) = loop {
            match download_block(
                next,
                chain,
                chain_id,
                head_meta.map(|h| h.1),
                &sequencer,
                block_validation_mode,
            )
            .await?
            {
                DownloadBlock::Block(block, commitments, state_update, state_diff_commitment) => {
                    break (block, commitments, state_update, state_diff_commitment)
                }
                DownloadBlock::AtHead => {
                    // Wait for the latest block to change.
                    if latest
                        .wait_for(|(_, hash)| hash != &head.unwrap_or_default().1)
                        .await
                        .is_err()
                    {
                        tracing::debug!("Latest tracking channel closed, exiting");
                        return Ok(());
                    }
                }
                DownloadBlock::Reorg => {
                    head = match head {
                        Some(some_head) => reorg(
                            &some_head,
                            chain,
                            chain_id,
                            &tx_event,
                            &sequencer,
                            block_validation_mode,
                            &blocks,
                        )
                        .await
                        .context("L2 reorg")?,
                        None => None,
                    };

                    match &head {
                        Some((number, hash, commitment)) => {
                            blocks.push(*number, *hash, *commitment)
                        }
                        None => blocks.reset_to_genesis(),
                    }

                    continue 'outer;
                }
            }
        };
        let t_block = t_block.elapsed();

        if let Some(some_head) = &head {
            if some_head.1 != block.parent_block_hash {
                head = reorg(
                    some_head,
                    chain,
                    chain_id,
                    &tx_event,
                    &sequencer,
                    block_validation_mode,
                    &blocks,
                )
                .await
                .context("L2 reorg")?;

                match &head {
                    Some((number, hash, commitment)) => blocks.push(*number, *hash, *commitment),
                    None => blocks.reset_to_genesis(),
                }

                continue 'outer;
            }
        }

        // Download and emit newly declared classes.
        let t_declare = std::time::Instant::now();
        let downloaded_classes = download_new_classes(
            &state_update,
            &sequencer,
            storage.clone(),
            fetch_casm_from_fgw,
        )
        .await
        .with_context(|| format!("Handling newly declared classes for block {next:?}"))?;
        emit_events_for_downloaded_classes(
            &tx_event,
            downloaded_classes,
            &state_update.declared_sierra_classes,
        )
        .await?;
        let t_declare = t_declare.elapsed();

        // Download signature
        let (signature_result, t_signature) =
            signature_handle.await.context("Joining signature task")?;
        let (signature, t_signature) = match signature_result {
            Ok(signature) => (signature, t_signature),
            Err(SequencerError::StarknetError(err))
                if err.code
                    == starknet_gateway_types::error::KnownStarknetErrorCode::BlockNotFound
                        .into() =>
            {
                // There is a race condition here: if the query for the signature was made
                // _before_ the block was published -- but by the time we
                // actually queried for the block it was there. In this case
                // we just retry the signature download.
                let t_signature = std::time::Instant::now();
                let signature = sequencer.signature(next.into()).await.with_context(|| {
                    format!("Fetch signature for block {next:?} from sequencer")
                })?;
                (signature, t_signature.elapsed())
            }
            Err(err) => {
                return Err(err)
                    .context(format!("Fetch signature for block {next:?} from sequencer"))
            }
        };

        // An extra sanity check for the signature API.
        anyhow::ensure!(
            block.block_hash == signature.block_hash,
            "Signature block hash mismatch, actual {:x}, expected {:x}",
            signature.block_hash.0,
            block.block_hash.0,
        );

        // Check block commitment signature
        let signature: BlockCommitmentSignature = signature.signature();
        let (signature, state_update) = match block_validation_mode {
            BlockValidationMode::Strict => {
                let block_hash = block.block_hash;
                let (verify_result, signature, state_update) = tokio::task::spawn_blocking(move || -> (Result<(), pathfinder_crypto::signature::SignatureError>, BlockCommitmentSignature, Box<StateUpdate>) {
                    let verify_result = signature
                        .verify(
                            sequencer_public_key,
                            block_hash,
                        );
                    (verify_result, signature, state_update)
                }).await?;
                if let Err(error) = verify_result {
                    tracing::warn!(%error, block_number=%block.block_number, "Block commitment signature mismatch");
                }
                (signature, state_update)
            }
            BlockValidationMode::AllowMismatch => (signature, state_update),
        };

        head = Some((next, block.block_hash, state_update.state_commitment));
        blocks.push(next, block.block_hash, state_update.state_commitment);

        let timings = Timings {
            block_download: t_block,
            class_declaration: t_declare,
            signature_download: t_signature,
        };

        tx_event
            .send(SyncEvent::Block(
                (block, commitments),
                state_update,
                Box::new(signature),
                Box::new(state_diff_commitment),
                timings,
            ))
            .await
            .context("Event channel closed")?;
    }
}

/// Emits the latest block hash and number from the gateway at regular
/// intervals.
///
/// Exits once all receivers are closed.
/// Errors are logged and ignored.
pub async fn poll_latest(
    gateway: impl GatewayApi,
    interval: Duration,
    sender: tokio::sync::watch::Sender<(BlockNumber, BlockHash)>,
) {
    let mut interval = tokio::time::interval(interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;

        let Ok(latest) = gateway
            .block_header(pathfinder_common::BlockId::Latest)
            .await
            .inspect_err(|e| tracing::debug!(error=%e, "Error requesting latest block ID"))
        else {
            continue;
        };

        if sender.send(latest).is_err() {
            tracing::debug!("Channel closed, exiting");
            break;
        }
    }
}

/// Download and emit new contract classes.
///
/// New classes can come from:
/// - DECLARE transactions
/// - `old_declared_contracts` from the state diff (Cairo 0.x classes)
/// - `declared_classes` from the state diff (Cairo 1.0 classes)
/// - `deployed_contracts` from the state diff (DEPLOY transactions)
/// - `replaced_classes` from the state diff
///
/// Note that due to an issue with the sequencer previously undeclared classes
/// can show up in `replaced_classes`. This is caused by DECLARE v0 transactions
/// that were _failing_ but the sequencer has still added the class to its list
/// of known classes...
pub async fn download_new_classes(
    state_update: &StateUpdate,
    sequencer: &impl GatewayApi,
    storage: Storage,
    fetch_casm_from_fgw: bool,
) -> Result<Vec<DownloadedClass>, anyhow::Error> {
    let deployed_classes = state_update
        .contract_updates
        .iter()
        .filter_map(|x| match x.1.class {
            Some(ContractClassUpdate::Deploy(hash)) => Some(hash),
            _ => None,
        });
    let declared_cairo_classes = state_update.declared_cairo_classes.iter().cloned();
    let declared_sierra_classes = state_update
        .declared_sierra_classes
        .keys()
        .map(|x| ClassHash(x.0));

    let new_classes = deployed_classes
        .chain(declared_cairo_classes)
        .chain(declared_sierra_classes)
        // Get unique class hashes only. Its unlikely they would have dupes here, but rather safe
        // than sorry.
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if new_classes.is_empty() {
        return Ok(vec![]);
    }

    let require_downloading = tokio::task::spawn_blocking(move || {
        let mut db_conn = storage
            .connection()
            .context("Creating database connection")?;
        let tx = db_conn
            .transaction()
            .context("Creating database transaction")?;

        let exists = tx
            .class_definitions_exist(&new_classes)
            .context("Querying class existence in database")?;

        let missing = new_classes
            .into_iter()
            .zip(exists.into_iter())
            .filter_map(|(class, exist)| (!exist).then_some(class))
            .collect::<HashSet<_>>();

        anyhow::Ok(missing)
    })
    .await
    .context("Joining database task")?
    .context("Querying database for missing classes")?;

    let futures = require_downloading.into_iter().map(|class_hash| {
        async move {
            download_class(sequencer, class_hash, fetch_casm_from_fgw)
                .await
                .with_context(|| format!("Downloading class {}", class_hash.0))
        }
        .in_current_span()
    });

    let stream = futures::stream::iter(futures).buffer_unordered(4);

    let downloaded_classes = stream.try_collect().await?;

    Ok(downloaded_classes)
}

enum DownloadBlock {
    Block(
        Box<Block>,
        (TransactionCommitment, EventCommitment, ReceiptCommitment),
        Box<StateUpdate>,
        StateDiffCommitment,
    ),
    AtHead,
    Reorg,
}

#[derive(Copy, Clone, Default)]
pub enum BlockValidationMode {
    #[default]
    Strict,

    // For testing only (test block hashes won't match)
    AllowMismatch,
}

async fn download_block(
    block_number: BlockNumber,
    chain: Chain,
    chain_id: ChainId,
    prev_block_hash: Option<BlockHash>,
    sequencer: &impl GatewayApi,
    mode: BlockValidationMode,
) -> anyhow::Result<DownloadBlock> {
    use rayon::prelude::*;
    use starknet_gateway_types::error::KnownStarknetErrorCode::BlockNotFound;

    match sequencer.state_update_with_block(block_number).await {
        Ok((block, state_update)) => {
            let block = Box::new(block);

            // Verify that transaction hashes match transaction contents.
            // Block hash is verified using these transaction hashes so we have to make
            // sure these are correct first.
            let (send, recv) = tokio::sync::oneshot::channel();
            rayon::spawn(move || {
                let result = block
                    .transactions
                    .par_iter()
                    .enumerate()
                    .try_for_each(|(i, txn)| {
                        if !txn.verify_hash(chain_id) {
                            anyhow::bail!("Transaction hash mismatch: block {block_number} idx {i}")
                        };
                        Ok(())
                    })
                    .map(|_| block);

                let _ = send.send(result);
            });
            let block = recv.await.expect("Panic on rayon thread")?;

            // Check if commitments and block hash are correct
            let verify_hash = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let state_diff_commitment =
                    StateUpdateData::from(state_update.clone()).compute_state_diff_commitment();
                let state_update = Box::new(state_update);
                let state_diff_length = state_update.state_diff_length();

                let block_number = block.block_number;
                let verify_result = verify_gateway_block_commitments_and_hash(
                    &block,
                    state_diff_commitment,
                    state_diff_length,
                    chain,
                    chain_id,
                )
                .with_context(move || format!("Verify block {block_number}"))?;
                Ok((block, state_update, state_diff_commitment, verify_result))
            });
            let (block, state_update, state_diff_commitment, verify_result) =
                verify_hash.await.context("Verify block hash")??;

            match (block.status, verify_result, mode) {
                (
                    Status::AcceptedOnL1 | Status::AcceptedOnL2,
                    VerifyResult::Match(commitments),
                    _,
                ) => Ok(DownloadBlock::Block(
                    block,
                    commitments,
                    state_update,
                    state_diff_commitment,
                )),
                (
                    Status::AcceptedOnL1 | Status::AcceptedOnL2,
                    VerifyResult::Mismatch,
                    BlockValidationMode::AllowMismatch,
                ) => Ok(DownloadBlock::Block(
                    block,
                    Default::default(),
                    state_update,
                    state_diff_commitment,
                )),
                (_, VerifyResult::Mismatch, BlockValidationMode::Strict) => {
                    Err(anyhow!("Block hash mismatch"))
                }
                _ => Err(anyhow!(
                    "Rejecting block as its status is {}, and only accepted blocks are allowed",
                    block.status
                )),
            }
        }
        Err(SequencerError::StarknetError(err)) if err.code == BlockNotFound.into() => {
            // This would occur if we queried past the head of the chain. We now need to
            // check that a reorg hasn't put us too far in the future. This does
            // run into race conditions with the sequencer but this is the best
            // we can do I think.
            let (latest_block_number, latest_block_hash) = sequencer
                .head()
                .await
                .context("Query sequencer for latest block")?;

            if latest_block_number + 1 == block_number {
                match prev_block_hash {
                    // We are definitely still at the head and it's just that a new block
                    // has not been published yet
                    Some(parent_block_hash) if parent_block_hash == latest_block_hash => {
                        Ok(DownloadBlock::AtHead)
                    }
                    // Our head is not valid anymore so there must have been a reorg only at this
                    // height
                    Some(_) => Ok(DownloadBlock::Reorg),
                    // There is something wrong with the sequencer, as we are attempting to get the
                    // genesis block Let's retry in a while
                    None => Ok(DownloadBlock::AtHead),
                }
            } else {
                // The new head is at lower height than our head which means there must have
                // been a reorg
                Ok(DownloadBlock::Reorg)
            }
        }
        Err(other) => Err(other).context("Download block from sequencer"),
    }
}

async fn bulk_sync<GatewayClient>(
    tx_event: mpsc::Sender<SyncEvent>,
    context: L2SyncContext<GatewayClient>,
    blocks: &mut BlockChain,
    head: &mut Option<(BlockNumber, BlockHash, StateCommitment)>,
    tail: BlockNumber,
) -> anyhow::Result<()>
where
    GatewayClient: GatewayApi + Clone + Send + 'static,
{
    let L2SyncContext {
        sequencer,
        chain,
        chain_id,
        block_validation_mode,
        storage,
        sequencer_public_key,
        fetch_concurrency,
        fetch_casm_from_fgw,
    } = context;

    let mut start = match head {
        Some(head) => head.0.get() + 1,
        None => BlockNumber::GENESIS.get(),
    };
    let end = tail.get();
    if start >= end {
        return Ok(());
    }

    tracing::trace!(%start, %end, "Catching up to the latest block");

    let mut futures = (start..=end)
        .map(|block_number| {
            let block_number = BlockNumber::new_or_panic(block_number);

            let _span =
                tracing::debug_span!("download_and_verify_block_data", %block_number).entered();
            tracing::trace!("Downloading block");

            let sequencer = sequencer.clone();
            let storage = storage.clone();

            async move {
                let t_block = std::time::Instant::now();
                let (block, state_update) = sequencer.state_update_with_block(block_number).await?;
                let t_block = t_block.elapsed();

                let t_signature = std::time::Instant::now();
                let signature = sequencer.signature(block_number.into()).await?;
                let t_signature = t_signature.elapsed();

                let span = tracing::Span::current();

                let (tx, rx) = tokio::sync::oneshot::channel();

                rayon::spawn(move || {
                    let _span = span.entered();

                    let t_verification = std::time::Instant::now();

                    let result = verify_block_and_state_update(
                        &block,
                        &state_update,
                        chain,
                        chain_id,
                        block_validation_mode,
                    )
                    .and_then(
                        |(
                            transaction_commitment,
                            event_commitment,
                            receipt_commitment,
                            state_diff_commitment,
                        )| {
                            verify_signature(
                                block.block_hash,
                                &signature,
                                sequencer_public_key,
                                BlockValidationMode::AllowMismatch,
                            )
                            .map_err(|err| err.into())
                            .map(|_| {
                                (
                                    block,
                                    state_update,
                                    signature,
                                    transaction_commitment,
                                    event_commitment,
                                    receipt_commitment,
                                    state_diff_commitment,
                                )
                            })
                        },
                    );

                    let t_verification = t_verification.elapsed();
                    tracing::trace!(elapsed=?t_verification, "Block verification done");

                    let _ = tx.send(result);
                });

                let (
                    block,
                    state_update,
                    signature,
                    transaction_commitment,
                    event_commitment,
                    receipt_commitment,
                    state_diff_commitment,
                ) = rx
                    .await
                    .expect("Panic on rayon thread while verifying block")
                    .context("Verifying block contents")?;

                let t_declare = std::time::Instant::now();
                let downloaded_classes =
                    download_new_classes(&state_update, &sequencer, storage, fetch_casm_from_fgw)
                        .await
                        .with_context(|| {
                            format!("Handling newly declared classes for block {block_number:?}")
                        })?;
                let t_declare = t_declare.elapsed();

                let timings = Timings {
                    block_download: t_block,
                    class_declaration: t_declare,
                    signature_download: t_signature,
                };

                Ok::<_, anyhow::Error>((
                    block,
                    state_update,
                    signature,
                    transaction_commitment,
                    event_commitment,
                    receipt_commitment,
                    state_diff_commitment,
                    downloaded_classes,
                    timings,
                ))
            }
            .in_current_span()
        })
        .peekable();

    // We want to download blocks in an unordered fashion, but still have a limit on
    // the size of the cache that is used to then sort the downloaded blocks before
    // emitting them. (Tries need to be updated in order, hence the sorting.)
    //
    // The limit is needed because if we encounter problems downloading a block, at
    // some point we need to wait for it, otherwise the cache would balloon being
    // filled with endless newer and newer blocks that we cannot emit and this would
    // lead to oom.
    const UNORDERED_CACHE_CAPACITY_FACTOR: usize = 32;

    while futures.peek().is_some() {
        let futures_chunk = futures
            .by_ref()
            .take(fetch_concurrency.get() * UNORDERED_CACHE_CAPACITY_FACTOR);

        let mut stream =
            futures::stream::iter(futures_chunk).buffer_unordered(fetch_concurrency.get());

        let mut ordered_blocks = BTreeMap::new();

        while let Some(result) = stream.next().await {
            let Ok(ok) = result else {
                // We've hit an error, so we stop the loop and return. `head` has been updated
                // to the last synced block so our "tracking" sync will just
                // continue from there.
                tracing::info!(
                    "Error during bulk syncing blocks, falling back to normal sync: {}",
                    result.err().unwrap()
                );
                return Ok(());
            };

            ordered_blocks.insert(ok.0.block_number.get(), ok);

            let keys = ordered_blocks.keys().copied().collect::<Vec<_>>();

            tracing::trace!(start, len = ordered_blocks.len(), ?keys, "Cached blocks");

            // Find number of elems till the first gap that we can emit right now
            let num_to_emit = ordered_blocks
                .keys()
                .take_while(|block_number| {
                    if **block_number == start {
                        start += 1;
                        true
                    } else {
                        false
                    }
                })
                .count();

            for _ in 0..num_to_emit {
                let (
                    _,
                    (
                        block,
                        state_update,
                        signature,
                        transaction_commitment,
                        event_commitment,
                        receipt_commitment,
                        state_diff_commitment,
                        downloaded_classes,
                        timings,
                    ),
                ) = ordered_blocks.pop_first().expect("num_to_emit > 0");

                *head = Some((
                    block.block_number,
                    block.block_hash,
                    state_update.state_commitment,
                ));
                blocks.push(
                    block.block_number,
                    block.block_hash,
                    state_update.state_commitment,
                );

                emit_events_for_downloaded_classes(
                    &tx_event,
                    downloaded_classes,
                    &state_update.declared_sierra_classes,
                )
                .await?;

                tx_event
                    .send(SyncEvent::Block(
                        (
                            Box::new(block),
                            (transaction_commitment, event_commitment, receipt_commitment),
                        ),
                        Box::new(state_update),
                        Box::new(signature.signature()),
                        Box::new(state_diff_commitment),
                        timings,
                    ))
                    .await
                    .context("Event channel closed")?;
            }
        }
    }

    Ok(())
}

pub(super) async fn emit_events_for_downloaded_classes(
    tx_event: &mpsc::Sender<SyncEvent>,
    downloaded_classes: Vec<DownloadedClass>,
    declared_sierra_classes: &HashMap<SierraHash, CasmHash>,
) -> anyhow::Result<()> {
    for downloaded_class in downloaded_classes {
        match downloaded_class {
            DownloadedClass::Cairo { definition, hash } => {
                tracing::trace!(class_hash=%hash, "Sending Cairo class event");
                tx_event
                    .send(SyncEvent::CairoClass { definition, hash })
                    .await
                    .with_context(|| {
                        format!(
                            "Sending Event::NewCairoContract for declared class {}",
                            hash.0
                        )
                    })?
            }
            DownloadedClass::Sierra {
                sierra_definition,
                sierra_hash,
                casm_definition,
            } => {
                // NOTE: we _have_ to use the same compiled_class_class hash as returned by the
                // feeder gateway, since that's what has been added to the class
                // commitment tree.
                let Some(casm_hash) = declared_sierra_classes
                    .iter()
                    .find_map(|(sierra, casm)| (sierra.0 == sierra_hash.0).then_some(*casm))
                else {
                    // This can occur if the sierra was in here as a deploy contract, if the class
                    // was declared in a previous block but not yet persisted by
                    // the database.
                    continue;
                };
                tracing::trace!(class_hash=%sierra_hash, "Sending Sierra class event");
                tx_event
                    .send(SyncEvent::SierraClass {
                        sierra_definition,
                        sierra_hash,
                        casm_definition,
                        casm_hash,
                    })
                    .await
                    .with_context(|| {
                        format!(
                            "Sending Event::NewSierraContract for declared class {}",
                            sierra_hash.0
                        )
                    })?
            }
        }
    }

    Ok(())
}

fn verify_block_and_state_update(
    block: &Block,
    state_update: &StateUpdate,
    chain: Chain,
    chain_id: ChainId,
    mode: BlockValidationMode,
) -> anyhow::Result<(
    TransactionCommitment,
    EventCommitment,
    ReceiptCommitment,
    StateDiffCommitment,
)> {
    // Check if commitments and block hash are correct
    let state_diff_commitment =
        StateUpdateData::from(state_update.clone()).compute_state_diff_commitment();
    let state_diff_length = state_update.state_diff_length();

    let verify_result = verify_gateway_block_commitments_and_hash(
        block,
        state_diff_commitment,
        state_diff_length,
        chain,
        chain_id,
    )
    .context("Verify block hash")?;

    let (transaction_commitment, event_commitment, receipt_commitment) =
        match (block.status, verify_result, mode) {
            (Status::AcceptedOnL1 | Status::AcceptedOnL2, VerifyResult::Match(commitments), _) => {
                Ok(commitments)
            }
            (
                Status::AcceptedOnL1 | Status::AcceptedOnL2,
                VerifyResult::Mismatch,
                BlockValidationMode::AllowMismatch,
            ) => Ok(Default::default()),
            (_, VerifyResult::Mismatch, BlockValidationMode::Strict) => {
                Err(anyhow!("Block hash mismatch"))
            }
            _ => Err(anyhow!(
                "Rejecting block as its status is {}, and only accepted blocks are allowed",
                block.status
            )),
        }?;

    // Check if transaction hashes are valid
    verify_transaction_hashes(block.block_number, &block.transactions, chain_id)
        .context("Verify transaction hashes")?;

    // Always compute the state diff commitment from the state update.
    // If any of the feeder gateway replies (block or signature) contain a state
    // diff commitment, check if the value matches. If it doesn't, just log the
    // fact.
    let computed_state_diff_commitment = state_update.compute_state_diff_commitment();

    if let Some(x) = block.state_diff_commitment {
        if x != computed_state_diff_commitment {
            tracing::warn!(
                "State diff commitment mismatch: computed {:x}, feeder gateway {:x}",
                computed_state_diff_commitment.0,
                x.0
            );
        }
    }

    Ok((
        transaction_commitment,
        event_commitment,
        receipt_commitment,
        computed_state_diff_commitment,
    ))
}

/// Check that transaction hashes match the actual contents.
fn verify_transaction_hashes(
    block_number: BlockNumber,
    transactions: &[pathfinder_common::transaction::Transaction],
    chain_id: ChainId,
) -> anyhow::Result<()> {
    use rayon::prelude::*;

    transactions
        .par_iter()
        .enumerate()
        .try_for_each(|(i, txn)| {
            if !txn.verify_hash(chain_id) {
                anyhow::bail!("Transaction hash mismatch: block {block_number} idx {i}")
            };
            Ok(())
        })
}

/// Check block commitment signature.
fn verify_signature(
    block_hash: BlockHash,
    signature: &BlockSignature,
    sequencer_public_key: PublicKey,
    mode: BlockValidationMode,
) -> Result<(), pathfinder_crypto::signature::SignatureError> {
    let signature = signature.signature();
    match mode {
        BlockValidationMode::Strict => signature.verify(sequencer_public_key, block_hash),
        BlockValidationMode::AllowMismatch => Ok(()),
    }
}

enum VerifyResult {
    Match((TransactionCommitment, EventCommitment, ReceiptCommitment)),
    Mismatch,
}

/// Verify that the block hash matches the actual contents.
fn verify_gateway_block_commitments_and_hash(
    block: &Block,
    state_diff_commitment: StateDiffCommitment,
    state_diff_length: u64,
    chain: Chain,
    chain_id: ChainId,
) -> anyhow::Result<VerifyResult> {
    let mut bhd =
        BlockHeaderData::from_gateway_block(block, state_diff_commitment, state_diff_length)?;

    let computed_transaction_commitment =
        calculate_transaction_commitment(&block.transactions, block.starknet_version)?;

    // Older blocks on mainnet don't carry a precalculated transaction commitment.
    if block.transaction_commitment == TransactionCommitment::ZERO {
        // Update with the computed transaction commitment, verification is not
        // possible.
        bhd.transaction_commitment = computed_transaction_commitment;
    } else if computed_transaction_commitment != bhd.transaction_commitment {
        tracing::debug!(%computed_transaction_commitment, actual_transaction_commitment=%bhd.transaction_commitment, "Transaction commitment mismatch");
        return Ok(VerifyResult::Mismatch);
    }

    let receipts = block
        .transaction_receipts
        .iter()
        .map(|(r, _)| r.clone())
        .collect::<Vec<_>>();
    let computed_receipt_commitment = calculate_receipt_commitment(receipts.as_slice())?;

    // Older blocks on mainnet don't carry a precalculated receipt commitment.
    if let Some(receipt_commitment) = block.receipt_commitment {
        if computed_receipt_commitment != receipt_commitment {
            tracing::debug!(%computed_receipt_commitment, actual_receipt_commitment=%receipt_commitment, "Receipt commitment mismatch");
            return Ok(VerifyResult::Mismatch);
        }
    } else {
        // Update with the computed transaction commitment, verification is not
        // possible.
        bhd.receipt_commitment = computed_receipt_commitment;
    }

    let events_with_tx_hashes = block
        .transaction_receipts
        .iter()
        .map(|(receipt, events)| (receipt.transaction_hash, events.as_slice()))
        .collect::<Vec<_>>();
    let event_commitment =
        calculate_event_commitment(&events_with_tx_hashes, block.starknet_version)?;

    // Older blocks on mainnet don't carry a precalculated event
    // commitment.
    if block.event_commitment == EventCommitment::ZERO {
        // Update with the computed transaction commitment, verification is not
        // possible.
        bhd.event_commitment = event_commitment;
    } else if event_commitment != block.event_commitment {
        tracing::debug!(computed_event_commitment=%event_commitment, actual_event_commitment=%block.event_commitment, "Event commitment mismatch");
        return Ok(VerifyResult::Mismatch);
    }

    Ok(match verify_block_hash(bhd, chain, chain_id)? {
        crate::state::block_hash::VerifyResult::Match => {
            // For pre-0.13.2 blocks we actually have to re-compute some commitments: after
            // we've verified that the block hash is correct we no longer need
            // the legacy commitments. The P2P protocol requires that all
            // commitments in block headers are the 0.13.2 variants for legacy
            // blocks.
            let (transaction_commitment, event_commitment, receipt_commitment) = if block
                .starknet_version
                < StarknetVersion::V_0_13_2
            {
                let transaction_commitment = calculate_transaction_commitment(
                    &block.transactions,
                    StarknetVersion::V_0_13_2,
                )?;
                let event_commitment =
                    calculate_event_commitment(&events_with_tx_hashes, StarknetVersion::V_0_13_2)?;
                (
                    transaction_commitment,
                    event_commitment,
                    computed_receipt_commitment,
                )
            } else {
                (
                    computed_transaction_commitment,
                    event_commitment,
                    computed_receipt_commitment,
                )
            };

            VerifyResult::Match((transaction_commitment, event_commitment, receipt_commitment))
        }
        crate::state::block_hash::VerifyResult::Mismatch => VerifyResult::Mismatch,
    })
}

async fn reorg(
    head: &(BlockNumber, BlockHash, StateCommitment),
    chain: Chain,
    chain_id: ChainId,
    tx_event: &mpsc::Sender<SyncEvent>,
    sequencer: &impl GatewayApi,
    mode: BlockValidationMode,
    blocks: &BlockChain,
) -> anyhow::Result<Option<(BlockNumber, BlockHash, StateCommitment)>> {
    // Go back in history until we find an L2 block that does still exist.
    // We already know the current head is invalid.
    let mut reorg_tail = *head;

    let new_head = loop {
        if reorg_tail.0 == BlockNumber::GENESIS {
            break None;
        }

        let previous_block_number = reorg_tail.0 - 1;
        let previous = blocks
            .get(&previous_block_number)
            .context("Reorg exceeded local blockchain cache")?;

        match download_block(
            previous_block_number,
            chain,
            chain_id,
            Some(previous.0),
            sequencer,
            mode,
        )
        .await
        .with_context(|| format!("Download block {previous_block_number} from sequencer"))?
        {
            DownloadBlock::Block(block, _, _, _) if block.block_hash == previous.0 => {
                break Some((previous_block_number, previous.0, previous.1));
            }
            _ => {}
        };

        reorg_tail = (previous_block_number, previous.0, previous.1);
    };

    let reorg_tail = new_head
        .as_ref()
        .map(|x| x.0 + 1)
        .unwrap_or(BlockNumber::GENESIS);

    tx_event
        .send(SyncEvent::Reorg(reorg_tail))
        .await
        .context("Event channel closed")?;

    Ok(new_head)
}

#[cfg(test)]
mod tests {
    mod sync {
        use std::num::NonZeroU32;
        use std::sync::LazyLock;

        use assert_matches::assert_matches;
        use pathfinder_common::macro_prelude::*;
        use pathfinder_common::{
            BlockHash,
            BlockId,
            BlockNumber,
            BlockTimestamp,
            Chain,
            ChainId,
            ClassHash,
            ContractAddress,
            GasPrice,
            PublicKey,
            SequencerAddress,
            StarknetVersion,
            StateCommitment,
            StateUpdate,
            StorageAddress,
            StorageValue,
        };
        use pathfinder_crypto::Felt;
        use pathfinder_storage::StorageBuilder;
        use starknet_gateway_client::MockGatewayApi;
        use starknet_gateway_types::error::{
            KnownStarknetErrorCode,
            SequencerError,
            StarknetError,
        };
        use starknet_gateway_types::reply;
        use starknet_gateway_types::reply::GasPrices;
        use tokio::sync::mpsc;
        use tokio::task::JoinHandle;

        use super::super::{bulk_sync, sync, BlockValidationMode, SyncEvent};
        use crate::state::l2::{BlockChain, L2SyncContext};

        const MODE: BlockValidationMode = BlockValidationMode::AllowMismatch;

        const DEF0: &str = r#"{
            "abi": [],
            "program": {
                "attributes": [],
                "builtins": [],
                "data": [],
                "hints": {},
                "identifiers": {},
                "main_scope": "contract definition "#;
        const DEF1: &str = r#"",
                "prime": "",
                "reference_manager": ""
            },
            "entry_points_by_type": {}
        }"#;

        const BLOCK0_NUMBER: BlockNumber = BlockNumber::GENESIS;
        const BLOCK1_NUMBER: BlockNumber = BlockNumber::new_or_panic(1);
        const BLOCK2_NUMBER: BlockNumber = BlockNumber::new_or_panic(2);
        const BLOCK3_NUMBER: BlockNumber = BlockNumber::new_or_panic(3);
        const BLOCK4_NUMBER: BlockNumber = BlockNumber::new_or_panic(4);

        const BLOCK0_HASH: BlockHash = block_hash_bytes!(b"block 0 hash");
        const BLOCK0_HASH_V2: BlockHash = block_hash_bytes!(b"block 0 hash v2");
        const BLOCK1_HASH: BlockHash = block_hash_bytes!(b"block 1 hash");
        const BLOCK1_HASH_V2: BlockHash = block_hash_bytes!(b"block 1 hash v2");
        const BLOCK2_HASH: BlockHash = block_hash_bytes!(b"block 2 hash");
        const BLOCK2_HASH_V2: BlockHash = block_hash_bytes!(b"block 2 hash v2");
        const BLOCK3_HASH: BlockHash = block_hash_bytes!(b"block 3 hash");

        const GLOBAL_ROOT0: StateCommitment = state_commitment_bytes!(b"global root 0");
        const GLOBAL_ROOT0_V2: StateCommitment = state_commitment_bytes!(b"global root 0 v2");
        const GLOBAL_ROOT1: StateCommitment = state_commitment_bytes!(b"global root 1");
        const GLOBAL_ROOT1_V2: StateCommitment = state_commitment_bytes!(b"global root 1 v2");
        const GLOBAL_ROOT2: StateCommitment = state_commitment_bytes!(b"global root 2");
        const GLOBAL_ROOT2_V2: StateCommitment = state_commitment_bytes!(b"global root 2 v2");
        const GLOBAL_ROOT3: StateCommitment = state_commitment_bytes!(b"global root 3");

        const CONTRACT0_ADDR: ContractAddress = contract_address_bytes!(b"contract 0 addr");
        const CONTRACT0_ADDR_V2: ContractAddress = contract_address_bytes!(b"contract 0 addr v2");
        const CONTRACT1_ADDR: ContractAddress = contract_address_bytes!(b"contract 1 addr");

        const CONTRACT0_HASH: ClassHash =
            class_hash!("0x03CC4D0167577958ADD7DD759418506E0930BB061597519CCEB8C3AC6277692E");
        const CONTRACT0_HASH_V2: ClassHash =
            class_hash!("0x01BE539E97D3BEFAE5D56D780BAF433802B3203DC6B2947FDB90C384AEF39F3E");
        const CONTRACT1_HASH: ClassHash =
            class_hash!("0x071B088C5C8CD884F3106D62C6CB8B423D1D3A58BFAD2EAA8AAC9E4E3E73529D");

        const STORAGE_KEY0: StorageAddress = storage_address_bytes!(b"contract 0 storage addr 0");
        const STORAGE_KEY1: StorageAddress = storage_address_bytes!(b"contract 1 storage addr 0");

        const STORAGE_VAL0: StorageValue = storage_value_bytes!(b"contract 0 storage val 0");
        const STORAGE_VAL0_V2: StorageValue = storage_value_bytes!(b"contract 0 storage val 0 v2");
        const STORAGE_VAL1: StorageValue = storage_value_bytes!(b"contract 1 storage val 0");

        const BLOCK0_SIGNATURE: reply::BlockSignature = reply::BlockSignature {
            block_hash: BLOCK0_HASH,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 0 signature r"),
                block_commitment_signature_elem_bytes!(b"block 0 signature s"),
            ],
        };
        // const BLOCK0_COMMITMENT_SIGNATURE: BlockCommitmentSignature =
        // BlockCommitmentSignature {     r: BLOCK0_SIGNATURE.signature[0],
        //     s: BLOCK0_SIGNATURE.signature[1],
        // };
        const BLOCK0_SIGNATURE_V2: reply::BlockSignature = reply::BlockSignature {
            block_hash: BLOCK0_HASH_V2,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 0 signature r 2"),
                block_commitment_signature_elem_bytes!(b"block 0 signature s 2"),
            ],
        };

        const BLOCK1_SIGNATURE: reply::BlockSignature = reply::BlockSignature {
            block_hash: BLOCK1_HASH,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 1 signature r"),
                block_commitment_signature_elem_bytes!(b"block 1 signature s"),
            ],
        };
        // const BLOCK1_COMMITMENT_SIGNATURE: BlockCommitmentSignature =
        // BlockCommitmentSignature {     r: BLOCK1_SIGNATURE.signature[0],
        //     s: BLOCK1_SIGNATURE.signature[1],
        // };
        const BLOCK1_SIGNATURE_V2: reply::BlockSignature = reply::BlockSignature {
            block_hash: BLOCK1_HASH_V2,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 1 signature r 2"),
                block_commitment_signature_elem_bytes!(b"block 1 signature s 2"),
            ],
        };
        const BLOCK2_SIGNATURE: reply::BlockSignature = reply::BlockSignature {
            block_hash: BLOCK2_HASH,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 2 signature r"),
                block_commitment_signature_elem_bytes!(b"block 2 signature s"),
            ],
        };
        const BLOCK2_SIGNATURE_V2: reply::BlockSignature = reply::BlockSignature {
            block_hash: BLOCK2_HASH_V2,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 2 signature r 2"),
                block_commitment_signature_elem_bytes!(b"block 2 signature s 2"),
            ],
        };
        const BLOCK3_SIGNATURE: reply::BlockSignature = reply::BlockSignature {
            block_hash: BLOCK3_HASH,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 3 signature r"),
                block_commitment_signature_elem_bytes!(b"block 3 signature s"),
            ],
        };

        fn spawn_sync_default(
            tx_event: mpsc::Sender<SyncEvent>,
            sequencer: MockGatewayApi,
        ) -> JoinHandle<anyhow::Result<()>> {
            let storage = StorageBuilder::in_memory_with_trie_pruning_and_pool_size(
                pathfinder_storage::TriePruneMode::Archive,
                NonZeroU32::new(5).unwrap(),
            )
            .unwrap();
            let sequencer = std::sync::Arc::new(sequencer);
            let context = L2SyncContext {
                sequencer,
                chain: Chain::SepoliaTestnet,
                chain_id: ChainId::SEPOLIA_TESTNET,
                block_validation_mode: MODE,
                storage,
                sequencer_public_key: PublicKey::ZERO,
                fetch_concurrency: std::num::NonZeroUsize::new(1).unwrap(),
                fetch_casm_from_fgw: false,
            };

            let latest = tokio::sync::watch::channel(Default::default());

            tokio::spawn(sync(
                tx_event,
                context,
                None,
                BlockChain::with_capacity(100, vec![]),
                latest.1,
            ))
        }

        fn spawn_bulk_sync(
            tx_event: mpsc::Sender<SyncEvent>,
            sequencer: MockGatewayApi,
        ) -> JoinHandle<anyhow::Result<Option<(BlockNumber, BlockHash, StateCommitment)>>> {
            let storage = StorageBuilder::in_memory_with_trie_pruning_and_pool_size(
                pathfinder_storage::TriePruneMode::Archive,
                NonZeroU32::new(5).unwrap(),
            )
            .unwrap();
            let sequencer = std::sync::Arc::new(sequencer);
            let context = L2SyncContext {
                sequencer,
                chain: Chain::SepoliaTestnet,
                chain_id: ChainId::SEPOLIA_TESTNET,
                block_validation_mode: MODE,
                storage,
                sequencer_public_key: PublicKey::ZERO,
                fetch_concurrency: std::num::NonZeroUsize::new(2).unwrap(),
                fetch_casm_from_fgw: false,
            };

            tokio::spawn(async move {
                let mut blocks = BlockChain::with_capacity(100, vec![]);
                let mut head = None;
                bulk_sync(
                    tx_event,
                    context,
                    &mut blocks,
                    &mut head,
                    BlockNumber::new_or_panic(1),
                )
                .await?;

                Ok(head)
            })
        }

        static CONTRACT0_DEF: LazyLock<bytes::Bytes> =
            LazyLock::new(|| format!("{DEF0}0{DEF1}").into());
        static CONTRACT0_DEF_V2: LazyLock<bytes::Bytes> =
            LazyLock::new(|| format!("{DEF0}0 v2{DEF1}").into());
        static CONTRACT1_DEF: LazyLock<bytes::Bytes> =
            LazyLock::new(|| format!("{DEF0}1{DEF1}").into());

        static BLOCK0: LazyLock<reply::Block> = LazyLock::new(|| reply::Block {
            block_hash: BLOCK0_HASH,
            block_number: BLOCK0_NUMBER,
            l1_gas_price: Default::default(),
            l1_data_gas_price: Default::default(),
            parent_block_hash: BlockHash(Felt::ZERO),
            sequencer_address: Some(SequencerAddress(Felt::ZERO)),
            state_commitment: GLOBAL_ROOT0,
            status: reply::Status::AcceptedOnL1,
            timestamp: BlockTimestamp::new_or_panic(0),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: StarknetVersion::default(),
            l1_da_mode: Default::default(),
            transaction_commitment: Default::default(),
            event_commitment: Default::default(),
            receipt_commitment: Default::default(),
            state_diff_commitment: Default::default(),
            state_diff_length: Default::default(),
        });
        static BLOCK0_V2: LazyLock<reply::Block> = LazyLock::new(|| reply::Block {
            block_hash: BLOCK0_HASH_V2,
            block_number: BLOCK0_NUMBER,
            l1_gas_price: GasPrices {
                price_in_wei: GasPrice::from_be_slice(b"gas price 0 v2").unwrap(),
                price_in_fri: GasPrice::from_be_slice(b"strk price 0 v2").unwrap(),
            },
            l1_data_gas_price: GasPrices {
                price_in_wei: GasPrice::from_be_slice(b"datgasprice 0 v2").unwrap(),
                price_in_fri: GasPrice::from_be_slice(b"datstrkpric 0 v2").unwrap(),
            },
            parent_block_hash: BlockHash(Felt::ZERO),
            sequencer_address: Some(SequencerAddress(
                Felt::from_be_slice(b"sequencer addr. 0 v2").unwrap(),
            )),
            state_commitment: GLOBAL_ROOT0_V2,
            status: reply::Status::AcceptedOnL2,
            timestamp: BlockTimestamp::new_or_panic(10),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: StarknetVersion::new(0, 9, 1, 0),
            l1_da_mode: Default::default(),
            transaction_commitment: Default::default(),
            event_commitment: Default::default(),
            receipt_commitment: Default::default(),
            state_diff_commitment: Default::default(),
            state_diff_length: Default::default(),
        });
        static BLOCK1: LazyLock<reply::Block> = LazyLock::new(|| reply::Block {
            block_hash: BLOCK1_HASH,
            block_number: BLOCK1_NUMBER,
            l1_gas_price: GasPrices {
                price_in_wei: GasPrice::from(1),
                price_in_fri: GasPrice::from(1),
            },
            l1_data_gas_price: GasPrices {
                price_in_wei: GasPrice::from(1),
                price_in_fri: GasPrice::from(1),
            },
            parent_block_hash: BLOCK0_HASH,
            sequencer_address: Some(SequencerAddress(
                Felt::from_be_slice(b"sequencer address 1").unwrap(),
            )),
            state_commitment: GLOBAL_ROOT1,
            status: reply::Status::AcceptedOnL1,
            timestamp: BlockTimestamp::new_or_panic(1),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: StarknetVersion::new(0, 9, 1, 0),
            l1_da_mode: Default::default(),
            transaction_commitment: Default::default(),
            event_commitment: Default::default(),
            receipt_commitment: Default::default(),
            state_diff_commitment: Default::default(),
            state_diff_length: Default::default(),
        });
        static BLOCK2: LazyLock<reply::Block> = LazyLock::new(|| reply::Block {
            block_hash: BLOCK2_HASH,
            block_number: BLOCK2_NUMBER,
            l1_gas_price: GasPrices {
                price_in_wei: GasPrice::from(2),
                price_in_fri: GasPrice::from(2),
            },
            l1_data_gas_price: GasPrices {
                price_in_wei: GasPrice::from(2),
                price_in_fri: GasPrice::from(2),
            },
            parent_block_hash: BLOCK1_HASH,
            sequencer_address: Some(SequencerAddress(
                Felt::from_be_slice(b"sequencer address 2").unwrap(),
            )),
            state_commitment: GLOBAL_ROOT2,
            status: reply::Status::AcceptedOnL1,
            timestamp: BlockTimestamp::new_or_panic(2),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: StarknetVersion::new(0, 9, 2, 0),
            l1_da_mode: Default::default(),
            transaction_commitment: Default::default(),
            event_commitment: Default::default(),
            receipt_commitment: Default::default(),
            state_diff_commitment: Default::default(),
            state_diff_length: Default::default(),
        });

        static STATE_UPDATE0: LazyLock<StateUpdate> = LazyLock::new(|| {
            StateUpdate::default()
                .with_block_hash(BLOCK0_HASH)
                .with_state_commitment(GLOBAL_ROOT0)
                .with_deployed_contract(CONTRACT0_ADDR, CONTRACT0_HASH)
                .with_storage_update(CONTRACT0_ADDR, STORAGE_KEY0, STORAGE_VAL0)
        });
        static STATE_UPDATE0_V2: LazyLock<StateUpdate> = LazyLock::new(|| {
            StateUpdate::default()
                .with_block_hash(BLOCK0_HASH_V2)
                .with_state_commitment(GLOBAL_ROOT0_V2)
                .with_deployed_contract(CONTRACT0_ADDR_V2, CONTRACT0_HASH_V2)
        });

        static STATE_UPDATE1: LazyLock<StateUpdate> = LazyLock::new(|| {
            StateUpdate::default()
                .with_block_hash(BLOCK1_HASH)
                .with_state_commitment(GLOBAL_ROOT1)
                .with_parent_state_commitment(GLOBAL_ROOT0)
                .with_deployed_contract(CONTRACT1_ADDR, CONTRACT1_HASH)
                .with_storage_update(CONTRACT0_ADDR, STORAGE_KEY0, STORAGE_VAL0_V2)
                .with_storage_update(CONTRACT1_ADDR, STORAGE_KEY1, STORAGE_VAL1)
        });

        static STATE_UPDATE1_V2: LazyLock<StateUpdate> = LazyLock::new(|| {
            StateUpdate::default()
                .with_block_hash(BLOCK1_HASH_V2)
                .with_state_commitment(GLOBAL_ROOT1_V2)
                .with_parent_state_commitment(GLOBAL_ROOT0_V2)
        });
        static STATE_UPDATE2: LazyLock<StateUpdate> = LazyLock::new(|| {
            StateUpdate::default()
                .with_block_hash(BLOCK2_HASH)
                .with_state_commitment(GLOBAL_ROOT2)
                .with_parent_state_commitment(GLOBAL_ROOT1)
        });
        static STATE_UPDATE2_V2: LazyLock<StateUpdate> = LazyLock::new(|| {
            StateUpdate::default()
                .with_block_hash(BLOCK2_HASH_V2)
                .with_state_commitment(GLOBAL_ROOT2_V2)
                .with_parent_state_commitment(GLOBAL_ROOT1_V2)
        });
        static STATE_UPDATE3: LazyLock<StateUpdate> = LazyLock::new(|| {
            StateUpdate::default()
                .with_block_hash(BLOCK3_HASH)
                .with_state_commitment(GLOBAL_ROOT3)
                .with_parent_state_commitment(GLOBAL_ROOT2)
        });

        /// Convenience wrapper
        fn expect_state_update_with_block(
            mock: &mut MockGatewayApi,
            seq: &mut mockall::Sequence,
            block: BlockNumber,
            returned_result: Result<(reply::Block, StateUpdate), SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_state_update_with_block()
                .with(eq(block))
                .times(1)
                .in_sequence(seq)
                .return_once(move |_| returned_result);
        }

        /// Convenience wrapper
        fn expect_state_update_with_block_no_sequence(
            mock: &mut MockGatewayApi,
            block: BlockNumber,
            returned_result: Result<(reply::Block, StateUpdate), SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_state_update_with_block()
                .with(eq(block))
                .times(1)
                .return_once(move |_| returned_result);
        }

        fn expect_state_update_with_block_no_sequence_at_most_once(
            mock: &mut MockGatewayApi,
            block: BlockNumber,
            returned_result: Result<(reply::Block, StateUpdate), SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_state_update_with_block()
                .with(eq(block))
                .times(..=1)
                .return_once(move |_| returned_result);
        }

        /// Convenience wrapper
        fn expect_block_header(
            mock: &mut MockGatewayApi,
            seq: &mut mockall::Sequence,
            block: BlockId,
            returned_result: Result<(BlockNumber, BlockHash), SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_block_header()
                .with(eq(block))
                .times(1)
                .in_sequence(seq)
                .return_once(move |_| returned_result);
        }

        /// Convenience wrapper
        fn expect_signature(
            mock: &mut MockGatewayApi,
            seq: &mut mockall::Sequence,
            block: BlockId,
            returned_result: Result<reply::BlockSignature, SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_signature()
                .with(eq(block))
                .times(1)
                .in_sequence(seq)
                .return_once(|_| returned_result);
        }

        /// Convenience wrapper
        fn expect_signature_no_sequence(
            mock: &mut MockGatewayApi,
            block: BlockId,
            returned_result: Result<reply::BlockSignature, SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_signature()
                .with(eq(block))
                .times(1)
                .return_once(|_| returned_result);
        }

        fn expect_signature_no_sequence_at_most_once(
            mock: &mut MockGatewayApi,
            block: BlockId,
            returned_result: Result<reply::BlockSignature, SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_signature()
                .with(eq(block))
                .times(..=1)
                .return_once(|_| returned_result);
        }

        /// Convenience wrapper
        fn expect_class_by_hash(
            mock: &mut MockGatewayApi,
            seq: &mut mockall::Sequence,
            class_hash: ClassHash,
            returned_result: Result<bytes::Bytes, SequencerError>,
        ) {
            mock.expect_pending_class_by_hash()
                .withf(move |x| x == &class_hash)
                .times(1)
                .in_sequence(seq)
                .return_once(|_| returned_result);
        }

        /// Convenience wrapper
        fn expect_class_by_hash_no_sequence(
            mock: &mut MockGatewayApi,
            class_hash: ClassHash,
            returned_result: Result<bytes::Bytes, SequencerError>,
        ) {
            mock.expect_pending_class_by_hash()
                .withf(move |x| x == &class_hash)
                .times(1)
                .return_once(|_| returned_result);
        }

        fn expect_class_by_hash_no_sequence_at_most_once(
            mock: &mut MockGatewayApi,
            class_hash: ClassHash,
            returned_result: Result<bytes::Bytes, SequencerError>,
        ) {
            mock.expect_pending_class_by_hash()
                .withf(move |x| x == &class_hash)
                .times(..=1)
                .return_once(|_| returned_result);
        }

        /// Convenience wrapper
        fn block_not_found() -> SequencerError {
            SequencerError::StarknetError(StarknetError {
                code: KnownStarknetErrorCode::BlockNotFound.into(),
                message: String::new(),
            })
        }

        mod happy_path {
            use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};

            use super::*;

            #[tokio::test]
            async fn from_genesis() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                // Download the genesis block with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Download block #1 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Stay at head, no more blocks available
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((BLOCK1.block_number, BLOCK1.block_hash)),
                );

                // Let's run the UUT
                let _jh = spawn_sync_default(tx_event, mock);

                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass { hash, .. } => {
                        assert_eq!(hash, CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, signature, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq_sorted!(*state_update, *STATE_UPDATE0);
                    // assert_eq!(*signature, BLOCK0_COMMITMENT_SIGNATURE);
                    assert_eq!(*signature, BLOCK0_SIGNATURE.signature());
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass { hash, .. } => {
                    assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, signature, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq_sorted!(*state_update, *STATE_UPDATE1);
                    // assert_eq!(*signature, BLOCK1_COMMITMENT_SIGNATURE);
                    assert_eq!(*signature, BLOCK1_SIGNATURE.signature());
                });
            }

            #[tokio::test]
            async fn resumed_after_genesis() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                // Start with downloading block #1
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );

                // Stay at head, no more blocks available
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((BLOCK1.block_number, BLOCK1.block_hash)),
                );

                // Let's run the UUT
                let mock = std::sync::Arc::new(mock);
                let context = L2SyncContext {
                    sequencer: mock,
                    chain: Chain::SepoliaTestnet,
                    chain_id: ChainId::SEPOLIA_TESTNET,
                    block_validation_mode: MODE,
                    storage: StorageBuilder::in_memory_with_trie_pruning_and_pool_size(
                        pathfinder_storage::TriePruneMode::Archive,
                        NonZeroU32::new(5).unwrap(),
                    )
                    .unwrap(),
                    sequencer_public_key: PublicKey::ZERO,
                    fetch_concurrency: std::num::NonZeroUsize::new(1).unwrap(),
                    fetch_casm_from_fgw: false,
                };
                let latest_track = tokio::sync::watch::channel(Default::default());

                let _jh = tokio::spawn(sync(
                    tx_event,
                    context,
                    Some((BLOCK0_NUMBER, BLOCK0_HASH, GLOBAL_ROOT0)),
                    BlockChain::with_capacity(
                        100,
                        vec![(BLOCK0_NUMBER, BLOCK0_HASH, GLOBAL_ROOT0)],
                    ),
                    latest_track.1,
                ));

                assert_matches!(rx_event.recv().await.unwrap(),
                SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
            }
        }

        mod errors {
            use starknet_gateway_types::reply::Status;

            use super::*;

            #[tokio::test]
            async fn invalid_block_status() {
                let (tx_event, _rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                // Block with a non-accepted status
                let mut block = BLOCK0.clone();
                block.status = Status::Reverted;
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((block, STATE_UPDATE0.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );

                let jh = spawn_sync_default(tx_event, mock);
                let error = jh.await.unwrap().unwrap_err();
                assert_eq!(
                    &error.root_cause().to_string(),
                    "Rejecting block as its status is REVERTED, and only accepted blocks are \
                     allowed"
                );
            }
        }

        mod reorg {
            use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};

            use super::*;

            #[tokio::test]
            // This reorg occurs at the genesis block, which is swapped for a new one.
            //
            // [block 0]
            //
            // Becomes:
            //
            // [block 0 v2]
            //
            async fn at_genesis_which_is_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                // Fetch the genesis block with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );

                // Block #1 is not there
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occurred
                // We indicate that reorg started at genesis
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((BLOCK0_V2.block_number, BLOCK0_V2.block_hash)),
                );

                // Finally the L2 sync task is downloading the new genesis block
                // from the fork with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0_V2.clone(), STATE_UPDATE0_V2.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH_V2,
                    Ok(CONTRACT0_DEF_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE_V2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Err(block_not_found()),
                );

                // Indicate that we are still staying at the head - the latest block matches our
                // head
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((BLOCK0_V2.block_number, BLOCK0_V2.block_hash)),
                );

                // Let's run the UUT
                let _jh = spawn_sync_default(tx_event, mock);

                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq_sorted!(*state_update, *STATE_UPDATE0);
                });
                // Reorg started from the genesis block
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK0_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK0_V2);
                    assert_eq_sorted!(*state_update, *STATE_UPDATE0_V2);
                });
            }

            #[tokio::test]
            // This reorg occurs at the genesis block, which means that the fork replaces
            // the entire chain.
            //
            // [block 0]-------[block 1]-------[block 2]
            //
            // Becomes:
            //
            // [block 0 v2]----[block 1 v2]
            //
            async fn at_genesis_which_is_not_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                let block1_v2 = reply::Block {
                    block_hash: BLOCK1_HASH_V2,
                    block_number: BLOCK1_NUMBER,
                    l1_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"gas price 1 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"strk price 1 v2").unwrap(),
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"datgasprice 1 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"datstrkpric 1 v2").unwrap(),
                    },
                    parent_block_hash: BLOCK0_HASH_V2,
                    sequencer_address: Some(SequencerAddress(
                        Felt::from_be_slice(b"sequencer addr. 1 v2").unwrap(),
                    )),
                    state_commitment: GLOBAL_ROOT1_V2,
                    status: reply::Status::AcceptedOnL2,
                    timestamp: BlockTimestamp::new_or_panic(4),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                    l1_da_mode: Default::default(),
                    transaction_commitment: Default::default(),
                    event_commitment: Default::default(),
                    receipt_commitment: Default::default(),
                    state_diff_commitment: Default::default(),
                    state_diff_length: Default::default(),
                };

                // Fetch the genesis block with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((BLOCK2.clone(), STATE_UPDATE2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );
                // Block #3 is not there
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occurred
                // We indicate that reorg started at genesis by setting the latest on the new
                // genesis block
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((BLOCK0_V2.block_number, BLOCK0_V2.block_hash)),
                );

                // Then the L2 sync task goes back block by block to find the last block where
                // the block hash matches the DB
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((block1_v2.clone(), STATE_UPDATE1_V2.clone())),
                );
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0_V2.clone(), STATE_UPDATE0_V2.clone())),
                );

                // Once the L2 sync task has found where reorg occurred,
                // it can get back to downloading the new blocks
                // Fetch the new genesis block from the fork with respective state update and
                // contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0_V2.clone(), STATE_UPDATE0_V2.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH_V2,
                    Ok(CONTRACT0_DEF_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE_V2.clone()),
                );
                // Fetch the new block #1 from the fork with respective state update and
                // contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((block1_v2.clone(), STATE_UPDATE1_V2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE_V2.clone()),
                );

                // Indicate that we are still staying at the head
                // No new blocks found and the latest block matches our head
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((block1_v2.block_number, block1_v2.block_hash)),
                );

                // Run the UUT
                let _jh = spawn_sync_default(tx_event, mock);

                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert_eq!(*state_update, *STATE_UPDATE2);
                });
                // Reorg started at the genesis block
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK0_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK0_V2);
                    assert_eq!(*state_update, *STATE_UPDATE0_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, block1_v2);
                    assert!(state_update.contract_updates.is_empty());
                });
            }

            #[tokio::test]
            // This reorg occurs after the genesis block, the fork
            // replaces the entire chain except the genesis block.
            //
            // [block 0]----[block 1]-------[block 2]-------[block 3]
            //
            // Becomes:
            //
            // [block 0]----[block 1 v2]----[block 2 v2]
            //
            async fn after_genesis_and_not_at_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                let block1_v2 = reply::Block {
                    block_hash: BLOCK1_HASH_V2,
                    block_number: BLOCK1_NUMBER,
                    l1_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"gas price 1 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"strk price 1 v2").unwrap(),
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"datgasprice 1 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"datstrkpric 1 v2").unwrap(),
                    },
                    parent_block_hash: BLOCK0_HASH,
                    sequencer_address: Some(SequencerAddress(
                        Felt::from_be_slice(b"sequencer addr. 1 v2").unwrap(),
                    )),
                    state_commitment: GLOBAL_ROOT1_V2,
                    status: reply::Status::AcceptedOnL2,
                    timestamp: BlockTimestamp::new_or_panic(4),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                    l1_da_mode: Default::default(),
                    transaction_commitment: Default::default(),
                    event_commitment: Default::default(),
                    receipt_commitment: Default::default(),
                    state_diff_commitment: Default::default(),
                    state_diff_length: Default::default(),
                };
                let block2_v2 = reply::Block {
                    block_hash: BLOCK2_HASH_V2,
                    block_number: BLOCK2_NUMBER,
                    l1_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"gas price 2 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"strk price 2 v2").unwrap(),
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"datgasprice 2 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"datstrkpric 2 v2").unwrap(),
                    },
                    parent_block_hash: BLOCK1_HASH_V2,
                    sequencer_address: Some(SequencerAddress(
                        Felt::from_be_slice(b"sequencer addr. 2 v2").unwrap(),
                    )),
                    state_commitment: GLOBAL_ROOT2_V2,
                    status: reply::Status::AcceptedOnL2,
                    timestamp: BlockTimestamp::new_or_panic(5),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                    l1_da_mode: Default::default(),
                    transaction_commitment: Default::default(),
                    event_commitment: Default::default(),
                    receipt_commitment: Default::default(),
                    state_diff_commitment: Default::default(),
                    state_diff_length: Default::default(),
                };
                let block3 = reply::Block {
                    block_hash: BLOCK3_HASH,
                    block_number: BLOCK3_NUMBER,
                    l1_gas_price: GasPrices {
                        price_in_wei: GasPrice::from(3),
                        price_in_fri: GasPrice::from(3),
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: GasPrice::from(3),
                        price_in_fri: GasPrice::from(3),
                    },
                    parent_block_hash: BLOCK2_HASH,
                    sequencer_address: Some(SequencerAddress(
                        Felt::from_be_slice(b"sequencer address 3").unwrap(),
                    )),
                    state_commitment: GLOBAL_ROOT3,
                    status: reply::Status::AcceptedOnL1,
                    timestamp: BlockTimestamp::new_or_panic(3),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                    l1_da_mode: Default::default(),
                    transaction_commitment: Default::default(),
                    event_commitment: Default::default(),
                    receipt_commitment: Default::default(),
                    state_diff_commitment: Default::default(),
                    state_diff_length: Default::default(),
                };

                // Fetch the genesis block with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((BLOCK2.clone(), STATE_UPDATE2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );
                // Fetch block #3 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER,
                    Ok((block3.clone(), STATE_UPDATE3.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK3_NUMBER.into(),
                    Ok(BLOCK3_SIGNATURE.clone()),
                );
                // Block #4 is not there
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK4_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK4_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occurred
                // We indicate that reorg started at block #1
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((block1_v2.block_number, block1_v2.block_hash)),
                );

                // L2 sync task goes back block by block to find where the block hash matches
                // the DB
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((block2_v2.clone(), STATE_UPDATE2_V2.clone())),
                );
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((block1_v2.clone(), STATE_UPDATE1_V2.clone())),
                );
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to
                // start again Fetch the new block #1 from the fork with
                // respective state update
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((block1_v2.clone(), STATE_UPDATE1_V2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE_V2.clone()),
                );
                // Fetch the new block #2 from the fork with respective state update
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((block2_v2.clone(), STATE_UPDATE2_V2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2_SIGNATURE_V2.clone()),
                );
                // Indicate that we are still staying at the head - no new blocks and the latest
                // block matches our head
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((block2_v2.block_number, block2_v2.block_hash)),
                );

                // Run the UUT
                let _jh = spawn_sync_default(tx_event, mock);

                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert_eq!(*state_update, *STATE_UPDATE2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, block3);
                    assert_eq!(*state_update, *STATE_UPDATE3);
                });
                // Reorg started from block #1
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK1_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, block1_v2);
                    assert_eq!(*state_update, *STATE_UPDATE1_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, block2_v2);
                    assert_eq!(*state_update, *STATE_UPDATE2_V2);
                });
            }

            #[tokio::test]
            // This reorg occurs after the genesis block, the fork
            // replaces only the head block.
            //
            // [block 0]----[block 1]----[block 2]
            //
            // Becomes:
            //
            // [block 0]----[block 1]----[block 2 v2]
            //
            async fn after_genesis_and_at_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                let block2_v2 = reply::Block {
                    block_hash: BLOCK2_HASH_V2,
                    block_number: BLOCK2_NUMBER,
                    l1_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"gas price 2 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"strk price 2 v2").unwrap(),
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"datgasprice 2 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"datstrkpric 2 v2").unwrap(),
                    },
                    parent_block_hash: BLOCK1_HASH,
                    sequencer_address: Some(SequencerAddress(
                        Felt::from_be_slice(b"sequencer addr. 2 v2").unwrap(),
                    )),
                    state_commitment: GLOBAL_ROOT2_V2,
                    status: reply::Status::AcceptedOnL2,
                    timestamp: BlockTimestamp::new_or_panic(5),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                    l1_da_mode: Default::default(),
                    transaction_commitment: Default::default(),
                    event_commitment: Default::default(),
                    receipt_commitment: Default::default(),
                    state_diff_commitment: Default::default(),
                    state_diff_length: Default::default(),
                };

                // Fetch the genesis block with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((BLOCK2.clone(), STATE_UPDATE2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );
                // Block #3 is not there
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occurred
                // We indicate that reorg started at block #2
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((block2_v2.block_number, block2_v2.block_hash)),
                );

                // L2 sync task goes back block by block to find where the block hash matches
                // the DB
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to
                // start again Fetch the new block #2 from the fork with
                // respective state update
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((block2_v2.clone(), STATE_UPDATE2_V2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2_SIGNATURE_V2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks and the latest
                // block matches our head
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((block2_v2.block_number, block2_v2.block_hash)),
                );

                // Run the UUT
                let _jh = spawn_sync_default(tx_event, mock);

                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert_eq!(*state_update, *STATE_UPDATE2);
                });
                // Reorg started from block #2
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK2_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, block2_v2);
                    assert_eq!(*state_update, *STATE_UPDATE2_V2);
                });
            }

            #[tokio::test]
            // This reorg occurs because the downloaded block at head turns out to indicate
            // a different parent hash than the previous downloaded block.
            //
            // [block 0]-----[block 1]       --[block 2]
            //            \                 /
            //             --[block 1 v2]--
            //
            async fn parent_hash_mismatch() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                let block1_v2 = reply::Block {
                    block_hash: BLOCK1_HASH_V2,
                    block_number: BLOCK1_NUMBER,
                    l1_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"gas price 1 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"strk price 1 v2").unwrap(),
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"datgasprice 1 v2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"datstrkpric 1 v2").unwrap(),
                    },
                    parent_block_hash: BLOCK0_HASH,
                    sequencer_address: Some(SequencerAddress(
                        Felt::from_be_slice(b"sequencer addr. 1 v2").unwrap(),
                    )),
                    state_commitment: GLOBAL_ROOT1_V2,
                    status: reply::Status::AcceptedOnL2,
                    timestamp: BlockTimestamp::new_or_panic(4),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                    l1_da_mode: Default::default(),
                    transaction_commitment: Default::default(),
                    event_commitment: Default::default(),
                    receipt_commitment: Default::default(),
                    state_diff_commitment: Default::default(),
                    state_diff_length: Default::default(),
                };
                let block2 = reply::Block {
                    block_hash: BLOCK2_HASH,
                    block_number: BLOCK2_NUMBER,
                    l1_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"gas price 2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"strk price 2").unwrap(),
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: GasPrice::from_be_slice(b"datgasprice 2").unwrap(),
                        price_in_fri: GasPrice::from_be_slice(b"datstrkpric 2").unwrap(),
                    },
                    parent_block_hash: BLOCK1_HASH_V2,
                    sequencer_address: Some(SequencerAddress(
                        Felt::from_be_slice(b"sequencer address 2").unwrap(),
                    )),
                    state_commitment: GLOBAL_ROOT2,
                    status: reply::Status::AcceptedOnL1,
                    timestamp: BlockTimestamp::new_or_panic(5),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                    l1_da_mode: Default::default(),
                    transaction_commitment: Default::default(),
                    event_commitment: Default::default(),
                    receipt_commitment: Default::default(),
                    state_diff_commitment: Default::default(),
                    state_diff_length: Default::default(),
                };

                // Fetch the genesis block with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );

                // Fetch block #1 with respective state update and contracts
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 whose parent hash does not match block #1 hash
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((block2.clone(), STATE_UPDATE2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );

                // L2 sync task goes back block by block to find where the block hash matches
                // the DB It starts at the previous block to which the mismatch
                // happened
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to
                // start again Fetch the new block #1 from the fork with
                // respective state update
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER,
                    Ok((block1_v2.clone(), STATE_UPDATE1_V2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE_V2.clone()),
                );
                // Fetch the block #2 again, now with respective state update
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER,
                    Ok((block2.clone(), STATE_UPDATE2.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks and the latest
                // block matches our head
                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER,
                    Err(block_not_found()),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((block2.block_number, block2.block_hash)),
                );

                // Run the UUT
                let _jh = spawn_sync_default(tx_event, mock);

                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                // Reorg started from block #1
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK1_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, block1_v2);
                    assert_eq!(*state_update, *STATE_UPDATE1_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _, _) => {
                    assert_eq!(*block, block2);
                    assert_eq!(*state_update, *STATE_UPDATE2);
                });
            }

            #[tokio::test]
            async fn shutdown() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                // Closing the event's channel should trigger the sync to exit with error after
                // the first send.
                rx_event.close();

                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();
                let mut signature_seq = mockall::Sequence::new();

                expect_state_update_with_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_signature(
                    &mut mock,
                    &mut signature_seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );

                // Run the UUT
                let jh = spawn_sync_default(tx_event, mock);

                // Wrap this in a timeout so we don't wait forever in case of test failure.
                // Right now closing the channel causes an error.
                tokio::time::timeout(std::time::Duration::from_secs(2), jh)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
            }
        }

        mod bulk {
            use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};

            use super::*;

            #[tokio::test]
            async fn happy_path() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();

                // Download the genesis block with respective state update and contracts
                expect_state_update_with_block_no_sequence(
                    &mut mock,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash_no_sequence(
                    &mut mock,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature_no_sequence(
                    &mut mock,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Download block #1 with respective state update and contracts
                expect_state_update_with_block_no_sequence(
                    &mut mock,
                    BLOCK1_NUMBER,
                    Ok((BLOCK1.clone(), STATE_UPDATE1.clone())),
                );
                expect_class_by_hash_no_sequence(
                    &mut mock,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature_no_sequence(
                    &mut mock,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );

                // Let's run the UUT
                let jh = spawn_bulk_sync(tx_event, mock);

                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass { hash, .. } => {
                        assert_eq!(hash, CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, signature, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq_sorted!(*state_update, *STATE_UPDATE0);
                    assert_eq!(*signature, BLOCK0_SIGNATURE.signature());
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass { hash, .. } => {
                    assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, signature, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq_sorted!(*state_update, *STATE_UPDATE1);
                    assert_eq!(*signature, BLOCK1_SIGNATURE.signature());
                });

                let result = jh.await.unwrap();
                assert_matches!(result, Ok(Some((BLOCK1_NUMBER, BLOCK1_HASH, _))));
            }

            #[tokio::test]
            async fn no_such_block() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();

                // Downloading the genesis block data is racing against the failure of block 1,
                // hence "at most once"
                expect_state_update_with_block_no_sequence_at_most_once(
                    &mut mock,
                    BLOCK0_NUMBER,
                    Ok((BLOCK0.clone(), STATE_UPDATE0.clone())),
                );
                expect_class_by_hash_no_sequence_at_most_once(
                    &mut mock,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature_no_sequence_at_most_once(
                    &mut mock,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Downloading block 1 fails with block not found
                expect_state_update_with_block_no_sequence(
                    &mut mock,
                    BLOCK1_NUMBER,
                    Err(block_not_found()),
                );

                // Let's run the UUT
                let jh = spawn_bulk_sync(tx_event, mock);

                // The entire unemitted, yet cached batch is rejected
                assert!(rx_event.recv().await.is_none());

                // Bulk sync should _not_ fail if the block is not found
                let result = jh.await.unwrap();
                assert_matches!(result, Ok(None));
            }
        }
    }

    mod block_chain {
        use pathfinder_common::macro_prelude::*;
        use pathfinder_common::BlockNumber;

        use crate::state::l2::BlockChain;

        #[test]
        fn circular_buffer_integrity() {
            let mut uut = BlockChain::with_capacity(
                3,
                vec![
                    (
                        BlockNumber::new_or_panic(1),
                        block_hash!("0x11"),
                        state_commitment!("0x21"),
                    ),
                    (
                        BlockNumber::new_or_panic(2),
                        block_hash!("0x13"),
                        state_commitment!("0x41"),
                    ),
                    (
                        BlockNumber::new_or_panic(3),
                        block_hash!("0x15"),
                        state_commitment!("0x61"),
                    ),
                ],
            );

            assert!(uut.get(&BlockNumber::new_or_panic(1)).is_some());
            assert!(uut.get(&BlockNumber::new_or_panic(2)).is_some());
            assert!(uut.get(&BlockNumber::new_or_panic(3)).is_some());
            uut.push(
                BlockNumber::new_or_panic(4),
                block_hash!("0x17"),
                state_commitment!("0x81"),
            );

            assert!(uut.get(&BlockNumber::new_or_panic(1)).is_none());
            assert!(uut.get(&BlockNumber::new_or_panic(2)).is_some());
            assert!(uut.get(&BlockNumber::new_or_panic(3)).is_some());
            assert!(uut.get(&BlockNumber::new_or_panic(4)).is_some());
        }

        #[test]
        fn reset() {
            let mut uut = BlockChain::with_capacity(
                3,
                vec![
                    (
                        BlockNumber::new_or_panic(1),
                        block_hash!("0x11"),
                        state_commitment!("0x21"),
                    ),
                    (
                        BlockNumber::new_or_panic(2),
                        block_hash!("0x13"),
                        state_commitment!("0x41"),
                    ),
                    (
                        BlockNumber::new_or_panic(3),
                        block_hash!("0x15"),
                        state_commitment!("0x61"),
                    ),
                ],
            );

            assert!(uut.get(&BlockNumber::new_or_panic(1)).is_some());
            assert!(uut.get(&BlockNumber::new_or_panic(2)).is_some());
            assert!(uut.get(&BlockNumber::new_or_panic(3)).is_some());

            uut.reset_to_genesis();

            assert!(uut.get(&BlockNumber::new_or_panic(1)).is_none());
            assert!(uut.get(&BlockNumber::new_or_panic(2)).is_none());
            assert!(uut.get(&BlockNumber::new_or_panic(3)).is_none());
        }
    }
}
