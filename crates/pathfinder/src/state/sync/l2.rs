use crate::state::block_hash::{verify_block_hash, VerifyResult};
use crate::state::sync::class::{download_class, DownloadedClass};
use crate::state::sync::{pending, SyncEvent};
use anyhow::{anyhow, Context};
use pathfinder_common::state_update::ContractClassUpdate;
use pathfinder_common::{
    BlockHash, BlockNumber, Chain, ChainId, ClassHash, EventCommitment, StarknetVersion,
    StateCommitment, StateUpdate, TransactionCommitment,
};
use pathfinder_rpc::{BlockHeader, TopicBroadcasters};
use pathfinder_storage::Storage;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::{
    error::SequencerError,
    reply::{Block, Status},
    transaction_hash::verify,
};
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Default, Debug, Clone, Copy)]
pub struct Timings {
    pub block_download: Duration,
    pub state_diff_download: Duration,
    pub class_declaration: Duration,
    pub signature_download: Duration,
}

/// A cache containing the last `N` blocks in the chain. Used to determine reorg extents
/// and ensure the integrity of new blocks.
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
    pub broadcasters: Option<TopicBroadcasters>,
    pub sequencer: GatewayClient,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub head_poll_interval: Duration,
    pub pending_poll_interval: Option<Duration>,
    pub block_validation_mode: BlockValidationMode,
    pub storage: Storage,
}

pub async fn sync<GatewayClient>(
    tx_event: mpsc::Sender<SyncEvent>,
    context: L2SyncContext<GatewayClient>,
    mut head: Option<(BlockNumber, BlockHash, StateCommitment)>,
    mut blocks: BlockChain,
) -> anyhow::Result<()>
where
    GatewayClient: GatewayApi + Clone + Send + 'static,
{
    let L2SyncContext {
        broadcasters,
        sequencer,
        chain,
        chain_id,
        head_poll_interval,
        pending_poll_interval,
        block_validation_mode,
        storage,
    } = context;

    'outer: loop {
        // Get the next block from L2.
        let (next, head_meta) = match &head {
            Some(head) => (head.0 + 1, Some(head)),
            None => (BlockNumber::GENESIS, None),
        };

        let t_block = std::time::Instant::now();
        // Next block and state update which we can get for free when exiting poll pending mode
        let mut next_block = None;
        let mut next_state_update = None;

        let (block, commitments) = loop {
            match download_block(
                next,
                // Reuse the next full block if we got it for free when polling pending
                std::mem::take(&mut next_block),
                chain,
                chain_id,
                head_meta.map(|h| h.1),
                &sequencer,
                block_validation_mode,
            )
            .await?
            {
                DownloadBlock::Block(block, commitments) => break (block, commitments),
                DownloadBlock::AtHead => {
                    // Poll pending if it is enabled, otherwise just wait to poll head again.
                    match pending_poll_interval {
                        Some(interval) => {
                            tracing::trace!("Entering pending mode");
                            let head = head_meta
                                .expect("Head hash should exist when entering pending mode");
                            (next_block, next_state_update) = pending::poll_pending(
                                tx_event.clone(),
                                &sequencer,
                                (head.1, head.2),
                                interval,
                                storage.clone(),
                            )
                            .await
                            .context("Polling pending block")?;
                        }
                        None => {
                            tracing::info!(poll_interval=?head_poll_interval, "At head of chain");
                            tokio::time::sleep(head_poll_interval).await;
                        }
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

        // Unwrap in both block and state update is safe as the block hash always exists (unless we query for pending).
        let block_hash = block.block_hash;
        let t_update = std::time::Instant::now();

        let state_update = match next_state_update {
            // Reuse the next full state update if we got it for free when polling pending
            Some(state_update) if state_update.block_hash == block_hash => state_update,
            // We were unlucky or poll pending is disabled
            Some(_) | None => sequencer
                .state_update(block_hash.into())
                .await
                .with_context(|| format!("Fetch state diff for block {next:?} from sequencer"))?,
        };

        anyhow::ensure!(
            state_update.block_hash != BlockHash::ZERO,
            "Gateway returned `pending` state update"
        );

        // An extra sanity check for the state update API.
        anyhow::ensure!(
            block_hash == state_update.block_hash,
            "State update block hash mismatch, actual {:x}, expected {:x}",
            block_hash.0,
            state_update.block_hash.0
        );
        let t_update = t_update.elapsed();

        // Download and emit newly declared classes.
        let t_declare = std::time::Instant::now();
        download_new_classes(
            &state_update,
            &sequencer,
            &tx_event,
            &block.starknet_version,
            storage.clone(),
        )
        .await
        .with_context(|| format!("Handling newly declared classes for block {next:?}"))?;
        let t_declare = t_declare.elapsed();

        let t_signature = std::time::Instant::now();
        let signature = sequencer
            .signature(block_hash.into())
            .await
            .with_context(|| format!("Fetch signature for block {next:?} from sequencer"))?;
        let t_signature = t_signature.elapsed();

        // An extra sanity check for the signature API.
        anyhow::ensure!(
            block_hash == signature.signature_input.block_hash,
            "Signature block hash mismatch, actual {:x}, expected {:x}",
            signature.signature_input.block_hash.0,
            block_hash.0,
        );
        let signature = signature.into();

        head = Some((next, block_hash, state_update.state_commitment));
        blocks.push(next, block_hash, state_update.state_commitment);

        let timings = Timings {
            block_download: t_block,
            state_diff_download: t_update,
            class_declaration: t_declare,
            signature_download: t_signature,
        };

        let block_header = BlockHeader::from(block.as_ref());

        tx_event
            .send(SyncEvent::Block(
                (block, commitments),
                Box::new(state_update),
                Box::new(signature),
                timings,
            ))
            .await
            .context("Event channel closed")?;

        if let Some(topics) = &broadcasters {
            topics
                .new_head
                .send_if_receiving(block_header)
                .context("Broadcasting failed")?;
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
/// that were _failing_ but the sequencer has still added the class to its list of
/// known classes...
pub async fn download_new_classes(
    state_update: &StateUpdate,
    sequencer: &impl GatewayApi,
    tx_event: &mpsc::Sender<SyncEvent>,
    version: &StarknetVersion,
    storage: Storage,
) -> Result<(), anyhow::Error> {
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
        // Get unique class hashes only. Its unlikely they would have dupes here, but rather safe than sorry.
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if new_classes.is_empty() {
        return Ok(());
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

    for class_hash in require_downloading {
        let class = download_class(sequencer, class_hash, version.clone())
            .await
            .with_context(|| format!("Downloading class {}", class_hash.0))?;

        match class {
            DownloadedClass::Cairo { definition, hash } => tx_event
                .send(SyncEvent::CairoClass { definition, hash })
                .await
                .with_context(|| {
                    format!(
                        "Sending Event::NewCairoContract for declared class {}",
                        class_hash.0
                    )
                })?,
            DownloadedClass::Sierra {
                sierra_definition,
                sierra_hash,
                casm_definition,
            } => {
                // NOTE: we _have_ to use the same compiled_class_class hash as returned by the feeder gateway,
                // since that's what has been added to the class commitment tree.
                let Some(casm_hash) = state_update
                    .declared_sierra_classes
                    .iter()
                    .find_map(|(sierra, casm)| (sierra.0 == class_hash.0).then_some(*casm))
                else {
                    // This can occur if the sierra was in here as a deploy contract, if the class was
                    // declared in a previous block but not yet persisted by the database.
                    continue;
                };
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
                            class_hash.0
                        )
                    })?
            }
        }
    }

    Ok(())
}

enum DownloadBlock {
    Block(Box<Block>, (TransactionCommitment, EventCommitment)),
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
    // Poll pending could exit when it encountered a finalized block, so we'd like to reuse it
    next_block: Option<Block>,
    chain: Chain,
    chain_id: ChainId,
    prev_block_hash: Option<BlockHash>,
    sequencer: &impl GatewayApi,
    mode: BlockValidationMode,
) -> anyhow::Result<DownloadBlock> {
    use starknet_gateway_types::{
        error::KnownStarknetErrorCode::BlockNotFound, reply::MaybePendingBlock,
    };

    let result = match next_block {
        // Reuse a finalized block downloaded before pending mode exited
        Some(block) if block.block_number == block_number => Ok(MaybePendingBlock::Block(block)),
        // Bad luck or poll pending is disabled
        Some(_) | None => sequencer.block(block_number.into()).await,
    };

    let result = match result {
        Ok(MaybePendingBlock::Block(block)) => {
            let block = Box::new(block);
            // Check if block hash is correct.
            let verify_hash = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let block_number = block.block_number;
                // In p2p the state commitment which is required to calculate the block hash can be missing, and in such case it is marked as 0s.
                #[cfg(feature = "p2p")]
                if block.state_commitment == StateCommitment::ZERO {
                    return Ok((block, VerifyResult::NotVerifiable));
                }

                let verify_result = verify_block_hash(&block, chain, chain_id, block.block_hash)
                    .with_context(move || format!("Verify block {block_number}"))?;
                Ok((block, verify_result))
            });
            let (block, verify_result) = verify_hash.await.context("Verify block hash")??;
            match (block.status, verify_result, mode) {
                (
                    Status::AcceptedOnL1 | Status::AcceptedOnL2,
                    VerifyResult::Match(commitments),
                    _,
                ) => Ok(DownloadBlock::Block(block, commitments)),
                (Status::AcceptedOnL1 | Status::AcceptedOnL2, VerifyResult::NotVerifiable, _) => {
                    Ok(DownloadBlock::Block(block, Default::default()))
                }
                (
                    Status::AcceptedOnL1 | Status::AcceptedOnL2,
                    VerifyResult::Mismatch,
                    BlockValidationMode::AllowMismatch,
                ) => Ok(DownloadBlock::Block(block, Default::default())),
                (_, VerifyResult::Mismatch, BlockValidationMode::Strict) => {
                    Err(anyhow!("Block hash mismatch"))
                }
                _ => Err(anyhow!(
                    "Rejecting block as its status is {}, and only accepted blocks are allowed",
                    block.status
                )),
            }
        }
        Ok(MaybePendingBlock::Pending(_)) => anyhow::bail!("Sequencer returned `pending` block"),
        Err(SequencerError::StarknetError(err)) if err.code == BlockNotFound.into() => {
            // This would occur if we queried past the head of the chain. We now need to check that
            // a reorg hasn't put us too far in the future. This does run into race conditions with
            // the sequencer but this is the best we can do I think.
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
                    // Our head is not valid anymore so there must have been a reorg only at this height
                    Some(_) => Ok(DownloadBlock::Reorg),
                    // There is something wrong with the sequencer, as we are attempting to get the genesis block
                    // Let's retry in a while
                    None => Ok(DownloadBlock::AtHead),
                }
            } else {
                // The new head is at lower height than our head which means there must have been a reorg
                Ok(DownloadBlock::Reorg)
            }
        }
        Err(other) => Err(other).context("Download block from sequencer"),
    };

    match result {
        Ok(DownloadBlock::Block(block, commitments)) => {
            use rayon::prelude::*;

            let (send, recv) = tokio::sync::oneshot::channel();

            rayon::scope(|s| {
                s.spawn(|_| {
                    let result = block.transactions.par_iter().enumerate().try_for_each(|(i, txn)| {
                        match verify(txn, chain_id, block_number) {
                            starknet_gateway_types::transaction_hash::VerifyResult::Match => {}
                            starknet_gateway_types::transaction_hash::VerifyResult::Mismatch(actual) =>
                                anyhow::bail!("Transaction hash mismatch: block {block_number} idx {i} expected {} calculated {}",
                                    txn.hash(),
                                    actual),
                            starknet_gateway_types::transaction_hash::VerifyResult::NotVerifiable => {
                                tracing::trace!(
                                    "Skipping transaction verification: block {block_number} idx {i} hash {}",
                                    txn.hash()
                                )
                            }
                        };
                        Ok(())
                    });

                    let _ = send.send(result);
                })
            });

            recv.await.expect("Panic on rayon thread")?;

            Ok(DownloadBlock::Block(block, commitments))
        }
        Ok(DownloadBlock::AtHead | DownloadBlock::Reorg) | Err(_) => result,
    }
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
            None,
            chain,
            chain_id,
            Some(previous.0),
            sequencer,
            mode,
        )
        .await
        .with_context(|| format!("Download block {previous_block_number} from sequencer"))?
        {
            DownloadBlock::Block(block, _) if block.block_hash == previous.0 => {
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
        use crate::state::l2::{BlockChain, L2SyncContext};
        use pathfinder_common::macro_prelude::*;
        use pathfinder_common::BlockCommitmentSignature;
        use pathfinder_common::StateUpdate;

        use super::super::{sync, BlockValidationMode, SyncEvent};
        use assert_matches::assert_matches;
        use pathfinder_common::{
            BlockHash, BlockId, BlockNumber, BlockTimestamp, Chain, ChainId, ClassHash,
            ContractAddress, GasPrice, SequencerAddress, StarknetVersion, StateCommitment,
            StorageAddress, StorageValue,
        };
        use pathfinder_crypto::Felt;
        use pathfinder_rpc::TopicBroadcasters;
        use pathfinder_storage::Storage;
        use starknet_gateway_client::MockGatewayApi;
        use starknet_gateway_types::{
            error::{KnownStarknetErrorCode, SequencerError, StarknetError},
            reply,
        };
        use std::time::Duration;
        use tokio::{sync::mpsc, task::JoinHandle};

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
            block_number: BLOCK0_NUMBER,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 0 signature r"),
                block_commitment_signature_elem_bytes!(b"block 0 signature s"),
            ],
            signature_input: reply::BlockSignatureInput {
                block_hash: BLOCK0_HASH,
                state_diff_commitment: state_diff_commitment_bytes!(
                    b"block 0 state diff commitment"
                ),
            },
        };
        const BLOCK0_COMMITMENT_SIGNATURE: BlockCommitmentSignature = BlockCommitmentSignature {
            r: BLOCK0_SIGNATURE.signature[0],
            s: BLOCK0_SIGNATURE.signature[1],
        };
        const BLOCK0_SIGNATURE_V2: reply::BlockSignature = reply::BlockSignature {
            block_number: BLOCK0_NUMBER,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 0 signature r 2"),
                block_commitment_signature_elem_bytes!(b"block 0 signature s 2"),
            ],
            signature_input: reply::BlockSignatureInput {
                block_hash: BLOCK0_HASH_V2,
                state_diff_commitment: state_diff_commitment_bytes!(
                    b"block 0 state diff commitment 2"
                ),
            },
        };

        const BLOCK1_SIGNATURE: reply::BlockSignature = reply::BlockSignature {
            block_number: BLOCK1_NUMBER,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 1 signature r"),
                block_commitment_signature_elem_bytes!(b"block 1 signature s"),
            ],
            signature_input: reply::BlockSignatureInput {
                block_hash: BLOCK1_HASH,
                state_diff_commitment: state_diff_commitment_bytes!(
                    b"block 1 state diff commitment"
                ),
            },
        };
        const BLOCK1_COMMITMENT_SIGNATURE: BlockCommitmentSignature = BlockCommitmentSignature {
            r: BLOCK1_SIGNATURE.signature[0],
            s: BLOCK1_SIGNATURE.signature[1],
        };
        const BLOCK1_SIGNATURE_V2: reply::BlockSignature = reply::BlockSignature {
            block_number: BLOCK1_NUMBER,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 1 signature r 2"),
                block_commitment_signature_elem_bytes!(b"block 1 signature s 2"),
            ],
            signature_input: reply::BlockSignatureInput {
                block_hash: BLOCK1_HASH_V2,
                state_diff_commitment: state_diff_commitment_bytes!(
                    b"block 1 state diff commitment 2"
                ),
            },
        };
        const BLOCK2_SIGNATURE: reply::BlockSignature = reply::BlockSignature {
            block_number: BLOCK2_NUMBER,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 2 signature r"),
                block_commitment_signature_elem_bytes!(b"block 2 signature s"),
            ],
            signature_input: reply::BlockSignatureInput {
                block_hash: BLOCK2_HASH,
                state_diff_commitment: state_diff_commitment_bytes!(
                    b"block 2 state diff commitment"
                ),
            },
        };
        const BLOCK2_SIGNATURE_V2: reply::BlockSignature = reply::BlockSignature {
            block_number: BLOCK2_NUMBER,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 2 signature r 2"),
                block_commitment_signature_elem_bytes!(b"block 2 signature s 2"),
            ],
            signature_input: reply::BlockSignatureInput {
                block_hash: BLOCK2_HASH_V2,
                state_diff_commitment: state_diff_commitment_bytes!(
                    b"block 2 state diff commitment 2"
                ),
            },
        };
        const BLOCK3_SIGNATURE: reply::BlockSignature = reply::BlockSignature {
            block_number: BLOCK3_NUMBER,
            signature: [
                block_commitment_signature_elem_bytes!(b"block 3 signature r"),
                block_commitment_signature_elem_bytes!(b"block 3 signature s"),
            ],
            signature_input: reply::BlockSignatureInput {
                block_hash: BLOCK3_HASH,
                state_diff_commitment: state_diff_commitment_bytes!(
                    b"block 3 state diff commitment"
                ),
            },
        };

        fn spawn_sync_default(
            tx_event: mpsc::Sender<SyncEvent>,
            sequencer: MockGatewayApi,
        ) -> JoinHandle<anyhow::Result<()>> {
            let storage = Storage::in_memory().unwrap();
            let sequencer = std::sync::Arc::new(sequencer);
            let context = L2SyncContext {
                broadcasters: Some(TopicBroadcasters::default()),
                sequencer,
                chain: Chain::Testnet,
                chain_id: ChainId::TESTNET,
                head_poll_interval: Duration::ZERO,
                pending_poll_interval: None,
                block_validation_mode: MODE,
                storage,
            };

            tokio::spawn(sync(
                tx_event,
                context,
                None,
                BlockChain::with_capacity(100, vec![]),
            ))
        }

        lazy_static::lazy_static! {
            static ref CONTRACT0_DEF: bytes::Bytes = bytes::Bytes::from(format!("{DEF0}0{DEF1}"));
            static ref CONTRACT0_DEF_V2: bytes::Bytes = bytes::Bytes::from(format!("{DEF0}0 v2{DEF1}"));
            static ref CONTRACT1_DEF: bytes::Bytes = bytes::Bytes::from(format!("{DEF0}1{DEF1}"));

            static ref BLOCK0: reply::Block = reply::Block {
                block_hash: BLOCK0_HASH,
                block_number: BLOCK0_NUMBER,
                gas_price: Some(GasPrice::ZERO),
                parent_block_hash: BlockHash(Felt::ZERO),
                sequencer_address: Some(SequencerAddress(Felt::ZERO)),
                state_commitment: GLOBAL_ROOT0,
                status: reply::Status::AcceptedOnL1,
                timestamp: BlockTimestamp::new_or_panic(0),
                transaction_receipts: vec![],
                transactions: vec![],
                starknet_version: StarknetVersion::default(),
            };
            static ref BLOCK0_V2: reply::Block = reply::Block {
                block_hash: BLOCK0_HASH_V2,
                block_number: BLOCK0_NUMBER,
                gas_price: Some(GasPrice::from_be_slice(b"gas price 0 v2").unwrap()),
                parent_block_hash: BlockHash(Felt::ZERO),
                sequencer_address: Some(SequencerAddress(Felt::from_be_slice(b"sequencer addr. 0 v2").unwrap())),
                state_commitment: GLOBAL_ROOT0_V2,
                status: reply::Status::AcceptedOnL2,
                timestamp: BlockTimestamp::new_or_panic(10),
                transaction_receipts: vec![],
                transactions: vec![],
                starknet_version: StarknetVersion::new(0, 9, 1),
            };
            static ref BLOCK1: reply::Block = reply::Block {
                block_hash: BLOCK1_HASH,
                block_number: BLOCK1_NUMBER,
                gas_price: Some(GasPrice::from(1)),
                parent_block_hash: BLOCK0_HASH,
                sequencer_address: Some(SequencerAddress(Felt::from_be_slice(b"sequencer address 1").unwrap())),
                state_commitment: GLOBAL_ROOT1,
                status: reply::Status::AcceptedOnL1,
                timestamp: BlockTimestamp::new_or_panic(1),
                transaction_receipts: vec![],
                transactions: vec![],
                starknet_version: StarknetVersion::new(0, 9, 1),
            };
            static ref BLOCK2: reply::Block = reply::Block {
                block_hash: BLOCK2_HASH,
                block_number: BLOCK2_NUMBER,
                gas_price: Some(GasPrice::from(2)),
                parent_block_hash: BLOCK1_HASH,
                sequencer_address: Some(SequencerAddress(Felt::from_be_slice(b"sequencer address 2").unwrap())),
                state_commitment: GLOBAL_ROOT2,
                status: reply::Status::AcceptedOnL1,
                timestamp: BlockTimestamp::new_or_panic(2),
                transaction_receipts: vec![],
                transactions: vec![],
                starknet_version: StarknetVersion::new(0, 9, 2),
            };

            static ref STATE_UPDATE0: StateUpdate = {
                StateUpdate::default()
                    .with_block_hash(BLOCK0_HASH)
                    .with_state_commitment(GLOBAL_ROOT0)
                    .with_deployed_contract(CONTRACT0_ADDR, CONTRACT0_HASH)
                    .with_storage_update(CONTRACT0_ADDR, STORAGE_KEY0, STORAGE_VAL0)
            };
            static ref STATE_UPDATE0_V2: StateUpdate = {
                StateUpdate::default()
                    .with_block_hash(BLOCK0_HASH_V2)
                    .with_state_commitment(GLOBAL_ROOT0_V2)
                    .with_deployed_contract(CONTRACT0_ADDR_V2, CONTRACT0_HASH_V2)
            };

            static ref STATE_UPDATE1: StateUpdate = {
                StateUpdate::default()
                    .with_block_hash(BLOCK1_HASH)
                    .with_state_commitment(GLOBAL_ROOT1)
                    .with_parent_state_commitment(GLOBAL_ROOT0)
                    .with_deployed_contract(CONTRACT1_ADDR, CONTRACT1_HASH)
                    .with_storage_update(CONTRACT0_ADDR, STORAGE_KEY0, STORAGE_VAL0_V2)
                    .with_storage_update(CONTRACT1_ADDR, STORAGE_KEY1, STORAGE_VAL1)
            };

            static ref STATE_UPDATE1_V2: StateUpdate = {
                StateUpdate::default()
                    .with_block_hash(BLOCK1_HASH_V2)
                    .with_state_commitment(GLOBAL_ROOT1_V2)
                    .with_parent_state_commitment(GLOBAL_ROOT0_V2)
            };
            static ref STATE_UPDATE2: StateUpdate = {
                StateUpdate::default()
                    .with_block_hash(BLOCK2_HASH)
                    .with_state_commitment(GLOBAL_ROOT2)
                    .with_parent_state_commitment(GLOBAL_ROOT1)
            };
            static ref STATE_UPDATE2_V2: StateUpdate = {
                StateUpdate::default()
                    .with_block_hash(BLOCK2_HASH_V2)
                    .with_state_commitment(GLOBAL_ROOT2_V2)
                    .with_parent_state_commitment(GLOBAL_ROOT1_V2)
            };
            static ref STATE_UPDATE3: StateUpdate = {
                StateUpdate::default()
                    .with_block_hash(BLOCK3_HASH)
                    .with_state_commitment(GLOBAL_ROOT3)
                    .with_parent_state_commitment(GLOBAL_ROOT2)
            };
        }

        /// Convenience wrapper
        fn expect_block(
            mock: &mut MockGatewayApi,
            seq: &mut mockall::Sequence,
            block: BlockId,
            returned_result: Result<reply::MaybePendingBlock, SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_block()
                .with(eq(block))
                .times(1)
                .in_sequence(seq)
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
        fn expect_state_update(
            mock: &mut MockGatewayApi,
            seq: &mut mockall::Sequence,
            block: BlockId,
            returned_result: Result<StateUpdate, SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_state_update()
                .with(eq(block))
                .times(1)
                .in_sequence(seq)
                .return_once(|_| returned_result);
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
        fn block_not_found() -> SequencerError {
            SequencerError::StarknetError(StarknetError {
                code: KnownStarknetErrorCode::BlockNotFound.into(),
                message: String::new(),
            })
        }

        mod happy_path {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn from_genesis() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();

                // Download the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Download block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Stay at head, no more blocks available
                expect_block(
                    &mut mock,
                    &mut seq,
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
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, signature, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                    assert_eq!(*signature, BLOCK0_COMMITMENT_SIGNATURE);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass { hash, .. } => {
                    assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, signature, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                    assert_eq!(*signature, BLOCK1_COMMITMENT_SIGNATURE);
                });
            }

            #[tokio::test]
            async fn resumed_after_genesis() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();

                // Start with downloading block #1
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );

                // Stay at head, no more blocks available
                expect_block(
                    &mut mock,
                    &mut seq,
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
                    broadcasters: Some(TopicBroadcasters::default()),
                    sequencer: mock,
                    chain: Chain::Testnet,
                    chain_id: ChainId::TESTNET,
                    head_poll_interval: Duration::ZERO,
                    pending_poll_interval: None,
                    block_validation_mode: MODE,
                    storage: Storage::in_memory().unwrap(),
                };

                let _jh = tokio::spawn(sync(
                    tx_event,
                    context,
                    Some((BLOCK0_NUMBER, BLOCK0_HASH, GLOBAL_ROOT0)),
                    BlockChain::with_capacity(
                        100,
                        vec![(BLOCK0_NUMBER, BLOCK0_HASH, GLOBAL_ROOT0)],
                    ),
                ));

                assert_matches!(rx_event.recv().await.unwrap(),
                SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
            }
        }

        mod errors {
            use super::*;
            use starknet_gateway_types::reply::Status;

            #[tokio::test]
            async fn invalid_block_status() {
                let (tx_event, _rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();

                // Block with a non-accepted status
                let mut block = BLOCK0.clone();
                block.status = Status::Reverted;
                expect_block(&mut mock, &mut seq, BLOCK0_NUMBER.into(), Ok(block.into()));

                let jh = spawn_sync_default(tx_event, mock);
                let error = jh.await.unwrap().unwrap_err();
                assert_eq!(
                    &error.to_string(),
                    "Rejecting block as its status is REVERTED, and only accepted blocks are allowed"
                );
            }
        }

        mod reorg {
            use super::*;
            use pretty_assertions::assert_eq;

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

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );

                // Block #1 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
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
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_V2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH_V2.into(),
                    Ok(STATE_UPDATE0_V2.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH_V2,
                    Ok(CONTRACT0_DEF_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH_V2.into(),
                    Ok(BLOCK0_SIGNATURE_V2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Err(block_not_found()),
                );

                // Indicate that we are still staying at the head - the latest block matches our head
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
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                // Reorg started from the genesis block
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK0_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT0_HASH_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK0_V2);
                    assert_eq!(*state_update, *STATE_UPDATE0_V2);
                });
            }

            #[tokio::test]
            // This reorg occurs at the genesis block, which means that the fork replaces the entire chain.
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

                let block1_v2 = reply::Block {
                    block_hash: BLOCK1_HASH_V2,
                    block_number: BLOCK1_NUMBER,
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 1 v2").unwrap()),
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
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(STATE_UPDATE2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );
                // Block #3 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occurred
                // We indicate that reorg started at genesis by setting the latest on the new genesis block
                expect_block_header(
                    &mut mock,
                    &mut seq,
                    BlockId::Latest,
                    Ok((BLOCK0_V2.block_number, BLOCK0_V2.block_hash)),
                );

                // Then the L2 sync task goes back block by block to find the last block where the block hash matches the DB
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone().into()),
                );
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_V2.clone().into()),
                );

                // Once the L2 sync task has found where reorg occurred,
                // it can get back to downloading the new blocks
                // Fetch the new genesis block from the fork with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_V2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH_V2.into(),
                    Ok(STATE_UPDATE0_V2.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH_V2,
                    Ok(CONTRACT0_DEF_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH_V2.into(),
                    Ok(BLOCK0_SIGNATURE_V2.clone()),
                );
                // Fetch the new block #1 from the fork with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH_V2.into(),
                    Ok(STATE_UPDATE1_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH_V2.into(),
                    Ok(BLOCK1_SIGNATURE_V2.clone()),
                );

                // Indicate that we are still staying at the head
                // No new blocks found and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
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
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
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
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK0_V2);
                    assert_eq!(*state_update, *STATE_UPDATE0_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
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

                let block1_v2 = reply::Block {
                    block_hash: BLOCK1_HASH_V2,
                    block_number: BLOCK1_NUMBER,
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 1 v2").unwrap()),
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
                };
                let block2_v2 = reply::Block {
                    block_hash: BLOCK2_HASH_V2,
                    block_number: BLOCK2_NUMBER,
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 2 v2").unwrap()),
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
                };
                let block3 = reply::Block {
                    block_hash: BLOCK3_HASH,
                    block_number: BLOCK3_NUMBER,
                    gas_price: Some(GasPrice::from(3)),
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
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(STATE_UPDATE2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );
                // Fetch block #3 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Ok(block3.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK3_HASH.into(),
                    Ok(STATE_UPDATE3.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK3_HASH.into(),
                    Ok(BLOCK3_SIGNATURE.clone()),
                );
                // Block #4 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
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

                // L2 sync task goes back block by block to find where the block hash matches the DB
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2_v2.clone().into()),
                );
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone().into()),
                );
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to start again
                // Fetch the new block #1 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH_V2.into(),
                    Ok(STATE_UPDATE1_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH_V2.into(),
                    Ok(BLOCK1_SIGNATURE_V2.clone()),
                );
                // Fetch the new block #2 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2_v2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH_V2.into(),
                    Ok(STATE_UPDATE2_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH_V2.into(),
                    Ok(BLOCK2_SIGNATURE_V2.clone()),
                );
                // Indicate that we are still staying at the head - no new blocks and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
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
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert_eq!(*state_update, *STATE_UPDATE2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, block3);
                    assert_eq!(*state_update, *STATE_UPDATE3);
                });
                // Reorg started from block #1
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK1_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, block1_v2);
                    assert_eq!(*state_update, *STATE_UPDATE1_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
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

                let block2_v2 = reply::Block {
                    block_hash: BLOCK2_HASH_V2,
                    block_number: BLOCK2_NUMBER,
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 2 v2").unwrap()),
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
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(STATE_UPDATE2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );
                // Block #3 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
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

                // L2 sync task goes back block by block to find where the block hash matches the DB
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone().into()),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to start again
                // Fetch the new block #2 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2_v2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH_V2.into(),
                    Ok(STATE_UPDATE2_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH_V2.into(),
                    Ok(BLOCK2_SIGNATURE_V2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
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
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert_eq!(*state_update, *STATE_UPDATE2);
                });
                // Reorg started from block #2
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK2_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
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

                let block1_v2 = reply::Block {
                    block_hash: BLOCK1_HASH_V2,
                    block_number: BLOCK1_NUMBER,
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 1 v2").unwrap()),
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
                };
                let block2 = reply::Block {
                    block_hash: BLOCK2_HASH,
                    block_number: BLOCK2_NUMBER,
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 2").unwrap()),
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
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT0_HASH,
                    Ok(CONTRACT0_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK0_HASH.into(),
                    Ok(BLOCK0_SIGNATURE.clone()),
                );

                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_class_by_hash(
                    &mut mock,
                    &mut seq,
                    CONTRACT1_HASH,
                    Ok(CONTRACT1_DEF.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH.into(),
                    Ok(BLOCK1_SIGNATURE.clone()),
                );
                // Fetch block #2 whose parent hash does not match block #1 hash
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2.clone().into()),
                );

                // L2 sync task goes back block by block to find where the block hash matches the DB
                // It starts at the previous block to which the mismatch happened
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to start again
                // Fetch the new block #1 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH_V2.into(),
                    Ok(STATE_UPDATE1_V2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK1_HASH_V2.into(),
                    Ok(BLOCK1_SIGNATURE_V2.clone()),
                );
                // Fetch the block #2 again, now with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(STATE_UPDATE2.clone()),
                );
                expect_signature(
                    &mut mock,
                    &mut seq,
                    BLOCK2_HASH.into(),
                    Ok(BLOCK2_SIGNATURE.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
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
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(*state_update, *STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    SyncEvent::CairoClass{hash, ..} => {
                        assert_eq!(hash, CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(*state_update, *STATE_UPDATE1);
                });
                // Reorg started from block #1
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Reorg(tail) => {
                    assert_eq!(tail, BLOCK1_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, block1_v2);
                    assert_eq!(*state_update, *STATE_UPDATE1_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), SyncEvent::Block((block, _), state_update, _, _) => {
                    assert_eq!(*block, block2);
                    assert_eq!(*state_update, *STATE_UPDATE2);
                });
            }

            #[tokio::test]
            async fn shutdown() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                // Closing the event's channel should trigger the sync to exit with error after the first send.
                rx_event.close();

                let mut mock = MockGatewayApi::new();
                let mut seq = mockall::Sequence::new();

                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone().into()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
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
