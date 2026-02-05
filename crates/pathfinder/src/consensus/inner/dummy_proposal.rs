//! Test helpers for consensus transaction testing
//!
//! This module provides utilities for creating realistic test transactions
//! and testing consensus scenarios with actual transaction execution.

use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::atomic::AtomicU64;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use p2p_proto::common::{Address, Hash, L1DataAvailabilityMode};
use p2p_proto::consensus::{BlockInfo, ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::{
    BlockHash,
    BlockId,
    BlockNumber,
    ChainId,
    ConsensusFinalizedL2Block,
    ContractAddress,
    StarknetVersion,
    StateCommitment,
};
use pathfinder_consensus::Round;
use pathfinder_crypto::Felt;
use pathfinder_executor::BlockExecutor;
use pathfinder_merkle_tree::starknet_state::update_starknet_state;
use pathfinder_storage::Storage;
use rand::{thread_rng, Rng, SeedableRng};

use crate::consensus::inner::conv::IntoModel;
use crate::consensus::inner::dto;
use crate::state::block_hash::compute_final_hash;
use crate::validator::{ProdTransactionMapper, ValidatorBlockInfoStage};

const DUMMY_PROPOSALS_1K: &[u8] = include_bytes!("dummy_proposal/fixtures.zst");

pub fn get_proposal_fixtures() -> anyhow::Result<Vec<(Vec<ProposalPart>, ConsensusFinalizedL2Block)>>
{
    let mut decompressor = zstd::bulk::Decompressor::new().unwrap();
    let encoded_fixtures = decompressor.decompress(DUMMY_PROPOSALS_1K, 10 * 1024 * 1024)?;
    let (fixtures_dtos, _): (
        Vec<(dto::ProposalParts, dto::PersistentConsensusFinalizedBlock)>,
        usize,
    ) = bincode::serde::decode_from_slice(&encoded_fixtures, bincode::config::standard())?;
    fixtures_dtos
        .into_iter()
        .map(|(dto_parts, dto_block)| {
            let parts = match dto_parts {
                dto::ProposalParts::V0(serde_parts) => serde_parts
                    .into_iter()
                    .map(|p| p.into_model())
                    .collect::<Vec<ProposalPart>>(),
            };
            let block = match dto_block {
                dto::PersistentConsensusFinalizedBlock::V0(serde_block) => serde_block.into_model(),
            };
            Ok((parts, block))
        })
        .collect()
}

pub fn create_proposal_fixtures(
    num_blocks: usize,
) -> anyhow::Result<Vec<(Vec<ProposalPart>, ConsensusFinalizedL2Block)>> {
    let stopwatch = std::time::Instant::now();
    tracing::info!("Creating proposal fixtures...");
    let main_storage =
        pathfinder_storage::StorageBuilder::in_tempdir_with_trie_pruning_and_pool_size(
            pathfinder_storage::TriePruneMode::Archive,
            NonZeroU32::new(std::thread::available_parallelism().unwrap().get() as u32 + 10)
                .unwrap(),
        )?;

    let mut fixtures = Vec::new();
    let mut committed_block_hashes = Vec::<BlockHash>::new();

    let mut percent_stopwatch = std::time::Instant::now();
    for height in 0..num_blocks as u64 {
        let (parts, block) = create(
            height,
            Round::new(0), /* unused */
            ContractAddress::ONE,
            main_storage.clone(),
            None,
        )?;

        // Commit block at `h`, otherwise h+1 will be deferred
        let mut main_db_conn = main_storage.connection()?;
        let main_db_tx = main_db_conn.transaction()?;
        let ConsensusFinalizedL2Block {
            header,
            state_update,
            ..
        } = &block;

        let (storage_commitment, class_commitment) = update_starknet_state(
            &main_db_tx,
            state_update.into(),
            true,
            BlockNumber::new_or_panic(height),
            main_storage.clone(),
        )?;

        let parent_hash = if height == 0 {
            BlockHash::ZERO
        } else {
            *committed_block_hashes.get(height as usize - 1).unwrap()
        };

        let header = header.clone().compute_hash(
            parent_hash,
            StateCommitment::calculate(
                storage_commitment,
                class_commitment,
                StarknetVersion::V_0_14_0,
            ),
            compute_final_hash,
        );

        main_db_tx.insert_block_header(&header)?;
        main_db_tx.insert_state_update_data(header.number, &state_update)?;
        main_db_tx.commit()?;
        fixtures.push((parts, block));
        committed_block_hashes.push(header.hash);

        if percent_stopwatch.elapsed() > Duration::from_secs(1) {
            tracing::info!(
                "Created {}% proposal fixtures so far...",
                (fixtures.len() * 100) as f32 / num_blocks as f32,
            );
            percent_stopwatch = std::time::Instant::now();
        }
    }

    tracing::info!(
        "Created {} proposal fixtures in {:.2} seconds",
        fixtures.len(),
        stopwatch.elapsed().as_secs_f32()
    );
    Ok(fixtures)
}

/// Blocks consensus tasks's processing loop until the parent block of height is
/// committed in main storage without blocking the async runtime.
pub(crate) async fn wait_for_parent_committed(
    height: u64,
    main_storage: Storage,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let parent_number = height.checked_sub(1);

    tracing::debug!(
        %height,
        ?parent_number,
        "Waiting for parent block to be committed"
    );

    util::task::spawn_blocking(move |cancellation_token| {
        if let Some(parent_number) = parent_number {
            loop {
                if cancellation_token.is_cancelled() {
                    break;
                }

                {
                    let mut main_db_conn = main_storage.connection()?;
                    let main_db_txn = main_db_conn.transaction()?;

                    if main_db_txn
                        .block_exists(BlockId::Number(BlockNumber::new_or_panic(parent_number)))?
                    {
                        break;
                    }

                    // Drop the transaction and return the connection to the
                    // pool before sleeping to avoid holding locks on the DB or
                    // shrinking available DB connections in the pool
                    // for longer than necessary
                }

                tracing::debug!(
                    %height,
                    %parent_number,
                    "Parent block not yet committed, sleeping"
                );

                std::thread::sleep(poll_interval);
            }
        }

        anyhow::Ok(())
    })
    .await??;

    Ok(())
}

#[derive(Debug)]
pub(crate) struct ProposalCreationConfig {
    pub num_batches: NonZeroUsize,
    pub batch_len: NonZeroUsize,
    pub num_executed_txns: NonZeroUsize,
}

/// Creates a dummy proposal for the given height and round.
///
/// The number of batches, batch length, and number of executed transactions
/// are randomized unless specified in the `config` parameter.
///
/// TODO: Until empty proposals reintroduce timestamps, we cannot create
/// empty proposals here.
pub(crate) fn create(
    height: u64,
    round: Round,
    proposer: ContractAddress,
    main_storage: Storage,
    config: Option<ProposalCreationConfig>,
) -> anyhow::Result<(Vec<ProposalPart>, ConsensusFinalizedL2Block)> {
    let round = round.as_u32().context(format!(
        "Attempted to create proposal with Nil round at height {height}"
    ))?;

    static INIT_TIMESTAMP: LazyLock<u64> = LazyLock::new(|| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    static TIMESTAMP_DELTA: AtomicU64 = AtomicU64::new(0);

    let timestamp =
        *INIT_TIMESTAMP + TIMESTAMP_DELTA.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let seed = thread_rng().gen::<u64>();
    tracing::debug!(%height, %round, %seed, ?config, "Creating dummy proposal");
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);

    let mut batches = Vec::new();
    let num_batches = config
        .as_ref()
        .map(|c| c.num_batches.get())
        .unwrap_or_else(|| rng.gen_range(1..=10));

    let mut next_txn_idx_start = 0;
    for _ in 1..=num_batches {
        let batch_len = config
            .as_ref()
            .map(|c| c.batch_len.get())
            .unwrap_or_else(|| rng.gen_range(1..=10));

        let batch = create_transaction_batch(
            height as u32,
            next_txn_idx_start,
            batch_len,
            ChainId::SEPOLIA_TESTNET,
        );

        batches.push(batch);
        next_txn_idx_start += batch_len;
    }

    let proposal_init = ProposalInit {
        height,
        round,
        valid_round: None,
        proposer: Address(proposer.0),
    };

    let mut parts = vec![ProposalPart::Init(proposal_init.clone())];

    let block_info = BlockInfo {
        height,
        builder: Address(proposer.0),
        timestamp,
        l2_gas_price_fri: 1_000_000,
        l1_gas_price_wei: 1_000_000,
        l1_data_gas_price_wei: 1_000_000,
        eth_to_fri_rate: 1_000_000_000_000_000_000,
        l1_da_mode: L1DataAvailabilityMode::Calldata,
    };

    parts.push(ProposalPart::BlockInfo(block_info.clone()));

    let validator = ValidatorBlockInfoStage::new(ChainId::SEPOLIA_TESTNET, proposal_init).unwrap();
    let mut validator = validator
        .validate_block_info::<BlockExecutor>(block_info.clone(), main_storage, None, None)
        .unwrap();

    let num_executed_txns = config
        .as_ref()
        .map(|c| c.num_executed_txns.get())
        .unwrap_or_else(|| rng.gen_range(1..=next_txn_idx_start));

    let txns_to_execute = batches
        .iter()
        .flatten()
        .take(num_executed_txns)
        .cloned()
        .collect();

    parts.extend(batches.into_iter().map(ProposalPart::TransactionBatch));
    parts.push(ProposalPart::ExecutedTransactionCount(
        num_executed_txns as u64,
    ));

    validator
        .execute_batch::<ProdTransactionMapper>(txns_to_execute)
        .unwrap();

    let block = validator.consensus_finalize0().unwrap();

    parts.push(ProposalPart::Fin(ProposalFin {
        proposal_commitment: Hash(block.header.state_diff_commitment.0),
    }));

    Ok((parts, block))
}

/// Creates a batch of transactions for testing
pub fn create_transaction_batch(
    seed: u32,
    start_index: usize,
    count: usize,
    chain_id: ChainId,
) -> Vec<p2p_proto::consensus::Transaction> {
    (start_index..start_index + count)
        .map(|i| create_l1_handler_transaction(seed, i, chain_id))
        .collect()
}

/// Creates a realistic L1Handler transaction for testing
///
/// `seed` is used to vary the transaction content independently of `index`,
/// so that we don't encounter duplicate transaction hashes across
/// multiple blocks.
pub fn create_l1_handler_transaction(
    seed: u32,
    index: usize,
    chain_id: ChainId,
) -> p2p_proto::consensus::Transaction {
    // base is a seed and index dependent value to avoid collisions but at the same
    // time easily allow to trace back which seed/index produced the transaction
    let base = index as u64 + ((seed as u64) << 32);
    let base = Felt::from_u64(base);

    // Create the L1Handler transaction
    let txn = p2p_proto::consensus::TransactionVariant::L1HandlerV0(
        p2p_proto::transaction::L1HandlerV0 {
            nonce: base,
            address: Address(base),
            entry_point_selector: base,
            calldata: vec![base],
        },
    );

    // Calculate the correct hash
    let l1_handler = pathfinder_common::transaction::L1HandlerTransaction {
        nonce: pathfinder_common::TransactionNonce(base),
        contract_address: ContractAddress::new_or_panic(base),
        entry_point_selector: pathfinder_common::EntryPoint(base),
        calldata: vec![pathfinder_common::CallParam(base)],
    };

    let hash = l1_handler.calculate_hash(chain_id);

    p2p_proto::consensus::Transaction {
        transaction_hash: p2p_proto::common::Hash(hash.0),
        txn,
    }
}

/// Creates a test proposal init and block info for the given height and round.
#[cfg(test)]
pub(crate) fn create_test_proposal_init(
    _chain_id: ChainId,
    height: u64,
    round: u32,
    proposer: ContractAddress,
) -> (ProposalInit, BlockInfo) {
    let proposer_address = Address(proposer.0);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let proposal_init = ProposalInit {
        height,
        round,
        valid_round: None,
        proposer: proposer_address,
    };

    let block_info = BlockInfo {
        height,
        timestamp,
        builder: proposer_address,
        l1_da_mode: L1DataAvailabilityMode::default(),
        l2_gas_price_fri: 1,
        l1_gas_price_wei: 1_000_000_000,
        l1_data_gas_price_wei: 1,
        eth_to_fri_rate: 1_000_000_000,
    };

    (proposal_init, block_info)
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::consensus::inner::conv::TryIntoDto;
    use crate::consensus::inner::dto;

    #[test]
    fn test_create_l1_handler_transaction() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let tx = create_l1_handler_transaction(0, 1, chain_id);

        // Verify the transaction has a valid hash
        assert!(!tx.transaction_hash.0.is_zero());

        // Verify it's an L1Handler transaction
        match tx.txn {
            p2p_proto::consensus::TransactionVariant::L1HandlerV0(_) => {}
            _ => panic!("Expected L1Handler transaction"),
        }
    }

    #[test]
    fn test_create_transaction_batch() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let batch = create_transaction_batch(0, 10, 5, chain_id);

        assert_eq!(batch.len(), 5);

        // Verify all transactions have different hashes
        let hashes: std::collections::HashSet<_> =
            batch.iter().map(|tx| tx.transaction_hash.0).collect();
        assert_eq!(hashes.len(), 5); // All unique
    }

    #[test_log::test]
    fn test_create_fixtures() {
        let fixtures = create_proposal_fixtures(20).unwrap();
        assert_eq!(fixtures.len(), 20);
    }

    #[test]
    fn test_get_proposal_fixtures() {
        let fixtures = get_proposal_fixtures().unwrap();
        assert!(!fixtures.is_empty());
    }

    #[ignore = "Use to generate proposal fixtures"]
    #[test_log::test]
    fn generate_proposal_fixtures_1k() {
        let fixtures = create_proposal_fixtures(1000).unwrap();

        let fixtures_dtos = fixtures
            .into_iter()
            .map(|(parts, block)| {
                let serde_parts = parts
                    .iter()
                    .map(|p| dto::ProposalPart::try_into_dto(p.clone()))
                    .collect::<Result<Vec<dto::ProposalPart>, _>>()
                    .unwrap();
                let dto_parts = dto::ProposalParts::V0(serde_parts);
                let serde_block =
                    dto::ConsensusFinalizedBlock::try_into_dto(block.clone()).unwrap();
                let dto_block = dto::PersistentConsensusFinalizedBlock::V0(serde_block);
                (dto_parts, dto_block)
            })
            .collect::<Vec<_>>();
        let encoded_fixtures =
            bincode::serde::encode_to_vec(fixtures_dtos, bincode::config::standard()).unwrap();
        let compressed_fixtures = zstd::bulk::compress(&encoded_fixtures, 10).unwrap();
        let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("src/consensus/inner/dummy_proposal/fixtures.zst");
        std::fs::write(path, compressed_fixtures).unwrap();
    }
}
