use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fake::Fake as _;
use p2p::consensus::HeightAndRound;
use p2p_proto::common::Address;
use p2p_proto::consensus::{
    BlockInfo,
    ProposalCommitment,
    ProposalFin,
    ProposalInit,
    ProposalPart,
    Transaction,
    TransactionsFin,
};
use pathfinder_common::{ChainId, ContractAddress};
use pathfinder_consensus::Round;
use pathfinder_executor::BlockExecutorExt;
use pathfinder_storage::StorageBuilder;
use proptest::prelude::*;
use rand::seq::SliceRandom as _;
use rand::Rng as _;

use crate::consensus::inner::batch_execution::BatchExecutionManager;
use crate::consensus::inner::consensus_task::create_empty_proposal;
use crate::consensus::inner::open_consensus_storage;
use crate::consensus::inner::p2p_task::{handle_incoming_proposal_part, ValidatorCache};
use crate::consensus::inner::persist_proposals::ConsensusProposals;
use crate::validator::TransactionMapper;

/// This test is focused more on correct parsing of the icoming parts rather
/// than actual execution. This is why we're mocking the executor to force
/// either success or failure. There is no deferred execution in the test
/// either. We're also starting with a fresh database and we're using one of the
/// 3 proposal types:
/// - valid and empty, execution always succeeds,
/// - structurally always valid with some fake transactions that nominally
///   should always succeed on empty db, however only sometimes passing
///   execution without error,
/// - invalid proposal (proposal parts well formed but the entire proposal not
///   always conforming to the spec), execution sometimes succeeds.
///
/// Ultimately, we end up with 5 possible paths, 2 of them leading to success.
#[test]
fn test_handle_incoming_proposal_part() {
    // TODO swap out BlockExecutor with a mock that can be instructed to
    // either succeed or fail execution based on the proposal case in some random
    // transaction
    let validator_cache = ValidatorCache::<MockExecutor>::new();
    let deferred_executions = Arc::new(Mutex::new(HashMap::new()));
    let main_storage = StorageBuilder::in_tempdir().unwrap();
    let consensus_storage_tempdir = tempfile::tempdir().unwrap();
    let consensus_storage = open_consensus_storage(consensus_storage_tempdir.path()).unwrap();
    let mut consensus_db_conn = consensus_storage.connection().unwrap();
    let consensus_db_tx = consensus_db_conn.transaction().unwrap();
    let proposals_db = ConsensusProposals::new(consensus_db_tx);
    let mut batch_execution_manager = BatchExecutionManager::new();

    let (proposal_parts, _finalized_block) = create_empty_proposal(
        ChainId::SEPOLIA_TESTNET,
        0,
        Round::new(0),
        ContractAddress::ZERO,
        main_storage.clone(),
    )
    .unwrap();
    let proposal_parts = create_structurally_valid_non_empty_proposal(42);
    let proposal_parts_len = proposal_parts.len();

    for (proposal_part, is_last) in proposal_parts
        .into_iter()
        .zip((0..proposal_parts_len).map(|x| x == proposal_parts_len - 1))
    {
        let proposal_commitment_w_origin =
            handle_incoming_proposal_part::<MockExecutor, MockMapper>(
                ChainId::SEPOLIA_TESTNET,
                // Arbitrary contract address for testing
                ContractAddress::ONE,
                HeightAndRound::new(0, 0),
                proposal_part,
                validator_cache.clone(),
                deferred_executions.clone(),
                main_storage.clone(),
                &proposals_db,
                &mut batch_execution_manager,
                // Utilized by failure injection which is not happening in this test, so we can
                // safely use an empty path
                &PathBuf::new(),
                // No failure injection in this test
                None,
            )
            .unwrap();
        assert_eq!(proposal_commitment_w_origin.is_some(), is_last);
    }
}

/// Creates a structurally valid, non-empty proposal with random parts.
/// The proposal will contain at least one transaction batch with random
/// fake transactions. The proposal will be well-formed but not necessarily
/// valid according to the consensus rules.
///
/// The proposal parts will be ordered as follows:
/// - Proposal Init
/// - Block Info
/// - In random order: one or more Transaction Batches, Transactions Fin,
///   Proposal Commitment
/// - Proposal Fin
fn create_structurally_valid_non_empty_proposal(seed: u64) -> Vec<ProposalPart> {
    use rand::SeedableRng;
    // Explicitly choose RNG to make sure seeded proposals are always reproducible
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);
    let mut proposal_parts = Vec::new();
    let init = ProposalPart::Init(ProposalInit {
        block_number: 0,
        round: 0,
        valid_round: None,
        proposer: Address(ContractAddress::ZERO.0),
    });
    let mut block_info: BlockInfo = fake::Faker.fake_with_rng(&mut rng);
    block_info.block_number = 0;
    block_info.builder = Address(ContractAddress::ZERO.0);
    let block_info = ProposalPart::BlockInfo(block_info);

    // Init and block info must be first
    proposal_parts.push(init);
    proposal_parts.push(block_info);

    let num_txns = rng.gen_range(1..1000);
    let transactions = (0..num_txns)
        .map(|_| fake::Faker.fake_with_rng(&mut rng))
        .collect::<Vec<Transaction>>();
    let mut relaxed_ordered_parts = split_random(&transactions, &mut rng)
        .into_iter()
        .map(ProposalPart::TransactionBatch)
        .collect::<Vec<_>>();

    let executed_transaction_count = rng.gen_range(1..=num_txns).try_into().unwrap();
    let transactions_fin = ProposalPart::TransactionsFin(TransactionsFin {
        executed_transaction_count,
    });
    let mut proposal_commitment: ProposalCommitment = fake::Faker.fake_with_rng(&mut rng);
    proposal_commitment.block_number = 0;
    proposal_commitment.builder = Address(ContractAddress::ZERO.0);
    let state_diff_commitment = proposal_commitment.state_diff_commitment;
    let proposal_commitment = ProposalPart::ProposalCommitment(proposal_commitment);

    relaxed_ordered_parts.push(transactions_fin);
    relaxed_ordered_parts.push(proposal_commitment);
    // All other parts except init, block info, and proposal fin can be in any order
    relaxed_ordered_parts.shuffle(&mut rng);

    proposal_parts.extend(relaxed_ordered_parts);

    let proposal_fin = ProposalPart::Fin(ProposalFin {
        proposal_commitment: state_diff_commitment,
    });
    proposal_parts.push(proposal_fin);
    proposal_parts
}

/// Takes the output of [`create_structurally_valid_non_empty_proposal`] and
/// does at least one of the following:
/// - removes all transaction batches,
/// - removes or duplicates some of the following: proposal init, block info,
///   transactions fin, proposal commitment, proposal fin
/// - reshuffles all of the parts without respect to to the spec, or how
///   permissive we are wrt the ordering,
fn create_structurally_invalid_proposal(seed: u64) -> Vec<ProposalPart> {
    use rand::SeedableRng;
    // Explicitly choose RNG to make sure seeded proposals are always reproducible
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);

    let mut proposal_parts = create_structurally_valid_non_empty_proposal(seed);
    let remove_all_txns: bool = rng.gen();
    let remove_not_duplicate_init: bool = rng.gen();
    let remove_not_duplicate_info: bool = rng.gen();
    let remove_not_duplicate_txn_fin: bool = rng.gen();
    let remove_not_duplicate_proposal_commitment: bool = rng.gen();
    let remove_not_duplicate_proposal_fin: bool = rng.gen();
    let shuffle: bool = rng.gen();
    if remove_all_txns {
        proposal_parts.retain(|x| !x.is_transaction_batch());
    }
    remove_or_duplicate_part(
        &mut proposal_parts,
        &mut rng,
        remove_not_duplicate_init,
        |x| x.is_proposal_init(),
    );
    remove_or_duplicate_part(
        &mut proposal_parts,
        &mut rng,
        remove_not_duplicate_info,
        |x| x.is_block_info(),
    );
    remove_or_duplicate_part(
        &mut proposal_parts,
        &mut rng,
        remove_not_duplicate_txn_fin,
        |x| x.is_transactions_fin(),
    );
    remove_or_duplicate_part(
        &mut proposal_parts,
        &mut rng,
        remove_not_duplicate_proposal_commitment,
        |x| x.is_proposal_commitment(),
    );
    remove_or_duplicate_part(
        &mut proposal_parts,
        &mut rng,
        remove_not_duplicate_proposal_fin,
        |x| x.is_proposal_fin(),
    );
    if shuffle {
        proposal_parts.shuffle(&mut rng);
    }
    proposal_parts
}

/// Removes a proposal part if the flag is true, or duplicates int if the flag
/// is false
fn remove_or_duplicate_part(
    proposal_parts: &mut Vec<ProposalPart>,
    rng: &mut impl rand::Rng,
    remove_or_duplicate: bool,
    match_fn: impl Fn(&ProposalPart) -> bool,
) {
    if remove_or_duplicate {
        proposal_parts.retain(|x| !match_fn(x));
    } else {
        let found = proposal_parts
            .iter()
            .enumerate()
            .find_map(|(i, x)| match_fn(x).then_some((i, x.clone())));
        if let Some((i, proposal)) = found {
            let offset = rng.gen_range(i..proposal_parts.len());
            proposal_parts.insert(offset, proposal);
        }
    }
}

fn split_random<T: Clone>(v: &[T], rng: &mut impl rand::Rng) -> Vec<Vec<T>> {
    let n = v.len();

    // 1. Choose a random number of parts: between 1 and n
    let parts = rng.gen_range(1..=n);

    if parts == 1 {
        return vec![v.to_vec()];
    }

    // 2. Generate (parts - 1) cut points in 1..n-1
    let mut cuts: Vec<usize> = (0..parts - 1).map(|_| rng.gen_range(1..n)).collect();

    // 3. Sort and deduplicate to avoid empty segments
    cuts.sort();
    cuts.dedup();

    // 4. Build the segments
    let mut result = Vec::with_capacity(parts);
    let mut start = 0;

    for cut in cuts {
        result.push(v[start..cut].to_vec());
        start = cut;
    }
    result.push(v[start..].to_vec());

    result
}

/// Strategy for generating proposal parts for proptests.
mod strategy {
    use proptest::prelude::*;

    #[derive(Debug, Clone, Copy)]
    pub enum ProposalCase {
        ValidEmpty,
        StructurallyValidNonEmptyExecutionOk,
        StructurallyValidNonEmptyExecutionFails,
        StructurallyInvalidExecutionOk,
        StructurallyInvalidExecutionFails,
    }

    /// Generates a composite strategy that yields a tuple of
    /// (ProposalCase, u64) where u64 can be used as a seed or
    /// identifier for generating proposal parts according to the
    /// specified case.
    pub fn composite() -> BoxedStrategy<(ProposalCase, u64)> {
        prop_oneof![
            // 1/20 (4% of the time)
            1 => (Just(ProposalCase::ValidEmpty), Just(0)),
            // 4/20 (20% of the time)
            4 => (Just(ProposalCase::StructurallyValidNonEmptyExecutionOk), any::<u64>()),
            // 5/20 (25% of the time)
            5 => (Just(ProposalCase::StructurallyValidNonEmptyExecutionFails), any::<u64>()),
            5 => (Just(ProposalCase::StructurallyInvalidExecutionOk), any::<u64>()),
            5 => (Just(ProposalCase::StructurallyInvalidExecutionFails), any::<u64>()),
        ]
        .boxed()
    }
}

struct MockExecutor;

impl BlockExecutorExt for MockExecutor {
    fn new(
        _: ChainId,
        _: pathfinder_executor::types::BlockInfo,
        _: ContractAddress,
        _: ContractAddress,
        _: pathfinder_storage::Connection,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn new_with_pending_state(
        _: ChainId,
        _: pathfinder_executor::types::BlockInfo,
        _: ContractAddress,
        _: ContractAddress,
        _: pathfinder_storage::Connection,
        _: std::sync::Arc<pathfinder_common::StateUpdate>,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn execute(
        &mut self,
        _: Vec<pathfinder_executor::Transaction>,
    ) -> Result<
        Vec<pathfinder_executor::types::ReceiptAndEvents>,
        pathfinder_executor::TransactionExecutionError,
    > {
        Ok(vec![])
    }

    fn finalize(self) -> anyhow::Result<pathfinder_executor::types::StateDiff> {
        Ok(pathfinder_executor::types::StateDiff::default())
    }

    fn set_transaction_index(&mut self, _: usize) {}

    fn extract_state_diff(&self) -> anyhow::Result<pathfinder_executor::types::StateDiff> {
        Ok(pathfinder_executor::types::StateDiff::default())
    }
}

struct MockMapper;

impl TransactionMapper for MockMapper {
    fn try_map_transaction(
        _: p2p_proto::consensus::Transaction,
    ) -> anyhow::Result<(
        pathfinder_common::transaction::Transaction,
        pathfinder_executor::Transaction,
    )> {
        Ok((
            pathfinder_common::transaction::Transaction::default(),
            pathfinder_executor::Transaction::L1Handler(
                starknet_api::executable_transaction::L1HandlerTransaction::default(),
            ),
        ))
    }
}
