//! This test is focused more on correct parsing of the icoming parts rather
//! than actual execution. This is why we're mocking the executor to force
//! either success or failure. There is no deferred execution in the test
//! either. We're also starting with a fresh database and we're using one of the
//! 3 proposal types:
//! - valid and empty, execution always succeeds,
//! - structurally always valid with some fake transactions that nominally
//!   should always succeed on empty db, however only sometimes passing
//!   execution without error,
//! - invalid proposal (proposal parts well formed but the entire proposal not
//!   always conforming to the spec), execution sometimes succeeds.
//!
//! Ultimately, we end up with 5 possible paths, 2 of them leading to success.
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex};

use fake::Fake as _;
use p2p::consensus::HeightAndRound;
use p2p::sync::client::conv::TryFromDto;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{
    BlockInfo,
    ProposalFin,
    ProposalInit,
    ProposalPart,
    Transaction,
    TransactionVariant as ConsensusVariant,
};
use p2p_proto::sync::transaction::{DeclareV3WithoutClass, TransactionVariant as SyncVariant};
use p2p_proto::transaction::DeclareV3WithClass;
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::{ChainId, ContractAddress, TransactionHash};
use pathfinder_executor::types::to_starknet_api_transaction;
use pathfinder_executor::{BlockExecutorExt, IntoStarkFelt};
use pathfinder_storage::StorageBuilder;
use proptest::prelude::*;
use rand::seq::SliceRandom as _;
use rand::Rng as _;

use crate::consensus::inner::batch_execution::BatchExecutionManager;
use crate::consensus::inner::p2p_task::{handle_incoming_proposal_part, ValidatorCache};
use crate::consensus::ProposalHandlingError;
use crate::validator::{deployed_address, TransactionExt};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    #[test]
    fn test_handle_incoming_proposal_part((proposal_type, seed) in strategy::composite()) {
        MockExecutor::set_seed(seed);
        let validator_cache = ValidatorCache::<MockExecutor>::new();
        let deferred_executions = Arc::new(Mutex::new(HashMap::new()));
        let main_storage = StorageBuilder::in_tempdir().unwrap();
        let mut batch_execution_manager = BatchExecutionManager::new(None);

        let (proposal_parts, expect_success) = match proposal_type {
            strategy::ProposalCase::ValidEmpty => (create_structurally_valid_empty_proposal(), true),
            strategy::ProposalCase::StructurallyValidNonEmptyExecutionOk =>
                create_structurally_valid_non_empty_proposal(seed, true),
            strategy::ProposalCase::StructurallyValidNonEmptyExecutionFails =>
                create_structurally_valid_non_empty_proposal(seed, false),
            strategy::ProposalCase::StructurallyInvalidExecutionOk =>
                create_structurally_invalid_proposal(seed, true),
            strategy::ProposalCase::StructurallyInvalidExecutionFails =>
                create_structurally_invalid_proposal(seed, false),
        };

        let mut result = if expect_success {
            Err(ProposalHandlingError::Fatal(anyhow::anyhow!(
                "No proposal parts processed"
            )))
        } else {
            Ok(None)
        };

        let proposal_parts_len = proposal_parts.len();
        let no_fin = proposal_parts.iter().all(|part| !part.is_proposal_fin());
        let debug_info = debug_info(&proposal_parts);
        let mut incoming_proposal_parts = HashMap::new();
        let mut finalized_blocks = HashMap::new();

        for (proposal_part, is_last) in proposal_parts
            .into_iter()
            .zip((0..proposal_parts_len).map(|x| x == proposal_parts_len - 1))
        {
            result =
                handle_incoming_proposal_part::<MockExecutor, MockMapper>(
                    ChainId::SEPOLIA_TESTNET,
                    HeightAndRound::new(0, 0),
                    proposal_part,
                    &mut incoming_proposal_parts,
                    &mut finalized_blocks,
                    validator_cache.clone(),
                    deferred_executions.clone(),
                    main_storage.clone(),
                    &mut batch_execution_manager,
                    // Utilized by failure injection which is not happening in this test, so we can
                    // safely use an empty path
                    &PathBuf::new(),
                    None,
                    // No failure injection in this test
                    None,
                );

            if expect_success {
                prop_assert!(result.is_ok(), "{}", debug_info);
                // If we expect success, all results must be Ok, and the last must contain valid value
                prop_assert_eq!(result.as_ref().unwrap().is_some(), is_last, "{}", debug_info);
            } else if result.is_err() {
                break;
            }
        }

        // If we expect failure, we stop at the first error, Fin could be missing as well
        // but the handler does not error out in such case.
        if !expect_success {
            prop_assert!(result.is_err() || no_fin, "{}", debug_info);
        }
    }
}

fn debug_info(proposal_parts: &[ProposalPart]) -> String {
    let num_txns = proposal_parts
        .iter()
        .filter_map(|part| match part {
            ProposalPart::TransactionBatch(batch) => Some(batch.len()),
            _ => None,
        })
        .sum::<usize>();
    let fail_at_txn = MockExecutor::get_fail_at_txn();
    let mut s = dump_parts(proposal_parts);
    s.push_str(&format!("\nTotal txns: {num_txns}"));
    if fail_at_txn != DONT_FAIL {
        s.push_str(&format!("\nExec fail at txn: {fail_at_txn}"));
    }
    s.push_str("\n=====\n");
    s
}

fn dump_parts(proposal_parts: &[ProposalPart]) -> String {
    let s = "\n=====\n[".to_string();
    let mut s = proposal_parts.iter().fold(s, |mut s, part| {
        s.push_str(&dump_part(part));
        s.push(',');
        s
    });
    s.pop(); // Remove last comma
    s.push(']');
    s
}

fn dump_part(part: &ProposalPart) -> Cow<'static, str> {
    match part {
        ProposalPart::Init(_) => "Init".into(),
        ProposalPart::Fin(_) => "Fin".into(),
        ProposalPart::BlockInfo(_) => "BlockInfo".into(),
        ProposalPart::TransactionBatch(batch) => format!("Batch(len: {})", batch.len()).into(),
        ProposalPart::ExecutedTransactionCount(count) => {
            format!("ExecutedTxnCount({})", count).into()
        }
    }
}

/// Creates a structurally valid, empty proposal.
///
/// The proposal parts will be ordered as follows:
/// - Proposal Init
/// - Proposal Fin
fn create_structurally_valid_empty_proposal() -> Vec<ProposalPart> {
    let mut proposal_parts = Vec::new();
    let init = ProposalPart::Init(ProposalInit {
        height: 0,
        round: 0,
        valid_round: None,
        proposer: Address(ContractAddress::ZERO.0),
    });
    proposal_parts.push(init);

    let proposal_fin = ProposalPart::Fin(ProposalFin {
        proposal_commitment: Hash::ZERO,
    });
    proposal_parts.push(proposal_fin);
    proposal_parts
}

/// Creates a structurally valid, non-empty proposal with random parts.
/// The proposal will contain at least one transaction batch with random
/// fake transactions. The proposal will be well-formed but not necessarily
/// valid according to the consensus rules.
///
/// The proposal parts will be ordered as follows:
/// - Proposal Init
/// - Block Info
/// - In random order: one or more Transaction Batches, Executed Transaction
///   Count,
/// - Proposal Fin
fn create_structurally_valid_non_empty_proposal(
    seed: u64,
    execution_succeeds: bool,
) -> (Vec<ProposalPart>, bool) {
    use rand::SeedableRng;
    // Explicitly choose RNG to make sure seeded proposals are always reproducible
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);
    let mut proposal_parts = Vec::new();
    let init = ProposalPart::Init(ProposalInit {
        height: 0,
        round: 0,
        valid_round: None,
        proposer: Address(ContractAddress::ZERO.0),
    });
    let mut block_info: BlockInfo = fake::Faker.fake_with_rng(&mut rng);
    block_info.height = 0;
    block_info.builder = Address(ContractAddress::ZERO.0);
    let block_info = ProposalPart::BlockInfo(block_info);

    // Init and block info must be first
    proposal_parts.push(init);
    proposal_parts.push(block_info);

    let num_txns = rng.gen_range(1..200);

    let transactions = (0..num_txns)
        .map(|_| fake::Faker.fake_with_rng(&mut rng))
        .collect::<Vec<Transaction>>();
    let mut relaxed_ordered_parts = split_random(&transactions, &mut rng)
        .into_iter()
        .map(ProposalPart::TransactionBatch)
        .collect::<Vec<_>>();

    let executed_transaction_count = rng.gen_range(1..=num_txns).try_into().unwrap();

    if execution_succeeds {
        MockExecutor::set_fail_at_txn(DONT_FAIL);
    } else {
        let fail_at = rng.gen_range(0..num_txns);
        MockExecutor::set_fail_at_txn(fail_at);
    }

    let executed_transaction_count =
        ProposalPart::ExecutedTransactionCount(executed_transaction_count);

    relaxed_ordered_parts.push(executed_transaction_count);
    // All other parts except init, block info, and proposal fin can be in any order
    relaxed_ordered_parts.shuffle(&mut rng);

    proposal_parts.extend(relaxed_ordered_parts);

    let proposal_fin = ProposalPart::Fin(ProposalFin {
        proposal_commitment: Hash::ZERO,
    });
    proposal_parts.push(proposal_fin);
    (proposal_parts, execution_succeeds)
}

#[derive(Debug, Clone, Copy, fake::Dummy)]
enum ModifyPart {
    DoNothing,
    Remove,
    Duplicate,
}

#[derive(Debug, Clone, Copy, fake::Dummy)]
struct InvalidProposalConfig {
    remove_all_txns: bool,
    init: ModifyPart,
    block_info: ModifyPart,
    executed_txn_count: ModifyPart,
    proposal_commitment: ModifyPart,
    proposal_fin: ModifyPart,
    shuffle: bool,
}

impl InvalidProposalConfig {
    /// Returns true if the configuration would result in a probable valid
    /// proposal.
    fn maybe_valid(&self) -> bool {
        // We don't take shuffling into account here because it can still result
        // in a valid proposal.
        !self.remove_all_txns
            && matches!(self.init, ModifyPart::DoNothing)
            && matches!(self.block_info, ModifyPart::DoNothing)
            && matches!(self.executed_txn_count, ModifyPart::DoNothing)
            && matches!(self.proposal_commitment, ModifyPart::DoNothing)
            && matches!(self.proposal_fin, ModifyPart::DoNothing)
    }
}

/// Takes the output of [`create_structurally_valid_non_empty_proposal`] and
/// does at least one of the following:
/// - removes all transaction batches,
/// - removes or duplicates some of the following: proposal init, block info,
///   executed transactions count, proposal fin
/// - reshuffles all of the parts without respect to to the spec, or how
///   permissive we are wrt the ordering.
fn create_structurally_invalid_proposal(
    seed: u64,
    execution_succeeds: bool,
) -> (Vec<ProposalPart>, bool) {
    use rand::SeedableRng;
    // Explicitly choose RNG to make sure seeded proposals are always reproducible
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);
    let (mut proposal_parts, _) =
        create_structurally_valid_non_empty_proposal(seed, execution_succeeds);
    let config: InvalidProposalConfig = fake::Faker.fake_with_rng(&mut rng);

    let original_parts = proposal_parts.clone();

    if config.remove_all_txns {
        proposal_parts.retain(|x| !x.is_transaction_batch());
    }
    modify_part(&mut proposal_parts, &mut rng, config.init, |x| {
        x.is_proposal_init()
    });
    modify_part(&mut proposal_parts, &mut rng, config.block_info, |x| {
        x.is_block_info()
    });
    modify_part(
        &mut proposal_parts,
        &mut rng,
        config.executed_txn_count,
        |x| x.is_executed_transaction_count(),
    );
    modify_part(&mut proposal_parts, &mut rng, config.proposal_fin, |x| {
        x.is_proposal_fin()
    });

    if config.shuffle {
        proposal_parts.shuffle(&mut rng);
    }

    // It's possible that all of the config flags were set to `Remove`, in which
    // case the proposal will be empty. To avoid that, we revert to the
    // original proposal, and later on the init at the head will be removed,
    // resulting in a proposal which will indeed be invalid.
    if proposal_parts.is_empty() {
        proposal_parts = original_parts;
    }

    // If we were unfortunate enough to end up with an unmodified proposal, let's at
    // least force removing the init at the head, so that the proposal is
    // invalid for sure.
    if config.maybe_valid() || well_ordered_non_empty_proposal(&proposal_parts) {
        proposal_parts.remove(0);
    }

    // This proposal should always fail, regardless of execution outcome
    (proposal_parts, false)
}

fn well_ordered_non_empty_proposal(proposal_parts: &[ProposalPart]) -> bool {
    match proposal_parts {
        [] => panic!("Proposal should not be empty"),
        [ProposalPart::Init(_)] => true,
        // Empty proposal
        [ProposalPart::Init(_), ProposalPart::Fin(_)] => true,
        // Non-empty proposal
        [ProposalPart::Init(_), ProposalPart::BlockInfo(_), rest @ ..] => {
            rest.last().is_none_or(|part| part.is_proposal_fin())
        }
        _ => false,
    }
}

/// Removes a proposal part if the flag is true, or duplicates it if the flag
/// is false
fn modify_part(
    proposal_parts: &mut Vec<ProposalPart>,
    rng: &mut impl rand::Rng,
    modify_part: ModifyPart,
    match_fn: impl Fn(&ProposalPart) -> bool,
) {
    match modify_part {
        ModifyPart::DoNothing => {}
        ModifyPart::Remove => proposal_parts.retain(|x| !match_fn(x)),
        ModifyPart::Duplicate => {
            let (i, proposal) = proposal_parts
                .iter()
                .enumerate()
                .find_map(|(i, x)| match_fn(x).then_some((i, x.clone())))
                .expect("Part to be present");
            let insert_pos = rng.gen_range(i..proposal_parts.len());
            proposal_parts.insert(insert_pos, proposal);
        }
    }
}

/// Splits a slice into a random number of parts (between 1 and slice length)
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
            1 => (Just(ProposalCase::ValidEmpty), any::<u64>()),
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

    /// We want execution in the proptests to be deterministic based on the seed
    /// set in the MockMapper. This way we can have proposals that produce
    /// consistent results which, in case of a successful test case, can then be
    /// serialized into the consensus DB. This way we bypass real execution but
    /// can still heavily test the other parts of the proposal handling logic,
    /// including the consensus DB ops.
    fn execute(
        &mut self,
        txns: Vec<pathfinder_executor::Transaction>,
    ) -> Result<
        Vec<pathfinder_executor::types::ReceiptAndEvents>,
        pathfinder_executor::TransactionExecutionError,
    > {
        MockExecutor::add_executed_txn_count(txns.len());

        let fail_at_txn = MockExecutor::get_fail_at_txn();
        if fail_at_txn != DONT_FAIL && MockExecutor::get_executed_txn_count() > fail_at_txn {
            return Err(
                pathfinder_executor::TransactionExecutionError::ExecutionError {
                    transaction_index: fail_at_txn,
                    error: "Injected execution failure for proptests".to_string(),
                    error_stack: Default::default(),
                },
            );
        }

        use rand::SeedableRng;
        let seed = MockExecutor::get_seed();
        // Explicitly choose RNG to make sure seeded proposals are always reproducible
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);

        let dummy = (
            // Garbage is fine as long as it's serializable
            pathfinder_executor::types::Receipt {
                actual_fee: fake::Faker.fake_with_rng(&mut rng),
                execution_resources: fake::Faker.fake_with_rng(&mut rng),
                l2_to_l1_messages: fake::Faker.fake_with_rng(&mut rng),
                execution_status: fake::Faker.fake_with_rng(&mut rng),
                transaction_index: fake::Faker.fake_with_rng(&mut rng),
            },
            fake::Faker.fake_with_rng(&mut rng),
        );
        Ok(vec![dummy; txns.len()])
    }

    fn finalize(self) -> anyhow::Result<pathfinder_executor::types::StateDiff> {
        Ok(pathfinder_executor::types::StateDiff::default())
    }

    fn set_transaction_index(&mut self, _: usize) {}

    fn extract_state_diff(&self) -> anyhow::Result<pathfinder_executor::types::StateDiff> {
        Ok(pathfinder_executor::types::StateDiff::default())
    }
}

const DONT_FAIL: usize = usize::MAX;

// Thread-local is a precaution to ensure that the settings are passed correctly
// even if multiple cases for a particular proptest are running in parallel,
// which I'm pretty sure doesn't happen with proptest as of now (28/11/2025).
// Anyway, it will still serve well in case we have more than one proptest
// instance in this module, which would then mean that there are at least 2
// proptests running in parallel.
thread_local! {
    pub static MOCK_EXECUTOR_SEED: AtomicU64 = const { AtomicU64::new(0) };
    pub static MOCK_EXECUTOR_EXECUTED_TXN_COUNT: AtomicUsize = const { AtomicUsize::new(0) };
    pub static MOCK_EXECUTOR_FAIL_AT_TXN: AtomicUsize = const { AtomicUsize::new(DONT_FAIL) };
}

impl MockExecutor {
    pub fn set_seed(seed: u64) {
        MOCK_EXECUTOR_SEED.with(|s| {
            s.store(seed, std::sync::atomic::Ordering::SeqCst);
        });
    }

    pub fn get_seed() -> u64 {
        MOCK_EXECUTOR_SEED.with(|s| s.load(std::sync::atomic::Ordering::SeqCst))
    }

    pub fn add_executed_txn_count(count: usize) {
        MOCK_EXECUTOR_EXECUTED_TXN_COUNT.with(|s| {
            s.fetch_add(count, std::sync::atomic::Ordering::SeqCst);
        });
    }

    pub fn get_executed_txn_count() -> usize {
        MOCK_EXECUTOR_EXECUTED_TXN_COUNT.with(|s| s.load(std::sync::atomic::Ordering::SeqCst))
    }

    pub fn set_fail_at_txn(txn_index: usize) {
        MOCK_EXECUTOR_FAIL_AT_TXN.with(|s| {
            s.store(txn_index, std::sync::atomic::Ordering::SeqCst);
        });
    }

    pub fn get_fail_at_txn() -> usize {
        MOCK_EXECUTOR_FAIL_AT_TXN.with(|s| s.load(std::sync::atomic::Ordering::SeqCst))
    }
}

struct MockMapper;

/// Does the same as ProdTransactionMapper with an exception:
/// - fills ClassInfo with dummy data
impl TransactionExt for MockMapper {
    fn try_map_transaction(
        transaction: p2p_proto::consensus::Transaction,
    ) -> anyhow::Result<(
        pathfinder_common::transaction::Transaction,
        pathfinder_executor::Transaction,
    )> {
        let p2p_proto::consensus::Transaction {
            txn,
            transaction_hash,
        } = transaction;
        let (variant, class_info) = match txn {
            ConsensusVariant::DeclareV3(DeclareV3WithClass {
                common,
                class: _, /* Ignore */
            }) => (
                SyncVariant::DeclareV3(DeclareV3WithoutClass {
                    common,
                    class_hash: Default::default(),
                }),
                Some(starknet_api::contract_class::ClassInfo {
                    contract_class: starknet_api::contract_class::ContractClass::V0(
                        starknet_api::deprecated_contract_class::ContractClass::default(),
                    ),
                    sierra_program_length: 0,
                    abi_length: 0,
                    sierra_version: starknet_api::contract_class::SierraVersion::DEPRECATED,
                }),
            ),
            ConsensusVariant::DeployAccountV3(v) => (SyncVariant::DeployAccountV3(v), None),
            ConsensusVariant::InvokeV3(v) => (SyncVariant::InvokeV3(v), None),
            ConsensusVariant::L1HandlerV0(v) => (SyncVariant::L1HandlerV0(v), None),
        };

        let common_txn_variant = TransactionVariant::try_from_dto(variant)?;

        let deployed_address = deployed_address(&common_txn_variant);

        // TODO(validator) why 10^12?
        let paid_fee_on_l1 = match &common_txn_variant {
            TransactionVariant::L1Handler(_) => {
                Some(starknet_api::transaction::fields::Fee(1_000_000_000_000))
            }
            _ => None,
        };

        let api_txn = to_starknet_api_transaction(common_txn_variant.clone())?;
        let tx_hash =
            starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt());
        let executor_txn = pathfinder_executor::Transaction::from_api(
            api_txn,
            tx_hash,
            class_info,
            paid_fee_on_l1,
            deployed_address,
            pathfinder_executor::AccountTransactionExecutionFlags::default(),
        )?;
        let common_txn = pathfinder_common::transaction::Transaction {
            hash: TransactionHash(transaction_hash.0),
            variant: common_txn_variant,
        };

        Ok((common_txn, executor_txn))
    }

    fn verify_hash(_: &pathfinder_common::transaction::Transaction, _: ChainId) -> bool {
        true
    }
}
