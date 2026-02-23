//! Utilities for initializing a devnet for development and testing purposes.
//! Heavily inspired by [starknet-devnet](https://github.com/0xSpaceShard/starknet-devnet) v0.7.1.
//! Unfortunately we cannot use `starknet-devnet` directly because it is not
//! state/storage API agnostic.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::{Instant, SystemTime};

use anyhow::{Context, Ok};
use p2p::sync::client::conv::ToDto as _;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{BlockInfo, ProposalInit};
use p2p_proto::sync::transaction::DeclareV3WithoutClass;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::transaction::{
    DataAvailabilityMode,
    DeclareTransactionV3,
    ResourceBound,
    ResourceBounds,
    TransactionVariant,
};
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockId,
    BlockNumber,
    BlockTimestamp,
    ChainId,
    ClassHash,
    ConsensusFinalizedL2Block,
    EventCommitment,
    GasPrice,
    L1DataAvailabilityMode,
    ReceiptCommitment,
    ResourceAmount,
    ResourcePricePerUnit,
    SequencerAddress,
    StarknetVersion,
    StateCommitment,
    Tip,
    TransactionCommitment,
    TransactionSignatureElem,
};
use pathfinder_crypto::signature::ecdsa_sign;
use pathfinder_crypto::Felt;
use pathfinder_executor::{ConcurrentStateReader, ExecutorWorkerPool};
use pathfinder_merkle_tree::starknet_state::update_starknet_state;
use pathfinder_storage::pruning::BlockchainHistoryMode;
use pathfinder_storage::{Storage, StorageBuilder, TriePruneMode};
use tempfile::TempDir;

use crate::devnet::account::Account;
use crate::devnet::class::{preprocess_sierra, PrepocessedSierra};
use crate::devnet::fixtures::RESOURCE_BOUNDS;
use crate::state::block_hash::compute_final_hash;
use crate::validator::{
    ProdTransactionMapper,
    ValidatorBlockInfoStage,
    ValidatorTransactionBatchStage,
    ValidatorWorkerPool,
};

mod account;
mod class;
mod contract;
mod fixtures;
mod proposal;
mod utils;

use fixtures::{ETH_TO_FRI_RATE, GAS_PRICE};

/// Initializes a devnet DB. The following contracts are predeclared,
/// predeployed and initialized if necessary: Cairo 1 account, ETH and STRK
/// ERC20s, and the UDC. The following contract is already declared but not
/// deployed: Hello Starknet.
pub fn init_db(proposer: Address) -> anyhow::Result<DevnetConfig> {
    let stopwatch = Instant::now();

    let timestamp = strictly_increasing_timestamp(None);
    let _bootstrap_db_dir = Rc::new(TempDir::new()?);
    let bootstrap_db_path = _bootstrap_db_dir.path().join("bootstrap.sqlite");

    let storage = StorageBuilder::file(bootstrap_db_path.clone())
        .trie_prune_mode(Some(TriePruneMode::Archive))
        .blockchain_history_mode(Some(BlockchainHistoryMode::Archive))
        .migrate()?
        .create_pool(
            NonZeroU32::new(5 + available_parallelism().unwrap().get() as u32).expect(">0"),
        )?;

    tracing::info!(
        "Initialized devnet bootstrap DB in {}",
        _bootstrap_db_dir.path().display(),
    );

    let mut db_conn = storage.connection()?;
    let db_txn = db_conn.transaction()?;
    let mut state_update = StateUpdateData::default();

    let mut account = predeploy_contracts(&db_txn, &mut state_update)?;

    let block_number = BlockNumber::GENESIS;
    let (storage_commitment, class_commitment) = update_starknet_state(
        &db_txn,
        (&state_update).into(),
        true,
        block_number,
        storage.clone(),
    )?;
    let state_commitment = StateCommitment::calculate(
        storage_commitment,
        class_commitment,
        StarknetVersion::V_0_14_0,
    );

    let mut genesis_header = BlockHeader {
        hash: BlockHash::ZERO, // Will be updated
        parent_hash: BlockHash::ZERO,
        number: block_number,
        timestamp,
        eth_l1_gas_price: GAS_PRICE,
        strk_l1_gas_price: GAS_PRICE,
        eth_l1_data_gas_price: GAS_PRICE,
        strk_l1_data_gas_price: GAS_PRICE,
        eth_l2_gas_price: GAS_PRICE,
        strk_l2_gas_price: GAS_PRICE,
        // Alice has this address in integration tests
        sequencer_address: SequencerAddress(proposer.0),
        starknet_version: StarknetVersion::V_0_14_0,
        // No events in genesis, so the root of an empty tree is zero
        event_commitment: EventCommitment(Felt::ZERO),
        state_commitment,
        // No transactions in genesis, so the root of an empty tree is zero
        transaction_commitment: TransactionCommitment(Felt::ZERO),
        transaction_count: 0,
        event_count: 0,
        l1_da_mode: L1DataAvailabilityMode::Calldata,
        // No transactions (and hence no receipts) in genesis, so the root of an empty tree is zero
        receipt_commitment: ReceiptCommitment(Felt::ZERO),
        state_diff_commitment: state_update.compute_state_diff_commitment(),
        state_diff_length: state_update.state_diff_length(),
    };

    genesis_header.hash = compute_final_hash(&genesis_header);

    db_txn.insert_block_header(&genesis_header).unwrap();
    db_txn
        .insert_state_update_data(block_number, &state_update)
        .unwrap();
    db_txn.commit().unwrap();

    tracing::info!(
        "Initialized devnet bootstrap DB genesis block in {} ms",
        stopwatch.elapsed().as_millis(),
    );

    let db_txn = db_conn.transaction()?;
    declare(
        storage.clone(),
        db_txn,
        &mut account,
        fixtures::HELLO_CLASS,
        proposer,
    )?;

    Ok(DevnetConfig {
        _bootstrap_db_dir,
        bootstrap_db_path,
        account_private_key: account.private_key(),
    })
}

#[derive(Debug, Clone)]
pub struct DevnetConfig {
    // We keep the temp dir around to ensure it isn't deleted until we're done
    _bootstrap_db_dir: Rc<TempDir>,
    bootstrap_db_path: PathBuf,
    account_private_key: Felt,
    // account_address: ContractAddress,
    // hello_starknet_address: ContractAddress,
}

impl DevnetConfig {
    pub fn bootstrap_db_path(&self) -> &Path {
        &self.bootstrap_db_path
    }

    pub fn account_private_key(&self) -> Felt {
        self.account_private_key
    }
}

/// Declare a Cairo 1 class (sierra bytecode) via the DeclareV3
/// transaction.
pub fn declare(
    storage: Storage,
    db_txn: pathfinder_storage::Transaction<'_>,
    account: &mut Account,
    serialized_sierra: &[u8],
    proposer: Address,
) -> anyhow::Result<()> {
    let stopwatch = Instant::now();

    let PrepocessedSierra {
        sierra_class_hash,
        cairo1_class_p2p,
        sierra_class_ser,
        casm_hash_v2,
        casm,
    } = preprocess_sierra(serialized_sierra, None)?;

    let worker_pool: ValidatorWorkerPool =
        ExecutorWorkerPool::<ConcurrentStateReader>::new(1).get();
    let latest_header = db_txn
        .block_header(BlockId::Latest)?
        .context("DB is empty")?;
    let next_block_number = latest_header.number + 1;

    let mut validator = new_validator(
        next_block_number,
        proposer,
        latest_header.timestamp,
        storage.clone(),
        worker_pool.clone(),
    );

    let declare = DeclareTransactionV3 {
        class_hash: ClassHash(sierra_class_hash.0),
        nonce: account.fetch_add_nonce(),
        nonce_data_availability_mode: DataAvailabilityMode::L1,
        fee_data_availability_mode: DataAvailabilityMode::L1,
        resource_bounds: RESOURCE_BOUNDS,
        tip: Tip(0),
        paymaster_data: vec![],
        signature: vec![/* Will be filled after signing */],
        account_deployment_data: vec![],
        sender_address: account.address(),
        compiled_class_hash: casm_hash_v2,
    };
    let mut variant = TransactionVariant::DeclareV3(declare);
    let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
    let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
    let TransactionVariant::DeclareV3(declare) = &mut variant else {
        unreachable!();
    };
    declare.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

    let variant = variant.to_dto();

    let p2p_proto::sync::transaction::TransactionVariant::DeclareV3(DeclareV3WithoutClass {
        common,
        ..
    }) = variant
    else {
        unreachable!();
    };

    let declare = p2p_proto::transaction::DeclareV3WithClass {
        common,
        class: cairo1_class_p2p,
    };
    let declare = p2p_proto::consensus::Transaction {
        txn: p2p_proto::consensus::TransactionVariant::DeclareV3(declare),
        transaction_hash: Hash(txn_hash.0),
    };

    validator
        .execute_batch::<ProdTransactionMapper>(vec![declare])
        .unwrap();

    let next_block = validator.consensus_finalize0().unwrap();

    let (storage_commitment, class_commitment) = update_starknet_state(
        &db_txn,
        (&next_block.state_update).into(),
        true,
        next_block.header.number,
        storage.clone(),
    )
    .unwrap();
    let state_commitment = StateCommitment::calculate(
        storage_commitment,
        class_commitment,
        StarknetVersion::V_0_14_0,
    );

    let ConsensusFinalizedL2Block {
        header,
        state_update,
        transactions_and_receipts,
        events,
    } = next_block;

    let next_header = header.compute_hash(latest_header.hash, state_commitment, compute_final_hash);

    db_txn.insert_block_header(&next_header).unwrap();

    // Insert classes before state update because the latter will trigger
    // `upsert_declared_at` and insert a NULL definition
    db_txn
        .insert_sierra_class_definition(&sierra_class_hash, &sierra_class_ser, &casm, &casm_hash_v2)
        .unwrap();

    db_txn
        .insert_state_update_data(next_header.number, &state_update)
        .unwrap();
    db_txn
        .insert_transaction_data(
            next_header.number,
            &transactions_and_receipts,
            Some(&events),
        )
        .unwrap();
    db_txn.commit().unwrap();

    let worker_pool = Arc::into_inner(worker_pool).expect("Refcount is 1");
    worker_pool.join();

    tracing::info!(
        "Declared class {sierra_class_hash} in block {} in {} ms",
        next_header.number,
        stopwatch.elapsed().as_millis(),
    );

    Ok(())
}

/// Predeclare, predeploy, and initialize if necessary: Cairo 1 account, ETH and
/// STRK ERC20s, and the UDC.
fn predeploy_contracts(
    db_txn: &pathfinder_storage::Transaction<'_>,
    state_update: &mut StateUpdateData,
) -> Result<Account, anyhow::Error> {
    fixtures::PREDECLARED_CLASSES
        .iter()
        .copied()
        .try_for_each(|(class, sierra_hash)| {
            class::predeclare(db_txn, state_update, class, Some(sierra_hash))
        })?;
    fixtures::PREDEPLOYED_CONTRACTS
        .iter()
        .copied()
        .try_for_each(|(contract_address, sierra_hash)| {
            contract::predeploy(state_update, contract_address, sierra_hash)
        })?;
    fixtures::ERC20S
        .iter()
        .copied()
        .try_for_each(|(contract_address, name, symbol)| {
            contract::erc20_init(state_update, contract_address, name, symbol)
        })?;
    let account = Account::new_from_fixture();
    account.predeploy(state_update)?;
    Ok(account)
}

/// Returns the current UNIX timestamp, ensuring that it is strictly increasing
/// across calls, if the previous timestamp is provided.
fn strictly_increasing_timestamp(prev: Option<BlockTimestamp>) -> BlockTimestamp {
    let current = BlockTimestamp::new_or_panic(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    match prev {
        Some(prev) if current.get() <= prev.get() => BlockTimestamp::new_or_panic(prev.get() + 1),
        _ => current,
    }
}

/*
/// Create a new validator for the given block height.
fn new_validator(height: BlockNumber, proposer: Address) -> ValidatorBlockInfoStage {
    ValidatorBlockInfoStage::new(
        ChainId::SEPOLIA_TESTNET,
        ProposalInit {
            height: height.get(),
            round: 0,
            valid_round: None,
            proposer,
        },
    )
    .expect("valid block height")
}
*/

fn new_validator(
    height: BlockNumber,
    proposer: Address,
    prev_timestamp: BlockTimestamp,
    storage: Storage,
    worker_pool: ValidatorWorkerPool,
) -> ValidatorTransactionBatchStage {
    let validator = ValidatorBlockInfoStage::new(
        ChainId::SEPOLIA_TESTNET,
        ProposalInit {
            height: height.get(),
            round: 0,
            valid_round: None,
            proposer,
        },
    )
    .expect("valid block height");

    validator
        .validate_block_info(
            block_info(height, proposer, prev_timestamp),
            storage.clone(),
            None,
            None,
            worker_pool.clone(),
        )
        .unwrap()
}

/// Block info for devnet blocks, sufficient for execution, provided that gas
/// prices are not validated against any oracle.
fn block_info(height: BlockNumber, proposer: Address, prev_timestamp: BlockTimestamp) -> BlockInfo {
    BlockInfo {
        height: height.get(),
        builder: proposer,
        timestamp: strictly_increasing_timestamp(Some(prev_timestamp)).get(),
        l2_gas_price_fri: GAS_PRICE.0,
        l1_gas_price_wei: GAS_PRICE.0,
        l1_data_gas_price_wei: GAS_PRICE.0,
        eth_to_fri_rate: ETH_TO_FRI_RATE,
        l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
    }
}

#[cfg(test)]
pub mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::thread::available_parallelism;
    use std::time::Instant;

    use p2p::sync::client::conv::ToDto as _;
    use p2p_proto::common::{Address, Hash};
    use p2p_proto::consensus::{BlockInfo, ProposalInit};
    use p2p_proto::sync::transaction::DeclareV3WithoutClass;
    use pathfinder_common::class_definition::Sierra;
    use pathfinder_common::transaction::{
        DataAvailabilityMode,
        DeclareTransactionV3,
        InvokeTransactionV3,
        ResourceBound,
        ResourceBounds,
        TransactionVariant,
    };
    use pathfinder_common::{
        felt,
        BlockHash,
        BlockHeader,
        BlockId,
        BlockTimestamp,
        CallParam,
        ChainId,
        ClassHash,
        ConsensusFinalizedL2Block,
        ContractAddress,
        EntryPoint,
        EventCommitment,
        GasPrice,
        L1DataAvailabilityMode,
        ReceiptCommitment,
        ResourceAmount,
        ResourcePricePerUnit,
        SequencerAddress,
        StarknetVersion,
        StateCommitment,
        Tip,
        TransactionCommitment,
        TransactionSignatureElem,
    };
    use pathfinder_crypto::signature::ecdsa_sign;
    use pathfinder_crypto::Felt;
    use pathfinder_executor::{ConcurrentStateReader, ExecutorWorkerPool};
    use pathfinder_merkle_tree::starknet_state::update_starknet_state;
    use pathfinder_storage::pruning::BlockchainHistoryMode;
    use pathfinder_storage::{Storage, TriePruneMode};
    use tempfile::tempdir;

    use crate::devnet::account::Account;
    use crate::devnet::class::{preprocess_sierra, PrepocessedSierra};
    use crate::devnet::{
        block_info,
        class,
        contract,
        fixtures,
        new_validator,
        strictly_increasing_timestamp,
    };
    use crate::state::block_hash::{
        calculate_event_commitment,
        calculate_receipt_commitment,
        calculate_transaction_commitment,
        compute_final_hash,
    };
    use crate::validator::{ProdTransactionMapper, ValidatorBlockInfoStage, ValidatorWorkerPool};

    #[test_log::test]
    fn init_declare_deploy_invoke_hello_abi() {
        use pathfinder_storage::StorageBuilder;

        // Block 0 - predeploys and initializes contracts, including the account we'll
        // use for testing
        // Block 1 - declare the Hello Starknet contract class
        let proposer = Address(Felt::ONE);
        let config = crate::devnet::init_db(proposer).unwrap();
        let path = config.bootstrap_db_path().to_owned();

        let storage = StorageBuilder::file(path)
            .migrate()
            .unwrap()
            .create_pool(
                NonZeroU32::new(5 + available_parallelism().unwrap().get() as u32).unwrap(),
            )
            .unwrap();

        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let block_1_header = db_txn.block_header(BlockId::Latest).unwrap().unwrap();
        let mut account = Account::from_storage(&db_txn).unwrap();
        drop(db_txn);

        let worker_pool: ValidatorWorkerPool =
            ExecutorWorkerPool::<ConcurrentStateReader>::new(1).get();

        // Block 2 - deploy a Hello Starknet contract instance via the UDC
        let block_2_number = block_1_header.number + 1;
        let mut validator = new_validator(
            block_2_number,
            proposer,
            block_1_header.timestamp,
            storage.clone(),
            worker_pool.clone(),
        );
        let deploy = account.hello_starknet_deploy().unwrap();
        validator
            .execute_batch::<ProdTransactionMapper>(vec![deploy])
            .unwrap();
        let block_2 = validator.consensus_finalize0().unwrap();

        let db_txn = db_conn.transaction().unwrap();
        let (block_2_header, hello_contract_address) =
            insert_block(storage.clone(), db_txn, block_2, block_1_header.hash);
        let hello_contract_address = hello_contract_address.unwrap();

        // Block 3 - invoke increase_balance and get_balance on the deployed Hello
        // Starknet instance
        let block_3_number = block_2_header.number + 1;
        let mut validator = new_validator(
            block_3_number,
            proposer,
            block_2_header.timestamp,
            storage.clone(),
            worker_pool.clone(),
        );
        let increase_balance = account.hello_starknet_increase_balance(hello_contract_address);
        let get_balance = account.hello_starknet_get_balance(hello_contract_address);
        validator
            .execute_batch::<ProdTransactionMapper>(vec![increase_balance, get_balance])
            .unwrap();
        let block_3 = validator.consensus_finalize0().unwrap();

        let db_txn = db_conn.transaction().unwrap();
        insert_block(storage.clone(), db_txn, block_3, block_2_header.hash);

        let worker_pool = Arc::into_inner(worker_pool).unwrap();
        worker_pool.join();
    }

    fn insert_block(
        storage: Storage,
        db_txn: pathfinder_storage::Transaction<'_>,
        block: ConsensusFinalizedL2Block,
        parent_hash: BlockHash,
    ) -> (BlockHeader, Option<ContractAddress>) {
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&block.state_update).into(),
            true,
            block.header.number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block;

        let hello_contract_address =
            state_update
                .contract_updates
                .iter()
                .find_map(|(contract_address, update)| {
                    update
                        .class
                        .is_some_and(|x| x.class_hash() == ClassHash(fixtures::HELLO_CLASS_HASH.0))
                        .then_some(*contract_address)
                });

        let header = header.compute_hash(parent_hash, state_commitment, compute_final_hash);

        db_txn.insert_block_header(&header).unwrap();
        db_txn
            .insert_state_update_data(header.number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(header.number, &transactions_and_receipts, Some(&events))
            .unwrap();
        db_txn.commit().unwrap();
        (header, hello_contract_address)
    }

    #[cfg(disable)]
    #[test]
    fn refactor_test_init_devnet() {
        use pathfinder_common::{BlockNumber, StarknetVersion, StateCommitment};
        use pathfinder_storage::StorageBuilder;

        let stopwatch = Instant::now();

        let config = crate::devnet::init_db().unwrap();

        eprintln!("{config:#?}");

        let path = config.bootstrap_db_path().to_owned();

        let storage = StorageBuilder::file(path)
            .trie_prune_mode(Some(TriePruneMode::Archive))
            .blockchain_history_mode(Some(BlockchainHistoryMode::Archive))
            .migrate()
            .unwrap()
            .create_pool(
                NonZeroU32::new(5 + available_parallelism().unwrap().get() as u32).unwrap(),
            )
            .unwrap();

        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let genesis_header = db_txn
            .block_header(BlockId::Number(BlockNumber::GENESIS))
            .unwrap()
            .unwrap();
        let timestamp = strictly_increasing_timestamp(Some(genesis_header.timestamp));

        let mut account = Account::from_storage(&db_txn).unwrap();

        let hello_class_hash = ClassHash(fixtures::HELLO_CLASS_HASH.0);

        let block_1_hash = db_txn
            .block_hash(BlockId::Number(BlockNumber::new_or_panic(1)))
            .unwrap()
            .unwrap();

        let stopwatch = Instant::now();

        let validator = ValidatorBlockInfoStage::new(
            ChainId::SEPOLIA_TESTNET,
            ProposalInit {
                height: 2,
                round: 0,
                valid_round: None,
                proposer: Address(Felt::ONE),
            },
        )
        .unwrap();

        let worker_pool: ValidatorWorkerPool =
            ExecutorWorkerPool::<ConcurrentStateReader>::new(1).get();

        let mut validator = validator
            .validate_block_info(
                BlockInfo {
                    height: 2,
                    builder: Address(Felt::ONE),
                    timestamp: timestamp.get() + 2,
                    l2_gas_price_fri: 1_000_000_000,
                    l1_gas_price_wei: 1_000_000_000,
                    l1_data_gas_price_wei: 1_000_000_000,
                    eth_to_fri_rate: 1_000_000_000,
                    l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
                },
                storage.clone(),
                None,
                None,
                worker_pool.clone(),
            )
            .unwrap();

        // Calldata structure for deployment via InvokeV3:
        // https://github.com/software-mansion/starknet-rust/blob/8c6e5eef7b2b19256ee643eefe742119188092e6/starknet-rust-accounts/src/single_owner.rs#L141
        //
        // Calldata structure for UDC:
        // https://docs.openzeppelin.com/contracts-cairo/2.x/udc
        // https://github.com/OpenZeppelin/cairo-contracts/blob/802735d432499124c684d28a5a0465ebf6c9cbdb/packages/presets/src/universal_deployer.cairo#L46
        //
        // "calldata": [
        //     /* Number of calls */
        //     "0x1",
        //     /* UDC address */
        //     "0x2ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125",
        //     /* Selector for 'deployContract' */
        //     "0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d",
        //     /* Calldata length */
        //     "0x4",
        //     /* UDC Calldata - class hash */
        //     "0x0457EF47CFAA819D9FE1372E8957815CDBA2252ED3E42A15536A5A40747C8A00",
        //     /* UDC Calldata - salt */
        //     "0x0",
        //     /* UDC Calldata - not_from_zero, 0 for origin independent deployment */
        //     "0x0",
        //     /* UDC Calldata - calldata to pass to the target contract */
        //     "0x0"
        // ],

        let selector = EntryPoint::hashed(b"deployContract");
        assert_eq!(
            selector,
            EntryPoint(felt!(
                "0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d"
            ))
        );

        let deploy = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: account.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // UDC address
                CallParam(fixtures::UDC_CONTRACT_ADDRESS.0),
                // Selector for 'deployContract'
                CallParam(selector.0),
                // Calldata length
                CallParam(Felt::from_u64(4)),
                // UDC Calldata - class hash
                CallParam(hello_class_hash.0),
                // UDC Calldata - salt
                CallParam::ZERO,
                // UDC Calldata - not_from_zero, 0 for origin independent deployment
                CallParam::ZERO,
                // UDC Calldata - calldata to pass to the target contract
                CallParam::ZERO,
            ],
            sender_address: account.address(),
            proof_facts: vec![],
        };

        eprintln!("Deploy transaction: {deploy:#?}");

        let mut variant = TransactionVariant::InvokeV3(deploy);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(deploy) = &mut variant else {
            unreachable!();
        };
        deploy.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(deploy) = variant else {
            unreachable!();
        };

        let deploy = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(deploy),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![deploy])
            .unwrap();

        let block_2 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 2: {block_2:#?}");

        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&block_2.state_update).into(),
            true,
            block_2.header.number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block_2;

        let hello_contract_address_block_2 = state_update
            .contract_updates
            .iter()
            .find_map(|(contract_address, update)| {
                update
                    .class
                    .is_some_and(|x| x.class_hash() == ClassHash(hello_class_hash.0))
                    .then_some(*contract_address)
            })
            .unwrap();

        let block_2_header =
            header.compute_hash(block_1_hash, state_commitment, compute_final_hash);
        let block_2_hash = block_2_header.hash;

        db_txn.insert_block_header(&block_2_header).unwrap();
        db_txn
            .insert_state_update_data(block_2_header.number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(
                block_2_header.number,
                &transactions_and_receipts,
                Some(&events),
            )
            .unwrap();
        db_txn.commit().unwrap();

        let computed_entry_point = EntryPoint::hashed(b"increase_balance").0;
        let expected_entry_point =
            felt!("0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320");
        assert_eq!(computed_entry_point, expected_entry_point);

        let validator = ValidatorBlockInfoStage::new(
            ChainId::SEPOLIA_TESTNET,
            ProposalInit {
                height: 3,
                round: 0,
                valid_round: None,
                proposer: Address(Felt::ONE),
            },
        )
        .unwrap();
        let mut validator = validator
            .validate_block_info(
                BlockInfo {
                    height: 3,
                    builder: Address(Felt::ONE),
                    timestamp: timestamp.get() + 3,
                    l2_gas_price_fri: 1_000_000_000,
                    l1_gas_price_wei: 1_000_000_000,
                    l1_data_gas_price_wei: 1_000_000_000,
                    eth_to_fri_rate: 1_000_000_000,
                    l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
                },
                storage.clone(),
                None,
                None,
                worker_pool.clone(),
            )
            .unwrap();

        let invoke = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: account.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // Hello contract address
                CallParam(hello_contract_address_block_2.0),
                // Selector for 'increase_balance'
                CallParam(EntryPoint::hashed(b"increase_balance").0),
                // Calldata length
                CallParam(Felt::ONE),
                // Hello starknet increase_balance argument
                CallParam(Felt::from_u64(0xFF)),
            ],
            sender_address: account.address(),
            proof_facts: vec![],
        };

        eprintln!("Invoke transaction: {invoke:#?}");

        let mut variant = TransactionVariant::InvokeV3(invoke);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(invoke) = &mut variant else {
            unreachable!();
        };
        invoke.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(invoke) = variant else {
            unreachable!();
        };

        let deploy = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(invoke),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![deploy])
            .unwrap();

        let block_3 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 3: {block_3:#?}");

        let block_number = BlockNumber::new_or_panic(3);
        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&state_update).into(),
            true,
            block_number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block_3;

        let block_3_header =
            header.compute_hash(block_2_hash, state_commitment, compute_final_hash);

        db_txn.insert_block_header(&block_3_header).unwrap();
        db_txn
            .insert_state_update_data(block_number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(block_number, &transactions_and_receipts, Some(&events))
            .unwrap();
        db_txn.commit().unwrap();

        let validator = ValidatorBlockInfoStage::new(
            ChainId::SEPOLIA_TESTNET,
            ProposalInit {
                height: 4,
                round: 0,
                valid_round: None,
                proposer: Address(Felt::ONE),
            },
        )
        .unwrap();

        let mut validator = validator
            .validate_block_info(
                BlockInfo {
                    height: 4,
                    builder: Address(Felt::ONE),
                    timestamp: timestamp.get() + 4,
                    l2_gas_price_fri: 1_000_000_000,
                    l1_gas_price_wei: 1_000_000_000,
                    l1_data_gas_price_wei: 1_000_000_000,
                    eth_to_fri_rate: 1_000_000_000,
                    l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
                },
                storage.clone(),
                None,
                None,
                worker_pool.clone(),
            )
            .unwrap();

        // Calldata structure for deployment via InvokeV3:
        // https://github.com/software-mansion/starknet-rust/blob/8c6e5eef7b2b19256ee643eefe742119188092e6/starknet-rust-accounts/src/single_owner.rs#L141
        //
        // Calldata structure for UDC:
        // https://docs.openzeppelin.com/contracts-cairo/2.x/udc
        // https://github.com/OpenZeppelin/cairo-contracts/blob/802735d432499124c684d28a5a0465ebf6c9cbdb/packages/presets/src/universal_deployer.cairo#L46
        //
        // "calldata": [
        //     /* Number of calls */
        //     "0x1",
        //     /* UDC address */
        //     "0x2ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125",
        //     /* Selector for 'deployContract' */
        //     "0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d",
        //     /* Calldata length */
        //     "0x4",
        //     /* UDC Calldata - class hash */
        //     "0x0457EF47CFAA819D9FE1372E8957815CDBA2252ED3E42A15536A5A40747C8A00",
        //     /* UDC Calldata - salt */
        //     "0x1",
        //     /* UDC Calldata - not_from_zero, 0 for origin independent deployment */
        //     "0x0",
        //     /* UDC Calldata - calldata to pass to the target contract */
        //     "0x0"
        // ],

        let selector = EntryPoint::hashed(b"deployContract");
        assert_eq!(
            selector,
            EntryPoint(felt!(
                "0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d"
            ))
        );

        let deploy = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: account.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // UDC address
                CallParam(fixtures::UDC_CONTRACT_ADDRESS.0),
                // Selector for 'deployContract'
                CallParam(selector.0),
                // Calldata length
                CallParam(Felt::from_u64(4)),
                // UDC Calldata - class hash
                CallParam(hello_class_hash.0),
                // UDC Calldata - salt
                CallParam(Felt::from_u64(1)),
                // UDC Calldata - not_from_zero, 0 for origin independent deployment
                CallParam::ZERO,
                // UDC Calldata - calldata to pass to the target contract
                CallParam::ZERO,
            ],
            sender_address: account.address(),
            proof_facts: vec![],
        };

        eprintln!("Deploy transaction: {deploy:#?}");

        let mut variant = TransactionVariant::InvokeV3(deploy);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(deploy) = &mut variant else {
            unreachable!();
        };
        deploy.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(deploy) = variant else {
            unreachable!();
        };

        let deploy = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(deploy),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![deploy])
            .unwrap();

        let block_4 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 4: {block_4:#?}");

        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&block_4.state_update).into(),
            true,
            block_4.header.number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block_4;

        let hello_contract_address_block_4 = state_update
            .contract_updates
            .iter()
            .find_map(|(contract_address, update)| {
                update
                    .class
                    .is_some_and(|x| x.class_hash() == ClassHash(hello_class_hash.0))
                    .then_some(*contract_address)
            })
            .unwrap();

        let block_4_header =
            header.compute_hash(block_1_hash, state_commitment, compute_final_hash);
        let block_4_hash = block_4_header.hash;

        db_txn.insert_block_header(&block_4_header).unwrap();
        db_txn
            .insert_state_update_data(block_4_header.number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(
                block_4_header.number,
                &transactions_and_receipts,
                Some(&events),
            )
            .unwrap();
        db_txn.commit().unwrap();

        let elapsed = stopwatch.elapsed();
        eprintln!(
            "Deploying hello starknet + invoking increase_balance: {} ms",
            elapsed.as_millis()
        );

        eprintln!("Hello contract address in block 2: {hello_contract_address_block_2}");
        eprintln!("Hello contract address in block 4: {hello_contract_address_block_4}");

        let computed_entry_point = EntryPoint::hashed(b"get_balance").0;
        let expected_entry_point =
            felt!("0x39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695");
        assert_eq!(computed_entry_point, expected_entry_point);

        let validator = ValidatorBlockInfoStage::new(
            ChainId::SEPOLIA_TESTNET,
            ProposalInit {
                height: 5,
                round: 0,
                valid_round: None,
                proposer: Address(Felt::ONE),
            },
        )
        .unwrap();
        let mut validator = validator
            .validate_block_info(
                BlockInfo {
                    height: 5,
                    builder: Address(Felt::ONE),
                    timestamp: timestamp.get() + 5,
                    l2_gas_price_fri: 1_000_000_000,
                    l1_gas_price_wei: 1_000_000_000,
                    l1_data_gas_price_wei: 1_000_000_000,
                    eth_to_fri_rate: 1_000_000_000,
                    l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
                },
                storage.clone(),
                None,
                None,
                worker_pool.clone(),
            )
            .unwrap();

        let invoke = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: account.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // Hello contract address
                CallParam(hello_contract_address_block_2.0),
                // Selector for 'get_balance'
                CallParam(EntryPoint::hashed(b"get_balance").0),
                // Calldata length
                CallParam(Felt::ZERO),
            ],
            sender_address: account.address(),
            proof_facts: vec![],
        };

        eprintln!("Invoke transaction: {invoke:#?}");

        let mut variant = TransactionVariant::InvokeV3(invoke);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(invoke) = &mut variant else {
            unreachable!();
        };
        invoke.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(invoke) = variant else {
            unreachable!();
        };

        let deploy = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(invoke),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![deploy])
            .unwrap();

        let block_5 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 5: {block_5:#?}");

        let block_number = BlockNumber::new_or_panic(5);
        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&state_update).into(),
            true,
            block_number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block_5;

        let block_5_header =
            header.compute_hash(block_4_hash, state_commitment, compute_final_hash);

        db_txn.insert_block_header(&block_5_header).unwrap();
        db_txn
            .insert_state_update_data(block_number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(block_number, &transactions_and_receipts, Some(&events))
            .unwrap();
        db_txn.commit().unwrap();

        let worker_pool = Arc::into_inner(worker_pool).unwrap();
        worker_pool.join();
    }

    #[cfg(disable)]
    #[test]
    fn backup_test_init_devnet() {
        use pathfinder_common::state_update::StateUpdateData;
        use pathfinder_common::{BlockNumber, StarknetVersion, StateCommitment};
        use pathfinder_storage::StorageBuilder;

        let stopwatch = Instant::now();

        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("bootstrap.sqlite");

        let storage = StorageBuilder::file(path)
            .trie_prune_mode(Some(TriePruneMode::Archive))
            .blockchain_history_mode(Some(BlockchainHistoryMode::Archive))
            .migrate()
            .unwrap()
            .create_pool(
                NonZeroU32::new(5 + available_parallelism().unwrap().get() as u32).unwrap(),
            )
            .unwrap();

        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let mut state_update = StateUpdateData::default();

        fixtures::PREDECLARED_CLASSES
            .iter()
            .copied()
            .for_each(|(class, class_hash)| {
                class::predeclare(&db_txn, &mut state_update, class, Some(class_hash)).unwrap()
            });

        fixtures::PREDEPLOYED_CONTRACTS.iter().copied().for_each(
            |(contract_address, class_hash)| {
                contract::predeploy(&mut state_update, contract_address, class_hash).unwrap()
            },
        );

        fixtures::ERC20S
            .iter()
            .copied()
            .for_each(|(contract_address, name, symbol)| {
                contract::erc20_init(&mut state_update, contract_address, name, symbol).unwrap();
            });

        let mut account = Account::new_from_fixture();
        account.predeploy(&mut state_update).unwrap();

        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&state_update).into(),
            true,
            BlockNumber::GENESIS,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let transaction_commitment =
            calculate_transaction_commitment(&[], StarknetVersion::V_0_14_0).unwrap();
        assert_eq!(transaction_commitment, TransactionCommitment::ZERO);
        eprintln!("Genesis transaction commitment: {transaction_commitment}");

        let receipt_commitment = calculate_receipt_commitment(&[]).unwrap();
        assert_eq!(receipt_commitment, ReceiptCommitment::ZERO);
        eprintln!("Genesis receipt commitment: {receipt_commitment}");

        let event_commitment = calculate_event_commitment(&[], StarknetVersion::V_0_14_0).unwrap();
        assert_eq!(event_commitment, EventCommitment::ZERO);
        eprintln!("Genesis event commitment: {event_commitment}");

        let timestamp = strictly_increasing_timestamp(None);
        let mut genesis_header = BlockHeader {
            hash: BlockHash::ZERO, // Will be updated
            parent_hash: BlockHash::ZERO,
            number: BlockNumber::GENESIS,
            timestamp,
            eth_l1_gas_price: GasPrice(1_000_000_000),
            strk_l1_gas_price: GasPrice(1_000_000_000),
            eth_l1_data_gas_price: GasPrice(1_000_000_000),
            strk_l1_data_gas_price: GasPrice(1_000_000_000),
            eth_l2_gas_price: GasPrice(1_000_000_000),
            strk_l2_gas_price: GasPrice(1_000_000_000),
            sequencer_address: SequencerAddress(Felt::ONE),
            starknet_version: StarknetVersion::V_0_14_0,
            event_commitment,
            state_commitment,
            transaction_commitment,
            transaction_count: 0,
            event_count: 0,
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            receipt_commitment,
            state_diff_commitment: state_update.compute_state_diff_commitment(),
            state_diff_length: state_update.state_diff_length(),
        };

        let block_hash = compute_final_hash(&genesis_header);
        genesis_header.hash = block_hash;

        db_txn.insert_block_header(&genesis_header).unwrap();
        db_txn
            .insert_state_update_data(BlockNumber::GENESIS, &state_update)
            .unwrap();
        db_txn.commit().unwrap();

        let hello_sierra_ser_incompatible = fixtures::HELLO_CLASS;
        let PrepocessedSierra {
            sierra_class_hash: hello_class_hash,
            sierra_class_ser: hello_sierra_ser_compatible,
            cairo1_class_p2p: hello_cairo1_class_p2p,
            casm_hash_v2: hello_casm_hash_v2,
            casm: hello_casm,
        } = preprocess_sierra(hello_sierra_ser_incompatible, None).unwrap();

        // let (hello_class_hash, sierra, hello_casm_hash_v2, hello_casm) =
        //     preprocess_sierra(hello_sierra_ser_incompatible).unwrap();
        eprintln!("Hello class hash: {hello_class_hash}");
        eprintln!("Hello casm hash v2: {hello_casm_hash_v2}");
        // let hello_sierra_ser_compatible = serde_json::to_vec(&sierra).unwrap();

        let worker_pool: ValidatorWorkerPool =
            ExecutorWorkerPool::<ConcurrentStateReader>::new(1).get();

        let validator = ValidatorBlockInfoStage::new(
            ChainId::SEPOLIA_TESTNET,
            ProposalInit {
                height: 1,
                round: 0,
                valid_round: None,
                proposer: Address(Felt::ONE),
            },
        )
        .unwrap();
        let mut validator = validator
            .validate_block_info(
                BlockInfo {
                    height: 1,
                    builder: Address(Felt::ONE),
                    timestamp: timestamp.get() + 1,
                    l2_gas_price_fri: 1_000_000_000,
                    l1_gas_price_wei: 1_000_000_000,
                    l1_data_gas_price_wei: 1_000_000_000,
                    eth_to_fri_rate: 1_000_000_000,
                    l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
                },
                storage.clone(),
                None,
                None,
                worker_pool.clone(),
            )
            .unwrap();

        let declare = DeclareTransactionV3 {
            class_hash: ClassHash(hello_class_hash.0),
            nonce: account.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            signature: vec![/* Will be filled after signing */],
            account_deployment_data: vec![],
            sender_address: account.address(),
            compiled_class_hash: hello_casm_hash_v2,
        };
        let mut variant = TransactionVariant::DeclareV3(declare);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::DeclareV3(declare) = &mut variant else {
            unreachable!();
        };
        declare.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        eprintln!("DTO: {variant:#?}");

        let p2p_proto::sync::transaction::TransactionVariant::DeclareV3(DeclareV3WithoutClass {
            common,
            class_hash,
        }) = variant
        else {
            unreachable!();
        };

        let declare = p2p_proto::transaction::DeclareV3WithClass {
            common,
            class: hello_cairo1_class_p2p,
        };

        // let Sierra {
        //     abi,
        //     sierra_program,
        //     contract_class_version,
        //     entry_points_by_type,
        // } = sierra;
        // let declare = p2p_proto::transaction::DeclareV3WithClass {
        //     common,
        //     class: p2p_proto::class::Cairo1Class {
        //         abi: abi.into_owned(),
        //         entry_points: p2p_proto::class::Cairo1EntryPoints {
        //             externals: entry_points_by_type
        //                 .external
        //                 .into_iter()
        //                 .map(|x| p2p_proto::class::SierraEntryPoint {
        //                     index: x.function_idx,
        //                     selector: x.selector.0,
        //                 })
        //                 .collect(),
        //             l1_handlers: entry_points_by_type
        //                 .l1_handler
        //                 .into_iter()
        //                 .map(|x| p2p_proto::class::SierraEntryPoint {
        //                     index: x.function_idx,
        //                     selector: x.selector.0,
        //                 })
        //                 .collect(),
        //             constructors: entry_points_by_type
        //                 .constructor
        //                 .into_iter()
        //                 .map(|x| p2p_proto::class::SierraEntryPoint {
        //                     index: x.function_idx,
        //                     selector: x.selector.0,
        //                 })
        //                 .collect(),
        //         },
        //         program: sierra_program,
        //         contract_class_version: contract_class_version.into_owned(),
        //     },
        // };
        let declare = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::DeclareV3(declare),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![declare])
            .unwrap();

        let block_1 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 1: {block_1:#?}");

        let block_number = BlockNumber::new_or_panic(1);
        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&state_update).into(),
            true,
            block_number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block_1;

        let header = header.compute_hash(genesis_header.hash, state_commitment, compute_final_hash);

        db_txn.insert_block_header(&header).unwrap();

        // Insert classes before state update because the latter will trigger
        // `upsert_declared_at` and insert a NULL definition
        db_txn
            .insert_sierra_class_definition(
                &hello_class_hash,
                &hello_sierra_ser_compatible,
                &hello_casm,
                &hello_casm_hash_v2,
            )
            .unwrap();

        drop(hello_sierra_ser_compatible);
        drop(hello_casm);

        db_txn
            .insert_state_update_data(block_number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(block_number, &transactions_and_receipts, Some(&events))
            .unwrap();
        db_txn.commit().unwrap();

        let elapsed = stopwatch.elapsed();
        eprintln!(
            "Init + declaring hello starknet: {} ms",
            elapsed.as_millis()
        );

        let stopwatch = Instant::now();

        let validator = ValidatorBlockInfoStage::new(
            ChainId::SEPOLIA_TESTNET,
            ProposalInit {
                height: 2,
                round: 0,
                valid_round: None,
                proposer: Address(Felt::ONE),
            },
        )
        .unwrap();
        let mut validator = validator
            .validate_block_info(
                BlockInfo {
                    height: 2,
                    builder: Address(Felt::ONE),
                    timestamp: timestamp.get() + 2,
                    l2_gas_price_fri: 1_000_000_000,
                    l1_gas_price_wei: 1_000_000_000,
                    l1_data_gas_price_wei: 1_000_000_000,
                    eth_to_fri_rate: 1_000_000_000,
                    l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
                },
                storage.clone(),
                None,
                None,
                worker_pool.clone(),
            )
            .unwrap();

        // Calldata structure for deployment via InvokeV3:
        // https://github.com/software-mansion/starknet-rust/blob/8c6e5eef7b2b19256ee643eefe742119188092e6/starknet-rust-accounts/src/single_owner.rs#L141
        //
        // Calldata structure for UDC:
        // https://docs.openzeppelin.com/contracts-cairo/2.x/udc
        // https://github.com/OpenZeppelin/cairo-contracts/blob/802735d432499124c684d28a5a0465ebf6c9cbdb/packages/presets/src/universal_deployer.cairo#L46
        //
        // "calldata": [
        //     /* Number of calls */
        //     "0x1",
        //     /* UDC address */
        //     "0x2ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125",
        //     /* Selector for 'deployContract' */
        //     "0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d",
        //     /* Calldata length */
        //     "0x4",
        //     /* UDC Calldata - class hash */
        //     "0x0457EF47CFAA819D9FE1372E8957815CDBA2252ED3E42A15536A5A40747C8A00",
        //     /* UDC Calldata - salt */
        //     "0x0",
        //     /* UDC Calldata - not_from_zero, 0 for origin independent deployment */
        //     "0x0",
        //     /* UDC Calldata - calldata to pass to the target contract */
        //     "0x0"
        // ],

        let selector = EntryPoint::hashed(b"deployContract");
        assert_eq!(
            selector,
            EntryPoint(felt!(
                "0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d"
            ))
        );

        let deploy = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: account.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // UDC address
                CallParam(fixtures::UDC_CONTRACT_ADDRESS.0),
                // Selector for 'deployContract'
                CallParam(selector.0),
                // Calldata length
                CallParam(Felt::from_u64(4)),
                // UDC Calldata - class hash
                CallParam(hello_class_hash.0),
                // UDC Calldata - salt
                CallParam::ZERO,
                // UDC Calldata - not_from_zero, 0 for origin independent deployment
                CallParam::ZERO,
                // UDC Calldata - calldata to pass to the target contract
                CallParam::ZERO,
            ],
            sender_address: account.address(),
            proof_facts: vec![],
        };

        eprintln!("Deploy transaction: {deploy:#?}");

        let mut variant = TransactionVariant::InvokeV3(deploy);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(deploy) = &mut variant else {
            unreachable!();
        };
        deploy.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(deploy) = variant else {
            unreachable!();
        };

        let deploy = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(deploy),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![deploy])
            .unwrap();

        let block_2 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 2: {block_2:#?}");

        let block_number = BlockNumber::new_or_panic(2);
        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&state_update).into(),
            true,
            block_number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block_2;

        let hello_contract_address = state_update
            .contract_updates
            .iter()
            .find_map(|(contract_address, update)| {
                update
                    .class
                    .is_some_and(|x| x.class_hash() == ClassHash(hello_class_hash.0))
                    .then_some(*contract_address)
            })
            .unwrap();

        let header = header.compute_hash(genesis_header.hash, state_commitment, compute_final_hash);

        db_txn.insert_block_header(&header).unwrap();
        db_txn
            .insert_state_update_data(block_number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(block_number, &transactions_and_receipts, Some(&events))
            .unwrap();
        db_txn.commit().unwrap();

        let computed_entry_point = EntryPoint::hashed(b"increase_balance").0;
        let expected_entry_point =
            felt!("0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320");
        assert_eq!(computed_entry_point, expected_entry_point);

        let validator = ValidatorBlockInfoStage::new(
            ChainId::SEPOLIA_TESTNET,
            ProposalInit {
                height: 3,
                round: 0,
                valid_round: None,
                proposer: Address(Felt::ONE),
            },
        )
        .unwrap();
        let mut validator = validator
            .validate_block_info(
                BlockInfo {
                    height: 3,
                    builder: Address(Felt::ONE),
                    timestamp: timestamp.get() + 3,
                    l2_gas_price_fri: 1_000_000_000,
                    l1_gas_price_wei: 1_000_000_000,
                    l1_data_gas_price_wei: 1_000_000_000,
                    eth_to_fri_rate: 1_000_000_000,
                    l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
                },
                storage.clone(),
                None,
                None,
                worker_pool.clone(),
            )
            .unwrap();

        let invoke = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: account.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(1_000_000),
                    max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // Hello contract address
                CallParam(hello_contract_address.0),
                // Selector for 'increase_balance'
                CallParam(EntryPoint::hashed(b"increase_balance").0),
                // Calldata length
                CallParam(Felt::ONE),
                // Hello starknet increase_balance argument
                CallParam(Felt::from_u64(0xFF)),
            ],
            sender_address: account.address(),
            proof_facts: vec![],
        };

        eprintln!("Invoke transaction: {invoke:#?}");

        let mut variant = TransactionVariant::InvokeV3(invoke);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(account.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(invoke) = &mut variant else {
            unreachable!();
        };
        invoke.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(invoke) = variant else {
            unreachable!();
        };

        let deploy = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(invoke),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![deploy])
            .unwrap();

        let block_3 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 3: {block_3:#?}");

        let block_number = BlockNumber::new_or_panic(3);
        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&state_update).into(),
            true,
            block_number,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        let ConsensusFinalizedL2Block {
            header,
            state_update,
            transactions_and_receipts,
            events,
        } = block_3;

        let header = header.compute_hash(genesis_header.hash, state_commitment, compute_final_hash);

        db_txn.insert_block_header(&header).unwrap();
        db_txn
            .insert_state_update_data(block_number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(block_number, &transactions_and_receipts, Some(&events))
            .unwrap();
        db_txn.commit().unwrap();

        let elapsed = stopwatch.elapsed();
        eprintln!(
            "Deploying hello starknet + invoking increase_balance: {} ms",
            elapsed.as_millis()
        );

        let worker_pool = Arc::into_inner(worker_pool).unwrap();
        worker_pool.join();
    }
}
