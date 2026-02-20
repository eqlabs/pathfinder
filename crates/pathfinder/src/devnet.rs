//! Utilities for initializing a devnet for development and testing purposes.
//! Heavily inspired by [starknet-devnet](https://github.com/0xSpaceShard/starknet-devnet) v0.7.1.
//! Unfortunately we cannot use `starknet-devnet` directly because it is not
//! state/storage API agnostic.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::thread::available_parallelism;
use std::time::{Instant, SystemTime};

use anyhow::Context;
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
use crate::devnet::class::{preprocess_sierra, PrepocessedSierraClass};
use crate::state::block_hash::compute_final_hash;
use crate::validator::{ProdTransactionMapper, ValidatorBlockInfoStage, ValidatorWorkerPool};

mod account;
mod class;
mod contract;
mod fixtures;
mod utils;

/// Some nonzero gas price
const GAS_PRICE: GasPrice = GasPrice(1_000_000_000);
/// WEI to FRI conversion rate is 1:1 for simplicity, so ETH to FRI conversion
/// rate is 1:1e18
const ETH_TO_FRI_RATE: u128 = 1_000_000_000_000_000_000;
/// Alice from integration tests
const PROPOSER_ADDRESS: Address = Address(Felt::ONE);

/// Initializes a devnet DB. The following contracts are predeclared,
/// predeployed and initialized if necessary: Cairo 1 account, ETH and STRK
/// ERC20s, and the UDC. The following contract is already declared but not
/// deployed: Hello Starknet.
pub fn init_db() -> anyhow::Result<DevnetConfig> {
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

    let mut db_conn = storage.connection()?;
    let db_txn = db_conn.transaction()?;
    let mut state_update = StateUpdateData::default();

    let (chargeable_account, account) = predeploy_contracts(&db_txn, &mut state_update)?;

    eprintln!(
        "Chargeable account address: {}",
        chargeable_account.address()
    );
    eprintln!("Account address: {}", account.address());

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
        sequencer_address: SequencerAddress(Felt::ONE),
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
) -> anyhow::Result<()> {
    let PrepocessedSierraClass {
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
    let next_timestamp = strictly_increasing_timestamp(Some(latest_header.timestamp));

    let validator = new_validator(next_block_number);
    let mut validator = validator
        .validate_block_info(
            block_info(next_block_number, next_timestamp),
            storage.clone(),
            None,
            None,
            worker_pool.clone(),
        )
        .unwrap();

    let declare = DeclareTransactionV3 {
        class_hash: ClassHash(sierra_class_hash.0),
        nonce: account.fetch_add_nonce(),
        nonce_data_availability_mode: DataAvailabilityMode::L1,
        fee_data_availability_mode: DataAvailabilityMode::L1,
        resource_bounds: resource_bounds(),
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
        class_hash,
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

    todo!()
}

/// Predeclare, predeploy, and initialize if necessary: Cairo 1 account, ETH and
/// STRK ERC20s, and the UDC.
fn predeploy_contracts(
    db_txn: &pathfinder_storage::Transaction<'_>,
    state_update: &mut StateUpdateData,
) -> Result<(Account, Account), anyhow::Error> {
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
    let mut accounts = Vec::new();
    [
        (
            Felt::ONE, // Keep ECDSA happy
            fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
            None,
        ),
        (
            fixtures::CHARGEABLE_ACCOUNT_PRIVATE_KEY,
            fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
            Some(fixtures::CHARGEABLE_ACCOUNT_ADDRESS),
        ),
    ]
    .iter()
    .copied()
    .try_for_each(|(private_key, sierra_hash, address)| {
        let account = Account::new(private_key, address)?;
        account.predeploy(state_update)?;
        accounts.push(account);
        anyhow::Ok(())
    })?;
    let chargeable_account = accounts.pop().expect("2 items");
    let account = accounts.pop().expect("1 item");
    // TODO this is not really necessary here, we only need to return the private
    // key of the non-chargeable account. From that we can recreate the entire
    // account, compute the address, etc.
    Ok((chargeable_account, account))
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

/// Create a new validator for the given block height.
fn new_validator(height: BlockNumber) -> ValidatorBlockInfoStage {
    ValidatorBlockInfoStage::new(
        ChainId::SEPOLIA_TESTNET,
        ProposalInit {
            height: height.get(),
            round: 0,
            valid_round: None,
            proposer: PROPOSER_ADDRESS,
        },
    )
    .expect("valid block height")
}

/// Block info for devnet blocks, sufficient for execution, provided that gas
/// prices are not validated against any oracle.
fn block_info(height: BlockNumber, prev_timestamp: BlockTimestamp) -> BlockInfo {
    BlockInfo {
        height: height.get(),
        builder: PROPOSER_ADDRESS,
        timestamp: strictly_increasing_timestamp(Some(prev_timestamp)).get(),
        l2_gas_price_fri: GAS_PRICE.0,
        l1_gas_price_wei: GAS_PRICE.0,
        l1_data_gas_price_wei: GAS_PRICE.0,
        eth_to_fri_rate: ETH_TO_FRI_RATE,
        l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
    }
}

/// Transaction resource_bounds for devnet transactions, sufficient for
/// execution.
fn resource_bounds() -> ResourceBounds {
    ResourceBounds {
        l1_gas: ResourceBound {
            max_amount: ResourceAmount(1_000_000),
            max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
        },
        l2_gas: ResourceBound {
            max_amount: ResourceAmount(1_000_000),
            max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
        },
        l1_data_gas: None,
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
        CallParam,
        ChainId,
        ClassHash,
        ConsensusFinalizedL2Block,
        EntryPoint,
        EventCommitment,
        GasPrice,
        L1DataAvailabilityMode,
        ReceiptCommitment,
        ResourceAmount,
        ResourcePricePerUnit,
        SequencerAddress,
        Tip,
        TransactionCommitment,
        TransactionSignatureElem,
    };
    use pathfinder_crypto::signature::ecdsa_sign;
    use pathfinder_crypto::Felt;
    use pathfinder_executor::{ConcurrentStateReader, ExecutorWorkerPool};
    use pathfinder_merkle_tree::starknet_state::update_starknet_state;
    use pathfinder_storage::pruning::BlockchainHistoryMode;
    use pathfinder_storage::TriePruneMode;
    use tempfile::tempdir;

    use crate::devnet::account::Account;
    use crate::devnet::class::{preprocess_sierra, PrepocessedSierraClass};
    use crate::devnet::{
        block_info,
        class,
        contract,
        fixtures,
        new_validator,
        resource_bounds,
        strictly_increasing_timestamp,
    };
    use crate::state::block_hash::{
        calculate_event_commitment,
        calculate_receipt_commitment,
        calculate_transaction_commitment,
        compute_final_hash,
    };
    use crate::validator::{ProdTransactionMapper, ValidatorBlockInfoStage, ValidatorWorkerPool};

    // #[test_log::test(test)]
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

        let mut account = Account::new(config.account_private_key(), None).unwrap();

        let hello_sierra_ser_incompatible = fixtures::HELLO_CLASS;
        let PrepocessedSierraClass {
            sierra_class_hash: hello_class_hash,
            cairo1_class_p2p: hello_cairo1_class_p2p,
            sierra_class_ser: hello_sierra_ser_compatible,
            casm_hash_v2: hello_casm_hash_v2,
            casm: hello_casm,
        } = preprocess_sierra(hello_sierra_ser_incompatible, None).unwrap();
        eprintln!("Hello class hash: {hello_class_hash}");
        eprintln!("Hello casm hash v2: {hello_casm_hash_v2}");

        let worker_pool: ValidatorWorkerPool =
            ExecutorWorkerPool::<ConcurrentStateReader>::auto().get();

        let block_1_height = BlockNumber::new_or_panic(1);
        let validator = new_validator(block_1_height);
        let mut validator = validator
            .validate_block_info(
                block_info(block_1_height, timestamp),
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
            resource_bounds: resource_bounds(),
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
        let declare = p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::DeclareV3(declare),
            transaction_hash: Hash(txn_hash.0),
        };

        validator
            .execute_batch::<ProdTransactionMapper>(vec![declare])
            .unwrap();

        let block_1 = validator.consensus_finalize0().unwrap();
        eprintln!("Block 1: {block_1:#?}");

        let genesis_hash = db_txn
            .block_hash(BlockId::Number(BlockNumber::GENESIS))
            .unwrap()
            .unwrap();

        eprintln!("Genesis hash: {genesis_hash}");

        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&block_1.state_update).into(),
            true,
            block_1.header.number,
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

        let header_1 = header.compute_hash(genesis_hash, state_commitment, compute_final_hash);
        let block_1_hash = header_1.hash;

        db_txn.insert_block_header(&header_1).unwrap();

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
            .insert_state_update_data(header_1.number, &state_update)
            .unwrap();
        db_txn
            .insert_transaction_data(header_1.number, &transactions_and_receipts, Some(&events))
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
            (&block_2.state_update).into(),
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

        let block_2_header =
            header.compute_hash(block_1_hash, state_commitment, compute_final_hash);
        let block_2_hash = block_2_header.hash;

        db_txn.insert_block_header(&block_2_header).unwrap();
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

        let header = header.compute_hash(block_2_hash, state_commitment, compute_final_hash);

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

    #[cfg(disabled)]
    #[test_log::test(test)]
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

        let mut accounts = Vec::new();
        [
            (
                Felt::from_u64(1 /* Keep ECDSA happy */),
                fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
                None,
            ),
            (
                fixtures::CHARGEABLE_ACCOUNT_PRIVATE_KEY,
                fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
                Some(fixtures::CHARGEABLE_ACCOUNT_ADDRESS),
            ),
        ]
        .iter()
        .copied()
        .for_each(|(private_key, class_hash, address)| {
            let account = Account::new(private_key, address).unwrap();
            account.predeploy(&mut state_update).unwrap();
            accounts.push(account);
        });
        let chargeable_account = accounts.pop().unwrap();
        let mut account = accounts.pop().unwrap();

        eprintln!(
            "Chargeable account address: {}",
            chargeable_account.address()
        );
        eprintln!("Account address: {}", account.address());

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
        let (hello_class_hash, sierra, hello_casm_hash_v2, hello_casm) =
            preprocess_sierra(hello_sierra_ser_incompatible).unwrap();
        eprintln!("Hello class hash: {hello_class_hash}");
        eprintln!("Hello casm hash v2: {hello_casm_hash_v2}");
        let hello_sierra_ser_compatible = serde_json::to_vec(&sierra).unwrap();

        let worker_pool: ValidatorWorkerPool =
            ExecutorWorkerPool::<ConcurrentStateReader>::auto().get();

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
        let Sierra {
            abi,
            sierra_program,
            contract_class_version,
            entry_points_by_type,
        } = sierra;
        let declare = p2p_proto::transaction::DeclareV3WithClass {
            common,
            class: p2p_proto::class::Cairo1Class {
                abi: abi.into_owned(),
                entry_points: p2p_proto::class::Cairo1EntryPoints {
                    externals: entry_points_by_type
                        .external
                        .into_iter()
                        .map(|x| p2p_proto::class::SierraEntryPoint {
                            index: x.function_idx,
                            selector: x.selector.0,
                        })
                        .collect(),
                    l1_handlers: entry_points_by_type
                        .l1_handler
                        .into_iter()
                        .map(|x| p2p_proto::class::SierraEntryPoint {
                            index: x.function_idx,
                            selector: x.selector.0,
                        })
                        .collect(),
                    constructors: entry_points_by_type
                        .constructor
                        .into_iter()
                        .map(|x| p2p_proto::class::SierraEntryPoint {
                            index: x.function_idx,
                            selector: x.selector.0,
                        })
                        .collect(),
                },
                program: sierra_program,
                contract_class_version: contract_class_version.into_owned(),
            },
        };
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
