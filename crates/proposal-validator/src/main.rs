use core::panic;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::iter::Extend;
use std::str::FromStr;

use anyhow::Context;
use p2p::sync::client::conv::{ToDto, TryFromDto};
use p2p_proto::class::Cairo1Class;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{
    BlockInfo,
    ProposalFin,
    ProposalInit,
    ProposalPart,
    TransactionVariant as ConsensusVariant,
};
use p2p_proto::transaction::{DeclareV3WithClass, TransactionVariant as SyncVariant};
use pathfinder_common::class_definition::{SelectorAndFunctionIndex, SierraEntryPoints};
use pathfinder_common::state_update::{ContractClassUpdate, StateUpdateData};
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    class_definition,
    BlockHeader,
    BlockNumber,
    ChainId,
    ClassHash,
    ContractAddress,
    ContractNonce,
    EntryPoint,
    L1DataAvailabilityMode,
    StateUpdate,
    StorageAddress,
    StorageValue,
};
use pathfinder_crypto::Felt;
use pathfinder_executor::types::{
    DeclaredSierraClass,
    DeployedContract,
    ReplacedClass,
    StateDiff,
    StorageDiff,
    TransactionSimulation,
};
use pathfinder_executor::{ClassInfo, ExecutionState, IntoStarkFelt};
use pathfinder_rpc::context::{ETH_FEE_TOKEN_ADDRESS, STRK_FEE_TOKEN_ADDRESS};
use pathfinder_rpc::map_transaction_variant;
use pathfinder_storage::StorageBuilder;
use starknet_api::contract_class::SierraVersion;
use starknet_api::core::PatriciaKey;
use starknet_api::transaction::fields::Fee;
use tracing::{debug, error, info, trace, warn};
use util::percentage::Percentage;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    debug!("Starting proposal validator");

    let database_path = std::env::args()
        .nth(1)
        .context("Please provide the database path as the first argument")?;

    let block_number = std::env::args()
        .nth(2)
        .context("Please provide the block number as the second argument")?
        .parse::<u64>()
        .context("Parsing block number")?;
    let block_number = BlockNumber::new(block_number).context("Parsing block number")?;

    // A wild guess based on pathfiner's `main()`
    let connection_pool_capacity = std::thread::available_parallelism()
        .context("Getting number of logical CPUs")?
        .checked_add(5)
        .expect(">5");

    let storage = StorageBuilder::file(database_path.into())
        .migrate()
        .context("Migrating database")?
        .create_read_only_pool(
            connection_pool_capacity
                .try_into()
                .expect("Max number of threads < 2^32-1"),
        )
        .context("Creating connection pool")?;

    let mut db_conn = storage.connection().context("Create database connection")?;

    let db_txn = db_conn
        .transaction()
        .context("Create database transaction")?;

    let (mut proposal, header) = create_proposal(&db_txn, block_number)?;

    let execution_state = ExecutionState::trace(
        ChainId::SEPOLIA_TESTNET,
        header,
        None,
        Default::default(),
        ETH_FEE_TOKEN_ADDRESS,
        STRK_FEE_TOKEN_ADDRESS,
        None,
    );

    // TODO verify
    assert!(matches!(
        proposal.pop_front().expect("Proposal init"),
        ProposalPart::ProposalInit(_)
    ));

    // TODO verify
    assert!(matches!(
        proposal.pop_front().expect("Block info"),
        ProposalPart::BlockInfo(_)
    ));

    // TODO verify
    assert!(matches!(
        proposal.pop_back().expect("Proposal fin"),
        ProposalPart::ProposalFin(_)
    ));

    let part = proposal.pop_front().expect("Transaction batch");
    let ProposalPart::TransactionBatch(txns) = part else {
        panic!("Expected transaction batch");
    };

    execute_batch(db_txn, execution_state, txns, block_number);

    Ok(())
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct StateDiffWithoutStorage {
    pub deployed_contracts: BTreeSet<DeployedContract>,
    pub deprecated_declared_classes: BTreeSet<ClassHash>,
    pub declared_classes: BTreeSet<DeclaredSierraClass>,
    pub nonces: BTreeMap<ContractAddress, ContractNonce>,
    pub replaced_classes: BTreeSet<ReplacedClass>,
}

impl From<&StateDiff> for StateDiffWithoutStorage {
    fn from(src: &StateDiff) -> Self {
        Self {
            deployed_contracts: src.deployed_contracts.iter().cloned().collect(),
            deprecated_declared_classes: src.deprecated_declared_classes.iter().copied().collect(),
            declared_classes: src.declared_classes.iter().cloned().collect(),
            nonces: src.nonces.iter().map(|(k, v)| (*k, *v)).collect(),
            replaced_classes: src.replaced_classes.iter().cloned().collect(),
        }
    }
}

impl From<&StateUpdate> for StateDiffWithoutStorage {
    fn from(src: &StateUpdate) -> Self {
        Self {
            deployed_contracts: src
                .contract_updates
                .iter()
                .filter_map(|(contract_address, contract_update)| {
                    contract_update.class.and_then(|update| match update {
                        ContractClassUpdate::Deploy(class_hash) => Some(DeployedContract {
                            address: *contract_address,
                            class_hash,
                        }),
                        ContractClassUpdate::Replace(_) => None,
                    })
                })
                .collect(),
            deprecated_declared_classes: src.declared_cairo_classes.iter().copied().collect(),
            declared_classes: src
                .declared_sierra_classes
                .iter()
                .map(|(sierra_hash, casm_hash)| DeclaredSierraClass {
                    class_hash: *sierra_hash,
                    compiled_class_hash: *casm_hash,
                })
                .collect(),
            nonces: src
                .contract_updates
                .iter()
                .filter_map(|(contract_address, contract_update)| {
                    contract_update
                        .nonce
                        .map(|nonce| (*contract_address, nonce))
                })
                .collect(),
            replaced_classes: src
                .contract_updates
                .iter()
                .filter_map(|(contract_address, contract_update)| {
                    contract_update.class.and_then(|update| match update {
                        ContractClassUpdate::Deploy(_) => None,
                        ContractClassUpdate::Replace(class_hash) => Some(ReplacedClass {
                            contract_address: *contract_address,
                            class_hash,
                        }),
                    })
                })
                .collect(),
        }
    }
}

fn execute_batch(
    db_tx: pathfinder_storage::Transaction<'_>,
    execution_state: ExecutionState,
    txns: Vec<p2p_proto::consensus::Transaction>,
    block_number: BlockNumber,
) {
    let expected_state_update = db_tx
        .state_update(block_number.into())
        .expect("DB is fine")
        .expect("Block exists");

    let txns = txns
        .into_iter()
        .map(compose_executor_transaction)
        .collect::<anyhow::Result<Vec<_>>>()
        .expect("Mapping into executor transactions");

    // Tuple:
    // (collected after each transaction execution,
    // vs
    // taken from the cached state of the executor after all were executed)
    let (txn_sims, state_changes_after_execution) =
        match pathfinder_executor::simulate2(db_tx, execution_state, txns, Percentage::new(0)) {
            Ok(x) => x,
            Err(error) => {
                error!(?error);
                return;
            }
        };

    let mut actual_storage: BTreeMap<ContractAddress, BTreeMap<StorageAddress, StorageValue>> =
        BTreeMap::new();
    txn_sims.iter().for_each(|txn_sim| {
        let storage_diffs = &txn_sim.state_diff().storage_diffs;
        storage_diffs
            .iter()
            .for_each(|(contract_address, storage)| {
                // IMPORTANT!!! Consecutive storage value updates to the same key are lost
                // except for the last one
                actual_storage.entry(*contract_address).or_default().extend(
                    storage
                        .iter()
                        .map(|StorageDiff { key, value }| (*key, *value)),
                );
            });
    });

    let mut actual_storage2: BTreeMap<ContractAddress, BTreeMap<StorageAddress, StorageValue>> =
        BTreeMap::new();
    state_changes_after_execution
        .storage_diffs
        .iter()
        .for_each(|(contract_address, storage)| {
            // IMPORTANT!!! Consecutive storage value updates to the same key are lost
            // except for the last one
            actual_storage2
                .entry(*contract_address)
                .or_default()
                .extend(
                    storage
                        .iter()
                        .map(|StorageDiff { key, value }| (*key, *value)),
                );
        });

    let expected_storage = expected_state_update
        .contract_updates
        .iter()
        .map(|(contract_address, update)| (contract_address, &update.storage))
        .chain(
            expected_state_update
                .system_contract_updates
                .iter()
                .map(|(contract_address, update)| (contract_address, &update.storage)),
        )
        .filter_map(|(contract_address, storage)| {
            let storage = storage
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect::<BTreeMap<_, _>>();
            // Omit contracts that have no storage updates
            (!storage.is_empty()).then_some((*contract_address, storage))
        })
        .collect::<BTreeMap<ContractAddress, BTreeMap<StorageAddress, StorageValue>>>();

    // pretty_assertions_sorted::assert_eq!(actual_storage, expected_storage,
    // "Actual vs Expected");
    pretty_assertions_sorted::assert_eq!(actual_storage2, expected_storage, "Actual2 vs Expected");
    // pretty_assertions_sorted::assert_eq!(actual_storage, actual_storage2,
    // "Actual vs Actual2");
    println!("Actual storage updates match expected ones!");

    let actual_rest = StateDiffWithoutStorage::from(&state_changes_after_execution);
    let expected_rest = StateDiffWithoutStorage::from(&expected_state_update);

    pretty_assertions_sorted::assert_eq!(
        actual_rest,
        expected_rest,
        "The rest: Actual vs Expected"
    );

    println!("The rest also matches!");

    // TODO validate other parts of the state update
}

// Based on [`pathfinder_rpc::executor::compose_executor_transaction`]
// TODO deduplicate the code with
// `pathfinder_rpc::executor::compose_executor_transaction` and move it to the
// executor crate
fn compose_executor_transaction(
    transaction: p2p_proto::consensus::Transaction,
) -> anyhow::Result<pathfinder_executor::Transaction> {
    let p2p_proto::consensus::Transaction {
        txn,
        transaction_hash,
    } = transaction;
    let (v, class_info) = match txn {
        ConsensusVariant::DeclareV3(DeclareV3WithClass { common, class }) => {
            (SyncVariant::DeclareV3(common), Some(class_info(class)?))
        }
        ConsensusVariant::DeployAccountV3(v) => (SyncVariant::DeployAccountV3(v), None),
        ConsensusVariant::InvokeV3(v) => (SyncVariant::InvokeV3(v), None),
        ConsensusVariant::L1HandlerV0(v) => (SyncVariant::L1HandlerV0(v), None),
    };

    let v =
        TransactionVariant::try_from_dto(v).expect("Proposal part was generated from a valid DB");

    let deployed_address = deployed_address(&v, true);

    // TODO why 10^12?
    let paid_fee_on_l1 = match &v {
        TransactionVariant::L1Handler(_) => Some(Fee(1_000_000_000_000)),
        _ => None,
    };

    let transaction = map_transaction_variant(v)?;
    let tx_hash = starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt());
    let tx = pathfinder_executor::Transaction::from_api(
        transaction,
        tx_hash,
        class_info,
        paid_fee_on_l1,
        deployed_address,
        pathfinder_executor::AccountTransactionExecutionFlags::default(),
    )?;

    Ok(tx)
}

fn class_info(class: Cairo1Class) -> anyhow::Result<ClassInfo> {
    let Cairo1Class {
        abi,
        entry_points,
        program,
        contract_class_version,
    } = class;

    let abi_length = abi.len();
    let sierra_program_length = program.len();
    let sierra_version =
        SierraVersion::from_str(&contract_class_version).context("Getting sierra version")?;

    let class_definition = class_definition::Sierra {
        abi: abi.into(),
        sierra_program: program,
        contract_class_version: contract_class_version.into(),
        entry_points_by_type: SierraEntryPoints {
            constructor: entry_points
                .constructors
                .into_iter()
                .map(|x| SelectorAndFunctionIndex {
                    selector: EntryPoint(x.selector),
                    function_idx: x.index,
                })
                .collect(),
            external: entry_points
                .externals
                .into_iter()
                .map(|x| SelectorAndFunctionIndex {
                    selector: EntryPoint(x.selector),
                    function_idx: x.index,
                })
                .collect(),
            l1_handler: entry_points
                .l1_handlers
                .into_iter()
                .map(|x| SelectorAndFunctionIndex {
                    selector: EntryPoint(x.selector),
                    function_idx: x.index,
                })
                .collect(),
        },
    };
    // TODO this is suboptimal, the same surplus serialization happens in the
    // broadcasted transactions case
    let class_definition =
        serde_json::to_vec(&class_definition).context("Serializing Sierra class definition")?;
    // TODO compile_to_casm should also accept a deserialized class definition
    let casm_contract_definition = pathfinder_compiler::compile_to_casm(&class_definition)
        .context("Compiling Sierra class definition to CASM")?;

    let casm_contract_definition = pathfinder_executor::parse_casm_definition(
        casm_contract_definition,
        sierra_version.clone(),
    )
    .context("Parsing CASM contract definition")?;
    let ci = ClassInfo::new(
        &casm_contract_definition,
        sierra_program_length,
        abi_length,
        sierra_version,
    )?;
    Ok(ci)
}

fn deployed_address(
    txnv: &TransactionVariant,
    is_proposal: bool,
) -> Option<starknet_api::core::ContractAddress> {
    match txnv {
        TransactionVariant::DeployAccountV3(t) => Some(starknet_api::core::ContractAddress(
            PatriciaKey::try_from(t.contract_address.get().into_starkfelt())
                .expect("No contract address overflow expected"),
        )),
        TransactionVariant::DeclareV3(_)
        | TransactionVariant::InvokeV3(_)
        | TransactionVariant::L1Handler(_) => None,
        TransactionVariant::DeclareV0(_)
        | TransactionVariant::DeclareV1(_)
        | TransactionVariant::DeclareV2(_)
        | TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_)
        | TransactionVariant::DeployAccountV1(_)
        | TransactionVariant::InvokeV0(_)
        | TransactionVariant::InvokeV1(_) => {
            if is_proposal {
                unreachable!("Proposal parts don't carry older transaction versions: {txnv:?}")
            } else {
                None
            }
        }
    }
}

/// Create a valid sequence of proposal parts for the given block.
fn create_proposal(
    db_txn: &pathfinder_storage::Transaction,
    block_number: BlockNumber,
) -> anyhow::Result<(VecDeque<ProposalPart>, BlockHeader)> {
    let header = db_txn
        .block_header(block_number.into())?
        .context("Block not found")?;

    trace!(?header);

    let mut proposal_parts = VecDeque::new();
    let height = header.number.get();

    proposal_parts.push_back(ProposalPart::ProposalInit(ProposalInit {
        height,
        // Decent random value
        round: 42,
        // FIXME
        valid_round: None,
        // Decent random value
        proposer: Address(Felt::from_u64(42)),
    }));

    use p2p_proto::common::L1DataAvailabilityMode::{Blob, Calldata};

    const ETHWEI: u128 = 1_000_000_000_000_000_000;

    let wei_l2_gas_price = if header.eth_l2_gas_price.0 == 0 {
        warn!("wei L2 gas price is 0, correcting to 1");
        1
    } else {
        header.eth_l2_gas_price.0
    };

    let fri_l2_gas_price = if header.strk_l2_gas_price.0 == 0 {
        warn!("fri L2 gas price is 0, correcting to 1");
        1
    } else {
        header.strk_l2_gas_price.0
    };

    proposal_parts.push_back(ProposalPart::BlockInfo(BlockInfo {
        height,
        timestamp: header.timestamp.get(),
        // Decent random value
        builder: Address(Felt::from_u64(42)),
        l1_da_mode: match header.l1_da_mode {
            L1DataAvailabilityMode::Calldata => Calldata,
            L1DataAvailabilityMode::Blob => Blob,
        },
        l2_gas_price_fri: fri_l2_gas_price,
        l1_gas_price_wei: header.eth_l1_gas_price.0,
        l1_data_gas_price_wei: header.eth_l1_data_gas_price.0,
        // Eth/Fri = Wei * 10^18 / Fri
        eth_to_fri_rate: wei_l2_gas_price * ETHWEI / fri_l2_gas_price,
    }));

    let txns = db_txn
        .transactions_for_block(block_number.into())?
        .context("Block not found")?;

    let txns = txns
        .into_iter()
        .map(|Transaction { hash, variant }| {
            use TransactionVariant::{DeclareV3, DeployAccountV3, InvokeV3, L1Handler};
            let sync_variant = if matches!(
                variant,
                DeclareV3(_) | DeployAccountV3(_) | InvokeV3(_) | L1Handler(_)
            ) {
                Ok(variant.to_dto())
            } else {
                Err(anyhow::anyhow!(
                    "Unsupported transaction variant: {:?}",
                    variant
                ))
            }?;
            let consensus_variant = match sync_variant {
                SyncVariant::DeclareV3(common) => {
                    let class = db_txn
                        .class_definition(ClassHash(common.class_hash.0))?
                        .context("Class not found")?;
                    let class =
                        serde_json::from_slice::<class_definition::Sierra<'_>>(&class)?.to_dto();
                    let v = p2p_proto::transaction::DeclareV3WithClass { common, class };
                    ConsensusVariant::DeclareV3(v)
                }
                SyncVariant::DeployAccountV3(v) => ConsensusVariant::DeployAccountV3(v),
                SyncVariant::InvokeV3(v) => ConsensusVariant::InvokeV3(v),
                SyncVariant::L1HandlerV0(v) => ConsensusVariant::L1HandlerV0(v),
                _ => unreachable!("Unsupported transaction variants already excluded"),
            };
            Ok(p2p_proto::consensus::Transaction {
                txn: consensus_variant,
                transaction_hash: Hash(hash.0),
            })
        })
        .collect::<anyhow::Result<_>>()?;

    proposal_parts.push_back(ProposalPart::TransactionBatch(txns));

    proposal_parts.push_back(ProposalPart::ProposalFin(ProposalFin {
        // FIXME
        proposal_commitment: Hash(Felt::from_u64(42)),
    }));

    Ok((proposal_parts, header))
}
