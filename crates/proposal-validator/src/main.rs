use core::panic;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::str::FromStr;
use std::usize;

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
use pathfinder_common::event::Event;
use pathfinder_common::receipt::{ExecutionStatus, L2ToL1Message, Receipt};
use pathfinder_common::state_update::{ContractClassUpdate, StateUpdateData};
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    class_definition,
    BlockHash,
    BlockHeader,
    BlockNumber,
    BlockTimestamp,
    ChainId,
    ClassHash,
    ContractAddress,
    ContractNonce,
    EntryPoint,
    L1DataAvailabilityMode,
    SequencerAddress,
    StateCommitment,
    StateUpdate,
    TransactionHash,
    TransactionIndex,
};
use pathfinder_crypto::Felt;
use pathfinder_executor::types::{
    DeclaredSierraClass,
    DeployedContract,
    ReplacedClass,
    StateDiff,
    ETH_TO_WEI_RATE,
};
use pathfinder_executor::{ClassInfo, IntoStarkFelt, Validator};
use pathfinder_lib::state::block_hash::{
    calculate_event_commitment,
    calculate_receipt_commitment,
    calculate_transaction_commitment,
    BlockHeaderData,
};
use pathfinder_merkle_tree::starknet_state::update_starknet_state;
use pathfinder_rpc::context::{ETH_FEE_TOKEN_ADDRESS, STRK_FEE_TOKEN_ADDRESS};
use pathfinder_rpc::map_transaction_variant;
use pathfinder_storage::StorageBuilder;
use rayon::prelude::*;
use starknet_api::block;
use starknet_api::contract_class::SierraVersion;
use starknet_api::core::PatriciaKey;
use starknet_api::transaction::fields::Fee;
use tracing::debug;

/*
fn compute_final_hash_v1(header: &BlockHeaderData) -> BlockHash {
    // Hash the block header.
    let mut hasher = PoseidonHasher::new();
   +hasher.write(felt_bytes!(b"STARKNET_BLOCK_HASH1").into());
   +hasher.write(header.number.get().into());
    hasher.write(header.state_commitment.0.into());
  ?+hasher.write(header.sequencer_address.0.into());
   +hasher.write(header.timestamp.get().into());
    hasher.write(concatenate_counts(header));
   +hasher.write(header.state_diff_commitment.0.into());
   +hasher.write(header.transaction_commitment.0.into());
   +hasher.write(header.event_commitment.0.into());
   +hasher.write(header.receipt_commitment.0.into());
   +hasher.write(gas_prices_to_hash(header));
 ---hasher.write(
        Felt::from_be_slice(header.starknet_version_str.as_bytes())
            .expect("Starknet version should fit into a felt")
            .into(),
    );
   +hasher.write(MontFelt::ZERO);
   +hasher.write(header.parent_hash.0.into());
    BlockHash(hasher.finish().into())
}
*/

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ReceiptWithoutExecutionResources {
    pub actual_fee: pathfinder_common::Fee,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_hash: TransactionHash,
    pub transaction_index: TransactionIndex,
}

impl From<Receipt> for ReceiptWithoutExecutionResources {
    fn from(receipt: Receipt) -> Self {
        Self {
            actual_fee: receipt.actual_fee,
            l2_to_l1_messages: receipt.l2_to_l1_messages,
            execution_status: receipt.execution_status,
            transaction_hash: receipt.transaction_hash,
            transaction_index: receipt.transaction_index,
        }
    }
}

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
        .create_pool(
            connection_pool_capacity
                .try_into()
                .expect("Max number of threads < 2^32-1"),
        )
        .context("Creating connection pool")?;

    let mut db_conn = storage.connection().context("Create database connection")?;

    let db_txn = db_conn
        .transaction()
        .context("Create database transaction")?;

    let (mut proposal, expected_header, expected_transactions, expected_receipts, expected_events) =
        create_proposal(&db_txn, block_number)?;

    let expected_state_update = db_txn
        .state_update(block_number.into())?
        .context("State update not found")?;

    // TODO verify
    assert!(matches!(
        proposal.pop_front().expect("Proposal init"),
        ProposalPart::ProposalInit(_)
    ));

    let Some(ProposalPart::BlockInfo(block_info)) = proposal.pop_front() else {
        panic!("Expected block info");
    };

    let block_number = BlockNumber::new_or_panic(block_info.height);
    let block_timestamp = BlockTimestamp::new_or_panic(block_info.timestamp);

    // TODO verify
    assert!(matches!(
        proposal.pop_back().expect("Proposal fin"),
        ProposalPart::ProposalFin(_)
    ));

    let part = proposal.pop_front().expect("Transaction batch");
    let ProposalPart::TransactionBatch(txns) = part else {
        panic!("Expected transaction batch");
    };

    use p2p_proto::common::L1DataAvailabilityMode::{Blob, Calldata};

    let txns = txns
        .into_iter()
        .map(map_transaction)
        .collect::<anyhow::Result<Vec<_>>>()
        .expect("Mapping into executor transactions");
    let (common_txn_variants, executor_txns): (Vec<_>, Vec<_>) = txns.into_iter().unzip();

    let txn_hashes = common_txn_variants
        .par_iter()
        .map(|v| v.calculate_hash(ChainId::SEPOLIA_TESTNET, false))
        .collect::<Vec<_>>();

    let common_txns = common_txn_variants
        .into_iter()
        .zip(txn_hashes.iter().copied())
        .map(|(variant, hash)| Transaction { hash, variant })
        .collect::<Vec<_>>();

    let transaction_commitment =
        calculate_transaction_commitment(&common_txns, expected_header.starknet_version)?;

    let block_info = pathfinder_executor::types::BlockInfo::try_from_proposal(
        block_info.height,
        block_info.timestamp,
        SequencerAddress(block_info.builder.0),
        match block_info.l1_da_mode {
            Calldata => L1DataAvailabilityMode::Calldata,
            Blob => L1DataAvailabilityMode::Blob,
        },
        block_info.l2_gas_price_fri,
        block_info.l1_gas_price_wei,
        block_info.l1_data_gas_price_wei,
        block_info.eth_to_fri_rate,
        expected_header.starknet_version,
        // TODO workaround for inconsistent ethfri rate in the blocks
        expected_header.eth_l2_gas_price.0,
        expected_header.strk_l1_gas_price.0,
        expected_header.strk_l1_data_gas_price.0,
    )?;

    let mut validator = Validator::new(
        ChainId::SEPOLIA_TESTNET,
        block_info,
        ETH_FEE_TOKEN_ADDRESS,
        STRK_FEE_TOKEN_ADDRESS,
        db_txn,
    )?;

    let (receipts, events): (Vec<_>, Vec<_>) =
        validator.execute(executor_txns)?.into_iter().unzip();

    let state_diff = validator.finalize()?;

    let receipts = receipts
        .into_iter()
        .zip(txn_hashes.iter().copied())
        .enumerate()
        .map(|(idx, (r, h))| Receipt {
            transaction_hash: h,
            transaction_index: TransactionIndex::new_or_panic(
                idx.try_into().expect("idx < i64::MAX"),
            ),
            ..r
        })
        .collect::<Vec<_>>();

    let receipt_commitment = calculate_receipt_commitment(&receipts)?;

    let events_ref_by_txn = events
        .iter()
        .zip(txn_hashes.iter().copied())
        .map(|(e, h)| (h, e.as_slice()))
        .collect::<Vec<_>>();
    let event_commitment =
        calculate_event_commitment(&events_ref_by_txn, expected_header.starknet_version)?;

    let events = events
        .into_iter()
        .zip(txn_hashes.iter().copied())
        .map(|(e, h)| (h, e))
        .collect::<Vec<_>>();

    // Compare transactions, receipts, events
    pretty_assertions_sorted::assert_eq!(
        common_txns,
        expected_transactions,
        "Comparing transactions: actual vs expected"
    );

    let receipts = receipts
        .into_iter()
        .map(ReceiptWithoutExecutionResources::from)
        .collect::<Vec<_>>();

    let expected_receipts = expected_receipts
        .into_iter()
        .map(ReceiptWithoutExecutionResources::from)
        .collect::<Vec<_>>();

    // TODO FIXME Execution resources dont match but is this important?
    // Because they're not hashed to get the receipt commitment.
    pretty_assertions_sorted::assert_eq!(
        receipts,
        expected_receipts,
        "Comparing receipts: actual vs expected EXCEPT execution resources"
    );

    pretty_assertions_sorted::assert_eq!(
        events,
        expected_events,
        "Comparing events: actual vs expected"
    );

    // Compare transaction-, receipt-, event- commitments
    assert_eq!(
        transaction_commitment,
        expected_header.transaction_commitment
    );
    assert_eq!(receipt_commitment, expected_header.receipt_commitment);
    assert_eq!(event_commitment, expected_header.event_commitment);

    /*
    let expected_state_diff = StateUpdateData::from(expected_state_update).into();
    pretty_assertions_sorted::assert_eq!(
        state_diff,
        expected_state_diff,
        "Comparing state updates: actual vs expected"
    );
    */

    let expected_state_update: StateUpdateData = expected_state_update.into();
    let state_update: StateUpdateData = state_diff.into();
    pretty_assertions_sorted::assert_eq!(
        state_update,
        expected_state_update,
        "Comparing state updates: actual vs expected"
    );

    let state_update_commitment = state_update.compute_state_diff_commitment();
    assert_eq!(
        state_update_commitment, expected_header.state_diff_commitment,
        "Comparing state diff commitments: actual vs expected"
    );

    let mut db_conn = storage.connection().context("Create database connection")?;
    let db_txn = db_conn
        .transaction()
        .context("Create database transaction")?;

    let (storage_commitment, class_commitment) = update_starknet_state(
        &db_txn,
        (&state_update).into(),
        true,
        expected_header.number,
        storage,
    )?;

    let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);

    assert_eq!(
        state_commitment, expected_header.state_commitment,
        "Comparing state commitments: actual vs expected"
    );

    let bhd = BlockHeaderData {
        // TODO FIXME we need a BlockHeader type, without the block hash
        hash: BlockHash::ZERO,
        parent_hash: expected_header.parent_hash,
        number: block_number,
        timestamp: block_timestamp,
        sequencer_address: todo!(),
        state_commitment,
        state_diff_commitment: todo!(),
        transaction_commitment,
        transaction_count: todo!(),
        event_commitment,
        event_count: todo!(),
        state_diff_length: todo!(),
        starknet_version: todo!(),
        starknet_version_str: todo!(),
        eth_l1_gas_price: todo!(),
        strk_l1_gas_price: todo!(),
        eth_l1_data_gas_price: todo!(),
        strk_l1_data_gas_price: todo!(),
        eth_l2_gas_price: todo!(),
        strk_l2_gas_price: todo!(),
        receipt_commitment,
        l1_da_mode: todo!(),
    };

    debug!("Proposal validation completed successfully");

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

fn map_transaction(
    transaction: p2p_proto::consensus::Transaction,
) -> anyhow::Result<(
    pathfinder_common::transaction::TransactionVariant,
    pathfinder_executor::Transaction,
)> {
    let p2p_proto::consensus::Transaction {
        txn,
        transaction_hash,
    } = transaction;
    let (variant, class_info) = match txn {
        ConsensusVariant::DeclareV3(DeclareV3WithClass { common, class }) => {
            (SyncVariant::DeclareV3(common), Some(class_info(class)?))
        }
        ConsensusVariant::DeployAccountV3(v) => (SyncVariant::DeployAccountV3(v), None),
        ConsensusVariant::InvokeV3(v) => (SyncVariant::InvokeV3(v), None),
        ConsensusVariant::L1HandlerV0(v) => (SyncVariant::L1HandlerV0(v), None),
    };

    let common_txn_variant = TransactionVariant::try_from_dto(variant)
        .expect("Proposal part was generated from a valid DB");

    let deployed_address = deployed_address(&common_txn_variant, true);

    // TODO why 10^12?
    let paid_fee_on_l1 = match &common_txn_variant {
        TransactionVariant::L1Handler(_) => Some(Fee(1_000_000_000_000)),
        _ => None,
    };

    let api_txn = map_transaction_variant(common_txn_variant.clone())?;
    let tx_hash = starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt());
    let executor_txn = pathfinder_executor::Transaction::from_api(
        api_txn,
        tx_hash,
        class_info,
        paid_fee_on_l1,
        deployed_address,
        pathfinder_executor::AccountTransactionExecutionFlags::default(),
    )?;

    Ok((common_txn_variant, executor_txn))
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
) -> anyhow::Result<(
    VecDeque<ProposalPart>,
    BlockHeader,
    Vec<Transaction>,
    Vec<Receipt>,
    Vec<(TransactionHash, Vec<Event>)>,
)> {
    let header = db_txn
        .block_header(block_number.into())?
        .context("Block not found")?;

    debug!("header: {header:#?}");

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

    // let wei_l2_gas_price = if header.eth_l2_gas_price.0 == 0 {
    //     warn!("wei L2 gas price is 0, correcting to 1");
    //     1
    // } else {
    //     header.eth_l2_gas_price.0
    // };

    // let fri_l2_gas_price = if header.strk_l2_gas_price.0 == 0 {
    //     warn!("fri L2 gas price is 0, correcting to 1");
    //     1
    // } else {
    //     header.strk_l2_gas_price.0
    // };

    // debug!(
    //     "header.eth_l1_data_gas_price.0: {}",
    //     header.eth_l1_data_gas_price.0
    // );
    // debug!("wei_l2_gas_price: {}", wei_l2_gas_price);
    // debug!("fri_l2_gas_price: {}", fri_l2_gas_price);
    // debug!(
    //     "wei_l2_gas_price * ETH_TO_WEI_RATE / fri_l2_gas_price: {}",
    //     wei_l2_gas_price * ETH_TO_WEI_RATE / fri_l2_gas_price
    // );
    // debug!(
    //     "fri_l2_gas_price * ETH_TO_WEI_RATE / wei_l2_gas_price: {}",
    //     fri_l2_gas_price * ETH_TO_WEI_RATE / wei_l2_gas_price
    // );

    proposal_parts.push_back(ProposalPart::BlockInfo(BlockInfo {
        height,
        timestamp: header.timestamp.get(),
        // Decent random value
        builder: Address(header.sequencer_address.0),
        l1_da_mode: match header.l1_da_mode {
            L1DataAvailabilityMode::Calldata => Calldata,
            L1DataAvailabilityMode::Blob => Blob,
        },
        l2_gas_price_fri: header.strk_l2_gas_price.0,
        l1_gas_price_wei: header.eth_l1_gas_price.0,
        l1_data_gas_price_wei: header.eth_l1_data_gas_price.0,
        eth_to_fri_rate: header.strk_l1_gas_price.0 * ETH_TO_WEI_RATE / header.eth_l1_gas_price.0,
    }));

    let (txns, receipts): (Vec<_>, Vec<_>) = db_txn
        .transactions_with_receipts_for_block(block_number.into())?
        .context("Block not found")?
        .into_iter()
        // TODO for testing -- start
        .skip(0)
        .take(usize::MAX)
        // TODO for testing -- end
        .unzip();
    let events = db_txn
        .events_for_block(block_number.into())?
        .context("Block not found")?
        .into_iter()
        // TODO for testing -- start
        .skip(0)
        .take(usize::MAX)
        // TODO for testing -- end
        .collect();

    // debug!("txn 1: {:#?}", txns[1]);

    let consensus_txns = txns
        .clone()
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

    proposal_parts.push_back(ProposalPart::TransactionBatch(consensus_txns));

    proposal_parts.push_back(ProposalPart::ProposalFin(ProposalFin {
        // FIXME
        proposal_commitment: Hash(Felt::from_u64(42)),
    }));

    Ok((proposal_parts, header, txns, receipts, events))
}
