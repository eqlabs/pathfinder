use std::str::FromStr;
use std::time::Instant;

use anyhow::Context;
use p2p::sync::client::conv::TryFromDto;
use p2p_proto::class::Cairo1Class;
use p2p_proto::common::Hash;
use p2p_proto::consensus::{
    BlockInfo,
    ProposalFin,
    ProposalInit,
    TransactionVariant as ConsensusVariant,
};
use p2p_proto::sync::transaction::{DeclareV3WithoutClass, TransactionVariant as SyncVariant};
use p2p_proto::transaction::DeclareV3WithClass;
use pathfinder_common::class_definition::{SelectorAndFunctionIndex, SierraEntryPoints};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    class_definition,
    BlockHash,
    BlockHeader,
    BlockNumber,
    ChainId,
    EntryPoint,
    L1DataAvailabilityMode,
    SequencerAddress,
    StarknetVersion,
    StateCommitment,
    TransactionHash,
};
use pathfinder_executor::types::{to_starknet_api_transaction, BlockInfoPriceConverter};
use pathfinder_executor::{BlockExecutor, ClassInfo, IntoStarkFelt};
use pathfinder_merkle_tree::starknet_state::update_starknet_state;
use pathfinder_rpc::context::{ETH_FEE_TOKEN_ADDRESS, STRK_FEE_TOKEN_ADDRESS};
use pathfinder_storage::Storage;
use rayon::prelude::*;
use tracing::debug;

use crate::state::block_hash::{
    self,
    calculate_event_commitment,
    calculate_receipt_commitment,
    calculate_transaction_commitment,
};

pub fn new(
    chain_id: ChainId,
    proposal_init: ProposalInit,
) -> anyhow::Result<ValidatorBlockInfoStage> {
    ValidatorBlockInfoStage::new(chain_id, proposal_init)
}

#[derive(Debug)]
pub struct ValidatorBlockInfoStage {
    chain_id: ChainId,
    proposal_height: BlockNumber,
}

impl ValidatorBlockInfoStage {
    pub fn new(
        chain_id: ChainId,
        proposal_init: ProposalInit,
    ) -> anyhow::Result<ValidatorBlockInfoStage> {
        // TODO(validator) how can we validate the proposal init?
        Ok(ValidatorBlockInfoStage {
            chain_id,
            proposal_height: BlockNumber::new(proposal_init.block_number)
                .context("ProposalInit height exceeds i64::MAX")?,
        })
    }

    pub fn validate_block_info(
        self,
        block_info: BlockInfo,
        workaround_starknet_version: StarknetVersion,
        db_conn: pathfinder_storage::Connection,
        // TODO eth_to_fri_rate is not suitable for current L2 data where there are 3 pairs of gas
        // prices in both wei & fri and they give 2 different ethfri rates
        workaround_l2_gas_price_wei: u128,
        workaround_l1_gas_price_fri: u128,
        workaround_l1_data_gas_price_fri: u128,
    ) -> anyhow::Result<ValidatorTransactionBatchStage> {
        let _span = tracing::debug_span!(
            "Validator::validate_block_info",
            height = %block_info.block_number,
            timestamp = %block_info.timestamp,
            builder = %block_info.builder.0,
        )
        .entered();

        let Self {
            chain_id,
            proposal_height,
        } = self;

        anyhow::ensure!(
            proposal_height == block_info.block_number,
            "ProposalInit height does not match BlockInfo height: {} != {}",
            proposal_height,
            block_info.block_number,
        );

        // TODO(validator) validate block info (timestamp, gas prices)

        let BlockInfo {
            block_number,
            timestamp,
            builder,
            l1_da_mode,
            l2_gas_price_fri,
            l1_gas_price_wei,
            l1_data_gas_price_wei,
            eth_to_strk_rate: _,
        } = block_info;

        let block_info = pathfinder_executor::types::BlockInfo::try_from_proposal(
            block_number,
            timestamp,
            SequencerAddress(builder.0),
            match l1_da_mode {
                p2p_proto::common::L1DataAvailabilityMode::Blob => L1DataAvailabilityMode::Blob,
                p2p_proto::common::L1DataAvailabilityMode::Calldata => {
                    L1DataAvailabilityMode::Calldata
                }
            },
            BlockInfoPriceConverter::legacy(
                l2_gas_price_fri,
                l1_gas_price_wei,
                l1_data_gas_price_wei,
                workaround_l2_gas_price_wei,
                workaround_l1_gas_price_fri,
                workaround_l1_data_gas_price_fri,
            ),
            workaround_starknet_version,
        )
        .context("Creating internal BlockInfo representation")?;

        let block_executor = BlockExecutor::new(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            db_conn,
        )
        .context("Creating BlockExecutor")?;

        Ok(ValidatorTransactionBatchStage {
            chain_id,
            block_info,
            block_executor,
            transactions: Vec::new(),
            receipts: Vec::new(),
            events: Vec::new(),
        })
    }

    pub fn validate_consensus_block_info(
        self,
        block_info: BlockInfo,
        db_conn: pathfinder_storage::Connection,
    ) -> anyhow::Result<ValidatorTransactionBatchStage> {
        let _span = tracing::debug_span!(
            "Validator::validate_block_info",
            height = %block_info.block_number,
            timestamp = %block_info.timestamp,
            builder = %block_info.builder.0,
        )
        .entered();

        let Self {
            chain_id,
            proposal_height,
        } = self;

        anyhow::ensure!(
            proposal_height == block_info.block_number,
            "ProposalInit height does not match BlockInfo height: {} != {}",
            proposal_height,
            block_info.block_number,
        );

        // TODO(validator) validate block info (timestamp, gas prices)

        let BlockInfo {
            block_number,
            timestamp,
            builder,
            l1_da_mode,
            l2_gas_price_fri,
            l1_gas_price_wei,
            l1_data_gas_price_wei,
            eth_to_strk_rate,
        } = block_info;

        let block_info = pathfinder_executor::types::BlockInfo::try_from_proposal(
            block_number,
            timestamp,
            SequencerAddress(builder.0),
            match l1_da_mode {
                p2p_proto::common::L1DataAvailabilityMode::Blob => L1DataAvailabilityMode::Blob,
                p2p_proto::common::L1DataAvailabilityMode::Calldata => {
                    L1DataAvailabilityMode::Calldata
                }
            },
            BlockInfoPriceConverter::consensus(
                l2_gas_price_fri,
                l1_gas_price_wei,
                l1_data_gas_price_wei,
                eth_to_strk_rate,
            ),
            StarknetVersion::new(0, 14, 0, 0), /* TODO(validator) should probably come from
                                                * somewhere... */
        )
        .context("Creating internal BlockInfo representation")?;

        let block_executor = BlockExecutor::new(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            db_conn,
        )
        .context("Creating BlockExecutor")?;

        Ok(ValidatorTransactionBatchStage {
            chain_id,
            block_info,
            block_executor,
            transactions: Vec::new(),
            receipts: Vec::new(),
            events: Vec::new(),
        })
    }
}

pub struct ValidatorTransactionBatchStage {
    chain_id: ChainId,
    block_info: pathfinder_executor::types::BlockInfo,
    block_executor: BlockExecutor,
    transactions: Vec<Transaction>,
    receipts: Vec<Receipt>,
    events: Vec<Vec<Event>>,
}

impl ValidatorTransactionBatchStage {
    pub fn execute_transactions(
        &mut self,
        transactions: Vec<p2p_proto::consensus::Transaction>,
    ) -> anyhow::Result<()> {
        let _span = tracing::debug_span!(
            "Validator::execute_transactions",
            height = %self.block_info.number,
            batch_size = %transactions.len(),
        )
        .entered();

        if transactions.is_empty() {
            // TODO(validator) is an empty batch valid?
            return Ok(());
        }

        let start = Instant::now();

        let txns = transactions
            .into_iter()
            .map(try_map_transaction)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (mut common_txns, executor_txns): (Vec<_>, Vec<_>) = txns.into_iter().unzip();

        let txn_hashes = common_txns
            .par_iter()
            .map(|t| {
                if t.verify_hash(self.chain_id) {
                    Ok(t.hash)
                } else {
                    Err(anyhow::anyhow!(
                        "Transaction hash mismatch, expected: {}",
                        t.hash
                    ))
                }
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .context("Verifying transaction hashes")?;

        let (receipts, mut events): (Vec<_>, Vec<_>) = self
            .block_executor
            .execute(executor_txns)?
            .into_iter()
            .unzip();

        let mut receipts = receipts
            .into_iter()
            .zip(txn_hashes)
            .map(|(receipt, hash)| Receipt {
                actual_fee: receipt.actual_fee,
                execution_resources: receipt.execution_resources,
                l2_to_l1_messages: receipt.l2_to_l1_messages,
                execution_status: receipt.execution_status,
                transaction_hash: hash,
                transaction_index: receipt.transaction_index,
            })
            .collect::<Vec<_>>();

        let start_idx = receipts
            .first()
            .expect("At least one transaction")
            .transaction_index
            .get();
        let end_idx = receipts
            .last()
            .expect("At least one transaction")
            .transaction_index
            .get();

        self.transactions.append(&mut common_txns);
        self.receipts.append(&mut receipts);
        self.events.append(&mut events);

        debug!(
            "Executed {} transactions ({}..={}) in {} ms",
            self.transactions.len(),
            start_idx,
            end_idx,
            start.elapsed().as_millis()
        );

        Ok(())
    }

    /// Does not compute the state commitment and block hash. Returns
    /// `Ok(Ok(ValidatorFinalizeStage))` if the expected block header
    /// matches the computed one, `Ok(Err((expected, actual)))` if they do
    /// not match, `Err` if there was an error during finalization.
    pub fn finalize(
        self,
        mut expected_block_header: BlockHeader,
    ) -> anyhow::Result<Result<ValidatorFinalizeStage, (BlockHeader, BlockHeader)>> {
        let _span = tracing::debug_span!(
            "Validator::finalize0",
            height = %self.block_info.number,
            num_transactions = %self.transactions.len(),
        )
        .entered();

        let start = Instant::now();

        let state_diff = self.block_executor.finalize()?;

        let transaction_commitment =
            calculate_transaction_commitment(&self.transactions, self.block_info.starknet_version)?;
        let receipt_commitment = calculate_receipt_commitment(&self.receipts)?;
        let events_ref_by_txn = self
            .events
            .iter()
            .zip(self.transactions.iter().map(|t| t.hash))
            .map(|(e, h)| (h, e.as_slice()))
            .collect::<Vec<_>>();
        let event_commitment =
            calculate_event_commitment(&events_ref_by_txn, self.block_info.starknet_version)?;

        let state_update = StateUpdateData::from(state_diff);
        let state_diff_commitment = state_update.compute_state_diff_commitment();

        expected_block_header.hash = BlockHash::ZERO; // UNUSED
        expected_block_header.parent_hash = BlockHash::ZERO; // UNUSED
        expected_block_header.state_commitment = StateCommitment::ZERO; // UNUSED

        let header = BlockHeader {
            hash: BlockHash::ZERO,        // UNUSED
            parent_hash: BlockHash::ZERO, // UNUSED
            number: self.block_info.number,
            timestamp: self.block_info.timestamp,
            eth_l1_gas_price: self.block_info.eth_l1_gas_price,
            strk_l1_gas_price: self.block_info.strk_l1_gas_price,
            eth_l1_data_gas_price: self.block_info.eth_l1_data_gas_price,
            strk_l1_data_gas_price: self.block_info.strk_l1_data_gas_price,
            eth_l2_gas_price: self.block_info.eth_l2_gas_price,
            strk_l2_gas_price: self.block_info.strk_l2_gas_price,
            sequencer_address: self.block_info.sequencer_address,
            starknet_version: self.block_info.starknet_version,
            event_commitment,
            state_commitment: StateCommitment::ZERO, // UNUSED
            transaction_commitment,
            transaction_count: self.transactions.len(),
            event_count: self.events.iter().flatten().count(),
            l1_da_mode: self.block_info.l1_da_mode,
            receipt_commitment,
            state_diff_commitment,
            state_diff_length: state_update.state_diff_length(),
        };

        debug!(
            "Block {} finalized in {} ms",
            self.block_info.number,
            start.elapsed().as_millis()
        );

        if header == expected_block_header {
            Ok(Ok(ValidatorFinalizeStage {
                header,
                state_update,
            }))
        } else {
            Ok(Err((expected_block_header, header)))
        }
    }

    pub fn consensus_finalize(
        self,
        proposal_commitment: Hash,
    ) -> anyhow::Result<ValidatorFinalizeStage> {
        let _span = tracing::debug_span!(
            "Validator::consensus_finalize",
            height = %self.block_info.number,
            num_transactions = %self.transactions.len(),
        )
        .entered();

        let start = Instant::now();

        let state_diff = self.block_executor.finalize()?;

        let transaction_commitment =
            calculate_transaction_commitment(&self.transactions, self.block_info.starknet_version)?;
        let receipt_commitment = calculate_receipt_commitment(&self.receipts)?;
        let events_ref_by_txn = self
            .events
            .iter()
            .zip(self.transactions.iter().map(|t| t.hash))
            .map(|(e, h)| (h, e.as_slice()))
            .collect::<Vec<_>>();
        let event_commitment =
            calculate_event_commitment(&events_ref_by_txn, self.block_info.starknet_version)?;

        let state_update = StateUpdateData::from(state_diff);
        let state_diff_commitment = state_update.compute_state_diff_commitment();

        let header = BlockHeader {
            hash: BlockHash::ZERO,        // UNUSED
            parent_hash: BlockHash::ZERO, // UNUSED
            number: self.block_info.number,
            timestamp: self.block_info.timestamp,
            eth_l1_gas_price: self.block_info.eth_l1_gas_price,
            strk_l1_gas_price: self.block_info.strk_l1_gas_price,
            eth_l1_data_gas_price: self.block_info.eth_l1_data_gas_price,
            strk_l1_data_gas_price: self.block_info.strk_l1_data_gas_price,
            eth_l2_gas_price: self.block_info.eth_l2_gas_price,
            strk_l2_gas_price: self.block_info.strk_l2_gas_price,
            sequencer_address: self.block_info.sequencer_address,
            starknet_version: self.block_info.starknet_version,
            event_commitment,
            state_commitment: StateCommitment::ZERO, // UNUSED
            transaction_commitment,
            transaction_count: self.transactions.len(),
            event_count: self.events.iter().flatten().count(),
            l1_da_mode: self.block_info.l1_da_mode,
            receipt_commitment,
            state_diff_commitment,
            state_diff_length: state_update.state_diff_length(),
        };

        debug!(
            "Block {} finalized in {} ms",
            self.block_info.number,
            start.elapsed().as_millis()
        );

        if state_diff_commitment.0 == proposal_commitment.0 {
            Ok(ValidatorFinalizeStage {
                header,
                state_update,
            })
        } else {
            Err(anyhow::anyhow!(
                "expected {}, actual {}",
                proposal_commitment,
                state_diff_commitment
            ))
        }
    }
}

pub struct ValidatorFinalizeStage {
    header: BlockHeader,
    state_update: StateUpdateData,
}

impl ValidatorFinalizeStage {
    // TODO(validator) we're using the block hash instead of the proposal commitment
    // here, which is incorrect but we don't have the proposal commitment
    // formula yet.
    /// Updates the tries, computes the state commitment and block hash, and
    /// validates that the computed block hash matches the one in the proposal
    /// fin.
    pub fn validate_block_hash(
        mut self,
        workaround_block_hash_in_proposal_fin: ProposalFin,
        workaround_parent_hash: BlockHash,
        storage: Storage,
    ) -> anyhow::Result<bool> {
        #[cfg(debug_assertions)]
        const VERIFY_HASHES: bool = true;
        #[cfg(not(debug_assertions))]
        const VERIFY_HASHES: bool = false;

        let _span = tracing::debug_span!(
            "Validator::finalize",
            height = %self.header.number,
            num_transactions = %self.header.transaction_count,
        )
        .entered();

        let start = Instant::now();

        let mut db_conn = storage.connection().context("Create database connection")?;
        let db_txn = db_conn
            .transaction()
            .context("Create database transaction")?;

        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&self.state_update).into(),
            VERIFY_HASHES,
            self.header.number,
            storage.clone(),
        )?;

        debug!(
            "Block {} tries updated in {} ms",
            self.header.number,
            start.elapsed().as_millis()
        );

        let start = Instant::now();
        self.header.parent_hash = workaround_parent_hash;
        self.header.state_commitment =
            StateCommitment::calculate(storage_commitment, class_commitment);

        let computed_block_hash = block_hash::compute_final_hash(&self.header);
        let expected_block_hash =
            BlockHash(workaround_block_hash_in_proposal_fin.proposal_commitment.0);

        debug!(
            "Block {} state commitment and block hash computed in {} ms",
            self.header.number,
            start.elapsed().as_millis()
        );

        Ok(computed_block_hash == expected_block_hash)
    }
}

pub enum ValidatorStage {
    BlockInfo(ValidatorBlockInfoStage),
    TransactionBatch(Box<ValidatorTransactionBatchStage>),
}

/// Maps consensus transaction to a pair of:
/// - common transaction, which is used for verifying the transaction hash
/// - executor transaction, which is used for executing the transaction
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
        ConsensusVariant::DeclareV3(DeclareV3WithClass { common, class }) => (
            SyncVariant::DeclareV3(DeclareV3WithoutClass {
                common,
                class_hash: Default::default(),
            }),
            Some(class_info(class)?),
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
    let tx_hash = starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt());
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
        starknet_api::contract_class::SierraVersion::from_str(&contract_class_version)
            .context("Getting sierra version")?;

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
    // TODO(validator) this is suboptimal, the same surplus serialization happens in
    // the broadcasted transactions case
    let class_definition =
        serde_json::to_vec(&class_definition).context("Serializing Sierra class definition")?;
    // TODO(validator) compile_to_casm should also accept a deserialized class
    // definition
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

fn deployed_address(txnv: &TransactionVariant) -> Option<starknet_api::core::ContractAddress> {
    match txnv {
        TransactionVariant::DeployAccountV3(t) => Some(starknet_api::core::ContractAddress(
            starknet_api::core::PatriciaKey::try_from(t.contract_address.get().into_starkfelt())
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
            unreachable!("Proposal parts don't carry older transaction versions: {txnv:?}")
        }
    }
}
