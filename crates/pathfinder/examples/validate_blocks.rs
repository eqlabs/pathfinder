use std::collections::VecDeque;

use anyhow::Context;
use p2p::sync::client::conv::ToDto;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{
    BlockInfo,
    ProposalFin,
    ProposalInit,
    ProposalPart,
    TransactionVariant as ConsensusVariant,
};
use p2p_proto::transaction::TransactionVariant as SyncVariant;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    class_definition,
    BlockHeader,
    BlockNumber,
    ChainId,
    ClassHash,
    L1DataAvailabilityMode,
};
use pathfinder_crypto::Felt;
use pathfinder_executor::types::ETH_TO_WEI_RATE;
use pathfinder_lib::validator;
use pathfinder_storage::StorageBuilder;
use tracing::{info, warn};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let database_path = std::env::args()
        .nth(1)
        .context("Please provide the database path as the first argument")?;

    // A wild guess based on pathfiner's `main()`
    let connection_pool_capacity = std::thread::available_parallelism()
        .context("Getting number of logical CPUs")?
        .checked_add(5)
        .expect(">5");

    let storage = StorageBuilder::file(database_path.clone().into())
        .migrate()
        .context("Migrating database")?
        .create_pool(
            connection_pool_capacity
                .try_into()
                .expect("Max number of threads < 2^32-1"),
        )
        .context("Creating connection pool")?;

    let mut buffer = String::new();

    while std::io::stdin().read_line(&mut buffer).is_ok() && !buffer.trim().is_empty() {
        let block_number: u64 = buffer
            .trim()
            .parse()
            .context("Parsing block number from stdin")?;
        buffer.clear();

        info!("{} validation started", block_number);

        let block_number = BlockNumber::new_or_panic(block_number);
        let mut db_conn = storage.connection().context("Create database connection")?;
        let db_tx = db_conn
            .transaction()
            .context("Create database transaction")?;
        let (mut proposal, header) = create_proposal(&db_tx, block_number)?;

        let Some(ProposalPart::ProposalInit(proposal_init)) = proposal.pop_front() else {
            panic!("Expected proposal init");
        };

        let validator = validator::new(ChainId::SEPOLIA_TESTNET, proposal_init)
            .context("Validator creation")?;

        let Some(ProposalPart::BlockInfo(block_info)) = proposal.pop_front() else {
            panic!("Expected block info");
        };

        let mut validator = validator
            .validate_block_info(
                block_info,
                header.starknet_version,
                db_tx,
                header.eth_l2_gas_price.0,
                header.strk_l1_gas_price.0,
                header.strk_l1_data_gas_price.0,
            )
            .context("Validating block info")?;

        let Some(ProposalPart::TransactionBatch(tnxs)) = proposal.pop_front() else {
            panic!("Expected transaction batch");
        };

        validator
            .execute_transactions(tnxs)
            .context("Validating transaction batch")?;

        // TODO for now it carries the block hash because we don't know how to calculate
        // the proposal commitment
        let Some(ProposalPart::ProposalFin(proposal_fin)) = proposal.pop_front() else {
            panic!("Expected proposal fin");
        };

        let success = validator
            .finalize(proposal_fin, header.parent_hash, storage.clone())
            .context("Finalizing validation")?;

        if success {
            info!("{} validation succeeded", block_number);
        } else {
            warn!("{} validation FAILED", block_number);
        }
    }

    Ok(())
}

type ProposalSimulation = (VecDeque<ProposalPart>, BlockHeader);

/// Create a valid sequence of proposal parts for the given block.
fn create_proposal(
    db_txn: &pathfinder_storage::Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<ProposalSimulation> {
    let header = db_txn
        .block_header(block_number.into())?
        .context("Block not found")?;

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

    let txns = db_txn
        .transactions_for_block(block_number.into())?
        .context("Block not found")?;

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
        // TODO using block hash for now, as we don't know how to calculate the proposal commitment
        proposal_commitment: Hash(header.hash.0),
    }));

    Ok((proposal_parts, header))
}
