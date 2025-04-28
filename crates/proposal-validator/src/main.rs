use core::panic;
use std::collections::VecDeque;

use anyhow::Context;
use p2p::sync::client::conv::{ToDto, TryFromDto};
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{BlockInfo, ProposalFin, ProposalInit, ProposalPart};
use p2p_proto::transaction::DeclareV3WithClass;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{class_definition, BlockNumber, ClassHash, L1DataAvailabilityMode};
use pathfinder_crypto::Felt;
use pathfinder_storage::StorageBuilder;
use tracing::{debug, warn};

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

    let mut proposal = create_proposal(&db_txn, block_number)?;

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

    proposal.into_iter().for_each(|part| {
        let ProposalPart::TransactionBatch(txns) = part else {
            panic!("Expected transaction batch");
        };

        execute_batch(txns);
    });

    Ok(())
}

fn execute_batch(txns: Vec<p2p_proto::consensus::Transaction>) {
    let x = txns
        .into_iter()
        .map(|t| {
            use p2p_proto::consensus::TransactionVariant as ConsensusVariant;
            use p2p_proto::transaction::TransactionVariant as SyncVariant;

            let t = match t.txn {
                ConsensusVariant::DeclareV3(DeclareV3WithClass { common, class }) => {
                    SyncVariant::DeclareV3(common)
                }
                ConsensusVariant::DeployAccountV3(v) => SyncVariant::DeployAccountV3(v),
                ConsensusVariant::InvokeV3(v) => SyncVariant::InvokeV3(v),
                ConsensusVariant::L1HandlerV0(v) => SyncVariant::L1HandlerV0(v),
            };

            TransactionVariant::try_from_dto(t)
                .expect("Proposal part was generated from a valid DB")
        })
        .collect::<Vec<_>>();
}

/// Create a valid sequence of proposal parts for the given block.
fn create_proposal(
    db_txn: &pathfinder_storage::Transaction,
    block_number: BlockNumber,
) -> anyhow::Result<VecDeque<ProposalPart>> {
    let header = db_txn
        .block_header(block_number.into())?
        .context("Block not found")?;

    debug!(?header);

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
            use p2p_proto::consensus::TransactionVariant as ConsensusVariant;
            use p2p_proto::transaction::TransactionVariant as SyncVariant;
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

    Ok(proposal_parts)
}
