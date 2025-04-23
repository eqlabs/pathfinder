use anyhow::Context;
use p2p::sync::client::conv::ToDto;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{BlockInfo, ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{class_definition, BlockNumber, ClassHash, L1DataAvailabilityMode};
use pathfinder_crypto::Felt;
use pathfinder_storage::StorageBuilder;

fn main() -> anyhow::Result<()> {
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

    let proposal = create_proposal(&db_txn, block_number)?;

    Ok(())
}

/// Create a valid sequence of proposal parts for the given block.
fn create_proposal(
    db_txn: &pathfinder_storage::Transaction,
    block_number: BlockNumber,
) -> anyhow::Result<Vec<ProposalPart>> {
    let header = db_txn
        .block_header(block_number.into())?
        .context("Block not found")?;

    let mut proposal_parts = Vec::new();
    let height = header.number.get();

    proposal_parts.push(ProposalPart::ProposalInit(ProposalInit {
        height,
        // Decent random value
        round: 42,
        // FIXME
        valid_round: None,
        // Decent random value
        proposer: Address(Felt::from_u64(42)),
    }));

    use p2p_proto::common::L1DataAvailabilityMode::{Blob, Calldata};

    proposal_parts.push(ProposalPart::BlockInfo(BlockInfo {
        height,
        timestamp: header.timestamp.get(),
        // Decent random value
        builder: Address(Felt::from_u64(42)),
        l1_da_mode: match header.l1_da_mode {
            L1DataAvailabilityMode::Calldata => Calldata,
            L1DataAvailabilityMode::Blob => Blob,
        },
        l2_gas_price_fri: header.strk_l2_gas_price.0,
        l1_gas_price_wei: header.eth_l2_gas_price.0,
        l1_data_gas_price_wei: header.eth_l1_data_gas_price.0,
        // Eth/Fri = Wei * 10^18 / Fri
        eth_to_fri_rate: header.eth_l2_gas_price.0.pow(18) / header.strk_l2_gas_price.0,
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

    proposal_parts.push(ProposalPart::TransactionBatch(txns));

    proposal_parts.push(ProposalPart::ProposalFin(ProposalFin {
        // FIXME
        proposal_commitment: Hash(Felt::from_u64(42)),
    }));

    Ok(proposal_parts)
}
