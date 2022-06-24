use anyhow::Context;
use pathfinder_lib::{
    core::{Chain, ClassHash, StarknetBlockNumber},
    sequencer::reply::transaction::Type as TransactionType,
    sequencer::{Client, ClientApi},
    state::CompressedContract,
    storage::{
        ContractCodeTable, StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable,
        Storage,
    },
};

/// Add missing declared classes.
///
/// Iterates over all transactions in the database and checks if we have the classes downloaded
/// for all declare transactions, downloading missing classes.
///
/// Usage:
/// `cargo run --release -p pathfinder --example fix_missing_classes ./mainnet.sqlite`
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let chain_name = std::env::args().nth(1).unwrap();
    let chain = match chain_name.as_str() {
        "mainnet" => Chain::Mainnet,
        "goerli" => Chain::Goerli,
        _ => panic!("Expected chain name: mainnet/goerli"),
    };

    let database_path = std::env::args().nth(2).unwrap();
    let storage = Storage::migrate(database_path.into())?;
    let db = storage
        .connection()
        .context("Opening database connection")?;

    let client = Client::new(chain)?;

    let latest_block_number = StarknetBlocksTable::get_latest_number(&db)?.unwrap();

    for block_number in 0..latest_block_number.0 {
        let block_id = StarknetBlocksBlockId::Number(StarknetBlockNumber(block_number));
        let transactions_and_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(&db, block_id)?;

        for (transaction, _) in transactions_and_receipts {
            if transaction.r#type == TransactionType::Declare {
                let class_hash = transaction.class_hash.unwrap();

                let exists = ContractCodeTable::exists(&db, &[class_hash])?[0];
                if !exists {
                    let compressed_contract =
                        download_and_compress_contract(class_hash, &client).await?;
                    ContractCodeTable::insert_compressed(&db, &compressed_contract)?;
                    println!("Downloaded missing class {:?}", class_hash);
                }
            }
        }
    }

    Ok(())
}

async fn download_and_compress_contract(
    class_hash: ClassHash,
    sequencer: &impl ClientApi,
) -> anyhow::Result<CompressedContract> {
    let contract_definition = sequencer
        .class_by_hash(class_hash)
        .await
        .context("Download contract from sequencer")?;

    // Parse the class definition for ABI, code and calculate the class hash. This can
    // be expensive, so perform in a blocking task.
    let extract = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let (abi, bytecode, hash) =
            pathfinder_lib::state::class_hash::extract_abi_code_hash(&contract_definition)?;
        Ok((contract_definition, abi, bytecode, hash))
    });
    let (contract_definition, abi, bytecode, hash) = extract
        .await
        .context("Parse contract definition and compute hash")??;

    // Sanity check.
    anyhow::ensure!(
        class_hash == hash,
        "Class hash mismatch for class {:?}",
        class_hash
    );

    let compress = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

        let abi = compressor.compress(&abi).context("Compress ABI")?;
        let bytecode = compressor
            .compress(&bytecode)
            .context("Compress bytecode")?;
        let definition = compressor
            .compress(&*contract_definition)
            .context("Compress definition")?;

        Ok((abi, bytecode, definition))
    });
    let (abi, bytecode, definition) = compress.await.context("Compress contract")??;

    Ok(CompressedContract {
        abi,
        bytecode,
        definition,
        hash,
    })
}
