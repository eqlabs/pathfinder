#[allow(unused)]
use anyhow::Context;
use pathfinder_common::{Chain, ClassHash};
use rusqlite::{OptionalExtension, Transaction};
use stark_hash::{Felt, OverflowError};

pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    let genesis = transaction
        .query_row(
            "SELECT hash FROM starknet_blocks WHERE number = 0",
            [],
            |r| Ok(Felt::from_be_slice(r.get_ref_unwrap(0).as_blob()?)),
        )
        .optional()?;

    let (minimum_block, chain) = match genesis {
        Some(Ok(x)) if x == pathfinder_common::consts::TESTNET_GENESIS_HASH.0 => {
            (231_579, Chain::Testnet)
        }
        Some(Ok(x)) if x == pathfinder_common::consts::MAINNET_GENESIS_HASH.0 => {
            (2700, Chain::Mainnet)
        }
        Some(Ok(y)) => anyhow::bail!("Unknown genesis block hash: {}", y),
        Some(Err(err @ OverflowError)) => {
            return Err(anyhow::Error::new(err).context("Failed to read genesis block hash"))
        }
        None => return Ok(()),
    };

    let latest_block_number =
        transaction.query_row("SELECT max(number) FROM starknet_blocks", [], |r| {
            Ok(r.get_ref(0)?.as_i64())
        })??;

    let (work_tx, work_rx) = std::sync::mpsc::sync_channel(1);
    let (downloaded_tx, downloaded_rx) = std::sync::mpsc::sync_channel(1);

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let handle = tokio::runtime::Handle::current();

    let downloader = std::thread::spawn(move || {
        {
            use starknet_gateway_client::{Client, ClientApi};

            let client = match chain {
                Chain::Mainnet => Client::mainnet(),
                Chain::Testnet => Client::testnet(),
                Chain::Testnet2 => Client::testnet2(),
                Chain::Integration => Client::integration(),
                Chain::Custom => anyhow::bail!("Migration is not applicable for custom networks"),
            };

            for class_hash in work_rx.iter() {
                let class = handle.block_on(client.class_by_hash(class_hash)).unwrap();
                downloaded_tx.send(class).unwrap();
            }
        }

        Ok(())
    });

    let extract_compress = std::thread::spawn(move || {
        let mut compressor = zstd::bulk::Compressor::new(10).unwrap();

        for class in downloaded_rx.iter() {
            let (abi, code, hash) =
                starknet_gateway_types::class_hash::extract_abi_code_hash(&class).unwrap();

            let definition = compressor.compress(&class).unwrap();
            let abi = compressor.compress(&abi).unwrap();
            let bytecode = compressor.compress(&code).unwrap();

            ready_tx
                .send(storage::CompressedContract {
                    abi,
                    bytecode,
                    definition,
                    hash,
                })
                .unwrap();
        }
    });

    let mut class_query = transaction.prepare("SELECT 1 FROM contract_code WHERE hash = ?")?;

    let mut tx_query = transaction.prepare(
        "SELECT tx
           FROM starknet_transactions txs
           JOIN starknet_blocks blocks ON (txs.block_hash = blocks.hash)
          WHERE blocks.number >= ?",
    )?;

    let mut tx_rows = tx_query.query([minimum_block])?;
    let mut buffer = Vec::new();

    let mut already_processing = std::collections::HashSet::new();

    let mut last_report = std::time::Instant::now();

    let mut processed = 0;

    tracing::info!(
        "Processing transactions from blocks {minimum_block}..={latest_block_number} for missed declare transactions. This can take a while..."
    );

    while let Some(tx_row) = tx_rows.next()? {
        processed += 1;

        // this is probably quite slow with this fast loops, don't copy paste it around without
        // consideration. this is quite small migration after all so not going for anything more
        // complex.
        if last_report.elapsed() >= std::time::Duration::from_secs(5) {
            tracing::info!(
                processed,
                missing = already_processing.len(),
                "Continuing to process transactions"
            );
            last_report = std::time::Instant::now();
        }

        buffer.clear();
        zstd::stream::copy_decode(tx_row.get_ref_unwrap(0).as_blob()?, &mut buffer)?;

        let tx = serde_json::from_slice::<SlimTransaction>(&buffer)?;

        let class_hash = match tx.r#type {
            TransactionType::Declare => tx
                .class_hash
                .expect("should had found a class hash in declare transaction"),
            _ => continue,
        };

        if class_query.exists([class_hash.0.as_be_bytes()])? {
            continue;
        }

        if !already_processing.insert(class_hash) {
            continue;
        }

        work_tx
            .send(class_hash)
            .context("Failed to send, some of tasks failed")?;
    }

    drop(work_tx);

    tracing::info!(classes = already_processing.len(), "Saving missed classes");

    drop(already_processing);

    for cc in ready_rx.iter() {
        storage::contract_code_insert_compressed(transaction, &cc)
            .with_context(|| format!("Failed to save class {}", cc.hash.0))?;
    }

    downloader.join().unwrap()?;
    extract_compress.join().unwrap();

    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TransactionType {
    #[serde(rename = "DEPLOY")]
    Deploy,
    #[serde(rename = "INVOKE_FUNCTION")]
    InvokeFunction,
    #[serde(rename = "DECLARE")]
    Declare,
}

#[derive(serde::Deserialize)]
struct SlimTransaction {
    r#type: TransactionType,
    #[serde(default)]
    class_hash: Option<ClassHash>,
}

/// These are copies of storage code we had matching the database schema for this migration.
mod storage {
    use rusqlite::{named_params, Transaction};

    use pathfinder_common::ClassHash;

    #[derive(Clone, PartialEq, Eq)]
    pub struct CompressedContract {
        pub abi: Vec<u8>,
        pub bytecode: Vec<u8>,
        pub definition: Vec<u8>,
        pub hash: ClassHash,
    }

    pub fn contract_code_insert_compressed(
        transaction: &Transaction<'_>,
        contract: &CompressedContract,
    ) -> anyhow::Result<()> {
        // check magics to verify these are zstd compressed files
        let magic = &[0x28, 0xb5, 0x2f, 0xfd];
        assert_eq!(&contract.abi[..4], magic);
        assert_eq!(&contract.bytecode[..4], magic);
        assert_eq!(&contract.definition[..4], magic);

        transaction.execute(
            r"INSERT INTO contract_code ( hash,  bytecode,  abi,  definition)
                             VALUES (:hash, :bytecode, :abi, :definition)",
            named_params! {
                ":hash": &contract.hash.0.to_be_bytes()[..],
                ":bytecode": &contract.bytecode[..],
                ":abi": &contract.abi[..],
                ":definition": &contract.definition[..],
            },
        )?;
        Ok(())
    }
}
