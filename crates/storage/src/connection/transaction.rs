//! Contains starknet transaction related code and __not__ database transaction.

use anyhow::Context;
use pathfinder_common::{BlockHash, BlockNumber, TransactionHash};
use starknet_gateway_types::reply::transaction as gateway;

use crate::{prelude::*, BlockId};

pub enum TransactionStatus {
    L1Accepted,
    L2Accepted,
}

pub(super) fn insert_transactions(
    tx: &Transaction<'_>,
    block_hash: BlockHash,
    block_number: BlockNumber,
    transaction_data: &[(gateway::Transaction, gateway::Receipt)],
) -> anyhow::Result<()> {
    if transaction_data.is_empty() {
        return Ok(());
    }

    let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;
    for (i, (transaction, receipt)) in transaction_data.iter().enumerate() {
        // Serialize and compress transaction data.
        let tx_data = serde_json::to_vec(&transaction).context("Serializing transaction")?;
        let tx_data = compressor
            .compress(&tx_data)
            .context("Compressing transaction")?;

        let serialized_receipt = serde_json::to_vec(&receipt).context("Serializing receipt")?;
        let serialized_receipt = compressor
            .compress(&serialized_receipt)
            .context("Compressing receipt")?;

        tx.inner().execute(r"INSERT OR REPLACE INTO starknet_transactions (hash, idx, block_hash, tx, receipt) VALUES (:hash, :idx, :block_hash, :tx, :receipt)",
                   named_params![
                ":hash": &transaction.hash(),
                ":idx": &i,
                ":block_hash": &block_hash,
                ":tx": &tx_data,
                ":receipt": &serialized_receipt,
            ]).context("Inserting transaction data")?;

        // insert events from receipt
        super::event::insert_events(tx, block_number, receipt.transaction_hash, &receipt.events)
            .context("Inserting events")?;
    }

    Ok(())
}

pub(super) fn transaction(
    tx: &Transaction<'_>,
    transaction: TransactionHash,
) -> anyhow::Result<Option<gateway::Transaction>> {
    let mut stmt = tx
        .inner()
        .prepare("SELECT tx FROM starknet_transactions WHERE hash = ?")
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&transaction])
        .context("Executing query")?;

    let row = match rows.next()? {
        Some(row) => row,
        None => return Ok(None),
    };

    let transaction = row.get_ref_unwrap(0).as_blob()?;
    let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
    let transaction = serde_json::from_slice(&transaction).context("Deserializing transaction")?;

    Ok(Some(transaction))
}

pub(super) fn transaction_with_receipt(
    tx: &Transaction<'_>,
    txn_hash: TransactionHash,
) -> anyhow::Result<Option<(gateway::Transaction, gateway::Receipt, BlockHash)>> {
    let mut stmt = tx
        .inner()
        .prepare("SELECT tx, receipt, block_hash FROM starknet_transactions WHERE hash = ?1")
        .context("Preparing statement")?;

    let mut rows = stmt.query(params![&txn_hash]).context("Executing query")?;

    let row = match rows.next()? {
        Some(row) => row,
        None => return Ok(None),
    };

    let transaction = row.get_ref_unwrap("tx").as_blob()?;
    let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
    let transaction = serde_json::from_slice(&transaction).context("Deserializing transaction")?;

    let receipt = match row.get_ref_unwrap("receipt").as_blob_or_null()? {
        Some(data) => data,
        None => return Ok(None),
    };
    let receipt = zstd::decode_all(receipt).context("Decompressing receipt")?;
    let receipt = serde_json::from_slice(&receipt).context("Deserializing receipt")?;

    let block_hash = row.get_block_hash("block_hash")?;

    Ok(Some((transaction, receipt, block_hash)))
}

pub(super) fn transaction_at_block(
    tx: &Transaction<'_>,
    block: BlockId,
    index: usize,
) -> anyhow::Result<Option<gateway::Transaction>> {
    // Identify block hash
    let Some((_, block_hash)) = tx.block_id(block)? else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare("SELECT tx FROM starknet_transactions WHERE block_hash = ? AND idx = ?")
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&block_hash, &index])
        .context("Executing query")?;

    let row = match rows.next()? {
        Some(row) => row,
        None => return Ok(None),
    };

    let transaction = match row.get_ref_unwrap(0).as_blob_or_null()? {
        Some(data) => data,
        None => return Ok(None),
    };

    let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
    let transaction = serde_json::from_slice(&transaction).context("Deserializing transaction")?;

    Ok(Some(transaction))
}

pub(super) fn transaction_count(tx: &Transaction<'_>, block: BlockId) -> anyhow::Result<usize> {
    match block {
        BlockId::Number(number) => tx
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM starknet_transactions
                JOIN starknet_blocks ON starknet_transactions.block_hash = starknet_blocks.hash
                WHERE number = ?1",
                params![&number],
                |row| row.get(0),
            )
            .context("Counting transactions"),
        BlockId::Hash(hash) => tx
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM starknet_transactions WHERE block_hash = ?1",
                params![&hash],
                |row| row.get(0),
            )
            .context("Counting transactions"),
        BlockId::Latest => {
            // First get the latest block
            let block = match tx.block_id(BlockId::Latest)? {
                Some((number, _)) => number,
                None => return Ok(0),
            };

            transaction_count(tx, block.into())
        }
    }
}

pub(super) fn transaction_data_for_block(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<Vec<(gateway::Transaction, gateway::Receipt)>>> {
    let Some((_, block_hash)) = tx.block_id(block)? else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare(
            "SELECT tx, receipt FROM starknet_transactions WHERE block_hash = ? ORDER BY idx ASC",
        )
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&block_hash])
        .context("Executing query")?;

    let mut data = Vec::new();
    while let Some(row) = rows.next()? {
        let receipt = row
            .get_ref_unwrap("receipt")
            .as_blob_or_null()?
            .context("Receipt data missing")?;
        let receipt = zstd::decode_all(receipt).context("Decompressing transaction receipt")?;
        let receipt =
            serde_json::from_slice(&receipt).context("Deserializing transaction receipt")?;

        let transaction = row
            .get_ref_unwrap("tx")
            .as_blob_or_null()?
            .context("Transaction data missing")?;
        let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
        let transaction =
            serde_json::from_slice(&transaction).context("Deserializing transaction")?;

        data.push((transaction, receipt));
    }

    Ok(Some(data))
}

pub(super) fn transaction_block_hash(
    tx: &Transaction<'_>,
    hash: TransactionHash,
) -> anyhow::Result<Option<BlockHash>> {
    tx.inner()
        .query_row(
            "SELECT block_hash FROM starknet_transactions WHERE hash = ?",
            params![&hash],
            |row| row.get_block_hash(0),
        )
        .optional()
        .map_err(|e| e.into())
}
