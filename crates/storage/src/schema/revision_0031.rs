use anyhow::Context;
use pathfinder_common::ContractNonce;

use crate::params::RowExt;

/// This migration re-serializes contract nonce's to use the new compressed felt encoding,
/// i.e. skipping leading zeros.
///
/// The only occurence at this time of this is the contract_states table.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    let total: usize = tx
        .query_row("SELECT COUNT(1) FROM contract_states", [], |row| row.get(0))
        .context("Counting rows in contract_states table")?;

    let mut read = tx
        .prepare("SELECT rowid, nonce FROM contract_states")
        .context("Preparing nonce read statement")?;

    let mut write = tx
        .prepare("UPDATE contract_states SET nonce = ? WHERE rowid = ?")
        .context("Preparing nonce update statement")?;

    let mut rows = read.query([]).context("Querying from contract_states")?;

    let mut count = 0;
    let mut t = std::time::Instant::now();
    while let Some(row) = rows.next().context("Reading next row")? {
        let rowid: usize = row.get(0).context("Getting rowid")?;
        let nonce: ContractNonce = row.get_contract_nonce(1).context("Getting nonce")?;

        write
            .execute(crate::params::params![&nonce, &rowid])
            .context("Updating nonce")?;

        count += 1;

        // log progress every 10 seconds
        if t.elapsed() > std::time::Duration::from_secs(10) {
            t = std::time::Instant::now();
            let progress = count * 100 / total;
            tracing::info!(progress, "Re-serializing nonces");
        }
    }

    Ok(())
}
