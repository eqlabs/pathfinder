use pathfinder_common::StateCommitment;
use pathfinder_ethereum::EthereumStateUpdate;
use rusqlite::Transaction;

use crate::{
    L1StateTable, RefsTable, StarknetBlocksBlockId, StarknetBlocksNumberOrLatest,
    StarknetBlocksTable,
};

pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute("DROP TABLE l1_state", [])?;
    tx.execute(
        r"CREATE TABLE l1_state (
            starknet_block_number      INTEGER PRIMARY KEY,
            starknet_block_hash        BLOB    NOT NULL,
            starknet_global_root       BLOB    NOT NULL
        )",
        [],
    )?;

    if let Some(update) = get_update(tx)? {
        L1StateTable::upsert(tx, &update)?;
    }

    Ok(())
}

fn get_update(tx: &Transaction<'_>) -> anyhow::Result<Option<EthereumStateUpdate>> {
    RefsTable::get_l1_l2_head(tx).and_then(|number| {
        Ok(if let Some(number) = number {
            let hash =
                StarknetBlocksTable::get_hash(tx, StarknetBlocksNumberOrLatest::Number(number))?;
            let state = StarknetBlocksTable::get_state_commitment(
                tx,
                StarknetBlocksBlockId::Number(number),
            )?
            .map(|(storage, class)| StateCommitment::calculate(storage, class));
            hash.zip(state).map(|(hash, state)| EthereumStateUpdate {
                global_root: state,
                block_number: number,
                block_hash: hash,
            })
        } else {
            None
        })
    })
}
