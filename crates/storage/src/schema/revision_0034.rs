use crate::params::named_params;
use pathfinder_common::{
    BlockHash, BlockNumber, ClassCommitment, StateCommitment, StorageCommitment,
};
use rusqlite::{OptionalExtension, Transaction};

use crate::params::RowExt;

pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute("DROP TABLE l1_state", [])?;
    tx.execute(
        r"CREATE TABLE l1_state (
            starknet_block_number      INTEGER PRIMARY KEY,
            starknet_block_hash        BLOB    NOT NULL,
            starknet_state_root        BLOB    NOT NULL
        )",
        [],
    )?;

    let maybe_head = tx
        .query_row(
            r"SELECT b.number, b.hash, b.root, b.class_commitment 
        FROM starknet_blocks b 
        INNER JOIN refs r ON r.l1_l2_head == b.number 
        LIMIT 1",
            [],
            |row| {
                let number: BlockNumber = row.get_block_number(0)?;
                let hash: BlockHash = row.get_block_hash(1)?;
                let storage: StorageCommitment = row.get_storage_commitment(2)?;
                let class: ClassCommitment = row.get_class_commitment(3)?;
                Ok((number, hash, storage, class))
            },
        )
        .optional()?;

    if let Some((number, hash, storage, class)) = maybe_head {
        let root = StateCommitment::calculate(storage, class);
        tx.execute(
            r"INSERT OR REPLACE INTO l1_state (
                        starknet_block_number,
                        starknet_block_hash,
                        starknet_state_root
                    ) VALUES (
                        :starknet_block_number,
                        :starknet_block_hash,
                        :starknet_state_root
                    )",
            named_params! {
                ":starknet_block_number": &number,
                ":starknet_block_hash": &hash,
                ":starknet_state_root": &root,
            },
        )?;
    }

    Ok(())
}
