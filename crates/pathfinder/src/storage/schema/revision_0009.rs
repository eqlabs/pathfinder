use crate::storage::schema::PostMigrationAction;
use anyhow::Context;
use rusqlite::Transaction;

pub(crate) fn migrate(transaction: &Transaction) -> anyhow::Result<PostMigrationAction> {
    // Add new columns to the blocks table
    transaction
        .execute_batch(
            r"ALTER TABLE starknet_blocks ADD COLUMN gas_price BLOB NOT NULL
            DEFAULT X'00000000000000000000000000000000';
            ALTER TABLE starknet_blocks ADD COLUMN sequencer_address BLOB NOT NULL
            DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000';",
        )
        .context("Add columns gas_price and starknet_address to starknet_blocks table")?;

    Ok(PostMigrationAction::None)
}

#[cfg(test)]
mod tests {
    use super::PostMigrationAction;

    use crate::{
        core::{
            GasPrice, GlobalRoot, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
            StarknetBlockTimestamp,
        },
        storage::{schema, StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable},
    };

    use pedersen::StarkHash;
    use rusqlite::{named_params, Connection};

    #[test]
    fn empty() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();
        schema::revision_0005::migrate(&transaction).unwrap();
        schema::revision_0006::migrate(&transaction).unwrap();
        schema::revision_0007::migrate(&transaction).unwrap();
        schema::revision_0008::migrate(&transaction).unwrap();

        let action = super::migrate(&transaction).unwrap();
        assert_eq!(action, PostMigrationAction::None);
    }

    #[test]
    fn stateful() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();
        schema::revision_0005::migrate(&transaction).unwrap();
        schema::revision_0006::migrate(&transaction).unwrap();
        schema::revision_0007::migrate(&transaction).unwrap();
        schema::revision_0008::migrate(&transaction).unwrap();

        let block_number = StarknetBlockNumber(1234);
        let block_hash = StarknetBlockHash(StarkHash::from_be_slice(b"a block hash").unwrap());
        let root = GlobalRoot(StarkHash::from_be_slice(b"some global root").unwrap());
        let timestamp = StarknetBlockTimestamp(5678);

        transaction
            .execute(
                r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp)
                                       VALUES (:number, :hash, :root, :timestamp)",
                named_params![
                    ":number": block_number.0,
                    ":hash": &block_hash.0.as_be_bytes(),
                    ":root": &root.0.as_be_bytes(),
                    ":timestamp": timestamp.0,
                ],
            )
            .unwrap();

        let action = super::migrate(&transaction).unwrap();
        assert_eq!(action, PostMigrationAction::None);

        let block = StarknetBlocksTable::get(&transaction, StarknetBlocksBlockId::Hash(block_hash))
            .unwrap()
            .unwrap();

        assert_eq!(
            block,
            StarknetBlock {
                number: block_number,
                hash: block_hash,
                root,
                timestamp,
                gas_price: GasPrice::ZERO,
                sequencer_address: SequencerAddress(StarkHash::ZERO)
            }
        )
    }
}
