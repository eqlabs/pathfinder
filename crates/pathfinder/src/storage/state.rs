use anyhow::Context;
use pedersen::StarkHash;
use rusqlite::{named_params, params, Connection, OptionalExtension, Transaction};
use web3::types::H256;

use crate::{
    core::{
        ContractHash, ContractRoot, ContractStateHash, EthereumBlockHash, EthereumBlockNumber,
        EthereumLogIndex, EthereumTransactionHash, EthereumTransactionIndex, GlobalRoot,
        StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
    },
    ethereum::{log::StateUpdateLog, BlockOrigin, EthOrigin, TransactionOrigin},
    sequencer::reply::transaction,
};

/// Contains the [L1 Starknet update logs](StateUpdateLog).
pub struct L1StateTable {}

pub enum L1TableBlockId {
    Number(StarknetBlockNumber),
    Latest,
}

impl From<StarknetBlockNumber> for L1TableBlockId {
    fn from(number: StarknetBlockNumber) -> Self {
        L1TableBlockId::Number(number)
    }
}

impl L1StateTable {
    pub fn insert(connection: &Connection, update: &StateUpdateLog) -> anyhow::Result<()> {
        connection
            .execute(
                r"INSERT INTO l1_state (
                        starknet_block_number,
                        starknet_global_root,
                        ethereum_block_hash,
                        ethereum_block_number,
                        ethereum_transaction_hash,
                        ethereum_transaction_index,
                        ethereum_log_index
                    ) VALUES (
                        :starknet_block_number,
                        :starknet_global_root,
                        :ethereum_block_hash,
                        :ethereum_block_number,
                        :ethereum_transaction_hash,
                        :ethereum_transaction_index,
                        :ethereum_log_index
                    )",
                named_params! {
                    ":starknet_block_number": update.block_number.0,
                    ":starknet_global_root": &update.global_root.0.as_be_bytes()[..],
                    ":ethereum_block_hash": &update.origin.block.hash.0[..],
                    ":ethereum_block_number": update.origin.block.number.0,
                    ":ethereum_transaction_hash": &update.origin.transaction.hash.0[..],
                    ":ethereum_transaction_index": update.origin.transaction.index.0,
                    ":ethereum_log_index": update.origin.log_index.0,
                },
            )
            .context("Insert L1 state update")?;

        Ok(())
    }

    /// Deletes all rows from __head down-to reorg_tail__
    /// i.e. it deletes all rows where `block number >= reorg_tail`.
    pub fn reorg(connection: &Connection, reorg_tail: StarknetBlockNumber) -> anyhow::Result<()> {
        connection.execute(
            "DELETE FROM l1_state WHERE starknet_block_number >= ?",
            params![reorg_tail.0],
        )?;
        Ok(())
    }

    pub fn get_root(
        connection: &Connection,
        block: L1TableBlockId,
    ) -> anyhow::Result<Option<GlobalRoot>> {
        let mut statement = match block {
            L1TableBlockId::Number(_) => {
                connection.prepare("SELECT starknet_global_root FROM l1_state WHERE starknet_block_number = ?")
            }
            L1TableBlockId::Latest => connection
                .prepare("SELECT starknet_global_root FROM l1_state ORDER BY starknet_block_number DESC LIMIT 1"),
        }?;

        let mut rows = match block {
            L1TableBlockId::Number(number) => statement.query(params![number.0]),
            L1TableBlockId::Latest => statement.query([]),
        }?;

        let row = rows.next()?;
        let row = match row {
            Some(row) => row,
            None => return Ok(None),
        };

        let starknet_global_root = row
            .get_ref_unwrap("starknet_global_root")
            .as_blob()
            .unwrap();
        let starknet_global_root = StarkHash::from_be_slice(starknet_global_root).unwrap();
        let starknet_global_root = GlobalRoot(starknet_global_root);

        Ok(Some(starknet_global_root))
    }

    pub fn get(
        connection: &Connection,
        block: L1TableBlockId,
    ) -> anyhow::Result<Option<StateUpdateLog>> {
        let mut statement = match block {
            L1TableBlockId::Number(_) => connection.prepare(
                r"SELECT starknet_block_number,
                    starknet_global_root,
                    ethereum_block_hash,
                    ethereum_block_number,
                    ethereum_transaction_hash,
                    ethereum_transaction_index,
                    ethereum_log_index
                FROM l1_state WHERE starknet_block_number = ?",
            ),
            L1TableBlockId::Latest => connection.prepare(
                r"SELECT starknet_block_number,
                    starknet_global_root,
                    ethereum_block_hash,
                    ethereum_block_number,
                    ethereum_transaction_hash,
                    ethereum_transaction_index,
                    ethereum_log_index
                FROM l1_state ORDER BY starknet_block_number DESC LIMIT 1",
            ),
        }?;

        let mut rows = match block {
            L1TableBlockId::Number(number) => statement.query(params![number.0]),
            L1TableBlockId::Latest => statement.query([]),
        }?;

        let row = rows.next()?;
        let row = match row {
            Some(row) => row,
            None => return Ok(None),
        };

        let starknet_block_number = row
            .get_ref_unwrap("starknet_block_number")
            .as_i64()
            .unwrap() as u64;
        let starknet_block_number = StarknetBlockNumber(starknet_block_number);

        let starknet_global_root = row
            .get_ref_unwrap("starknet_global_root")
            .as_blob()
            .unwrap();
        let starknet_global_root = StarkHash::from_be_slice(starknet_global_root).unwrap();
        let starknet_global_root = GlobalRoot(starknet_global_root);

        let ethereum_block_hash = row.get_ref_unwrap("ethereum_block_hash").as_blob().unwrap();
        let ethereum_block_hash = EthereumBlockHash(H256(ethereum_block_hash.try_into().unwrap()));

        let ethereum_block_number = row
            .get_ref_unwrap("ethereum_block_number")
            .as_i64()
            .unwrap() as u64;
        let ethereum_block_number = EthereumBlockNumber(ethereum_block_number);

        let ethereum_transaction_hash = row
            .get_ref_unwrap("ethereum_transaction_hash")
            .as_blob()
            .unwrap();
        let ethereum_transaction_hash =
            EthereumTransactionHash(H256(ethereum_transaction_hash.try_into().unwrap()));

        let ethereum_transaction_index = row
            .get_ref_unwrap("ethereum_transaction_index")
            .as_i64()
            .unwrap() as u64;
        let ethereum_transaction_index = EthereumTransactionIndex(ethereum_transaction_index);

        let ethereum_log_index = row.get_ref_unwrap("ethereum_log_index").as_i64().unwrap() as u64;
        let ethereum_log_index = EthereumLogIndex(ethereum_log_index);

        Ok(Some(StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: ethereum_block_hash,
                    number: ethereum_block_number,
                },
                transaction: TransactionOrigin {
                    hash: ethereum_transaction_hash,
                    index: ethereum_transaction_index,
                },
                log_index: ethereum_log_index,
            },
            global_root: starknet_global_root,
            block_number: starknet_block_number,
        }))
    }
}

pub struct RefsTable {}
impl RefsTable {
    pub fn get_l1_l2_head(connection: &Connection) -> anyhow::Result<Option<StarknetBlockNumber>> {
        // This table always contains exactly one row.
        let block_number =
            connection.query_row("SELECT l1_l2_head FROM refs WHERE idx = 1", [], |row| {
                let block_number = row
                    .get_ref_unwrap(0)
                    .as_i64_or_null()
                    .unwrap()
                    .map(|x| StarknetBlockNumber(x as u64));

                Ok(block_number)
            })?;

        Ok(block_number)
    }

    pub fn set_l1_l2_head(
        connection: &Connection,
        head: Option<StarknetBlockNumber>,
    ) -> anyhow::Result<()> {
        match head {
            Some(number) => {
                connection.execute("UPDATE refs SET l1_l2_head = ? WHERE idx = 1", [number.0])
            }
            None => connection.execute("UPDATE refs SET l1_l2_head = NULL WHERE idx = 1", []),
        }?;

        Ok(())
    }
}
/// Stores all knowm [StarknetBlocks][StarknetBlock].
pub struct StarknetBlocksTable {}
impl StarknetBlocksTable {
    pub fn insert(connection: &Connection, block: &StarknetBlock) -> anyhow::Result<()> {
        let transactions =
            serde_json::ser::to_vec(&block.transactions).context("Serialize transactions")?;
        let receipts = serde_json::ser::to_vec(&block.transaction_receipts)
            .context("Serialize transaction receipts")?;

        // TODO: compress transactions...

        connection.execute(
        r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp,  transactions,  transaction_receipts)
                               VALUES (:number, :hash, :root, :timestamp, :transactions, :transaction_receipts)",
        named_params! {
                ":number": block.number.0,
                ":hash": &block.hash.0.as_be_bytes()[..],
                ":root": &block.root.0.as_be_bytes()[..],
                ":timestamp": block.timestamp.0,
                ":transactions": &transactions,
                ":transaction_receipts": &receipts,
            },
        )?;

        Ok(())
    }

    pub fn get_without_tx(
        connection: &Connection,
        block: StarknetBlocksBlockId,
    ) -> anyhow::Result<Option<StarknetBlockWithoutTx>> {
        let mut statement = match block {
            StarknetBlocksBlockId::Number(_) => {
                connection.prepare("SELECT hash, number, root, timestamp FROM starknet_blocks WHERE number = ?")
            }
            StarknetBlocksBlockId::Latest => {
                connection.prepare("SELECT hash, number, root, timestamp FROM starknet_blocks ORDER BY number DESC LIMIT 1")
            }
        }?;

        let mut rows = match block {
            StarknetBlocksBlockId::Number(number) => statement.query(params![number.0]),
            StarknetBlocksBlockId::Latest => statement.query([]),
        }?;

        let row = rows.next().context("Iterate rows")?;

        match row {
            Some(row) => {
                let number = row.get_ref_unwrap("number").as_i64().unwrap() as u64;
                let number = StarknetBlockNumber(number);

                let hash = row.get_ref_unwrap("hash").as_blob().unwrap();
                let hash = StarkHash::from_be_slice(hash).unwrap();
                let hash = StarknetBlockHash(hash);

                let root = row.get_ref_unwrap("root").as_blob().unwrap();
                let root = StarkHash::from_be_slice(root).unwrap();
                let root = GlobalRoot(root);

                let timestamp = row.get_ref_unwrap("timestamp").as_i64().unwrap() as u64;
                let timestamp = StarknetBlockTimestamp(timestamp);

                let block = StarknetBlockWithoutTx {
                    number,
                    hash,
                    root,
                    timestamp,
                };

                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Deletes all rows from __head down-to reorg_tail__
    /// i.e. it deletes all rows where `block number >= reorg_tail`.
    pub fn reorg(connection: &Connection, reorg_tail: StarknetBlockNumber) -> anyhow::Result<()> {
        connection.execute(
            "DELETE FROM starknet_blocks WHERE number >= ?",
            params![reorg_tail.0],
        )?;
        Ok(())
    }
}

pub enum StarknetBlocksBlockId {
    Number(StarknetBlockNumber),
    Latest,
}

impl From<StarknetBlockNumber> for StarknetBlocksBlockId {
    fn from(number: StarknetBlockNumber) -> Self {
        StarknetBlocksBlockId::Number(number)
    }
}

/// Describes a Starknet block.
#[derive(Debug, Clone)]
pub struct StarknetBlock {
    pub number: StarknetBlockNumber,
    pub hash: StarknetBlockHash,
    pub root: GlobalRoot,
    pub timestamp: StarknetBlockTimestamp,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
}

/// Same as [StarknetBlock] but without the expensive transaction data.
#[derive(Debug, Clone, PartialEq)]
pub struct StarknetBlockWithoutTx {
    pub number: StarknetBlockNumber,
    pub hash: StarknetBlockHash,
    pub root: GlobalRoot,
    pub timestamp: StarknetBlockTimestamp,
}

/// Stores the contract state hash along with its preimage. This is useful to
/// map between the global state tree and the contracts tree.
///
/// Specifically it stores
///
/// - [contract state hash](ContractStateHash)
/// - [contract hash](ContractHash)
/// - [contract root](ContractRoot)
pub struct ContractsStateTable {}

impl ContractsStateTable {
    /// Insert a state hash into the table. Does nothing if the state hash already exists.
    pub fn insert(
        transaction: &Transaction,
        state_hash: ContractStateHash,
        hash: ContractHash,
        root: ContractRoot,
    ) -> anyhow::Result<()> {
        transaction.execute(
            r"INSERT INTO contract_states ( state_hash,  hash,  root)
                                       VALUES (:state_hash, :hash, :root)
                                       ON CONFLICT DO NOTHING",
            named_params! {
                ":state_hash": &state_hash.0.to_be_bytes()[..],
                ":hash": &hash.0.to_be_bytes()[..],
                ":root": &root.0.to_be_bytes()[..],
            },
        )?;
        Ok(())
    }

    /// Gets the root associated with the given state hash, or [None]
    /// if it does not exist.
    pub fn get_root(
        transaction: &Transaction,
        state_hash: ContractStateHash,
    ) -> anyhow::Result<Option<ContractRoot>> {
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT root FROM contract_states WHERE state_hash = :state_hash",
                named_params! {
                    ":state_hash": &state_hash.0.to_be_bytes()[..]
                },
                |row| row.get("root"),
            )
            .optional()?;

        let bytes = match bytes {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let bytes: [u8; 32] = match bytes.try_into() {
            Ok(bytes) => bytes,
            Err(bytes) => anyhow::bail!("Bad contract root length: {}", bytes.len()),
        };

        let root = StarkHash::from_be_bytes(bytes)?;
        let root = ContractRoot(root);

        Ok(Some(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    mod contracts {
        use super::*;

        #[test]
        fn get_root() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            crate::storage::migrate_to_1(&transaction).unwrap();

            let state_hash = ContractStateHash(StarkHash::from_hex_str("abc").unwrap());
            let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());
            let root = ContractRoot(StarkHash::from_hex_str("def").unwrap());

            ContractsStateTable::insert(&transaction, state_hash, hash, root).unwrap();

            let result = ContractsStateTable::get_root(&transaction, state_hash).unwrap();

            assert_eq!(result, Some(root));
        }
    }

    mod refs {
        use super::*;

        mod l1_l2_head {
            use super::*;

            #[test]
            fn fresh_is_none() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let l1_l2_head = RefsTable::get_l1_l2_head(&connection).unwrap();
                assert_eq!(l1_l2_head, None);
            }

            #[test]
            fn set_get() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let expected = Some(StarknetBlockNumber(22));
                RefsTable::set_l1_l2_head(&connection, expected).unwrap();
                assert_eq!(expected, RefsTable::get_l1_l2_head(&connection).unwrap());

                let expected = Some(StarknetBlockNumber(25));
                RefsTable::set_l1_l2_head(&connection, expected).unwrap();
                assert_eq!(expected, RefsTable::get_l1_l2_head(&connection).unwrap());

                RefsTable::set_l1_l2_head(&connection, None).unwrap();
                assert_eq!(None, RefsTable::get_l1_l2_head(&connection).unwrap());
            }
        }
    }

    mod l1_state_table {
        use super::*;

        /// Creates a set of consecutive [StateUpdateLog]s starting from L2 genesis,
        /// with arbitrary other values.
        fn create_updates() -> [StateUpdateLog; 3] {
            (0..3)
                .map(|i| StateUpdateLog {
                    origin: EthOrigin {
                        block: BlockOrigin {
                            hash: EthereumBlockHash(H256::from_low_u64_le(i + 33)),
                            number: EthereumBlockNumber(i + 12_000),
                        },
                        transaction: TransactionOrigin {
                            hash: EthereumTransactionHash(H256::from_low_u64_le(i + 999)),
                            index: EthereumTransactionIndex(i + 20_000),
                        },
                        log_index: EthereumLogIndex(i + 500),
                    },
                    global_root: GlobalRoot(
                        StarkHash::from_hex_str(&"3".repeat(i as usize + 1)).unwrap(),
                    ),
                    block_number: StarknetBlockNumber::GENESIS + i,
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }

        mod get {
            use super::*;

            #[test]
            fn none() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                let non_existent = updates.last().unwrap().block_number + 1;
                assert_eq!(
                    L1StateTable::get(&connection, non_existent.into()).unwrap(),
                    None
                );
            }

            #[test]
            fn some() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                for (idx, update) in updates.iter().enumerate() {
                    assert_eq!(
                        L1StateTable::get(&connection, update.block_number.into())
                            .unwrap()
                            .as_ref(),
                        Some(update),
                        "Update {}",
                        idx
                    );
                }
            }

            mod latest {
                use super::*;

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    assert_eq!(
                        L1StateTable::get(&connection, L1TableBlockId::Latest).unwrap(),
                        None
                    );
                }

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let updates = create_updates();
                    for update in &updates {
                        L1StateTable::insert(&connection, update).unwrap();
                    }

                    assert_eq!(
                        L1StateTable::get(&connection, L1TableBlockId::Latest)
                            .unwrap()
                            .as_ref(),
                        updates.last()
                    );
                }
            }
        }

        mod get_root {
            use super::*;

            #[test]
            fn none() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                let non_existent = updates.last().unwrap().block_number + 1;
                assert_eq!(
                    L1StateTable::get_root(&connection, non_existent.into()).unwrap(),
                    None
                );
            }

            #[test]
            fn some() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                for (idx, update) in updates.iter().enumerate() {
                    assert_eq!(
                        L1StateTable::get_root(&connection, update.block_number.into()).unwrap(),
                        Some(update.global_root),
                        "Update {}",
                        idx
                    );
                }
            }

            mod latest {
                use super::*;

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    assert_eq!(
                        L1StateTable::get_root(&connection, L1TableBlockId::Latest).unwrap(),
                        None
                    );
                }

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let updates = create_updates();
                    for update in &updates {
                        L1StateTable::insert(&connection, update).unwrap();
                    }

                    assert_eq!(
                        L1StateTable::get_root(&connection, L1TableBlockId::Latest).unwrap(),
                        Some(updates.last().unwrap().global_root)
                    );
                }
            }
        }

        mod reorg {
            use super::*;

            #[test]
            fn full() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                L1StateTable::reorg(&connection, StarknetBlockNumber::GENESIS).unwrap();

                assert_eq!(
                    L1StateTable::get(&connection, L1TableBlockId::Latest).unwrap(),
                    None
                );
            }

            #[test]
            fn partial() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                let reorg_tail = updates[1].block_number;
                L1StateTable::reorg(&connection, reorg_tail).unwrap();

                assert_eq!(
                    L1StateTable::get(&connection, L1TableBlockId::Latest)
                        .unwrap()
                        .as_ref(),
                    Some(&updates[0])
                );
            }
        }
    }

    mod starknet_blocks {
        use super::*;

        /// Creates a set of consecutive [StarknetBlock]s starting from L2 genesis,
        /// with arbitrary other values.
        fn create_blocks() -> [StarknetBlock; 3] {
            (0..3)
                .map(|i| StarknetBlock {
                    number: StarknetBlockNumber::GENESIS + i,
                    hash: StarknetBlockHash(
                        StarkHash::from_hex_str(&"a".repeat(i as usize + 3)).unwrap(),
                    ),
                    root: GlobalRoot(StarkHash::from_hex_str(&"f".repeat(i as usize + 3)).unwrap()),
                    timestamp: StarknetBlockTimestamp(i + 500),
                    transaction_receipts: Vec::new(),
                    transactions: Vec::new(),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }

        mod get {
            use super::*;

            #[test]
            fn some() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let blocks = create_blocks();
                for block in &blocks {
                    StarknetBlocksTable::insert(&connection, block).unwrap();
                }

                for block in blocks {
                    let result =
                        StarknetBlocksTable::get_without_tx(&connection, block.number.into())
                            .unwrap()
                            .unwrap();

                    assert_eq!(result.hash, block.hash);
                    assert_eq!(result.number, block.number);
                    assert_eq!(result.root, block.root);
                    assert_eq!(result.timestamp, block.timestamp);
                }
            }

            #[test]
            fn none() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let blocks = create_blocks();
                for block in &blocks {
                    StarknetBlocksTable::insert(&connection, block).unwrap();
                }

                let non_existent = blocks.last().unwrap().number + 1;
                assert_eq!(
                    StarknetBlocksTable::get_without_tx(&connection, non_existent.into()).unwrap(),
                    None
                );
            }

            mod latest {
                use super::*;

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    let expected = blocks
                        .last()
                        .map(|block| StarknetBlockWithoutTx {
                            number: block.number,
                            hash: block.hash,
                            root: block.root,
                            timestamp: block.timestamp,
                        })
                        .unwrap();

                    let latest = StarknetBlocksTable::get_without_tx(
                        &connection,
                        StarknetBlocksBlockId::Latest,
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(latest, expected);
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let latest_root = StarknetBlocksTable::get_without_tx(
                        &connection,
                        StarknetBlocksBlockId::Latest,
                    )
                    .unwrap();
                    assert_eq!(latest_root, None);
                }
            }
        }

        mod reorg {
            use super::*;

            #[test]
            fn full() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let blocks = create_blocks();
                for block in &blocks {
                    StarknetBlocksTable::insert(&connection, block).unwrap();
                }

                StarknetBlocksTable::reorg(&connection, StarknetBlockNumber::GENESIS).unwrap();

                assert_eq!(
                    StarknetBlocksTable::get_without_tx(&connection, StarknetBlocksBlockId::Latest)
                        .unwrap(),
                    None
                );
            }

            #[test]
            fn partial() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let blocks = create_blocks();
                for block in &blocks {
                    StarknetBlocksTable::insert(&connection, block).unwrap();
                }

                let reorg_tail = blocks[1].number;
                StarknetBlocksTable::reorg(&connection, reorg_tail).unwrap();

                let expected = StarknetBlockWithoutTx {
                    number: blocks[0].number,
                    hash: blocks[0].hash,
                    root: blocks[0].root,
                    timestamp: blocks[0].timestamp,
                };

                assert_eq!(
                    StarknetBlocksTable::get_without_tx(&connection, StarknetBlocksBlockId::Latest)
                        .unwrap(),
                    Some(expected)
                );
            }
        }
    }
}
