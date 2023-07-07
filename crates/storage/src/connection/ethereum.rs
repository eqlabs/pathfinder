use pathfinder_common::BlockNumber;
use pathfinder_ethereum::EthereumStateUpdate;

use crate::prelude::*;

pub(super) fn upsert_l1_state(
    tx: &Transaction<'_>,
    update: &EthereumStateUpdate,
) -> anyhow::Result<()> {
    tx.inner().execute(
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
            ":starknet_block_number": &update.block_number,
            ":starknet_block_hash": &update.block_hash,
            ":starknet_state_root": &update.state_root,
        },
    )?;

    Ok(())
}

pub(super) fn l1_state_at_number(
    tx: &Transaction<'_>,
    block: BlockNumber,
) -> anyhow::Result<Option<EthereumStateUpdate>> {
    tx.inner()
        .query_row(
            r"SELECT starknet_block_number, starknet_block_hash, starknet_state_root FROM l1_state 
            WHERE starknet_block_number = ?",
            params![&block],
            |row| {
                let block_number = row.get_block_number(0)?;
                let block_hash = row.get_block_hash(1)?;
                let state_root = row.get_state_commitment(2)?;

                Ok(EthereumStateUpdate {
                    state_root,
                    block_number,
                    block_hash,
                })
            },
        )
        .optional()
        .map_err(|e| e.into())
}

pub(super) fn latest_l1_state(tx: &Transaction<'_>) -> anyhow::Result<Option<EthereumStateUpdate>> {
    tx.inner()
        .query_row(
            r"SELECT starknet_block_number, starknet_block_hash, starknet_state_root FROM l1_state 
            ORDER BY starknet_block_number DESC
            LIMIT 1",
            [],
            |row| {
                let block_number = row.get_block_number(0)?;
                let block_hash = row.get_block_hash(1)?;
                let state_root = row.get_state_commitment(2)?;

                Ok(EthereumStateUpdate {
                    state_root,
                    block_number,
                    block_hash,
                })
            },
        )
        .optional()
        .map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Storage;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHash, StateCommitment};
    use pathfinder_ethereum::EthereumStateUpdate;
    use stark_hash::Felt;

    /// Creates a set of consecutive [StateUpdateLog]s starting from L2 genesis,
    /// with arbitrary other values.
    fn create_updates() -> [EthereumStateUpdate; 3] {
        (0..3usize)
            .map(|i| EthereumStateUpdate {
                state_root: StateCommitment(Felt::from_hex_str(&"3".repeat(i + 1)).unwrap()),
                block_number: BlockNumber::GENESIS + i as u64,
                block_hash: BlockHash(Felt::from_hex_str(&"F".repeat(i + 1)).unwrap()),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn empty() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let result = l1_state_at_number(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, None);

        let result = latest_l1_state(&tx).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn latest() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let updates = create_updates();
        let expected = updates.last().unwrap().clone();
        for update in updates {
            upsert_l1_state(&tx, &update).unwrap();
        }

        let result = latest_l1_state(&tx).unwrap().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn upsert_and_at_number() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let updates = create_updates();
        for update in updates.clone() {
            upsert_l1_state(&tx, &update).unwrap();
        }

        for expected in updates {
            let result = l1_state_at_number(&tx, expected.block_number).unwrap();

            assert_eq!(result, Some(expected));
        }
    }

    #[test]
    fn upsert_overwrites() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let original = EthereumStateUpdate {
            state_root: state_commitment!("0x1234"),
            block_number: BlockNumber::new_or_panic(10),
            block_hash: block_hash!("0xabdd"),
        };
        upsert_l1_state(&tx, &original).unwrap();

        let new_value = EthereumStateUpdate {
            state_root: state_commitment!("0xabcdef"),
            block_number: original.block_number,
            block_hash: block_hash!("0xccdd22"),
        };
        upsert_l1_state(&tx, &new_value).unwrap();

        let result = l1_state_at_number(&tx, original.block_number)
            .unwrap()
            .unwrap();
        assert_eq!(result, new_value);
    }
}
