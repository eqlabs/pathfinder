use pathfinder_common::BlockNumber;
use pathfinder_ethereum::EthereumStateUpdate;

use crate::prelude::*;

impl Transaction<'_> {
    pub fn upsert_l1_state(&self, update: &EthereumStateUpdate) -> anyhow::Result<()> {
        self.inner().execute(
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

    pub fn l1_state_at_number(
        &self,
        block: BlockNumber,
    ) -> anyhow::Result<Option<EthereumStateUpdate>> {
        self.inner()
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
                    l1_block_number: None,
                })
            },
        )
        .optional()
        .map_err(|e| e.into())
    }

    pub fn latest_l1_state(&self) -> anyhow::Result<Option<EthereumStateUpdate>> {
        self.inner()
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
                    l1_block_number: None,
                })
            },
        )
        .optional()
        .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHash, StateCommitment};
    use pathfinder_crypto::Felt;
    use pathfinder_ethereum::EthereumStateUpdate;

    use super::*;

    /// Creates a set of consecutive [StateUpdateLog]s starting from L2 genesis,
    /// with arbitrary other values.
    fn create_updates() -> [EthereumStateUpdate; 3] {
        (0..3usize)
            .map(|i| EthereumStateUpdate {
                state_root: StateCommitment(Felt::from_hex_str(&"3".repeat(i + 1)).unwrap()),
                block_number: BlockNumber::GENESIS + i as u64,
                block_hash: BlockHash(Felt::from_hex_str(&"F".repeat(i + 1)).unwrap()),
                l1_block_number: None,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn empty() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let result = tx.l1_state_at_number(BlockNumber::GENESIS).unwrap();
        assert_eq!(result, None);

        let result = tx.latest_l1_state().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn latest() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let updates = create_updates();
        let expected = *updates.last().unwrap();
        for update in updates {
            tx.upsert_l1_state(&update).unwrap();
        }

        let result = tx.latest_l1_state().unwrap().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn upsert_and_at_number() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let updates = create_updates();
        for update in &updates {
            tx.upsert_l1_state(update).unwrap();
        }

        for expected in updates {
            let result = tx.l1_state_at_number(expected.block_number).unwrap();

            assert_eq!(result, Some(expected));
        }
    }

    #[test]
    fn upsert_overwrites() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let original = EthereumStateUpdate {
            state_root: state_commitment!("0x1234"),
            block_number: BlockNumber::new_or_panic(10),
            block_hash: block_hash!("0xabdd"),
            l1_block_number: None,
        };
        tx.upsert_l1_state(&original).unwrap();

        let new_value = EthereumStateUpdate {
            state_root: state_commitment!("0xabcdef"),
            block_number: original.block_number,
            block_hash: block_hash!("0xccdd22"),
            l1_block_number: None,
        };
        tx.upsert_l1_state(&new_value).unwrap();

        let result = tx
            .l1_state_at_number(original.block_number)
            .unwrap()
            .unwrap();
        assert_eq!(result, new_value);
    }
}
