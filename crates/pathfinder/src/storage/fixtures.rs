//! Basic test fixtures for storage.

use crate::{
    core::{
        ClassHash, ContractAddress, ContractNonce, GasPrice, GlobalRoot, SequencerAddress,
        StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp, StorageAddress,
        StorageValue,
    },
    rpc::types::reply::{
        state_update::{
            DeclaredContract, DeployedContract, Nonce, StateDiff, StorageDiff, StorageItem,
        },
        StateUpdate,
    },
    storage::{StarknetBlock, Storage},
};
use rusqlite::Transaction;
use stark_hash::StarkHash;

/// Generate [`StarkHash`] from a sequence of bytes.
macro_rules! hash {
        ($($value:expr),*) => {
            StarkHash::from_be_slice(&[$($value),*]).unwrap()
        };
    }

pub(crate) use hash;

/// Initializers for storage test fixtures.
pub mod init {
    use super::*;
    use crate::storage::{StarknetBlocksTable, StarknetStateUpdatesTable};

    /// Inserts `n` state updates, referring to blocks with numbers `(0..n)` and hashes `("0x0".."0xn")` respectively.
    pub fn with_n_state_updates(tx: &Transaction<'_>, n: u8) -> Vec<StateUpdate> {
        (0..n)
            .into_iter()
            .map(|n| {
                StarknetBlocksTable::insert(tx, &StarknetBlock::nth(n), None).unwrap();
                let update = StateUpdate::with_block_hash(n);
                StarknetStateUpdatesTable::insert(tx, update.block_hash.unwrap(), &update).unwrap();
                update
            })
            .collect()
    }
}

impl StateUpdate {
    /// Creates a [`StateUpdate`] for a block with hash `0xh` filled with arbitrary data useful for testing.
    pub fn with_block_hash(h: u8) -> Self {
        Self {
            block_hash: Some(StarknetBlockHash(hash!(h))),
            new_root: GlobalRoot(hash!(1, h)),
            old_root: GlobalRoot(hash!(2, h)),
            state_diff: StateDiff {
                storage_diffs: vec![StorageDiff {
                    address: ContractAddress(hash!(3, h)),
                    storage_entries: vec![StorageItem {
                        key: StorageAddress(hash!(4, h)),
                        value: StorageValue(hash!(5, h)),
                    }],
                }],
                declared_contracts: vec![DeclaredContract {
                    class_hash: ClassHash(hash!(6, h)),
                }],
                deployed_contracts: vec![DeployedContract {
                    address: ContractAddress(hash!(7, h)),
                    class_hash: ClassHash(hash!(8, h)),
                }],
                nonces: vec![Nonce {
                    contract_address: ContractAddress(hash!(9, h)),
                    nonce: ContractNonce(hash!(10, h)),
                }],
            },
        }
    }
}

impl StarknetBlock {
    /// Creates a [`StarknetBlock`] with number `n` and hash `0xh` filled with arbitrary data useful for testing.
    pub fn nth(n: u8) -> Self {
        Self {
            number: StarknetBlockNumber(n as u64),
            hash: StarknetBlockHash(hash!(n)),
            root: GlobalRoot(hash!(1, n)),
            timestamp: StarknetBlockTimestamp(n as u64 + 1000),
            gas_price: GasPrice(n as u128 + 2000),
            sequencer_address: SequencerAddress(hash!(2, n)),
        }
    }
}

/// Creates test storage in memory that contains N state updates,
/// referring to blocks with numbers (0..N) and ("0x0".."0xN") hashes respectively.
pub fn with_n_state_updates<F>(n: u8, f: F)
where
    F: FnOnce(&Storage, &Transaction<'_>, Vec<StateUpdate>),
{
    let storage = Storage::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    f(&storage, &tx, init::with_n_state_updates(&tx, n))
}
