//! Basic test fixtures for storage.

use crate::core::{
    ClassHash, ContractAddress, ContractNonce, GasPrice, GlobalRoot, SequencerAddress,
    StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp, StorageAddress, StorageValue,
};
use crate::rpc::v01::types::reply::{
    state_update::{DeclaredContract, DeployedContract, Nonce, StateDiff, StorageDiff},
    StateUpdate,
};
use crate::sequencer;
use crate::storage::{StarknetBlock, Storage};
use rusqlite::Transaction;
use stark_hash::StarkHash;
use std::collections::HashMap;

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

    /// Inserts `N` state updates, referring to blocks with numbers `(0..N)` and hashes `("0x0".."0xN")` respectively.
    pub fn with_n_state_updates(tx: &Transaction<'_>, n: u8) -> Vec<StateUpdate> {
        (0..n)
            .into_iter()
            .map(|n| {
                let block = StarknetBlock::nth(n);
                StarknetBlocksTable::insert(tx, &block, None).unwrap();
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
                    address: ContractAddress::new_or_panic(hash!(3, h)),
                    key: StorageAddress::new_or_panic(hash!(4, h)),
                    value: StorageValue(hash!(5, h)),
                }],
                declared_contracts: vec![DeclaredContract {
                    class_hash: ClassHash(hash!(6, h)),
                }],
                deployed_contracts: vec![DeployedContract {
                    address: ContractAddress::new_or_panic(hash!(7, h)),
                    class_hash: ClassHash(hash!(8, h)),
                }],
                nonces: vec![Nonce {
                    contract_address: ContractAddress::new_or_panic(hash!(9, h)),
                    nonce: ContractNonce(hash!(10, h)),
                }],
            },
        }
    }
}

impl StarknetBlock {
    /// Creates a [`StarknetBlock`] with number `N` and hash `0xN` filled with arbitrary data useful for testing.
    pub fn nth(n: u8) -> Self {
        Self {
            number: StarknetBlockNumber::new(n as u64).expect("block number out of range"),
            hash: StarknetBlockHash(hash!(n)),
            root: GlobalRoot(hash!(1, n)),
            timestamp: StarknetBlockTimestamp::new(n as u64 + 1000)
                .expect("block timestamp out of range"),
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

/// Helper type which allows for more flexible pending data setup
#[derive(Clone, Debug)]
pub struct RawPendingData {
    pub block: Option<sequencer::reply::PendingBlock>,
    pub state_update: Option<sequencer::reply::StateUpdate>,
}

impl sequencer::reply::PendingBlock {
    /// Use in tests where an instance has to be provided for initializatioin
    /// because the api does not accept `Option<PendingBlock>` but otherwise
    /// the values will not be used.
    pub fn dummy_for_test() -> Self {
        Self {
            gas_price: GasPrice::ZERO,
            parent_hash: StarknetBlockHash(StarkHash::ZERO),
            sequencer_address: SequencerAddress(StarkHash::ZERO),
            status: sequencer::reply::Status::AcceptedOnL1,
            timestamp: StarknetBlockTimestamp::new_or_panic(0),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: None,
        }
    }
}

impl sequencer::reply::StateUpdate {
    /// Use in tests where an instance has to be provided for initializatioin
    /// because the api does not accept `Option<StateUpdate>` but otherwise
    /// the values will not be used.
    pub fn dummy_for_test() -> Self {
        Self {
            block_hash: None,
            new_root: GlobalRoot(StarkHash::ZERO),
            old_root: GlobalRoot(StarkHash::ZERO),
            state_diff: sequencer::reply::state_update::StateDiff {
                storage_diffs: HashMap::new(),
                deployed_contracts: vec![],
                declared_contracts: vec![],
                nonces: HashMap::new(),
            },
        }
    }
}
