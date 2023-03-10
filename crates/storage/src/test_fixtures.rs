//! Basic test fixtures for storage.

use crate::{
    types::{
        state_update::{
            DeclaredCairoClass, DeclaredSierraClass, DeployedContract, Nonce, ReplacedClass,
            StateDiff, StorageDiff,
        },
        StateUpdate,
    },
    {StarknetBlock, Storage},
};
use pathfinder_common::{
    CasmHash, ClassHash, ContractAddress, ContractNonce, GasPrice, SequencerAddress, SierraHash,
    StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp, StateCommitment,
    StorageAddress, StorageValue,
};
use rusqlite::Transaction;
use stark_hash::Felt;

/// Generate [`Felt`] from a sequence of bytes.
macro_rules! hash {
    ($($value:expr),*) => {
        Felt::from_be_slice(&[$($value),*]).unwrap()
    };
}

pub(crate) use hash;

/// Initializers for storage test fixtures.
pub mod init {
    use super::*;
    use crate::{StarknetBlocksTable, StarknetStateUpdatesTable};
    use pathfinder_common::{ClassCommitment, StorageCommitment};

    /// Inserts `n` state updates, referring to blocks with numbers `(0..n)` and hashes `("0x0".."0xn")` respectively.
    pub fn with_n_state_updates(tx: &Transaction<'_>, n: u8) -> Vec<StateUpdate> {
        (0..n)
            .map(|n| {
                StarknetBlocksTable::insert(
                    tx,
                    &StarknetBlock::nth(n),
                    None,
                    StorageCommitment(hash!(11, n)),
                    ClassCommitment(hash!(12, n)),
                )
                .unwrap();
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
            new_root: StateCommitment(hash!(1, h)),
            old_root: StateCommitment(hash!(2, h)),
            state_diff: StateDiff {
                storage_diffs: vec![StorageDiff {
                    address: ContractAddress::new_or_panic(hash!(3, h)),
                    key: StorageAddress::new_or_panic(hash!(4, h)),
                    value: StorageValue(hash!(5, h)),
                }],
                declared_contracts: vec![DeclaredCairoClass {
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
                declared_sierra_classes: vec![DeclaredSierraClass {
                    class_hash: SierraHash(hash!(11, h)),
                    compiled_class_hash: CasmHash(hash!(12, h)),
                }],
                replaced_classes: vec![ReplacedClass {
                    address: ContractAddress::new_or_panic(hash!(13, h)),
                    class_hash: ClassHash(hash!(14, h)),
                }],
            },
        }
    }
}

impl StarknetBlock {
    /// Creates a [`StarknetBlock`] with number `n` and hash `0xh` filled with arbitrary data useful for testing.
    pub fn nth(n: u8) -> Self {
        Self {
            number: StarknetBlockNumber::new(n as u64).expect("block number out of range"),
            hash: StarknetBlockHash(hash!(n)),
            root: StateCommitment(hash!(1, n)),
            timestamp: StarknetBlockTimestamp::new(n as u64 + 1000)
                .expect("block timestamp out of range"),
            gas_price: GasPrice(n as u128 + 2000),
            sequencer_address: SequencerAddress(hash!(2, n)),
            transaction_commitment: None,
            event_commitment: None,
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
