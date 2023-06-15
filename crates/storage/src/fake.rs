//! Create fake blockchain data for test purposes
use crate::Storage;
use pathfinder_common::{BlockHeader, StateUpdate};
use starknet_gateway_types::reply::transaction as gateway;

/// Initialize [`Storage`] with fake blocks and state updates
/// maintaining [limited consistency guarantees](crate::fake::init::with_n_blocks)
pub fn with_n_blocks(
    storage: &Storage,
    n: usize,
) -> Vec<(
    BlockHeader,
    Vec<(gateway::Transaction, gateway::Receipt)>,
    StateUpdate,
)> {
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();
    let fake_data = init::with_n_blocks(n);
    fake_data
        .iter()
        .for_each(|(header, transaction_data, state_update)| {
            tx.insert_block_header(header).unwrap();
            tx.insert_transaction_data(header.hash, header.number, transaction_data)
                .unwrap();
            tx.insert_state_update(header.number, &state_update)
                .unwrap();
        });
    fake_data
}

/// Raw _fakers_
pub mod init {
    use fake::{Fake, Faker};
    use pathfinder_common::{
        BlockHash, BlockHeader, BlockNumber, StateCommitment, StateUpdate, TransactionIndex,
    };
    use starknet_gateway_types::reply::transaction as gateway;

    /// Create fake blocks and state updates with __very__ limited consistency guarantees
    /// - block headers:
    ///     - consecutive numbering starting from genesis (`0`) up to `n-1`
    ///     - parent hash wrt previous block, genesis' parent hash is `0`
    /// - block bodies:
    ///     - transaction indices within a block
    ///     - transaction hashes in respective receipts
    /// - state updates:
    ///     - block hashes
    ///     - old roots wrt previous state update, genesis' old root is `0`
    ///     
    pub fn with_n_blocks(
        n: usize,
    ) -> Vec<(
        BlockHeader,
        Vec<(gateway::Transaction, gateway::Receipt)>,
        StateUpdate,
    )> {
        let mut init = Vec::with_capacity(n);

        for i in 0..n {
            let mut header = Faker.fake::<BlockHeader>();
            header.number =
                BlockNumber::new_or_panic(i.try_into().expect("u64 is at least as wide as usize"));
            let transactions_and_receipts = Faker
                .fake::<Vec<gateway::Transaction>>()
                .into_iter()
                .enumerate()
                .map(|(i, t)| {
                    let transaction_hash = t.hash();
                    (
                        t,
                        gateway::Receipt {
                            transaction_hash,
                            transaction_index: TransactionIndex::new_or_panic(
                                i.try_into().expect("u64 is at least as wide as usize"),
                            ),
                            ..Faker.fake()
                        },
                    )
                })
                .collect();
            init.push((
                header,
                transactions_and_receipts,
                Faker.fake::<StateUpdate>(),
            ));
        }

        // Fix block headers and state updates
        let (header, _, state_update) = init.get_mut(0).unwrap();
        header.parent_hash = BlockHash::ZERO;
        state_update.block_hash = header.hash;
        state_update.parent_state_commitment = StateCommitment::ZERO;

        for i in 1..n {
            let (parent_hash, parent_state_commitment) = init
                .get(i - 1)
                .map(|(h, _, s)| (h.hash, s.state_commitment))
                .unwrap();
            let (header, _, state_update) = init.get_mut(i).unwrap();
            header.parent_hash = parent_hash;
            state_update.block_hash = header.hash;
            state_update.parent_state_commitment = parent_state_commitment;
        }

        init
    }
}
