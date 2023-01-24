use anyhow::{Context, Error, Result};
use bitvec::prelude::BitView;
use pathfinder_common::{
    Chain, EventCommitment, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
    StarknetBlockTimestamp, StateCommitment, TransactionCommitment,
};
use pathfinder_merkle_tree::merkle_tree::MerkleTree;
use stark_hash::{stark_hash, Felt, HashChain};
use starknet_gateway_types::reply::{
    transaction::{Event, Receipt, Transaction},
    Block,
};

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Match((TransactionCommitment, EventCommitment)),
    Mismatch,
    NotVerifiable,
}

/// Verify the block hash value.
///
/// The method to compute the block hash is documented
/// [here](https://docs.starknet.io/docs/Blocks/header/#block-hash).
///
/// Unfortunately that'a not-fully-correct description, since the transaction
/// commitment Merkle tree is not constructed directly with the transaction
/// hashes, but with a hash computed from the transaction hash and the signature
/// values (for invoke transactions).
///
/// See the `compute_block_hash.py` helper script that uses the cairo-lang
/// Python implementation to compute the block hash for details.
pub fn verify_block_hash(
    block: &Block,
    chain: Chain,
    expected_block_hash: StarknetBlockHash,
) -> Result<VerifyResult> {
    let meta_info = meta::for_chain(chain);
    if !meta_info.can_verify(block.block_number) {
        return Ok(VerifyResult::NotVerifiable);
    }

    let num_transactions: u64 = block
        .transactions
        .len()
        .try_into()
        .expect("too many transactions in block");
    let transaction_commitment = calculate_transaction_commitment(&block.transactions)?;
    let event_commitment = calculate_event_commitment(&block.transaction_receipts)?;

    let verified = if meta_info.uses_pre_0_7_hash_algorithm(block.block_number) {
        use pathfinder_common::ChainId;
        let chain_id = match chain {
            Chain::Mainnet => ChainId::MAINNET,
            Chain::Testnet => ChainId::TESTNET,
            Chain::Integration => ChainId::INTEGRATION,
            Chain::Testnet2 => ChainId::TESTNET2,
            Chain::Custom => {
                anyhow::bail!("Chain::Custom should not have any pre 0.7 block hashes")
            }
        };

        let block_hash = compute_final_hash_pre_0_7(
            block.block_number,
            block.state_commitment,
            num_transactions,
            transaction_commitment.0,
            block.parent_block_hash,
            chain_id,
        );
        block_hash == expected_block_hash
    } else {
        let num_events = number_of_events_in_block(block);
        let num_events: u64 = num_events.try_into().expect("too many events in block");

        let block_sequencer_address = block
            .sequencer_address
            .unwrap_or(SequencerAddress(Felt::ZERO));

        std::iter::once(&block_sequencer_address)
            .chain(meta_info.fallback_sequencer_address.iter())
            .any(|address| {
                let block_hash = compute_final_hash(
                    block.block_number,
                    block.state_commitment,
                    address,
                    block.timestamp,
                    num_transactions,
                    transaction_commitment.0,
                    num_events,
                    event_commitment.0,
                    block.parent_block_hash,
                );
                block_hash == expected_block_hash
            })
    };

    Ok(match verified {
        false => VerifyResult::Mismatch,
        true => VerifyResult::Match((transaction_commitment, event_commitment)),
    })
}

mod meta {
    use pathfinder_common::{felt, Chain, SequencerAddress, StarknetBlockNumber};
    use std::ops::Range;

    /// Metadata about Starknet chains we use for block hash calculation
    ///
    /// Since the method for calculating block hashes has changed during the
    /// operation of the Starknet alpha network, we need this information
    /// to be able to decide which method to use for block hash calculation.
    ///
    /// * Before the Starknet 0.7 release block hashes were calculated with
    ///   a slightly different algorithm (the Starknet chain ID was hashed
    ///   into the final value). Zero was used both instead of the block
    ///   timestamp and the sequencer value.
    /// * After Starknet 0.7 and before Starknet 0.8 the block hash does
    ///   not include the chain id anymore. The proper block timestamp is used
    ///   but zero is used as the sequencer address.
    /// * After Starknet 0.8 and before Starknet 0.8.2 the sequencer address
    ///   is non-zero and is used for the block hash calculation. However, the
    ///   blocks don't include the sequencer address that was used for the
    ///   calculation and for the majority of the blocks the block hash
    ///   value is irrecoverable.
    /// * After Starknet 0.8.2 all blocks include the correct sequencer address
    ///   value.
    #[derive(Clone)]
    pub struct BlockHashMetaInfo {
        /// The number of the first block that was hashed with the Starknet 0.7 hash algorithm.
        pub first_0_7_block: StarknetBlockNumber,
        /// The range of block numbers that can't be verified because of an unknown sequencer address.
        pub not_verifiable_range: Option<Range<StarknetBlockNumber>>,
        /// Fallback sequencer address to use for blocks that don't include the address.
        pub fallback_sequencer_address: Option<SequencerAddress>,
    }

    impl BlockHashMetaInfo {
        pub fn can_verify(&self, block_number: StarknetBlockNumber) -> bool {
            match &self.not_verifiable_range {
                Some(range) => !range.contains(&block_number),
                None => true,
            }
        }

        pub fn uses_pre_0_7_hash_algorithm(&self, block_number: StarknetBlockNumber) -> bool {
            block_number < self.first_0_7_block
        }
    }

    const TESTNET_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: StarknetBlockNumber::new_or_panic(47028),
        not_verifiable_range: Some(
            StarknetBlockNumber::new_or_panic(119802)..StarknetBlockNumber::new_or_panic(148428),
        ),
        fallback_sequencer_address: Some(SequencerAddress(felt!(
            "046a89ae102987331d369645031b49c27738ed096f2789c24449966da4c6de6b"
        ))),
    };

    const TESTNET2_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: StarknetBlockNumber::new_or_panic(0),
        not_verifiable_range: None,
        fallback_sequencer_address: Some(SequencerAddress(felt!(
            "046a89ae102987331d369645031b49c27738ed096f2789c24449966da4c6de6b"
        ))),
    };

    const MAINNET_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: StarknetBlockNumber::new_or_panic(833),
        not_verifiable_range: None,
        fallback_sequencer_address: Some(SequencerAddress(felt!(
            "021f4b90b0377c82bf330b7b5295820769e72d79d8acd0effa0ebde6e9988bc5"
        ))),
    };

    const INTEGRATION_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: StarknetBlockNumber::new_or_panic(110511),
        not_verifiable_range: Some(
            StarknetBlockNumber::new_or_panic(0)..StarknetBlockNumber::new_or_panic(110511),
        ),
        fallback_sequencer_address: Some(SequencerAddress(felt!(
            "046a89ae102987331d369645031b49c27738ed096f2789c24449966da4c6de6b"
        ))),
    };

    const CUSTOM_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: StarknetBlockNumber::new_or_panic(0),
        not_verifiable_range: None,
        fallback_sequencer_address: None,
    };

    pub fn for_chain(chain: Chain) -> &'static BlockHashMetaInfo {
        match chain {
            Chain::Mainnet => &MAINNET_METAINFO,
            Chain::Testnet => &TESTNET_METAINFO,
            Chain::Testnet2 => &TESTNET2_METAINFO,
            Chain::Integration => &INTEGRATION_METAINFO,
            Chain::Custom => &CUSTOM_METAINFO,
        }
    }
}

/// Computes the final block hash for pre-0.7 blocks.
///
/// This deviates from later algorithms by hashing a chain-specific
/// ID into the final hash.
///
/// Note that for these blocks we're using zero for:
///   * timestamps
///   * sequencer addresses
///   * event number and event commitment
fn compute_final_hash_pre_0_7(
    block_number: StarknetBlockNumber,
    state_root: StateCommitment,
    num_transactions: u64,
    transaction_commitment: Felt,
    parent_block_hash: StarknetBlockHash,
    chain_id: pathfinder_common::ChainId,
) -> StarknetBlockHash {
    let mut chain = HashChain::default();

    // block number
    chain.update(Felt::from(block_number.get()));
    // global state root
    chain.update(state_root.0);
    // sequencer address: these versions used 0 as the sequencer address
    chain.update(Felt::ZERO);
    // block timestamp: these versions used 0 as a timestamp for block hash computation
    chain.update(Felt::ZERO);
    // number of transactions
    chain.update(Felt::from(num_transactions));
    // transaction commitment
    chain.update(transaction_commitment);
    // number of events
    chain.update(Felt::ZERO);
    // event commitment
    chain.update(Felt::ZERO);
    // reserved: protocol version
    chain.update(Felt::ZERO);
    // reserved: extra data
    chain.update(Felt::ZERO);
    // EXTRA FIELD: chain id
    chain.update(chain_id.0);
    // parent block hash
    chain.update(parent_block_hash.0);

    StarknetBlockHash(chain.finalize())
}

/// This implements the final hashing step for post-0.7 blocks.
#[allow(clippy::too_many_arguments)]
fn compute_final_hash(
    block_number: StarknetBlockNumber,
    state_root: StateCommitment,
    sequencer_address: &SequencerAddress,
    timestamp: StarknetBlockTimestamp,
    num_transactions: u64,
    transaction_commitment: Felt,
    num_events: u64,
    event_commitment: Felt,
    parent_block_hash: StarknetBlockHash,
) -> StarknetBlockHash {
    let mut chain = HashChain::default();

    // block number
    chain.update(Felt::from(block_number.get()));
    // global state root
    chain.update(state_root.0);
    // sequencer address
    chain.update(sequencer_address.0);
    // block timestamp
    chain.update(Felt::from(timestamp.get()));
    // number of transactions
    chain.update(Felt::from(num_transactions));
    // transaction commitment
    chain.update(transaction_commitment);
    // number of events
    chain.update(Felt::from(num_events));
    // event commitment
    chain.update(event_commitment);
    // reserved: protocol version
    chain.update(Felt::ZERO);
    // reserved: extra data
    chain.update(Felt::ZERO);
    // parent block hash
    chain.update(parent_block_hash.0);

    StarknetBlockHash(chain.finalize())
}

/// A Patricia Merkle tree with height 64 used to compute transaction and event commitments.
///
/// According to the [documentation](https://docs.starknet.io/docs/Blocks/header/#block-header)
/// the commitment trees are of height 64, because the key used is the 64 bit representation
/// of the index of the transaction / event within the block.
///
/// The tree height is 64 in our case since our set operation takes u64 index values.
struct CommitmentTree {
    tree: MerkleTree<(), pathfinder_merkle_tree::PedersenHash>,
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self {
            tree: MerkleTree::empty((), 64),
        }
    }
}

impl CommitmentTree {
    pub fn set(&mut self, index: u64, value: Felt) -> Result<()> {
        let key = index.to_be_bytes();
        self.tree.set(key.view_bits(), value)
    }

    pub fn commit(self) -> Result<Felt> {
        self.tree.commit()
    }
}

/// Calculate transaction commitment hash value.
///
/// The transaction commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (transaction_index, transaction_hash_with_signature)
/// key-value pairs to the tree and computing the root hash.
pub fn calculate_transaction_commitment(
    transactions: &[Transaction],
) -> Result<TransactionCommitment> {
    let mut tree = CommitmentTree::default();

    transactions
        .iter()
        .enumerate()
        .try_for_each(|(idx, tx)| {
            let idx: u64 = idx
                .try_into()
                .expect("too many transactions while calculating commitment");
            let final_hash = calculate_transaction_hash_with_signature(tx);
            tree.set(idx, final_hash)?;
            Result::<_, Error>::Ok(())
        })
        .context("Failed to create transaction commitment tree")?;

    Ok(TransactionCommitment(tree.commit()?))
}

/// Compute the combined hash of the transaction hash and the signature.
///
/// Since the transaction hash doesn't take the signature values as its input
/// computing the transaction commitent uses a hash value that combines
/// the transaction hash with the array of signature values.
///
/// Note that for non-invoke transactions we don't actually have signatures. The
/// cairo-lang uses an empty list (whose hash is not the ZERO value!) in that
/// case.
fn calculate_transaction_hash_with_signature(tx: &Transaction) -> Felt {
    lazy_static::lazy_static!(
        static ref HASH_OF_EMPTY_LIST: Felt = HashChain::default().finalize();
    );

    let signature_hash = match tx {
        Transaction::Invoke(tx) => {
            let mut hash = HashChain::default();
            for signature in tx.signature() {
                hash.update(signature.0);
            }
            hash.finalize()
        }
        Transaction::Declare(_)
        | Transaction::Deploy(_)
        | Transaction::DeployAccount(_)
        | Transaction::L1Handler(_) => *HASH_OF_EMPTY_LIST,
    };

    stark_hash(tx.hash().0, signature_hash)
}

/// Calculate event commitment hash value.
///
/// The event commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (event_index, event_hash) key-value pairs to the
/// tree and computing the root hash.
pub fn calculate_event_commitment(transaction_receipts: &[Receipt]) -> Result<EventCommitment> {
    let mut tree = CommitmentTree::default();

    transaction_receipts
        .iter()
        .flat_map(|receipt| receipt.events.iter())
        .enumerate()
        .try_for_each(|(idx, e)| {
            let idx: u64 = idx
                .try_into()
                .expect("too many events in transaction receipt");
            let event_hash = calculate_event_hash(e);
            tree.set(idx, event_hash)?;
            Result::<_, Error>::Ok(())
        })
        .context("Failed to create event commitment tree")?;

    Ok(EventCommitment(tree.commit()?))
}

/// Calculate the hash of an event.
///
/// See the [documentation](https://docs.starknet.io/docs/Events/starknet-events#event-hash)
/// for details.
fn calculate_event_hash(event: &Event) -> Felt {
    let mut keys_hash = HashChain::default();
    for key in event.keys.iter() {
        keys_hash.update(key.0);
    }
    let keys_hash = keys_hash.finalize();

    let mut data_hash = HashChain::default();
    for data in event.data.iter() {
        data_hash.update(data.0);
    }
    let data_hash = data_hash.finalize();

    let mut event_hash = HashChain::default();
    event_hash.update(*event.from_address.get());
    event_hash.update(keys_hash);
    event_hash.update(data_hash);

    event_hash.finalize()
}

/// Return the number of events in the block.
fn number_of_events_in_block(block: &Block) -> usize {
    block
        .transaction_receipts
        .iter()
        .flat_map(|r| r.events.iter())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use pathfinder_common::{felt, EntryPoint, Fee};
    use starknet_gateway_types::reply::{
        transaction::{EntryPointType, InvokeTransaction, InvokeTransactionV0},
        Block,
    };

    #[test]
    fn test_event_hash() {
        use pathfinder_common::{ContractAddress, EventData, EventKey};

        let event = Event {
            from_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
            data: vec![
                EventData(felt!("0x5")),
                EventData(felt!("0x6")),
                EventData(felt!("0x7")),
                EventData(felt!("0x8")),
                EventData(felt!("0x9")),
            ],
            keys: vec![
                EventKey(felt!("0x1")),
                EventKey(felt!("0x2")),
                EventKey(felt!("0x3")),
                EventKey(felt!("0x4")),
            ],
        };

        // produced by the cairo-lang Python implementation:
        // `hex(calculate_event_hash(0xdeadbeef, [1, 2, 3, 4], [5, 6, 7, 8, 9]))`
        let expected_event_hash =
            felt!("0xdb96455b3a61f9139f7921667188d31d1e1d49fb60a1aa3dbf3756dbe3a9b4");
        let calculated_event_hash = calculate_event_hash(&event);
        assert_eq!(expected_event_hash, calculated_event_hash);
    }

    #[test]
    fn test_final_transaction_hash() {
        use pathfinder_common::{
            ContractAddress, StarknetTransactionHash, TransactionSignatureElem,
        };

        let transaction = Transaction::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
            calldata: vec![],
            sender_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
            entry_point_type: Some(EntryPointType::External),
            entry_point_selector: EntryPoint(felt!("0xe")),
            max_fee: Fee(0u128.to_be_bytes().into()),
            signature: vec![
                TransactionSignatureElem(felt!("0x2")),
                TransactionSignatureElem(felt!("0x3")),
            ],
            transaction_hash: StarknetTransactionHash(felt!("0x1")),
        }));

        // produced by the cairo-lang Python implementation:
        // `hex(calculate_single_tx_hash_with_signature(1, [2, 3], hash_function=pedersen_hash))`
        let expected_final_hash =
            Felt::from_hex_str("0x259c3bd5a1951eafb2f41e0b783eab92cfe4e108b2b1f071e3736f06b909431")
                .unwrap();
        let calculated_final_hash = calculate_transaction_hash_with_signature(&transaction);
        assert_eq!(expected_final_hash, calculated_final_hash);
    }

    #[test]
    fn test_commitment_merkle_tree() {
        let mut tree = CommitmentTree::default();

        for (idx, hash) in [1u64, 2, 3, 4].into_iter().enumerate() {
            let hash = Felt::from(hash);
            let idx: u64 = idx.try_into().unwrap();
            tree.set(idx, hash).unwrap();
        }

        // produced by the cairo-lang Python implementation:
        // `hex(asyncio.run(calculate_patricia_root([1, 2, 3, 4], height=64, ffc=ffc))))`
        let expected_root_hash =
            felt!("0x1a0e579b6b444769e4626331230b5ae39bd880f47e703b73fa56bf77e52e461");
        let computed_root_hash = tree.commit().unwrap();

        assert_eq!(expected_root_hash, computed_root_hash);
    }

    #[test]
    fn test_number_of_events_in_block() {
        let json = starknet_gateway_test_fixtures::v0_9_0::block::NUMBER_156000;
        let block: Block = serde_json::from_str(json).unwrap();

        // this expected value comes from processing the raw JSON and counting the number of events
        const EXPECTED_NUMBER_OF_EVENTS: usize = 55;
        assert_eq!(number_of_events_in_block(&block), EXPECTED_NUMBER_OF_EVENTS);
    }

    #[test]
    fn test_block_hash_without_sequencer_address() {
        // This tests with a post-0.7, pre-0.8.0 block where zero is used as the sequencer address.
        let json = starknet_gateway_test_fixtures::v0_9_0::block::NUMBER_90000;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_block_hash(&block, Chain::Testnet, block.block_hash).unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_with_sequencer_address() {
        // This tests with a post-0.8.2 block where we have correct sequencer address
        // information in the block itself.
        let json = starknet_gateway_test_fixtures::v0_9_0::block::NUMBER_231579;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_block_hash(&block, Chain::Testnet, block.block_hash).unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_with_sequencer_address_unavailable_but_not_zero() {
        // This tests with a post-0.8.0 pre-0.8.2 block where we don't have the sequencer
        // address in the JSON but the block hash was calculated with the magic value below
        // instead of zero.
        let json = starknet_gateway_test_fixtures::v0_9_0::block::NUMBER_156000;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_block_hash(&block, Chain::Testnet, block.block_hash,).unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_0() {
        // This tests with a pre-0.7 block where the chain ID was hashed into
        // the block hash.
        let json = starknet_gateway_test_fixtures::v0_9_0::block::GENESIS;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_block_hash(&block, Chain::Testnet, block.block_hash).unwrap(),
            VerifyResult::Match(_)
        );
    }
}
