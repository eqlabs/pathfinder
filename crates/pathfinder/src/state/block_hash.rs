use anyhow::{Context, Result};
use pathfinder_common::event::Event;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    BlockTimestamp,
    Chain,
    ChainId,
    EventCommitment,
    SequencerAddress,
    StarknetVersion,
    StateCommitment,
    TransactionCommitment,
    TransactionSignatureElem,
};
use pathfinder_crypto::hash::{pedersen_hash, HashChain};
use pathfinder_crypto::Felt;
use pathfinder_merkle_tree::TransactionOrEventTree;
use starknet_gateway_types::reply::Block;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Match((TransactionCommitment, EventCommitment)),
    Mismatch,
}

impl VerifyResult {
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match(_))
    }
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
pub fn verify_gateway_block_hash(
    block: &Block,
    chain: Chain,
    chain_id: ChainId,
) -> Result<VerifyResult> {
    let transaction_final_hash_type =
        TransactionCommitmentFinalHashType::for_version(&block.starknet_version);
    let transaction_commitment =
        calculate_transaction_commitment(&block.transactions, transaction_final_hash_type)?;

    let mut block_header_data = BlockHeaderVerificationData::from(block);

    // Older blocks on mainnet don't carry a precalculated transaction
    // commitment.
    if block.transaction_commitment == TransactionCommitment::ZERO {
        block_header_data.transaction_commitment = transaction_commitment;
    } else if transaction_commitment != block.transaction_commitment {
        return Ok(VerifyResult::Mismatch);
    }

    let event_commitment = calculate_event_commitment(
        &block
            .transaction_receipts
            .iter()
            .flat_map(|(_, events)| events)
            .collect::<Vec<_>>(),
    )?;

    // Older blocks on mainnet don't carry a precalculated event
    // commitment.
    if block.event_commitment == EventCommitment::ZERO {
        block_header_data.event_commitment = event_commitment;
    } else if event_commitment != block.event_commitment {
        return Ok(VerifyResult::Mismatch);
    }

    verify_block_hash0(block_header_data, chain, chain_id)
}

pub fn verify_block_hash(
    block_header: &BlockHeader,
    chain: Chain,
    chain_id: ChainId,
) -> Result<VerifyResult> {
    verify_block_hash0(block_header.into(), chain, chain_id)
}

#[derive(Clone, Copy, Debug)]
struct BlockHeaderVerificationData {
    expected_hash: BlockHash,
    parent_hash: BlockHash,
    number: BlockNumber,
    timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    state_commitment: StateCommitment,
    transaction_commitment: TransactionCommitment,
    transaction_count: u64,
    event_commitment: EventCommitment,
    event_count: u64,
}

impl From<&Block> for BlockHeaderVerificationData {
    fn from(block: &Block) -> Self {
        Self {
            expected_hash: block.block_hash,
            parent_hash: block.parent_block_hash,
            number: block.block_number,
            timestamp: block.timestamp,
            sequencer_address: block
                .sequencer_address
                .unwrap_or(SequencerAddress(Felt::ZERO)),
            state_commitment: block.state_commitment,
            transaction_commitment: block.transaction_commitment,
            transaction_count: block
                .transactions
                .len()
                .try_into()
                .expect("ptr size is 64bits"),
            event_commitment: block.event_commitment,
            event_count: block
                .transaction_receipts
                .iter()
                .flat_map(|(_, events)| events)
                .count()
                .try_into()
                .expect("ptr size is 64bits"),
        }
    }
}

impl From<&BlockHeader> for BlockHeaderVerificationData {
    fn from(header: &BlockHeader) -> Self {
        Self {
            expected_hash: header.hash,
            parent_hash: header.parent_hash,
            number: header.number,
            timestamp: header.timestamp,
            sequencer_address: header.sequencer_address,
            state_commitment: header.state_commitment,
            transaction_commitment: header.transaction_commitment,
            transaction_count: header
                .transaction_count
                .try_into()
                .expect("ptr size is 64bits"),
            event_commitment: header.event_commitment,
            event_count: header.event_count.try_into().expect("ptr size is 64bits"),
        }
    }
}

fn verify_block_hash0(
    block_header_data: BlockHeaderVerificationData,
    chain: Chain,
    chain_id: ChainId,
) -> Result<VerifyResult> {
    let BlockHeaderVerificationData {
        expected_hash,
        parent_hash,
        number,
        timestamp,
        sequencer_address,
        state_commitment,
        transaction_commitment,
        transaction_count,
        event_commitment,
        event_count,
    } = block_header_data;

    let meta_info = meta::for_chain(chain);

    let verified = if meta_info.uses_pre_0_7_hash_algorithm(number) {
        anyhow::ensure!(
            chain != Chain::Custom,
            "Chain::Custom should not have any pre 0.7 block hashes"
        );

        let computed_hash = compute_final_hash_pre_0_7(
            number,
            state_commitment,
            transaction_count,
            transaction_commitment.0,
            parent_hash,
            chain_id,
        );
        computed_hash == expected_hash
    } else {
        std::iter::once(&sequencer_address)
            .chain(meta_info.fallback_sequencer_address.iter())
            .any(|address| {
                let computed_hash = compute_final_hash(
                    number,
                    state_commitment,
                    address,
                    timestamp,
                    transaction_count,
                    transaction_commitment.0,
                    event_count,
                    event_commitment.0,
                    parent_hash,
                );
                computed_hash == expected_hash
            })
    };

    Ok(match verified {
        false => VerifyResult::Mismatch,
        true => VerifyResult::Match((transaction_commitment, event_commitment)),
    })
}

mod meta {
    use pathfinder_common::{sequencer_address, BlockNumber, Chain, SequencerAddress};

    /// Metadata about Starknet chains we use for block hash calculation
    ///
    /// Since the method for calculating block hashes has changed during the
    /// operation of the Starknet alpha network, we need this information
    /// to be able to decide which method to use for block hash calculation.
    ///
    /// * Before the Starknet 0.7 release block hashes were calculated with a
    ///   slightly different algorithm (the Starknet chain ID was hashed into
    ///   the final value). Zero was used both instead of the block timestamp
    ///   and the sequencer value.
    /// * After Starknet 0.7 and before Starknet 0.8 the block hash does not
    ///   include the chain id anymore. The proper block timestamp is used but
    ///   zero is used as the sequencer address.
    /// * After Starknet 0.8 and before Starknet 0.8.2 the sequencer address is
    ///   non-zero and is used for the block hash calculation. However, the
    ///   blocks don't include the sequencer address that was used for the
    ///   calculation and for the majority of the blocks the block hash value is
    ///   irrecoverable.
    /// * After Starknet 0.8.2 all blocks include the correct sequencer address
    ///   value.
    #[derive(Clone)]
    pub struct BlockHashMetaInfo {
        /// The number of the first block that was hashed with the Starknet 0.7
        /// hash algorithm.
        pub first_0_7_block: BlockNumber,
        /// Fallback sequencer address to use for blocks that don't include the
        /// address.
        pub fallback_sequencer_address: Option<SequencerAddress>,
    }

    impl BlockHashMetaInfo {
        pub fn uses_pre_0_7_hash_algorithm(&self, block_number: BlockNumber) -> bool {
            block_number < self.first_0_7_block
        }
    }

    const MAINNET_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: BlockNumber::new_or_panic(833),
        fallback_sequencer_address: Some(sequencer_address!(
            "021f4b90b0377c82bf330b7b5295820769e72d79d8acd0effa0ebde6e9988bc5"
        )),
    };

    const SEPOLIA_TESTNET_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: BlockNumber::new_or_panic(0),
        fallback_sequencer_address: None,
    };

    const SEPOLIA_INTEGRATION_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: BlockNumber::new_or_panic(0),
        fallback_sequencer_address: None,
    };

    const CUSTOM_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
        first_0_7_block: BlockNumber::new_or_panic(0),
        fallback_sequencer_address: None,
    };

    pub fn for_chain(chain: Chain) -> &'static BlockHashMetaInfo {
        match chain {
            Chain::Mainnet => &MAINNET_METAINFO,
            Chain::SepoliaTestnet => &SEPOLIA_TESTNET_METAINFO,
            Chain::SepoliaIntegration => &SEPOLIA_INTEGRATION_METAINFO,
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
    block_number: BlockNumber,
    state_root: StateCommitment,
    num_transactions: u64,
    transaction_commitment: Felt,
    parent_block_hash: BlockHash,
    chain_id: pathfinder_common::ChainId,
) -> BlockHash {
    let mut chain = HashChain::default();

    // block number
    chain.update(Felt::from(block_number.get()));
    // global state root
    chain.update(state_root.0);
    // sequencer address: these versions used 0 as the sequencer address
    chain.update(Felt::ZERO);
    // block timestamp: these versions used 0 as a timestamp for block hash
    // computation
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

    BlockHash(chain.finalize())
}

/// This implements the final hashing step for post-0.7 blocks.
#[allow(clippy::too_many_arguments)]
fn compute_final_hash(
    block_number: BlockNumber,
    state_root: StateCommitment,
    sequencer_address: &SequencerAddress,
    timestamp: BlockTimestamp,
    num_transactions: u64,
    transaction_commitment: Felt,
    num_events: u64,
    event_commitment: Felt,
    parent_block_hash: BlockHash,
) -> BlockHash {
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

    BlockHash(chain.finalize())
}

pub enum TransactionCommitmentFinalHashType {
    SignatureIncludedForInvokeOnly,
    Normal,
}

impl TransactionCommitmentFinalHashType {
    pub fn for_version(version: &StarknetVersion) -> Self {
        const V_0_11_1: StarknetVersion = StarknetVersion::new(0, 11, 1, 0);
        if version < &V_0_11_1 {
            Self::SignatureIncludedForInvokeOnly
        } else {
            Self::Normal
        }
    }
}

/// Calculate transaction commitment hash value.
///
/// The transaction commitment is the root of the Patricia Merkle tree with
/// height 64 constructed by adding the (transaction_index,
/// transaction_hash_with_signature) key-value pairs to the tree and computing
/// the root hash.
pub fn calculate_transaction_commitment(
    transactions: &[Transaction],
    final_hash_type: TransactionCommitmentFinalHashType,
) -> Result<TransactionCommitment> {
    use rayon::prelude::*;

    let mut final_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            final_hashes = transactions
                .par_iter()
                .map(|tx| match final_hash_type {
                    TransactionCommitmentFinalHashType::Normal => {
                        calculate_transaction_hash_with_signature(tx)
                    }
                    TransactionCommitmentFinalHashType::SignatureIncludedForInvokeOnly => {
                        calculate_transaction_hash_with_signature_pre_0_11_1(tx)
                    }
                })
                .collect();
        })
    });

    let mut tree = TransactionOrEventTree::default();

    final_hashes
        .into_iter()
        .enumerate()
        .try_for_each(|(idx, final_hash)| {
            let idx: u64 = idx
                .try_into()
                .expect("too many transactions while calculating commitment");
            tree.set(idx, final_hash)
        })
        .context("Building transaction commitment tree")?;

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
fn calculate_transaction_hash_with_signature_pre_0_11_1(tx: &Transaction) -> Felt {
    lazy_static::lazy_static!(
        static ref HASH_OF_EMPTY_LIST: Felt = HashChain::default().finalize();
    );

    let signature_hash = match &tx.variant {
        TransactionVariant::InvokeV0(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::InvokeV1(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::InvokeV3(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeclareV0(_)
        | TransactionVariant::DeclareV1(_)
        | TransactionVariant::DeclareV2(_)
        | TransactionVariant::DeclareV3(_)
        | TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_)
        | TransactionVariant::DeployAccountV1(_)
        | TransactionVariant::DeployAccountV3(_)
        | TransactionVariant::L1Handler(_) => *HASH_OF_EMPTY_LIST,
    };

    pedersen_hash(tx.hash.0, signature_hash)
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

    let signature_hash = match &tx.variant {
        TransactionVariant::InvokeV0(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeclareV0(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeclareV1(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeclareV2(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeclareV3(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeployAccountV1(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeployAccountV3(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::InvokeV1(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::InvokeV3(tx) => calculate_signature_hash(&tx.signature),
        TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_)
        | TransactionVariant::L1Handler(_) => *HASH_OF_EMPTY_LIST,
    };

    pedersen_hash(tx.hash.0, signature_hash)
}

fn calculate_signature_hash(signature: &[TransactionSignatureElem]) -> Felt {
    let mut hash = HashChain::default();
    for s in signature {
        hash.update(s.0);
    }
    hash.finalize()
}

/// Calculate event commitment hash value.
///
/// The event commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (event_index, event_hash) key-value pairs to the
/// tree and computing the root hash.
pub fn calculate_event_commitment(transaction_events: &[&Event]) -> Result<EventCommitment> {
    use rayon::prelude::*;

    let mut event_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            event_hashes = transaction_events
                .par_iter()
                .map(|&e| calculate_event_hash(e))
                .collect();
        })
    });

    let mut tree = TransactionOrEventTree::default();

    event_hashes
        .into_iter()
        .enumerate()
        .try_for_each(|(idx, hash)| {
            let idx: u64 = idx
                .try_into()
                .expect("too many events in transaction receipt");
            tree.set(idx, hash)
        })
        .context("Building event commitment tree")?;

    Ok(EventCommitment(tree.commit()?))
}

/// Calculate the hash of an event.
///
/// See the [documentation](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/starknet-events/#event_hash)
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

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::felt;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::transaction::{EntryPointType, InvokeTransactionV0};
    use pathfinder_crypto::Felt;

    use super::*;

    #[test]
    fn test_event_hash() {
        let event = Event {
            from_address: contract_address!("0xdeadbeef"),
            data: vec![
                event_data!("0x5"),
                event_data!("0x6"),
                event_data!("0x7"),
                event_data!("0x8"),
                event_data!("0x9"),
            ],
            keys: vec![
                event_key!("0x1"),
                event_key!("0x2"),
                event_key!("0x3"),
                event_key!("0x4"),
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
        let transaction = Transaction {
            hash: transaction_hash!("0x1"),
            variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
                sender_address: contract_address!("0xdeadbeef"),
                entry_point_type: Some(EntryPointType::External),
                entry_point_selector: entry_point!("0xe"),
                signature: vec![
                    transaction_signature_elem!("0x2"),
                    transaction_signature_elem!("0x3"),
                ],
                ..Default::default()
            }),
        };

        // produced by the cairo-lang Python implementation:
        // `hex(calculate_single_tx_hash_with_signature(1, [2, 3],
        // hash_function=pedersen_hash))`
        let expected_final_hash =
            Felt::from_hex_str("0x259c3bd5a1951eafb2f41e0b783eab92cfe4e108b2b1f071e3736f06b909431")
                .unwrap();
        let calculated_final_hash = calculate_transaction_hash_with_signature(&transaction);
        assert_eq!(expected_final_hash, calculated_final_hash);
    }

    #[test]
    fn test_block_hash_without_sequencer_address() {
        // This tests with a post-0.7, pre-0.8.0 block where zero is used as the
        // sequencer address.
        let json = starknet_gateway_test_fixtures::v0_7_0::block::MAINNET_2240;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_gateway_block_hash(&block, Chain::Mainnet, ChainId::MAINNET).unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_with_sequencer_address() {
        // This tests with a post-0.8.2 block where we have correct sequencer address
        // information in the block itself.
        let json = starknet_gateway_test_fixtures::v0_9_0::block::MAINNET_2800;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_gateway_block_hash(&block, Chain::Mainnet, ChainId::MAINNET).unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_with_sequencer_address_unavailable_but_not_zero() {
        // This tests with a post-0.8.0 pre-0.8.2 block where we don't have the
        // sequencer address in the JSON but the block hash was calculated with
        // the magic value below instead of zero.
        let json = starknet_gateway_test_fixtures::v0_8_0::block::MAINNET_2500;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_gateway_block_hash(&block, Chain::Mainnet, ChainId::MAINNET).unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_0_11_1() {
        let json = starknet_gateway_test_fixtures::v0_11_1::block::MAINNET_65000;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_gateway_block_hash(&block, Chain::Mainnet, ChainId::MAINNET).unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_0() {
        // This tests with a pre-0.7 block where the chain ID was hashed into
        // the block hash.
        let json = starknet_gateway_test_fixtures::pre_0_7_0::block::MAINNET_GENESIS;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_gateway_block_hash(&block, Chain::Mainnet, ChainId::MAINNET).unwrap(),
            VerifyResult::Match(_)
        );
    }
}
