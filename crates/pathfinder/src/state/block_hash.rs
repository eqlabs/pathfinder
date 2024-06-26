use anyhow::{Context, Result};
use pathfinder_common::event::Event;
use pathfinder_common::hash::{FeltHash, PedersenHash, PoseidonHash};
use pathfinder_common::receipt::{ExecutionStatus, Receipt};
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
    TransactionHash,
    TransactionSignatureElem,
};
use pathfinder_crypto::hash::{pedersen_hash, poseidon_hash_many, HashChain, PoseidonHasher};
use pathfinder_crypto::{Felt, MontFelt};
use pathfinder_merkle_tree::TransactionOrEventTree;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha3::Digest;
use starknet_gateway_types::reply::Block;

const V_0_11_1: StarknetVersion = StarknetVersion::new(0, 11, 1, 0);
const V_0_13_2: StarknetVersion = StarknetVersion::new(0, 13, 2, 0);

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
    let transaction_commitment =
        calculate_transaction_commitment(&block.transactions, block.starknet_version)?;

    let mut block_header_data = BlockHeaderData::from(block);

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
            .map(|(receipt, events)| (receipt.transaction_hash, events.as_slice()))
            .collect::<Vec<_>>(),
        block.starknet_version,
    )?;

    // Older blocks on mainnet don't carry a precalculated event
    // commitment.
    if block.event_commitment == EventCommitment::ZERO {
        block_header_data.event_commitment = event_commitment;
    } else if event_commitment != block.event_commitment {
        return Ok(VerifyResult::Mismatch);
    }

    verify_block_hash(block_header_data, chain, chain_id)
}

#[derive(Clone, Copy, Debug)]
pub struct BlockHeaderData {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub number: BlockNumber,
    pub timestamp: BlockTimestamp,
    pub sequencer_address: SequencerAddress,
    pub state_commitment: StateCommitment,
    pub transaction_commitment: TransactionCommitment,
    pub transaction_count: u64,
    pub event_commitment: EventCommitment,
    pub event_count: u64,
}

impl From<&Block> for BlockHeaderData {
    fn from(block: &Block) -> Self {
        Self {
            hash: block.block_hash,
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

impl From<&BlockHeader> for BlockHeaderData {
    fn from(header: &BlockHeader) -> Self {
        Self {
            hash: header.hash,
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

pub fn verify_block_hash(
    block_header_data: BlockHeaderData,
    chain: Chain,
    chain_id: ChainId,
) -> Result<VerifyResult> {
    let BlockHeaderData {
        hash: expected_hash,
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

/// Calculate transaction commitment hash value.
///
/// The transaction commitment is the root of the Patricia Merkle tree with
/// height 64 constructed by adding the (transaction_index,
/// transaction_hash_with_signature) key-value pairs to the tree and computing
/// the root hash.
pub fn calculate_transaction_commitment(
    transactions: &[Transaction],
    version: StarknetVersion,
) -> Result<TransactionCommitment> {
    use rayon::prelude::*;

    let mut final_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            final_hashes = transactions
                .par_iter()
                .map(|tx| {
                    if version < V_0_11_1 {
                        calculate_transaction_hash_with_signature_pre_0_11_1(tx)
                    } else if version < V_0_13_2 {
                        calculate_transaction_hash_with_signature_pre_0_13_2(tx)
                    } else {
                        calculate_transaction_hash_with_signature(tx)
                    }
                })
                .collect();
        })
    });

    if version < V_0_13_2 {
        calculate_commitment_root::<PedersenHash>(final_hashes).map(TransactionCommitment)
    } else {
        calculate_commitment_root::<PoseidonHash>(final_hashes).map(TransactionCommitment)
    }
}

pub fn calculate_receipt_commitment(receipts: &[Receipt]) -> Result<Felt> {
    let mut hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            hashes = receipts
                .par_iter()
                .map(|receipt| {
                    poseidon_hash_many(&[
                        receipt.transaction_hash.0.into(),
                        receipt.actual_fee.0.into(),
                        // Calculate hash of messages sent.
                        {
                            let mut hasher = PoseidonHasher::new();
                            hasher.write((receipt.l2_to_l1_messages.len() as u64).into());
                            for msg in &receipt.l2_to_l1_messages {
                                hasher.write(msg.from_address.0.into());
                                hasher.write(msg.to_address.0.into());
                                hasher.write((msg.payload.len() as u64).into());
                                for payload in &msg.payload {
                                    hasher.write(payload.0.into());
                                }
                            }
                            hasher.finish()
                        },
                        // Calculate hash of execution status.
                        match &receipt.execution_status {
                            ExecutionStatus::Succeeded => MontFelt::ZERO,
                            ExecutionStatus::Reverted { reason } => {
                                let mut keccak = sha3::Keccak256::default();
                                keccak.update(reason.as_bytes());
                                let mut hashed_bytes: [u8; 32] = keccak.finalize().into();
                                hashed_bytes[0] &= 0b00000011_u8; // Discard the six MSBs.
                                MontFelt::from_be_bytes(hashed_bytes)
                            }
                        },
                        MontFelt::ZERO,
                        receipt.execution_resources.data_availability.l1_gas.into(),
                        receipt
                            .execution_resources
                            .data_availability
                            .l1_data_gas
                            .into(),
                    ])
                    .into()
                })
                .collect();
        })
    });
    calculate_commitment_root::<PoseidonHash>(hashes)
}

fn calculate_commitment_root<H: FeltHash>(hashes: Vec<Felt>) -> Result<Felt> {
    let mut tree: TransactionOrEventTree<H> = Default::default();

    hashes
        .into_iter()
        .enumerate()
        .try_for_each(|(idx, final_hash)| {
            let idx: u64 = idx
                .try_into()
                .expect("too many transactions while calculating commitment");
            tree.set(idx, final_hash)
        })
        .context("Building transaction commitment tree")?;

    tree.commit()
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

/// Compute the combined hash of the transaction hash and the signature for
/// block before v0.13.2.
///
/// Since the transaction hash doesn't take the signature values as its input
/// computing the transaction commitment uses a hash value that combines
/// the transaction hash with the array of signature values.
///
/// Note that for non-invoke transactions we don't actually have signatures. The
/// cairo-lang uses an empty list (whose hash is not the ZERO value!) in that
/// case.
fn calculate_transaction_hash_with_signature_pre_0_13_2(tx: &Transaction) -> Felt {
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

/// Compute the combined hash of the transaction hash and the signature.
///
/// [Reference code from StarkWare](https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/block_hash_calculator.rs#L95-L98).
fn calculate_transaction_hash_with_signature(tx: &Transaction) -> Felt {
    let signature = match &tx.variant {
        TransactionVariant::InvokeV0(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV0(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV1(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV2(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV3(tx) => tx.signature.as_slice(),
        TransactionVariant::DeployAccountV1(tx) => tx.signature.as_slice(),
        TransactionVariant::DeployAccountV3(tx) => tx.signature.as_slice(),
        TransactionVariant::InvokeV1(tx) => tx.signature.as_slice(),
        TransactionVariant::InvokeV3(tx) => tx.signature.as_slice(),
        TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_)
        | TransactionVariant::L1Handler(_) => &[TransactionSignatureElem::ZERO],
    };

    let mut hasher = PoseidonHasher::new();
    hasher.write(tx.hash.0.into());
    for elem in signature {
        hasher.write(elem.0.into());
    }
    hasher.finish().into()
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
pub fn calculate_event_commitment(
    transaction_events: &[(TransactionHash, &[Event])],
    version: StarknetVersion,
) -> Result<EventCommitment> {
    use rayon::prelude::*;

    let mut event_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            event_hashes = transaction_events
                .par_iter()
                .flat_map(|(tx_hash, events)| events.par_iter().map(|e| (*tx_hash, e)))
                .map(|(tx_hash, e)| {
                    if version < V_0_13_2 {
                        calculate_event_hash_pre_0_13_2(e)
                    } else {
                        calculate_event_hash(e, tx_hash)
                    }
                })
                .collect();
        })
    });

    if version < V_0_13_2 {
        calculate_commitment_root::<PedersenHash>(event_hashes).map(EventCommitment)
    } else {
        calculate_commitment_root::<PoseidonHash>(event_hashes).map(EventCommitment)
    }
}

/// Calculate the hash of a pre-v0.13.2 Starknet event.
///
/// See the [documentation](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/starknet-events/#event_hash)
/// for details.
fn calculate_event_hash_pre_0_13_2(event: &Event) -> Felt {
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

/// Calculate the hash of an event.
/// [Reference code from StarkWare](https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/event_commitment.rs#L33).
fn calculate_event_hash(event: &Event, transaction_hash: TransactionHash) -> Felt {
    let mut hasher = PoseidonHasher::new();
    hasher.write(event.from_address.0.into());
    hasher.write(transaction_hash.0.into());
    hasher.write((event.keys.len() as u64).into());
    for key in &event.keys {
        hasher.write(key.0.into());
    }
    hasher.write((event.data.len() as u64).into());
    for data in &event.data {
        hasher.write(data.0.into());
    }
    hasher.finish().into()
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::receipt::{
        ExecutionDataAvailability,
        ExecutionResources,
        L2ToL1Message,
    };
    use pathfinder_common::transaction::{
        EntryPointType,
        InvokeTransactionV0,
        InvokeTransactionV3,
    };
    use pathfinder_common::{
        felt,
        ContractAddress,
        EventData,
        EventKey,
        Fee,
        L2ToL1MessagePayloadElem,
        TransactionHash,
    };
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
        let calculated_event_hash = calculate_event_hash_pre_0_13_2(&event);
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
        let calculated_final_hash =
            calculate_transaction_hash_with_signature_pre_0_13_2(&transaction);
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

    /// Source:
    /// https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/transaction_commitment_test.rs#L12-L29.
    #[test]
    fn test_transaction_hash_with_signature_0_13_2() {
        let transaction = Transaction {
            hash: TransactionHash(Felt::ONE),
            variant: TransactionVariant::InvokeV3(InvokeTransactionV3 {
                signature: vec![
                    TransactionSignatureElem(Felt::from_u64(2)),
                    TransactionSignatureElem(Felt::from_u64(3)),
                ],
                ..Default::default()
            }),
        };
        let expected = felt!("0x2f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad082");
        assert_eq!(
            calculate_transaction_hash_with_signature(&transaction),
            expected
        );

        let transaction = Transaction {
            hash: TransactionHash(Felt::ONE),
            variant: TransactionVariant::L1Handler(Default::default()),
        };
        let expected = felt!("0x00a93bf5e58b9378d093aa86ddc2f61a3295a1d1e665bd0ef3384dd07b30e033");
        assert_eq!(
            calculate_transaction_hash_with_signature(&transaction),
            expected
        );
    }

    /// Source:
    /// https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/transaction_commitment_test.rs#L32.
    #[test]
    fn test_transaction_commitment_0_13_2() {
        let transaction = Transaction {
            hash: TransactionHash(Felt::ONE),
            variant: TransactionVariant::InvokeV3(InvokeTransactionV3 {
                signature: vec![
                    TransactionSignatureElem(Felt::from_u64(2)),
                    TransactionSignatureElem(Felt::from_u64(3)),
                ],
                ..Default::default()
            }),
        };
        let expected = TransactionCommitment(felt!(
            "0x0282b635972328bd1cfa86496fe920d20bd9440cd78ee8dc90ae2b383d664dcf"
        ));
        assert_eq!(
            calculate_transaction_commitment(&[transaction.clone(), transaction], V_0_13_2)
                .unwrap(),
            expected
        );
    }

    /// Source:
    /// https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/event_commitment_test.rs#L10.
    #[test]
    fn test_event_commitment_0_13_2() {
        let events = &[get_event(0), get_event(1), get_event(2)];
        let expected = felt!("0x069bb140ddbbeb01d81c7201ecfb933031306e45dab9c77ff9f9ba3cd4c2b9c3");
        assert_eq!(
            calculate_event_commitment(&[(transaction_hash!("0x1234"), events)], V_0_13_2)
                .unwrap()
                .0,
            expected
        );

        fn get_event(seed: u64) -> Event {
            Event {
                from_address: ContractAddress(Felt::from_u64(seed + 8)),
                keys: [seed, seed + 1]
                    .iter()
                    .map(|key| EventKey(Felt::from(*key)))
                    .collect(),
                data: [seed + 2, seed + 3, seed + 4]
                    .into_iter()
                    .map(Felt::from)
                    .map(EventData)
                    .collect(),
            }
        }
    }

    // Source:
    // https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/receipt_commitment_test.rs#L16.
    #[test]
    fn test_receipt_commitment_0_13_2() {
        let receipt = Receipt {
            transaction_hash: TransactionHash(1234_u64.into()),
            actual_fee: Fee(99804_u64.into()),
            l2_to_l1_messages: vec![
                L2ToL1Message {
                    from_address: ContractAddress(34_u64.into()),
                    to_address: ContractAddress(35_u64.into()),
                    payload: vec![
                        L2ToL1MessagePayloadElem(Felt::from_u64(36_u64.into())),
                        L2ToL1MessagePayloadElem(Felt::from_u64(37_u64.into())),
                    ],
                },
                L2ToL1Message {
                    from_address: ContractAddress(56_u64.into()),
                    to_address: ContractAddress(57_u64.into()),
                    payload: vec![
                        L2ToL1MessagePayloadElem(Felt::from_u64(58_u64.into())),
                        L2ToL1MessagePayloadElem(Felt::from_u64(59_u64.into())),
                    ],
                },
            ],
            execution_resources: ExecutionResources {
                data_availability: ExecutionDataAvailability {
                    l1_gas: 16580,
                    l1_data_gas: 32,
                },
                ..Default::default()
            },
            execution_status: ExecutionStatus::Reverted {
                reason: "aborted".to_string(),
            },
            ..Default::default()
        };
        let expected_root =
            felt!("0x31963cb891ebb825e83514deb748c89b6967b5368cbc48a9b56193a1464ca87");
        assert_eq!(
            calculate_receipt_commitment(&[receipt]).unwrap(),
            expected_root
        );
    }
}
