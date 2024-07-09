use std::io::Write;

use anyhow::{Context, Result};
use pathfinder_common::event::Event;
use pathfinder_common::hash::{FeltHash, PedersenHash, PoseidonHash};
use pathfinder_common::receipt::{ExecutionStatus, Receipt};
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    felt_bytes,
    BlockHash,
    BlockHeader,
    BlockNumber,
    BlockTimestamp,
    Chain,
    ChainId,
    EventCommitment,
    GasPrice,
    L1DataAvailabilityMode,
    ReceiptCommitment,
    SequencerAddress,
    SignedBlockHeader,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
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
    state_diff_commitment: StateDiffCommitment,
    state_diff_length: u64,
    chain: Chain,
    chain_id: ChainId,
) -> Result<VerifyResult> {
    let transaction_commitment =
        calculate_transaction_commitment(&block.transactions, block.starknet_version)?;

    let mut block_header_data =
        BlockHeaderData::from_block(block, state_diff_commitment, state_diff_length)?;

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

#[derive(Clone, Debug, Default)]
pub struct BlockHeaderData {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub number: BlockNumber,
    pub timestamp: BlockTimestamp,
    pub sequencer_address: SequencerAddress,
    pub state_commitment: StateCommitment,
    pub state_diff_commitment: StateDiffCommitment,
    pub transaction_commitment: TransactionCommitment,
    pub transaction_count: u64,
    pub event_commitment: EventCommitment,
    pub event_count: u64,
    pub state_diff_length: u64,
    pub starknet_version: StarknetVersion,
    pub starknet_version_str: String,
    pub eth_l1_gas_price: GasPrice,
    pub strk_l1_gas_price: GasPrice,
    pub eth_l1_data_gas_price: GasPrice,
    pub strk_l1_data_gas_price: GasPrice,
    pub receipt_commitment: ReceiptCommitment,
    pub l1_da_mode: L1DataAvailabilityMode,
}

impl BlockHeaderData {
    pub fn from_header(
        header: &BlockHeader,
        receipt_commitment: ReceiptCommitment,
        state_diff_commitment: StateDiffCommitment,
        state_diff_length: u64,
    ) -> Self {
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
            starknet_version: header.starknet_version,
            starknet_version_str: header.starknet_version.to_string(),
            state_diff_length,
            eth_l1_gas_price: header.eth_l1_gas_price,
            strk_l1_gas_price: header.strk_l1_gas_price,
            eth_l1_data_gas_price: header.eth_l1_data_gas_price,
            strk_l1_data_gas_price: header.strk_l1_data_gas_price,
            receipt_commitment,
            l1_da_mode: header.l1_da_mode,
            state_diff_commitment,
        }
    }

    pub fn from_block(
        block: &Block,
        state_diff_commitment: StateDiffCommitment,
        state_diff_length: u64,
    ) -> Result<Self> {
        let receipts = block
            .transaction_receipts
            .iter()
            .map(|(receipt, _)| receipt.clone())
            .collect::<Vec<_>>();
        let receipt_commitment = calculate_receipt_commitment(&receipts)?;
        Ok(Self {
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
            starknet_version: block.starknet_version,
            starknet_version_str: block.starknet_version.to_string(),
            state_diff_commitment,
            state_diff_length,
            eth_l1_gas_price: block.l1_gas_price.price_in_wei,
            strk_l1_gas_price: block.l1_gas_price.price_in_fri,
            eth_l1_data_gas_price: block.l1_data_gas_price.price_in_wei,
            strk_l1_data_gas_price: block.l1_data_gas_price.price_in_fri,
            receipt_commitment,
            l1_da_mode: block.l1_da_mode.into(),
        })
    }

    pub fn from_signed_header(
        sbh: &SignedBlockHeader,
        receipt_commitment: ReceiptCommitment,
    ) -> Self {
        Self {
            hash: sbh.header.hash,
            parent_hash: sbh.header.parent_hash,
            number: sbh.header.number,
            timestamp: sbh.header.timestamp,
            sequencer_address: sbh.header.sequencer_address,
            state_commitment: sbh.header.state_commitment,
            transaction_commitment: sbh.header.transaction_commitment,
            transaction_count: sbh
                .header
                .transaction_count
                .try_into()
                .expect("ptr size is 64 bits"),
            event_commitment: sbh.header.event_commitment,
            event_count: sbh
                .header
                .event_count
                .try_into()
                .expect("ptr size is 64 bits"),
            state_diff_commitment: sbh.state_diff_commitment,
            state_diff_length: sbh.state_diff_length,
            starknet_version: sbh.header.starknet_version,
            starknet_version_str: sbh.header.starknet_version.to_string(),
            eth_l1_gas_price: sbh.header.eth_l1_gas_price,
            strk_l1_gas_price: sbh.header.strk_l1_gas_price,
            eth_l1_data_gas_price: sbh.header.eth_l1_data_gas_price,
            strk_l1_data_gas_price: sbh.header.strk_l1_data_gas_price,
            receipt_commitment,
            l1_da_mode: sbh.header.l1_da_mode,
        }
    }
}

pub fn verify_block_hash(
    header: BlockHeaderData,
    chain: Chain,
    chain_id: ChainId,
) -> Result<VerifyResult> {
    let meta_info = meta::for_chain(chain);

    let verified = if meta_info.uses_pre_0_7_hash_algorithm(header.number) {
        anyhow::ensure!(
            chain != Chain::Custom,
            "Chain::Custom should not have any pre 0.7 block hashes"
        );

        let computed_hash = compute_final_hash_pre_0_7(&header, chain_id);
        computed_hash == header.hash
    } else if header.starknet_version < V_0_13_2 {
        let computed_hash = compute_final_hash_pre_0_13_2(&header);
        if computed_hash == header.hash {
            true
        } else if let Some(fallback_sequencer_address) = meta_info.fallback_sequencer_address {
            // Try with the fallback sequencer address.
            let computed_hash = compute_final_hash_pre_0_13_2(&BlockHeaderData {
                sequencer_address: fallback_sequencer_address,
                ..header
            });
            computed_hash == header.hash
        } else {
            false
        }
    } else {
        let computed_hash = compute_final_hash(&header)?;
        computed_hash == header.hash
    };

    Ok(match verified {
        false => VerifyResult::Mismatch,
        true => VerifyResult::Match((header.transaction_commitment, header.event_commitment)),
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
fn compute_final_hash_pre_0_7(header: &BlockHeaderData, chain_id: ChainId) -> BlockHash {
    let mut chain = HashChain::default();

    // block number
    chain.update(Felt::from(header.number.get()));
    // global state root
    chain.update(header.state_commitment.0);
    // sequencer address: these versions used 0 as the sequencer address
    chain.update(Felt::ZERO);
    // block timestamp: these versions used 0 as a timestamp for block hash
    // computation
    chain.update(Felt::ZERO);
    // number of transactions
    chain.update(Felt::from(header.transaction_count));
    // transaction commitment
    chain.update(header.transaction_commitment.0);
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
    chain.update(header.parent_hash.0);

    BlockHash(chain.finalize())
}

/// This implements the final hashing step for post-0.7, pre-0.13.2 blocks.
fn compute_final_hash_pre_0_13_2(header: &BlockHeaderData) -> BlockHash {
    let mut chain = HashChain::default();

    // block number
    chain.update(Felt::from(header.number.get()));
    // global state root
    chain.update(header.state_commitment.0);
    // sequencer address
    chain.update(header.sequencer_address.0);
    // block timestamp
    chain.update(Felt::from(header.timestamp.get()));
    // number of transactions
    chain.update(Felt::from(header.transaction_count));
    // transaction commitment
    chain.update(header.transaction_commitment.0);
    // number of events
    chain.update(Felt::from(header.event_count));
    // event commitment
    chain.update(header.event_commitment.0);
    // reserved: protocol version
    chain.update(Felt::ZERO);
    // reserved: extra data
    chain.update(Felt::ZERO);
    // parent block hash
    chain.update(header.parent_hash.0);

    BlockHash(chain.finalize())
}

pub(crate) fn compute_final_hash(header: &BlockHeaderData) -> Result<BlockHash> {
    // Concatenate the transaction count, event count, state diff length, and L1
    // data availability mode into a single felt.
    let mut concat_counts = [0u8; 32];
    let mut writer = concat_counts.as_mut_slice();
    writer
        .write_all(&header.transaction_count.to_be_bytes())
        .unwrap();
    writer.write_all(&header.event_count.to_be_bytes()).unwrap();
    writer
        .write_all(&header.state_diff_length.to_be_bytes())
        .unwrap();
    writer
        .write_all(&[match header.l1_da_mode {
            L1DataAvailabilityMode::Calldata => 0,
            L1DataAvailabilityMode::Blob => 0b10000000,
        }])
        .unwrap();
    let concat_counts = MontFelt::from_be_bytes(concat_counts);
    // Hash the block header.
    let mut hasher = PoseidonHasher::new();
    hasher.write(felt_bytes!(b"STARKNET_BLOCK_HASH0").into());
    hasher.write(header.number.get().into());
    hasher.write(header.state_commitment.0.into());
    hasher.write(header.sequencer_address.0.into());
    hasher.write(header.timestamp.get().into());
    hasher.write(concat_counts);
    hasher.write(header.state_diff_commitment.0.into());
    hasher.write(header.transaction_commitment.0.into());
    hasher.write(header.event_commitment.0.into());
    hasher.write(header.receipt_commitment.0.into());
    hasher.write(header.eth_l1_gas_price.0.into());
    hasher.write(header.strk_l1_gas_price.0.into());
    hasher.write(header.eth_l1_data_gas_price.0.into());
    hasher.write(header.strk_l1_data_gas_price.0.into());
    hasher.write(
        Felt::from_be_slice(header.starknet_version_str.as_bytes())
            .expect("Starknet version should fit into a felt")
            .into(),
    );
    hasher.write(MontFelt::ZERO);
    hasher.write(header.parent_hash.0.into());
    Ok(BlockHash(hasher.finish().into()))
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

pub fn calculate_receipt_commitment(receipts: &[Receipt]) -> Result<ReceiptCommitment> {
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
                        // Revert reason.
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
                        // Execution resources:
                        // L2 gas
                        MontFelt::ZERO,
                        // L1 gas consumed
                        receipt.execution_resources.total_gas_consumed.l1_gas.into(),
                        // L1 data gas consumed
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
    calculate_commitment_root::<PoseidonHash>(hashes).map(ReceiptCommitment)
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
    use p2p_proto::state;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::receipt::{ExecutionResources, L1Gas, L2ToL1Message};
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
    use starknet_gateway_test_fixtures::v0_12_2::state_update;
    use starknet_gateway_types::reply::StateUpdate;

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
            verify_gateway_block_hash(
                &block,
                Default::default(),
                0,
                Chain::Mainnet,
                ChainId::MAINNET
            )
            .unwrap(),
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
            verify_gateway_block_hash(
                &block,
                Default::default(),
                0,
                Chain::Mainnet,
                ChainId::MAINNET
            )
            .unwrap(),
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
            verify_gateway_block_hash(
                &block,
                Default::default(),
                0,
                Chain::Mainnet,
                ChainId::MAINNET
            )
            .unwrap(),
            VerifyResult::Match(_)
        );
    }

    #[test]
    fn test_block_hash_0_11_1() {
        let json = starknet_gateway_test_fixtures::v0_11_1::block::MAINNET_65000;
        let block: Block = serde_json::from_str(json).unwrap();

        assert_matches!(
            verify_gateway_block_hash(
                &block,
                Default::default(),
                0,
                Chain::Mainnet,
                ChainId::MAINNET
            )
            .unwrap(),
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
            verify_gateway_block_hash(
                &block,
                Default::default(),
                0,
                Chain::Mainnet,
                ChainId::MAINNET
            )
            .unwrap(),
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
                        L2ToL1MessagePayloadElem(36_u64.into()),
                        L2ToL1MessagePayloadElem(37_u64.into()),
                    ],
                },
                L2ToL1Message {
                    from_address: ContractAddress(56_u64.into()),
                    to_address: ContractAddress(57_u64.into()),
                    payload: vec![
                        L2ToL1MessagePayloadElem(58_u64.into()),
                        L2ToL1MessagePayloadElem(59_u64.into()),
                    ],
                },
            ],
            execution_resources: ExecutionResources {
                data_availability: L1Gas {
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
        let expected_root = ReceiptCommitment(felt!(
            "0x31963cb891ebb825e83514deb748c89b6967b5368cbc48a9b56193a1464ca87"
        ));
        assert_eq!(
            calculate_receipt_commitment(&[receipt]).unwrap(),
            expected_root
        );
    }

    // Source:
    // https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/block_hash_calculator_test.rs#L51
    #[test]
    fn test_block_hash_0_13_2() {
        let header = BlockHeaderData {
            hash: Default::default(),
            number: BlockNumber::new_or_panic(1),
            state_commitment: StateCommitment(2u64.into()),
            sequencer_address: SequencerAddress(3u64.into()),
            timestamp: BlockTimestamp::new_or_panic(4),
            l1_da_mode: L1DataAvailabilityMode::Blob,
            strk_l1_gas_price: GasPrice(6),
            eth_l1_gas_price: GasPrice(7),
            strk_l1_data_gas_price: GasPrice(10),
            eth_l1_data_gas_price: GasPrice(9),
            starknet_version: V_0_13_2,
            starknet_version_str: "10".to_string(),
            parent_hash: BlockHash(11u64.into()),
            transaction_commitment: TransactionCommitment(felt!(
                "0x72f432efa51e2a34f68404ac5e77514301e26eb53ec89badd8173f4e8561b95"
            )),
            transaction_count: 1,
            event_commitment: EventCommitment(Felt::ZERO),
            event_count: 0,
            state_diff_commitment: StateDiffCommitment(felt!(
                "0x281f5966e49ad7dad9323826d53d1d27c0c4e6ebe5525e2e2fbca549bfa0a67"
            )),
            state_diff_length: 10,
            receipt_commitment: ReceiptCommitment(felt!(
                "0x8e7dfb2772c2ac26e712fb97404355d66db0ba9555f0f64f30d61a56df9c76"
            )),
        };
        let expected_hash = BlockHash(felt!(
            "0x061e4998d51a248f1d0288d7e17f6287757b0e5e6c5e1e58ddf740616e312134"
        ));
        assert_eq!(compute_final_hash(&header).unwrap(), expected_hash);
    }

    // Source
    // https://integration-sepolia.starknet.io/feeder_gateway/get_block?blockNumber=35747
    #[test]
    fn test_block_hash_0_13_1_1_last() {
        let x = r#"
{
  "block_hash": "0x77140bef51bbb4d1932f17cc5081825ff18465a1df4440ca0429a4fa80f1dc5",
  "parent_block_hash": "0xf3a58fec42543a563a346ed5ee6537ce70f498d9e7941a3763a5304d554de2",
  "block_number": 35747,
  "state_root": "0xb120f982c77eab1b25f29349fb1458f32157887c64feb91e51e7f4cad62721",
  "transaction_commitment": "0x73534c7d612853aae0ac04f1067e19967868ec0c1bd45bf8bde32218c9dc363",
  "event_commitment": "0x72df341db81079417c4752483251f1a066832694e98bf36630d695fd43c2998",
  "status": "ACCEPTED_ON_L2",
  "l1_da_mode": "BLOB",
  "l1_gas_price": {
    "price_in_wei": "0x662569618",
    "price_in_fri": "0x8182a7269971"
  },
  "l1_data_gas_price": {
    "price_in_wei": "0xd30430f",
    "price_in_fri": "0x10b8bd0e1a5"
  },
  "transactions": [
    {
      "transaction_hash": "0x68c26c6bc37bdfb5a5e47188a43b5cd4bdd9eac65dd9514e7d8bd37b96286d5",
      "version": "0x3",
      "signature": [
        "0x42efeb40b6bd9ccb70686cde7a2ba94564d3cef0d8cbff1d7fe3c3bca3de146",
        "0x7deab771eeb627d82ccc386f3eae92c4f3070b1a0758faedc1131a35eee6c75"
      ],
      "nonce": "0xa876",
      "nonce_data_availability_mode": 0,
      "fee_data_availability_mode": 0,
      "resource_bounds": {
        "L1_GAS": {
          "max_amount": "0x186a00",
          "max_price_per_unit": "0x38d7ea4c68000"
        },
        "L2_GAS": {
          "max_amount": "0x0",
          "max_price_per_unit": "0x0"
        }
      },
      "tip": "0x0",
      "paymaster_data": [],
      "sender_address": "0x520982d994c3a28dc18b24fafa38ed9faa84ba3682a69798c40e4e67b6c8d23",
      "calldata": [
        "0x2",
        "0x9ec48db01f487d12811e379be9fd2277518eeb6d0279bf163249c5f02a025c",
        "0x27c3334165536f239cfd400ed956eabff55fc60de4fb56728b6a4f6b87db01c",
        "0x4",
        "0x9ec48db01f487d12811e379be9fd2277518eeb6d0279bf163249c5f02a025c",
        "0x2fd9126ee011f3a837cea02e32ae4ee73342d827e216998e5616bab88d8b7ea",
        "0x1",
        "0x2fd9126ee011f3a837cea02e32ae4ee73342d827e216998e5616bab88d8b7ea",
        "0x9ec48db01f487d12811e379be9fd2277518eeb6d0279bf163249c5f02a025c",
        "0x27a4a7332e590dd789019a6d125ff2aacd358e453090978cbf81f0d85e4c045",
        "0x2",
        "0x5bea0b1c6f487cfeab708280b15e2d454c52677843565200c4e789190a30bfe",
        "0x3dacc5dfb43b03b7c4f7c3bc22b6007751a444d6963ebaed34952025df04bfa"
      ],
      "account_deployment_data": [],
      "type": "INVOKE_FUNCTION"
    },
    {
      "transaction_hash": "0x42120d9bab62b4347e2c8bf60ab7a3ad63a04cb7e3ab5800a0bf2cb0261377f",
      "version": "0x0",
      "contract_address": "0x4c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
      "entry_point_selector": "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
      "nonce": "0x48",
      "calldata": [
        "0x6bc7a9f029e5e0cfe84c5b8b1acc0ea952eaed3b",
        "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
        "0x2b5e3af16b1880000",
        "0x0"
      ],
      "type": "L1_HANDLER"
    },
    {
      "transaction_hash": "0x15c695ddb5d298325fc24dc2245bf8173456538398cb0276c587875bd332605",
      "version": "0x0",
      "contract_address": "0x594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d",
      "entry_point_selector": "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
      "nonce": "0x49",
      "calldata": [
        "0x6fe45befc2c0e0f619d5ccfb6fa4d40590f6bc53",
        "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
        "0x3635c9adc5dea00000",
        "0x0"
      ],
      "type": "L1_HANDLER"
    },
    {
      "transaction_hash": "0x4954055bba42f81a0a1ec0712904075795492312008e1e7c9cd791362a22f17",
      "version": "0x0",
      "contract_address": "0x4c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
      "entry_point_selector": "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
      "nonce": "0x4a",
      "calldata": [
        "0x6bc7a9f029e5e0cfe84c5b8b1acc0ea952eaed3b",
        "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
        "0x2b5e3af16b1880000",
        "0x0"
      ],
      "type": "L1_HANDLER"
    }
  ],
  "timestamp": 1720424304,
  "sequencer_address": "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
  "transaction_receipts": [
    {
      "execution_status": "SUCCEEDED",
      "transaction_index": 0,
      "transaction_hash": "0x68c26c6bc37bdfb5a5e47188a43b5cd4bdd9eac65dd9514e7d8bd37b96286d5",
      "l2_to_l1_messages": [],
      "events": [
        {
          "from_address": "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
          "keys": [
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9",
            "0x520982d994c3a28dc18b24fafa38ed9faa84ba3682a69798c40e4e67b6c8d23",
            "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8"
          ],
          "data": [
            "0xbab43870c3b45",
            "0x0"
          ]
        }
      ],
      "execution_resources": {
        "n_steps": 7661,
        "builtin_instance_counter": {
          "pedersen_builtin": 27,
          "range_check_builtin": 218,
          "ec_op_builtin": 3
        },
        "n_memory_holes": 0,
        "data_availability": {
          "l1_gas": 0,
          "l1_data_gas": 256
        }
      },
      "actual_fee": "0xbab43870c3b45"
    },
    {
      "execution_status": "SUCCEEDED",
      "transaction_index": 1,
      "transaction_hash": "0x42120d9bab62b4347e2c8bf60ab7a3ad63a04cb7e3ab5800a0bf2cb0261377f",
      "l1_to_l2_consumed_message": {
        "from_address": "0x6BC7a9f029E5E0CFe84c5b8b1acC0EA952EAed3b",
        "to_address": "0x4c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
        "selector": "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
        "payload": [
          "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
          "0x2b5e3af16b1880000",
          "0x0"
        ],
        "nonce": "0x48"
      },
      "l2_to_l1_messages": [],
      "events": [
        {
          "from_address": "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
          "keys": [
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
          ],
          "data": [
            "0x0",
            "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
            "0x2b5e3af16b1880000",
            "0x0"
          ]
        },
        {
          "from_address": "0x4c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
          "keys": [
            "0x221e5a5008f7a28564f0eaa32cdeb0848d10657c449aed3e15d12150a7c2db3"
          ],
          "data": [
            "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
            "0x2b5e3af16b1880000",
            "0x0"
          ]
        }
      ],
      "execution_resources": {
        "n_steps": 9309,
        "builtin_instance_counter": {
          "pedersen_builtin": 18,
          "range_check_builtin": 193
        },
        "n_memory_holes": 0,
        "data_availability": {
          "l1_gas": 0,
          "l1_data_gas": 128
        }
      },
      "actual_fee": "0x0"
    },
    {
      "execution_status": "SUCCEEDED",
      "transaction_index": 2,
      "transaction_hash": "0x15c695ddb5d298325fc24dc2245bf8173456538398cb0276c587875bd332605",
      "l1_to_l2_consumed_message": {
        "from_address": "0x6FE45BEFC2C0E0F619D5ccFB6fA4D40590f6bC53",
        "to_address": "0x594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d",
        "selector": "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
        "payload": [
          "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
          "0x3635c9adc5dea00000",
          "0x0"
        ],
        "nonce": "0x49"
      },
      "l2_to_l1_messages": [],
      "events": [
        {
          "from_address": "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
          "keys": [
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9",
            "0x0",
            "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91"
          ],
          "data": [
            "0x3635c9adc5dea00000",
            "0x0"
          ]
        },
        {
          "from_address": "0x594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d",
          "keys": [
            "0x221e5a5008f7a28564f0eaa32cdeb0848d10657c449aed3e15d12150a7c2db3"
          ],
          "data": [
            "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
            "0x3635c9adc5dea00000",
            "0x0"
          ]
        }
      ],
      "execution_resources": {
        "n_steps": 10499,
        "builtin_instance_counter": {
          "pedersen_builtin": 20,
          "bitwise_builtin": 4,
          "range_check_builtin": 256,
          "poseidon_builtin": 3
        },
        "n_memory_holes": 0,
        "data_availability": {
          "l1_gas": 0,
          "l1_data_gas": 320
        }
      },
      "actual_fee": "0x0"
    },
    {
      "execution_status": "SUCCEEDED",
      "transaction_index": 3,
      "transaction_hash": "0x4954055bba42f81a0a1ec0712904075795492312008e1e7c9cd791362a22f17",
      "l1_to_l2_consumed_message": {
        "from_address": "0x6BC7a9f029E5E0CFe84c5b8b1acC0EA952EAed3b",
        "to_address": "0x4c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
        "selector": "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
        "payload": [
          "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
          "0x2b5e3af16b1880000",
          "0x0"
        ],
        "nonce": "0x4a"
      },
      "l2_to_l1_messages": [],
      "events": [
        {
          "from_address": "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
          "keys": [
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
          ],
          "data": [
            "0x0",
            "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
            "0x2b5e3af16b1880000",
            "0x0"
          ]
        },
        {
          "from_address": "0x4c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
          "keys": [
            "0x221e5a5008f7a28564f0eaa32cdeb0848d10657c449aed3e15d12150a7c2db3"
          ],
          "data": [
            "0x2bd054bcb02078a9a446a9af0965ba0dcae83f3abad204e870dec9a22070e91",
            "0x2b5e3af16b1880000",
            "0x0"
          ]
        }
      ],
      "execution_resources": {
        "n_steps": 9309,
        "builtin_instance_counter": {
          "range_check_builtin": 193,
          "pedersen_builtin": 18
        },
        "n_memory_holes": 0,
        "data_availability": {
          "l1_gas": 0,
          "l1_data_gas": 128
        }
      },
      "actual_fee": "0x0"
    }
  ],
  "starknet_version": "0.13.1.1"
}
"#;

        let state_update = r#"

{
  "block_hash": "0x77140bef51bbb4d1932f17cc5081825ff18465a1df4440ca0429a4fa80f1dc5",
  "new_root": "0xb120f982c77eab1b25f29349fb1458f32157887c64feb91e51e7f4cad62721",
  "old_root": "0x7d7dd6c697ec671d7287f463aa82b351868661bcccc26a96059f634ddae93a5",
  "state_diff": {
    "storage_diffs": {
      "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d": [
        {
          "key": "0xed8fd27cdbb89ef3373393dc40d4f8c5fe1219f6b008e779c206dd3bf78ab5",
          "value": "0x43aa0426d0128048000"
        },
        {
          "key": "0x110e2f729c9c2b988559994a3daccd838cf52faf88e18101373e67dd061455a",
          "value": "0x3f27f5e4f8c00aaf0000"
        },
        {
          "key": "0x1756b3d5a44d149c3c4efaf9b31c543d6f7ff9480708e21b42dbf2ba2ac6c15",
          "value": "0x668b9770000000000000000000000000003ee510b44ac32aa70000"
        },
        {
          "key": "0x38c10662a48073f77efadb4820d93ad877d4de93741e9165b24bc8877d93b78",
          "value": "0xf"
        },
        {
          "key": "0x5496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a",
          "value": "0x9b676bca4085f7fe7af"
        },
        {
          "key": "0x5fd2d8ba5f4be0a0888ef0fb89ae08b7bc01101dfd572ceaaf71319515710a4",
          "value": "0x1cc2600689bb1736860"
        }
      ],
      "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7": [
        {
          "key": "0xed8fd27cdbb89ef3373393dc40d4f8c5fe1219f6b008e779c206dd3bf78ab5",
          "value": "0x56bcc7761a81fb5a9"
        },
        {
          "key": "0x110e2f729c9c2b988559994a3daccd838cf52faf88e18101373e67dd061455a",
          "value": "0x1b65554fb50aed2ee4"
        }
      ],
      "0x1": [
        {
          "key": "0x8b99",
          "value": "0x6b0b81ecd20e90c0efde8e9f164e7fde8115ecf095b925ada5bc38c85148ce"
        }
      ],
      "0x9ec48db01f487d12811e379be9fd2277518eeb6d0279bf163249c5f02a025c": [
        {
          "key": "0x5bea0b1c6f487cfeab708280b15e2d454c52677843565200c4e789190a30bfe",
          "value": "0x3dacc5dfb43b03b7c4f7c3bc22b6007751a444d6963ebaed34952025df04bfa"
        }
      ]
    },
    "nonces": {
      "0x520982d994c3a28dc18b24fafa38ed9faa84ba3682a69798c40e4e67b6c8d23": "0xa877"
    },
    "deployed_contracts": [],
    "old_declared_contracts": [],
    "declared_classes": [],
    "replaced_classes": []
  }
}

"#;

        let block: Block = serde_json::from_str(x).unwrap();
        let given = block.block_hash;

        let state_update: StateUpdate = serde_json::from_str(state_update).unwrap();
        let state_update: pathfinder_common::StateUpdate = state_update.into();
        let state_diff_length = state_update.state_diff_length();

        let block_header_data = BlockHeaderData::from_block(
            &block,
            //block.state_diff_commitment.unwrap(),
            state_update.compute_state_diff_commitment(StarknetVersion::new(0, 13, 1, 1)),
            // block.state_diff_length.unwrap(),
            state_diff_length,
        )
        .unwrap();

        assert_eq!(compute_final_hash_pre_0_13_2(&block_header_data), given);
    }

    // Source
    // https://integration-sepolia.starknet.io/feeder_gateway/get_block?blockNumber=35748
    #[test]
    fn test_block_hash_0_13_2_first() {
        let x = r#"

{
  "block_hash": "0x1ea2a9cfa3df5297d58c0a04d09d276bc68d40fe64701305bbe2ed8f417e869",
  "parent_block_hash": "0x77140bef51bbb4d1932f17cc5081825ff18465a1df4440ca0429a4fa80f1dc5",
  "block_number": 35748,
  "state_root": "0x38e01cbe2d5721780b2e1a478fd131f2ffcc099528dd2e1289f26b027127790",
  "transaction_commitment": "0x54f43cf29b80cc83aef36f3195b73cb165ad12553eae147b4cce62adbf0b180",
  "event_commitment": "0x12dfbe9dbbaba9c34b5a4c0ba622dcd8e2bb0264481c77f073008b59825a758",
  "receipt_commitment": "0x6f12628d21a8df7f158b631d801fc0dd20034b9e22eca255bddc0c1c1bc283f",
  "state_diff_commitment": "0x23587c54d590b57b8e25acbf1e1a422eb4cd104e95ee4a681021a6bb7456afa",
  "state_diff_length": 6,
  "status": "ACCEPTED_ON_L2",
  "l1_da_mode": "BLOB",
  "l1_gas_price": {
    "price_in_wei": "0x7427e87c4",
    "price_in_fri": "0x9346cee0949c"
  },
  "l1_data_gas_price": {
    "price_in_wei": "0x3b095dc6",
    "price_in_fri": "0x4ada914d823"
  },
  "transactions": [
    {
      "transaction_hash": "0x5ac644bbd6ae98d3be2d988439854e33f0961e24f349a63b43e16d172bfe747",
      "version": "0x2",
      "max_fee": "0x4f6ac5195e92e4",
      "signature": [
        "0x43ad3c7c77f7b7762db41ee9d33958813ee25efed77bc7199e08f4f40b1a59",
        "0xfedb8715405faf28de29a07a3f3f06f078bac3fcb67ac7f5ae392e15a75921"
      ],
      "nonce": "0xd",
      "class_hash": "0x2fd9e122406490dc0f299f3070eaaa8df854d97ff81b47e91da32b8cd9d757a",
      "compiled_class_hash": "0x55d1e0ee31f8f937fc75b37045129fbe0e01747baacb44b89d2d3d2c649117e",
      "sender_address": "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
      "type": "DECLARE"
    },
    {
      "transaction_hash": "0x21bc0afe54123b946855e1bf9389d943313df5c5c396fbf0630234a44f6f592",
      "version": "0x2",
      "max_fee": "0xe6e9346a5ae75a",
      "signature": [
        "0x12a928f7042a66c5419fc5182da6879c357f013335d8b61d0ad774009afbb40",
        "0x63479f4343dc2f068bff99fbbf0027250a672999fb5675cee1f2d1a64d33844"
      ],
      "nonce": "0xe",
      "class_hash": "0x19de7881922dbc95846b1bb9464dba34046c46470cfb5e18b4cb2892fd4111f",
      "compiled_class_hash": "0x6506976af042088c9ea49e6cc9c9a12838ee6920bb989dce02f5c6467667367",
      "sender_address": "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
      "type": "DECLARE"
    }
  ],
  "timestamp": 1720426817,
  "sequencer_address": "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
  "transaction_receipts": [
    {
      "execution_status": "SUCCEEDED",
      "transaction_index": 0,
      "transaction_hash": "0x5ac644bbd6ae98d3be2d988439854e33f0961e24f349a63b43e16d172bfe747",
      "l2_to_l1_messages": [],
      "events": [
        {
          "from_address": "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
          "keys": [
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
          ],
          "data": [
            "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
            "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
            "0xd07af45c84550",
            "0x0"
          ]
        }
      ],
      "execution_resources": {
        "n_steps": 3950,
        "builtin_instance_counter": {
          "pedersen_builtin": 16,
          "range_check_builtin": 157,
          "ecdsa_builtin": 1,
          "poseidon_builtin": 4
        },
        "n_memory_holes": 0,
        "data_availability": {
          "l1_gas": 0,
          "l1_data_gas": 192
        },
        "total_gas_consumed": {
          "l1_gas": 117620,
          "l1_data_gas": 192
        }
      },
      "actual_fee": "0xd07af45c84550"
    },
    {
      "execution_status": "SUCCEEDED",
      "transaction_index": 1,
      "transaction_hash": "0x21bc0afe54123b946855e1bf9389d943313df5c5c396fbf0630234a44f6f592",
      "l2_to_l1_messages": [],
      "events": [
        {
          "from_address": "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
          "keys": [
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
          ],
          "data": [
            "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
            "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
            "0x471426f16c4330",
            "0x0"
          ]
        }
      ],
      "execution_resources": {
        "n_steps": 3950,
        "builtin_instance_counter": {
          "poseidon_builtin": 4,
          "ecdsa_builtin": 1,
          "range_check_builtin": 157,
          "pedersen_builtin": 16
        },
        "n_memory_holes": 0,
        "data_availability": {
          "l1_gas": 0,
          "l1_data_gas": 192
        },
        "total_gas_consumed": {
          "l1_gas": 641644,
          "l1_data_gas": 192
        }
      },
      "actual_fee": "0x471426f16c4330"
    }
  ],
  "starknet_version": "0.13.2"
}

"#;

        let state_update = r#"

{
  "block_hash": "0x1ea2a9cfa3df5297d58c0a04d09d276bc68d40fe64701305bbe2ed8f417e869",
  "new_root": "0x38e01cbe2d5721780b2e1a478fd131f2ffcc099528dd2e1289f26b027127790",
  "old_root": "0xb120f982c77eab1b25f29349fb1458f32157887c64feb91e51e7f4cad62721",
  "state_diff": {
    "storage_diffs": {
      "0x1": [
        {
          "key": "0x8b9a",
          "value": "0x6ae6fe45c608e642524de25140f19a44d40dc26286e38d3f184c7fb2fd21767"
        }
      ],
      "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7": [
        {
          "key": "0x84a17db3276b7f8c33d3cdae9067d3db20b6a24b5c29fd185df2f7f42c0713",
          "value": "0x90d0c5a3d34c3e73"
        },
        {
          "key": "0x5496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a",
          "value": "0x55620cf9acab16e56"
        }
      ]
    },
    "nonces": {
      "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365": "0xf"
    },
    "deployed_contracts": [],
    "old_declared_contracts": [],
    "declared_classes": [
      {
        "class_hash": "0x19de7881922dbc95846b1bb9464dba34046c46470cfb5e18b4cb2892fd4111f",
        "compiled_class_hash": "0x6506976af042088c9ea49e6cc9c9a12838ee6920bb989dce02f5c6467667367"
      },
      {
        "class_hash": "0x2fd9e122406490dc0f299f3070eaaa8df854d97ff81b47e91da32b8cd9d757a",
        "compiled_class_hash": "0x55d1e0ee31f8f937fc75b37045129fbe0e01747baacb44b89d2d3d2c649117e"
      }
    ],
    "replaced_classes": []
  }
}

"#;

        let block: Block = serde_json::from_str(x).unwrap();
        let given = block.block_hash;

        let state_update: StateUpdate = serde_json::from_str(state_update).unwrap();
        let state_update: pathfinder_common::StateUpdate = state_update.into();
        let state_diff_length = state_update.state_diff_length();
        let state_diff_commitment =
            state_update.compute_state_diff_commitment(StarknetVersion::new(0, 13, 2, 0));

        assert_eq!(state_diff_length, block.state_diff_length.unwrap());
        assert_eq!(state_diff_commitment, block.state_diff_commitment.unwrap());

        let receipts: Vec<_> = block
            .transaction_receipts
            .iter()
            .map(|(receipt, _)| receipt.clone())
            .collect();
        assert_eq!(
            calculate_receipt_commitment(&receipts).unwrap(),
            block.receipt_commitment.unwrap()
        );

        let block_header_data = BlockHeaderData::from_block(
            &block,
            block.state_diff_commitment.unwrap(),
            block.state_diff_length.unwrap(),
        )
        .unwrap();

        assert_eq!(
            compute_final_hash(&block_header_data).unwrap(),
            given,
            "0.13.2 hash"
        );

        assert_eq!(
            compute_final_hash_pre_0_13_2(&block_header_data),
            given,
            "pre 0.13.2 hash"
        );
    }
}
