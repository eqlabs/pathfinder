#![allow(dead_code, unused_variables)]
use anyhow::Context;
use futures::StreamExt;
use p2p::libp2p::PeerId;
use p2p::PeerData;
use p2p_proto::header;
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    Chain,
    ChainId,
    ClassCommitment,
    PublicKey,
    SignedBlockHeader,
    StarknetVersion,
    StorageCommitment,
};
use pathfinder_storage::Storage;

use crate::state::block_hash::{BlockHeaderData, VerifyResult};
use crate::sync::error::SyncError;
use crate::sync::stream::{ProcessStage, SyncReceiver};

type SignedHeaderResult = Result<PeerData<SignedBlockHeader>, SyncError>;

/// Describes a gap in the stored headers.
///
/// Both head and tail form part of the gap i.e. it is an inclusive range.
#[derive(Debug)]
pub(super) struct HeaderGap {
    /// Freshest block height of the gap.
    pub head: BlockNumber,
    /// Hash of the gap's head block. Used to validate the header chain data
    /// received.
    pub head_hash: BlockHash,
    /// Oldest block height of the gap.
    pub tail: BlockNumber,
    /// Oldest block's parent's hash. Used to link any received data to the
    /// existing local chain data.
    pub tail_parent_hash: BlockHash,
}

impl HeaderGap {
    pub fn head(&self) -> (BlockNumber, BlockHash) {
        (self.head, self.head_hash)
    }
}

/// Returns the first [HeaderGap] in headers, searching from the given block
/// backwards.
pub(super) async fn next_gap(
    storage: Storage,
    head: BlockNumber,
    head_hash: BlockHash,
) -> anyhow::Result<Option<HeaderGap>> {
    util::task::spawn_blocking(move |_| {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        tracing::trace!(%head, "Searching for next gap");

        // It's possible for the head block to be the head of the gap. This can occur
        // when called with the L1 anchor which has not been synced yet.
        let head_exists = db
            .block_exists(head.into())
            .context("Checking if search head exists locally")?;

        let (head, head_hash) = if head_exists {
            // Find the next header that exists, but whose parent does not.
            let Some(gap_head) = db
                .next_ancestor_without_parent(head)
                .context("Querying head of gap")?
            else {
                // No headers are missing so no gap found.
                tracing::trace!("No gap found in headers");
                return Ok(None);
            };

            let gap_head_header = db
                .block_header(gap_head.0.into())
                .context("Fetching gap head block header")?
                .context("Gap head should exist")?;
            let gap_head_parent_number = gap_head
                .0
                .parent()
                .expect("next_ancestor_without_parent() cannot return genesis");
            let gap_head_parent_hash = gap_head_header.parent_hash;

            (gap_head_parent_number, gap_head_parent_hash)
        } else {
            // Start of search is already missing so it becomes the head of the gap.
            tracing::trace!(%head, "Start of search was missing");
            (head, head_hash)
        };

        let (tail, tail_parent_hash) =
            match db.next_ancestor(head).context("Querying tail of gap")? {
                Some((tail, tail_hash)) => (tail + 1, tail_hash),
                None => {
                    // By this point we are certain there is a gap, so the tail automatically
                    // becomes genesis if no actual tail block is found.
                    (BlockNumber::GENESIS, BlockHash::ZERO)
                }
            };

        tracing::trace!(%head, %tail, "Found gap");

        Ok(Some(HeaderGap {
            head,
            head_hash,
            tail,
            tail_parent_hash,
        }))
    })
    .await
    .context("Joining blocking task")?
}

/// Ensures that the hash chain is continuous i.e. that block numbers increment
/// and hashes become parent hashes.
pub struct ForwardContinuity {
    next: BlockNumber,
    parent_hash: BlockHash,
}

/// Ensures that the header chain is continuous (backwards).
///
/// The backwards variant of [ForwardContinuity].
pub struct BackwardContinuity {
    /// Expected next block number.
    ///
    /// Is an option to represent having reached genesis.
    pub number: Option<BlockNumber>,
    /// Expected block hash.
    pub hash: BlockHash,
}

/// Ensures that the block hash and signature are correct.
pub struct VerifyHashAndSignature {
    chain_id: ChainId,
    public_key: PublicKey,
    block_hash_db: Option<pathfinder_block_hashes::BlockHashDb>,
}

impl ForwardContinuity {
    pub fn new(next: BlockNumber, parent_hash: BlockHash) -> Self {
        Self { next, parent_hash }
    }
}

impl ProcessStage for ForwardContinuity {
    const NAME: &'static str = "Headers::Continuity";

    type Input = SignedBlockHeader;
    type Output = SignedBlockHeader;

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        let header = &input.header;

        if header.number != self.next || header.parent_hash != self.parent_hash {
            tracing::debug!(%peer, expected_block_number=%self.next, actual_block_number=%header.number, expected_parent_block_hash=%self.parent_hash, actual_parent_block_hash=%header.parent_hash, "Block chain discontinuity");
            return Err(SyncError::Discontinuity(*peer));
        }

        self.next += 1;
        self.parent_hash = header.hash;

        Ok(input)
    }
}

impl BackwardContinuity {
    /// Creates a new [BackwardContinuity] from the next block's expected number
    /// and hash.
    pub fn new(number: BlockNumber, hash: BlockHash) -> Self {
        Self {
            number: Some(number),
            hash,
        }
    }
}

impl ProcessStage for BackwardContinuity {
    const NAME: &'static str = "Headers::Continuity";

    type Input = SignedBlockHeader;
    type Output = SignedBlockHeader;

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        let number = self.number.ok_or_else(|| {
            tracing::debug!(actual_block_number=%input.header.number, actual_block_hash=%input.header.hash, "Block chain discontinuity, no block expected before genesis");
            SyncError::Discontinuity(*peer)
        })?;

        if input.header.number != number || input.header.hash != self.hash {
            tracing::debug!(expected_block_number=%number, actual_block_number=%input.header.number, expected_block_hash=%self.hash, actual_block_hash=%input.header.hash, "Block chain discontinuity");
            return Err(SyncError::Discontinuity(*peer));
        }

        self.number = number.parent();
        self.hash = input.header.parent_hash;

        Ok(input)
    }
}

impl ProcessStage for VerifyHashAndSignature {
    const NAME: &'static str = "Headers::Verify";
    type Input = SignedBlockHeader;
    type Output = SignedBlockHeader;

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        if !self.verify_hash(&input.header) {
            return Err(SyncError::BadBlockHash(*peer));
        }

        if !self.verify_signature(&input) {
            return Err(SyncError::BadHeaderSignature(*peer));
        }

        Ok(input)
    }
}

impl VerifyHashAndSignature {
    pub fn new(
        chain_id: ChainId,
        public_key: PublicKey,
        block_hash_db: Option<pathfinder_block_hashes::BlockHashDb>,
    ) -> Self {
        Self {
            chain_id,
            public_key,
            block_hash_db,
        }
    }

    fn verify_hash(&self, header: &BlockHeader) -> bool {
        let expected_hash = self
            .block_hash_db
            .as_ref()
            .and_then(|db| db.block_hash(header.number))
            .unwrap_or(header.hash);
        let computed_hash = crate::state::block_hash::compute_final_hash(&BlockHeaderData {
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
                .expect("ptr size is 64 bits"),
            event_commitment: header.event_commitment,
            event_count: header.event_count.try_into().expect("ptr size is 64 bits"),
            state_diff_commitment: header.state_diff_commitment,
            state_diff_length: header.state_diff_length,
            starknet_version: header.starknet_version,
            starknet_version_str: header.starknet_version.to_string(),
            eth_l1_gas_price: header.eth_l1_gas_price,
            strk_l1_gas_price: header.strk_l1_gas_price,
            eth_l1_data_gas_price: header.eth_l1_data_gas_price,
            strk_l1_data_gas_price: header.strk_l1_data_gas_price,
            eth_l2_gas_price: header.eth_l2_gas_price,
            strk_l2_gas_price: header.strk_l2_gas_price,
            receipt_commitment: header.receipt_commitment,
            l1_da_mode: header.l1_da_mode,
        });
        {
            if computed_hash == expected_hash {
                true
            } else {
                tracing::debug!(block_number=%header.number, expected_block_hash=%expected_hash, actual_block_hash=%computed_hash, "Block hash mismatch");
                false
            }
        }
    }

    fn verify_signature(&self, header: &SignedBlockHeader) -> bool {
        header
            .signature
            .verify(self.public_key, header.header.hash)
            .inspect_err(
                |error| tracing::debug!(%error, ?header, "Header signature verification failed"),
            )
            .is_ok()
    }
}

pub struct Persist {
    pub connection: pathfinder_storage::Connection,
}

impl ProcessStage for Persist {
    const NAME: &'static str = "Headers::Persist";
    type Input = Vec<SignedBlockHeader>;
    type Output = BlockNumber;

    fn map(&mut self, _: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        let tail = input.last().expect("not empty").header.number;
        let tx = self
            .connection
            .transaction()
            .context("Creating database transaction")?;

        for SignedBlockHeader { header, signature } in input {
            tx.insert_block_header(&header)
                .context("Persisting block header")?;
            tx.insert_signature(header.number, &signature)
                .context("Persisting block signature")?;
        }

        tx.commit().context("Committing database transaction")?;
        Ok(tail)
    }
}
