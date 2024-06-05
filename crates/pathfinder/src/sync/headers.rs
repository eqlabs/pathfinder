#![allow(dead_code, unused_variables)]
use anyhow::Context;
use futures::StreamExt;
use p2p::client::peer_agnostic::SignedBlockHeader;
use p2p::PeerData;
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    Chain,
    ChainId,
    ClassCommitment,
    PublicKey,
    StorageCommitment,
};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

use crate::state::block_hash::{verify_block_hash, BlockHeaderData, VerifyResult};
use crate::sync::error::{SyncError, SyncError2};
use crate::sync::stream::{ProcessStage, SyncReceiver};

type SignedHeaderResult = Result<PeerData<SignedBlockHeader>, SyncError>;

/// Describes a gap in the stored headers.
///
/// Both head and tail form part of the gap i.e. it is an inclusive range.
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
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        // It's possible for the head block to be the head of the gap. This can occur
        // when called with the L1 anchor which has not been synced yet.
        let head_exists = db
            .block_exists(head.into())
            .context("Checking if search head exists locally")?;
        let gap_head = if head_exists {
            // Find the next header that exists, but whose parent does not.
            let Some(gap_head) = db
                .next_ancestor_without_parent(head)
                .context("Querying head of gap")?
            else {
                // No headers are missing so no gap found.
                return Ok(None);
            };

            gap_head
        } else {
            // Start of search is already missing so it becomes the head of the gap.
            (head, head_hash)
        };

        let gap_tail = db
            .next_ancestor(gap_head.0)
            .context("Querying tail of gap")?
            // By this point we are certain there is a gap, so the tail automatically becomes
            // genesis if no actual tail block is found.
            .unwrap_or_default();

        Ok(Some(HeaderGap {
            head: gap_head.0,
            head_hash: gap_head.1,
            tail: gap_tail.0 + 1,
            tail_parent_hash: gap_tail.1,
        }))
    })
    .await
    .context("Joining blocking task")?
}

pub(super) async fn query(
    storage: Storage,
    block_number: BlockNumber,
) -> anyhow::Result<Option<BlockHeader>> {
    spawn_blocking({
        move || {
            let mut db = storage
                .connection()
                .context("Creating database connection")?;
            let db = db.transaction().context("Creating database transaction")?;
            db.block_header(block_number.into())
                .context("Querying first block without transactions")
        }
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
    chain: Chain,
    chain_id: ChainId,
    public_key: PublicKey,
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

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let header = &input.header;

        if header.number != self.next || header.parent_hash != self.parent_hash {
            return Err(SyncError2::Discontinuity);
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

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let number = self.number.ok_or(SyncError2::Discontinuity)?;

        if input.header.number != number || input.header.hash != self.hash {
            return Err(SyncError2::Discontinuity);
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

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        if !self.verify_hash(&input) {
            return Err(SyncError2::BadBlockHash);
        }

        if !self.verify_signature(&input) {
            return Err(SyncError2::BadHeaderSignature);
        }

        Ok(input)
    }
}

impl VerifyHashAndSignature {
    pub fn new(chain: Chain, chain_id: ChainId, public_key: PublicKey) -> Self {
        Self {
            chain,
            chain_id,
            public_key,
        }
    }

    fn verify_hash(&self, header: &SignedBlockHeader) -> bool {
        let h = &header.header;
        matches!(
            verify_block_hash(
                BlockHeaderData {
                    hash: h.hash,
                    parent_hash: h.parent_hash,
                    number: h.number,
                    timestamp: h.timestamp,
                    sequencer_address: h.sequencer_address,
                    state_commitment: h.state_commitment,
                    transaction_commitment: h.transaction_commitment,
                    transaction_count: h.transaction_count.try_into().expect("ptr size is 64 bits"),
                    event_commitment: h.event_commitment,
                    event_count: h.event_count.try_into().expect("ptr size is 64 bits"),
                },
                self.chain,
                self.chain_id
            ),
            Ok(VerifyResult::Match(_))
        )
    }

    fn verify_signature(&self, header: &SignedBlockHeader) -> bool {
        header
            .signature
            .verify(
                self.public_key,
                header.header.hash,
                header.state_diff_commitment,
            )
            .is_ok()
    }
}

pub fn spawn_header_source(
    header_stream: impl futures::Stream<Item = PeerData<SignedBlockHeader>> + Send + 'static,
) -> SyncReceiver<SignedBlockHeader> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    tokio::spawn(async move {
        let mut headers = Box::pin(header_stream);

        while let Some(header) = headers.next().await {
            if tx.send(Ok(header)).await.is_err() {
                return;
            }
        }
    });

    SyncReceiver::from_receiver(rx)
}

pub struct Persist {
    pub connection: pathfinder_storage::Connection,
}

impl ProcessStage for Persist {
    const NAME: &'static str = "Headers::Persist";
    type Input = Vec<SignedBlockHeader>;
    type Output = ();

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let tx = self
            .connection
            .transaction()
            .context("Creating database transaction")?;

        for SignedBlockHeader {
            header,
            signature,
            state_diff_commitment,
            state_diff_length,
        } in input
        {
            tx.insert_block_header(&pathfinder_common::BlockHeader {
                hash: header.hash,
                parent_hash: header.parent_hash,
                number: header.number,
                timestamp: header.timestamp,
                eth_l1_gas_price: header.eth_l1_gas_price,
                strk_l1_gas_price: header.strk_l1_gas_price,
                eth_l1_data_gas_price: header.eth_l1_data_gas_price,
                strk_l1_data_gas_price: header.strk_l1_data_gas_price,
                sequencer_address: header.sequencer_address,
                starknet_version: header.starknet_version,
                class_commitment: ClassCommitment::ZERO,
                event_commitment: header.event_commitment,
                state_commitment: header.state_commitment,
                storage_commitment: StorageCommitment::ZERO,
                transaction_commitment: header.transaction_commitment,
                transaction_count: header.transaction_count,
                event_count: header.event_count,
                l1_da_mode: header.l1_da_mode,
            })
            .context("Persisting block header")?;
            tx.insert_signature(header.number, &signature)
                .context("Persisting block signature")?;
            tx.update_state_diff_commitment_and_length(
                header.number,
                state_diff_commitment,
                state_diff_length,
            )
            .context("Persisting state diff length")?;
        }

        tx.commit().context("Committing database transaction")?;
        Ok(())
    }
}
