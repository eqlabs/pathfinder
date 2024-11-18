use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use anyhow::{anyhow, Context};
use p2p::client::types::TransactionData;
use p2p::libp2p::PeerId;
use p2p::PeerData;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    BlockHeader,
    BlockNumber,
    ChainId,
    StarknetVersion,
    TransactionCommitment,
    TransactionHash,
};
use pathfinder_storage::Storage;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::error::SyncError;
use super::storage_adapters;
use super::stream::ProcessStage;
use crate::state::block_hash::calculate_transaction_commitment;

/// For a single block
#[derive(Clone, Debug)]
pub struct UnverifiedTransactions {
    pub expected_commitment: TransactionCommitment,
    pub transactions: Vec<(Transaction, Receipt)>,
    pub version: StarknetVersion,
    pub block_number: BlockNumber,
}

pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    tokio::task::spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        let first_block = db
            .first_block_without_transactions()
            .context("Querying first block without transactions")?;

        match first_block {
            Some(first_block) if first_block <= head => Ok(Some(first_block)),
            Some(_) | None => Ok(None),
        }
    })
    .await
    .context("Joining blocking task")?
}

pub(super) fn get_counts(
    db: pathfinder_storage::Transaction<'_>,
    start: BlockNumber,
    batch_size: NonZeroUsize,
) -> anyhow::Result<VecDeque<usize>> {
    db.transaction_counts(start, batch_size)
        .context("Querying transaction counts")
}

pub(super) fn counts_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
    batch_size: NonZeroUsize,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    storage_adapters::counts_stream(storage, start, stop, batch_size, get_counts)
}

pub struct CalculateHashes(pub ChainId);

impl ProcessStage for CalculateHashes {
    const NAME: &'static str = "Transactions::Hashes";
    type Input = (
        TransactionData,
        BlockNumber,
        StarknetVersion,
        TransactionCommitment,
    );
    type Output = UnverifiedTransactions;

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        use rayon::prelude::*;
        let (transactions, block_number, version, expected_commitment) = input;
        let transactions = transactions
            .into_par_iter()
            .map(|(tx, r)| {
                let computed_hash = tx.variant.calculate_hash(self.0, false);
                if tx.hash != computed_hash {
                    tracing::debug!(%peer, %block_number, expected_hash=%tx.hash, %computed_hash, "Transaction hash mismatch");
                    Err(SyncError::BadTransactionHash(*peer))
                } else {
                    let receipt = Receipt {
                        actual_fee: r.actual_fee,
                        execution_resources: r.execution_resources,
                        l2_to_l1_messages: r.l2_to_l1_messages,
                        execution_status: r.execution_status,
                        transaction_hash: computed_hash,
                        transaction_index: r.transaction_index,
                    };
                    Ok((tx, receipt))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(UnverifiedTransactions {
            expected_commitment,
            transactions,
            version,
            block_number,
        })
    }
}

pub struct FetchCommitmentFromDb<T> {
    db: pathfinder_storage::Connection,
    _marker: std::marker::PhantomData<T>,
}

impl<T> FetchCommitmentFromDb<T> {
    pub fn new(db: pathfinder_storage::Connection) -> Self {
        Self {
            db,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> ProcessStage for FetchCommitmentFromDb<T> {
    const NAME: &'static str = "Transactions::FetchCommitmentFromDb";
    type Input = (T, BlockNumber);
    type Output = (T, BlockNumber, StarknetVersion, TransactionCommitment);

    fn map(
        &mut self,
        _: &PeerId,
        (data, block_number): Self::Input,
    ) -> Result<Self::Output, SyncError> {
        let mut db = self
            .db
            .transaction()
            .context("Creating database transaction")?;
        let version = db
            .block_version(block_number)
            .context("Fetching starknet version")?
            // This block header is supposed to be in the database so this is a fatal error
            .context("Starknet version not found in db")?;
        let commitment = db
            .transaction_commitment(block_number)
            .context("Fetching transaction commitment")?
            // This block header is supposed to be in the database so this is a fatal error
            .context("Transaction commitment not found in db")?;
        Ok((data, block_number, version, commitment))
    }
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "Transactions::Verify";
    type Input = UnverifiedTransactions;
    type Output = Vec<(Transaction, Receipt)>;

    fn map(&mut self, peer: &PeerId, transactions: Self::Input) -> Result<Self::Output, SyncError> {
        let UnverifiedTransactions {
            expected_commitment,
            transactions,
            version,
            block_number,
        } = transactions;
        let txs: Vec<_> = transactions.iter().map(|(t, _)| t.clone()).collect();
        // This computation can only fail in case of internal trie error which is always
        // a fatal error
        let actual = calculate_transaction_commitment(&txs, version.max(StarknetVersion::V_0_13_2))
            .context("Computing transaction commitment")?;
        if actual != expected_commitment {
            tracing::debug!(%peer, %block_number, %expected_commitment, actual_commitment=%actual, "Transaction commitment mismatch");
            return Err(SyncError::TransactionCommitmentMismatch(*peer));
        }
        Ok(transactions)
    }
}

pub struct Store {
    db: pathfinder_storage::Connection,
    current_block: BlockNumber,
}

impl Store {
    pub fn new(db: pathfinder_storage::Connection, start: BlockNumber) -> Self {
        Self {
            db,
            current_block: start,
        }
    }
}

impl ProcessStage for Store {
    const NAME: &'static str = "Transactions::Persist";
    type Input = Vec<(Transaction, Receipt)>;
    type Output = BlockNumber;

    fn map(&mut self, _: &PeerId, transactions: Self::Input) -> Result<Self::Output, SyncError> {
        let mut db = self
            .db
            .transaction()
            .context("Creating database transaction")?;

        let tail = self.current_block;

        db.insert_transaction_data(self.current_block, &transactions, None)
            .context("Inserting transactions and receipts")?;
        db.commit().context("Committing db transaction")?;

        self.current_block += 1;

        Ok(tail)
    }
}
