use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use anyhow::{anyhow, Context};
use p2p::client::peer_agnostic::{self, TransactionData};
use p2p::PeerData;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    BlockHeader,
    BlockNumber,
    ChainId,
    TransactionCommitment,
    TransactionHash,
};
use pathfinder_storage::Storage;

use super::error::{SyncError, SyncError2};
use super::stream::ProcessStage;
use crate::state::block_hash::{
    calculate_transaction_commitment,
    TransactionCommitmentFinalHashType,
};
use crate::sync::stream::{BufferStage, SyncReceiver};

/// For a single block
#[derive(Clone, Debug)]
pub struct UnverifiedTransactions {
    pub expected_commitment: TransactionCommitment,
    pub transactions: Vec<(Transaction, Receipt)>,
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

pub(super) fn counts_and_commitments_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop_inclusive: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<(usize, TransactionCommitment)>> {
    const BATCH_SIZE: usize = 1000;

    async_stream::try_stream! {
        let mut batch = VecDeque::new();

        while start <= stop_inclusive {
            if let Some(counts) = batch.pop_front() {
                yield counts;
                continue;
            }

            let batch_size = NonZeroUsize::new(
                BATCH_SIZE.min(
                    (stop_inclusive.get() - start.get() + 1)
                        .try_into()
                        .expect("ptr size is 64bits"),
                ),
            )
            .expect(">0");
            let storage = storage.clone();

            batch = tokio::task::spawn_blocking(move || {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().context("Creating database transaction")?;
                db.transaction_counts_and_commitments(start.into(), batch_size)
                    .context("Querying transaction counts")
            })
            .await
            .context("Joining blocking task")??;

            if batch.is_empty() {
                Err(anyhow::anyhow!(
                    "No transaction counts found for range: start {start}, batch_size: {batch_size}"
                ))?;
                break;
            }

            start += batch.len().try_into().expect("ptr size is 64bits");
        }

        while let Some(counts) = batch.pop_front() {
            yield counts;
        }
    }
}

pub struct CalculateHashes(pub ChainId);

impl ProcessStage for CalculateHashes {
    const NAME: &'static str = "Transactions::Hashes";
    type Input = TransactionData;
    type Output = UnverifiedTransactions;

    fn map(&mut self, td: Self::Input) -> Result<Self::Output, SyncError2> {
        use rayon::prelude::*;
        let TransactionData {
            expected_commitment,
            transactions,
        } = td;
        let transactions = transactions
            .into_par_iter()
            .map(|(tv, r)| {
                let transaction_hash = tv.calculate_hash(self.0, false);
                let transaction = Transaction {
                    hash: transaction_hash,
                    variant: tv,
                };
                let receipt = Receipt {
                    actual_fee: r.actual_fee,
                    execution_resources: r.execution_resources,
                    l2_to_l1_messages: r.l2_to_l1_messages,
                    execution_status: r.execution_status,
                    transaction_hash,
                    transaction_index: r.transaction_index,
                };
                (transaction, receipt)
            })
            .collect::<Vec<_>>();
        Ok(UnverifiedTransactions {
            expected_commitment,
            transactions,
        })
    }
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "Transactions::Verify";
    type Input = UnverifiedTransactions;
    type Output = Vec<(Transaction, Receipt)>;

    fn map(&mut self, transactions: Self::Input) -> Result<Self::Output, super::error::SyncError2> {
        let UnverifiedTransactions {
            expected_commitment,
            transactions,
        } = transactions;
        let txs: Vec<_> = transactions.iter().map(|(t, _)| t.clone()).collect();
        let actual =
            calculate_transaction_commitment(&txs, TransactionCommitmentFinalHashType::Normal)?;
        if actual != expected_commitment {
            return Err(SyncError2::TransactionCommitmentMismatch);
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

    fn map(&mut self, transactions: Self::Input) -> Result<Self::Output, SyncError2> {
        let db = self
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

pub struct DatabaseBlockBuffer {
    connection: pathfinder_storage::Connection,
    block: BlockNumber,
    end: BlockNumber,
}

impl BufferStage for DatabaseBlockBuffer {
    type AdditionalData = TransactionCommitment;
    const TOO_FEW_ERROR: SyncError2 = SyncError2::TooFewTransactions;

    fn next_amount(&mut self) -> Option<(usize, Self::AdditionalData)> {
        if self.block > self.end {
            return None;
        }

        let amount = self
            .connection
            .transaction()
            .inspect_err(|error| {
                tracing::warn!(%error, "Failed to open database transaction");
            })
            .ok()?
            .transaction_counts_and_commitments(self.block.into(), NonZeroUsize::new(1).unwrap())
            .inspect_err(|error| {
                tracing::warn!(%error, block=%self.block, "Failed to read transaction count and commitment");
            })
            .ok()?
            .pop();

        if amount.is_none() {
            tracing::warn!(block=%self.block, "No transaction count and commitment found in database.");
        }

        amount
    }
}
