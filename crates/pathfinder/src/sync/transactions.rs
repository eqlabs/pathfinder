use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use anyhow::{anyhow, Context};
use p2p::client::peer_agnostic::{self, UnverifiedTransactionData};
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

use super::error::{SyncError, SyncError2};
use super::stream::ProcessStage;
use crate::state::block_hash::calculate_transaction_commitment;

/// For a single block
#[derive(Clone, Debug)]
pub struct UnverifiedTransactions {
    pub expected_commitment: TransactionCommitment,
    pub transactions: Vec<(Transaction, Receipt)>,
    pub version: StarknetVersion,
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

/// The starknet version is necessary to calculate the transaction hashes.
/// During checkpoint sync, the version can be fetched from the database.
pub struct FetchStarknetVersionFromDb(pub pathfinder_storage::Connection);

impl ProcessStage for FetchStarknetVersionFromDb {
    const NAME: &'static str = "Transactions::FetchStarknetVersionFromDb";
    type Input = UnverifiedTransactionData;
    type Output = (UnverifiedTransactionData, StarknetVersion);

    fn map(&mut self, data: Self::Input) -> Result<Self::Output, SyncError2> {
        let mut db = self
            .0
            .transaction()
            .context("Creating database transaction")?;

        let version = db
            .block_version(data.block_number)
            .context("Fetching starknet version")?
            .ok_or(SyncError2::StarknetVersionNotFound)?;
        Ok((data, version))
    }
}

pub struct CalculateHashes(pub ChainId);

impl ProcessStage for CalculateHashes {
    const NAME: &'static str = "Transactions::Hashes";
    type Input = (UnverifiedTransactionData, StarknetVersion);
    type Output = UnverifiedTransactions;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        use rayon::prelude::*;
        let (
            UnverifiedTransactionData {
                expected_commitment,
                transactions,
                ..
            },
            version,
        ) = input;
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
            version,
        })
    }
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "Transactions::Verify";
    type Input = UnverifiedTransactions;
    type Output = Vec<(Transaction, Receipt)>;

    fn map(&mut self, transactions: Self::Input) -> Result<Self::Output, SyncError2> {
        let UnverifiedTransactions {
            expected_commitment,
            transactions,
            version,
        } = transactions;
        let txs: Vec<_> = transactions.iter().map(|(t, _)| t.clone()).collect();
        let actual = calculate_transaction_commitment(&txs, version)?;
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
