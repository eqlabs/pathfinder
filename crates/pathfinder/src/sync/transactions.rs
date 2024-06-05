use std::collections::HashMap;
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

/// For a single block
#[derive(Clone, Debug)]
pub struct Transactions {
    pub block_number: BlockNumber,
    pub expected_commitment: TransactionCommitment,
    pub transactions: Vec<(Transaction, Receipt)>,
}

/// For a single block
#[derive(Clone, Debug)]
pub struct VerifiedTransactions {
    pub block_number: BlockNumber,
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
        let mut batch = Vec::new();

        while start <= stop_inclusive {
            if let Some(counts) = batch.pop() {
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
    }
}

pub(super) async fn compute_hashes(
    transactions: PeerData<TransactionData>,
    chain_id: ChainId,
) -> Result<PeerData<Transactions>, SyncError> {
    Ok(tokio::task::spawn_blocking(move || {
        use rayon::prelude::*;
        let PeerData {
            peer,
            data:
                TransactionData {
                    block_number,
                    expected_commitment,
                    transactions,
                },
        } = transactions;

        let transactions = transactions
            .into_par_iter()
            .map(|(tv, r)| {
                let transaction_hash = tv.calculate_hash(chain_id, false);
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

        PeerData::new(
            peer,
            Transactions {
                block_number,
                expected_commitment,
                transactions,
            },
        )
    })
    .await
    .context("Joining blocking task")?)
}

// TODO verify receipt commitments
pub(super) async fn verify_commitment(
    transactions: PeerData<Transactions>,
) -> Result<PeerData<VerifiedTransactions>, SyncError> {
    tokio::task::spawn_blocking(move || {
        let PeerData {
            peer,
            data:
                Transactions {
                    block_number,
                    expected_commitment,
                    transactions,
                },
        } = transactions;

        let (transactions, receipts): (Vec<_>, Vec<_>) = transactions.into_iter().unzip();
        let actual_commitment = calculate_transaction_commitment(
            &transactions,
            TransactionCommitmentFinalHashType::Normal,
        )?;
        if actual_commitment == expected_commitment {
            Ok(PeerData {
                peer,
                data: VerifiedTransactions {
                    block_number,
                    transactions: transactions.into_iter().zip(receipts).collect::<Vec<_>>(),
                },
            })
        } else {
            Err(SyncError::TransactionCommitmentMismatch(peer))
        }
    })
    .await
    .context("Joining blocking task")?
}

pub(super) async fn persist(
    storage: Storage,
    transactions: Vec<PeerData<VerifiedTransactions>>,
) -> Result<BlockNumber, SyncError> {
    tokio::task::spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        let tail = transactions
            .last()
            .map(|x| x.data.block_number)
            .context("Verification results are empty, no block to persist")?;

        for VerifiedTransactions {
            block_number,
            transactions,
        } in transactions.into_iter().map(|x| x.data)
        {
            db.insert_transaction_data(block_number, &transactions, None)
                .context("Inserting transactions")?;
        }
        db.commit().context("Committing db transaction")?;
        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}

pub struct CalculateHashes(pub ChainId);

impl ProcessStage for CalculateHashes {
    const NAME: &'static str = "Transactions::Hashes";
    type Input = (
        TransactionCommitment,
        Vec<(TransactionVariant, peer_agnostic::Receipt)>,
    );
    type Output = (TransactionCommitment, Vec<(Transaction, Receipt)>);

    fn map(&mut self, (commitment, transactions): Self::Input) -> Result<Self::Output, SyncError2> {
        use rayon::prelude::*;
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
        Ok((commitment, transactions))
    }
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "Transactions::Verify";
    type Input = (TransactionCommitment, Vec<(Transaction, Receipt)>);
    type Output = Vec<(Transaction, Receipt)>;

    fn map(
        &mut self,
        (commitment, transactions): Self::Input,
    ) -> Result<Self::Output, super::error::SyncError2> {
        let txs: Vec<_> = transactions.iter().map(|(t, _)| t.clone()).collect();
        let actual =
            calculate_transaction_commitment(&txs, TransactionCommitmentFinalHashType::Normal)?;
        if actual != commitment {
            return Err(SyncError2::TransactionCommitmentMismatch);
        }
        Ok(transactions)
    }
}
