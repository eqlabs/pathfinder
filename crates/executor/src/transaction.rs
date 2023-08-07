use blockifier::transaction::transaction_execution::Transaction;

use pathfinder_common::TransactionHash;

use super::felt::IntoFelt;

pub(super) fn transaction_hash(transaction: &Transaction) -> TransactionHash {
    TransactionHash(transaction.transaction_hash().0.into_felt())
}
