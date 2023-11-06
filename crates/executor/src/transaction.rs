use blockifier::transaction::transaction_execution::Transaction;

use pathfinder_common::TransactionHash;

use super::felt::IntoFelt;

// This workaround will not be necessary after the PR:
// https://github.com/starkware-libs/blockifier/pull/927
pub fn transaction_hash(transaction: &Transaction) -> TransactionHash {
    TransactionHash(
        match transaction {
            Transaction::AccountTransaction(tx) => match tx {
                blockifier::transaction::account_transaction::AccountTransaction::Declare(tx) => {
                    tx.tx().transaction_hash()
                }
                blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(
                    tx,
                ) => tx.transaction_hash,
                blockifier::transaction::account_transaction::AccountTransaction::Invoke(tx) => {
                    tx.transaction_hash()
                }
            },
            Transaction::L1HandlerTransaction(tx) => tx.tx.transaction_hash,
        }
        .0
        .into_felt(),
    )
}
