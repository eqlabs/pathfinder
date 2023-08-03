use blockifier::transaction::transaction_execution::Transaction;

use pathfinder_common::TransactionHash;

use super::felt::IntoFelt;

pub(super) fn transaction_hash(transaction: &Transaction) -> TransactionHash {
    TransactionHash(
        match transaction {
            Transaction::AccountTransaction(tx) => match tx {
                blockifier::transaction::account_transaction::AccountTransaction::Declare(tx) => {
                    tx.tx_hash()
                }
                blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(
                    tx,
                ) => tx.tx_hash,
                blockifier::transaction::account_transaction::AccountTransaction::Invoke(tx) => {
                    tx.tx_hash
                }
            },
            Transaction::L1HandlerTransaction(tx) => tx.tx_hash,
        }
        .0
        .into_felt(),
    )
}
