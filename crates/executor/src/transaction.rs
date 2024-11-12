use blockifier::transaction::objects::{FeeType, HasRelatedFeeType};
use blockifier::transaction::transaction_execution::Transaction;
use pathfinder_common::TransactionHash;

use super::felt::IntoFelt;

// This workaround will not be necessary after the PR:
// https://github.com/starkware-libs/blockifier/pull/927
pub fn transaction_hash(transaction: &Transaction) -> TransactionHash {
    TransactionHash(
        match transaction {
            Transaction::Account(tx) => match tx {
                blockifier::transaction::account_transaction::AccountTransaction::Declare(tx) => {
                    tx.tx_hash()
                }
                blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(
                    tx,
                ) => tx.tx_hash(),
                blockifier::transaction::account_transaction::AccountTransaction::Invoke(tx) => {
                    tx.tx_hash()
                }
            },
            Transaction::L1Handler(tx) => tx.tx_hash,
        }
        .0
        .into_felt(),
    )
}

pub fn fee_type(transaction: &Transaction) -> FeeType {
    match transaction {
        Transaction::Account(tx) => tx.fee_type(),
        Transaction::L1Handler(tx) => tx.fee_type(),
    }
}
