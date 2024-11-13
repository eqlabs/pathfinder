use blockifier::transaction::objects::{FeeType, HasRelatedFeeType};
use blockifier::transaction::transaction_execution::Transaction;
use pathfinder_common::TransactionHash;

use super::felt::IntoFelt;

// This workaround will not be necessary after the PR:
// https://github.com/starkware-libs/blockifier/pull/927
pub fn transaction_hash(transaction: &Transaction) -> TransactionHash {
    TransactionHash(
        match transaction {
            Transaction::Account(outer) => match &outer.tx {
                starknet_api::executable_transaction::AccountTransaction::Declare(inner) => {
                    inner.tx_hash
                }
                starknet_api::executable_transaction::AccountTransaction::DeployAccount(
                    inner,
                ) => inner.tx_hash(),
                starknet_api::executable_transaction::AccountTransaction::Invoke(inner) => {
                    inner.tx_hash()
                }
            },
            Transaction::L1Handler(outer) => outer.tx_hash,
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
