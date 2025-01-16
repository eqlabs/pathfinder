use blockifier::transaction::objects::HasRelatedFeeType;
use blockifier::transaction::transaction_execution::Transaction;
use pathfinder_common::TransactionHash;
use starknet_api::block::FeeType;
use starknet_api::transaction::fields::GasVectorComputationMode;

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
                starknet_api::executable_transaction::AccountTransaction::DeployAccount(inner) => {
                    inner.tx_hash()
                }
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

pub fn gas_vector_computation_mode(transaction: &Transaction) -> GasVectorComputationMode {
    match &transaction {
        Transaction::Account(account_transaction) => {
            use starknet_api::executable_transaction::AccountTransaction;
            match &account_transaction.tx {
                AccountTransaction::Declare(tx) => {
                    use starknet_api::transaction::DeclareTransaction;
                    match &tx.tx {
                        DeclareTransaction::V3(tx) => {
                            tx.resource_bounds.get_gas_vector_computation_mode()
                        }
                        _ => GasVectorComputationMode::NoL2Gas,
                    }
                }
                AccountTransaction::DeployAccount(tx) => {
                    use starknet_api::transaction::DeployAccountTransaction;
                    match &tx.tx {
                        DeployAccountTransaction::V3(tx) => {
                            tx.resource_bounds.get_gas_vector_computation_mode()
                        }
                        _ => GasVectorComputationMode::NoL2Gas,
                    }
                }
                AccountTransaction::Invoke(tx) => {
                    use starknet_api::transaction::InvokeTransaction;
                    match &tx.tx {
                        InvokeTransaction::V3(tx) => {
                            tx.resource_bounds.get_gas_vector_computation_mode()
                        }
                        _ => GasVectorComputationMode::NoL2Gas,
                    }
                }
            }
        }
        Transaction::L1Handler(_) => GasVectorComputationMode::NoL2Gas,
    }
}
