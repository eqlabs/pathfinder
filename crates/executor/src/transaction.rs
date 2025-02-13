use blockifier::execution::contract_class::TrackedResource;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::UpdatableState;
use blockifier::transaction::objects::{HasRelatedFeeType, TransactionExecutionInfo};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use pathfinder_common::TransactionHash;
use starknet_api::block::FeeType;
use starknet_api::core::ClassHash;
use starknet_api::execution_resources::GasAmount;
use starknet_api::transaction::fields::GasVectorComputationMode;

use super::felt::IntoFelt;
use crate::TransactionExecutionError;

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

/// Starknet 0.13.4 introduced runtime L2 gas accounting but due to how
/// `blockifier` handles execution resources, it is only enabled if both the
/// caller and the "callee" contract classes were compiled as Seirra 1.7.
///
/// This function determines if the fee estimation should consider L2 gas
/// accounting or not.
pub(crate) fn l2_gas_accounting_enabled<S>(
    tx: &Transaction,
    state: &S,
    block_context: &blockifier::context::BlockContext,
    gas_vector_computation_mode: &GasVectorComputationMode,
) -> blockifier::state::state_api::StateResult<bool>
where
    S: UpdatableState,
{
    let sender_class_hash = state.get_class_hash_at(tx.sender_address())?;
    // Uninitialized class.
    if sender_class_hash == ClassHash::default() {
        return Ok(false);
    }

    let tracked_resource = state
        .get_compiled_class(sender_class_hash)?
        .tracked_resource(
            &block_context
                .versioned_constants()
                .min_sierra_version_for_sierra_gas,
            None,
        );

    // This is _not quite_ correct because only the sender contract class is
    // checked, but it is close enough. The default fee estimation with L2 gas
    // accounting (`l2_gas_consumed * 1.1`) will cover the case when the sender
    // contract class Seirra version is >= 1.7 but the called contract class
    // version is < 1.7.
    Ok(
        gas_vector_computation_mode == &GasVectorComputationMode::All
            && tracked_resource == TrackedResource::SierraGas,
    )
}

/// The margin for the binary search for the minimal L2 gas limit.
const L2_GAS_SEARCH_MARGIN: GasAmount = GasAmount(1_000_000);

/// Searches for the minimal L2 gas limit (within a certain margin) that allows
/// the transaction to execute without running out of L2 gas. Uses this limit to
/// execute the transaction. Exceeding the user provided L2 gas limit is not
/// allowed.
///
/// This is needed because Starknet 0.13.4 introduced runtime L2 gas accounting
/// which could lead to transactions being reverted because of insufficient L2
/// gas, even though the limit was set to the L2 gas cost of the transaction
/// (because the worst-case path gas requirements are larger than the actual
/// cost).
pub(crate) fn find_l2_gas_limit_and_execute_transaction<S>(
    tx: &mut Transaction,
    tx_index: usize,
    state: &mut S,
    block_context: &blockifier::context::BlockContext,
) -> Result<TransactionExecutionInfo, TransactionExecutionError>
where
    S: UpdatableState,
{
    let initial_l2_gas_limit = get_l2_gas_limit(tx);

    // Start with MAX gas limit to get the consumed L2 gas.
    set_l2_gas_limit(tx, GasAmount::MAX);
    let tx_info = match simulate_transaction(tx, tx_index, state, block_context) {
        Ok(tx_info) => tx_info,
        Err(TransactionSimulationError::ExecutionError(error)) => {
            return Err(error);
        }
        Err(TransactionSimulationError::OutOfGas) => {
            return Err(
                anyhow::anyhow!("Fee estimation failed, maximum gas limit exceeded").into(),
            );
        }
    };

    let GasAmount(l2_gas_consumed) = tx_info.receipt.gas.l2_gas;

    // Add a 10% buffer to the actual L2 gas fee.
    let l2_gas_adjusted = GasAmount(l2_gas_consumed.saturating_add(l2_gas_consumed / 10));
    set_l2_gas_limit(tx, l2_gas_adjusted);

    let l2_gas_limit = match simulate_transaction(tx, tx_index, state, block_context) {
        Ok(_) => {
            // If 110% of the actual transaction gas fee is enough, we use that
            // as the estimate and skip the binary search.
            l2_gas_adjusted
        }
        Err(TransactionSimulationError::OutOfGas) => {
            let mut lower_bound = GasAmount(l2_gas_consumed);
            let mut upper_bound = GasAmount::MAX;

            let mut current_l2_gas_limit = midpoint(lower_bound, upper_bound);

            // Run a binary search to find the minimal gas limit that still allows the
            // transaction to execute without running out of L2 gas.
            loop {
                tracing::debug!(
                    "Searching for minimal L2 gas limit in range [{lower_bound}; {upper_bound}]. \
                     Current limit: {current_l2_gas_limit}"
                );
                set_l2_gas_limit(tx, current_l2_gas_limit);

                // Special case where the search would get stuck if `current_l2_gas_limit ==
                // lower_bound` but the required amount is equal to the upper bound.
                let bounds_diff = upper_bound
                    .checked_sub(lower_bound)
                    .expect("Upper bound >= lower bound");
                if bounds_diff == GasAmount(1) && current_l2_gas_limit == lower_bound {
                    lower_bound = upper_bound;
                    current_l2_gas_limit = upper_bound;
                }

                match simulate_transaction(tx, tx_index, state, block_context) {
                    Ok(_) => {
                        if search_done(lower_bound, upper_bound, L2_GAS_SEARCH_MARGIN) {
                            break;
                        }

                        upper_bound = current_l2_gas_limit;
                        current_l2_gas_limit = midpoint(lower_bound, upper_bound);
                    }
                    Err(TransactionSimulationError::OutOfGas) => {
                        lower_bound = current_l2_gas_limit;
                        current_l2_gas_limit = midpoint(lower_bound, upper_bound);
                    }
                    Err(TransactionSimulationError::ExecutionError(error)) => {
                        return Err(error);
                    }
                }
            }

            current_l2_gas_limit
        }
        Err(TransactionSimulationError::ExecutionError(error)) => {
            return Err(error);
        }
    };

    if l2_gas_limit > initial_l2_gas_limit {
        tracing::debug!(
            initial_limit=%initial_l2_gas_limit,
            final_limit=%l2_gas_limit,
            "Initial L2 gas limit exceeded"
        );
        // Set the L2 gas limit to zero so that the transaction reverts with a detailed
        // `ExecutionError`.
        set_l2_gas_limit(tx, GasAmount::ZERO);
        match execute_transaction(tx, tx_index, state, block_context) {
            Err(e @ TransactionExecutionError::ExecutionError { .. }) => {
                return Err(e);
            }
            _ => unreachable!("Transaction should revert when gas limit is zero"),
        }
    }

    // Finally, execute the transaction with the found L2 gas limit and set that
    // limit as the estimate.
    set_l2_gas_limit(tx, l2_gas_limit);
    let mut tx_info = execute_transaction(tx, tx_index, state, block_context)
        .expect("Transaction already executed successfully");
    tx_info.receipt.gas.l2_gas = l2_gas_limit;

    Ok(tx_info)
}

/// Execute the transaction and handle common errors.
pub(crate) fn execute_transaction<S>(
    tx: &Transaction,
    tx_index: usize,
    state: &mut S,
    block_context: &blockifier::context::BlockContext,
) -> Result<TransactionExecutionInfo, TransactionExecutionError>
where
    S: UpdatableState,
{
    match tx.execute(state, block_context) {
        Ok(tx_info) => {
            if let Some(revert_error) = tx_info.revert_error {
                let revert_string = revert_error.to_string();
                tracing::debug!(revert_error=%revert_string, "Transaction reverted");

                return Err(TransactionExecutionError::ExecutionError {
                    transaction_index: tx_index,
                    error: revert_string,
                    error_stack: revert_error.into(),
                });
            }

            Ok(tx_info)
        }
        Err(error) => {
            tracing::debug!(%error, %tx_index, "Transaction estimation failed");

            Err(TransactionExecutionError::new(tx_index, error))
        }
    }
}

/// Calculates the midpoint between two gas amounts without overflowing.
fn midpoint(a: GasAmount, b: GasAmount) -> GasAmount {
    let GasAmount(a) = a;
    let GasAmount(b) = b;
    let distance = b.checked_sub(a).expect("b >= a");

    GasAmount(a + distance / 2)
}

fn search_done(lower_bound: GasAmount, upper_bound: GasAmount, search_margin: GasAmount) -> bool {
    let diff = upper_bound
        .checked_sub(lower_bound)
        .expect("Upper bound should be greater than lower bound");

    diff <= search_margin
}

/// Execute transaction without updating the execution state.
fn simulate_transaction<S>(
    tx: &Transaction,
    tx_index: usize,
    state: &mut S,
    block_context: &blockifier::context::BlockContext,
) -> Result<TransactionExecutionInfo, TransactionSimulationError>
where
    S: UpdatableState,
{
    // No need to call `.abort()` since it just drops the state.
    let mut tx_state = CachedState::<_>::create_transactional(state);
    match tx.execute(&mut tx_state, block_context) {
        Ok(tx_info) if failed_with_insufficient_l2_gas(&tx_info) => {
            Err(TransactionSimulationError::OutOfGas)
        }
        Ok(tx_info) => Ok(tx_info),
        Err(error) => {
            tracing::debug!(%error, %tx_index, "Transaction simulation failed");
            let error = TransactionExecutionError::new(tx_index, error);

            Err(TransactionSimulationError::ExecutionError(error))
        }
    }
}

enum TransactionSimulationError {
    OutOfGas,
    ExecutionError(TransactionExecutionError),
}

fn set_l2_gas_limit(transaction: &mut Transaction, gas_limit: GasAmount) {
    if let Transaction::Account(ref mut account_transaction) = transaction {
        use starknet_api::executable_transaction::AccountTransaction;
        use starknet_api::transaction::fields::ValidResourceBounds;

        match &mut account_transaction.tx {
            AccountTransaction::Declare(ref mut tx) => {
                use starknet_api::transaction::DeclareTransaction;
                if let DeclareTransaction::V3(ref mut tx) = &mut tx.tx {
                    match &mut tx.resource_bounds {
                        ValidResourceBounds::L1Gas(_) => {}
                        ValidResourceBounds::AllResources(ref mut all_resource_bounds) => {
                            all_resource_bounds.l2_gas.max_amount = gas_limit;
                            return;
                        }
                    }
                }
            }
            AccountTransaction::DeployAccount(ref mut tx) => {
                use starknet_api::transaction::DeployAccountTransaction;
                if let DeployAccountTransaction::V3(ref mut tx) = &mut tx.tx {
                    match &mut tx.resource_bounds {
                        ValidResourceBounds::L1Gas(_) => {}
                        ValidResourceBounds::AllResources(ref mut all_resource_bounds) => {
                            all_resource_bounds.l2_gas.max_amount = gas_limit;
                            return;
                        }
                    }
                }
            }
            AccountTransaction::Invoke(tx) => {
                use starknet_api::transaction::InvokeTransaction;
                if let InvokeTransaction::V3(ref mut tx) = &mut tx.tx {
                    match &mut tx.resource_bounds {
                        ValidResourceBounds::L1Gas(_) => {}
                        ValidResourceBounds::AllResources(ref mut all_resource_bounds) => {
                            all_resource_bounds.l2_gas.max_amount = gas_limit;
                            return;
                        }
                    }
                }
            }
        }
    }

    // This function should only be called with account transaction versions that
    // have L2 gas. It's a pain to set it up through the type system, so we'll
    // just return early in expected cases (see match above) and panic if we get
    // here.
    tracing::debug!(transaction=?transaction, "update_l2_gas_limit() called with a transaction that doesn't have L2 gas");
    unreachable!();
}

fn get_l2_gas_limit(tx: &Transaction) -> GasAmount {
    if let Transaction::Account(account_transaction) = tx {
        use starknet_api::executable_transaction::AccountTransaction;
        use starknet_api::transaction::fields::ValidResourceBounds;

        match &account_transaction.tx {
            AccountTransaction::Declare(tx) => {
                use starknet_api::transaction::DeclareTransaction;
                if let DeclareTransaction::V3(tx) = &tx.tx {
                    match &tx.resource_bounds {
                        ValidResourceBounds::L1Gas(_) => {}
                        ValidResourceBounds::AllResources(all_resource_bounds) => {
                            return all_resource_bounds.l2_gas.max_amount;
                        }
                    }
                }
            }
            AccountTransaction::DeployAccount(tx) => {
                use starknet_api::transaction::DeployAccountTransaction;
                if let DeployAccountTransaction::V3(tx) = &tx.tx {
                    match &tx.resource_bounds {
                        ValidResourceBounds::L1Gas(_) => {}
                        ValidResourceBounds::AllResources(all_resource_bounds) => {
                            return all_resource_bounds.l2_gas.max_amount;
                        }
                    }
                }
            }
            AccountTransaction::Invoke(tx) => {
                use starknet_api::transaction::InvokeTransaction;
                if let InvokeTransaction::V3(tx) = &tx.tx {
                    match &tx.resource_bounds {
                        ValidResourceBounds::L1Gas(_) => {}
                        ValidResourceBounds::AllResources(all_resource_bounds) => {
                            return all_resource_bounds.l2_gas.max_amount;
                        }
                    }
                }
            }
        }
    }

    // This function should only be called with account transaction versions that
    // have L2 gas. It's a pain to set it up through the type system, so we'll
    // just return early in expected cases (see match above) and panic if we get
    // here.
    tracing::debug!(transaction=?tx, "update_l2_gas_limit() called with a transaction that doesn't have L2 gas");
    unreachable!();
}

fn failed_with_insufficient_l2_gas(tx_info: &TransactionExecutionInfo) -> bool {
    let Some(revert_error) = &tx_info.revert_error else {
        return false;
    };

    revert_error.to_string().contains("Out of gas")
}
