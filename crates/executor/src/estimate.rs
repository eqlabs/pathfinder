use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::UpdatableState;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use starknet_api::execution_resources::GasAmount;

use super::error::TransactionExecutionError;
use super::execution_state::ExecutionState;
use super::transaction::transaction_hash;
use super::types::FeeEstimate;

pub fn estimate(
    execution_state: ExecutionState<'_>,
    transactions: Vec<Transaction>,
) -> Result<Vec<FeeEstimate>, TransactionExecutionError> {
    let block_number = execution_state.header.number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    transactions
        .into_iter()
        .enumerate()
        .map(|(tx_index, mut tx)| {
            let _span = tracing::debug_span!(
                "estimate",
                block_number = %block_number,
                transaction_hash = %transaction_hash(&tx),
                transaction_index = %tx_index
            )
            .entered();

            let tx_info = match fee_estimation_version(&tx) {
                FeeEstimationVersion::WithoutL2Gas => {
                    execute_transaction(&tx, tx_index, &mut state, &block_context)
                }
                FeeEstimationVersion::WithL2Gas => find_l2_gas_limit_and_execute_transaction(
                    &mut tx,
                    tx_index,
                    &mut state,
                    &block_context,
                ),
            }?;

            tracing::trace!(
                actual_fee = %tx_info.receipt.fee.0,
                actual_resources = ?tx_info.receipt.resources,
                "Transaction estimation finished"
            );

            Ok(FeeEstimate::from_tx_and_tx_info(
                &tx,
                &tx_info,
                &block_context,
            ))
        })
        .collect()
}

/// The margin for the binary search for the minimal L2 gas limit.
const L2_GAS_SEARCH_MARGIN: GasAmount = GasAmount(100);

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
fn find_l2_gas_limit_and_execute_transaction<S>(
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
    update_l2_gas_limit(tx, GasAmount::MAX);
    let tx_info = match simulate_transaction(tx, tx_index, state, block_context) {
        Ok(tx_info) => tx_info,
        Err(TransactionSimulationError::ExecutionError(error)) => {
            return Err(error);
        }
        Err(TransactionSimulationError::OutOfGas) => {
            unreachable!("Transaction should not run out of gas with MAX gas limit")
        }
    };

    let l2_gas_consumed = tx_info.receipt.gas.l2_gas;

    // TODO: g = (1 + EPSILON) * g
    // This step is missing. Check what EPSILON is, then implement it.

    let mut lower_bound = l2_gas_consumed;
    let mut upper_bound = GasAmount::MAX;

    let mut current_l2_gas_limit = midpoint(lower_bound, upper_bound);

    // Run a binary search to find the minimal gas limit that still allows the
    // transaction to execute without running out of L2 gas.
    loop {
        tracing::debug!(current_limit=%current_l2_gas_limit, "Searching for minimal L2 gas limit");
        update_l2_gas_limit(tx, current_l2_gas_limit);

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

    if current_l2_gas_limit > initial_l2_gas_limit {
        tracing::debug!(
            initial_limit=%initial_l2_gas_limit,
            final_limit=%current_l2_gas_limit,
            "Initial L2 gas limit exceeded"
        );
        // Set the L2 gas limit to zero so that the transaction reverts.
        update_l2_gas_limit(tx, GasAmount::ZERO);
        return execute_transaction(tx, tx_index, state, block_context);
    }

    // Finally, execute the transaction with the found L2 gas limit and set that
    // limit as the estimate.
    let mut tx_info = execute_transaction(tx, tx_index, state, block_context)
        .expect("Transaction already executed successfully");
    tx_info.receipt.gas.l2_gas = current_l2_gas_limit;

    Ok(tx_info)
}

/// Calculates the midpoint between two gas amounts without overflowing.
fn midpoint(a: GasAmount, b: GasAmount) -> GasAmount {
    let GasAmount(a) = a;
    let GasAmount(b) = b;
    GasAmount(a + (b - a) / 2)
}

fn search_done(lower_bound: GasAmount, upper_bound: GasAmount, search_margin: GasAmount) -> bool {
    let diff = upper_bound
        .checked_sub(lower_bound)
        .expect("Upper bound should be greater than lower bound");

    diff <= search_margin
}

/// Execute the transaction and handle common errors.
fn execute_transaction<S>(
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

impl FeeEstimate {
    fn from_tx_and_tx_info(
        transaction: &Transaction,
        tx_info: &TransactionExecutionInfo,
        block_context: &blockifier::context::BlockContext,
    ) -> Self {
        let fee_type = super::transaction::fee_type(transaction);
        let gas_vector_computation_mode =
            super::transaction::gas_vector_computation_mode(&transaction);
        let minimal_gas_vector = match transaction {
            Transaction::Account(account_transaction) => {
                Some(blockifier::fee::gas_usage::estimate_minimal_gas_vector(
                    block_context,
                    account_transaction,
                    &gas_vector_computation_mode,
                ))
            }
            Transaction::L1Handler(_) => None,
        };

        FeeEstimate::from_tx_info_and_gas_price(
            tx_info,
            block_context.block_info(),
            fee_type,
            &minimal_gas_vector,
        )
    }
}

fn update_l2_gas_limit(transaction: &mut Transaction, gas_limit: GasAmount) {
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

fn fee_estimation_version(transaction: &Transaction) -> FeeEstimationVersion {
    fn fee_estimation_from_resource_bounds(
        resource_bounds: &starknet_api::transaction::fields::ValidResourceBounds,
    ) -> FeeEstimationVersion {
        use starknet_api::transaction::fields::ValidResourceBounds;
        match resource_bounds {
            ValidResourceBounds::AllResources(_) => FeeEstimationVersion::WithL2Gas,
            ValidResourceBounds::L1Gas(_) => FeeEstimationVersion::WithoutL2Gas,
        }
    }

    match &transaction {
        Transaction::Account(account_transaction) => {
            use starknet_api::executable_transaction::AccountTransaction;
            match &account_transaction.tx {
                AccountTransaction::Declare(inner) => {
                    use starknet_api::transaction::DeclareTransaction;
                    match &inner.tx {
                        DeclareTransaction::V3(tx) => {
                            fee_estimation_from_resource_bounds(&tx.resource_bounds)
                        }
                        _ => FeeEstimationVersion::WithoutL2Gas,
                    }
                }
                AccountTransaction::DeployAccount(inner) => {
                    use starknet_api::transaction::DeployAccountTransaction;
                    match &inner.tx {
                        DeployAccountTransaction::V3(tx) => {
                            fee_estimation_from_resource_bounds(&tx.resource_bounds)
                        }
                        _ => FeeEstimationVersion::WithoutL2Gas,
                    }
                }
                AccountTransaction::Invoke(inner) => {
                    use starknet_api::transaction::InvokeTransaction;
                    match &inner.tx {
                        InvokeTransaction::V3(tx) => {
                            fee_estimation_from_resource_bounds(&tx.resource_bounds)
                        }
                        _ => FeeEstimationVersion::WithoutL2Gas,
                    }
                }
            }
        }
        Transaction::L1Handler(_) => FeeEstimationVersion::WithoutL2Gas,
    }
}

/// Fee estimation can currently take place in two ways - with or without L2
/// gas.
///
/// For the transactions before Starknet 0.13.4, the fee estimation is done
/// without L2 gas. For the ones after this version, the fee estimation is done
/// with L2 gas.
enum FeeEstimationVersion {
    WithoutL2Gas,
    WithL2Gas,
}

fn failed_with_insufficient_l2_gas(tx_info: &TransactionExecutionInfo) -> bool {
    let Some(revert_error) = &tx_info.revert_error else {
        return false;
    };

    // TODO: Is there a type-safe way to check for this error?
    revert_error.to_string().contains("Out of gas")
}
