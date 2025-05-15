use blockifier::execution::contract_class::TrackedResource;
use blockifier::state::cached_state::{CachedState, MutRefState};
use blockifier::state::state_api::UpdatableState;
use blockifier::transaction::account_transaction::ExecutionFlags;
use blockifier::transaction::objects::{HasRelatedFeeType, TransactionExecutionInfo};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use starknet_api::core::ClassHash;
use starknet_api::execution_resources::{GasAmount, GasVector};
use starknet_api::transaction::fields::{
    AllResourceBounds,
    GasVectorComputationMode,
    ValidResourceBounds,
};
use util::percentage::Percentage;

use crate::TransactionExecutionError;

pub enum ExecutionBehaviorOnRevert {
    Fail,
    Continue,
}

impl ExecutionBehaviorOnRevert {
    pub fn should_fail_on_revert(&self) -> bool {
        matches!(self, Self::Fail)
    }
}

pub(crate) fn gas_vector_computation_mode(transaction: &Transaction) -> GasVectorComputationMode {
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
    if is_deploy_account_transaction(tx) {
        return Ok(gas_vector_computation_mode == &GasVectorComputationMode::All);
    }

    let sender_class_hash = state.get_class_hash_at(tx.sender_address())?;
    // Uninitialized class.
    if sender_class_hash == ClassHash::default() {
        tracing::debug!(sender_address=%tx.sender_address(), "Sender class not deployed yet, skipping L2 gas accounting");
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

fn is_deploy_account_transaction(transaction: &Transaction) -> bool {
    matches!(
        transaction,
        Transaction::Account(
            blockifier::transaction::account_transaction::AccountTransaction {
                tx: starknet_api::executable_transaction::AccountTransaction::DeployAccount(_),
                ..
            }
        )
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
///
/// Returns both the TransactionExecutionInfo (with the receipt containing
/// the _actual_ L2 gas amount used) and the gas vector with the minimal
/// gas limit (to be used to compute the fee estimation).
pub(crate) fn find_l2_gas_limit_and_execute_transaction<S>(
    tx: &mut Transaction,
    tx_index: usize,
    state: &mut S,
    block_context: &blockifier::context::BlockContext,
    revert_behavior: ExecutionBehaviorOnRevert,
    epsilon: Percentage,
) -> Result<(TransactionExecutionInfo, GasVector), TransactionExecutionError>
where
    S: UpdatableState,
{
    let execution_flags = get_execution_flags(tx);
    let initial_resource_bounds = get_resource_bounds(tx)?;
    let initial_l2_gas_limit = initial_resource_bounds.l2_gas.max_amount;

    let max_l2_gas_limit = get_max_l2_gas_amount_covered_by_balance(tx, block_context, state)?;
    set_l2_gas_limit(tx, max_l2_gas_limit);
    let (tx_info, _) =
        match simulate_transaction(tx, tx_index, state, block_context, &revert_behavior) {
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

    // Add a buffer (in terms of %) to the actual L2 gas fee.
    let l2_gas_adjusted = GasAmount(l2_gas_consumed.saturating_add(epsilon.of(l2_gas_consumed)));
    set_l2_gas_limit(tx, l2_gas_adjusted);

    let (gas_limit, tx_info, tx_state) =
        match simulate_transaction(tx, tx_index, state, block_context, &revert_behavior) {
            Ok((tx_info, tx_state)) => {
                metrics::increment_counter!("rpc_fee_estimation.without_binary_search");
                // If 110% of the actual transaction gas fee is enough, we use that
                // as the estimate and skip the binary search.
                let gas_limit = GasVector {
                    l2_gas: l2_gas_adjusted,
                    ..tx_info.receipt.gas
                };
                (gas_limit, tx_info, tx_state)
            }
            Err(TransactionSimulationError::OutOfGas) => {
                metrics::increment_counter!("rpc_fee_estimation.with_binary_search");

                let mut lower_bound = GasAmount(l2_gas_consumed);
                let mut upper_bound = max_l2_gas_limit;

                let mut current_l2_gas_limit = midpoint(lower_bound, upper_bound);

                let mut steps = 0;

                // Run a binary search to find the minimal gas limit that still allows the
                // transaction to execute without running out of L2 gas.
                let (tx_info, tx_state) = loop {
                    steps += 1;

                    tracing::debug!(
                        lower_bound=%lower_bound,
                        upper_bound=%upper_bound,
                        current=%current_l2_gas_limit,
                        "Searching for minimal L2 gas limit"
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

                    match simulate_transaction(tx, tx_index, state, block_context, &revert_behavior)
                    {
                        Ok((tx_info, tx_state)) => {
                            if search_done(lower_bound, upper_bound, L2_GAS_SEARCH_MARGIN) {
                                break (tx_info, tx_state);
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
                };

                metrics::histogram!("rpc_fee_estimation.steps_to_converge", steps as f64);

                let gas_limit = GasVector {
                    l2_gas: current_l2_gas_limit,
                    ..tx_info.receipt.gas
                };

                (gas_limit, tx_info, tx_state)
            }
            Err(TransactionSimulationError::ExecutionError(error)) => {
                return Err(error);
            }
        };

    metrics::histogram!(
        "rpc_fee_estimation.l2_gas_difference_between_limit_and_consumed",
        gas_limit
            .l2_gas
            .0
            .checked_sub(l2_gas_consumed)
            .expect("l2_gas_limit > l2_gas_consumed") as f64
    );

    let (tx_info, tx_state) =
        if execution_flags.charge_fee && gas_limit.l2_gas > initial_l2_gas_limit {
            tracing::debug!(
                initial_limit=%initial_l2_gas_limit,
                final_limit=%gas_limit.l2_gas,
                "Initial L2 gas limit exceeded"
            );

            // Set the L2 gas limit to the initial gas limit so that the transaction
            // reverts.
            set_l2_gas_limit(tx, initial_l2_gas_limit);

            // Revert state changes, and run the transaction again with the initial state.
            tx_state.abort();
            let mut tx_state = CachedState::<_>::create_transactional(state);

            // Make sure we return the gas limit we've determined is sufficient to run the
            // transaction, and _not_ the resources for the reverted transaction.
            let (tx_info, _) =
                execute_transaction(tx, tx_index, &mut tx_state, block_context, &revert_behavior)?;

            (tx_info, tx_state)
        } else {
            (tx_info, tx_state)
        };

    // State changes must be committed once the search is done.
    tx_state.commit();

    Ok((tx_info, gas_limit))
}

/// Execute the transaction and handle common errors.
pub(crate) fn execute_transaction<S>(
    tx: &Transaction,
    tx_index: usize,
    state: &mut S,
    block_context: &blockifier::context::BlockContext,
    revert_behavior: &ExecutionBehaviorOnRevert,
) -> Result<(TransactionExecutionInfo, GasVector), TransactionExecutionError>
where
    S: UpdatableState,
{
    match tx.execute(state, block_context) {
        Ok(tx_info) => {
            if revert_behavior.should_fail_on_revert() {
                if let Some(revert_error) = tx_info.revert_error {
                    let revert_string = revert_error.to_string();
                    tracing::debug!(revert_error=%revert_string, "Transaction reverted");

                    return Err(TransactionExecutionError::ExecutionError {
                        transaction_index: tx_index,
                        error: revert_string,
                        error_stack: revert_error.into(),
                    });
                }
            }

            let gas_limit = tx_info.receipt.gas;

            Ok((tx_info, gas_limit))
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

/// Execute transaction without updating the execution state directly. Instead,
/// the function returns the transactional state handle to the caller to decide
/// whether to commit the state update or not.
fn simulate_transaction<'state, S>(
    tx: &Transaction,
    tx_index: usize,
    state: &'state mut S,
    block_context: &blockifier::context::BlockContext,
    revert_behavior: &ExecutionBehaviorOnRevert,
) -> Result<
    (
        TransactionExecutionInfo,
        CachedState<MutRefState<'state, S>>,
    ),
    TransactionSimulationError,
>
where
    S: UpdatableState,
{
    let mut tx_state = CachedState::<_>::create_transactional(state);
    match tx.execute(&mut tx_state, block_context) {
        Ok(tx_info) if failed_with_insufficient_l2_gas(&tx_info) => {
            Err(TransactionSimulationError::OutOfGas)
        }
        Ok(tx_info) => {
            if revert_behavior.should_fail_on_revert() {
                if let Some(revert_error) = tx_info.revert_error {
                    let revert_string = revert_error.to_string();
                    tracing::debug!(revert_error=%revert_string, "Transaction reverted");

                    return Err(TransactionSimulationError::ExecutionError(
                        TransactionExecutionError::ExecutionError {
                            transaction_index: tx_index,
                            error: revert_string,
                            error_stack: revert_error.into(),
                        },
                    ));
                }
            }

            Ok((tx_info, tx_state))
        }
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

fn get_resource_bounds(tx: &Transaction) -> Result<AllResourceBounds, TransactionExecutionError> {
    use starknet_api::transaction::{
        DeclareTransaction,
        DeclareTransactionV3,
        DeployAccountTransaction,
        DeployAccountTransactionV3,
        InvokeTransaction,
        InvokeTransactionV3,
    };

    match tx {
        Transaction::Account(
            blockifier::transaction::account_transaction::AccountTransaction {
                tx:
                    starknet_api::executable_transaction::AccountTransaction::Declare(
                        starknet_api::executable_transaction::DeclareTransaction {
                            tx:
                                DeclareTransaction::V3(DeclareTransactionV3 {
                                    resource_bounds:
                                        ValidResourceBounds::AllResources(all_resources),
                                    ..
                                }),
                            ..
                        },
                    ),
                ..
            },
        ) => Ok(*all_resources),
        Transaction::Account(
            blockifier::transaction::account_transaction::AccountTransaction {
                tx:
                    starknet_api::executable_transaction::AccountTransaction::DeployAccount(
                        starknet_api::executable_transaction::DeployAccountTransaction {
                            tx:
                                DeployAccountTransaction::V3(DeployAccountTransactionV3 {
                                    resource_bounds:
                                        ValidResourceBounds::AllResources(all_resources),
                                    ..
                                }),
                            ..
                        },
                    ),
                ..
            },
        ) => Ok(*all_resources),
        Transaction::Account(
            blockifier::transaction::account_transaction::AccountTransaction {
                tx:
                    starknet_api::executable_transaction::AccountTransaction::Invoke(
                        starknet_api::executable_transaction::InvokeTransaction {
                            tx:
                                InvokeTransaction::V3(InvokeTransactionV3 {
                                    resource_bounds:
                                        ValidResourceBounds::AllResources(all_resources),
                                    ..
                                }),
                            ..
                        },
                    ),
                ..
            },
        ) => Ok(*all_resources),
        _ => Err(anyhow::anyhow!("Transaction doesn't have L2 gas").into()),
    }
}

fn get_execution_flags(tx: &Transaction) -> ExecutionFlags {
    match tx {
        Transaction::Account(account_transaction) => account_transaction.execution_flags.clone(),
        Transaction::L1Handler(_) => Default::default(),
    }
}

fn get_max_l2_gas_amount_covered_by_balance<S>(
    tx: &Transaction,
    block_context: &blockifier::context::BlockContext,
    state: &mut S,
) -> Result<GasAmount, TransactionExecutionError>
where
    S: UpdatableState,
{
    let initial_resource_bounds = get_resource_bounds(tx)?;
    let resource_bounds_without_l2_gas = AllResourceBounds {
        l2_gas: Default::default(),
        ..initial_resource_bounds
    };
    let max_possible_fee_without_l2_gas =
        ValidResourceBounds::AllResources(resource_bounds_without_l2_gas).max_possible_fee();

    match tx {
        Transaction::Account(account_transaction) => {
            match account_transaction.tx {
                starknet_api::executable_transaction::AccountTransaction::Declare(_)
                | starknet_api::executable_transaction::AccountTransaction::Invoke(_) => {
                    let fee_token_address = block_context
                        .chain_info()
                        .fee_token_address(&account_transaction.fee_type());
                    let balance = state.get_fee_token_balance(
                        account_transaction.sender_address(),
                        fee_token_address,
                    )?;
                    let balance = (balance.1.to_biguint() << 128) + balance.0.to_biguint();

                    tracing::warn!(%balance, "Balance");

                    if balance > max_possible_fee_without_l2_gas.0.into() {
                        // The maximum amount of L2 gas that can be bought with the balance.
                        let max_amount = (balance - max_possible_fee_without_l2_gas.0)
                            / initial_resource_bounds
                                .l2_gas
                                .max_price_per_unit
                                .0
                                .max(1u64.into());
                        Ok(u64::try_from(max_amount).unwrap_or(u64::MAX).into())
                    } else {
                        // Balance is less than committed L1 gas and L1 data gas, tx will fail
                        // anyway. Let it pass through here so that
                        // execution returns a detailed error.
                        Ok(GasAmount::ZERO)
                    }
                }
                starknet_api::executable_transaction::AccountTransaction::DeployAccount(_) => {
                    Ok(block_context
                        .versioned_constants()
                        .initial_gas_no_user_l2_bound())
                }
            }
        }
        Transaction::L1Handler(_) => {
            // L1 handler transactions don't have L2 gas.
            Err(anyhow::anyhow!("L1 handler transactions don't have L2 gas").into())
        }
    }
}

fn failed_with_insufficient_l2_gas(tx_info: &TransactionExecutionInfo) -> bool {
    let Some(revert_error) = &tx_info.revert_error else {
        return false;
    };

    revert_error.to_string().contains("Out of gas")
}
