use blockifier::blockifier::transaction_executor::{
    TransactionExecutionOutput,
    BLOCK_STATE_ACCESS_ERR,
};
use blockifier::execution::contract_class::TrackedResource;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::account_transaction::ExecutionFlags;
use blockifier::transaction::objects::{HasRelatedFeeType, TransactionExecutionInfo};
use blockifier::transaction::transaction_execution::Transaction;
use starknet_api::core::ClassHash;
use starknet_api::execution_resources::{GasAmount, GasVector};
use starknet_api::transaction::fields::{
    AllResourceBounds,
    GasVectorComputationMode,
    Tip,
    ValidResourceBounds,
};
use util::percentage::Percentage;

use crate::error::TransactionExecutorError;
use crate::execution_state::{PathfinderExecutionState, PathfinderExecutor};
use crate::state_reader::RcStorageAdapter;
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
pub(crate) fn l2_gas_accounting_enabled(
    tx: &Transaction,
    state: &PathfinderExecutionState<RcStorageAdapter<'_>>,
    block_context: &blockifier::context::BlockContext,
    gas_vector_computation_mode: &GasVectorComputationMode,
) -> blockifier::state::state_api::StateResult<bool> {
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
pub(crate) fn find_l2_gas_limit_and_execute_transaction(
    tx: &mut Transaction,
    tx_index: usize,
    tx_executor: &mut PathfinderExecutor<RcStorageAdapter<'_>>,
    revert_behavior: ExecutionBehaviorOnRevert,
    epsilon: Percentage,
) -> Result<(TransactionExecutionOutput, GasVector), TransactionExecutionError> {
    let execution_flags = get_execution_flags(tx);
    let initial_resource_bounds = get_resource_bounds(tx)?;
    let initial_l2_gas_limit = initial_resource_bounds.l2_gas.max_amount;

    let max_l2_gas_limit = if execution_flags.charge_fee {
        // If charge_fee is set, blockifier will enforce that the account balance covers
        // the committed bounds, including the L2 gas limit. If it doesn't, the
        // transaction will be rejected.
        get_max_l2_gas_amount_covered_by_balance(
            tx,
            &tx_executor.block_context,
            tx_executor
                .block_state
                .as_mut()
                .expect(BLOCK_STATE_ACCESS_ERR),
        )?
    } else {
        tx_executor
            .block_context
            .versioned_constants()
            .os_constants
            .execute_max_sierra_gas
    };

    tracing::trace!(
        l2_gas_limit=%initial_l2_gas_limit,
        max_l2_gas_limit=%max_l2_gas_limit,
        "L2 gas limits to use for fee estimation"
    );
    set_l2_gas_limit(tx, max_l2_gas_limit);

    let (output, saved_state) =
        match simulate_transaction(tx, tx_index, tx_executor, &revert_behavior) {
            Ok(output) => output,
            Err(TransactionSimulationError::ExecutionError(error)) => {
                return Err(error);
            }
            Err(TransactionSimulationError::OutOfGas(_)) => {
                return Err(
                    anyhow::anyhow!("Fee estimation failed, maximum gas limit exceeded").into(),
                );
            }
        };
    tx_executor.block_state = Some(saved_state);

    let GasAmount(l2_gas_consumed) = output.0.receipt.gas.l2_gas;

    // Add a buffer (in terms of %) to the actual L2 gas fee.
    let l2_gas_adjusted = GasAmount(l2_gas_consumed.saturating_add(epsilon.of(l2_gas_consumed)));
    set_l2_gas_limit(tx, l2_gas_adjusted);

    let (gas_limit, output, saved_state) =
        match simulate_transaction(tx, tx_index, tx_executor, &revert_behavior) {
            Ok((output, saved_state)) => {
                metrics::counter!("rpc_fee_estimation.without_binary_search").increment(1);
                // If 110% of the actual transaction gas fee is enough, we use that
                // as the estimate and skip the binary search.
                let gas_limit = GasVector {
                    l2_gas: l2_gas_adjusted,
                    ..output.0.receipt.gas
                };
                (gas_limit, output, saved_state)
            }
            Err(TransactionSimulationError::OutOfGas(saved_state)) => {
                tx_executor.block_state = Some(saved_state);

                metrics::counter!("rpc_fee_estimation.with_binary_search").increment(1);

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

                    match simulate_transaction(tx, tx_index, tx_executor, &revert_behavior) {
                        Ok((output, saved_state)) => {
                            if search_done(lower_bound, upper_bound, L2_GAS_SEARCH_MARGIN) {
                                break (output, saved_state);
                            }

                            tx_executor.block_state = Some(saved_state);
                            upper_bound = current_l2_gas_limit;
                            current_l2_gas_limit = midpoint(lower_bound, upper_bound);
                        }
                        Err(TransactionSimulationError::OutOfGas(saved_state)) => {
                            tx_executor.block_state = Some(saved_state);
                            lower_bound = current_l2_gas_limit;
                            current_l2_gas_limit = midpoint(lower_bound, upper_bound);
                        }
                        Err(TransactionSimulationError::ExecutionError(error)) => {
                            return Err(error);
                        }
                    }
                };

                metrics::histogram!("rpc_fee_estimation.steps_to_converge").record(steps as f64);

                let gas_limit = GasVector {
                    l2_gas: current_l2_gas_limit,
                    ..output.0.receipt.gas
                };

                (gas_limit, tx_info, tx_state)
            }
            Err(TransactionSimulationError::ExecutionError(error)) => {
                return Err(error);
            }
        };

    metrics::histogram!("rpc_fee_estimation.l2_gas_difference_between_limit_and_consumed",).record(
        gas_limit
            .l2_gas
            .0
            .checked_sub(l2_gas_consumed)
            .expect("l2_gas_limit > l2_gas_consumed") as f64,
    );

    let output = if execution_flags.charge_fee && gas_limit.l2_gas > initial_l2_gas_limit {
        tracing::debug!(
            initial_limit=%initial_l2_gas_limit,
            final_limit=%gas_limit.l2_gas,
            "Initial L2 gas limit exceeded"
        );

        // Set the L2 gas limit to the initial gas limit so that the transaction
        // reverts.
        set_l2_gas_limit(tx, initial_l2_gas_limit);

        // Revert state changes, and run the transaction again with the initial state.
        tx_executor.block_state = Some(saved_state);

        // Make sure we return the gas limit we've determined is sufficient to run the
        // transaction, and _not_ the resources for the reverted transaction.
        let (output, _) = execute_transaction(tx, tx_index, tx_executor, revert_behavior)?;

        output
    } else {
        // Not necessary but let's be explicit about not reverting the final execution
        // on the executor.
        drop(saved_state);
        output
    };

    Ok((output, gas_limit))
}

/// Execute the transaction and handle common errors.
pub(crate) fn execute_transaction(
    tx: &Transaction,
    tx_index: usize,
    tx_executor: &mut PathfinderExecutor<RcStorageAdapter<'_>>,
    revert_behavior: ExecutionBehaviorOnRevert,
) -> Result<(TransactionExecutionOutput, GasVector), TransactionExecutionError> {
    match tx_executor.execute(tx) {
        Ok(output) => {
            if revert_behavior.should_fail_on_revert() {
                if let Some(revert_error) = output.0.revert_error {
                    let revert_string = revert_error.to_string();
                    tracing::debug!(revert_error=%revert_string, "Transaction reverted");

                    return Err(TransactionExecutionError::ExecutionError {
                        transaction_index: tx_index,
                        error: revert_string,
                        error_stack: revert_error.into(),
                    });
                }
            }
            let gas_limit = output.0.receipt.gas;

            Ok((output, gas_limit))
        }
        Err(error) => {
            tracing::debug!(%error, %tx_index, "Transaction execution failed");
            let error = TransactionExecutorError::new(tx_index, error);
            Err(error.into())
        }
    }
}

/// Calculates the midpoint between two gas amounts without overflowing.
fn midpoint(a: GasAmount, b: GasAmount) -> GasAmount {
    let GasAmount(a) = a;
    let GasAmount(b) = b;
    let distance = b.checked_sub(a).expect("b >= a");

    // NB: Without ceiling, the binary search could enter an infinite loop if the
    // target is ever equal to the upper bound and the difference between the bounds
    // is 1.
    GasAmount(a + distance.div_ceil(2))
}

fn search_done(lower_bound: GasAmount, upper_bound: GasAmount, search_margin: GasAmount) -> bool {
    let diff = upper_bound
        .checked_sub(lower_bound)
        .expect("Upper bound should be greater than lower bound");

    diff <= search_margin
}

/// Execute transaction without updating the execution state directly. Instead,
/// the function returns the saved initial state to the caller to decide whether
/// to commit the state update (by doing nothing) or revert it (by assigning it
/// back into the executor).
#[allow(clippy::result_large_err)]
fn simulate_transaction<'tx>(
    tx: &Transaction,
    tx_index: usize,
    tx_executor: &mut PathfinderExecutor<RcStorageAdapter<'tx>>,
    revert_behavior: &ExecutionBehaviorOnRevert,
) -> Result<
    (
        TransactionExecutionOutput,
        PathfinderExecutionState<RcStorageAdapter<'tx>>,
    ),
    TransactionSimulationError<'tx>,
> {
    let initial_state = tx_executor
        .block_state
        .as_ref()
        .expect(BLOCK_STATE_ACCESS_ERR)
        .clone();
    match tx_executor.execute(tx) {
        Ok((tx_info, _)) if failed_with_insufficient_l2_gas(&tx_info) => {
            Err(TransactionSimulationError::OutOfGas(initial_state))
        }
        Ok(output) => {
            if revert_behavior.should_fail_on_revert() {
                if let Some(revert_error) = output.0.revert_error {
                    let revert_string = revert_error.to_string();
                    tracing::debug!(revert_error=%revert_string, "Transaction reverted");

                    let error = TransactionExecutionError::ExecutionError {
                        transaction_index: tx_index,
                        error: revert_string,
                        error_stack: revert_error.into(),
                    };
                    return Err(TransactionSimulationError::ExecutionError(error));
                }
            }

            Ok((output, initial_state))
        }
        Err(error) => {
            tracing::debug!(%error, %tx_index, "Transaction simulation failed");

            // Check if the error is due to running out of gas. Transactions might run out
            // of gas during validation, in which case we don't get a revert
            // error.
            if failed_with_insufficient_l2_gas_error(&error) {
                return Err(TransactionSimulationError::OutOfGas(initial_state));
            }

            let error = TransactionExecutorError::new(tx_index, error);
            Err(TransactionSimulationError::ExecutionError(error.into()))
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum TransactionSimulationError<'tx> {
    OutOfGas(PathfinderExecutionState<RcStorageAdapter<'tx>>),
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

pub(crate) fn get_tip(tx: &Transaction) -> Tip {
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
                            tx: DeclareTransaction::V3(DeclareTransactionV3 { tip, .. }),
                            ..
                        },
                    ),
                ..
            },
        ) => *tip,
        Transaction::Account(
            blockifier::transaction::account_transaction::AccountTransaction {
                tx:
                    starknet_api::executable_transaction::AccountTransaction::DeployAccount(
                        starknet_api::executable_transaction::DeployAccountTransaction {
                            tx: DeployAccountTransaction::V3(DeployAccountTransactionV3 { tip, .. }),
                            ..
                        },
                    ),
                ..
            },
        ) => *tip,
        Transaction::Account(
            blockifier::transaction::account_transaction::AccountTransaction {
                tx:
                    starknet_api::executable_transaction::AccountTransaction::Invoke(
                        starknet_api::executable_transaction::InvokeTransaction {
                            tx: InvokeTransaction::V3(InvokeTransactionV3 { tip, .. }),
                            ..
                        },
                    ),
                ..
            },
        ) => *tip,
        _ => Tip::ZERO,
    }
}

fn get_execution_flags(tx: &Transaction) -> ExecutionFlags {
    match tx {
        Transaction::Account(account_transaction) => account_transaction.execution_flags.clone(),
        Transaction::L1Handler(_) => Default::default(),
    }
}

fn get_max_l2_gas_amount_covered_by_balance(
    tx: &Transaction,
    block_context: &blockifier::context::BlockContext,
    state: &mut PathfinderExecutionState<RcStorageAdapter<'_>>,
) -> Result<GasAmount, TransactionExecutionError> {
    let initial_resource_bounds = get_resource_bounds(tx)?;
    let resource_bounds_without_l2_gas = AllResourceBounds {
        l2_gas: Default::default(),
        ..initial_resource_bounds
    };
    let max_possible_fee_without_l2_gas =
        ValidResourceBounds::AllResources(resource_bounds_without_l2_gas)
            .max_possible_fee(get_tip(tx));

    match tx {
        Transaction::Account(account_transaction) => {
            let fee_token_address = block_context
                .chain_info()
                .fee_token_address(&account_transaction.fee_type());
            let (balance_low, balance_high) = state
                .get_fee_token_balance(account_transaction.sender_address(), fee_token_address)?;
            let balance = balance_from_felt_pair(balance_low, balance_high);

            tracing::trace!(%balance, "Balance");

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
                tracing::trace!(
                    %balance,
                    "Balance does not cover committed L1 gas and L1 data gas"
                );
                Ok(GasAmount::ZERO)
            }
        }
        Transaction::L1Handler(_) => {
            // L1 handler transactions don't have L2 gas.
            Err(anyhow::anyhow!("L1 handler transactions don't have L2 gas").into())
        }
    }
}

/// Combines two `Felt252` values (low and high) into a `BigUint` balance.
///
/// Cairo U256 values are represented as a pair of `Felt252` values, where the
/// first element is the low 128 bits and the second element is the high 128
/// bits.
///
/// Note that we return `num_bigint::BigUint` here instead of U256 because we
/// want to be able to perform further arithmetic operations on the result.
fn balance_from_felt_pair(low: cairo_vm::Felt252, high: cairo_vm::Felt252) -> num_bigint::BigUint {
    (high.to_biguint() << 128) + low.to_biguint()
}

const OUT_OF_GAS_CAIRO_STRING: &str = "0x4f7574206f6620676173 ('Out of gas')";

fn failed_with_insufficient_l2_gas(tx_info: &TransactionExecutionInfo) -> bool {
    let Some(revert_error) = &tx_info.revert_error else {
        return false;
    };

    revert_error.to_string().contains(OUT_OF_GAS_CAIRO_STRING)
}

fn failed_with_insufficient_l2_gas_error(
    error: &blockifier::blockifier::transaction_executor::TransactionExecutorError,
) -> bool {
    error.to_string().contains(OUT_OF_GAS_CAIRO_STRING)
}
