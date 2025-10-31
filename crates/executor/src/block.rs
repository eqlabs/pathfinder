use anyhow::Context;
use blockifier::blockifier::transaction_executor::BLOCK_STATE_ACCESS_ERR;
use blockifier::state::cached_state::StateChanges;
use blockifier::transaction::objects::TransactionExecutionInfo;
use pathfinder_common::{ChainId, ClassHash, ContractAddress, TransactionIndex};

use crate::error::TransactionExecutorError;
use crate::execution_state::{create_executor, PathfinderExecutionState, PathfinderExecutor};
use crate::state_reader::ConcurrentStorageAdapter;
use crate::types::{
    to_receipt_and_events,
    to_state_diff,
    transaction_declared_deprecated_class,
    transaction_type,
    BlockInfo,
    Receipt,
    StateDiff,
};
use crate::{ExecutionState, Transaction, TransactionExecutionError};

/// Executes transactions from a single block. Produces transactions receipts,
/// events, and the final state diff for the entire block.
pub struct BlockExecutor {
    executor: PathfinderExecutor<ConcurrentStorageAdapter>,
    initial_state: PathfinderExecutionState<ConcurrentStorageAdapter>,
    declared_deprecated_classes: Vec<ClassHash>,
    next_txn_idx: usize,
}

type ReceiptAndEvents = (Receipt, Vec<pathfinder_common::event::Event>);

impl BlockExecutor {
    pub fn new(
        chain_id: ChainId,
        block_info: BlockInfo,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
        db_conn: pathfinder_storage::Connection,
    ) -> anyhow::Result<Self> {
        let execution_state = ExecutionState::validation(
            chain_id,
            block_info,
            None,
            Default::default(),
            eth_fee_address,
            strk_fee_address,
            None,
        );
        let storage_adapter = ConcurrentStorageAdapter::new(db_conn);
        let executor = create_executor(storage_adapter, execution_state)?;
        let initial_state = executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .clone();

        Ok(Self {
            executor,
            initial_state,
            declared_deprecated_classes: Vec::new(),
            next_txn_idx: 0,
        })
    }

    /// Create a new BlockExecutor with a pre-existing initial state
    /// This allows for executor chaining where the new executor starts with
    /// the final state of a previous executor
    pub fn new_with_initial_state(
        chain_id: ChainId,
        block_info: BlockInfo,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
        db_conn: pathfinder_storage::Connection,
        initial_state: PathfinderExecutionState<ConcurrentStorageAdapter>,
    ) -> anyhow::Result<Self> {
        let execution_state = ExecutionState::validation(
            chain_id,
            block_info,
            None,
            Default::default(),
            eth_fee_address,
            strk_fee_address,
            None,
        );
        let storage_adapter = ConcurrentStorageAdapter::new(db_conn);
        let mut executor = create_executor(storage_adapter, execution_state)?;

        // Set the initial state
        if let Some(block_state) = executor.block_state.as_mut() {
            *block_state = initial_state.clone();
        }

        Ok(Self {
            executor,
            initial_state,
            declared_deprecated_classes: Vec::new(),
            next_txn_idx: 0,
        })
    }

    /// Evecute a batch of transactions in the current block.
    pub fn execute(
        &mut self,
        txns: Vec<Transaction>,
    ) -> Result<Vec<ReceiptAndEvents>, TransactionExecutionError> {
        if txns.is_empty() {
            return Ok(vec![]);
        }

        let start_tx_index = self.next_txn_idx;
        self.next_txn_idx += txns.len();
        let block_number = self.executor.block_context.block_info().block_number;

        let _span = tracing::debug_span!(
            "BlockExecutor::execute",
            block_number = %block_number,
            from_tx_index = %start_tx_index,
            to_tx_index = %(self.next_txn_idx - 1),
        )
        .entered();

        // TODO(validator) specify execution_deadline as an additional safeguard
        let results = self
            .executor
            .execute_txs(&txns, None)
            .into_iter()
            .enumerate()
            .map(|(i, result)| {
                let tx_index = start_tx_index + i;
                match result {
                    Ok((tx_info, _)) => Ok((tx_index, tx_info)),
                    Err(error) => Err(TransactionExecutorError::new(tx_index, error)),
                }
            })
            .collect::<Result<Vec<(usize, TransactionExecutionInfo)>, TransactionExecutorError>>(
            )?;
        let receipts_events = results
            .into_iter()
            .zip(txns.into_iter())
            .map(|((tx_index, tx_info), tx)| {
                let tx_type = transaction_type(&tx);
                if let Some(class) = transaction_declared_deprecated_class(&tx) {
                    self.declared_deprecated_classes.push(class)
                }
                let gas_vector_computation_mode =
                    crate::transaction::gas_vector_computation_mode(&tx);

                to_receipt_and_events(
                    tx_type,
                    TransactionIndex::new(tx_index.try_into().expect("ptr size is 64bits"))
                        .context("tx_index < i64::MAX")?,
                    tx_info,
                    self.executor.block_context.versioned_constants(),
                    &gas_vector_computation_mode,
                )
                .map_err(TransactionExecutionError::Custom)
            })
            .collect::<Result<Vec<_>, TransactionExecutionError>>()?;
        Ok(receipts_events)
    }

    /// Finalizes block execution and returns the state diff for the block.
    pub fn finalize(self) -> anyhow::Result<StateDiff> {
        let Self {
            mut executor,
            initial_state,
            declared_deprecated_classes,
            ..
        } = self;

        executor.finalize()?;

        let mut state = executor.block_state.expect(BLOCK_STATE_ACCESS_ERR);
        let StateChanges { state_maps, .. } = state.to_state_diff()?;
        let diff = to_state_diff(
            state_maps,
            initial_state,
            declared_deprecated_classes.into_iter(),
        )?;
        Ok(diff)
    }

    /// Get the final state of the executor
    /// This allows for state extraction before finalizing
    pub fn get_final_state(
        &self,
    ) -> anyhow::Result<PathfinderExecutionState<ConcurrentStorageAdapter>> {
        let final_state = self
            .executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .clone();
        Ok(final_state)
    }

    /// Get the current transaction index
    /// This allows for tracking transaction indices across chained executors
    pub fn get_transaction_index(&self) -> usize {
        self.next_txn_idx
    }

    /// Set the transaction index
    /// This allows for setting the correct starting index for chained executors
    pub fn set_transaction_index(&mut self, index: usize) {
        self.next_txn_idx = index;
    }
}

#[cfg(test)]
mod tests {

    use pathfinder_common::transaction::{L1HandlerTransaction, TransactionVariant};
    use pathfinder_common::{
        contract_address,
        CallParam,
        ChainId,
        ContractAddress,
        EntryPoint,
        TransactionHash,
        TransactionNonce,
    };
    use pathfinder_crypto::Felt;
    use pathfinder_storage::StorageBuilder;

    use crate::BlockExecutor;

    // Fee token addresses (same as in pathfinder_rpc::context)
    const ETH_FEE_TOKEN_ADDRESS: ContractAddress =
        contract_address!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");
    const STRK_FEE_TOKEN_ADDRESS: ContractAddress =
        contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

    /// Creates a simple L1Handler transaction for testing
    fn create_simple_l1_handler_transaction(
        index: usize,
        chain_id: ChainId,
    ) -> pathfinder_common::transaction::Transaction {
        let nonce = Felt::from_hex_str(&format!("0x{index}")).unwrap();
        let address = Felt::from_hex_str(&format!("0x{index:x}")).unwrap();
        let entry_point_selector = Felt::from_hex_str(&format!("0x{index}")).unwrap();
        let calldata = [Felt::from_hex_str(&format!("0x{index}")).unwrap()];

        let l1_handler = L1HandlerTransaction {
            nonce: TransactionNonce(nonce),
            contract_address: ContractAddress::new_or_panic(address),
            entry_point_selector: EntryPoint(entry_point_selector),
            calldata: calldata.iter().map(|c| CallParam(*c)).collect(),
        };

        let hash = l1_handler.calculate_hash(chain_id);

        pathfinder_common::transaction::Transaction {
            hash: TransactionHash(hash.0),
            variant: TransactionVariant::L1Handler(l1_handler),
        }
    }

    /// Converts common transaction to executor transaction
    fn convert_to_executor_transaction(
        transaction: pathfinder_common::transaction::Transaction,
    ) -> anyhow::Result<crate::Transaction> {
        use pathfinder_common::transaction::TransactionVariant;
        use starknet_api::core::{
            ContractAddress as StarknetContractAddress,
            EntryPointSelector,
            Nonce,
            PatriciaKey,
        };
        use starknet_api::transaction::fields::Calldata;
        use starknet_api::transaction::{
            L1HandlerTransaction as StarknetL1HandlerTransaction,
            Transaction as StarknetApiTransaction,
            TransactionVersion,
        };

        use crate::felt::IntoStarkFelt;
        use crate::AccountTransactionExecutionFlags;

        match transaction.variant {
            TransactionVariant::L1Handler(l1_handler) => {
                // Convert to Starknet API transaction
                let starknet_txn =
                    StarknetApiTransaction::L1Handler(StarknetL1HandlerTransaction {
                        version: TransactionVersion::ZERO,
                        nonce: Nonce(l1_handler.nonce.0.into_starkfelt()),
                        contract_address: StarknetContractAddress(
                            PatriciaKey::try_from(
                                l1_handler.contract_address.get().into_starkfelt(),
                            )
                            .expect("No contract address overflow expected"),
                        ),
                        entry_point_selector: EntryPointSelector(
                            l1_handler.entry_point_selector.0.into_starkfelt(),
                        ),
                        calldata: Calldata(std::sync::Arc::new(
                            l1_handler
                                .calldata
                                .iter()
                                .map(|c| c.0.into_starkfelt())
                                .collect(),
                        )),
                    });

                // Convert to executor transaction
                let tx_hash =
                    starknet_api::transaction::TransactionHash(transaction.hash.0.into_starkfelt());
                let executor_txn = crate::Transaction::from_api(
                    starknet_txn,
                    tx_hash,
                    None,
                    Some(starknet_api::transaction::fields::Fee(1_000_000_000_000)),
                    None,
                    AccountTransactionExecutionFlags::default(),
                )?;

                Ok(executor_txn)
            }
            _ => anyhow::bail!("Unsupported transaction type for testing"),
        }
    }

    /// Detailed validation of state diff content
    fn validate_state_diff_content(
        single_state_diff: &crate::types::StateDiff,
        chained_state_diff: &crate::types::StateDiff,
    ) {
        // Storage diffs content validation
        assert_eq!(
            single_state_diff.storage_diffs.len(),
            chained_state_diff.storage_diffs.len(),
            "Storage diffs count mismatch"
        );

        // Compare storage diffs by contract address
        for (contract_addr, single_diffs) in &single_state_diff.storage_diffs {
            let chained_diffs = chained_state_diff
                .storage_diffs
                .get(contract_addr)
                .expect("Contract address missing in chained storage diffs");

            assert_eq!(
                single_diffs.len(),
                chained_diffs.len(),
                "Storage diffs count mismatch for contract {contract_addr:?}"
            );

            // Sort storage entries by key for comparison
            let mut single_entries = single_diffs.clone();
            let mut chained_entries = chained_diffs.clone();
            single_entries.sort_by_key(|entry| entry.key);
            chained_entries.sort_by_key(|entry| entry.key);

            for (j, (single_entry, chained_entry)) in single_entries
                .iter()
                .zip(chained_entries.iter())
                .enumerate()
            {
                assert_eq!(
                    single_entry.key, chained_entry.key,
                    "Storage key mismatch for contract {contract_addr:?} entry {j}"
                );
                assert_eq!(
                    single_entry.value, chained_entry.value,
                    "Storage value mismatch for contract {contract_addr:?} entry {j}"
                );
            }
        }

        // Deployed contracts content validation
        assert_eq!(
            single_state_diff.deployed_contracts.len(),
            chained_state_diff.deployed_contracts.len(),
            "Deployed contracts count mismatch"
        );

        let mut single_deployed = single_state_diff.deployed_contracts.clone();
        let mut chained_deployed = chained_state_diff.deployed_contracts.clone();
        single_deployed.sort_by_key(|contract| contract.address);
        chained_deployed.sort_by_key(|contract| contract.address);

        for (i, (single_contract, chained_contract)) in single_deployed
            .iter()
            .zip(chained_deployed.iter())
            .enumerate()
        {
            assert_eq!(
                single_contract.address, chained_contract.address,
                "Deployed contract address mismatch {i}"
            );
            assert_eq!(
                single_contract.class_hash, chained_contract.class_hash,
                "Deployed contract class hash mismatch {i}"
            );
        }

        // Declared classes content validation
        assert_eq!(
            single_state_diff.declared_classes.len(),
            chained_state_diff.declared_classes.len(),
            "Declared classes count mismatch"
        );

        let mut single_declared = single_state_diff.declared_classes.clone();
        let mut chained_declared = chained_state_diff.declared_classes.clone();
        single_declared.sort_by_key(|class| class.class_hash);
        chained_declared.sort_by_key(|class| class.class_hash);

        for (i, (single_class, chained_class)) in single_declared
            .iter()
            .zip(chained_declared.iter())
            .enumerate()
        {
            assert_eq!(
                single_class.class_hash, chained_class.class_hash,
                "Declared class hash mismatch {i}"
            );
            assert_eq!(
                single_class.compiled_class_hash, chained_class.compiled_class_hash,
                "Declared compiled class hash mismatch {i}"
            );
        }

        // Nonces content validation
        assert_eq!(
            single_state_diff.nonces.len(),
            chained_state_diff.nonces.len(),
            "Nonces count mismatch"
        );

        for (contract_addr, single_nonce) in &single_state_diff.nonces {
            let chained_nonce = chained_state_diff
                .nonces
                .get(contract_addr)
                .expect("Contract address missing in chained nonces");

            assert_eq!(
                single_nonce, chained_nonce,
                "Nonce mismatch for contract {contract_addr:?}"
            );
        }

        // Replaced classes content validation
        assert_eq!(
            single_state_diff.replaced_classes.len(),
            chained_state_diff.replaced_classes.len(),
            "Replaced classes count mismatch"
        );

        let mut single_replaced = single_state_diff.replaced_classes.clone();
        let mut chained_replaced = chained_state_diff.replaced_classes.clone();
        single_replaced.sort_by_key(|replaced| replaced.contract_address);
        chained_replaced.sort_by_key(|replaced| replaced.contract_address);

        for (i, (single_replaced, chained_replaced)) in single_replaced
            .iter()
            .zip(chained_replaced.iter())
            .enumerate()
        {
            assert_eq!(
                single_replaced.contract_address, chained_replaced.contract_address,
                "Replaced class contract address mismatch {i}"
            );
            assert_eq!(
                single_replaced.class_hash, chained_replaced.class_hash,
                "Replaced class hash mismatch {i}"
            );
        }
    }

    #[test]
    fn test_detailed_state_content_validation() {
        // Create test storage
        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;

        let block_info = crate::types::BlockInfo {
            number: pathfinder_common::BlockNumber::new_or_panic(1),
            timestamp: pathfinder_common::BlockTimestamp::new_or_panic(1000),
            sequencer_address: pathfinder_common::SequencerAddress::ZERO,
            l1_da_mode: pathfinder_common::L1DataAvailabilityMode::Calldata,
            eth_l1_gas_price: pathfinder_common::GasPrice::ZERO,
            strk_l1_gas_price: pathfinder_common::GasPrice::ZERO,
            eth_l1_data_gas_price: pathfinder_common::GasPrice::ZERO,
            strk_l1_data_gas_price: pathfinder_common::GasPrice::ZERO,
            eth_l2_gas_price: pathfinder_common::GasPrice::ZERO,
            strk_l2_gas_price: pathfinder_common::GasPrice::ZERO,
            starknet_version: pathfinder_common::StarknetVersion::new(0, 14, 0, 0),
        };

        // Create "real" transactions
        let common_transactions = vec![
            create_simple_l1_handler_transaction(1, chain_id),
            create_simple_l1_handler_transaction(2, chain_id),
            create_simple_l1_handler_transaction(3, chain_id),
        ];

        // Convert to executor transactions
        let executor_transactions: Vec<crate::Transaction> = common_transactions
            .into_iter()
            .map(convert_to_executor_transaction)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("Failed to convert transactions");

        // Execute them all in a single executor
        let mut single_executor = BlockExecutor::new(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            storage.connection().expect("Failed to get connection"),
        )
        .expect("Failed to create single executor");

        let single_receipts = single_executor
            .execute(executor_transactions.clone())
            .expect("Failed to execute in single executor");
        let single_state_diff = single_executor
            .finalize()
            .expect("Failed to finalize single executor");

        // Now execute them in a chained fashion, simulating 3 batches of 1 tx each
        let batch1 = vec![executor_transactions[0].clone()];
        let batch2 = vec![executor_transactions[1].clone()];
        let batch3 = vec![executor_transactions[2].clone()];

        // Execute batch 1
        let mut executor1 = BlockExecutor::new(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            storage.connection().expect("Failed to get connection"),
        )
        .expect("Failed to create executor1");

        let receipts1 = executor1.execute(batch1).expect("Failed to execute batch1");
        let state1 = executor1
            .get_final_state()
            .expect("Failed to get state from executor1");

        // Execute batch 2 with state from batch 1
        let mut executor2 = BlockExecutor::new_with_initial_state(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            storage.connection().expect("Failed to get connection"),
            state1,
        )
        .expect("Failed to create executor2");

        let receipts2 = executor2.execute(batch2).expect("Failed to execute batch2");
        let state2 = executor2
            .get_final_state()
            .expect("Failed to get state from executor2");

        // Execute batch 3 with state from batch 2
        let mut executor3 = BlockExecutor::new_with_initial_state(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            storage.connection().expect("Failed to get connection"),
            state2,
        )
        .expect("Failed to create executor3");

        let receipts3 = executor3.execute(batch3).expect("Failed to execute batch3");
        let state_diff3 = executor3.finalize().expect("Failed to finalize executor3");

        // Basic count validation first
        let total_chained_receipts = receipts1.len() + receipts2.len() + receipts3.len();
        assert_eq!(
            single_receipts.len(),
            total_chained_receipts,
            "Receipt count mismatch"
        );

        // Detailed state diff content validation
        validate_state_diff_content(&single_state_diff, &state_diff3);
    }

    /// Test with different batch sizes
    #[test]
    fn test_different_batch_sizes_consistency() {
        // Create test storage
        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;

        let block_info = crate::types::BlockInfo {
            number: pathfinder_common::BlockNumber::new_or_panic(1),
            timestamp: pathfinder_common::BlockTimestamp::new_or_panic(1000),
            sequencer_address: pathfinder_common::SequencerAddress::ZERO,
            l1_da_mode: pathfinder_common::L1DataAvailabilityMode::Calldata,
            eth_l1_gas_price: pathfinder_common::GasPrice::ZERO,
            strk_l1_gas_price: pathfinder_common::GasPrice::ZERO,
            eth_l1_data_gas_price: pathfinder_common::GasPrice::ZERO,
            strk_l1_data_gas_price: pathfinder_common::GasPrice::ZERO,
            eth_l2_gas_price: pathfinder_common::GasPrice::ZERO,
            strk_l2_gas_price: pathfinder_common::GasPrice::ZERO,
            starknet_version: pathfinder_common::StarknetVersion::new(0, 14, 0, 0),
        };

        // Create 5 transactions
        let common_transactions = (0..5)
            .map(|i| create_simple_l1_handler_transaction(i, chain_id))
            .collect::<Vec<_>>();

        let executor_transactions: Vec<crate::Transaction> = common_transactions
            .into_iter()
            .map(convert_to_executor_transaction)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("Failed to convert transactions");

        // Single executor execution
        let mut single_executor = BlockExecutor::new(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            storage.connection().expect("Failed to get connection"),
        )
        .expect("Failed to create single executor");

        let single_receipts = single_executor
            .execute(executor_transactions.clone())
            .expect("Failed to execute");
        let single_state_diff = single_executor.finalize().expect("Failed to finalize");

        // Chained execution with different batch sizes: [2, 1, 2]
        let batches = vec![
            vec![
                executor_transactions[0].clone(),
                executor_transactions[1].clone(),
            ],
            vec![executor_transactions[2].clone()],
            vec![
                executor_transactions[3].clone(),
                executor_transactions[4].clone(),
            ],
        ];

        let mut current_executor = BlockExecutor::new(
            chain_id,
            block_info,
            ETH_FEE_TOKEN_ADDRESS,
            STRK_FEE_TOKEN_ADDRESS,
            storage.connection().expect("Failed to get connection"),
        )
        .expect("Failed to create first executor");

        let mut total_receipts = 0;

        for batch in batches.into_iter() {
            current_executor = BlockExecutor::new(
                chain_id,
                block_info,
                ETH_FEE_TOKEN_ADDRESS,
                STRK_FEE_TOKEN_ADDRESS,
                storage.connection().expect("Failed to get connection"),
            )
            .expect("Failed to create executor");

            let receipts = current_executor
                .execute(batch)
                .expect("Failed to execute batch");
            total_receipts += receipts.len();
        }

        let final_state_diff = current_executor.finalize().expect("Failed to finalize");

        // Check receipt count as a first sanity check
        assert_eq!(
            single_receipts.len(),
            total_receipts,
            "Receipt count mismatch"
        );

        // Detailed content validation
        validate_state_diff_content(&single_state_diff, &final_state_diff);
    }
}
