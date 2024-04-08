use crate::context::RpcContext;

use crate::v06::method::trace_block_transactions as v06;

pub async fn trace_block_transactions(
    context: RpcContext,
    input: v06::TraceBlockTransactionsInput,
) -> Result<v06::TraceBlockTransactionsOutput, v06::TraceBlockTransactionsError> {
    v06::trace_block_transactions_impl(context, input).await
}

#[cfg(test)]
pub(crate) mod tests {
    use pathfinder_common::{
        block_hash, receipt::Receipt, transaction_hash, BlockHeader, GasPrice, SierraHash,
        StarknetVersion, TransactionIndex,
    };
    use pathfinder_common::{BlockId, L1DataAvailabilityMode};
    use starknet_gateway_types::reply::GasPrices;
    use tokio::task::JoinSet;

    use super::v06::{Trace, TraceBlockTransactionsInput, TraceBlockTransactionsOutput};
    use super::{trace_block_transactions, RpcContext};
    use crate::v04::method::simulate_transactions::tests::setup_storage_with_starknet_version;

    pub(crate) async fn setup_multi_tx_trace_test(
    ) -> anyhow::Result<(RpcContext, BlockHeader, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::fixtures;

        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 0)).await;
        let context = RpcContext::for_tests().with_storage(storage.clone());

        let transactions = vec![
            fixtures::input::declare(account_contract_address).into_common(context.chain_id),
            fixtures::input::universal_deployer(
                account_contract_address,
                universal_deployer_address,
            )
            .into_common(context.chain_id),
            fixtures::input::invoke(account_contract_address).into_common(context.chain_id),
        ];

        let traces = vec![
            fixtures::expected_output_0_13_1::declare(account_contract_address, &last_block_header)
                .transaction_trace,
            fixtures::expected_output_0_13_1::universal_deployer(
                account_contract_address,
                &last_block_header,
                universal_deployer_address,
            )
            .transaction_trace,
            fixtures::expected_output_0_13_1::invoke(
                account_contract_address,
                &last_block_header,
                test_storage_value,
            )
            .transaction_trace,
        ];

        let next_block_header = {
            let mut db = storage.connection()?;
            let tx = db.transaction()?;

            tx.insert_sierra_class(
                &SierraHash(fixtures::SIERRA_HASH.0),
                fixtures::SIERRA_DEFINITION,
                &fixtures::CASM_HASH,
                fixtures::CASM_DEFINITION,
            )?;

            let next_block_header = BlockHeader::builder()
                .with_number(last_block_header.number + 1)
                .with_eth_l1_gas_price(GasPrice(1))
                .with_eth_l1_data_gas_price(GasPrice(2))
                .with_parent_hash(last_block_header.hash)
                .with_starknet_version(last_block_header.starknet_version)
                .with_sequencer_address(last_block_header.sequencer_address)
                .with_timestamp(last_block_header.timestamp)
                .with_starknet_version(StarknetVersion::new(0, 13, 1, 0))
                .with_l1_da_mode(L1DataAvailabilityMode::Blob)
                .finalize_with_hash(block_hash!("0x1"));
            tx.insert_block_header(&next_block_header)?;

            let dummy_receipt = Receipt {
                transaction_hash: transaction_hash!("0x1"),
                transaction_index: TransactionIndex::new_or_panic(0),
                ..Default::default()
            };
            tx.insert_transaction_data(
                next_block_header.number,
                &[
                    pathfinder_storage::TransactionData {
                        transaction: transactions[0].clone(),
                        receipt: Some(dummy_receipt.clone()),
                        events: Some(vec![]),
                    },
                    pathfinder_storage::TransactionData {
                        transaction: transactions[1].clone(),
                        receipt: Some(dummy_receipt.clone()),
                        events: Some(vec![]),
                    },
                    pathfinder_storage::TransactionData {
                        transaction: transactions[2].clone(),
                        receipt: Some(dummy_receipt.clone()),
                        events: Some(vec![]),
                    },
                ],
            )?;
            tx.commit()?;

            next_block_header
        };

        let traces = vec![
            Trace {
                transaction_hash: transactions[0].hash,
                trace_root: traces[0].clone(),
            },
            Trace {
                transaction_hash: transactions[1].hash,
                trace_root: traces[1].clone(),
            },
            Trace {
                transaction_hash: transactions[2].hash,
                trace_root: traces[2].clone(),
            },
        ];

        Ok((context, next_block_header, traces))
    }

    #[tokio::test]
    async fn test_multiple_transactions() -> anyhow::Result<()> {
        let (context, next_block_header, traces) = setup_multi_tx_trace_test().await?;

        let input = TraceBlockTransactionsInput {
            block_id: next_block_header.hash.into(),
        };
        let output = trace_block_transactions(context, input).await.unwrap();
        let expected = TraceBlockTransactionsOutput(traces);

        pretty_assertions_sorted::assert_eq!(output, expected);
        Ok(())
    }

    /// Test that multiple requests for the same block return correctly. This checks that the
    /// trace request coalescing doesn't do anything unexpected.
    #[tokio::test]
    async fn test_request_coalescing() -> anyhow::Result<()> {
        const NUM_REQUESTS: usize = 1000;

        let (context, next_block_header, traces) = setup_multi_tx_trace_test().await?;

        let input = TraceBlockTransactionsInput {
            block_id: next_block_header.hash.into(),
        };
        let mut joins = JoinSet::new();
        for _ in 0..NUM_REQUESTS {
            let input = input.clone();
            let context = context.clone();
            joins.spawn(async move { trace_block_transactions(context, input).await.unwrap() });
        }
        let mut outputs = Vec::new();
        while let Some(output) = joins.join_next().await {
            outputs.push(output.unwrap());
        }
        let expected = vec![TraceBlockTransactionsOutput(traces); NUM_REQUESTS];

        pretty_assertions_sorted::assert_eq!(outputs, expected);
        Ok(())
    }

    pub(crate) async fn setup_multi_tx_trace_pending_test(
    ) -> anyhow::Result<(RpcContext, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::fixtures;

        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 0)).await;
        let context = RpcContext::for_tests().with_storage(storage.clone());

        let transactions = vec![
            fixtures::input::declare(account_contract_address).into_common(context.chain_id),
            fixtures::input::universal_deployer(
                account_contract_address,
                universal_deployer_address,
            )
            .into_common(context.chain_id),
            fixtures::input::invoke(account_contract_address).into_common(context.chain_id),
        ];

        let traces = vec![
            fixtures::expected_output_0_13_1::declare(account_contract_address, &last_block_header)
                .transaction_trace,
            fixtures::expected_output_0_13_1::universal_deployer(
                account_contract_address,
                &last_block_header,
                universal_deployer_address,
            )
            .transaction_trace,
            fixtures::expected_output_0_13_1::invoke(
                account_contract_address,
                &last_block_header,
                test_storage_value,
            )
            .transaction_trace,
        ];

        let pending_block = {
            let mut db = storage.connection()?;
            let tx = db.transaction()?;

            tx.insert_sierra_class(
                &SierraHash(fixtures::SIERRA_HASH.0),
                fixtures::SIERRA_DEFINITION,
                &fixtures::CASM_HASH,
                fixtures::CASM_DEFINITION,
            )?;

            let dummy_receipt = Receipt {
                transaction_hash: transaction_hash!("0x1"),
                transaction_index: TransactionIndex::new_or_panic(0),
                ..Default::default()
            };

            let transaction_receipts = vec![(dummy_receipt, vec![]); 3];

            let pending_block = starknet_gateway_types::reply::PendingBlock {
                l1_gas_price: GasPrices {
                    price_in_wei: GasPrice(1),
                    price_in_fri: GasPrice(1),
                },
                l1_data_gas_price: GasPrices {
                    price_in_wei: GasPrice(2),
                    price_in_fri: GasPrice(2),
                },
                parent_hash: last_block_header.hash,
                sequencer_address: last_block_header.sequencer_address,
                status: starknet_gateway_types::reply::Status::Pending,
                timestamp: last_block_header.timestamp,
                transaction_receipts,
                transactions: transactions.iter().cloned().map(Into::into).collect(),
                starknet_version: last_block_header.starknet_version,
                l1_da_mode: starknet_gateway_types::reply::L1DataAvailabilityMode::Blob,
            };

            tx.commit()?;

            pending_block
        };

        let pending_data = crate::pending::PendingData {
            block: pending_block.into(),
            state_update: Default::default(),
            number: last_block_header.number + 1,
        };

        let (tx, rx) = tokio::sync::watch::channel(Default::default());
        tx.send(pending_data).unwrap();

        let context = context.with_pending_data(rx);

        let traces = vec![
            Trace {
                transaction_hash: transactions[0].hash,
                trace_root: traces[0].clone(),
            },
            Trace {
                transaction_hash: transactions[1].hash,
                trace_root: traces[1].clone(),
            },
            Trace {
                transaction_hash: transactions[2].hash,
                trace_root: traces[2].clone(),
            },
        ];

        Ok((context, traces))
    }

    #[tokio::test]
    async fn test_multiple_pending_transactions() -> anyhow::Result<()> {
        let (context, traces) = setup_multi_tx_trace_pending_test().await?;

        let input = TraceBlockTransactionsInput {
            block_id: BlockId::Pending,
        };
        let output = trace_block_transactions(context, input).await.unwrap();
        let expected = TraceBlockTransactionsOutput(traces);

        pretty_assertions_sorted::assert_eq!(output, expected);
        Ok(())
    }
}
