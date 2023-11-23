use crate::context::RpcContext;
use crate::v06::method::get_transaction_receipt as v06;

pub async fn get_transaction_receipt(
    context: RpcContext,
    input: v06::GetTransactionReceiptInput,
) -> Result<v06::types::MaybePendingTransactionReceipt, v06::GetTransactionReceiptError> {
    v06::get_transaction_receipt_impl(context, input)
        .await
        .map(|x| x.into_v5_form())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::{macro_prelude::*, BlockNumber, Fee};
    use starknet_gateway_types::reply::transaction::ExecutionResources;
    use v06::types::*;

    #[tokio::test]
    async fn v05_gas_check() {
        let context = RpcContext::for_tests();
        let input = v06::GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"txn 0"),
        };

        let result = super::get_transaction_receipt(context, input)
            .await
            .unwrap();
        assert_eq!(
            result,
            MaybePendingTransactionReceipt::Normal(TransactionReceipt::Invoke(
                InvokeTransactionReceipt {
                    common: CommonTransactionReceiptProperties {
                        transaction_hash: transaction_hash_bytes!(b"txn 0"),
                        actual_fee: FeePayment::V05(Fee::ZERO),
                        block_hash: block_hash_bytes!(b"genesis"),
                        block_number: BlockNumber::new_or_panic(0),
                        messages_sent: vec![],
                        events: vec![Event {
                            data: vec![event_data_bytes!(b"event 0 data")],
                            from_address: contract_address_bytes!(b"event 0 from addr"),
                            keys: vec![event_key_bytes!(b"event 0 key")],
                        }],
                        execution_status: ExecutionStatus::Succeeded,
                        finality_status: FinalityStatus::AcceptedOnL1,
                        revert_reason: None,
                        execution_resources: ExecutionResources::default().into(),
                    }
                }
            ))
        )
    }
}
