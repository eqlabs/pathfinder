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
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockNumber, Fee};
    use v06::types::*;

    use super::*;

    #[tokio::test]
    async fn check_v05_representation() {
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
                        execution_resources: ExecutionResourcesProperties::V05(
                            ExecutionResourcesPropertiesV05 {
                                steps: 10,
                                memory_holes: 5,
                                pedersen_builtin_applications: 32,
                                ..Default::default()
                            }
                        ),
                    }
                }
            ))
        )
    }

    #[tokio::test]
    async fn json_output() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = v06::GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"txn 0"),
        };

        let receipt = get_transaction_receipt(context.clone(), input)
            .await
            .unwrap();

        let receipt = serde_json::to_value(receipt).unwrap();

        let expected = serde_json::json!({
            "transaction_hash": transaction_hash_bytes!(b"txn 0"),
            "actual_fee": "0x0",
            "execution_resources": {
                "steps": "0xa",
                "memory_holes": "0x5",
                "range_check_builtin_applications": "0x0",
                "pedersen_builtin_applications": "0x20",
                "poseidon_builtin_applications": "0x0",
                "ec_op_builtin_applications": "0x0",
                "ecdsa_builtin_applications": "0x0",
                "bitwise_builtin_applications": "0x0",
                "keccak_builtin_applications": "0x0"
            },
            "execution_status": "SUCCEEDED",
            "finality_status": "ACCEPTED_ON_L1",
            "block_hash": block_hash_bytes!(b"genesis"),
            "block_number": 0,
            "messages_sent": [],
            "events": [
                {
                    "data": [event_data_bytes!(b"event 0 data")],
                    "from_address": contract_address_bytes!(b"event 0 from addr"),
                    "keys": [event_key_bytes!(b"event 0 key")]
                }
            ],
            "type": "INVOKE",
        });

        assert_eq!(receipt, expected);
    }
}
