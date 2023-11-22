use crate::context::RpcContext;
use crate::v05::method::get_transaction_receipt as v05;

pub async fn get_transaction_receipt(
    context: RpcContext,
    input: v05::GetTransactionReceiptInput,
) -> Result<v05::types::MaybePendingTransactionReceipt, v05::GetTransactionReceiptError> {
    // v0.5 has a different fee structure, but that gets handled in the v0.5 method. We can
    // safely use the impl as is.
    v05::get_transaction_receipt_impl(context, input).await
}

#[cfg(test)]
mod tests {
    use pathfinder_common::{block_hash_bytes, transaction_hash_bytes};

    use super::*;

    #[tokio::test]
    async fn fee_serde() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = v05::GetTransactionReceiptInput {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };

        let receipt = get_transaction_receipt(context.clone(), input)
            .await
            .unwrap();

        let receipt = serde_json::to_value(receipt).unwrap();

        let expected = serde_json::json!({
            "transaction_hash": transaction_hash_bytes!(b"txn reverted"),
            "actual_fee": {
                "amount": "0x0",
                "unit": "WEI",
            },
            "execution_resources": {
                "bitwise_builtin_applications": "0x0",
                "ec_op_builtin_applications": "0x0",
                "ecdsa_builtin_applications": "0x0",
                "keccak_builtin_applications": "0x0",
                "memory_holes": "0x0",
                "steps": "0x0",
                "pedersen_builtin_applications": "0x0",
                "poseidon_builtin_applications": "0x0",
                "range_check_builtin_applications": "0x0",
            },
            "execution_status": "REVERTED",
            "finality_status": "ACCEPTED_ON_L2",
            "block_hash": block_hash_bytes!(b"latest"),
            "block_number": 2,
            "messages_sent": [],
            "revert_reason": "Reverted because",
            "events": [],
            "type": "INVOKE",
        });

        assert_eq!(receipt, expected);
    }
}
