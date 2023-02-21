use crate::v02::types::reply::Transaction;
use crate::v02::RpcContext;

crate::error::generate_rpc_error_subset!(GetNonceError:);

pub async fn pending_transactions(context: RpcContext) -> Result<Vec<Transaction>, GetNonceError> {
    let transactions = match context.pending_data {
        Some(data) => match data.block().await {
            Some(block) => block.transactions.iter().map(Transaction::from).collect(),
            None => Vec::new(),
        },
        None => Vec::new(),
    };

    Ok(transactions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::reply::{
        CommonDeclareInvokeTransactionProperties, DeployTransaction, InvokeTransaction,
        InvokeTransactionV0,
    };
    use pathfinder_common::{
        felt_bytes, ClassHash, ContractAddress, ContractAddressSalt, EntryPoint,
        StarknetTransactionHash, TransactionNonce, TransactionVersion,
    };

    #[tokio::test]
    async fn pending() {
        // Transcribed from the `RpcContext::for_tests_with_pending` transactions.
        let tx0 = InvokeTransactionV0 {
            common: CommonDeclareInvokeTransactionProperties {
                hash: StarknetTransactionHash(felt_bytes!(b"pending tx hash 0")),
                max_fee: crate::v02::types::request::Call::DEFAULT_MAX_FEE,
                signature: vec![],
                nonce: TransactionNonce::ZERO,
            },
            contract_address: ContractAddress::new_or_panic(felt_bytes!(
                b"pending contract addr 0"
            )),
            entry_point_selector: EntryPoint(felt_bytes!(b"entry point 0")),
            calldata: vec![],
        };

        let tx1 = DeployTransaction {
            hash: StarknetTransactionHash(felt_bytes!(b"pending tx hash 1")),
            class_hash: ClassHash(felt_bytes!(b"pending class hash 1")),
            version: TransactionVersion::ZERO,
            contract_address_salt: ContractAddressSalt(felt_bytes!(b"salty")),
            constructor_calldata: vec![],
        };

        let expected = vec![
            Transaction::Invoke(InvokeTransaction::V0(tx0)),
            Transaction::Deploy(tx1),
        ];

        let context = RpcContext::for_tests_with_pending().await;
        let result = pending_transactions(context).await.unwrap();

        assert_eq!(result, expected);
    }
}
