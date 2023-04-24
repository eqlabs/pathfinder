use crate::reply::transaction::{
    DeclareTransaction, DeclareTransactionV0V1, DeclareTransactionV2, DeployAccountTransaction,
    DeployTransaction, InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1,
    L1HandlerTransaction, Transaction,
};
use pathfinder_common::StarknetTransactionHash;

#[derive(Debug, PartialEq)]
pub enum ComputedTransactionHash {
    DeclareV0V1(StarknetTransactionHash),
    DeclareV2(StarknetTransactionHash),
    Deploy(StarknetTransactionHash),
    DeployAccount(StarknetTransactionHash),
    InvokeV0(StarknetTransactionHash),
    InvokeV1(StarknetTransactionHash),
    L1Handler(StarknetTransactionHash),
}

impl ComputedTransactionHash {
    pub fn hash(&self) -> StarknetTransactionHash {
        match self {
            ComputedTransactionHash::DeclareV0V1(h) => *h,
            ComputedTransactionHash::DeclareV2(h) => *h,
            ComputedTransactionHash::Deploy(h) => *h,
            ComputedTransactionHash::DeployAccount(h) => *h,
            ComputedTransactionHash::InvokeV0(h) => *h,
            ComputedTransactionHash::InvokeV1(h) => *h,
            ComputedTransactionHash::L1Handler(h) => *h,
        }
    }
}

pub fn compute_transaction_hash(txn: Transaction) -> ComputedTransactionHash {
    match txn {
        Transaction::Declare(DeclareTransaction::V0(txn) | DeclareTransaction::V1(txn)) => {
            compute_declare_v0v1_hash(txn)
        }
        Transaction::Declare(DeclareTransaction::V2(txn)) => compute_declare_v2_hash(txn),
        Transaction::Deploy(txn) => compute_deploy_hash(txn),
        Transaction::DeployAccount(txn) => compute_deploy_account_hash(txn),
        Transaction::Invoke(InvokeTransaction::V0(txn)) => compute_invoke_v0_hash(txn),
        Transaction::Invoke(InvokeTransaction::V1(txn)) => compute_invoke_v1_hash(txn),
        Transaction::L1Handler(txn) => compute_l1_handler_hash(txn),
    }
}

fn compute_declare_v0v1_hash(_txn: DeclareTransactionV0V1) -> ComputedTransactionHash {
    todo!()
}

fn compute_declare_v2_hash(_txn: DeclareTransactionV2) -> ComputedTransactionHash {
    todo!()
}

fn compute_deploy_hash(_txn: DeployTransaction) -> ComputedTransactionHash {
    todo!()
}

fn compute_deploy_account_hash(_txn: DeployAccountTransaction) -> ComputedTransactionHash {
    todo!()
}

fn compute_invoke_v0_hash(_txn: InvokeTransactionV0) -> ComputedTransactionHash {
    todo!()
}

fn compute_invoke_v1_hash(_txn: InvokeTransactionV1) -> ComputedTransactionHash {
    todo!()
}

fn compute_l1_handler_hash(_txn: L1HandlerTransaction) -> ComputedTransactionHash {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::compute_transaction_hash;
    use crate::reply::Transaction;
    use starknet_gateway_test_fixtures::{v0_11_0, v0_8_2, v0_9_0};

    #[test]
    fn success() {
        let declare_v0_231579 =
            serde_json::from_str::<Transaction>(v0_9_0::transaction::DECLARE).unwrap();
        let declare_v1_463319 =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::declare::v1::BLOCK_463319)
                .unwrap();
        let declare_v1_797215 =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::declare::v1::BLOCK_797215)
                .unwrap();
        let declare_v2_797220 =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::declare::v2::BLOCK_797220)
                .unwrap();
        let deploy_v0_231579 =
            serde_json::from_str::<Transaction>(v0_9_0::transaction::DEPLOY).unwrap();
        let deploy_account_v1_375919 = serde_json::from_str::<Transaction>(
            v0_11_0::transaction::deploy_account::v1::BLOCK_375919,
        )
        .unwrap();
        let deploy_account_v1_797k = serde_json::from_str::<Transaction>(
            v0_11_0::transaction::deploy_account::v1::BLOCK_797K,
        )
        .unwrap();
        let invoke_v0_genesis =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::invoke::v0::GENESIS).unwrap();
        let invoke_v0_21520 =
            serde_json::from_str::<Transaction>(v0_8_2::transaction::INVOKE).unwrap();
        let invoke_v0_231579 =
            serde_json::from_str::<Transaction>(v0_9_0::transaction::INVOKE).unwrap();
        let invoke_v1_420k =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::invoke::v1::BLOCK_420K)
                .unwrap();
        let invoke_v1_790k =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::invoke::v1::BLOCK_790K)
                .unwrap();
        let l1_handler_v0_1564 =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::l1_handler::v0::BLOCK_1564)
                .unwrap();
        let l1_handler_v0_790k =
            serde_json::from_str::<Transaction>(v0_11_0::transaction::l1_handler::v0::BLOCK_790K)
                .unwrap();

        [
            declare_v0_231579,
            declare_v1_463319,
            declare_v1_797215,
            declare_v2_797220,
            deploy_v0_231579,
            deploy_account_v1_375919,
            deploy_account_v1_797k,
            invoke_v0_genesis,
            invoke_v0_21520,
            invoke_v0_231579,
            invoke_v1_420k,
            invoke_v1_790k,
            l1_handler_v0_1564,
            l1_handler_v0_790k,
        ]
        .into_iter()
        .for_each(|txn| {
            let txn = txn.transaction.unwrap();
            eprintln!("{}", txn.hash());
            assert_eq!(compute_transaction_hash(txn.clone()).hash(), txn.hash())
        })
    }
}
