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
    use crate::reply::transaction::Transaction;
    use starknet_gateway_test_fixtures::{v0_8_2, v0_9_0};

    #[test]
    fn success() {
        let declare_v0 = serde_json::from_str::<Transaction>(v0_9_0::transaction::DECLARE).unwrap();
        let deploy_v0 = serde_json::from_str::<Transaction>(v0_9_0::transaction::DEPLOY).unwrap();
        let invoke_v0_starknet_v0_8 =
            serde_json::from_str::<Transaction>(v0_8_2::transaction::INVOKE).unwrap();
        let invoke_v0_starknet_v0_9 =
            serde_json::from_str::<Transaction>(v0_9_0::transaction::INVOKE).unwrap();

        [
            declare_v0,
            deploy_v0,
            invoke_v0_starknet_v0_8,
            invoke_v0_starknet_v0_9,
        ]
        .into_iter()
        .for_each(|txn| assert_eq!(compute_transaction_hash(txn.clone()).hash(), txn.hash()))
    }
}
