//! Calculate transaction hashes.

use crate::reply::transaction::{
    DeclareTransaction, DeclareTransactionV0V1, DeclareTransactionV2, DeployAccountTransaction,
    DeployTransaction, InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1,
    L1HandlerTransaction, Transaction,
};
use pathfinder_common::{StarknetTransactionHash, TransactionVersion};

use crate::class_hash::truncated_keccak;
use anyhow::{Context, Result};
use pathfinder_common::{felt_bytes, ChainId};
use sha3::{Digest, Keccak256};
use stark_hash::{Felt, HashChain};

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

/// Computes transaction hash according to the formulas from [starknet docs](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/).
pub fn compute_transaction_hash(
    txn: &Transaction,
    chain_id: ChainId,
) -> Result<ComputedTransactionHash> {
    match txn {
        Transaction::Declare(DeclareTransaction::V0(txn)) => compute_declare_v0_hash(txn, chain_id),
        Transaction::Declare(DeclareTransaction::V1(txn)) => compute_declare_v1_hash(txn),
        Transaction::Declare(DeclareTransaction::V2(txn)) => compute_declare_v2_hash(txn),
        Transaction::Deploy(txn) => compute_deploy_hash(txn, chain_id),
        Transaction::DeployAccount(txn) => compute_deploy_account_hash(txn),
        Transaction::Invoke(InvokeTransaction::V0(txn)) => compute_invoke_v0_hash(txn),
        Transaction::Invoke(InvokeTransaction::V1(txn)) => compute_invoke_v1_hash(txn),
        Transaction::L1Handler(txn) => compute_l1_handler_hash(txn),
    }
}

/// Computes declare v0 transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#v0_hash_calculation_2):
/// ```text=
/// declare_v0_tx_hash = h("declare", version, sender_address,
///     0, h([]), max_fee, chain_id, class_hash)
/// ```
///
/// FIXME Tell SW to fix their formula
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
fn compute_declare_v0_hash(
    txn: &DeclareTransactionV0V1,
    chain_id: ChainId,
) -> Result<ComputedTransactionHash> {
    let mut h = HashChain::default();
    h.update(felt_bytes!(b"declare"));
    h.update(
        Felt::from_be_slice(TransactionVersion::ZERO.0.as_bytes())
            .context("Converting version into Felt")?,
    );
    h.update(*txn.sender_address.get());
    h.update(Felt::ZERO);
    h.update(HashChain::default().finalize());
    h.update(txn.max_fee.0);
    h.update(chain_id.0);
    h.update(txn.class_hash.0);

    Ok(ComputedTransactionHash::Deploy(StarknetTransactionHash(
        h.finalize(),
    )))
}

fn compute_declare_v1_hash(_txn: &DeclareTransactionV0V1) -> Result<ComputedTransactionHash> {
    todo!()
}

fn compute_declare_v2_hash(_txn: &DeclareTransactionV2) -> Result<ComputedTransactionHash> {
    todo!()
}

/// Computes deploy transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#deploy_transaction):
/// ```text=
/// deploy_tx_hash = h(
///     "deploy", version, contract_address, sn_keccak("constructor"),
///     h(constructor_calldata), 0, chain_id)
/// ```
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash), and `sn_keccak` is [Starknet Keccak](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#Starknet-keccak)
fn compute_deploy_hash(
    txn: &DeployTransaction,
    chain_id: ChainId,
) -> Result<ComputedTransactionHash> {
    let mut h = HashChain::default();
    h.update(felt_bytes!(b"deploy"));
    h.update(
        Felt::from_be_slice(txn.version.0.as_bytes()).context("Converting version into Felt")?,
    );
    h.update(*txn.contract_address.get());
    let c = {
        let mut keccak = Keccak256::default();
        keccak.update(b"constructor");
        truncated_keccak(<[u8; 32]>::from(keccak.finalize()))
    };
    h.update(c);
    let cc = {
        let hh = txn.constructor_calldata.iter().fold(
            HashChain::default(),
            |mut hh, constructor_param| {
                hh.update(constructor_param.0);
                hh
            },
        );
        hh.finalize()
    };
    h.update(cc);
    h.update(Felt::ZERO);
    h.update(chain_id.0);

    Ok(ComputedTransactionHash::Deploy(StarknetTransactionHash(
        h.finalize(),
    )))
}

fn compute_deploy_account_hash(_txn: &DeployAccountTransaction) -> Result<ComputedTransactionHash> {
    todo!()
}

fn compute_invoke_v0_hash(_txn: &InvokeTransactionV0) -> Result<ComputedTransactionHash> {
    todo!()
}

fn compute_invoke_v1_hash(_txn: &InvokeTransactionV1) -> Result<ComputedTransactionHash> {
    todo!()
}

fn compute_l1_handler_hash(_txn: &L1HandlerTransaction) -> Result<ComputedTransactionHash> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::compute_transaction_hash;
    use crate::reply::Transaction;
    use pathfinder_common::ChainId;
    use starknet_gateway_test_fixtures::{v0_11_0, v0_8_2, v0_9_0};

    macro_rules! case {
        ($target:expr) => {{
            let line = line!();

            (
                serde_json::from_str::<Transaction>($target)
                    .expect(&format!("deserialization is Ok, line: {line}"))
                    .transaction
                    .expect(&format!("transaction is Some, line: {line}")),
                line,
            )
        }};
    }

    #[test]
    fn success() {
        let declare_v0_231579 = case!(v0_9_0::transaction::DECLARE);
        let declare_v1_463319 = case!(v0_11_0::transaction::declare::v1::BLOCK_463319);
        let declare_v1_797215 = case!(v0_11_0::transaction::declare::v1::BLOCK_797215);
        let declare_v2_797220 = case!(v0_11_0::transaction::declare::v2::BLOCK_797220);
        let deploy_v0_231579 = case!(v0_9_0::transaction::DEPLOY);
        let deploy_account_v1_375919 =
            case!(v0_11_0::transaction::deploy_account::v1::BLOCK_375919);
        let deploy_account_v1_797k = case!(v0_11_0::transaction::deploy_account::v1::BLOCK_797K);
        let invoke_v0_genesis = case!(v0_11_0::transaction::invoke::v0::GENESIS);
        let invoke_v0_21520 = case!(v0_8_2::transaction::INVOKE);
        let invoke_v0_231579 = case!(v0_9_0::transaction::INVOKE);
        let invoke_v1_420k = case!(v0_11_0::transaction::invoke::v1::BLOCK_420K);
        let invoke_v1_790k = case!(v0_11_0::transaction::invoke::v1::BLOCK_790K);
        let l1_handler_v0_1564 = case!(v0_11_0::transaction::l1_handler::v0::BLOCK_1564);
        let l1_handler_v0_790k = case!(v0_11_0::transaction::l1_handler::v0::BLOCK_790K);

        [
            declare_v0_231579,
            // declare_v1_463319,
            // declare_v1_797215,
            // declare_v2_797220,
            deploy_v0_231579,
            // deploy_account_v1_375919,
            // deploy_account_v1_797k,
            // invoke_v0_genesis,
            // invoke_v0_21520,
            // invoke_v0_231579,
            // invoke_v1_420k,
            // invoke_v1_790k,
            // l1_handler_v0_1564,
            // l1_handler_v0_790k,
        ]
        .iter()
        .for_each(|(txn, line)| {
            assert_eq!(
                compute_transaction_hash(txn, ChainId::TESTNET)
                    .expect(&format!("line: {line}"))
                    .hash(),
                txn.hash(),
                "line: {line}"
            )
        })
    }
}
