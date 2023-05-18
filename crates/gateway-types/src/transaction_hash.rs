//! Calculate transaction hashes.

use crate::reply::transaction::{
    DeclareTransaction, DeclareTransactionV0V1, DeclareTransactionV2, DeployAccountTransaction,
    DeployTransaction, InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1,
    L1HandlerTransaction, Transaction,
};
use pathfinder_common::{
    BlockNumber, CasmHash, ClassHash, ContractAddress, EntryPoint, Fee, TransactionHash,
    TransactionNonce, TransactionVersion,
};

use crate::class_hash::truncated_keccak;
use pathfinder_common::ChainId;
use sha3::{Digest, Keccak256};
use stark_hash::{Felt, HashChain};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum VerifyResult {
    Match,
    Mismatch(TransactionHash),
    NotVerifiable,
}

pub fn verify(txn: &Transaction, chain_id: ChainId, block_number: BlockNumber) -> VerifyResult {
    let chain_id = match chain_id {
        // We don't know how to properly compute hashes of some old L1 Handler transactions
        // Worse still those are invokes in old snapshots but currently are served as
        // L1 handler txns.
        ChainId::MAINNET => {
            if block_number.get() <= 4399 && matches!(txn, Transaction::L1Handler(_)) {
                // Unable to compute, skipping
                return VerifyResult::NotVerifiable;
            } else {
                chain_id
            }
        }
        ChainId::TESTNET => {
            if block_number.get() <= 306007 && matches!(txn, Transaction::L1Handler(_)) {
                // Unable to compute, skipping
                return VerifyResult::NotVerifiable;
            } else {
                chain_id
            }
        }
        // Earlier blocks on testnet2 used the same chain id as testnet (ie. goerli)
        ChainId::TESTNET2 => {
            if block_number.get() <= 21086 {
                ChainId::TESTNET
            } else {
                chain_id
            }
        }
        _ => chain_id,
    };

    let computed_hash = compute_transaction_hash(txn, chain_id);

    if computed_hash == txn.hash() {
        VerifyResult::Match
    } else {
        VerifyResult::Mismatch(computed_hash)
    }
}

/// Computes transaction hash according to the formulas from [starknet docs](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/).
///
/// ## Important
///
/// For __Invoke v0__, __Deploy__ and __L1 Handler__ there is a fallback hash calculation
/// algorithm used in case a hash mismatch is encountered and the fallback's result becomes
/// the ultimate result of the computation.
pub fn compute_transaction_hash(txn: &Transaction, chain_id: ChainId) -> TransactionHash {
    match txn {
        Transaction::Declare(DeclareTransaction::V0(txn)) => compute_declare_v0_hash(txn, chain_id),
        Transaction::Declare(DeclareTransaction::V1(txn)) => compute_declare_v1_hash(txn, chain_id),
        Transaction::Declare(DeclareTransaction::V2(txn)) => compute_declare_v2_hash(txn, chain_id),
        Transaction::Deploy(txn) => compute_deploy_hash(txn, chain_id),
        Transaction::DeployAccount(txn) => compute_deploy_account_hash(txn, chain_id),
        Transaction::Invoke(InvokeTransaction::V0(txn)) => compute_invoke_v0_hash(txn, chain_id),
        Transaction::Invoke(InvokeTransaction::V1(txn)) => compute_invoke_v1_hash(txn, chain_id),
        Transaction::L1Handler(txn) => compute_l1_handler_hash(txn, chain_id),
    }
}

/// Computes declare v0 transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#v0_hash_calculation_2):
/// ```text=
/// declare_v0_tx_hash = h("declare", version, sender_address,
///     0, h([]), max_fee, chain_id, class_hash)
/// ```
///
/// FIXME: SW should fix the formula in the docs
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
fn compute_declare_v0_hash(txn: &DeclareTransactionV0V1, chain_id: ChainId) -> TransactionHash {
    compute_txn_hash(
        b"declare",
        TransactionVersion::ZERO,
        txn.sender_address,
        None,
        HashChain::default().finalize(), // Hash of an empty Felt list
        None,
        chain_id,
        txn.class_hash,
        None,
    )
}

/// Computes declare v1 transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#v1_hash_calculation_2):
/// ```text=
/// declare_v1_tx_hash = h("declare", version, sender_address,
///     0, h([class_hash]), max_fee, chain_id, nonce)
/// ```
///
/// FIXME: SW should fix the formula in the docs
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
fn compute_declare_v1_hash(txn: &DeclareTransactionV0V1, chain_id: ChainId) -> TransactionHash {
    compute_txn_hash(
        b"declare",
        TransactionVersion::ONE,
        txn.sender_address,
        None,
        {
            let mut h = HashChain::default();
            h.update(txn.class_hash.0);
            h.finalize()
        },
        Some(txn.max_fee),
        chain_id,
        txn.nonce,
        None,
    )
}

/// Computes declare v2 transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#v2_hash_calculation):
/// ```text=
/// declare_v2_tx_hash = h("declare", version, sender_address,
///     0, h([class_hash]), max_fee, chain_id, nonce, compiled_class_hash)
/// ```
///
/// FIXME: SW should fix the formula in the docs
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
fn compute_declare_v2_hash(txn: &DeclareTransactionV2, chain_id: ChainId) -> TransactionHash {
    compute_txn_hash(
        b"declare",
        TransactionVersion::TWO,
        txn.sender_address,
        None,
        {
            let mut h = HashChain::default();
            h.update(txn.class_hash.0);
            h.finalize()
        },
        Some(txn.max_fee),
        chain_id,
        txn.nonce,
        Some(txn.compiled_class_hash),
    )
}

/// Computes deploy transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#deploy_transaction):
/// ```text=
/// deploy_tx_hash = h(
///     "deploy", version, contract_address, sn_keccak("constructor"),
///     h(constructor_calldata), 0, chain_id)
/// ```
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash), and `sn_keccak` is [Starknet Keccak](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#Starknet-keccak)
fn compute_deploy_hash(txn: &DeployTransaction, chain_id: ChainId) -> TransactionHash {
    lazy_static::lazy_static!(
        static ref CONSTRUCTOR: EntryPoint = {
            let mut keccak = Keccak256::default();
            keccak.update(b"constructor");
            EntryPoint(truncated_keccak(<[u8; 32]>::from(keccak.finalize())))};
    );

    let constructor_params_hash = {
        let hh = txn.constructor_calldata.iter().fold(
            HashChain::default(),
            |mut hh, constructor_param| {
                hh.update(constructor_param.0);
                hh
            },
        );
        hh.finalize()
    };

    let h = compute_txn_hash(
        b"deploy",
        txn.version,
        txn.contract_address,
        Some(*CONSTRUCTOR),
        constructor_params_hash,
        None,
        chain_id,
        (),
        None,
    );

    if h == txn.transaction_hash {
        h
    } else {
        legacy_compute_txn_hash(
            b"deploy",
            txn.contract_address,
            Some(*CONSTRUCTOR),
            constructor_params_hash,
            chain_id,
        )
    }
}

/// Computes deploy account transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#deploy_account_hash_calculation):
/// ```text=
/// deploy_account_tx_hash = h(
///     "deploy_account", version, contract_address, 0,
///     h(class_hash, contract_address_salt, constructor_calldata),
///     max_fee, chain_id, nonce)
/// ```
///
/// FIXME: SW should fix the formula in the docs
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
fn compute_deploy_account_hash(
    txn: &DeployAccountTransaction,
    chain_id: ChainId,
) -> TransactionHash {
    compute_txn_hash(
        b"deploy_account",
        txn.version,
        txn.contract_address,
        None,
        {
            let mut hh = HashChain::default();
            hh.update(txn.class_hash.0);
            hh.update(txn.contract_address_salt.0);
            hh = txn
                .constructor_calldata
                .iter()
                .fold(hh, |mut hh, constructor_param| {
                    hh.update(constructor_param.0);
                    hh
                });
            hh.finalize()
        },
        Some(txn.max_fee),
        chain_id,
        txn.nonce,
        None,
    )
}

/// Computes invoke v0 account transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#v0_hash_calculation):
/// ```text=
/// invoke_v0_tx_hash = h("invoke", version, sender_address,
///     entry_point_selector, h(calldata), max_fee, chain_id)
/// ```
///
/// FIXME: SW should fix the formula in the docs
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
fn compute_invoke_v0_hash(txn: &InvokeTransactionV0, chain_id: ChainId) -> TransactionHash {
    let call_params_hash = {
        let mut hh = HashChain::default();
        hh = txn.calldata.iter().fold(hh, |mut hh, call_param| {
            hh.update(call_param.0);
            hh
        });
        hh.finalize()
    };

    let h = compute_txn_hash(
        b"invoke",
        TransactionVersion::ZERO,
        txn.sender_address,
        Some(txn.entry_point_selector),
        call_params_hash,
        Some(txn.max_fee),
        chain_id,
        (),
        None,
    );

    if h == txn.transaction_hash {
        h
    } else {
        legacy_compute_txn_hash(
            b"invoke",
            txn.sender_address,
            Some(txn.entry_point_selector),
            call_params_hash,
            chain_id,
        )
    }
}

/// Computes invoke v1 transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#v1_hash_calculation):
/// ```text=
/// invoke_v1_tx_hash = h("invoke", version, sender_address,
///     0, h(calldata), max_fee, chain_id, nonce)
/// ```
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
fn compute_invoke_v1_hash(txn: &InvokeTransactionV1, chain_id: ChainId) -> TransactionHash {
    compute_txn_hash(
        b"invoke",
        TransactionVersion::ONE,
        txn.sender_address,
        None,
        {
            let mut hh = HashChain::default();
            hh = txn.calldata.iter().fold(hh, |mut hh, call_param| {
                hh.update(call_param.0);
                hh
            });
            hh.finalize()
        },
        Some(txn.max_fee),
        chain_id,
        txn.nonce,
        None,
    )
}

/// Computes l1 handler transaction hash based on [this formula](https://docs.starknet.io/documentation/architecture_and_concepts/L1-L2_Communication/messaging-mechanism/#structure_and_hashing_l1-l2):
/// ```text=
/// l1_handler_tx_hash = h("l1_handler", version, contract_address,
///     entry_point_selector, h(calldata), 0, chain_id, nonce)
/// ```
///
/// FIXME: SW should fix the formula in the docs
///
/// Where `h` is [Pedersen hash](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#pedersen_hash)
///
/// ## Important
///
/// Guarantees correct computation for Starknet **0.9.1** transactions onwards
fn compute_l1_handler_hash(txn: &L1HandlerTransaction, chain_id: ChainId) -> TransactionHash {
    let call_params_hash = {
        let mut hh = HashChain::default();
        hh = txn.calldata.iter().fold(hh, |mut hh, call_param| {
            hh.update(call_param.0);
            hh
        });
        hh.finalize()
    };

    let h = compute_txn_hash(
        b"l1_handler",
        txn.version,
        txn.contract_address,
        Some(txn.entry_point_selector),
        call_params_hash,
        None,
        chain_id,
        txn.nonce,
        None,
    );

    if h == txn.transaction_hash {
        h
    } else {
        legacy_compute_txn_hash(
            // Oldest L1 Handler transactions were actually Invokes
            // which later on were "renamed" to be the former,
            // yet the hashes remain, hence the prefix
            b"invoke",
            txn.contract_address,
            Some(txn.entry_point_selector),
            call_params_hash,
            chain_id,
        )
    }
}

#[derive(Copy, Clone, Debug)]
enum NonceOrClassHash {
    Nonce(TransactionNonce),
    ClassHash(ClassHash),
    None,
}

impl From<TransactionNonce> for NonceOrClassHash {
    fn from(n: TransactionNonce) -> Self {
        Self::Nonce(n)
    }
}

impl From<ClassHash> for NonceOrClassHash {
    fn from(c: ClassHash) -> Self {
        Self::ClassHash(c)
    }
}

impl From<()> for NonceOrClassHash {
    fn from(_: ()) -> Self {
        Self::None
    }
}

/// _Generic_ compute transaction hash for older transactions (pre 0.8-ish)
fn legacy_compute_txn_hash(
    prefix: &[u8],
    address: ContractAddress,
    entry_point_selector: Option<EntryPoint>,
    list_hash: Felt,
    chain_id: ChainId,
) -> TransactionHash {
    let mut h = HashChain::default();
    h.update(Felt::from_be_slice(prefix).expect("prefix is convertible"));
    h.update(*address.get());
    h.update(entry_point_selector.map(|e| e.0).unwrap_or(Felt::ZERO));
    h.update(list_hash);
    h.update(chain_id.0);

    TransactionHash(h.finalize())
}

/// _Generic_ compute transaction hash for transactions
#[allow(clippy::too_many_arguments)]
fn compute_txn_hash(
    prefix: &[u8],
    version: TransactionVersion,
    address: ContractAddress,
    entry_point_selector: Option<EntryPoint>,
    list_hash: Felt,
    max_fee: Option<Fee>,
    chain_id: ChainId,
    nonce_or_class_hash: impl Into<NonceOrClassHash>,
    compiled_class_hash: Option<CasmHash>,
) -> TransactionHash {
    let mut h = HashChain::default();
    h.update(Felt::from_be_slice(prefix).expect("prefix is convertible"));
    h.update(Felt::from_be_slice(version.0.as_bytes()).expect("version is convertible"));
    h.update(*address.get());
    h.update(entry_point_selector.map(|e| e.0).unwrap_or(Felt::ZERO));
    h.update(list_hash);
    h.update(max_fee.map(|e| e.0).unwrap_or(Felt::ZERO));
    h.update(chain_id.0);

    match nonce_or_class_hash.into() {
        NonceOrClassHash::Nonce(nonce) => h.update(nonce.0),
        NonceOrClassHash::ClassHash(class_hash) => h.update(class_hash.0),
        NonceOrClassHash::None => {}
    }

    if let Some(compiled_class_hash) = compiled_class_hash {
        h.update(compiled_class_hash.0);
    }

    TransactionHash(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::compute_transaction_hash;
    use pathfinder_common::ChainId;
    use starknet_gateway_test_fixtures::{v0_11_0, v0_8_2, v0_9_0};

    macro_rules! case {
        ($target:expr) => {{
            let line = line!();

            (
                serde_json::from_str::<crate::reply::Transaction>($target)
                    .expect(&format!("deserialization is Ok, line: {line}"))
                    .transaction
                    .expect(&format!("transaction is Some, line: {line}")),
                line,
            )
        }};
    }

    #[test]
    fn computation() {
        // At the beginning testnet2 used chain id of testnet for hash calculation
        let testnet2_with_wrong_chain_id =
            serde_json::from_str(v0_11_0::transaction::deploy::v1::GENESIS_TESTNET2).unwrap();
        assert_eq!(
            compute_transaction_hash(&testnet2_with_wrong_chain_id, ChainId::TESTNET),
            testnet2_with_wrong_chain_id.hash()
        );

        [
            // Declare
            case!(v0_9_0::transaction::DECLARE), // v0
            case!(v0_11_0::transaction::declare::v1::BLOCK_463319),
            case!(v0_11_0::transaction::declare::v1::BLOCK_797215),
            case!(v0_11_0::transaction::declare::v2::BLOCK_797220),
            // Deploy
            case!(v0_11_0::transaction::deploy::v0::GENESIS),
            case!(v0_9_0::transaction::DEPLOY), // v0
            case!(v0_11_0::transaction::deploy::v1::BLOCK_485004),
            // Deploy account
            case!(v0_11_0::transaction::deploy_account::v1::BLOCK_375919),
            case!(v0_11_0::transaction::deploy_account::v1::BLOCK_797K),
            // Invoke
            case!(v0_11_0::transaction::invoke::v0::GENESIS),
            case!(v0_8_2::transaction::INVOKE),
            case!(v0_9_0::transaction::INVOKE),
            case!(v0_11_0::transaction::invoke::v1::BLOCK_420K),
            case!(v0_11_0::transaction::invoke::v1::BLOCK_790K),
            // L1 Handler
            case!(v0_11_0::transaction::l1_handler::v0::BLOCK_1564),
            case!(v0_11_0::transaction::l1_handler::v0::BLOCK_272866),
            case!(v0_11_0::transaction::l1_handler::v0::BLOCK_790K),
        ]
        .iter()
        .for_each(|(txn, line)| {
            let actual_hash = compute_transaction_hash(txn, ChainId::TESTNET);
            assert_eq!(actual_hash, txn.hash(), "line: {line}");
        });
    }

    mod verification {
        use crate::transaction_hash::{verify, VerifyResult};
        use pathfinder_common::{BlockNumber, ChainId};

        mod skipped {
            use crate::transaction_hash::{verify, VerifyResult};
            use pathfinder_common::{BlockNumber, ChainId};
            use starknet_gateway_test_fixtures::v0_11_0;

            #[test]
            fn rewritten_old_l1_handler() {
                let block_854_idx_96 =
                    serde_json::from_str(v0_11_0::transaction::l1_handler::v0::BLOCK_854_IDX_96)
                        .unwrap();

                assert_eq!(
                    verify(
                        &block_854_idx_96,
                        ChainId::TESTNET,
                        BlockNumber::new_or_panic(854),
                    ),
                    VerifyResult::NotVerifiable
                );
            }

            #[test]
            fn old_l1_handler_in_invoke_v0() {
                let block_854_idx_96 =
                    serde_json::from_str(v0_11_0::transaction::invoke::v0::BLOCK_854_IDX_96)
                        .unwrap();

                assert_eq!(
                    verify(
                        &block_854_idx_96,
                        ChainId::TESTNET,
                        BlockNumber::new_or_panic(854),
                    ),
                    VerifyResult::NotVerifiable
                );
            }
        }

        #[test]
        fn ok() {
            let (txn, _) = case!(super::v0_11_0::transaction::declare::v2::BLOCK_797220);

            assert_eq!(
                verify(&txn, ChainId::TESTNET, BlockNumber::new_or_panic(797220),),
                VerifyResult::Match
            );
        }

        #[test]
        fn failed() {
            let (txn, _) = case!(super::v0_11_0::transaction::declare::v2::BLOCK_797220);
            // Wrong chain id to force failure
            assert!(matches!(
                verify(&txn, ChainId::MAINNET, BlockNumber::new_or_panic(797220),),
                VerifyResult::Mismatch(_)
            ))
        }
    }
}
