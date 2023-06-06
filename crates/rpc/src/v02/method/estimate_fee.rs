use crate::context::RpcContext;
use crate::v02::types::{reply::FeeEstimate, request::BroadcastedTransaction};
use crate::v03::method::common::prepare_handle_and_block;
use pathfinder_common::BlockId;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateFeeInput {
    request: BroadcastedTransaction,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError,
    InvalidMessageSelector,
    InvalidCallData
);

impl From<crate::cairo::ext_py::CallFailure> for EstimateFeeError {
    fn from(c: crate::cairo::ext_py::CallFailure) -> Self {
        use crate::cairo::ext_py::CallFailure::*;
        match c {
            NoSuchBlock => Self::BlockNotFound,
            NoSuchContract => Self::ContractNotFound,
            InvalidEntryPoint => Self::InvalidMessageSelector,
            ExecutionFailed(e) => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
            // Intentionally hide the message under Internal
            Internal(_) | Shutdown => Self::Internal(anyhow::anyhow!("Internal error")),
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<FeeEstimate, EstimateFeeError> {
    let (handle, gas_price, when, pending_timestamp, pending_update) =
        prepare_handle_and_block(&context, input.block_id).await?;

    let mut result = handle
        .estimate_fee(
            vec![input.request],
            when,
            gas_price,
            pending_update,
            pending_timestamp,
        )
        .await?;

    if result.len() != 1 {
        return Err(
            anyhow::anyhow!("Internal error: expected exactly one fee estimation result").into(),
        );
    }

    let result = result.pop().unwrap();

    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransaction;
    use pathfinder_common::{
        felt, BlockHash, CallParam, Chain, ContractAddress, Fee, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_storage::JournalMode;
    use std::path::PathBuf;

    mod parsing {
        use super::*;

        fn test_invoke_txn() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                crate::v02::types::request::BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(felt!("0x6")),
                    signature: vec![TransactionSignatureElem(felt!("0x7"))],
                    nonce: TransactionNonce(felt!("0x8")),
                    sender_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                    calldata: vec![CallParam(felt!("0xff"))],
                },
            ))
        }

        #[test]
        fn positional_args() {
            use jsonrpsee::types::Params;

            let positional = r#"[
                {
                    "type": "INVOKE",
                    "version": "0x100000000000000000000000000000001",
                    "max_fee": "0x6",
                    "signature": [
                        "0x7"
                    ],
                    "nonce": "0x8",
                    "sender_address": "0xaaa",
                    "calldata": [
                        "0xff"
                    ]
                },
                { "block_hash": "0xabcde" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: test_invoke_txn(),
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named_args = r#"{
                "request": {
                    "type": "INVOKE",
                    "version": "0x100000000000000000000000000000001",
                    "max_fee": "0x6",
                    "signature": [
                        "0x7"
                    ],
                    "nonce": "0x8",
                    "sender_address": "0xaaa",
                    "calldata": [
                        "0xff"
                    ]
                },
                "block_id": { "block_hash": "0xabcde" }
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: test_invoke_txn(),
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    // These tests require a Python environment properly set up _and_ a mainnet database with the first six blocks.
    pub(crate) mod ext_py {
        use std::sync::Arc;

        use super::*;
        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV1,
            BroadcastedDeclareTransactionV2, BroadcastedInvokeTransactionV1,
        };
        use crate::v02::types::{ContractClass, SierraContractClass};
        use pathfinder_common::{
            felt_bytes, BlockNumber, BlockTimestamp, CasmHash, ClassCommitment, ContractNonce,
            ContractRoot, GasPrice, SequencerAddress, StarknetVersion, StateCommitment,
        };
        use pathfinder_storage::types::state_update::{DeployedContract, StateDiff};
        use pathfinder_storage::{
            insert_canonical_state_diff, StarknetBlock, StarknetBlocksTable, Storage,
        };
        use stark_hash::Felt;

        // Mainnet block number 5
        pub(crate) const BLOCK_5: BlockId = BlockId::Hash(BlockHash(felt!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        )));

        pub(crate) fn valid_invoke_v1(account_address: ContractAddress) -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(Default::default()),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    sender_address: account_address,
                    calldata: vec![
                        // Transaction data taken from:
                        // https://alpha-mainnet.starknet.io/feeder_gateway/get_transaction?transactionHash=0x000c52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5
                        //
                        // Structure of "outer" calldata (BroadcastedInvokeTransactionV1::calldata) is based on:
                        //
                        // https://github.com/OpenZeppelin/cairo-contracts/blob/4dd04250c55ae8a5bbcb72663c989bb204e8d998/src/openzeppelin/account/IAccount.cairo#L30
                        //
                        // func __execute__(
                        //     call_array_len: felt,          // <-- number of contract calls passed through this account in this transaction (here: 1)
                        //     call_array: AccountCallArray*, // <-- metadata for each passed contract call
                        //     calldata_len: felt,            // <-- unused
                        //     calldata: felt*                // <-- this entire "outer" vector (BroadcastedInvokeTransactionV1::calldata)
                        // )
                        //
                        // Metadata for each contract call passed through the account
                        //
                        // https://github.com/OpenZeppelin/cairo-contracts/blob/4dd04250c55ae8a5bbcb72663c989bb204e8d998/src/openzeppelin/account/library.cairo#L52
                        //
                        // struct AccountCallArray {
                        //     to: felt,            // The address of the contract that is being called
                        //     selector: felt,      // Entry point selector for the contract function called
                        //     data_offset: felt,   // Offset in the "outer" calldata (BroadcastedInvokeTransactionV1::calldata) to the next contract's calldata
                        //     data_len: felt,      // Size of the calldata for this contract function call
                        // }
                        //
                        // To see how the above structure is translated to a proper calldata for a single call instance see
                        // a "preset" implementation of IAccount
                        // https://github.com/OpenZeppelin/cairo-contracts/blob/4dd04250c55ae8a5bbcb72663c989bb204e8d998/src/openzeppelin/account/presets/Account.cairo#L128
                        // https://github.com/OpenZeppelin/cairo-contracts/blob/main/src/openzeppelin/account/library.cairo#L239
                        //
                        // especially
                        //
                        // func _from_call_array_to_call{syscall_ptr: felt*}(
                        //     call_array_len: felt, call_array: AccountCallArray*, calldata: felt*, calls: Call*
                        // )
                        //
                        // Called contract address, i.e. AccountCallArray::to
                        CallParam(felt!(
                            "05a02acdbf218464be3dd787df7a302f71fab586cad5588410ba88b3ed7b3a21"
                        )),
                        // Entry point selector for the called contract, i.e. AccountCallArray::selector
                        CallParam(felt!(
                            "03d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3"
                        )),
                        // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                        CallParam(felt!("2")),
                        // Proper calldata for this contract
                        CallParam(felt!(
                            "e150b6c2db6ed644483b01685571de46d2045f267d437632b508c19f3eb877"
                        )),
                        CallParam(felt!(
                            "0494196e88ce16bff11180d59f3c75e4ba3475d9fba76249ab5f044bcd25add6"
                        )),
                    ],
                },
            ))
        }

        pub(crate) fn test_storage_with_account() -> (
            tempfile::TempDir,
            Storage,
            ContractAddress,
            BlockHash,
            BlockNumber,
        ) {
            let mut source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            source_path.push("fixtures/mainnet.sqlite");

            let db_dir = tempfile::TempDir::new().unwrap();
            let mut db_path = PathBuf::from(db_dir.path());
            db_path.push("mainnet.sqlite");

            std::fs::copy(&source_path, &db_path).unwrap();

            let storage = pathfinder_storage::Storage::migrate(db_path, JournalMode::WAL).unwrap();

            let (account_address, latest_block_hash, latest_block_number) =
                add_dummy_account(storage.clone());

            (
                db_dir,
                storage,
                account_address,
                latest_block_hash,
                latest_block_number,
            )
        }

        pub(crate) async fn test_context_with_call_handling() -> (
            tempfile::TempDir,
            RpcContext,
            tokio::task::JoinHandle<()>,
            ContractAddress,
            BlockHash,
        ) {
            use pathfinder_common::ChainId;

            let (db_dir, storage, account_address, latest_block_hash, _) =
                test_storage_with_account();

            let sync_state = Arc::new(crate::SyncState::default());
            let (call_handle, cairo_handle) = crate::cairo::ext_py::start(
                storage.path().into(),
                std::num::NonZeroUsize::try_from(2).unwrap(),
                futures::future::pending(),
                Chain::Mainnet,
            )
            .await
            .unwrap();

            let sequencer = starknet_gateway_client::Client::new(Chain::Mainnet).unwrap();
            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);
            (
                db_dir,
                context.with_call_handling(call_handle),
                cairo_handle,
                account_address,
                latest_block_hash,
            )
        }

        fn add_dummy_account(
            storage: pathfinder_storage::Storage,
        ) -> (ContractAddress, BlockHash, BlockNumber) {
            let mut db_conn = storage.connection().unwrap();
            let db_txn = db_conn.transaction().unwrap();

            //
            // "Declare"
            //
            let class_hash =
                starknet_gateway_test_fixtures::class_definitions::DUMMY_ACCOUNT_CLASS_HASH;
            let class_definition = starknet_gateway_test_fixtures::class_definitions::DUMMY_ACCOUNT;

            pathfinder_storage::ClassDefinitionsTable::insert(
                &db_txn,
                class_hash,
                class_definition,
            )
            .unwrap();

            //
            // "Deploy"
            //
            let contract_address = ContractAddress::new_or_panic(felt_bytes!(b"account"));
            let contract_root = ContractRoot::ZERO;
            let contract_nonce = ContractNonce::ZERO;
            let contract_state_hash =
                pathfinder_merkle_tree::contract_state::calculate_contract_state_hash(
                    class_hash,
                    contract_root,
                    contract_nonce,
                );

            pathfinder_storage::ContractsStateTable::upsert(
                &db_txn,
                contract_state_hash,
                class_hash,
                contract_root,
                contract_nonce,
            )
            .unwrap();

            let storage_commitment = StarknetBlocksTable::get_storage_commitment(
                &db_txn,
                pathfinder_storage::StarknetBlocksBlockId::Latest,
            )
            .unwrap()
            .unwrap();

            let latest_block_number = StarknetBlocksTable::get_latest_number(&db_txn)
                .unwrap()
                .unwrap();

            let mut storage_commitment_tree =
                pathfinder_merkle_tree::StorageCommitmentTree::load(&db_txn, storage_commitment);

            storage_commitment_tree
                .set(contract_address, contract_state_hash)
                .unwrap();

            let new_storage_commitment = storage_commitment_tree
                .commit_and_persist_changes()
                .unwrap();

            let new_block = StarknetBlock {
                number: latest_block_number + 1,
                hash: BlockHash(felt_bytes!(b"latest block")),
                state_commmitment: StateCommitment::calculate(
                    new_storage_commitment,
                    ClassCommitment::ZERO,
                ),
                timestamp: BlockTimestamp::new_or_panic(0),
                gas_price: GasPrice::ZERO,
                sequencer_address: SequencerAddress(Felt::ZERO),
                transaction_commitment: None,
                event_commitment: None,
            };

            pathfinder_storage::StarknetBlocksTable::insert(
                &db_txn,
                &new_block,
                &StarknetVersion::default(),
                new_storage_commitment,
                ClassCommitment::ZERO,
            )
            .unwrap();

            pathfinder_storage::CanonicalBlocksTable::insert(
                &db_txn,
                new_block.number,
                new_block.hash,
            )
            .unwrap();

            let state_diff = StateDiff {
                storage_diffs: vec![],
                declared_contracts: vec![],
                deployed_contracts: vec![DeployedContract {
                    address: contract_address,
                    class_hash,
                }],
                nonces: vec![],
                declared_sierra_classes: vec![],
                replaced_classes: vec![],
            };

            insert_canonical_state_diff(&db_txn, new_block.number, &state_diff).unwrap();

            // Persist
            db_txn.commit().unwrap();

            (contract_address, new_block.hash, new_block.number)
        }

        #[tokio::test]
        async fn no_such_block() {
            let (_db_dir, context, _join_handle, account_address, _) =
                test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: valid_invoke_v1(account_address),
                block_id: BlockId::Hash(BlockHash(felt_bytes!(b"nonexistent"))),
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (_db_dir, context, _join_handle, account_address, _) =
                test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        sender_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
                        ..valid_invoke_v1(account_address)
                            .into_invoke()
                            .unwrap()
                            .into_v1()
                            .unwrap()
                    },
                )),
                block_id: BLOCK_5,
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::ContractNotFound));
        }

        #[tokio::test]
        async fn successful_invoke_v1() {
            let (_db_dir, context, _join_handle, account_address, latest_block_hash) =
                test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: valid_invoke_v1(account_address),
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(result, FeeEstimate::default(),);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v1() {
            let (_db_dir, context, _join_handle, account_address, latest_block_hash) =
                test_context_with_call_handling().await;

            let contract_class = {
                let json = starknet_gateway_test_fixtures::class_definitions::CONTRACT_DEFINITION;
                ContractClass::from_definition_bytes(json)
                    .unwrap()
                    .as_cairo()
                    .unwrap()
            };

            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V1(BroadcastedDeclareTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(Default::default()),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class,
                    sender_address: account_address,
                }),
            );

            let input = EstimateFeeInput {
                request: declare_transaction,
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(result, FeeEstimate::default(),);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v2() {
            let (_db_dir, context, _join_handle, account_address, latest_block_hash) =
                test_context_with_call_handling().await;

            let contract_class: SierraContractClass = {
                let definition =
                    starknet_gateway_test_fixtures::class_definitions::CAIRO_1_1_0_RC0_SIERRA;
                ContractClass::from_definition_bytes(definition)
                    .unwrap()
                    .as_sierra()
                    .unwrap()
            };

            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V2(BroadcastedDeclareTransactionV2 {
                    version: TransactionVersion::TWO_WITH_QUERY_VERSION,
                    max_fee: Fee(Default::default()),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class,
                    sender_address: account_address,
                    // Taken from
                    // https://external.integration.starknet.io/feeder_gateway/get_state_update?blockNumber=289143
                    compiled_class_hash: CasmHash::new_or_panic(felt!(
                        "0xf2056a217cc9cabef54d4b1bceea5a3e8625457cb393698ba507259ed6f3c"
                    )),
                }),
            );

            let input = EstimateFeeInput {
                request: declare_transaction,
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(result, FeeEstimate::default(),);
        }
    }
}
