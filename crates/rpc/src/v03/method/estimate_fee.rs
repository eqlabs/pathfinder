use anyhow::Context;
use serde_with::serde_as;

use crate::{context::RpcContext, v02::types::request::BroadcastedTransaction};
use pathfinder_common::BlockId;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateFeeInput {
    request: Vec<BroadcastedTransaction>,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<pathfinder_executor::CallError> for EstimateFeeError {
    fn from(value: pathfinder_executor::CallError) -> Self {
        use pathfinder_executor::CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::Internal(anyhow::anyhow!("Invalid message selector")),
            Reverted(revert_error) => {
                Self::Internal(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
            Internal(e) => Self::Internal(e),
        }
    }
}

impl From<crate::executor::ExecutionStateError> for EstimateFeeError {
    fn from(error: crate::executor::ExecutionStateError) -> Self {
        use crate::executor::ExecutionStateError::*;
        match error {
            BlockNotFound => Self::BlockNotFound,
            Internal(e) => Self::Internal(e),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct FeeEstimate {
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_consumed: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_price: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub overall_fee: primitive_types::U256,
}

impl From<pathfinder_executor::types::FeeEstimate> for FeeEstimate {
    fn from(value: pathfinder_executor::types::FeeEstimate) -> Self {
        Self {
            gas_consumed: value.gas_consumed,
            gas_price: value.gas_price,
            overall_fee: value.overall_fee,
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<Vec<FeeEstimate>, EstimateFeeError> {
    let chain_id = context.chain_id;

    let execution_state = crate::executor::execution_state(context, input.block_id, None).await?;

    let span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let transactions = input
            .request
            .iter()
            .map(|tx| crate::executor::map_broadcasted_transaction(tx, chain_id))
            .collect::<Result<Vec<_>, _>>()?;

        let result = pathfinder_executor::estimate(execution_state, transactions)?;

        Ok::<_, EstimateFeeError>(result)
    })
    .await
    .context("Executing transaction")??;

    Ok(result.into_iter().map(Into::into).collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransaction;
    use pathfinder_common::{
        felt, BlockHash, CallParam, ContractAddress, Fee, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };
    use stark_hash::Felt;

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
                [
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
                    }
                ],
                { "block_hash": "0xabcde" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named_args = r#"{
                "request": [
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
                    }
                ],
                "block_id": { "block_hash": "0xabcde" }
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(BlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    mod in_memory {
        use std::sync::Arc;

        use super::*;

        use pathfinder_common::{macro_prelude::*, EntryPoint, StorageAddress};

        use pathfinder_common::{
            felt, BlockHash, BlockHeader, BlockNumber, BlockTimestamp, ChainId, ContractAddress,
            GasPrice, StateUpdate,
        };
        use pathfinder_storage::Storage;
        use starknet_gateway_test_fixtures::class_definitions::{
            DUMMY_ACCOUNT, DUMMY_ACCOUNT_CLASS_HASH,
        };

        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV2,
            BroadcastedInvokeTransactionV1,
        };
        use crate::v02::types::{ContractClass, SierraContractClass};

        async fn test_context() -> (RpcContext, BlockHeader, ContractAddress, ContractAddress) {
            let storage = Storage::in_memory().unwrap();
            let mut db = storage.connection().unwrap();
            let tx = db.transaction().unwrap();

            // Empty genesis block
            let header = BlockHeader::builder()
                .with_number(BlockNumber::GENESIS)
                .with_timestamp(BlockTimestamp::new_or_panic(0))
                .finalize_with_hash(BlockHash(felt!("0xb00")));
            tx.insert_block_header(&header).unwrap();

            // Declare & deploy an account class, a universal deployer class and the fee token ERC20 class
            let block1_number = BlockNumber::GENESIS + 1;
            let block1_hash = BlockHash(felt!("0xb01"));

            tx.insert_cairo_class(DUMMY_ACCOUNT_CLASS_HASH, DUMMY_ACCOUNT)
                .unwrap();

            let universal_deployer_definition =
                include_bytes!("../../../fixtures/contracts/universal_deployer.json");
            let universal_deployer_class_hash =
                class_hash!("0x06f38fb91ddbf325a0625533576bb6f6eafd9341868a9ec3faa4b01ce6c4f4dc");

            tx.insert_cairo_class(universal_deployer_class_hash, universal_deployer_definition)
                .unwrap();

            let erc20_class_hash = starknet_gateway_test_fixtures::class_definitions::ERC20_CONTRACT_DEFINITION_CLASS_HASH;
            let erc20_class_definition =
                starknet_gateway_test_fixtures::class_definitions::ERC20_CONTRACT_DEFINITION;

            tx.insert_cairo_class(erc20_class_hash, erc20_class_definition)
                .unwrap();

            let header = BlockHeader::builder()
                .with_number(block1_number)
                .with_timestamp(BlockTimestamp::new_or_panic(1))
                .with_gas_price(GasPrice(1))
                .finalize_with_hash(block1_hash);
            tx.insert_block_header(&header).unwrap();

            let account_contract_address = contract_address!("0xc01");
            let universal_deployer_address = contract_address!("0xc02");

            let account_balance_key = StorageAddress::from_map_name_and_key(
                b"ERC20_balances",
                account_contract_address.0,
            );

            let state_update = StateUpdate::default()
                .with_block_hash(block1_hash)
                .with_declared_cairo_class(DUMMY_ACCOUNT_CLASS_HASH)
                .with_declared_cairo_class(universal_deployer_class_hash)
                .with_declared_cairo_class(erc20_class_hash)
                .with_deployed_contract(account_contract_address, DUMMY_ACCOUNT_CLASS_HASH)
                .with_deployed_contract(universal_deployer_address, universal_deployer_class_hash)
                .with_deployed_contract(pathfinder_executor::FEE_TOKEN_ADDRESS, erc20_class_hash)
                .with_storage_update(
                    pathfinder_executor::FEE_TOKEN_ADDRESS,
                    account_balance_key,
                    storage_value!("0x10000000000000000000000000000"),
                );
            tx.insert_state_update(block1_number, &state_update)
                .unwrap();

            tx.commit().unwrap();

            let sync_state = Arc::new(crate::SyncState::default());
            let sequencer = starknet_gateway_client::Client::mainnet();

            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);

            (
                context,
                header,
                account_contract_address,
                universal_deployer_address,
            )
        }

        #[test_log::test(tokio::test)]
        async fn declare_deploy_and_invoke_sierra_class() {
            let (context, last_block_header, account_contract_address, universal_deployer_address) =
                test_context().await;

            let sierra_definition =
                include_bytes!("../../../fixtures/contracts/storage_access.json");
            let sierra_hash =
                class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
            let casm_hash =
                casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");

            let contract_class: SierraContractClass =
                ContractClass::from_definition_bytes(sierra_definition)
                    .unwrap()
                    .as_sierra()
                    .unwrap();

            assert_eq!(contract_class.class_hash().unwrap().hash(), sierra_hash);

            let max_fee = Fee(Felt::from_u64(10_000_000));

            // declare test class
            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V2(BroadcastedDeclareTransactionV2 {
                    version: TransactionVersion::TWO,
                    max_fee,
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class,
                    sender_address: account_contract_address,
                    compiled_class_hash: casm_hash,
                }),
            );
            // deploy with unversal deployer contract
            let deploy_transaction = BroadcastedTransaction::Invoke(
                BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                    nonce: transaction_nonce!("0x1"),
                    version: TransactionVersion::ONE,
                    max_fee,
                    signature: vec![],
                    sender_address: account_contract_address,
                    calldata: vec![
                        CallParam(*universal_deployer_address.get()),
                        // Entry point selector for the called contract, i.e. AccountCallArray::selector
                        CallParam(EntryPoint::hashed(b"deployContract").0),
                        // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                        call_param!("4"),
                        // classHash
                        CallParam(sierra_hash.0),
                        // salt
                        call_param!("0x0"),
                        // unique
                        call_param!("0x0"),
                        // calldata_len
                        call_param!("0x0"),
                    ],
                }),
            );
            // invoke deployed contract
            let invoke_transaction = BroadcastedTransaction::Invoke(
                BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                    nonce: transaction_nonce!("0x2"),
                    version: TransactionVersion::ONE,
                    max_fee,
                    signature: vec![],
                    sender_address: account_contract_address,
                    calldata: vec![
                        // address of the deployed test contract
                        CallParam(felt!(
                            "0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7"
                        )),
                        // Entry point selector for the called contract, i.e. AccountCallArray::selector
                        CallParam(EntryPoint::hashed(b"get_data").0),
                        // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                        call_param!("0"),
                    ],
                }),
            );

            let input = EstimateFeeInput {
                request: vec![declare_transaction, deploy_transaction, invoke_transaction],
                block_id: BlockId::Number(last_block_header.number),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let declare_expected = FeeEstimate {
                gas_consumed: 3700.into(),
                gas_price: 1.into(),
                overall_fee: 3700.into(),
            };
            let deploy_expected = FeeEstimate {
                gas_consumed: 4337.into(),
                gas_price: 1.into(),
                overall_fee: 4337.into(),
            };
            let invoke_expected = FeeEstimate {
                gas_consumed: 2491.into(),
                gas_price: 1.into(),
                overall_fee: 2491.into(),
            };
            assert_eq!(
                result,
                vec![declare_expected, deploy_expected, invoke_expected]
            );
        }
    }

    // These tests require a mainnet database with the first six blocks.
    pub(crate) mod mainnet {
        use std::num::NonZeroU32;
        use std::path::PathBuf;
        use std::sync::Arc;

        use super::*;

        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV0,
            BroadcastedDeclareTransactionV1, BroadcastedDeclareTransactionV2,
            BroadcastedInvokeTransactionV1,
        };
        use crate::v02::types::{ContractClass, SierraContractClass};
        use pathfinder_common::{felt_bytes, CasmHash, GasPrice, StorageAddress};
        use pathfinder_common::{macro_prelude::*, BlockNumber};
        use pathfinder_storage::{JournalMode, Storage};

        pub(crate) async fn test_context(
        ) -> (tempfile::TempDir, RpcContext, ContractAddress, BlockHash) {
            use pathfinder_common::ChainId;

            let (db_dir, storage, account_address, latest_block_hash, _) =
                test_storage_with_account(GasPrice(1));

            let sync_state = Arc::new(crate::SyncState::default());

            let sequencer = starknet_gateway_client::Client::mainnet();
            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);
            (db_dir, context, account_address, latest_block_hash)
        }

        pub(crate) fn valid_invoke_v1(account_address: ContractAddress) -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: fee!("0x1000000000000000"),
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
                        call_param!(
                            "05a02acdbf218464be3dd787df7a302f71fab586cad5588410ba88b3ed7b3a21"
                        ),
                        // Entry point selector for the called contract, i.e. AccountCallArray::selector
                        call_param!(
                            "03d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3"
                        ),
                        // Length of the call data for the called contract, i.e. AccountCallArray::data_len
                        call_param!("2"),
                        // Proper calldata for this contract
                        call_param!(
                            "e150b6c2db6ed644483b01685571de46d2045f267d437632b508c19f3eb877"
                        ),
                        call_param!(
                            "0494196e88ce16bff11180d59f3c75e4ba3475d9fba76249ab5f044bcd25add6"
                        ),
                    ],
                },
            ))
        }

        pub(crate) fn test_storage_with_account(
            gas_price: GasPrice,
        ) -> (
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

            let storage = pathfinder_storage::Storage::migrate(db_path, JournalMode::WAL)
                .unwrap()
                .create_pool(NonZeroU32::new(1).unwrap())
                .unwrap();

            let (account_address, latest_block_hash, latest_block_number) =
                add_dummy_account(storage.clone(), gas_price);

            (
                db_dir,
                storage,
                account_address,
                latest_block_hash,
                latest_block_number,
            )
        }

        fn add_dummy_account(
            storage: pathfinder_storage::Storage,
            gas_price: GasPrice,
        ) -> (ContractAddress, BlockHash, BlockNumber) {
            let mut db_conn = storage.connection().unwrap();
            let db_txn = db_conn.transaction().unwrap();

            //
            // "Declare"
            //
            let account_class_hash =
                starknet_gateway_test_fixtures::class_definitions::DUMMY_ACCOUNT_CLASS_HASH;
            let account_class_definition =
                starknet_gateway_test_fixtures::class_definitions::DUMMY_ACCOUNT;

            db_txn
                .insert_cairo_class(account_class_hash, account_class_definition)
                .unwrap();

            let erc20_class_hash = starknet_gateway_test_fixtures::class_definitions::ERC20_CONTRACT_DEFINITION_CLASS_HASH;
            let erc20_class_definition =
                starknet_gateway_test_fixtures::class_definitions::ERC20_CONTRACT_DEFINITION;

            db_txn
                .insert_cairo_class(erc20_class_hash, erc20_class_definition)
                .unwrap();

            //
            // "Deploy"
            //
            let account_contract_address = contract_address_bytes!(b"account");

            let latest_header = db_txn
                .block_header(pathfinder_storage::BlockId::Latest)
                .unwrap()
                .unwrap();

            let new_header = latest_header
                .child_builder()
                .with_gas_price(gas_price)
                .with_calculated_state_commitment()
                .finalize_with_hash(block_hash_bytes!(b"latest block"));
            db_txn.insert_block_header(&new_header).unwrap();

            let account_balance_key = StorageAddress::from_map_name_and_key(
                b"ERC20_balances",
                account_contract_address.0,
            );

            let state_update = new_header
                .init_state_update()
                .with_declared_cairo_class(account_class_hash)
                .with_declared_cairo_class(erc20_class_hash)
                .with_deployed_contract(account_contract_address, account_class_hash)
                .with_deployed_contract(pathfinder_executor::FEE_TOKEN_ADDRESS, erc20_class_hash)
                .with_storage_update(
                    pathfinder_executor::FEE_TOKEN_ADDRESS,
                    account_balance_key,
                    storage_value!("0x10000000000000000000000000000"),
                );

            db_txn
                .insert_state_update(new_header.number, &state_update)
                .unwrap();

            // Persist
            db_txn.commit().unwrap();

            (account_contract_address, new_header.hash, new_header.number)
        }

        #[tokio::test]
        async fn no_such_block() {
            let (_db_dir, context, account_address, _) = test_context().await;

            let input = EstimateFeeInput {
                request: vec![valid_invoke_v1(account_address)],
                block_id: BlockId::Hash(BlockHash(felt_bytes!(b"nonexistent"))),
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (_db_dir, context, account_address, latest_block_hash) = test_context().await;

            let mainnet_invoke = valid_invoke_v1(account_address)
                .into_invoke()
                .unwrap()
                .into_v1()
                .unwrap();
            let input = EstimateFeeInput {
                request: vec![BroadcastedTransaction::Invoke(
                    BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                        sender_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
                        ..mainnet_invoke
                    }),
                )],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::ContractNotFound));
        }

        #[test_log::test(tokio::test)]
        async fn successful_invoke_v1() {
            let (_db_dir, context, account_address, latest_block_hash) = test_context().await;

            let transaction0 = valid_invoke_v1(account_address);
            let transaction1 = BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                BroadcastedInvokeTransactionV1 {
                    nonce: TransactionNonce(felt!("0x1")),
                    ..transaction0
                        .clone()
                        .into_invoke()
                        .unwrap()
                        .into_v1()
                        .unwrap()
                },
            ));
            let input = EstimateFeeInput {
                request: vec![transaction0, transaction1],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let address =
                StorageAddress::from_map_name_and_key(b"ERC20_balances", account_address.0);
            tracing::trace!(%address, "Storage address");
            let result = estimate_fee(context, input).await.unwrap();
            let expected0 = FeeEstimate {
                gas_consumed: 4938.into(),
                gas_price: 1.into(),
                overall_fee: 4938.into(),
            };
            let expected1 = FeeEstimate {
                gas_consumed: 2490.into(),
                gas_price: 1.into(),
                overall_fee: 2490.into(),
            };
            assert_eq!(result, vec![expected0, expected1]);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v0() {
            let (_db_dir, context, _join_handle, _account_address, latest_block_hash) =
                test_context_with_call_handling().await;

            let contract_class = {
                let json = starknet_gateway_test_fixtures::class_definitions::CONTRACT_DEFINITION;
                ContractClass::from_definition_bytes(json)
                    .unwrap()
                    .as_cairo()
                    .unwrap()
            };

            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V0(BroadcastedDeclareTransactionV0 {
                    version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                    max_fee: Fee::default(),
                    signature: vec![],
                    contract_class,
                    sender_address: contract_address!("0x1"),
                }),
            );

            let input = EstimateFeeInput {
                request: vec![declare_transaction],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(result, vec![FeeEstimate::default()]);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v1() {
            let (_db_dir, context, account_address, latest_block_hash) = test_context().await;

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
                    max_fee: Fee(Felt::from_u64(10_000_000)),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class,
                    sender_address: account_address,
                }),
            );

            let input = EstimateFeeInput {
                request: vec![declare_transaction],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let expected = FeeEstimate {
                gas_consumed: 1252.into(),
                gas_price: 1.into(),
                overall_fee: 1252.into(),
            };
            assert_eq!(result, vec![expected]);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v2() {
            let (_db_dir, context, account_address, latest_block_hash) = test_context().await;

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
                    max_fee: Fee(Felt::from_u64(10_000_000)),
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
                request: vec![declare_transaction],
                block_id: BlockId::Hash(latest_block_hash),
            };
            let result = estimate_fee(context, input).await.unwrap();
            let expected = FeeEstimate {
                gas_consumed: 3700.into(),
                gas_price: 1.into(),
                overall_fee: 3700.into(),
            };
            assert_eq!(result, vec![expected]);
        }
    }
}
