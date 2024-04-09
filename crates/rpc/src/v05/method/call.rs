use crate::context::RpcContext;
use crate::error::ApplicationError;
use crate::felt::RpcFelt;
use anyhow::Context;
use pathfinder_common::{BlockId, CallParam, CallResultValue, ContractAddress, EntryPoint};
use pathfinder_executor::{ExecutionState, L1BlobDataAvailability};

#[derive(Debug)]
pub enum CallError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    ContractNotFound,
    ContractErrorV05 { revert_error: String },
}

impl From<anyhow::Error> for CallError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<pathfinder_executor::CallError> for CallError {
    fn from(value: pathfinder_executor::CallError) -> Self {
        use pathfinder_executor::CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::Custom(anyhow::anyhow!("Invalid message selector")),
            ContractError(error) => Self::ContractErrorV05 {
                revert_error: format!("Execution error: {}", error),
            },
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
        }
    }
}

impl From<crate::executor::ExecutionStateError> for CallError {
    fn from(error: crate::executor::ExecutionStateError) -> Self {
        use crate::executor::ExecutionStateError::*;
        match error {
            BlockNotFound => Self::BlockNotFound,
            Internal(e) => Self::Internal(e),
        }
    }
}

impl From<CallError> for ApplicationError {
    fn from(value: CallError) -> Self {
        match value {
            CallError::BlockNotFound => ApplicationError::BlockNotFound,
            CallError::ContractNotFound => ApplicationError::ContractNotFound,
            CallError::ContractErrorV05 { revert_error } => {
                ApplicationError::ContractErrorV05 { revert_error }
            }
            CallError::Internal(e) => ApplicationError::Internal(e),
            CallError::Custom(e) => ApplicationError::Custom(e),
        }
    }
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CallInput {
    pub request: FunctionCall,
    pub block_id: BlockId,
}

#[derive(Clone, serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionCall {
    pub contract_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub calldata: Vec<CallParam>,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct CallOutput(#[serde_as(as = "Vec<RpcFelt>")] pub Vec<CallResultValue>);

pub async fn call(context: RpcContext, input: CallInput) -> Result<CallOutput, CallError> {
    let span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = context
            .storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let (header, pending) = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                (pending.header(), Some(pending.state_update.clone()))
            }
            other => {
                let block_id = other.try_into().expect("Only pending cast should fail");
                let header = db
                    .block_header(block_id)
                    .context("Querying block header")?
                    .ok_or(CallError::BlockNotFound)?;

                (header, None)
            }
        };

        let state = ExecutionState::simulation(
            &db,
            context.chain_id,
            header,
            pending,
            L1BlobDataAvailability::Disabled,
        );

        let result = pathfinder_executor::call(
            state,
            input.request.contract_address,
            input.request.entry_point_selector,
            input.request.calldata,
        )?;

        Ok(result)
    })
    .await
    .context("Executing call")?;

    result.map(CallOutput)
}

#[cfg(test)]
mod tests {
    use super::*;

    use pathfinder_common::macro_prelude::*;

    mod parsing {
        use super::*;
        use serde_json::json;

        #[test]
        fn positional_args() {
            let positional = json!([
                { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                { "block_hash": "0xbbbbbbbb" }
            ]);

            let input = serde_json::from_value::<CallInput>(positional).unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: contract_address!("0xabcde"),
                    entry_point_selector: entry_point!("0xee"),
                    calldata: vec![call_param!("0x1234"), call_param!("0x2345")],
                },
                block_id: block_hash!("0xbbbbbbbb").into(),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = json!({
                "request": { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                "block_id": { "block_hash": "0xbbbbbbbb" }
            });

            let input = serde_json::from_value::<CallInput>(named).unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: contract_address!("0xabcde"),
                    entry_point_selector: entry_point!("0xee"),
                    calldata: vec![call_param!("0x1234"), call_param!("0x2345")],
                },
                block_id: block_hash!("0xbbbbbbbb").into(),
            };
            assert_eq!(input, expected);
        }
    }

    mod in_memory {

        use super::*;

        use crate::pending::PendingData;
        use pathfinder_common::{
            felt, BlockHash, BlockHeader, BlockNumber, BlockTimestamp, ClassHash, ContractAddress,
            GasPrice, StateUpdate, StorageAddress, StorageValue,
        };
        use starknet_gateway_test_fixtures::class_definitions::{
            CONTRACT_DEFINITION, CONTRACT_DEFINITION_CLASS_HASH,
        };
        use starknet_gateway_types::reply::{GasPrices, L1DataAvailabilityMode, PendingBlock};

        async fn test_context() -> (
            RpcContext,
            BlockHeader,
            ContractAddress,
            StorageAddress,
            StorageValue,
        ) {
            let storage = pathfinder_storage::StorageBuilder::in_memory().unwrap();
            let mut db = storage.connection().unwrap();
            let tx = db.transaction().unwrap();

            // Empty genesis block
            let header = BlockHeader::builder()
                .with_number(BlockNumber::GENESIS)
                .with_timestamp(BlockTimestamp::new_or_panic(0))
                .finalize_with_hash(BlockHash(felt!("0xb00")));
            tx.insert_block_header(&header).unwrap();

            // Declare & deploy a test class providing an entry point reading from storage
            let block1_number = BlockNumber::GENESIS + 1;
            let block1_hash = BlockHash(felt!("0xb01"));

            tx.insert_cairo_class(CONTRACT_DEFINITION_CLASS_HASH, CONTRACT_DEFINITION)
                .unwrap();

            let header = BlockHeader::builder()
                .with_number(block1_number)
                .with_timestamp(BlockTimestamp::new_or_panic(1))
                .with_eth_l1_gas_price(GasPrice(1))
                .finalize_with_hash(block1_hash);
            tx.insert_block_header(&header).unwrap();

            let test_contract_address = ContractAddress::new_or_panic(felt!("0xc01"));
            let test_contract_key = StorageAddress::new_or_panic(felt!("0x123"));
            let test_contract_value = StorageValue(felt!("0x3"));

            let state_update = StateUpdate::default()
                .with_block_hash(block1_hash)
                .with_declared_cairo_class(CONTRACT_DEFINITION_CLASS_HASH)
                .with_deployed_contract(test_contract_address, CONTRACT_DEFINITION_CLASS_HASH)
                .with_storage_update(
                    test_contract_address,
                    test_contract_key,
                    test_contract_value,
                );
            tx.insert_state_update(block1_number, &state_update)
                .unwrap();

            tx.commit().unwrap();

            let context =
                RpcContext::for_tests_on(pathfinder_common::Chain::Mainnet).with_storage(storage);

            (
                context,
                header,
                test_contract_address,
                test_contract_key,
                test_contract_value,
            )
        }

        #[tokio::test]
        async fn storage_access() {
            let (context, _last_block_header, contract_address, test_key, test_value) =
                test_context().await;

            let input = CallInput {
                request: FunctionCall {
                    contract_address,
                    entry_point_selector: EntryPoint::hashed(b"get_value"),
                    calldata: vec![CallParam(*test_key.get())],
                },
                block_id: BlockId::Latest,
            };
            let result = call(context, input).await.unwrap();
            assert_eq!(result, CallOutput(vec![CallResultValue(test_value.0)]));
        }

        #[tokio::test]
        async fn storage_updated_in_pending() {
            let (context, last_block_header, contract_address, test_key, test_value) =
                test_context().await;

            let new_value = StorageValue(felt!("0x09"));
            let pending_data = pending_data_with_update(
                last_block_header,
                StateUpdate::default().with_storage_update(contract_address, test_key, new_value),
            );

            let (_tx, rx) = tokio::sync::watch::channel(pending_data);
            let context = context.with_pending_data(rx);

            // unchanged on latest block
            let input = CallInput {
                request: FunctionCall {
                    contract_address,
                    entry_point_selector: EntryPoint::hashed(b"get_value"),
                    calldata: vec![CallParam(*test_key.get())],
                },
                block_id: BlockId::Latest,
            };
            let result = call(context.clone(), input).await.unwrap();
            assert_eq!(result, CallOutput(vec![CallResultValue(test_value.0)]));

            // updated on pending
            let input = CallInput {
                request: FunctionCall {
                    contract_address,
                    entry_point_selector: EntryPoint::hashed(b"get_value"),
                    calldata: vec![CallParam(*test_key.get())],
                },
                block_id: BlockId::Pending,
            };
            let result = call(context, input).await.unwrap();
            assert_eq!(result, CallOutput(vec![CallResultValue(new_value.0)]));
        }

        #[tokio::test]
        async fn contract_deployed_in_pending() {
            let (context, last_block_header, _contract_address, test_key, _test_value) =
                test_context().await;

            let new_value = storage_value!("0x09");
            let new_contract_address = contract_address!("0xdeadbeef");
            let pending_data = pending_data_with_update(
                last_block_header,
                StateUpdate::default()
                    .with_deployed_contract(new_contract_address, CONTRACT_DEFINITION_CLASS_HASH)
                    .with_storage_update(new_contract_address, test_key, new_value),
            );
            let (_tx, rx) = tokio::sync::watch::channel(pending_data);
            let context = context.with_pending_data(rx);

            let input = CallInput {
                request: FunctionCall {
                    contract_address: new_contract_address,
                    entry_point_selector: EntryPoint::hashed(b"get_value"),
                    calldata: vec![CallParam(*test_key.get())],
                },
                block_id: BlockId::Pending,
            };
            let result = call(context.clone(), input).await.unwrap();
            assert_eq!(result, CallOutput(vec![CallResultValue(new_value.0)]));
        }

        #[test_log::test(tokio::test)]
        async fn contract_declared_and_deployed_in_pending() {
            let (context, last_block_header, _contract_address, _test_key, _test_value) =
                test_context().await;

            let sierra_definition =
                include_bytes!("../../../fixtures/contracts/storage_access.json");
            let sierra_hash =
                sierra_hash!("0x0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
            let casm_definition = include_bytes!("../../../fixtures/contracts/storage_access.casm");
            let casm_hash =
                casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");

            let mut connection = context.storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            tx.insert_sierra_class(&sierra_hash, sierra_definition, &casm_hash, casm_definition)
                .unwrap();
            tx.commit().unwrap();

            drop(connection);

            let storage_key = StorageAddress::from_name(b"my_storage_var");
            let storage_value = storage_value!("0x09");
            let new_contract_address = contract_address!("0xdeadbeef");
            let pending_data = pending_data_with_update(
                last_block_header,
                StateUpdate::default()
                    .with_declared_sierra_class(sierra_hash, casm_hash)
                    .with_deployed_contract(new_contract_address, ClassHash(sierra_hash.0))
                    .with_storage_update(new_contract_address, storage_key, storage_value),
            );
            let (_tx, rx) = tokio::sync::watch::channel(pending_data);
            let context = context.with_pending_data(rx);

            let input = CallInput {
                request: FunctionCall {
                    contract_address: new_contract_address,
                    entry_point_selector: EntryPoint::hashed(b"get_data"),
                    calldata: vec![],
                },
                block_id: BlockId::Pending,
            };
            let result = call(context.clone(), input).await.unwrap();
            assert_eq!(result, CallOutput(vec![CallResultValue(storage_value.0)]));
        }

        fn pending_data_with_update(
            last_block_header: BlockHeader,
            state_update: StateUpdate,
        ) -> PendingData {
            PendingData {
                block: PendingBlock {
                    l1_gas_price: GasPrices {
                        price_in_wei: last_block_header.eth_l1_gas_price,
                        price_in_fri: Default::default(),
                    },
                    l1_data_gas_price: Default::default(),
                    parent_hash: last_block_header.hash,
                    sequencer_address: last_block_header.sequencer_address,
                    status: starknet_gateway_types::reply::Status::Pending,
                    timestamp: BlockTimestamp::new_or_panic(last_block_header.timestamp.get() + 1),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: last_block_header.starknet_version,
                    l1_da_mode: L1DataAvailabilityMode::Calldata,
                }
                .into(),
                state_update: state_update.into(),
                number: last_block_header.number + 1,
            }
        }

        #[tokio::test]
        async fn call_sierra_class() {
            let (context, last_block_header, _contract_address, _test_key, _test_value) =
                test_context().await;

            let sierra_definition =
                include_bytes!("../../../fixtures/contracts/storage_access.json");
            let sierra_hash =
                sierra_hash!("0x03f6241e01a5afcb81f181518d74a1d3c8fc49c2aa583f805b67732e494ba9a8");
            let casm_definition = include_bytes!("../../../fixtures/contracts/storage_access.casm");
            let casm_hash =
                casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");

            let block_number = BlockNumber::new_or_panic(last_block_header.number.get() + 1);
            let contract_address = contract_address!("0xcaaaa");
            let storage_key = StorageAddress::from_name(b"my_storage_var");
            let storage_value = storage_value!("0xb");

            let mut connection = context.storage.connection().unwrap();
            let tx = connection.transaction().unwrap();

            tx.insert_sierra_class(&sierra_hash, sierra_definition, &casm_hash, casm_definition)
                .unwrap();

            let header = BlockHeader::builder()
                .with_number(block_number)
                .finalize_with_hash(block_hash!("0xb02"));
            tx.insert_block_header(&header).unwrap();

            let state_update = StateUpdate::default()
                .with_declared_sierra_class(sierra_hash, casm_hash)
                .with_deployed_contract(contract_address, ClassHash(*sierra_hash.get()))
                .with_storage_update(contract_address, storage_key, storage_value);
            tx.insert_state_update(block_number, &state_update).unwrap();

            tx.commit().unwrap();

            let input = CallInput {
                request: FunctionCall {
                    contract_address,
                    entry_point_selector: EntryPoint::hashed(b"get_data"),
                    calldata: vec![],
                },
                block_id: BlockId::Latest,
            };
            let result = call(context, input).await.unwrap();
            assert_eq!(result, CallOutput(vec![CallResultValue(storage_value.0)]));
        }
    }

    mod mainnet {
        use super::*;
        use std::num::NonZeroU32;
        use std::path::PathBuf;

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(block_hash!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        ));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_call() -> FunctionCall {
            FunctionCall {
                contract_address: contract_address!(
                    "020cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6"
                ),
                entry_point_selector: entry_point!(
                    "03d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3"
                ),
                calldata: vec![
                    call_param!("e150b6c2db6ed644483b01685571de46d2045f267d437632b508c19f3eb877"),
                    call_param!("0494196e88ce16bff11180d59f3c75e4ba3475d9fba76249ab5f044bcd25add6"),
                ],
            }
        }

        async fn test_context() -> (tempfile::TempDir, RpcContext) {
            let mut source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            source_path.push("fixtures/mainnet.sqlite");

            let db_dir = tempfile::TempDir::new().unwrap();
            let mut db_path = PathBuf::from(db_dir.path());
            db_path.push("mainnet.sqlite");

            std::fs::copy(&source_path, &db_path).unwrap();

            let storage = pathfinder_storage::StorageBuilder::file(db_path)
                .migrate()
                .unwrap()
                .create_pool(NonZeroU32::new(1).unwrap())
                .unwrap();

            let context =
                RpcContext::for_tests_on(pathfinder_common::Chain::Mainnet).with_storage(storage);

            (db_dir, context)
        }

        #[tokio::test]
        async fn no_such_block() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BlockId::Hash(block_hash_bytes!(b"nonexistent")),
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: FunctionCall {
                    contract_address: contract_address!("0xdeadbeef"),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::ContractNotFound));
        }

        #[tokio::test]
        async fn invalid_message_selector() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: FunctionCall {
                    entry_point_selector: EntryPoint(Default::default()),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::Custom(_)));
        }

        #[tokio::test]
        async fn successful_call() {
            let (_temp_dir, context) = test_context().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BLOCK_5,
            };

            let result = call(context, input).await.unwrap();
            assert_eq!(result.0, vec![]);
        }
    }
}
