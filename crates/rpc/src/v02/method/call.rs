use crate::context::RpcContext;
use crate::felt::RpcFelt;
use anyhow::Context;
use pathfinder_common::{
    BlockId, CallParam, CallResultValue, ContractAddress, EntryPoint, StarknetBlockNumber,
};
use pathfinder_storage::{
    StarknetBlocksBlockId, StarknetBlocksNumberOrLatest, StarknetBlocksTable,
};

crate::error::generate_rpc_error_subset!(
    CallError: BlockNotFound,
    ContractNotFound,
    InvalidMessageSelector,
    InvalidCallData,
    ContractError
);

impl From<crate::cairo::ext_py::CallFailure> for CallError {
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

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct CallInput {
    request: FunctionCall,
    block_id: BlockId,
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct FunctionCall {
    pub contract_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub calldata: Vec<CallParam>,
}

impl From<FunctionCall> for crate::v02::types::request::Call {
    fn from(call: FunctionCall) -> Self {
        Self {
            contract_address: call.contract_address,
            calldata: call.calldata,
            entry_point_selector: Some(call.entry_point_selector),
            // TODO: these fields are estimateFee-only and effectively ignored
            // by the underlying implementation. We can remove these once
            // JSON-RPC v0.1.0 is removed.
            signature: vec![],
            max_fee: Self::DEFAULT_MAX_FEE,
            version: Self::DEFAULT_VERSION,
            nonce: Self::DEFAULT_NONCE,
        }
    }
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
pub struct CallOutput(#[serde_as(as = "Vec<RpcFelt>")] Vec<CallResultValue>);

pub async fn call(context: RpcContext, input: CallInput) -> Result<CallOutput, CallError> {
    // let handle = context
    //     .call_handle
    //     .as_ref()
    //     .ok_or_else(|| anyhow::anyhow!("Unsupported configuration"))?;

    let (when, pending_timestamp, pending_update) =
        super::estimate_fee::base_block_and_pending_for_call(input.block_id, &context.pending_data)
            .await?;

    let block_id = match when {
        crate::cairo::ext_py::BlockHashNumberOrLatest::Hash(h) => StarknetBlocksBlockId::Hash(h),
        crate::cairo::ext_py::BlockHashNumberOrLatest::Number(n) => {
            StarknetBlocksBlockId::Number(n)
        }
        crate::cairo::ext_py::BlockHashNumberOrLatest::Latest => StarknetBlocksBlockId::Latest,
    };

    // FIXME: this should be a blocking task
    let mut db = context.storage.connection()?;
    let tx = db.transaction().context("Creating database transaction")?;

    let storage_commitment = StarknetBlocksTable::get_storage_commitment(&tx, block_id)
        .context("Reading storage root for block")?
        .ok_or_else(|| CallError::BlockNotFound)?;

    let state_reader = state::SqliteReader {
        storage: context.storage.clone(),
        storage_commitment,
    };

    // let result = handle
    //     .call(
    //         input.request.into(),
    //         when,
    //         pending_update,
    //         pending_timestamp,
    //     )
    //     .await?;

    // Ok(CallOutput(result))

    unimplemented!()
}

mod state {
    use pathfinder_common::{ClassHash, StorageAddress, StorageCommitment};
    use pathfinder_merkle_tree::state_tree::{ContractsStateTree, StorageCommitmentTree};
    use pathfinder_storage::{ContractCodeTable, ContractsStateTable};
    use stark_hash::Felt;
    use starknet_rs::business_logic::state::state_api::StateReader;
    use starknet_rs::core::errors::state_errors::StateError;
    use starknet_rs::services::api::contract_class_errors::ContractClassError;
    use starknet_rs::starknet_storage::errors::storage_errors::StorageError;

    pub struct SqliteReader {
        pub storage: pathfinder_storage::Storage,
        pub storage_commitment: StorageCommitment,
    }

    impl StateReader for SqliteReader {
        fn get_contract_class(
            &mut self,
            class_hash: &starknet_rs::utils::ClassHash,
        ) -> Result<starknet_rs::services::api::contract_class::ContractClass, StateError> {
            let class_hash =
                ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

            let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
            let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

            let definition = ContractCodeTable::get_class_raw(&tx, class_hash)
                .map_err(map_anyhow_to_state_err)?;

            match definition {
                Some(definition) => {
                    let raw_contract_class: starknet_api::state::ContractClass =
                        serde_json::from_slice(&definition).map_err(|_| {
                            StateError::ContractClass(ContractClassError::NoneEntryPointType)
                        })?;
                    let contract_class = raw_contract_class.into();
                    Ok(contract_class)
                }
                None => Err(StateError::MissingClassHash()),
            }
        }

        fn get_class_hash_at(
            &mut self,
            contract_address: &starknet_rs::utils::Address,
        ) -> Result<
            starknet_rs::utils::ClassHash,
            starknet_rs::core::errors::state_errors::StateError,
        > {
            let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
            let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

            let tree = StorageCommitmentTree::load(&tx, self.storage_commitment)
                .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;
            let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
                Felt::from_be_slice(&contract_address.0.to_bytes_be())
                    .expect("Overflow in contract address"),
            );
            let state_hash = tree
                .get(pathfinder_contract_address)
                .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;

            use rusqlite::OptionalExtension;

            let class_hash: Option<ClassHash> = tx
                .query_row(
                    "SELECT hash FROM contract_states WHERE state_hash=?",
                    [state_hash],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?;

            let class_hash =
                class_hash.ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))?;

            Ok(class_hash.0.to_be_bytes())
        }

        fn get_nonce_at(
            &mut self,
            contract_address: &starknet_rs::utils::Address,
        ) -> Result<cairo_felt::Felt252, starknet_rs::core::errors::state_errors::StateError>
        {
            let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
            let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

            let tree = StorageCommitmentTree::load(&tx, self.storage_commitment)
                .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;

            let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
                Felt::from_be_slice(&contract_address.0.to_bytes_be())
                    .expect("Overflow in contract address"),
            );
            let state_hash = tree
                .get(pathfinder_contract_address)
                .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?
                .ok_or_else(|| StateError::ContractAddressUnavailable(contract_address.clone()))?;

            let nonce = ContractsStateTable::get_nonce(&tx, state_hash)
                .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?
                .ok_or_else(|| StateError::ContractAddressUnavailable(contract_address.clone()))?;

            Ok(cairo_felt::Felt252::from_bytes_be(nonce.0.as_be_bytes()))
        }

        fn get_storage_at(
            &mut self,
            storage_entry: &starknet_rs::business_logic::state::state_cache::StorageEntry,
        ) -> Result<cairo_felt::Felt252, starknet_rs::core::errors::state_errors::StateError>
        {
            let (contract_address, storage_key) = storage_entry;
            let storage_key =
                StorageAddress::new(Felt::from_be_slice(storage_key).map_err(|_| {
                    StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
                })?)
                .ok_or_else(|| {
                    StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
                })?;

            let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
            let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

            let tree = StorageCommitmentTree::load(&tx, self.storage_commitment)
                .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;

            let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
                Felt::from_be_slice(&contract_address.0.to_bytes_be())
                    .expect("Overflow in contract address"),
            );
            let state_hash = tree
                .get(pathfinder_contract_address)
                .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?
                .ok_or_else(|| StateError::ContractAddressUnavailable(contract_address.clone()))?;

            let contract_state_root = ContractsStateTable::get_root(&tx, state_hash)
                .map_err(|_| StateError::NoneContractState(contract_address.clone()))?
                .ok_or_else(|| StateError::NoneContractState(contract_address.clone()))?;

            let contract_state_tree = ContractsStateTree::load(&tx, contract_state_root)
                .map_err(|_| StateError::NoneStorage(storage_entry.clone()))?;

            let storage_val = contract_state_tree
                .get(storage_key)
                .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?
                .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()))?;

            Ok(cairo_felt::Felt252::from_bytes_be(
                storage_val.0.as_be_bytes(),
            ))
        }

        fn count_actual_storage_changes(&mut self) -> (usize, usize) {
            // read-only storage
            (0, 0)
        }
    }

    // FIXME: we clearly need something more expressive than this
    fn map_sqlite_to_state_err(
        _e: rusqlite::Error,
    ) -> starknet_rs::core::errors::state_errors::StateError {
        StateError::Storage(StorageError::ErrorFetchingData)
    }

    fn map_anyhow_to_state_err(
        _e: anyhow::Error,
    ) -> starknet_rs::core::errors::state_errors::StateError {
        StateError::Storage(StorageError::ErrorFetchingData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::felt;

    mod parsing {
        use super::*;
        use jsonrpsee::types::Params;
        use pathfinder_common::StarknetBlockHash;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                { "block_hash": "0xbbbbbbbb" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<CallInput>().unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(felt!("0xabcde")),
                    entry_point_selector: EntryPoint(felt!("0xee")),
                    calldata: vec![CallParam(felt!("0x1234")), CallParam(felt!("0x2345"))],
                },
                block_id: StarknetBlockHash(felt!("0xbbbbbbbb")).into(),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = r#"{
                "request": { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                "block_id": { "block_hash": "0xbbbbbbbb" }
            }"#;
            let named = Params::new(Some(named));

            let input = named.parse::<CallInput>().unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(felt!("0xabcde")),
                    entry_point_selector: EntryPoint(felt!("0xee")),
                    calldata: vec![CallParam(felt!("0x1234")), CallParam(felt!("0x2345"))],
                },
                block_id: StarknetBlockHash(felt!("0xbbbbbbbb")).into(),
            };
            assert_eq!(input, expected);
        }
    }

    mod ext_py {
        use super::*;
        use pathfinder_common::{felt_bytes, Chain, StarknetBlockHash};
        use pathfinder_storage::JournalMode;
        use std::path::PathBuf;
        use std::sync::Arc;

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(StarknetBlockHash(felt!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        )));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_call() -> FunctionCall {
            FunctionCall {
                contract_address: ContractAddress::new_or_panic(felt!(
                    "020cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6"
                )),
                entry_point_selector: EntryPoint(felt!(
                    "03d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3"
                )),
                calldata: vec![
                    CallParam(felt!(
                        "e150b6c2db6ed644483b01685571de46d2045f267d437632b508c19f3eb877"
                    )),
                    CallParam(felt!(
                        "0494196e88ce16bff11180d59f3c75e4ba3475d9fba76249ab5f044bcd25add6"
                    )),
                ],
            }
        }

        async fn test_context_with_call_handling() -> RpcContext {
            use pathfinder_common::ChainId;

            let mut database_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            database_path.push("fixtures/mainnet.sqlite");
            let storage =
                pathfinder_storage::Storage::migrate(database_path.clone(), JournalMode::WAL)
                    .unwrap();
            let sync_state = Arc::new(crate::SyncState::default());

            let sequencer = starknet_gateway_client::Client::new(Chain::Mainnet).unwrap();

            RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer)
        }

        #[tokio::test]
        async fn no_such_block() {
            let context = test_context_with_call_handling().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BlockId::Hash(StarknetBlockHash(felt_bytes!(b"nonexistent"))),
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let context = test_context_with_call_handling().await;

            let input = CallInput {
                request: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::ContractNotFound));
        }

        #[tokio::test]
        async fn invalid_message_selector() {
            let context = test_context_with_call_handling().await;

            let input = CallInput {
                request: FunctionCall {
                    entry_point_selector: EntryPoint(Default::default()),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::InvalidMessageSelector));
        }

        #[tokio::test]
        async fn successful_call() {
            let context = test_context_with_call_handling().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BLOCK_5,
            };

            let result = call(context, input).await.unwrap();
            assert_eq!(result.0, vec![]);
        }
    }
}
