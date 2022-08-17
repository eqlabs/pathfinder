//! StarkNet node JSON-RPC related modules.
pub mod api;
pub mod serde;
#[cfg(test)]
pub mod test_client;
#[cfg(test)]
pub mod test_setup;
pub mod types;

use crate::{
    core::{
        BlockId, CallSignatureElem, ClassHash, ConstructorParam, ContractAddress,
        ContractAddressSalt, Fee, StarknetTransactionHash, StarknetTransactionIndex,
        TransactionVersion,
    },
    rpc::{
        api::{BlockResponseScope, RpcApi},
        serde::{CallSignatureElemAsDecimalStr, FeeAsHexStr, TransactionVersionAsHexStr},
        types::request::{Call, ContractCall, EventFilter},
    },
    sequencer::request::add_transaction::ContractDefinition,
};
use ::serde::Deserialize;
use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle, RpcModule};

use std::{net::SocketAddr, result::Result};

/// Helper wrapper for attaching spans to rpc method implementations
struct RpcModuleWrapper<Context>(jsonrpsee::RpcModule<Context>);

impl<Context: Send + Sync + 'static> RpcModuleWrapper<Context> {
    /// This wrapper helper adds a tracing span around all rpc methods with name = method_name.
    ///
    /// It could do more, for example trace the outputs, durations.
    ///
    /// This is the only one method provided at the moment, because it's the only one used. If you
    /// need to use some other `register_*` method from [`jsonrpsee::RpcModule`], just add it to
    /// this wrapper.
    fn register_async_method<R, Fun, Fut>(
        &mut self,
        method_name: &'static str,
        callback: Fun,
    ) -> Result<
        jsonrpsee::core::server::rpc_module::MethodResourcesBuilder<'_>,
        jsonrpsee::core::Error,
    >
    where
        R: ::serde::Serialize + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<R, jsonrpsee::core::Error>> + Send,
        Fun: (Fn(jsonrpsee::types::Params<'static>, std::sync::Arc<Context>) -> Fut)
            + Copy
            + Send
            + Sync
            + 'static,
    {
        use tracing::Instrument;

        self.0.register_async_method(method_name, move |p, c| {
            // why info here? it's the same used in warp tracing filter for example.
            let span = tracing::info_span!("rpc_method", name = method_name);
            callback(p, c).instrument(span)
        })
    }

    fn into_inner(self) -> jsonrpsee::RpcModule<Context> {
        self.0
    }
}

/// Starts the HTTP-RPC server.
pub async fn run_server(
    addr: SocketAddr,
    api: RpcApi,
) -> Result<(HttpServerHandle, SocketAddr), anyhow::Error> {
    let server = HttpServerBuilder::default()
        .build(addr)
        .await
        .map_err(|e| match e {
            jsonrpsee::core::Error::Transport(_) => {
                use std::error::Error;

                if let Some(inner) = e.source().and_then(|inner| inner.downcast_ref::<std::io::Error>()) {
                    if let std::io::ErrorKind::AddrInUse = inner.kind() {
                        return anyhow::Error::new(e)
                        .context(format!("RPC address is already in use: {addr}.

Hint: This usually means you are already running another instance of pathfinder.
Hint: If this happens when upgrading, make sure to shut down the first one first.
Hint: If you are looking to run two instances of pathfinder, you must configure them with different http rpc addresses."))
                    }
                }

                anyhow::Error::new(e)
            }
            _ => anyhow::Error::new(e),
        })?;
    let local_addr = server.local_addr()?;
    let mut module = RpcModuleWrapper(RpcModule::new(api));
    module.register_async_method(
        "starknet_getBlockWithTxHashes",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                block_id: BlockId,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .get_block(params.block_id, BlockResponseScope::TransactionHashes)
                .await
        },
    )?;
    module.register_async_method("starknet_getBlockWithTxs", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_block(params.block_id, BlockResponseScope::FullTransactions)
            .await
    })?;
    module.register_async_method("starknet_getStateUpdate", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context.get_state_update(params.block_id).await
    })?;
    module.register_async_method("starknet_getStorageAt", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            contract_address: ContractAddress,
            key: crate::core::StorageAddress,
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_storage_at(params.contract_address, params.key, params.block_id)
            .await
    })?;
    module.register_async_method(
        "starknet_getTransactionByHash",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                transaction_hash: StarknetTransactionHash,
            }
            context
                .get_transaction_by_hash(params.parse::<NamedArgs>()?.transaction_hash)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getTransactionByBlockIdAndIndex",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                block_id: BlockId,
                index: StarknetTransactionIndex,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .get_transaction_by_block_id_and_index(params.block_id, params.index)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getTransactionReceipt",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                transaction_hash: StarknetTransactionHash,
            }
            context
                .get_transaction_receipt(params.parse::<NamedArgs>()?.transaction_hash)
                .await
        },
    )?;
    module.register_async_method("starknet_getClass", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            class_hash: ClassHash,
        }
        context
            .get_class(params.parse::<NamedArgs>()?.class_hash)
            .await
    })?;
    module.register_async_method("starknet_getClassHashAt", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
            contract_address: ContractAddress,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_class_hash_at(params.block_id, params.contract_address)
            .await
    })?;
    module.register_async_method("starknet_getClassAt", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
            contract_address: ContractAddress,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_class_at(params.block_id, params.contract_address)
            .await
    })?;
    module.register_async_method(
        "starknet_getBlockTransactionCount",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                block_id: BlockId,
            }
            context
                .get_block_transaction_count(params.parse::<NamedArgs>()?.block_id)
                .await
        },
    )?;
    module.register_async_method("starknet_getNonce", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            contract_address: ContractAddress,
        }
        context
            .get_nonce(params.parse::<NamedArgs>()?.contract_address)
            .await
    })?;
    module.register_async_method("starknet_call", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            request: Call,
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context.call(params.request, params.block_id).await
    })?;
    module.register_async_method("starknet_estimateFee", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            request: Call,
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context.estimate_fee(params.request, params.block_id).await
    })?;
    module.register_async_method("starknet_blockNumber", |_, context| async move {
        context.block_number().await
    })?;
    module.register_async_method("starknet_blockHashAndNumber", |_, context| async move {
        context.block_hash_and_number().await
    })?;
    module.register_async_method("starknet_chainId", |_, context| async move {
        context.chain_id().await
    })?;
    module.register_async_method("starknet_pendingTransactions", |_, context| async move {
        context.pending_transactions().await
    })?;
    module.register_async_method("starknet_syncing", |_, context| async move {
        context.syncing().await
    })?;
    module.register_async_method("starknet_getEvents", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            filter: EventFilter,
        }
        let request = params.parse::<NamedArgs>()?.filter;
        context.get_events(request).await
    })?;
    module.register_async_method(
        "starknet_addInvokeTransaction",
        |params, context| async move {
            #[serde_with::serde_as]
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                function_invocation: ContractCall,
                #[serde_as(as = "Vec<CallSignatureElemAsDecimalStr>")]
                signature: Vec<CallSignatureElem>,
                #[serde_as(as = "FeeAsHexStr")]
                max_fee: Fee,
                #[serde_as(as = "TransactionVersionAsHexStr")]
                version: TransactionVersion,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .add_invoke_transaction(
                    params.function_invocation,
                    params.signature,
                    params.max_fee,
                    params.version,
                )
                .await
        },
    )?;
    module.register_async_method(
        "starknet_addDeclareTransaction",
        |params, context| async move {
            #[serde_with::serde_as]
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                contract_class: ContractDefinition,
                #[serde_as(as = "TransactionVersionAsHexStr")]
                version: TransactionVersion,
                // An undocumented parameter that we forward to the sequencer API
                // A deploy token is required to deploy contracts on Starknet mainnet only.
                #[serde(default)]
                token: Option<String>,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .add_declare_transaction(params.contract_class, params.version, params.token)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_addDeployTransaction",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                contract_address_salt: ContractAddressSalt,
                constructor_calldata: Vec<ConstructorParam>,
                contract_definition: ContractDefinition,
                // An undocumented parameter that we forward to the sequencer API
                // A deploy token is required to deploy contracts on Starknet mainnet only.
                #[serde(default)]
                token: Option<String>,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .add_deploy_transaction(
                    params.contract_address_salt,
                    params.constructor_calldata,
                    params.contract_definition,
                    params.token,
                )
                .await
        },
    )?;

    let module = module.into_inner();
    Ok(server.start(module).map(|handle| (handle, local_addr))?)
}

#[cfg(test)]
mod tests {
    use super::{test_client::client, *};
    use crate::{
        core::{
            Chain, ClassHash, ContractAddress, EntryPoint, EventData, EventKey, GasPrice,
            GlobalRoot, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
            StarknetBlockTimestamp, StorageAddress,
        },
        rpc::{run_server, types::reply::BlockHashAndNumber},
        sequencer::{
            reply::{
                state_update::StorageDiff,
                transaction::{
                    execution_resources::{BuiltinInstanceCounter, EmptyBuiltinInstanceCounter},
                    EntryPointType, Event, ExecutionResources, InvokeTransaction, Receipt,
                },
            },
            test_utils::*,
            Client,
        },
        starkhash, starkhash_bytes,
        state::{state_tree::GlobalStateTree, PendingData, SyncState},
        storage::{
            CanonicalBlocksTable, ContractCodeTable, ContractsTable, StarknetBlock,
            StarknetBlocksTable, StarknetTransactionsTable, Storage,
        },
    };
    use assert_matches::assert_matches;
    use jsonrpsee::{rpc_params, types::ParamsSer};
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use stark_hash::StarkHash;
    use std::{
        collections::BTreeMap,
        net::{Ipv4Addr, SocketAddrV4},
        sync::Arc,
    };

    /// Helper function: produces named rpc method args map.
    fn by_name<const N: usize>(params: [(&'_ str, serde_json::Value); N]) -> Option<ParamsSer<'_>> {
        Some(BTreeMap::from(params).into())
    }

    lazy_static::lazy_static! {
        static ref LOCALHOST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    }

    // Local test helper
    fn setup_storage() -> Storage {
        use crate::sequencer::reply::transaction::Transaction;
        use crate::{
            core::StorageValue,
            state::{update_contract_state, CompressedContract},
        };
        use web3::types::H128;

        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let db_txn = connection.transaction().unwrap();

        let contract0_addr = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0"));
        let contract1_addr = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));

        let class0_hash = ClassHash(starkhash_bytes!(b"class 0 hash"));
        let class1_hash = ClassHash(starkhash_bytes!(b"class 1 hash"));

        let contract0_update = vec![];

        let storage_addr = StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0"));
        let contract1_update0 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(starkhash_bytes!(b"storage value 0")),
        }];
        let contract1_update1 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(starkhash_bytes!(b"storage value 1")),
        }];
        let contract1_update2 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(starkhash_bytes!(b"storage value 2")),
        }];

        // We need to set the magic bytes for zstd compression to simulate a compressed
        // contract definition, as this is asserted for internally
        let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
        let contract0_code = CompressedContract {
            abi: zstd_magic.clone(),
            bytecode: zstd_magic.clone(),
            definition: zstd_magic,
            hash: class0_hash,
        };
        let mut contract1_code = contract0_code.clone();
        contract1_code.hash = class1_hash;

        ContractCodeTable::insert_compressed(&db_txn, &contract0_code).unwrap();
        ContractCodeTable::insert_compressed(&db_txn, &contract1_code).unwrap();

        ContractsTable::upsert(&db_txn, contract0_addr, class0_hash).unwrap();
        ContractsTable::upsert(&db_txn, contract1_addr, class1_hash).unwrap();

        let mut global_tree = GlobalStateTree::load(&db_txn, GlobalRoot(StarkHash::ZERO)).unwrap();
        let contract_state_hash =
            update_contract_state(contract0_addr, &contract0_update, &global_tree, &db_txn)
                .unwrap();
        global_tree
            .set(contract0_addr, contract_state_hash)
            .unwrap();
        let global_root0 = global_tree.apply().unwrap();

        let mut global_tree = GlobalStateTree::load(&db_txn, global_root0).unwrap();
        let contract_state_hash =
            update_contract_state(contract1_addr, &contract1_update0, &global_tree, &db_txn)
                .unwrap();
        global_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let contract_state_hash =
            update_contract_state(contract1_addr, &contract1_update1, &global_tree, &db_txn)
                .unwrap();
        global_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let global_root1 = global_tree.apply().unwrap();

        let mut global_tree = GlobalStateTree::load(&db_txn, global_root1).unwrap();
        let contract_state_hash =
            update_contract_state(contract1_addr, &contract1_update2, &global_tree, &db_txn)
                .unwrap();
        global_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let global_root2 = global_tree.apply().unwrap();

        let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
        let block0 = StarknetBlock {
            number: StarknetBlockNumber::GENESIS,
            hash: genesis_hash,
            root: global_root0,
            timestamp: StarknetBlockTimestamp::new_or_panic(0),
            gas_price: GasPrice::ZERO,
            sequencer_address: SequencerAddress(StarkHash::ZERO),
        };
        let block1_hash = StarknetBlockHash(starkhash_bytes!(b"block 1"));
        let block1 = StarknetBlock {
            number: StarknetBlockNumber::new_or_panic(1),
            hash: block1_hash,
            root: global_root1,
            timestamp: StarknetBlockTimestamp::new_or_panic(1),
            gas_price: GasPrice::from(1),
            sequencer_address: SequencerAddress(starkhash_bytes!(&[1u8])),
        };
        let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
        let block2 = StarknetBlock {
            number: StarknetBlockNumber::new_or_panic(2),
            hash: latest_hash,
            root: global_root2,
            timestamp: StarknetBlockTimestamp::new_or_panic(2),
            gas_price: GasPrice::from(2),
            sequencer_address: SequencerAddress(starkhash_bytes!(&[2u8])),
        };
        StarknetBlocksTable::insert(&db_txn, &block0, None).unwrap();
        StarknetBlocksTable::insert(&db_txn, &block1, None).unwrap();
        StarknetBlocksTable::insert(&db_txn, &block2, None).unwrap();

        CanonicalBlocksTable::insert(&db_txn, block0.number, block0.hash).unwrap();
        CanonicalBlocksTable::insert(&db_txn, block1.number, block1.hash).unwrap();
        CanonicalBlocksTable::insert(&db_txn, block2.number, block2.hash).unwrap();

        let txn0_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
        // TODO introduce other types of transactions too
        let txn0 = InvokeTransaction {
            calldata: vec![],
            contract_address: contract0_addr,
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPoint(StarkHash::ZERO),
            max_fee: Fee(H128::zero()),
            signature: vec![],
            transaction_hash: txn0_hash,
        };
        let mut receipt0 = Receipt {
            actual_fee: None,
            events: vec![],
            execution_resources: ExecutionResources {
                builtin_instance_counter: BuiltinInstanceCounter::Empty(
                    EmptyBuiltinInstanceCounter {},
                ),
                n_memory_holes: 0,
                n_steps: 0,
            },
            l1_to_l2_consumed_message: None,
            l2_to_l1_messages: vec![],
            transaction_hash: txn0_hash,
            transaction_index: StarknetTransactionIndex::new_or_panic(0),
        };
        let txn1_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 1"));
        let txn2_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 2"));
        let txn3_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 3"));
        let txn4_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 4 "));
        let txn5_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 5"));
        let mut txn1 = txn0.clone();
        let mut txn2 = txn0.clone();
        let mut txn3 = txn0.clone();
        let mut txn4 = txn0.clone();
        txn1.transaction_hash = txn1_hash;
        txn1.contract_address = contract1_addr;
        txn2.transaction_hash = txn2_hash;
        txn2.contract_address = contract1_addr;
        txn3.transaction_hash = txn3_hash;
        txn3.contract_address = contract1_addr;
        txn4.transaction_hash = txn4_hash;

        txn4.contract_address = ContractAddress::new_or_panic(StarkHash::ZERO);
        let mut txn5 = txn4.clone();
        txn5.transaction_hash = txn5_hash;
        let txn0 = Transaction::Invoke(txn0);
        let txn1 = Transaction::Invoke(txn1);
        let txn2 = Transaction::Invoke(txn2);
        let txn3 = Transaction::Invoke(txn3);
        let txn4 = Transaction::Invoke(txn4);
        let txn5 = Transaction::Invoke(txn5);
        let mut receipt1 = receipt0.clone();
        let mut receipt2 = receipt0.clone();
        let mut receipt3 = receipt0.clone();
        let mut receipt4 = receipt0.clone();
        let mut receipt5 = receipt0.clone();
        receipt0.events = vec![Event {
            data: vec![EventData(starkhash_bytes!(b"event 0 data"))],
            from_address: ContractAddress::new_or_panic(starkhash_bytes!(b"event 0 from addr")),
            keys: vec![EventKey(starkhash_bytes!(b"event 0 key"))],
        }];
        receipt1.transaction_hash = txn1_hash;
        receipt2.transaction_hash = txn2_hash;
        receipt3.transaction_hash = txn3_hash;
        receipt4.transaction_hash = txn4_hash;
        receipt5.transaction_hash = txn5_hash;
        let transaction_data0 = [(txn0, receipt0)];
        let transaction_data1 = [(txn1, receipt1), (txn2, receipt2)];
        let transaction_data2 = [(txn3, receipt3), (txn4, receipt4), (txn5, receipt5)];
        StarknetTransactionsTable::upsert(&db_txn, block0.hash, block0.number, &transaction_data0)
            .unwrap();
        StarknetTransactionsTable::upsert(&db_txn, block1.hash, block1.number, &transaction_data1)
            .unwrap();
        StarknetTransactionsTable::upsert(&db_txn, block2.hash, block2.number, &transaction_data2)
            .unwrap();

        db_txn.commit().unwrap();
        storage
    }

    /// Creates [PendingData] which correctly links to the provided [Storage].
    ///
    /// i.e. the pending block's parent hash will be the latest block's hash from storage,
    /// and similarly for the pending state diffs state root.
    async fn create_pending_data(storage: Storage) -> PendingData {
        use crate::core::StorageValue;
        use crate::sequencer::reply::transaction::DeployTransaction;
        use crate::sequencer::reply::transaction::Transaction;

        let storage2 = storage.clone();
        let latest = tokio::task::spawn_blocking(move || {
            let mut db = storage2.connection().unwrap();
            let tx = db.transaction().unwrap();

            use crate::storage::StarknetBlocksBlockId;
            StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
                .unwrap()
                .expect("Storage should contain a latest block")
        })
        .await
        .unwrap();

        let transactions: Vec<Transaction> = vec![
            InvokeTransaction {
                calldata: vec![],
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(
                    b"pending contract addr 0"
                )),
                entry_point_selector: EntryPoint(starkhash_bytes!(b"entry point 0")),
                entry_point_type: EntryPointType::External,
                max_fee: Call::DEFAULT_MAX_FEE,
                signature: vec![],
                transaction_hash: StarknetTransactionHash(starkhash_bytes!(b"pending tx hash 0")),
            }
            .into(),
            DeployTransaction {
                contract_address: ContractAddress::new_or_panic(starkhash!("01122355")),
                contract_address_salt: ContractAddressSalt(starkhash_bytes!(b"salty")),
                class_hash: ClassHash(starkhash_bytes!(b"pending class hash 1")),
                constructor_calldata: vec![],
                transaction_hash: StarknetTransactionHash(starkhash_bytes!(b"pending tx hash 1")),
            }
            .into(),
        ];

        let transaction_receipts = vec![
            Receipt {
                actual_fee: None,
                events: vec![
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(starkhash!("abcddddddd")),
                        keys: vec![EventKey(starkhash_bytes!(b"pending key"))],
                    },
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(starkhash!("abcddddddd")),
                        keys: vec![EventKey(starkhash_bytes!(b"pending key"))],
                    },
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(starkhash!("abcaaaaaaa")),
                        keys: vec![EventKey(starkhash_bytes!(b"pending key 2"))],
                    },
                ],
                execution_resources: ExecutionResources {
                    builtin_instance_counter: BuiltinInstanceCounter::Empty(
                        EmptyBuiltinInstanceCounter {},
                    ),
                    n_memory_holes: 0,
                    n_steps: 0,
                },
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: vec![],
                transaction_hash: transactions[0].hash(),
                transaction_index: StarknetTransactionIndex::new_or_panic(0),
            },
            Receipt {
                actual_fee: None,
                events: vec![],
                execution_resources: ExecutionResources {
                    builtin_instance_counter: BuiltinInstanceCounter::Empty(
                        EmptyBuiltinInstanceCounter {},
                    ),
                    n_memory_holes: 0,
                    n_steps: 0,
                },
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: vec![],
                transaction_hash: transactions[1].hash(),
                transaction_index: StarknetTransactionIndex::new_or_panic(1),
            },
        ];

        let block = crate::sequencer::reply::PendingBlock {
            gas_price: GasPrice::from_be_slice(b"gas price").unwrap(),
            parent_hash: latest.hash,
            sequencer_address: SequencerAddress(starkhash_bytes!(b"pending sequencer address")),
            status: crate::sequencer::reply::Status::Pending,
            timestamp: StarknetBlockTimestamp::new_or_panic(1234567),
            transaction_receipts,
            transactions,
            starknet_version: Some("pending version".to_owned()),
        };

        use crate::sequencer::reply as seq_reply;
        let deployed_contracts = vec![
            seq_reply::state_update::DeployedContract {
                address: ContractAddress::new_or_panic(starkhash_bytes!(
                    b"pending contract 0 address"
                )),
                class_hash: ClassHash(starkhash_bytes!(b"pending contract 0 hash")),
            },
            seq_reply::state_update::DeployedContract {
                address: ContractAddress::new_or_panic(starkhash_bytes!(
                    b"pending contract 1 address"
                )),
                class_hash: ClassHash(starkhash_bytes!(b"pending contract 1 hash")),
            },
        ];
        let storage_diffs = [(
            deployed_contracts[1].address,
            vec![
                seq_reply::state_update::StorageDiff {
                    key: StorageAddress::new_or_panic(starkhash_bytes!(b"pending storage key 0")),
                    value: StorageValue(starkhash_bytes!(b"pending storage value 0")),
                },
                seq_reply::state_update::StorageDiff {
                    key: StorageAddress::new_or_panic(starkhash_bytes!(b"pending storage key 1")),
                    value: StorageValue(starkhash_bytes!(b"pending storage value 1")),
                },
            ],
        )]
        .into_iter()
        .collect();

        let state_diff = crate::sequencer::reply::state_update::StateDiff {
            storage_diffs,
            deployed_contracts,
            declared_contracts: Vec::new(),
        };

        // The class definitions must be inserted into the database.
        let deployed_contracts = state_diff.deployed_contracts.clone();
        let deploy_storage = storage.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = deploy_storage.connection().unwrap();
            let tx = db.transaction().unwrap();
            let compressed_definition = include_bytes!("../fixtures/contract_definition.json.zst");
            for deployed in deployed_contracts {
                // The abi, bytecode, definition are expected to be zstd compressed, and are
                // checked for the magic bytes.
                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
                let contract = crate::state::CompressedContract {
                    abi: zstd_magic.clone(),
                    bytecode: zstd_magic.clone(),
                    definition: compressed_definition.to_vec(),
                    hash: deployed.class_hash,
                };
                ContractCodeTable::insert_compressed(&tx, &contract).unwrap();
            }
            tx.commit().unwrap();
        })
        .await
        .unwrap();

        // Use a roll-back transaction to calculate pending state root.
        // This must not be committed as we don't want to inject the diff
        // into storage, but do require database IO to determine the root.
        //
        // Load from latest block in storage's root.
        let state_diff2 = state_diff.clone();
        let pending_root = tokio::task::spawn_blocking(move || {
            let mut db = storage.connection().unwrap();
            let tmp_tx = db.transaction().unwrap();
            let mut global_tree = GlobalStateTree::load(&tmp_tx, latest.root).unwrap();
            for deployed in state_diff2.deployed_contracts {
                ContractsTable::upsert(&tmp_tx, deployed.address, deployed.class_hash).unwrap();
            }
            for (contract_address, storage_diffs) in state_diff2.storage_diffs {
                use crate::state::update_contract_state;
                let state_hash =
                    update_contract_state(contract_address, &storage_diffs, &global_tree, &tmp_tx)
                        .unwrap();
                global_tree.set(contract_address, state_hash).unwrap();
            }
            let pending_root = global_tree.apply().unwrap();
            tmp_tx.rollback().unwrap();
            pending_root
        })
        .await
        .unwrap();

        let state_update = crate::sequencer::reply::StateUpdate {
            // This must be `None` for a pending state update.
            block_hash: None,
            new_root: pending_root,
            old_root: latest.root,
            state_diff,
        };

        let pending_data = PendingData::default();
        pending_data
            .set(Arc::new(block), Arc::new(state_update))
            .await;
        pending_data
    }

    mod get_block {
        use super::*;
        use crate::rpc::types::reply::{Block, Transactions};
        use crate::{
            core::{StarknetBlockHash, StarknetBlockNumber},
            sequencer::reply::PendingBlock,
        };
        use pretty_assertions::assert_eq;
        use stark_hash::StarkHash;

        #[tokio::test]
        async fn genesis_by_hash() {
            let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
            let genesis_id = BlockId::Hash(genesis_hash);
            let params = rpc_params!(genesis_id);

            check_result(params, move |block, _| {
                assert_eq!(block.block_number, Some(StarknetBlockNumber::GENESIS));
                assert_eq!(block.block_hash, Some(genesis_hash));
            })
            .await;
        }

        async fn check_result<F: Fn(&Block, &PendingBlock)>(
            params: Option<ParamsSer<'_>>,
            check_fn: F,
        ) {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let block = client(addr)
                .request::<Block>("starknet_getBlockWithTxHashes", params.clone())
                .await
                .unwrap();

            assert_matches!(block.transactions, Transactions::HashesOnly(_) => {});
            let pending_block = pending_data.block().await.unwrap();
            check_fn(&block, &pending_block);

            let block = client(addr)
                .request::<Block>("starknet_getBlockWithTxs", params)
                .await
                .unwrap();
            assert_matches!(block.transactions, Transactions::Full(_) => {});
            let pending_block = pending_data.block().await.unwrap();
            check_fn(&block, &pending_block);
        }

        #[tokio::test]
        async fn genesis_by_number() {
            let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
            let genesis_id = BlockId::Number(StarknetBlockNumber::GENESIS);
            let params = rpc_params!(genesis_id);

            check_result(params, move |block, _| {
                assert_eq!(block.block_number, Some(StarknetBlockNumber::GENESIS));
                assert_eq!(block.block_hash, Some(genesis_hash));
            })
            .await;
        }

        mod latest {
            use super::*;

            mod positional_args {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn all() {
                    let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
                    let params = rpc_params!(BlockId::Latest);

                    check_result(params, move |block, _| {
                        assert_eq!(
                            block.block_number,
                            Some(StarknetBlockNumber::new_or_panic(2))
                        );
                        assert_eq!(block.block_hash, Some(latest_hash));
                    })
                    .await;
                }
            }

            mod named_args {
                use super::*;
                use pretty_assertions::assert_eq;
                use serde_json::json;

                #[tokio::test]
                async fn all() {
                    let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
                    let params = by_name([("block_id", json!("latest"))]);

                    check_result(params, move |block, _| {
                        assert_eq!(
                            block.block_number,
                            Some(StarknetBlockNumber::new_or_panic(2))
                        );
                        assert_eq!(block.block_hash, Some(latest_hash));
                    })
                    .await;
                }
            }
        }

        #[tokio::test]
        async fn pending() {
            let params = rpc_params!(BlockId::Pending);
            check_result(params, move |block, pending| {
                assert_eq!(block.parent_hash, pending.parent_hash);
            })
            .await;
        }

        #[tokio::test]
        async fn invalid_block_id() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(BlockId::Hash(StarknetBlockHash(StarkHash::ZERO)));
            let error = client(addr)
                .request::<Block>("starknet_getBlockWithTxHashes", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::InvalidBlockId, error);
        }
    }

    mod get_state_update {
        use crate::rpc::{test_setup::Test, types::reply::ErrorCode};
        use crate::storage::fixtures::init::with_n_state_updates;
        use serde_json::json;

        #[tokio::test]
        async fn happy_path_and_starkware_errors() {
            Test::new("starknet_getStateUpdate", line!())
                .with_storage(|tx| with_n_state_updates(tx, 3))
                .with_params_json(json!([
                    {"block_hash":"0x0"},
                    {"block_hash":"0x1"},
                    {"block_number":0},
                    {"block_number":1},
                    "latest",
                    {"block_hash":"0xdead"},
                    {"block_number":9999}
                ]))
                .map_err_to_starkware_error_code()
                .map_expected(|in_storage| {
                    let in_storage = in_storage.collect::<Vec<_>>();
                    vec![
                        Ok(in_storage[0].clone()),
                        Ok(in_storage[1].clone()),
                        Ok(in_storage[0].clone()),
                        Ok(in_storage[1].clone()),
                        Ok(in_storage[2].clone()),
                        Err(ErrorCode::InvalidBlockId),
                        Err(ErrorCode::InvalidBlockId),
                    ]
                })
                .run()
                .await;
        }

        #[tokio::test]
        #[ignore = "implement after local pending is merged into master"]
        async fn pending() {
            todo!()
        }
    }

    mod get_storage_at {
        use super::*;
        use crate::{
            core::StorageValue,
            rpc::types::{BlockHashOrTag, Tag},
        };
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn key_is_field_modulus() {
            use std::str::FromStr;

            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
                web3::types::H256::from_str(
                    "0x0800000000000011000000000000000000000000000000000000000000000001"
                )
                .unwrap(),
                BlockId::Latest
            );
            client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn key_is_less_than_modulus_but_252_bits() {
            use std::str::FromStr;

            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
                web3::types::H256::from_str(
                    "0x0800000000000000000000000000000000000000000000000000000000000000"
                )
                .unwrap(),
                BlockId::Latest
            );
            client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn non_existent_contract_address() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                ContractAddress::new_or_panic(starkhash_bytes!(b"nonexistent")),
                StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0")),
                BlockId::Latest
            );
            let error = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::ContractNotFound, error);
        }

        #[tokio::test]
        async fn pre_deploy_block_hash() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1")),
                StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0")),
                BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"genesis")))
            );
            let error = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::ContractNotFound, error);
        }

        #[tokio::test]
        async fn non_existent_block_hash() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1")),
                StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0")),
                BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"nonexistent")))
            );
            let error = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::InvalidBlockId, error);
        }

        #[tokio::test]
        async fn deployment_block() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1")),
                StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0")),
                BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"block 1")))
            );
            let value = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
            assert_eq!(value.0, starkhash_bytes!(b"storage value 1"));
        }

        mod latest_block {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn positional_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1")),
                    StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0")),
                    BlockId::Latest
                );
                let value = client(addr)
                    .request::<StorageValue>("starknet_getStorageAt", params)
                    .await
                    .unwrap();
                assert_eq!(value.0, starkhash_bytes!(b"storage value 2"));
            }

            #[tokio::test]
            async fn named_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = by_name([
                    ("contract_address", json! {starkhash_bytes!(b"contract 1")}),
                    ("key", json! {starkhash_bytes!(b"storage addr 0")}),
                    ("block_id", json! {"latest"}),
                ]);
                let value = client(addr)
                    .request::<StorageValue>("starknet_getStorageAt", params)
                    .await
                    .unwrap();
                assert_eq!(value.0, starkhash_bytes!(b"storage value 2"));
            }
        }

        #[tokio::test]
        async fn pending_block() {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            // Pick an arbitrary pending storage update to query.
            let state_update = pending_data.state_update().await.unwrap();
            let (contract, updates) = state_update.state_diff.storage_diffs.iter().next().unwrap();
            let storage_key = updates[0].key;
            let storage_val = updates[0].value;

            let params = rpc_params!(contract, storage_key, BlockHashOrTag::Tag(Tag::Pending));
            let result = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
            assert_eq!(result, storage_val);
        }
    }

    mod get_transaction_by_hash {
        use super::*;
        use crate::rpc::types::reply::Transaction;
        use pretty_assertions::assert_eq;

        mod accepted {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn positional_args() {
                let storage = setup_storage();
                let hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(hash);
                let transaction = client(addr)
                    .request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
                assert_eq!(transaction.hash(), hash);
            }

            #[tokio::test]
            async fn named_args() {
                let storage = setup_storage();
                let hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = by_name([("transaction_hash", json!(hash))]);
                let transaction = client(addr)
                    .request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
                assert_eq!(transaction.hash(), hash);
            }

            #[tokio::test]
            async fn pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                // Select an arbitrary pending transaction to query.
                let expected = pending_data.block().await.unwrap();
                let expected: Transaction = expected.transactions.first().unwrap().into();

                let params = rpc_params!(expected.hash());
                let transaction = client(addr)
                    .request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
                assert_eq!(transaction, expected);
            }
        }

        #[tokio::test]
        async fn invalid_hash() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(INVALID_TX_HASH);
            let error = client(addr)
                .request::<Transaction>("starknet_getTransactionByHash", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::types::reply::ErrorCode::InvalidTransactionHash,
                error
            );
        }
    }

    mod get_transaction_by_block_id_and_index {
        use super::*;
        use crate::rpc::types::reply::Transaction;
        use pretty_assertions::assert_eq;

        async fn check_result<F: Fn(&Transaction)>(params: Option<ParamsSer<'_>>, check_fn: F) {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let txn = client(addr)
                .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                .await
                .unwrap();

            check_fn(&txn);
        }

        #[tokio::test]
        async fn genesis_by_hash() {
            let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
            let genesis_id = BlockId::Hash(genesis_hash);
            let params = rpc_params!(genesis_id, 0);
            check_result(params, move |txn| {
                assert_eq!(
                    txn.hash(),
                    StarknetTransactionHash(starkhash_bytes!(b"txn 0"))
                )
            })
            .await;
        }

        #[tokio::test]
        async fn genesis_by_number() {
            let genesis_id = BlockId::Number(StarknetBlockNumber::GENESIS);
            let params = rpc_params!(genesis_id, 0);
            check_result(params, move |txn| {
                assert_eq!(
                    txn.hash(),
                    StarknetTransactionHash(starkhash_bytes!(b"txn 0"))
                )
            })
            .await;
        }

        mod latest {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(BlockId::Latest, 0);
                check_result(params, move |txn| {
                    assert_eq!(
                        txn.hash(),
                        StarknetTransactionHash(starkhash_bytes!(b"txn 3"))
                    );
                })
                .await;
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([("block_id", json!("latest")), ("index", json!(0))]);
                check_result(params, move |txn| {
                    assert_eq!(
                        txn.hash(),
                        StarknetTransactionHash(starkhash_bytes!(b"txn 3"))
                    );
                })
                .await;
            }
        }

        #[tokio::test]
        async fn pending() {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            const TX_IDX: usize = 1;
            let expected = pending_data.block().await.unwrap();
            assert!(TX_IDX <= expected.transactions.len());
            let expected: Transaction = expected.transactions.get(TX_IDX).unwrap().into();

            let params = rpc_params!(BlockId::Pending, TX_IDX);
            let transaction = client(addr)
                .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                .await
                .unwrap();

            assert_eq!(transaction, expected);
        }

        #[tokio::test]
        async fn invalid_block() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(BlockId::Hash(StarknetBlockHash(StarkHash::ZERO)), 0);
            let error = client(addr)
                .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::InvalidBlockId, error);
        }

        #[tokio::test]
        async fn invalid_transaction_index() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
            let genesis_id = BlockId::Hash(genesis_hash);
            let params = rpc_params!(genesis_id, 123);
            let error = client(addr)
                .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::types::reply::ErrorCode::InvalidTransactionIndex,
                error
            );
        }
    }

    mod get_transaction_receipt {
        use super::*;
        use crate::rpc::types::reply::TransactionReceipt;
        use pretty_assertions::assert_eq;

        mod accepted {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn positional_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let txn_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                let params = rpc_params!(txn_hash);
                let receipt = client(addr)
                    .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                    .await
                    .unwrap();
                assert_eq!(receipt.hash(), txn_hash);
                assert_matches!(
                    receipt,
                    TransactionReceipt::Invoke(invoke) => assert_eq!(
                        invoke.events[0].keys[0],
                        EventKey(starkhash_bytes!(b"event 0 key"))
                    )
                );
            }

            #[tokio::test]
            async fn named_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let txn_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                let params = by_name([("transaction_hash", json!(txn_hash))]);
                let receipt = client(addr)
                    .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                    .await
                    .unwrap();
                assert_eq!(receipt.hash(), txn_hash);
                assert_matches!(
                    receipt,
                    TransactionReceipt::Invoke(invoke) => assert_eq!(
                        invoke.events[0].keys[0],
                        EventKey(starkhash_bytes!(b"event 0 key"))
                    )
                );
            }

            #[tokio::test]
            async fn pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                // Select an arbitrary pending transaction to query.
                let expected = pending_data.block().await.unwrap();
                let expected = expected.transaction_receipts.first().unwrap();

                let params = rpc_params!(expected.transaction_hash);
                let receipt = client(addr)
                    .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                    .await
                    .unwrap();
                // Only asserting the hash because translating from Sequencer receipt to RPC receipt is pita.
                assert_eq!(receipt.hash(), expected.transaction_hash);
                assert_matches!(
                    receipt,
                    TransactionReceipt::PendingInvoke(invoke) => {
                        assert_eq!(invoke.common.actual_fee, Fee(Default::default()));
                        assert_eq!(invoke.events.len(), 3);
                    }
                );
            }
        }

        #[tokio::test]
        async fn invalid() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let txn_hash = StarknetTransactionHash(starkhash_bytes!(b"not found"));
            let params = rpc_params!(txn_hash);
            let error = client(addr)
                .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::types::reply::ErrorCode::InvalidTransactionHash,
                error
            );
        }
    }

    mod get_class {
        use super::contract_setup::setup_class_and_contract;
        use super::*;
        use crate::core::ContractClass;
        use crate::rpc::types::reply::ErrorCode;

        mod positional_args {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn returns_invalid_contract_class_hash_for_nonexistent_class() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(INVALID_CLASS_HASH);
                let error = client(addr)
                    .request::<ContractClass>("starknet_getClass", params)
                    .await
                    .unwrap_err();
                assert_eq!(ErrorCode::InvalidContractClassHash, error);
            }

            #[tokio::test]
            async fn returns_program_and_entry_points_for_known_class() {
                let storage = setup_storage();

                let mut conn = storage.connection().unwrap();
                let transaction = conn.transaction().unwrap();
                let (_contract_address, class_hash, program, entry_points) =
                    setup_class_and_contract(&transaction).unwrap();
                transaction.commit().unwrap();

                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = rpc_params!(class_hash);
                let class = client(addr)
                    .request::<ContractClass>("starknet_getClass", params)
                    .await
                    .unwrap();

                assert_eq!(class.entry_points_by_type, entry_points);
                assert_eq!(class.program, program);
            }
        }

        mod named_args {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn returns_program_and_entry_points_for_known_class() {
                let storage = setup_storage();

                let mut conn = storage.connection().unwrap();
                let transaction = conn.transaction().unwrap();
                let (_contract_address, class_hash, program, entry_points) =
                    setup_class_and_contract(&transaction).unwrap();
                transaction.commit().unwrap();

                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = by_name([("class_hash", json!(class_hash))]);
                let class = client(addr)
                    .request::<ContractClass>("starknet_getClass", params)
                    .await
                    .unwrap();

                assert_eq!(class.entry_points_by_type, entry_points);
                assert_eq!(class.program, program);
            }
        }
    }

    mod get_class_hash_at {
        use super::*;

        mod positional_args {
            use super::*;
            use crate::rpc::types::reply::ErrorCode;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn returns_contract_not_found_for_nonexistent_contract() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(BlockId::Latest, INVALID_CONTRACT_ADDR);
                let error = client(addr)
                    .request::<ClassHash>("starknet_getClassHashAt", params)
                    .await
                    .unwrap_err();
                assert_eq!(ErrorCode::ContractNotFound, error);
            }

            #[tokio::test]
            async fn returns_class_hash_for_existing_contract() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let contract_address =
                    ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
                let params = rpc_params!(BlockId::Latest, contract_address);
                let class_hash = client(addr)
                    .request::<ClassHash>("starknet_getClassHashAt", params)
                    .await
                    .unwrap();
                let expected_class_hash = ClassHash(starkhash_bytes!(b"class 1 hash"));
                assert_eq!(class_hash, expected_class_hash);
            }

            #[tokio::test]
            async fn returns_not_found_for_existing_contract_that_is_not_yet_deployed() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let contract_address =
                    ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
                let params = rpc_params!(
                    BlockId::Number(StarknetBlockNumber::GENESIS),
                    contract_address
                );
                let error = client(addr)
                    .request::<ClassHash>("starknet_getClassHashAt", params)
                    .await
                    .unwrap_err();
                assert_eq!(ErrorCode::ContractNotFound, error);
            }

            #[tokio::test]
            async fn pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let contract = pending_data.state_update().await.unwrap();
                let contract = contract.state_diff.deployed_contracts.first().unwrap();

                let params = rpc_params!(BlockId::Pending, contract.address);
                let class_hash = client(addr)
                    .request::<ClassHash>("starknet_getClassHashAt", params)
                    .await
                    .unwrap();
                assert_eq!(class_hash, contract.class_hash);
            }
        }

        mod named_args {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn returns_class_hash_for_existing_contract() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let contract_address =
                    ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
                let params = by_name([
                    ("block_id", json!("latest")),
                    ("contract_address", json!(contract_address)),
                ]);
                let class_hash = client(addr)
                    .request::<ClassHash>("starknet_getClassHashAt", params)
                    .await
                    .unwrap();
                let expected_class_hash = ClassHash(starkhash_bytes!(b"class 1 hash"));
                assert_eq!(class_hash, expected_class_hash);
            }
        }
    }

    mod get_class_at {
        use super::contract_setup::setup_class_and_contract;
        use super::*;
        use crate::core::ContractClass;
        use crate::rpc::types::reply::ErrorCode;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_contract_address() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(BlockId::Latest, INVALID_CONTRACT_ADDR);
            let error = client(addr)
                .request::<ContractClass>("starknet_getClassAt", params)
                .await
                .unwrap_err();
            assert_eq!(ErrorCode::ContractNotFound, error);
        }

        #[tokio::test]
        async fn returns_not_found_if_we_dont_know_about_the_contract() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let not_found = client(addr)
                .request::<ContractClass>(
                    "starknet_getClassAt",
                    rpc_params!(
                        BlockId::Latest,
                        "0x4ae0618c330c59559a59a27d143dd1c07cd74cf4e5e5a7cd85d53c6bf0e89dc"
                    ),
                )
                .await
                .unwrap_err();

            assert_eq!(ErrorCode::ContractNotFound, not_found);
        }

        #[tokio::test]
        async fn returns_program_and_entry_points_for_known_class() {
            use crate::core::ContractClass;
            use futures::stream::TryStreamExt;

            let storage = setup_storage();
            let mut conn = storage.connection().unwrap();
            let transaction = conn.transaction().unwrap();
            let (contract_address, _class_hash, program, entry_points) =
                setup_class_and_contract(&transaction).unwrap();
            transaction.commit().unwrap();

            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let client = client(addr);

            // both parameters, these used to be separate tests
            let rets = [
                rpc_params!(BlockId::Latest, contract_address),
                by_name([
                    ("block_id", json!("latest")),
                    ("contract_address", json!(contract_address)),
                ]),
            ]
            .into_iter()
            .map(|arg| client.request::<ContractClass>("starknet_getClassAt", arg))
            .collect::<futures::stream::FuturesOrdered<_>>()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();

            assert_eq!(rets.len(), 2);

            assert_eq!(rets[0], rets[1]);
            assert_eq!(rets[0].entry_points_by_type, entry_points);
            assert_eq!(rets[0].program, program);
        }

        #[tokio::test]
        async fn returns_not_found_for_existing_contract_that_is_not_yet_deployed() {
            use crate::core::ContractClass;

            let storage = setup_storage();
            let mut conn = storage.connection().unwrap();
            let transaction = conn.transaction().unwrap();
            let (contract_address, _class_hash, _program, _entry_points) =
                setup_class_and_contract(&transaction).unwrap();
            transaction.commit().unwrap();

            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let not_found = client(addr)
                .request::<ContractClass>(
                    "starknet_getClassAt",
                    rpc_params!(
                        BlockId::Number(StarknetBlockNumber::new_or_panic(2)),
                        contract_address
                    ),
                )
                .await
                .unwrap_err();

            assert_eq!(ErrorCode::ContractNotFound, not_found);
        }

        #[tokio::test]
        async fn pending() {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let contract = pending_data.state_update().await.unwrap();
            let contract = contract.state_diff.deployed_contracts.first().unwrap();

            let params = rpc_params!(BlockId::Pending, contract.address);
            client(addr)
                .request::<ContractClass>("starknet_getClassAt", params)
                .await
                .unwrap();
        }
    }

    mod contract_setup {
        use crate::{
            core::StorageValue, sequencer::reply::state_update::StorageDiff, starkhash,
            state::update_contract_state, storage::StarknetBlocksBlockId,
        };

        use super::*;
        use anyhow::Context;
        use bytes::Bytes;
        use flate2::{write::GzEncoder, Compression};
        use pretty_assertions::assert_eq;

        pub fn setup_class_and_contract(
            transaction: &rusqlite::Transaction<'_>,
        ) -> anyhow::Result<(ContractAddress, ClassHash, String, serde_json::Value)> {
            let contract_definition = include_bytes!("../fixtures/contract_definition.json.zst");
            let buffer = zstd::decode_all(std::io::Cursor::new(contract_definition))?;
            let contract_definition = Bytes::from(buffer);

            let contract_address = ContractAddress::new_or_panic(starkhash!(
                "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
            ));
            let expected_hash =
                starkhash!("050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b");

            let (abi, bytecode, hash) =
                crate::state::class_hash::extract_abi_code_hash(&*contract_definition)?;

            assert_eq!(hash.0, expected_hash);

            let (program, entry_points) =
                crate::state::class_hash::extract_program_and_entry_points_by_type(
                    &*contract_definition,
                )?;

            crate::storage::ContractCodeTable::insert(
                transaction,
                hash,
                &abi,
                &bytecode,
                &contract_definition,
            )
            .context("Deploy testing contract")?;

            crate::storage::ContractsTable::upsert(transaction, contract_address, hash)?;

            let mut compressor = GzEncoder::new(Vec::new(), Compression::fast());
            serde_json::to_writer(&mut compressor, &program)?;
            let program = compressor.finish()?;

            let program = base64::encode(program);

            // insert a new block whose state includes the contract
            let storage_addr = StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr"));
            let storage_diff = vec![StorageDiff {
                key: storage_addr,
                value: StorageValue(starkhash_bytes!(b"storage_value")),
            }];
            let block2 = StarknetBlocksTable::get(
                transaction,
                StarknetBlocksBlockId::Number(StarknetBlockNumber::new_or_panic(2)),
            )
            .unwrap()
            .unwrap();
            let mut global_tree = GlobalStateTree::load(transaction, block2.root).unwrap();
            let contract_state_hash =
                update_contract_state(contract_address, &storage_diff, &global_tree, transaction)
                    .unwrap();
            global_tree
                .set(contract_address, contract_state_hash)
                .unwrap();

            let block3 = StarknetBlock {
                number: StarknetBlockNumber::new_or_panic(3),
                hash: StarknetBlockHash(starkhash_bytes!(b"block 3 hash")),
                root: global_tree.apply().unwrap(),
                timestamp: StarknetBlockTimestamp::new_or_panic(3),
                gas_price: GasPrice::from(3),
                sequencer_address: SequencerAddress(starkhash_bytes!(&[3u8])),
            };

            StarknetBlocksTable::insert(transaction, &block3, None).unwrap();

            Ok((contract_address, hash, program, entry_points))
        }
    }

    mod get_block_transaction_count {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn genesis() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(BlockId::Hash(StarknetBlockHash(starkhash_bytes!(
                b"genesis"
            ))));
            let count = client(addr)
                .request::<u64>("starknet_getBlockTransactionCount", params)
                .await
                .unwrap();
            assert_eq!(count, 1);
        }

        mod latest {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn positional_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(BlockId::Latest);
                let count = client(addr)
                    .request::<u64>("starknet_getBlockTransactionCount", params)
                    .await
                    .unwrap();
                assert_eq!(count, 3);
            }

            #[tokio::test]
            async fn named_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = by_name([("block_id", json!("latest"))]);
                let count = client(addr)
                    .request::<u64>("starknet_getBlockTransactionCount", params)
                    .await
                    .unwrap();
                assert_eq!(count, 3);
            }
        }

        #[tokio::test]
        async fn pending() {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let expected = pending_data.block().await.unwrap().transactions.len();
            let params = rpc_params!(BlockId::Pending);
            let count = client(addr)
                .request::<u64>("starknet_getBlockTransactionCount", params)
                .await
                .unwrap();
            assert_eq!(count, expected as u64);
        }

        #[tokio::test]
        async fn invalid_hash() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(BlockId::Hash(StarknetBlockHash(StarkHash::ZERO)));
            let error = client(addr)
                .request::<u64>("starknet_getBlockTransactionCount", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::InvalidBlockId, error);
        }

        #[tokio::test]
        async fn invalid_number() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(BlockId::Number(StarknetBlockNumber::new_or_panic(123)));
            let error = client(addr)
                .request::<u64>("starknet_getBlockTransactionCount", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::InvalidBlockId, error);
        }
    }

    mod pending_transactions {
        use super::*;
        use crate::rpc::types::reply::Transaction;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn with_pending() {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let expected = pending_data
                .block()
                .await
                .unwrap()
                .transactions
                .clone()
                .into_iter()
                .map(Transaction::from)
                .collect::<Vec<_>>();

            let transactions = client(addr)
                .request::<Vec<Transaction>>("starknet_pendingTransactions", rpc_params![])
                .await
                .unwrap();

            assert_eq!(transactions, expected);
        }

        #[tokio::test]
        async fn defaults_to_latest() {
            let storage = setup_storage();
            // empty pending data, which should result in `starknet_pendingTransactions` using
            // the `latest` transactions instead.
            let pending_data = PendingData::default();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage.clone(), sequencer, Chain::Goerli, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let mut conn = storage.connection().unwrap();
            let db_tx = conn.transaction().unwrap();
            let expected = StarknetTransactionsTable::get_transactions_for_latest_block(&db_tx)
                .unwrap()
                .into_iter()
                .map(Transaction::from)
                .collect::<Vec<_>>();

            let transactions = client(addr)
                .request::<Vec<Transaction>>("starknet_pendingTransactions", rpc_params![])
                .await
                .unwrap();

            assert_eq!(transactions, expected);
        }
    }

    #[tokio::test]
    async fn get_nonce() {
        use crate::core::ContractNonce;

        let storage = setup_storage();
        let sequencer = Client::new(Chain::Goerli).unwrap();
        let sync_state = Arc::new(SyncState::default());
        let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state.clone());
        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

        // This contract is created in `setup_storage`
        let valid_contract = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0"));

        // With no version set yet -- this occurs when `getNonce` is called before
        // we have received a `latest` update from the gateway at pathfinder startup.
        // Unlikely to occur, but worth testing.
        client(addr)
            .request::<ContractNonce>("starknet_getNonce", rpc_params!(valid_contract))
            .await
            .expect_err("unset version should error");

        // Nonces pre-0.10.0 have a default value of 0.
        *sync_state.version.write().await = Some("0.9.1".to_string());
        let version = client(addr)
            .request::<ContractNonce>("starknet_getNonce", rpc_params!(valid_contract))
            .await
            .expect("pre-0.10.0 version should succeed");
        assert_eq!(version, ContractNonce(StarkHash::ZERO));

        // Invalid contract should error.
        let invalid_contract = ContractAddress::new_or_panic(starkhash_bytes!(b"invalid"));
        let error = client(addr)
            .request::<ContractNonce>("starknet_getNonce", rpc_params!(invalid_contract))
            .await
            .expect_err("invalid contract should error");
        let expected = crate::rpc::types::reply::ErrorCode::ContractNotFound;
        assert_eq!(expected, error);

        // Versions post 0.10.0 are unsupported currently.
        *sync_state.version.write().await = Some("0.10.0".to_string());
        client(addr)
            .request::<ContractNonce>("starknet_getNonce", rpc_params!(valid_contract))
            .await
            .expect_err("post-0.10.0 version should fail");
    }

    // FIXME: these tests are largely defunct because they have never used ext_py, and handle
    // parsing issues.
    mod call {
        use super::*;
        use crate::{
            core::{CallParam, CallResultValue},
            rpc::types::request::Call,
            starkhash,
        };
        use pretty_assertions::assert_eq;

        const INVOKE_CONTRACT_BLOCK_ID: BlockId = BlockId::Hash(StarknetBlockHash(starkhash!(
            "03871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"
        )));
        const PRE_DEPLOY_CONTRACT_BLOCK_ID: BlockId = BlockId::Hash(StarknetBlockHash(starkhash!(
            "05ef884a311df4339c8df791ce19bf305d7cf299416666b167bc56dd2d1f435f"
        )));
        const INVALID_BLOCK_ID: BlockId = BlockId::Hash(StarknetBlockHash(starkhash!(
            "06d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"
        )));
        const CALL_DATA: [CallParam; 1] = [CallParam(starkhash!("1234"))];

        #[ignore = "no longer works without setting up ext_py"]
        #[tokio::test]
        async fn latest_invoked_block() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.to_vec(),
                    contract_address: VALID_CONTRACT_ADDR,
                    entry_point_selector: VALID_ENTRY_POINT,
                    signature: Default::default(),
                    max_fee: Call::DEFAULT_MAX_FEE,
                    version: Call::DEFAULT_VERSION,
                },
                INVOKE_CONTRACT_BLOCK_ID
            );
            client(addr)
                .request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap();
        }

        mod latest_block {
            use super::*;

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn positional_args() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.to_vec(),
                        contract_address: VALID_CONTRACT_ADDR,
                        entry_point_selector: VALID_ENTRY_POINT,
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                    },
                    BlockId::Latest
                );
                client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap();
            }

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn named_args() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = by_name([
                    (
                        "request",
                        json!({
                            "calldata": &CALL_DATA,
                            "contract_address": VALID_CONTRACT_ADDR,
                            "entry_point_selector": VALID_ENTRY_POINT,
                        }),
                    ),
                    ("block_id", json!("latest")),
                ]);
                client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap();
            }
        }

        #[ignore = "no longer works without setting up ext_py"]
        #[tokio::test]
        async fn pending_block() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.to_vec(),
                    contract_address: VALID_CONTRACT_ADDR,
                    entry_point_selector: VALID_ENTRY_POINT,
                    signature: Default::default(),
                    max_fee: Call::DEFAULT_MAX_FEE,
                    version: Call::DEFAULT_VERSION,
                },
                BlockId::Pending
            );
            client(addr)
                .request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap();
        }

        #[ignore = "no longer works without setting up ext_py"]
        #[tokio::test]
        async fn invalid_entry_point() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.to_vec(),
                    contract_address: VALID_CONTRACT_ADDR,
                    entry_point_selector: INVALID_ENTRY_POINT,
                    signature: Default::default(),
                    max_fee: Call::DEFAULT_MAX_FEE,
                    version: Call::DEFAULT_VERSION,
                },
                BlockId::Latest
            );
            let error = client(addr)
                .request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::types::reply::ErrorCode::InvalidMessageSelector,
                error
            );
        }

        #[ignore = "no longer works without setting up ext_py"]
        #[tokio::test]
        async fn invalid_contract_address() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.to_vec(),
                    contract_address: INVALID_CONTRACT_ADDR,
                    entry_point_selector: VALID_ENTRY_POINT,
                    signature: Default::default(),
                    max_fee: Call::DEFAULT_MAX_FEE,
                    version: Call::DEFAULT_VERSION,
                },
                BlockId::Latest
            );
            let error = client(addr)
                .request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::ContractNotFound, error);
        }

        #[ignore = "no longer works without setting up ext_py"]
        #[tokio::test]
        async fn invalid_call_data() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                Call {
                    calldata: vec![],
                    contract_address: VALID_CONTRACT_ADDR,
                    entry_point_selector: VALID_ENTRY_POINT,
                    signature: Default::default(),
                    max_fee: Call::DEFAULT_MAX_FEE,
                    version: Call::DEFAULT_VERSION,
                },
                BlockId::Latest
            );
            let error = client(addr)
                .request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::InvalidCallData, error);
        }

        #[ignore = "no longer works without setting up ext_py"]
        #[tokio::test]
        async fn uninitialized_contract() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.to_vec(),
                    contract_address: VALID_CONTRACT_ADDR,
                    entry_point_selector: VALID_ENTRY_POINT,
                    signature: Default::default(),
                    max_fee: Call::DEFAULT_MAX_FEE,
                    version: Call::DEFAULT_VERSION,
                },
                PRE_DEPLOY_CONTRACT_BLOCK_ID
            );
            let error = client(addr)
                .request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::ContractNotFound, error);
        }

        #[ignore = "no longer works without setting up ext_py"]
        #[tokio::test]
        async fn invalid_block_hash() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.to_vec(),
                    contract_address: VALID_CONTRACT_ADDR,
                    entry_point_selector: VALID_ENTRY_POINT,
                    signature: Default::default(),
                    max_fee: Call::DEFAULT_MAX_FEE,
                    version: Call::DEFAULT_VERSION,
                },
                INVALID_BLOCK_ID
            );
            let error = client(addr)
                .request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_eq!(crate::rpc::types::reply::ErrorCode::InvalidBlockId, error);
        }
    }

    #[tokio::test]
    async fn block_number() {
        let storage = setup_storage();
        let sequencer = Client::new(Chain::Goerli).unwrap();
        let sync_state = Arc::new(SyncState::default());
        let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
        let number = client(addr)
            .request::<u64>("starknet_blockNumber", rpc_params!())
            .await
            .unwrap();
        assert_eq!(number, 2);
    }

    #[tokio::test]
    async fn block_hash_and_number() {
        let storage = setup_storage();
        let sequencer = Client::new(Chain::Goerli).unwrap();
        let sync_state = Arc::new(SyncState::default());
        let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
        let latest = client(addr)
            .request::<BlockHashAndNumber>("starknet_blockHashAndNumber", rpc_params!())
            .await
            .unwrap();
        let expected = BlockHashAndNumber {
            hash: StarknetBlockHash(starkhash_bytes!(b"latest")),
            number: StarknetBlockNumber::new_or_panic(2),
        };
        assert_eq!(latest, expected);
    }

    #[tokio::test]
    async fn chain_id() {
        use futures::stream::StreamExt;

        assert_eq!(
            [Chain::Goerli, Chain::Mainnet]
                .iter()
                .map(|set_chain| async {
                    let storage = Storage::in_memory().unwrap();
                    let sequencer = Client::new(*set_chain).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, *set_chain, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let params = rpc_params!();
                    client(addr)
                        .request::<String>("starknet_chainId", params)
                        .await
                        .unwrap()
                })
                .collect::<futures::stream::FuturesOrdered<_>>()
                .collect::<Vec<_>>()
                .await,
            vec![
                format!("0x{}", hex::encode("SN_GOERLI")),
                format!("0x{}", hex::encode("SN_MAIN")),
            ]
        );
    }

    mod syncing {
        use crate::rpc::types::reply::{syncing, Syncing};
        use pretty_assertions::assert_eq;

        use super::*;

        #[tokio::test]
        async fn not_syncing() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let syncing = client(addr)
                .request::<Syncing>("starknet_syncing", rpc_params!())
                .await
                .unwrap();

            assert_eq!(syncing, Syncing::False(false));
        }

        #[tokio::test]
        async fn syncing() {
            use crate::rpc::types::reply::syncing::NumberedBlock;
            let expected = Syncing::Status(syncing::Status {
                starting: NumberedBlock::from(("abbacd", 1)),
                current: NumberedBlock::from(("abbace", 2)),
                highest: NumberedBlock::from(("abbacf", 3)),
            });

            let storage = setup_storage();
            let sequencer = Client::new(Chain::Goerli).unwrap();
            let sync_state = Arc::new(SyncState::default());
            *sync_state.status.write().await = expected.clone();
            let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let syncing = client(addr)
                .request::<Syncing>("starknet_syncing", rpc_params!())
                .await
                .unwrap();

            assert_eq!(syncing, expected);
        }
    }

    mod events {
        use super::*;

        use super::types::reply::{EmittedEvent, GetEventsResult};
        use crate::storage::test_utils;

        fn setup() -> (Storage, Vec<EmittedEvent>) {
            let (storage, events) = test_utils::setup_test_storage();
            let events = events.into_iter().map(EmittedEvent::from).collect();
            (storage, events)
        }

        mod positional_args {
            use super::*;
            use crate::starkhash;

            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn get_events_with_empty_filter() {
                let (storage, events) = setup();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = rpc_params!(EventFilter {
                    from_block: None,
                    to_block: None,
                    address: None,
                    keys: vec![],
                    page_size: test_utils::NUM_EVENTS,
                    page_number: 0,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events,
                        page_number: 0,
                        is_last_page: true,
                    }
                );
            }

            #[tokio::test]
            async fn get_events_with_fully_specified_filter() {
                let (storage, events) = setup();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let expected_event = &events[1];
                let params = rpc_params!(EventFilter {
                    from_block: Some(expected_event.block_number.unwrap().into()),
                    to_block: Some(expected_event.block_number.unwrap().into()),
                    address: Some(expected_event.from_address),
                    // we're using a key which is present in _all_ events
                    keys: vec![EventKey(starkhash!("deadbeef"))],
                    page_size: test_utils::NUM_EVENTS,
                    page_number: 0,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events: vec![expected_event.clone()],
                        page_number: 0,
                        is_last_page: true,
                    }
                );
            }

            #[tokio::test]
            async fn get_events_by_block() {
                let (storage, events) = setup();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                const BLOCK_NUMBER: usize = 2;
                let params = rpc_params!(EventFilter {
                    from_block: Some(StarknetBlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()),
                    to_block: Some(StarknetBlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()),
                    address: None,
                    keys: vec![],
                    page_size: test_utils::NUM_EVENTS,
                    page_number: 0,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();

                let expected_events = &events[test_utils::EVENTS_PER_BLOCK * BLOCK_NUMBER
                    ..test_utils::EVENTS_PER_BLOCK * (BLOCK_NUMBER + 1)];
                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events: expected_events.to_vec(),
                        page_number: 0,
                        is_last_page: true,
                    }
                );
            }

            #[tokio::test]
            async fn get_events_with_invalid_page_size() {
                let (storage, _events) = setup();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = rpc_params!(EventFilter {
                    from_block: None,
                    to_block: None,
                    address: None,
                    keys: vec![],
                    page_size: crate::storage::StarknetEventsTable::PAGE_SIZE_LIMIT + 1,
                    page_number: 0,
                });
                let error = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap_err();

                assert_eq!(crate::rpc::types::reply::ErrorCode::PageSizeTooBig, error);
            }

            #[tokio::test]
            async fn get_events_by_key_with_paging() {
                let (storage, events) = setup();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let expected_events = &events[27..32];
                let keys_for_expected_events: Vec<_> =
                    expected_events.iter().map(|e| e.keys[0]).collect();

                let params = rpc_params!(EventFilter {
                    from_block: None,
                    to_block: None,
                    address: None,
                    keys: keys_for_expected_events.clone(),
                    page_size: 2,
                    page_number: 0,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();
                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events: expected_events[..2].to_vec(),
                        page_number: 0,
                        is_last_page: false,
                    }
                );

                let params = rpc_params!(EventFilter {
                    from_block: None,
                    to_block: None,
                    address: None,
                    keys: keys_for_expected_events.clone(),
                    page_size: 2,
                    page_number: 1,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();
                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events: expected_events[2..4].to_vec(),
                        page_number: 1,
                        is_last_page: false,
                    }
                );

                let params = rpc_params!(EventFilter {
                    from_block: None,
                    to_block: None,
                    address: None,
                    keys: keys_for_expected_events.clone(),
                    page_size: 2,
                    page_number: 2,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();
                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events: expected_events[4..].to_vec(),
                        page_number: 2,
                        is_last_page: true,
                    }
                );

                // nonexistent page
                let params = rpc_params!(EventFilter {
                    from_block: None,
                    to_block: None,
                    address: None,
                    keys: keys_for_expected_events.clone(),
                    page_size: 2,
                    page_number: 3,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();
                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events: vec![],
                        page_number: 3,
                        is_last_page: true,
                    }
                );
            }
        }

        mod named_args {
            use super::*;

            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn get_events_with_empty_filter() {
                let (storage, events) = setup();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = by_name([(
                    "filter",
                    json!({"page_size": test_utils::NUM_EVENTS, "page_number": 0}),
                )]);
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events,
                        page_number: 0,
                        is_last_page: true,
                    }
                );
            }

            #[tokio::test]
            async fn get_events_with_fully_specified_filter() {
                let (storage, events) = setup();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let expected_event = &events[1];
                let params = by_name([(
                    "filter",
                    json!({
                        "fromBlock": {
                            "block_number": expected_event.block_number.unwrap().get()
                        },
                        "toBlock": {
                            "block_number": expected_event.block_number.unwrap().get()
                        },
                        "address": expected_event.from_address,
                        "keys": [expected_event.keys[0]],
                        "page_size": super::test_utils::NUM_EVENTS,
                        "page_number": 0,
                    }),
                )]);

                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    GetEventsResult {
                        events: vec![expected_event.clone()],
                        page_number: 0,
                        is_last_page: true,
                    }
                );
            }
        }

        mod pending {
            use super::*;

            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn backward_range() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                    .with_pending_data(pending_data);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = rpc_params!(EventFilter {
                    from_block: Some(BlockId::Pending),
                    to_block: Some(BlockId::Latest),
                    address: None,
                    keys: vec![],
                    page_size: 100,
                    page_number: 0,
                });
                let rpc_result = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", params)
                    .await
                    .unwrap();
                assert!(rpc_result.events.is_empty());
            }

            #[tokio::test]
            async fn all_events() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                    .with_pending_data(pending_data);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let mut filter = EventFilter {
                    from_block: None,
                    to_block: Some(BlockId::Latest),
                    address: None,
                    keys: vec![],
                    page_size: 1024,
                    page_number: 0,
                };

                let events = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", rpc_params!(filter.clone()))
                    .await
                    .unwrap();

                filter.from_block = Some(BlockId::Pending);
                filter.to_block = Some(BlockId::Pending);
                let pending_events = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", rpc_params!(filter.clone()))
                    .await
                    .unwrap();

                filter.from_block = None;
                let all_events = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", rpc_params!(filter))
                    .await
                    .unwrap();

                let expected = events
                    .events
                    .into_iter()
                    .chain(pending_events.events.into_iter())
                    .collect::<Vec<_>>();

                assert_eq!(all_events.events, expected);
                assert!(all_events.is_last_page);
            }

            #[tokio::test]
            async fn paging() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state)
                    .with_pending_data(pending_data);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let mut filter = EventFilter {
                    from_block: None,
                    to_block: Some(BlockId::Pending),
                    address: None,
                    keys: vec![],
                    page_size: 1024,
                    page_number: 0,
                };

                let all = client(addr)
                    .request::<GetEventsResult>("starknet_getEvents", rpc_params!(filter.clone()))
                    .await
                    .unwrap()
                    .events;

                filter.page_size = 2;
                let mut last_pages = Vec::new();
                for (idx, chunk) in all.chunks(filter.page_size).enumerate() {
                    filter.page_number = idx;
                    let result = client(addr)
                        .request::<GetEventsResult>(
                            "starknet_getEvents",
                            rpc_params!(filter.clone()),
                        )
                        .await
                        .unwrap();
                    assert_eq!(result.page_number, idx);
                    assert_eq!(result.events, chunk);

                    last_pages.push(result.is_last_page);
                }

                let mut expected = vec![false; last_pages.len() - 1];
                expected.push(true);
                assert_eq!(last_pages, expected);
            }
        }
    }

    mod add_transaction {
        use super::*;
        use crate::rpc::types::reply::{
            DeclareTransactionResult, DeployTransactionResult, InvokeTransactionResult,
        };

        lazy_static::lazy_static! {
            pub static ref CONTRACT_DEFINITION_JSON: serde_json::Value = {
                let json = include_bytes!("../resources/deploy_transaction.json");
                let mut json: serde_json::Value = serde_json::from_slice(json).unwrap();
                json["contract_definition"].take()
            };
        }

        mod positional_args {
            use std::collections::HashMap;

            use super::*;
            use crate::{
                core::{ByteCodeOffset, CallParam, ClassHash, EntryPoint},
                sequencer::request::contract::{EntryPointType, SelectorAndOffset},
                starkhash,
            };

            use pretty_assertions::assert_eq;
            use web3::types::H256;

            lazy_static::lazy_static! {
                pub static ref CALL: ContractCall = ContractCall {
                    contract_address: ContractAddress::new_or_panic(
                        starkhash!("023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd")
                    ),
                    calldata: vec![
                        CallParam(starkhash!("01")),
                        CallParam(starkhash!("0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1")),
                        CallParam(starkhash!("0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320")),
                        CallParam(starkhash!("00")),
                        CallParam(starkhash!("01")),
                        CallParam(starkhash!("01")),
                        CallParam(starkhash!("2b")),
                        CallParam(starkhash!("00")),
                    ],
                    entry_point_selector: EntryPoint(starkhash!("015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"))
                };
                pub static ref SIGNATURE: Vec<CallSignatureElem> = vec![
                    CallSignatureElem(starkhash!("07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5")),
                    CallSignatureElem(starkhash!("071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8")),
                ];
                pub static ref MAX_FEE: Fee = Fee(5444010076217u128.to_be_bytes().into());
                pub static ref TRANSACTION_VERSION: TransactionVersion = TransactionVersion(H256::zero());

                pub static ref ENTRY_POINTS_BY_TYPE: HashMap<EntryPointType, Vec<SelectorAndOffset>> =
                    HashMap::from([
                        (EntryPointType::Constructor, vec![]),
                        (
                            EntryPointType::External,
                            vec![
                                SelectorAndOffset {
                                    offset: ByteCodeOffset(starkhash!("3a")),
                                    selector: EntryPoint::hashed(&b"increase_balance"[..]),
                                },
                                SelectorAndOffset{
                                    offset: ByteCodeOffset(starkhash!("5b")),
                                    selector: EntryPoint::hashed(&b"get_balance"[..]),
                                },
                            ],
                        ),
                        (EntryPointType::L1Handler, vec![]),
                    ]);
                pub static ref PROGRAM: String = CONTRACT_DEFINITION_JSON["program"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                pub static ref CONTRACT_DEFINITION: ContractDefinition = ContractDefinition {
                    program: PROGRAM.clone(),
                    entry_points_by_type: ENTRY_POINTS_BY_TYPE.clone(),
                    abi: Some(CONTRACT_DEFINITION_JSON["abi"].clone()),
                };
            }

            #[tokio::test]
            async fn invoke_transaction() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = rpc_params!(
                    CALL.clone(),
                    SIGNATURE.clone(),
                    *MAX_FEE,
                    *TRANSACTION_VERSION
                );
                let rpc_result = client(addr)
                    .request::<InvokeTransactionResult>("starknet_addInvokeTransaction", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    InvokeTransactionResult {
                        transaction_hash: StarknetTransactionHash(starkhash!(
                            "0389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"
                        ))
                    }
                );
            }

            #[tokio::test]
            async fn declare_transaction() {
                let storage = setup_storage();
                let sequencer = Client::integration().unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let contract_class = CONTRACT_DEFINITION.clone();

                let params = rpc_params!(contract_class, *TRANSACTION_VERSION);

                let rpc_result = client(addr)
                    .request::<DeclareTransactionResult>("starknet_addDeclareTransaction", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    DeclareTransactionResult {
                        transaction_hash: StarknetTransactionHash(starkhash!(
                            "077ccba4df42cf0f74a8eb59a96d7880fae371edca5d000ca5f9985652c8a8ed"
                        )),
                        class_hash: ClassHash(starkhash!(
                            "0711941b11a8236b8cca42b664e19342ac7300abb1dc44957763cb65877c2708"
                        )),
                    }
                );
            }

            #[tokio::test]
            async fn deploy_transaction() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let contract_definition = CONTRACT_DEFINITION.clone();
                let contract_address_salt = ContractAddressSalt(starkhash!(
                    "05864b5e296c05028ac2bbc4a4c1378f56a3489d13e581f21d566bb94580f76d"
                ));
                let constructor_calldata: Vec<ConstructorParam> = vec![];

                let params = rpc_params!(
                    contract_address_salt,
                    constructor_calldata,
                    contract_definition
                );

                let rpc_result = client(addr)
                    .request::<DeployTransactionResult>("starknet_addDeployTransaction", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    DeployTransactionResult {
                        transaction_hash: StarknetTransactionHash(starkhash!(
                            "057ed4b4c76a1ca0ba044a654dd3ee2d0d3e550343d739350a22aacdd524110d"
                        )),
                        contract_address: ContractAddress::new_or_panic(starkhash!(
                            "03926aea98213ec34fe9783d803237d221c54c52344422e1f4942a5b340fa6ad"
                        )),
                    }
                );
            }
        }

        mod named_args {
            use crate::{core::ClassHash, starkhash};

            use super::*;

            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn invoke_transaction() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = by_name([
                    (
                        "function_invocation",
                        json!({
                            "contract_address": "0x23371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                            "calldata": [
                                "1",
                                "0x677BB1CDC050E8D63855E8743AB6E09179138DEF390676CC03C484DAF112BA1",
                                "0x362398BEC32BC0EBB411203221A35A0301193A96F317EBE5E40BE9F60D15320",
                                "0",
                                "1",
                                "1",
                                "0x2B",
                                "0"
                            ],
                            "entry_point_selector": "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
                        }),
                    ),
                    (
                        "signature",
                        json!([
                            "3557065757165699682249469970267166698995647077461960906176449260016084767701",
                            "3202126414680946801789588986259466145787792017299869598314522555275920413944"
                        ]),
                    ),
                    ("max_fee", json!("0x4f388496839")),
                    ("version", json!("0x0")),
                ]);

                let rpc_result = client(addr)
                    .request::<InvokeTransactionResult>("starknet_addInvokeTransaction", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    InvokeTransactionResult {
                        transaction_hash: StarknetTransactionHash(starkhash!(
                            "0389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"
                        ))
                    }
                );
            }

            #[tokio::test]
            async fn declare_transaction() {
                let storage = setup_storage();
                let sequencer = Client::integration().unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = by_name([
                    ("contract_class", CONTRACT_DEFINITION_JSON.clone()),
                    ("version", json!("0x0")),
                ]);

                let rpc_result = client(addr)
                    .request::<DeclareTransactionResult>("starknet_addDeclareTransaction", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    DeclareTransactionResult {
                        transaction_hash: StarknetTransactionHash(starkhash!(
                            "077ccba4df42cf0f74a8eb59a96d7880fae371edca5d000ca5f9985652c8a8ed"
                        )),
                        class_hash: ClassHash(starkhash!(
                            "0711941b11a8236b8cca42b664e19342ac7300abb1dc44957763cb65877c2708"
                        )),
                    }
                );
            }

            #[tokio::test]
            async fn deploy_transaction() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Goerli).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Goerli, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let params = by_name([
                    (
                        "contract_address_salt",
                        json!("0x5864b5e296c05028ac2bbc4a4c1378f56a3489d13e581f21d566bb94580f76d"),
                    ),
                    ("constructor_calldata", json!([])),
                    ("contract_definition", CONTRACT_DEFINITION_JSON.clone()),
                ]);

                let rpc_result = client(addr)
                    .request::<DeployTransactionResult>("starknet_addDeployTransaction", params)
                    .await
                    .unwrap();

                assert_eq!(
                    rpc_result,
                    DeployTransactionResult {
                        transaction_hash: StarknetTransactionHash(starkhash!(
                            "057ed4b4c76a1ca0ba044a654dd3ee2d0d3e550343d739350a22aacdd524110d"
                        )),
                        contract_address: ContractAddress::new_or_panic(starkhash!(
                            "03926aea98213ec34fe9783d803237d221c54c52344422e1f4942a5b340fa6ad"
                        )),
                    }
                );
            }
        }
    }
}
