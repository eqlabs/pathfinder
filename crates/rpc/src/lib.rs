//! Starknet node JSON-RPC related modules.
pub mod context;
mod dto;
mod error;
mod executor;
mod felt;
mod jsonrpc;
pub(crate) mod method;
pub mod middleware;
mod pathfinder;
mod pending;
#[cfg(test)]
mod test_setup;
pub mod v02;
pub mod v03;
pub mod v04;
pub mod v05;
pub mod v06;
pub mod v07;

pub use executor::compose_executor_transaction;
pub use pending::PendingData;

use crate::jsonrpc::rpc_handler;
use crate::jsonrpc::websocket::websocket_handler;
pub use crate::jsonrpc::websocket::{BlockHeader, TopicBroadcasters};
use crate::v02::types::syncing::Syncing;
use anyhow::Context;
use axum::error_handling::HandleErrorLayer;
use axum::extract::DefaultBodyLimit;

use axum::response::IntoResponse;
use context::RpcContext;
use http::Request;
use hyper::Body;
use pathfinder_common::AllowedOrigins;
use std::{net::SocketAddr, result::Result};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_http::cors::CorsLayer;
use tower_http::ServiceBuilderExt;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;

#[derive(Copy, Clone, Debug, Default, PartialEq, PartialOrd)]
pub enum RpcVersion {
    V04,
    V05,
    V06,
    #[default]
    V07,
    PathfinderV01,
}

impl RpcVersion {
    fn to_str(self) -> &'static str {
        match self {
            RpcVersion::V04 => "v0.4",
            RpcVersion::V05 => "v0.5",
            RpcVersion::V06 => "v0.6",
            RpcVersion::V07 => "v0.7",
            RpcVersion::PathfinderV01 => "v0.1",
        }
    }
}

pub struct RpcServer {
    addr: SocketAddr,
    context: RpcContext,
    max_connections: usize,
    cors: Option<CorsLayer>,
    default_version: RpcVersion,
}

impl RpcServer {
    pub fn new(addr: SocketAddr, context: RpcContext, default_version: RpcVersion) -> Self {
        Self {
            addr,
            context,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            cors: None,
            default_version,
        }
    }

    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub fn with_cors(self, allowed_origins: AllowedOrigins) -> Self {
        Self {
            cors: Some(middleware::cors::with_allowed_origins(allowed_origins)),
            ..self
        }
    }

    /// Starts the HTTP-RPC server.
    pub fn spawn(self) -> Result<(JoinHandle<anyhow::Result<()>>, SocketAddr), anyhow::Error> {
        use axum::routing::{get, post};

        // TODO: make this configurable
        const REQUEST_MAX_SIZE: usize = 10 * 1024 * 1024;
        // TODO: make this configurable
        const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

        let listener = match std::net::TcpListener::bind(self.addr) {
            Ok(listener) => listener,
            Err(e) => return Err(e).context(format!("RPC address {} is already in use.
    
            Hint: This usually means you are already running another instance of pathfinder.
            Hint: If this happens when upgrading, make sure to shut down the first one first.
            Hint: If you are looking to run two instances of pathfinder, you must configure them with different http rpc addresses.", self.addr)),
        };
        let addr = listener
            .local_addr()
            .context("Getting local address from listener")?;
        let server = axum::Server::from_tcp(listener).context("Binding server to tcp listener")?;

        async fn handle_middleware_errors(err: axum::BoxError) -> (http::StatusCode, String) {
            use http::StatusCode;
            if err.is::<tower::timeout::error::Elapsed>() {
                (
                    StatusCode::REQUEST_TIMEOUT,
                    "Request took too long".to_string(),
                )
            } else {
                // TODO: confirm this isn't too verbose.
                tracing::warn!(error = err, "Unhandled middleware error");

                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
        }

        let middleware = tower::ServiceBuilder::new()
            // Convert errors created by middleware layers into responses.
            // This is required by axum -- axum doesn't deal with Result, errors
            // must be responses as well.
            .layer(HandleErrorLayer::new(handle_middleware_errors))
            // make sure to set request ids before the request reaches `TraceLayer`
            .set_x_request_id(middleware::request_id::RequestIdSource::default())
            .concurrency_limit(self.max_connections)
            .layer(DefaultBodyLimit::max(REQUEST_MAX_SIZE))
            .timeout(REQUEST_TIMEOUT)
            .layer(middleware::tracing::trace_layer())
            .option_layer(self.cors)
            .propagate_x_request_id();

        /// Returns success for requests with an empty body without reading
        /// the entire body.
        async fn empty_body(request: Request<Body>) -> impl IntoResponse {
            use hyper::body::HttpBody;
            if request.body().is_end_stream() {
                http::StatusCode::OK.into_response()
            } else {
                http::StatusCode::METHOD_NOT_ALLOWED.into_response()
            }
        }

        let v04_routes = v04::register_routes().build(self.context.clone());
        let v05_routes = v05::register_routes().build(self.context.clone());
        let v06_routes = v06::register_routes().build(self.context.clone());
        let v07_routes = v07::register_routes().build(self.context.clone());
        let pathfinder_routes = pathfinder::register_routes().build(self.context.clone());

        let default_router = match self.default_version {
            RpcVersion::V04 => v04_routes.clone(),
            RpcVersion::V05 => v05_routes.clone(),
            RpcVersion::V06 => v06_routes.clone(),
            RpcVersion::V07 => v07_routes.clone(),
            RpcVersion::PathfinderV01 => {
                anyhow::bail!("Did not expect default RPC version to be Pathfinder v0.1")
            }
        };

        let router = axum::Router::new()
            // Also return success for get's with an empty body. These are often
            // used by monitoring bots to check service health.
            .route("/", get(empty_body).post(rpc_handler))
            .with_state(default_router)
            .route("/rpc/v0.4", post(rpc_handler))
            .route("/rpc/v0_4", post(rpc_handler))
            .with_state(v04_routes)
            .route("/rpc/v0.5", post(rpc_handler))
            .route("/rpc/v0_5", post(rpc_handler))
            .with_state(v05_routes)
            .route("/rpc/v0_6", post(rpc_handler))
            .with_state(v06_routes)
            .route("/rpc/v0_7", post(rpc_handler))
            .with_state(v07_routes)
            .route("/rpc/pathfinder/v0.1", post(rpc_handler))
            .with_state(pathfinder_routes);

        let router = if self.context.websocket.is_some() {
            router.route("/ws", get(websocket_handler))
        } else {
            router
        };

        let router = router
            .with_state(self.context.websocket.clone().unwrap_or_default())
            .layer(middleware);

        let server_handle = tokio::spawn(async move {
            server
                .serve(router.into_make_service())
                .await
                .map_err(Into::into)
        });

        Ok((server_handle, addr))
    }

    pub fn get_topic_broadcasters(&self) -> Option<&TopicBroadcasters> {
        self.context
            .websocket
            .as_ref()
            .map(|websocket| &websocket.broadcasters)
    }
}

pub struct SyncState {
    pub status: RwLock<Syncing>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            status: RwLock::new(Syncing::False(false)),
        }
    }
}

pub mod test_utils {
    use crate::pending::PendingData;
    use pathfinder_common::event::Event;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::prelude::*;
    use pathfinder_common::receipt::{
        BuiltinCounters, ExecutionResources, ExecutionStatus, L2ToL1Message, Receipt,
    };
    use pathfinder_common::transaction::*;
    use pathfinder_merkle_tree::StorageCommitmentTree;
    use pathfinder_storage::{BlockId, Storage};
    use primitive_types::H160;
    use starknet_gateway_types::reply::GasPrices;
    use std::collections::HashMap;

    // Creates storage for tests
    pub fn setup_storage() -> Storage {
        use pathfinder_merkle_tree::contract_state::update_contract_state;

        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let db_txn = connection.transaction().unwrap();

        let class_commitment0 = class_commitment_bytes!(b"class commitment 0");
        let class_commitment1 = class_commitment_bytes!(b"class commitment 1");
        let class_commitment2 = class_commitment_bytes!(b"class commitment 2");

        let contract0_addr = contract_address_bytes!(b"contract 0");
        let contract1_addr = contract_address_bytes!(b"contract 1");
        let contract2_addr = contract_address_bytes!(b"contract 2 (sierra)");

        let class0_hash = class_hash_bytes!(b"class 0 hash");
        let class1_hash = class_hash_bytes!(b"class 1 hash");
        let class2_hash = class_hash_bytes!(b"class 2 hash (sierra)");
        let class_hash_pending = class_hash_bytes!(b"class pending hash");

        let storage_addr = storage_address_bytes!(b"storage addr 0");

        let state_update0 = StateUpdate::default()
            .with_deployed_contract(contract0_addr, class0_hash)
            .with_contract_nonce(contract0_addr, contract_nonce!("0x1"));

        let state_update1 = StateUpdate::default()
            .with_deployed_contract(contract1_addr, class1_hash)
            .with_storage_update(
                contract1_addr,
                storage_addr,
                storage_value_bytes!(b"storage value 1"),
            );

        let state_update2 = StateUpdate::default()
            .with_deployed_contract(contract2_addr, class2_hash)
            .with_contract_nonce(contract1_addr, contract_nonce!("0x10"))
            .with_contract_nonce(contract2_addr, contract_nonce!("0xfeed"))
            .with_storage_update(
                contract1_addr,
                storage_addr,
                storage_value_bytes!(b"storage value 2"),
            );

        let contract0_update = HashMap::new();

        let storage_addr = storage_address_bytes!(b"storage addr 0");
        let contract1_update1 =
            HashMap::from([(storage_addr, storage_value_bytes!(b"storage value 1"))]);
        let contract1_update2 =
            HashMap::from([(storage_addr, storage_value_bytes!(b"storage value 2"))]);

        let class0_definition =
            starknet_gateway_test_fixtures::class_definitions::CONTRACT_DEFINITION.to_vec();
        let class1_definition = &class0_definition;
        let sierra_class_definition =
            starknet_gateway_test_fixtures::class_definitions::CAIRO_0_11_SIERRA.to_vec();

        db_txn
            .insert_cairo_class(class0_hash, &class0_definition)
            .unwrap();
        db_txn
            .insert_cairo_class(class1_hash, class1_definition)
            .unwrap();
        db_txn
            .insert_sierra_class(
                &SierraHash(class2_hash.0),
                &sierra_class_definition,
                &casm_hash_bytes!(b"non-existent"),
                &[],
            )
            .unwrap();
        db_txn
            .insert_cairo_class(class_hash_pending, &class0_definition)
            .unwrap();

        // Update block 0
        let update_results = update_contract_state(
            contract0_addr,
            &contract0_update,
            Some(contract_nonce!("0x1")),
            Some(class0_hash),
            &db_txn,
            false,
            BlockNumber::GENESIS,
        )
        .unwrap();
        let contract_state_hash = update_results.state_hash;
        update_results
            .insert(BlockNumber::GENESIS, &db_txn)
            .unwrap();
        let mut storage_commitment_tree = StorageCommitmentTree::empty(&db_txn);
        storage_commitment_tree
            .set(contract0_addr, contract_state_hash)
            .unwrap();

        let (storage_commitment0, nodes) = storage_commitment_tree.commit().unwrap();
        let storage_root_idx = db_txn
            .insert_storage_trie(storage_commitment0, &nodes)
            .unwrap();
        db_txn
            .insert_storage_root(BlockNumber::GENESIS, Some(storage_root_idx))
            .unwrap();
        let header0 = BlockHeader::builder()
            .with_number(BlockNumber::GENESIS)
            .with_storage_commitment(storage_commitment0)
            .with_class_commitment(class_commitment0)
            .with_calculated_state_commitment()
            .finalize_with_hash(block_hash_bytes!(b"genesis"));
        db_txn.insert_block_header(&header0).unwrap();
        db_txn
            .insert_state_update(header0.number, &state_update0)
            .unwrap();

        // Update block 1
        let mut storage_commitment_tree =
            StorageCommitmentTree::load(&db_txn, BlockNumber::GENESIS).unwrap();
        storage_commitment_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let update_results = update_contract_state(
            contract1_addr,
            &contract1_update1,
            None,
            Some(class1_hash),
            &db_txn,
            false,
            BlockNumber::GENESIS + 1,
        )
        .unwrap();
        let contract_state_hash = update_results.state_hash;
        update_results
            .insert(BlockNumber::GENESIS + 1, &db_txn)
            .unwrap();
        storage_commitment_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let (storage_commitment1, nodes) = storage_commitment_tree.commit().unwrap();
        let storage_root_idx = db_txn
            .insert_storage_trie(storage_commitment1, &nodes)
            .unwrap();
        db_txn
            .insert_storage_root(BlockNumber::GENESIS + 1, Some(storage_root_idx))
            .unwrap();
        let header1 = header0
            .child_builder()
            .with_timestamp(BlockTimestamp::new_or_panic(1))
            .with_storage_commitment(storage_commitment1)
            .with_class_commitment(class_commitment1)
            .with_calculated_state_commitment()
            .with_eth_l1_gas_price(GasPrice::from(1))
            .with_sequencer_address(sequencer_address_bytes!(&[1u8]))
            .finalize_with_hash(block_hash_bytes!(b"block 1"));
        db_txn.insert_block_header(&header1).unwrap();
        db_txn
            .insert_state_update(header1.number, &state_update1)
            .unwrap();

        // Update block 2
        let mut storage_commitment_tree =
            StorageCommitmentTree::load(&db_txn, BlockNumber::GENESIS + 1).unwrap();
        let update_results = update_contract_state(
            contract1_addr,
            &contract1_update2,
            Some(contract_nonce!("0x10")),
            None,
            &db_txn,
            false,
            BlockNumber::GENESIS + 2,
        )
        .unwrap();
        let contract_state_hash = update_results.state_hash;
        update_results
            .insert(BlockNumber::GENESIS + 2, &db_txn)
            .unwrap();
        storage_commitment_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();

        let update_results = update_contract_state(
            contract2_addr,
            &HashMap::new(),
            Some(contract_nonce!("0xfeed")),
            Some(class2_hash),
            &db_txn,
            false,
            BlockNumber::GENESIS + 2,
        )
        .unwrap();
        let contract_state_hash = update_results.state_hash;
        update_results
            .insert(BlockNumber::GENESIS + 2, &db_txn)
            .unwrap();
        storage_commitment_tree
            .set(contract2_addr, contract_state_hash)
            .unwrap();
        let (storage_commitment2, nodes) = storage_commitment_tree.commit().unwrap();
        let storage_root_idx = db_txn
            .insert_storage_trie(storage_commitment2, &nodes)
            .unwrap();
        db_txn
            .insert_storage_root(BlockNumber::GENESIS + 2, Some(storage_root_idx))
            .unwrap();
        let header2 = header1
            .child_builder()
            .with_timestamp(BlockTimestamp::new_or_panic(2))
            .with_storage_commitment(storage_commitment2)
            .with_class_commitment(class_commitment2)
            .with_calculated_state_commitment()
            .with_eth_l1_gas_price(GasPrice::from(2))
            .with_sequencer_address(sequencer_address_bytes!(&[2u8]))
            .finalize_with_hash(block_hash_bytes!(b"latest"));

        db_txn.insert_block_header(&header2).unwrap();
        db_txn
            .insert_state_update(header2.number, &state_update2)
            .unwrap();

        // TODO introduce other types of transactions too
        let txn0 = Transaction {
            hash: transaction_hash_bytes!(b"txn 0"),
            variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
                sender_address: contract0_addr,
                ..Default::default()
            }),
        };
        let mut receipt0 = Receipt {
            execution_resources: ExecutionResources {
                builtins: BuiltinCounters {
                    output: 33,
                    pedersen: 32,
                    ..Default::default()
                },
                n_memory_holes: 5,
                n_steps: 10,
                data_availability: Default::default(),
            },
            transaction_hash: txn0.hash,
            ..Default::default()
        };

        let txn1 = Transaction {
            hash: transaction_hash_bytes!(b"txn 1"),
            variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
                sender_address: contract1_addr,
                ..Default::default()
            }),
        };
        let txn2 = Transaction {
            hash: transaction_hash_bytes!(b"txn 2"),
            ..txn1.clone()
        };
        let txn3 = Transaction {
            hash: transaction_hash_bytes!(b"txn 3"),
            ..txn1.clone()
        };
        let txn4 = Transaction {
            hash: transaction_hash_bytes!(b"txn 4"),
            variant: TransactionVariant::InvokeV0(Default::default()),
        };
        let txn5 = Transaction {
            hash: transaction_hash_bytes!(b"txn 5"),
            ..txn1.clone()
        };
        let txn6 = Transaction {
            hash: transaction_hash_bytes!(b"txn 6"),
            ..txn1.clone()
        };
        let txn_reverted = Transaction {
            hash: transaction_hash_bytes!(b"txn reverted"),
            ..txn1.clone()
        };
        let mut receipt1 = receipt0.clone();
        let mut receipt2 = receipt0.clone();
        let mut receipt3 = receipt0.clone();
        let mut receipt4 = receipt0.clone();
        let mut receipt5 = receipt0.clone();
        let mut receipt_reverted = receipt0.clone();
        let mut receipt6 = Receipt {
            l2_to_l1_messages: vec![L2ToL1Message {
                from_address: contract_address!("0xcafebabe"),
                payload: vec![
                    l2_to_l1_message_payload_elem!("0x1"),
                    l2_to_l1_message_payload_elem!("0x2"),
                    l2_to_l1_message_payload_elem!("0x3"),
                ],
                to_address: EthereumAddress(H160::zero()),
            }],
            ..receipt0.clone()
        };
        receipt0.events = vec![Event {
            data: vec![event_data_bytes!(b"event 0 data")],
            from_address: contract_address_bytes!(b"event 0 from addr"),
            keys: vec![event_key_bytes!(b"event 0 key")],
        }];
        receipt1.transaction_hash = txn1.hash;
        receipt2.transaction_hash = txn2.hash;
        receipt3.transaction_hash = txn3.hash;
        receipt4.transaction_hash = txn4.hash;
        receipt5.transaction_hash = txn5.hash;
        receipt6.transaction_hash = txn6.hash;
        receipt_reverted.transaction_hash = txn_reverted.hash;
        receipt_reverted.execution_status = ExecutionStatus::Reverted {
            reason: "Reverted because".to_owned(),
        };

        let transaction_data0 = [(txn0, Some(receipt0))];
        let transaction_data1 = [(txn1, Some(receipt1)), (txn2, Some(receipt2))];
        let transaction_data2 = [
            (txn3, Some(receipt3)),
            (txn4, Some(receipt4)),
            (txn5, Some(receipt5)),
            (txn6, Some(receipt6)),
            (txn_reverted, Some(receipt_reverted)),
        ];
        db_txn
            .insert_transaction_data(header0.hash, header0.number, &transaction_data0)
            .unwrap();
        db_txn
            .insert_transaction_data(header1.hash, header1.number, &transaction_data1)
            .unwrap();
        db_txn
            .insert_transaction_data(header2.hash, header2.number, &transaction_data2)
            .unwrap();

        // Mark block 0 as L1 accepted.
        db_txn.update_l1_l2_pointer(Some(header0.number)).unwrap();

        db_txn.commit().unwrap();
        storage
    }

    /// Creates [PendingData] which correctly links to the provided [Storage].
    ///
    /// i.e. the pending block's parent hash will be the latest block's hash from storage,
    /// and similarly for the pending state diffs state root.
    pub async fn create_pending_data(storage: Storage) -> PendingData {
        let storage2 = storage.clone();
        let latest = tokio::task::spawn_blocking(move || {
            let mut db = storage2.connection().unwrap();
            let tx = db.transaction().unwrap();

            tx.block_header(BlockId::Latest)
                .unwrap()
                .expect("Storage should contain a latest block")
        })
        .await
        .unwrap();

        let transactions: Vec<Transaction> = vec![
            Transaction {
                hash: transaction_hash_bytes!(b"pending tx hash 0"),
                variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
                    sender_address: contract_address_bytes!(b"pending contract addr 0"),
                    entry_point_selector: entry_point_bytes!(b"entry point 0"),
                    entry_point_type: Some(EntryPointType::External),
                    ..Default::default()
                }),
            },
            Transaction {
                hash: transaction_hash_bytes!(b"pending tx hash 1"),
                variant: TransactionVariant::Deploy(DeployTransaction {
                    contract_address: contract_address!("0x1122355"),
                    contract_address_salt: contract_address_salt_bytes!(b"salty"),
                    class_hash: class_hash_bytes!(b"pending class hash 1"),
                    ..Default::default()
                }),
            },
            Transaction {
                hash: transaction_hash_bytes!(b"pending reverted"),
                variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
                    sender_address: contract_address_bytes!(b"pending contract addr 0"),
                    entry_point_selector: entry_point_bytes!(b"entry point 0"),
                    entry_point_type: Some(EntryPointType::External),
                    ..Default::default()
                }),
            },
        ];

        let transaction_receipts = vec![
            Receipt {
                actual_fee: None,
                events: vec![
                    Event {
                        data: vec![],
                        from_address: contract_address!("0xabcddddddd"),
                        keys: vec![event_key_bytes!(b"pending key")],
                    },
                    Event {
                        data: vec![],
                        from_address: contract_address!("0xabcddddddd"),
                        keys: vec![
                            event_key_bytes!(b"pending key"),
                            event_key_bytes!(b"second pending key"),
                        ],
                    },
                    Event {
                        data: vec![],
                        from_address: contract_address!("0xabcaaaaaaa"),
                        keys: vec![event_key_bytes!(b"pending key 2")],
                    },
                ],
                execution_resources: ExecutionResources::default(),
                transaction_hash: transactions[0].hash,
                transaction_index: TransactionIndex::new_or_panic(0),
                ..Default::default()
            },
            Receipt {
                execution_resources: ExecutionResources::default(),
                transaction_hash: transactions[1].hash,
                transaction_index: TransactionIndex::new_or_panic(1),
                ..Default::default()
            },
            // Reverted and without events
            Receipt {
                execution_resources: ExecutionResources::default(),
                transaction_hash: transactions[2].hash,
                transaction_index: TransactionIndex::new_or_panic(2),
                execution_status: ExecutionStatus::Reverted {
                    reason: "Reverted!".to_owned(),
                },
                ..Default::default()
            },
        ];

        let transactions = transactions.into_iter().map(Into::into).collect();
        let transaction_receipts = transaction_receipts.into_iter().map(Into::into).collect();

        let block = starknet_gateway_types::reply::PendingBlock {
            eth_l1_gas_price_implementation_detail: Some(
                GasPrice::from_be_slice(b"gas price").unwrap(),
            ),
            strk_l1_gas_price_implementation_detail: Some(
                GasPrice::from_be_slice(b"strk gas price").unwrap(),
            ),
            l1_gas_price_implementation_detail: None,
            l1_data_gas_price: Some(GasPrices {
                price_in_wei: GasPrice::from_be_slice(b"datgasprice").unwrap(),
                price_in_fri: GasPrice::from_be_slice(b"strk datgasprice").unwrap(),
            }),
            parent_hash: latest.hash,
            sequencer_address: sequencer_address_bytes!(b"pending sequencer address"),
            status: starknet_gateway_types::reply::Status::Pending,
            timestamp: BlockTimestamp::new_or_panic(1234567),
            transaction_receipts,
            transactions,
            starknet_version: StarknetVersion::new(0, 11, 0),
            l1_da_mode: Some(starknet_gateway_types::reply::L1DataAvailabilityMode::Calldata),
        };

        let contract1 = contract_address_bytes!(b"pending contract 1 address");
        let state_update = StateUpdate::default()
            .with_parent_state_commitment(latest.state_commitment)
            .with_declared_cairo_class(class_hash_bytes!(b"pending class 0 hash"))
            .with_declared_cairo_class(class_hash_bytes!(b"pending class 1 hash"))
            .with_deployed_contract(
                contract_address_bytes!(b"pending contract 0 address"),
                class_hash_bytes!(b"pending class 0 hash"),
            )
            .with_deployed_contract(contract1, class_hash_bytes!(b"pending class 1 hash"))
            .with_storage_update(
                contract1,
                storage_address_bytes!(b"pending storage key 0"),
                storage_value_bytes!(b"pending storage value 0"),
            )
            .with_storage_update(
                contract1,
                storage_address_bytes!(b"pending storage key 1"),
                storage_value_bytes!(b"pending storage value 1"),
            )
            // This is not a real contract and should be re-worked..
            .with_replaced_class(
                contract_address_bytes!(b"pending contract 2 (replaced)"),
                class_hash_bytes!(b"pending class 2 hash (replaced)"),
            )
            .with_contract_nonce(
                contract_address_bytes!(b"contract 1"),
                contract_nonce_bytes!(b"pending nonce"),
            );

        // The class definitions must be inserted into the database.
        let state_update_copy = state_update.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = storage.connection().unwrap();
            let tx = db.transaction().unwrap();
            let class_definition =
                starknet_gateway_test_fixtures::class_definitions::CONTRACT_DEFINITION;

            for cairo in state_update_copy.declared_cairo_classes {
                tx.insert_cairo_class(cairo, class_definition).unwrap();
            }

            for (sierra, casm) in state_update_copy.declared_sierra_classes {
                tx.insert_sierra_class(&sierra, b"sierra def", &casm, b"casm def")
                    .unwrap();
            }

            tx.commit().unwrap();
        })
        .await
        .unwrap();

        PendingData {
            block: block.into(),
            state_update: state_update.into(),
            number: latest.number + 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn roundtrip_syncing() {
        use crate::v02::types::syncing::{NumberedBlock, Status, Syncing};

        let examples = [
            (line!(), "false", Syncing::False(false)),
            // this shouldn't exist but it exists now
            (line!(), "true", Syncing::False(true)),
            (
                line!(),
                r#"{"starting_block_hash":"0xa","starting_block_num":"0x1","current_block_hash":"0xb","current_block_num":"0x2","highest_block_hash":"0xc","highest_block_num":"0x3"}"#,
                Syncing::Status(Status {
                    starting: NumberedBlock::from(("a", 1)),
                    current: NumberedBlock::from(("b", 2)),
                    highest: NumberedBlock::from(("c", 3)),
                }),
            ),
        ];

        for (line, input, expected) in examples {
            let parsed = serde_json::from_str::<Syncing>(input).unwrap();
            let output = serde_json::to_string(&parsed).unwrap();

            assert_eq!(parsed, expected, "example from line {line}");
            assert_eq!(&output, input, "example from line {line}");
        }
    }

    #[tokio::test]
    async fn empty_get_on_root_is_ok() {
        // Monitoring bots often get query `/` with no body as a form
        // of health check. Test that we return success for such queries.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let context = RpcContext::for_tests();
        let (_jh, addr) = RpcServer::new(addr, context, RpcVersion::V04)
            .spawn()
            .unwrap();

        let url = format!("http://{addr}/");

        let client = reqwest::Client::new();
        // No body
        let status = client.get(url.clone()).send().await.unwrap().status();
        assert!(status.is_success());
        // Empty body - unsure if this is actually different to no body.
        let status = client
            .get(url.clone())
            .body("")
            .send()
            .await
            .unwrap()
            .status();
        assert!(status.is_success());
        // Non-empty body should fail.
        let status = client
            .get(url.clone())
            .body("x")
            .send()
            .await
            .unwrap()
            .status();
        assert!(!status.is_success());
    }

    #[rustfmt::skip]
    #[rstest::rstest]
    #[case::root_api  ("/", "v04/starknet_api_openrpc.json",       &[])]
    #[case::root_trace("/", "v04/starknet_trace_api_openrpc.json", &[])]
    #[case::root_write("/", "v04/starknet_write_api.json",         &[])]
    #[case::root_pathfinder("/", "pathfinder_rpc_api.json", &["pathfinder_version"])]

    #[case::v0_7_api  ("/rpc/v0_7", "v07/starknet_api_openrpc.json", &[])]
    #[case::v0_7_trace("/rpc/v0_7", "v07/starknet_trace_api_openrpc.json", &[])]
    #[case::v0_7_write("/rpc/v0_7", "v07/starknet_write_api.json", &[])]
    // get_transaction_status is now part of the official spec, so we are phasing it out.
    #[case::v0_7_pathfinder("/rpc/v0_7", "pathfinder_rpc_api.json", &["pathfinder_version", "pathfinder_getTransactionStatus"])]

    #[case::v0_6_api  ("/rpc/v0_6", "v06/starknet_api_openrpc.json", &[])]
    #[case::v0_6_trace("/rpc/v0_6", "v06/starknet_trace_api_openrpc.json", &[])]
    #[case::v0_6_write("/rpc/v0_6", "v06/starknet_write_api.json", &[])]
    // get_transaction_status is now part of the official spec, so we are phasing it out.
    #[case::v0_6_pathfinder("/rpc/v0_6", "pathfinder_rpc_api.json", &["pathfinder_version", "pathfinder_getTransactionStatus"])]

    #[case::v05_api  ("/rpc/v0.5", "v05/starknet_api_openrpc.json", &[])]
    #[case::v05_trace("/rpc/v0.5", "v05/starknet_trace_api_openrpc.json", &[])]
    #[case::v05_write("/rpc/v0.5", "v05/starknet_write_api.json",         &[])]
    #[case::v05_pathfinder("/rpc/v0.5", "pathfinder_rpc_api.json", &["pathfinder_version"])]
    #[case::v0_5_api  ("/rpc/v0_5", "v05/starknet_api_openrpc.json", &[])]
    #[case::v0_5_trace("/rpc/v0_5", "v05/starknet_trace_api_openrpc.json", &[])]
    #[case::v0_5_write("/rpc/v0_5", "v05/starknet_write_api.json",         &[])]
    #[case::v0_5_pathfinder("/rpc/v0_5", "pathfinder_rpc_api.json", &["pathfinder_version"])]

    #[case::v04_api  ("/rpc/v0.4", "v04/starknet_api_openrpc.json",       &[])]
    #[case::v04_trace("/rpc/v0.4", "v04/starknet_trace_api_openrpc.json", &[])]
    #[case::v04_write("/rpc/v0.4", "v04/starknet_write_api.json",         &[])]
    #[case::v04_pathfinder("/rpc/v0.4", "pathfinder_rpc_api.json", &["pathfinder_version"])]
    #[case::v0_4_api  ("/rpc/v0_4", "v04/starknet_api_openrpc.json", &[])]
    #[case::v0_4_trace("/rpc/v0_4", "v04/starknet_trace_api_openrpc.json", &[])]
    #[case::v0_4_write("/rpc/v0_4", "v04/starknet_write_api.json",         &[])]
    #[case::v0_4_pathfinder("/rpc/v0_4", "pathfinder_rpc_api.json", &["pathfinder_version"])]
    
    #[case::pathfinder("/rpc/pathfinder/v0.1", "pathfinder_rpc_api.json", &[])]

    #[tokio::test]
    async fn rpc_routing(
        #[case] route: &'static str,
        #[case] specification: std::path::PathBuf,
        #[case] exclude: &[&'static str],
    ) {
        let specification = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("doc")
            .join("rpc")
            .join(specification);
        let specification = std::fs::File::open(specification).unwrap();
        let specification = serde_json::from_reader::<_, serde_json::Value>(specification).unwrap();

        let mut methods = specification["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["name"].as_str().unwrap())
            .collect::<Vec<_>>();

        for excluded in exclude {
            assert!(
                methods.contains(excluded),
                "Excluded method {excluded} was not found in the specification"
            );
        }
        
        methods.retain(|x| !exclude.contains(x));

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let context = RpcContext::for_tests();
        let (_jh, addr) = RpcServer::new(addr, context, RpcVersion::V04)
            .spawn()
            .unwrap();

        let url = format!("http://{addr}{route}");
        let client = reqwest::Client::new();

        let method_not_found = json!(-32601);

        let mut failures = Vec::new();
        for method in methods {
            let request = json!({
                "jsonrpc": "2.0",
                "method": method,
                "id": 0,
            });

            let res: serde_json::Value = client
                .post(url.clone())
                .json(&request)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();

            if res["error"]["code"] == method_not_found {
                failures.push(method);
            }
        }

        if !failures.is_empty() {
            panic!("{failures:#?} were not found");
        }

        // Check that excluded methods are indeed not present.
        failures.clear();
        for excluded in exclude {
            let request = json!({
                "jsonrpc": "2.0",
                "method": excluded,
                "id": 0,
            });

            let res: serde_json::Value = client
                .post(url.clone())
                .json(&request)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();

            if res["error"]["code"] != method_not_found {
                failures.push(excluded);
            }
        }

        if !failures.is_empty() {
            panic!("{failures:#?} were marked as excluded but are actually present");
        }
    }
}
