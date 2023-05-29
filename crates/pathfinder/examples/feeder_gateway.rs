use std::collections::HashMap;

use anyhow::Context;
use pathfinder_common::{
    BlockHash, BlockNumber, Chain, ClassHash, ContractAddress, ContractNonce, StateCommitment,
};
use pathfinder_ethereum::ContractAddresses;
use pathfinder_storage::{StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable};
use serde::Deserialize;
use stark_hash::Felt;
use starknet_gateway_types::reply::{
    state_update::{DeclaredSierraClass, DeployedContract, ReplacedClass, StorageDiff},
    Status,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use warp::Filter;

/// Serve feeder gateway REST endpoints required for pathfinder to sync.
///
/// Usage:
/// `cargo run --release -p pathfinder --example feeder_gateway ./testnet2.sqlite`
///
/// Then pathfinder can be run with the following arguments to use this tool as a sync source:
///
/// ```text
/// cargo run --release -p pathfinder -- \
///     --network custom --chain-id SN_GOERLI2 \
///     --gateway-url http://localhost:8080/gateway \
///     --feeder-gateway-url http://localhost:8080/feeder_gateway \
///     --data-directory /tmp
/// ```
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
    serve().await
}

async fn serve() -> anyhow::Result<()> {
    let database_path = std::env::args().nth(1).unwrap();
    let storage = pathfinder_storage::Storage::migrate(
        database_path.into(),
        pathfinder_storage::JournalMode::WAL,
    )?;

    let chain = {
        let mut connection = storage.connection()?;
        let tx = connection.transaction()?;
        get_chain(&tx)?
    };

    let get_contract_addresses = warp::path("get_contract_addresses").map(move || {
        let addresses = contract_addresses(chain).unwrap();
        let reply =
            serde_json::json!({"GpsStatementVerifier": addresses.gps, "Starknet": addresses.core});
        warp::reply::json(&reply)
    });

    #[derive(Debug, Deserialize)]
    struct BlockIdParam {
        #[serde(default, rename = "blockNumber")]
        block_number: Option<String>,
        #[serde(default, rename = "blockHash")]
        block_hash: Option<BlockHash>,
    }

    impl TryInto<StarknetBlocksBlockId> for BlockIdParam {
        type Error = ();

        fn try_into(self) -> Result<StarknetBlocksBlockId, Self::Error> {
            if let Some(n) = self.block_number {
                if n == "latest" {
                    return Ok(StarknetBlocksBlockId::Latest);
                } else {
                    let n: u64 = n.parse().map_err(|_| ())?;
                    return Ok(StarknetBlocksBlockId::Number(BlockNumber::new_or_panic(n)));
                }
            }

            if let Some(h) = self.block_hash {
                return Ok(StarknetBlocksBlockId::Hash(h));
            }
            Err(())
        }
    }

    let get_block = warp::path("get_block")
        .and(warp::query::<BlockIdParam>())
        .and_then({
            let storage = storage.clone();
            move |block_id: BlockIdParam| {
                let storage = storage.clone();
                async move {
                    match block_id.try_into() {
                        Ok(block_id) => {
                            let block = tokio::task::spawn_blocking(move || {
                                let mut connection = storage.connection().unwrap();
                                let tx = connection.transaction().unwrap();

                                resolve_block(&tx, block_id)
                            }).await.unwrap();

                            match block {
                                Ok(block) => {
                                    Ok(warp::reply::json(&block))
                                },
                                Err(_) => {
                                    let error = serde_json::json!({"code": "StarknetErrorCode.BLOCK_NOT_FOUND", "message": "Block number not found"});
                                    Ok(warp::reply::json(&error))
                                }
                            }
                        },
                        Err(_) => Err(warp::reject::reject()),
                    }
                }
            }
        });

    let get_state_update = warp::path("get_state_update")
        .and(warp::query::<BlockIdParam>())
        .and_then({
            let storage = storage.clone();
            move |block_id: BlockIdParam| {
                let storage = storage.clone();
                async move {
                    match block_id.try_into() {
                        Ok(block_id) => {
                            let state_update = tokio::task::spawn_blocking(move || {
                                let mut connection = storage.connection().unwrap();
                                let tx = connection.transaction().unwrap();

                                resolve_state_update(&tx, block_id)
                            }).await.unwrap();

                            match state_update {
                                Ok(state_update) => {
                                    Ok(warp::reply::json(&state_update))
                                },
                                Err(_) => {
                                    let error = serde_json::json!({"code": "StarknetErrorCode.BLOCK_NOT_FOUND", "message": "Block number not found"});
                                    Ok(warp::reply::json(&error))
                                }
                            }
                        },
                        Err(_) => Err(warp::reject::reject()),
                    }
                }
            }
        });

    #[derive(Debug, Deserialize)]
    struct ClassHashParam {
        #[serde(rename = "classHash")]
        class_hash: ClassHash,
    }

    let get_class_by_hash = warp::path("get_class_by_hash")
        .and(warp::query::<ClassHashParam>())
        .then({
            let storage = storage.clone();
            move |class_hash: ClassHashParam| {
                let storage = storage.clone();
                async move {
                    let class = tokio::task::spawn_blocking(move || {
                        let mut connection = storage.connection().unwrap();
                        let tx = connection.transaction().unwrap();

                        resolve_class(&tx, class_hash.class_hash)
                    }).await.unwrap();

                    match class {
                        Ok(class) => {
                            let response = warp::http::Response::builder().header("content-type", "application/json").body(class).unwrap();
                            Ok(response)
                        },
                        Err(_) => {
                            let error = r#"{"code": "StarknetErrorCode.UNDECLARED_CLASS", "message": "Class not found"}"#;
                            let response = warp::http::Response::builder().status(500).body(error.as_bytes().to_owned()).unwrap();
                            Ok(response)
                        }
                    }
                }
            }
        });

    let handler = warp::get()
        .and(warp::path("feeder_gateway"))
        .and(
            get_block
                .or(get_state_update)
                .or(get_contract_addresses)
                .or(get_class_by_hash),
        )
        .with(warp::filters::trace::request());

    warp::serve(handler).run(([127, 0, 0, 1], 8080)).await;

    Ok(())
}

fn get_chain(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<Chain> {
    use pathfinder_common::consts::{
        INTEGRATION_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET2_GENESIS_HASH, TESTNET_GENESIS_HASH,
    };

    let genesis_hash = StarknetBlocksTable::get_hash(tx, BlockNumber::GENESIS.into())
        .unwrap()
        .context("Getting genesis hash")?;

    let chain = match genesis_hash {
        MAINNET_GENESIS_HASH => Chain::Mainnet,
        TESTNET_GENESIS_HASH => Chain::Testnet,
        TESTNET2_GENESIS_HASH => Chain::Testnet2,
        INTEGRATION_GENESIS_HASH => Chain::Integration,
        _other => Chain::Custom,
    };

    Ok(chain)
}

fn contract_addresses(_chain: Chain) -> anyhow::Result<ContractAddresses> {
    // TODO(SM): fix this
    Ok(ContractAddresses::default())
}

fn resolve_block(
    tx: &rusqlite::Transaction<'_>,
    block_id: StarknetBlocksBlockId,
) -> anyhow::Result<starknet_gateway_types::reply::Block> {
    let block =
        pathfinder_storage::StarknetBlocksTable::get(tx, block_id)?.context("Fetching block")?;

    let parent_hash = match block.number {
        BlockNumber::GENESIS => BlockHash(Felt::ZERO),
        other => {
            let parent_block = StarknetBlocksTable::get(tx, (other - 1).into())
                .context("Read parent block from database")?
                .context("Parent block missing")?;

            parent_block.hash
        }
    };

    let transactions_receipts =
        StarknetTransactionsTable::get_transaction_data_for_block(tx, block.number.into())
            .context("Reading transactions from database")?;

    let (transactions, transaction_receipts): (Vec<_>, Vec<_>) =
        transactions_receipts.into_iter().unzip();

    let block_status = get_block_status(tx, block.number)?;
    let block_version = StarknetBlocksTable::get_version(tx, block_id)?;

    Ok(starknet_gateway_types::reply::Block {
        block_hash: block.hash,
        block_number: block.number,
        gas_price: Some(block.gas_price),
        parent_block_hash: parent_hash,
        sequencer_address: Some(block.sequencer_address),
        state_commitment: block.state_commmitment,
        status: block_status,
        timestamp: block.timestamp,
        transaction_receipts,
        transactions,
        starknet_version: block_version,
    })
}

fn get_block_status(
    tx: &rusqlite::Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<Status> {
    // All our data is L2 accepted, check our L1-L2 head to see if this block has been accepted on L1.
    let l1_l2_head = pathfinder_storage::RefsTable::get_l1_l2_head(tx)
        .context("Read latest L1 head from database")?;
    let block_status = match l1_l2_head {
        Some(number) if number >= block_number => Status::AcceptedOnL1,
        _ => Status::AcceptedOnL2,
    };

    Ok(block_status)
}

fn resolve_state_update(
    tx: &rusqlite::Transaction<'_>,
    block: StarknetBlocksBlockId,
) -> anyhow::Result<starknet_gateway_types::reply::StateUpdate> {
    use pathfinder_common::{CasmHash, SierraHash, StorageAddress, StorageValue};
    use starknet_gateway_types::reply::{state_update::StateDiff, StateUpdate};

    let (number, block_hash, new_root, old_root) =
        block_info(tx, block)?.context("Read block info from database")?;

    let mut stmt = tx
        .prepare_cached("SELECT contract_address, nonce FROM nonce_updates WHERE block_number = ?")
        .context("Preparing nonce update query statement")?;
    let nonces = stmt
        .query_map([number], |row| {
            let contract_address = row.get(0)?;
            let nonce = row.get(1)?;

            Ok((contract_address, nonce))
        })
        .context("Querying nonce updates")?
        .collect::<Result<HashMap<ContractAddress, ContractNonce>, _>>()
        .context("Iterating over nonce query rows")?;

    let mut stmt = tx
        .prepare_cached(
            "SELECT contract_address, storage_address, storage_value FROM storage_updates WHERE block_number = ?"
        )
        .context("Preparing storage update query statement")?;
    let storage_tuples = stmt
        .query_map([number], |row| {
            let contract_address: ContractAddress = row.get(0)?;
            let storage_address: StorageAddress = row.get(1)?;
            let storage_value: StorageValue = row.get(2)?;

            Ok((contract_address, storage_address, storage_value))
        })
        .context("Querying storage updates")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over storage query rows")?;
    // Convert storage tuples to contract based mapping.
    let mut storage_diffs: HashMap<ContractAddress, Vec<StorageDiff>> = HashMap::new();
    for (addr, key, value) in storage_tuples {
        storage_diffs
            .entry(addr)
            .or_default()
            .push(StorageDiff { key, value });
    }

    let mut stmt = tx
        .prepare_cached(
            r"SELECT
                class_definitions.hash AS class_hash,
                casm_definitions.compiled_class_hash AS compiled_class_hash
            FROM
                class_definitions
            LEFT OUTER JOIN
                casm_definitions ON casm_definitions.hash = class_definitions.hash
            WHERE
                class_definitions.block_number = ?",
        )
        .context("Preparing class declaration query statement")?;
    enum DeclaredClass {
        Deprecated(ClassHash),
        Sierra(DeclaredSierraClass),
    }
    let declared_classes = stmt
        .query_map([number], |row| {
            let class_hash: ClassHash = row.get(0)?;
            let compiled_class_hash: Option<CasmHash> = row.get(1)?;

            Ok(match compiled_class_hash {
                Some(compiled_class_hash) => DeclaredClass::Sierra(DeclaredSierraClass {
                    class_hash: SierraHash(class_hash.0),
                    compiled_class_hash,
                }),
                None => DeclaredClass::Deprecated(class_hash),
            })
        })
        .context("Querying class declarations")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over class declaration query rows")?;
    let (deprecated_declared_classes, declared_classes): (Vec<_>, Vec<_>) = declared_classes
        .into_iter()
        .partition(|c| matches!(c, DeclaredClass::Deprecated(_)));
    let deprecated_declared_classes = deprecated_declared_classes
        .into_iter()
        .map(|c| match c {
            DeclaredClass::Deprecated(c) => c,
            DeclaredClass::Sierra(_) => {
                panic!("Internal error: unexpected Sierra class declaration")
            }
        })
        .collect();
    let declared_classes = declared_classes
        .into_iter()
        .map(|c| match c {
            DeclaredClass::Deprecated(_) => {
                panic!("Internal error: unexpected deprecated class declaration")
            }
            DeclaredClass::Sierra(c) => c,
        })
        .collect();

    let mut stmt = tx
        .prepare_cached(
            r"SELECT
                cu1.contract_address AS contract_address,
                cu1.class_hash AS class_hash,
                cu2.block_number IS NOT NULL AS is_replaced
            FROM
                contract_updates cu1
            LEFT OUTER JOIN
                contract_updates cu2 ON cu1.contract_address = cu2.contract_address AND cu2.block_number < cu1.block_number
            WHERE
                cu1.block_number = ?",
        )
        .context("Preparing contract update query statement")?;
    enum DeployedOrReplacedContract {
        Deployed(DeployedContract),
        Replaced(ReplacedClass),
    }
    let deployed_and_replaced_contracts = stmt
        .query_map([number], |row| {
            let address: ContractAddress = row.get(0)?;
            let class_hash: ClassHash = row.get(1)?;
            let is_replaced: bool = row.get(2)?;

            Ok(match is_replaced {
                true => DeployedOrReplacedContract::Replaced(ReplacedClass {
                    address,
                    class_hash,
                }),
                false => DeployedOrReplacedContract::Deployed(DeployedContract {
                    address,
                    class_hash,
                }),
            })
        })
        .context("Querying contract deployments")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over contract deployment query rows")?;
    let (deployed_contracts, replaced_classes): (Vec<_>, Vec<_>) = deployed_and_replaced_contracts
        .into_iter()
        .partition(|c| matches!(c, DeployedOrReplacedContract::Deployed(_)));
    let deployed_contracts = deployed_contracts
        .into_iter()
        .map(|c| match c {
            DeployedOrReplacedContract::Deployed(c) => c,
            DeployedOrReplacedContract::Replaced(_) => {
                panic!("Internal error: unexpected replaced class")
            }
        })
        .collect();
    let replaced_classes = replaced_classes
        .into_iter()
        .map(|c| match c {
            DeployedOrReplacedContract::Deployed(_) => {
                panic!("Internal error: unexpected deployed contract")
            }
            DeployedOrReplacedContract::Replaced(c) => c,
        })
        .collect();

    let state_update = StateUpdate {
        block_hash,
        new_root,
        old_root,
        state_diff: StateDiff {
            storage_diffs,
            old_declared_contracts: deprecated_declared_classes,
            declared_classes,
            deployed_contracts,
            replaced_classes,
            nonces,
        },
    };

    Ok(state_update)
}

fn block_info(
    tx: &rusqlite::Transaction<'_>,
    block: StarknetBlocksBlockId,
) -> anyhow::Result<Option<(BlockNumber, BlockHash, StateCommitment, StateCommitment)>> {
    let block = StarknetBlocksTable::get(tx, block)?;
    Ok(match block {
        None => None,
        Some(block) => {
            let old_root = if block.number == BlockNumber::GENESIS {
                Some(StateCommitment(Felt::ZERO))
            } else {
                let previous_block_number = BlockNumber::new_or_panic(block.number.get() - 1);
                StarknetBlocksTable::get(tx, StarknetBlocksBlockId::Number(previous_block_number))?
                    .map(|b| b.state_commmitment)
            };

            old_root.map(|old_root| (block.number, block.hash, block.state_commmitment, old_root))
        }
    })
}

fn resolve_class(tx: &rusqlite::Transaction<'_>, class_hash: ClassHash) -> anyhow::Result<Vec<u8>> {
    use rusqlite::OptionalExtension;

    tracing::info!(%class_hash, "Resolving class hash");

    let definition = tx
        .query_row(
            r"SELECT definition FROM class_definitions WHERE hash = ?",
            [class_hash],
            |row| {
                let def = row.get_ref_unwrap(0).as_blob()?.to_owned();
                Ok(def)
            },
        )
        .optional()
        .context("Reading class definition from database")?
        .ok_or_else(|| anyhow::anyhow!("No such class found"))?;

    let definition = zstd::decode_all(&*definition).context("Decompressing class definition")?;

    Ok(definition)
}
