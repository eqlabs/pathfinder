use std::collections::HashMap;

use anyhow::Context;
use pathfinder_common::{
    BlockHash, BlockNumber, Chain, ClassHash, ContractAddress, ContractNonce, StateCommitment,
};
use pathfinder_storage::BlockId;
use primitive_types::H160;
use serde::Deserialize;
use starknet_gateway_types::reply::{
    state_update::{DeclaredSierraClass, DeployedContract, ReplacedClass, StorageDiff},
    Status,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use warp::Filter;

/// Groups the Starknet contract addresses for a specific chain.
pub struct ContractAddresses {
    pub core: H160,
    pub gps: H160,
}

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

    impl TryInto<BlockId> for BlockIdParam {
        type Error = ();

        fn try_into(self) -> Result<BlockId, Self::Error> {
            if let Some(n) = self.block_number {
                if n == "latest" {
                    return Ok(BlockId::Latest);
                } else {
                    let n: u64 = n.parse().map_err(|_| ())?;
                    return Ok(BlockId::Number(BlockNumber::new_or_panic(n)));
                }
            }

            if let Some(h) = self.block_hash {
                return Ok(BlockId::Hash(h));
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

fn get_chain(tx: &pathfinder_storage::Transaction<'_>) -> anyhow::Result<Chain> {
    use pathfinder_common::consts::{
        INTEGRATION_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET2_GENESIS_HASH, TESTNET_GENESIS_HASH,
    };

    let genesis_hash = tx
        .block_id(BlockNumber::GENESIS.into())
        .unwrap()
        .context("Getting genesis hash")?
        .1;

    let chain = match genesis_hash {
        MAINNET_GENESIS_HASH => Chain::Mainnet,
        TESTNET_GENESIS_HASH => Chain::Testnet,
        TESTNET2_GENESIS_HASH => Chain::Testnet2,
        INTEGRATION_GENESIS_HASH => Chain::Integration,
        _other => Chain::Custom,
    };

    Ok(chain)
}

fn contract_addresses(chain: Chain) -> anyhow::Result<ContractAddresses> {
    fn parse(hex: &str) -> H160 {
        let slice: [u8; 20] = const_decoder::Decoder::Hex.decode(hex.as_bytes());
        H160::from(slice)
    }

    Ok(match chain {
        Chain::Mainnet => ContractAddresses {
            core: parse("c662c410C0ECf747543f5bA90660f6ABeBD9C8c4"),
            gps: parse("47312450B3Ac8b5b8e247a6bB6d523e7605bDb60"),
        },
        Chain::Testnet => ContractAddresses {
            core: parse("de29d060D45901Fb19ED6C6e959EB22d8626708e"),
            gps: parse("8f97970aC5a9aa8D130d35146F5b59c4aef57963"),
        },
        Chain::Testnet2 => ContractAddresses {
            core: parse("a4eD3aD27c294565cB0DCc993BDdCC75432D498c"),
            gps: parse("8f97970aC5a9aa8D130d35146F5b59c4aef57963"),
        },
        Chain::Integration | Chain::Custom => ContractAddresses {
            core: parse("d5c325D183C592C94998000C5e0EED9e6655c020"),
            gps: parse("8f97970aC5a9aa8D130d35146F5b59c4aef57963"),
        },
    })
}

fn resolve_block(
    tx: &pathfinder_storage::Transaction<'_>,
    block_id: BlockId,
) -> anyhow::Result<starknet_gateway_types::reply::Block> {
    let header = tx
        .block_header(block_id)
        .context("Fetching block header")?
        .context("Block header missing")?;

    let transactions_receipts = tx
        .transaction_data_for_block(header.number.into())
        .context("Reading transactions from database")?
        .context("Transaction data missing")?;

    let (transactions, transaction_receipts): (Vec<_>, Vec<_>) =
        transactions_receipts.into_iter().unzip();

    let block_status = tx
        .block_is_l1_accepted(header.number)
        .context("Querying block status")?;
    let block_status = if block_status {
        Status::AcceptedOnL1
    } else {
        Status::AcceptedOnL2
    };

    Ok(starknet_gateway_types::reply::Block {
        block_hash: header.hash,
        block_number: header.number,
        gas_price: Some(header.gas_price),
        parent_block_hash: header.parent_hash,
        sequencer_address: Some(header.sequencer_address),
        state_commitment: header.state_commitment,
        status: block_status,
        timestamp: header.timestamp,
        transaction_receipts,
        transactions,
        starknet_version: header.starknet_version,
    })
}

fn resolve_state_update(
    tx: &pathfinder_storage::Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<starknet_gateway_types::reply::StateUpdate> {
    use pathfinder_common::{CasmHash, SierraHash, StorageAddress, StorageValue};
    use starknet_gateway_types::reply::{state_update::StateDiff, StateUpdate};

    let header = tx
        .block_header(block)
        .context("Fetching block header")?
        .context("Block header is missing")?;

    let parent_state_commmitment = if header.number - 1 == BlockNumber::GENESIS {
        StateCommitment::default()
    } else {
        tx.block_header(header.parent_hash.into())
            .context("Fetching parent block header")?
            .context("Parent block header is missing")?
            .state_commitment
    };

    let mut stmt = tx
        .prepare_cached("SELECT contract_address, nonce FROM nonce_updates WHERE block_number = ?")
        .context("Preparing nonce update query statement")?;
    let nonces = stmt
        .query_map([header.number], |row| {
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
        .query_map([header.number], |row| {
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
        .query_map([header.number], |row| {
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
        .query_map([header.number], |row| {
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
        block_hash: header.hash,
        new_root: header.state_commitment,
        old_root: parent_state_commmitment,
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

fn resolve_class(
    tx: &pathfinder_storage::Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Vec<u8>> {
    tracing::info!(%class_hash, "Resolving class hash");

    let definition = tx
        .class_definition(class_hash)
        .context("Reading class definition from database")?
        .ok_or_else(|| anyhow::anyhow!("No such class found"))?;

    Ok(definition)
}
