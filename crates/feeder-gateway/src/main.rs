/// Serve feeder gateway REST endpoints required for pathfinder to sync.
///
/// Usage:
/// `cargo run --release -p feeder-gateway ./testnet-sepolia.sqlite`
///
/// Then pathfinder can be run with the following arguments to use this tool as
/// a sync source:
///
/// ```text
/// cargo run --release -p pathfinder -- \
///     --network custom --chain-id SN_SEPOLIA \
///     --ethereum.url https://eth-sepolia.alchemyapi.io/v2/YOUR_API_KEY
///     --gateway-url http://localhost:8080/gateway \
///     --feeder-gateway-url http://localhost:8080/feeder_gateway \
///     --data-directory /tmp
/// ```
///
/// Optionally this tool can simulate reorgs. To have the tool return data so
/// that pathfinder reorgs from block 50 to 40 use the following command line:
/// `cargo run --release -p pathfinder --example feeder_gateway
/// ./testnet-sepolia.sqlite --reorg-at-block 50 --reorg-to-block 40`
use std::collections::HashMap;
use std::convert::Infallible;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context;
use clap::{Args, Parser};
use pathfinder_common::prelude::*;
use pathfinder_common::state_update::ContractClassUpdate;
use pathfinder_common::{BlockId, Chain};
use pathfinder_lib::state::block_hash::{
    calculate_event_commitment,
    calculate_receipt_commitment,
    calculate_transaction_commitment,
};
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use starknet_gateway_types::reply::state_update::{
    DeclaredSierraClass,
    DeployedContract,
    MigratedCompiledClass,
    ReplacedClass,
    StorageDiff,
};
use starknet_gateway_types::reply::{GasPrices, Status};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use warp::Filter;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(long_help = "Database path")]
    pub database_path: PathBuf,
    #[command(flatten)]
    pub reorg: ReorgCli,
}

#[derive(Debug, Clone, Args)]
struct ReorgCli {
    #[arg(long, long_help = "Reorg should happen after this block", value_parser = parse_block_number, requires = "reorg_to_block")]
    pub reorg_at_block: Option<BlockNumber>,
    #[arg(long, long_help = "Reorg should roll back state to this block", value_parser = parse_block_number, requires = "reorg_at_block")]
    pub reorg_to_block: Option<BlockNumber>,
}

fn parse_block_number(s: &str) -> Result<BlockNumber, String> {
    let n: u64 = s
        .parse()
        .map_err(|e| format!("Invalid block number '{s}': {e}"))?;
    BlockNumber::new(n).ok_or_else(|| format!("Invalid block number '{s}'"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
    serve(cli).await
}

#[derive(Debug, Clone)]
struct ReorgConfig {
    pub reorg_at_block: BlockNumber,
    pub reorg_to_block: BlockNumber,
}

async fn serve(cli: Cli) -> anyhow::Result<()> {
    let database_path = std::env::args().nth(1).unwrap();
    let storage = pathfinder_storage::StorageBuilder::file(database_path.into())
        .migrate()?
        .create_pool(NonZeroU32::new(10).unwrap())
        .unwrap();

    let chain = {
        let mut connection = storage.connection()?;
        let tx = connection.transaction()?;
        get_chain(&tx)?
    };

    let reorg_config = cli.reorg.reorg_at_block.and_then(|reorg_at_block| {
        cli.reorg.reorg_to_block.map(|reorg_to_block| ReorgConfig {
            reorg_at_block,
            reorg_to_block,
        })
    });
    let reorged = Arc::new(AtomicBool::new(false));

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
        #[serde(default, rename = "includeBlock")]
        include_block: Option<bool>,
        #[serde(default, rename = "headerOnly")]
        header_only: Option<bool>,
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
            let reorg_config = reorg_config.clone();
            let reorged = reorged.clone();

            move |block_id: BlockIdParam| {
                let storage = storage.clone();
                let reorg_config = reorg_config.clone();
                let reorged = reorged.clone();

                async move {
                    let header_only = block_id.header_only.unwrap_or(false);

                    match block_id.try_into() {
                        Ok(block_id) => {
                            let block = tokio::task::spawn_blocking(move || {
                                let mut connection = storage.connection().unwrap();
                                let tx = connection.transaction().unwrap();

                                resolve_block(&tx, block_id, &reorg_config, reorged)
                            }).await.unwrap();

                            match block {
                                Ok(block) => {
                                    if header_only {
                                        #[derive(Serialize)]
                                        struct HashAndNumber {
                                            block_hash: BlockHash,
                                            block_number: BlockNumber,
                                        }

                                        let reply = HashAndNumber {
                                            block_hash: block.block_hash,
                                            block_number: block.block_number,
                                        };

                                        Ok(warp::reply::json(&reply))
                                    } else {
                                        Ok(warp::reply::json(&block))
                                    }
                                },
                                Err(e) => {
                                    tracing::error!("Error fetching block: {:?}", e);
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

    let get_signature = warp::path("get_signature")
        .and(warp::query::<BlockIdParam>())
        .and_then({
            let storage = storage.clone();
            move |block_id: BlockIdParam| {
                let storage = storage.clone();
                async move {
                    match block_id.try_into() {
                        Ok(block_id) => {
                            let signature = tokio::task::spawn_blocking(move || {
                                let mut connection = storage.connection().unwrap();
                                let tx = connection.transaction().unwrap();

                                resolve_signature(&tx, block_id)
                            }).await.unwrap();

                            match signature {
                                Ok(signature) => {
                                        Ok(warp::reply::json(&signature))
                                },
                                Err(e) => {
                                    tracing::error!("Error fetching signature: {:?}", e);
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
            let reorg_config = reorg_config.clone();
            let reorged = reorged.clone();

            move |block_id: BlockIdParam| {
                let storage = storage.clone();
                let reorg_config = reorg_config.clone();
                let reorged = reorged.clone();
                async move {
                    let include_block = block_id.include_block.unwrap_or(false);

                    match block_id.try_into() {
                        Ok(block_id) => {
                            let block_and_state_update = tokio::task::spawn_blocking(move || {
                                let mut connection = storage.connection().unwrap();
                                let tx = connection.transaction().unwrap();

                                resolve_state_update(&tx, block_id, &reorg_config, reorged.clone()).and_then(|state_update| resolve_block(&tx, block_id, &reorg_config, reorged).map(|block| (block, state_update)))
                            }).await.unwrap();

                            match block_and_state_update {
                                Ok((block, state_update)) => {
                                    if include_block {
                                        #[derive(Serialize)]
                                        struct StateUpdateWithBlock {
                                            state_update: starknet_gateway_types::reply::StateUpdate,
                                            block: starknet_gateway_types::reply::Block,
                                        }

                                        let reply = StateUpdateWithBlock {
                                            state_update,
                                            block,
                                        };

                                        Ok(warp::reply::with_status(warp::reply::json(&reply), warp::http::StatusCode::OK))
                                    } else {
                                        Ok(warp::reply::with_status(warp::reply::json(&state_update), warp::http::StatusCode::OK))
                                    }
                                },
                                Err(_) => {
                                    let error = serde_json::json!({"code": "StarknetErrorCode.BLOCK_NOT_FOUND", "message": "Block number not found"});
                                    Ok(warp::reply::with_status(warp::reply::json(&error), warp::http::StatusCode::BAD_REQUEST))
                                }
                            }
                        },
                        Err(_) => Err(warp::reject::reject()),
                    }
                }
            }
        });

    let get_public_key = warp::path("get_public_key").then(|| async {
        warp::reply::json(&serde_json::json!(
            "0x1252b6bce1351844c677869c6327e80eae1535755b611c66b8f46e595b40eea"
        ))
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
                            Result::<_, Infallible>::Ok(response)
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
                .or(get_class_by_hash)
                .or(get_signature)
                .or(get_public_key),
        )
        .with(warp::filters::trace::request());

    warp::serve(handler).run(([127, 0, 0, 1], 8080)).await;

    Ok(())
}

fn get_chain(tx: &pathfinder_storage::Transaction<'_>) -> anyhow::Result<Chain> {
    use pathfinder_common::consts::{
        MAINNET_GENESIS_HASH,
        SEPOLIA_INTEGRATION_GENESIS_HASH,
        SEPOLIA_TESTNET_GENESIS_HASH,
    };

    let genesis_hash = tx
        .block_hash(BlockNumber::GENESIS.into())
        .unwrap()
        .context("Getting genesis hash")?;

    let chain = match genesis_hash {
        MAINNET_GENESIS_HASH => Chain::Mainnet,
        SEPOLIA_TESTNET_GENESIS_HASH => Chain::SepoliaTestnet,
        SEPOLIA_INTEGRATION_GENESIS_HASH => Chain::SepoliaIntegration,
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
        Chain::Custom => ContractAddresses {
            // Formerly also Goerli integration
            core: parse("d5c325D183C592C94998000C5e0EED9e6655c020"),
            gps: parse("8f97970aC5a9aa8D130d35146F5b59c4aef57963"),
        },
        Chain::SepoliaTestnet => ContractAddresses {
            core: parse("E2Bb56ee936fd6433DC0F6e7e3b8365C906AA057"),
            gps: parse("07ec0D28e50322Eb0C159B9090ecF3aeA8346DFe"),
        },
        Chain::SepoliaIntegration => ContractAddresses {
            core: parse("4737c0c1B4D5b1A687B42610DdabEE781152359c"),
            gps: parse("07ec0D28e50322Eb0C159B9090ecF3aeA8346DFe"),
        },
    })
}

/// Groups the Starknet contract addresses for a specific chain.
///
/// Getting addresses: <SEQUENCER_URL>/feeder_gateway/get_contract_addresses
pub struct ContractAddresses {
    pub core: H160,
    pub gps: H160,
}

#[tracing::instrument(level = "trace", skip(tx))]
fn resolve_block(
    tx: &pathfinder_storage::Transaction<'_>,
    block_id: BlockId,
    reorg_config: &Option<ReorgConfig>,
    reorged: Arc<AtomicBool>,
) -> anyhow::Result<starknet_gateway_types::reply::Block> {
    let resolved_block_id =
        resolve_block_id(block_id, reorg_config, reorged).context("Resolving block id")?;

    let header = tx
        .block_header(resolved_block_id)
        .context("Fetching block header")?
        .context("Block header missing")?;

    let transactions_receipts = tx
        .transaction_data_for_block(header.number.into())
        .context("Reading transactions from database")?
        .context("Transaction data missing")?;

    let receipts = transactions_receipts
        .iter()
        .map(|(_, r, _)| r.clone())
        .collect::<Vec<_>>();

    let receipt_commitment = calculate_receipt_commitment(&receipts)?;

    let (transactions, transaction_receipts): (Vec<_>, Vec<_>) = transactions_receipts
        .into_iter()
        .map(|(tx, rx, ev)| (tx, (rx, ev)))
        .unzip();

    let (transaction_commitment, event_commitment) =
        if header.starknet_version < StarknetVersion::V_0_13_2 {
            // This needs to be re-calculated because we _always_ store 0.13.2 commitments
            // in the DB for P2P sync purposes
            let transaction_commitment =
                calculate_transaction_commitment(&transactions, header.starknet_version)?;
            let events: Vec<_> = transaction_receipts
                .iter()
                .map(|(receipt, events)| (receipt.transaction_hash, events.as_slice()))
                .collect();
            let event_commitment = calculate_event_commitment(&events, header.starknet_version)?;
            (transaction_commitment, event_commitment)
        } else {
            (header.transaction_commitment, header.event_commitment)
        };

    let block_status = tx
        .block_is_l1_accepted(header.number.into())
        .context("Querying block status")?;
    let block_status = if block_status {
        Status::AcceptedOnL1
    } else {
        Status::AcceptedOnL2
    };

    // If the block id was reorged, we should return a non-matching block hash
    // to trigger reorg detection in Pathfinder.
    let block_hash = if block_id != resolved_block_id {
        BlockHash::ZERO
    } else {
        header.hash
    };

    Ok(starknet_gateway_types::reply::Block {
        block_hash,
        block_number: header.number,
        l1_gas_price: GasPrices {
            price_in_wei: header.eth_l1_gas_price,
            price_in_fri: header.strk_l1_gas_price,
        },
        l1_data_gas_price: GasPrices {
            price_in_wei: header.eth_l1_data_gas_price,
            price_in_fri: header.strk_l1_data_gas_price,
        },
        l2_gas_price: Some(GasPrices {
            price_in_wei: header.eth_l2_gas_price,
            price_in_fri: header.strk_l2_gas_price,
        }),
        parent_block_hash: header.parent_hash,
        sequencer_address: Some(header.sequencer_address),
        state_commitment: header.state_commitment,
        status: block_status,
        timestamp: header.timestamp,
        transaction_receipts,
        transactions,
        starknet_version: header.starknet_version,
        l1_da_mode: header.l1_da_mode.into(),
        transaction_commitment,
        event_commitment,
        receipt_commitment: Some(receipt_commitment),
        state_diff_commitment: Some(header.state_diff_commitment),
        state_diff_length: Some(header.state_diff_length),
    })
}

#[tracing::instrument(level = "trace", skip(tx))]
fn resolve_signature(
    tx: &pathfinder_storage::Transaction<'_>,
    block_id: BlockId,
) -> anyhow::Result<starknet_gateway_types::reply::BlockSignature> {
    let header = tx
        .block_header(block_id)
        .context("Fetching block header")?
        .context("Block header missing")?;

    let signature = tx
        .signature(block_id)
        .context("Fetching signature")?
        // fall back to zero since we might have missing signatures in old DBs
        .unwrap_or(BlockCommitmentSignature {
            r: BlockCommitmentSignatureElem::ZERO,
            s: BlockCommitmentSignatureElem::ZERO,
        });

    Ok(starknet_gateway_types::reply::BlockSignature {
        block_hash: header.hash,
        signature: [signature.r, signature.s],
    })
}

/// Apply reorg transformation to block id.
fn resolve_block_id(
    block_id: BlockId,
    reorg_config: &Option<ReorgConfig>,
    reorged: Arc<AtomicBool>,
) -> anyhow::Result<BlockId> {
    let block_id = if let Some(reorg_config) = reorg_config {
        match block_id {
            BlockId::Number(block_number) => {
                if reorged.load(Ordering::Relaxed) {
                    // reorg is active
                    if block_number > reorg_config.reorg_to_block {
                        anyhow::bail!("Reorged block requested");
                    }
                    reorged.store(false, Ordering::Relaxed);
                } else {
                    // reorg should start at this block
                    if block_number > reorg_config.reorg_at_block {
                        tracing::warn!(%reorg_config.reorg_to_block, "Reorg");
                        reorged.store(true, Ordering::Relaxed);
                        anyhow::bail!("Reorg happened");
                    }
                }

                block_id
            }
            BlockId::Latest => {
                if reorged.load(Ordering::Relaxed) {
                    reorg_config.reorg_to_block.into()
                } else {
                    block_id
                }
            }
            _ => block_id,
        }
    } else {
        block_id
    };

    Ok(block_id)
}

#[tracing::instrument(level = "trace", skip(tx))]
fn resolve_state_update(
    tx: &pathfinder_storage::Transaction<'_>,
    block: BlockId,
    reorg_config: &Option<ReorgConfig>,
    reorged: Arc<AtomicBool>,
) -> anyhow::Result<starknet_gateway_types::reply::StateUpdate> {
    let block = resolve_block_id(block, reorg_config, reorged).context("Resolving block id")?;

    tx.state_update(block)
        .context("Fetching state update")?
        .context("State update missing")
        .map(storage_to_gateway)
}

#[tracing::instrument(level = "trace", skip(tx))]
fn resolve_class(
    tx: &pathfinder_storage::Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Vec<u8>> {
    let definition = tx
        .class_definition(class_hash)
        .context("Reading class definition from database")?
        .context("No such class found")?;

    Ok(definition)
}

fn storage_to_gateway(
    state_update: pathfinder_common::StateUpdate,
) -> starknet_gateway_types::reply::StateUpdate {
    let mut storage_diffs = HashMap::new();
    let mut deployed_contracts = Vec::new();
    let mut nonces = HashMap::new();
    let mut replaced_classes = Vec::new();

    for (address, update) in state_update.contract_updates {
        if let Some(nonce) = update.nonce {
            nonces.insert(address, nonce);
        }

        match update.class {
            Some(ContractClassUpdate::Deploy(class_hash)) => {
                deployed_contracts.push(DeployedContract {
                    address,
                    class_hash,
                })
            }
            Some(ContractClassUpdate::Replace(class_hash)) => {
                replaced_classes.push(ReplacedClass {
                    address,
                    class_hash,
                })
            }
            None => {}
        }

        let storage = update
            .storage
            .into_iter()
            .map(|(key, value)| StorageDiff { key, value })
            .collect();

        storage_diffs.insert(address, storage);
    }

    for (address, update) in state_update.system_contract_updates {
        let storage = update
            .storage
            .into_iter()
            .map(|(key, value)| StorageDiff { key, value })
            .collect();

        storage_diffs.insert(address, storage);
    }

    let declared_classes = state_update
        .declared_sierra_classes
        .into_iter()
        .map(|(class_hash, compiled_class_hash)| DeclaredSierraClass {
            class_hash,
            compiled_class_hash,
        })
        .collect();

    let migrated_compiled_classes = state_update
        .migrated_compiled_classes
        .into_iter()
        .map(|(sierra_hash, casm_hash)| MigratedCompiledClass {
            class_hash: sierra_hash,
            compiled_class_hash: casm_hash,
        })
        .collect();

    let state_diff = starknet_gateway_types::reply::state_update::StateDiff {
        storage_diffs,
        deployed_contracts,
        old_declared_contracts: state_update.declared_cairo_classes,
        declared_classes,
        nonces,
        replaced_classes,
        migrated_compiled_classes,
    };

    starknet_gateway_types::reply::StateUpdate {
        block_hash: state_update.block_hash,
        new_root: state_update.state_commitment,
        old_root: state_update.parent_state_commitment,
        state_diff,
    }
}
