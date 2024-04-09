use std::collections::HashMap;
use std::convert::Infallible;
use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::state_update::ContractClassUpdate;
use pathfinder_common::{
    state_diff_commitment_bytes, BlockCommitmentSignature, BlockCommitmentSignatureElem, BlockHash,
    BlockNumber, Chain, ClassHash,
};
use pathfinder_storage::BlockId;
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use starknet_gateway_types::reply::GasPrices;
use starknet_gateway_types::reply::{
    state_update::{DeclaredSierraClass, DeployedContract, ReplacedClass, StorageDiff},
    Status,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use warp::Filter;

/// Groups the Starknet contract addresses for a specific chain.
///
/// Getting addresses: <SEQUENCER_URL>/feeder_gateway/get_contract_addresses
pub struct ContractAddresses {
    pub core: H160,
    pub gps: H160,
}

/// Serve feeder gateway REST endpoints required for pathfinder to sync.
///
/// Usage:
/// `cargo run --release -p pathfinder --example feeder_gateway ./testnet-sepolia.sqlite`
///
/// Then pathfinder can be run with the following arguments to use this tool as a sync source:
///
/// ```text
/// cargo run --release -p pathfinder -- \
///     --network custom --chain-id SN_SEPOLIA \
///     --ethereum.url https://eth-sepolia.alchemyapi.io/v2/YOUR_API_KEY
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
    let storage = pathfinder_storage::StorageBuilder::file(database_path.into())
        .migrate()?
        .create_pool(NonZeroU32::new(10).unwrap())
        .unwrap();

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
            move |block_id: BlockIdParam| {
                let storage = storage.clone();
                async move {
                    let header_only = block_id.header_only.unwrap_or(false);

                    match block_id.try_into() {
                        Ok(block_id) => {
                            let block = tokio::task::spawn_blocking(move || {
                                let mut connection = storage.connection().unwrap();
                                let tx = connection.transaction().unwrap();

                                resolve_block(&tx, block_id)
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
            move |block_id: BlockIdParam| {
                let storage = storage.clone();
                async move {
                    let include_block = block_id.include_block.unwrap_or(false);

                    match block_id.try_into() {
                        Ok(block_id) => {
                            let (state_update, block) = tokio::task::spawn_blocking(move || {
                                let mut connection = storage.connection().unwrap();
                                let tx = connection.transaction().unwrap();

                                let state_update = resolve_state_update(&tx, block_id);
                                let block = resolve_block(&tx, block_id);

                                (state_update, block)
                            }).await.unwrap();

                            match (state_update, block) {
                                (Ok(state_update), Ok(block)) => {
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

                                        Ok(warp::reply::json(&reply))
                                    } else {
                                        Ok(warp::reply::json(&state_update))
                                    }
                                },
                                _ => {
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
                .or(get_signature),
        )
        .with(warp::filters::trace::request());

    warp::serve(handler).run(([127, 0, 0, 1], 8080)).await;

    Ok(())
}

fn get_chain(tx: &pathfinder_storage::Transaction<'_>) -> anyhow::Result<Chain> {
    use pathfinder_common::consts::{
        MAINNET_GENESIS_HASH, SEPOLIA_INTEGRATION_GENESIS_HASH, SEPOLIA_TESTNET_GENESIS_HASH,
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

#[tracing::instrument(level = "trace", skip(tx))]
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

    let (transactions, transaction_receipts): (Vec<_>, Vec<_>) = transactions_receipts
        .into_iter()
        .map(|(tx, rx, ev)| (tx, (rx, ev)))
        .unzip();

    let block_status = tx
        .block_is_l1_accepted(header.number.into())
        .context("Querying block status")?;
    let block_status = if block_status {
        Status::AcceptedOnL1
    } else {
        Status::AcceptedOnL2
    };

    Ok(starknet_gateway_types::reply::Block {
        block_hash: header.hash,
        block_number: header.number,
        l1_gas_price: GasPrices {
            price_in_wei: header.eth_l1_gas_price,
            price_in_fri: header.strk_l1_gas_price,
        },
        l1_data_gas_price: GasPrices {
            price_in_wei: header.eth_l1_data_gas_price,
            price_in_fri: header.strk_l1_data_gas_price,
        },
        parent_block_hash: header.parent_hash,
        sequencer_address: Some(header.sequencer_address),
        state_commitment: header.state_commitment,
        status: block_status,
        timestamp: header.timestamp,
        transaction_receipts,
        transactions,
        starknet_version: header.starknet_version,
        l1_da_mode: header.l1_da_mode.into(),
        transaction_commitment: header.transaction_commitment,
        event_commitment: header.event_commitment,
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
        block_number: header.number,
        signature: [signature.r, signature.s],
        signature_input: starknet_gateway_types::reply::BlockSignatureInput {
            block_hash: header.hash,
            state_diff_commitment: state_diff_commitment_bytes!(b"fake commitment"),
        },
    })
}

#[tracing::instrument(level = "trace", skip(tx))]
fn resolve_state_update(
    tx: &pathfinder_storage::Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<starknet_gateway_types::reply::StateUpdate> {
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
        .ok_or_else(|| anyhow::anyhow!("No such class found"))?;

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

    let state_diff = starknet_gateway_types::reply::state_update::StateDiff {
        storage_diffs,
        deployed_contracts,
        old_declared_contracts: state_update.declared_cairo_classes,
        declared_classes,
        nonces,
        replaced_classes,
    };

    starknet_gateway_types::reply::StateUpdate {
        block_hash: state_update.block_hash,
        new_root: state_update.state_commitment,
        old_root: state_update.parent_state_commitment,
        state_diff,
    }
}
