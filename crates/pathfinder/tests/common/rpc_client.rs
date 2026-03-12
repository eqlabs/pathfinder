//! Utilities for interacting with the RPC interface of a Pathfinder instance.

use std::time::Duration;

use anyhow::Context as _;
use p2p::consensus::HeightAndRound;
use pathfinder_common::{consensus_info, TransactionHash};
use serde::Deserialize;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::common::pathfinder_instance::PathfinderInstance;

/// Spawns a task which waits until the node at `rpc_port` has reached at least
/// `height`. Polls every `poll_interval`. Returns a handle to the spawned task
/// that runs the rpc client.
pub fn wait_for_height(
    instance: &PathfinderInstance,
    height: u64,
    poll_interval: Duration,
    next_hnr_tx: Option<mpsc::Sender<HeightAndRound>>,
    err_tx: mpsc::Sender<anyhow::Error>,
) -> JoinHandle<()> {
    tokio::spawn(wait_for_height_fut(
        instance.name(),
        instance.rpc_port_watch_rx().clone(),
        height,
        poll_interval,
        next_hnr_tx,
        err_tx,
    ))
}

/// Waits until the node at `rpc_port` has reached at least `height`.
/// Polls every `poll_interval`.
async fn wait_for_height_fut(
    name: &'static str,
    mut rpc_port_watch_rx: watch::Receiver<(u32, u16)>,
    height: u64,
    poll_interval: Duration,
    next_hnr_tx: Option<mpsc::Sender<HeightAndRound>>,
    error_tx: mpsc::Sender<anyhow::Error>,
) {
    let mut last_hnr = None;

    loop {
        // Sleeping first actually makes sense here, because the node will likely not
        // have any decided heights immediately after the RPC server is ready.
        sleep(poll_interval).await;

        // We're waiting for the rpc port to change from 0 on each iteriation, because
        // in case of tests where the instance is terminated and then respawned the RPC
        // port number will temporarily be reset to 0.
        let (pid, rpc_port) =
            if let Ok(borrowed) = rpc_port_watch_rx.wait_for(|port| *port != (0, 0)).await {
                *borrowed
            } else {
                println!("Rpc port watch for {name} is closed");
                continue;
            };

        let highest_decided = match handle_reply(
            get_consensus_info(rpc_port).await,
            name,
            pid,
            rpc_port,
            "consensus info",
            error_tx.clone(),
        )
        .await
        {
            HandleReplyResult::Process(ConsensusInfoOutput {
                highest_decided, ..
            }) => highest_decided,
            HandleReplyResult::Continue => continue,
            HandleReplyResult::Bail => return,
        };

        println!(
            "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} decided h:r {}",
            highest_decided
                .as_ref()
                .map(|info| format!("{}", HeightAndRound::new(info.height.get(), info.round)))
                .unwrap_or("None".to_string()),
        );

        if let Some(highest_decided) = highest_decided {
            let current = HeightAndRound::new(highest_decided.height.get(), highest_decided.round);

            if let Some(tx) = &next_hnr_tx {
                if last_hnr.is_none() || last_hnr.as_ref() != Some(&current) {
                    last_hnr = Some(current);
                    let _ = tx.send(current).await;
                }
            }

            if highest_decided.height.get() >= height {
                return;
            }
        }
    }
}

pub fn wait_for_block_exists(
    instance: &PathfinderInstance,
    block_height: u64,
    poll_interval: Duration,
    disallow_reverted_txns: bool,
    error_tx: mpsc::Sender<anyhow::Error>,
) -> JoinHandle<()> {
    tokio::spawn(wait_for_block_exists_fut(
        instance.name(),
        instance.rpc_port_watch_rx().clone(),
        block_height,
        poll_interval,
        disallow_reverted_txns,
        error_tx,
    ))
}

async fn wait_for_block_exists_fut(
    name: &'static str,
    mut rpc_port_watch_rx: watch::Receiver<(u32, u16)>,
    block_height: u64,
    poll_interval: Duration,
    disallow_reverted_txns: bool,
    // Propagates deserialization and unexpected reverted transaction errors back to the test. This
    // way we can bail out earlier instead of waiting for the `utils::join_all` timeout, which will
    // still mask the actual error.
    error_tx: mpsc::Sender<anyhow::Error>,
) {
    loop {
        // Sleeping first actually makes sense here, because the node will likely not
        // have any decided heights immediately after the RPC server is ready.
        sleep(poll_interval).await;

        // We're waiting for the rpc port to change from 0 on each iteriation, because
        // in case of tests where the instance is terminated and then respawned the RPC
        // port number will temporarily be reset to 0.
        let (pid, rpc_port) =
            if let Ok(borrowed) = rpc_port_watch_rx.wait_for(|port| *port != (0, 0)).await {
                *borrowed
            } else {
                println!("Rpc port watch for {name} is closed");
                continue;
            };

        let block = match handle_reply(
            get_latest_block_with_receipts(rpc_port).await,
            name,
            pid,
            rpc_port,
            "latest block",
            error_tx.clone(),
        )
        .await
        {
            HandleReplyResult::Process(block) => block,
            HandleReplyResult::Continue => continue,
            HandleReplyResult::Bail => return,
        };

        if disallow_reverted_txns {
            let reverted_txns = block
                .transactions
                .iter()
                .filter_map(|tx| {
                    matches!(tx.receipt.execution_status, ExecutionStatus::Reverted)
                        .then_some(tx.receipt.transaction_hash)
                })
                .collect::<Vec<_>>();
            if !reverted_txns.is_empty() {
                error_tx
                    .send(anyhow::anyhow!(
                        "Unexpected reverted transactions in block {}: {reverted_txns:?}",
                        block.block_number
                    ))
                    .await
                    .unwrap();
            }
        }

        if block.block_number < block_height {
            println!(
                "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} has block {} < \
                 {block_height}",
                block.block_number
            );
        } else {
            println!(
                "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} has block \
                 {block_height}",
            );
            // Finally, success!
            return;
        }
    }
}

enum HandleReplyResult<T> {
    Process(T),
    Continue,
    Bail,
}

async fn handle_reply<T>(
    reply: Result<JsonRpcReply2<T>, reqwest::Error>,
    name: &'static str,
    pid: u32,
    rpc_port: u16,
    artifact_name: &'static str,
    error_tx: mpsc::Sender<anyhow::Error>,
) -> HandleReplyResult<T> {
    match reply {
        Ok(JsonRpcReply2::Success { result, .. }) => HandleReplyResult::Process(result),
        Ok(JsonRpcReply2::Error { .. }) => {
            println!(
                "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} {artifact_name} \
                 unavailable yet"
            );
            // It seems like the node does not have this artifact available yet, but it
            // might be available soon, so let's just wait.
            HandleReplyResult::Continue
        }
        Err(error) if error.is_decode() => {
            error_tx
                .send(anyhow::Error::new(error).context(format!(
                    "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} malformed RPC \
                     response"
                )))
                .await
                .unwrap();
            // We're can't fix the issue here, waiting won't work either, we're done
            HandleReplyResult::Bail
        }
        Err(_) => {
            // There's not much we can do here. Some of these maybe be send errors due to
            // the node being in the process of being respawned, so let's just wait.
            HandleReplyResult::Continue
        }
    }
}

pub async fn get_consensus_info(
    rpc_port: u16,
) -> Result<JsonRpcReply2<ConsensusInfoOutput>, reqwest::Error> {
    reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{rpc_port}/rpc/pathfinder/unstable"
        ))
        .body(r#"{"jsonrpc":"2.0","id":0,"method":"pathfinder_consensusInfo","params":[]}"#)
        .header("Content-Type", "application/json")
        .send()
        .await?
        .json::<JsonRpcReply2<ConsensusInfoOutput>>()
        .await
}

pub async fn get_cached_artifacts_info(
    instance: &PathfinderInstance,
    less_than_height: u64,
) -> anyhow::Result<Vec<CachedItem>> {
    let fut = async move {
        let name = instance.name();
        let mut rpc_port_watch_rx = instance.rpc_port_watch_rx().clone();
        // If any of the nodes crashes we need to timeout otherwise the test will just
        // hang forever.
        let (pid, rpc_port) =
            if let Ok(borrowed) = rpc_port_watch_rx.wait_for(|port| *port != (0, 0)).await {
                *borrowed
            } else {
                panic!("Rpc port watch for {name} is closed");
            };

        let mut cached = match get_consensus_info(rpc_port).await {
            Ok(JsonRpcReply2::Success {
                result: ConsensusInfoOutput { cached, .. },
                ..
            }) => cached,
            Ok(JsonRpcReply2::Error { .. }) => {
                anyhow::bail!(
                    "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} consensus info \
                     unavailable yet"
                );
            }
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!(
                    "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} malformed RPC \
                     response"
                )));
            }
        };
        cached.retain(|CachedItem { height, .. }| *height < less_than_height);
        Ok(cached)
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .context("Getting cached artifacts info timed out")
        .and_then(|x| x)
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum JsonRpcReply2<T> {
    Success {
        #[serde(rename = "id")]
        _id: u64,
        #[serde(rename = "jsonrpc")]
        _jsonrpc: serde_json::Value,
        result: T,
    },
    Error {
        #[serde(rename = "id")]
        _id: u64,
        #[serde(rename = "jsonrpc")]
        _jsonrpc: serde_json::Value,
        #[serde(rename = "error")]
        _error: serde_json::Value,
    },
}

#[derive(Debug, Deserialize)]
pub struct ConsensusInfoOutput {
    pub highest_decided: Option<consensus_info::Decision>,
    pub application_peer_scores: Vec<ApplicationPeerScore>,
    pub cached: Vec<CachedItem>,
}

#[derive(Debug, Deserialize)]
pub struct ApplicationPeerScore {
    #[serde(alias = "peer_id")]
    pub _peer_id: String,
    pub score: f64,
}

#[derive(Debug, Deserialize)]
pub struct CachedItem {
    pub height: u64,
    #[serde(alias = "proposals")]
    pub _proposals: Vec<consensus_info::ProposalParts>,
    #[serde(alias = "blocks")]
    pub _blocks: Vec<consensus_info::FinalizedBlock>,
}

#[derive(Deserialize)]
struct Block {
    block_number: u64,
    transactions: Vec<ReceiptAndTransaction>,
}

#[derive(Deserialize)]
struct ReceiptAndTransaction {
    receipt: Receipt,
}

#[derive(Deserialize)]
struct Receipt {
    execution_status: ExecutionStatus,
    transaction_hash: TransactionHash,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ExecutionStatus {
    Succeeded,
    Reverted,
}

async fn get_latest_block_with_receipts(
    rpc_port: u16,
) -> Result<JsonRpcReply2<Block>, reqwest::Error> {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{rpc_port}"))
        .body(
            r#"{
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "starknet_getBlockWithReceipts",
                    "params": {
                        "block_id": "latest"
                    }
                }"#,
        )
        .header("Content-Type", "application/json")
        .send()
        .await?
        .json::<JsonRpcReply2<Block>>()
        .await
}
