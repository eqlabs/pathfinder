//! Utilities for interacting with the RPC interface of a Pathfinder instance.

use std::time::Duration;

use anyhow::Context;
use p2p::consensus::HeightAndRound;
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
) -> JoinHandle<()> {
    tokio::spawn(wait_for_height_fut(
        instance.name(),
        instance.rpc_port_watch_rx().clone(),
        height,
        poll_interval,
        next_hnr_tx,
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

        let Ok(JsonRpcReply {
            result: ConsensusInfo {
                highest_decided, ..
            },
        }) = get_consensus_info(name, rpc_port).await
        else {
            println!(
                "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} not responding yet"
            );
            continue;
        };

        println!(
            "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} decided h:r {}",
            highest_decided
                .as_ref()
                .map(|info| format!("{}", HeightAndRound::new(info.height, info.round)))
                .unwrap_or("None".to_string()),
        );

        if let Some(highest_decided) = highest_decided {
            let current = HeightAndRound::new(highest_decided.height, highest_decided.round);

            if let Some(tx) = &next_hnr_tx {
                if last_hnr.is_none() || last_hnr.as_ref() != Some(&current) {
                    last_hnr = Some(current);
                    let _ = tx.send(current).await;
                }
            }

            if highest_decided.height >= height {
                return;
            }
        }
    }
}

pub fn wait_for_block_exists(
    instance: &PathfinderInstance,
    block_height: u64,
    poll_interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(wait_for_block_exists_fut(
        instance.name(),
        instance.rpc_port_watch_rx().clone(),
        block_height,
        poll_interval,
    ))
}

async fn wait_for_block_exists_fut(
    name: &'static str,
    mut rpc_port_watch_rx: watch::Receiver<(u32, u16)>,
    block_height: u64,
    poll_interval: Duration,
) {
    #[derive(Deserialize)]
    struct Block {
        block_number: u64,
    }

    async fn get_latest_block_with_receipts(
        rpc_port: u16,
    ) -> anyhow::Result<JsonRpcReply<Option<Block>>> {
        let reply = reqwest::Client::new()
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
            .await
            .context("Sending JSON-RPC request to get latest block")?;

        let parsed = reply
            .json::<JsonRpcReply<Option<Block>>>()
            .await
            .context("Sending JSON-RPC request to get latest block")?;

        Ok(parsed)
    }

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

        let Ok(reply) = get_latest_block_with_receipts(rpc_port).await else {
            println!(
                "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} not responding yet"
            );
            continue;
        };

        if let Some(b) = reply.result {
            if b.block_number < block_height {
                println!(
                    "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} has block {} < \
                     {block_height}",
                    b.block_number
                );
            } else {
                println!(
                    "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} has block \
                     {block_height}",
                );
                return;
            }
        }
    }
}

pub async fn get_consensus_info(
    name: &'static str,
    rpc_port: u16,
) -> anyhow::Result<JsonRpcReply<ConsensusInfo>> {
    reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{rpc_port}/rpc/pathfinder/unstable"
        ))
        .body(r#"{"jsonrpc":"2.0","id":0,"method":"pathfinder_consensusInfo","params":[]}"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .with_context(|| format!("Sending JSON-RPC request as {name}"))?
        .json::<JsonRpcReply<ConsensusInfo>>()
        .await
        .with_context(|| format!("Parsing JSON-RPC response as {name}"))
}

#[derive(Deserialize)]
pub struct JsonRpcReply<T> {
    pub result: T,
}

#[derive(Deserialize)]
pub struct ConsensusInfo {
    pub highest_decided: Option<DecisionInfo>,
    pub peer_score_change_counter: Option<u64>,
}

#[derive(Deserialize)]
pub struct DecisionInfo {
    pub height: u64,
    pub round: u32,
}
