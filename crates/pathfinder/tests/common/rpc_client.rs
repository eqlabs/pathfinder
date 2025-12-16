//! Utilities for interacting with the RPC interface of a Pathfinder instance.

use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use tokio::sync::watch;
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
) -> JoinHandle<()> {
    tokio::spawn(wait_for_height_fut(
        instance.name(),
        instance.rpc_port_watch_rx().clone(),
        height,
        poll_interval,
    ))
}

/// Waits until the node at `rpc_port` has reached at least `height`.
/// Polls every `poll_interval`.
async fn wait_for_height_fut(
    name: &'static str,
    mut rpc_port_watch_rx: watch::Receiver<(u32, u16)>,
    height: u64,
    poll_interval: Duration,
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

        let Ok(JsonRpcReply {
            result:
                ConsensusInfoResult {
                    highest_decided_height,
                    ..
                },
        }) = get_consensus_info(name, rpc_port).await
        else {
            println!(
                "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} not responding yet"
            );
            continue;
        };

        println!(
            "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} decided height: \
             {highest_decided_height:?}"
        );

        if let Some(highest_decided_height) = highest_decided_height {
            if highest_decided_height >= height {
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
        block_hash: String,
    }

    async fn get_block_with_receipts(
        rpc_port: u16,
        block_height: u64,
    ) -> anyhow::Result<JsonRpcReply<Option<Block>>> {
        let reply = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{rpc_port}"))
            .body(format!(
                r#"{{
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "starknet_getBlockWithReceipts",
                    "params": {{
                        "block_id": {{
                            "block_number": {block_height}
                        }}
                    }}
                }}"#,
            ))
            .header("Content-Type", "application/json")
            .send()
            .await
            .with_context(|| format!("Sending JSON-RPC request to get block {block_height}"))?;

        let parsed = reply
            .json::<JsonRpcReply<Option<Block>>>()
            .await
            .with_context(|| format!("Parsing JSON-RPC response for block {block_height}"))?;

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

        let Ok(reply) = get_block_with_receipts(rpc_port, block_height).await else {
            println!(
                "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} not responding yet"
            );
            continue;
        };

        if let Some(b) = reply.result {
            if b.block_number == block_height {
                println!(
                    "Pathfinder instance {name:<7} (pid: {pid}) port {rpc_port} has block \
                     {block_height} with hash {}",
                    b.block_hash
                );
                return;
            }
        }
    }
}

pub async fn get_consensus_info(
    name: &'static str,
    rpc_port: u16,
) -> anyhow::Result<JsonRpcReply<ConsensusInfoResult>> {
    reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{rpc_port}/rpc/pathfinder/unstable"
        ))
        .body(r#"{"jsonrpc":"2.0","id":0,"method":"pathfinder_consensusInfo","params":[]}"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .with_context(|| format!("Sending JSON-RPC request as {name}"))?
        .json::<JsonRpcReply<ConsensusInfoResult>>()
        .await
        .with_context(|| format!("Parsing JSON-RPC response as {name}"))
}

#[derive(Deserialize)]
pub struct JsonRpcReply<T> {
    pub result: T,
}

#[derive(Deserialize)]
pub struct ConsensusInfoResult {
    pub highest_decided_height: Option<u64>,
    pub peer_score_change_counter: Option<u64>,
}
