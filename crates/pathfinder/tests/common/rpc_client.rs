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
) -> JoinHandle<anyhow::Result<()>> {
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
    mut rpc_port_watch_rx: watch::Receiver<u16>,
    height: u64,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    rpc_port_watch_rx
        .wait_for(|port| *port != 0)
        .await
        .context("Waiting for port to change from 0")?;

    loop {
        let rpc_port = *rpc_port_watch_rx.borrow();

        // Sleeping first actually makes sense here, because the node will likely not
        // have any decided heights immediately after the RPC server is ready.
        sleep(poll_interval).await;

        let Ok(reply) = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{rpc_port}/rpc/pathfinder/unstable"
            ))
            .body(r#"{"jsonrpc":"2.0","id":0,"method":"pathfinder_consensusInfo","params":[]}"#)
            .header("Content-Type", "application/json")
            .send()
            .await
        else {
            println!("Pathfinder instance {name:<7} not responding yet");
            continue;
        };

        let Reply {
            result: Height {
                highest_decided_height,
            },
        } = reply.json::<Reply>().await.unwrap();

        println!("Pathfinder instance {name:<7} decided height: {highest_decided_height:?}");

        if let Some(highest_decided_height) = highest_decided_height {
            if highest_decided_height >= height {
                return Ok(());
            }
        }
    }
}

#[derive(Deserialize)]
struct Reply {
    result: Height,
}

#[derive(Deserialize)]
struct Height {
    highest_decided_height: Option<u64>,
}
