//! Utilities for interacting with the RPC interface of a Pathfinder instance.

use std::time::Duration;

use serde::Deserialize;
use tokio::time::sleep;

/// Waits until the node at `rpc_port` has reached at least `height`.
/// Polls every `poll_interval`.
pub async fn wait_for_height(
    name: &'static str,
    rpc_port: u16,
    height: u64,
    poll_interval: Duration,
) {
    loop {
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
                return;
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
