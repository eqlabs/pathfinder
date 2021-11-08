use web3::{transports::WebSocket, Web3};

use crate::ethereum::{contract::CoreContract, BlockId};

mod config;
mod ethereum;
mod rpc;
mod sequencer;
mod storage;

#[tokio::main]
async fn main() {
    println!("🏁 Starting node.");

    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().expect("Configuration failed");

    let websocket = WebSocket::new(config.ethereum.url.as_str())
        .await
        .expect("Failed to open Ethereum websocket");
    let websocket = Web3::new(websocket);

    let l1_core_contract = CoreContract::load(websocket);

    let state_root = l1_core_contract
        .state_root(BlockId::Latest)
        .await
        .expect("Failed to query L1 state root");

    println!("The latest state root hash is: {:#16x}", state_root);

    rpc::run_server(config.http_rpc_addr)
        .await
        .expect("⚠️ Failed to start HTTP-RPC server");

    println!("🛑 Node stopped.");
}
