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

    let l1_client =
        ethereum::Client::new(config.ethereum).expect("Failed to create Ethereum client");

    let state_root = l1_client
        .latest_state_root()
        .await
        .expect("Failed to query L1 state root");

    println!("The latest state root hash is: {:#16x}", state_root);

    rpc::run_server(config.http_rpc_addr)
        .await
        .expect("⚠️ Failed to start HTTP-RPC server");

    println!("🛑 Node stopped.");
}
