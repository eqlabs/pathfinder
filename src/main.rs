mod config;
mod ethereum;
mod rpc;
mod sequencer;

#[tokio::main]
async fn main() {
    println!("🏁 Starting node.");

    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().expect("Configuration failed");

    // let l1_client =
    //     ethereum::Client::new(config.ethereum).expect("Failed to create Ethereum client");

    // let state_root = l1_client
    //     .latest_state_root()
    //     .await
    //     .expect("Failed to query L1 state root");

    // println!("The latest state root hash is: {:#16x}", state_root);

    rpc::rpc_server::run_server(&config.http_rpc)
        .await
        .expect("Running HTTP-RPC server failed");

    println!("🛑 Node stopped.");
}
