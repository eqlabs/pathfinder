mod config;
mod ethereum;
mod sequencer;

#[tokio::main]
async fn main() {
    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().expect("Configuration failed");

    let l1_client =
        ethereum::Client::new(&config.ethereum_rpc_url).expect("Failed to create Ethereum client");

    let state_root = l1_client
        .latest_state_root()
        .await
        .expect("Failed to query L1 state root");

    println!("The latest state root hash is: {:#16x}", state_root);
}
