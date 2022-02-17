use pathfinder_lib::{config, rpc, sequencer, storage::Storage};

#[tokio::main]
async fn main() {
    println!("🏁 Starting node.");
    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().expect("Configuration failed");

    // TODO: get database path from configuration
    let storage = Storage::migrate("database.sqlite".into()).unwrap();
    // TODO: pass the correct value from ethereum::chain.
    let sequencer = sequencer::Client::new(pathfinder_lib::ethereum::Chain::Goerli).unwrap();
    let api = rpc::api::RpcApi::new(storage, sequencer, pathfinder_lib::ethereum::Chain::Goerli);

    let (_handle, local_addr) =
        rpc::run_server(config.http_rpc_addr, api).expect("⚠️ Failed to start HTTP-RPC server");
    println!("📡 HTTP-RPC server started on: {}", local_addr);
    let () = std::future::pending().await;
}
