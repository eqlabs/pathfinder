use pathfinder_lib::{config, rpc};

#[tokio::main]
async fn main() {
    println!("🏁 Starting node.");

    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().expect("Configuration failed");

    rpc::run_server(config.http_rpc_addr)
        .await
        .expect("⚠️ Failed to start HTTP-RPC server");

    println!("🛑 Node stopped.");
}
