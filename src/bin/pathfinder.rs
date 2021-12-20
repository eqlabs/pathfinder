use pathfinder_lib::{config, rpc};

#[tokio::main]
async fn main() {
    println!("🏁 Starting node.");

    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().expect("Configuration failed");

    let _handle = rpc::run_server(config.http_rpc_addr).expect("⚠️ Failed to start HTTP-RPC server");
    let () = std::future::pending().await;
}
