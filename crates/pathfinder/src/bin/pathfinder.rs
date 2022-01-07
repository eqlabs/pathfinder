use pathfinder_lib::{config, rpc};

#[tokio::main]
async fn main() {
    println!("🏁 Starting node.");
    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().expect("Configuration failed");
    let (_handle, local_addr) =
        rpc::run_server(config.http_rpc_addr).expect("⚠️ Failed to start HTTP-RPC server");
    println!("📡 HTTP-RPC server started on: {}", local_addr);
    let () = std::future::pending().await;
}
