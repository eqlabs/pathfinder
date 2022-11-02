#![deny(rust_2018_idioms)]

use std::path::Path;

use clap::Parser;
use libp2p::identity::Keypair;
use libp2p::Multiaddr;
use serde_derive::Deserialize;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, value_parser, env = "IDENTITY_CONFIG_FILE")]
    identity_config_file: Option<std::path::PathBuf>,
    #[clap(long, value_parser, env = "LISTEN_ON")]
    listen_on: Multiaddr,
    #[clap(long, value_parser, env = "BOOTSTRAP_ADDRESSES")]
    bootstrap_addresses: Vec<Multiaddr>,
}

#[derive(Clone, Deserialize)]
struct IdentityConfig {
    pub private_key: String,
}

impl IdentityConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

impl zeroize::Zeroize for IdentityConfig {
    fn zeroize(&mut self) {
        self.private_key.zeroize()
    }
}

pub struct TokioExecutor();

impl libp2p::core::Executor for TokioExecutor {
    fn exec(
        &self,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static + Send>>,
    ) {
        tokio::task::spawn(future);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    setup_tracing();

    let args = Args::parse();
    let keypair = match &args.identity_config_file {
        Some(path) => {
            let config = Zeroizing::new(IdentityConfig::from_file(path.as_path())?);
            let private_key = Zeroizing::new(base64::decode(config.private_key.as_bytes())?);
            Keypair::from_protobuf_encoding(&private_key)?
        }
        None => {
            tracing::info!("No private key configured, generating a new one");
            Keypair::Ed25519(libp2p::identity::ed25519::Keypair::generate())
        }
    };

    let peer_id = keypair.public().to_peer_id();
    tracing::info!(%peer_id, "Starting up");

    let capabilities = ["core/block-propagate/1", "core/blocks-sync/1"];
    let p2p_task = p2p::start(
        keypair,
        args.listen_on,
        args.bootstrap_addresses,
        &capabilities,
        // SN_GOERLI chain ID
        0x534e5f474f45524c49u128,
    )?;
    p2p_task.await?;

    Ok(())
}

fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();
}
