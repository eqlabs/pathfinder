use std::num::NonZeroU32;
use std::path::PathBuf;

use clap::Parser;
use pathfinder_common::BlockNumber;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(long_help = "Database path")]
    pub database_path: PathBuf,
    #[arg(long, long_help = "Roll back state to this block", value_parser = parse_block_number)]
    pub target_block: BlockNumber,
}

fn parse_block_number(s: &str) -> Result<BlockNumber, String> {
    let n: u64 = s
        .parse()
        .map_err(|e| format!("Invalid block number '{s}': {e}"))?;
    BlockNumber::new(n).ok_or_else(|| format!("Invalid block number '{s}'"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let storage = pathfinder_storage::StorageBuilder::file(cli.database_path.into())
        .migrate()?
        .create_pool(NonZeroU32::new(10).unwrap())
        .unwrap();

    let mut connection = storage.connection().unwrap();

    pathfinder_lib::state::l2_reorg(&mut connection, cli.target_block)
        .await
        .unwrap();

    Ok(())
}
