use std::fs;
use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use clap::Parser;
use pathfinder_common::BlockNumber;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(
        long,
        value_name = "db.sqlite",
        long_help = "Path to database file (must exist)",
        default_value = "mainnet.sqlite"
    )]
    pub db: PathBuf,
    #[arg(
        long,
        short = 'f',
        value_name = "n",
        long_help = "First block of the dumped range",
        default_value = "0"
    )]
    pub from_block: u64,
    #[arg(
        long,
        short = 't',
        value_name = "n",
        long_help = "Last block of the dumped range",
        default_value = "100"
    )]
    pub to_block: u64,
    #[arg(
        long,
        value_name = "output",
        long_help = "Path to output directory",
        default_value = "ground"
    )]
    pub output_dir: PathBuf,
}

fn make_ground_path(dir: &Path, from_block: u64, to_block: u64) -> PathBuf {
    let basename = if from_block == to_block {
        from_block.to_string()
    } else {
        format!("{}+{}", from_block, to_block - from_block)
    };
    let name = format!("{}.jsonl", basename);
    dir.join(name)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let storage = pathfinder_storage::StorageBuilder::file(cli.db)
        .migrate()?
        .create_pool(NonZeroU32::new(10).unwrap())?;
    let mut db_conn = storage.connection()?;
    let db_tx = db_conn.transaction()?;
    fs::create_dir_all(&cli.output_dir)?;
    let output_dir = fs::canonicalize(&cli.output_dir)?;
    let output_path = make_ground_path(&output_dir, cli.from_block, cli.to_block);
    let mut output_file = fs::File::create(output_path)?;
    for n in cli.from_block..=cli.to_block {
        let bn = BlockNumber::new(n).ok_or_else(|| anyhow!("invalid block number {}", n))?;
        if let Some(pairs) = db_tx.events_for_block(bn.into())? {
            for pair in pairs {
                let tx_hash = pair.0;
                for event in &pair.1 {
                    let v = serde_json::json!({
                        "block_number": n,
                        "data": event.data,
                        "from_address": event.from_address,
                        "keys": event.keys,
                        "transaction_hash": tx_hash.clone(),
                    });
                    writeln!(&mut output_file, "{}", v)?;
                }
            }
        }
    }

    Ok(())
}
