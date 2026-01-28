use std::fs;
use std::io::Write;
use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use pathfinder_common::{BlockNumber, ContractAddress, EventKey};
use pathfinder_crypto::{Felt, HexParseError};
use serde_json::json;

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
        short = 'a',
        value_name = "addr",
        long_help = "Filter output by this from address"
    )]
    pub address: Option<String>,
    #[arg(
        long,
        short = 'k',
        value_name = "list",
        long_help = "Filter output by these keys"
    )]
    pub keys: Option<String>,
    #[arg(
        long,
        value_name = "output",
        long_help = "Path to output directory",
        default_value = "ground"
    )]
    pub output_dir: PathBuf,
}

fn make_ground_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    let dir = fs::canonicalize(&cli.output_dir)?;
    let mut basename = if cli.from_block == cli.to_block {
        cli.from_block.to_string()
    } else {
        format!("{}+{}", cli.from_block, cli.to_block - cli.from_block)
    };

    let filter_number = 0;
    let mut filter_json = json!({});
    if let Some(addr) = &cli.address {
        filter_json["address"] = json!(addr);
    }

    if let Some(raw_keys) = &cli.keys {
        let keys: Vec<_> = raw_keys
            .split(',')
            .map(|s| if s.is_empty() { vec![] } else { vec![s] })
            .collect();
        filter_json["keys"] = json!(keys);
    }

    if let serde_json::Value::Object(ref filter_map) = filter_json {
        if !filter_map.is_empty() {
            let filter_name = format!("{basename}f{filter_number}.json");
            let filter_path = dir.join(filter_name);
            fs::write(filter_path, filter_json.to_string())?;

            basename = format!("{basename}w{filter_number}");
        }
    }

    let name = format!("{basename}.jsonl");
    Ok(dir.join(name))
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let storage = pathfinder_storage::StorageBuilder::file(cli.db.clone())
        .migrate()?
        .create_pool(NonZeroU32::new(10).unwrap())?;
    let mut db_conn = storage.connection()?;
    let db_tx = db_conn.transaction()?;
    fs::create_dir_all(&cli.output_dir)?;
    let output_path = make_ground_path(&cli)?;
    let mut output_file = fs::File::create(output_path)?;

    let address = if let Some(addr) = cli.address {
        let felt = Felt::from_hex_str(&addr)?;
        Some(ContractAddress::new_or_panic(felt))
    } else {
        None
    };

    let keys = if let Some(raw_keys) = cli.keys {
        let cooked_keys = raw_keys
            .trim_end_matches(',')
            .split(',')
            .map(|s| {
                if s.is_empty() {
                    Ok(None)
                } else {
                    let f = Felt::from_hex_str(s)?;
                    Ok(Some(EventKey(f)))
                }
            })
            .collect::<Result<Vec<Option<EventKey>>, HexParseError>>()?;
        Some(cooked_keys)
    } else {
        None
    };

    for n in cli.from_block..=cli.to_block {
        let bn = BlockNumber::new(n).context(format!("invalid block number {n}"))?;
        if let Some(pairs) = db_tx.events_for_block(bn.into())? {
            for pair in pairs {
                let tx_hash = pair.0 .0;
                for event in &pair.1 {
                    let accept_address = if let Some(addr) = address {
                        event.from_address == addr
                    } else {
                        true
                    };
                    let accept_keys = if let Some(ref keys) = keys {
                        if keys.len() > event.keys.len() {
                            false
                        } else {
                            keys.iter().zip(event.keys.iter()).all(|(k, ek)| {
                                if let Some(k) = k {
                                    *k == *ek
                                } else {
                                    true
                                }
                            })
                        }
                    } else {
                        true
                    };
                    if accept_address && accept_keys {
                        let v = json!({
                            "block_number": n,
                            "data": event.data,
                            "from_address": event.from_address,
                            "keys": event.keys,
                            "transaction_hash": tx_hash.clone(),
                        });
                        writeln!(&mut output_file, "{v}")?;
                    }
                }
            }
        }
    }

    Ok(())
}
