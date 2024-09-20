use std::collections::BTreeSet;
use std::env::args;
use std::fs::create_dir;
use std::time::Duration;

use anyhow::Context;
use futures::{stream, StreamExt, TryStreamExt};
use pathfinder_common::BlockNumber;
use starknet_gateway_types::reply::{Block, StateUpdate};

#[allow(unused)]
#[derive(serde::Deserialize)]
struct BlockAndStateUpdate {
    block: Block,
    state_update: StateUpdate,
}

#[allow(unused)]
#[derive(serde::Deserialize)]
struct Head {
    block_hash: String,
    block_number: u64,
}

/// Download blocks and state updates from the mainnet feeder gateway. Store
/// each pair in a separate file.
///
/// Example usage:
/// `while true; do cargo run --release -p pathfinder --example fgw_downloader
/// -- API_KEY NETWORK [START]; sleep 5; done`
///
/// NETWORK is either `mainnet` or `sepolia`.
#[tokio::main(flavor = "multi_thread", worker_threads = 64)]
async fn main() -> anyhow::Result<()> {
    let api_key = args()
        .nth(1)
        .context("Missing API key")?;

    let network = args()
        .nth(2)
        .context("Missing network")?;

    let cli_start = match args().nth(3) {
        Some(start) => Some(BlockNumber::new(start.parse::<u64>().context("Invalid start block")?).context("Invalid start block")?),
        None => None,
    };

    anyhow::ensure!(
        network == "mainnet" || network == "sepolia",
        "Invalid network: {network}"
    );

    let download_dir = format!("./downloaded-{}", network);

    match create_dir(&download_dir) {
        Ok(_) => println!("Created directory: {download_dir}"),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            println!("Directory already exists: {download_dir}")
        }
        Err(e) => return Err(e).with_context(|| format!("Creating directory {download_dir}")),
    }

    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(120))
        .build()?;

    let Head {
        block_number: head,
        ..
    } = client.get(format!("https://alpha-{network}.starknet.io/feeder_gateway/get_block?blockNumber=latest&headerOnly=true")).send().await?.json::<Head>().await?;

    // let concurrency_limit = std::thread::available_parallelism()?.get() * 16;
    let concurrency_limit = std::thread::available_parallelism()?.get();

    let files = std::fs::read_dir(&download_dir)
        .with_context(|| format!("Reading directory: {download_dir}"))?;
    let files = files
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|file_name| {
            file_name
                .strip_suffix(".json.zst")
                .and_then(|block_number| block_number.parse::<i64>().ok())
        })
        .collect::<BTreeSet<_>>();

    let mut gaps = Vec::new();

    let last = files
        .into_iter()
        .scan(0i64, |expected, block_number| {
            if block_number == *expected {
                // No gap
            } else {
                let gap_size = block_number - *expected;
                for i in 0..gap_size {
                    gaps.push((*expected + i) as u64);
                }
            }

            *expected = block_number + 1;
            Some(block_number + 1)
        })
        .last()
        .unwrap_or(-1);

    println!("Num gaps: {}", gaps.len());
    println!("Last: {last}");

    let start = BlockNumber::new((last + 1) as u64)
        .ok_or(anyhow::anyhow!("Block number overflow"))
        .context("Start block")?;
    let start = std::cmp::min(start, cli_start.unwrap_or(start));

    println!("Start: {start}");

    stream::iter(gaps).chain(stream::iter(start.get()..=head))
        .map(anyhow::Result::<u64>::Ok)
        .try_for_each_concurrent(concurrency_limit, |block_number| {
            let client = client.clone();
            let api_key = api_key.clone();
            let network = network.clone();
            let download_dir = download_dir.clone();

            async move {
                println!("Get:  {block_number}");

                let cloned_api_key = api_key.clone();

                let block_txt = client.get(format!("https://alpha-{network}.starknet.io/feeder_gateway/get_state_update?blockNumber={block_number}&includeBlock=true"))
                    .header("X-Throttling-Bypass", cloned_api_key).send().await?.text().await?;

                let block_and_state_update = serde_json::from_str::<BlockAndStateUpdate>(&block_txt).context("Deserialize block and state update")?;
                let declared_classes = block_and_state_update.state_update.state_diff.declared_classes.iter().map(|x| x.class_hash);

                let classes_txt = stream::iter(declared_classes).map(|class_hash| {
                    let client = client.clone();
                    let api_key = api_key.clone();
                    let network = network.clone();

                    async move {
                        let class_txt = client.get(format!("https://alpha-{network}.starknet.io/feeder_gateway/get_class_by_hash?classHash={class_hash}&blockNumber=pending"))
                        .header("X-Throttling-Bypass", api_key).send().await?.text().await?;
    
                        anyhow::Ok(class_txt)
                    }
                }).buffer_unordered(concurrency_limit).try_collect::<Vec<_>>().await?;

                let classes_txt = classes_txt.join(",");

                let final_txt = format!(
                    "{{
                        \"block\": {block_txt},
                        \"classes\": [{classes_txt}]
                    }}",
                );

                tokio::task::spawn_blocking(move ||
                    {
                        let compressed = zstd::encode_all(final_txt.as_bytes(), 10)?;
                        std::fs::write(format!("{download_dir}/{block_number}.json.zst"), compressed)?;
                        std::io::Result::Ok(())
                    }
                ).await.context("Join blocking task")?.with_context(|| format!("Writing block: {block_number}"))?;

                println!("Done: {block_number}");

                anyhow::Result::Ok(())
            }
        })
        .await.context("Downloading failed")?;

    Ok(())
}
