use anyhow::Context;
use futures::{stream, StreamExt, TryStreamExt};
use starknet_gateway_types::reply::{Block, StateUpdate};
use std::collections::BTreeSet;
use std::env::args;

#[allow(unused)]
#[derive(serde::Deserialize)]
struct BlockAndStateUpdate {
    block: Block,
    state_update: StateUpdate,
}

/// Verifies the downloaded DTOs.
///
/// Example usage:
/// `cargo run --release -p pathfinder --example fgw_dto_verifier -- ./download_dir`
#[tokio::main(flavor = "multi_thread", worker_threads = 64)]
async fn main() -> anyhow::Result<()> {
    let dto_dir = args()
        .nth(1)
        .ok_or(anyhow::anyhow!("Missing DTO directory"))
        .context("DTO directory")?;

    let start = args()
        .nth(2)
        .map(|s| s.parse::<u64>().context("Parsing start block"))
        .transpose()?
        .unwrap_or_default();

    let concurrency_limit = std::thread::available_parallelism()?.get() * 16;

    let files = std::fs::read_dir(dto_dir.clone())
        .with_context(|| format!("Reading directory: {}", dto_dir))?;
    let block_numbers = files
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .map(|file_name| {
            file_name
                .strip_suffix(".json.zst")
                .unwrap_or(&file_name)
                .parse::<u64>()
                .unwrap_or_default()
        })
        .skip_while(|n| *n < start)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    stream::iter(block_numbers)
        .map(anyhow::Ok)
        .try_for_each_concurrent(concurrency_limit, |block_number| {
            let dto_dir = dto_dir.clone();
            async move {
                let file_path = format!("{}/{}.json.zst", dto_dir, block_number);

                println!("Read: {block_number}");

                let bytes = tokio::task::spawn_blocking(move || {
                    let bytes = std::fs::read(&file_path)
                        .with_context(|| format!("Reading: {block_number}.json.zst"))?;

                    zstd::decode_all(&bytes[..])
                        .with_context(|| format!("Decompressing {block_number}.json.zst"))
                })
                .await
                .context("Joining blocking task")??;

                match serde_json::from_slice::<BlockAndStateUpdate>(&bytes) {
                    Ok(_) => println!("Done: {block_number}"),
                    Err(error) => panic!("Failed to deserialize: {block_number}, error: {error}"),
                };

                anyhow::Result::Ok(())
            }
        })
        .await
        .context("Stream failed")?;

    Ok(())
}
