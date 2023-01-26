//! An example which showcases how to handle L1 chain reorganisations.
//!
//! The intent is to follow the L1 chain and keep a set amount of local history.
//! This local history should be maintained even when L1 chain reorganisations occur.

use std::{collections::VecDeque, io::Write, time::Duration};

use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{Block, BlockId, BlockNumber, H256};
use reqwest::Url;

#[tokio::main]
async fn main() {
    let provider = setup_provider();
    /// The maximum amount of blocks to keep.
    const MAX_HISTORY: usize = 128;

    let mut history = VecDeque::with_capacity(MAX_HISTORY);

    loop {
        if history.is_empty() {
            let block = init_local_head(&provider, MAX_HISTORY as u64).await;
            history.push_back(block.clone());
        }
        // Safe as we always check empty above.
        let latest_local = history.back().unwrap();

        match get_next_block(&provider, latest_local).await {
            Ok(block) => {
                let block_no = block.number.unwrap();

                // Only keep MAX_HISTORY elements.
                if history.len() + 1 > MAX_HISTORY {
                    history.pop_front();
                }

                history.push_back(block);

                println!(
                    "Downloaded block {} (history length: {})",
                    block_no,
                    history.len()
                );
            }
            Err(_reorg) => {
                let old_length = history.len();
                handle_reorg(&provider, &mut history).await;
                let new_length = history.len();

                println!(
                    "Reorg event, deleted {} most recent blocks (out of {})",
                    old_length - new_length,
                    old_length
                );
            }
        }
    }
}

/// Downloads a block `depth` away from the latest on chain.
async fn init_local_head(provider: &Provider<Http>, depth: u64) -> Block<H256> {
    let l1_latest = provider
        .get_block_number()
        .await
        .expect("Failed to get latest block number from Ethereum");

    // Start back a bit so that we don't have to wait to fill up history.
    let local_head = l1_latest - depth;
    provider
        .get_block(BlockId::Number(BlockNumber::Number(local_head)))
        .await
        .expect("Failed to read block")
        .expect("Earliest block is missing")
}

/// Handles L1 chain reorgs, by deleting history until we are back in sync
/// with the L1 chain.
async fn handle_reorg(provider: &Provider<Http>, history: &mut VecDeque<Block<H256>>) {
    let mut delete_count = 0;
    for block in history.iter().rev() {
        let number = block.number.unwrap();
        let number = BlockId::Number(BlockNumber::Number(number));
        let l1_block = provider.get_block(number).await.unwrap();

        if let Some(l1_block) = l1_block {
            if &l1_block == block {
                break;
            }
        }

        delete_count += 1;
    }

    for _ in 0..delete_count {
        history.pop_back();
    }
}

/// Indicates that a reorg occurred.
struct Reorg;

/// Retrieve the next block from L1. If we have reached L1 HEAD, will poll until
/// next block is available.
///
/// Returns [Err(Reorg)] if an L1 chain reorganization occurred.
async fn get_next_block(
    provider: &Provider<Http>,
    local_head: &Block<H256>,
) -> Result<Block<H256>, Reorg> {
    let local_number = local_head.number.expect("Block should have number");
    let next_block = local_number + 1u64;
    let next_block = BlockId::Number(BlockNumber::Number(next_block));

    // A tracker to allow better printing.
    let mut sleep_mode = false;

    loop {
        match provider
            .get_block(next_block)
            .await
            .expect("Failed to read block")
        {
            Some(block) => match block.parent_hash == local_head.hash.unwrap() {
                true => {
                    if sleep_mode {
                        println!();
                    }
                    return Ok(block);
                }
                false => {
                    if sleep_mode {
                        println!();
                    }
                    return Err(Reorg);
                }
            },
            None => {
                // Block does not exist, this could be because we have reach the HEAD, or because
                // there was a reorg and the requested block number is far ahead of reality.
                let l1_latest = provider
                    .get_block_number()
                    .await
                    .expect("Failed to get latest block number from Ethereum");

                match l1_latest < local_number {
                    true => {
                        if sleep_mode {
                            println!();
                        }
                        return Err(Reorg);
                    }
                    false => {
                        match sleep_mode {
                            true => {
                                print!(".");
                                std::io::stdout().flush().unwrap();
                            }
                            false => {
                                sleep_mode = true;
                                print!("No new block, sleeping ");
                                std::io::stdout().flush().unwrap();
                            }
                        }

                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }
}

/// Creates the Ethereum conntection for the Goerli test network,
/// using the `PATHFINDER_ETHEREUM_HTTP_GOERLI_xxx` environment
/// variables.
fn setup_provider() -> Provider<Http> {
    let key_prefix = "PATHFINDER_ETHEREUM_HTTP_GOERLI";

    let url_key = format!("{key_prefix}_URL");
    let password_key = format!("{key_prefix}_PASSWORD");

    let url = std::env::var(&url_key)
        .unwrap_or_else(|_| panic!("Ethereum URL environment var not set {url_key}"));

    let password = std::env::var(password_key).ok();

    let mut url = url.parse::<Url>().expect("Bad Ethereum URL");
    url.set_password(password.as_deref()).unwrap();

    let provider = Http::new(url);

    Provider::new(provider)
}
