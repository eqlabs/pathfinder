//! Demonstrates how to retrieve a StarkNet state update from L1 using event logs.
//!
//! As a high-level overview of the log events:
//! (in chronological order, for a single state update)
//!
//!     1. Multiple LogMemoryPageFactContinuous get emitted by the MemoryPageFactRegistry contract.
//!        These logs contain no data themselves, but the transactions they were emitted by do.
//!
//!     2. A LogMemoryPagesHashes is emitted by the GpsStatementVerifier contract.
//!        It contains a list of memory pages which can be combined and parsed to
//!        form the actual state update information.
//!
//!     3. The core contract emits two logs, LogStateUpdate and LogStateTransitionFact.
//!        The latter identifies a specific fact (from 2) and links it to this state update.
//!
//! This example assumes you've identified the fact in (3). It then retrieves the logs from (2)
//! until we find one which matches the one you've identified. This log (2) then contains a list
//! of memory page logs (1) which we then retrieve. Finally, we retrieve these memory page logs'
//! data from their transactions which gets parsed into the state update.
//!
//! Note that these logs are spread over multiple L1 transactions and blocks. This example therefore
//! only searches an L1 block range of `N-10_000` : `N` where `N` is the block containing the state
//! update (3).

use std::{collections::HashMap, str::FromStr};

use clap::Arg;
use pathfinder_lib::ethereum::starknet::{Log, Starknet};
use web3::{
    transports::WebSocket,
    types::{BlockNumber, TransactionId, H256},
};

#[tokio::main]
async fn main() {
    let (fact_hash, to_block, ws) = parse_cli_args().await;

    let starknet = Starknet::load(ws);

    // The range of L1 blocks to search for relevant logs.
    //
    // This will not be perfect, but its good enough for this example.
    // A more robust implementation would keep searching backwards until
    // all relevant logs have been found.
    let from_block = to_block - 10_000;

    // Retrieve all StarkNet logs within the L1 block range.
    let logs = starknet
        .retrieve_logs(
            BlockNumber::Number(from_block.into()),
            BlockNumber::Number(to_block.into()),
        )
        .await
        .unwrap();

    // Sort the logs into Fact and Memory Page logs.
    let mut facts = HashMap::new();
    let mut mempages = HashMap::new();
    logs.into_iter().for_each(|log| match log {
        Log::Fact(fact) => {
            facts.insert(fact.hash, fact.mempage_hashes);
        }
        Log::Mempage(mempage) => {
            mempages.insert(mempage.hash, mempage.origin.transaction_hash);
        }
    });

    // Identify the memory page logs of the fact we are interested in.
    let fact_mempages = facts
        .get(&fact_hash)
        .expect("No list of memory pages found for the requested hash");

    // Identify the memory page transactions of that fact.
    let fact_transactions = fact_mempages
        .iter()
        .map(|mp| {
            let t = mempages.get(mp).expect("Memory page log missing");
            TransactionId::Hash(*t)
        })
        .collect::<Vec<_>>();

    // Retrieve the memory page transactions, and interpret it as a state update fact.
    let fact = starknet
        .retrieve_fact(&fact_transactions)
        .await
        .expect("Failed to retrieve the fact's transactions");

    println!("Fact {:?}:\n\n{:#?}", fact_hash, fact);
}

/// Creates the CLI and parses the resulting arguments.
async fn parse_cli_args() -> (H256, u64, WebSocket) {
    let cli = clap::App::new("fact-retrieval")
        .about("Retrieves and displays a StarkNet state update fact")
        .after_help("You can use Etherscan to identify a fact hash to retrieve. The fact hash for a state update is emitted as a `LogStateTransitionFact` log.")
        .arg(
            Arg::with_name("fact")
                .long("fact")
                .takes_value(true)
                .help("The fact hash that you want to retrieve in hex format.")
                .value_name("HASH")
        )
        .arg(
             Arg::with_name("block")
                .long("block")
                .takes_value(true)
                .help("The L1 block number at which the state update occurred.")
        )
        .arg(
            Arg::with_name("url")
                .long("url")
                .takes_value(true)
                .value_name("URL")
                .long_help(r#"This should point to the websocket RPC endpoint of your Ethereum entry-point, typically a local Ethereum client or a hosted gateway service such as Infura or Cloudflare.

Examples:
    infura: wss://goerli.infura.io/ws/v3/<PROJECT_ID>
    geth:   wss://localhost:8545"#));

    let args = cli.get_matches();

    let fact = args.value_of("fact").expect("fact hash is required");
    let url = args.value_of("url").expect("websocket url is required");
    let block = args.value_of("block").expect("block number is requried");

    let fact = H256::from_str(fact).expect("A valid hash string");
    let ws = WebSocket::new(url).await.expect("A valid websocket URL");
    let block = u64::from_str(block).expect("A valid block number");

    (fact, block, ws)
}
