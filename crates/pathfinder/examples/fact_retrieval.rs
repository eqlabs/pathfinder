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

use std::str::FromStr;

use clap::Arg;
use pathfinder_lib::{
    core::{EthereumBlockHash, StarknetBlockNumber},
    ethereum::{
        api::Web3EthImpl,
        log::{get_logs, MetaLog, StateUpdateLog},
        state_update::StateUpdate,
    },
};
use web3::types::{H256, U256};
use web3::{transports::Http, types::FilterBuilder, Web3};

#[tokio::main]
async fn main() {
    let (transport, block_hash, block_no) = parse_cli_args();

    let chain = pathfinder_lib::ethereum::chain(&transport)
        .await
        .expect("Failed to identify Ethereum network");

    // Get the state update event at the given block.
    let filter = FilterBuilder::default()
        .block_hash(block_hash.0)
        .address(vec![StateUpdateLog::contract_address(chain)])
        .topics(Some(vec![StateUpdateLog::signature()]), None, None, None)
        .build();
    let logs = get_logs(&transport, filter).await.unwrap();

    let update_log = logs
        .into_iter()
        .map(|log| StateUpdateLog::try_from(log).expect("state update log parsing failed"))
        .find(|log| log.block_number == block_no)
        .expect("state update log not found");

    let state_update = StateUpdate::retrieve(&transport, update_log, chain)
        .await
        .expect("Failed to retrieve the state update");

    println!("State update:\n\n{:#?}", state_update);
}

/// Creates the CLI and parses the resulting arguments.
fn parse_cli_args() -> (Web3EthImpl<Http>, EthereumBlockHash, StarknetBlockNumber) {
    let cli = clap::Command::new("fact-retrieval")
        .about("Retrieves and displays a StarkNet state update fact")
        .after_help("You can use Etherscan to identify a fact hash to retrieve. The fact hash for a state update is emitted as a `LogStateTransitionFact` log.")
        .arg(
            Arg::new("seq-no")
                .long("sequence-number")
                .short('s')
                .takes_value(true)
                .help("The state update's sequence number.")
                .value_name("INT")
        )
        .arg(
             Arg::new("block")
                .long("block-hash")
                .short('b')
                .takes_value(true)
                .value_name("HASH")
                .help("The L1 block hash at which the state update occurred.")
        )
        .arg(
            Arg::new("url")
                .long("url")
                .short('u')
                .takes_value(true)
                .value_name("HTTP(S) URL")
                .long_help(r#"This should point to the HTTP RPC endpoint of your Ethereum entry-point, typically a local Ethereum client or a hosted gateway service such as Infura or Cloudflare.

Examples:
    infura: https://goerli.infura.io/v3/<PROJECT_ID>
    geth:   https://localhost:8545"#));

    let args = cli.get_matches();

    let url = args.value_of("url").expect("Ethereum HTTP url is required");
    let block = args.value_of("block").expect("block hash is required");
    let seq_no = args
        .value_of("seq-no")
        .expect("sequence number is required");

    let client = Http::new(url).expect("A valid HTTP URL");

    let block = H256::from_str(block).expect("A valid block hash");
    let block = EthereumBlockHash(block);
    let seq_no = U256::from_dec_str(seq_no).expect("A valid sequence number");
    let seq_no = StarknetBlockNumber(seq_no.as_u64());

    let client = Web3EthImpl(Web3::new(client));

    (client, block, seq_no)
}
