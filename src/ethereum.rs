//! StarkNet L1 interactions.
use std::str::FromStr;

use web3::{
    contract::Contract,
    contract::{self, Options},
    transports::Http,
    types::{BlockId, BlockNumber, H160, H256, U256},
};

use crate::config::EthereumConfig;

/// The StarkNet L1 contract's ABI's file contents.
const CONTRACT_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/starknet.abi"
));

/// A client for interacting with StarkNet's L1 Ethereum contract.
pub struct Client {
    contract: Contract<Http>,
}

impl Client {
    /// Creates a new L1 Ethereum client using the given Ethereum entry-point.
    pub fn new(cfg: EthereumConfig) -> web3::Result<Self> {
        // The current StarkNet L1 contract address on Goerli.
        let contract_address =
            H160::from_str("0x5e6229F2D4d977d20A50219E521dE6Dd694d45cc").unwrap();

        let http_client = match cfg.user {
            Some(user) => reqwest::Client::builder().user_agent(user),
            None => reqwest::Client::builder(),
        }
        .build()
        .map_err(|err| {
            web3::Error::Transport(format!("failed to build Ethereum HTTP client: {}", err))
        })?;

        let transport = web3::transports::Http::with_client(http_client, cfg.url);
        let w3 = web3::Web3::new(transport);

        let contract = match Contract::from_json(w3.eth(), contract_address, CONTRACT_ABI) {
            Ok(contract) => contract,
            Err(err) => todo!("errors need handling: {:?}", err),
        };

        Ok(Self { contract })
    }

    /// The current state root.
    pub async fn latest_state_root(&self) -> contract::Result<U256> {
        self.query_state_root(BlockId::Number(BlockNumber::Latest))
            .await
    }

    /// The state root at the block hash.
    pub async fn state_root_at_hash(&self, block_hash: H256) -> contract::Result<U256> {
        self.query_state_root(BlockId::Hash(block_hash)).await
    }

    /// Helper function which queries L1 for state root at some block.
    async fn query_state_root(&self, block_id: BlockId) -> contract::Result<U256> {
        self.contract
            .query("stateRoot", (), None, Options::default(), Some(block_id))
            .await
    }

    /// The current state sequence number.
    pub async fn latest_state_sequence_number(&self) -> contract::Result<web3::ethabi::Int> {
        self.query_state_sequence_number(BlockId::Number(BlockNumber::Latest))
            .await
    }

    /// The state sequence number at the block hash.
    pub async fn state_sequence_number_at_hash(&self, block_hash: H256) -> contract::Result<U256> {
        self.query_state_sequence_number(BlockId::Hash(block_hash))
            .await
    }

    /// Helper function which queries L1 for state root at some block.
    async fn query_state_sequence_number(&self, block_id: BlockId) -> contract::Result<U256> {
        self.contract
            .query(
                "stateSequenceNumber",
                (),
                None,
                Options::default(),
                Some(block_id),
            )
            .await
    }
}
