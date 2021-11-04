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
const CORE_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/starknet.json"
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

        // Create HTTP client with optional user-agent
        let http_client = match cfg.user {
            Some(user) => reqwest::Client::builder().user_agent(user),
            None => reqwest::Client::builder(),
        }
        .build()
        .map_err(|err| {
            web3::Error::Transport(format!("failed to build Ethereum HTTP client: {}", err))
        })?;

        // Set the password on the URL.
        let url = match cfg.password {
            Some(password) => {
                let mut url = cfg.url;
                url.set_password(Some(&password)).map_err(|_| {
                    web3::Error::Transport("failed to apply Ethereum password".to_owned())
                })?;
                url
            }
            None => cfg.url,
        };

        let transport = web3::transports::Http::with_client(http_client, url);
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

#[cfg(test)]
mod tests {
    use std::env;

    use reqwest::Url;

    use super::*;

    /// Creates an [EthereumConfig] from environment variables.
    ///
    /// Done this way to prevent leaking URLs, passwords etc but we still
    /// want to test this during CI.
    fn eth_config_from_env() -> EthereumConfig {
        let url = env::var("STARKNET_ETHEREUM_URL")
            .expect("Ethereum URL environment var not set (STARKNET_ETHEREUM_URL)");
        let user = env::var("STARKNET_ETHEREUM_USER").ok();
        let password = env::var("STARKNET_ETHEREUM_PASSWORD").ok();

        let url = url.parse::<Url>().expect("Bad ethereum URL");

        EthereumConfig {
            url,
            user,
            password,
        }
    }

    /// Returns the known StarkNet state at a specific hash:
    ///     (hash, root, sequence number)
    fn known_state() -> (H256, U256, U256) {
        let hash =
            H256::from_str("4de373d45a29e0d6fe702f1d8c1d1bda81edc18a6409146af2dc6f9ea2f6503b")
                .unwrap();

        let root = U256::from_dec_str(
            "1451723332915230892027004852411811409047732733786127578001959737407326381523",
        )
        .unwrap();

        let sequence_number = U256::from_dec_str("19872").unwrap();

        (hash, root, sequence_number)
    }

    #[tokio::test]
    async fn latest_state_root() {
        let client = Client::new(eth_config_from_env()).unwrap();
        assert!(client.latest_state_root().await.is_ok());
    }

    #[tokio::test]
    async fn latest_state_sequence_number() {
        let client = Client::new(eth_config_from_env()).unwrap();
        assert!(client.latest_state_sequence_number().await.is_ok());
    }

    #[tokio::test]
    async fn state_root_at_hash() {
        let (hash, root, _) = known_state();
        let client = Client::new(eth_config_from_env()).unwrap();
        let result = client.state_root_at_hash(hash).await.unwrap();

        assert_eq!(result, root);
    }

    #[tokio::test]
    async fn state_sequence_number_at_hash() {
        let (hash, _, sequence_number) = known_state();
        let client = Client::new(eth_config_from_env()).unwrap();
        let result = client.state_sequence_number_at_hash(hash).await.unwrap();

        assert_eq!(result, sequence_number);
    }
}
