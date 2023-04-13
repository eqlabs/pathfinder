use pathfinder_common::{EthereumAddress, EthereumChain};
use primitive_types::{H256, U256};
use reqwest::{Client, Url};

/// Describes a state update log event.
///
/// This is emitted by the Starknet core contract.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct L1StateUpdate {
    pub eth_block_number: u64,
    pub block_number: u64,
    pub global_root: H256,
}

#[derive(Clone)]
pub struct StarknetEthereumClient {
    pub l1_addr: EthereumAddress,
    pub eth: EthereumClient,
}

#[derive(Clone)]
pub struct EthereumClient {
    url: Url,
    http: Client,
}

impl EthereumClient {
    pub fn new(url: reqwest::Url) -> Self {
        let http_client = reqwest::ClientBuilder::new()
            .build()
            .expect("reqwest HTTP client");
        Self {
            url,
            http: http_client,
        }
    }

    pub fn new_with_password(mut url: reqwest::Url, password: &str) -> anyhow::Result<Self> {
        url.set_password(Some(password))
            .map_err(|_| anyhow::anyhow!("Setting password failed"))?;
        let http_client = reqwest::ClientBuilder::new()
            .build()
            .expect("reqwest HTTP client");
        Ok(Self {
            url,
            http: http_client,
        })
    }
}

impl StarknetEthereumClient {
    pub fn new(client: EthereumClient, l1_addr: EthereumAddress) -> Self {
        Self {
            l1_addr,
            eth: client,
        }
    }
}

pub mod core_contract {
    use const_decoder::Decoder;

    // Sources of L1 contract addresses:
    //
    // $ curl https://alpha-mainnet.starknet.io/feeder_gateway/get_contract_addresses
    // {"GpsStatementVerifier": "0x47312450B3Ac8b5b8e247a6bB6d523e7605bDb60", "Starknet": "0xc662c410C0ECf747543f5bA90660f6ABeBD9C8c4"}
    //
    // $ curl https://alpha4.starknet.io/feeder_gateway/get_contract_addresses
    // {"GpsStatementVerifier": "0x8f97970aC5a9aa8D130d35146F5b59c4aef57963", "Starknet": "0xde29d060D45901Fb19ED6C6e959EB22d8626708e"}
    //
    // $ curl https://alpha4-2.starknet.io/feeder_gateway/get_contract_addresses
    // {"GpsStatementVerifier": "0x8f97970aC5a9aa8D130d35146F5b59c4aef57963", "Starknet": "0xa4eD3aD27c294565cB0DCc993BDdCC75432D498c"}
    //
    // $ curl https://external.integration.starknet.io/feeder_gateway/get_contract_addresses
    // {"GpsStatementVerifier": "0x8f97970aC5a9aa8D130d35146F5b59c4aef57963", "Starknet": "0xd5c325D183C592C94998000C5e0EED9e6655c020"}

    pub const MAINNET: [u8; 20] = Decoder::Hex.decode(b"c662c410C0ECf747543f5bA90660f6ABeBD9C8c4");
    pub const TESTNET: [u8; 20] = Decoder::Hex.decode(b"de29d060D45901Fb19ED6C6e959EB22d8626708e");
    pub const TESTNET2: [u8; 20] = Decoder::Hex.decode(b"a4eD3aD27c294565cB0DCc993BDdCC75432D498c");
    pub const INTEGRATION: [u8; 20] =
        Decoder::Hex.decode(b"d5c325D183C592C94998000C5e0EED9e6655c020");
}

impl EthereumClient {
    async fn get_block_number(&self) -> anyhow::Result<U256> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id" :0
        });
        let res: serde_json::Value = self
            .http
            .post(self.url.as_str())
            .json(&req)
            .send()
            .await?
            .json()
            .await?;
        let block_number = res["result"]
            .as_str()
            .and_then(|txt| U256::from_str_radix(txt, 16).ok())
            .ok_or(anyhow::anyhow!("Failed to get block number"))?;
        Ok(block_number)
    }

    pub async fn gas_price(&self) -> anyhow::Result<U256> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
            "params": [],
            "id" :0
        });
        let res: serde_json::Value = self
            .http
            .post(self.url.as_str())
            .json(&req)
            .send()
            .await?
            .json()
            .await?;
        let block_number = res["result"]
            .as_str()
            .and_then(|txt| U256::from_str_radix(txt, 16).ok())
            .ok_or(anyhow::anyhow!("Failed to get gas price"))?;
        Ok(block_number)
    }

    pub async fn chain_id(&self) -> anyhow::Result<EthereumChain> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_chainId",
            "params": [],
            "id" :0
        });
        let res: serde_json::Value = self
            .http
            .post(self.url.as_str())
            .json(&req)
            .send()
            .await?
            .json()
            .await?;
        let id = res["result"]
            .as_str()
            .and_then(|txt| U256::from_str_radix(txt, 16).ok())
            .ok_or(anyhow::anyhow!("Failed to get chain id"))?;
        Ok(match id {
            x if x == U256::from(1u32) => EthereumChain::Mainnet,
            x if x == U256::from(5u32) => EthereumChain::Goerli,
            x => EthereumChain::Other(x),
        })
    }
}

impl StarknetEthereumClient {
    pub async fn get_starknet_state(&self) -> anyhow::Result<L1StateUpdate> {
        let eth_block_number = self.eth.get_block_number().await?;
        let starknet_block_number = self.get_starknet_block_number(&eth_block_number).await?;
        let starknet_state_root = self.get_starknet_state_root(&eth_block_number).await?;
        Ok(L1StateUpdate {
            eth_block_number: eth_block_number.as_u64(),
            block_number: starknet_block_number.as_u64(),
            global_root: starknet_state_root,
        })
    }

    async fn get_starknet_block_number(&self, block_number: &U256) -> anyhow::Result<U256> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": self.l1_addr,
                    "value": "0x0",
                    "data": "0x35befa5d"
                },
                block_number
            ],
            "id" :0
        });
        let res: serde_json::Value = self
            .eth
            .http
            .post(self.eth.url.as_str())
            .json(&req)
            .send()
            .await?
            .json()
            .await?;
        let block_number = res["result"]
            .as_str()
            .and_then(|txt| U256::from_str_radix(txt, 16).ok())
            .ok_or(anyhow::anyhow!("Failed to get starknet block number"))?;
        Ok(block_number)
    }

    async fn get_starknet_state_root(&self, block_number: &U256) -> anyhow::Result<H256> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": self.l1_addr,
                    "value": "0x0",
                    "data": "0x9588eca2"
                },
                block_number
            ],
            "id" :0
        });
        let res: serde_json::Value = self
            .eth
            .http
            .post(self.eth.url.as_str())
            .json(&req)
            .send()
            .await?
            .json()
            .await?;
        let state_root = res["result"]
            .as_str()
            .and_then(|txt| {
                let u256 = U256::from_str_radix(txt, 16).ok()?;
                let mut h256 = H256::zero();
                u256.to_big_endian(h256.as_mut());
                Some(h256)
            })
            .ok_or(anyhow::anyhow!("Failed to get starknet state root"))?;

        Ok(state_root)
    }

    pub async fn gas_price(&self) -> anyhow::Result<U256> {
        Ok(self.eth.gas_price().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use httpmock::prelude::*;
    use primitive_types::H160;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_get_block_number() {
        let server = MockServer::start_async().await;

        let mock = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x103588d"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let block_number = eth.get_block_number().await.expect("get_block_number");

        mock.assert();
        let expected = U256::from_str_radix("0x103588d", 16).expect("block number");
        assert_eq!(block_number, expected);
    }

    #[tokio::test]
    async fn test_gas_price() {
        let server = MockServer::start_async().await;

        let mock = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_gasPrice","params":[]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x52df48d1d"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let gas_price = eth.gas_price().await.expect("gas_price");

        mock.assert();
        let expected = U256::from_str_radix("0x52df48d1d", 16).expect("gas price");
        assert_eq!(gas_price, expected);
    }

    #[tokio::test]
    async fn test_chain_id() {
        let server = MockServer::start_async().await;

        let mock = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_chainId","params":[]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x1"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let chain_id = eth.chain_id().await.expect("chain_id");

        mock.assert();
        assert_eq!(chain_id, EthereumChain::Mainnet);
    }

    #[tokio::test]
    async fn test_get_starknet_block_number() {
        let server = MockServer::start_async().await;

        let mock = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x35befa5d","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},"0x103d1f2"]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x0000000000000000000000000000000000000000000000000000000000007eeb"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = StarknetEthereumClient::new(eth, l1_addr);

        let eth_block_number = U256::from_str_radix("0x103d1f2", 16).expect("eth_block_number");
        let block_number = eth
            .get_starknet_block_number(&eth_block_number)
            .await
            .expect("get_starknet_block_number");

        mock.assert();
        let expected = U256::from_str_radix("0x7eeb", 16).expect("starknet block number");
        assert_eq!(block_number, expected);
    }

    #[tokio::test]
    async fn test_get_starknet_state_root() {
        let server = MockServer::start_async().await;

        let mock = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x9588eca2","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},"0x103d1f2"]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = StarknetEthereumClient::new(eth, l1_addr);

        let eth_block_number = U256::from_str_radix("0x103d1f2", 16).expect("eth_block_number");

        let state_root = eth
            .get_starknet_state_root(&eth_block_number)
            .await
            .expect("get_starknet_state_root");

        mock.assert();
        let expected =
            H256::from_str("0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f")
                .expect("starknet state root");
        assert_eq!(state_root, expected);
    }

    #[tokio::test]
    async fn test_get_starknet_state() {
        let server = MockServer::start_async().await;

        let mock_block_number = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x103d1f2"}"#);
        });

        let mock_block = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x35befa5d","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},"0x103d1f2"]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x0000000000000000000000000000000000000000000000000000000000007eeb"}"#);
        });

        let mock_state = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x9588eca2","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},"0x103d1f2"]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = StarknetEthereumClient::new(eth, l1_addr);

        let eth_block_number = U256::from_str_radix("0x103d1f2", 16).expect("block number");
        let block_number = U256::from_str_radix("0x7eeb", 16).expect("starknet block number");
        let global_root =
            H256::from_str("0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f")
                .expect("starknet state root");
        let expected = L1StateUpdate {
            eth_block_number: eth_block_number.as_u64(),
            block_number: block_number.as_u64(),
            global_root,
        };

        let state = eth.get_starknet_state().await.expect("state");
        mock_block_number.assert();
        mock_block.assert();
        mock_state.assert();
        assert_eq!(state, expected);
    }
}
