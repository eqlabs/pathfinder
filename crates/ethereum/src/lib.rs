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

#[async_trait::async_trait]
pub trait EthereumClientApi {
    async fn gas_price(&self) -> anyhow::Result<U256>;
    async fn get_starknet_state(&self) -> anyhow::Result<L1StateUpdate>;
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

#[async_trait::async_trait]
impl EthereumClientApi for StarknetEthereumClient {
    async fn gas_price(&self) -> anyhow::Result<U256> {
        let result = self
            .eth
            .call_rpc(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_gasPrice",
                "params": [],
                "id" :0
            }))
            .await?;
        get_u256(&result)
    }

    async fn get_starknet_state(&self) -> anyhow::Result<L1StateUpdate> {
        let (eth_block_number, eth_block_hash) = self.eth.get_latest_block().await?;
        let starknet_block_number = self.get_starknet_block_number(&eth_block_hash).await?;
        let starknet_state_root = self.get_starknet_state_root(&eth_block_hash).await?;
        Ok(L1StateUpdate {
            eth_block_number: eth_block_number.as_u64(),
            block_number: starknet_block_number.as_u64(),
            global_root: starknet_state_root,
        })
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

    pub fn get_init_block(addr: &super::EthereumAddress) -> u64 {
        let addr: [u8; 20] = addr.0.as_bytes().try_into().unwrap_or_default();
        match addr {
            // https://etherscan.io/tx/0x4810a17f4fa3460fa20990b786d0b5be1be66a2cdc261e85f8e482e2ea06ba54
            MAINNET => 13620297,
            // https://goerli.etherscan.io/tx/0x87f8705d0f9d39409519f57bd1633617417223a9dec38d7b57fc4a6560d2e7fd
            TESTNET => 5853128,
            // https://goerli.etherscan.io/tx/0x15f897201c15b66d12f431d97b1118be5640530e539f3ee3c7f5dacf3e9e2b7b
            TESTNET2 => 7843384,
            // https://goerli.etherscan.io/tx/0xbfeb9011a4a8c203467dca1e0fe312df8d6ce9764118f369fff6f98dea2f5cad
            INTEGRATION => 5986750,
            _ => 0,
        }
    }
}

fn get_u256(value: &serde_json::Value) -> anyhow::Result<U256> {
    value
        .as_str()
        .and_then(|txt| U256::from_str_radix(txt, 16).ok())
        .ok_or(anyhow::anyhow!("Failed to fetch U256"))
}

fn get_h256(value: &serde_json::Value) -> anyhow::Result<H256> {
    use std::str::FromStr;
    value
        .as_str()
        .and_then(|txt| H256::from_str(txt).ok())
        .ok_or(anyhow::anyhow!("Failed to fetch H256"))
}

async fn get_starknet_block_num(
    client: &StarknetEthereumClient,
    eth_block_num: U256,
) -> anyhow::Result<U256> {
    client
        .eth
        .call_rpc(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": client.l1_addr,
                    "value": "0x0",
                    "data": "0x35befa5d"
                },
                eth_block_num
            ],
            "id": 0
        }))
        .await
        .and_then(|x| get_u256(&x))
}

pub async fn bsearch_starknet_matching_block(
    client: &StarknetEthereumClient,
    block_number: u64,
    min_block: u64,
) -> anyhow::Result<U256> {
    let min_block = U256::from(core_contract::get_init_block(&client.l1_addr).max(min_block));
    let max_block = client.eth.get_block_number().await?;
    let mut lo = min_block;
    let mut hi = max_block;
    while lo < hi {
        let m = lo + (hi - lo) / 2;
        let block = get_starknet_block_num(client, m).await?;
        if block.as_u64() == block_number {
            // Early exit: we are good with any block, not necessary the lowest one
            return Ok(m);
        }
        if block_number < block.as_u64() {
            hi = m;
        } else {
            lo = m + 1;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(anyhow::anyhow!("No matching block found"))
}

// TODO(SM): use or remove
#[allow(dead_code)]
async fn find_matching_ethereum_block(
    client: &StarknetEthereumClient,
    block_number: u64,
    block_root: &[u8],
    current_head: u64,
) -> anyhow::Result<u64> {
    let eth_block_num = bsearch_starknet_matching_block(client, block_number, current_head).await?;
    let eth_block_hash = client.eth.get_block_hash(eth_block_num).await?;
    let expected_state_root = client.get_starknet_state_root(&eth_block_hash).await?;
    let expected_state_root = expected_state_root.as_bytes();

    if expected_state_root == block_root {
        Ok(eth_block_num.as_u64())
    } else {
        Err(anyhow::anyhow!(
            "State root did not match L1 ({:?}) for block {}.",
            expected_state_root,
            block_number,
        ))
    }
}

impl EthereumClient {
    async fn call_rpc(&self, request: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let response: serde_json::Value = self
            .http
            .post(self.url.as_str())
            .json(&request)
            .send()
            .await?
            .json()
            .await?;
        tracing::debug!(method=?request["method"], result=?response["result"], error=?response["error"], "L1 call");
        Ok(response["result"].clone())
    }

    async fn get_block_number(&self) -> anyhow::Result<U256> {
        let result = self
            .call_rpc(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id" :0
            }))
            .await?;
        get_u256(&result)
    }

    pub async fn get_block_hash(&self, number: U256) -> anyhow::Result<H256> {
        let result = self
            .call_rpc(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [number, false],
                "id" :0
            }))
            .await?;
        get_h256(&result["hash"])
    }

    async fn get_latest_block(&self) -> anyhow::Result<(U256, H256)> {
        let result = self
            .call_rpc(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": ["latest", false],
                "id" :0
            }))
            .await?;
        let block_num = get_u256(&result["number"])?;
        let block_hash = get_h256(&result["hash"])?;
        Ok((block_num, block_hash))
    }

    pub async fn chain_id(&self) -> anyhow::Result<EthereumChain> {
        let result = self
            .call_rpc(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_chainId",
                "params": [],
                "id" :0
            }))
            .await?;
        let id = get_u256(&result)?;
        Ok(match id {
            x if x == U256::from(1u32) => EthereumChain::Mainnet,
            x if x == U256::from(5u32) => EthereumChain::Goerli,
            x => EthereumChain::Other(x),
        })
    }
}

impl StarknetEthereumClient {
    async fn get_starknet_block_number(&self, block_hash: &H256) -> anyhow::Result<U256> {
        let result = self
            .eth
            .call_rpc(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": self.l1_addr,
                        "value": "0x0",
                        "data": "0x35befa5d"
                    },
                    {"blockHash": block_hash}
                ],
                "id" :0
            }))
            .await?;
        get_u256(&result)
    }

    pub async fn get_starknet_state_root(&self, block_hash: &H256) -> anyhow::Result<H256> {
        let result = self
            .eth
            .call_rpc(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": self.l1_addr,
                        "value": "0x0",
                        "data": "0x9588eca2"
                    },
                    {"blockHash": block_hash}
                ],
                "id" :0
            }))
            .await?;
        get_h256(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use httpmock::prelude::*;
    use primitive_types::H160;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_bsearch_starknet_matching_block() {
        let server = MockServer::start_async().await;

        let mocks = vec![
            server.mock(|when, then| {
                when.path("/")
                    .method(POST)
                    .header("Content-type", "application/json")
                    .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}"#);
                then.status(200)
                    .header("Content-type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x104d733"}"#);
            }),
            server.mock(|when, then| {
                when.path("/")
                    .method(POST)
                    .header("Content-type", "application/json")
                    .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x35befa5d","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},"0xea55be"]}"#);
                then.status(200)
                    .header("Content-type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x00000000000000000000000000000000000000000000000000000000000010f5"}"#);
            }),
            server.mock(|when, then| {
                when.path("/")
                    .method(POST)
                    .header("Content-type", "application/json")
                    .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x35befa5d","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},"0xf79679"]}"#);
                then.status(200)
                    .header("Content-type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000430d"}"#);
            }),
        ];

        let url = Url::parse(&server.url("/")).expect("url");
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = StarknetEthereumClient::new(EthereumClient::new(url), l1_addr);

        let block = U256::from_str("0x430d").expect("block");
        let found = bsearch_starknet_matching_block(&eth, block.as_u64(), 0)
            .await
            .expect("found");
        let expected = U256::from_str("0xf79679").expect("expected");

        mocks.into_iter().for_each(|mock| mock.assert());
        assert!(found >= expected, "{} >= {}", found, expected);
    }

    #[tokio::test]
    async fn test_get_latest_block() {
        let server = MockServer::start_async().await;

        let mock = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":{"number":"0x1048e0e","hash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let (block_num, block_hash) = eth.get_latest_block().await.expect("get_latest_block");

        mock.assert();
        let expected_num = U256::from_str_radix("0x1048e0e", 16).expect("block number");
        let expected_hash =
            H256::from_str("0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff")
                .expect("block hash");
        assert_eq!((block_num, block_hash), (expected_num, expected_hash));
    }

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
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x1048e0e"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let block_number = eth.get_block_number().await.expect("get_block_number");

        mock.assert();
        let expected = U256::from_str_radix("0x1048e0e", 16).expect("block number");
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
        let l1_addr = EthereumAddress(H160::default());
        let eth = StarknetEthereumClient::new(eth, l1_addr);
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
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x35befa5d","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},{"blockHash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x0000000000000000000000000000000000000000000000000000000000007eeb"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = StarknetEthereumClient::new(eth, l1_addr);

        let eth_block_hash =
            H256::from_str("0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff")
                .expect("eth_block_hash");
        let block_number = eth
            .get_starknet_block_number(&eth_block_hash)
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
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x9588eca2","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},{"blockHash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = StarknetEthereumClient::new(eth, l1_addr);

        let eth_block_hash =
            H256::from_str("0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff")
                .expect("eth_block_hash");
        let state_root = eth
            .get_starknet_state_root(&eth_block_hash)
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
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":{"number":"0x1048e0e","hash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}}"#);
        });

        let mock_block = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x35befa5d","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},{"blockHash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x0000000000000000000000000000000000000000000000000000000000007eeb"}"#);
        });

        let mock_state = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x9588eca2","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},{"blockHash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}"#);
        });

        let url = Url::parse(&server.url("/")).expect("url");
        let eth = EthereumClient::new(url);
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = StarknetEthereumClient::new(eth, l1_addr);

        let eth_block_number = U256::from_str_radix("0x1048e0e", 16).expect("block number");
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
