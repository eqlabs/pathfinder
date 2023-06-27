use pathfinder_common::{BlockHash, BlockNumber, EthereumChain, StateCommitment};
use primitive_types::{H160, H256, U256};
use stark_hash::Felt;

pub mod core_addr {
    use const_decoder::Decoder;

    pub const MAINNET: [u8; 20] = Decoder::Hex.decode(b"c662c410C0ECf747543f5bA90660f6ABeBD9C8c4");
    pub const TESTNET: [u8; 20] = Decoder::Hex.decode(b"de29d060D45901Fb19ED6C6e959EB22d8626708e");
    pub const TESTNET2: [u8; 20] = Decoder::Hex.decode(b"a4eD3aD27c294565cB0DCc993BDdCC75432D498c");
    pub const INTEGRATION: [u8; 20] =
        Decoder::Hex.decode(b"d5c325D183C592C94998000C5e0EED9e6655c020");
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthereumStateUpdate {
    pub state_root: StateCommitment,
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
}

#[async_trait::async_trait]
pub trait EthereumApi {
    async fn get_starknet_state(&self, address: &H160) -> anyhow::Result<EthereumStateUpdate>;
    async fn get_chain(&self) -> anyhow::Result<EthereumChain>;
}

#[derive(Clone, Debug)]
pub struct EthereumClient {
    http: reqwest::Client,
    url: reqwest::Url,
}

const HTTP_OK: u16 = 200;

impl EthereumClient {
    pub fn with_password(mut url: reqwest::Url, password: &str) -> anyhow::Result<Self> {
        url.set_password(Some(password))
            .map_err(|_| anyhow::anyhow!("Setting password failed"))?;
        Self::new(url)
    }

    pub fn new(url: reqwest::Url) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::ClientBuilder::new().build()?,
            url,
        })
    }

    async fn get_finalized_block_hash(&self) -> anyhow::Result<H256> {
        self.call_ethereum(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [
                "finalized",
                false
            ],
            "id": 0
        }))
        .await
        .and_then(|value| get_h256(&value["hash"]))
    }

    async fn call_starknet_contract(
        &self,
        block_hash: &str,
        address: &str,
        signature: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let data = encode_ethereum_call_data(signature.as_bytes());
        self.call_ethereum(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": address,
                    "value": "0x0",
                    "data": data
                },
                {"blockHash": block_hash}
            ],
            "id": 0
        }))
        .await
    }

    async fn call_ethereum(&self, value: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let res = self.http.post(self.url.clone()).json(&value).send().await?;

        let status = res.status();
        let (code, message) = (status.as_u16(), status.as_str());
        if code != HTTP_OK {
            tracing::error!(code, message, "Ethereum call failed");
            anyhow::bail!(code);
        }

        let response: serde_json::Value = res.json().await?;
        Ok(response["result"].clone())
    }
}

#[async_trait::async_trait]
impl EthereumApi for EthereumClient {
    async fn get_starknet_state(&self, address: &H160) -> anyhow::Result<EthereumStateUpdate> {
        let hash = self.get_finalized_block_hash().await?;
        let hash = format!("0x{}", hex::encode(hash.as_bytes()));
        let addr = format!("0x{}", hex::encode(address.as_bytes()));
        Ok(EthereumStateUpdate {
            state_root: self
                .call_starknet_contract(&hash, &addr, "stateRoot()")
                .await
                .and_then(|value| get_h256(&value))
                .and_then(get_felt)
                .map(StateCommitment)?,
            block_hash: self
                .call_starknet_contract(&hash, &addr, "stateBlockHash()")
                .await
                .and_then(|value| get_h256(&value))
                .and_then(get_felt)
                .map(BlockHash)?,
            block_number: self
                .call_starknet_contract(&hash, &addr, "stateBlockNumber()")
                .await
                .and_then(|value| get_u256(&value))
                .and_then(get_number)?,
        })
    }

    async fn get_chain(&self) -> anyhow::Result<EthereumChain> {
        let id = self
            .call_ethereum(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_chainId",
                "params": [],
                "id": 0
            }))
            .await
            .and_then(|value| get_u256(&value))?;
        Ok(match id {
            x if x == U256::from(1u32) => EthereumChain::Mainnet,
            x if x == U256::from(5u32) => EthereumChain::Goerli,
            x => EthereumChain::Other(x),
        })
    }
}

fn encode_ethereum_call_data(signature: &[u8]) -> String {
    let mut output: [u8; 32] = Default::default();
    keccak_hash::keccak_256(signature, &mut output[..]);
    format!("0x{}", hex::encode(&output[0..4]))
}

fn get_h256(value: &serde_json::Value) -> anyhow::Result<H256> {
    use std::str::FromStr;
    value
        .as_str()
        .map(lpad64)
        .and_then(|val| H256::from_str(&val).ok())
        .ok_or(anyhow::anyhow!("Failed to fetch H256"))
}

fn get_u256(value: &serde_json::Value) -> anyhow::Result<U256> {
    use std::str::FromStr;
    value
        .as_str()
        .map(lpad64)
        .and_then(|val| U256::from_str(&val).ok())
        .ok_or(anyhow::anyhow!("Failed to fetch U256"))
}

fn get_felt(value: H256) -> anyhow::Result<Felt> {
    let felt = Felt::from_be_slice(value.as_bytes())?;
    Ok(felt)
}

fn get_number(value: U256) -> anyhow::Result<BlockNumber> {
    let value = value.as_u64();
    BlockNumber::new(value).ok_or(anyhow::anyhow!("Failed to read u64 from U256"))
}

fn lpad64(value: &str) -> String {
    let input = value.strip_prefix("0x").unwrap_or(value);
    let prefix = if value.starts_with("0x") { "0x" } else { "" };
    if input.len() == 64 {
        format!("{prefix}{input}")
    } else {
        format!("{prefix}{input:0>64}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use httpmock::prelude::*;
    use primitive_types::H160;
    use reqwest::Url;
    use std::str::FromStr;

    #[tokio::test]
    #[ignore = "live ethereum call"]
    async fn test_live() -> anyhow::Result<()> {
        let address = H160::from(core_addr::MAINNET);

        let url = Url::parse("https://eth.llamarpc.com")?;
        let client = EthereumClient::new(url)?;

        let state = client.get_starknet_state(&address).await?;
        println!("{state:#?}");

        let chain = client.get_chain().await?;
        println!("{chain:?}");

        Ok(())
    }

    #[tokio::test]
    async fn test_chain_id() -> anyhow::Result<()> {
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

        let url = Url::parse(&server.url("/"))?;
        let eth = EthereumClient::new(url)?;
        let chain_id = eth.get_chain().await?;

        mock.assert();
        assert_eq!(chain_id, EthereumChain::Mainnet);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_starknet_state() -> anyhow::Result<()> {
        let server = MockServer::start_async().await;

        let mock_ethereum_block = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":{"number":"0x1048e0e","hash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}}"#);
        });

        let mock_block_number = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x35befa5d","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},{"blockHash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x0000000000000000000000000000000000000000000000000000000000007eeb"}"#);
        });

        let mock_block_hash = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x382d83e3","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},{"blockHash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}"#);
        });

        let mock_state_root = server.mock(|when, then| {
            when.path("/")
                .method(POST)
                .header("Content-type", "application/json")
                .body(r#"{"id":0,"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x9588eca2","to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0"},{"blockHash":"0x9921984fd976f261e0d70618b51e3db3724b9f4d28d0534c3483dd2162f13fff"}]}"#);
            then.status(200)
                .header("Content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}"#);
        });

        let url = Url::parse(&server.url("/"))?;
        let eth = EthereumClient::new(url)?;

        let block_number = U256::from_str_radix("0x7eeb", 16)?;
        let block_hash =
            H256::from_str("0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f")?;
        let global_root =
            H256::from_str("0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f")?;
        let expected = EthereumStateUpdate {
            state_root: StateCommitment(get_felt(global_root)?),
            block_number: get_number(block_number)?,
            block_hash: BlockHash(get_felt(block_hash)?),
        };

        let addr = H160::from_slice(&core_addr::MAINNET);
        let state = eth.get_starknet_state(&addr).await?;

        mock_ethereum_block.assert();
        mock_block_number.assert();
        mock_block_hash.assert();
        mock_state_root.assert();
        assert_eq!(state, expected);
        Ok(())
    }

    #[test]
    fn test_h256() {
        assert!(H256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000007eeb"
        )
        .is_ok());
        assert!(H256::from_str("0x7eeb").is_err());

        let expected =
            H256::from_str("0x0000000000000000000000000000000000000000000000000000000000007eeb")
                .unwrap();
        assert_eq!(H256::from_str(&lpad64("0x7eeb")).unwrap(), expected);
    }

    #[test]
    fn test_lpad64() {
        for (input, expected) in [
            (
                "0x0000000000000000000000000000000000000000000000000000000000007eeb",
                "0x0000000000000000000000000000000000000000000000000000000000007eeb",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000007eeb",
                "0000000000000000000000000000000000000000000000000000000000007eeb",
            ),
            (
                "7eeb",
                "0000000000000000000000000000000000000000000000000000000000007eeb",
            ),
            (
                "0x7eeb",
                "0x0000000000000000000000000000000000000000000000000000000000007eeb",
            ),
            (
                "",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0x",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            assert_eq!(lpad64(input), expected, "for input: {}", input);
        }
    }
}
