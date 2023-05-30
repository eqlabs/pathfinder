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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumStateUpdate {
    pub global_root: StateCommitment,
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
    pub fn from_config(url: reqwest::Url, _password: Option<String>) -> anyhow::Result<Self> {
        // TODO(SM): password
        Ok(Self {
            http: reqwest::ClientBuilder::new().build().expect("reqwest"),
            url,
        })
    }

    async fn get_latest_block_hash(&self) -> anyhow::Result<H256> {
        self.call_ethereum(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [
                "latest",
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
        let hash = self.get_latest_block_hash().await?;
        let hash = format!("0x{}", hex::encode(hash.as_bytes()));
        let addr = format!("0x{}", hex::encode(address.as_bytes()));
        Ok(EthereumStateUpdate {
            global_root: self
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
        .and_then(|txt| H256::from_str(txt).ok())
        .ok_or(anyhow::anyhow!("Failed to fetch H256"))
}

fn get_u256(value: &serde_json::Value) -> anyhow::Result<U256> {
    value
        .as_str()
        .and_then(|txt| U256::from_str_radix(txt, 16).ok())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // TODO(SM): httpmock
    async fn test_get_state() -> anyhow::Result<()> {
        let address = H160::from(core_addr::MAINNET);

        let client =
            EthereumClient::from_config(reqwest::Url::parse("https://eth.llamarpc.com")?, None)?;

        let state = client.get_starknet_state(&address).await?;
        println!("{state:?}");

        let chain = client.get_chain().await?;
        println!("{chain:?}");

        Ok(())
    }
}
