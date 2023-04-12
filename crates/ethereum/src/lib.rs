use pathfinder_common::EthereumAddress;
use primitive_types::{H256, U256};

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
pub struct EthereumClient {
    l1_addr: EthereumAddress,
    rpc_url: String,
    http_client: reqwest::Client,
}

impl EthereumClient {
    pub fn new(rpc_url: &str, l1_addr: EthereumAddress) -> Self {
        let http_client = reqwest::ClientBuilder::new()
            .build()
            .expect("reqwest HTTP client");
        Self {
            l1_addr,
            rpc_url: rpc_url.to_owned(),
            http_client,
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
    pub async fn get_starknet_state(&self) -> anyhow::Result<L1StateUpdate> {
        let eth_block_number = self.get_block_number().await?;
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
            .http_client
            .post(&self.rpc_url)
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
            .http_client
            .post(&self.rpc_url)
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
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
            "params": [],
            "id" :0
        });
        let res: serde_json::Value = self
            .http_client
            .post(&self.rpc_url)
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

    pub async fn get_block_number(&self) -> anyhow::Result<U256> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id" :0
        });
        let res: serde_json::Value = self
            .http_client
            .post(&self.rpc_url)
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
}

// TODO(SM): make tests hermetic (test against local http mock server)
#[cfg(test)]
mod tests {
    use primitive_types::H160;

    use super::*;

    #[tokio::test]
    async fn test_get_block_number() {
        // curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":0}' https://eth.llamarpc.com
        // {"jsonrpc":"2.0","id":0,"result":"0x103588d"}

        let eth = EthereumClient::new("https://eth.llamarpc.com", EthereumAddress(H160::zero()));
        let block_number = eth.get_block_number().await.expect("get_block_number");

        let expected = U256::from_dec_str("17027570").expect("min block");
        assert!(block_number >= expected);
    }

    #[tokio::test]
    async fn test_gas_price() {
        // $ curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":42}' https://eth.llamarpc.com
        // {"jsonrpc":"2.0","id":42,"result":"0x52df48d1d"}

        let eth = EthereumClient::new("https://eth.llamarpc.com", EthereumAddress(H160::zero()));
        let gas_price = eth.gas_price().await.expect("gas_price");

        let zero = U256::zero();
        assert!(gas_price > zero);
    }

    #[tokio::test]
    async fn test_get_starknet_block_number() {
        // $ curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0","data":"0x35befa5d"}, "0x103588d"],"id":1}' https://eth.llamarpc.com
        // {"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000007eeb"}

        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = EthereumClient::new("https://eth.llamarpc.com", l1_addr);

        let eth_block_number = U256::from_dec_str("17027570").expect("eth_block_number");

        let block_number = eth
            .get_starknet_block_number(&eth_block_number)
            .await
            .expect("get_starknet_block_number");

        let expected = U256::from_dec_str("36284").expect("min block");
        assert!(block_number >= expected);
    }

    #[tokio::test]
    async fn test_get_starknet_state_root() {
        // $ curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0","data":"0x9588eca2"}, "0x103588d"],"id":1}' https://eth.llamarpc.com
        // {"jsonrpc":"2.0","id":1,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}

        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = EthereumClient::new("https://eth.llamarpc.com", l1_addr);

        let eth_block_number = U256::from_dec_str("17027570").expect("eth_block_number");

        let state_root = eth
            .get_starknet_state_root(&eth_block_number)
            .await
            .expect("get_starknet_state_root");

        let zero = H256::zero();
        assert!(state_root > zero);
    }

    #[tokio::test]
    async fn test_get_starknet_state() {
        let l1_addr = EthereumAddress(H160::from_slice(&core_contract::MAINNET));
        let eth = EthereumClient::new("https://eth.llamarpc.com", l1_addr);

        assert!(eth.get_starknet_state().await.is_ok());
    }
}
