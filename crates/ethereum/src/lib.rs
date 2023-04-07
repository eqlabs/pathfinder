use pathfinder_common::{
    Chain, EthereumAddress, EthereumBlockHash, EthereumBlockNumber, StarknetBlockNumber,
    StateCommitment,
};
use primitive_types::{H160, U256};

#[derive(Debug, Default, Clone, PartialEq, Hash, Eq)]
pub struct EthereumBlock {
    pub hash: EthereumBlockHash,
    pub number: EthereumBlockNumber,
}

/// Describes a state update log event.
///
/// This is emitted by the Starknet core contract.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct L1StateUpdate {
    pub eth_block: EthereumBlock,
    pub global_root: StateCommitment,
    pub block_number: StarknetBlockNumber,
}

#[derive(Clone)]
pub struct EthereumClient {
    network: Chain,
    l1_core_address: EthereumAddress,
    // TODO(SM): add http client
}

impl EthereumClient {
    pub fn dummy() -> Self {
        Self {
            network: Chain::Mainnet,
            l1_core_address: EthereumAddress(H160::zero()),
        }
    }
}

pub mod core_contract {
    use const_decoder::Decoder;

    pub const MAINNET: [u8; 20] = Decoder::Hex.decode(b"c662c410C0ECf747543f5bA90660f6ABeBD9C8c4");
    pub const TESTNET: [u8; 20] = Decoder::Hex.decode(b"de29d060D45901Fb19ED6C6e959EB22d8626708e");
    pub const TESTNET2: [u8; 20] = Decoder::Hex.decode(b"a4eD3aD27c294565cB0DCc993BDdCC75432D498c");
    pub const INTEGRATION: [u8; 20] =
        Decoder::Hex.decode(b"d5c325D183C592C94998000C5e0EED9e6655c020");
}

impl EthereumClient {
    pub async fn gas_price(&self) -> anyhow::Result<U256> {
        // TODO(SM): impl
        Ok(U256::zero())
    }

    pub async fn get_starknet_state(&self) -> anyhow::Result<L1StateUpdate> {
        // TODO(SM): impl
        Ok(L1StateUpdate::default())
    }

    pub async fn get_block_number(&self) -> anyhow::Result<U256> {
        // TODO(SM): impl
        Ok(U256::zero())
    }
}

/*

curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":0}' https://eth.llamarpc.com
{"jsonrpc":"2.0","id":0,"result":"0x103588d"}

$ curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0","data":"0x35befa5d"}, "0x103588d"],"id":1}' https://eth.llamarpc.com
{"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000007eeb"}

$ curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xc662c410c0ecf747543f5ba90660f6abebd9c8c4","value":"0x0","data":"0x9588eca2"}, "0x103588d"],"id":1}' https://eth.llamarpc.com
{"jsonrpc":"2.0","id":1,"result":"0x02a4651c1ba5151c48ebeb4477216b04d7a65058a5b99e5fbc602507ae933d2f"}

$ curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":42}' https://eth.llamarpc.com
{"jsonrpc":"2.0","id":42,"result":"0x52df48d1d"}

---

$ curl https://alpha-mainnet.starknet.io/feeder_gateway/get_contract_addresses
{"GpsStatementVerifier": "0x47312450B3Ac8b5b8e247a6bB6d523e7605bDb60", "Starknet": "0xc662c410C0ECf747543f5bA90660f6ABeBD9C8c4"}

$ curl https://alpha4.starknet.io/feeder_gateway/get_contract_addresses
{"GpsStatementVerifier": "0x8f97970aC5a9aa8D130d35146F5b59c4aef57963", "Starknet": "0xde29d060D45901Fb19ED6C6e959EB22d8626708e"}

$ curl https://alpha4-2.starknet.io/feeder_gateway/get_contract_addresses
{"GpsStatementVerifier": "0x8f97970aC5a9aa8D130d35146F5b59c4aef57963", "Starknet": "0xa4eD3aD27c294565cB0DCc993BDdCC75432D498c"}

$ curl https://external.integration.starknet.io/feeder_gateway/get_contract_addresses
{"GpsStatementVerifier": "0x8f97970aC5a9aa8D130d35146F5b59c4aef57963", "Starknet": "0xd5c325D183C592C94998000C5e0EED9e6655c020"}

 */
