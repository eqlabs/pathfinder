use pathfinder_common::{BlockHash, BlockNumber, EthereumChain, StateCommitment};

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
    async fn get_starknet_state(&self) -> anyhow::Result<EthereumStateUpdate>;
    async fn get_chain(&self) -> anyhow::Result<EthereumChain>;
}

#[derive(Clone, Debug)]
pub struct EthereumClient {}

impl EthereumClient {
    pub fn from_config(_url: reqwest::Url, _password: Option<String>) -> anyhow::Result<Self> {
        Ok(Self {}) // TODO(SM):
    }
}

#[async_trait::async_trait]
impl EthereumApi for EthereumClient {
    async fn get_starknet_state(&self) -> anyhow::Result<EthereumStateUpdate> {
        unimplemented!() // TODO(SM):
    }

    async fn get_chain(&self) -> anyhow::Result<EthereumChain> {
        unimplemented!() // TODO(SM):
    }
}
