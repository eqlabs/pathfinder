use pathfinder_common::{BlockHash, BlockNumber, EthereumChain, StateCommitment};
use primitive_types::H160;

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

// TODO(SM): remove this pointless thing
/// Groups the Starknet contract addresses for a specific chain.
#[derive(Default)]
pub struct ContractAddresses {
    pub core: H160,
    pub gps: H160,
    pub mempage: H160,
}
