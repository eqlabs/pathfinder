#![allow(dead_code, unused)]

use anyhow::Context;
use error::SyncError2;
use p2p::client::peer_agnostic::Client as P2PClient;
use pathfinder_common::{BlockNumber, Chain, ChainId, PublicKey, StarknetVersion};
use primitive_types::H160;
use starknet_gateway_client::Client as GatewayClient;
use stream::ProcessStage;

mod checkpoint;
mod class_definitions;
mod error;
mod events;
mod headers;
mod state_updates;
mod stream;
mod track;
mod transactions;

const CHECKPOINT_MARGIN: u64 = 10;

pub struct Sync {
    pub storage: pathfinder_storage::Storage,
    pub p2p: P2PClient,
    pub eth_client: pathfinder_ethereum::EthereumClient,
    pub eth_address: H160,
    pub fgw_client: GatewayClient,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub public_key: PublicKey,
}

impl Sync {
    pub async fn run(self) -> anyhow::Result<()> {
        self.checkpoint_sync().await?;

        // TODO: depending on how this is implemented, we might want to loop around it.
        self.track_sync().await
    }

    async fn handle_error(&self, err: error::SyncError) {
        // TODO
        tracing::debug!(
            error = format!("{:#}", err),
            "Log and punish as appropriate"
        );
    }

    async fn get_checkpoint(&self) -> anyhow::Result<pathfinder_ethereum::EthereumStateUpdate> {
        use pathfinder_ethereum::EthereumApi;
        self.eth_client
            .get_starknet_state(&self.eth_address)
            .await
            .context("Fetching latest L1 checkpoint")
    }

    /// Run checkpoint sync until it completes successfully, and we are within
    /// some margin of the latest L1 block.
    async fn checkpoint_sync(&self) -> anyhow::Result<()> {
        let mut checkpoint = self.get_checkpoint().await?;
        loop {
            let result = checkpoint::Sync {
                storage: self.storage.clone(),
                p2p: self.p2p.clone(),
                eth_client: self.eth_client.clone(),
                eth_address: self.eth_address,
                fgw_client: self.fgw_client.clone(),
                chain: self.chain,
                chain_id: self.chain_id,
                public_key: self.public_key,
            }
            .run(checkpoint.clone())
            .await;

            // Handle the error
            if let Err(err) = result {
                self.handle_error(err).await;
                continue;
            }

            // Initial sync might take so long, that the latest checkpoint is actually far
            // ahead again. Repeat until we are within some margin of L1.
            let latest_checkpoint = self.get_checkpoint().await?;
            if checkpoint.block_number + CHECKPOINT_MARGIN < latest_checkpoint.block_number {
                checkpoint = latest_checkpoint;
                continue;
            }

            break;
        }

        Ok(())
    }

    async fn track_sync(&self) -> anyhow::Result<()> {
        todo!();
    }
}

/// The starknet version is necessary to calculate some of the hashes and
/// commitments.
pub struct FetchStarknetVersionFromDb<T> {
    db: pathfinder_storage::Connection,
    _marker: std::marker::PhantomData<T>,
}

impl<T> FetchStarknetVersionFromDb<T> {
    pub fn new(db: pathfinder_storage::Connection) -> Self {
        Self {
            db,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> ProcessStage for FetchStarknetVersionFromDb<T> {
    const NAME: &'static str = "Transactions::FetchStarknetVersionFromDb";
    type Input = (T, BlockNumber);
    type Output = (T, StarknetVersion);

    fn map(&mut self, (data, block_number): Self::Input) -> Result<Self::Output, SyncError2> {
        let mut db = self
            .db
            .transaction()
            .context("Creating database transaction")?;
        let version = db
            .block_version(block_number)
            .context("Fetching starknet version")?
            .ok_or(SyncError2::StarknetVersionNotFound)?;
        Ok((data, version))
    }
}
