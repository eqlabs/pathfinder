//! A temporary wrapper around the sequencer client that mocks the real
//! p2p api that is currently being worked on.
use crate::core::{BlockId, ClassHash, ContractAddress};
use crate::core::{Chain, StarknetBlockHash};
use crate::sequencer::error::{SequencerError, StarknetErrorCode};
use crate::sequencer::{
    self,
    reply::{Block, MaybePendingBlock, StateUpdate},
    ClientApi,
};
use bytes::Bytes;
use stark_hash::StarkHash;
use std::time::Duration;
use tokio::sync::mpsc;

pub fn new(
    sequencer: sequencer::Client,
    chain: Chain,
) -> anyhow::Result<(Client, mpsc::Receiver<Event>, MainLoop)> {
    let (event_sender, event_receiver) = mpsc::channel(1);

    Ok((
        Client {
            sequencer: sequencer.clone(),
        },
        event_receiver,
        MainLoop::new(sequencer, chain, event_sender),
    ))
}

#[derive(Clone, Debug)]
pub struct Client {
    sequencer: sequencer::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestBlockError {
    /// Block with a given id was not found
    #[error("block not found")]
    BlockNotFound,
    /// Failed to get block
    #[error(transparent)]
    Other(SequencerError),
}

impl From<SequencerError> for RequestBlockError {
    fn from(e: SequencerError) -> Self {
        match e {
            SequencerError::StarknetError(error)
                if error.code == StarknetErrorCode::BlockNotFound =>
            {
                Self::BlockNotFound
            }
            SequencerError::StarknetError(_)
            | SequencerError::ReqwestError(_)
            | SequencerError::InvalidStarknetErrorVariant => Self::Other(e),
        }
    }
}

impl Client {
    pub async fn request_block(
        &self,
        block_id: BlockId,
    ) -> Result<MaybePendingBlock, RequestBlockError> {
        match self.sequencer.block(block_id).await {
            Ok(block) => Ok(block),
            Err(SequencerError::StarknetError(error))
                if error.code == StarknetErrorCode::BlockNotFound =>
            {
                Err(RequestBlockError::BlockNotFound)
            }
            Err(other) => Err(RequestBlockError::Other(other)),
        }
    }

    pub async fn request_state_diff(&self, block_id: BlockId) -> anyhow::Result<StateUpdate> {
        let state_update = self.sequencer.state_update(block_id).await?;
        Ok(state_update)
    }

    pub async fn request_class(&self, class_hash: ClassHash) -> anyhow::Result<Bytes> {
        let class = self.sequencer.class_by_hash(class_hash).await?;
        Ok(class)
    }

    pub async fn request_contract(
        &self,
        contract_address: ContractAddress,
    ) -> anyhow::Result<Bytes> {
        let contract = self.sequencer.full_contract(contract_address).await?;
        Ok(contract)
    }
}

#[derive(Debug)]
pub enum Event {
    NewBlock(Block),
}

pub struct MainLoop {
    sequencer: sequencer::Client,
    chain: Chain,
    event_sender: mpsc::Sender<Event>,
}

impl MainLoop {
    fn new(sequencer: sequencer::Client, chain: Chain, event_sender: mpsc::Sender<Event>) -> Self {
        Self {
            sequencer,
            chain,
            event_sender,
        }
    }

    pub async fn run(self) {
        // Keep head_poll_interval private
        let poll_interval: Duration = match self.chain {
            // 5 minute interval for a 30 minute block time.
            Chain::Mainnet => Duration::from_secs(60 * 5),
            // 30 second interval for a 2 minute block time.
            _ => Duration::from_secs(30),
        };

        let poll_start = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut poll_interval = tokio::time::interval_at(poll_start, poll_interval);
        let mut last_block = StarknetBlockHash(StarkHash::ZERO);

        loop {
            let tick = poll_interval.tick();

            tokio::select! {
                _ = tick => {
                    match self.sequencer.block(BlockId::Latest).await {
                        Ok(block) =>
                            match block {
                                MaybePendingBlock::Block(block) => {
                                    if last_block != block.block_hash {
                                        let number = block.block_number;
                                        let hash = block.block_hash;
                                        tracing::debug!(%number, %hash, "Gossipsub: new block");
                                        match self.event_sender.send(Event::NewBlock(block)).await {
                                            Ok(_) => {},
                                            Err(error) => tracing::error!(reason=%error, "Sending latest block"),
                                        }
                                        last_block = hash;
                                    }
                                }
                                MaybePendingBlock::Pending(_) => {},
                            }
                        Err(error) => tracing::error!(reason=%error, "Polling latest block"),
                    }
                }
            }
        }
    }
}
