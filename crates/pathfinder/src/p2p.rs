//! A temporary wrapper around the sequencer client that mocks the real
//! p2p api that is currently being worked on.
//!
//! ## Important
//!
//! - Types returned by this api will change soon.
//! - Guarantees that this api makes can change soon.
use crate::core::{
    BlockId, Chain, ClassHash, ContractAddress, StarknetBlockHash, StarknetBlockNumber,
};
use crate::sequencer::{
    self,
    error::{SequencerError, StarknetErrorCode},
    reply::{Block, MaybePendingBlock, StateUpdate},
    ClientApi,
};
use bytes::Bytes;
use stark_hash::StarkHash;
use std::time::Duration;
use tokio::sync::mpsc;

/// Creates:
/// - the client used to retrieve data from p2p network on a request-response basis
/// - the receiver which notifies of incoming p2p events that we're subscribing to
/// - the p2p main loop which is used to drive the entire libp2p processing
pub fn new<SequencerClient: Clone>(
    sequencer: SequencerClient,
    chain: Chain,
) -> anyhow::Result<(
    Client<SequencerClient>,
    mpsc::Receiver<Event>,
    MainLoop<SequencerClient>,
)> {
    let (event_sender, event_receiver) = mpsc::channel(1);
    // Helps uphold api guarantees
    let (last_requested_block_tx, last_requested_block_rx) = mpsc::channel(1);

    Ok((
        Client {
            sequencer: sequencer.clone(),
            latest_block_tx: last_requested_block_tx,
        },
        event_receiver,
        MainLoop::new(sequencer, last_requested_block_rx, chain, event_sender),
    ))
}

/// A mock p2p client that uses a sequencer client under the hood
#[derive(Clone, Debug)]
pub struct Client<SequencerClient> {
    sequencer: SequencerClient,
    latest_block_tx: mpsc::Sender<Block>,
}

/// Errors returned by [`Client::request_block`]
#[derive(Debug, thiserror::Error)]
pub enum RequestBlockError {
    /// Block with a given id was not found
    #[error("block not found")]
    BlockNotFound,
    /// Failed to get block
    #[error(transparent)]
    Other(SequencerError),
    /// Underlying sequencer client returned a pending block
    #[error("got pending block")]
    GotPending,
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

impl<SequencerClient: ClientApi> Client<SequencerClient> {
    /// Requests a block by id
    ///
    /// ## Guarantee
    ///
    /// This method will never succeed when requesting past the latest block carried in [`Event::NewBlock`]
    pub async fn request_block(&self, block_id: BlockId) -> Result<Block, RequestBlockError> {
        match self.sequencer.block(block_id).await {
            Ok(MaybePendingBlock::Block(block)) => {
                self.latest_block_tx
                    .send(block.clone())
                    .await
                    .expect("the channel is not closed");
                Ok(block)
            }
            Ok(MaybePendingBlock::Pending(_)) => Err(RequestBlockError::GotPending),
            Err(SequencerError::StarknetError(error))
                if error.code == StarknetErrorCode::BlockNotFound =>
            {
                Err(RequestBlockError::BlockNotFound)
            }
            Err(other) => Err(RequestBlockError::Other(other)),
        }
    }

    /// Requests a state diff by id
    pub async fn request_state_diff(&self, block_id: BlockId) -> anyhow::Result<StateUpdate> {
        let state_update = self.sequencer.state_update(block_id).await?;
        Ok(state_update)
    }

    /// Requests a contract class by class hash
    pub async fn request_class(&self, class_hash: ClassHash) -> anyhow::Result<Bytes> {
        let class = self.sequencer.class_by_hash(class_hash).await?;
        Ok(class)
    }

    /// Requests a full contract definiton by contract address
    pub async fn request_contract(
        &self,
        contract_address: ContractAddress,
    ) -> anyhow::Result<Bytes> {
        let contract = self.sequencer.full_contract(contract_address).await?;
        Ok(contract)
    }

    #[cfg(test)]
    pub async fn for_tests(sequencer: SequencerClient) -> Self {
        // Let's make the channel deep enough so that it does not complain
        let (latest_block_tx, rx) = mpsc::channel(100);
        let _ = Box::leak(Box::new(rx));
        Self {
            sequencer,
            latest_block_tx,
        }
    }
}

/// Events received via Gossipsub
#[derive(Debug)]
pub enum Event {
    /// ## Guarantee
    ///
    /// Always carries the latest available block, [`Client::request_block`] will never succeed when
    /// requesting past this block
    NewBlock(Block),
}

/// The main loop that drives lip2p operation
pub struct MainLoop<SequencerClient> {
    sequencer: SequencerClient,
    last_requested_block_rx: mpsc::Receiver<Block>,
    chain: Chain,
    event_sender: mpsc::Sender<Event>,
}

impl<SequencerClient> MainLoop<SequencerClient> {
    /// Creates new main loop
    fn new(
        sequencer: SequencerClient,
        last_requested_block_rx: mpsc::Receiver<Block>,
        chain: Chain,
        event_sender: mpsc::Sender<Event>,
    ) -> Self {
        Self {
            sequencer,
            last_requested_block_rx,
            chain,
            event_sender,
        }
    }

    /// Entry point for the loop
    pub async fn run(self) -> anyhow::Result<()>
    where
        SequencerClient: sequencer::ClientApi,
    {
        // Keep head_poll_interval private
        let poll_interval: Duration = match self.chain {
            // 5 minute interval for a 30 minute block time.
            Chain::Mainnet => Duration::from_secs(60 * 5),
            // 30 second interval for a 2 minute block time.
            _ => Duration::from_secs(30),
        };

        // Start immediately
        let mut poll_interval = tokio::time::interval(poll_interval);
        let mut last_block_hash = StarknetBlockHash(StarkHash::ZERO);
        let mut last_block_number = StarknetBlockNumber::MAX;
        let mut last_requested_block_rx = self.last_requested_block_rx;

        loop {
            let tick = poll_interval.tick();

            tokio::select! {
                _ = tick => {
                    tracing::trace!(target: "p2p", "Gossipsub: poll latest");
                    match self.sequencer.block(BlockId::Latest).await {
                        Ok(block) =>
                            match block {
                                MaybePendingBlock::Block(block) => {
                                    tracing::trace!(target: "p2p", number=%block.block_number, hash=%block.block_hash, "Gossipsub: polled");

                                    if last_block_hash != block.block_hash {
                                        last_block_hash = block.block_hash;
                                        last_block_number = block.block_number;

                                        let number = block.block_number;
                                        let hash = block.block_hash;
                                        tracing::trace!(target: "p2p", %number, %hash, "Gossipsub: new block SEND START");
                                        match self.event_sender.send(Event::NewBlock(block)).await {
                                            Ok(_) => {
                                                tracing::trace!(target: "p2p", %number, %hash, "Gossipsub: new block SEND DONE");
                                            },
                                            Err(_) => anyhow::bail!("Unexpected event channel closure"),
                                        }
                                    }
                                }
                                MaybePendingBlock::Pending(_) => {
                                    tracing::warn!(target: "p2p", "Gossipsub: polled pending");
                                },
                            }
                        Err(error) => tracing::error!(target: "p2p", reason=%error, "Polling latest block"),
                    }
                }
                last_requested_block = last_requested_block_rx.recv() => {
                    tracing::trace!(target: "p2p", "Gossipsub: poll kechup");
                    match last_requested_block {
                        Some(block) => {
                            if last_block_number < block.block_number {
                                last_block_hash = block.block_hash;
                                last_block_number = block.block_number;

                                tracing::trace!(target: "p2p", number=%last_block_number, hash=%last_block_hash, "Gossipsub: new block SEND START kechup");
                                match self.event_sender.send(Event::NewBlock(block.clone())).await {
                                    Ok(_) => {
                                        tracing::trace!(target: "p2p", number=%last_block_number, hash=%last_block_hash, "Gossipsub: new block SEND DONE kechup");
                                    },
                                    Err(_) => anyhow::bail!("Unexpected event channel closure"),
                                }
                            }
                        },
                        None => anyhow::bail!("Unexpected channel closure"),
                    }
                }
            }
        }
    }
}
