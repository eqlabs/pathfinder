//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use futures::{channel::mpsc, StreamExt};
use libp2p::PeerId;
use p2p_proto::block::{BlockBodiesRequest, BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::common::{Direction, Iteration};
use p2p_proto::event::EventsRequest;
use p2p_proto::receipt::{Receipt, ReceiptsRequest};
use p2p_proto::transaction::TransactionsRequest;
use pathfinder_common::{
    event::Event,
    transaction::{DeployAccountTransactionV0V1, DeployAccountTransactionV3, TransactionVariant},
    BlockHash, BlockNumber, ContractAddress, TransactionHash,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tokio::sync::RwLock;

use crate::client::peer_aware;
use crate::client::types::{
    MaybeSignedBlockHeader, RawDeployAccountTransaction, StateUpdateWithDefinitions,
};
use crate::peers;
use crate::sync::protocol;

mod parse;

use parse::ParserState;

/// Data received from a specific peer.
#[derive(Debug)]
pub struct PeerData<T> {
    pub peer: PeerId,
    pub data: T,
}

impl<T> PeerData<T> {
    pub fn new(peer: PeerId, data: T) -> Self {
        Self { peer, data }
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    inner: peer_aware::Client,
    block_propagation_topic: String,
    peers_with_capability: Arc<RwLock<PeersWithCapability>>,
    // FIXME
    _peers: Arc<RwLock<peers::Peers>>,
}

// TODO Rework the API!
// I.e. make sure the api looks reasonable from the perspective of
// the __user__, which is the sync driving algo/entity.
impl Client {
    pub fn new(
        inner: peer_aware::Client,
        block_propagation_topic: String,
        peers: Arc<RwLock<peers::Peers>>,
    ) -> Self {
        Self {
            inner,
            block_propagation_topic,
            peers_with_capability: Default::default(),
            _peers: peers,
        }
    }

    // Propagate new L2 head head
    pub async fn propagate_new_head(
        &self,
        block_id: p2p_proto::common::BlockId,
    ) -> anyhow::Result<()> {
        tracing::debug!(number=%block_id.number, hash=%block_id.hash.0, topic=%self.block_propagation_topic,
            "Propagating head"
        );

        self.inner
            .publish(
                &self.block_propagation_topic,
                p2p_proto::block::NewBlock::Id(block_id),
            )
            .await
    }

    async fn get_update_peers_with_sync_capability(&self, capability: &str) -> Vec<PeerId> {
        use rand::seq::SliceRandom;

        let r = self.peers_with_capability.read().await;
        let mut peers = if let Some(peers) = r.get(capability) {
            peers.iter().copied().collect::<Vec<_>>()
        } else {
            // Avoid deadlock
            drop(r);

            let mut peers = self
                .inner
                .get_capability_providers(capability)
                .await
                .unwrap_or_default();

            let _i_should_have_the_capability_too = peers.remove(self.inner.peer_id());
            debug_assert!(_i_should_have_the_capability_too);

            let peers_vec = peers.iter().copied().collect::<Vec<_>>();

            let mut w = self.peers_with_capability.write().await;
            w.update(capability, peers);
            peers_vec
        };
        peers.shuffle(&mut rand::thread_rng());
        peers
    }

    pub async fn block_headers(
        &self,
        start_block: BlockNumber,
        num_blocks: usize,
    ) -> anyhow::Result<Vec<MaybeSignedBlockHeader>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        for peer in self
            .get_update_peers_with_sync_capability(protocol::Headers::NAME)
            .await
        {
            let request = BlockHeadersRequest {
                iteration: Iteration {
                    start: start_block.get().into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response_receiver = self.inner.send_headers_sync_request(peer, request).await;

            match response_receiver {
                Ok(mut receiver) => {
                    // Limits on max message size and our internal limit of maximum blocks per response
                    // imply that we can't receive more than 1 response. See static asserts in
                    // [`pathfinder_lib::p2p_network::sync_handlers`].
                    let Some(BlockHeadersResponse { parts }) = receiver.next().await else {
                        // Try the next peer
                        break;
                    };

                    let mut state = parse::block_header::State::Uninitialized;
                    for part in parts {
                        if let Err(error) = state.advance(part) {
                            tracing::debug!(from=%peer, %error, "headers response parsing");
                            // Try the next peer
                            break;
                        }
                    }

                    if let Some(headers) = state.take_parsed() {
                        // Success
                        return Ok(headers);
                    } else {
                        // Try the next peer
                        tracing::debug!(from=%peer, "unexpected end of part");
                        break;
                    }
                }
                // Try the next peer
                Err(error) => {
                    tracing::debug!(from=%peer, %error, "headers request failed");
                }
            }
        }

        anyhow::bail!("No valid responses to headers request: start {start_block}, n {num_blocks}")
    }

    /// Including new class definitions
    pub async fn state_updates(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> anyhow::Result<Vec<StateUpdateWithDefinitions>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let peers = self
            .get_update_peers_with_sync_capability(protocol::Bodies::NAME)
            .await;
        for peer in peers {
            let request = BlockBodiesRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response_receiver = self.inner.send_bodies_sync_request(peer, request).await;

            match response_receiver {
                Ok(rx) => {
                    if let Some(parsed) = parse::<parse::state_update::State>(&peer, rx).await {
                        return Ok(parsed);
                    }
                }
                Err(error) => tracing::debug!(from=%peer, %error, "bodies request failed"),
            }
        }

        anyhow::bail!(
            "No valid responses to bodies request: start {start_block_hash}, n {num_blocks}"
        )
    }

    pub async fn transactions(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> anyhow::Result<HashMap<BlockHash, Vec<TransactionVariant>>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let peers = self
            .get_update_peers_with_sync_capability(protocol::Transactions::NAME)
            .await;
        for peer in peers {
            let request = TransactionsRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response_receiver = self
                .inner
                .send_transactions_sync_request(peer, request)
                .await;

            match response_receiver {
                Ok(rx) => {
                    if let Some(parsed) = parse::<parse::transactions::State>(&peer, rx).await {
                        let computed = compute_contract_addresses(parsed.deploy_account)
                            .await
                            .context(
                                "compute contract addresses for deploy account transactions",
                            )?;

                        let mut parsed: HashMap<_, _> = parsed
                            .other
                            .into_iter()
                            .map(|(h, txns)| {
                                (h, txns.into_iter().map(|t| t.into_variant()).collect())
                            })
                            .collect();
                        parsed.extend(computed);

                        return Ok(parsed);
                    }
                }
                Err(error) => tracing::debug!(from=%peer, %error, "transactions request failed"),
            }
        }

        anyhow::bail!(
            "No valid responses to transactions request: start {start_block_hash}, n {num_blocks}"
        )
    }

    pub async fn receipts(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> anyhow::Result<HashMap<BlockHash, Vec<Receipt>>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let peers = self
            .get_update_peers_with_sync_capability(protocol::Receipts::NAME)
            .await;
        for peer in peers {
            let request = ReceiptsRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response_receiver = self.inner.send_receipts_sync_request(peer, request).await;

            match response_receiver {
                Ok(rx) => {
                    if let Some(parsed) = parse::<parse::receipts::State>(&peer, rx).await {
                        return Ok(parsed);
                    }
                }
                Err(error) => tracing::debug!(from=%peer, %error, "receipts request failed"),
            }
        }

        anyhow::bail!(
            "No valid responses to receipts request: start {start_block_hash}, n {num_blocks}"
        )
    }

    pub async fn event(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> anyhow::Result<HashMap<BlockHash, HashMap<TransactionHash, Vec<Event>>>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let peers = self
            .get_update_peers_with_sync_capability(protocol::Events::NAME)
            .await;
        for peer in peers {
            let request = EventsRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response_receiver = self.inner.send_events_sync_request(peer, request).await;

            match response_receiver {
                Ok(rx) => {
                    if let Some(parsed) = parse::<parse::events::State>(&peer, rx).await {
                        return Ok(parsed);
                    }
                }
                Err(error) => tracing::debug!(from=%peer, %error, "events request failed"),
            }
        }

        anyhow::bail!(
            "No valid responses to events request: start {start_block_hash}, n {num_blocks}"
        )
    }
}

/// Does not block the current thread.
async fn compute_contract_addresses(
    deploy_account: HashMap<BlockHash, Vec<super::types::RawDeployAccountTransaction>>,
) -> anyhow::Result<Vec<(BlockHash, Vec<TransactionVariant>)>> {
    let jh = tokio::task::spawn_blocking(move || {
        // Now we can compute the missing addresses
        let computed: Vec<_> = deploy_account
            .into_par_iter()
            .map(|(block_hash, transactions)| {
                (
                    block_hash,
                    transactions
                        .into_par_iter()
                        .map(|t| match t {
                            RawDeployAccountTransaction::DeployAccountV0V1(x) => {
                                let contract_address = ContractAddress::deployed_contract_address(
                                    x.constructor_calldata.iter().copied(),
                                    &x.contract_address_salt,
                                    &x.class_hash,
                                );
                                TransactionVariant::DeployAccountV0V1(
                                    DeployAccountTransactionV0V1 {
                                        contract_address,
                                        max_fee: x.max_fee,
                                        version: x.version,
                                        signature: x.signature,
                                        nonce: x.nonce,
                                        contract_address_salt: x.contract_address_salt,
                                        constructor_calldata: x.constructor_calldata,
                                        class_hash: x.class_hash,
                                    },
                                )
                            }
                            RawDeployAccountTransaction::DeployAccountV3(x) => {
                                let contract_address = ContractAddress::deployed_contract_address(
                                    x.constructor_calldata.iter().copied(),
                                    &x.contract_address_salt,
                                    &x.class_hash,
                                );
                                TransactionVariant::DeployAccountV3(DeployAccountTransactionV3 {
                                    contract_address,
                                    signature: x.signature,
                                    nonce: x.nonce,
                                    nonce_data_availability_mode: x.nonce_data_availability_mode,
                                    fee_data_availability_mode: x.fee_data_availability_mode,
                                    resource_bounds: x.resource_bounds,
                                    tip: x.tip,
                                    paymaster_data: x.paymaster_data,
                                    contract_address_salt: x.contract_address_salt,
                                    constructor_calldata: x.constructor_calldata,
                                    class_hash: x.class_hash,
                                })
                            }
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        computed
    });
    let computed = jh.await.context("task ended unexpectedly")?;
    Ok(computed)
}

async fn parse<P: Default + ParserState>(
    peer: &PeerId,
    mut receiver: mpsc::Receiver<P::Dto>,
) -> Option<P::Out> {
    let mut state = P::default();

    while let Some(response) = receiver.next().await {
        if let Err(error) = state.advance(response) {
            tracing::debug!(from=%peer, %error, "{} response parsing", std::any::type_name::<P::Dto>());
            break;
        }
    }

    state.take_parsed().or_else(|| {
        tracing::debug!(from=%peer, "empty response or unexpected end of response");
        None
    })
}

#[derive(Clone, Debug)]
struct PeersWithCapability {
    set: HashMap<String, HashSet<PeerId>>,
    last_update: std::time::Instant,
    timeout: Duration,
}

impl PeersWithCapability {
    pub fn new(timeout: Duration) -> Self {
        Self {
            set: Default::default(),
            last_update: std::time::Instant::now(),
            timeout,
        }
    }

    /// Does not clear if elapsed, instead the caller is expected to call [`Self::update`]
    pub fn get(&self, capability: &str) -> Option<&HashSet<PeerId>> {
        if self.last_update.elapsed() > self.timeout {
            None
        } else {
            self.set.get(capability)
        }
    }

    pub fn update(&mut self, capability: &str, peers: HashSet<PeerId>) {
        self.last_update = std::time::Instant::now();
        self.set.insert(capability.to_owned(), peers);
    }
}

impl Default for PeersWithCapability {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}
