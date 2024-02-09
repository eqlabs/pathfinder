//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use futures::StreamExt;
use libp2p::PeerId;
use p2p_proto::class::{Class, ClassesRequest};
use p2p_proto::common::{Direction, Iteration};
use p2p_proto::event::EventsRequest;
use p2p_proto::header::BlockHeadersRequest;
use p2p_proto::receipt::{Receipt, ReceiptsRequest};
use p2p_proto::state::StateDiffsRequest;
use p2p_proto::transaction::TransactionsRequest;
use pathfinder_common::transaction::{
    DeployAccountTransactionV0V1, DeployAccountTransactionV3, TransactionVariant,
};
use pathfinder_common::{event::Event, StateUpdate};
use pathfinder_common::{
    BlockHash, BlockNumber, ContractAddress, SignedBlockHeader, TransactionHash,
};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use tokio::sync::RwLock;

use crate::client::peer_aware;
use crate::client::types::RawDeployAccountTransaction;
use crate::sync::protocol;

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
}

// TODO Rework the API!
// I.e. make sure the api looks reasonable from the perspective of
// the __user__, which is the sync driving algo/entity.
impl Client {
    pub fn new(inner: peer_aware::Client, block_propagation_topic: String) -> Self {
        Self {
            inner,
            block_propagation_topic,
            peers_with_capability: Default::default(),
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
                p2p_proto::header::NewBlock::Id(block_id),
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

    pub fn header_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        reverse: bool,
    ) -> impl futures::Stream<Item = PeerData<SignedBlockHeader>> {
        // FIXME
        // Keep compiler happy
        let (_, rx) = futures::channel::mpsc::channel(0);
        rx
        // let (mut start, stop, direction) = match reverse {
        //     true => (stop, start, Direction::Backward),
        //     false => (start, stop, Direction::Forward),
        // };

        // async_stream::stream! {
        //     // Loop which refreshes peer set once we exhaust it.
        //     loop {
        //         let peers = self
        //             .get_update_peers_with_sync_capability(protocol::Headers::NAME)
        //             .await;

        //         // Attempt each peer.
        //         'next_peer: for peer in peers {
        //             let limit = start.get().max(stop.get()) - start.get().min(stop.get());

        //             let request = BlockHeadersRequest {
        //                 iteration: Iteration {
        //                     start: start.get().into(),
        //                     direction,
        //                     limit,
        //                     step: 1.into(),
        //                 },
        //             };

        //             let responses = match self.inner.send_headers_sync_request(peer, request).await
        //             {
        //                 Ok(x) => x,
        //                 Err(error) => {
        //                     // Failed to establish connection, try next peer.
        //                     tracing::debug!(%peer, reason=%error, "Headers request failed");
        //                     continue 'next_peer;
        //                 }
        //             };

        //             let mut responses = responses
        //                 .flat_map(|response| futures::stream::iter(response.parts))
        //                 .chunks(2)
        //                 .scan((), |(), chunk| async { parse::handle_signed_header_chunk(chunk) })
        //                 .boxed();

        //             while let Some(signed_header) = responses.next().await {
        //                 let signed_header = match signed_header {
        //                     Ok(signed_header) => signed_header,
        //                     Err(error) => {
        //                         tracing::debug!(%peer, %error, "Header stream failed");
        //                         continue 'next_peer;
        //                     }
        //                 };

        //                 // Small sanity check. We cannot reliably check the hash here,
        //                 // its easier for the caller to ensure it matches expectations.
        //                 if signed_header.header.number != start {
        //                     tracing::debug!(%peer, "Wrong block number");
        //                     continue 'next_peer;
        //                 }

        //                 start = match direction {
        //                     Direction::Forward => start + 1,
        //                     // unwrap_or_default is safe as this is the genesis edge case,
        //                     // at which point the loop will complete at the end of this iteration.
        //                     Direction::Backward => start.parent().unwrap_or_default(),
        //                 };

        //                 yield PeerData::new(peer, signed_header);
        //             }

        //             // TODO: track how much and how fast this peer responded with i.e. don't let them drip feed us etc.
        //         }
        //     }
        // }
    }
}

// TODO
/// Does not block the current thread.
async fn _compute_contract_addresses(
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
