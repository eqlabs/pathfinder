//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use libp2p::PeerId;
use p2p_proto_v1::common::{BlockNumberOrHash, Direction, Fin, Hash, Iteration};
use p2p_proto_v1::consts::MAX_PARTS_PER_CLASS;
use p2p_proto_v1::{
    block::{
        BlockBodiesResponse, BlockBodyMessage, BlockHeadersRequest, BlockHeadersResponse,
        BlockHeadersResponsePart,
    },
    common::BlockId,
};
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use tokio::sync::RwLock;

use crate::sync::protocol;
use crate::{
    client::{
        peer_aware,
        types::{BlockHeader, Class, StateUpdate},
    },
    peers,
};

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
        block_id: p2p_proto_v1::common::BlockId,
    ) -> anyhow::Result<()> {
        tracing::debug!(number=%block_id.number, hash=%block_id.hash.0, topic=%self.block_propagation_topic,
            "Propagating head"
        );

        self.inner
            .publish(
                &self.block_propagation_topic,
                p2p_proto_v1::block::NewBlock::Id(block_id),
            )
            .await
    }

    async fn get_update_peers_with_sync_capability(&self, capability: &[u8]) -> Vec<PeerId> {
        use rand::seq::SliceRandom;

        let r = self.peers_with_capability.read().await;
        let mut peers = if let Some(peers) = r.get(capability) {
            peers.into_iter().copied().collect::<Vec<_>>()
        } else {
            // Avoid deadlock
            drop(r);

            let mut peers = self
                .inner
                .get_capability_providers(std::str::from_utf8(capability).expect("valid UTF-8"))
                .await
                .unwrap_or_default();

            let _i_should_have_the_capability_too = peers.remove(&self.inner.peer_id());
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
    ) -> Option<Vec<p2p_proto_v0::common::BlockHeader>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let count: u64 = num_blocks.try_into().ok()?;

        for peer in self
            .get_update_peers_with_sync_capability(protocol::Headers::NAME)
            .await
        {
            let response = self.inner.send_sync_request(peer, todo!("use v1")).await;

            match response {
                Ok(_) => {
                    todo!("use v1");
                    tracing::debug!(%peer, "Got unexpected response to GetBlockHeaders");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetBlockHeaders failed");
                    continue;
                }
            }
        }

        tracing::debug!(%start_block, %num_blocks, "No peers with block headers found for");

        None
    }

    /// Including new class definitions
    pub async fn state_updates(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> Option<Vec<(BlockHash, (StateUpdate, Vec<Class>))>> {
        if num_blocks == 0 {
            return Some(Default::default());
        }

        let limit: u64 = num_blocks.try_into().ok()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let mut peers = self
            .get_update_peers_with_sync_capability(protocol::Bodies::NAME)
            .await
            .into_iter();

        'try_next_peer: loop {
            let peer = peers.next()?;
            let request = BlockHeadersRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };

            let response = self.inner.send_sync_request(peer, todo!("fixme")).await;
            let response: anyhow::Result<_> = Ok(vec![]); // FIXME

            let mut state_updates = HashMap::<BlockId, (StateUpdate, Vec<Class>)>::new();
            match response {
                Ok(body_responses) => {
                    if body_responses.is_empty() {
                        tracing::debug!(%peer, "Empty BlockBodiesResponse");
                        // Try with another peer
                    } else {
                        let mut current_id = None;

                        for body_response in body_responses {
                            let BlockBodiesResponse { id, body_message } = body_response;

                            match (id, body_message) {
                                (Some(id), BlockBodyMessage::Diff(d)) => {
                                    match StateUpdate::try_from(d) {
                                        Ok(su) => {
                                            state_updates.insert(id, (su, Default::default()));
                                            current_id = Some(id);
                                        }
                                        Err(error) => {
                                            tracing::debug!(from=%peer, %error, "Decoding BlockBodiesResponse");
                                            break 'try_next_peer;
                                        }
                                    }
                                }
                                (Some(id), BlockBodyMessage::Classes(c)) => match current_id {
                                    Some(current_id) if current_id == id => {
                                        match state_updates.get_mut(&id) {
                                            Some((_, classes)) => {
                                                match classes_from_proto(c.classes) {
                                                    Ok(more_classes) => {
                                                        classes.extend(more_classes)
                                                    }
                                                    Err(error) => {
                                                        tracing::debug!(from=%peer, %error, "Decoding BlockBodiesResponse");
                                                        break 'try_next_peer;
                                                    }
                                                }
                                            }
                                            None => {
                                                tracing::debug!(from=%peer, %id, "Classes should be preceded with StateDiff for the same id in BlockBodiesResponse");
                                                break 'try_next_peer;
                                            }
                                        }
                                    }
                                    Some(current_id) => {
                                        tracing::debug!(from=%peer, expected=%current_id, %id, "Id mismatch in BlockBodiesResponse");
                                        break 'try_next_peer;
                                    }
                                    None => {
                                        tracing::debug!(from=%peer, %id, "Classes should be preceded with StateDiff for the same id in BlockBodiesResponse");
                                        break 'try_next_peer;
                                    }
                                },
                                (Some(_), BlockBodyMessage::Proof(_)) => {
                                    // TODO proof handling
                                }
                                (id, BlockBodyMessage::Fin(Fin { error })) => {
                                    match (id, &mut current_id) {
                                        (Some(id), Some(curr_id)) if *curr_id == id => {
                                            // [Diff, Classes*, Fin]
                                            //                  ^^^
                                            // The block is correctly delimited
                                            if let Some(error) = error {
                                                tracing::debug!(from=%peer, %id, ?error, "BlockBodiesResponse delimited with an error");
                                                // This is ok, assume no more blocks from this peer past this point.
                                                // Use only the blocks that we've accumulated so far.
                                                break;
                                            } else {
                                                // Process the next block from the same peer
                                                current_id = None;
                                            }
                                        }
                                        (Some(id), Some(current_id)) => {
                                            // [..., Diff, Classes*, Fin]
                                            //                       ^^^
                                            // The block is correctly delimited but the id is wrong, that's against the spec
                                            tracing::debug!(from=%peer, expected=%current_id, %id, "Id mismatch in BlockBodiesResponse");
                                            break 'try_next_peer;
                                        }
                                        (None | Some(_), None) => {
                                            if state_updates.is_empty() {
                                                // We only got [Fin] from this peer.
                                                // We haven't accumulated any blocks yet.
                                                break 'try_next_peer;
                                            } else {
                                                // [..., Diff, Classes*, Fin, Fin]
                                                //                            ^^^
                                                // The last block was properly delimited and we've got an additional Fin, which could
                                                // signal the reason why the peer is not sending any more blocks.
                                                tracing::debug!(from=%peer, ?error, ?id, "Additional Fin after last block BlockBodiesResponse");
                                                // Use only the blocks that we've accumulated so far.
                                                break;
                                            }
                                        }
                                        (None, Some(_)) => {
                                            // [Diff, Classes*, Fin]
                                            //                  ^^^
                                            // The block seems to be correctly delimited but Fin does not contain valid id
                                            // which is against the spec.
                                            break 'try_next_peer;
                                        }
                                    }

                                    break 'try_next_peer;
                                }
                                (
                                    None,
                                    BlockBodyMessage::Diff(_)
                                    | BlockBodyMessage::Classes(_)
                                    | BlockBodyMessage::Proof(_),
                                ) => {
                                    tracing::debug!(from=%peer, "Missing id in BlockBodiesResponse");
                                    break 'try_next_peer;
                                }
                            }
                        }

                        if state_updates.is_empty() {
                            tracing::debug!(from=%peer, "Empty BlockBodiesResponse");
                            // Try the next peer instead
                        } else {
                            return Some(
                                state_updates
                                    .into_iter()
                                    .map(|(k, v)| (BlockHash(k.hash.0), v))
                                    .collect(),
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "BlockBodiesRequest failed");
                    // Try the next peer instead
                }
            }
        }

        tracing::debug!(%start_block_hash, %num_blocks, "No peers with block bodies found for");

        None
    }
}

/// Merges partitoned classes if necessary
fn classes_from_proto(classes: Vec<p2p_proto_v1::state::Class>) -> anyhow::Result<Vec<Class>> {
    #[derive(Copy, Clone, Debug, Default, PartialEq)]
    struct Ctx {
        hash: Hash,
        total_parts: u32,
        part_num: u32,
    }

    impl Ctx {
        fn matches_next_part(&self, hash: Hash, total_parts: u32, part_num: u32) -> bool {
            self.hash == hash && self.total_parts == total_parts && self.part_num + 1 == part_num
        }
    }

    let mut gathered = Vec::new();
    let mut ctx: Option<Ctx> = None;

    for class in classes {
        match (class.total_parts, class.part_num) {
            // Small class definition, not partitioned
            (None, None) => gathered.push(Class {
                hash: ClassHash(class.compiled_hash.0),
                definition: class.definition,
            }),
            // Large class definition, partitioned. Immediately reject invalid values or
            // obvious attempts at DoS-ing us.
            (Some(total_parts), Some(part_num))
                if total_parts > 0
                    && total_parts < MAX_PARTS_PER_CLASS
                    && part_num < total_parts =>
            {
                match ctx {
                    // First part of a larger definition
                    None if part_num == 0 => {
                        gathered.push(Class {
                            hash: ClassHash(class.compiled_hash.0),
                            definition: class.definition,
                        });
                        ctx = Some(Ctx {
                            hash: class.compiled_hash,
                            total_parts,
                            part_num,
                        });
                    }
                    // Another part of the same definition
                    Some(some_ctx)
                        if some_ctx.matches_next_part(
                            class.compiled_hash,
                            total_parts,
                            part_num,
                        ) =>
                    {
                        gathered
                            .last_mut()
                            .expect("gathered is not empty")
                            .definition
                            .extend(class.definition);

                        // This was the last part
                        if total_parts == part_num {
                            ctx = None;
                        }
                    }
                    None | Some(_) => {
                        anyhow::bail!("Invalid Class part: {:?}/{:?}", part_num, total_parts)
                    }
                }
            }
            _ => anyhow::bail!(
                "Invalid Class part: {:?}/{:?}",
                class.part_num,
                class.total_parts,
            ),
        }
    }

    Ok(gathered)
}

#[derive(Clone, Debug)]
struct PeersWithCapability {
    set: HashMap<Vec<u8>, HashSet<PeerId>>,
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
    pub fn get(&self, capability: &[u8]) -> Option<&HashSet<PeerId>> {
        if self.last_update.elapsed() > self.timeout {
            None
        } else {
            self.set.get(capability)
        }
    }

    pub fn update(&mut self, capability: &[u8], peers: HashSet<PeerId>) {
        self.last_update = std::time::Instant::now();
        self.set.insert(capability.to_owned(), peers);
    }
}

impl Default for PeersWithCapability {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}
