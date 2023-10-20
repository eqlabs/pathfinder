//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    ops::ControlFlow,
    sync::Arc,
    time::Duration,
};

use libp2p::PeerId;
use p2p_proto_v1::consts::MAX_PARTS_PER_CLASS;
use p2p_proto_v1::{
    block::BlockBodiesRequest,
    common::{Direction, Fin, Hash, Iteration},
};
use p2p_proto_v1::{
    block::{BlockBodiesResponse, BlockBodyMessage, BlockHeadersRequest, BlockHeadersResponse},
    common::BlockId,
};
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use tokio::sync::RwLock;

use crate::sync::protocol;
use crate::{
    client::{
        peer_aware,
        types::{BlockHeader, Class, StateUpdateWithDefs},
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
    ) -> anyhow::Result<Vec<BlockHeader>> {
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
            let response = self.inner.send_sync_request(peer, todo!("fixme")).await;
            let response: anyhow::Result<_> = todo!("fixme");

            match response {
                Ok(BlockHeadersResponse { parts }) => {
                    let mut state = parse::block_header::State::Uninitialized;
                    for part in parts {
                        if let Err(error) = state.advance(part) {
                            tracing::debug!(from=%peer, %error, "headers response parsing failed");
                            // Try the next peer
                            break;
                        }
                    }

                    if let Some(headers) = state.consume() {
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
    ) -> anyhow::Result<Vec<StateUpdateWithDefs>> {
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

            let response = self.inner.send_sync_request(peer, todo!("fixme")).await;
            let response: anyhow::Result<_> = Ok(vec![]); // FIXME

            match response {
                Ok(body_responses) => {
                    match parse_block_body_responses(body_responses) {
                        // We've got something potentially useful from this peer
                        Ok(su) if !su.is_empty() => return Ok(su),
                        // Try the next peer instead
                        Ok(_) => tracing::debug!(from=%peer, "Empty bodies response"),
                        Err(error) => {
                            tracing::debug!(from=%peer, %error, "Parsing bodies response failed")
                        }
                    }
                }
                // Try the next peer instead
                Err(error) => {
                    tracing::debug!(from=%peer, %error, "Bodies response failed");
                }
            }
        }

        anyhow::bail!(
            "No valid responses to bodies request: start {start_block_hash}, n {num_blocks}"
        )
    }
}

mod parse {
    pub(crate) mod block_header {
        use crate::client::types::BlockHeader;
        use anyhow::Context;
        use p2p_proto_v1::block::BlockHeadersResponsePart;

        #[derive(Debug)]
        pub enum State {
            Uninitialized,
            Header { headers: Vec<BlockHeader> },
            _Signature, // TODO add signature support
            Fin { headers: Vec<BlockHeader> },
        }

        impl State {
            pub fn advance(&mut self, part: BlockHeadersResponsePart) -> anyhow::Result<()> {
                let state = std::mem::replace(self, State::Uninitialized);
                *self = match (state, part) {
                    (State::Uninitialized, BlockHeadersResponsePart::Header(header)) => {
                        let header = BlockHeader::try_from(*header).context("parsing header")?;
                        Self::Header {
                            headers: vec![header],
                        }
                    }
                    (State::Header { headers }, BlockHeadersResponsePart::Fin(_)) => {
                        Self::Fin { headers }
                    }
                    (State::Header { headers: _ }, BlockHeadersResponsePart::Signatures(_)) => {
                        todo!("add signatures support")
                    }
                    (State::_Signature, _) => todo!("add signatures support"),
                    (State::Fin { mut headers }, BlockHeadersResponsePart::Header(header)) => {
                        let header = BlockHeader::try_from(*header).context("parsing header")?;
                        headers.push(header);
                        Self::Header { headers }
                    }
                    (_, part) => anyhow::bail!("Unexpected part {part:?}"),
                };
                Ok(())
            }

            pub fn consume(self) -> Option<Vec<BlockHeader>> {
                match self {
                    State::Fin { headers } if !headers.is_empty() => Some(headers),
                    _ => {
                        tracing::debug!("unexpected end of part");
                        None
                    }
                }
            }
        }
    }
}

fn parse_block_body_responses(
    body_responses: Vec<BlockBodiesResponse>,
) -> anyhow::Result<Vec<StateUpdateWithDefs>> {
    let mut current_id = None;
    let mut state_updates = Vec::new();

    for body_response in body_responses {
        let BlockBodiesResponse { id, body_message } = body_response;

        match (id, body_message) {
            (Some(id), BlockBodyMessage::Diff(diff)) => {
                anyhow::ensure!(current_id.is_none(), "unexpected diff, id: {id}");

                state_updates.push(StateUpdateWithDefs {
                    block_hash: BlockHash(id.hash.0),
                    state_update: diff.into(),
                    classes: Default::default(),
                });
                current_id = Some(id);
            }
            (Some(id), BlockBodyMessage::Classes(new)) => match current_id {
                Some(current_id) if current_id == id => {
                    let current = state_updates
                        .last_mut()
                        .expect("state update for this id is present");
                    current.classes.extend(classes_from_dto(new.classes)?);
                }
                Some(current_id) => {
                    anyhow::bail!("id mismatch in classes: expected {current_id}, got {id}",)
                }
                None => {
                    anyhow::bail!("unexpected classes, id: {id}")
                }
            },
            (Some(_), BlockBodyMessage::Proof(_)) => {
                unimplemented!()
            }
            (Some(id), BlockBodyMessage::Fin(Fin { error })) => {
                match handle_fin(id, current_id, error, state_updates.is_empty())? {
                    // There are still blocks from this peer to process
                    ControlFlow::Continue(_) => current_id = None,
                    // We've got all blocks from this peer
                    ControlFlow::Break(_) => break,
                }
            }
            (None, _) => {
                anyhow::bail!("id missing")
            }
        }
    }

    Ok(state_updates)
}

fn handle_fin(
    id: BlockId,
    current_id: Option<BlockId>,
    error: Option<p2p_proto_v1::common::Error>,
    accumulator_is_empty: bool,
) -> anyhow::Result<ControlFlow<()>> {
    match current_id {
        Some(curr_id) if curr_id == id => {
            // [Diff, Classes*, Fin]
            //                  ^^^
            // The block is correctly delimited
            if let Some(error) = error {
                tracing::debug!(%id, ?error, "Bodies response delimited with an error");
                // This is ok, assume no more blocks from this peer past this point.
                // Use only the blocks that we've accumulated so far.
                Ok(ControlFlow::Break(()))
            } else {
                // Process the next block from the same peer
                Ok(ControlFlow::Continue(()))
            }
        }
        Some(current_id) => {
            // [..., Diff, Classes*, Fin]
            //                       ^^^
            // The block is correctly delimited but the id is wrong, that's against the spec
            anyhow::bail!("Id mismatch in Fin in bodies response: expected {current_id}, got {id}",)
        }
        None => {
            if accumulator_is_empty {
                // We only got [Fin] from this peer.
                // We haven't accumulated any blocks yet.
                anyhow::bail!("Bodies response starts with Fin")
            } else {
                // [..., Diff, Classes*, Fin, Fin]
                //                            ^^^
                // The last block was properly delimited and we've got an additional Fin, which could
                // signal the reason why the peer is not sending any more blocks.
                tracing::debug!(
                    ?error,
                    ?id,
                    "Additional Fin after last block in bodies response"
                );
                // Use only the blocks that we've accumulated so far.
                Ok(ControlFlow::Break(()))
            }
        }
    }
}

/// Merges partitoned classes if necessary
fn classes_from_dto(classes: Vec<p2p_proto_v1::state::Class>) -> anyhow::Result<Vec<Class>> {
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

        fn advance(mut self) -> Option<Self> {
            // This was the last part
            if self.part_num == self.total_parts {
                None
            } else {
                self.part_num += 1;
                Some(self)
            }
        }
    }

    let mut converted = Vec::new();
    let mut ctx: Option<Ctx> = None;

    for class in classes {
        match (class.total_parts, class.part_num) {
            // Small class definition, not partitioned
            (None, None) => converted.push(Class {
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
                        converted.push(Class {
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
                        converted
                            .last_mut()
                            .expect("gathered is not empty")
                            .definition
                            .extend(class.definition);

                        ctx = some_ctx.advance();
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

    Ok(converted)
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
