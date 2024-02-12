use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use futures::{channel::mpsc::Receiver as ResponseReceiver, StreamExt};
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::identify;
use libp2p::kad::{
    self, BootstrapError, BootstrapOk, ProgressStep, QueryId, QueryInfo, QueryResult,
};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::SwarmEvent;
use libp2p::PeerId;
use p2p_proto::block::{BlockBodiesResponse, BlockHeadersResponse};
use p2p_proto::event::EventsResponse;
use p2p_proto::receipt::ReceiptsResponse;
use p2p_proto::transaction::TransactionsResponse;
use p2p_proto::{ToProtobuf, TryFromProtobuf};
use p2p_stream::{self, OutboundRequestId};
use pathfinder_common::ChainId;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;

use crate::behaviour;
#[cfg(test)]
use crate::test_utils;
use crate::Config;
use crate::{Command, EmptyResultSender, Event, TestCommand, TestEvent};

pub struct MainLoop {
    cfg: crate::Config,
    swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<Event>,
    /// Match dial commands with their senders so that we can notify the caller when the dial
    /// succeeds or fails.
    pending_dials: HashMap<PeerId, EmptyResultSender>,
    pending_sync_requests: PendingRequests,
    // TODO there's no sync status message anymore so we have to:
    // 1. set the idle connection timeout to maximum value to keep connections open (earlier: keep alive::Behavior)
    // 2. update the sync head info of our peers using a different mechanism
    // request_sync_status: HashSetDelay<PeerId>,
    pending_queries: PendingQueries,
    chain_id: ChainId,
    /// Ongoing Kademlia bootstrap query.
    ongoing_bootstrap: Option<QueryId>,
    _pending_test_queries: TestQueries,
}

#[derive(Debug, Default)]
struct PendingRequests {
    pub headers: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<BlockHeadersResponse>>>,
    >,
    pub bodies: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<BlockBodiesResponse>>>,
    >,
    pub transactions: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<TransactionsResponse>>>,
    >,
    pub receipts: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<ReceiptsResponse>>>,
    >,
    pub events: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<EventsResponse>>>,
    >,
}

#[derive(Debug, Default)]
struct PendingQueries {
    pub get_providers: HashMap<QueryId, mpsc::Sender<anyhow::Result<HashSet<PeerId>>>>,
}

impl MainLoop {
    pub(crate) fn new(
        swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<Event>,
        cfg: Config,
        chain_id: ChainId,
    ) -> Self {
        Self {
            cfg,
            swarm,
            command_receiver,
            event_sender,
            pending_dials: Default::default(),
            pending_sync_requests: Default::default(),
            pending_queries: Default::default(),
            chain_id,
            ongoing_bootstrap: None,
            _pending_test_queries: Default::default(),
        }
    }

    pub async fn run(mut self) {
        // Delay bootstrap so that by the time we attempt it we've connected to the bootstrap node
        let bootstrap_start = tokio::time::Instant::now() + self.cfg.bootstrap.start_offset;
        let mut bootstrap_interval =
            tokio::time::interval_at(bootstrap_start, self.cfg.bootstrap.period);

        let mut network_status_interval = tokio::time::interval(Duration::from_secs(5));
        let mut peer_status_interval = tokio::time::interval(Duration::from_secs(30));
        let me = *self.swarm.local_peer_id();

        loop {
            let bootstrap_interval_tick = bootstrap_interval.tick();
            tokio::pin!(bootstrap_interval_tick);

            let network_status_interval_tick = network_status_interval.tick();
            tokio::pin!(network_status_interval_tick);

            let peer_status_interval_tick = peer_status_interval.tick();
            tokio::pin!(peer_status_interval_tick);

            tokio::select! {
                _ = network_status_interval_tick => {
                    let network_info = self.swarm.network_info();
                    let num_peers = network_info.num_peers();
                    let connection_counters = network_info.connection_counters();
                    let num_established_connections = connection_counters.num_established();
                    let num_pending_connections = connection_counters.num_pending();
                    tracing::info!(%num_peers, %num_established_connections, %num_pending_connections, "Network status")
                }
                _ = peer_status_interval_tick => {
                    let dht = self.swarm.behaviour_mut().kademlia_mut()
                        .kbuckets()
                        // Cannot .into_iter() a KBucketRef, hence the inner collect followed by flat_map
                        .map(|kbucket_ref| {
                            kbucket_ref
                                .iter()
                                .map(|entry_ref| *entry_ref.node.key.preimage())
                                .collect::<Vec<_>>()
                        })
                        .flat_map(|peers_in_bucket| peers_in_bucket.into_iter())
                        .collect::<HashSet<_>>();
                    let connected = self
                        .swarm
                        .behaviour_mut()
                        .peers()
                        .filter_map(|(peer_id, peer)| {
                            if peer.is_connected() {
                                Some(peer_id)
                            } else {
                                None
                            }
                        }).collect::<Vec<_>>();

                    tracing::info!(
                        "Peer status: me {}, connected {:?}, dht {:?}",
                        me,
                        connected,
                        dht,
                    );
                }
                _ = bootstrap_interval_tick => {
                    tracing::debug!("Checking low watermark");
                    if let Some(query_id) = self.ongoing_bootstrap {
                        match self.swarm.behaviour_mut().kademlia_mut().query_mut(&query_id) {
                            Some(mut query) if matches!(query.info(), QueryInfo::Bootstrap {
                                step: ProgressStep { last: false, .. }, .. }
                            ) => {
                                tracing::debug!("Previous bootstrap still in progress, aborting it");
                                query.finish();
                                continue;
                            }
                            _ => self.ongoing_bootstrap = None,
                        }
                    }
                    if self.swarm.behaviour_mut().outbound_peers().count() < self.cfg.low_watermark {
                        if let Ok(query_id) = self.swarm.behaviour_mut().kademlia_mut().bootstrap() {
                            self.ongoing_bootstrap = Some(query_id);
                            send_test_event(
                                &self.event_sender,
                                TestEvent::KademliaBootstrapStarted,
                            )
                            .await;
                        }
                    }
                }
                command = self.command_receiver.recv() => {
                    match command {
                        Some(c) => self.handle_command(c).await,
                        None => return,
                    }
                }
                Some(event) = self.swarm.next() => self.handle_event(event).await,
            }
        }
    }

    async fn handle_event(&mut self, event: SwarmEvent<behaviour::Event>) {
        match event {
            // ===========================
            // Connection management
            // ===========================
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_dials.remove(&peer_id) {
                        let _ = sender.send(Ok(()));
                        tracing::debug!(%peer_id, "Established outbound connection");
                    }
                    // FIXME else: trigger an error?
                } else {
                    tracing::debug!(%peer_id, "Established inbound connection");
                }

                send_test_event(
                    &self.event_sender,
                    TestEvent::ConnectionEstablished {
                        outbound: endpoint.is_dialer(),
                        remote: peer_id,
                    },
                )
                .await;
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    if let Some(sender) = self.pending_dials.remove(&peer_id) {
                        let _ = sender.send(Err(error.into()));
                    }
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                connection_id: _, // TODO consider tracking connection IDs for peers
                ..
            } => {
                tracing::debug!(%peer_id, "Connection closed");
                if num_established == 0 {
                    send_test_event(
                        &self.event_sender,
                        TestEvent::ConnectionClosed { remote: peer_id },
                    )
                    .await;
                }
            }
            SwarmEvent::Dialing {
                // The only API available to the caller [`crate::client::peer_aware::Client`] only allows for dialing
                // **known** peers, so we can discard the `None` case here.
                peer_id: Some(peer_id),
                connection_id: _, // TODO consider tracking connection ids for peers
            } => {
                tracing::debug!(%peer_id, "Dialing peer");
            }
            // ===========================
            // Identify
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Identify(e)) => {
                if let identify::Event::Received {
                    peer_id,
                    info:
                        identify::Info {
                            listen_addrs,
                            protocols,
                            observed_addr,
                            ..
                        },
                } = *e
                {
                    // Important change in libp2p-v0.52 compared to v0.51:
                    //
                    // https://github.com/libp2p/rust-libp2p/releases/tag/libp2p-v0.52.0
                    //
                    // As a consequence, the observed address reported by identify is no longer
                    // considered an external address but just an address candidate.
                    //
                    // https://github.com/libp2p/rust-libp2p/blob/master/protocols/identify/CHANGELOG.md#0430
                    //
                    // Observed addresses (aka. external address candidates) of the local node, reported by a remote node via libp2p-identify,
                    // are no longer automatically considered confirmed external addresses, in other words they are no longer trusted by default.
                    // Instead users need to confirm the reported observed address either manually, or by using libp2p-autonat.
                    // In trusted environments users can simply extract observed addresses from a
                    // libp2p-identify::Event::Received { info: libp2p_identify::Info { observed_addr }} and confirm them via Swarm::add_external_address.

                    self.swarm.add_external_address(observed_addr);

                    if protocols
                        .iter()
                        .any(|p| p.as_ref() == behaviour::kademlia_protocol_name(self.chain_id))
                    {
                        for addr in &listen_addrs {
                            self.swarm
                                .behaviour_mut()
                                .kademlia_mut()
                                .add_address(&peer_id, addr.clone());
                        }

                        if listen_addrs.is_empty() {
                            tracing::warn!(%peer_id, "Failed to add peer to DHT, no listening addresses");
                        } else {
                            tracing::debug!(%peer_id, "Added peer to DHT");
                        }
                    }
                }
            }
            // ===========================
            // Pings
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Ping(event)) => {
                self.swarm.behaviour_mut().pinged(event);
            }
            // ===========================
            // Block propagation
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Gossipsub(gossipsub::Event::Message {
                propagation_source: peer_id,
                message_id: id,
                message,
            })) => {
                use prost::Message;

                match p2p_proto::proto::block::NewBlock::decode(message.data.as_ref()) {
                    Ok(new_block) => {
                        match p2p_proto::block::NewBlock::try_from_protobuf(new_block, "message") {
                            Ok(new_block) => {
                                tracing::trace!(
                                    "Gossipsub Message: [id={}][peer={}] {:?} ({} bytes)",
                                    id,
                                    peer_id,
                                    new_block,
                                    message.data.len()
                                );
                                self.event_sender
                                    .send(Event::BlockPropagation {
                                        from: peer_id,
                                        new_block,
                                    })
                                    .await
                                    .expect("Event receiver not to be dropped");
                            }
                            Err(error) => {
                                tracing::error!(from=%peer_id, %error, "Gossipsub Message")
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(from=%peer_id, %error, "Gossipsub Message");
                    }
                };
            }
            // ===========================
            // Discovery
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Kademlia(e)) => match e {
                kad::Event::OutboundQueryProgressed {
                    step, result, id, ..
                } => {
                    if step.last {
                        match result {
                            libp2p::kad::QueryResult::Bootstrap(result) => {
                                let network_info = self.swarm.network_info();
                                let num_peers = network_info.num_peers();
                                let connection_counters = network_info.connection_counters();
                                let num_connections = connection_counters.num_connections();

                                let result = match result {
                                    Ok(BootstrapOk { peer, .. }) => {
                                        tracing::debug!(%num_peers, %num_connections, "Periodic bootstrap completed");
                                        Ok(peer)
                                    }
                                    Err(BootstrapError::Timeout { peer, .. }) => {
                                        tracing::warn!(%num_peers, %num_connections, "Periodic bootstrap failed");
                                        Err(peer)
                                    }
                                };
                                self.ongoing_bootstrap = None;
                                send_test_event(
                                    &self.event_sender,
                                    TestEvent::KademliaBootstrapCompleted(result),
                                )
                                .await;
                            }
                            QueryResult::GetProviders(result) => {
                                use libp2p::kad::GetProvidersOk;

                                let result = match result {
                                    Ok(GetProvidersOk::FoundProviders { providers, .. }) => {
                                        Ok(providers)
                                    }
                                    Ok(GetProvidersOk::FinishedWithNoAdditionalRecord {
                                        ..
                                    }) => Ok(Default::default()),
                                    Err(e) => Err(e.into()),
                                };

                                let sender = self
                                    .pending_queries
                                    .get_providers
                                    .remove(&id)
                                    .expect("Query to be pending");

                                sender
                                    .send(result)
                                    .await
                                    .expect("Receiver not to be dropped");
                            }
                            _ => self.test_query_completed(id, result).await,
                        }
                    } else if let QueryResult::GetProviders(result) = result {
                        use libp2p::kad::GetProvidersOk;

                        let result = match result {
                            Ok(GetProvidersOk::FoundProviders { providers, .. }) => Ok(providers),
                            Ok(_) => Ok(Default::default()),
                            Err(_) => {
                                unreachable!(
                                    "when a query times out libp2p makes it the last stage"
                                )
                            }
                        };

                        let sender = self
                            .pending_queries
                            .get_providers
                            .get(&id)
                            .expect("Query to be pending");

                        sender
                            .send(result)
                            .await
                            .expect("Receiver not to be dropped");
                    } else {
                        self.test_query_progressed(id, result).await;
                    }
                }
                kad::Event::RoutingUpdated {
                    peer, is_new_peer, ..
                } => {
                    if is_new_peer {
                        send_test_event(
                            &self.event_sender,
                            TestEvent::PeerAddedToDHT { remote: peer },
                        )
                        .await
                    }
                }
                _ => {}
            },
            // ===========================
            // Block sync
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::HeadersSync(
                p2p_stream::Event::InboundRequest {
                    request_id,
                    request,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(?request, %peer, %request_id, "Received sync request");

                self.event_sender
                    .send(Event::InboundHeadersSyncRequest {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            SwarmEvent::Behaviour(behaviour::Event::HeadersSync(
                p2p_stream::Event::OutboundRequestSentAwaitingResponses {
                    request_id,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(%peer, %request_id, "Sync request sent");

                let _ = self
                    .pending_sync_requests
                    .headers
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Ok(channel));
            }
            SwarmEvent::Behaviour(behaviour::Event::BodiesSync(
                p2p_stream::Event::InboundRequest {
                    request_id,
                    request,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(?request, %peer, %request_id, "Received sync request");

                self.event_sender
                    .send(Event::InboundBodiesSyncRequest {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            SwarmEvent::Behaviour(behaviour::Event::BodiesSync(
                p2p_stream::Event::OutboundRequestSentAwaitingResponses {
                    request_id,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(%peer, %request_id, "Sync request sent");

                let _ = self
                    .pending_sync_requests
                    .bodies
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Ok(channel));
            }
            SwarmEvent::Behaviour(behaviour::Event::TransactionsSync(
                p2p_stream::Event::InboundRequest {
                    request_id,
                    request,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(?request, %peer, %request_id, "Received sync request");

                self.event_sender
                    .send(Event::InboundTransactionsSyncRequest {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            SwarmEvent::Behaviour(behaviour::Event::TransactionsSync(
                p2p_stream::Event::OutboundRequestSentAwaitingResponses {
                    request_id,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(%peer, %request_id, "Sync request sent");

                let _ = self
                    .pending_sync_requests
                    .transactions
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Ok(channel));
            }
            SwarmEvent::Behaviour(behaviour::Event::ReceiptsSync(
                p2p_stream::Event::InboundRequest {
                    request_id,
                    request,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(?request, %peer, %request_id, "Received sync request");

                self.event_sender
                    .send(Event::InboundReceiptsSyncRequest {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            SwarmEvent::Behaviour(behaviour::Event::ReceiptsSync(
                p2p_stream::Event::OutboundRequestSentAwaitingResponses {
                    request_id,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(%peer, %request_id, "Sync request sent");

                let _ = self
                    .pending_sync_requests
                    .receipts
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Ok(channel));
            }
            SwarmEvent::Behaviour(behaviour::Event::EventsSync(
                p2p_stream::Event::InboundRequest {
                    request_id,
                    request,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(?request, %peer, %request_id, "Received sync request");

                self.event_sender
                    .send(Event::InboundEventsSyncRequest {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            SwarmEvent::Behaviour(behaviour::Event::EventsSync(
                p2p_stream::Event::OutboundRequestSentAwaitingResponses {
                    request_id,
                    peer,
                    channel,
                },
            )) => {
                tracing::debug!(%peer, %request_id, "Sync request sent");

                let _ = self
                    .pending_sync_requests
                    .events
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Ok(channel));
            }
            SwarmEvent::Behaviour(behaviour::Event::HeadersSync(
                p2p_stream::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!(?request_id, ?error, "Outbound request failed");
                let _ = self
                    .pending_sync_requests
                    .headers
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Err(error.into()));
            }
            SwarmEvent::Behaviour(behaviour::Event::BodiesSync(
                p2p_stream::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!(?request_id, ?error, "Outbound request failed");
                let _ = self
                    .pending_sync_requests
                    .bodies
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Err(error.into()));
            }
            SwarmEvent::Behaviour(behaviour::Event::TransactionsSync(
                p2p_stream::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!(?request_id, ?error, "Outbound request failed");
                let _ = self
                    .pending_sync_requests
                    .transactions
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Err(error.into()));
            }
            SwarmEvent::Behaviour(behaviour::Event::ReceiptsSync(
                p2p_stream::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!(?request_id, ?error, "Outbound request failed");
                let _ = self
                    .pending_sync_requests
                    .receipts
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Err(error.into()));
            }
            SwarmEvent::Behaviour(behaviour::Event::EventsSync(
                p2p_stream::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!(?request_id, ?error, "Outbound request failed");
                let _ = self
                    .pending_sync_requests
                    .events
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Err(error.into()));
            }
            // ===========================
            // NAT hole punching
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Dcutr(event)) => {
                tracing::debug!(?event, "DCUtR event");
            }
            // ===========================
            // Ignored or forwarded for
            // test purposes
            // ===========================
            event => {
                match &event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let my_peerid = *self.swarm.local_peer_id();
                        let address = address.clone().with(Protocol::P2p(my_peerid));

                        tracing::debug!(%address, "New listen");
                    }
                    _ => tracing::trace!(?event, "Ignoring event"),
                }
                self.handle_event_for_test(event).await;
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::StarListening { addr, sender } => {
                let _ = match self.swarm.listen_on(addr.clone()) {
                    Ok(_) => {
                        tracing::debug!(%addr, "Started listening");
                        sender.send(Ok(()))
                    }
                    Err(e) => sender.send(Err(e.into())),
                };
            }
            Command::Dial {
                peer_id,
                addr,
                sender,
            } => {
                if let std::collections::hash_map::Entry::Vacant(e) =
                    self.pending_dials.entry(peer_id)
                {
                    self.swarm
                        .behaviour_mut()
                        .kademlia_mut()
                        .add_address(&peer_id, addr.clone());
                    match self.swarm.dial(
                        // Dial a known peer with a given address only if it's not connected yet
                        // and we haven't started dialing yet.
                        DialOpts::peer_id(peer_id)
                            .addresses(vec![addr.clone()])
                            .build(),
                    ) {
                        Ok(_) => {
                            tracing::debug!(%addr, "Dialed peer");
                            e.insert(sender);
                        }
                        Err(e) => {
                            let _ = sender.send(Err(e.into()));
                        }
                    };
                } else {
                    let _ = sender.send(Err(anyhow::anyhow!("Dialing is already pending")));
                }
            }
            Command::Disconnect { peer_id, sender } => {
                let _ = sender.send(self.disconnect(peer_id).await);
            }
            Command::ProvideCapability { capability, sender } => {
                let _ = match self.swarm.behaviour_mut().provide_capability(&capability) {
                    Ok(_) => {
                        tracing::debug!(%capability, "Providing capability");
                        sender.send(Ok(()))
                    }
                    Err(e) => sender.send(Err(e)),
                };
            }
            Command::GetCapabilityProviders { capability, sender } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .get_capability_providers(&capability);
                self.pending_queries.get_providers.insert(query_id, sender);
            }
            Command::SubscribeTopic { topic, sender } => {
                let _ = match self.swarm.behaviour_mut().subscribe_topic(&topic) {
                    Ok(_) => {
                        tracing::debug!(%topic, "Subscribing to topic");
                        sender.send(Ok(()))
                    }
                    Err(e) => sender.send(Err(e)),
                };
            }
            Command::SendHeadersSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending sync request");

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .headers_sync_mut()
                    .send_request(&peer_id, request);
                self.pending_sync_requests
                    .headers
                    .insert(request_id, sender);
            }
            Command::SendBodiesSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending sync request");

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .bodies_sync_mut()
                    .send_request(&peer_id, request);
                self.pending_sync_requests.bodies.insert(request_id, sender);
            }
            Command::SendTransactionsSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending sync request");

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .transactions_sync_mut()
                    .send_request(&peer_id, request);
                self.pending_sync_requests
                    .transactions
                    .insert(request_id, sender);
            }
            Command::SendReceiptsSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending sync request");

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .receipts_sync_mut()
                    .send_request(&peer_id, request);
                self.pending_sync_requests
                    .receipts
                    .insert(request_id, sender);
            }
            Command::SendEventsSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending sync request");

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .events_sync_mut()
                    .send_request(&peer_id, request);
                self.pending_sync_requests.events.insert(request_id, sender);
            }
            Command::PublishPropagationMessage {
                topic,
                new_block,
                sender,
            } => {
                use prost::Message;
                let data: Vec<u8> = new_block.to_protobuf().encode_to_vec();
                let result = self.publish_data(topic, &data);
                let _ = sender.send(result);
            }
            Command::NotUseful { peer_id, sender } => {
                self.swarm.behaviour_mut().not_useful(peer_id);
                let _ = sender.send(());
            }
            Command::_Test(command) => self.handle_test_command(command).await,
        };
    }

    fn publish_data(&mut self, topic: IdentTopic, data: &[u8]) -> anyhow::Result<()> {
        let message_id = self
            .swarm
            .behaviour_mut()
            .gossipsub_mut()
            .publish(topic, data)
            .map_err(|e| anyhow::anyhow!("Gossipsub publish failed: {}", e))?;
        tracing::debug!(?message_id, "Data published");
        Ok(())
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> anyhow::Result<()> {
        self.pending_dials.remove(&peer_id);
        match self.swarm.disconnect_peer_id(peer_id) {
            Ok(()) => {
                tracing::debug!(%peer_id, "Disconnected");
                Ok(())
            }
            Err(()) => Err(anyhow::anyhow!("Failed to disconnect: peer not connected")),
        }
    }

    /// No-op outside tests
    async fn handle_event_for_test(&mut self, _event: SwarmEvent<behaviour::Event>) {
        #[cfg(test)]
        test_utils::handle_event(&self.event_sender, _event).await
    }

    /// No-op outside tests
    async fn handle_test_command(&mut self, _command: TestCommand) {
        #[cfg(test)]
        test_utils::handle_command(
            self.swarm.behaviour_mut(),
            _command,
            &mut self._pending_test_queries.inner,
        )
        .await;
    }

    /// Handle the final stage of the query, no-op outside tests
    async fn test_query_completed(&mut self, _id: QueryId, _result: QueryResult) {
        #[cfg(test)]
        test_utils::query_completed(
            &mut self._pending_test_queries.inner,
            &self.event_sender,
            _id,
            _result,
        )
        .await;
    }

    /// Handle all stages except the final one, no-op outside tests
    async fn test_query_progressed(&mut self, _id: QueryId, _result: QueryResult) {
        #[cfg(test)]
        test_utils::query_progressed(&self._pending_test_queries.inner, _id, _result).await
    }
}

/// No-op outside tests
async fn send_test_event(_event_sender: &mpsc::Sender<Event>, _event: TestEvent) {
    #[cfg(test)]
    test_utils::send_event(_event_sender, _event).await
}

#[derive(Debug, Default)]
struct TestQueries {
    #[cfg(test)]
    inner: test_utils::PendingQueries,
}
