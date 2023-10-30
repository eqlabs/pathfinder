use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;

use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::kad::{BootstrapError, BootstrapOk, KademliaEvent, QueryId, QueryResult};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, RequestId};
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, PeerId};
use p2p_proto_v1::block::{BlockBodiesResponseList, BlockHeadersResponse};
use p2p_proto_v1::event::EventsResponseList;
use p2p_proto_v1::receipt::ReceiptsResponseList;
use p2p_proto_v1::transaction::TransactionsResponseList;
use p2p_proto_v1::{ToProtobuf, TryFromProtobuf};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::Duration;

use crate::behaviour;
use crate::peers;
#[cfg(test)]
use crate::test_utils;
use crate::{
    BootstrapConfig, Command, EmptyResultSender, Event, PeriodicTaskConfig, TestCommand, TestEvent,
};

pub struct MainLoop {
    bootstrap_cfg: BootstrapConfig,
    swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<Event>,
    peers: Arc<RwLock<peers::Peers>>,
    pending_dials: HashMap<PeerId, EmptyResultSender>,
    pending_sync_requests: PendingRequests,
    // TODO there's no sync status message anymore so we have to:
    // 1. use keep alive to keep connections open
    // 2. update the sync head info of our peers using a different mechanism
    // request_sync_status: HashSetDelay<PeerId>,
    pending_queries: PendingQueries,
    _pending_test_queries: TestQueries,
}

#[derive(Debug, Default)]
struct PendingRequests {
    pub headers: HashMap<RequestId, oneshot::Sender<anyhow::Result<BlockHeadersResponse>>>,
    pub bodies: HashMap<RequestId, oneshot::Sender<anyhow::Result<BlockBodiesResponseList>>>,
    pub transactions: HashMap<RequestId, oneshot::Sender<anyhow::Result<TransactionsResponseList>>>,
    pub receipts: HashMap<RequestId, oneshot::Sender<anyhow::Result<ReceiptsResponseList>>>,
    pub events: HashMap<RequestId, oneshot::Sender<anyhow::Result<EventsResponseList>>>,
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
        peers: Arc<RwLock<peers::Peers>>,
        periodic_cfg: PeriodicTaskConfig,
    ) -> Self {
        Self {
            bootstrap_cfg: periodic_cfg.bootstrap,
            swarm,
            command_receiver,
            event_sender,
            peers,
            pending_dials: Default::default(),
            pending_sync_requests: Default::default(),
            pending_queries: Default::default(),
            _pending_test_queries: Default::default(),
        }
    }

    pub async fn run(mut self) {
        // Delay bootstrap so that by the time we attempt it we've connected to the bootstrap node
        let bootstrap_start = tokio::time::Instant::now() + self.bootstrap_cfg.start_offset;
        let mut bootstrap_interval =
            tokio::time::interval_at(bootstrap_start, self.bootstrap_cfg.period);

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
                    let dht = self.swarm.behaviour_mut().kademlia
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
                    let guard = self.peers.read().await;
                    let connected = guard.connected().collect::<Vec<_>>();

                    tracing::info!(
                        "Peer status: me {}, connected {:?}, dht {:?}",
                        me,
                        connected,
                        dht,
                    );
                }
                _ = bootstrap_interval_tick => {
                    tracing::debug!("Doing periodical bootstrap");
                    _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                }
                command = self.command_receiver.recv() => {
                    match command {
                        Some(c) => self.handle_command(c).await,
                        None => return,
                    }
                }
                Some(event) = self.swarm.next() => {
                    if let Err(e) = self.handle_event(event).await {
                        tracing::error!("event handling failed: {}", e);
                    }
                },
            }
        }
    }

    async fn handle_event<E: std::fmt::Debug>(
        &mut self,
        event: SwarmEvent<behaviour::Event, E>,
    ) -> anyhow::Result<()> {
        match event {
            // ===========================
            // Connection management
            // ===========================
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.peers.write().await.peer_connected(&peer_id);

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

                Ok(())
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                if let Some(peer_id) = peer_id {
                    self.peers.write().await.peer_dial_error(&peer_id);

                    tracing::debug!(%peer_id, %error, "Error while dialing peer");

                    if let Some(sender) = self.pending_dials.remove(&peer_id) {
                        let _ = sender.send(Err(error.into()));
                    }
                }
                Ok(())
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    self.peers.write().await.peer_disconnected(&peer_id);
                    tracing::debug!(%peer_id, "Fully disconnected from");
                } else {
                    tracing::debug!(%peer_id, other_connections_for_this_peer=%num_established, "Connection closed");
                }
                Ok(())
            }
            SwarmEvent::Dialing(peer_id) => {
                self.peers.write().await.peer_dialing(&peer_id);
                tracing::debug!(%peer_id, "Dialing peer");
                Ok(())
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
                            ..
                        },
                } = *e
                {
                    if protocols
                        .iter()
                        .any(|p| p.as_bytes() == behaviour::KADEMLIA_PROTOCOL_NAME)
                    {
                        for addr in &listen_addrs {
                            self.swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, addr.clone());
                        }

                        if listen_addrs.is_empty() {
                            tracing::warn!(%peer_id, "Failed to add peer to DHT, no listening addresses");
                        } else {
                            tracing::debug!(%peer_id, "Added peer to DHT");
                        }
                    }
                }
                Ok(())
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

                match p2p_proto_v1::proto::block::NewBlock::decode(message.data.as_ref()) {
                    Ok(new_block) => {
                        match p2p_proto_v1::block::NewBlock::try_from_protobuf(new_block, "message")
                        {
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
                                    .await?;
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
                Ok(())
            }
            // ===========================
            // Discovery
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Kademlia(e)) => {
                match e {
                    KademliaEvent::OutboundQueryProgressed {
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
                                    send_test_event(
                                        &self.event_sender,
                                        TestEvent::PeriodicBootstrapCompleted(result),
                                    )
                                    .await;
                                }
                                QueryResult::GetProviders(result) => {
                                    use libp2p::kad::GetProvidersOk;

                                    let result = match result {
                                        Ok(GetProvidersOk::FoundProviders {
                                            providers, ..
                                        }) => Ok(providers),
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
                                Ok(GetProvidersOk::FoundProviders { providers, .. }) => {
                                    Ok(providers)
                                }
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
                    KademliaEvent::RoutingUpdated {
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
                }

                Ok(())
            }
            // ===========================
            // Block sync
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::HeadersSync(
                request_response::Event::Message { message, peer },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    tracing::debug!(?request, %peer, "Received sync request");

                    self.event_sender
                        .send(Event::InboundHeadersSyncRequest {
                            from: peer,
                            request,
                            channel,
                        })
                        .await
                        .expect("Event receiver not to be dropped");

                    Ok(())
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let _ = self
                        .pending_sync_requests
                        .headers
                        .remove(&request_id)
                        .expect("Block sync request still to be pending")
                        .send(Ok(response));
                    Ok(())
                }
            },
            SwarmEvent::Behaviour(behaviour::Event::BodiesSync(
                request_response::Event::Message { message, peer },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    tracing::debug!(?request, %peer, "Received sync request");

                    self.event_sender
                        .send(Event::InboundBodiesSyncRequest {
                            from: peer,
                            request,
                            channel,
                        })
                        .await
                        .expect("Event receiver not to be dropped");

                    Ok(())
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let _ = self
                        .pending_sync_requests
                        .bodies
                        .remove(&request_id)
                        .expect("Block sync request still to be pending")
                        .send(Ok(response));
                    Ok(())
                }
            },
            SwarmEvent::Behaviour(behaviour::Event::TransactionsSync(
                request_response::Event::Message { message, peer },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    tracing::debug!(?request, %peer, "Received sync request");

                    self.event_sender
                        .send(Event::InboundTransactionsSyncRequest {
                            from: peer,
                            request,
                            channel,
                        })
                        .await
                        .expect("Event receiver not to be dropped");

                    Ok(())
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let _ = self
                        .pending_sync_requests
                        .transactions
                        .remove(&request_id)
                        .expect("Block sync request still to be pending")
                        .send(Ok(response));
                    Ok(())
                }
            },
            SwarmEvent::Behaviour(behaviour::Event::ReceiptsSync(
                request_response::Event::Message { message, peer },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    tracing::debug!(?request, %peer, "Received sync request");

                    self.event_sender
                        .send(Event::InboundReceiptsSyncRequest {
                            from: peer,
                            request,
                            channel,
                        })
                        .await
                        .expect("Event receiver not to be dropped");

                    Ok(())
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let _ = self
                        .pending_sync_requests
                        .receipts
                        .remove(&request_id)
                        .expect("Block sync request still to be pending")
                        .send(Ok(response));
                    Ok(())
                }
            },
            SwarmEvent::Behaviour(behaviour::Event::EventsSync(
                request_response::Event::Message { message, peer },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    tracing::debug!(?request, %peer, "Received sync request");

                    self.event_sender
                        .send(Event::InboundEventsSyncRequest {
                            from: peer,
                            request,
                            channel,
                        })
                        .await
                        .expect("Event receiver not to be dropped");

                    Ok(())
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let _ = self
                        .pending_sync_requests
                        .events
                        .remove(&request_id)
                        .expect("Block sync request still to be pending")
                        .send(Ok(response));
                    Ok(())
                }
            },
            SwarmEvent::Behaviour(behaviour::Event::HeadersSync(
                request_response::Event::OutboundFailure {
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
                Ok(())
            }
            SwarmEvent::Behaviour(behaviour::Event::BodiesSync(
                request_response::Event::OutboundFailure {
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
                Ok(())
            }
            SwarmEvent::Behaviour(behaviour::Event::TransactionsSync(
                request_response::Event::OutboundFailure {
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
                Ok(())
            }
            SwarmEvent::Behaviour(behaviour::Event::ReceiptsSync(
                request_response::Event::OutboundFailure {
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
                Ok(())
            }
            SwarmEvent::Behaviour(behaviour::Event::EventsSync(
                request_response::Event::OutboundFailure {
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
                Ok(())
            }
            // ===========================
            // NAT hole punching
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Dcutr(event)) => {
                tracing::debug!(?event, "DCUtR event");
                Ok(())
            }
            // ===========================
            // Ignored or forwarded for
            // test purposes
            // ===========================
            event => {
                match &event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let my_peerid = *self.swarm.local_peer_id();
                        let address = address.clone().with(Protocol::P2p(my_peerid.into()));

                        tracing::debug!(%address, "New listen");
                    }
                    _ => tracing::trace!(?event, "Ignoring event"),
                }
                self.handle_event_for_test(event).await;
                Ok(())
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
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    match self.swarm.dial(addr.clone()) {
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
                    .headers_sync
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
                    .bodies_sync
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
                    .transactions_sync
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
                    .receipts_sync
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
                    .events_sync
                    .send_request(&peer_id, request);
                self.pending_sync_requests.events.insert(request_id, sender);
            }
            // All Send*SyncResponse: In case of failure a RequestResponseEvent::InboundFailure will or has been be emitted.
            Command::SendHeadersSyncResponse { channel, response } => {
                tracing::debug!(%response, "Sending sync response");

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .headers_sync
                    .send_response(channel, response);
            }
            Command::SendBodiesSyncResponse { channel, response } => {
                tracing::debug!(%response, "Sending sync response");

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .bodies_sync
                    .send_response(channel, response);
            }
            Command::SendTransactionsSyncResponse { channel, response } => {
                tracing::debug!(%response, "Sending sync response");

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .transactions_sync
                    .send_response(channel, response);
            }
            Command::SendReceiptsSyncResponse { channel, response } => {
                tracing::debug!(%response, "Sending sync response");

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .receipts_sync
                    .send_response(channel, response);
            }
            Command::SendEventsSyncResponse { channel, response } => {
                tracing::debug!(%response, "Sending sync response");

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .events_sync
                    .send_response(channel, response);
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
            Command::_Test(command) => self.handle_test_command(command).await,
        };
    }

    fn publish_data(&mut self, topic: IdentTopic, data: &[u8]) -> anyhow::Result<()> {
        let message_id = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, data)
            .map_err(|e| anyhow::anyhow!("Gossipsub publish failed: {}", e))?;
        tracing::debug!(?message_id, "Data published");
        Ok(())
    }

    /// No-op outside tests
    async fn handle_event_for_test<E: std::fmt::Debug>(
        &mut self,
        _event: SwarmEvent<behaviour::Event, E>,
    ) {
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
