use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::{cmp, task};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::ConnectionEstablished;
use libp2p::swarm::{
    ConnectionClosed,
    ConnectionDenied,
    ConnectionId,
    DialFailure,
    FromSwarm,
    NetworkBehaviour,
    THandler,
    THandlerInEvent,
    THandlerOutEvent,
    ToSwarm,
};
use libp2p::{autonat, dcutr, identify, identity, ping, relay, Multiaddr, PeerId, StreamProtocol};
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::ChainId;

mod builder;

pub use builder::Builder;

use crate::peers::{Connectivity, Direction, KeyedNetworkGroup, Peer, PeerSet};
use crate::secret::Secret;
use crate::sync::codec;
use crate::Config;

/// The default kademlia protocol name for a given Starknet chain.
pub fn kademlia_protocol_name(chain_id: ChainId) -> StreamProtocol {
    StreamProtocol::try_from_owned(format!("/starknet/kad/{}/1.0.0", chain_id.as_str()))
        .expect("Starts with /")
}

pub type BehaviourWithRelayTransport = (Behaviour, relay::client::Transport);

pub struct Behaviour {
    cfg: Config,
    peers: PeerSet,
    swarm: crate::Client,
    secret: Secret,
    inner: Inner,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event", event_process = false)]
pub struct Inner {
    relay: relay::client::Behaviour,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    header_sync: p2p_stream::Behaviour<codec::Headers>,
    class_sync: p2p_stream::Behaviour<codec::Classes>,
    state_diff_sync: p2p_stream::Behaviour<codec::StateDiffs>,
    transaction_sync: p2p_stream::Behaviour<codec::Transactions>,
    event_sync: p2p_stream::Behaviour<codec::Events>,
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = <Inner as NetworkBehaviour>::ToSwarm;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Disconnect peers without an IP address.
        Self::get_ip(remote_addr)?;

        self.check_duplicate_connection(peer)?;
        self.prevent_evicted_peer_reconnections(peer)?;

        // Is the peer connecting over a relay?
        let is_relayed = remote_addr.iter().any(|p| p == Protocol::P2pCircuit);

        // Limit the number of inbound peer connections. Different limits apply to
        // direct peers and peers connecting over a relay.
        if is_relayed {
            if self.inbound_relayed_peers().count() >= self.cfg.max_inbound_relayed_peers {
                self.evict_inbound_peer(
                    self.inbound_relayed_peers()
                        .map(|(peer_id, peer)| (peer_id, peer.clone()))
                        .collect(),
                )?;
            }
        } else if self.inbound_direct_peers().count() >= self.cfg.max_inbound_direct_peers {
            self.evict_inbound_peer(
                self.inbound_direct_peers()
                    .map(|(peer_id, peer)| (peer_id, peer.clone()))
                    .collect(),
            )?;
        }

        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Disconnect peers without an IP address.
        Self::get_ip(addr)?;

        self.check_duplicate_connection(peer)?;
        self.prevent_evicted_peer_reconnections(peer)?;

        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id, endpoint, ..
            }) => {
                let direction = if endpoint.is_dialer() {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                };

                // Disconnect peers without an IP address.
                let Ok(peer_ip) = Self::get_ip(endpoint.get_remote_address()) else {
                    tracing::debug!(%peer_id, "Peer has no IP address, disconnecting");
                    self.peers.upsert(
                        peer_id,
                        |peer| {
                            peer.connectivity = Connectivity::Disconnecting {
                                connected_at: Some(Instant::now()),
                            };
                        },
                        || Peer {
                            connectivity: Connectivity::Disconnecting {
                                connected_at: Some(Instant::now()),
                            },
                            direction,
                            addr: None,
                            keyed_network_group: None,
                            min_ping: None,
                            evicted: false,
                            useful: true,
                        },
                    );
                    let swarm = self.swarm.clone();
                    tokio::spawn(async move {
                        if let Err(err) = swarm.disconnect(peer_id).await {
                            tracing::debug!(%peer_id, %err, "Failed to disconnect peer");
                        }
                    });
                    return;
                };

                self.peers.upsert(
                    peer_id,
                    |peer| {
                        peer.connectivity = Connectivity::Connected {
                            connected_at: Instant::now(),
                        };
                        peer.addr = Some(endpoint.get_remote_address().clone());
                        peer.keyed_network_group =
                            Some(KeyedNetworkGroup::new(&self.secret, peer_ip));
                    },
                    || Peer {
                        connectivity: Connectivity::Connected {
                            connected_at: Instant::now(),
                        },
                        direction,
                        addr: Some(endpoint.get_remote_address().clone()),
                        keyed_network_group: Some(KeyedNetworkGroup::new(&self.secret, peer_ip)),
                        min_ping: None,
                        evicted: false,
                        useful: true,
                    },
                );
            }
            FromSwarm::DialFailure(DialFailure { peer_id, error, .. }) => {
                if let Some(peer_id) = peer_id {
                    self.peers.upsert(
                        peer_id,
                        |peer| {
                            if !peer.is_connected() {
                                // If there was no successful connection when the dialing failed,
                                // then the peer is definitely not connected. Otherwise, this might
                                // have been a redial attempt, and the peer might still be
                                // connected.
                                peer.connectivity = Connectivity::Disconnected {
                                    connected_at: None,
                                    disconnected_at: Instant::now(),
                                };
                            };
                        },
                        || Peer {
                            connectivity: Connectivity::Disconnected {
                                connected_at: None,
                                disconnected_at: Instant::now(),
                            },
                            direction: Direction::Outbound,
                            min_ping: None,
                            addr: None,
                            keyed_network_group: None,
                            evicted: false,
                            useful: true,
                        },
                    );
                }
                tracing::debug!(?peer_id, %error, "Error while dialing peer");
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                remaining_established,
                ..
            }) => {
                if remaining_established == 0 {
                    self.peers.update(peer_id, |peer| {
                        peer.connectivity = Connectivity::Disconnected {
                            connected_at: peer.connected_at(),
                            disconnected_at: Instant::now(),
                        };
                    });
                    tracing::debug!(%peer_id, "Fully disconnected from");
                } else {
                    tracing::debug!(%peer_id, %remaining_established, "Connection closed");
                }
            }
            _ => {}
        }

        self.inner.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event)
    }

    fn poll(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // Apply rate limiting to inbound connections.
        let rate_limit_interval =
            Instant::now() - self.cfg.inbound_connections_rate_limit.interval..Instant::now();
        let num_connected = self
            .peers()
            .filter(|(_, peer)| peer.is_inbound())
            .filter_map(|(_, peer)| peer.connected_at())
            .filter(|t| rate_limit_interval.contains(t))
            .count();
        if num_connected >= self.cfg.inbound_connections_rate_limit.max {
            tracing::debug!(%connection_id, %remote_addr, "Too many inbound connections, closing");
            return Err(ConnectionDenied::new("too many inbound connections"));
        }

        // Extract the peer IP from the multiaddr, or disconnect the peer if he doesn't
        // have one.
        let peer_ip = Self::get_ip(remote_addr)?;

        // If the peer is not in the IP whitelist, disconnect.
        if !self
            .cfg
            .ip_whitelist
            .iter()
            .any(|net| net.contains(&peer_ip))
        {
            tracing::debug!(%peer_ip, %connection_id, "Peer not in IP whitelist, disconnecting");
            return Err(ConnectionDenied::new("peer not in IP whitelist"));
        }

        // Is the peer connecting over a relay?
        let is_relayed = remote_addr.iter().any(|p| p == Protocol::P2pCircuit);

        // Prevent the peer from reconnecting too quickly.

        // Get the list of IP addresses of recently connected inbound peers.
        let mut recent_peers = self.peers().filter_map(|(_, peer)| {
            if !peer.is_inbound() {
                return None;
            }
            peer.connected_at().and_then(|connected_at| {
                // If the connecting peer is relayed, only consider relayed peers for the recent
                // peers set. Otherwise, only consider direct peers. Different connection
                // timeouts apply to direct and relayed peers.
                if is_relayed {
                    if !peer.is_relayed()
                        || connected_at.elapsed() >= self.cfg.relay_connection_timeout
                    {
                        return None;
                    }
                } else if peer.is_relayed()
                    || connected_at.elapsed() >= self.cfg.direct_connection_timeout
                {
                    return None;
                }
                peer.ip_addr()
            })
        });

        // If the peer IP is in the recent peers set, this means he is attempting to
        // reconnect too quickly. Close the connection.
        if recent_peers.any(|ip| ip == peer_ip) {
            tracing::debug!(%connection_id, "Peer attempted to reconnect too quickly, closing");
            return Err(ConnectionDenied::new("reconnect too quickly"));
        }

        // Attempt to extract peer ID from the multiaddr.
        let peer_id = remote_addr.iter().find_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        });

        // If we can extract the peer ID, prevent evicted peers from reconnecting too
        // quickly.
        if let Some(peer_id) = peer_id {
            self.prevent_evicted_peer_reconnections(peer_id)?;
        }

        drop(recent_peers);

        // Limit the number of inbound peer connections. Different limits apply to
        // direct peers and peers connecting over a relay.
        //
        // This same check happens when the connection is established, but we are also
        // checking here because it allows us to avoid potentially expensive
        // protocol negotiation with the peer if there are already too many
        // inbound connections.
        //
        // The check must be repeated when the connection is established due to race
        // conditions, since multiple peers may be attempting to connect at the
        // same time.
        if is_relayed {
            if self.inbound_relayed_peers().count() >= self.cfg.max_inbound_relayed_peers {
                self.evict_inbound_peer(
                    self.inbound_relayed_peers()
                        .map(|(peer_id, peer)| (peer_id, peer.clone()))
                        .collect(),
                )?;
            }
        } else if self.inbound_direct_peers().count() >= self.cfg.max_inbound_direct_peers {
            self.evict_inbound_peer(
                self.inbound_direct_peers()
                    .map(|(peer_id, peer)| (peer_id, peer.clone()))
                    .collect(),
            )?;
        }

        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(peer_id) = maybe_peer {
            if effective_role.is_dialer() {
                // This really is an outbound connection, and not a connection that requires
                // hole-punching.

                self.prevent_evicted_peer_reconnections(peer_id)?;

                if self.outbound_peers().count() >= self.cfg.max_outbound_peers {
                    self.evict_outbound_peer()?;
                }

                self.peers.upsert(
                    peer_id,
                    |peer| {
                        if !peer.is_connected() {
                            peer.connectivity = Connectivity::Dialing;
                        } else {
                            // If peer is already connected, this is a redial.
                            // The peer is still
                            // connected.
                        }
                    },
                    || Peer {
                        connectivity: Connectivity::Dialing,
                        direction: Direction::Outbound,
                        addr: None,
                        keyed_network_group: None,
                        min_ping: None,
                        evicted: false,
                        useful: true,
                    },
                );
            }
        }
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }
}

impl Behaviour {
    pub fn builder(identity: identity::Keypair, chain_id: ChainId, cfg: Config) -> Builder {
        Builder::new(identity, chain_id, cfg)
    }

    pub fn provide_capability(&mut self, capability: &str) -> anyhow::Result<()> {
        let key = string_to_key(capability);
        self.inner.kademlia.start_providing(key)?;
        Ok(())
    }

    pub fn get_capability_providers(&mut self, capability: &str) -> kad::QueryId {
        let key = string_to_key(capability);
        self.inner.kademlia.get_providers(key)
    }

    pub fn get_closest_peers(&mut self, peer: PeerId) -> kad::QueryId {
        self.inner.kademlia.get_closest_peers(peer)
    }

    pub fn subscribe_topic(&mut self, topic: &IdentTopic) -> anyhow::Result<()> {
        self.inner.gossipsub.subscribe(topic)?;
        Ok(())
    }

    /// Notify the behaviour of a ping event.
    pub fn pinged(&mut self, event: ping::Event) {
        match event.result {
            Ok(duration) => {
                self.peers.update(event.peer, |peer| {
                    peer.min_ping = Some(match peer.min_ping {
                        Some(min_ping) => min_ping.min(duration),
                        None => duration,
                    });
                });
            }
            Err(err) => {
                tracing::debug!(%err, peer_id = %event.peer, "Ping failed");
            }
        }
    }

    /// Only allow one connection per peer. If the peer is already connected,
    /// close the new connection.
    fn check_duplicate_connection(&mut self, peer_id: PeerId) -> Result<(), ConnectionDenied> {
        if self
            .peers
            .get(peer_id)
            .map_or(false, |peer| peer.is_connected())
        {
            tracing::debug!(%peer_id, "Peer already connected, closing");
            return Err(ConnectionDenied::new("duplicate connection"));
        }
        Ok(())
    }

    /// Evict an outbound peer to make space for a new outbound connection.
    ///
    /// Only peers which are flagged as not useful are considered for eviction.
    /// If there are no such peers, the outgoing connection gets denied.
    fn evict_outbound_peer(&mut self) -> Result<(), ConnectionDenied> {
        let mut candidates: Vec<_> = self.outbound_peers().collect();

        // Only peers which are flagged as not useful are considered for eviction.
        candidates.retain(|(_, peer)| !peer.useful);

        // The peer to be evicted is the one with the highest SHA3(eviction_secret ||
        // peer_id) value. This is deterministic but unpredictable by any
        // outside observer.
        candidates.sort_by_key(|(peer_id, _)| {
            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::default();
            self.secret.hash_into(&mut hasher);
            hasher.update(peer_id.to_bytes());
            hasher.finalize()
        });
        let Some((peer_id, _)) = candidates.pop() else {
            tracing::debug!(
                "Outbound peer limit reached, but no peers could be evicted, disconnecting"
            );
            return Err(ConnectionDenied::new(
                "outbound peer limit reached and no peers could be evicted",
            ));
        };
        drop(candidates);

        // Disconnect the evicted peer.
        tracing::debug!(%peer_id, "Evicting outbound peer");
        self.peers.update(peer_id, |peer| {
            peer.connectivity = Connectivity::Disconnecting {
                connected_at: peer.connected_at(),
            };
            peer.evicted = true;
        });
        tokio::spawn({
            let swarm = self.swarm.clone();
            async move {
                if let Err(e) = swarm.disconnect(peer_id).await {
                    tracing::debug!(%peer_id, %e, "Failed to disconnect evicted peer");
                }
            }
        });

        Ok(())
    }

    /// Disconnect an inbound peer to make space for a new inbound connection.
    ///
    /// This method is written with the goal of not allowing an attacker to
    /// control which peers are evicted, so that the attacker cannot eclipse
    /// our node.
    ///
    /// If no peer can be evicted, the incoming connection gets denied.
    fn evict_inbound_peer(
        &mut self,
        mut candidates: HashMap<PeerId, Peer>,
    ) -> Result<(), ConnectionDenied> {
        // Group the peers by the keyed network group, and pick 4 groups
        // with the smallest value (which is deterministic, but unpredictable
        // by the attacker). Pick one peer from each group, and protect that
        // peer from eviction. For the attacker to circumvent this step, he
        // would need to be able to allocate very specific IPs, and he would
        // need to be able to predict which prefixes we are going to protect,
        // which is impossible. The goal is to ensure we are connected to a
        // diverse set of IP addresses.

        // Group the peers by keyed network group.
        let mut grouped = HashMap::<KeyedNetworkGroup, Vec<PeerId>>::new();
        for (&peer_id, peer) in candidates.iter() {
            grouped
                .entry(peer.keyed_network_group.expect("peer is connected"))
                .or_default()
                .push(peer_id);
        }
        let grouped = grouped;

        // Pick the peers to protect.
        let mut sorted: Vec<_> = grouped.iter().collect();
        sorted.sort_by_key(|&(group, _)| group);
        for (_, peers) in sorted.iter().take(4) {
            // Pick the peer with the smallest SHA3(eviction_secret || peer_id) value and
            // protect it from eviction. This is deterministic but unpredictable
            // by any outside observer.
            if let Some(peer_id) = peers.iter().min_by_key(|peer_id| {
                use sha3::{Digest, Sha3_256};
                let mut hasher = Sha3_256::default();
                self.secret.hash_into(&mut hasher);
                hasher.update(peer_id.to_bytes());
                hasher.finalize()
            }) {
                candidates.remove(peer_id);
            }
        }

        // Protect 8 peers with the lowest minimum ping time. To circumvent this
        // step, the attacker would have to be able to run nodes that are
        // geographically closer to us than these peers, which is difficult to do.
        let mut ping_times: Vec<_> = candidates
            .iter()
            .filter_map(|(&peer_id, peer)| peer.min_ping.map(|ping| (peer_id, ping)))
            .collect();
        ping_times.sort_by_key(|&(_, ping)| ping);
        for (peer_id, _) in ping_times.iter().take(8) {
            candidates.remove(peer_id);
        }

        // TODO #1754: Save 4 nodes that have most recently gossiped valid transactions,
        // and 8 nodes that have most recently gossiped a valid new head (or any
        // other block if we are still syncing).

        // Of the remaining nodes, protect half of them which have been connected
        // for the longest time.
        let mut connected_at: Vec<_> = candidates
            .iter()
            .map(|(&peer_id, peer)| (peer_id, peer.connected_at().expect("peer is connected")))
            .collect();
        connected_at.sort_by_key(|&(_, connected_at)| cmp::Reverse(connected_at));
        for (peer_id, _) in connected_at.iter().take(candidates.len() / 2) {
            candidates.remove(peer_id);
        }

        // Finally, evict the youngest peer in the most populous group.
        // This is achieved by sorting all the peers by a) total number
        // of connected peers which share their keyed network, breaking
        // ties with b) keyed network group (in reverse order, since we
        // use regular order in the first step of the eviction algorithm),
        // breaking ties with c) connection time. Evict the first peer
        // after sorting.
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        candidates.sort_by(|(_, a), (_, b)| {
            match grouped[&a.keyed_network_group.expect("peer is connected")]
                .len()
                .cmp(&grouped[&b.keyed_network_group.expect("peer is connected")].len())
            {
                cmp::Ordering::Equal => match cmp::Reverse(a.keyed_network_group)
                    .cmp(&cmp::Reverse(b.keyed_network_group))
                {
                    cmp::Ordering::Equal => a
                        .connected_at()
                        .expect("peer is connected")
                        .cmp(&b.connected_at().expect("peer is connected")),
                    other => other,
                },
                other => other,
            }
        });
        let Some((peer_id, _)) = candidates.into_iter().next() else {
            tracing::debug!(
                "Inbound peer limit reached, but no peers could be evicted, disconnecting"
            );
            return Err(ConnectionDenied::new(
                "inbound peer limit reached and no peers could be evicted",
            ));
        };

        // Disconnect the evicted peer.
        tracing::debug!(%peer_id, "Evicting inbound peer");
        self.peers.update(peer_id, |peer| {
            peer.connectivity = Connectivity::Disconnecting {
                connected_at: peer.connected_at(),
            };
            peer.evicted = true;
        });
        tokio::spawn({
            let swarm = self.swarm.clone();
            async move {
                if let Err(e) = swarm.disconnect(peer_id).await {
                    tracing::debug!(%peer_id, %e, "Failed to disconnect evicted peer");
                }
            }
        });

        Ok(())
    }

    /// Prevent evicted peers from reconnecting too quickly.
    fn prevent_evicted_peer_reconnections(&self, peer_id: PeerId) -> Result<(), ConnectionDenied> {
        let timeout = if cfg!(test) {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(30)
        };
        match self.peers.get(peer_id) {
            Some(Peer {
                evicted: true,
                connectivity:
                    Connectivity::Disconnected {
                        disconnected_at, ..
                    },
                ..
            }) if disconnected_at.elapsed() < timeout => {
                tracing::debug!(%peer_id, "Evicted peer attempting to reconnect too quickly, disconnecting");
                Err(ConnectionDenied::new(
                    "evicted peer reconnecting too quickly",
                ))
            }
            _ => Ok(()),
        }
    }

    /// Get the IP address from a multiaddr, or disconnect the peer if it
    /// doesn't have one.
    fn get_ip(addr: &Multiaddr) -> Result<IpAddr, ConnectionDenied> {
        addr.iter()
            .find_map(|p| match p {
                Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
            .ok_or_else(|| {
                tracing::debug!(%addr, "Peer has no IP address, disconnecting");
                ConnectionDenied::new("peer has no IP")
            })
    }

    pub fn not_useful(&mut self, peer_id: PeerId) {
        self.peers.update(peer_id, |peer| {
            peer.useful = false;
        });
    }

    pub fn kademlia(&self) -> &kad::Behaviour<MemoryStore> {
        &self.inner.kademlia
    }

    pub fn kademlia_mut(&mut self) -> &mut kad::Behaviour<MemoryStore> {
        &mut self.inner.kademlia
    }

    pub fn gossipsub_mut(&mut self) -> &mut gossipsub::Behaviour {
        &mut self.inner.gossipsub
    }

    pub fn headers_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Headers> {
        &mut self.inner.header_sync
    }

    pub fn classes_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Classes> {
        &mut self.inner.class_sync
    }

    pub fn state_diffs_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::StateDiffs> {
        &mut self.inner.state_diff_sync
    }

    pub fn transactions_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Transactions> {
        &mut self.inner.transaction_sync
    }

    pub fn events_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Events> {
        &mut self.inner.event_sync
    }

    pub fn peers(&self) -> impl Iterator<Item = (PeerId, &Peer)> {
        self.peers.iter()
    }

    /// Outbound peers connected to us.
    pub fn outbound_peers(&self) -> impl Iterator<Item = (PeerId, &Peer)> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.is_connected() && peer.is_outbound())
    }

    /// Inbound non-relayed peers connected to us.
    fn inbound_direct_peers(&self) -> impl Iterator<Item = (PeerId, &Peer)> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.is_connected() && peer.is_inbound() && !peer.is_relayed())
    }

    /// Inbound relayed peers connected to us.
    fn inbound_relayed_peers(&self) -> impl Iterator<Item = (PeerId, &Peer)> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.is_connected() && peer.is_inbound() && peer.is_relayed())
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Event {
    Relay(relay::client::Event),
    Autonat(autonat::Event),
    Dcutr(dcutr::Event),
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Kademlia(kad::Event),
    Gossipsub(gossipsub::Event),
    HeadersSync(p2p_stream::Event<BlockHeadersRequest, BlockHeadersResponse>),
    ClassesSync(p2p_stream::Event<ClassesRequest, ClassesResponse>),
    StateDiffsSync(p2p_stream::Event<StateDiffsRequest, StateDiffsResponse>),
    TransactionsSync(p2p_stream::Event<TransactionsRequest, TransactionsResponse>),
    EventsSync(p2p_stream::Event<EventsRequest, EventsResponse>),
}

impl From<relay::client::Event> for Event {
    fn from(event: relay::client::Event) -> Self {
        Event::Relay(event)
    }
}

impl From<autonat::Event> for Event {
    fn from(event: autonat::Event) -> Self {
        Event::Autonat(event)
    }
}

impl From<dcutr::Event> for Event {
    fn from(event: dcutr::Event) -> Self {
        Event::Dcutr(event)
    }
}

impl From<ping::Event> for Event {
    fn from(event: ping::Event) -> Self {
        Event::Ping(event)
    }
}

impl From<identify::Event> for Event {
    fn from(event: identify::Event) -> Self {
        Event::Identify(Box::new(event))
    }
}

impl From<kad::Event> for Event {
    fn from(event: kad::Event) -> Self {
        Event::Kademlia(event)
    }
}

impl From<gossipsub::Event> for Event {
    fn from(event: gossipsub::Event) -> Self {
        Event::Gossipsub(event)
    }
}

impl From<p2p_stream::Event<BlockHeadersRequest, BlockHeadersResponse>> for Event {
    fn from(event: p2p_stream::Event<BlockHeadersRequest, BlockHeadersResponse>) -> Self {
        Event::HeadersSync(event)
    }
}

impl From<p2p_stream::Event<ClassesRequest, ClassesResponse>> for Event {
    fn from(event: p2p_stream::Event<ClassesRequest, ClassesResponse>) -> Self {
        Event::ClassesSync(event)
    }
}

impl From<p2p_stream::Event<StateDiffsRequest, StateDiffsResponse>> for Event {
    fn from(event: p2p_stream::Event<StateDiffsRequest, StateDiffsResponse>) -> Self {
        Event::StateDiffsSync(event)
    }
}

impl From<p2p_stream::Event<TransactionsRequest, TransactionsResponse>> for Event {
    fn from(event: p2p_stream::Event<TransactionsRequest, TransactionsResponse>) -> Self {
        Event::TransactionsSync(event)
    }
}

impl From<p2p_stream::Event<EventsRequest, EventsResponse>> for Event {
    fn from(event: p2p_stream::Event<EventsRequest, EventsResponse>) -> Self {
        Event::EventsSync(event)
    }
}

fn string_to_key(input: &str) -> kad::RecordKey {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    kad::RecordKey::new(&result.as_slice())
}
