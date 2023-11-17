// Equlibrium Labs: This work is an extension of libp2p's request-response protocol,
// hence the original copyright notice is included below.
//
//
// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Generic single-request/response-stream protocols, later referred to as
//! request/streaming-response.
//!
//! ## General Usage
//!
//! The [`Behaviour`] struct is a [`NetworkBehaviour`] that implements a generic
//! request/streaming-response protocol or protocol family, whereby each request is
//! sent over a new substream on a connection. `Behaviour` is generic
//! over the actual messages being sent, which are defined in terms of a
//! [`Codec`]. Creating a request/streaming-response protocol thus amounts
//! to providing an implementation of this trait which can then be
//! given to [`Behaviour::with_codec`]. Further configuration options are
//! available via the [`Config`].
//!
//! Outbound requests are sent using [`Behaviour::send_request`] and the
//! responses received via [`Event::OutboundRequestAcceptedAwaitingResponses::channel`].
//!
//! Inbound requests are received via [`Event::InboundRequest`] and responses are sent
//! via [`Event::InboundRequest::channel`].
//!
//! ## Protocol Families
//!
//! A single [`Behaviour`] instance can be used with an entire
//! protocol family that share the same request and response types.
//! For that purpose, [`Codec::Protocol`] is typically
//! instantiated with a sum type.

// TODO remove dead code, update & fix the comments

mod codec;
mod handler;

pub use codec::Codec;

use crate::handler::OutboundMessage;
use futures::channel::mpsc;
use handler::Handler;
use libp2p::core::{ConnectedPoint, Endpoint, Multiaddr};
use libp2p::identity::PeerId;
use libp2p::swarm::{
    behaviour::{AddressChange, ConnectionClosed, DialFailure, FromSwarm},
    dial_opts::DialOpts,
    ConnectionDenied, ConnectionHandler, ConnectionId, NetworkBehaviour, NotifyHandler, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use smallvec::SmallVec;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt, io,
    sync::{atomic::AtomicU64, Arc},
    task::{Context, Poll},
    time::Duration,
};

/// The events emitted by a request-response [`Behaviour`].
#[derive(Debug)]
pub enum Event<TRequest, TResponse, TChannelResponse = TResponse> {
    /// An incoming request from another peer.
    InboundRequest {
        /// The peer who sent the request.
        peer: PeerId,
        /// The ID of the request.
        request_id: InboundRequestId,
        /// The request message.
        request: TRequest,
        /// The channel through which we are expected to send responses.
        channel: mpsc::Sender<TChannelResponse>,
    },
    /// Outbound request to another peer was accepted and we can now await responses.
    OutboundRequestAcceptedAwaitingResponses {
        /// The peer who received our request.
        peer: PeerId,
        /// The ID of the outbound request.
        request_id: OutboundRequestId,
        /// The channel through which we can receive the responses.
        channel: mpsc::Receiver<TResponse>,
    },
    /// An outbound request failed.
    OutboundFailure {
        /// The peer to whom the request was sent.
        peer: PeerId,
        /// The (local) ID of the failed request.
        request_id: OutboundRequestId,
        /// The error that occurred.
        error: OutboundFailure,
    },
    /// An inbound request failed.
    InboundFailure {
        /// The peer from whom the request was received.
        peer: PeerId,
        /// The ID of the failed inbound request.
        request_id: InboundRequestId,
        /// The error that occurred.
        error: InboundFailure,
    },
    OutboundResponseStreamClosed {
        /// The peer to whom the responses were sent.
        peer: PeerId,
        /// The ID of the inbound request to which responses were sent.
        request_id: InboundRequestId,
    },
    InboundResponseStreamClosed {
        /// The peer from whom the responses were received.
        peer: PeerId,
        /// The ID of the outbound request to which responses were received.
        request_id: OutboundRequestId,
    },
}

/// Possible failures occurring in the context of sending
/// an outbound request and receiving the response.
#[derive(Debug)]
pub enum OutboundFailure {
    /// The request could not be sent because a dialing attempt failed.
    DialFailure,
    /// The request timed out before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    Timeout,
    /// The connection closed before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    ConnectionClosed,
    /// The remote supports none of the requested protocols.
    UnsupportedProtocols,
    /// An IO failure happened on an outbound stream.
    Io(io::Error),
}

impl fmt::Display for OutboundFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutboundFailure::DialFailure => write!(f, "Failed to dial the requested peer"),
            OutboundFailure::Timeout => write!(f, "Timeout while waiting for a response"),
            OutboundFailure::ConnectionClosed => {
                write!(f, "Connection was closed before a response was received")
            }
            OutboundFailure::UnsupportedProtocols => {
                write!(f, "The remote supports none of the requested protocols")
            }
            OutboundFailure::Io(e) => write!(f, "IO error on outbound stream: {e}"),
        }
    }
}

impl std::error::Error for OutboundFailure {}

/// Possible failures occurring in the context of receiving an
/// inbound request and sending a response.
#[derive(Debug)]
pub enum InboundFailure {
    /// TODO
    /// The inbound request timed out, either while reading the
    /// incoming request or before a response is sent, e.g. if
    /// [`Behaviour::send_response`] is not called in a
    /// timely manner.
    Timeout,
    /// The connection closed before a response could be send.
    ConnectionClosed,
    /// An IO failure happened on an inbound stream.
    Io(io::Error),
}

impl fmt::Display for InboundFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InboundFailure::Timeout => {
                write!(f, "Timeout while receiving request or sending response")
            }
            InboundFailure::ConnectionClosed => {
                write!(f, "Connection was closed before a response could be sent")
            }
            InboundFailure::Io(e) => write!(f, "IO error on inbound stream: {e}"),
        }
    }
}

impl std::error::Error for InboundFailure {}

/// The ID of an inbound request.
///
/// Note: [`InboundRequestId`]'s uniqueness is only guaranteed between
/// inbound requests of the same originating [`Behaviour`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct InboundRequestId(u64);

impl fmt::Display for InboundRequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The ID of an outbound request.
///
/// Note: [`OutboundRequestId`]'s uniqueness is only guaranteed between
/// outbound requests of the same originating [`Behaviour`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct OutboundRequestId(u64);

impl fmt::Display for OutboundRequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The configuration for a `Behaviour` protocol.
#[derive(Debug, Clone)]
pub struct Config {
    request_timeout: Duration,
    max_concurrent_streams: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            max_concurrent_streams: 100,
        }
    }
}

impl Config {
    /// Sets the timeout for inbound and outbound requests.
    #[deprecated(note = "Use `Config::with_request_timeout` for one-liner constructions.")]
    pub fn set_request_timeout(&mut self, v: Duration) -> &mut Self {
        self.request_timeout = v;
        self
    }

    /// Sets the timeout for inbound and outbound requests.
    pub fn with_request_timeout(mut self, v: Duration) -> Self {
        self.request_timeout = v;
        self
    }

    /// Sets the upper bound for the number of concurrent inbound + outbound streams.
    pub fn with_max_concurrent_streams(mut self, num_streams: usize) -> Self {
        self.max_concurrent_streams = num_streams;
        self
    }
}

/// A request/response protocol for some message codec.
pub struct Behaviour<TCodec>
where
    TCodec: Codec + Clone + Send + 'static,
{
    /// The supported protocols.
    protocols: SmallVec<[TCodec::Protocol; 2]>,
    /// The next (local) request ID.
    next_outbound_request_id: OutboundRequestId,
    /// The next (inbound) request ID.
    next_inbound_request_id: Arc<AtomicU64>,
    /// The protocol configuration.
    config: Config,
    /// The protocol codec for reading and writing requests and responses.
    codec: TCodec,
    /// Pending events to return from `poll`.
    pending_events:
        VecDeque<ToSwarm<Event<TCodec::Request, TCodec::Response>, OutboundMessage<TCodec>>>,
    /// The currently connected peers, their pending outbound and inbound responses and their known,
    /// reachable addresses, if any.
    connected: HashMap<PeerId, SmallVec<[Connection; 2]>>,
    /// Externally managed addresses via `add_address` and `remove_address`.
    addresses: HashMap<PeerId, HashSet<Multiaddr>>,
    /// Requests that have not yet been sent and are waiting for a connection
    /// to be established.
    pending_outbound_requests: HashMap<PeerId, SmallVec<[OutboundMessage<TCodec>; 10]>>,
}

impl<TCodec> Behaviour<TCodec>
where
    TCodec: Codec + Default + Clone + Send + 'static,
{
    /// Creates a new `Behaviour` for the given protocols and configuration, using [`Default`] to construct the codec.
    pub fn new<I>(protocols: I, cfg: Config) -> Self
    where
        I: IntoIterator<Item = TCodec::Protocol>,
    {
        Self::with_codec(TCodec::default(), protocols, cfg)
    }
}

impl<TCodec> Behaviour<TCodec>
where
    TCodec: Codec + Clone + Send + 'static,
{
    /// Creates a new `Behaviour` for the given
    /// protocols, codec and configuration.
    pub fn with_codec<I>(codec: TCodec, protocols: I, cfg: Config) -> Self
    where
        I: IntoIterator<Item = TCodec::Protocol>,
    {
        Behaviour {
            protocols: protocols.into_iter().collect(),
            next_outbound_request_id: OutboundRequestId(1),
            next_inbound_request_id: Arc::new(AtomicU64::new(1)),
            config: cfg,
            codec,
            pending_events: VecDeque::new(),
            connected: HashMap::new(),
            pending_outbound_requests: HashMap::new(),
            addresses: HashMap::new(),
        }
    }

    /// Initiates sending a request.
    ///
    /// If the targeted peer is currently not connected, a dialing
    /// attempt is initiated and the request is sent as soon as a
    /// connection is established.
    ///
    /// > **Note**: In order for such a dialing attempt to succeed,
    /// > the `RequestResonse` protocol must either be embedded
    /// > in another `NetworkBehaviour` that provides peer and
    /// > address discovery, or known addresses of peers must be
    /// > managed via [`Behaviour::add_address`] and
    /// > [`Behaviour::remove_address`].
    pub fn send_request(&mut self, peer: &PeerId, request: TCodec::Request) -> OutboundRequestId {
        let request_id = self.next_outbound_request_id();

        let request = OutboundMessage {
            request_id,
            request,
            protocols: self.protocols.clone(),
        };

        if let Some(request) = self.try_send_request(peer, request) {
            self.pending_events.push_back(ToSwarm::Dial {
                opts: DialOpts::peer_id(*peer).build(),
            });

            self.pending_outbound_requests
                .entry(*peer)
                .or_default()
                .push(request);
        }

        request_id
    }

    /// Adds a known address for a peer that can be used for
    /// dialing attempts by the `Swarm`, i.e. is returned
    /// by [`NetworkBehaviour::handle_pending_outbound_connection`].
    ///
    /// Addresses added in this way are only removed by `remove_address`.
    ///
    /// Returns true if the address was added, false otherwise (i.e. if the
    /// address is already in the list).
    pub fn add_address(&mut self, peer: &PeerId, address: Multiaddr) -> bool {
        self.addresses.entry(*peer).or_default().insert(address)
    }

    /// Removes an address of a peer previously added via `add_address`.
    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        let mut last = false;
        if let Some(addresses) = self.addresses.get_mut(peer) {
            addresses.retain(|a| a != address);
            last = addresses.is_empty();
        }
        if last {
            self.addresses.remove(peer);
        }
    }

    /// Checks whether a peer is currently connected.
    pub fn is_connected(&self, peer: &PeerId) -> bool {
        if let Some(connections) = self.connected.get(peer) {
            !connections.is_empty()
        } else {
            false
        }
    }

    /// Checks whether an outbound request to the peer with the provided
    /// [`PeerId`] initiated by [`Behaviour::send_request`] is still
    /// pending, i.e. waiting for a response.
    pub fn is_pending_outbound(&self, peer: &PeerId, request_id: &OutboundRequestId) -> bool {
        // Check if request is already sent on established connection.
        let est_conn = self
            .connected
            .get(peer)
            .map(|cs| {
                cs.iter()
                    .any(|c| c.pending_outbound_responses.contains(request_id))
            })
            .unwrap_or(false);
        // Check if request is still pending to be sent.
        let pen_conn = self
            .pending_outbound_requests
            .get(peer)
            .map(|rps| rps.iter().any(|rp| rp.request_id == *request_id))
            .unwrap_or(false);

        est_conn || pen_conn
    }

    /// Checks whether an inbound request from the peer with the provided
    /// [`PeerId`] is still pending, i.e. waiting for a response by the local
    /// node through [`Behaviour::send_response`].
    pub fn is_pending_inbound(&self, peer: &PeerId, request_id: &InboundRequestId) -> bool {
        self.connected
            .get(peer)
            .map(|cs| {
                cs.iter()
                    .any(|c| c.pending_inbound_responses.contains(request_id))
            })
            .unwrap_or(false)
    }

    /// Returns the next outbound request ID.
    fn next_outbound_request_id(&mut self) -> OutboundRequestId {
        let request_id = self.next_outbound_request_id;
        self.next_outbound_request_id.0 += 1;
        request_id
    }

    /// Tries to send a request by queueing an appropriate event to be
    /// emitted to the `Swarm`. If the peer is not currently connected,
    /// the given request is return unchanged.
    fn try_send_request(
        &mut self,
        peer: &PeerId,
        request: OutboundMessage<TCodec>,
    ) -> Option<OutboundMessage<TCodec>> {
        if let Some(connections) = self.connected.get_mut(peer) {
            if connections.is_empty() {
                return Some(request);
            }
            let ix = (request.request_id.0 as usize) % connections.len();
            let conn = &mut connections[ix];
            conn.pending_outbound_responses.insert(request.request_id);
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id: *peer,
                handler: NotifyHandler::One(conn.id),
                event: request,
            });
            None
        } else {
            Some(request)
        }
    }

    /// Remove pending outbound response for the given peer and connection.
    ///
    /// Returns `true` if the provided connection to the given peer is still
    /// alive and the [`OutboundRequestId`] was previously present and is now removed.
    /// Returns `false` otherwise.
    ///
    /// TODO rename to remove_pending_outbound_request_stream
    fn remove_pending_outbound_response(
        &mut self,
        peer: &PeerId,
        connection: ConnectionId,
        request: OutboundRequestId,
    ) -> bool {
        self.get_connection_mut(peer, connection)
            .map(|c| c.pending_outbound_responses.remove(&request))
            .unwrap_or(false)
    }

    /// Remove pending inbound response for the given peer and connection.
    ///
    /// Returns `true` if the provided connection to the given peer is still
    /// alive and the [`InboundRequestId`] was previously present and is now removed.
    /// Returns `false` otherwise.
    ///
    /// TODO rename to remove_pending_inbound_request_stream
    fn remove_pending_inbound_response(
        &mut self,
        peer: &PeerId,
        connection: ConnectionId,
        request: InboundRequestId,
    ) -> bool {
        self.get_connection_mut(peer, connection)
            .map(|c| c.pending_inbound_responses.remove(&request))
            .unwrap_or(false)
    }

    /// Returns a mutable reference to the connection in `self.connected`
    /// corresponding to the given [`PeerId`] and [`ConnectionId`].
    fn get_connection_mut(
        &mut self,
        peer: &PeerId,
        connection: ConnectionId,
    ) -> Option<&mut Connection> {
        self.connected
            .get_mut(peer)
            .and_then(|connections| connections.iter_mut().find(|c| c.id == connection))
    }

    fn on_address_change(
        &mut self,
        AddressChange {
            peer_id,
            connection_id,
            new,
            ..
        }: AddressChange,
    ) {
        let new_address = match new {
            ConnectedPoint::Dialer { address, .. } => Some(address.clone()),
            ConnectedPoint::Listener { .. } => None,
        };
        let connections = self
            .connected
            .get_mut(&peer_id)
            .expect("Address change can only happen on an established connection.");

        let connection = connections
            .iter_mut()
            .find(|c| c.id == connection_id)
            .expect("Address change can only happen on an established connection.");
        connection.remote_address = new_address;
    }

    fn on_connection_closed(
        &mut self,
        ConnectionClosed {
            peer_id,
            connection_id,
            remaining_established,
            ..
        }: ConnectionClosed,
    ) {
        let connections = self
            .connected
            .get_mut(&peer_id)
            .expect("Expected some established connection to peer before closing.");

        let connection = connections
            .iter()
            .position(|c| c.id == connection_id)
            .map(|p: usize| connections.remove(p))
            .expect("Expected connection to be established before closing.");

        debug_assert_eq!(connections.is_empty(), remaining_established == 0);
        if connections.is_empty() {
            self.connected.remove(&peer_id);
        }

        for request_id in connection.pending_inbound_responses {
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(Event::InboundFailure {
                    peer: peer_id,
                    request_id,
                    error: InboundFailure::ConnectionClosed,
                }));
        }

        for request_id in connection.pending_outbound_responses {
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(Event::OutboundFailure {
                    peer: peer_id,
                    request_id,
                    error: OutboundFailure::ConnectionClosed,
                }));
        }
    }

    fn on_dial_failure(&mut self, DialFailure { peer_id, .. }: DialFailure) {
        if let Some(peer) = peer_id {
            // If there are pending outgoing requests when a dial failure occurs,
            // it is implied that we are not connected to the peer, since pending
            // outgoing requests are drained when a connection is established and
            // only created when a peer is not connected when a request is made.
            // Thus these requests must be considered failed, even if there is
            // another, concurrent dialing attempt ongoing.
            if let Some(pending) = self.pending_outbound_requests.remove(&peer) {
                for request in pending {
                    self.pending_events
                        .push_back(ToSwarm::GenerateEvent(Event::OutboundFailure {
                            peer,
                            request_id: request.request_id,
                            error: OutboundFailure::DialFailure,
                        }));
                }
            }
        }
    }

    /// Preloads a new [`Handler`] with requests that are waiting to be sent to the newly connected peer.
    fn preload_new_handler(
        &mut self,
        handler: &mut Handler<TCodec>,
        peer: PeerId,
        connection_id: ConnectionId,
        remote_address: Option<Multiaddr>,
    ) {
        let mut connection = Connection::new(connection_id, remote_address);

        if let Some(pending_requests) = self.pending_outbound_requests.remove(&peer) {
            for request in pending_requests {
                connection
                    .pending_outbound_responses
                    .insert(request.request_id);
                handler.on_behaviour_event(request);
            }
        }

        self.connected.entry(peer).or_default().push(connection);
    }
}

impl<TCodec> NetworkBehaviour for Behaviour<TCodec>
where
    TCodec: Codec + Send + Clone + 'static,
{
    type ConnectionHandler = Handler<TCodec>;
    type ToSwarm = Event<TCodec::Request, TCodec::Response>;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let mut handler = Handler::new(
            self.protocols.clone(),
            self.codec.clone(),
            self.config.request_timeout,
            self.next_inbound_request_id.clone(),
            self.config.max_concurrent_streams,
        );

        self.preload_new_handler(&mut handler, peer, connection_id, None);

        Ok(handler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let peer = match maybe_peer {
            None => return Ok(vec![]),
            Some(peer) => peer,
        };

        let mut addresses = Vec::new();
        if let Some(connections) = self.connected.get(&peer) {
            addresses.extend(connections.iter().filter_map(|c| c.remote_address.clone()))
        }
        if let Some(more) = self.addresses.get(&peer) {
            addresses.extend(more.iter().cloned());
        }

        Ok(addresses)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        remote_address: &Multiaddr,
        _: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let mut handler = Handler::new(
            self.protocols.clone(),
            self.codec.clone(),
            self.config.request_timeout,
            self.next_inbound_request_id.clone(),
            self.config.max_concurrent_streams,
        );

        self.preload_new_handler(
            &mut handler,
            peer,
            connection_id,
            Some(remote_address.clone()),
        );

        Ok(handler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(_) => {}
            FromSwarm::ConnectionClosed(connection_closed) => {
                self.on_connection_closed(connection_closed)
            }
            FromSwarm::AddressChange(address_change) => self.on_address_change(address_change),
            FromSwarm::DialFailure(dial_failure) => self.on_dial_failure(dial_failure),
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            handler::Event::OutboundRequestAcceptedAwaitingResponses {
                request_id,
                receiver,
            } => {
                let removed = self.remove_pending_outbound_response(&peer, connection, request_id);
                debug_assert!(
                    removed,
                    "Expect request_id to be pending before getting the response channel.",
                );

                self.pending_events.push_back(ToSwarm::GenerateEvent(
                    Event::OutboundRequestAcceptedAwaitingResponses {
                        peer,
                        request_id,
                        channel: receiver,
                    },
                ));
            }
            handler::Event::InboundRequest {
                request_id,
                request,
                sender,
            } => match self.get_connection_mut(&peer, connection) {
                Some(connection) => {
                    let inserted = connection.pending_inbound_responses.insert(request_id);
                    debug_assert!(inserted, "Expect id of new request to be unknown.");

                    self.pending_events
                        .push_back(ToSwarm::GenerateEvent(Event::InboundRequest {
                            peer,
                            request_id,
                            request,
                            channel: sender,
                        }))
                }
                None => {
                    tracing::debug!("Connection ({connection}) closed after `Event::Request` ({request_id}) has been emitted.");
                }
            },
            handler::Event::OutboundResponseStreamClosed(request_id) => {
                let removed = self.remove_pending_inbound_response(&peer, connection, request_id);
                // TODO probably cannot assert this anymore
                debug_assert!(
                    removed,
                    "Expect request_id to be pending before response is sent."
                );

                self.pending_events.push_back(ToSwarm::GenerateEvent(
                    Event::OutboundResponseStreamClosed { peer, request_id },
                ));
            }
            handler::Event::InboundResponseStreamClosed(request_id) => {
                let removed = self.remove_pending_outbound_response(&peer, connection, request_id);

                // TODO
                debug_assert!(
                    !removed,
                    "Expect request_id to have been removed from pending because the response channel has already been available."
                );

                self.pending_events.push_back(ToSwarm::GenerateEvent(
                    Event::InboundResponseStreamClosed { peer, request_id },
                ));
            }
            handler::Event::OutboundTimeout(request_id) => {
                let removed = self.remove_pending_outbound_response(&peer, connection, request_id);
                debug_assert!(
                    !removed,
                    "Expect request_id to be pending before request times out."
                );

                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::OutboundFailure {
                        peer,
                        request_id,
                        error: OutboundFailure::Timeout,
                    }));
            }
            handler::Event::OutboundUnsupportedProtocols(request_id) => {
                let removed = self.remove_pending_outbound_response(&peer, connection, request_id);
                debug_assert!(
                    removed,
                    "Expect request_id to be pending before failing to connect.",
                );

                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::OutboundFailure {
                        peer,
                        request_id,
                        error: OutboundFailure::UnsupportedProtocols,
                    }));
            }
            handler::Event::OutboundStreamFailed { request_id, error } => {
                let _removed = self.remove_pending_outbound_response(&peer, connection, request_id);

                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::OutboundFailure {
                        peer,
                        request_id,
                        error: OutboundFailure::Io(error),
                    }))
            }
            handler::Event::InboundTimeout(request_id) => {
                let removed = self.remove_pending_inbound_response(&peer, connection, request_id);

                if removed {
                    self.pending_events
                        .push_back(ToSwarm::GenerateEvent(Event::InboundFailure {
                            peer,
                            request_id,
                            error: InboundFailure::Timeout,
                        }));
                } else {
                    // This happens when timeout is emitted before `read_request` finishes.
                    tracing::debug!(
                        "Inbound request timeout for an unknown request_id ({request_id})"
                    );
                }
            }
            handler::Event::InboundStreamFailed { request_id, error } => {
                let removed = self.remove_pending_inbound_response(&peer, connection, request_id);

                if removed {
                    self.pending_events
                        .push_back(ToSwarm::GenerateEvent(Event::InboundFailure {
                            peer,
                            request_id,
                            error: InboundFailure::Io(error),
                        }));
                } else {
                    // This happens when `read_request` fails.
                    tracing::debug!("Inbound failure is reported for an unknown request_id ({request_id}): {error}");
                }
            }
        }
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(ev) = self.pending_events.pop_front() {
            return Poll::Ready(ev);
        } else if self.pending_events.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.pending_events.shrink_to_fit();
        }

        Poll::Pending
    }
}

/// Internal threshold for when to shrink the capacity
/// of empty queues. If the capacity of an empty queue
/// exceeds this threshold, the associated memory is
/// released.
const EMPTY_QUEUE_SHRINK_THRESHOLD: usize = 100;

/// Internal information tracked for an established connection.
struct Connection {
    id: ConnectionId,
    remote_address: Option<Multiaddr>,
    /// Pending outbound responses where corresponding inbound requests have
    /// been received on this connection and emitted via `poll` but have not yet
    /// been answered.
    ///
    /// TODO rename to pending_outbound_response_streams
    pending_outbound_responses: HashSet<OutboundRequestId>,
    /// Pending inbound responses for previously sent requests on this
    /// connection.
    ///
    /// TODO rename to pending_inbound_response_streams
    pending_inbound_responses: HashSet<InboundRequestId>,
}

impl Connection {
    fn new(id: ConnectionId, remote_address: Option<Multiaddr>) -> Self {
        Self {
            id,
            remote_address,
            pending_outbound_responses: Default::default(),
            pending_inbound_responses: Default::default(),
        }
    }
}