use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::{cmp, task};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::ConnectionEstablished;
use libp2p::swarm::{
    CloseConnection,
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
use libp2p::{ping, Multiaddr, PeerId};

use crate::peers::{Connectivity, Direction, KeyedNetworkGroup, Peer, PeerSet};


