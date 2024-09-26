//! Common utilities for p2p_stream integration tests.
use std::fmt::Debug;
use std::time::Duration;
use std::{io, iter};

use anyhow::{bail, Result};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::identity::{Keypair, PeerId};
use libp2p::swarm::{self, NetworkBehaviour, StreamProtocol, Swarm};
use libp2p::{yamux, Transport};
use p2p_stream::{Codec, InboundFailure, InboundRequestId, OutboundFailure, OutboundRequestId};

#[derive(Clone, Default)]
pub struct TestCodec;

pub type TestSwarm = Swarm<p2p_stream::Behaviour<TestCodec>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    FailOnReadRequest,
    FailOnReadResponse,
    TimeoutOnReadResponse,
    FailOnWriteRequest,
    FailOnWriteResponse,
    TimeoutOnWriteResponse,
    SanityRequest,
    SanityResponse(u32), // The highest byte is ignored
    TimeoutOnWriteRequest,
    TimeoutOnReadRequest,
}

impl From<Action> for u32 {
    fn from(value: Action) -> Self {
        match value {
            Action::FailOnReadRequest => 0,
            Action::FailOnReadResponse => 1,
            Action::TimeoutOnReadResponse => 2,
            Action::FailOnWriteRequest => 3,
            Action::FailOnWriteResponse => 4,
            Action::TimeoutOnWriteResponse => 5,
            Action::SanityRequest => 6,
            Action::SanityResponse(id) => 7 | ((id & 0x00FFFFFF) << 8),
            Action::TimeoutOnWriteRequest => 8,
            Action::TimeoutOnReadRequest => 9,
        }
    }
}

impl TryFrom<u32> for Action {
    type Error = io::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value & 0x000000FF {
            0 => Ok(Action::FailOnReadRequest),
            1 => Ok(Action::FailOnReadResponse),
            2 => Ok(Action::TimeoutOnReadResponse),
            3 => Ok(Action::FailOnWriteRequest),
            4 => Ok(Action::FailOnWriteResponse),
            5 => Ok(Action::TimeoutOnWriteResponse),
            6 => Ok(Action::SanityRequest),
            7 => Ok(Action::SanityResponse((value & 0xFFFFFF00) >> 8)),
            8 => Ok(Action::TimeoutOnWriteRequest),
            9 => Ok(Action::TimeoutOnReadRequest),
            _ => Err(io::Error::new(io::ErrorKind::Other, "invalid action")),
        }
    }
}

#[async_trait]
impl Codec for TestCodec {
    type Protocol = StreamProtocol;
    type Request = Action;
    type Response = Action;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = [0u8; std::mem::size_of::<u32>()];

        io.read_exact(&mut buf).await?;

        match u32::from_be_bytes(buf).try_into()? {
            Action::FailOnReadRequest => {
                Err(io::Error::new(io::ErrorKind::Other, "FailOnReadRequest"))
            }
            Action::TimeoutOnReadRequest => loop {
                tokio::time::sleep(Duration::MAX).await;
            },
            action => Ok(action),
        }
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = [0u8; std::mem::size_of::<u32>()];

        io.read_exact(&mut buf).await?;

        match u32::from_be_bytes(buf).try_into()? {
            Action::FailOnReadResponse => {
                Err(io::Error::new(io::ErrorKind::Other, "FailOnReadResponse"))
            }
            Action::TimeoutOnReadResponse => loop {
                tokio::time::sleep(Duration::MAX).await;
            },
            action => Ok(action),
        }
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match req {
            Action::FailOnWriteRequest => {
                Err(io::Error::new(io::ErrorKind::Other, "FailOnWriteRequest"))
            }
            Action::TimeoutOnWriteRequest => loop {
                tokio::time::sleep(Duration::MAX).await;
            },
            action => {
                let bytes = u32::from(action).to_be_bytes();
                io.write_all(&bytes).await?;
                Ok(())
            }
        }
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match res {
            Action::FailOnWriteResponse => {
                Err(io::Error::new(io::ErrorKind::Other, "FailOnWriteResponse"))
            }
            Action::TimeoutOnWriteResponse => loop {
                tokio::time::sleep(Duration::MAX).await;
            },
            action => {
                let bytes = u32::from(action).to_be_bytes();
                io.write_all(&bytes).await?;
                Ok(())
            }
        }
    }
}

/// [`SwarmExt::new_ephemeral`] uses `async_std` executor, but we're using
/// `tokio`
pub(crate) fn new_ephemeral_with_tokio_executor<B>(
    behaviour_fn: impl FnOnce(Keypair) -> B,
) -> Swarm<B>
where
    B: NetworkBehaviour + Send,
    <B as NetworkBehaviour>::ToSwarm: Debug,
{
    let identity = Keypair::generate_ed25519();
    let peer_id = PeerId::from(identity.public());

    let transport = MemoryTransport::default()
        .or_transport(libp2p::tcp::tokio::Transport::default())
        .upgrade(Version::V1)
        .authenticate(libp2p_plaintext::Config::new(&identity))
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    Swarm::new(
        transport,
        behaviour_fn(identity),
        peer_id,
        swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(5)), /* Some tests need connections to be kept alive beyond what the individual behaviour configures., */
    )
}

pub fn new_swarm_with_timeout(
    timeout: Duration,
) -> (PeerId, Swarm<p2p_stream::Behaviour<TestCodec>>) {
    let protocols = iter::once(StreamProtocol::new("/test/1"));
    let cfg = p2p_stream::Config::default().request_timeout(timeout);

    // SwarmExt::new_ephemeral uses async::std
    let swarm = new_ephemeral_with_tokio_executor(|_| {
        p2p_stream::Behaviour::<TestCodec>::with_codec_and_protocols(TestCodec, protocols, cfg)
    });

    let peed_id = *swarm.local_peer_id();

    (peed_id, swarm)
}

pub fn new_swarm() -> (PeerId, Swarm<p2p_stream::Behaviour<TestCodec>>) {
    new_swarm_with_timeout(Duration::from_millis(100))
}

pub async fn wait_no_events(swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>) {
    loop {
        if let Ok(ev) = swarm.select_next_some().await.try_into_behaviour_event() {
            panic!("Unexpected event: {ev:?}")
        }
    }
}

pub async fn wait_inbound_request(
    swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>,
) -> Result<(PeerId, InboundRequestId, Action, mpsc::Sender<Action>)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(p2p_stream::Event::InboundRequest {
                peer,
                request_id,
                request,
                channel,
            }) => {
                return Ok((peer, request_id, request, channel));
            }
            Ok(ev) => bail!("Unexpected event: {ev:?}"),
            Err(..) => {}
        }
    }
}

pub async fn wait_outbound_request_sent_awaiting_responses(
    swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>,
) -> Result<(
    PeerId,
    OutboundRequestId,
    mpsc::Receiver<std::io::Result<Action>>,
)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(p2p_stream::Event::OutboundRequestSentAwaitingResponses {
                peer,
                request_id,
                channel,
            }) => {
                return Ok((peer, request_id, channel));
            }
            Ok(ev) => bail!("Unexpected event: {ev:?}"),
            Err(..) => {}
        }
    }
}

pub async fn wait_outbound_response_stream_closed(
    swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>,
) -> Result<(PeerId, InboundRequestId)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(p2p_stream::Event::OutboundResponseStreamClosed {
                peer, request_id, ..
            }) => {
                return Ok((peer, request_id));
            }
            Ok(ev) => bail!("Unexpected event: {ev:?}"),
            Err(..) => {}
        }
    }
}

pub async fn wait_inbound_response_stream_closed(
    swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>,
) -> Result<(PeerId, OutboundRequestId)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(p2p_stream::Event::InboundResponseStreamClosed {
                peer, request_id, ..
            }) => {
                return Ok((peer, request_id));
            }
            Ok(ev) => bail!("Unexpected event: {ev:?}"),
            Err(..) => {}
        }
    }
}

pub async fn wait_inbound_failure(
    swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>,
) -> Result<(PeerId, InboundRequestId, InboundFailure)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(p2p_stream::Event::InboundFailure {
                peer,
                request_id,
                error,
            }) => {
                return Ok((peer, request_id, error));
            }
            Ok(ev) => bail!("Unexpected event: {ev:?}"),
            Err(..) => {}
        }
    }
}

pub async fn wait_outbound_failure(
    swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>,
) -> Result<(PeerId, OutboundRequestId, OutboundFailure)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(p2p_stream::Event::OutboundFailure {
                peer,
                request_id,
                error,
            }) => {
                return Ok((peer, request_id, error));
            }
            Ok(ev) => bail!("Unexpected event: {ev:?}"),
            Err(..) => {}
        }
    }
}
