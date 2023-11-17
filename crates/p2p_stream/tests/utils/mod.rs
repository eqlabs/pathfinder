//! Common utilities for p2p_stream integration tests.
use anyhow::{bail, Result};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::identity::PeerId;
use libp2p::swarm::{StreamProtocol, Swarm};
use libp2p_swarm_test::SwarmExt;
use p2p_stream::{Codec, InboundFailure, InboundRequestId, OutboundFailure, OutboundRequestId};
use std::time::Duration;
use std::{io, iter};

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

        if buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        match u32::from_be_bytes(buf).try_into()? {
            Action::FailOnReadRequest => {
                Err(io::Error::new(io::ErrorKind::Other, "FailOnReadRequest"))
            }
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

        if buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

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

pub fn new_swarm_with_timeout(
    timeout: Duration,
) -> (PeerId, Swarm<p2p_stream::Behaviour<TestCodec>>) {
    let protocols = iter::once(StreamProtocol::new("/test/1"));
    let cfg = p2p_stream::Config::default().with_request_timeout(timeout);

    let swarm = Swarm::new_ephemeral(|_| p2p_stream::Behaviour::<TestCodec>::new(protocols, cfg));
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

pub async fn wait_outbound_request_accepted_awaiting_responses(
    swarm: &mut Swarm<p2p_stream::Behaviour<TestCodec>>,
) -> Result<(PeerId, OutboundRequestId, mpsc::Receiver<Action>)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(p2p_stream::Event::OutboundRequestAcceptedAwaitingResponses {
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
