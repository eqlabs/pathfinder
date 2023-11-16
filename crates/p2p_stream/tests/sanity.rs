use anyhow::{bail, Result};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{pin_mut, prelude::*};
use libp2p::identity::PeerId;
use libp2p::swarm::{StreamProtocol, Swarm};
use libp2p_swarm_test::SwarmExt;
use p2p_stream as rrs;
use rrs::{Codec, InboundRequestId, OutboundRequestId};
use std::time::Duration;
use std::{io, iter};
use tracing_subscriber::EnvFilter;

#[tokio::test]
async fn sanity() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // `swarm2` needs to have a bigger timeout to avoid racing
    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_millis(1000));
    let (peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_millis(1000));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    // Expects Action::SanityRequest, replies with 3x Action::SanityResponse
    let server_task = async move {
        let (peer, req_id, action, mut resp_channel) =
            wait_inbound_request(&mut swarm1).await.unwrap();

        assert_eq!(peer, peer2_id);
        assert_eq!(action, Action::SanityRequest);

        resp_channel.send(Action::SanityResponse).await.unwrap();
        resp_channel.send(Action::SanityResponse).await.unwrap();
        resp_channel.send(Action::SanityResponse).await.unwrap();

        // Force close the stream
        drop(resp_channel);

        let (peer, req_id_done) = wait_outbound_response_stream_closed(&mut swarm1)
            .await
            .unwrap();

        assert_eq!(peer, peer2_id);
        assert_eq!(req_id_done, req_id);
    };

    // Starts with Action::SanityRequest, expects 3x Action::SanityResponse
    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::SanityRequest);

        let (peer, req_id_done, mut resp_channel) =
            wait_outbound_request_accepted_awaiting_responses(&mut swarm2)
                .await
                .unwrap();

        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert_eq!(resp_channel.next().await.unwrap(), Action::SanityResponse);
        assert_eq!(resp_channel.next().await.unwrap(), Action::SanityResponse);
        assert_eq!(resp_channel.next().await.unwrap(), Action::SanityResponse);

        // Keep alive the task, so only `server_task` can finish
        wait_no_events(&mut swarm2).await;
    };

    let server_task = server_task.fuse();
    let client_task = client_task.fuse();

    pin_mut!(server_task);
    pin_mut!(client_task);

    loop {
        futures::select! {
            _ = server_task => {
                eprintln!("server_task done");
                break;
            },
            _ = client_task => {
                eprintln!("client_task done");
                break;
            },
        }
    }
}

#[derive(Clone, Default)]
struct TestCodec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    FailOnReadRequest,
    FailOnReadResponse,
    TimeoutOnReadResponse,
    FailOnWriteRequest,
    FailOnWriteResponse,
    TimeoutOnWriteResponse,
    SanityRequest,
    SanityResponse,
}

impl From<Action> for u8 {
    fn from(value: Action) -> Self {
        match value {
            Action::FailOnReadRequest => 0,
            Action::FailOnReadResponse => 1,
            Action::TimeoutOnReadResponse => 2,
            Action::FailOnWriteRequest => 3,
            Action::FailOnWriteResponse => 4,
            Action::TimeoutOnWriteResponse => 5,
            Action::SanityRequest => 6,
            Action::SanityResponse => 7,
        }
    }
}

impl TryFrom<u8> for Action {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Action::FailOnReadRequest),
            1 => Ok(Action::FailOnReadResponse),
            2 => Ok(Action::TimeoutOnReadResponse),
            3 => Ok(Action::FailOnWriteRequest),
            4 => Ok(Action::FailOnWriteResponse),
            5 => Ok(Action::TimeoutOnWriteResponse),
            6 => Ok(Action::SanityRequest),
            7 => Ok(Action::SanityResponse),
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
        let mut buf = [0u8];
        // Message is 1 byte long
        loop {
            if io.read(&mut buf).await? == 1 {
                break;
            }
        }

        if buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        assert_eq!(buf.len(), 1);

        match buf[0].try_into()? {
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
        let mut buf = [0u8];

        // Message is 1 byte long
        loop {
            if io.read(&mut buf).await? == 1 {
                break;
            }
        }

        if buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        assert_eq!(buf.len(), 1);

        match buf[0].try_into()? {
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
                let bytes = [action.into()];
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
                let bytes = [action.into()];
                io.write_all(&bytes).await?;
                Ok(())
            }
        }
    }
}

fn new_swarm_with_timeout(timeout: Duration) -> (PeerId, Swarm<rrs::Behaviour<TestCodec>>) {
    let protocols = iter::once(StreamProtocol::new("/test/1"));
    let cfg = rrs::Config::default().with_request_timeout(timeout);

    let swarm = Swarm::new_ephemeral(|_| rrs::Behaviour::<TestCodec>::new(protocols, cfg));
    let peed_id = *swarm.local_peer_id();

    (peed_id, swarm)
}

async fn wait_no_events(swarm: &mut Swarm<rrs::Behaviour<TestCodec>>) {
    loop {
        if let Ok(ev) = swarm.select_next_some().await.try_into_behaviour_event() {
            panic!("Unexpected event: {ev:?}")
        }
    }
}

async fn wait_inbound_request(
    swarm: &mut Swarm<rrs::Behaviour<TestCodec>>,
) -> Result<(PeerId, InboundRequestId, Action, mpsc::Sender<Action>)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(rrs::Event::InboundRequest {
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

async fn wait_outbound_request_accepted_awaiting_responses(
    swarm: &mut Swarm<rrs::Behaviour<TestCodec>>,
) -> Result<(PeerId, OutboundRequestId, mpsc::Receiver<Action>)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(rrs::Event::OutboundRequestAcceptedAwaitingResponses {
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

async fn wait_outbound_response_stream_closed(
    swarm: &mut Swarm<rrs::Behaviour<TestCodec>>,
) -> Result<(PeerId, InboundRequestId)> {
    loop {
        match swarm.select_next_some().await.try_into_behaviour_event() {
            Ok(rrs::Event::OutboundResponseStreamClosed {
                peer, request_id, ..
            }) => {
                return Ok((peer, request_id));
            }
            Ok(ev) => bail!("Unexpected event: {ev:?}"),
            Err(..) => {}
        }
    }
}
