use futures::prelude::*;
use libp2p_swarm_test::SwarmExt;
use p2p_stream::{InboundFailure, OutboundFailure};
use std::{io, pin::pin, time::Duration};
use tracing_subscriber::EnvFilter;

mod utils;

use utils::{
    new_swarm, new_swarm_with_timeout, wait_inbound_failure, wait_inbound_request,
    wait_inbound_response_stream_closed, wait_no_events, wait_outbound_failure,
    wait_outbound_request_sent_awaiting_responses, Action,
};

#[tokio::test]
async fn report_outbound_failure_on_read_response() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (peer1_id, mut swarm1) = new_swarm();
    let (peer2_id, mut swarm2) = new_swarm();

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        let (peer, _req_id, action, mut resp_channel) =
            wait_inbound_request(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(action, Action::FailOnReadResponse);

        resp_channel.send(Action::FailOnReadResponse).await.unwrap();

        // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed` instead
        wait_no_events(&mut swarm1).await;
    };

    // Expects OutboundFailure::Io failure with `FailOnReadResponse` error
    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::FailOnReadResponse);

        let (peer, req_id_done, mut resp_channel) =
            wait_outbound_request_sent_awaiting_responses(&mut swarm2)
                .await
                .unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(resp_channel.next().await.is_none());

        let (peer, req_id_done, error) = wait_outbound_failure(&mut swarm2).await.unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        let error = match error {
            OutboundFailure::Io(e) => e,
            e => panic!("Unexpected error: {e:?}"),
        };

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error.into_inner().unwrap().to_string(),
            "FailOnReadResponse"
        );
    };

    let server_task = pin!(server_task);
    let client_task = pin!(client_task);
    futures::future::select(server_task, client_task).await;
}

#[tokio::test]
async fn report_outbound_failure_on_write_request() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (peer1_id, mut swarm1) = new_swarm();
    let (_peer2_id, mut swarm2) = new_swarm();

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    // Expects no events because `Event::Request` is produced after `read_request`.
    // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed` instead.
    let server_task = wait_no_events(&mut swarm1);

    // Expects OutboundFailure::Io failure with `FailOnWriteRequest` error.
    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::FailOnWriteRequest);

        let (peer, req_id_done, error) = wait_outbound_failure(&mut swarm2).await.unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        let error = match error {
            OutboundFailure::Io(e) => e,
            e => panic!("Unexpected error: {e:?}"),
        };

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error.into_inner().unwrap().to_string(),
            "FailOnWriteRequest"
        );
    };

    let server_task = pin!(server_task);
    let client_task = pin!(client_task);
    futures::future::select(server_task, client_task).await;
}

#[tokio::test]
async fn report_outbound_timeout_on_read_response() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // `swarm1` needs to have a bigger timeout to avoid racing
    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_millis(200));
    let (peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_millis(100));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        let (peer, req_id, action, mut resp_tx) = wait_inbound_request(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(action, Action::TimeoutOnReadResponse);

        resp_tx.send(Action::TimeoutOnReadResponse).await.unwrap();

        let (peer, req_id_done, error) = wait_inbound_failure(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(req_id_done, req_id);
        assert!(matches!(error, InboundFailure::Timeout));

        // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed` instead
        wait_no_events(&mut swarm1).await;
    };

    // Expects OutboundFailure::Timeout
    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::TimeoutOnReadResponse);

        let (peer, req_id_done, mut resp_rx) =
            wait_outbound_request_sent_awaiting_responses(&mut swarm2)
                .await
                .unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(resp_rx.next().await.is_none());

        let (peer, req_id_done, error) = wait_outbound_failure(&mut swarm2).await.unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);
        assert!(matches!(error, OutboundFailure::Timeout));
    };

    let server_task = pin!(server_task);
    let client_task = pin!(client_task);
    futures::future::select(server_task, client_task).await;
}

#[tokio::test]
async fn report_inbound_failure_on_read_request() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (peer1_id, mut swarm1) = new_swarm();
    let (peer2_id, mut swarm2) = new_swarm();

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    // Expects no events because `Event::Request` is produced after `read_request`.
    // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed` instead.
    let server_task = wait_no_events(&mut swarm1);

    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::FailOnReadRequest);

        let (peer, req_id_done, mut resp_rx) =
            wait_outbound_request_sent_awaiting_responses(&mut swarm2)
                .await
                .unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(resp_rx.next().await.is_none());

        let (peer, req_id_done) = wait_inbound_response_stream_closed(&mut swarm2)
            .await
            .unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);
    };

    let server_task = pin!(server_task);
    let client_task = pin!(client_task);
    futures::future::select(server_task, client_task).await;
}

#[tokio::test]
async fn report_inbound_failure_on_write_response() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (peer1_id, mut swarm1) = new_swarm();
    let (peer2_id, mut swarm2) = new_swarm();

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        let (peer, req_id, action, mut resp_tx) = wait_inbound_request(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(action, Action::FailOnWriteResponse);

        resp_tx.send(Action::FailOnWriteResponse).await.unwrap();

        let (peer, req_id_done, error) = wait_inbound_failure(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(req_id_done, req_id);

        let error = match error {
            InboundFailure::Io(e) => e,
            e => panic!("Unexpected error: {e:?}"),
        };

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error.into_inner().unwrap().to_string(),
            "FailOnWriteResponse"
        );

        wait_no_events(&mut swarm1).await;
    };

    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::FailOnWriteResponse);

        let (peer, req_id_done, mut resp_rx) =
            wait_outbound_request_sent_awaiting_responses(&mut swarm2)
                .await
                .unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(resp_rx.next().await.is_none());

        // We cannot know if writing response failed or there was no response written at all.
        wait_inbound_response_stream_closed(&mut swarm2)
            .await
            .unwrap();
    };

    let server_task = pin!(server_task);
    let client_task = pin!(client_task);
    futures::future::select(server_task, client_task).await;
}

#[tokio::test]
async fn report_inbound_timeout_on_write_response() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // `swarm2` needs to have a bigger timeout to avoid racing
    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_millis(100));
    let (peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_millis(200));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        let (peer, req_id, action, mut resp_channel) =
            wait_inbound_request(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(action, Action::TimeoutOnWriteResponse);

        resp_channel
            .send(Action::TimeoutOnWriteResponse)
            .await
            .unwrap();

        let (peer, req_id_done, error) = wait_inbound_failure(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(req_id_done, req_id);
        assert!(matches!(error, InboundFailure::Timeout));
    };

    // Expects OutboundFailure::ConnectionClosed or io::ErrorKind::UnexpectedEof
    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::TimeoutOnWriteResponse);

        let (peer, req_id_done, mut resp_channel) =
            wait_outbound_request_sent_awaiting_responses(&mut swarm2)
                .await
                .unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(resp_channel.next().await.is_none());

        let (peer, req_id_done, error) = wait_outbound_failure(&mut swarm2).await.unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        match error {
            OutboundFailure::ConnectionClosed => {
                // ConnectionClosed is allowed here because we mainly test the behavior
                // of `server_task`.
            }
            OutboundFailure::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
            e => panic!("Unexpected error: {e:?}"),
        }

        // Keep alive the task, so only `server_task` can finish
        wait_no_events(&mut swarm2).await;
    };

    let server_task = pin!(server_task);
    let client_task = pin!(client_task);
    futures::future::select(server_task, client_task).await;
}

#[tokio::test]
async fn report_outbound_timeout_on_write_request() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // `swarm1` needs to have a bigger timeout to avoid racing
    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_millis(200));
    let (_peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_millis(100));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    // Expects no events because `Event::Request` is produced after `read_request`.
    // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed` instead.
    let server_task = wait_no_events(&mut swarm1);

    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::TimeoutOnWriteRequest);

        let (peer, req_id_done, error) = wait_outbound_failure(&mut swarm2).await.unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(matches!(error, OutboundFailure::Timeout));
    };

    let server_task = pin!(server_task);
    let client_task = pin!(client_task);
    futures::future::select(server_task, client_task).await;
}

#[tokio::test]
async fn report_inbound_timeout_on_read_request() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // `swarm2` needs to have a bigger timeout to avoid racing
    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_millis(100));
    let (peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_millis(200));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        let (peer, _req_id_done, error) = wait_inbound_failure(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert!(matches!(error, InboundFailure::Timeout));
    };

    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::TimeoutOnReadRequest);

        let (peer, req_id_done, mut resp_channel) =
            wait_outbound_request_sent_awaiting_responses(&mut swarm2)
                .await
                .unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(resp_channel.next().await.is_none());

        wait_inbound_response_stream_closed(&mut swarm2)
            .await
            .unwrap();
    };

    loop {
        tokio::select! {
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
