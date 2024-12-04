use std::io;
use std::time::Duration;

use futures::prelude::*;
use libp2p_swarm_test::SwarmExt;
use p2p_stream::{InboundFailure, OutboundFailure};

pub mod utils;

use utils::{
    new_swarm,
    new_swarm_with_timeout,
    wait_inbound_failure,
    wait_inbound_request,
    wait_inbound_response_stream_closed,
    wait_no_events,
    wait_outbound_failure,
    wait_outbound_request_sent_awaiting_responses,
    Action,
};

#[test_log::test(tokio::test)]
async fn report_outbound_failure_on_read_response_failure() {
    let (peer1_id, mut swarm1) = new_swarm();
    let (peer2_id, mut swarm2) = new_swarm();

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        let (peer, req_id, action, mut resp_channel) =
            wait_inbound_request(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(action, Action::FailOnReadResponse);

        resp_channel.send(Action::FailOnReadResponse).await.unwrap();

        // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed`
        // instead Wait for swarm2 disconnecting
        let (peer, req_id_done, error) = wait_inbound_failure(&mut swarm1).await.unwrap();
        assert_eq!(peer, peer2_id);
        assert_eq!(req_id_done, req_id);
        assert!(matches!(error, InboundFailure::ConnectionClosed));
    };

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

        assert!(
            matches!(resp_channel.next().await, Some(Err(x)) if x.kind() == io::ErrorKind::Other && x.to_string() == "FailOnReadResponse")
        );

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

    // Make sure both run to completion
    tokio::join!(server_task, client_task);
}

#[test_log::test(tokio::test)]
async fn report_outbound_failure_on_write_request_failure() {
    let (peer1_id, mut swarm1) = new_swarm();
    let (_peer2_id, mut swarm2) = new_swarm();

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    // Expects no events because `Event::Request` is produced after `read_request`.
    // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed`
    // instead.
    let server_task = async move {
        wait_no_events(&mut swarm1).await;
    };

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

    // Server should always "outrun" the client
    tokio::spawn(server_task);

    // Make sure client runs to completion
    client_task.await;
}

#[test_log::test(tokio::test)]
async fn report_outbound_timeout_on_read_response_timeout() {
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
        assert!(matches!(error, InboundFailure::ConnectionClosed));
    };

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

    // Make sure both run to completion
    tokio::join!(server_task, client_task);
}

#[test_log::test(tokio::test)]
async fn report_inbound_closure_on_read_request_failure() {
    let (peer1_id, mut swarm1) = new_swarm();
    let (_peer2_id, mut swarm2) = new_swarm();

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    // Expects no events because `Event::IncomingRequest` is produced after
    // `read_request`. Keep the connection alive, otherwise swarm2 may receive
    // `ConnectionClosed` instead.
    let server_task = async move {
        wait_no_events(&mut swarm1).await;
    };

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

    // Server should always "outrun" the client
    tokio::spawn(server_task);

    // Make sure client runs to completion
    client_task.await;
}

#[test_log::test(tokio::test)]
async fn report_inbound_failure_on_write_response_failure() {
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

        // We cannot know if writing response failed or there was no response written at
        // all.
        wait_inbound_response_stream_closed(&mut swarm2)
            .await
            .unwrap();
    };

    // Make sure both run to completion
    tokio::join!(client_task, server_task);
}

#[test_log::test(tokio::test)]
async fn report_inbound_timeout_on_write_response_timeout() {
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

        let (peer, req_id_done) = wait_inbound_response_stream_closed(&mut swarm2)
            .await
            .unwrap();

        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);
    };

    // Make sure both run to completion
    tokio::join!(client_task, server_task);
}

#[test_log::test(tokio::test)]
async fn report_outbound_timeout_on_write_request_timeout() {
    // `swarm1` needs to have a bigger timeout to avoid racing
    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_millis(200));
    let (_peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_millis(100));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    // Expects no events because `Event::Request` is produced after `read_request`.
    // Keep the connection alive, otherwise swarm2 may receive `ConnectionClosed`
    // instead.
    let server_task = async move {
        wait_no_events(&mut swarm1).await;
    };

    let client_task = async move {
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&peer1_id, Action::TimeoutOnWriteRequest);

        let (peer, req_id_done, error) = wait_outbound_failure(&mut swarm2).await.unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);

        assert!(matches!(error, OutboundFailure::Timeout));
    };

    // Server should always "outrun" the client
    tokio::spawn(server_task);

    // Make sure client runs to completion
    client_task.await;
}

#[test_log::test(tokio::test)]
async fn report_outbound_timeout_on_read_request_timeout() {
    // `swarm2` needs to have a bigger timeout to avoid racing
    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_millis(200));
    let (_peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_millis(100));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        wait_no_events(&mut swarm1).await;
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

        let (peer, req_id_done, error) = wait_outbound_failure(&mut swarm2).await.unwrap();
        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);
        assert!(matches!(error, OutboundFailure::Timeout));
    };

    // Server should always "outrun" the client
    tokio::spawn(server_task);

    // Make sure client runs to completion
    client_task.await;
}
