use futures::prelude::*;
use libp2p_swarm_test::SwarmExt;
use p2p_stream::OutboundFailure;
use std::{io, pin::pin};
use tracing_subscriber::EnvFilter;

mod utils;

use utils::{
    new_swarm, wait_inbound_request, wait_no_events, wait_outbound_failure,
    wait_outbound_request_accepted_awaiting_responses, Action,
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
            wait_outbound_request_accepted_awaiting_responses(&mut swarm2)
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
