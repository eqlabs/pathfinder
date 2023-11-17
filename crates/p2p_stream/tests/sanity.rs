use fake::Fake;
use futures::{pin_mut, prelude::*};
use libp2p_swarm_test::SwarmExt;
use rstest::rstest;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

mod utils;

use utils::{
    new_swarm_with_timeout, wait_inbound_request, wait_inbound_response_stream_closed,
    wait_outbound_request_accepted_awaiting_responses, wait_outbound_response_stream_closed,
    Action,
};

#[rstest]
#[tokio::test]
async fn sanity(#[values(0, 1, (2..100000).fake())] num_responses: usize) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (peer1_id, mut swarm1) = new_swarm_with_timeout(Duration::from_secs(10));
    let (peer2_id, mut swarm2) = new_swarm_with_timeout(Duration::from_secs(10));

    swarm1.listen().with_memory_addr_external().await;
    swarm2.connect(&mut swarm1).await;

    let server_task = async move {
        let (peer, req_id, action, mut resp_channel) =
            wait_inbound_request(&mut swarm1).await.unwrap();

        assert_eq!(peer, peer2_id);
        assert_eq!(action, Action::SanityRequest);

        for i in 0..num_responses {
            resp_channel
                .send(Action::SanityResponse(i as u32))
                .await
                .unwrap();
        }

        // Force close the stream
        drop(resp_channel);

        let (peer, req_id_done) = wait_outbound_response_stream_closed(&mut swarm1)
            .await
            .unwrap();

        assert_eq!(peer, peer2_id);
        assert_eq!(req_id_done, req_id);
    };

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

        for i in 0..num_responses {
            assert_eq!(
                resp_channel.next().await.unwrap(),
                Action::SanityResponse(i as u32)
            );
        }

        let (peer, req_id_done) = wait_inbound_response_stream_closed(&mut swarm2)
            .await
            .unwrap();

        assert_eq!(peer, peer1_id);
        assert_eq!(req_id_done, req_id);
    };

    let server_task = server_task.fuse();
    let client_task = client_task.fuse();

    pin_mut!(server_task);
    pin_mut!(client_task);

    loop {
        futures::select! {
            _ = server_task => {
                break;
            },
            _ = client_task => {
                break;
            },
        }
    }
}
