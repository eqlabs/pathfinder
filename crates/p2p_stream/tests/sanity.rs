use fake::Fake;
use futures::{pin_mut, prelude::*};
use libp2p::PeerId;
use libp2p_swarm_test::SwarmExt;
use rstest::rstest;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

mod utils;

use utils::{
    new_swarm_with_timeout, wait_inbound_request, wait_inbound_response_stream_closed,
    wait_outbound_request_accepted_awaiting_responses, wait_outbound_response_stream_closed,
    Action, TestSwarm,
};

struct Requestor {
    peer_id: PeerId,
    swarm: TestSwarm,
}

struct Responder {
    peer_id: PeerId,
    swarm: TestSwarm,
}

struct Scenario {
    requestor: Requestor,
    responder: Responder,
}

// peer1 is the server, peer2 is the client
async fn setup() -> (PeerId, TestSwarm, PeerId, TestSwarm) {
    let (srv_peer_id, mut srv_swarm) = new_swarm_with_timeout(Duration::from_secs(10));
    let (cli_peer_id, mut cli_swarm) = new_swarm_with_timeout(Duration::from_secs(10));

    srv_swarm.listen().with_memory_addr_external().await;
    cli_swarm.connect(&mut srv_swarm).await;

    (srv_peer_id, srv_swarm, cli_peer_id, cli_swarm)
}

async fn client_request_to_server() -> Scenario {
    let (srv_peer_id, srv_swarm, cli_peer_id, cli_swarm) = setup().await;

    Scenario {
        requestor: Requestor {
            peer_id: cli_peer_id,
            swarm: cli_swarm,
        },
        responder: Responder {
            peer_id: srv_peer_id,
            swarm: srv_swarm,
        },
    }
}

async fn server_request_to_client() -> Scenario {
    let (srv_peer_id, srv_swarm, cli_peer_id, cli_swarm) = setup().await;

    Scenario {
        requestor: Requestor {
            peer_id: srv_peer_id,
            swarm: srv_swarm,
        },
        responder: Responder {
            peer_id: cli_peer_id,
            swarm: cli_swarm,
        },
    }
}

#[rstest]
#[case::client_request_to_server(client_request_to_server())]
#[case::server_request_to_client(server_request_to_client())]
#[tokio::test]
async fn sanity(
    #[values(0, 1, (2..100000).fake())] num_responses: usize,
    #[case]
    #[future]
    scenario: Scenario,
) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let Scenario {
        mut requestor,
        mut responder,
    } = scenario.await;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let responder_task = async move {
        let (peer, req_id, action, mut resp_tx) =
            wait_inbound_request(&mut responder.swarm).await.unwrap();

        assert_eq!(peer, requestor.peer_id);
        assert_eq!(action, Action::SanityRequest);

        for i in 0..num_responses {
            resp_tx
                .send(Action::SanityResponse(i as u32))
                .await
                .unwrap();
        }

        // Force close the stream
        drop(resp_tx);

        let (peer, req_id_done) = wait_outbound_response_stream_closed(&mut responder.swarm)
            .await
            .unwrap();

        assert_eq!(peer, requestor.peer_id);
        assert_eq!(req_id_done, req_id);
    };

    let requestor_task = async move {
        let req_id = requestor
            .swarm
            .behaviour_mut()
            .send_request(&responder.peer_id, Action::SanityRequest);

        let (peer, req_id_done, mut resp_rx) =
            wait_outbound_request_accepted_awaiting_responses(&mut requestor.swarm)
                .await
                .unwrap();

        assert_eq!(peer, responder.peer_id);
        assert_eq!(req_id_done, req_id);

        for i in 0..num_responses {
            assert_eq!(
                resp_rx.next().await.unwrap(),
                Action::SanityResponse(i as u32)
            );
        }

        let (peer, req_id_done) = wait_inbound_response_stream_closed(&mut requestor.swarm)
            .await
            .unwrap();

        assert_eq!(peer, responder.peer_id);
        assert_eq!(req_id_done, req_id);
    };

    let server_task = responder_task.fuse();
    let client_task = requestor_task.fuse();

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
