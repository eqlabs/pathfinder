use std::time::Duration;

use fake::Fake;
use futures::prelude::*;
use libp2p::PeerId;
use libp2p_swarm_test::SwarmExt;
use rstest::rstest;

pub mod utils;

use utils::{
    new_swarm_with_timeout,
    wait_inbound_request,
    wait_inbound_response_stream_closed,
    wait_outbound_request_sent_awaiting_responses,
    wait_outbound_response_stream_closed,
    Action,
    TestSwarm,
};

struct Requester {
    peer_id: PeerId,
    swarm: TestSwarm,
}

struct Responder {
    peer_id: PeerId,
    swarm: TestSwarm,
}

struct Scenario {
    requester: Requester,
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
        requester: Requester {
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
        requester: Requester {
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
#[test_log::test(tokio::test)]
async fn sanity(
    #[values(0, 1, (2..10000).fake())] num_responses: usize,
    #[case]
    #[future]
    scenario: Scenario,
) {
    let Scenario {
        mut requester,
        mut responder,
    } = scenario.await;

    let responder_task = async move {
        let (peer, req_id, action, mut resp_tx) =
            wait_inbound_request(&mut responder.swarm).await.unwrap();

        assert_eq!(peer, requester.peer_id);
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

        assert_eq!(peer, requester.peer_id);
        assert_eq!(req_id_done, req_id);
    };

    let requester_task = async move {
        let req_id = requester
            .swarm
            .behaviour_mut()
            .send_request(&responder.peer_id, Action::SanityRequest);

        let (peer, req_id_done, mut resp_rx) =
            wait_outbound_request_sent_awaiting_responses(&mut requester.swarm)
                .await
                .unwrap();

        assert_eq!(peer, responder.peer_id);
        assert_eq!(req_id_done, req_id);

        for i in 0..num_responses {
            assert_eq!(
                resp_rx.next().await.unwrap().unwrap(),
                Action::SanityResponse(i as u32)
            );
        }

        let (peer, req_id_done) = wait_inbound_response_stream_closed(&mut requester.swarm)
            .await
            .unwrap();

        assert_eq!(peer, responder.peer_id);
        assert_eq!(req_id_done, req_id);
    };

    tokio::join!(responder_task, requester_task);
}
