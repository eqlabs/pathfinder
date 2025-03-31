use std::fmt::Debug;

use fake::{Fake, Faker};
use futures::SinkExt;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use rstest::rstest;
use tokio::sync::mpsc;

use crate::sync::Event;
use crate::test_utils::peer::TestPeer;
use crate::test_utils::{consume_all_events_forever, filter_events};

async fn create_peers() -> (TestPeer, TestPeer) {
    let mut server = TestPeer::default();
    let client = TestPeer::default();

    let server_addr = server.start_listening().await.unwrap();

    tracing::info!(%server.peer_id, %server_addr, "Server");
    tracing::info!(%client.peer_id, "Client");

    client
        .client
        .dial(server.peer_id, server_addr)
        .await
        .unwrap();

    (server, client)
}

async fn server_to_client() -> (TestPeer, TestPeer) {
    create_peers().await
}

async fn client_to_server() -> (TestPeer, TestPeer) {
    let (s, c) = create_peers().await;
    (c, s)
}

mod successful_sync {
    use super::*;

    /// Defines a test case named [`$test_name`], where there are 2 peers:
    /// - peer2 sends a request to peer1
    /// - peer1 responds with a random number of responses
    /// - request is of type [`$req_type`] and is sent using [`$req_fn`]
    /// - response is of type [`$res_type`]
    /// - [`$event_variant`] is the event that tells peer1 that it received
    ///   peer2's request
    macro_rules! define_test {
        ($test_name:ident, $req_type:ty, $res_type:ty, $event_variant:ident, $req_fn:ident) => {
            #[rstest]
            #[case::server_to_client(server_to_client().await)]
            #[case::client_to_server(client_to_server().await)]
            #[test_log::test(tokio::test)]
            async fn $test_name(#[case] peers: (TestPeer, TestPeer)) {
                let (peer1, peer2) = peers;
                // Fake some request for peer2 to send to peer1
                let expected_request = Faker.fake::<$req_type>();

                // Filter peer1's events to fish out the request from peer2 and the channel that
                // peer1 will use to send the responses
                // This is also to keep peer1's event loop going
                let mut tx_ready =
                    filter_events(peer1.app_event_receiver, move |event| match event {
                        Event::$event_variant {
                            from,
                            channel,
                            request: actual_request,
                        } => {
                            // Peer 1 should receive the request from peer2
                            assert_eq!(from, peer2.peer_id);
                            // Received request should match what peer2 sent
                            assert_eq!(expected_request, actual_request);
                            Some(channel)
                        }
                        _ => None,
                    });

                // This is to keep peer2's event loop going
                consume_all_events_forever(peer2.app_event_receiver);

                // Peer2 sends the request to peer1, and waits for the response receiver
                let mut rx = peer2
                    .client
                    .app_client()
                    .$req_fn(peer1.peer_id, expected_request)
                    .await
                    .expect(&format!(
                        "sending request using: {}, line: {}",
                        std::stringify!($req_fn),
                        line!()
                    ));

                // Peer1 waits for response channel to be ready
                let mut tx = tx_ready.recv().await.expect(&format!(
                    "waiting for response channel to be ready, line: {}",
                    line!()
                ));

                // Peer1 sends a random number of responses to Peer2
                for _ in 0usize..(1..100).fake() {
                    let expected_response = Faker.fake::<$res_type>();
                    // Peer1 sends the response
                    tx.send(expected_response.clone())
                        .await
                        .expect(&format!("sending expected response, line: {}", line!()));
                    // Peer2 waits for the response
                    let actual_response = rx
                        .next()
                        .await
                        .expect(&format!("receiving actual response, line: {}", line!()))
                        .expect(&format!("response should be Ok(), line: {}", line!()));
                    // See if they match
                    assert_eq!(
                        expected_response,
                        actual_response,
                        "response mismatch, line: {}",
                        line!()
                    );
                }
            }
        };
    }

    define_test!(
        sync_headers,
        BlockHeadersRequest,
        BlockHeadersResponse,
        InboundHeadersRequest,
        send_headers_sync_request
    );

    define_test!(
        sync_classes,
        ClassesRequest,
        ClassesResponse,
        InboundClassesRequest,
        send_classes_sync_request
    );

    define_test!(
        sync_state_diffs,
        StateDiffsRequest,
        StateDiffsResponse,
        InboundStateDiffsRequest,
        send_state_diffs_sync_request
    );

    define_test!(
        sync_transactions,
        TransactionsRequest,
        TransactionsResponse,
        InboundTransactionsRequest,
        send_transactions_sync_request
    );

    define_test!(
        sync_events,
        EventsRequest,
        EventsResponse,
        InboundEventsRequest,
        send_events_sync_request
    );
}

#[cfg(fixme)]
mod propagate_codec_errors_to_caller {
    use super::*;
    use crate::test_utils::sync::TypeErasedReadFactory;

    enum BadPeer {
        Server,
        Client,
    }

    enum BadCodec {
        Headers,
        Transactions,
        StateDiffs,
        Classes,
        Events,
    }

    fn error_factory<T>() -> TypeErasedReadFactory<T> {
        Box::new(|| {
            Box::new(|_| {
                async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "stream error",
                    ))
                }
                .boxed()
            })
        })
    }

    async fn create_peers(bad_peer: BadPeer, bad_codec: BadCodec) -> (TestPeer, TestPeer) {
        let good = TestPeer::default();

        let keypair = Keypair::generate_ed25519();
        let cfg = Config::for_test();
        let chain_id = ChainId::SEPOLIA_TESTNET;

        let bb = crate::behaviour::Builder::new(keypair.clone(), chain_id, cfg.clone());
        let bb = match bad_codec {
            BadCodec::Headers => bb.header_sync_behaviour(p2p_stream::Behaviour::with_codec(
                codec::Headers::for_test().set_read_response_factory(error_factory()),
                Default::default(),
            )),
            BadCodec::Transactions => {
                bb.transaction_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::Transactions::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
            BadCodec::StateDiffs => {
                bb.state_diff_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::StateDiffs::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
            BadCodec::Classes => bb.class_sync_behaviour(p2p_stream::Behaviour::with_codec(
                codec::Classes::for_test().set_read_response_factory(error_factory()),
                Default::default(),
            )),
            BadCodec::Events => bb.event_sync_behaviour(p2p_stream::Behaviour::with_codec(
                codec::Events::for_test().set_read_response_factory(error_factory()),
                Default::default(),
            )),
        };

        let p2p_builder =
            crate::Builder::new(keypair.clone(), cfg.clone(), chain_id).behaviour_builder(bb);
        let bad = TestPeer::builder()
            .keypair(keypair)
            .p2p_builder(p2p_builder)
            .build(cfg);

        let (mut server, client) = match bad_peer {
            BadPeer::Server => (bad, good),
            BadPeer::Client => (good, bad),
        };

        let server_addr = server.start_listening().await.unwrap();

        tracing::info!(%server.peer_id, %server_addr, "Server");
        tracing::info!(%client.peer_id, "Client");

        client
            .client
            .dial(server.peer_id, server_addr)
            .await
            .unwrap();

        (server, client)
    }

    async fn server_to_bad_client(bad_codec: BadCodec) -> (TestPeer, TestPeer) {
        create_peers(BadPeer::Client, bad_codec).await
    }

    async fn client_to_bad_server(bad_codec: BadCodec) -> (TestPeer, TestPeer) {
        let (s, c) = create_peers(BadPeer::Server, bad_codec).await;
        (c, s)
    }

    /// Defines a test case named [`$test_name`], where there are 2 peers:
    /// - peer2 sends a request to peer1
    /// - peer1 responds with a random response
    /// - peer2's codec is mocked to fail upon reception, simulating peer1
    ///   sending garbage in response
    /// - request is of type [`$req_type`] and is sent using [`$req_fn`]
    /// - response is of type [`$res_type`]
    /// - [`$event_variant`] is the event that tells peer1 that it received
    ///   peer2's request
    /// - [`$bad_codec`] is the codec that will be mocked to fail upon reception
    macro_rules! define_test {
        ($test_name:ident, $req_type:ty, $res_type:ty, $event_variant:ident, $req_fn:ident, $bad_codec:expr) => {
            #[rstest]
            #[case::server_to_client(server_to_bad_client($bad_codec).await)]
            #[case::client_to_server(client_to_bad_server($bad_codec).await)]
            #[test_log::test(tokio::test)]
            async fn $test_name(#[case] peers: (TestPeer, TestPeer)) {
                let (peer1, peer2) = peers;

                // Fake some request for peer2 to send to peer1
                let expected_request = Faker.fake::<$req_type>();

                // Filter peer1's events to fish out the request from peer2 and the channel that
                // peer1 will use to send the responses
                // This is also to keep peer1's event loop going
                let mut tx_ready = filter_events(peer1.app_event_receiver, move |event| match event {
                    Event::$event_variant {
                        from,
                        channel,
                        request: actual_request,
                    } => {
                        // Peer 1 should receive the request from peer2
                        assert_eq!(from, peer2.peer_id);
                        // Received request should match what peer2 sent
                        assert_eq!(expected_request, actual_request);
                        Some(channel)
                    }
                    _ => None,
                });

                // This is to keep peer2's event loop going
                consume_all_events_forever(peer2.app_event_receiver);

                // Peer2 sends the request to peer1, and waits for the response receiver
                let mut rx = peer2
                    .client
                    .app_client()
                    .$req_fn(peer1.peer_id, expected_request)
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "sending request using: {}, line: {}",
                            std::stringify!($req_fn),
                            // "TODO",
                            line!()
                        )
                    });

                // Peer1 waits for response channel to be ready
                let mut tx = tx_ready.recv().await.unwrap_or_else(|| {
                    panic!(
                        "waiting for response channel to be ready, line: {}",
                        line!()
                    )
                });

                let expected_response = Faker.fake::<$res_type>();
                // Peer1 sends 1 response, but peer2's codec is mocked to fail upon reception
                // simulating peer1 sending garbage in response
                tx.send(expected_response.clone())
                    .await
                    .unwrap_or_else(|_| panic!("sending expected response, line: {}", line!()));

                // Peer2 waits for the response
                let actual_response = rx.next().await.unwrap();
                eprintln!("actual_response {:?}", actual_response);
                assert!(
                    matches!(actual_response, Err(e) if e.kind() == std::io::ErrorKind::Other && e.to_string() == "stream error")
                );
            }
        };
    }

    define_test!(
        sync_headers,
        BlockHeadersRequest,
        BlockHeadersResponse,
        InboundHeadersRequest,
        send_headers_sync_request,
        BadCodec::Headers
    );

    define_test!(
        sync_classes,
        ClassesRequest,
        ClassesResponse,
        InboundClassesRequest,
        send_classes_sync_request,
        BadCodec::Classes
    );

    define_test!(
        sync_state_diffs,
        StateDiffsRequest,
        StateDiffsResponse,
        InboundStateDiffsRequest,
        send_state_diffs_sync_request,
        BadCodec::StateDiffs
    );

    define_test!(
        sync_transactions,
        TransactionsRequest,
        TransactionsResponse,
        InboundTransactionsRequest,
        send_transactions_sync_request,
        BadCodec::Transactions
    );

    define_test!(
        sync_events,
        EventsRequest,
        EventsResponse,
        InboundEventsRequest,
        send_events_sync_request,
        BadCodec::Events
    );
}
