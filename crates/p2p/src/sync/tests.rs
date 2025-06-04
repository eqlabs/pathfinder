use fake::{Fake, Faker};
use futures::{FutureExt, SinkExt, StreamExt};
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use rstest::rstest;

use crate::sync::behaviour::Behaviour;
use crate::sync::client::Client;
use crate::sync::protocol::codec;
use crate::sync::{Config, Event};
use crate::test_utils::peer::TestPeerBuilder;
use crate::test_utils::{consume_all_events_forever, filter_events};

type SyncTestPeer = crate::test_utils::peer::TestPeer<Behaviour>;

fn create_peer() -> SyncTestPeer {
    TestPeerBuilder::new()
        .app_behaviour(Behaviour::new(Config::for_test()))
        .build(crate::core::Config::for_test())
}

async fn create_peers() -> (SyncTestPeer, SyncTestPeer) {
    let mut server = create_peer();
    let client = create_peer();

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

async fn server_to_client() -> (SyncTestPeer, SyncTestPeer) {
    create_peers().await
}

async fn client_to_server() -> (SyncTestPeer, SyncTestPeer) {
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
            async fn $test_name(#[case] peers: (SyncTestPeer, SyncTestPeer)) {
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
                let mut rx = Client::from(peer2.client.as_pair())
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
        send_headers_request
    );

    define_test!(
        sync_classes,
        ClassesRequest,
        ClassesResponse,
        InboundClassesRequest,
        send_classes_request
    );

    define_test!(
        sync_state_diffs,
        StateDiffsRequest,
        StateDiffsResponse,
        InboundStateDiffsRequest,
        send_state_diffs_request
    );

    define_test!(
        sync_transactions,
        TransactionsRequest,
        TransactionsResponse,
        InboundTransactionsRequest,
        send_transactions_request
    );

    define_test!(
        sync_events,
        EventsRequest,
        EventsResponse,
        InboundEventsRequest,
        send_events_request
    );
}

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
        Box::new(|| Box::new(|_| async { Err(std::io::Error::other("stream error")) }.boxed()))
    }

    async fn create_peers(bad_peer: BadPeer, bad_codec: BadCodec) -> (SyncTestPeer, SyncTestPeer) {
        let good = create_peer();

        let sync_behaviour_builder = Behaviour::builder(Config::for_test());
        let sync_behaviour_builder = match bad_codec {
            BadCodec::Headers => {
                sync_behaviour_builder.header_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::Headers::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
            BadCodec::Transactions => sync_behaviour_builder.transaction_sync_behaviour(
                p2p_stream::Behaviour::with_codec(
                    codec::Transactions::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ),
            ),
            BadCodec::StateDiffs => {
                sync_behaviour_builder.state_diff_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::StateDiffs::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
            BadCodec::Classes => {
                sync_behaviour_builder.class_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::Classes::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
            BadCodec::Events => {
                sync_behaviour_builder.event_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::Events::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
        };

        let bad = SyncTestPeer::builder()
            .app_behaviour(sync_behaviour_builder.build())
            .build(crate::core::Config::for_test());

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

    async fn server_to_bad_client(bad_codec: BadCodec) -> (SyncTestPeer, SyncTestPeer) {
        create_peers(BadPeer::Client, bad_codec).await
    }

    async fn client_to_bad_server(bad_codec: BadCodec) -> (SyncTestPeer, SyncTestPeer) {
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
            async fn $test_name(#[case] peers: (SyncTestPeer, SyncTestPeer)) {
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
                let mut rx = Client::from(peer2.client.as_pair())
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
        send_headers_request,
        BadCodec::Headers
    );

    define_test!(
        sync_classes,
        ClassesRequest,
        ClassesResponse,
        InboundClassesRequest,
        send_classes_request,
        BadCodec::Classes
    );

    define_test!(
        sync_state_diffs,
        StateDiffsRequest,
        StateDiffsResponse,
        InboundStateDiffsRequest,
        send_state_diffs_request,
        BadCodec::StateDiffs
    );

    define_test!(
        sync_transactions,
        TransactionsRequest,
        TransactionsResponse,
        InboundTransactionsRequest,
        send_transactions_request,
        BadCodec::Transactions
    );

    define_test!(
        sync_events,
        EventsRequest,
        EventsResponse,
        InboundEventsRequest,
        send_events_request,
        BadCodec::Events
    );
}
