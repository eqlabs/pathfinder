use futures::{stream, TryStreamExt};
use rstest::rstest;
use BlockHeadersResponse::Fin as HdrFin;
use ClassesResponse::Fin as ClassFin;
use EventsResponse::Fin as EventFin;
use StateDiffsResponse::Fin as SDFin;
use TransactionsResponse::Fin as TxnFin;

use super::*;
use crate::client::peer_agnostic::fixtures::*;

#[rstest]
#[case::one_peer_1_block(
    1,
    // Simulated responses
    vec![Ok((peer(0), vec![hdr_resp(0), HdrFin]))],
    // Expected stream
    vec![(peer(0), hdr(0))]
)]
#[case::one_peer_2_blocks(
    // Peer gives responses for all blocks in one go
    2,
    vec![Ok((peer(0), vec![hdr_resp(1), hdr_resp(2), HdrFin]))],
    vec![
        (peer(0), hdr(1)), // block 0
        (peer(0), hdr(2))  // block 1
    ]
)]
#[case::one_peer_2_blocks_in_2_attempts(
    // Peer gives a response for the second block after a retry
    2,
    vec![
        Ok((peer(0), vec![hdr_resp(3), HdrFin])),
        Ok((peer(0), vec![hdr_resp(4), HdrFin])),
    ],
    vec![
        (peer(0), hdr(3)),
        (peer(0), hdr(4))
    ]
)]
#[case::two_peers_1_block_per_peer(
    2,
    vec![
        // Errors are ignored
        Err(peer(1)),
        Ok((peer(0), vec![hdr_resp(5), HdrFin])),
        Err(peer(0)),
        Ok((peer(1), vec![hdr_resp(6), HdrFin]))
    ],
    vec![
        (peer(0), hdr(5)),
        (peer(1), hdr(6))
    ]
)]
#[case::first_peer_full_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 but no fin
        Ok((peer(0), vec![hdr_resp(7)])),
        Ok((peer(1), vec![hdr_resp(8), HdrFin]))
    ],
    vec![
        // We assume this block 0 could be correct
        (peer(0), hdr(7)), // block 0
        (peer(1), hdr(8))  // block 1
    ]
)]
#[case::last_peer_full_block_no_fin(
    2,
    vec![
        Ok((peer(0), vec![hdr_resp(7), HdrFin])),
        // Last peer gives full block 1 but no fin
        Ok((peer(1), vec![hdr_resp(8)]))
    ],
    vec![
        // We assume this block 0 could be correct
        (peer(0), hdr(7)), // block 0
        (peer(1), hdr(8))  // block 1
    ]
)]
#[case::too_many_responses_with_fin(
    1,
    vec![Ok((peer(0), vec![hdr_resp(9), hdr_resp(10), HdrFin]))],
    vec![(peer(0), hdr(9))]
)]
#[case::too_many_responses_no_fin(
    1,
    vec![Ok((peer(0), vec![hdr_resp(9), hdr_resp(10), hdr_resp(11)]))],
    vec![(peer(0), hdr(9))]
)]
#[case::empty_response_streams_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![])),
        Ok((peer(1), vec![hdr_resp(11), HdrFin])),
        Ok((peer(2), vec![]))
    ],
    vec![(peer(1), hdr(11))]
)]
#[case::empty_responses_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![HdrFin])),
        Ok((peer(1), vec![hdr_resp(11), HdrFin])),
        Ok((peer(2), vec![HdrFin]))
    ],
    vec![(peer(1), hdr(11))]
)]
#[test_log::test(tokio::test)]
async fn make_header_stream(
    #[case] num_blocks: usize,
    #[case] responses: Vec<Result<(TestPeer, Vec<BlockHeadersResponse>), TestPeer>>,
    #[case] expected_stream: Vec<(TestPeer, SignedBlockHeader)>,
) {
    let _ = env_logger::builder().is_test(true).try_init();

    for (reverse, direction) in [(false, "forward"), (true, "backward")] {
        let (peers, responses) = unzip_fixtures(responses.clone());
        let get_peers = move || {
            let peers = peers.clone();
            async move { peers }
        };
        let send_request = move |_: PeerId, _: BlockHeadersRequest| {
            let responses = responses.clone();
            async move { send_request(responses).await }
        };
        let start = BlockNumber::GENESIS;
        let stop = start + (num_blocks - 1) as u64;

        let actual = super::header_stream::make(start, stop, reverse, get_peers, send_request)
            .map(|x| (TestPeer(x.peer), x.data))
            .collect::<Vec<_>>()
            .await;

        pretty_assertions_sorted::assert_eq!(actual, expected_stream, "Direction: {}", direction);
    }
}

#[rstest]
#[case::one_peer_1_block(
    1,
    // Simulated responses
    //                    transaction  transaction index
    //                              |  |
    vec![Ok((peer(0), vec![txn_resp(0, 0), txn_resp(1, 1), TxnFin]))],
    // Expected number of transactions per block
    vec![2],
    // Expected stream
    //               transaction  transaction index
    //                         |  |
    vec![Ok((peer(0), vec![txn(0, 0), txn(1, 1)]))]
)]
#[case::one_peer_2_blocks(
    // Peer gives responses for all blocks in one go
    2,
    vec![Ok((peer(0), vec![txn_resp(2, 0), txn_resp(3, 0), TxnFin]))],
    vec![1, 1],
    vec![
        Ok((peer(0), vec![txn(2, 0)])), // block 0
        Ok((peer(0), vec![txn(3, 0)]))  // block 1
    ]
)]
#[case::one_peer_2_blocks_in_2_attempts(
    // Peer gives a response for the second block after a retry
    2,
    vec![
        Ok((peer(0), vec![txn_resp(4, 0), TxnFin])),
        Ok((peer(0), vec![txn_resp(5, 0), TxnFin]))
    ],
    vec![1, 1],
    vec![
        Ok((peer(0), vec![txn(4, 0)])),
        Ok((peer(0), vec![txn(5, 0)]))
    ]
)]
#[case::two_peers_1_block_per_peer(
    2,
    vec![
        // Errors are ignored
        Err(peer(1)),
        Ok((peer(0), vec![txn_resp(6, 0), TxnFin])),
        Err(peer(0)),
        Ok((peer(1), vec![txn_resp(7, 0), TxnFin]))
    ],
    vec![1, 1],
    vec![
        Ok((peer(0), vec![txn(6, 0)])),
        Ok((peer(1), vec![txn(7, 0)]))
    ]
)]
#[case::first_peer_premature_eos_with_fin(
    2,
    vec![
        // First peer gives full block 0 and half of block 1
        Ok((peer(0), vec![txn_resp(8, 0), txn_resp(9, 0), TxnFin])),
        Ok((peer(1), vec![txn_resp(9, 0), txn_resp(10, 1), TxnFin]))
    ],
    vec![1, 2],
    vec![
        Ok((peer(0), vec![txn(8, 0)])),
        Ok((peer(1), vec![txn(9, 0), txn(10, 1)]))
    ]
)]
#[case::first_peer_full_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 but no fin
        Ok((peer(0), vec![txn_resp(11, 0)])),
        Ok((peer(1), vec![txn_resp(12, 0), TxnFin]))
    ],
    vec![1, 1],
    vec![
        // We assume this block 0 could be correct
        Ok((peer(0), vec![txn(11, 0)])), // block 0
        Ok((peer(1), vec![txn(12, 0)]))  // block 1
    ]
)]
#[case::last_peer_full_block_no_fin(
    2,
    vec![
        Ok((peer(0), vec![txn_resp(11, 0), TxnFin])),
        Ok((peer(1), vec![txn_resp(12, 0)]))
    ],
    vec![1, 1],
    vec![
        Ok((peer(0), vec![txn(11, 0)])), // block 0
        Ok((peer(1), vec![txn(12, 0)]))  // block 1
    ]
)]
// The same as above but the first peer gives half of the second block before closing the
// stream
#[case::first_peer_half_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 and partial block 1 but no fin
        Ok((peer(0), vec![txn_resp(13, 0), txn_resp(14, 0)])),
        Ok((peer(1), vec![txn_resp(14, 0), txn_resp(15, 1), TxnFin]))
    ],
    vec![1, 2],
    vec![
        // We assume this block could be correct so we move to the next one
        Ok((peer(0), vec![txn(13, 0)])),            // block 0
        Ok((peer(1), vec![txn(14, 0), txn(15, 1)])) // block 1
    ]
)]
#[case::count_steam_is_too_short(
    2,
    vec![
        // 2 blocks in responses
        Ok((peer(0), vec![txn_resp(16, 0), TxnFin])),
        Ok((peer(0), vec![txn_resp(17, 0), TxnFin]))
    ],
    vec![1], // but only 1 block provided in the count stream
    vec![
        Ok((peer(0), vec![txn(16, 0)])),
        Err(()) // the second block is not processed
    ]
)]
#[case::too_many_responses_with_fin(
    1,
    vec![Ok((peer(0), vec![txn_resp(18, 0), txn_resp(19, 0), TxnFin]))],
    vec![1],
    vec![Ok((peer(0), vec![txn(18, 0)]))]
)]
#[case::too_many_responses_no_fin(
    1,
    vec![Ok((peer(0), vec![txn_resp(18, 0), txn_resp(19, 0)]))],
    vec![1],
    vec![Ok((peer(0), vec![txn(18, 0)]))]
)]
#[case::empty_response_streams_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![])),
        Ok((peer(1), vec![txn_resp(20, 0), TxnFin])),
        Ok((peer(2), vec![]))
    ],
    vec![1],
    vec![Ok((peer(1), vec![txn(20, 0)]))]
)]
#[case::empty_responses_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![TxnFin])),
        Ok((peer(1), vec![txn_resp(20, 0), TxnFin])),
        Ok((peer(2), vec![TxnFin]))
    ],
    vec![1],
    vec![Ok((peer(1), vec![txn(20, 0)]))]
)]
#[test_log::test(tokio::test)]
async fn make_transaction_stream(
    #[case] num_blocks: usize,
    #[case] responses: Vec<Result<(TestPeer, Vec<TransactionsResponse>), TestPeer>>,
    #[case] num_txns_per_block: Vec<usize>,
    #[case] expected_stream: Vec<Result<(TestPeer, Vec<TestTxn>), ()>>,
) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peers, responses) = unzip_fixtures(responses);
    let get_peers = move || {
        let peers = peers.clone();
        async move { peers }
    };
    let send_request = move |_: PeerId, _: TransactionsRequest| {
        let responses = responses.clone();
        async move { send_request(responses).await }
    };

    let start = BlockNumber::GENESIS;
    let stop = start + (num_blocks - 1) as u64;

    let actual = super::transaction_stream::make(
        start,
        stop,
        stream::iter(num_txns_per_block.into_iter().map(Ok)),
        get_peers,
        send_request,
    )
    .map_ok(|x| {
        (
            TestPeer(x.peer),
            x.data.0.into_iter().map(TestTxn::new).collect(),
        )
    })
    .map_err(|_| ())
    .collect::<Vec<_>>()
    .await;

    pretty_assertions_sorted::assert_eq!(actual, expected_stream);
}

#[rstest]
#[case::one_peer_1_block(
    1,
    vec![Ok((peer(0), vec![contract_diff(0), declared_class(0), SDFin]))],
    vec![len(0)],
    vec![Ok((peer(0), state_diff(0)))]
)]
#[case::one_peer_2_blocks(
    2,
    vec![Ok((peer(0), vec![contract_diff(1), declared_class(1), contract_diff(2), declared_class(2), SDFin]))],
    vec![len(1), len(2)],
    vec![
        Ok((peer(0), state_diff(1))),
        Ok((peer(0), state_diff(2)))
    ]
)]
#[case::one_peer_2_blocks_in_2_attempts(
    // Peer gives a response for the second block after a retry
    2,
    vec![
        Ok((peer(0), vec![contract_diff(3), declared_class(3), SDFin])),
        Ok((peer(0), vec![contract_diff(4), declared_class(4), SDFin])),
    ],
    vec![len(3), len(4)],
    vec![
        Ok((peer(0), state_diff(3))),
        Ok((peer(0), state_diff(4)))
    ]
)]
#[case::two_peers_1_block_per_peer(
    2,
    vec![
        // Errors are ignored
        Err(peer(1)),
        Ok((peer(0), vec![contract_diff(5), declared_class(5), SDFin])),
        Err(peer(0)),
        Ok((peer(1), vec![contract_diff(6), declared_class(6), SDFin])),
    ],
    vec![len(5), len(6)],
    vec![
        Ok((peer(0), state_diff(5))),
        Ok((peer(1), state_diff(6)))
    ]
)]
#[case::first_peer_premature_eos_with_fin(
    2,
    vec![
        // First peer gives full block 0 and half of block 1
        Ok((peer(0), vec![contract_diff(7), declared_class(7), contract_diff(8), SDFin])),
        Ok((peer(1), vec![contract_diff(8), declared_class(8), SDFin]))
    ],
    vec![len(7), len(8)],
    vec![
        Ok((peer(0), state_diff(7))),
        Ok((peer(1), state_diff(8)))
    ]
)]
#[case::first_peer_full_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 but no fin
        Ok((peer(0), vec![contract_diff(9), declared_class(9)])),
        Ok((peer(1), vec![contract_diff(10), declared_class(10), SDFin]))
    ],
    vec![len(9), len(10)],
    vec![
        Ok((peer(0), state_diff(9))),
        Ok((peer(1), state_diff(10)))
    ]
)]
#[case::last_peer_full_block_no_fin(
    2,
    vec![
        Ok((peer(0), vec![contract_diff(9), declared_class(9), SDFin])),
        Ok((peer(1), vec![contract_diff(10), declared_class(10)]))
    ],
    vec![len(9), len(10)],
    vec![
        Ok((peer(0), state_diff(9))),
        Ok((peer(1), state_diff(10)))
    ]
)]
// The same as above but the first peer gives half of the second block before closing the
// stream
#[case::first_peer_half_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 and partial block 1 but no fin
        Ok((peer(0), vec![contract_diff(11), declared_class(11), contract_diff(12)])),
        Ok((peer(1), vec![contract_diff(12), declared_class(12), SDFin])),
    ],
    vec![len(11), len(12)],
    vec![
        Ok((peer(0), state_diff(11))),
        Ok((peer(1), state_diff(12)))
    ]
)]
#[case::count_steam_is_too_short(
    2,
    vec![
        // 2 blocks in responses
        Ok((peer(0), vec![contract_diff(13), declared_class(13), SDFin])),
        Ok((peer(0), vec![contract_diff(14), declared_class(14), SDFin]))
    ],
    vec![len(13)], // but only 1 block provided in the count stream
    vec![
        Ok((peer(0), state_diff(13))),
        Err(()) // the second block is not processed
    ]
)]
#[case::too_many_responses_storage_with_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(15), declared_class(15), surplus_storage(), SDFin]))],
    vec![len(15)],
    vec![Ok((peer(0), state_diff(15)))]
)]
#[case::too_many_responses_storage_no_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(15), declared_class(15), surplus_storage()]))],
    vec![len(15)],
    vec![Ok((peer(0), state_diff(15)))]
)]
#[case::too_many_responses_nonce_with_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(16), declared_class(16), surplus_nonce(), SDFin]))],
    vec![len(16)],
    vec![Ok((peer(0), state_diff(16)))]
)]
#[case::too_many_responses_nonce_no_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(16), declared_class(16), surplus_nonce()]))],
    vec![len(16)],
    vec![Ok((peer(0), state_diff(16)))]
)]
#[case::too_many_responses_class_with_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(17), declared_class(17), surplus_class(), SDFin]))],
    vec![len(17)],
    vec![Ok((peer(0), state_diff(17)))]
)]
#[case::too_many_responses_class_no_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(17), declared_class(17), surplus_class()]))],
    vec![len(17)],
    vec![Ok((peer(0), state_diff(17)))]
)]
#[case::too_many_responses_declaration_with_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(18), declared_class(18), declared_class(19), SDFin]))],
    vec![len(18)],
    vec![Ok((peer(0), state_diff(18)))]
)]
#[case::too_many_responses_declaration_no_fin(
    1,
    vec![Ok((peer(0), vec![contract_diff(18), declared_class(18), declared_class(19)]))],
    vec![len(18)],
    vec![Ok((peer(0), state_diff(18)))]
)]
#[case::empty_response_streams_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![])),
        Ok((peer(1), vec![contract_diff(20), declared_class(20), SDFin])),
        Ok((peer(2), vec![]))
    ],
    vec![len(20)],
    vec![Ok((peer(1), state_diff(20)))]
)]
#[case::empty_responses_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![SDFin])),
        Ok((peer(1), vec![contract_diff(20), declared_class(20), SDFin])),
        Ok((peer(2), vec![SDFin]))
    ],
    vec![len(20)],
    vec![Ok((peer(1), state_diff(20)))]
)]
#[test_log::test(tokio::test)]
async fn make_state_diff_stream(
    #[case] num_blocks: usize,
    #[case] responses: Vec<Result<(TestPeer, Vec<StateDiffsResponse>), TestPeer>>,
    #[case] state_diff_len_per_block: Vec<usize>,
    #[case] expected_stream: Vec<Result<(TestPeer, StateUpdateData), ()>>,
) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peers, responses) = unzip_fixtures(responses);
    let get_peers = move || {
        let peers = peers.clone();
        async move { peers }
    };
    let send_request = move |_: PeerId, _: StateDiffsRequest| {
        let responses = responses.clone();
        async move { send_request(responses).await }
    };

    let start = BlockNumber::GENESIS;
    let stop = start + (num_blocks - 1) as u64;

    let actual = super::state_diff_stream::make(
        start,
        stop,
        stream::iter(state_diff_len_per_block.into_iter().map(Ok)),
        get_peers,
        send_request,
    )
    .map_ok(|x| (TestPeer(x.peer), x.data))
    .map_err(|_| ())
    .collect::<Vec<_>>()
    .await;

    let expected = expected_stream
        .into_iter()
        .enumerate()
        .map(|(i, x)| x.map(|(p, su)| (p, (su, BlockNumber::new_or_panic(i as u64)))))
        .collect::<Vec<_>>();

    pretty_assertions_sorted::assert_eq!(actual, expected);
}

#[rstest]
#[case::one_peer_1_block(
    1,
    //                              class
    //                                |
    vec![Ok((peer(0), vec![class_resp(0), ClassFin]))],
    vec![1],
    //                  class  block
    //                      |  |
    vec![Ok((peer(0), class(0, 0)))]
)]
#[case::one_peer_2_blocks(
    2,
    vec![Ok((peer(0), vec![class_resp(1), class_resp(2), ClassFin]))],
    vec![1, 1],
    vec![
        Ok((peer(0), class(1, 0))),
        Ok((peer(0), class(2, 1)))
    ]
)]
#[case::one_peer_2_blocks_in_2_attempts(
    // Peer gives a response for the second block after a retry
    2,
    vec![
        Ok((peer(0), vec![class_resp(3), class_resp(4), ClassFin])),
        Ok((peer(0), vec![class_resp(5), class_resp(6), ClassFin])),
    ],
    vec![2, 2],
    vec![
        Ok((peer(0), class(3, 0))),
        Ok((peer(0), class(4, 0))),
        Ok((peer(0), class(5, 1))),
        Ok((peer(0), class(6, 1)))
    ]
)]
#[case::two_peers_1_block_per_peer(
    2,
    vec![
        // Errors are ignored
        Err(peer(1)),
        Ok((peer(0), vec![class_resp(7), ClassFin])),
        Err(peer(0)),
        Ok((peer(1), vec![class_resp(8), ClassFin])),
    ],
    vec![1, 1],
    vec![
        Ok((peer(0), class(7, 0))),
        Ok((peer(1), class(8, 1)))
    ]
)]
#[case::first_peer_premature_eos_with_fin(
    2,
    vec![
        // First peer gives full block 0 and half of block 1
        Ok((peer(0), vec![class_resp(9), class_resp(10), ClassFin])),
        Ok((peer(1), vec![class_resp(10), class_resp(11), ClassFin]))
    ],
    vec![1, 2],
    vec![
        Ok((peer(0), class(9, 0))),
        Ok((peer(1), class(10, 1))),
        Ok((peer(1), class(11, 1)))
    ]
)]
#[case::first_peer_full_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 but no fin
        Ok((peer(0), vec![class_resp(12), class_resp(13)])),
        Ok((peer(1), vec![class_resp(14), ClassFin]))
    ],
    vec![2, 1],
    vec![
        Ok((peer(0), class(12, 0))),
        Ok((peer(0), class(13, 0))),
        Ok((peer(1), class(14, 1))),
    ]
)]
#[case::last_peer_full_block_no_fin(
    2,
    vec![
        Ok((peer(0), vec![class_resp(12), class_resp(13), ClassFin])),
        Ok((peer(1), vec![class_resp(14)]))
    ],
    vec![2, 1],
    vec![
        Ok((peer(0), class(12, 0))),
        Ok((peer(0), class(13, 0))),
        Ok((peer(1), class(14, 1))),
    ]
)]
// The same as above but the first peer gives half of the second block before closing the
// stream
#[case::first_peer_half_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 and partial block 1 but no fin
        Ok((peer(0), vec![class_resp(15), class_resp(16), class_resp(17)])),
        Ok((peer(1), vec![class_resp(16), class_resp(17), class_resp(18), ClassFin])),
    ],
    vec![1, 3],
    vec![
        Ok((peer(0), class(15, 0))),
        Ok((peer(1), class(16, 1))),
        Ok((peer(1), class(17, 1))),
        Ok((peer(1), class(18, 1))),
    ]
)]
#[case::count_steam_is_too_short(
    2,
    vec![
        // 2 blocks in responses
        Ok((peer(0), vec![class_resp(19), ClassFin])),
        Ok((peer(0), vec![class_resp(20), ClassFin]))
    ],
    vec![1], // but only 1 block provided in the count stream
    vec![
        Ok((peer(0), class(19, 0))),
        Err(()) // the second block is not processed
    ]
)]
#[case::too_many_responses_declaration_with_fin(
    1,
    vec![Ok((peer(0), vec![class_resp(21), class_resp(22), ClassFin]))],
    vec![1],
    vec![Ok((peer(0), class(21, 0)))]
)]
#[case::too_many_responses_declaration_no_fin(
    1,
    vec![Ok((peer(0), vec![class_resp(21), class_resp(22)]))],
    vec![1],
    vec![Ok((peer(0), class(21, 0)))]
)]
#[case::empty_response_streams_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![])),
        Ok((peer(1), vec![class_resp(22), ClassFin])),
        Ok((peer(2), vec![]))
    ],
    vec![1],
    vec![Ok((peer(1), class(22, 0)))]
)]
#[case::empty_responses_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![ClassFin])),
        Ok((peer(1), vec![class_resp(22), ClassFin])),
        Ok((peer(2), vec![ClassFin]))
    ],
    vec![1],
    vec![Ok((peer(1), class(22, 0)))]
)]
#[test_log::test(tokio::test)]
async fn make_class_definition_stream(
    #[case] num_blocks: usize,
    #[case] responses: Vec<Result<(TestPeer, Vec<ClassesResponse>), TestPeer>>,
    #[case] declared_classes_per_block: Vec<usize>,
    #[case] expected_stream: Vec<Result<(TestPeer, ClassDefinition), ()>>,
) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peers, responses) = unzip_fixtures(responses);
    let get_peers = move || {
        let peers = peers.clone();
        async move { peers }
    };
    let send_request = move |_: PeerId, _: ClassesRequest| {
        let responses = responses.clone();
        async move { send_request(responses).await }
    };

    let start = BlockNumber::GENESIS;
    let stop = start + (num_blocks - 1) as u64;

    let actual = super::class_definition_stream::make(
        start,
        stop,
        stream::iter(declared_classes_per_block.into_iter().map(Ok)),
        get_peers,
        send_request,
    )
    .map_ok(|x| (TestPeer(x.peer), x.data))
    .map_err(|_| ())
    .collect::<Vec<_>>()
    .await;

    pretty_assertions_sorted::assert_eq!(actual, expected_stream);
}

#[rstest]
#[case::one_peer_1_block(
    1,
    //                            event  transaction
    //                                |  |
    vec![Ok((peer(0), vec![event_resp(0, 0), event_resp(1, 0), event_resp(2, 2), EventFin]))],
    vec![3],
    //                                      transaction
    //                                events   |                block
    //                                   / \   |                  |
    vec![Ok((peer(0), events(vec![(vec![0, 1], 0), (vec![2], 2)], 0)))]
)]
#[case::one_peer_2_blocks(
    2,
    vec![Ok((peer(0), vec![event_resp(3, 3), event_resp(4, 3), event_resp(5, 5), event_resp(6, 6), EventFin]))],
    vec![2, 2],
    vec![
        Ok((peer(0), events(vec![(vec![3, 4], 3)], 0))),
        Ok((peer(0), events(vec![(vec![5], 5), (vec![6], 6)], 1)))
    ]
)]
#[case::one_peer_2_blocks_in_2_attempts(
    // Peer gives a response for the second block after a retry
    2,
    vec![
        Ok((peer(0), vec![event_resp(7, 7), event_resp(8, 8), EventFin])),
        Ok((peer(0), vec![event_resp(9, 9), event_resp(10, 9), EventFin])),
    ],
    vec![2, 2],
    vec![
        Ok((peer(0), events(vec![(vec![7], 7), (vec![8], 8)], 0))),
        Ok((peer(0), events(vec![(vec![9, 10], 9)], 1))),
    ]
)]
#[case::two_peers_1_block_per_peer(
    2,
    vec![
        // Errors are ignored
        Err(peer(1)),
        Ok((peer(0), vec![event_resp(11, 11), event_resp(12, 11), EventFin])),
        Err(peer(0)),
        Ok((peer(1), vec![event_resp(13, 13), EventFin])),
    ],
    vec![2, 1],
    vec![
        Ok((peer(0), events(vec![(vec![11, 12], 11)], 0))),
        Ok((peer(1), events(vec![(vec![13], 13)], 1))),
    ]
)]
#[case::first_peer_premature_eos_with_fin(
    2,
    vec![
        // First peer gives full block 0 and half of block 1
        Ok((peer(0), vec![event_resp(14, 14), event_resp(15, 14), event_resp(16, 16), EventFin])),
        Ok((peer(1), vec![event_resp(16, 16), event_resp(17, 16), EventFin])),
    ],
    vec![2, 2],
    vec![
        Ok((peer(0), events(vec![(vec![14, 15], 14)], 0))),
        Ok((peer(1), events(vec![(vec![16, 17], 16)], 1))),
    ]
)]
#[case::first_peer_full_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 but no fin
        Ok((peer(0), vec![event_resp(18, 18)])),
        Ok((peer(1), vec![event_resp(19, 19), EventFin]))
    ],
    vec![1, 1],
    vec![
        Ok((peer(0), events(vec![(vec![18], 18)], 0))),
        Ok((peer(1), events(vec![(vec![19], 19)], 1))),
    ]
)]
#[case::last_peer_full_block_no_fin(
    2,
    vec![
        Ok((peer(0), vec![event_resp(18, 18), EventFin])),
        Ok((peer(1), vec![event_resp(19, 19)]))
    ],
    vec![1, 1],
    vec![
        Ok((peer(0), events(vec![(vec![18], 18)], 0))),
        Ok((peer(1), events(vec![(vec![19], 19)], 1))),
    ]
)]
// The same as above but the first peer gives half of the second block before closing the
// stream
#[case::first_peer_half_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 and partial block 1 but no fin
        Ok((peer(0), vec![event_resp(20, 20), event_resp(21, 21), event_resp(22, 22)])),
        Ok((peer(1), vec![event_resp(22, 22), event_resp(23, 22), event_resp(24, 22), EventFin])),
    ],
    vec![2, 3],
    vec![
        Ok((peer(0), events(vec![(vec![20], 20), (vec![21], 21)], 0))),
        Ok((peer(1), events(vec![(vec![22, 23, 24], 22)], 1))),
    ]
)]
#[case::count_steam_is_too_short(
    2,
    vec![
        // 2 blocks in responses
        Ok((peer(0), vec![event_resp(25, 25), EventFin])),
        Ok((peer(0), vec![event_resp(26, 26), EventFin]))
    ],
    vec![1], // but only 1 block provided in the count stream
    vec![
        Ok((peer(0), events(vec![(vec![25], 25)], 0))),
        Err(()) // the second block is not processed
    ]
)]
#[case::too_many_responses_with_fin(
    1,
    vec![Ok((peer(0), vec![event_resp(27, 27), event_resp(28, 27), event_resp(29, 27), EventFin]))],
    vec![1],
    vec![
        Ok((peer(0), events(vec![(vec![27], 27)], 0))),
    ]
)]
#[case::too_many_responses_no_fin(
    1,
    vec![Ok((peer(0), vec![event_resp(27, 27), event_resp(28, 27), event_resp(29, 27)]))],
    vec![1],
    vec![
        Ok((peer(0), events(vec![(vec![27], 27)], 0))),
    ]
)]
#[case::empty_response_streams_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![])),
        Ok((peer(0), vec![event_resp(30, 30), EventFin])),
        Ok((peer(2), vec![]))
    ],
    vec![1],
    vec![
        Ok((peer(0), events(vec![(vec![30], 30)], 0)))
    ]
)]
#[case::empty_responses_are_ignored(
    1,
    vec![
        Ok((peer(0), vec![EventFin])),
        Ok((peer(0), vec![event_resp(30, 30), EventFin])),
        Ok((peer(2), vec![EventFin]))
    ],
    vec![1],
    vec![
        Ok((peer(0), events(vec![(vec![30], 30)], 0)))
    ]
)]
#[test_log::test(tokio::test)]
async fn make_event_stream(
    #[case] num_blocks: usize,
    #[case] responses: Vec<Result<(TestPeer, Vec<EventsResponse>), TestPeer>>,
    #[case] events_per_block: Vec<usize>,
    #[case] expected_stream: Vec<Result<(TestPeer, TaggedEventsForBlockByTransaction), ()>>,
) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peers, responses) = unzip_fixtures(responses);
    let get_peers = move || {
        let peers = peers.clone();
        async move { peers }
    };
    let send_request = move |_: PeerId, _: EventsRequest| {
        let responses = responses.clone();
        async move { send_request(responses).await }
    };

    let start = BlockNumber::GENESIS;
    let stop = start + (num_blocks - 1) as u64;

    let actual = super::event_stream::make(
        start,
        stop,
        stream::iter(events_per_block.into_iter().map(Ok)),
        get_peers,
        send_request,
    )
    .map_ok(|x| {
        (
            TestPeer(x.peer),
            (
                x.data.0,
                x.data
                    .1
                    .into_iter()
                    .map(|(t, e)| (TaggedTransactionHash(t), e))
                    .collect(),
            ),
        )
    })
    .map_err(|_| ())
    .collect::<Vec<_>>()
    .await;

    pretty_assertions_sorted::assert_eq!(actual, expected_stream);
}
