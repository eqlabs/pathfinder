use futures::{stream, TryStreamExt};
use rstest::rstest;
use StateDiffsResponse::Fin as SDFin;
use TransactionsResponse::Fin as TxnFin;

use super::*;
use crate::client::peer_agnostic::fixtures::*;

#[rstest]
#[case::one_peer_1_block(
    1,
    // Simulated responses
    vec![Ok((peer(0), vec![txn_resp(0, 0), txn_resp(1, 1), TxnFin]))],
    // Expected number of transactions per block
    vec![2],
    // Expected stream
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
        Err(peer(0)) // the second block is not processed
    ]
)]
#[case::too_many_responses(
    1,
    vec![Ok((peer(0), vec![txn_resp(18, 0), txn_resp(19, 0), TxnFin]))],
    vec![1],
    vec![Ok((peer(0), vec![txn(18, 0)]))]
)]
#[test_log::test(tokio::test)]
async fn make_transaction_stream(
    #[case] num_blocks: usize,
    #[case] responses: Vec<Result<(TestPeer, Vec<TransactionsResponse>), TestPeer>>,
    #[case] num_txns_per_block: Vec<usize>,
    #[case] expected_stream: Vec<Result<(TestPeer, Vec<TestTxn>), TestPeer>>,
) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peers, responses) = unzip_fixtures(responses);
    let get_peers = || async { peers.clone() };
    let send_request =
        |_: PeerId, _: TransactionsRequest| async { send_request(responses.clone()).await };

    let start = BlockNumber::GENESIS;
    let stop = start + (num_blocks - 1) as u64;

    let actual = super::make_transaction_stream(
        start,
        stop,
        stream::iter(
            num_txns_per_block
                .into_iter()
                .map(|x| Ok((x, Default::default()))),
        ),
        get_peers,
        send_request,
    )
    .map_ok(|x| {
        (
            TestPeer(x.peer),
            x.data
                .0
                .transactions
                .into_iter()
                .map(TestTxn::new)
                .collect(),
        )
    })
    .map_err(|x| TestPeer(x.peer))
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
    vec![Ok((peer(0), vec![contract_diff(0), declared_class(0), contract_diff(1), declared_class(1), SDFin]))],
    vec![len(0), len(1)],
    vec![Ok((peer(0), state_diff(0))), Ok((peer(0), state_diff(1)))]
)]
#[case::one_peer_2_blocks_in_2_attempts(
    // Peer gives a response for the second block after a retry
    2,
    vec![
        Ok((peer(0), vec![contract_diff(0), declared_class(0), SDFin])),
        Ok((peer(0), vec![contract_diff(1), declared_class(1), SDFin])),
    ],
    vec![len(0), len(1)],
    vec![
        Ok((peer(0), state_diff(0))),
        Ok((peer(0), state_diff(1)))
    ]
)]
#[case::two_peers_1_block_per_peer(
    2,
    vec![
        // Errors are ignored
        Err(peer(1)),
        Ok((peer(0), vec![contract_diff(0), declared_class(0), SDFin])),
        Err(peer(0)),
        Ok((peer(1), vec![contract_diff(1), declared_class(1), SDFin])),
    ],
    vec![len(0), len(1)],
    vec![
        Ok((peer(0), state_diff(0))),
        Ok((peer(1), state_diff(1)))
    ]
)]
#[case::first_peer_premature_eos_with_fin(
    2,
    vec![
        // First peer gives full block 0 and half of block 1
        Ok((peer(0), vec![contract_diff(0), declared_class(0), contract_diff(1), SDFin])),
        Ok((peer(1), vec![contract_diff(1), declared_class(1), SDFin]))
    ],
    vec![len(0), len(1)],
    vec![
        Ok((peer(0), state_diff(0))),
        Ok((peer(1), state_diff(1)))
    ]
)]
#[case::first_peer_full_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 but no fin
        Ok((peer(0), vec![contract_diff(0), declared_class(0)])),
        Ok((peer(1), vec![contract_diff(1), declared_class(1), SDFin]))
    ],
    vec![len(0), len(1)],
    vec![
        Ok((peer(0), state_diff(0))),
        Ok((peer(1), state_diff(1)))
    ]
)]
// The same as above but the first peer gives half of the second block before closing the
// stream
#[case::first_peer_half_block_no_fin(
    2,
    vec![
        // First peer gives full block 0 and partial block 1 but no fin
        Ok((peer(0), vec![contract_diff(0), declared_class(0), contract_diff(1)])),
        Ok((peer(1), vec![contract_diff(1), declared_class(1), SDFin])),
    ],
    vec![len(0), len(1)],
    vec![
        Ok((peer(0), state_diff(0))),
        Ok((peer(1), state_diff(1)))
    ]
)]
#[case::count_steam_is_too_short(
    2,
    vec![
        // 2 blocks in responses
        Ok((peer(0), vec![contract_diff(0), declared_class(0), SDFin])),
        Ok((peer(0), vec![contract_diff(1), declared_class(1), SDFin]))
    ],
    vec![len(0)], // but only 1 block provided in the count stream
    vec![
        Ok((peer(0), state_diff(0))),
        Err(peer(0)) // the second block is not processed
    ]
)]
#[case::too_many_responses_storage(
    1,
    vec![Ok((peer(0), vec![contract_diff(0), declared_class(0), surplus_storage(), SDFin]))],
    vec![len(0)],
    vec![Ok((peer(0), state_diff(0)))]
)]
#[case::too_many_responses_nonce(
    1,
    vec![Ok((peer(0), vec![contract_diff(0), declared_class(0), surplus_nonce(), SDFin]))],
    vec![len(0)],
    vec![Ok((peer(0), state_diff(0)))]
)]
#[case::too_many_responses_class(
    1,
    vec![Ok((peer(0), vec![contract_diff(0), declared_class(0), surplus_class(), SDFin]))],
    vec![len(0)],
    vec![Ok((peer(0), state_diff(0)))]
)]
#[case::too_many_responses_declaration(
    1,
    vec![Ok((peer(0), vec![contract_diff(0), declared_class(0), declared_class(1), SDFin]))],
    vec![len(0)],
    vec![Ok((peer(0), state_diff(0)))]
)]
#[test_log::test(tokio::test)]
async fn make_state_diff_stream(
    #[case] num_blocks: usize,
    #[case] responses: Vec<Result<(TestPeer, Vec<StateDiffsResponse>), TestPeer>>,
    #[case] state_diff_len_per_block: Vec<usize>,
    #[case] expected_stream: Vec<Result<(TestPeer, UnverifiedStateUpdateData), TestPeer>>,
) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peers, responses) = unzip_fixtures(responses);
    let get_peers = || async { peers.clone() };
    let send_request =
        |_: PeerId, _: StateDiffsRequest| async { send_request(responses.clone()).await };

    let start = BlockNumber::GENESIS;
    let stop = start + (num_blocks - 1) as u64;

    let actual = super::make_state_diff_stream(
        start,
        stop,
        stream::iter(
            state_diff_len_per_block
                .into_iter()
                .map(|x| Ok((x, Default::default()))),
        ),
        get_peers,
        send_request,
    )
    .map_ok(|x| (TestPeer(x.peer), x.data))
    .map_err(|x| TestPeer(x.peer))
    .collect::<Vec<_>>()
    .await;

    let expected = expected_stream
        .into_iter()
        .enumerate()
        .map(|(i, x)| x.map(|(p, su)| (p, (su, BlockNumber::new_or_panic(i as u64)))))
        .collect::<Vec<_>>();

    pretty_assertions_sorted::assert_eq!(actual, expected);
}
