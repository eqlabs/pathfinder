use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use p2p::libp2p::{identity::Keypair, multiaddr::Multiaddr, PeerId};
use p2p::Peers;
use p2p_proto as proto;
use pathfinder_common::{ChainId, StarknetBlockHash, StarknetBlockNumber};
use pathfinder_rpc::SyncState;
use pathfinder_storage::{StarknetBlocksBlockId, StarknetTransactionsTable, Storage};
use proto::sync::{BlockBodies, StateDiffs};
use stark_hash::StarkHash;
use tokio::sync::RwLock;
use tracing::Instrument;

const PERIODIC_STATUS_INTERVAL: Duration = Duration::from_secs(30);

#[tracing::instrument(name = "p2p", skip_all)]
pub async fn start(
    chain_id: ChainId,
    mut storage: Storage,
    sync_state: Arc<SyncState>,
    listen_on: Multiaddr,
    bootstrap_addresses: &[Multiaddr],
) -> anyhow::Result<(Arc<RwLock<Peers>>, p2p::Client, tokio::task::JoinHandle<()>)> {
    let keypair = Keypair::Ed25519(p2p::libp2p::identity::ed25519::Keypair::generate());

    let peer_id = keypair.public().to_peer_id();
    tracing::info!(%peer_id, "Starting P2P");

    let peers: Arc<RwLock<Peers>> = Arc::new(RwLock::new(Default::default()));
    let (mut p2p_client, mut p2p_events, p2p_main_loop) =
        p2p::new(keypair, peers.clone(), PERIODIC_STATUS_INTERVAL);

    let mut main_loop_handle = {
        let span = tracing::info_span!("behaviour");
        tokio::task::spawn(p2p_main_loop.run().instrument(span))
    };

    p2p_client
        .start_listening(listen_on)
        .await
        .context("Starting P2P listener")?;

    for bootstrap_address in bootstrap_addresses {
        let peer_id = bootstrap_address
            .iter()
            .find_map(|p| match p {
                p2p::libp2p::multiaddr::Protocol::P2p(h) => PeerId::from_multihash(h).ok(),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("Boostrap addresses must inlcude peer ID"))?;
        p2p_client.dial(peer_id, bootstrap_address.clone()).await?;
        p2p_client
            .start_listening(
                bootstrap_address
                    .clone()
                    .with(p2p::libp2p::multiaddr::Protocol::P2pCircuit),
            )
            .await
            .context("Starting relay listener")?;
    }

    let block_propagation_topic = format!("blocks/{}", chain_id.to_hex_str());
    p2p_client.subscribe_topic(&block_propagation_topic).await?;

    let join_handle = {
        let mut p2p_client = p2p_client.clone();
        tokio::task::spawn(
            async move {
                loop {
                    tokio::select! {
                        _ = &mut main_loop_handle => {
                            tracing::error!("p2p task ended unexpectedly");
                            break;
                        }
                        Some(event) = p2p_events.recv() => {
                            match handle_p2p_event(event, chain_id, &mut storage, &sync_state, &mut p2p_client).await {
                                Ok(()) => {},
                                Err(e) => { tracing::error!("Failed to handle P2P event: {}", e) },
                            }
                        }
                    }
                }
            }
            .in_current_span(),
        )
    };

    Ok((peers, p2p_client, join_handle))
}

const MAX_HEADERS_COUNT: u64 = 1000;

async fn handle_p2p_event(
    event: p2p::Event,
    chain_id: ChainId,
    storage: &mut Storage,
    sync_state: &SyncState,
    p2p_client: &mut p2p::Client,
) -> anyhow::Result<()> {
    match event {
        p2p::Event::SyncPeerConnected { peer_id }
        | p2p::Event::SyncPeerRequestStatus { peer_id } => {
            // get initial status by sending a status request
            p2p_client
                .send_sync_status_request(peer_id, current_status(chain_id, sync_state).await)
                .await;
        }
        p2p::Event::InboundSyncRequest {
            request, channel, ..
        } => {
            use p2p_proto::sync::{Request, Response};
            let response = match request {
                Request::GetBlockHeaders(r) => {
                    Response::BlockHeaders(handle_get_block_headers(r, storage).await?)
                }
                Request::GetBlockBodies(_r) => Response::BlockBodies(BlockBodies {
                    block_bodies: vec![],
                }),
                Request::GetStateDiffs(_r) => Response::StateDiffs(StateDiffs {
                    block_state_updates: vec![],
                }),
                Request::Status(_) => Response::Status(current_status(chain_id, sync_state).await),
            };
            p2p_client.send_sync_response(channel, response).await;
        }
        p2p::Event::BlockPropagation(block_propagation) => {
            tracing::info!(?block_propagation, "Block Propagation");
        }
    }

    Ok(())
}

async fn current_status(chain_id: ChainId, sync_state: &SyncState) -> p2p_proto::sync::Status {
    use p2p_proto::sync::Status;
    use pathfinder_rpc::v01::types::reply::Syncing;

    let sync_status = { sync_state.status.read().await.clone() };
    match sync_status {
        Syncing::False(_) => Status {
            chain_id: chain_id.0,
            height: 0,
            hash: StarkHash::ZERO,
        },
        Syncing::Status(status) => Status {
            chain_id: chain_id.0,
            height: status.current.number.get(),
            hash: status.current.hash.0,
        },
    }
}

// TODO: we currently ignore the size limit.
async fn handle_get_block_headers(
    request: p2p_proto::sync::GetBlockHeaders,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::BlockHeaders> {
    let storage = storage.clone();
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;

        let headers = fetch_block_headers(tx, request)?;

        Ok(p2p_proto::sync::BlockHeaders { headers })
    })
    .await
    .context("Database read panic or shutting down")?
}

fn fetch_block_headers(
    tx: rusqlite::Transaction<'_>,
    request: p2p_proto::sync::GetBlockHeaders,
) -> anyhow::Result<Vec<p2p_proto::common::BlockHeader>> {
    use pathfinder_storage::StarknetBlocksTable;

    let mut count = std::cmp::min(request.count, MAX_HEADERS_COUNT);
    let mut headers = Vec::new();

    let mut next_block_number =
        StarknetBlocksTable::get_number(&tx, StarknetBlockHash(request.start_block))?;

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(block) = StarknetBlocksTable::get(
            &tx,
            pathfinder_storage::StarknetBlocksBlockId::Number(block_number),
        )? else {
            // no such block in our database, stop iterating
            break;
        };

        let parent_block_number = block_number
            .get()
            .checked_sub(1)
            .and_then(StarknetBlockNumber::new);
        let parent_block_hash = match parent_block_number {
            Some(number) => StarknetBlocksTable::get_hash(&tx, number.into())?,
            None => None,
        };

        let transaction_count = StarknetTransactionsTable::get_transaction_count(
            &tx,
            StarknetBlocksBlockId::Hash(block.hash),
        )?;

        headers.push(p2p_proto::common::BlockHeader {
            parent_block_hash: parent_block_hash
                .unwrap_or_else(|| StarknetBlockHash(StarkHash::ZERO))
                .0,
            block_number: block.number.get(),
            global_state_root: block.root.0,
            sequencer_address: block.sequencer_address.0,
            block_timestamp: block.timestamp.get(),
            transaction_count: transaction_count
                .try_into()
                .context("Too many transactions")?,
            // TODO: how to get these values. We'd have to store these (along with the parent hash) as part of the starknet_blocks table
            // so that we can implement this effectively. Unfortunately re-computing these values is slow...
            transaction_commitment: StarkHash::ZERO,
            event_count: 0,
            event_commitment: StarkHash::ZERO,
            // TODO: what's the protocol version?
            protocol_version: 0,
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(headers)
}

/// Returns next block number considering direction.
///
/// None is returned if we're out-of-bounds.
fn get_next_block_number(
    current: StarknetBlockNumber,
    direction: proto::sync::Direction,
) -> Option<StarknetBlockNumber> {
    match direction {
        proto::sync::Direction::Forward => current
            .get()
            .checked_add(1)
            .and_then(StarknetBlockNumber::new),
        proto::sync::Direction::Backward => current
            .get()
            .checked_sub(1)
            .and_then(StarknetBlockNumber::new),
    }
}

#[cfg(test)]
mod tests {
    use super::proto::sync::Direction;
    use p2p_proto::sync::GetBlockHeaders;
    use pathfinder_common::StarknetBlockNumber;

    use super::{fetch_block_headers, get_next_block_number};

    #[test]
    fn test_get_next_block_number() {
        let genesis = StarknetBlockNumber::new_or_panic(0);
        assert_eq!(get_next_block_number(genesis, Direction::Backward), None);
        assert_eq!(
            get_next_block_number(genesis, Direction::Forward),
            Some(StarknetBlockNumber::new_or_panic(1))
        );

        assert_eq!(
            get_next_block_number(StarknetBlockNumber::new_or_panic(1), Direction::Backward),
            Some(genesis)
        );
        assert_eq!(
            get_next_block_number(StarknetBlockNumber::new_or_panic(1), Direction::Forward),
            Some(StarknetBlockNumber::new_or_panic(2))
        );
    }

    #[test]
    fn test_fetch_block_headers_forward() {
        let (storage, blocks, _transactions, _receipts, _events) =
            pathfinder_storage::test_utils::setup_test_storage_and_return_test_data();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const COUNT: usize = 3;
        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: blocks[0].hash.0,
                count: COUNT as u64,
                size_limit: 100,
                direction: Direction::Forward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            blocks
                .iter()
                .take(COUNT)
                .map(|b| b.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .take(COUNT)
                .map(|b| b.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .skip(1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .take(COUNT - 1)
                .map(|b| b.hash.0)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_forward_all_blocks() {
        let (storage, blocks, _transactions, _receipts, _events) =
            pathfinder_storage::test_utils::setup_test_storage_and_return_test_data();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: blocks[0].hash.0,
                count: blocks.len() as u64 + 10,
                size_limit: 100,
                direction: Direction::Forward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            blocks.iter().map(|b| b.number.get()).collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            blocks.iter().map(|b| b.timestamp.get()).collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .skip(1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .take(blocks.len() - 1)
                .map(|b| b.hash.0)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_backward() {
        let (storage, blocks, _transactions, _receipts, _events) =
            pathfinder_storage::test_utils::setup_test_storage_and_return_test_data();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const COUNT: usize = 3;
        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: blocks[3].hash.0,
                count: COUNT as u64,
                size_limit: 100,
                direction: Direction::Backward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| b.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| b.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .take(COUNT - 1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .rev()
                .skip(1)
                .take(COUNT - 1)
                .map(|b| b.hash.0)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_backward_all_blocks() {
        let (storage, blocks, _transactions, _receipts, _events) =
            pathfinder_storage::test_utils::setup_test_storage_and_return_test_data();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: blocks[3].hash.0,
                count: blocks.len() as u64 + 10,
                size_limit: 100,
                direction: Direction::Backward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.block_number).collect::<Vec<_>>(),
            blocks
                .iter()
                .rev()
                .map(|b| b.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers
                .iter()
                .map(|h| h.block_timestamp)
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .rev()
                .map(|b| b.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .take(blocks.len() - 1)
                .map(|h| h.parent_block_hash)
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .rev()
                .skip(1)
                .take(blocks.len() - 1)
                .map(|b| b.hash.0)
                .collect::<Vec<_>>()
        );
    }
}
