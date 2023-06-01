use anyhow::{anyhow, Context};
use p2p_proto as proto;
use pathfinder_common::{BlockHash, BlockNumber, ClassCommitment, StorageCommitment};
use pathfinder_storage::{StarknetTransactionsTable, Storage, Transaction};
use stark_hash::Felt;

const MAX_HEADERS_COUNT: u64 = 1000;

// TODO: we currently ignore the size limit.
pub async fn get_block_headers(
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
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetBlockHeaders,
) -> anyhow::Result<Vec<p2p_proto::common::BlockHeader>> {
    use pathfinder_storage::StarknetBlocksTable;

    let mut count = std::cmp::min(request.count, MAX_HEADERS_COUNT);
    let mut headers = Vec::new();

    let mut next_block_number = Some(BlockNumber::new_or_panic(request.start_block));

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(block) = StarknetBlocksTable::get(
            &tx,
            block_number.into(),
        )? else {
            // no such block in our database, stop iterating
            break;
        };

        let parent_block_number = block_number.get().checked_sub(1).and_then(BlockNumber::new);
        let parent_block_hash = match parent_block_number {
            Some(number) => StarknetBlocksTable::get_hash(&tx, number.into())?,
            None => None,
        };

        let transaction_count =
            StarknetTransactionsTable::get_transaction_count(&tx, block.hash.into())?;

        let starknet_version = StarknetBlocksTable::get_version(&tx, block_number.into())?;
        let (storage_commitment, class_commitment) =
            StarknetBlocksTable::get_state_commitment(&tx, block_number.into())?
                .unwrap_or((StorageCommitment::ZERO, ClassCommitment::ZERO));

        headers.push(p2p_proto::common::BlockHeader {
            hash: block.hash.0,
            parent_hash: parent_block_hash.unwrap_or(BlockHash(Felt::ZERO)).0,
            number: block.number.get(),
            state_commitment: block.state_commmitment.0,
            storage_commitment: storage_commitment.0,
            class_commitment: class_commitment.0,
            sequencer_address: block.sequencer_address.0,
            timestamp: block.timestamp.get(),
            gas_price: block.gas_price.0.into(),
            transaction_count: transaction_count
                .try_into()
                .context("Too many transactions")?,
            transaction_commitment: block
                .transaction_commitment
                .map(|tx| tx.0)
                .ok_or(anyhow!("Transaction commitment missing"))?,
            event_count: 0,
            event_commitment: block
                .event_commitment
                .map(|ev| ev.0)
                .ok_or(anyhow!("Event commitment missing"))?,
            starknet_version: starknet_version.take_inner(),
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
    current: BlockNumber,
    direction: proto::sync::Direction,
) -> Option<BlockNumber> {
    match direction {
        proto::sync::Direction::Forward => current.get().checked_add(1).and_then(BlockNumber::new),
        proto::sync::Direction::Backward => current.get().checked_sub(1).and_then(BlockNumber::new),
    }
}

// TODO rework to iterate over all types of requests (headers, bodies, state diffs)
// unfortunately cannot cover classes (ie cairo0/sierra)
#[cfg(test)]
mod tests {
    use super::proto::sync::Direction;
    use p2p_proto::sync::GetBlockHeaders;
    use pathfinder_common::BlockNumber;

    use super::{fetch_block_headers, get_next_block_number};

    #[test]
    fn test_get_next_block_number() {
        let genesis = BlockNumber::new_or_panic(0);
        assert_eq!(get_next_block_number(genesis, Direction::Backward), None);
        assert_eq!(
            get_next_block_number(genesis, Direction::Forward),
            Some(BlockNumber::new_or_panic(1))
        );

        assert_eq!(
            get_next_block_number(BlockNumber::new_or_panic(1), Direction::Backward),
            Some(genesis)
        );
        assert_eq!(
            get_next_block_number(BlockNumber::new_or_panic(1), Direction::Forward),
            Some(BlockNumber::new_or_panic(2))
        );
    }

    #[test]
    fn test_fetch_block_headers_forward() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const COUNT: usize = 3;
        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[0].block.number.get(),
                count: COUNT as u64,
                size_limit: 100,
                direction: Direction::Forward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT)
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT)
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .skip(1)
                .map(|h| h.parent_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(COUNT)
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_forward_all_blocks() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[0].block.number.get(),
                count: test_data.blocks.len() as u64 + 10,
                size_limit: 100,
                direction: Direction::Forward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .skip(1)
                .map(|h| h.parent_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .take(test_data.blocks.len() - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_backward() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const COUNT: usize = 3;
        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[3].block.number.get(),
                count: COUNT as u64,
                size_limit: 100,
                direction: Direction::Backward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .take(COUNT - 1)
                .map(|h| h.parent_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .skip(1)
                .take(COUNT - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .take(COUNT)
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fetch_block_headers_backward_all_blocks() {
        let (storage, test_data) = pathfinder_storage::test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let headers = fetch_block_headers(
            tx,
            GetBlockHeaders {
                start_block: test_data.blocks[3].block.number.get(),
                count: test_data.blocks.len() as u64 + 10,
                size_limit: 100,
                direction: Direction::Backward,
            },
        )
        .unwrap();

        assert_eq!(
            headers.iter().map(|h| h.number).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .map(|b| b.block.number.get())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            headers.iter().map(|h| h.timestamp).collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .map(|b| b.block.timestamp.get())
                .collect::<Vec<_>>()
        );

        // check that the parent hashes are correct
        assert_eq!(
            headers
                .iter()
                .take(test_data.blocks.len() - 1)
                .map(|h| h.parent_hash)
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .skip(1)
                .take(test_data.blocks.len() - 1)
                .map(|b| b.block.hash.0)
                .collect::<Vec<_>>()
        );

        // check that event & transaction commitments match
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.event_commitment, h.transaction_commitment))
                .collect::<Vec<_>>(),
            test_data
                .blocks
                .iter()
                .rev()
                .map(|b| (
                    b.block.event_commitment.unwrap_or_default().0,
                    b.block.transaction_commitment.unwrap_or_default().0
                ))
                .collect::<Vec<_>>()
        );
    }
}
