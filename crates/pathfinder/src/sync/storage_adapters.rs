use std::collections::VecDeque;
use std::num::NonZeroUsize;

use anyhow::Context;
use pathfinder_common::BlockNumber;
use pathfinder_storage::Storage;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub fn counts_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
    batch_size: NonZeroUsize,
    db_getter: impl Fn(
            pathfinder_storage::Transaction<'_>,
            BlockNumber,
            NonZeroUsize,
        ) -> anyhow::Result<VecDeque<usize>>
        + Copy
        + Send
        + 'static,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || {
        let mut batch = VecDeque::new();

        while start <= stop {
            if let Some(counts) = batch.pop_front() {
                _ = tx.blocking_send(Ok(counts));
                continue;
            }

            let batch_size = batch_size.min(
                NonZeroUsize::new(
                    (stop.get() - start.get() + 1)
                        .try_into()
                        .expect("ptr size is 64bits"),
                )
                .expect(">0"),
            );
            let storage = storage.clone();

            let get = move || {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().context("Creating database transaction")?;

                batch = db_getter(db, start, batch_size)?;

                anyhow::ensure!(
                    !batch.is_empty(),
                    "No counts found: start {start}, batch_size {batch_size}"
                );

                Ok(batch)
            };

            batch = match get() {
                Ok(x) => x,
                Err(e) => {
                    _ = tx.blocking_send(Err(e));
                    return;
                }
            };

            start += batch.len().try_into().expect("ptr size is 64bits");
        }

        while let Some(counts) = batch.pop_front() {
            _ = tx.blocking_send(Ok(counts));
        }
    });

    ReceiverStream::new(rx)
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use pathfinder_common::{BlockHeader, SignedBlockHeader, StateUpdate};
    use pathfinder_storage::fake::Block;

    use super::*;
    use crate::sync::{class_definitions, events, state_updates, transactions};

    fn expected_transaction_counts(b: Block) -> usize {
        let Block {
            header:
                SignedBlockHeader {
                    header:
                        BlockHeader {
                            transaction_count, ..
                        },
                    ..
                },
            ..
        } = b;
        transaction_count
    }

    fn expected_state_diff_lengths(b: Block) -> usize {
        let Block {
            header:
                SignedBlockHeader {
                    header:
                        BlockHeader {
                            state_diff_length, ..
                        },
                    ..
                },
            ..
        } = b;
        state_diff_length as usize
    }

    fn expected_class_definition_counts(b: Block) -> usize {
        let Block {
            state_update:
                StateUpdate {
                    declared_cairo_classes,
                    declared_sierra_classes,
                    ..
                },
            ..
        } = b;
        declared_cairo_classes.len() + declared_sierra_classes.len()
    }

    fn expected_event_counts(b: Block) -> usize {
        let Block {
            transaction_data, ..
        } = b;
        transaction_data
            .iter()
            .fold(0, |acc, (_, _, evs)| acc + evs.len())
    }

    #[rstest::rstest]
    #[case::request_shorter_than_batch_size(1)]
    #[case::request_equal_to_batch_size(2)]
    #[case::request_longer_than_batch_size(3)]
    #[case::request_equal_to_db_size(5)]
    #[case::request_longer_than_db_size(6)]
    #[tokio::test]
    async fn counts_stream(
        #[case] len: usize,
        #[values(
            (transactions::get_counts, expected_transaction_counts),
            (state_updates::get_state_diff_lengths, expected_state_diff_lengths),
            (class_definitions::get_counts, expected_class_definition_counts),
            (events::get_counts, expected_event_counts))]
        case: (
            impl Fn(
                    pathfinder_storage::Transaction<'_>,
                    BlockNumber,
                    NonZeroUsize,
                ) -> anyhow::Result<VecDeque<usize>>
                + Copy
                + Send
                + 'static,
            impl Fn(Block) -> usize,
        ),
    ) {
        let (db_getter, count_extractor) = case;

        const DB_LEN: usize = 5;
        let ok_len = len.min(DB_LEN);
        let storage = pathfinder_storage::StorageBuilder::in_memory().unwrap();
        let expected = pathfinder_storage::fake::with_n_blocks(&storage, DB_LEN)
            .into_iter()
            .map(count_extractor)
            .collect::<Vec<_>>();
        let stream = super::counts_stream(
            storage.clone(),
            BlockNumber::GENESIS,
            BlockNumber::GENESIS + len as u64 - 1,
            NonZeroUsize::new(2).unwrap(),
            db_getter,
        );

        let mut remainder = stream.collect::<Vec<_>>().await;

        let actual = remainder
            .drain(..ok_len)
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();

        assert_eq!(expected[..ok_len], actual);

        if len > DB_LEN {
            assert!(remainder.pop().unwrap().is_err());
        } else {
            assert!(remainder.is_empty());
        }
    }
}
