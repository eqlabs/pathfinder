use anyhow::Context;
use ethers::types::H160;
use futures::Future;
use pathfinder_common::{Chain, EthereumBlockHash, EthereumBlockNumber, StarknetBlockNumber};
use pathfinder_ethereum::{
    log::StateUpdateLog,
    provider::EthereumTransport,
    state_update::{FetchError, StateRootFetcher},
};
use pathfinder_retry::Retry;
use std::{num::NonZeroU64, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, RwLock};

/// Events and queries emitted by L1 sync process.
#[derive(Debug)]
pub enum Event {
    /// New L1 [update logs](StateUpdateLog) found.
    Update(Vec<StateUpdateLog>),
    /// An L1 reorg was detected, contains the reorg-tail which
    /// indicates the oldest block which is now invalid
    /// i.e. reorg-tail + 1 should be the new head.
    Reorg(StarknetBlockNumber),
    /// Query for the [update log](StateUpdateLog) of the given block.
    ///
    /// The receiver should return the [update log](StateUpdateLog) using the
    /// [oneshot::channel].
    QueryUpdate(StarknetBlockNumber, oneshot::Sender<Option<StateUpdateLog>>),
}

/// Syncs L1 state update logs. Emits [sync events](Event) which should be handled
/// to update storage and respond to queries.
pub async fn sync<T>(
    tx_event: mpsc::Sender<Event>,
    transport: T,
    chain: Chain,
    core_address: H160,
    head: Option<StateUpdateLog>,
) -> anyhow::Result<()>
where
    T: EthereumTransport + Send + Sync + Clone,
{
    let eth_api = EthereumImpl {
        logs: Arc::new(RwLock::new(StateRootFetcher::new(
            head,
            chain,
            core_address.0.into(),
        ))),
        transport,
    };

    // The core sync logic implementation.
    sync_impl(eth_api, tx_event, chain).await
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
trait EthereumApi {
    async fn fetch_logs(&mut self) -> Result<Vec<StateUpdateLog>, FetchError>;

    async fn set_log_head(&mut self, head: Option<StateUpdateLog>);

    async fn log_head(&self) -> Option<StateUpdateLog>;

    async fn block_hash(
        &self,
        block: EthereumBlockNumber,
    ) -> anyhow::Result<Option<EthereumBlockHash>>;
}

/// A helper function to keep the backoff strategy construction separated.
async fn retry<T, E, Fut, FutureFactory, RetryCondition>(
    future_factory: FutureFactory,
    retry_condition: RetryCondition,
) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
    FutureFactory: FnMut() -> Fut,
    RetryCondition: FnMut(&E) -> bool,
{
    Retry::exponential(future_factory, NonZeroU64::new(2).unwrap())
        .factor(NonZeroU64::new(15).unwrap())
        .max_delay(Duration::from_secs(10 * 60))
        .when(retry_condition)
        .await
}

#[derive(Clone)]
struct EthereumImpl<T: EthereumTransport + Send + Sync> {
    logs: Arc<RwLock<StateRootFetcher>>,
    transport: T,
}

#[async_trait::async_trait]
impl<T: EthereumTransport + Send + Sync + Clone> EthereumApi for EthereumImpl<T> {
    async fn fetch_logs(&mut self) -> Result<Vec<StateUpdateLog>, FetchError> {
        let ff = || async {
            let logs = self.logs.clone();
            let transport = self.transport.clone();
            let mut logs = logs.write().await;
            logs.fetch(transport).await
        };
        let logs = retry(ff, |error| match error {
            FetchError::Other(other) => {
                tracing::warn!(reason=%other, "Failed fetching L1 logs, retrying");
                true
            }
            FetchError::Reorg => false,
        })
        .await?;
        Ok(logs)
    }

    async fn set_log_head(&mut self, head: Option<StateUpdateLog>) {
        self.logs.write().await.set_head(head);
    }

    async fn log_head(&self) -> Option<StateUpdateLog> {
        self.logs.read().await.head().clone()
    }

    async fn block_hash(
        &self,
        block: EthereumBlockNumber,
    ) -> anyhow::Result<Option<EthereumBlockHash>> {
        // No explicit retrying here as any `EthereumTransport` implementor should already hadle that there.
        Ok(self
            .transport
            .block(block.0.into())
            .await?
            .map(|b| EthereumBlockHash(b.hash.unwrap().0.into())))
    }
}

/// Sends [sync events](Event) on its channel.
///
/// Main purpose is to simplify the code in [sync_impl] by abstracting
/// out the error mapping and oneshot channel receives.
struct EventSender(mpsc::Sender<Event>);

#[derive(Debug, PartialEq, Clone, Copy)]
struct ChannelClosedError;

impl EventSender {
    /// Sends [Event::QueryUpdate] on its channel and returns the result.
    async fn get_update(
        &self,
        block: StarknetBlockNumber,
    ) -> Result<Option<StateUpdateLog>, ChannelClosedError> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Event::QueryUpdate(block, tx))
            .await
            .map_err(|_send_err| ChannelClosedError)?;

        rx.await.map_err(|_recv_err| ChannelClosedError)
    }

    /// Sends [Event::Update] on its channel.
    async fn updates(&self, updates: Vec<StateUpdateLog>) -> Result<(), ChannelClosedError> {
        self.0
            .send(Event::Update(updates))
            .await
            .map_err(|_send_err| ChannelClosedError)
    }

    /// Sends [Event::Reorg] on its channel.
    async fn reorg(&self, block: StarknetBlockNumber) -> Result<(), ChannelClosedError> {
        self.0
            .send(Event::Reorg(block))
            .await
            .map_err(|_send_err| ChannelClosedError)
    }
}

async fn sync_impl(
    mut eth_api: impl EthereumApi,
    tx_event: mpsc::Sender<Event>,
    chain: Chain,
) -> anyhow::Result<()> {
    use crate::state::sync::head_poll_interval;

    let head_poll_interval = head_poll_interval(chain);

    let event_sender = EventSender(tx_event);
    loop {
        match eth_api.fetch_logs().await {
            Ok(logs) => {
                // If empty, then we are at head of chain, sleep a bit and try again.
                if logs.is_empty() {
                    tokio::time::sleep(head_poll_interval).await;
                    continue;
                }

                // There were log updates, send the event!
                if let Err(_exit) = event_sender.updates(logs).await {
                    return Ok(());
                }
            }
            Err(FetchError::Reorg) => {
                // Unwrap is safe as it is not be possible to get a reorg event if there
                // was no latest log to reorg against. We know that this block already needs to
                // be reorg'd since it triggered the reorg in the first place.
                let mut reorg_tail = eth_api.log_head().await.clone().unwrap();

                // Check each Starknet block in reverse history order, until we find a still
                // valid block. This becomes the new head of our L1 state.
                let new_head = loop {
                    // We have reached Starknet genesis, no older blocks to check.
                    if reorg_tail.block_number == StarknetBlockNumber::GENESIS {
                        break None;
                    }

                    // Reqeuest the previous Starknet block update.
                    let update = match event_sender.get_update(reorg_tail.block_number - 1).await {
                        Ok(update) => update,
                        Err(_exit) => return Ok(()),
                    };

                    // It is possible for the database to not contain this update if we only keep a limited history.
                    // In which case we have to essentially reset to starting from genesis again.
                    let update = match update {
                        Some(update) => update,
                        None => {
                            break None;
                        }
                    };

                    // Fetch the L1 block for this Starknet update.
                    //
                    // We need to query L1 by block number. If we query by hash, this may still exist
                    // but won't be connected to the "main" L1 chain. So instead we query by number and
                    // check if the hash matches ours. It is also possible the block number no longer exists,
                    // in which case this block is also invalid.
                    if let Some(block_hash) = eth_api
                        .block_hash(update.origin.block.number)
                        .await
                        .context("Fetch block from L1")?
                    {
                        if update.origin.block.hash == block_hash {
                            break Some(update);
                        }
                    }
                    // This block no longer exists, update tail and check next block.
                    reorg_tail = update;
                };

                let reorg_tail_number = new_head
                    .as_ref()
                    .map(|log| log.block_number + 1)
                    .unwrap_or(StarknetBlockNumber::GENESIS);

                // Send Reorg event, with the oldest Starknet block which was invalidated by this L1 reorg.
                if let Err(_exit) = event_sender.reorg(reorg_tail_number).await {
                    return Ok(());
                }

                // Update the Ethereum log fetcher.
                eth_api.set_log_head(new_head).await;
            }
            // Unreachable provided that `eth_api` implements a retry policy.
            Err(FetchError::Other(other)) => anyhow::bail!(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod sync_ethereum_state_impl {
        use super::*;
        use ethers::types::H256;
        use pathfinder_common::{
            felt, EthereumLogIndex, EthereumTransactionHash, EthereumTransactionIndex,
            StateCommitment,
        };
        use pathfinder_ethereum::{BlockOrigin, EthOrigin, TransactionOrigin};
        use stark_hash::Felt;

        #[tokio::test]
        async fn happy_path() {
            // Test that we receive log update events in the correct order.
            //
            // We use an EthereumApi mocker, which expects 2 `fetch_logs` calls
            // and returns a different log batch for each call.
            //
            // We then expect two log update events to be emitted which match batch
            // 1 and then 2 respectively.

            // Channel capacity should be one so we can block further events, after the ones
            // we care about i.e. so the process doesn't keep querying.
            let (tx_event, mut rx_event) = mpsc::channel(1);

            let logs1 = vec![StateUpdateLog {
                origin: EthOrigin {
                    block: BlockOrigin {
                        hash: EthereumBlockHash(H256::from_low_u64_be(133)),
                        number: EthereumBlockNumber(200),
                    },
                    transaction: TransactionOrigin {
                        hash: EthereumTransactionHash(H256::from_low_u64_be(244)),
                        index: EthereumTransactionIndex(211),
                    },
                    log_index: EthereumLogIndex(10),
                },
                global_root: StateCommitment(felt!("0x123")),
                block_number: StarknetBlockNumber::GENESIS,
            }];

            let logs2 = vec![StateUpdateLog {
                origin: EthOrigin {
                    block: BlockOrigin {
                        hash: EthereumBlockHash(H256::from_low_u64_be(441)),
                        number: EthereumBlockNumber(213),
                    },
                    transaction: TransactionOrigin {
                        hash: EthereumTransactionHash(H256::from_low_u64_be(555)),
                        index: EthereumTransactionIndex(21),
                    },
                    log_index: EthereumLogIndex(2),
                },
                global_root: StateCommitment(felt!("0x456abc")),
                block_number: StarknetBlockNumber::new_or_panic(1),
            }];

            // Create a mocker which expects
            let mut mock_fetcher = MockEthereumApi::new();
            let mut seq = mockall::Sequence::new();
            let mock_output = Ok(logs1.clone());
            mock_fetcher
                .expect_fetch_logs()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(move || mock_output);
            let mock_output = Ok(logs2.clone());
            mock_fetcher
                .expect_fetch_logs()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(move || mock_output);
            // The process will keep trying to fetch logs, so we need to
            // accept a third call. Output doesn't matter as we block progress
            // by not receiving the third event.
            let mock_output = Ok(logs2.clone());
            mock_fetcher
                .expect_fetch_logs()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|| mock_output);

            tokio::spawn(sync_impl(mock_fetcher, tx_event, Chain::Testnet));

            match rx_event.recv().await.unwrap() {
                Event::Update(recv) => assert_eq!(recv, logs1),
                _other => panic!("Expected Updates event"),
            }

            match rx_event.recv().await.unwrap() {
                Event::Update(recv) => assert_eq!(recv, logs2),
                _other => panic!("Expected Updates event"),
            }
        }

        #[tokio::test]
        async fn shutdown() {
            let (tx_event, mut rx_event) = mpsc::channel(1);

            let logs = vec![StateUpdateLog {
                origin: EthOrigin {
                    block: BlockOrigin {
                        hash: EthereumBlockHash(H256::from_low_u64_be(133)),
                        number: EthereumBlockNumber(200),
                    },
                    transaction: TransactionOrigin {
                        hash: EthereumTransactionHash(H256::from_low_u64_be(244)),
                        index: EthereumTransactionIndex(211),
                    },
                    log_index: EthereumLogIndex(10),
                },
                global_root: StateCommitment(felt!("0x123")),
                block_number: StarknetBlockNumber::GENESIS,
            }];

            // Closing the event's channel should trigger the sync to exit after the first send.
            rx_event.close();
            let mut mock_fetcher = MockEthereumApi::new();
            mock_fetcher
                .expect_fetch_logs()
                .return_once(move || Ok(logs));
            let handle = tokio::spawn(sync_impl(mock_fetcher, tx_event, Chain::Testnet));

            // Wrap this in a timeout so we don't wait forever in case of test failure.
            tokio::time::timeout(Duration::from_secs(2), handle)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }

        mod reorg {
            use super::*;

            #[tokio::test]
            async fn partial() {
                // Test a partial reorg, i.e. we still have valid blocks remaining after the reorg.
                let (tx_event, mut rx_event) = mpsc::channel(1);

                // Create somewhat unique logs with sequential Starknet block numbers.
                let logs = (0..10)
                    .map(|i| StateUpdateLog {
                        origin: EthOrigin {
                            block: BlockOrigin {
                                hash: EthereumBlockHash(H256::from_low_u64_be(i * 3 + 10)),
                                number: EthereumBlockNumber(i * 2 + 5999),
                            },
                            transaction: TransactionOrigin {
                                hash: EthereumTransactionHash(H256::from_low_u64_be(i + 21)),
                                index: EthereumTransactionIndex(i + 10),
                            },
                            log_index: EthereumLogIndex(i + 3),
                        },
                        global_root: StateCommitment(
                            Felt::from_hex_str(&i.to_string().repeat(i as usize)).unwrap(),
                        ),
                        block_number: StarknetBlockNumber::new_or_panic(i),
                    })
                    .collect::<Vec<_>>();

                const REORG_COUNT: usize = 4;
                let expected_tail = logs.iter().rev().nth(REORG_COUNT).unwrap().clone();
                let expected_head = logs.iter().rev().nth(REORG_COUNT + 1).unwrap().clone();

                let mut mock_fetcher = MockEthereumApi::new();
                let mut seq = mockall::Sequence::new();
                let mock_output = Ok(logs.clone());
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(move || mock_output);
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(|| Err(FetchError::Reorg));
                // We now expect queries for Starknet blocks and a check for the Ethereum hash thereof.
                // This should start at head-1, until we give a hash that does match.
                mock_fetcher
                    .expect_log_head()
                    .return_const(logs.last().cloned());
                let mock_head = expected_head.clone();
                mock_fetcher.expect_block_hash().returning(move |block| {
                    if block == mock_head.origin.block.number {
                        Ok(Some(mock_head.origin.block.hash))
                    } else {
                        Ok(Some(EthereumBlockHash(H256::from_low_u64_be(66666))))
                    }
                });
                let mock_head = Some(expected_head);
                mock_fetcher
                    .expect_set_log_head()
                    .times(1)
                    .in_sequence(&mut seq)
                    .withf(move |x| x == &mock_head)
                    .return_const(());
                let mock_output = Ok(logs.clone());
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(move || mock_output);

                tokio::spawn(sync_impl(mock_fetcher, tx_event, Chain::Testnet));

                // Receive first log update event.
                match rx_event.recv().await.unwrap() {
                    Event::Update(recv) => assert_eq!(recv, logs),
                    _other => panic!("Expected Updates event"),
                }

                // Answer the get update requests.
                for i in 0..REORG_COUNT + 1 {
                    let log = logs[logs.len() - 2 - i].clone();
                    match rx_event.recv().await.unwrap() {
                        Event::QueryUpdate(block, tx) => {
                            assert_eq!(block, log.block_number);
                            tx.send(Some(log.clone())).unwrap();
                        }
                        _other => panic!("Expected GetUpdate event"),
                    }
                }

                // We now expect a reorg event to be emitted.
                match rx_event.recv().await.unwrap() {
                    Event::Reorg(recv_tail) => {
                        assert_eq!(recv_tail, expected_tail.block_number)
                    }
                    _other => panic!("Expected Reorg event, got {_other:?}"),
                }
            }

            #[tokio::test]
            async fn to_genesis() {
                // Test a full reorg, i.e. all blocks are invalid.
                let (tx_event, mut rx_event) = mpsc::channel(1);

                // Create somewhat unique logs with sequential Starknet block numbers.
                let logs = (0..10)
                    .map(|i| StateUpdateLog {
                        origin: EthOrigin {
                            block: BlockOrigin {
                                hash: EthereumBlockHash(H256::from_low_u64_be(i * 3 + 10)),
                                number: EthereumBlockNumber(i * 2 + 5999),
                            },
                            transaction: TransactionOrigin {
                                hash: EthereumTransactionHash(H256::from_low_u64_be(i + 21)),
                                index: EthereumTransactionIndex(i + 10),
                            },
                            log_index: EthereumLogIndex(i + 3),
                        },
                        global_root: StateCommitment(
                            Felt::from_hex_str(&i.to_string().repeat(i as usize)).unwrap(),
                        ),
                        block_number: StarknetBlockNumber::new_or_panic(i),
                    })
                    .collect::<Vec<_>>();

                let mut mock_fetcher = MockEthereumApi::new();
                let mut seq = mockall::Sequence::new();
                let mock_output = Ok(logs.clone());
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(move || mock_output);
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(|| Err(FetchError::Reorg));
                mock_fetcher
                    .expect_set_log_head()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_const(())
                    .withf(|x| x.is_none());
                mock_fetcher
                    .expect_log_head()
                    .times(1)
                    .return_const(logs.last().cloned());
                mock_fetcher
                    .expect_block_hash()
                    .returning(|_| Ok(Some(EthereumBlockHash(H256::from_low_u64_be(66666)))));
                let mock_output = Ok(logs.clone());
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(move || mock_output);

                tokio::spawn(sync_impl(mock_fetcher, tx_event, Chain::Testnet));

                // Receive the first log update event.
                match rx_event.recv().await.unwrap() {
                    Event::Update(recv) => assert_eq!(recv, logs),
                    _other => panic!("Expected Updates event"),
                }

                // Answer the GetUpdate queries.
                for log in logs.iter().rev().skip(1) {
                    match rx_event.recv().await.unwrap() {
                        Event::QueryUpdate(block, tx) => {
                            assert_eq!(block, log.block_number);
                            tx.send(Some(log.clone())).unwrap();
                        }
                        _other => panic!("Expected GetUpdate event"),
                    }
                }

                // We now expect a reorg event to be emitted.
                match rx_event.recv().await.unwrap() {
                    Event::Reorg(recv_tail) => {
                        assert_eq!(recv_tail, StarknetBlockNumber::GENESIS)
                    }
                    _other => panic!("Expected Reorg event"),
                }
            }

            #[tokio::test]
            async fn past_known_history() {
                // Test a full reorg where we only kept the last N blocks of history. i.e. there was a partial-reorg
                // but it exceeded our stored history so we need to full reset anyway.
                let (tx_event, mut rx_event) = mpsc::channel(1);

                // Create somewhat unique logs with sequential Starknet block numbers.
                let logs = (0..10)
                    .map(|i| StateUpdateLog {
                        origin: EthOrigin {
                            block: BlockOrigin {
                                hash: EthereumBlockHash(H256::from_low_u64_be(i * 3 + 10)),
                                number: EthereumBlockNumber(i * 2 + 5999),
                            },
                            transaction: TransactionOrigin {
                                hash: EthereumTransactionHash(H256::from_low_u64_be(i + 21)),
                                index: EthereumTransactionIndex(i + 10),
                            },
                            log_index: EthereumLogIndex(i + 3),
                        },
                        global_root: StateCommitment(
                            Felt::from_hex_str(&i.to_string().repeat(i as usize)).unwrap(),
                        ),
                        block_number: StarknetBlockNumber::new_or_panic(i),
                    })
                    .collect::<Vec<_>>();

                let mut mock_fetcher = MockEthereumApi::new();
                let mut seq = mockall::Sequence::new();
                let mock_output = Ok(logs.clone());
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(move || mock_output);
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(|| Err(FetchError::Reorg));
                // We now expect queries for Starknet blocks and a check for the Ethereum hash thereof.
                // This should start at head-1, until we give a hash that does match.
                mock_fetcher
                    .expect_log_head()
                    .return_const(logs.last().cloned());
                mock_fetcher.expect_set_log_head().return_const(());
                mock_fetcher
                    .expect_block_hash()
                    .returning(|_| Ok(Some(EthereumBlockHash(H256::from_low_u64_be(66666)))));
                let mock_output = Ok(logs.clone());
                mock_fetcher
                    .expect_fetch_logs()
                    .times(1)
                    .in_sequence(&mut seq)
                    .return_once(move || mock_output);

                tokio::spawn(sync_impl(mock_fetcher, tx_event, Chain::Testnet));

                // First log batch event.
                match rx_event.recv().await.unwrap() {
                    Event::Update(recv) => assert_eq!(recv, logs),
                    _other => panic!("Expected Updates event"),
                }

                for i in 0..4 {
                    let log = logs[logs.len() - 2 - i].clone();
                    match rx_event.recv().await.unwrap() {
                        Event::QueryUpdate(block, tx) => {
                            assert_eq!(block, log.block_number);
                            tx.send(Some(log.clone())).unwrap();
                        }
                        _other => panic!("Expected GetUpdate event"),
                    }
                }
                match rx_event.recv().await.unwrap() {
                    Event::QueryUpdate(_, tx) => {
                        tx.send(None).unwrap();
                    }
                    _other => panic!("Expected GetUpdate event"),
                }

                // We expect a reorg event up to genesis.
                match rx_event.recv().await.unwrap() {
                    Event::Reorg(recv_tail) => {
                        assert_eq!(recv_tail, StarknetBlockNumber::GENESIS)
                    }
                    _other => panic!("Expected Reorg event, got {_other:?}"),
                }
            }
        }
    }
}
