//! Handles syncing Starknet state from the Ethereum chain.
//!
//! [sync_ethereum_state] is the entry-point and is meant to be a long running
//!  process which fetches [StateUpdateLogs](StateUpdateLog) from L1.
//!
//! New logs and reorg events are communicated using [Events](Event).

// TODO: remove this once we use this code.
#![allow(dead_code)]

use std::time::Duration;

use anyhow::Context;
use tokio::sync::{mpsc, oneshot};
use web3::{
    transports::Http,
    types::{BlockId, BlockNumber},
    Transport, Web3,
};

use crate::{
    core::{EthereumBlockHash, EthereumBlockNumber, StarknetBlockNumber},
    ethereum::{
        log::{FetchError, StateUpdateLog},
        state_update::state_root::StateRootFetcher,
        Chain,
    },
};

/// The set of events which may be emitted by [sync_ethereum_state].
#[derive(Debug)]
pub enum Event {
    /// Request the [StateUpdateLog] for the [StarknetBlockNumber]. The result should be returned
    /// using the [oneshot::Sender] channel.
    GetUpdate(StarknetBlockNumber, oneshot::Sender<Option<StateUpdateLog>>),
    /// Batch of new [StateUpdateLog].
    Updates(Vec<StateUpdateLog>),
    /// An L1 reorg was detected. Contains the reorg tail.
    /// i.e. all blocks __up-to-and-including__ this value are now invalid.
    Reorg(StarknetBlockNumber),
}

/// Syncs L1 state update logs. Emits [Events](Event) which should be handled
/// to update storage and respond to queries.
pub async fn sync_ethereum_state(
    tx_event: mpsc::Sender<Event>,
    transport: Web3<Http>,
    chain: Chain,
    head: Option<StateUpdateLog>,
) -> anyhow::Result<()> {
    // Spawn the Ethereum command handling function.
    let (tx_eth, rx_eth) = mpsc::channel(5);
    let eth_future = ethereum_fetcher(chain, transport, rx_eth, head.clone());
    let _eth_future = tokio::spawn(eth_future);

    // The core sync logic implementation.
    sync_ethereum_state_impl(tx_eth, tx_event, head).await
}

/// Sends [Events](Event) on its channel.
///
/// Main purpose is to simplify the code in [sync_ethereum_state_impl] by abstracting
/// out the error mapping and oneshot channel receives.
struct EventSender(mpsc::Sender<Event>);

#[derive(Debug, PartialEq, Clone, Copy)]
struct ChannelClosedError;

impl EventSender {
    /// Sends [Event::GetUpdate] on its channel and returns the result.
    async fn get_update(
        &self,
        block: StarknetBlockNumber,
    ) -> Result<Option<StateUpdateLog>, ChannelClosedError> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Event::GetUpdate(block, tx))
            .await
            .map_err(|_send_err| ChannelClosedError)?;

        rx.await.map_err(|_recv_err| ChannelClosedError)
    }

    /// Sends [Event::Updates] on its channel.
    async fn updates(&self, updates: Vec<StateUpdateLog>) -> Result<(), ChannelClosedError> {
        self.0
            .send(Event::Updates(updates))
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

/// Set of Ethereum queries and commands which [sync_ethereum_state_impl] may emit.
///
/// The receiver of these commands should be capable of instrumenting a [StateRootFetcher]
/// as well as fetching [EthereumBlockHash] from the Ethereum chain.
#[derive(Debug)]
enum EthereumCommand {
    /// Set the [StateRootFetcher's](StateRootFetcher) head to the given value.
    NewLogHead(Option<StateUpdateLog>),
    /// Return the next set of logs from the [StateRootFetcher].
    FetchLogs(oneshot::Sender<FetchResult>),
    /// Fetch the [EthereumBlockHash] for the given [EthereumBlockNumber].
    FetchBlockHash(
        EthereumBlockNumber,
        oneshot::Sender<Option<EthereumBlockHash>>,
    ),
}
type FetchResult = Result<Vec<StateUpdateLog>, FetchError>;

/// Sends [EthereumCommands](EthereumCommand) on its channel.
///
/// Main purpose is to simplify the code in [sync_ethereum_state_impl] by abstracting
/// out the error mapping and oneshot channel receives.
struct EthereumCommander(mpsc::Sender<EthereumCommand>);
impl EthereumCommander {
    /// Sends a [EthereumCommand::NewLogHead] command.
    async fn new_log_head(&self, head: Option<StateUpdateLog>) -> anyhow::Result<()> {
        self.0
            .send(EthereumCommand::NewLogHead(head.clone()))
            .await
            .map_err(|_send_err| anyhow::anyhow!("Ethereum commands channel closed"))
            .context("Initializing log fetching")
    }

    /// Sends a [EthereumCommand::FetchLogs] command and returns the result.
    async fn fetch_logs(&self) -> anyhow::Result<FetchResult> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(EthereumCommand::FetchLogs(tx))
            .await
            .map_err(|_send_err| anyhow::anyhow!("Ethereum commands channel closed"))
            .context("Fetch logs")?;
        rx.await
            .map_err(|_recv_err| anyhow::anyhow!("Oneshot channel closed"))
            .context("Fetch logs")
    }

    /// Sends a [EthereumCommand::FetchBlockHash] command and returns the result.
    async fn fetch_block_hash(
        &self,
        block: EthereumBlockNumber,
    ) -> anyhow::Result<Option<EthereumBlockHash>> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(EthereumCommand::FetchBlockHash(block, tx))
            .await
            .map_err(|_send_err| anyhow::anyhow!("Ethereum commands channel closed"))
            .context("Fetch Ethereum block hash")?;

        rx.await
            .map_err(|_recv_err| anyhow::anyhow!("Oneshot channel closed"))
            .context("Fetch Ethereum block hash")
    }
}

/// A receiver for [EthereumCommand].
///
/// The [StateRootFetcher] is initialized to start from `head`.
///
/// This function runs until the `rx_eth_cmds` channel is closed.
async fn ethereum_fetcher<Tr: Transport + std::marker::Send>(
    chain: Chain,
    transport: Web3<Tr>,
    mut rx_eth_cmds: mpsc::Receiver<EthereumCommand>,
    head: Option<StateUpdateLog>,
) -> anyhow::Result<()> {
    let mut fetcher = StateRootFetcher::new(head, chain);

    while let Some(cmd) = rx_eth_cmds.recv().await {
        use EthereumCommand::*;
        match cmd {
            NewLogHead(head) => fetcher = StateRootFetcher::new(head, chain),
            FetchLogs(tx) => {
                let result = fetcher.fetch(&transport).await;
                tx.send(result)
                    .map_err(|_recv_err| anyhow::anyhow!("Oneshot channel closed"))
                    .context("Send fetch log result")?;
            }
            FetchBlockHash(block, tx) => {
                let result = transport
                    .eth()
                    .block(BlockId::Number(BlockNumber::Number(block.0.into())))
                    .await
                    .context("Fetch block from L1")?
                    // Unwrap is safe as block hash is only None when used with pending.
                    .map(|block| EthereumBlockHash(block.hash.unwrap()));
                tx.send(result)
                    .map_err(|_recv_err| anyhow::anyhow!("Oneshot channel closed"))
                    .context("Send fetch block hash result")?;
            }
        }
    }

    Ok(())
}

/// The sync logic for [sync_ethereum_state].
///
/// It uses an extra channel to communicate [EthereumCommands](EthereumCommand) which enables testing
/// this logic independently of an actual Ethereum endpoint. This also allows us to test reorgs more
/// effectively.
///
/// Runs until the `tx_event` channel is closed, at which point this function will close the `tx_eth_cmds` channel.
///
/// Expects the [EthereumCommand] receiver to have been configured with the same `head` update log.
///
/// # Algorithm overview
///
/// On the happy path, we fetch the next batch of Starknet state update logs from Ethereum and emit
/// these using [Event::Updates].
///
/// If there was an Ethereum reorg, we determine which of our Starknet blocks is now invalidated
/// and emit the [Event::Reorg] event.
async fn sync_ethereum_state_impl(
    tx_eth_cmds: mpsc::Sender<EthereumCommand>,
    tx_event: mpsc::Sender<Event>,
    mut head: Option<StateUpdateLog>,
) -> anyhow::Result<()> {
    let eth_cmd = EthereumCommander(tx_eth_cmds);
    let event_sender = EventSender(tx_event);

    loop {
        match eth_cmd.fetch_logs().await? {
            Ok(logs) => {
                // If empty, then we are at head of chain, sleep a bit and try again.
                if logs.is_empty() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }

                // There were log updates, send the event!
                head = logs.last().cloned();
                if let Err(_exit) = event_sender.updates(logs).await {
                    return Ok(());
                }
            }
            Err(FetchError::Reorg) => {
                // Unwrap is safe as it is not be possible to get a reorg event if there
                // was no latest log to reorg against. We know that this block already needs to
                // be reorg'd since it triggered the reorg in the first place.
                let mut reorg_tail = head.clone().unwrap();

                // Check each Starknet block in reverse history order, until we find a still
                // valid block. This becomes the new head of our L1 state.
                head = loop {
                    // We have reached Starknet genesis, no older blocks to check.
                    if reorg_tail.block_number == StarknetBlockNumber::GENESIS {
                        break None;
                    }

                    // Reqeuest the previous Starknet block update.
                    let update = match event_sender
                        .get_update(reorg_tail.block_number.decrement())
                        .await
                    {
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
                    if let Some(block_hash) =
                        eth_cmd.fetch_block_hash(update.origin.block.number).await?
                    {
                        if update.origin.block.hash == block_hash {
                            break Some(update);
                        }
                    }
                    // This block no longer exists, update tail and check next block.
                    reorg_tail = update;
                };

                let reorg_tail_number = head
                    .as_ref()
                    .map(|log| log.block_number.increment())
                    .unwrap_or(StarknetBlockNumber::GENESIS);

                // Send Reorg event, with the oldest Starknet block which was invalidated by this L1 reorg.
                if let Err(_exit) = event_sender.reorg(reorg_tail_number).await {
                    return Ok(());
                }

                // Update the Ethereum log fetcher.
                eth_cmd.new_log_head(head.clone()).await?;
            }
            Err(FetchError::Other(other)) => anyhow::bail!(other),
        }
    }
}

// TODO: tests
#[cfg(test)]
mod tests {
    use super::*;

    mod sync_ethereum_state_impl {
        use assert_matches::assert_matches;
        use pedersen::StarkHash;
        use web3::types::H256;

        use crate::{
            core::{
                EthereumLogIndex, EthereumTransactionHash, EthereumTransactionIndex, GlobalRoot,
            },
            ethereum::{BlockOrigin, EthOrigin, TransactionOrigin},
        };

        use super::*;

        #[tokio::test]
        async fn happy_path() {
            let (tx_event, mut rx_event) = mpsc::channel(5);
            let (tx_eth, mut rx_eth) = mpsc::channel(5);

            tokio::spawn(sync_ethereum_state_impl(tx_eth, tx_event, None));

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
                global_root: GlobalRoot(StarkHash::from_hex_str("123").unwrap()),
                block_number: StarknetBlockNumber(0),
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
                global_root: GlobalRoot(StarkHash::from_hex_str("456abc").unwrap()),
                block_number: StarknetBlockNumber(1),
            }];

            match rx_eth.recv().await.unwrap() {
                EthereumCommand::FetchLogs(tx) => tx.send(Ok(logs1.clone())).unwrap(),
                _other => panic!("Expected FetchLogs command"),
            }

            match rx_eth.recv().await.unwrap() {
                EthereumCommand::FetchLogs(tx) => tx.send(Ok(logs2.clone())).unwrap(),
                _other => panic!("Expected FetchLogs command"),
            }

            match rx_event.recv().await.unwrap() {
                Event::Updates(logs) => assert_eq!(logs, logs1),
                _other => panic!("Expected Updates event"),
            }

            match rx_event.recv().await.unwrap() {
                Event::Updates(logs) => assert_eq!(logs, logs2),
                _other => panic!("Expected Updates event"),
            }
        }

        #[tokio::test]
        async fn shutdown() {
            use tokio::sync::mpsc::error::TryRecvError;

            let (tx_event, mut rx_event) = mpsc::channel(5);
            let (tx_eth, mut rx_eth) = mpsc::channel(5);

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
                global_root: GlobalRoot(StarkHash::from_hex_str("123").unwrap()),
                block_number: StarknetBlockNumber(0),
            }];

            // Closing the event's channel should trigger the sync to exit after the first send.
            rx_event.close();
            let handle = tokio::spawn(sync_ethereum_state_impl(tx_eth, tx_event, None));

            match rx_eth.recv().await.unwrap() {
                EthereumCommand::FetchLogs(tx) => tx.send(Ok(logs1)).unwrap(),
                _other => panic!("Expected FetchLogs command"),
            }
            // Wrap this in a timeout so we don't wait forever in case of test failure.
            tokio::time::timeout(Duration::from_secs(2), handle)
                .await
                .unwrap()
                .unwrap()
                .unwrap();

            // This in turn should close the Ethereum commands channel.
            assert_matches!(rx_eth.try_recv(), Err(TryRecvError::Disconnected));
        }

        mod reorg {
            use super::*;

            #[tokio::test]
            // Test a partial reorg, i.e. we still have valid blocks remaining after the reorg.
            async fn partial() {
                let (tx_event, mut rx_event) = mpsc::channel(5);
                let (tx_eth, mut rx_eth) = mpsc::channel(5);

                tokio::spawn(sync_ethereum_state_impl(tx_eth, tx_event, None));

                // Create somewhat unique logs with sequential Starknet block numbers.
                let mut logs = (0..10)
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
                        global_root: GlobalRoot(
                            StarkHash::from_hex_str(&i.to_string().repeat(i as usize)).unwrap(),
                        ),
                        block_number: StarknetBlockNumber(i as u64),
                    })
                    .collect::<Vec<_>>();

                // Send some logs which we can then reorg
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::FetchLogs(tx) => tx.send(Ok(logs.clone())).unwrap(),
                    _other => panic!("Expected FetchLogs command"),
                }
                match rx_event.recv().await.unwrap() {
                    Event::Updates(recv) => assert_eq!(recv, logs),
                    _other => panic!("Expected Updates event"),
                }

                // Trigger a reorg
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::FetchLogs(tx) => tx.send(Err(FetchError::Reorg)).unwrap(),
                    _other => panic!("Expected FetchLogs command"),
                }

                // We now expect queries for Starknet blocks and a check for the Ethereum hash thereof.
                // This should start at head-1, until we give a hash that does match.
                let mut reorg_tail = logs.pop().unwrap().block_number;
                for _ in 0..4 {
                    let log = logs.pop().unwrap();
                    reorg_tail = log.block_number;

                    match rx_event.recv().await.unwrap() {
                        Event::GetUpdate(block, tx) => {
                            assert_eq!(block, log.block_number);
                            tx.send(Some(log.clone())).unwrap();
                        }
                        _other => panic!("Expected GetUpdate event"),
                    }

                    // Send back a mismatching hash, indicating that this block should be reorg'd.
                    match rx_eth.recv().await.unwrap() {
                        EthereumCommand::FetchBlockHash(block, tx) => {
                            assert_eq!(block, log.origin.block.number);
                            tx.send(Some(EthereumBlockHash(H256::from_low_u64_be(66666))))
                                .unwrap();
                        }
                        _other => panic!("Expected FetchBlockHash command"),
                    }
                }

                // This time send a matching hash, so that the reorg checking stops.
                let head = logs.pop().unwrap();
                match rx_event.recv().await.unwrap() {
                    Event::GetUpdate(block, tx) => {
                        assert_eq!(block, head.block_number);
                        tx.send(Some(head.clone())).unwrap();
                    }
                    _other => panic!("Expected GetUpdate event"),
                }
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::FetchBlockHash(block, tx) => {
                        assert_eq!(block, head.origin.block.number);
                        tx.send(Some(head.origin.block.hash)).unwrap();
                    }
                    _other => panic!("Expected FetchBlockHash command"),
                }

                // We now expect a reorg event to be emitted.
                match rx_event.recv().await.unwrap() {
                    Event::Reorg(recv_tail) => assert_eq!(recv_tail, reorg_tail),
                    _other => panic!("Expected Reorg event"),
                }

                // And a NewLogHead for the Ethereum logs.
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::NewLogHead(recv_head) => assert_eq!(recv_head, Some(head)),
                    _other => panic!("Expected NewLogHead command"),
                }
            }

            #[tokio::test]
            // Test a full reorg, i.e. all blocks are invalid.
            async fn to_genesis() {
                let (tx_event, mut rx_event) = mpsc::channel(5);
                let (tx_eth, mut rx_eth) = mpsc::channel(5);

                tokio::spawn(sync_ethereum_state_impl(tx_eth, tx_event, None));

                // Create somewhat unique logs with sequential Starknet block numbers.
                let mut logs = (0..10)
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
                        global_root: GlobalRoot(
                            StarkHash::from_hex_str(&i.to_string().repeat(i as usize)).unwrap(),
                        ),
                        block_number: StarknetBlockNumber(i as u64),
                    })
                    .collect::<Vec<_>>();

                // Send some logs which we can then reorg
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::FetchLogs(tx) => tx.send(Ok(logs.clone())).unwrap(),
                    _other => panic!("Expected FetchLogs command"),
                }
                match rx_event.recv().await.unwrap() {
                    Event::Updates(recv) => assert_eq!(recv, logs),
                    _other => panic!("Expected Updates event"),
                }

                // Trigger a reorg
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::FetchLogs(tx) => tx.send(Err(FetchError::Reorg)).unwrap(),
                    _other => panic!("Expected FetchLogs command"),
                }

                // We now expect queries for Starknet blocks and a check for the Ethereum hash thereof.
                // This should start at head-1, until we give a hash that does match. Since we are testing
                // a full reorg including genesis, we do this for all blocks.
                let mut reorg_tail = logs.pop().unwrap().block_number;
                for _ in 0..logs.len() {
                    let log = logs.pop().unwrap();
                    reorg_tail = log.block_number;

                    match rx_event.recv().await.unwrap() {
                        Event::GetUpdate(block, tx) => {
                            assert_eq!(block, log.block_number);
                            tx.send(Some(log.clone())).unwrap();
                        }
                        _other => panic!("Expected GetUpdate event"),
                    }

                    // Send back a mismatching hash, indicating that this block should be reorg'd.
                    match rx_eth.recv().await.unwrap() {
                        EthereumCommand::FetchBlockHash(block, tx) => {
                            assert_eq!(block, log.origin.block.number);
                            tx.send(Some(EthereumBlockHash(H256::from_low_u64_be(66666))))
                                .unwrap();
                        }
                        _other => panic!("Expected FetchBlockHash command"),
                    }
                }

                // We now expect a reorg event to be emitted.
                match rx_event.recv().await.unwrap() {
                    Event::Reorg(recv_tail) => assert_eq!(recv_tail, reorg_tail),
                    _other => panic!("Expected Reorg event"),
                }

                // And a None NewLogHead for the Ethereum logs.
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::NewLogHead(recv_head) => assert_eq!(recv_head, None),
                    _other => panic!("Expected NewLogHead command"),
                }
            }

            #[tokio::test]
            // Test a full reorg where we only kept the last N blocks of history. i.e. all of our
            // blocks are invalid but we did not keep full history. This means we should restart
            // from genesis again.
            async fn past_known_history() {
                let (tx_event, mut rx_event) = mpsc::channel(5);
                let (tx_eth, mut rx_eth) = mpsc::channel(5);

                tokio::spawn(sync_ethereum_state_impl(tx_eth, tx_event, None));

                // Create somewhat unique logs with sequential Starknet block numbers.
                let mut logs = (0..10)
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
                        global_root: GlobalRoot(
                            StarkHash::from_hex_str(&i.to_string().repeat(i as usize)).unwrap(),
                        ),
                        block_number: StarknetBlockNumber(i as u64),
                    })
                    .collect::<Vec<_>>();

                // Send some logs which we can then reorg
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::FetchLogs(tx) => tx.send(Ok(logs.clone())).unwrap(),
                    _other => panic!("Expected FetchLogs command"),
                }
                match rx_event.recv().await.unwrap() {
                    Event::Updates(recv) => assert_eq!(recv, logs),
                    _other => panic!("Expected Updates event"),
                }

                // Trigger a reorg
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::FetchLogs(tx) => tx.send(Err(FetchError::Reorg)).unwrap(),
                    _other => panic!("Expected FetchLogs command"),
                }

                // We now expect queries for Starknet blocks and a check for the Ethereum hash thereof.
                // This should start at head-1, until we give a hash that does match.
                logs.pop().unwrap();
                for _ in 0..4 {
                    let log = logs.pop().unwrap();

                    match rx_event.recv().await.unwrap() {
                        Event::GetUpdate(block, tx) => {
                            assert_eq!(block, log.block_number);
                            tx.send(Some(log.clone())).unwrap();
                        }
                        _other => panic!("Expected GetUpdate event"),
                    }

                    // Send back a mismatching hash, indicating that this block should be reorg'd.
                    match rx_eth.recv().await.unwrap() {
                        EthereumCommand::FetchBlockHash(block, tx) => {
                            assert_eq!(block, log.origin.block.number);
                            tx.send(Some(EthereumBlockHash(H256::from_low_u64_be(66666))))
                                .unwrap();
                        }
                        _other => panic!("Expected FetchBlockHash command"),
                    }
                }

                // This time, send None to indicate that we no longer that have this block in our history.
                let head = logs.pop().unwrap();
                match rx_event.recv().await.unwrap() {
                    Event::GetUpdate(block, tx) => {
                        assert_eq!(block, head.block_number);
                        tx.send(None).unwrap();
                    }
                    _other => panic!("Expected GetUpdate event"),
                }

                // We now expect a reorg event to be emitted.
                match rx_event.recv().await.unwrap() {
                    Event::Reorg(recv_tail) => assert_eq!(recv_tail, StarknetBlockNumber::GENESIS),
                    _other => panic!("Expected Reorg event"),
                }

                // And a None NewLogHead for the Ethereum logs.
                match rx_eth.recv().await.unwrap() {
                    EthereumCommand::NewLogHead(recv_head) => assert_eq!(recv_head, None),
                    _other => panic!("Expected NewLogHead command"),
                }
            }
        }
    }

    mod ethereum_fetcher {
        use std::str::FromStr;

        use web3::types::H256;

        use crate::ethereum::test::create_test_transport;

        use super::*;

        #[tokio::test]
        async fn shutdown() {
            let chain = Chain::Goerli;
            let transport = create_test_transport(chain);
            let (tx, rx) = mpsc::channel(5);
            let handle = tokio::spawn(ethereum_fetcher(chain, transport, rx, None));

            // Closing the channel should end the process.
            drop(tx);
            handle.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn fetch_block_hash() {
            let chain = Chain::Goerli;
            let transport = create_test_transport(chain);
            let (tx_cmd, rx_cmd) = mpsc::channel(5);
            tokio::spawn(ethereum_fetcher(chain, transport, rx_cmd, None));

            // Known Goerli block taken from Etherscan: https://goerli.etherscan.io/block/6394313
            let block = EthereumBlockNumber(6394313);
            let expected = EthereumBlockHash(
                H256::from_str(
                    "0xb62e6ad17be4b190c58d856e1148d65aaff09be47f82a4149628fc11d51627f9",
                )
                .unwrap(),
            );
            let (tx, rx) = oneshot::channel();

            tx_cmd
                .send(EthereumCommand::FetchBlockHash(block, tx))
                .await
                .unwrap();

            assert_eq!(rx.await.unwrap(), Some(expected));
        }

        #[tokio::test]
        async fn logs() {
            let chain = Chain::Goerli;
            let transport = create_test_transport(chain);
            let (tx_cmd, rx_cmd) = mpsc::channel(5);

            tokio::spawn(ethereum_fetcher(chain, transport, rx_cmd, None));

            let (tx, rx) = oneshot::channel();
            tx_cmd.send(EthereumCommand::FetchLogs(tx)).await.unwrap();

            let mut log_fetcher = StateRootFetcher::new(None, chain);
            let transport = create_test_transport(chain);

            // First read
            let expected = log_fetcher.fetch(&transport).await.unwrap();
            let logs = rx.await.unwrap().unwrap();
            assert_eq!(logs, expected);

            // Pick arbitrary point to reset logs to.
            let reset_head = logs.last().cloned().unwrap();

            // Second read
            let (tx, rx) = oneshot::channel();
            tx_cmd.send(EthereumCommand::FetchLogs(tx)).await.unwrap();
            let expected = log_fetcher.fetch(&transport).await.unwrap();
            let logs = rx.await.unwrap().unwrap();
            assert_eq!(logs, expected);

            // Reset, should match second read.
            log_fetcher = StateRootFetcher::new(Some(reset_head.clone()), chain);
            let expected = log_fetcher.fetch(&transport).await.unwrap();
            tx_cmd
                .send(EthereumCommand::NewLogHead(Some(reset_head)))
                .await
                .unwrap();
            let (tx, rx) = oneshot::channel();
            tx_cmd.send(EthereumCommand::FetchLogs(tx)).await.unwrap();
            let logs = rx.await.unwrap().unwrap();
            assert_eq!(logs, expected);
        }
    }
}
