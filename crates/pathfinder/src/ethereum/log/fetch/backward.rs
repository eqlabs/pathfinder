use web3::types::{BlockNumber, FilterBuilder};

use crate::ethereum::{
    api::Web3EthApi,
    log::{
        fetch::{EitherMetaLog, MetaLog},
        get_logs, GetLogsError,
    },
    Chain,
};

#[derive(Debug)]
pub enum BackwardFetchError {
    /// An L1 chain reorganisation occurred. At the very least, the lastest log
    /// returned previously is now invalid.
    Reorg,
    /// L1 genesis has been reached, there are no more logs to fetch.
    GenesisReached,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for BackwardFetchError {
    fn from(err: anyhow::Error) -> Self {
        BackwardFetchError::Other(err)
    }
}

impl From<web3::error::Error> for BackwardFetchError {
    fn from(err: web3::error::Error) -> Self {
        BackwardFetchError::Other(anyhow::anyhow!(err))
    }
}

/// Fetches logs backwards through L1 history, accounting for chain
/// reorganisations. Fetches two logs types at once (see [EitherMetaLog]).
///
/// Similar to [LogFetcher](super::forward::LogFetcher), but going
/// backwards.
///
/// We use [EitherMetaLog] since we generally want to start
/// at some log type A, but search backwards for all logs of type B.
pub struct BackwardLogFetcher<L, R>
where
    L: MetaLog + PartialEq + std::fmt::Debug + Clone,
    R: MetaLog + PartialEq + std::fmt::Debug + Clone,
{
    tail: EitherMetaLog<L, R>,
    stride: u64,
    base_filter: FilterBuilder,
}

impl<L, R> BackwardLogFetcher<L, R>
where
    L: MetaLog + PartialEq + std::fmt::Debug + Clone,
    R: MetaLog + PartialEq + std::fmt::Debug + Clone,
{
    /// Creates a [LogFetcher](super::forward::LogFetcher) which fetches logs starting from `tail`'s origin on L1.
    ///
    /// In other words, the first log returned will be the one __before__ `tail`.
    pub fn new(tail: EitherMetaLog<L, R>, chain: Chain) -> Self {
        let base_filter = FilterBuilder::default()
            .address(vec![L::contract_address(chain), R::contract_address(chain)])
            .topics(Some(vec![L::signature(), R::signature()]), None, None, None);

        Self {
            tail,
            stride: 10_000,
            base_filter,
        }
    }

    /// Fetches the next set of logs from L1.
    ///
    /// ## Important: logs are returned in reverse chronological order.
    ///
    /// This set will never be empty. Reaching genesis is instead
    /// indicated by [BackwardFetchError::GenesisReached].
    pub async fn fetch(
        &mut self,
        transport: &impl Web3EthApi,
    ) -> Result<Vec<EitherMetaLog<L, R>>, BackwardFetchError> {
        let to_block = self.tail.origin().block.number.0;
        let base_filter = self
            .base_filter
            .clone()
            .to_block(BlockNumber::Number(to_block.into()));

        // The largest stride we are allowed to take. This gets
        // set if we encounter the Infura result cap error.
        //
        // Allows us to perform a binary search of the query range space.
        //
        // This is required to avoid cycles of:
        //   1. Find no new logs, increase search range
        //   2. Hit result limit error, decrease search range
        let mut stride_cap = None;

        loop {
            let from_block = to_block.saturating_sub(self.stride);
            let filter = base_filter
                .clone()
                .from_block(BlockNumber::Number(from_block.into()))
                .build();

            let logs = match get_logs(transport, filter).await {
                Ok(logs) => logs,
                Err(GetLogsError::QueryLimit) => {
                    stride_cap = Some(self.stride);
                    self.stride = (self.stride / 2).max(1);

                    continue;
                }
                Err(GetLogsError::UnknownBlock) => return Err(BackwardFetchError::Reorg),
                Err(GetLogsError::Other(other)) => return Err(BackwardFetchError::Other(other)),
            };

            // We need to iterate in reverse since that is the direction we are searching in.
            let mut logs = logs.into_iter().rev();

            // Check for reorgs.
            //
            // We queried for logs starting from the same block as tail. We need to account
            // for logs that occurred in the same block and transaction, but with a larger log index.
            //
            // If the tail log is not in the set then we have a reorg event.
            loop {
                match logs.next().map(EitherMetaLog::try_from) {
                    Some(Ok(log))
                        if log.origin().block == self.tail.origin().block
                            && log.origin().log_index.0 > self.tail.origin().log_index.0 =>
                    {
                        continue;
                    }
                    Some(Ok(log)) if log == self.tail => break,
                    _ => return Err(BackwardFetchError::Reorg),
                }
            }

            let logs = logs
                .map(EitherMetaLog::try_from)
                .collect::<Result<Vec<EitherMetaLog<L, R>>, _>>()?;

            // If there are no new logs, then either we have reached L1 genesis
            // or we need to increase our query range.
            if logs.is_empty() {
                if from_block > 0 {
                    match stride_cap {
                        Some(max) => self.stride = (self.stride.saturating_add(max + 1)) / 2,
                        None => self.stride = self.stride.saturating_mul(2),
                    }
                    continue;
                } else {
                    return Err(BackwardFetchError::GenesisReached);
                }
            }

            // unwrap is safe due to the is_empty check above.
            self.tail = logs.last().unwrap().clone();

            return Ok(logs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use pedersen::StarkHash;
    use web3::types::H256;

    use crate::{
        core::{
            EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
            EthereumTransactionIndex, GlobalRoot, StarknetBlockNumber,
        },
        ethereum::{
            log::StateUpdateLog, test_transport, BlockOrigin, EthOrigin, TransactionOrigin,
        },
    };

    #[tokio::test]
    async fn consistency() {
        // We use StateUpdateLog because it comes with a handy block number
        // we can use to check for sequentiality.
        let update_log = StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: EthereumBlockHash(
                        H256::from_str(
                            "0x0b3208a115098a1654a092b35c8668794c23ddfef35100c83d59fb9b5993bfbb",
                        )
                        .unwrap(),
                    ),
                    number: EthereumBlockNumber(5904264),
                },
                transaction: TransactionOrigin {
                    hash: EthereumTransactionHash(
                        H256::from_str(
                            "0xcdbfab0ca513e6b1c0eee89adb60478e7c8ea4d80edbddc470be41c630ae67c4",
                        )
                        .unwrap(),
                    ),
                    index: EthereumTransactionIndex(7),
                },
                log_index: EthereumLogIndex(17),
            },
            global_root: GlobalRoot(
                StarkHash::from_hex_str(
                    "0x05EA3EB34039C870869FD7E6E51B46C10A289AA88A8887E8DA8F1009D84EA98B",
                )
                .unwrap(),
            ),
            block_number: StarknetBlockNumber(7690),
        };

        // We use the same log type twice; this shouldn't matter and let's us check
        // the block number sequence.
        let chain = crate::ethereum::Chain::Goerli;
        let mut fetcher = BackwardLogFetcher::<StateUpdateLog, StateUpdateLog>::new(
            EitherMetaLog::Left(update_log.clone()),
            chain,
        );

        let transport = test_transport(chain);
        let logs = fetcher.fetch(&transport).await.unwrap();
        let mut block_number = update_log.block_number.0 - 1;
        for log in logs {
            let log = match log {
                EitherMetaLog::Left(log) => log,
                EitherMetaLog::Right(log) => log,
            };
            assert_eq!(log.block_number.0, block_number, "First fetch");
            block_number -= 1;
        }
        let logs = fetcher.fetch(&transport).await.unwrap();
        for log in logs {
            let log = match log {
                EitherMetaLog::Left(log) => log,
                EitherMetaLog::Right(log) => log,
            };
            assert_eq!(log.block_number.0, block_number, "Second fetch");
            block_number -= 1;
        }
    }
}
