use web3::{
    types::{BlockNumber, FilterBuilder},
    Transport, Web3,
};

use crate::ethereum::log::{
    fetch::{EitherMetaLog, MetaLog},
    get_logs, GetLogsError,
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
    L: MetaLog + PartialEq + std::fmt::Debug,
    R: MetaLog + PartialEq + std::fmt::Debug,
{
    last_known: EitherMetaLog<L, R>,
    stride: u64,
    base_filter: FilterBuilder,
}

impl<L, R> BackwardLogFetcher<L, R>
where
    L: MetaLog + PartialEq + std::fmt::Debug,
    R: MetaLog + PartialEq + std::fmt::Debug,
{
    /// Creates a [LogFetcher](super::forward::LogFetcher) which fetches logs starting from `last_known`'s origin on L1.
    ///
    /// In other words, the first log returned will be the one *before* `last_known`.
    pub fn new(last_known: EitherMetaLog<L, R>) -> Self {
        let base_filter = FilterBuilder::default()
            .address(vec![L::contract_address(), R::contract_address()])
            .topics(Some(vec![L::signature(), R::signature()]), None, None, None);

        Self {
            last_known,
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
    pub async fn fetch<Tr: Transport>(
        &mut self,
        transport: &Web3<Tr>,
    ) -> Result<Vec<EitherMetaLog<L, R>>, BackwardFetchError> {
        let to_block = self.last_known.origin().block.number;
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
                Err(GetLogsError::Other(other)) => return Err(BackwardFetchError::Other(other)),
            };

            // We need to iterate in reverse since that is the direction we are searching in.
            let mut logs = logs.into_iter().rev();

            // Check for reorgs. Only required if there was a last known update to validate.
            //
            // We queried for logs starting from the same block as last known. We need to account
            // for logs that occurred in the same block and transaction, but with a larger log index.
            //
            // If the last known log is not in the set then we have a reorg event.
            loop {
                match logs.next().map(EitherMetaLog::try_from) {
                    Some(Ok(log))
                        if log.origin().block == self.last_known.origin().block
                            && log.origin().log_index > self.last_known.origin().log_index =>
                    {
                        continue;
                    }
                    Some(Ok(log)) if log == self.last_known => break,
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

            return Ok(logs);
        }
    }
}
