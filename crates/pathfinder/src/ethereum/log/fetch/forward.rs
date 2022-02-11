use anyhow::Context;
use web3::{
    types::{BlockNumber, FilterBuilder},
    Transport, Web3,
};

use crate::ethereum::log::{fetch::MetaLog, get_logs, GetLogsError};

/// Fetches consecutive logs of type T from L1, accounting for chain
/// reorganisations.
pub struct LogFetcher<T>
where
    T: MetaLog + PartialEq + std::fmt::Debug + Clone,
{
    last_known: Option<T>,
    stride: u64,
    base_filter: FilterBuilder,
}

#[derive(Debug)]
pub enum FetchError {
    /// An L1 chain reorganisation occurred. At the very least, the lastest log
    /// returned previously is now invalid.
    Reorg,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for FetchError {
    fn from(err: anyhow::Error) -> Self {
        FetchError::Other(err)
    }
}

impl<T> LogFetcher<T>
where
    T: MetaLog + PartialEq + std::fmt::Debug + Clone,
{
    /// Creates a [LogFetcher] which fetches logs starting from `last_known`'s origin on L1.
    /// If `last_known` is [None] then the starting point is genesis.
    ///
    /// In other words, the first log returned will be the one after `last_known`.
    pub fn new(last_known: Option<T>) -> Self {
        let base_filter = FilterBuilder::default()
            .address(vec![T::contract_address()])
            .topics(Some(vec![T::signature()]), None, None, None);

        Self {
            last_known,
            stride: 10_000,
            base_filter,
        }
    }

    /// Fetches the next set of logs from L1. This set may be empty, in which
    /// case we have reached the current end of the L1 chain.
    pub async fn fetch<Tr: Transport>(
        &mut self,
        transport: &Web3<Tr>,
    ) -> Result<Vec<T>, FetchError> {
        // Algorithm overview.
        //
        // There are two key difficulties this algorithm needs to handle.
        //
        //  1. L1 chain reorgs
        //  2. Infura query result limit
        //
        // We handle (1) by always including the last known log in our query,
        // which lets us check for continuity across queries.
        //
        // We handle (2) by using a dynamic query range. We basically perform a
        // binary-search of the query range until we find a range that returns
        // data.

        let from_block = self
            .last_known
            .as_ref()
            .map(|update| update.origin().block.number.0)
            .unwrap_or_default();
        let base_filter = self
            .base_filter
            .clone()
            .from_block(BlockNumber::Number(from_block.into()));

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
            let to_block = from_block.saturating_add(self.stride);
            let filter = base_filter
                .clone()
                .to_block(BlockNumber::Number(to_block.into()))
                .build();

            let logs = match get_logs(transport, filter).await {
                Ok(logs) => logs,
                Err(GetLogsError::QueryLimit) => {
                    stride_cap = Some(self.stride);
                    self.stride = (self.stride / 2).max(1);

                    continue;
                }
                Err(GetLogsError::Other(other)) => return Err(FetchError::Other(other)),
            };

            let mut logs = logs.into_iter();

            // Check for reorgs. Only required if there was a last known update to validate.
            //
            // We queried for logs starting from the same block as last known. We need to account
            // for logs that occurred in the same block and transaction, but with a smaller log index.
            //
            // If the last known log is not in the set then we have a reorg event.
            if let Some(last) = self.last_known.as_ref() {
                loop {
                    match logs.next().map(T::try_from) {
                        Some(Ok(log))
                            if log.origin().block == last.origin().block
                                && log.origin().log_index.0 < last.origin().log_index.0 =>
                        {
                            continue
                        }
                        Some(Ok(log)) if &log == last => break,
                        _ => return Err(FetchError::Reorg),
                    }
                }
            }

            let logs = logs.map(T::try_from).collect::<Result<Vec<T>, _>>()?;

            // If there are no new logs, then either we have reached the end of L1,
            // or we need to increase our query range.
            if logs.is_empty() {
                let latest_on_chain = transport
                    .eth()
                    .block_number()
                    .await
                    .context("Get latest block number from L1")?
                    .as_u64();

                if to_block < latest_on_chain {
                    match stride_cap {
                        Some(max) => self.stride = (self.stride.saturating_add(max + 1)) / 2,
                        None => self.stride = self.stride.saturating_mul(2),
                    }
                    continue;
                }
            }

            if let Some(last) = logs.last() {
                self.last_known = Some(last.clone());
            }

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
            log::StateUpdateLog, test::create_test_transport, BlockOrigin, EthOrigin,
            TransactionOrigin,
        },
    };

    #[tokio::test]
    async fn consistency() {
        // Give a starting point so that we don't search overly long.
        // We use StateUpdateLog because it comes with a handy block number
        // we can use to check for sequentiality.
        let starknet_genesis_log = StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: EthereumBlockHash(
                        H256::from_str(
                            "0xa3c7bb4baa81bb8bc5cc75ace7d8296b2668ccc2fd5ac9d22b5eefcfbf7f3444",
                        )
                        .unwrap(),
                    ),
                    number: EthereumBlockNumber(5854324),
                },
                transaction: TransactionOrigin {
                    hash: EthereumTransactionHash(
                        H256::from_str(
                            "0x97ee44ba80d1ad5cff4a5adc02311f6e19490f48ea5a57c7f510e469cae7e65b",
                        )
                        .unwrap(),
                    ),
                    index: EthereumTransactionIndex(4),
                },
                log_index: EthereumLogIndex(23),
            },
            global_root: GlobalRoot(
                StarkHash::from_hex_str(
                    "0x02C2BB91714F8448ED814BDAC274AB6FCDBAFC22D835F9E847E5BEE8C2E5444E",
                )
                .unwrap(),
            ),
            block_number: StarknetBlockNumber(0),
        };

        let mut root_fetcher = LogFetcher::<StateUpdateLog>::new(Some(starknet_genesis_log));
        let transport = create_test_transport(crate::ethereum::Chain::Goerli);
        let mut block_number = 1;

        let logs = root_fetcher.fetch(&transport).await.unwrap();
        for log in logs {
            assert_eq!(log.block_number.0, block_number, "First fetch");
            block_number += 1;
        }
        let logs = root_fetcher.fetch(&transport).await.unwrap();
        for log in logs {
            assert_eq!(log.block_number.0, block_number, "Second fetch");
            block_number += 1;
        }
    }
}
