use ethers::types::{Filter, H160};
use pathfinder_common::{Chain, EthereumBlockNumber};

use crate::log::StateUpdateLog;

use anyhow::Context;

use crate::provider::{EthereumTransport, LogsError};

#[derive(Clone)]
pub struct StateRootFetcher {
    head: Option<StateUpdateLog>,
    genesis: EthereumBlockNumber,
    stride: u64,
    base_filter: Filter,
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

/// The Mainnet Ethereum block containing the Starknet genesis [StateUpdateLog].
const MAINNET_GENESIS: EthereumBlockNumber = EthereumBlockNumber(13_627_224);
/// The Goerli Ethereum block containing the Starknet genesis [StateUpdateLog] for testnet.
const TESTNET_GENESIS: EthereumBlockNumber = EthereumBlockNumber(5_854_324);
/// The Goerli Ethereum block containing the Starknet genesis [StateUpdateLog] for testnet 2.
const TESTNET2_GENESIS: EthereumBlockNumber = EthereumBlockNumber(5_854_324);
/// The Goerli Ethereum block containing the Starknet genesis [StateUpdateLog] for integration.
const INTEGRATION_GENESIS: EthereumBlockNumber = EthereumBlockNumber(5_986_835);

impl StateRootFetcher {
    pub fn new(head: Option<StateUpdateLog>, chain: Chain, contract_address: H160) -> Self {
        let genesis = match chain {
            Chain::Mainnet => MAINNET_GENESIS,
            Chain::Testnet => TESTNET_GENESIS,
            Chain::Testnet2 => TESTNET2_GENESIS,
            Chain::Integration => INTEGRATION_GENESIS,
            Chain::Custom => EthereumBlockNumber(0),
        };

        let signature = StateUpdateLog::signature();
        let signature: ethers::types::H256 = signature.0.into();

        let base_filter = Filter::default()
            .address(vec![contract_address])
            .topic0(signature);

        Self {
            head,
            stride: 10_000,
            base_filter,
            genesis,
        }
    }

    #[cfg(test)]
    fn testnet(head: Option<StateUpdateLog>) -> Self {
        let contract_address = crate::contract::TESTNET_ADDRESSES.core;

        Self::new(head, Chain::Testnet, contract_address.0.into())
    }

    pub fn set_head(&mut self, head: Option<StateUpdateLog>) {
        self.head = head;
    }

    pub fn head(&self) -> &Option<StateUpdateLog> {
        &self.head
    }

    /// Fetches the next set of logs from L1. This set may be empty, in which
    /// case we have reached the current end of the L1 chain.
    pub async fn fetch(
        &mut self,
        transport: impl EthereumTransport,
    ) -> Result<Vec<StateUpdateLog>, FetchError> {
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
            .head
            .as_ref()
            .map(|update| update.origin.block.number.0)
            .unwrap_or(self.genesis.0);
        let base_filter = self.base_filter.clone().from_block(from_block);

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
            let filter = base_filter.clone().to_block(to_block);

            let logs = match transport.logs(filter).await {
                Ok(logs) => logs,
                Err(LogsError::QueryLimit) => {
                    stride_cap = Some(self.stride);
                    self.stride = (self.stride / 2).max(1);

                    continue;
                }
                Err(LogsError::UnknownBlock) => {
                    // This implies either:
                    //  - the `to_block` exceeds the current chain state, or
                    //  - both `from_block` and `to_block` exceed the current chain state which indicates a reorg occurred.
                    // so lets check this by querying for the `to_block`.
                    let chain_head = transport
                        .block_number()
                        .await
                        .context("Get latest block number from L1")?;

                    if from_block <= chain_head {
                        self.stride = (chain_head - from_block).max(1);
                        continue;
                    } else {
                        return Err(FetchError::Reorg);
                    }
                }
                Err(LogsError::Other(other)) => {
                    return Err(FetchError::Other(anyhow::Error::new(other)))
                }
            };

            let mut logs = logs.into_iter();

            // Check for reorgs. Only required if there was a head to validate.
            //
            // We queried for logs starting from the same block as head. We need to account
            // for logs that occurred in the same block and transaction, but with a smaller log index.
            //
            // If the head log is not in the set then we have a reorg event.
            if let Some(head) = self.head.as_ref() {
                loop {
                    match logs.next().map(StateUpdateLog::try_from) {
                        Some(Ok(log))
                            if log.origin.block == head.origin.block
                                && log.origin.log_index.0 < head.origin.log_index.0 =>
                        {
                            continue
                        }
                        Some(Ok(log)) if &log == head => break,
                        _ => return Err(FetchError::Reorg),
                    }
                }
            }

            let logs = logs
                .map(StateUpdateLog::try_from)
                .collect::<Result<Vec<StateUpdateLog>, _>>()?;

            // If there are no new logs, then either we have reached the end of L1,
            // or we need to increase our query range.
            if logs.is_empty() {
                let chain_head = transport
                    .block_number()
                    .await
                    .context("Get latest block number from L1")?;

                if to_block < chain_head {
                    match stride_cap {
                        Some(max) => self.stride = (self.stride.saturating_add(max + 1)) / 2,
                        None => self.stride = self.stride.saturating_mul(2),
                    }
                    continue;
                }
            }

            if let Some(head) = logs.last() {
                self.head = Some(head.clone());
            }

            return Ok(logs);
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;

    use pathfinder_common::{Chain, StarknetBlockNumber};

    use crate::provider::HttpProvider;

    use super::*;

    #[tokio::test]
    async fn first_fetch() {
        // The first state root retrieved should be the genesis event,
        // with a sequence number of 0.
        let chain = Chain::Testnet;
        let transport = HttpProvider::test_provider(chain);

        let mut uut = StateRootFetcher::testnet(None);
        let first_fetch = uut.fetch(transport).await.unwrap();
        let first = first_fetch.first().expect("Should be at least one log");

        assert_eq!(first.block_number, StarknetBlockNumber::GENESIS);
    }

    mod genesis {
        use ethers::types::{BlockNumber, Filter};
        use pretty_assertions::assert_eq;

        use crate::provider::EthereumTransport;

        use super::*;

        #[tokio::test]
        async fn mainnet() {
            use crate::contract::MAINNET_ADDRESSES;
            // Checks `MAINNET_GENESIS` contains the actual Starknet genesis StateUpdateLog
            let chain = Chain::Mainnet;
            let transport = HttpProvider::test_provider(chain);

            let block_number = BlockNumber::Number(MAINNET_GENESIS.0.into());

            let filter = Filter::default()
                .address(MAINNET_ADDRESSES.core)
                .topic0(StateUpdateLog::signature())
                .from_block(block_number)
                .to_block(block_number);

            let logs = transport.logs(filter).await.unwrap();
            let logs = logs
                .into_iter()
                .map(StateUpdateLog::try_from)
                .collect::<Result<Vec<StateUpdateLog>, _>>()
                .unwrap();

            assert_eq!(
                logs.first().unwrap().block_number,
                StarknetBlockNumber::GENESIS
            );
        }

        #[tokio::test]
        async fn testnet() {
            use crate::contract::TESTNET_ADDRESSES;
            // Checks `TESTNET_GENESIS` contains the actual Starknet genesis StateUpdateLog
            let chain = Chain::Testnet;
            let transport = HttpProvider::test_provider(chain);

            let block_number = BlockNumber::Number(TESTNET_GENESIS.0.into());

            let filter = Filter::default()
                .address(TESTNET_ADDRESSES.core)
                .topic0(StateUpdateLog::signature())
                .from_block(block_number)
                .to_block(block_number);

            let logs = transport.logs(filter).await.unwrap();
            let logs = logs
                .into_iter()
                .map(StateUpdateLog::try_from)
                .collect::<Result<Vec<StateUpdateLog>, _>>()
                .unwrap();

            assert_eq!(
                logs.first().unwrap().block_number,
                StarknetBlockNumber::GENESIS
            );
        }

        #[tokio::test]
        async fn integration() {
            use crate::contract::INTEGRATION_ADDRESSES;
            let chain = Chain::Integration;
            let transport = HttpProvider::test_provider(chain);

            let block_number = BlockNumber::Number(INTEGRATION_GENESIS.0.into());

            let filter = Filter::default()
                .address(INTEGRATION_ADDRESSES.core)
                .topic0(StateUpdateLog::signature())
                .from_block(block_number)
                .to_block(block_number);

            let logs = transport.logs(filter).await.unwrap();
            let logs = logs
                .into_iter()
                .map(StateUpdateLog::try_from)
                .collect::<Result<Vec<StateUpdateLog>, _>>()
                .unwrap();

            assert_eq!(
                logs.first().unwrap().block_number,
                StarknetBlockNumber::GENESIS
            );
        }
    }

    mod reorg {
        use ethers::types::H256;

        use pathfinder_common::{
            felt, EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex,
            EthereumTransactionHash, EthereumTransactionIndex, StateCommitment,
        };

        use crate::{
            provider::EthereumTransport, state_update::FetchError, BlockOrigin, EthOrigin,
            TransactionOrigin,
        };

        use super::*;

        #[tokio::test]
        async fn block_replaced() {
            // Seed with a incorrect update at the L1 genesis block.
            // This should get interpretted as a reorg once the correct
            // first L2 update log is found.
            let chain = Chain::Testnet;
            let transport = HttpProvider::test_provider(chain);

            // Note that block_number must be 0 so that we pull all of L1 history.
            // This makes the test robust against L2 changes, updates or deployments
            // on other chains. (since we don't know when L2 history on L1 starts).
            let not_genesis = StateUpdateLog {
                origin: EthOrigin {
                    block: BlockOrigin {
                        hash: EthereumBlockHash(H256::from_low_u64_le(10)),
                        number: EthereumBlockNumber(0),
                    },
                    transaction: TransactionOrigin {
                        hash: EthereumTransactionHash(H256::from_low_u64_le(11)),
                        index: EthereumTransactionIndex(12),
                    },
                    log_index: EthereumLogIndex(11),
                },
                global_root: StateCommitment(felt!("0x12354")),
                block_number: StarknetBlockNumber::new_or_panic(3),
            };

            let mut uut = StateRootFetcher::testnet(Some(not_genesis));
            assert_matches!(uut.fetch(transport).await, Err(FetchError::Reorg));
        }

        #[tokio::test]
        async fn block_removed() {
            // Seed with an origin beyond the current L1 chain state.
            // This should be interpreted as a reorg as this update
            // won't be found.
            let chain = Chain::Testnet;
            let transport = HttpProvider::test_provider(chain);

            let latest_on_chain = transport.block_number().await.unwrap();

            let not_genesis = StateUpdateLog {
                origin: EthOrigin {
                    block: BlockOrigin {
                        hash: EthereumBlockHash(H256::from_low_u64_le(10)),
                        number: EthereumBlockNumber(latest_on_chain + 500),
                    },
                    transaction: TransactionOrigin {
                        hash: EthereumTransactionHash(H256::from_low_u64_le(11)),
                        index: EthereumTransactionIndex(12),
                    },
                    log_index: EthereumLogIndex(11),
                },
                global_root: StateCommitment(felt!("0x12354")),
                block_number: StarknetBlockNumber::new_or_panic(3),
            };

            let mut uut = StateRootFetcher::testnet(Some(not_genesis));
            assert_matches!(uut.fetch(transport).await, Err(FetchError::Reorg));
        }
    }
}
