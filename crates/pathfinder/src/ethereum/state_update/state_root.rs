use crate::{
    core::EthereumBlockNumber,
    ethereum::{
        log::{LogFetcher, StateUpdateLog},
        Chain,
    },
};

/// A simple wrapper for [LogFetcher]<[StateUpdateLog]>.
pub struct StateRootFetcher(LogFetcher<StateUpdateLog>);

/// The Mainnet Ethereum block containing the Starknet genesis [StateUpdateLog].
const MAINNET_GENESIS: EthereumBlockNumber = EthereumBlockNumber(13_627_224);
/// The Goerli Ethereum block containing the Starknet genesis [StateUpdateLog].
const GOERLI_GENESIS: EthereumBlockNumber = EthereumBlockNumber(5_854_324);

impl StateRootFetcher {
    pub fn new(head: Option<StateUpdateLog>, chain: Chain) -> Self {
        let genesis = match chain {
            Chain::Mainnet => MAINNET_GENESIS,
            Chain::Goerli => GOERLI_GENESIS,
        };

        let inner = LogFetcher::<StateUpdateLog>::new(head, chain, genesis);
        Self(inner)
    }
}

impl std::ops::Deref for StateRootFetcher {
    type Target = LogFetcher<StateUpdateLog>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for StateRootFetcher {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;

    use crate::{
        core::StarknetBlockNumber,
        ethereum::{test_transport, Chain},
    };

    use super::*;

    #[tokio::test]
    async fn first_fetch() {
        // The first state root retrieved should be the genesis event,
        // with a sequence number of 0.
        let chain = Chain::Goerli;
        let transport = test_transport(chain);

        let mut uut = StateRootFetcher::new(None, chain);
        let first_fetch = uut.fetch(&transport).await.unwrap();
        let first = first_fetch.first().expect("Should be at least one log");

        assert_eq!(first.block_number, StarknetBlockNumber(0));
    }

    mod genesis {
        use pretty_assertions::assert_eq;
        use web3::types::{BlockNumber, FilterBuilder};

        use crate::ethereum::log::{get_logs, MetaLog};

        use super::*;

        #[tokio::test]
        async fn mainnet() {
            // Checks `MAINNET_GENESIS` contains the actual Starknet genesis StateUpdateLog
            let chain = Chain::Mainnet;
            let transport = test_transport(chain);

            let block_number = BlockNumber::Number(MAINNET_GENESIS.0.into());

            let filter = FilterBuilder::default()
                .address(vec![StateUpdateLog::contract_address(chain)])
                .topics(Some(vec![StateUpdateLog::signature()]), None, None, None)
                .from_block(block_number)
                .to_block(block_number)
                .build();

            let logs = get_logs(&transport, filter).await.unwrap();
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
        async fn goerli() {
            // Checks `GOERLI_GENESIS` contains the actual Starknet genesis StateUpdateLog
            let chain = Chain::Goerli;
            let transport = test_transport(chain);

            let block_number = BlockNumber::Number(GOERLI_GENESIS.0.into());

            let filter = FilterBuilder::default()
                .address(vec![StateUpdateLog::contract_address(chain)])
                .topics(Some(vec![StateUpdateLog::signature()]), None, None, None)
                .from_block(block_number)
                .to_block(block_number)
                .build();

            let logs = get_logs(&transport, filter).await.unwrap();
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
        use pedersen::StarkHash;
        use web3::types::H256;

        use crate::{
            core::{
                EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
                EthereumTransactionIndex, GlobalRoot,
            },
            ethereum::{
                api::Web3EthApi, log::FetchError, BlockOrigin, EthOrigin, TransactionOrigin,
            },
        };

        use super::*;

        #[tokio::test]
        async fn block_replaced() {
            // Seed with a incorrect update at the L1 genesis block.
            // This should get interpretted as a reorg once the correct
            // first L2 update log is found.
            let chain = Chain::Goerli;
            let transport = test_transport(chain);

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
                global_root: GlobalRoot(StarkHash::from_hex_str("12354").unwrap()),
                block_number: StarknetBlockNumber(3),
            };

            let mut uut = StateRootFetcher::new(Some(not_genesis), chain);
            assert_matches!(uut.fetch(&transport).await, Err(FetchError::Reorg));
        }

        #[tokio::test]
        async fn block_removed() {
            // Seed with an origin beyond the current L1 chain state.
            // This should be interpreted as a reorg as this update
            // won't be found.
            let chain = Chain::Goerli;
            let transport = test_transport(chain);

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
                global_root: GlobalRoot(StarkHash::from_hex_str("12354").unwrap()),
                block_number: StarknetBlockNumber(3),
            };

            let mut uut = StateRootFetcher::new(Some(not_genesis), chain);
            assert_matches!(uut.fetch(&transport).await, Err(FetchError::Reorg));
        }
    }
}
