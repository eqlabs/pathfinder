use crate::ethereum::{
    log::{LogFetcher, StateUpdateLog},
    Chain,
};

/// A simple wrapper for [LogFetcher]<[StateUpdateLog]>.
pub struct StateRootFetcher(LogFetcher<StateUpdateLog>);

impl StateRootFetcher {
    pub fn new(last_known: Option<StateUpdateLog>, chain: Chain) -> Self {
        let inner = LogFetcher::<StateUpdateLog>::new(last_known, chain);
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
        ethereum::{test::create_test_transport, Chain},
    };

    use super::*;

    #[tokio::test]
    async fn genesis() {
        // The first state root retrieved should be the genesis event,
        // with a sequence number of 0.
        let chain = Chain::Goerli;
        let transport = create_test_transport(chain);

        let mut uut = StateRootFetcher::new(None, chain);
        let first_fetch = uut.fetch(&transport).await.unwrap();
        let first = first_fetch.first().expect("Should be at least one log");

        assert_eq!(first.block_number, StarknetBlockNumber(0));
    }

    mod reorg {
        use pedersen::StarkHash;
        use web3::types::H256;

        use crate::{
            core::{
                EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
                EthereumTransactionIndex, GlobalRoot,
            },
            ethereum::{log::FetchError, BlockOrigin, EthOrigin, TransactionOrigin},
        };

        use super::*;

        #[tokio::test]
        async fn block_replaced() {
            // Seed with a incorrect update at the L1 genesis block.
            // This should get interpretted as a reorg once the correct
            // first L2 update log is found.
            let chain = Chain::Goerli;
            let transport = create_test_transport(chain);

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
            let transport = create_test_transport(chain);

            let latest_on_chain = transport.eth().block_number().await.unwrap().as_u64();

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
