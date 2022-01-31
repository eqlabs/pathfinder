use crate::ethereum::log::{LogFetcher, StateUpdateLog};

/// A simple alias for [LogFetcher]<[StateUpdateLog]>.
pub type StateRootFetcher = LogFetcher<StateUpdateLog>;

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
        let ws = create_test_transport(Chain::Goerli).await;

        let mut uut = StateRootFetcher::new(None);
        let first_fetch = uut.fetch(&ws).await.unwrap();
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
            let ws = create_test_transport(Chain::Goerli).await;

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

            let mut uut = StateRootFetcher::new(Some(not_genesis));
            assert_matches!(uut.fetch(&ws).await, Err(FetchError::Reorg));
        }

        #[tokio::test]
        async fn block_removed() {
            // Seed with an origin beyond the current L1 chain state.
            // This should be interpreted as a reorg as this update
            // won't be found.
            let ws = create_test_transport(Chain::Goerli).await;

            let latest_on_chain = ws.eth().block_number().await.unwrap().as_u64();

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

            let mut uut = StateRootFetcher::new(Some(not_genesis));
            assert_matches!(uut.fetch(&ws).await, Err(FetchError::Reorg));
        }
    }
}
