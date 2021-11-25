use std::{collections::VecDeque, time::Duration};

use web3::{transports::WebSocket, types::BlockNumber, Web3};

use crate::ethereum::starknet::{
    contract::{LogWithOrigin, StateUpdateLog},
    CoreContract, GetLogsError,
};

/// Provides a reorg aware stream of L2 state update logs.
///
/// ## Important
///
/// [StateRootStream] keeps an internal buffer of update logs.
/// Once these are exhausted, a new set of logs are retrieved from
/// L1. **Only** at this point can reorgs be detected. This implies
/// that although this buffer was valid when retrieved, that in the
/// interim a reorg could have occurred invalidating this buffer.
///
/// The implication is that your other L1 / L2 queries will
/// still need to be reorg aware.
pub struct StateRootStream {
    last: Option<LogWithOrigin<StateUpdateLog>>,
    core_contract: CoreContract,
    websocket: Web3<WebSocket>,
    buffer: VecDeque<LogWithOrigin<StateUpdateLog>>,
    stride: u64,
}

#[derive(Debug)]
pub enum GetRootError {
    /// An L1 chain reorganisation occurred. At the very least
    /// the last update returned is no longer valid.
    Reorg,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for GetRootError {
    fn from(err: anyhow::Error) -> Self {
        GetRootError::Other(err)
    }
}

impl From<web3::Error> for GetRootError {
    fn from(err: web3::Error) -> Self {
        GetRootError::Other(anyhow::anyhow!("Unexpected error: {}", err))
    }
}

impl StateRootStream {
    /// Creates a new [StateRootStream].
    ///
    /// `last_known` should be set to the last known valid [StateUpdateLog],
    /// or [None] if you are starting from scratch.
    pub fn new(
        websocket: Web3<WebSocket>,
        last_known: Option<LogWithOrigin<StateUpdateLog>>,
    ) -> Self {
        let core_contract = CoreContract::load(websocket.clone());

        Self {
            last: last_known,
            buffer: VecDeque::new(),
            core_contract,
            websocket,
            stride: 100_000,
        }
    }

    /// Returns the next [StateUpdateLog].
    ///
    /// If [GetRootError::Reorg] is returned, this [StateRootStream] will no longer
    /// be valid and should be discarded. One sensible reaction is to validate your
    /// state and purge whatever has been reorg'd away. Then create a new [StateRootStream]
    /// starting with your new valid state.
    pub async fn next(&mut self) -> Result<LogWithOrigin<StateUpdateLog>, GetRootError> {
        if self.buffer.is_empty() {
            self.buffer = self.retrieve_logs().await?;
        }
        // SAFETY: unwrap is safe due to the above empty check and that
        // retrieve_next_updates will only return once there is a new update.
        let last = self.buffer.pop_front().unwrap();
        self.last = Some(last.clone());
        Ok(last)
    }

    /// Gets the next batch of [StateUpdateLog] from L1. Checks that
    /// `self.last` is still valid and no reorg occurred.
    ///
    /// ## Reorg detection
    ///
    /// We include the last known log's block in the query. If there was
    /// no reorg then we will receive this log as part of the result set.
    ///
    /// ## Dealing with Infura's cap error
    ///
    /// Infura responds with an error if the query is too large, and would
    /// result in more than 10 000 logs. To deal with this, we use a binary
    /// search like query range. We need at least 2 logs (1 is the last known)
    /// to have a new update.
    async fn retrieve_logs(
        &mut self,
    ) -> Result<VecDeque<LogWithOrigin<StateUpdateLog>>, GetRootError> {
        let from_block = self
            .last
            .as_ref()
            .map(|update| update.origin.block_number)
            .unwrap_or_default();

        // The largest stride we are allowed to take. This gets
        // set if we encounter the Infura result cap error.
        //
        // Allows us to perform a binary search of the query range space.
        let mut stride_cap = None;

        loop {
            let to_block = from_block.saturating_add(self.stride);

            let mut logs = match self.get_logs(from_block, to_block).await {
                Ok(logs) => logs,
                Err(GetLogsError::QueryLimit) => {
                    // Infura result cap error. We need to reduce our query range.
                    stride_cap = Some(self.stride);
                    self.stride = (self.stride / 2).max(1);

                    continue;
                }
                Err(GetLogsError::Other(other)) => return Err(GetRootError::Other(other)),
            };

            // Check for reorgs. Only required if there was a last known update to validate.
            if let Some(last) = self.last.as_ref() {
                // We queried for logs starting from the same block as last known. We need to account
                // for logs that occurred in the same block and transaction, but with a smaller log index.
                //
                // If the last known log is not in the set then we have a reorg event.
                loop {
                    match logs.pop_front() {
                        // Log from the same origin point, but smaller log index.
                        Some(log)
                            if log.origin == last.origin && log.log_index < last.log_index =>
                        {
                            continue
                        }
                        // Log found. Yay!
                        Some(log) if &log == last => break,
                        _ => return Err(GetRootError::Reorg),
                    }
                }
            }

            // At this point we have validated and removed the last known log.
            // If there are no new logs then either:
            //  1. there are no new logs on L1, or
            //  2. we need to increase our stride
            if logs.is_empty() {
                let latest_on_chain = self.websocket.eth().block_number().await?.as_u64();

                if to_block <= latest_on_chain {
                    // Increase stride. Account for stride cap (binary search style)
                    // so that we don't run into a cycle of:
                    //  1. No logs, increase stride
                    //  2. Infura result cap, reduce stride
                    match stride_cap {
                        Some(max) => self.stride = (self.stride.saturating_add(max + 1)) / 2,
                        None => self.stride = self.stride.saturating_mul(2),
                    }
                } else {
                    // No new logs on L1, sleep and try again..
                    const SLEEP: Duration = Duration::from_secs(5);
                    tokio::time::sleep(SLEEP).await;
                }

                continue;
            }

            return Ok(logs);
        }
    }

    /// Helper function that retrieves and parses the [StateUpdateLogs](StateUpdateLog) from L1.
    async fn get_logs(
        &self,
        from: u64,
        to: u64,
    ) -> Result<VecDeque<LogWithOrigin<StateUpdateLog>>, GetLogsError> {
        let log_filter = web3::types::FilterBuilder::default()
            .address(vec![self.core_contract.address])
            .topics(
                Some(vec![self.core_contract.state_update_event.signature()]),
                None,
                None,
                None,
            )
            .from_block(BlockNumber::Number(from.into()))
            .to_block(BlockNumber::Number(to.into()))
            .build();

        let logs = self
            .websocket
            .eth()
            .logs(log_filter)
            .await?
            .iter()
            .map(|log| self.core_contract.state_update_event.parse_log(log))
            .collect::<Result<VecDeque<_>, _>>()?;

        Ok(logs)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use web3::types::{H256, U256};

    use crate::ethereum::{test::create_test_websocket, EthOrigin};

    use super::*;

    #[tokio::test]
    async fn genesis() {
        // The first state root retrieved should be the genesis event,
        // with a sequence number of 0.
        let ws = create_test_websocket().await;
        let ws = Web3::new(ws);

        let mut uut = StateRootStream::new(ws, None);
        let genesis_root = uut.next().await.unwrap();

        assert_eq!(genesis_root.data.sequence_number, U256::from(0));
    }

    mod reorg {
        use super::*;

        #[tokio::test]
        async fn block_replaced() {
            // Seed with a incorrect update at the L1 genesis block.
            // This should get interpretted as a reorg once the correct
            // first L2 update log is found.
            let ws = create_test_websocket().await;
            let ws = Web3::new(ws);

            // Note that block_number must be 0 so that we pull all of L1 history.
            // This makes the test robust against L2 changes, updates or deployments
            // on other chains. (since we don't know when L2 history on L1 starts).
            let not_genesis = LogWithOrigin {
                origin: EthOrigin {
                    block_hash: H256::from_low_u64_le(10),
                    block_number: 0,
                    transaction_hash: H256::from_low_u64_le(1123),
                    transaction_index: 12,
                },
                data: StateUpdateLog {
                    global_root: U256::from(12354),
                    sequence_number: U256::from(3),
                },
                log_index: U256::from(12),
            };

            let mut uut = StateRootStream::new(ws, Some(not_genesis));
            assert_matches!(uut.next().await, Err(GetRootError::Reorg));
        }

        #[tokio::test]
        async fn block_removed() {
            // Seed with an origin beyond the current L1 chain state.
            // This should be interpretted as a reorg as this update
            // won't be found.
            let ws = create_test_websocket().await;
            let ws = Web3::new(ws);

            let latest_on_chain = ws.eth().block_number().await.unwrap().as_u64();

            let not_genesis = LogWithOrigin {
                origin: EthOrigin {
                    block_hash: H256::from_low_u64_le(10),
                    block_number: latest_on_chain + 500,
                    transaction_hash: H256::from_low_u64_le(1123),
                    transaction_index: 12,
                },
                data: StateUpdateLog {
                    global_root: U256::from(12354),
                    sequence_number: U256::from(3),
                },
                log_index: U256::from(12),
            };

            let mut uut = StateRootStream::new(ws, Some(not_genesis));
            assert_matches!(uut.next().await, Err(GetRootError::Reorg));
        }
    }
}
