//! Provides abstractions to interface with StarkNet's Ethereum contracts and events.
use web3::{
    transports::WebSocket,
    types::{BlockNumber, TransactionId, U256},
    Web3,
};

use anyhow::{Context, Result};

use crate::ethereum::contract::{FactLog, GpsContract, MempageContract, MempageLog};

/// Provides abstractions for interacting with StarkNet contracts on Ethereum.
pub struct Starknet {
    gps_contract: GpsContract,
    mempage_contract: MempageContract,
    ws: Web3<WebSocket>,
}

/// A StarkNet Ethereum [Log] event.
#[derive(Debug)]
pub enum Log {
    Fact(FactLog),
    Mempage(MempageLog),
}

/// Error return by `Starknet::get_logs`.
///
/// Currently only contains errors specific to the Infura RPC API.
#[derive(Debug)]
pub enum GetLogsError {
    /// Infura query timed out, should reduce the query scope.
    InfuraQueryTimeout,
    /// Infura is limited to 10 000 log results, should reduce the query scope.
    InfuraResultLimit,
    Other(anyhow::Error),
}

impl From<web3::Error> for GetLogsError {
    fn from(err: web3::Error) -> Self {
        use GetLogsError::*;
        match err {
            web3::Error::Rpc(err) => match err.message.as_str() {
                "query timeout exceeded" => InfuraQueryTimeout,
                "query returned more than 10000 results" => InfuraResultLimit,
                other => Other(anyhow::anyhow!("Unexpected RPC error: {}", other)),
            },
            other => Other(anyhow::anyhow!("Unexpected error: {}", other)),
        }
    }
}

impl From<anyhow::Error> for GetLogsError {
    fn from(err: anyhow::Error) -> Self {
        GetLogsError::Other(err)
    }
}

impl Starknet {
    /// Creates a new [Starknet] interface, loading the relevant StarkNet contracts and events.
    pub fn load(web_socket: WebSocket) -> Starknet {
        let gps_contract = GpsContract::load(Web3::new(web_socket.clone()));
        let mempage_contract = MempageContract::load(Web3::new(web_socket.clone()));

        Self {
            gps_contract,
            mempage_contract,
            ws: Web3::new(web_socket),
        }
    }

    /// Retrieves all StarkNet [logs](Log) from L1.
    ///
    /// Query may exceed the [time](GetLogsError::InfuraQueryTimeout) or
    /// [result size](GetLogsError::InfuraResultLimit) limit, in which case
    /// the query range should be reduced.
    pub async fn retrieve_logs(
        &self,
        from: BlockNumber,
        to: BlockNumber,
    ) -> std::result::Result<Vec<Log>, GetLogsError> {
        let log_filter = web3::types::FilterBuilder::default()
            .address(vec![
                self.mempage_contract.address(),
                self.gps_contract.address(),
            ])
            .topics(
                Some(vec![
                    self.mempage_contract.mempage_event.signature(),
                    self.gps_contract.fact_event.signature(),
                ]),
                None,
                None,
                None,
            )
            .from_block(from)
            .to_block(to)
            .build();

        Ok(self
            .ws
            .eth()
            .logs(log_filter)
            .await?
            .iter()
            .map(|log| self.parse_log(log))
            .collect::<Result<Vec<_>>>()?)
    }

    /// Retrieve's the transaction from L1 and interprets it's data as a StarkNet memory page.
    async fn retrieve_mempage(&self, transaction: TransactionId) -> Result<Vec<U256>> {
        let transaction = self
            .ws
            .eth()
            .transaction(transaction)
            .await?
            .context("mempage transaction is missing on chain")?;

        self.mempage_contract.decode_mempage(&transaction)
    }

    /// Parses an [Ethereum log](web3::types::Log) into a StarkNet [Log].
    fn parse_log(&self, log: &web3::types::Log) -> Result<Log> {
        // The first topic of an Ethereum log is its signature. We use this
        // to identify the StarkNet log type.
        match log.topics.first() {
            Some(topic) if topic == &self.mempage_contract.mempage_event.signature() => {
                Ok(Log::Mempage(
                    self.mempage_contract
                        .mempage_event
                        .parse_log(log)
                        .context("mempage log parsing")?,
                ))
            }
            Some(topic) if topic == &self.gps_contract.fact_event.signature() => Ok(Log::Fact(
                self.gps_contract
                    .fact_event
                    .parse_log(log)
                    .context("fact log parsing")?,
            )),
            Some(topic) => anyhow::bail!("unknown log signature: {}", topic),
            None => anyhow::bail!("log contained no signature"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ethereum::test::{
        create_test_websocket, fact_test_tx, mempage_test_tx, retrieve_log,
    };
    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn load() {
        let ws = create_test_websocket().await;
        Starknet::load(ws);
    }

    #[tokio::test]
    async fn retrieve_mempage() {
        let ws = create_test_websocket().await;
        let starknet = Starknet::load(ws);

        let tx_hash = TransactionId::Hash(mempage_test_tx().origin.transaction_hash);

        starknet.retrieve_mempage(tx_hash).await.unwrap();
    }

    #[tokio::test]
    async fn parse_mempage_log() {
        let ws = create_test_websocket().await;
        let starknet = Starknet::load(ws);
        let mempage_tx = mempage_test_tx();

        let log = retrieve_log(&mempage_tx).await;
        let mempage_log = starknet.parse_log(&log).unwrap();

        assert_matches!(mempage_log, Log::Mempage(..));
    }

    #[tokio::test]
    async fn parse_fact_log() {
        let ws = create_test_websocket().await;
        let starknet = Starknet::load(ws);
        let fact_tx = fact_test_tx();

        let log = retrieve_log(&fact_tx).await;
        let fact_log = starknet.parse_log(&log).unwrap();

        assert_matches!(fact_log, Log::Fact(..));
    }

    #[cfg(test)]
    mod retrieve_logs {
        use super::*;

        #[tokio::test]
        async fn ok() {
            let ws = create_test_websocket().await;
            let starknet = Starknet::load(ws);
            // The block the StarkNet core contract was deployed with.
            // Use this to retrieve a small set of logs.
            let to = 5745469;
            let from = to + 10;

            let result = starknet
                .retrieve_logs(
                    BlockNumber::Number(to.into()),
                    BlockNumber::Number(from.into()),
                )
                .await;

            let logs = result.unwrap();
            assert_eq!(logs.len(), 12);
        }

        #[tokio::test]
        async fn query_limit_exceeded() {
            let ws = create_test_websocket().await;
            let starknet = Starknet::load(ws);
            // Query the full range of blocks available. This should exceed the result
            // limit unless the StarkNet network is very young.
            let result = starknet
                .retrieve_logs(BlockNumber::Earliest, BlockNumber::Latest)
                .await;

            assert_matches!(result, Err(GetLogsError::InfuraResultLimit));
        }
    }
}
