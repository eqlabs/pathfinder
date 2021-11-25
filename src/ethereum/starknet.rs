//! Provides abstractions to interface with StarkNet's Ethereum contracts and events.
mod contract;
mod fact;

pub use contract::*;
use fact::*;

use web3::{
    futures::future::try_join_all,
    transports::WebSocket,
    types::{BlockNumber, TransactionId, U256},
    Web3,
};

use anyhow::{Context, Result};

use crate::ethereum::{
    starknet::contract::{
        FactLog, GpsContract, MempageContract, MempageLog, StateTransitionFactLog, StateUpdateLog,
    },
    RpcErrorCode,
};

/// Provides abstractions for interacting with StarkNet contracts on Ethereum.
pub struct Starknet {
    gps_contract: GpsContract,
    mempage_contract: MempageContract,
    core_contract: CoreContract,
    ws: Web3<WebSocket>,
}

/// A StarkNet Ethereum [Log] event.
#[derive(Debug)]
pub enum StarknetLog {
    Fact(LogWithOrigin<FactLog>),
    Mempage(LogWithOrigin<MempageLog>),
    StateUpdate(LogWithOrigin<StateUpdateLog>),
    StateTransitionFact(LogWithOrigin<StateTransitionFactLog>),
}

/// Error return by `Starknet::get_logs`.
///
/// Currently only contains errors specific to the Infura RPC API.
#[derive(Debug)]
pub enum GetLogsError {
    /// Query exceeded limits (time or result length).
    QueryLimit,
    Other(anyhow::Error),
}

impl From<web3::Error> for GetLogsError {
    fn from(err: web3::Error) -> Self {
        use GetLogsError::*;
        match err {
            web3::Error::Rpc(err) if err.code.code() == RpcErrorCode::LimitExceeded.code() => {
                GetLogsError::QueryLimit
            }
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
        let core_contract = CoreContract::load(Web3::new(web_socket.clone()));

        Self {
            gps_contract,
            mempage_contract,
            core_contract,
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
    ) -> std::result::Result<Vec<StarknetLog>, GetLogsError> {
        let log_filter = web3::types::FilterBuilder::default()
            .address(vec![
                self.mempage_contract.address,
                self.gps_contract.address,
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

    /// Fetches and interprets the memory pages into a StarkNet [Fact].
    pub async fn retrieve_fact(&self, mempage_txs: &[TransactionId]) -> Result<Fact> {
        // Retrieve mempages from L1, skip first page.
        //
        // Uncertain what the first page contains, but its not fact data.
        let token_futures = mempage_txs
            .iter()
            .skip(1)
            .map(|tx| self.retrieve_mempage(tx.clone()))
            .collect::<Vec<_>>();
        let pages = try_join_all(token_futures).await?.into_iter().flatten();

        Fact::parse_mempages(pages)
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
    fn parse_log(&self, log: &web3::types::Log) -> Result<StarknetLog> {
        // The first topic of an Ethereum log is its signature. We use this
        // to identify the StarkNet log type.
        match log.topics.first() {
            Some(topic) if topic == &self.mempage_contract.mempage_event.signature() => {
                Ok(StarknetLog::Mempage(
                    self.mempage_contract
                        .mempage_event
                        .parse_log(log)
                        .context("mempage log parsing")?,
                ))
            }
            Some(topic) if topic == &self.gps_contract.fact_event.signature() => {
                Ok(StarknetLog::Fact(
                    self.gps_contract
                        .fact_event
                        .parse_log(log)
                        .context("fact log parsing")?,
                ))
            }
            Some(topic) if topic == &self.core_contract.state_transition_event.signature() => {
                Ok(StarknetLog::StateTransitionFact(
                    self.core_contract
                        .state_transition_event
                        .parse_log(log)
                        .context("state transition fact log parsing")?,
                ))
            }
            Some(topic) if topic == &self.core_contract.state_update_event.signature() => {
                Ok(StarknetLog::StateUpdate(
                    self.core_contract
                        .state_update_event
                        .parse_log(log)
                        .context("state update log parsing")?,
                ))
            }
            Some(topic) => anyhow::bail!("unknown log signature: {}", topic),
            None => anyhow::bail!("log contained no signature"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use crate::ethereum::test::{
        create_test_websocket, fact_test_tx, mempage_test_tx, retrieve_log,
    };
    use assert_matches::assert_matches;
    use web3::types::H256;

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

            assert_matches!(result, Err(GetLogsError::QueryLimit));
        }
    }

    // Tests our fact retrieval against the results from the StarkWare
    // python script results.
    #[tokio::test]
    async fn retrieve_fact() {
        let ws = create_test_websocket().await;
        let starknet = Starknet::load(ws);

        let fact_hash =
            H256::from_str("0x983e4a7350a46070642a1ba0e6df4b097d527633c1ef256a2140c9ad0f264587")
                .unwrap();

        let from = 5742000;
        let to = from + 10_000;

        let logs = starknet
            .retrieve_logs(
                BlockNumber::Number(from.into()),
                BlockNumber::Number(to.into()),
            )
            .await
            .unwrap();

        let mut facts = HashMap::new();
        let mut mempages = HashMap::new();

        logs.iter().for_each(|log| match log {
            Log::Fact(fact) => {
                facts.insert(fact.hash, fact.mempage_hashes.clone());
            }
            Log::Mempage(mempage) => {
                mempages.insert(mempage.hash, mempage.origin.transaction_hash);
            }
        });

        let fact_mempages = facts.get(&fact_hash).unwrap();

        let tx = fact_mempages
            .iter()
            .map(|mp| {
                let t = mempages.get(mp).unwrap();
                TransactionId::Hash(*t)
            })
            .collect::<Vec<_>>();

        let fact = starknet.retrieve_fact(&tx).await.unwrap();

        let expected = Fact {
            deployed_contracts: vec![
                DeployedContract {
                    address: U256::from_str(
                        "0x55231fadef974ea197e68c99fdb1896a3793e3db35f7fac120ae11bd7ae221",
                    )
                    .unwrap(),
                    hash: U256::from_str(
                        "0x2f42c7edbed0fabd97d566fa27674df17bd0f36b888c55fb6d69f5db98201ed",
                    )
                    .unwrap(),
                    call_data: vec![
                        U256::from_str(
                            "0x567aaf5e66bde341cbd4582e9c275ad9bc1de92fa57a9b9d02b75f14433259",
                        )
                        .unwrap(),
                        U256::from_str(
                            "0x30435903dcd550c23d5c7b80a3c2b80971e1e3107e49938e0a1f884eaf45416",
                        )
                        .unwrap(),
                    ],
                },
                DeployedContract {
                    address: U256::from_str(
                        "0x85f7a619508eb9b6035ef700c5a2b32ce7d98781a9aa5f951aa5f73d78ca18",
                    )
                    .unwrap(),
                    hash: U256::from_str(
                        "0x4f279979402f0a86770030d520010242f5d18c731a43a126d3d416eee036e0a",
                    )
                    .unwrap(),
                    call_data: vec![U256::from(2), U256::from(1), U256::from(2)],
                },
            ],
            contract_updates: vec![
                ContractUpdate {
                    address: U256::from_str(
                        "0x4095069acd316ec7d0fb479e2a22b6c80fdefa36eb9aa2d98770393a2f0793",
                    )
                    .unwrap(),
                    storage_updates: vec![StorageUpdate {
                        address: U256::from_str(
                            "0x415768d4e7426fcae576c82580903e277c028ace66a738ba50b333b4dba2a0",
                        ).unwrap(),
                        value: U256::from_dec_str("1436351082076388378937592820583595915390412612503470928012048545736083828717").unwrap(),
                    }],
                },
                ContractUpdate {
                    address: U256::from_str(
                        "0x55231fadef974ea197e68c99fdb1896a3793e3db35f7fac120ae11bd7ae221",
                    )
                    .unwrap(),
                    storage_updates: vec![StorageUpdate {
                        address: U256::from_str(
                            "0x567aaf5e66bde341cbd4582e9c275ad9bc1de92fa57a9b9d02b75f14433259",
                        ).unwrap(),
                        value: U256::from_dec_str("1364375615306131238293526755218258502029326963887457755108602545788322862102").unwrap(),
                    }],
                },
                ContractUpdate {
                    address: U256::from_str(
                        "0x85f7a619508eb9b6035ef700c5a2b32ce7d98781a9aa5f951aa5f73d78ca18",
                    )
                    .unwrap(),
                    storage_updates: vec![StorageUpdate {
                        address: U256::from_str(
                            "0xd3492e64be829d49fe51f410d37fa2cf87aabd7a0dc2c85946067e2d61412f",
                        ).unwrap(),
                        value: U256::from(2),
                    },
                    StorageUpdate {
                        address: U256::from_str(
                            "0xd3492e64be829d49fe51f410d37fa2cf87aabd7a0dc2c85946067e2d614130",
                        ).unwrap(),
                        value: U256::from(3),
                    }],
                },
                ContractUpdate {
                    address: U256::from_str(
                        "0x308136cc7250bdb051ae19abf9133f4d8982966146ee334a7f4aa57c4fe334f",
                    )
                    .unwrap(),
                    storage_updates: vec![],
                },
                ContractUpdate {
                    address: U256::from_str(
                        "0x730dad481c14b223102383eb2dced32d2478926bc20fe01a3c5f6b0dea8bc94",
                    )
                    .unwrap(),
                    storage_updates: vec![],
                },
            ],
        };

        assert_eq!(fact, expected);
    }
}
