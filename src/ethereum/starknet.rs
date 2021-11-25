//! Provides abstractions to interface with StarkNet's Ethereum contracts and events.
mod contract;
mod fact;
mod state_root;

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
    use std::str::FromStr;

    use crate::ethereum::test::{
        create_test_websocket, fact_test_tx, mempage_test_tx, retrieve_log,
    };
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;
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

        assert_matches!(mempage_log, StarknetLog::Mempage(..));
    }

    #[tokio::test]
    async fn parse_fact_log() {
        let ws = create_test_websocket().await;
        let starknet = Starknet::load(ws);
        let fact_tx = fact_test_tx();

        let log = retrieve_log(&fact_tx).await;
        let fact_log = starknet.parse_log(&log).unwrap();

        assert_matches!(fact_log, StarknetLog::Fact(..));
    }

    #[cfg(test)]
    mod retrieve_logs {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn ok() {
            let ws = create_test_websocket().await;
            let starknet = Starknet::load(ws);

            let from = 5864142;
            let to = 5864142 - 100;

            let result = starknet
                .retrieve_logs(
                    BlockNumber::Number(to.into()),
                    BlockNumber::Number(from.into()),
                )
                .await;

            let logs = result.unwrap();
            assert_eq!(logs.len(), 84);
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

        // A fact containing both contract deploments and storage updates.
        //
        // Randomly chosen using:
        //  https://goerli.etherscan.io/address/0x67D629978274b4E1e07256Ec2ef39185bb3d4D0d#events
        let fact_hash =
            H256::from_str("0xbf3b7d196393ee7b5ddddf6e219830c65cc94b4afa5af613ec94a7ed651c2813")
                .unwrap();

        // Block number containing this fact update.
        let to = 5876654;
        // Memory pages logs are emitted in blocks prior to the update.
        // So we need to retrieve logs from a range to ensure we get all
        // the required logs for this fact.
        let from = to - 10_000;

        let logs = starknet
            .retrieve_logs(
                BlockNumber::Number(from.into()),
                BlockNumber::Number(to.into()),
            )
            .await
            .unwrap();

        // Find our fact hash in the logs
        let fact = logs
            .iter()
            .find_map(|log| match log {
                StarknetLog::Fact(f) if f.data.hash == fact_hash => Some(f.clone()),
                _ => None,
            })
            .unwrap();

        // Collect memory page logs that belong to our fact
        let mempage_txs = logs
            .iter()
            .filter_map(|log| match log {
                StarknetLog::Mempage(mempage)
                    if fact.data.mempage_hashes.contains(&mempage.data.hash) =>
                {
                    let tx = mempage.origin.transaction_hash;
                    Some(TransactionId::Hash(tx))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        let fact = starknet.retrieve_fact(&mempage_txs).await.unwrap();

        let expected = Fact {
            deployed_contracts: vec![
                DeployedContract {
                    address: U256::from_dec_str("2005238406252901036683599278926811665941308458283132997267154497601833857461").unwrap(),
                    hash: U256::from_dec_str("2175195626185073029849142407296785061642163892759228526742429373445244228408").unwrap(),
                    call_data: vec![],
                },
                DeployedContract {
                    address: U256::from_dec_str("1380657829967356330790660033071345383611153364290931023546902339385807484883").unwrap(),
                    hash: U256::from_dec_str("2175195626185073029849142407296785061642163892759228526742429373445244228408").unwrap(),
                    call_data: vec![],
                },
            ],
            contract_updates: vec![
                ContractUpdate {
                    address: U256::from_dec_str("1380657829967356330790660033071345383611153364290931023546902339385807484883").unwrap(),
                    storage_updates: vec![]
                },
                ContractUpdate {
                    address: U256::from_dec_str("1755069831273166072366458588985965223979686686906815766019613573637758579966").unwrap(),
                    storage_updates: vec![
                        StorageUpdate {
                            address: U256::from_dec_str("814079005391940027390129862062157285361348684878695833898695909074510122245").unwrap(),
                            value: U256::from_dec_str("2145888722024684049935776658900472878504765045824615012672687402235959174952").unwrap()
                        },
                        StorageUpdate {
                            address: U256::from_dec_str("1410752890141599390055702225444248987277077018130707938554244692172889272177").unwrap(),
                            value: U256::from(0)
                        },
                        StorageUpdate {
                            address: U256::from_dec_str("1563672576422918850564506150092036819309968525068313502302455251173901598124").unwrap(),
                            value: U256::from(11)
                        },
                        StorageUpdate {
                            address: U256::from_dec_str("1788136559461238800386522850547867498833152733095516909793758980120885021902").unwrap(),
                            value: U256::from(0)
                        }
                    ]
                },
                ContractUpdate {
                    address: U256::from_dec_str("2005238406252901036683599278926811665941308458283132997267154497601833857461").unwrap(),
                    storage_updates: vec![]
                },
                ContractUpdate {
                    address: U256::from_dec_str("2211333340133722854231389664684920138369167001212521106227823317724820414359").unwrap(),
                    storage_updates: vec![
                        StorageUpdate {
                            address: U256::from_dec_str("2433998266483775785325659667502784461255680180764730822921086061280079738301").unwrap(),
                            value: U256::from_dec_str("447000000000000000000").unwrap()
                        },
                        StorageUpdate {
                            address: U256::from_dec_str("3303413371309657170411995174561851664035014984988022984254662524842095446428").unwrap(),
                            value: U256::from_dec_str("500000000000000000000").unwrap()
                        }
                    ]
                }
            ]
        };

        assert_eq!(fact, expected);
    }
}
