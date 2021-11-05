//! Provides abstractions to interface with StarkNet's Ethereum contracts and events.
use std::{convert::TryFrom, str::FromStr};

use web3::{
    contract::{tokens::Tokenizable, Contract},
    ethabi::{Event, LogParam, RawLog, Token},
    futures::future::try_join_all,
    transports::WebSocket,
    types::{BlockNumber, TransactionId, H160, H256, U256},
    Web3,
};

use anyhow::{Context, Result};

use crate::ethereum::mempage::MempageParsingExt;

const CORE_ADDR: &str = "0x67D629978274b4E1e07256Ec2ef39185bb3d4D0d";
const GPS_ADDR: &str = "0xB02D49C4d89f0CeA504C4C93934E7fC66e20A257";
const MEMPAGE_ADDR: &str = "0xb609Eba1DC0298A984Fa8a34528966E997C5BB13";

const GPS_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/gps_statement_verifier.json"
));

const MEMPAGE_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/memory_page_fact_registry.json"
));

/// An Ethereum origin point.
pub struct EthOrigin {
    pub block_hash: H256,
    pub block_number: u64,
    pub transaction_hash: H256,
    pub transaction_index: u64,
}

impl TryFrom<&web3::types::Log> for EthOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &web3::types::Log) -> Result<Self, Self::Error> {
        let block_hash = log.block_hash.context("missing block hash")?;
        let block_number = log.block_number.context("missing block hash")?.as_u64();
        let transaction_hash = log.transaction_hash.context("missing transaction hash")?;
        let transaction_index = log
            .transaction_index
            .context("missing transaction index")?
            .as_u64();

        Ok(EthOrigin {
            block_hash,
            block_number,
            transaction_hash,
            transaction_index,
        })
    }
}

/// A StarkNet Ethereum log containing a Fact.
///
/// Contains a list of memory pages which can be
/// parsed to reveal the state updates provided
/// by this [FactLog].
pub struct FactLog {
    origin: EthOrigin,
    hash: H256,
    mempage_hashes: Vec<H256>,
}

/// An Ethereum log representing a StarkNet memory page.
///
/// The log's Ethereum transaction contains the actual data
/// of this memory page.
pub struct MempageLog {
    origin: EthOrigin,
    hash: H256,
}

/// Describes the deployment of a new StarkNet contract.
pub struct DeployedContract {
    pub address: H160,
    pub hash: H256,
    pub call_data: Vec<U256>,
}

/// A StarkNet contract's storage updates.
pub struct ContractUpdate {
    pub address: H160,
    pub storage_updates: Vec<StorageUpdate>,
}

/// A StarkNet contract's storage update.
pub struct StorageUpdate {
    pub address: H160,
    pub value: U256,
}

/// The set of state updates of a StarkNet [Fact].
///
/// Contains new [DeployedContracts](DeployedContract) as well as [ContractUpdates](ContractUpdate).
pub struct Fact {
    pub deployed_contracts: Vec<DeployedContract>,
    pub contract_updates: Vec<ContractUpdate>,
}

/// Provides abstractions for interacting with StarkNet contracts on Ethereum.
pub struct Starknet {
    gps_contract: Contract<WebSocket>,
    mempage_contract: Contract<WebSocket>,

    gps_event: Event,
    mempage_event: Event,

    ws: Web3<WebSocket>,
}

/// A StarkNet Ethereum [Log] event.
pub enum Log {
    Fact(FactLog),
    Mempage(MempageLog),
}

/// Error return by `Starknet::get_logs`.
///
/// Currently only contains errors specific to the Infura RPC API.
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
    pub fn load(web_socket: WebSocket) -> Result<Self> {
        let transport = web3::Web3::new(web_socket);
        let mempage_addr = H160::from_str(MEMPAGE_ADDR).context("mempage address parsing")?;
        let mempage_contract = Contract::from_json(transport.eth(), mempage_addr, MEMPAGE_ABI)
            .context("mempage contract parsing")?;
        let mempage_event = mempage_contract
            .abi()
            .event("LogMemoryPageFactContinuous")
            .context("mempage event parsing")?
            .clone();

        let gps_addr = H160::from_str(GPS_ADDR).context("gps address parsing")?;
        let gps_contract = Contract::from_json(transport.eth(), gps_addr, GPS_ABI)
            .context("gps contract parsing")?;
        let gps_event = gps_contract
            .abi()
            .event("LogMemoryPagesHashes")
            .context("gps event parsing")?
            .clone();

        Ok(Self {
            gps_contract,
            mempage_contract,
            gps_event,
            mempage_event,
            ws: transport,
        })
    }

    /// Fetches and interprets the memory pages into a StarkNet [Fact].
    pub async fn interpret_fact(&self, mempage_txs: &[H256]) -> Result<Fact> {
        // Collect mempages from L1. Skip first page (not sure what this contains,
        // but its not relevant here).
        let token_futures = mempage_txs
            .iter()
            .skip(1)
            .map(|tx| self.get_mempage(*tx))
            .collect::<Vec<_>>();
        let pages = try_join_all(token_futures).await?;
        let mut tokens = pages.iter().cloned().flatten();

        let num_contracts = tokens
            .parse_u256()
            .context("number of contracts deployed")?
            .as_usize();

        let deployed_contracts = (0..num_contracts)
            .map(|i| {
                tokens
                    .parse_deployed_contract()
                    .with_context(|| format!("contract {} of {}", i, num_contracts))
            })
            .collect::<Result<_, _>>()?;

        let num_updates = tokens
            .parse_u256()
            .context("number of contract updates")?
            .as_usize();
        let contract_updates = (0..num_updates)
            .map(|i| {
                tokens
                    .parse_contract_update()
                    .with_context(|| format!("contract update {} of {}", i, num_updates))
            })
            .collect::<Result<_, _>>()?;

        Ok(Fact {
            deployed_contracts,
            contract_updates,
        })
    }

    /// Decode's an Ethereum transaction as a StarkNet memory page.
    async fn get_mempage(&self, transaction: H256) -> Result<Vec<Token>> {
        let transaction = self
            .ws
            .eth()
            .transaction(TransactionId::Hash(transaction))
            .await?
            .context("mempage transaction is missing on chain")?;

        self.mempage_contract
            .abi()
            .function("name")
            .unwrap()
            .decode_input(&transaction.input.0)
            .context("mempage input decoding failed")
    }

    /// Queries Ethereum for all StarkNet [Logs](Log) between `from` and `to` Ethereum blocks.
    pub async fn get_logs(
        &self,
        from: BlockNumber,
        to: BlockNumber,
    ) -> std::result::Result<Vec<Log>, GetLogsError> {
        let log_filter = web3::types::FilterBuilder::default()
            .address(vec![
                self.mempage_contract.address(),
                self.gps_contract.address(),
            ])
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

    /// Parses an [Ethereum log](web3::types::Log) into a StarkNet [Log].
    fn parse_log(&self, log: &web3::types::Log) -> Result<Log> {
        // The first topic of an Ethereum log is its signature. We use this
        // to identify the StarkNet log type.
        match log.topics.first() {
            Some(topic) if topic == &self.mempage_event.signature() => Ok(Log::Mempage(
                self.parse_mempage_log(log).context("mempage log parsing")?,
            )),
            Some(topic) if topic == &self.gps_event.signature() => Ok(Log::Fact(
                self.parse_gps_log(log).context("gps log parsing")?,
            )),
            Some(topic) => anyhow::bail!("unknown log signature: {}", topic),
            None => anyhow::bail!("log contained no signature"),
        }
    }

    /// Parses an [Ethereum log](web3::types::Log) into a StarkNet [FactLog].
    fn parse_gps_log(&self, log: &web3::types::Log) -> Result<FactLog> {
        let origin = EthOrigin::try_from(log)?;

        let log = RawLog {
            topics: log.topics.clone(),
            data: log.data.0.clone(),
        };

        let log = self.gps_event.parse_log(log)?;
        let hash = get_log_hash_param(&log, "factHash")?;

        let mempage_hashes = get_log_param(&log, "pagesHashes")?;
        let mempage_hashes = mempage_hashes
            .value
            .into_array()
            .context("page hashes could not be cast to array")?
            .iter()
            .map(|token| H256::from_token(token.clone()))
            .collect::<Result<Vec<_>, _>>()
            .context("page hash could not be parsed")?;

        Ok(FactLog {
            origin,
            mempage_hashes,
            hash,
        })
    }

    /// Parses an [Ethereum log](web3::types::Log) into a StarkNet [MempageLog].
    fn parse_mempage_log(&self, log: &web3::types::Log) -> Result<MempageLog> {
        let origin = EthOrigin::try_from(log)?;

        let log = RawLog {
            topics: log.topics.clone(),
            data: log.data.0.clone(),
        };

        let log = self.gps_event.parse_log(log)?;
        let hash = get_log_hash_param(&log, "memoryHash")?;

        Ok(MempageLog { hash, origin })
    }
}

fn get_log_param(log: &web3::ethabi::Log, param: &str) -> Result<LogParam> {
    log.params
        .iter()
        .find(|p| p.name == param)
        .cloned()
        .with_context(|| format!("parameter {} not found", param))
}

fn get_log_hash_param(log: &web3::ethabi::Log, param: &str) -> Result<H256> {
    let param = get_log_param(log, param)?;
    H256::from_token(param.value.clone())
        .with_context(|| format!("failed to parse log hash token: {:?}", param.value))
}
