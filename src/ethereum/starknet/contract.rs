mod core;
mod gps;
mod mempage;

use std::marker::PhantomData;

use anyhow::Context;
use web3::ethabi::Event;
use web3::ethabi::RawLog;
use web3::types::H256;
use web3::types::U256;

use crate::ethereum::EthOrigin;

pub use self::core::*;
pub use self::gps::*;
pub use self::mempage::*;

/// A [StarknetEvent] which can parse logs emitted by this event.
pub struct StarknetEvent<T>
where
    T: TryFrom<web3::ethabi::Log, Error = anyhow::Error>,
{
    event: Event,
    log_type: PhantomData<T>,
}

impl<T> StarknetEvent<T>
where
    T: TryFrom<web3::ethabi::Log, Error = anyhow::Error>,
{
    pub fn new(event: Event) -> Self {
        Self {
            event,
            log_type: PhantomData {},
        }
    }

    /// This event's signature. Can be used to identify an Ethereum log by comparing to its first topic.
    pub fn signature(&self) -> H256 {
        self.event.signature()
    }

    /// Parses an Ethereum log.
    pub fn parse_log(&self, log: &web3::types::Log) -> anyhow::Result<LogWithOrigin<T>> {
        let origin = EthOrigin::try_from(log)?;
        let log_index = log.log_index.context("log index missing")?;

        let log = RawLog {
            topics: log.topics.clone(),
            data: log.data.0.clone(),
        };

        let log = self.event.parse_log(log)?;
        let data = T::try_from(log)?;

        Ok(LogWithOrigin {
            origin,
            data,
            log_index,
        })
    }
}

/// A parsed Starknet log with its [Ethereum origin](EthOrigin).
#[derive(Debug, Clone, PartialEq)]
pub struct LogWithOrigin<T>
where
    T: TryFrom<web3::ethabi::Log, Error = anyhow::Error>,
{
    pub origin: EthOrigin,
    pub log_index: U256,
    pub data: T,
}
