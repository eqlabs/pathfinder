use std::path::PathBuf;
use std::time::Duration;

use malachite_types::{ThresholdParams, TimeoutKind};

/// The configuration for the consensus engine.
#[derive(Clone, Debug, Default)]
pub struct Config<A> {
    /// The address of the validator.
    pub address: A,
    /// The initial height.
    pub initial_height: u64,
    /// The timeout configuration.
    pub timeout_values: TimeoutValues,
    /// The number of completed heights to keep in memory.
    pub history_depth: u64,
    /// The directory to store the write-ahead log.
    pub wal_dir: PathBuf,
    /// The tendermint threshold parameters (not exposed to the outside, yet)
    pub(crate) threshold_params: ThresholdParams,
}

impl<A: Default> Config<A> {
    /// Create a new consensus config with the default values for a single
    /// validator.
    pub fn new(address: A) -> Self {
        Self {
            address,
            history_depth: 10,
            wal_dir: PathBuf::from("wal"),
            ..Default::default()
        }
    }

    /// Set the initial height.
    pub fn with_initial_height(mut self, height: u64) -> Self {
        self.initial_height = height;
        self
    }

    /// Set the timeout values.
    pub fn with_timeout_values(mut self, timeout_values: TimeoutValues) -> Self {
        self.timeout_values = timeout_values;
        self
    }

    /// Set the number of completed heights to keep in memory.
    pub fn with_history_depth(mut self, history_depth: u64) -> Self {
        self.history_depth = history_depth;
        self
    }

    /// Set the WAL directory.
    pub fn with_wal_dir(mut self, wal_dir: PathBuf) -> Self {
        self.wal_dir = wal_dir;
        self
    }
}

/// The timeout values for the consensus engine.
#[derive(Debug, Clone)]
pub struct TimeoutValues {
    /// The timeout for the propose step.
    pub propose: Duration,
    /// The timeout for the prevote step.
    pub prevote: Duration,
    /// The timeout for the precommit step.
    pub precommit: Duration,
    /// Timeout to rebroadcast the last prevote.
    pub rebroadcast: Duration,
}

impl Default for TimeoutValues {
    fn default() -> Self {
        Self {
            propose: Duration::from_secs(10),
            prevote: Duration::from_secs(10),
            precommit: Duration::from_secs(10),
            rebroadcast: Duration::from_secs(10),
        }
    }
}

impl TimeoutValues {
    /// Get the timeout for a given timeout kind.
    pub fn get(&self, kind: TimeoutKind) -> Duration {
        match kind {
            TimeoutKind::Propose => self.propose,
            TimeoutKind::Prevote => self.prevote,
            TimeoutKind::Precommit => self.precommit,
            TimeoutKind::Rebroadcast => self.rebroadcast,
        }
    }
}
