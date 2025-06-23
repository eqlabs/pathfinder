use std::time::Duration;

use malachite_types::{ThresholdParams, TimeoutKind};

use crate::{Height, ValidatorAddress, VoteSyncMode};

/// The configuration for the consensus engine.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// The address of the validator.
    pub address: ValidatorAddress,
    /// The initial height.
    pub initial_height: Height,
    /// The threshold parameters.
    pub threshold_params: ThresholdParams,
    /// The vote sync mode.
    pub vote_sync_mode: VoteSyncMode,
    /// The timeout configuration.
    pub timeout_values: TimeoutValues,
    /// The number of completed heights to keep in memory.
    pub history_depth: u64,
}

impl Config {
    /// Create a new consensus config with the default values for a single
    /// validator.
    pub fn new(address: ValidatorAddress) -> Self {
        Self {
            address,
            history_depth: 10,
            ..Default::default()
        }
    }

    /// Set the initial height.
    pub fn with_initial_height(mut self, height: Height) -> Self {
        self.initial_height = height;
        self
    }

    /// Set the threshold parameters.
    pub fn with_threshold_params(mut self, threshold_params: ThresholdParams) -> Self {
        self.threshold_params = threshold_params;
        self
    }

    /// Set the vote sync mode.
    pub fn with_vote_sync_mode(mut self, vote_sync_mode: VoteSyncMode) -> Self {
        self.vote_sync_mode = vote_sync_mode;
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
    /// Timeout for detecting consensus being in the prevote step for too long.
    pub prevote_time_limit: Duration,
    /// Timeout for detecting consensus being in the precommit step for too
    /// long.
    pub precommit_time_limit: Duration,
    /// Timeout to rebroadcast the last prevote.
    pub prevote_rebroadcast: Duration,
    /// Timeout to rebroadcast the last precommit.
    pub precommit_rebroadcast: Duration,
}

impl Default for TimeoutValues {
    fn default() -> Self {
        Self {
            propose: Duration::from_secs(10),
            prevote: Duration::from_secs(10),
            precommit: Duration::from_secs(10),
            prevote_time_limit: Duration::from_secs(10),
            precommit_time_limit: Duration::from_secs(10),
            prevote_rebroadcast: Duration::from_secs(10),
            precommit_rebroadcast: Duration::from_secs(10),
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
            TimeoutKind::PrevoteTimeLimit => self.prevote_time_limit,
            TimeoutKind::PrecommitTimeLimit => self.precommit_time_limit,
            TimeoutKind::PrevoteRebroadcast => self.prevote_rebroadcast,
            TimeoutKind::PrecommitRebroadcast => self.precommit_rebroadcast,
        }
    }
}
