//! Error types for proposal handling.

use crate::validator::WrongValidatorStageError;

/// Errors that can occur when handling incoming proposal parts.
///
/// These errors are classified as recoverable (from peers) or fatal (our
/// state).
#[derive(Debug, thiserror::Error)]
pub enum ProposalError {
    /// Unexpected proposal part received (e.g., Init when expecting BlockInfo).
    #[error("Unexpected proposal part: {message}")]
    UnexpectedProposalPart { message: String },

    /// Validator stage not found in cache.
    #[error("No ValidatorStage for height and round {height_and_round}")]
    // TODO why is height_and_round a String?
    ValidatorStageNotFound { height_and_round: String },

    /// Wrong validator stage type (e.g., expected BlockInfo but got
    /// TransactionBatch).
    #[error("Wrong validator stage: {message}")]
    WrongValidatorStage { message: String },
    // TODO(consensus) add more error variants:
    // - Recoverable: Execution failed due to proposal content
    // - Fatal: Execution failed due to storage/DB error
}

impl From<WrongValidatorStageError> for ProposalError {
    fn from(err: WrongValidatorStageError) -> Self {
        ProposalError::WrongValidatorStage {
            message: format!("{err}"),
        }
    }
}

impl From<WrongValidatorStageError> for ProposalHandlingError {
    fn from(err: WrongValidatorStageError) -> Self {
        Self::Recoverable(err.into())
    }
}

/// Errors that can occur when handling incoming proposal parts.
///
/// This enum wraps all possible error types, automatically classifying them:
/// - `ProposalError` is always recoverable (from peers)
/// - `anyhow::Error` is always fatal (our state, DB errors, etc.)
#[derive(Debug, thiserror::Error)]
pub enum ProposalHandlingError {
    /// Recoverable error from peer data (malformed proposals, out-of-order
    /// parts).
    #[error(transparent)]
    Recoverable(#[from] ProposalError),

    /// Fatal error (DB errors, validation failures, state corruption).
    #[error(transparent)]
    Fatal(#[from] anyhow::Error),
}

impl ProposalHandlingError {
    /// Check if this error is recoverable.
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::Recoverable(_))
    }

    /// Get the error message for logging.
    pub fn error_message(&self) -> String {
        match self {
            Self::Recoverable(e) => format!("{e}"),
            Self::Fatal(e) => format!("{e:#}"),
        }
    }
}

impl From<pathfinder_storage::StorageError> for ProposalHandlingError {
    fn from(value: pathfinder_storage::StorageError) -> Self {
        Self::Fatal(value.into())
    }
}
