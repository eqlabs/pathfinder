//! Error types for the consensus engine.

use std::fmt;

/// An error that occurred in the consensus engine.
///
/// This error type wraps internal errors and provides information about
/// whether the error is recoverable or fatal.
#[derive(Debug)]
pub struct ConsensusError {
    inner: anyhow::Error,
    kind: ErrorKind,
}

// Note: We don't expose malachite error types in the public API.
// The error is converted to anyhow::Error internally.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Error occurred during WAL recovery (e.g., corrupted entry)
    WalRecovery,
    /// Error from the consensus engine internals (e.g., malachite errors)
    Internal,
}

impl ConsensusError {
    /// Create a WAL recovery error (recoverable).
    pub fn wal_recovery(error: anyhow::Error) -> Self {
        Self {
            inner: error,
            kind: ErrorKind::WalRecovery,
        }
    }

    /// Create an internal consensus engine error from a malachite error.
    ///
    /// All malachite errors are treated as fatal and classified as internal
    /// errors, but we could potentially identify recoverable ones in the
    /// future.
    pub(crate) fn malachite<Ctx>(error: malachite_consensus::Error<Ctx>) -> Self
    where
        Ctx: malachite_types::Context,
    {
        // Convert to anyhow::Error for storage (we don't leak malachite types)
        let anyhow_err: anyhow::Error = error.into();

        Self {
            inner: anyhow_err,
            kind: ErrorKind::Internal,
        }
    }

    /// Check if this error is recoverable.
    ///
    /// Recoverable errors are those that don't indicate state corruption or
    /// bugs, and the consensus engine can continue operating after handling
    /// them.
    pub fn is_recoverable(&self) -> bool {
        matches!(self.kind, ErrorKind::WalRecovery)
    }
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for ConsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}
