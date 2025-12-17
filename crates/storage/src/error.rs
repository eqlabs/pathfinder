//! Error types for storage operations.

use thiserror::Error;

/// Storage/database errors that occur during storage operations.
///
/// This error type represents all storage-related failures (connection errors,
/// query failures, transaction errors, etc.). All storage errors are considered
/// fatal as they likely indicate problems with our infra.
///
/// This is a simple wrapper around `anyhow::Error` that serves as a boundary
/// marker, indicating that the error originated from storage operations. The
/// underlying error chain is preserved for debugging.
///
/// Note: Because all storage errors are considered fatal, exposing different
/// variants (e.g. `SqliteError`, `PoolError`, etc.) didn't seem relevant.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct StorageError(#[from] anyhow::Error);

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self(anyhow::Error::from(error))
    }
}

impl From<r2d2::Error> for StorageError {
    fn from(error: r2d2::Error) -> Self {
        Self(anyhow::Error::from(error))
    }
}
