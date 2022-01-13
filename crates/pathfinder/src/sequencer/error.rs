//! Sequencer related error types.
use crate::rpc::types::reply::ErrorCode as RpcErrorCode;
use jsonrpsee::types as rpc;
use serde::{Deserialize, Serialize};

/// Sequencer errors.
#[derive(Debug, thiserror::Error)]
pub enum SequencerError {
    /// All errors related to deserializing sequencer replies.
    #[error("Failed to deserialize sequencer reply: {0}")]
    DeserializationError(#[from] serde_json::Error),
    /// Starknet specific errors.
    #[error("Starknet error: {0}")]
    StarknetError(#[from] StarknetError),
    /// Networking and protocol related errors.
    #[error("Sequencer transport error: {0}")]
    TransportError(#[from] reqwest::Error),
}

impl From<SequencerError> for rpc::Error {
    fn from(e: SequencerError) -> Self {
        match e {
            SequencerError::DeserializationError(e) => {
                rpc::Error::Call(rpc::CallError::Failed(e.into()))
            }
            SequencerError::StarknetError(e) => match e.code {
                StarknetErrorCode::OutOfRangeBlockHash | StarknetErrorCode::BlockNotFound => {
                    RpcErrorCode::InvalidBlockHash.into()
                }
                StarknetErrorCode::OutOfRangeContractAddress
                | StarknetErrorCode::UninitializedContract => RpcErrorCode::ContractNotFound.into(),
                StarknetErrorCode::OutOfRangeTransactionHash => {
                    rpc::Error::Call(rpc::CallError::Custom {
                        code: RpcErrorCode::INVALID_TRANSACTION_HASH as i32,
                        message: RpcErrorCode::INVALID_TRANSACTION_HASH_STR.to_owned(),
                        data: None,
                    })
                }
                StarknetErrorCode::OutOfRangeStorageKey => RpcErrorCode::InvalidStorageKey.into(),
                StarknetErrorCode::TransactionFailed => RpcErrorCode::InvalidCallData.into(),
                StarknetErrorCode::EntryPointNotFound => {
                    RpcErrorCode::InvalidMessageSelector.into()
                }
                StarknetErrorCode::MalformedRequest
                    if e.message.contains("Block ID should be in the range") =>
                {
                    RpcErrorCode::InvalidBlockNumber.into()
                }
                _ => rpc::Error::Call(rpc::CallError::Failed(e.into())),
            },
            SequencerError::TransportError(e) => rpc::Error::Call(rpc::CallError::Failed(e.into())),
        }
    }
}

/// Used for deserializing specific Starknet sequencer error data.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct StarknetError {
    pub code: StarknetErrorCode,
    pub message: String,
    // The `problems` field is intentionally omitted here
    // Let's deserialize it if it proves necessary
}

impl std::error::Error for StarknetError {}

impl std::fmt::Display for StarknetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Represents starknet specific error codes reported by the sequencer.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum StarknetErrorCode {
    #[serde(rename = "StarknetErrorCode.BLOCK_NOT_FOUND")]
    BlockNotFound,
    #[serde(rename = "StarknetErrorCode.ENTRY_POINT_NOT_FOUND_IN_CONTRACT")]
    EntryPointNotFound,
    #[serde(rename = "StarknetErrorCode.OUT_OF_RANGE_CONTRACT_ADDRESS")]
    OutOfRangeContractAddress,
    #[serde(rename = "StarknetErrorCode.OUT_OF_RANGE_CONTRACT_STORAGE_KEY")]
    OutOfRangeStorageKey,
    #[serde(rename = "StarkErrorCode.SCHEMA_VALIDATION_ERROR")]
    SchemaValidationError,
    #[serde(rename = "StarknetErrorCode.TRANSACTION_FAILED")]
    TransactionFailed,
    #[serde(rename = "StarknetErrorCode.UNINITIALIZED_CONTRACT")]
    UninitializedContract,
    #[serde(rename = "StarknetErrorCode.OUT_OF_RANGE_BLOCK_HASH")]
    OutOfRangeBlockHash,
    #[serde(rename = "StarknetErrorCode.OUT_OF_RANGE_TRANSACTION_HASH")]
    OutOfRangeTransactionHash,
    #[serde(rename = "StarkErrorCode.MALFORMED_REQUEST")]
    MalformedRequest,
}
