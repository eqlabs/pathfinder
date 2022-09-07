#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("Failed to write transaction")]
    FailedToReceiveTxn,
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Invalid message selector")]
    InvalidMessageSelector,
    #[error("Invalid call data")]
    InvalidCallData,
    #[error("Block not found")]
    BlockNotFound,
    #[error("Transaction hash not found")]
    TxnHashNotFound,
    #[error("Invalid transaction index in a block")]
    InvalidTxnIndex,
    #[error("Class hash not found")]
    ClassHashNotFoundUND,
    #[error("Requested page size is too big")]
    PageSizeTooBig,
    #[error("There are no blocks")]
    NoBlocks,
    #[error("The supplied continuation token is invalid or unknown")]
    InvalidContinuationToken,
    #[error("Contract error")]
    ContractError,
    #[error(transparent)]
    Internal(anyhow::Error),
}

impl RpcError {
    pub fn code(&self) -> i32 {
        match self {
            RpcError::FailedToReceiveTxn => 1,
            RpcError::ContractNotFound => 20,
            RpcError::InvalidMessageSelector => 21,
            RpcError::InvalidCallData => 22,
            RpcError::BlockNotFound => 24,
            RpcError::TxnHashNotFound => 25,
            RpcError::InvalidTxnIndex => 27,
            RpcError::ClassHashNotFoundUND => 28,
            RpcError::PageSizeTooBig => 31,
            RpcError::NoBlocks => 32,
            RpcError::InvalidContinuationToken => 33,
            RpcError::ContractError => 40,
            RpcError::Internal(_) => jsonrpsee::types::error::ErrorCode::InternalError.code(),
        }
    }
}

impl From<RpcError> for jsonrpsee::core::error::Error {
    fn from(err: RpcError) -> Self {
        use jsonrpsee::types::error::{CallError, ErrorObject};

        CallError::Custom(ErrorObject::owned(err.code(), err.to_string(), None::<()>)).into()
    }
}
