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
    ClassHashNotFound,
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
            RpcError::ClassHashNotFound => 28,
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

/// Generates an enum subset of [RpcError] along with boilerplate for mapping the variants.
///
/// This is useful for RPC methods which may only emit a few of the [RpcError] variants as this
/// macro can be used to quickly create the enum-subset with the required glue code.
///
/// ## Usage
/// ```no_run
/// rpc_error_subset!(<enum_name>: <variant a>, <variant b>, <variant N>);
/// ```
/// Note that the variants __must__ match the [RpcError] variant names and that [RpcError::Internal]
/// is always included by default (and therefore should not be part of macro input).
///
/// ## Specifics
/// This macro generates the following:
///
/// 1. New enum definition with `#[derive(Debug)]`
/// 2. `impl From<NewEnum> for RpcError`
/// 3. `impl From<anyhow::Error> for NewEnum`
///
/// It always includes the `Internal(anyhow::Error)` variant.
///
/// ## Example with expansion
/// ```no_run
/// // This macro invocation:
/// rpc_error_subset!(MyEnum: BlockNotFound, NoBlocks);
/// // expands to:
/// #[derive(debug)]
/// pub enum MyError {
///     BlockNotFound,
///     NoBlocks,
///     Internal(anyhow::Error),
/// }
///
/// impl From<MyError> for RpcError {
///     fn from(x: MyError) -> Self {
///         match x {
///             MyError::BlockNotFound => Self::BlockNotFound,
///             MyError::NoBlocks => Self::NoBlocks,
///             MyError::Internal(internal) => Self::Internal(internal),
///         }
///     }
/// }
///
/// impl From<anyhow::Error> for MyError {
///     fn from(e: anyhow::Error) -> Self {
///         Self::Internal(e)
///     }
/// }
/// ```
#[macro_export]
macro_rules! rpc_error_subset {
    // This macro uses the following advanced techniques:
    //   - tt-muncher (https://danielkeep.github.io/tlborm/book/pat-incremental-tt-munchers.html)
    //   - push-down-accumulation (https://danielkeep.github.io/tlborm/book/pat-push-down-accumulation.html)
    //
    // All macro arms (except the entry-point) begin with `@XXX` to prevent accidental usage.
    //
    // It would be possible to allow for custom `#[derive()]` and other attributes, but these are currently not supported.

    // Entry-point for the macro
    ($enum_name:ident: $($subset:tt),+) => {
        crate::rpc_error_subset!(@enum_def, $enum_name, $($subset),+);
        crate::rpc_error_subset!(@from_anyhow, $enum_name);
        crate::rpc_error_subset!(@from_def, $enum_name, $($subset),+);
    };
    // Generates the enum definition, nothing tricky here.
    (@enum_def, $enum_name:ident, $($subset:tt),+) => {
        #[derive(Debug)]
        pub enum $enum_name {
            $($subset),+,
            Internal(anyhow::Error),
        }
    };
    // Generates From<anyhow::Error>, nothing tricky here.
    (@from_anyhow, $enum_name:ident) => {
        impl From<anyhow::Error> for $enum_name {
            fn from(e: anyhow::Error) -> Self {
                Self::Internal(e)
            }
        }
    };
    // Generates From<$enum_name> for RpcError, this macro arm itself is not tricky,
    // however its child calls are.
    //
    // We pass down the variants, which will get tt-munched until we reach the base case.
    // We also initialize the match "arms" (`{}`) as empty. These will be accumulated until
    // we reach the base case at which point the match itself is generated using the arms.
    //
    // We cannot generate the match in this macro arm as each macro invocation must result in
    // a valid AST (I think). This means that having the match at this level would require the
    // child calls only return arm(s) -- which is not valid syntax by itself.
    //
    // By pushing the arms from this level downwards, and creating the match statement at the lowest
    // level, we guarantee that only valid valid Rust will bubble back up.
    (@from_def, $enum_name:ident, $($variants:ident),*) => {
        impl From<$enum_name> for crate::rpc::error::RpcError {
            fn from(x: $enum_name) -> Self {
                crate::rpc_error_subset!(@parse, x, $enum_name, {}, $($variants),*)
            }
        }
    };
    // Termination case (no further input to munch). We generate the match statement here.
    (@parse, $var:ident, $enum_name:ident, {$($arms:tt)*}, $(,)*) => {
        match $var {
            $($arms)*
            $enum_name::Internal(internal) => Self::Internal(internal),
        }
    };
    // Append variant to arms. Continue parsing the remaining variants.
    (@parse, $var:ident, $enum_name:ident, {$($arms:tt)*}, $variant:ident, $($tail:ident),*) => {
        crate::rpc_error_subset!(
            @parse, $var, $enum_name,
            {
                $($arms)*
                $enum_name::$variant => Self::$variant,
            },
            $($tail),*,
        )
    };
}
