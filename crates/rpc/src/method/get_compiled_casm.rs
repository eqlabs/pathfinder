use anyhow::Context;
use pathfinder_common::casm_class::CasmContractClass;
use pathfinder_common::ClassHash;

use crate::context::RpcContext;
use crate::error::ApplicationError;

#[derive(Debug)]
pub struct Input {
    pub class_hash: ClassHash,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                class_hash: ClassHash(value.deserialize("class_hash")?),
            })
        })
    }
}

#[derive(Debug)]
pub struct Output(CasmContractClass);

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        self.0.serialize(serializer)
    }
}

#[derive(Debug)]
pub enum Error {
    CompilationFailed,
    ClassHashNotFound(ClassHash),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

impl From<Error> for crate::jsonrpc::RpcError {
    fn from(error: Error) -> Self {
        match error {
            Error::CompilationFailed => Self::ApplicationError(ApplicationError::CompilationFailed),
            Error::ClassHashNotFound(_) => {
                Self::ApplicationError(ApplicationError::ClassHashNotFound)
            }
            Error::Internal(e) => Self::InternalError(e),
        }
    }
}

/// Get the compiled casm for a given class hash.
pub async fn get_compiled_casm(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();
    let jh = tokio::task::spawn_blocking(move || -> Result<Output, Error> {
        let _g = span.enter();

        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")
            .map_err(Error::Internal)?;

        let tx = db
            .transaction()
            .context("Creating database transaction")
            .map_err(Error::Internal)?;

        // Get the class definition
        let casm_definition = tx
            .casm_definition(input.class_hash)
            .context("Fetching class definition")
            .map_err(Error::Internal)?
            .ok_or(Error::ClassHashNotFound(input.class_hash))?;

        // Convert to JSON string
        let casm_definition_str = String::from_utf8_lossy(&casm_definition);

        // Parse the casm definition
        let casm_contract_class = CasmContractClass::try_from(casm_definition_str.as_ref())
            .context("Parsing casm definition")
            .map_err(|_| Error::CompilationFailed)?;

        Ok(Output(casm_contract_class))
    });

    jh.await.context("Fetching compiled casm")?
}
