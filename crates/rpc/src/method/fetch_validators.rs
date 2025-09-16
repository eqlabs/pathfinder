use anyhow::Context;

use crate::context::RpcContext;
use crate::error::ApplicationError;
use crate::RpcVersion;

#[derive(Debug)]
pub enum FetchValidatorsError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    ContractNotFound,
    NoValidators { height: u64 },
    InvalidValidatorData(String),
}

impl From<anyhow::Error> for FetchValidatorsError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<validator_fetcher::ValidatorFetcherError> for FetchValidatorsError {
    fn from(err: validator_fetcher::ValidatorFetcherError) -> Self {
        use validator_fetcher::ValidatorFetcherError::*;
        match err {
            Database(e) => Self::Internal(e),
            ContractCall(msg) => {
                if msg.contains("Contract not found") {
                    Self::ContractNotFound
                } else {
                    Self::Custom(anyhow::anyhow!(msg))
                }
            }
            NoValidators { height } => Self::NoValidators { height },
            InvalidValidatorData(msg) => Self::InvalidValidatorData(msg),
            BlockNotFound => Self::BlockNotFound,
            UnsupportedNetwork(chain_id) => {
                Self::Custom(anyhow::anyhow!("Unsupported network: {}", chain_id))
            }
        }
    }
}

impl From<FetchValidatorsError> for ApplicationError {
    fn from(value: FetchValidatorsError) -> Self {
        match value {
            FetchValidatorsError::BlockNotFound => ApplicationError::BlockNotFound,
            FetchValidatorsError::ContractNotFound => ApplicationError::ContractNotFound,
            FetchValidatorsError::NoValidators { .. } => {
                ApplicationError::Custom(anyhow::anyhow!("No validators found"))
            }
            FetchValidatorsError::InvalidValidatorData(msg) => {
                ApplicationError::Custom(anyhow::anyhow!(msg))
            }
            FetchValidatorsError::Internal(e) => ApplicationError::Internal(e),
            FetchValidatorsError::Custom(e) => ApplicationError::Custom(e),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub height: u64,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                height: value.deserialize_serde("height")?,
            })
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    pub validators: Vec<ValidatorInfoResponse>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct ValidatorInfoResponse {
    pub address: String,
    pub public_key: String,
    pub voting_power: u64,
}

impl crate::dto::SerializeForVersion for ValidatorInfoResponse {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("address", &self.address)?;
        serializer.serialize_field("public_key", &self.public_key)?;
        serializer.serialize_field("voting_power", &self.voting_power)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &ValidatorInfoResponse {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        (*self).serialize(serializer)
    }
}

impl crate::dto::SerializeForVersion for Vec<ValidatorInfoResponse> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_iter(self.len(), &mut self.iter())
    }
}

impl From<Vec<validator_fetcher::ValidatorInfo>> for Output {
    fn from(validators: Vec<validator_fetcher::ValidatorInfo>) -> Self {
        let validators = validators
            .into_iter()
            .map(|validator| ValidatorInfoResponse {
                address: format!("0x{:064x}", validator.address.0),
                public_key: format!(
                    "0x{}",
                    validator
                        .public_key
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
                voting_power: validator.voting_power,
            })
            .collect();

        Self { validators }
    }
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("validators", &self.validators)?;
        serializer.end()
    }
}

/// Fetches validators from a Starknet contract at a specific height
pub async fn fetch_validators(
    context: RpcContext,
    input: Input,
    _rpc_version: RpcVersion,
) -> Result<Output, FetchValidatorsError> {
    let span = tracing::Span::current();
    let result = util::task::spawn_blocking(move |_| {
        let _g = span.enter();

        let mut db_conn = context
            .storage
            .connection()
            .context("Creating database connection")?;
        let db_tx = db_conn
            .transaction()
            .context("Creating database transaction")?;

        // Always use the latest block for validator fetching
        let block_id = pathfinder_common::BlockId::Latest;
        let header = db_tx
            .block_header(block_id)
            .context("Querying latest block header")?
            .ok_or(FetchValidatorsError::BlockNotFound)?;

        // Use the validator fetcher to get validators
        let validators = validator_fetcher::get_validators_at_height(
            &context.storage,
            context.chain_id,
            header,
            input.height,
        )?;

        Ok(Output::from(validators))
    })
    .await
    .context("Database read panic or shutting down")?;

    result
}
