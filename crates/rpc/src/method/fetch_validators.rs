use anyhow::Context;
use pathfinder_consensus_fetcher as consensus_fetcher;

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

impl From<consensus_fetcher::ConsensusFetcherError> for FetchValidatorsError {
    fn from(err: consensus_fetcher::ConsensusFetcherError) -> Self {
        use consensus_fetcher::ConsensusFetcherError::*;
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
            _ => unreachable!(),
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

impl From<Vec<consensus_fetcher::ValidatorInfo>> for Output {
    fn from(validators: Vec<consensus_fetcher::ValidatorInfo>) -> Self {
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

        // Always use the latest block for validator fetching
        // Use the validator fetcher to get validators
        let validators = consensus_fetcher::get_validators_at_height(
            &context.storage,
            context.chain_id,
            input.height,
        )?;

        Ok(Output::from(validators))
    })
    .await
    .context("Database read panic or shutting down")?;

    result
}
