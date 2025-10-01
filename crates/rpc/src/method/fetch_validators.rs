use anyhow::Context;
use pathfinder_consensus_fetcher as consensus_fetcher;

use crate::context::RpcContext;
use crate::error::ApplicationError;
use crate::RpcVersion;

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
) -> Result<Output, ApplicationError> {
    let span = tracing::Span::current();
    let validators = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        consensus_fetcher::get_validators_at_height(
            &context.storage,
            context.chain_id,
            input.height,
        )
    })
    .await
    .context("Database read panic or shutting down")?
    .map_err(ApplicationError::from)?;

    Ok(Output::from(validators))
}
