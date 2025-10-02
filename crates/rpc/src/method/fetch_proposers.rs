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
    pub proposers: Vec<ProposerInfoResponse>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProposerInfoResponse {
    pub address: String,
    pub public_key: String,
    pub priority: u64,
}

impl crate::dto::SerializeForVersion for ProposerInfoResponse {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("address", &self.address)?;
        serializer.serialize_field("public_key", &self.public_key)?;
        serializer.serialize_field("priority", &self.priority)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &ProposerInfoResponse {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        (*self).serialize(serializer)
    }
}

impl crate::dto::SerializeForVersion for Vec<ProposerInfoResponse> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_iter(self.len(), &mut self.iter())
    }
}

impl From<Vec<consensus_fetcher::ProposerInfo>> for Output {
    fn from(proposers: Vec<consensus_fetcher::ProposerInfo>) -> Self {
        let proposers = proposers
            .into_iter()
            .map(|proposer| ProposerInfoResponse {
                address: format!("0x{:064x}", proposer.address.0),
                public_key: format!(
                    "0x{}",
                    proposer
                        .public_key
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
                priority: proposer.priority,
            })
            .collect();

        Self { proposers }
    }
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("proposers", &self.proposers)?;
        serializer.end()
    }
}

/// Fetches proposers from a Starknet contract at a specific height
pub async fn fetch_proposers(
    context: RpcContext,
    input: Input,
    _rpc_version: RpcVersion,
) -> Result<Output, ApplicationError> {
    let span = tracing::Span::current();
    let proposers = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        consensus_fetcher::get_proposers_at_height(&context.storage, context.chain_id, input.height)
    })
    .await
    .context("Database read panic or shutting down")?
    .map_err(ApplicationError::from)?;

    Ok(Output::from(proposers))
}
