use anyhow::Context;
use pathfinder_consensus_fetcher as consensus_fetcher;

use crate::context::RpcContext;
use crate::error::ApplicationError;
use crate::RpcVersion;

#[derive(Debug)]
pub enum FetchProposersError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    ContractNotFound,
    NoProposers { height: u64 },
    InvalidProposerData(String),
}

impl From<anyhow::Error> for FetchProposersError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<consensus_fetcher::ConsensusFetcherError> for FetchProposersError {
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
            NoProposers { height } => Self::NoProposers { height },
            InvalidProposerData(msg) => Self::InvalidProposerData(msg),
            BlockNotFound => Self::BlockNotFound,
            UnsupportedNetwork(chain_id) => {
                Self::Custom(anyhow::anyhow!("Unsupported network: {}", chain_id))
            }
            _ => unreachable!(),
        }
    }
}

impl From<FetchProposersError> for ApplicationError {
    fn from(value: FetchProposersError) -> Self {
        match value {
            FetchProposersError::BlockNotFound => ApplicationError::BlockNotFound,
            FetchProposersError::ContractNotFound => ApplicationError::ContractNotFound,
            FetchProposersError::NoProposers { .. } => {
                ApplicationError::Custom(anyhow::anyhow!("No proposers found"))
            }
            FetchProposersError::InvalidProposerData(msg) => {
                ApplicationError::Custom(anyhow::anyhow!(msg))
            }
            FetchProposersError::Internal(e) => ApplicationError::Internal(e),
            FetchProposersError::Custom(e) => ApplicationError::Custom(e),
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
) -> Result<Output, FetchProposersError> {
    let span = tracing::Span::current();
    let result = util::task::spawn_blocking(move |_| {
        let _g = span.enter();

        // Always use the latest block for proposer fetching
        // Use the validator fetcher to get proposers
        let proposers = consensus_fetcher::get_proposers_at_height(
            &context.storage,
            context.chain_id,
            input.height,
        )?;

        Ok(Output::from(proposers))
    })
    .await
    .context("Database read panic or shutting down")?;

    result
}
