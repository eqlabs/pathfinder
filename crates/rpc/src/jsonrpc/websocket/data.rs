//! See [the parent module documentation](super)

use std::borrow::Cow;
use std::sync::Arc;

use pathfinder_common::{EventKey, TransactionHash};
use serde::ser::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;
use starknet_gateway_types::reply::transaction_status::{ExecutionStatus, FinalityStatus};

use crate::jsonrpc::router::RpcResponses;
use crate::jsonrpc::{RequestId, RpcError, RpcResponse};
use crate::method::get_events::types::EmittedEvent;

#[derive(serde::Deserialize, Serialize)]
pub(super) struct Kind<'a> {
    #[serde(borrow)]
    pub(super) kind: Cow<'a, str>,
}

#[derive(Debug, serde::Deserialize, Serialize)]
pub(super) struct EventFilterParams {
    pub(super) kind: String,
    #[serde(default)]
    pub(super) address: Option<pathfinder_common::ContractAddress>,
    #[serde(default)]
    pub(super) keys: Vec<Vec<EventKey>>,
}

#[derive(Debug, serde::Deserialize, Serialize)]
pub(super) struct TransactionStatusParams {
    pub(super) kind: String,
    pub(super) transaction_hash: TransactionHash,
}

#[derive(Deserialize, Serialize)]
pub(super) struct SubscriptionId {
    pub(super) id: u32,
}

pub(super) struct SubscriptionItem<T> {
    pub(super) subscription_id: u32,
    pub(super) item: T,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct TransactionStatus {
    pub(super) finality_status: TransactionFinalityStatus,
    pub(super) execution_status: TransactionExecutionStatus,
}

impl From<starknet_gateway_types::reply::TransactionStatus> for TransactionStatus {
    fn from(value: starknet_gateway_types::reply::TransactionStatus) -> Self {
        Self {
            finality_status: match value.finality_status {
                FinalityStatus::NotReceived => TransactionFinalityStatus::NotReceived,
                FinalityStatus::Received => TransactionFinalityStatus::Received,
                FinalityStatus::AcceptedOnL1 => TransactionFinalityStatus::AcceptedOnL1,
                FinalityStatus::AcceptedOnL2 => TransactionFinalityStatus::AcceptedOnL2,
            },
            execution_status: match value.execution_status {
                ExecutionStatus::Succeeded => TransactionExecutionStatus::Succeeded,
                ExecutionStatus::Reverted => TransactionExecutionStatus::Reverted,
                ExecutionStatus::Rejected => TransactionExecutionStatus::Rejected,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionFinalityStatus {
    #[serde(rename = "NOT_RECEIVED")]
    NotReceived,
    #[serde(rename = "RECEIVED")]
    Received,
    #[serde(rename = "ACCEPTED_ON_L1")]
    AcceptedOnL1,
    #[serde(rename = "ACCEPTED_ON_L2")]
    AcceptedOnL2,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionExecutionStatus {
    #[default]
    Succeeded,
    Reverted,
    Rejected,
}

impl<T: Serialize> Serialize for SubscriptionItem<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct ResultHelper<'a, U: Serialize> {
            subscription: u32,
            result: &'a U,
        }

        use serde::ser::SerializeMap;
        let mut obj = serializer.serialize_map(Some(3))?;
        obj.serialize_entry("jsonrpc", "2.0")?;
        obj.serialize_entry("method", "pathfinder_subscription")?;
        obj.serialize_entry(
            "result",
            &ResultHelper {
                subscription: self.subscription_id,
                result: &self.item,
            },
        )?;
        obj.end()
    }
}

pub(super) enum ResponseEvent {
    Subscribed {
        subscription_id: u32,
        request_id: RequestId,
    },
    Unsubscribed {
        success: bool,
        request_id: RequestId,
    },
    SubscriptionClosed {
        subscription_id: u32,
        reason: String,
    },
    InvalidRequest(String),
    InvalidParams(RequestId, String),
    InternalError(RequestId, anyhow::Error),
    Header(SubscriptionItem<Arc<Value>>),
    Responses(RpcResponses),
    Event(SubscriptionItem<Arc<EmittedEvent>>),
    TransactionStatus(SubscriptionItem<Arc<TransactionStatus>>),
    RpcError(RpcError),
}

impl ResponseEvent {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            ResponseEvent::InvalidRequest(_) => "InvalidRequest",
            ResponseEvent::Header(_) => "BlockHeader",
            ResponseEvent::Subscribed { .. } => "Subscribed",
            ResponseEvent::Unsubscribed { .. } => "Unsubscribed",
            ResponseEvent::SubscriptionClosed { .. } => "SubscriptionClosed",
            ResponseEvent::InvalidParams(..) => "InvalidParams",
            ResponseEvent::Responses(_) => "Responses",
            ResponseEvent::Event(_) => "Event",
            ResponseEvent::TransactionStatus(_) => "TransactionStatus",
            ResponseEvent::InternalError(_, _) => "InternalError",
            ResponseEvent::RpcError(_) => "RpcError",
        }
    }
}

impl Serialize for ResponseEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ResponseEvent::InvalidRequest(e) => {
                RpcResponse::invalid_request(e.clone()).serialize(serializer)
            }
            ResponseEvent::InvalidParams(request_id, e) => {
                RpcResponse::invalid_params(request_id.clone(), e.clone()).serialize(serializer)
            }
            ResponseEvent::InternalError(request_id, e) => {
                RpcResponse::internal_error(request_id.clone(), e.to_string()).serialize(serializer)
            }
            ResponseEvent::Header(header) => header.serialize(serializer),
            ResponseEvent::Event(event) => event.serialize(serializer),
            ResponseEvent::Subscribed {
                subscription_id,
                request_id,
            } => successful_response(&subscription_id, request_id.clone())
                .map_err(|_json_err| Error::custom("Payload serialization failed"))?
                .serialize(serializer),
            ResponseEvent::Unsubscribed {
                success,
                request_id,
            } => successful_response(&success, request_id.clone())
                .map_err(|_json_err| Error::custom("Payload serialization failed"))?
                .serialize(serializer),
            ResponseEvent::SubscriptionClosed {
                subscription_id,
                reason,
            } => RpcResponse {
                output: Err(RpcError::WebsocketSubscriptionClosed {
                    subscription_id: *subscription_id,
                    reason: reason.to_owned(),
                }),
                id: RequestId::Null,
            }
            .serialize(serializer),
            ResponseEvent::Responses(responses) => responses.serialize(serializer),
            ResponseEvent::TransactionStatus(status) => status.serialize(serializer),
            ResponseEvent::RpcError(error) => error.serialize(serializer),
        }
    }
}

pub(super) fn successful_response<P>(
    payload: &P,
    request_id: RequestId,
) -> Result<RpcResponse, serde_json::Error>
where
    P: Serialize,
{
    let payload = serde_json::to_value(payload)?;
    Ok(RpcResponse {
        output: Ok(payload),
        id: request_id,
    })
}

#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader(pub pathfinder_common::BlockHeader);

impl From<pathfinder_common::BlockHeader> for BlockHeader {
    fn from(value: pathfinder_common::BlockHeader) -> Self {
        Self(value)
    }
}

impl serde::Serialize for BlockHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let pathfinder_common::BlockHeader {
            hash,
            parent_hash,
            number,
            timestamp,
            eth_l1_gas_price,
            strk_l1_gas_price,
            eth_l1_data_gas_price,
            strk_l1_data_gas_price,
            sequencer_address,
            starknet_version,
            class_commitment,
            event_commitment,
            state_commitment,
            storage_commitment,
            transaction_commitment,
            transaction_count,
            event_count,
            l1_da_mode,
        } = &self.0;

        let mut map = serializer.serialize_map(Some(15))?;

        map.serialize_entry("hash", &hash)?;
        map.serialize_entry("parent_hash", &parent_hash)?;
        map.serialize_entry("number", &number)?;
        map.serialize_entry("timestamp", &timestamp)?;
        map.serialize_entry("eth_l1_gas_price", &eth_l1_gas_price)?;
        map.serialize_entry("strk_l1_gas_price", &strk_l1_gas_price)?;
        map.serialize_entry("eth_l1_data_gas_price", &eth_l1_data_gas_price)?;
        map.serialize_entry("strk_l1_data_gas_price", &strk_l1_data_gas_price)?;
        map.serialize_entry("sequencer_address", &sequencer_address)?;
        map.serialize_entry("starknet_version", &starknet_version.to_string())?;
        map.serialize_entry("class_commitment", &class_commitment)?;
        map.serialize_entry("event_commitment", &event_commitment)?;
        map.serialize_entry("state_commitment", &state_commitment)?;
        map.serialize_entry("storage_commitment", &storage_commitment)?;
        map.serialize_entry("transaction_commitment", &transaction_commitment)?;
        map.serialize_entry("transaction_count", &transaction_count)?;
        map.serialize_entry("event_count", &event_count)?;
        map.serialize_entry("l1_da_mode", &l1_da_mode)?;

        map.end()
    }
}
