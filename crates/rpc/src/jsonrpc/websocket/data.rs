//! See [the parent module documentation](super)

use std::sync::Arc;

use pathfinder_common::{
    BlockHash,
    BlockNumber,
    ContractAddress,
    EventData,
    EventKey,
    TransactionHash,
};
use serde::ser::Error;
use serde::Deserialize;
use serde_json::Value;

use crate::dto::serialize;
use crate::jsonrpc::router::RpcResponses;
use crate::jsonrpc::{RequestId, RpcError, RpcResponse};

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(tag = "kind")]
pub(super) enum Params {
    #[serde(rename = "newHeads")]
    NewHeads,
    #[serde(rename = "events")]
    Events(EventFilterParams),
    #[serde(rename = "transactionStatus")]
    TransactionStatus(TransactionStatusParams),
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub(super) struct EventFilterParams {
    #[serde(default)]
    pub(super) address: Option<pathfinder_common::ContractAddress>,
    #[serde(default)]
    pub(super) keys: Vec<Vec<EventKey>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct TransactionStatusParams {
    pub(super) transaction_hash: TransactionHash,
}

#[derive(Deserialize, serde::Serialize)]
pub(super) struct SubscriptionId {
    pub(super) id: u32,
}

#[derive(Debug)]
pub(super) struct SubscriptionItem<T> {
    pub(super) subscription_id: u32,
    pub(super) item: T,
}

impl<T: serde::Serialize> serde::Serialize for SubscriptionItem<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct ResultHelper<'a, U: serde::Serialize> {
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

#[derive(Debug)]
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
    TransactionStatus(SubscriptionItem<Arc<TransactionStatusUpdate>>),
    RpcError(RpcError),
}

/// Describes an emitted event returned by starknet_getEvents
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct EmittedEvent {
    pub data: Vec<EventData>,
    pub keys: Vec<EventKey>,
    pub from_address: ContractAddress,
    /// [`None`] for pending events.
    pub block_hash: Option<BlockHash>,
    /// [`None`] for pending events.
    pub block_number: Option<BlockNumber>,
    pub transaction_hash: TransactionHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionStatusUpdate {
    Received = 0,
    Rejected = 1,
    Succeeded = 2,
    Reverted = 3,
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

impl serialize::SerializeForVersion for ResponseEvent {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            ResponseEvent::InvalidRequest(e) => {
                RpcResponse::invalid_request(e.clone(), serializer.version).serialize(serializer)
            }
            ResponseEvent::InvalidParams(request_id, e) => {
                RpcResponse::invalid_params(request_id.clone(), e.clone(), serializer.version)
                    .serialize(serializer)
            }
            ResponseEvent::InternalError(request_id, e) => {
                RpcResponse::internal_error(request_id.clone(), e.to_string(), serializer.version)
                    .serialize(serializer)
            }
            ResponseEvent::Header(header) => header.serialize(serializer),
            ResponseEvent::Event(event) => event.serialize(serializer),
            ResponseEvent::Subscribed {
                subscription_id,
                request_id,
            } => successful_response(&subscription_id, request_id.clone(), serializer.version)
                .map_err(|_json_err| Error::custom("Payload serialization failed"))?
                .serialize(serializer),
            ResponseEvent::Unsubscribed {
                success,
                request_id,
            } => successful_response(&success, request_id.clone(), serializer.version)
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
                version: serializer.version,
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
    version: crate::RpcVersion,
) -> Result<RpcResponse, serde_json::Error>
where
    P: serde::Serialize,
{
    let payload = serde_json::to_value(payload)?;
    Ok(RpcResponse {
        output: Ok(payload),
        id: request_id,
        version,
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
            eth_l2_gas_price,
            strk_l2_gas_price,
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
            receipt_commitment,
            state_diff_commitment: _,
            state_diff_length: _,
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
        map.serialize_entry("eth_l2_gas_price", &eth_l2_gas_price)?;
        map.serialize_entry("strk_l2_gas_price", &strk_l2_gas_price)?;
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
        map.serialize_entry("receipt_commitment", &receipt_commitment)?;

        map.end()
    }
}
