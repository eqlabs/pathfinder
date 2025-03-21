//! See [the parent module documentation](super)

use std::sync::Arc;

use pathfinder_common::prelude::*;
use serde::ser::Error;
use serde::Deserialize;
use serde_json::Value;

use crate::dto::SerializeForVersion;
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

impl<T: SerializeForVersion> SerializeForVersion for SubscriptionItem<T> {
    fn serialize(
        &self,
        base_serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = base_serializer.serialize_struct()?;

        serializer.serialize_field("jsonrpc", &"2.0")?;
        serializer.serialize_field("method", &"pathfinder_subscription")?;
        serializer.serialize_field(
            "result",
            &ResultHelper {
                subscription: self.subscription_id,
                result: &self.item,
            },
        )?;

        serializer.end()
    }
}

struct ResultHelper<'a, U: SerializeForVersion> {
    subscription: u32,
    result: &'a U,
}

impl<T: SerializeForVersion> SerializeForVersion for ResultHelper<'_, T> {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("subscription", &self.subscription)?;
        s.serialize_field("result", self.result)?;
        s.end()
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl SerializeForVersion for EmittedEvent {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut obj = serializer.serialize_struct()?;
        obj.serialize_iter("data", self.data.len(), &mut self.data.iter())?;
        obj.serialize_iter("keys", self.keys.len(), &mut self.keys.iter())?;
        obj.serialize_field("from_address", &self.from_address)?;
        obj.serialize_optional("block_hash", self.block_hash)?;
        obj.serialize_optional("block_number", self.block_number)?;
        obj.serialize_field("transaction_hash", &self.transaction_hash)?;
        obj.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransactionStatusUpdate {
    Received = 0,
    Rejected = 1,
    Succeeded = 2,
    Reverted = 3,
}

impl crate::dto::SerializeForVersion for TransactionStatusUpdate {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            TransactionStatusUpdate::Received => "RECEIVED",
            TransactionStatusUpdate::Rejected => "REJECTED",
            TransactionStatusUpdate::Succeeded => "SUCCEEDED",
            TransactionStatusUpdate::Reverted => "REVERTED",
        }
        .serialize(serializer)
    }
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

impl crate::dto::SerializeForVersion for ResponseEvent {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
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
            ResponseEvent::Header(header) => {
                let si = SubscriptionItem {
                    subscription_id: header.subscription_id,
                    item: (*header.item).clone(),
                };
                si.serialize(serializer)
            }
            ResponseEvent::Event(event) => {
                let si = SubscriptionItem {
                    subscription_id: event.subscription_id,
                    item: (*event.item).clone(),
                };
                si.serialize(serializer)
            }
            ResponseEvent::Subscribed {
                subscription_id,
                request_id,
            } => successful_response(subscription_id, request_id.clone(), serializer.version)
                .map_err(|_json_err| Error::custom("Payload serialization failed"))?
                .serialize(serializer),
            ResponseEvent::Unsubscribed {
                success,
                request_id,
            } => successful_response(success, request_id.clone(), serializer.version)
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
            ResponseEvent::TransactionStatus(status) => {
                let si = SubscriptionItem {
                    subscription_id: status.subscription_id,
                    item: *status.item,
                };
                si.serialize(serializer)
            }
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
    P: SerializeForVersion,
{
    let payload = payload.serialize(crate::dto::Serializer::new(version))?;
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
            event_commitment,
            state_commitment,
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
        map.serialize_entry("event_commitment", &event_commitment)?;
        map.serialize_entry("state_commitment", &state_commitment)?;
        map.serialize_entry("transaction_commitment", &transaction_commitment)?;
        map.serialize_entry("transaction_count", &transaction_count)?;
        map.serialize_entry("event_count", &event_count)?;
        map.serialize_entry("l1_da_mode", &l1_da_mode)?;
        map.serialize_entry("receipt_commitment", &receipt_commitment)?;

        map.end()
    }
}

impl SerializeForVersion for BlockHeader {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut obj = serializer.serialize_struct()?;

        let header = &self.0;
        obj.serialize_field("hash", &header.hash)?;
        obj.serialize_field("parent_hash", &header.parent_hash)?;
        obj.serialize_field("number", &header.number)?;
        obj.serialize_field("timestamp", &header.timestamp)?;
        obj.serialize_field("eth_l1_gas_price", &header.eth_l1_gas_price)?;
        obj.serialize_field("strk_l1_gas_price", &header.strk_l1_gas_price)?;
        obj.serialize_field("eth_l1_data_gas_price", &header.eth_l1_data_gas_price)?;
        obj.serialize_field("strk_l1_data_gas_price", &header.strk_l1_data_gas_price)?;
        obj.serialize_field("eth_l2_gas_price", &header.eth_l2_gas_price)?;
        obj.serialize_field("strk_l2_gas_price", &header.strk_l2_gas_price)?;
        obj.serialize_field("sequencer_address", &header.sequencer_address)?;
        obj.serialize_field("starknet_version", &header.starknet_version.to_string())?;
        obj.serialize_field("event_commitment", &header.event_commitment)?;
        obj.serialize_field("state_commitment", &header.state_commitment)?;
        obj.serialize_field("transaction_commitment", &header.transaction_commitment)?;
        obj.serialize_field("transaction_count", &header.transaction_count)?;
        obj.serialize_field("event_count", &header.event_count)?;
        obj.serialize_field("l1_da_mode", &header.l1_da_mode)?;
        obj.serialize_field("receipt_commitment", &header.receipt_commitment)?;

        obj.end()
    }
}
