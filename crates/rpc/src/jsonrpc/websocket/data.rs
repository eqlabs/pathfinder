//! See [the parent module documentation](super)

use crate::jsonrpc::{RequestId, RpcError, RpcResponse};
use serde::ser::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(serde::Deserialize, Serialize)]
pub(super) struct Kind<'a> {
    #[serde(borrow)]
    pub(super) kind: Cow<'a, str>,
}

#[derive(Deserialize, Serialize)]
pub(super) struct SubscriptionId {
    pub(super) id: u32,
}

pub(super) struct SubscriptionItem<T> {
    pub(super) subscription_id: u32,
    pub(super) item: T,
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

pub(super) enum OwnedRequestId {
    Number(i64),
    String(String),
    Null,
    Notification,
}

impl From<RequestId<'_>> for OwnedRequestId {
    fn from(value: RequestId<'_>) -> Self {
        match value {
            RequestId::Number(x) => OwnedRequestId::Number(x),
            RequestId::String(x) => OwnedRequestId::String(x.into_owned()),
            RequestId::Null => OwnedRequestId::Null,
            RequestId::Notification => OwnedRequestId::Notification,
        }
    }
}

impl<'a> From<&'a OwnedRequestId> for RequestId<'a> {
    fn from(value: &'a OwnedRequestId) -> Self {
        match value {
            OwnedRequestId::Number(x) => RequestId::Number(*x),
            OwnedRequestId::String(x) => RequestId::String(x.into()),
            OwnedRequestId::Null => RequestId::Null,
            OwnedRequestId::Notification => RequestId::Notification,
        }
    }
}

pub(super) enum ResponseEvent {
    Subscribed {
        subscription_id: u32,
        request_id: OwnedRequestId,
    },
    Unsubscribed {
        success: bool,
        request_id: OwnedRequestId,
    },
    SubscriptionClosed {
        subscription_id: u32,
        reason: String,
    },
    InvalidRequest,
    InvalidMethod(OwnedRequestId),
    InvalidParams(OwnedRequestId),
    Header(SubscriptionItem<Arc<Value>>),
}

impl ResponseEvent {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            ResponseEvent::InvalidRequest => "InvalidRequest",
            ResponseEvent::InvalidMethod(_) => "InvalidMethod",
            ResponseEvent::Header(_) => "BlockHeader",
            ResponseEvent::Subscribed { .. } => "Subscribed",
            ResponseEvent::Unsubscribed { .. } => "Unsubscribed",
            ResponseEvent::SubscriptionClosed { .. } => "SubscriptionClosed",
            ResponseEvent::InvalidParams(_) => "InvalidParams",
        }
    }
}

impl Serialize for ResponseEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ResponseEvent::InvalidRequest => RpcResponse::INVALID_REQUEST.serialize(serializer),
            ResponseEvent::InvalidMethod(id) => {
                RpcResponse::method_not_found(id.into()).serialize(serializer)
            }
            ResponseEvent::InvalidParams(id) => {
                RpcResponse::invalid_params(id.into()).serialize(serializer)
            }
            ResponseEvent::Header(header) => header.serialize(serializer),
            ResponseEvent::Subscribed {
                subscription_id,
                request_id,
            } => successful_response(&subscription_id, request_id.into())
                .map_err(|_json_err| Error::custom("Payload serialization failed"))?
                .serialize(serializer),
            ResponseEvent::Unsubscribed {
                success,
                request_id,
            } => successful_response(&success, request_id.into())
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
        }
    }
}

pub(super) fn successful_response<'a, P>(
    payload: &P,
    request_id: RequestId<'a>,
) -> Result<RpcResponse<'a>, serde_json::Error>
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
            sequencer_address,
            starknet_version,
            class_commitment,
            event_commitment,
            state_commitment,
            storage_commitment,
            transaction_commitment,
            transaction_count,
            event_count,
        } = &self.0;

        let mut map = serializer.serialize_map(Some(15))?;

        map.serialize_entry("hash", &hash)?;
        map.serialize_entry("parent_hash", &parent_hash)?;
        map.serialize_entry("number", &number)?;
        map.serialize_entry("timestamp", &timestamp)?;
        map.serialize_entry("eth_l1_gas_price", &eth_l1_gas_price)?;
        map.serialize_entry("strk_l1_gas_price", &strk_l1_gas_price)?;
        map.serialize_entry("sequencer_address", &sequencer_address)?;
        map.serialize_entry("starknet_version", &starknet_version)?;
        map.serialize_entry("class_commitment", &class_commitment)?;
        map.serialize_entry("event_commitment", &event_commitment)?;
        map.serialize_entry("state_commitment", &state_commitment)?;
        map.serialize_entry("storage_commitment", &storage_commitment)?;
        map.serialize_entry("transaction_commitment", &transaction_commitment)?;
        map.serialize_entry("transaction_count", &transaction_count)?;
        map.serialize_entry("event_count", &event_count)?;

        map.end()
    }
}
