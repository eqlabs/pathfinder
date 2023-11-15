//! See [the parent module documentation](super)

use crate::jsonrpc::{RequestId, RpcError, RpcResponse};
use pathfinder_common::BlockHash;
use pathfinder_common::BlockNumber;
use pathfinder_common::BlockTimestamp;
use pathfinder_common::GasPrice;
use pathfinder_common::SequencerAddress;
use pathfinder_common::StarknetVersion;
use pathfinder_common::StateCommitment;
use serde::ser::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;

use pathfinder_serde::GasPriceAsHexStr;
use starknet_gateway_types::reply::{Block, Status};

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
#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeader {
    pub block_hash: BlockHash,
    pub block_number: BlockNumber,

    #[serde_as(as = "Option<GasPriceAsHexStr>")]
    #[serde(default)]
    pub gas_price: Option<GasPrice>,
    pub parent_block_hash: BlockHash,

    #[serde(default)]
    pub sequencer_address: Option<SequencerAddress>,

    #[serde(alias = "state_root")]
    pub state_commitment: StateCommitment,
    pub status: Status,
    pub timestamp: BlockTimestamp,

    #[serde(default)]
    pub starknet_version: StarknetVersion,
}

impl From<&Block> for BlockHeader {
    fn from(b: &Block) -> Self {
        Self {
            block_hash: b.block_hash,
            block_number: b.block_number,
            gas_price: b.eth_l1_gas_price,
            parent_block_hash: b.parent_block_hash,
            sequencer_address: b.sequencer_address,
            state_commitment: b.state_commitment,
            status: b.status,
            timestamp: b.timestamp,
            starknet_version: b.starknet_version.clone(),
        }
    }
}
