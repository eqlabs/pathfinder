use std::collections::HashSet;
use std::future::Future;

use pathfinder_common::ContractAddress;
use tokio::sync::mpsc;

use crate::context::RpcContext;
use crate::jsonrpc::{RpcError, RpcSubscriptionFlow, SubscriptionMessage};
use crate::RpcVersion;

// JSON-RPC 0.9.0 has removed `starknet_subscribePendingTransactions`, and
// pre-0.9.0 APIs should not have access to pre-confirmed data. That
// is, if the update is from a pre-confirmed block, we should just
// ignore it. Note that this renders this method mostly useless,
// since after the Starknet 0.14.0 update no transactions will be
// sent over this subscription.
pub struct SubscribePendingTransactions;

#[derive(Debug, Clone, Default)]
pub struct Params {
    _transaction_details: Option<bool>,
    _sender_address: Option<HashSet<ContractAddress>>,
}

impl crate::dto::DeserializeForVersion for Option<Params> {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        if value.is_null() {
            return Ok(None);
        }
        value.deserialize_map(|value| {
            Ok(Some(Params {
                _transaction_details: value.deserialize_optional_serde("transaction_details")?,
                _sender_address: value
                    .deserialize_optional_array("sender_address", |addr| {
                        Ok(ContractAddress(addr.deserialize()?))
                    })?
                    .map(|addrs| addrs.into_iter().collect()),
            }))
        })
    }
}

#[derive(Debug)]
pub struct Notification;

impl crate::dto::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_unit()
    }
}

impl RpcSubscriptionFlow for SubscribePendingTransactions {
    type Params = Option<Params>;
    type Notification = Notification;

    fn subscribe(
        _state: RpcContext,
        _version: RpcVersion,
        _params: Self::Params,
        _tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) -> impl Future<Output = Result<(), RpcError>> {
        std::future::pending()
    }
}
