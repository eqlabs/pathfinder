use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};
use crate::method::subscribe_new_heads::SubscribeNewHeads;
use crate::method::subscribe_pending_transactions::SubscribePendingTransactions;

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V08)
        // TODO This is for testing - figure out if this should be removed or included when
        // implementing RPC spec 0.8.
        .register("starknet_syncing",                      crate::method::syncing)
        .register("starknet_subscribeNewHeads",            SubscribeNewHeads)
        .register("starknet_subscribePendingTransactions", SubscribePendingTransactions)
        .register("starknet_specVersion",                  || "0.8.0-rc0")
}
