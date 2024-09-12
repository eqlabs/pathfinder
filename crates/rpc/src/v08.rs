use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};
use crate::method::subscribe_new_heads::SubscribeNewHeads;

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V08)
        .register("starknet_subscribeNewHeads",                   SubscribeNewHeads)
        .register("starknet_specVersion",                         || "0.8.0")
}
