//! This RPC API should **always** be considered unstable and for internal use
//! only. Its main purpose is to aid integration testing so expect it to change
//! anytime!

use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};
use crate::method::consensus_info;
use crate::method::fetch_validators;

pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::PathfinderV01)
        .register("pathfinder_consensusInfo", consensus_info::consensus_info)
        .register("pathfinder_fetchValidators", fetch_validators::fetch_validators)
}
