use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};
use crate::method;

pub mod unstable;

pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::PathfinderV01)
        .register("pathfinder_version", || pathfinder_version::VERSION)
        .register(
            "pathfinder_lastL1AcceptedBlockHashAndNumber",
            method::last_l1_accepted_block_hash_and_number,
        )
}
