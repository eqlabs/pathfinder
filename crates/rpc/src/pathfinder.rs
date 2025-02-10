use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

pub(crate) mod methods;

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::PathfinderV01)
        .register("pathfinder_version",              || { pathfinder_version::VERSION })
        .register("pathfinder_getProof",             methods::get_proof)
        .register("pathfinder_getClassProof",        methods::get_class_proof)
        .register("pathfinder_getTransactionStatus", methods::get_transaction_status)
}
