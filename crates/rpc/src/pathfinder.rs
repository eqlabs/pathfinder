use crate::jsonrpc::RpcRouter;

pub(crate) mod methods;

#[rustfmt::skip]
pub fn rpc_router() -> RpcRouter {
    RpcRouter::builder("v0.1")
        .register("pathfinder_version",              || { pathfinder_common::consts::VERGEN_GIT_DESCRIBE })
        .register("pathfinder_getProof",             methods::get_proof)
        .register("pathfinder_getTransactionStatus", methods::get_transaction_status)
        .build()
}
