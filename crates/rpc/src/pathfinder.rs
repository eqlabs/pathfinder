use jsonrpsee::core::server::rpc_module::Methods;

use crate::context::RpcContext;
use crate::error::RpcError;

pub(crate) mod methods;

/// Registers all methods for the pathfinder RPC API
pub fn register_methods(context: RpcContext) -> anyhow::Result<Methods> {
    let methods = crate::module::Module::new(context)
        .register_method_with_no_input("pathfinder_version", |_| async {
            Result::<_, RpcError>::Ok(pathfinder_common::consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT)
        })?
        .register_method("pathfinder_getProof", methods::get_proof::get_proof)?
        .build();

    Ok(methods)
}
