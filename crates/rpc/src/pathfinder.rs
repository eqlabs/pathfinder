use jsonrpsee::core::server::rpc_module::Methods;

use crate::context::RpcContext;
use crate::error::RpcError;

mod methods;

/// Registers all methods for the pathfinder RPC API
pub fn register_methods(context: RpcContext) -> anyhow::Result<Methods> {
    let methods = crate::module::Module::new(context)
        .register_method_with_no_input("pathfinder_version", |_| async {
            Result::<_, RpcError>::Ok(pathfinder_common::consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT)
        })?
        .build();

    Ok(methods)
}
