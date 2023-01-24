use jsonrpsee::core::server::rpc_module::Methods;

use crate::context::RpcContext;

pub mod method;

use crate::v02::method as v02_method;

/// Registers all methods for the v0.3 RPC API
pub fn register_methods(context: RpcContext) -> anyhow::Result<Methods> {
    let methods = crate::module::Module::new(context)
        .register_method_with_no_input("starknet_syncing", v02_method::syncing)?
        .build();

    Ok(methods)
}
