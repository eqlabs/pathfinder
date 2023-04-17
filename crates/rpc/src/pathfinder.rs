use crate::error::RpcError;
use crate::module::Module;

pub(crate) mod methods;

/// Registers all methods for the pathfinder RPC API
pub fn register_methods(module: Module) -> anyhow::Result<Module> {
    let module = module
        .register_method_with_no_input("v0.1_pathfinder_version", |_| async {
            Result::<_, RpcError>::Ok(pathfinder_common::consts::VERGEN_GIT_DESCRIBE)
        })?
        .register_method("v0.1_pathfinder_getProof", methods::get_proof)?
        .register_method(
            "v0.1_pathfinder_getTransactionStatus",
            methods::get_transaction_status,
        )?;

    Ok(module)
}
