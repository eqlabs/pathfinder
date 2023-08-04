use crate::error::RpcError;
use crate::jsonrpc::RpcResult;
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

pub struct RpcHandlerPathfinder;

#[axum::async_trait]
impl crate::jsonrpc::RpcMethodHandler for RpcHandlerPathfinder {
    async fn call_method(
        method: &str,
        ctx: crate::context::RpcContext,
        params: serde_json::Value,
    ) -> RpcResult {
        use crate::jsonrpc::RpcMethod;

        #[rustfmt::skip]
        let output = match method {
            "pathfinder_version"              => (|| { pathfinder_common::consts::VERGEN_GIT_DESCRIBE }).invoke("pathfinder_version", "v0.1", ctx, params).await,
            "pathfinder_getProof"             => methods::get_proof.invoke("pathfinder_getProof", "v0.1", ctx, params).await,
            "pathfinder_getTransactionStatus" => methods::get_transaction_status.invoke("pathfinder_getTransactionStatus", "v0.1", ctx, params).await,
            unknown => Err(crate::jsonrpc::RpcError::MethodNotFound {
                method: unknown.to_owned(),
            }),
        };

        output
    }
}
