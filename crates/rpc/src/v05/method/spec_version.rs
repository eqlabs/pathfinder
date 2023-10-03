use crate::context::RpcContext;

crate::error::generate_rpc_error_subset!(SpecVersionError);

pub async fn spec_version(_context: RpcContext) -> Result<String, SpecVersionError> {
    Ok("0.5.0".to_owned())
}
