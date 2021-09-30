use super::rpc_trait::RpcFunctionsServer;
use jsonrpsee::types::async_trait;

pub struct RpcImpl;

#[async_trait]
impl RpcFunctionsServer for RpcImpl {
    async fn get_block(&self, id: Option<String>) -> String {
        format!("Hello block id {}", id.unwrap_or_default())
    }
}
