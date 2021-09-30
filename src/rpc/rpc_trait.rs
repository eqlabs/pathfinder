use jsonrpsee::proc_macros::rpc;

#[rpc(server, namespace = "starknet")]
pub trait RpcFunctions {
    #[method(name = "getBlock")]
    async fn get_block(&self, id: Option<String>) -> String;
}
