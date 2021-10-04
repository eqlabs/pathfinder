//! Implementation of JSON-RPC endpoints.
use crate::{rpc::rpc_trait::RpcApiServer, sequencer::Client};
use jsonrpsee::types::async_trait;

pub struct RpcImpl;

#[doc = include_str!("doc/rpc_api.md")]
#[async_trait]
impl RpcApiServer for RpcImpl {
    #[doc = include_str!("doc/block_number.md")]
    async fn block_number(&self) -> String {
        "block_number OK".to_owned()
    }

    #[doc = include_str!("doc/get_block_by_hash.md")]
    async fn get_block_by_hash(&self, _block_hash: String) -> String {
        "get_block_by_hash OK".to_owned()
    }

    #[doc = include_str!("doc/get_block_by_number.md")]
    async fn get_block_by_number(&self, _block_number: String) -> String {
        "get_block_by_number OK".to_owned()
    }

    #[doc = include_str!("doc/get_transaction_by_hash.md")]
    async fn get_transaction_by_hash(&self, _transaction_hash: String) -> String {
        "get_transaction_by_hash OK".to_owned()
    }

    #[doc = include_str!("doc/get_transaction_by_block_hash_and_index.md")]
    async fn get_transaction_by_block_hash_and_index(
        &self,
        _block_hash: String,
        _transaction_index: String,
    ) -> String {
        "get_transaction_by_block_hash_and_index OK".to_owned()
    }

    #[doc = include_str!("doc/get_transaction_by_block_number_and_index.md")]
    async fn get_transaction_by_block_number_and_index(
        &self,
        _block_number: String,
        _transaction_index: String,
    ) -> String {
        "get_transaction_by_block_number_and_index OK".to_owned()
    }

    #[doc = include_str!("doc/get_storage.md")]
    async fn get_storage(&self, _contract_address: String, _key: String) -> String {
        "get_storage OK".to_owned()
    }

    #[doc = include_str!("doc/get_code.md")]
    async fn get_code(&self, _contract_address: String) -> String {
        "get_code OK".to_owned()
    }

    #[doc = include_str!("doc/call.md")]
    async fn call(
        &self,
        _contract_address: String,
        _call_data: Vec<String>,
        _entry_point: String,
    ) -> String {
        "call OK".to_owned()
    }
}
