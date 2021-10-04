use super::rpc_trait::RpcFunctionsServer;
use jsonrpsee::types::async_trait;

pub struct RpcImpl;

#[async_trait]
impl RpcFunctionsServer for RpcImpl {
    /// Returns the number of the most recent accepted-on-chain or the most recent pending block,
    /// depending on the `accepted_on_chain` flag value.
    async fn block_number(&self, _accepted_on_chain: bool) -> String {
        "block_number OK".to_owned()
    }
    /// Returns information about a block by hash.
    async fn get_block_by_hash(&self, _block_hash: String) -> String {
        "get_block_by_hash OK".to_owned()
    }
    /// Returns information about a block by number.
    async fn get_block_by_number(&self, _block_number: String) -> String {
        "get_block_by_number OK".to_owned()
    }
    /// Returns the information about a transaction requested by transaction hash.
    async fn get_transaction_by_hash(&self, _transaction_hash: String) -> String {
        "get_transaction_by_hash OK".to_owned()
    }
    /// Returns information about a transaction by block hash and transaction index position.
    async fn get_transaction_by_block_hash_and_index(
        &self,
        _block_hash: String,
        _transaction_index: String,
    ) -> String {
        "get_transaction_by_block_hash_and_index OK".to_owned()
    }
    /// Returns information about a transaction by block number and transaction index position.
    async fn get_transaction_by_block_number_and_index(
        &self,
        _block_number: String,
        _transaction_index: String,
    ) -> String {
        "get_transaction_by_block_number_and_index OK".to_owned()
    }
    /// Returns the value from a storage position at a given address.
    async fn get_storage(&self, _contract_address: String, _key: String) -> String {
        "get_storage OK".to_owned()
    }
    /// Returns code at a given address.
    async fn get_code(&self, _contract_address: String) -> String {
        "get_code OK".to_owned()
    }
    /// Executes a new call immediately without creating a transaction on the block chain.
    async fn call(
        &self,
        _contract_address: String,
        _call_data: Vec<String>,
        _entry_point: String,
    ) -> String {
        "call OK".to_owned()
    }
}
