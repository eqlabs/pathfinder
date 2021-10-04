use jsonrpsee::proc_macros::rpc;

/// Describes the RPC API methods.
/// The methods are trying to follow the `eth1.0-apis` covention. For comparison:
/// - [eth1.0 API spec repo](https://github.com/ethereum/execution-apis)
/// - [eth1.0 API spec viewer on openrpc playground](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/eth1.0-apis/assembled-spec/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=true&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false)
#[rpc(server, namespace = "starknet")]
pub trait RpcFunctions {
    /// Returns the number of the most recent accepted-on-chain or the most recent pending block,
    /// depending on the `accepted_on_chain` flag value.
    ///
    /// __Pending__ means that the block passed the validation and is waiting to be sent on-chain.
    ///
    /// This call is the equivalent of `eth_blockNumber` in `eth1.0-apis`.
    #[method(name = "blockNumber")]
    async fn block_number(&self, accepted_on_chain: bool) -> String;
    /// Returns information about a block by hash.
    ///
    /// This call is the equivalent of `eth_getBlockByHash` in `eth1.0-apis`.
    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(&self, block_hash: String) -> String;
    /// Returns information about a block by number.
    ///
    /// This call is the equivalent of `eth_getBlockByNumber` in `eth1.0-apis`.
    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(&self, block_number: String) -> String;
    /// Returns the information about a transaction requested by transaction hash.
    ///
    /// This call is the equivalent of `eth_getTransactionByHash` in `eth1.0-apis`.
    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(&self, transaction_hash: String) -> String;
    /// Returns information about a transaction by block hash and transaction index position.
    ///
    /// This call is the equivalent of `eth_getTransactionByBlockHashAndIndex` in `eth1.0-apis`.
    #[method(name = "getTransactionByBlockHashAndIndex")]
    async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: String,
        transaction_index: String,
    ) -> String;
    /// Returns information about a transaction by block number and transaction index position.
    ///
    /// This call is the equivalent of `eth_getTransactionByBlockNumberAndIndex` in `eth1.0-apis`.
    #[method(name = "getTransactionByBlockNumberAndIndex")]
    async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: String,
        transaction_index: String,
    ) -> String;
    /// Returns the value from a storage position at a given address.
    ///
    /// This call is the equivalent of `eth_getStorage` in `eth1.0-apis`.
    #[method(name = "getStorage")]
    async fn get_storage(&self, contract_address: String, key: String) -> String;
    /// Returns code at a given address.
    ///
    /// This call is the equivalent of `eth_getCode` in `eth1.0-apis`.
    #[method(name = "getCode")]
    async fn get_code(&self, contract_address: String) -> String;
    /// Executes a new call immediately without creating a transaction on the block chain.
    ///
    /// This call is the equivalent of `eth_call` in `eth1.0-apis`.
    #[method(name = "call")]
    async fn call(
        &self,
        contract_address: String,
        call_data: Vec<String>,
        entry_point: String,
    ) -> String;
}
