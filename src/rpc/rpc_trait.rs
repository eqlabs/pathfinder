//! Definition of JSON-RPC endpoints.
//!
//! The trait [RpcApiServer] describes the RPC API methods served by the node.
//! The methods are trying to follow the eth1.0 API covention. For comparison:
//! - [eth1.0 API spec repo](https://github.com/ethereum/execution-apis)
//! - [eth1.0 API spec viewer on openrpc playground](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/eth1.0-apis/assembled-spec/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=true&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false)
//!
//! __TODO__ At the moment the `latest` special tag value means the most recent pending,
//! while later on we should make a distinction between most recent accepted on chain and most recent pending.
use crate::rpc::rpc_types::reply;
use jsonrpsee::{proc_macros::rpc, types::error::Error};
use web3::types::{H256, U256};
#[rpc(server, namespace = "starknet")]
pub trait RpcApi {
    /// Returns the number of the most recent block.
    ///
    /// This call is the equivalent of `eth_blockNumber` in eth1.0 API.
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> Result<U256, Error>;

    /// Returns information about a block by hash. `block_hash` should either be
    /// a 32 byte value encoded as 0x-prefixed hex string or one of special tag values
    /// - `latest`, which means the most recent block,
    /// - `earliest`, which means the genesis block.
    ///
    /// This call is the equivalent of `eth_getBlockByHash` in eth1.0 API.
    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(&self, block_hash: String) -> Result<reply::Block, Error>;

    /// Returns information about a block by number. `block_number` should either be
    /// a 0x-prefixed hex-encoded unsigned integer or one of special tag values
    /// - `latest`, which means the most recent block,
    /// - `earliest`, which means the genesis block.
    ///
    /// This call is the equivalent of `eth_getBlockByHash` in eth1.0 API.
    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(&self, block_number: String) -> Result<reply::Block, Error>;

    /// Returns the information about a transaction requested by transaction hash.
    /// `transaction_hash` should be a 32 byte value encoded as 0x-prefixed hex string.
    ///
    /// This call is the equivalent of `eth_getTransactionByHash` in eth1.0 API.
    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(
        &self,
        transaction_hash: String,
    ) -> Result<reply::Transaction, Error>;

    /// Returns the information about a transaction requested by transaction number.
    /// `transaction_number` should be a 0x-prefixed hex-encoded unsigned integer.
    ///
    /// This call is the equivalent of `eth_getTransactionByHash` in eth1.0 API.
    #[method(name = "getTransactionByNumber")]
    async fn get_transaction_by_number(
        &self,
        transaction_hash: String,
    ) -> Result<reply::Transaction, Error>;

    /// Returns information about a transaction by block hash and transaction index position.
    /// `block_hash` should either be a 32 byte value encoded as 0x-prefixed hex string or
    /// one of special tag values:
    /// - `latest`, which means the most recent block,
    /// - `earliest`, which means the genesis block.
    /// `transaction_index` should either be a 0x-prefixed hex-encoded unsigned integer.
    ///
    /// This call is the equivalent of `eth_getTransactionByBlockHashAndIndex` in eth1.0 API.
    #[method(name = "getTransactionByBlockHashAndIndex")]
    async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: String,
        transaction_index: u32,
    ) -> Result<reply::transaction::Transaction, Error>;

    /// Returns information about a transaction by block number and transaction index position.
    /// `block_number` should either be a 0x-prefixed hex-encoded unsigned integer or
    /// one of special tag values:
    /// - `latest`, which means the most recent block,
    /// - `earliest`, which means the genesis block.
    /// `transaction_index` should either be a 0x-prefixed hex-encoded unsigned integer.
    ///
    /// This call is the equivalent of `eth_getTransactionByBlockNumberAndIndex` in eth1.0 API.
    #[method(name = "getTransactionByBlockNumberAndIndex")]
    async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: String,
        transaction_index: u32,
    ) -> Result<reply::transaction::Transaction, Error>;

    /// Returns the value from a storage position at a given address.
    /// Both `contract_address` and `key` should be a 32 byte value encoded as 0x-prefixed hex string.
    ///
    /// This call is the equivalent of `eth_getStorage` in eth1.0 API.
    #[method(name = "getStorage")]
    async fn get_storage(&self, contract_address: H256, key: U256) -> Result<H256, Error>;

    /// Returns code at a given address.
    /// `contract_address` should be a 32 byte value encoded as 0x-prefixed hex string.
    ///
    /// This call is the equivalent of `eth_getCode` in eth1.0 API.
    #[method(name = "getCode")]
    async fn get_code(&self, contract_address: H256) -> Result<reply::Code, Error>;

    /// Executes a new call immediately without creating a transaction on the block chain.
    /// `contract_address` and `entry_point` should be a 32 byte value encoded as 0x-prefixed hex string.
    /// `call_data` should be an array of 32 byte values encoded as 0x-prefixed hex strings.
    ///
    /// This call is the equivalent of `eth_call` in eth1.0 API.
    #[method(name = "call")]
    async fn call(
        &self,
        contract_address: H256,
        call_data: Vec<U256>,
        entry_point: H256,
    ) -> Result<reply::Call, Error>;
}
