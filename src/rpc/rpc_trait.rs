//! Definition of JSON-RPC endpoints.
//!
//! The trait [RpcApiServer] describes the RPC API methods served by the node.
//! The methods are taken from [the Starknet operator API spec](https://github.com/starkware-libs/starknet-adrs/blob/master/api/starknet_operator_api_openrpc.json).
//! Any extensions to the above spec are explicitly marked in the documentation.
use crate::{
    rpc::types::{relaxed, BlockHashOrTag, BlockNumberOrTag, Syncing},
    sequencer::{reply, request::Call},
};
use jsonrpsee::{proc_macros::rpc, types::error::Error};
use web3::types::U256;

/// TODO
/// Add proper output structs as per spec.
/// Add proper error code handling as per spec.
#[rpc(client, server, namespace = "starknet")]
pub trait RpcApi {
    /// Get block information given the block id.
    /// `block_hash` is the hash (id) of the requested block, represented as up to 64 0x-prefixed
    /// hex digits, or a block tag:
    /// - `latest`, which means the most recent block.
    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(&self, block_hash: BlockHashOrTag) -> Result<reply::Block, Error>;

    /// Get block information given the block number (its height).
    /// `block_number` is the number (height) of the requested block, represented as an integer, or a block tag:
    /// - `latest`, which means the most recent block.
    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::Block, Error>;

    /// Get the information about the result of executing the requested block.
    /// `block_hash` is the hash (id) of the requested block, represented as up to 64 0x-prefixed
    /// hex digits, or a block tag:
    /// - `latest`, which means the most recent block,
    #[method(name = "getStateUpdateByHash")]
    async fn get_state_update_by_hash(&self, block_hash: BlockHashOrTag) -> Result<(), Error>;

    /// Get the value of the storage at the given address and key.
    /// `contract_address` is the address of the contract to read from, `key` is the key to the storage value for the given contract,
    /// both represented as up to 64 0x-prefixed hex digits.
    /// `block_hash` is the hash (id) of the requested block, represented as up to 64 0x-prefixed
    /// hex digits, or a block tag:
    /// - `latest`, which means the most recent block.
    #[method(name = "getStorageAt")]
    async fn get_storage_at(
        &self,
        contract_address: relaxed::H256,
        key: relaxed::H256,
        block_hash: BlockHashOrTag,
    ) -> Result<relaxed::H256, Error>;

    /// Get the value of the storage at the given address and key.
    /// A __temporary replacement__ for [get_storage_at](RpcApiServer::get_storage_at) until we know how to calculate block hash.
    #[method(name = "getStorageAtByBlockNumber")]
    async fn get_storage_at_by_block_number(
        &self,
        contract_address: relaxed::H256,
        key: relaxed::H256,
        block_number: BlockNumberOrTag,
    ) -> Result<relaxed::H256, Error>;

    /// Get the details and status of a submitted transaction.
    /// `transaction_hash` is the hash of the requested transaction, represented as up to 64 0x-prefixed
    /// hex digits.
    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<reply::Transaction, Error>;

    /// Get the details of a transaction by a given block hash and index.
    /// `block_hash` is the hash (id) of the requested block, represented as up to 64 0x-prefixed
    /// hex digits, or a block tag:
    /// - `latest`, which means the most recent block.
    ///
    /// Get the details of the transaction given by the identified block and index in that block.
    /// If no transaction is found, null is returned.
    #[method(name = "getTransactionByBlockHashAndIndex")]
    async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: BlockHashOrTag,
        index: u64,
    ) -> Result<reply::transaction::Transaction, Error>;

    /// Get the details of a transaction by a given block hash and index.
    /// `block_number` is the number (height) of the requested block, represented as an integer, or a block tag:
    /// - `latest`, which means the most recent block.
    ///
    /// Get the details of the transaction given by the identified block and index in that block.
    /// If no transaction is found, null is returned.
    #[method(name = "getTransactionByBlockNumberAndIndex")]
    async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: BlockNumberOrTag,
        index: u64,
    ) -> Result<reply::transaction::Transaction, Error>;

    /// Get the transaction receipt by the transaction hash.
    /// `transaction_hash` is the hash of the requested transaction, represented as up to 64 0x-prefixed
    /// hex digits.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<reply::TransactionStatus, Error>;

    /// Get the code of a specific contract.
    /// `contract_address` is the address of the contract to read from, represented as up to 64 0x-prefixed hex digits.
    #[method(name = "getCode")]
    async fn get_code(&self, contract_address: relaxed::H256) -> Result<reply::Code, Error>;

    /// Get the number of transactions in a block given a block hash.
    /// `block_hash` is the hash (id) of the requested block, represented as up to 64 0x-prefixed
    /// hex digits, or a block tag:
    /// - `latest`, which means the most recent block.
    ///
    /// Returns the number of transactions in the designated block.
    #[method(name = "getBlockTransactionCountByHash")]
    async fn get_block_transaction_count_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<u64, Error>;

    /// Get the number of transactions in a block given a block hash.
    /// `block_number` is the number (height) of the requested block, represented as an integer, or a block tag:
    /// - `latest`, which means the most recent block.
    ///
    /// Returns the number of transactions in the designated block.
    #[method(name = "getBlockTransactionCountByNumber")]
    async fn get_block_transaction_count_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<u64, Error>;

    /// Call a starknet function without creating a StarkNet transaction.
    /// `block_hash` is the hash (id) of the requested block, represented as up to 64 0x-prefixed
    /// hex digits, or a block tag:
    /// - `latest`, which means the most recent block.
    ///
    /// Calls a function in a contract and returns the return value.
    /// Using this call will not create a transaction. Hence, will not change the state.
    #[method(name = "call")]
    async fn call(&self, request: Call, block_hash: BlockHashOrTag) -> Result<reply::Call, Error>;

    /// Get the most recent accepted block number.
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> Result<U256, Error>;

    /// Return the currently configured StarkNet chain id.
    #[method(name = "chainId")]
    async fn chain_id(&self) -> Result<relaxed::H256, Error>;

    /// Returns the transactions in the transaction pool, recognized by this sequencer.
    #[method(name = "pendingTransactions")]
    async fn pending_transactions(&self) -> Result<(), Error>;

    /// Returns the current starknet protocol version identifier, as supported by this node.
    #[method(name = "protocolVersion")]
    async fn protocol_version(&self) -> Result<relaxed::H256, Error>;

    /// Returns an object about the sync status, or false if the node is not synching.
    #[method(name = "syncing")]
    async fn syncing(&self) -> Result<Syncing, Error>;
}
