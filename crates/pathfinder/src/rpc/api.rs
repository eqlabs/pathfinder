//! Implementation of JSON-RPC endpoints.
use crate::{
    rpc::types::{
        relaxed,
        reply::{Block, Code, ErrorCode, StateUpdate, Syncing, Transaction, TransactionReceipt},
        request::{BlockResponseScope, Call},
        BlockHashOrTag, BlockNumberOrTag, Tag,
    },
    sequencer::{
        reply as raw, reply::starknet::Error as RawError,
        reply::starknet::ErrorCode as RawErrorCode, Client,
    },
};
use jsonrpsee::types::error::{CallError, Error};
use reqwest::Url;
use std::convert::{From, TryInto};
use web3::types::H256;

/// Helper function for creating invalid transaction hash call error.
///
/// Unfortunately invalid transaction hash has the same error code as
/// cannot be used.
/// invalid block hash, so `ErrorCode::InvalidTransactionHash.into()`
fn invalid_transaction_hash() -> Error {
    Error::Call(CallError::Custom {
        code: ErrorCode::InvalidTransactionHash as i32,
        message: "Invalid transaction hash".to_owned(),
        data: None,
    })
}

/// Helper function.
fn transaction_index_not_found(index: usize) -> Error {
    Error::Call(CallError::InvalidParams(anyhow::anyhow!(
        "transaction index {} not found",
        index
    )))
}

/// Implements JSON-RPC endpoints.
///
/// __TODO__ directly calls [sequencer::Client](crate::sequencer::Client) until storage is implemented.
pub struct RpcApi(Client);

impl Default for RpcApi {
    fn default() -> Self {
        let module = Client::new(Url::parse("https://alpha4.starknet.io/").expect("Valid URL."));
        Self(module)
    }
}

/// Based on [the Starknet operator API spec](https://github.com/starkware-libs/starknet-adrs/blob/master/api/starknet_operator_api_openrpc.json).
impl RpcApi {
    /// Helper function.
    async fn get_raw_block_by_hash(&self, block_hash: BlockHashOrTag) -> Result<raw::Block, Error> {
        // TODO get this from storage
        let block = self
            .0
            .block_by_hash(block_hash)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<RawError>().map(|e| e.code) {
                    Some(RawErrorCode::OutOfRangeBlockHash | RawErrorCode::BlockNotFound) => {
                        ErrorCode::InvalidBlockHash.into()
                    }
                    Some(_) | None => e.into(),
                }
            })?;
        Ok(block)
    }

    /// Get block information given the block hash.
    /// `block_hash` is the hash of the requested block, represented as a 0x-prefixed
    /// hex string, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_block_by_hash(
        &self,
        block_hash: BlockHashOrTag,
        requested_scope: Option<BlockResponseScope>,
    ) -> Result<Block, Error> {
        let block = self.get_raw_block_by_hash(block_hash).await?;
        let scope = requested_scope.unwrap_or_default();
        Ok(Block::from_scoped(block, scope))
    }

    /// Helper function.
    async fn get_raw_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<raw::Block, Error> {
        let block = self
            .0
            .block_by_number(block_number)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<RawError>() {
                    Some(starknet_e)
                        if starknet_e.code == RawErrorCode::MalformedRequest
                            && starknet_e
                                .message
                                .contains("Block ID should be in the range") =>
                    {
                        ErrorCode::InvalidBlockNumber.into()
                    }
                    Some(_) | None => e.into(),
                }
            })?;
        Ok(block)
    }

    /// Get block information given the block number (its height).
    /// `block_number` is the number (height) of the requested block, represented as an integer, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
        requested_scope: Option<BlockResponseScope>,
    ) -> Result<Block, Error> {
        let block = self.get_raw_block_by_number(block_number).await?;
        let scope = requested_scope.unwrap_or_default();
        Ok(Block::from_scoped(block, scope))
    }

    /// Get the information about the result of executing the requested block.
    /// `block_hash` is the hash of the requested block, represented as a 0x-prefixed
    /// hex string, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_state_update_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<StateUpdate, Error> {
        // TODO get this from storage or directly from L1
        match block_hash {
            BlockHashOrTag::Tag(Tag::Latest) => todo!("Implement L1 state diff retrieval."),
            BlockHashOrTag::Tag(Tag::Pending) => {
                todo!("Implement when sequencer support for pending tag available.")
            }
            BlockHashOrTag::Hash(_) => todo!("Implement L1 state diff retrieval."),
        }
    }

    /// Get the value of the storage at the given address and key.
    /// `contract_address` is the address of the contract to read from, `key` is the key to the storage value for the given contract,
    /// both represented as 0x-prefixed hex strings.
    /// `block_hash` is the hash of the requested block, represented as a 0x-prefixed
    /// hex string, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_storage_at(
        &self,
        contract_address: relaxed::H256,
        key: relaxed::H256,
        block_hash: BlockHashOrTag,
    ) -> Result<relaxed::H256, Error> {
        let key: H256 = *key;
        let key: [u8; 32] = key.into();
        let storage = self
            .0
            .storage(*contract_address, key.into(), block_hash)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<RawError>() {
                    Some(starknet_e) => match starknet_e.code {
                        RawErrorCode::OutOfRangeContractAddress
                        | RawErrorCode::UninitializedContract => ErrorCode::ContractNotFound.into(),
                        RawErrorCode::OutOfRangeStorageKey => ErrorCode::InvalidStorageKey.into(),
                        RawErrorCode::OutOfRangeBlockHash | RawErrorCode::BlockNotFound => {
                            ErrorCode::InvalidBlockHash.into()
                        }
                        _ => e.into(),
                    },
                    None => e.into(),
                }
            })?;
        let x: [u8; 32] = storage.into();
        Ok(H256::from(x).into())
    }

    /// Helper function.
    async fn get_raw_transaction_by_hash(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<raw::Transaction, Error> {
        // TODO get this from storage
        let txn = self
            .0
            .transaction(*transaction_hash)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<RawError>() {
                    Some(starknet_e) => match starknet_e.code {
                        RawErrorCode::OutOfRangeTransactionHash => invalid_transaction_hash(),
                        _ => e.into(),
                    },
                    None => e.into(),
                }
            })?;
        if txn.status == raw::transaction::Status::NotReceived {
            return Err(invalid_transaction_hash());
        }
        Ok(txn)
    }

    /// Get the details and status of a submitted transaction.
    /// `transaction_hash` is the hash of the requested transaction, represented as a 0x-prefixed
    /// hex string.
    pub async fn get_transaction_by_hash(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<Transaction, Error> {
        // TODO get this from storage
        let txn = self.get_raw_transaction_by_hash(transaction_hash).await?;
        Ok(txn.into())
    }

    /// Get the details of a transaction by a given block hash and index.
    /// `block_hash` is the hash of the requested block, represented as a 0x-prefixed
    /// hex string, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: BlockHashOrTag,
        index: u64,
    ) -> Result<Transaction, Error> {
        // TODO get this from storage
        let block = self.get_raw_block_by_hash(block_hash).await?;
        let index: usize = index
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        block.transactions.into_iter().nth(index).map_or(
            Err(transaction_index_not_found(index)),
            |txn| Ok(txn.into()),
        )
    }

    /// Get the details of a transaction by a given block number and index.
    /// `block_number` is the number (height) of the requested block, represented as an integer, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: BlockNumberOrTag,
        index: u64,
    ) -> Result<Transaction, Error> {
        // TODO get this from storage
        let block = self.get_raw_block_by_number(block_number).await?;
        let index: usize = index
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        block.transactions.into_iter().nth(index).map_or(
            Err(transaction_index_not_found(index)),
            |txn| Ok(txn.into()),
        )
    }

    /// Get the transaction receipt by the transaction hash.
    /// `transaction_hash` is the hash of the requested transaction, represented as a 0x-prefixed
    /// hex string.
    pub async fn get_transaction_receipt(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<TransactionReceipt, Error> {
        let txn = self.get_raw_transaction_by_hash(transaction_hash).await?;
        if let Some(block_hash) = txn.block_hash {
            if let Some(index) = txn.transaction_index {
                let block = self
                    .get_raw_block_by_hash(BlockHashOrTag::Hash(block_hash))
                    .await?;
                let index: usize = index
                    .try_into()
                    .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;
                block
                    .transaction_receipts
                    .into_iter()
                    .nth(index)
                    .map_or(Err(transaction_index_not_found(index)), |receipt| {
                        Ok(receipt.into())
                    })
            } else {
                Err(Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                    "transaction index not found"
                ))))
            }
        } else {
            Err(ErrorCode::InvalidBlockHash.into())
        }
    }

    /// Get the code of a specific contract.
    /// `contract_address` is the address of the contract to read from, represented as a 0x-prefixed hex string.
    pub async fn get_code(&self, contract_address: relaxed::H256) -> Result<Code, Error> {
        let code = self
            .0
            .code(*contract_address, BlockHashOrTag::Tag(Tag::Latest))
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<RawError>().map(|e| e.code) {
                    Some(
                        RawErrorCode::OutOfRangeContractAddress
                        | RawErrorCode::UninitializedContract,
                    ) => ErrorCode::ContractNotFound.into(),
                    Some(_) | None => e.into(),
                }
            })?;
        Ok(code)
    }

    /// Get the number of transactions in a block given a block hash.
    /// `block_hash` is the hash of the requested block, represented as a 0x-prefixed
    /// hex string, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_block_transaction_count_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<u64, Error> {
        // TODO get this from storage
        let block = self.get_raw_block_by_hash(block_hash).await?;
        let len: u64 = block
            .transactions
            .len()
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;
        Ok(len)
    }

    /// Get the number of transactions in a block given a block hash.
    /// `block_number` is the number (height) of the requested block, represented as an integer, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn get_block_transaction_count_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<u64, Error> {
        // TODO get this from storage
        let block = self.get_raw_block_by_number(block_number).await?;
        let len: u64 = block
            .transactions
            .len()
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;
        Ok(len)
    }

    /// Call a starknet function without creating a StarkNet transaction.
    /// `block_hash` is the hash of the requested block, represented as a 0x-prefixed
    /// hex string, or a block tag:
    /// - `latest`, which means the most recent block.
    pub async fn call(
        &self,
        request: Call,
        block_hash: BlockHashOrTag,
    ) -> Result<Vec<relaxed::H256>, Error> {
        let call = self
            .0
            .call(request.into(), block_hash)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<RawError>() {
                    Some(starknet_e) => match starknet_e.code {
                        RawErrorCode::EntryPointNotFound => {
                            ErrorCode::InvalidMessageSelector.into()
                        }
                        RawErrorCode::OutOfRangeContractAddress
                        | RawErrorCode::UninitializedContract => ErrorCode::ContractNotFound.into(),
                        RawErrorCode::TransactionFailed => ErrorCode::InvalidCallData.into(),
                        RawErrorCode::OutOfRangeBlockHash | RawErrorCode::BlockNotFound => {
                            ErrorCode::InvalidBlockHash.into()
                        }
                        _ => e.into(),
                    },
                    None => e.into(),
                }
            })?;
        Ok(call.into())
    }

    /// Get the most recent accepted block number.
    pub async fn block_number(&self) -> Result<u64, Error> {
        let block = self
            .0
            .block_by_hash(BlockHashOrTag::Tag(Tag::Latest))
            .await?;
        Ok(block.block_number)
    }

    /// Return the currently configured StarkNet chain id.
    pub async fn chain_id(&self) -> Result<relaxed::H256, Error> {
        todo!("Figure out where to take it from.")
    }

    /// Returns the transactions in the transaction pool, recognized by this sequencer.
    pub async fn pending_transactions(&self) -> Result<Vec<Transaction>, Error> {
        todo!("Figure out where to take them from.")
    }

    /// Returns the current starknet protocol version identifier, as supported by this node.
    pub async fn protocol_version(&self) -> Result<relaxed::H256, Error> {
        todo!("Figure out where to take it from.")
    }

    /// Returns an object about the sync status, or false if the node is not synching.
    pub async fn syncing(&self) -> Result<Syncing, Error> {
        todo!("Figure out where to take it from.")
    }
}
