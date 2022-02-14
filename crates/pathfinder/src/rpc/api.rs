//! Implementation of JSON-RPC endpoints.
use crate::{
    core::{
        CallResultValue, ContractAddress, ContractCode, StarknetChainId, StarknetProtocolVersion,
        StarknetTransactionHash, StarknetTransactionIndex, StorageAddress, StorageValue,
    },
    rpc::types::{
        reply::{Block, ErrorCode, StateUpdate, Syncing, Transaction, TransactionReceipt},
        request::{BlockResponseScope, Call, OverflowingStorageAddress},
        BlockHashOrTag, BlockNumberOrTag, Tag,
    },
    sequencer::{self, reply as raw},
    storage::{self, Storage},
};
use anyhow::Context;
use jsonrpsee::types::{
    error::{CallError, Error},
    RpcResult,
};
use pedersen::OverflowError;
use std::convert::TryInto;

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
pub struct RpcApi {
    storage: Storage,
    sequencer: sequencer::Client,
}

/// Based on [the Starknet operator API spec](https://github.com/starkware-libs/starknet-adrs/blob/master/api/starknet_operator_api_openrpc.json).
impl RpcApi {
    pub fn new(storage: Storage, sequencer: sequencer::Client) -> Self {
        Self { storage, sequencer }
    }

    /// Helper function.
    async fn get_raw_block_by_hash(&self, block_hash: BlockHashOrTag) -> RpcResult<raw::Block> {
        // TODO get this from storage
        let block = self.sequencer.block_by_hash(block_hash).await?;
        Ok(block)
    }

    /// Get block information given the block hash.
    /// `block_hash` is the [Hash](crate::rpc::types::BlockHashOrTag::Hash) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn get_block_by_hash(
        &self,
        block_hash: BlockHashOrTag,
        requested_scope: Option<BlockResponseScope>,
    ) -> RpcResult<Block> {
        let block = self.get_raw_block_by_hash(block_hash).await?;
        let scope = requested_scope.unwrap_or_default();
        Ok(Block::from_scoped(block, scope))
    }

    /// Helper function.
    async fn get_raw_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> RpcResult<raw::Block> {
        let block = self.sequencer.block_by_number(block_number).await?;
        Ok(block)
    }

    /// Get block information given the block number (its height).
    /// `block_number` is the [Number](crate::rpc::types::BlockNumberOrTag::Number) (height) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn get_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
        requested_scope: Option<BlockResponseScope>,
    ) -> RpcResult<Block> {
        let block = self.get_raw_block_by_number(block_number).await?;
        let scope = requested_scope.unwrap_or_default();
        Ok(Block::from_scoped(block, scope))
    }

    /// Get the information about the result of executing the requested block.
    /// `block_hash` is the [Hash](crate::rpc::types::BlockHashOrTag::Hash) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn get_state_update_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<StateUpdate> {
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
    /// `block_hash` is the [Hash](crate::rpc::types::BlockHashOrTag::Hash) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    ///
    /// We are using overflowing type for `key` to be able to correctly report
    /// [`INVALID_STORAGE_KEY`](https://github.com/starkware-libs/starknet-specs/blob/64044c2c8be136b6fdf7f13896ea0422bf211a74/api/starknet_api_openrpc.json#L1043)
    /// as per
    /// [StarkNet RPC spec](https://github.com/starkware-libs/starknet-specs/blob/64044c2c8be136b6fdf7f13896ea0422bf211a74/api/starknet_api_openrpc.json#L144),
    /// otherwise we would report [-32602](https://www.jsonrpc.org/specification#error_object).
    pub async fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: OverflowingStorageAddress,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<StorageValue> {
        use crate::{
            state::state_tree::{ContractsStateTree, GlobalStateTree},
            storage::{ContractsStateTable, GlobalStateTable},
        };
        use pedersen::StarkHash;

        let key = StorageAddress(StarkHash::from_be_bytes(key.0.to_fixed_bytes()).map_err(
            // Report that the value is >= than the field modulus
            // Use explicit typing in closure arg to force compiler error should error variants ever be expanded
            |_e: OverflowError| Error::from(ErrorCode::InvalidStorageKey),
        )?);

        if key.0.has_more_than_251_bits() {
            // Report that the value is more than 251 bits
            return Err(Error::from(ErrorCode::InvalidStorageKey));
        }

        if let BlockHashOrTag::Tag(Tag::Pending) = block_hash {
            // Pending request is always forwarded
            return Ok(self
                .sequencer
                .storage(contract_address, key, block_hash)
                .await?);
        }

        // We cannot just return Error::Internal (-32003) in cases which are not covered by starknet RPC API spec
        // as jsonrpsee reserved it for internal subscription related errors only, so we resort to
        // CallError::Custom with the same code value and message as Error::Internal. This way we can still provide
        // an "Internal server error" but with additional context.
        //
        // This error is used for all instances of operations that are not explicitly specified in the StarkNet spec.
        // See https://github.com/starkware-libs/starknet-specs/blob/master/api/starknet_api_openrpc.json
        let internal_server_error = |e: anyhow::Error| {
            Error::Call(CallError::Custom {
                code: jsonrpsee::types::v2::error::INTERNAL_ERROR_CODE,
                message: format!("{}: {}", jsonrpsee::types::v2::error::INTERNAL_ERROR_MSG, e),
                data: None,
            })
        };

        let mut db = self
            .storage
            .connection()
            .context("Opening database connection")
            .map_err(internal_server_error)?;
        let tx = db
            .transaction()
            .context("Creating database transaction")
            .map_err(internal_server_error)?;

        // Use internal_server_error to indicate that the process of querying for a particular block failed,
        // which is not the same as being sure that the block is not in the db.
        let global_root = match block_hash {
            BlockHashOrTag::Hash(hash) => GlobalStateTable::get_root_at_block_hash(&tx, hash)
                .map_err(internal_server_error)?,
            BlockHashOrTag::Tag(tag) => match tag {
                Tag::Latest => {
                    GlobalStateTable::get_latest_root(&tx).map_err(internal_server_error)?
                }
                Tag::Pending => unreachable!("Pending has already been handled above"),
            },
        }
        // Since the db query succeeded in execution, we can now report if the block hash was indeed not found
        // by using a dedicated error code from the RPC API spec
        .ok_or_else(|| Error::from(ErrorCode::InvalidBlockHash))?;

        let global_state_tree = GlobalStateTree::load(&tx, global_root)
            .context("Global state tree")
            .map_err(internal_server_error)?;

        // There is a dedicated error code for a non-existent contract in the RPC API spec, so use it.
        let contract_state_hash = global_state_tree
            .get(contract_address)
            .map_err(|_| Error::from(ErrorCode::ContractNotFound))?;

        let contract_state_root = ContractsStateTable::get_root(&tx, contract_state_hash)
            .context("Get contract state root")
            .map_err(internal_server_error)?
            .ok_or_else(|| {
                internal_server_error(anyhow::anyhow!(
                    "Contract state root not found for contract state hash {}",
                    contract_state_hash.0
                ))
            })?;

        let contract_state_tree = ContractsStateTree::load(&tx, contract_state_root)
            .context("Load contract state tree")
            .map_err(internal_server_error)?;

        // ContractsStateTree::get() will return zero if the value is still not found (and we know the key is valid),
        // which is consistent with the specification:
        // https://github.com/starkware-libs/starknet-specs/blob/64044c2c8be136b6fdf7f13896ea0422bf211a74/api/starknet_api_openrpc.json#L136)
        let storage_val = contract_state_tree
            .get(key)
            .context("Get value from contract state tree")
            .map_err(internal_server_error)?;

        Ok(storage_val)
    }

    /// Helper function.
    async fn get_raw_transaction_by_hash(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> RpcResult<raw::Transaction> {
        // TODO get this from storage
        let txn = self.sequencer.transaction(transaction_hash).await?;
        if txn.status == raw::Status::NotReceived {
            return Err(ErrorCode::InvalidTransactionHash.into());
        }
        Ok(txn)
    }

    /// Get the details and status of a submitted transaction.
    /// `transaction_hash` is the hash of the requested transaction.
    pub async fn get_transaction_by_hash(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> RpcResult<Transaction> {
        // TODO get this from storage
        let txn = self.get_raw_transaction_by_hash(transaction_hash).await?;
        let txn = txn.try_into()?;
        Ok(txn)
    }

    /// Get the details of a transaction by a given block hash and index.
    /// `block_hash` is the [Hash](crate::rpc::types::BlockHashOrTag::Hash) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: BlockHashOrTag,
        index: StarknetTransactionIndex,
    ) -> RpcResult<Transaction> {
        // TODO get this from storage
        let block = self.get_raw_block_by_hash(block_hash).await?;
        let index: usize = index
            .0
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        block.transactions.into_iter().nth(index).map_or(
            Err(transaction_index_not_found(index)),
            |txn| Ok(txn.into()),
        )
    }

    /// Get the details of a transaction by a given block number and index.
    /// `block_number` is the [Number](crate::rpc::types::BlockNumberOrTag::Number) (height) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: BlockNumberOrTag,
        index: StarknetTransactionIndex,
    ) -> RpcResult<Transaction> {
        // TODO get this from storage
        let block = self.get_raw_block_by_number(block_number).await?;
        let index: usize = index
            .0
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        block.transactions.into_iter().nth(index).map_or(
            Err(transaction_index_not_found(index)),
            |txn| Ok(txn.into()),
        )
    }

    /// Get the transaction receipt by the transaction hash.
    /// `transaction_hash` is the hash of the requested transaction.
    pub async fn get_transaction_receipt(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> RpcResult<TransactionReceipt> {
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
                        Ok(TransactionReceipt::with_status(receipt, block.status))
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
    /// `contract_address` is the address of the contract to read from.
    pub async fn get_code(&self, contract_address: ContractAddress) -> RpcResult<ContractCode> {
        let mut db = self
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        let code = storage::ContractCodeTable::get_code(&tx, contract_address)
            .context("Fetching code from database")?;

        match code {
            Some(code) => Ok(code),
            None => Err(ErrorCode::ContractNotFound.into()),
        }
    }

    /// Get the number of transactions in a block given a block hash.
    /// `block_hash` is the [Hash](crate::rpc::types::BlockHashOrTag::Hash) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn get_block_transaction_count_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<u64> {
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
    /// `block_hash` is the [Hash](crate::rpc::types::BlockHashOrTag::Hash) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn get_block_transaction_count_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> RpcResult<u64> {
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
    /// `block_hash` is the [Hash](crate::rpc::types::BlockHashOrTag::Hash) or [Tag](crate::rpc::types::BlockHashOrTag::Tag)
    /// of the requested block.
    pub async fn call(
        &self,
        request: Call,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<Vec<CallResultValue>> {
        let call = self.sequencer.call(request.into(), block_hash).await?;
        Ok(call.result)
    }

    /// Get the most recent accepted block number.
    pub async fn block_number(&self) -> RpcResult<u64> {
        let block = self
            .sequencer
            .block_by_hash(BlockHashOrTag::Tag(Tag::Latest))
            .await?;
        let number = block.block_number.ok_or(anyhow::anyhow!(
            "Block number field missing in latest block."
        ))?;
        Ok(number.0)
    }

    /// Return the currently configured StarkNet chain id.
    pub async fn chain_id(&self) -> RpcResult<StarknetChainId> {
        todo!("Figure out where to take it from.")
    }

    /// Returns the transactions in the transaction pool, recognized by this sequencer.
    pub async fn pending_transactions(&self) -> RpcResult<Vec<Transaction>> {
        todo!("Figure out where to take them from.")
    }

    /// Returns the current starknet protocol version identifier, as supported by this node.
    pub async fn protocol_version(&self) -> RpcResult<StarknetProtocolVersion> {
        todo!("Figure out where to take it from.")
    }

    /// Returns an object about the sync status, or false if the node is not synching.
    pub async fn syncing(&self) -> RpcResult<Syncing> {
        todo!("Figure out where to take it from.")
    }
}
