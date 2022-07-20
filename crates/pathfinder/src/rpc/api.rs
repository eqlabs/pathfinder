//! Implementation of JSON-RPC endpoints.
use crate::{
    cairo::ext_py,
    core::{
        BlockId, CallResultValue, CallSignatureElem, Chain, ClassHash, ConstructorParam,
        ContractAddress, ContractAddressSalt, ContractClass, ContractCode, Fee, GasPrice,
        GlobalRoot, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
        StarknetBlockTimestamp, StarknetTransactionHash, StarknetTransactionIndex, StorageValue,
        TransactionNonce, TransactionVersion,
    },
    rpc::types::{
        reply::{
            Block, BlockStatus, ErrorCode, FeeEstimate, GetEventsResult, Syncing, Transaction,
            TransactionReceipt,
        },
        request::{Call, ContractCall, EventFilter, OverflowingStorageAddress},
        BlockHashOrTag, BlockNumberOrTag, Tag,
    },
    sequencer::{self, request::add_transaction::ContractDefinition, ClientApi},
    state::SyncState,
    storage::{
        ContractsTable, EventFilterError, RefsTable, StarknetBlocksBlockId, StarknetBlocksTable,
        StarknetEventsTable, StarknetTransactionsTable, Storage,
    },
};
use anyhow::Context;
use jsonrpsee::{
    core::{error::Error, RpcResult},
    types::{error::CallError, ErrorObject},
};
use stark_hash::StarkHash;
use std::convert::TryInto;
use std::sync::Arc;

use super::types::reply::{
    DeclareTransactionResult, DeployTransactionResult, InvokeTransactionResult,
};

/// Implements JSON-RPC endpoints.
pub struct RpcApi {
    storage: Storage,
    sequencer: sequencer::Client,
    chain: Chain,
    call_handle: Option<ext_py::Handle>,
    shared_gas_price: Option<Cached>,
    sync_state: Arc<SyncState>,
}

#[derive(Debug)]
pub struct RawBlock {
    pub number: StarknetBlockNumber,
    pub hash: StarknetBlockHash,
    pub root: GlobalRoot,
    pub parent_hash: StarknetBlockHash,
    pub parent_root: GlobalRoot,
    pub timestamp: StarknetBlockTimestamp,
    pub status: BlockStatus,
    pub sequencer: SequencerAddress,
    pub gas_price: GasPrice,
}

/// Determines the type of response to block related queries.
#[derive(Copy, Clone, Debug)]
pub enum BlockResponseScope {
    TransactionHashes,
    FullTransactions,
}

impl Default for BlockResponseScope {
    fn default() -> Self {
        BlockResponseScope::TransactionHashes
    }
}

/// Based on [the Starknet operator API spec](https://github.com/starkware-libs/starknet-specs/blob/master/api/starknet_api_openrpc.json).
impl RpcApi {
    pub fn new(
        storage: Storage,
        sequencer: sequencer::Client,
        chain: Chain,
        sync_state: Arc<SyncState>,
    ) -> Self {
        Self {
            storage,
            sequencer,
            chain,
            call_handle: None,
            shared_gas_price: None,
            sync_state,
        }
    }

    pub fn with_call_handling(self, call_handle: ext_py::Handle) -> Self {
        Self {
            call_handle: Some(call_handle),
            ..self
        }
    }

    pub fn with_eth_gas_price(self, shared: Cached) -> Self {
        Self {
            shared_gas_price: Some(shared),
            ..self
        }
    }

    /// Get block information given the block id.
    pub async fn get_block(
        &self,
        block_id: BlockId,
        scope: BlockResponseScope,
    ) -> RpcResult<Block> {
        let block_id = match block_id {
            BlockId::Pending => {
                let block = self
                    .sequencer
                    .block(block_id)
                    .await
                    .map_err(internal_server_error)?;

                let block = Block::from_sequencer_scoped(block, scope);
                return Ok(block);
            }
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
            BlockId::Latest => StarknetBlocksBlockId::Latest,
        };

        let storage = self.storage.clone();
        let span = tracing::Span::current();

        tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut connection = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let transaction = connection
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            // Need to get the block status. This also tests that the block hash is valid.
            let block = Self::get_raw_block(&transaction, block_id)?;

            let transactions = Self::get_block_transactions(&transaction, block.number, scope)?;

            Ok(Block::from_raw(block, transactions))
        })
        .await
        .context("Database read panic or shutting down")
        .map_err(internal_server_error)
        .and_then(|x| x)
    }

    /// Determines block status based on the current L1-L2 stored in the DB.
    fn get_block_status(
        db_tx: &rusqlite::Transaction<'_>,
        block_number: StarknetBlockNumber,
    ) -> RpcResult<BlockStatus> {
        // All our data is L2 accepted, check our L1-L2 head to see if this block has been accepted on L1.
        let l1_l2_head = RefsTable::get_l1_l2_head(db_tx)
            .context("Read latest L1 head from database")
            .map_err(internal_server_error)?;
        let block_status = match l1_l2_head {
            Some(number) if number >= block_number => BlockStatus::AcceptedOnL1,
            _ => BlockStatus::AcceptedOnL2,
        };

        Ok(block_status)
    }

    /// This function assumes that the block ID is valid i.e. it won't check if the block hash or number exist.
    fn get_block_transactions(
        db_tx: &rusqlite::Transaction<'_>,
        block_number: StarknetBlockNumber,
        scope: BlockResponseScope,
    ) -> RpcResult<super::types::reply::Transactions> {
        let transactions_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(db_tx, block_number.into())
                .context("Reading transactions from database")
                .map_err(internal_server_error)?;

        use super::types::reply;
        match scope {
            BlockResponseScope::TransactionHashes => Ok(reply::Transactions::HashesOnly(
                transactions_receipts
                    .into_iter()
                    .map(|(t, _)| t.hash())
                    .collect(),
            )),
            BlockResponseScope::FullTransactions => Ok(reply::Transactions::Full(
                transactions_receipts
                    .into_iter()
                    .map(|(t, _)| t.into())
                    .collect(),
            )),
        }
    }

    /// Fetches a [RawBlock] from storage.
    fn get_raw_block(
        transaction: &rusqlite::Transaction<'_>,
        block_id: StarknetBlocksBlockId,
    ) -> RpcResult<RawBlock> {
        let block = StarknetBlocksTable::get(transaction, block_id)
            .context("Read block from database")
            .map_err(internal_server_error)?
            .ok_or_else(|| Error::from(ErrorCode::InvalidBlockId))?;

        let block_status = Self::get_block_status(transaction, block.number)?;

        let (parent_hash, parent_root) = match block.number {
            StarknetBlockNumber::GENESIS => (
                StarknetBlockHash(StarkHash::ZERO),
                GlobalRoot(StarkHash::ZERO),
            ),
            other => {
                let parent_block = StarknetBlocksTable::get(transaction, (other - 1).into())
                    .context("Read parent block from database")
                    .map_err(internal_server_error)?
                    .context("Parent block missing")?;

                (parent_block.hash, parent_block.root)
            }
        };

        let block = RawBlock {
            number: block.number,
            hash: block.hash,
            root: block.root,
            parent_hash,
            parent_root,
            timestamp: block.timestamp,
            status: block_status,
            gas_price: block.gas_price,
            sequencer: block.sequencer_address,
        };

        Ok(block)
    }

    // /// Get the information about the result of executing the requested block.
    // pub async fn get_state_update_by_hash(
    //     &self,
    //     block_hash: BlockHashOrTag,
    // ) -> RpcResult<StateUpdate> {
    //     // TODO get this from storage or directly from L1
    //     match block_hash {
    //         BlockHashOrTag::Tag(Tag::Latest) => todo!("Implement L1 state diff retrieval."),
    //         BlockHashOrTag::Tag(Tag::Pending) => {
    //             todo!("Implement when sequencer support for pending tag available.")
    //         }
    //         BlockHashOrTag::Hash(_) => todo!("Implement L1 state diff retrieval."),
    //     }
    // }

    /// Get the value of the storage at the given address and key.
    ///
    /// We are using overflowing type for `key` to be able to correctly report `INVALID_STORAGE_KEY` as per
    /// [StarkNet RPC spec](https://github.com/starkware-libs/starknet-specs/blob/master/api/starknet_api_openrpc.json),
    /// otherwise we would report [-32602](https://www.jsonrpc.org/specification#error_object).
    pub async fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: OverflowingStorageAddress,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<StorageValue> {
        use crate::{
            core::StorageAddress,
            state::state_tree::{ContractsStateTree, GlobalStateTree},
            storage::ContractsStateTable,
        };
        use stark_hash::OverflowError;

        let key = StorageAddress(StarkHash::from_be_bytes(key.0.to_fixed_bytes()).map_err(
            // Report that the value is >= than the field modulus
            // Use explicit typing in closure arg to force compiler error should error variants ever be expanded
            |_e: OverflowError| Error::from(ErrorCode::InvalidStorageKey),
        )?);

        if key.0.has_more_than_251_bits() {
            // Report that the value is more than 251 bits
            return Err(Error::from(ErrorCode::InvalidStorageKey));
        }

        let block_id = match block_hash {
            BlockHashOrTag::Hash(hash) => hash.into(),
            BlockHashOrTag::Tag(Tag::Latest) => StarknetBlocksBlockId::Latest,
            BlockHashOrTag::Tag(Tag::Pending) => {
                return Ok(self
                    .sequencer
                    .storage(contract_address, key, block_hash)
                    .await?);
            }
        };

        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            // Use internal_server_error to indicate that the process of querying for a particular block failed,
            // which is not the same as being sure that the block is not in the db.
            let global_root = StarknetBlocksTable::get_root(&tx, block_id)
                .map_err(internal_server_error)?
                // Since the db query succeeded in execution, we can now report if the block hash was indeed not found
                // by using a dedicated error code from the RPC API spec
                .ok_or_else(|| Error::from(ErrorCode::InvalidBlockId))?;

            let global_state_tree = GlobalStateTree::load(&tx, global_root)
                .context("Global state tree")
                .map_err(internal_server_error)?;

            let contract_state_hash = global_state_tree
                .get(contract_address)
                .context("Get contract state hash from global state tree")
                .map_err(internal_server_error)?;

            // There is a dedicated error code for a non-existent contract in the RPC API spec, so use it.
            if contract_state_hash.0 == StarkHash::ZERO {
                return Err(Error::from(ErrorCode::ContractNotFound));
            }

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
            // which is consistent with the specification.
            let storage_val = contract_state_tree
                .get(key)
                .context("Get value from contract state tree")
                .map_err(internal_server_error)?;

            Ok(storage_val)
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            // flatten is unstable
            .and_then(|x| x)
    }

    /// Get the details and status of a submitted transaction.
    pub async fn get_transaction_by_hash(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> RpcResult<Transaction> {
        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let db_tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            // Get the transaction from storage.
            StarknetTransactionsTable::get_transaction(&db_tx, transaction_hash)
                .context("Reading transaction from database")?
                .ok_or_else(|| ErrorCode::InvalidTransactionHash.into())
                .map(|tx| tx.into())
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the details of a transaction by a given block hash and index.
    pub async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: BlockHashOrTag,
        index: StarknetTransactionIndex,
    ) -> RpcResult<Transaction> {
        let index: usize = index
            .0
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        let block_id = match block_hash {
            BlockHashOrTag::Hash(hash) => StarknetBlocksBlockId::Hash(hash),
            BlockHashOrTag::Tag(Tag::Latest) => StarknetBlocksBlockId::Latest,
            BlockHashOrTag::Tag(Tag::Pending) => {
                let block = self
                    .sequencer
                    .block(block_hash.into())
                    .await
                    .context("Fetch block from sequencer")
                    .map_err(internal_server_error)?;

                return block
                    .transactions()
                    .iter()
                    .nth(index)
                    .map_or(Err(ErrorCode::InvalidTransactionIndex.into()), |txn| {
                        Ok(txn.into())
                    });
            }
        };

        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let db_tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            // Get the transaction from storage.
            match StarknetTransactionsTable::get_transaction_at_block(&db_tx, block_id, index)
                .context("Reading transaction from database")?
            {
                Some(transaction) => Ok(transaction.into()),
                None => {
                    // We now need to check whether it was the block hash or transaction index which were invalid. We do this by checking if the block exists
                    // at all. If no, then the block hash is invalid. If yes, then the index is invalid.
                    //
                    // get_root is cheaper than querying the full block.
                    match StarknetBlocksTable::get_root(&db_tx, block_id)
                        .context("Reading block from database")?
                    {
                        Some(_) => Err(ErrorCode::InvalidTransactionIndex.into()),
                        None => Err(ErrorCode::InvalidBlockId.into()),
                    }
                }
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the details of a transaction by a given block number and index.
    pub async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: BlockNumberOrTag,
        index: StarknetTransactionIndex,
    ) -> RpcResult<Transaction> {
        let index: usize = index
            .0
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        let block_id = match block_number {
            BlockNumberOrTag::Number(number) => StarknetBlocksBlockId::Number(number),
            BlockNumberOrTag::Tag(Tag::Latest) => StarknetBlocksBlockId::Latest,
            BlockNumberOrTag::Tag(Tag::Pending) => {
                let block = self
                    .sequencer
                    .block(block_number.into())
                    .await
                    .context("Fetch block from sequencer")
                    .map_err(internal_server_error)?;

                return block
                    .transactions()
                    .iter()
                    .nth(index)
                    .map_or(Err(ErrorCode::InvalidTransactionIndex.into()), |txn| {
                        Ok(txn.clone().into())
                    });
            }
        };

        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let db_tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            // Get the transaction from storage.
            match StarknetTransactionsTable::get_transaction_at_block(&db_tx, block_id, index)
                .context("Reading transaction from database")?
            {
                Some(transaction) => Ok(transaction.into()),
                None => {
                    // We now need to check whether it was the block number or transaction index which were invalid. We do this by checking if the block exists
                    // at all. If no, then the block number is invalid. If yes, then the index is invalid.
                    //
                    // get_root is cheaper than querying the full block.
                    match StarknetBlocksTable::get_root(&db_tx, block_id)
                        .context("Reading block from database")?
                    {
                        Some(_) => Err(ErrorCode::InvalidTransactionIndex.into()),
                        None => Err(ErrorCode::InvalidBlockId.into()),
                    }
                }
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the transaction receipt by the transaction hash.
    pub async fn get_transaction_receipt(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> RpcResult<TransactionReceipt> {
        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let db_tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            match StarknetTransactionsTable::get_receipt(&db_tx, transaction_hash)
                .context("Reading transaction receipt from database")
                .map_err(internal_server_error)?
            {
                Some((receipt, block_hash)) => {
                    // We require the block status here as well..
                    let block = StarknetBlocksTable::get(&db_tx, block_hash.into())
                        .context("Reading block from database")
                        .map_err(internal_server_error)?
                        .context("Block missing from database")
                        .map_err(internal_server_error)?;

                    let block_status = Self::get_block_status(&db_tx, block.number)?;

                    // We require the transaction so that we can return the right RPC type for the receipt.
                    match StarknetTransactionsTable::get_transaction(&db_tx, transaction_hash)
                        .context("Reading transaction from database")
                        .map_err(internal_server_error)?
                    {
                        Some(transaction) => Ok(TransactionReceipt::with_block_status(
                            receipt,
                            block_status,
                            &transaction,
                        )),
                        None => Err(ErrorCode::InvalidTransactionHash.into()),
                    }
                }
                None => Err(ErrorCode::InvalidTransactionHash.into()),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the class based on its hash.
    ///
    /// This is for the deprecated starknet_getCode API that requires returning the
    /// contract bytecode and abi.
    pub async fn get_code(&self, contract_address: ContractAddress) -> RpcResult<ContractCode> {
        use crate::storage::ContractCodeTable;

        let storage = self.storage.clone();

        let jh = tokio::task::spawn_blocking(move || {
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;
            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            let class_hash = ContractsTable::get_hash(&tx, contract_address)
                .context("Fetching class hash from database")
                .map_err(internal_server_error)?;

            let class_hash = match class_hash {
                Some(hash) => hash,
                None => return Err(ErrorCode::ContractNotFound.into()),
            };

            let code = ContractCodeTable::get_code(&tx, class_hash)
                .context("Fetching code from database")
                .map_err(internal_server_error)?;

            match code {
                Some(code) => Ok(code),
                None => Err(ErrorCode::InvalidContractClassHash.into()),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the class based on its hash.
    pub async fn get_class(&self, class_hash: ClassHash) -> RpcResult<ContractClass> {
        use crate::storage::ContractCodeTable;

        let storage = self.storage.clone();

        let jh = tokio::task::spawn_blocking(move || {
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;
            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            let class = ContractCodeTable::get_class(&tx, class_hash)
                .context("Fetching code from database")
                .map_err(internal_server_error)?;

            match class {
                Some(class) => Ok(class),
                None => Err(ErrorCode::InvalidContractClassHash.into()),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the class hash of a specific contract.
    pub async fn get_class_hash_at(
        &self,
        contract_address: ContractAddress,
    ) -> RpcResult<ClassHash> {
        let storage = self.storage.clone();

        let jh = tokio::task::spawn_blocking(move || {
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;
            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            let class_hash = ContractsTable::get_hash(&tx, contract_address)
                .context("Fetching class hash from database")
                .map_err(internal_server_error)?;

            match class_hash {
                Some(hash) => Ok(hash),
                None => Err(ErrorCode::ContractNotFound.into()),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the class of a specific contract.
    /// `contract_address` is the address of the contract to read from.
    pub async fn get_class_at(
        &self,
        contract_address: ContractAddress,
    ) -> RpcResult<ContractClass> {
        use crate::storage::ContractCodeTable;

        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;
            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            let class_hash = ContractsTable::get_hash(&tx, contract_address)
                .context("Fetching class hash from database")
                .map_err(internal_server_error)?;

            let class_hash = match class_hash {
                Some(hash) => hash,
                None => return Err(ErrorCode::ContractNotFound.into()),
            };

            let code = ContractCodeTable::get_class(&tx, class_hash)
                .context("Fetching code from database")
                .map_err(internal_server_error)?;

            match code {
                Some(code) => Ok(code),
                None => Err(ErrorCode::ContractNotFound.into()),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the number of transactions in a block given a block hash.
    pub async fn get_block_transaction_count_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<u64> {
        let block_id = match block_hash {
            BlockHashOrTag::Hash(hash) => hash.into(),
            BlockHashOrTag::Tag(Tag::Latest) => StarknetBlocksBlockId::Latest,
            BlockHashOrTag::Tag(Tag::Pending) => {
                let block = self
                    .sequencer
                    .block(block_hash.into())
                    .await
                    .context("Fetch block from sequencer")
                    .map_err(internal_server_error)?;

                let len: u64 =
                    block.transactions().len().try_into().map_err(|e| {
                        Error::Call(CallError::InvalidParams(anyhow::Error::new(e)))
                    })?;

                return Ok(len);
            }
        };

        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;
            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            match StarknetTransactionsTable::get_transaction_count(&tx, block_id)
                .context("Reading transaction count from database")
                .map_err(internal_server_error)?
            {
                0 => {
                    // We need to check if the value was 0 because there were no transactions, or because the block hash
                    // is invalid.
                    //
                    // get_root is cheaper than querying the full block.
                    match StarknetBlocksTable::get_root(&tx, block_id)
                        .context("Reading block from database")?
                    {
                        Some(_) => Ok(0),
                        None => Err(ErrorCode::InvalidBlockId.into()),
                    }
                }
                other => Ok(other as u64),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the number of transactions in a block given a block hash.
    pub async fn get_block_transaction_count_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> RpcResult<u64> {
        let block_id = match block_number {
            BlockNumberOrTag::Number(number) => number.into(),
            BlockNumberOrTag::Tag(Tag::Latest) => StarknetBlocksBlockId::Latest,
            BlockNumberOrTag::Tag(Tag::Pending) => {
                let block = self
                    .sequencer
                    .block(block_number.into())
                    .await
                    .context("Fetch block from sequencer")
                    .map_err(internal_server_error)?;

                let len: u64 =
                    block.transactions().len().try_into().map_err(|e| {
                        Error::Call(CallError::InvalidParams(anyhow::Error::new(e)))
                    })?;

                return Ok(len);
            }
        };

        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;
            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            match StarknetTransactionsTable::get_transaction_count(&tx, block_id)
                .context("Reading transaction count from database")
                .map_err(internal_server_error)?
            {
                0 => {
                    // We need to check if the value was 0 because there were no transactions, or because the block number
                    // is invalid.
                    //
                    // get_root is cheaper than querying the full block.
                    match StarknetBlocksTable::get_root(&tx, block_id)
                        .context("Reading block from database")?
                    {
                        Some(_) => Ok(0),
                        None => Err(ErrorCode::InvalidBlockId.into()),
                    }
                }
                other => Ok(other as u64),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Call a starknet function without creating a StarkNet transaction.
    pub async fn call(
        &self,
        request: Call,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<Vec<CallResultValue>> {
        use futures::future::TryFutureExt;

        match (self.call_handle.as_ref(), &block_hash) {
            (Some(h), &BlockHashOrTag::Hash(_) | &BlockHashOrTag::Tag(Tag::Latest)) => {
                // we don't yet handle pending at all, and latest has been decided to be whatever
                // block we have, which is exactly how the py/src/call.py handles it.
                h.call(request, block_hash).map_err(Error::from).await
            }
            (Some(_), _) => {
                // just forward it to the sequencer for now.
                self.sequencer
                    .call(request.into(), block_hash)
                    .map_ok(|x| x.result)
                    .map_err(Error::from)
                    .await
            }
            (None, _) => {
                // this is to remain consistent with estimateFee
                Err(internal_server_error("Unsupported configuration"))
            }
        }
    }

    /// Get the most recent accepted block number.
    pub async fn block_number(&self) -> RpcResult<u64> {
        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;
            let tx = db
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            StarknetBlocksTable::get_latest_number(&tx)
                .context("Reading latest block number from database")
                .map_err(internal_server_error)?
                .context("Database is empty")
                .map_err(internal_server_error)
                .map(|number| number.0)
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Return the currently configured StarkNet chain id.
    pub async fn chain_id(&self) -> RpcResult<String> {
        Ok(self.chain.starknet_chain_id().to_hex_str().into_owned())
    }

    // /// Returns the transactions in the transaction pool, recognized by this sequencer.
    // pub async fn pending_transactions(&self) -> RpcResult<Vec<Transaction>> {
    //     todo!("Figure out where to take them from.")
    // }

    // /// Returns the current starknet protocol version identifier, as supported by this node.
    // pub async fn protocol_version(&self) -> RpcResult<StarknetProtocolVersion> {
    //     todo!("Figure out where to take it from.")
    // }

    /// Returns an object about the sync status, or false if the node is not synching.
    pub async fn syncing(&self) -> RpcResult<Syncing> {
        // Scoped so I don't have to think too hard about mutex guard drop semantics.
        let value = { self.sync_state.status.read().await.clone() };
        Ok(value)
    }

    /// Returns events matching the specified filter
    pub async fn get_events(&self, request: EventFilter) -> RpcResult<GetEventsResult> {
        let storage = self.storage.clone();
        let span = tracing::Span::current();

        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut connection = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let filter = request.into();
            let tx = connection
                .transaction()
                .context("Opening database transaction")
                .map_err(internal_server_error)?;
            // We don't add context here, because [StarknetEventsTable::get_events] adds its
            // own context to the errors. This way we get meaningful error information
            // for errors related to query parameters.
            let page = StarknetEventsTable::get_events(&tx, &filter).map_err(|e| {
                if let Some(e) = e.downcast_ref::<EventFilterError>() {
                    Error::from(*e)
                } else {
                    internal_server_error(e)
                }
            })?;

            Ok(GetEventsResult {
                events: page.events.into_iter().map(|e| e.into()).collect(),
                page_number: filter.page_number,
                is_last_page: page.is_last_page,
            })
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            // flatten is unstable
            .and_then(|x| x)
    }

    /// Submit a new transaction to be added to the chain.
    ///
    /// This method just forwards the request received over the JSON-RPC
    /// interface to the sequencer.
    pub async fn add_invoke_transaction(
        &self,
        call: ContractCall,
        signature: Vec<CallSignatureElem>,
        max_fee: Fee,
        version: TransactionVersion,
    ) -> RpcResult<InvokeTransactionResult> {
        let mut call: sequencer::request::Call = call.into();
        call.signature = signature;

        let result = self
            .sequencer
            .add_invoke_transaction(call, max_fee, version)
            .await?;
        Ok(InvokeTransactionResult {
            transaction_hash: result.transaction_hash,
        })
    }

    /// Submit a new declare transaction.
    ///
    /// "Similarly to deploy, declare transactions will contain the contract class.
    /// The state of StarkNet will contain a list of declared classes, that can
    /// be appended to via the new declare transaction."
    ///
    /// This method just forwards the request received over the JSON-RPC
    /// interface to the sequencer.
    pub async fn add_declare_transaction(
        &self,
        contract_class: ContractDefinition,
        version: TransactionVersion,
        token: Option<String>,
    ) -> RpcResult<DeclareTransactionResult> {
        let result = self
            .sequencer
            .add_declare_transaction(
                contract_class,
                // actual address dumped from a `starknet declare` call
                ContractAddress(StarkHash::from_hex_str("0x1").unwrap()),
                Fee(0u128.to_be_bytes().into()),
                vec![],
                TransactionNonce(StarkHash::ZERO),
                version,
                token,
            )
            .await?;
        Ok(DeclareTransactionResult {
            transaction_hash: result.transaction_hash,
            class_hash: result.class_hash,
        })
    }

    /// Submit a new deploy contract transaction.
    ///
    /// This method just forwards the request received over the JSON-RPC
    /// interface to the sequencer.
    pub async fn add_deploy_transaction(
        &self,
        contract_address_salt: ContractAddressSalt,
        constructor_calldata: Vec<ConstructorParam>,
        contract_definition: ContractDefinition,
        token: Option<String>,
    ) -> RpcResult<DeployTransactionResult> {
        let result = self
            .sequencer
            .add_deploy_transaction(
                contract_address_salt,
                constructor_calldata,
                contract_definition,
                token,
            )
            .await?;
        Ok(DeployTransactionResult {
            transaction_hash: result.transaction_hash,
            contract_address: result.address,
        })
    }

    pub async fn estimate_fee(
        &self,
        request: Call,
        block_hash: BlockHashOrTag,
    ) -> RpcResult<FeeEstimate> {
        use crate::cairo::ext_py::GasPriceSource;

        match (
            self.call_handle.as_ref(),
            self.shared_gas_price.as_ref(),
            &block_hash,
        ) {
            (Some(h), _, &BlockHashOrTag::Hash(_)) => {
                // discussed during estimateFee work: when using block_hash use the gasPrice from
                // the starknet_blocks::gas_price column, otherwise (tags) get the latest eth_gasPrice.
                h.estimate_fee(request, block_hash, GasPriceSource::PastBlock)
                    .await
                    .map_err(Error::from)
            }
            (Some(h), Some(g), &BlockHashOrTag::Tag(Tag::Latest)) => {
                // now we want the gas_price from our hopefully pre-fetched source, it will be the
                // same when we finally have pending support

                let gas_price = g
                    .get()
                    .await
                    .ok_or_else(|| internal_server_error("eth_gasPrice unavailable"))?;

                h.estimate_fee(request, block_hash, GasPriceSource::Current(gas_price))
                    .await
                    .map_err(Error::from)
            }
            (Some(_), Some(_), &BlockHashOrTag::Tag(Tag::Pending)) => {
                Err(internal_server_error("Unimplemented"))
            }
            _ => {
                // sequencer return type is incompatible with jsonrpc api return type
                Err(internal_server_error("Unsupported configuration"))
            }
        }
    }
}

impl From<ext_py::CallFailure> for jsonrpsee::core::Error {
    fn from(e: ext_py::CallFailure) -> Self {
        use ext_py::CallFailure::*;
        match e {
            NoSuchBlock => Error::from(ErrorCode::InvalidBlockId),
            NoSuchContract => Error::from(ErrorCode::ContractNotFound),
            InvalidEntryPoint => Error::from(ErrorCode::InvalidMessageSelector),
            ExecutionFailed(e) => internal_server_error(e),
            // Intentionally hide the message under Internal
            Internal(_) | Shutdown => static_internal_server_error(),
        }
    }
}

impl From<EventFilterError> for jsonrpsee::core::Error {
    fn from(e: EventFilterError) -> Self {
        match e {
            EventFilterError::PageSizeTooBig(max_size) => {
                let error = ErrorCode::PageSizeTooBig as i32;
                Error::Call(CallError::Custom(ErrorObject::owned(
                    error,
                    ErrorCode::PageSizeTooBig.to_string(),
                    Some(serde_json::json!({ "max_page_size": max_size })),
                )))
            }
        }
    }
}

// We cannot just return Error::Internal (-32003) in cases which are not covered by starknet RPC API spec
// as jsonrpsee reserved it for internal subscription related errors only, so we resort to
// CallError::Custom with the same code value and message as Error::Internal. This way we can still provide
// an "Internal server error" but with additional context.
//
// This error is used for all instances of operations that are not explicitly specified in the StarkNet spec.
// See <https://github.com/starkware-libs/starknet-specs/blob/master/api/starknet_api_openrpc.json>
fn internal_server_error(e: impl std::fmt::Display) -> jsonrpsee::core::Error {
    Error::Call(CallError::Custom(ErrorObject::owned(
        jsonrpsee::types::error::ErrorCode::InternalError.code(),
        format!("{}: {}", jsonrpsee::types::error::INTERNAL_ERROR_MSG, e),
        None::<()>,
    )))
}

fn static_internal_server_error() -> jsonrpsee::core::Error {
    Error::Call(CallError::Custom(ErrorObject::from(
        jsonrpsee::types::error::ErrorCode::InternalError,
    )))
}

/// Caching of `eth_gasPrice` with single request at a time refreshing.
///
/// The `gasPrice` is used for [`RpcApi::estimate_fee`] when user requests for [`BlockHashOrTag::Tag`].
#[derive(Clone)]
pub struct Cached {
    inner: std::sync::Arc<std::sync::Mutex<Inner>>,
    eth: Arc<dyn crate::ethereum::transport::EthereumTransport + Send + Sync + 'static>,
}

impl Cached {
    pub fn new(
        eth: Arc<dyn crate::ethereum::transport::EthereumTransport + Send + Sync + 'static>,
    ) -> Self {
        Cached {
            inner: Default::default(),
            eth,
        }
    }

    /// Returns either a fast fresh value, slower a periodically polled value or fails because
    /// polling has stopped.
    async fn get(&self) -> Option<web3::types::H256> {
        let mut rx = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            let stale_limit = std::time::Duration::from_secs(10);

            if let Some((fetched_at, gas_price)) = g.latest.as_ref() {
                if fetched_at.elapsed() < stale_limit {
                    // fresh
                    let accepted = *gas_price;
                    return Some(accepted);
                }
            }

            // clear stale since it's not going to be useful for anyone
            g.latest = None;

            // this is an adaptation of https://fasterthanli.me/articles/request-coalescing-in-async-rust

            if let Some(tx) = g.next.upgrade() {
                // there's already an existing request being fulfilled
                tx.subscribe()
            } else {
                let (tx, rx) = tokio::sync::broadcast::channel(1);

                // the use of Weak works here, because the only strong reference is being sent to
                // the async task, which upon completion holds the lock again while sending
                // everyone listening the response, and clears the weak.
                let tx = std::sync::Arc::new(tx);

                let inner = self.inner.clone();
                let eth = self.eth.clone();

                g.next = std::sync::Arc::downgrade(&tx);

                // in general, asking eth_gasPrice seems to be fast enough especially as we already
                // have a connection open because the EthereumTransport impl is being used for sync
                // as well.
                //
                // it being fast enough, allows us to just coalesce the requests, but also not poll
                // for fun while no one is using the gas estimation.
                tokio::spawn(async move {
                    let price = match eth.gas_price().await {
                        Ok(price) => price,
                        Err(_e) => {
                            let _ = tx.send(None);
                            return;
                        }
                    };

                    let now = std::time::Instant::now();

                    let mut out = [0u8; 32];
                    price.to_big_endian(&mut out[..]);
                    let gas_price = web3::types::H256::from(out);

                    let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
                    g.latest.replace((now, gas_price));

                    let _ = tx.send(Some(gas_price));
                    drop(tx);
                    // when g is dropped and the mutex unlocked, no one will be able to upgrade
                    // the weak, because the only strong has been dropped.
                });

                rx
            }
        };

        rx.recv().await.ok().and_then(|i| i)
    }
}

#[derive(Default)]
struct Inner {
    latest: Option<(std::time::Instant, web3::types::H256)>,
    next: std::sync::Weak<tokio::sync::broadcast::Sender<Option<web3::types::H256>>>,
}
