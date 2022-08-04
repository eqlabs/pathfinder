//! Implementation of JSON-RPC endpoints.
use crate::{
    cairo::ext_py::{self, BlockHashNumberOrLatest},
    core::{
        BlockId, CallResultValue, CallSignatureElem, Chain, ClassHash, ConstructorParam,
        ContractAddress, ContractAddressSalt, ContractClass, ContractNonce, Fee, GasPrice,
        GlobalRoot, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
        StarknetBlockTimestamp, StarknetTransactionHash, StarknetTransactionIndex, StorageAddress,
        StorageValue, TransactionNonce, TransactionVersion,
    },
    rpc::types::{
        reply::{
            Block, BlockHashAndNumber, BlockStatus, EmittedEvent, ErrorCode, FeeEstimate,
            GetEventsResult, StateUpdate, Syncing, Transaction, TransactionReceipt,
        },
        request::{Call, ContractCall, EventFilter},
    },
    sequencer::{self, request::add_transaction::ContractDefinition, ClientApi},
    state::{state_tree::GlobalStateTree, PendingData, SyncState},
    storage::{
        ContractsTable, EventFilterError, RefsTable, StarknetBlocksBlockId, StarknetBlocksTable,
        StarknetEventsTable, StarknetStateUpdatesTable, StarknetTransactionsTable, Storage,
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
    pending_data: Option<PendingData>,
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
            pending_data: None,
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

    pub fn with_pending_data(self, pending_data: PendingData) -> Self {
        Self {
            pending_data: Some(pending_data),
            ..self
        }
    }

    /// Returns [PendingData]; errors if [RpcApi] was not configured with one.
    ///
    /// This is useful for queries to access pending data or return an error via `?` if it
    /// is not meant to be used (as on testnet for example).
    fn pending_data(&self) -> anyhow::Result<&PendingData> {
        self.pending_data
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Pending data not supported in this configuration"))
    }

    /// Get block information given the block id.
    pub async fn get_block(
        &self,
        block_id: BlockId,
        scope: BlockResponseScope,
    ) -> RpcResult<Block> {
        let block_id = match block_id {
            BlockId::Pending => match self.pending_data()?.block().await {
                Some(block) => {
                    return Ok(Block::from_sequencer_scoped(
                        block.as_ref().clone().into(),
                        scope,
                    ));
                }
                None => StarknetBlocksBlockId::Latest,
            },
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

    /// Get the information about the result of executing the requested block.
    ///
    /// FIXME: add support for pending
    pub async fn get_state_update(&self, block_id: BlockId) -> RpcResult<StateUpdate> {
        let block_id = match block_id {
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
            BlockId::Latest => StarknetBlocksBlockId::Latest,
            BlockId::Pending => {
                return Err(ErrorCode::InvalidBlockId.into());
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

            let block_hash = match block_id {
                StarknetBlocksBlockId::Hash(h) => h,
                StarknetBlocksBlockId::Number(_) | StarknetBlocksBlockId::Latest => {
                    StarknetBlocksTable::get_hash(
                        &tx,
                        block_id.try_into().expect("block_id is not a hash"),
                    )
                    .context("Read block from database")
                    .map_err(internal_server_error)?
                    .ok_or_else(|| Error::from(ErrorCode::InvalidBlockId))?
                }
            };

            let state_update = StarknetStateUpdatesTable::get(&tx, block_hash)
                .context("Read state update from database")
                .map_err(internal_server_error)?
                .ok_or_else(|| Error::from(ErrorCode::InvalidBlockId))?;

            Ok(state_update)
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            // flatten is unstable
            .and_then(|x| x)
    }

    /// Get the value of the storage at the given address and key.
    ///
    /// We are using overflowing type for `key` to be able to correctly report `INVALID_STORAGE_KEY` as per
    /// [StarkNet RPC spec](https://github.com/starkware-libs/starknet-specs/blob/master/api/starknet_api_openrpc.json),
    /// otherwise we would report [-32602](https://www.jsonrpc.org/specification#error_object).
    pub async fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageAddress,
        block_id: BlockId,
    ) -> RpcResult<StorageValue> {
        use crate::{state::state_tree::ContractsStateTree, storage::ContractsStateTable};

        let block_id = match block_id {
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
            BlockId::Latest => StarknetBlocksBlockId::Latest,
            BlockId::Pending => {
                // Pending storage will either be part of the pending state update,
                // or it will come from latest if it isn't part of the pending diff.
                match self.pending_data()?.state_update().await {
                    Some(update) => {
                        let pending_value = update
                            .state_diff
                            .storage_diffs
                            .get(&contract_address)
                            .and_then(|storage| {
                                storage
                                    .iter()
                                    .find_map(|update| (update.key == key).then(|| update.value))
                            });

                        match pending_value {
                            Some(value) => return Ok(value),
                            None => StarknetBlocksBlockId::Latest,
                        }
                    }
                    // Default to latest if pending data is not available.
                    None => StarknetBlocksBlockId::Latest,
                }
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
        // First check pending data as this is in-mem and should be faster.
        if let Ok(pending) = self.pending_data() {
            let pending_tx = pending.block().await.and_then(|block| {
                block
                    .transactions
                    .iter()
                    .find(|tx| tx.hash() == transaction_hash)
                    .cloned()
            });

            if let Some(pending_tx) = pending_tx {
                return Ok(pending_tx.into());
            }
        }

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
    pub async fn get_transaction_by_block_id_and_index(
        &self,
        block_id: BlockId,
        index: StarknetTransactionIndex,
    ) -> RpcResult<Transaction> {
        let index: usize = index
            .0
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        let block_id = match block_id {
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
            BlockId::Latest => StarknetBlocksBlockId::Latest,
            BlockId::Pending => match self.pending_data()?.block().await {
                Some(block) => {
                    return block
                        .transactions
                        .get(index)
                        .map_or(Err(ErrorCode::InvalidTransactionIndex.into()), |txn| {
                            Ok(txn.into())
                        })
                }
                // Default to latest if pending data is not available.
                None => StarknetBlocksBlockId::Latest,
            },
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

    /// Get the transaction receipt by the transaction hash.
    pub async fn get_transaction_receipt(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> RpcResult<TransactionReceipt> {
        // First check pending data as this is in-mem and should be faster.
        if let Ok(pending) = self.pending_data() {
            let receipt_transaction = pending.block().await.and_then(|block| {
                block
                    .transaction_receipts
                    .iter()
                    .zip(block.transactions.iter())
                    .find_map(|(receipt, tx)| {
                        (receipt.transaction_hash == transaction_hash)
                            .then(|| (receipt.clone(), tx.clone()))
                    })
            });

            if let Some((receipt, transaction)) = receipt_transaction {
                return Ok(TransactionReceipt::pending_from(receipt, &transaction));
            };
        }

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
                        Some(transaction) => Ok(TransactionReceipt::with_block_data(
                            receipt,
                            block_status,
                            block.hash,
                            block.number,
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
    pub async fn get_class(&self, class_hash: ClassHash) -> RpcResult<ContractClass> {
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
        block_id: BlockId,
        contract_address: ContractAddress,
    ) -> RpcResult<ClassHash> {
        let block_id = match block_id {
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
            BlockId::Latest => StarknetBlocksBlockId::Latest,
            BlockId::Pending => match self.pending_data()?.state_update().await {
                Some(state_update) => {
                    let class_hash =
                        state_update
                            .state_diff
                            .deployed_contracts
                            .iter()
                            .find_map(|deploy| {
                                (deploy.address == contract_address).then_some(deploy.class_hash)
                            });
                    match class_hash {
                        Some(class_hash) => return Ok(class_hash),
                        // Check if contract does not already exist in known blocks.
                        None => StarknetBlocksBlockId::Latest,
                    }
                }
                // Default to latest if pending data is not available.
                None => StarknetBlocksBlockId::Latest,
            },
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

            let class_hash = ContractsTable::get_hash(&tx, contract_address)
                .context("Fetching class hash from database")
                .map_err(internal_server_error)?;

            match class_hash {
                Some(class_hash) => {
                    // check if contract existed at block
                    match Self::contract_exists_at_block_id(&tx, contract_address, block_id)
                        .context("Checking contract existence at block")
                        .map_err(internal_server_error)?
                    {
                        false => Err(ErrorCode::ContractNotFound.into()),
                        true => Ok(class_hash),
                    }
                }
                None => Err(ErrorCode::ContractNotFound.into()),
            }
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    fn contract_exists_at_block_id(
        tx: &rusqlite::Transaction<'_>,
        contract_address: ContractAddress,
        block_id: StarknetBlocksBlockId,
    ) -> anyhow::Result<bool> {
        let global_root = match StarknetBlocksTable::get_root(tx, block_id)? {
            Some(root) => root,
            None => return Ok(false),
        };
        let global_state_tree =
            GlobalStateTree::load(tx, global_root).context("Global state tree")?;
        let contract_state_hash = global_state_tree
            .get(contract_address)
            .context("Contract ")?;
        Ok(contract_state_hash.0 != StarkHash::ZERO)
    }

    /// Get the class of a specific contract.
    /// `contract_address` is the address of the contract to read from.
    pub async fn get_class_at(
        &self,
        block_id: BlockId,
        contract_address: ContractAddress,
    ) -> RpcResult<ContractClass> {
        use crate::storage::ContractCodeTable;
        let span = tracing::Span::current();

        let block_id = match block_id {
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
            BlockId::Latest => StarknetBlocksBlockId::Latest,
            BlockId::Pending => match self.pending_data()?.state_update().await {
                Some(state_update) => {
                    let class_hash =
                        state_update
                            .state_diff
                            .deployed_contracts
                            .iter()
                            .find_map(|deploy| {
                                (deploy.address == contract_address).then_some(deploy.class_hash)
                            });
                    match class_hash {
                        Some(class_hash) => {
                            let storage = self.storage.clone();
                            let code = tokio::task::spawn_blocking(move || {
                                let _g = span.enter();
                                let mut db = storage
                                    .connection()
                                    .context("Opening database connection")
                                    .map_err(internal_server_error)?;
                                let tx = db
                                    .transaction()
                                    .context("Creating database transaction")
                                    .map_err(internal_server_error)?;
                                let code = ContractCodeTable::get_class(&tx, class_hash)
                                    .context("Fetching code from database");

                                let code = code.map_err(internal_server_error)?;

                                anyhow::Result::<_>::Ok(code)
                            })
                            .await
                            .context("Database read panic or shutting down")
                            .map_err(internal_server_error)??
                            .context("Missing class in database")
                            .map_err(internal_server_error)?;
                            return Ok(code);
                        }
                        // Check if contract does not already exist in known blocks.
                        None => StarknetBlocksBlockId::Latest,
                    }
                }
                // Default to latest if pending data is not available.
                None => StarknetBlocksBlockId::Latest,
            },
        };

        let storage = self.storage.clone();

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
                Some(class_hash) => {
                    match Self::contract_exists_at_block_id(&tx, contract_address, block_id)
                        .context("Checking contract existence at block")
                        .map_err(internal_server_error)?
                    {
                        false => return Err(ErrorCode::ContractNotFound.into()),
                        true => class_hash,
                    }
                }
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

    /// Get the number of transactions in a block given a block id.
    pub async fn get_block_transaction_count(&self, block_id: BlockId) -> RpcResult<u64> {
        let block_id = match block_id {
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => number.into(),
            BlockId::Latest => StarknetBlocksBlockId::Latest,
            BlockId::Pending => {
                let count = match self.pending_data()?.block().await {
                    Some(block) => block.transactions.len(),
                    None => 0,
                };

                return Ok(count as u64);
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

    /// Call a starknet transaction locally.
    pub async fn call(&self, request: Call, block_id: BlockId) -> RpcResult<Vec<CallResultValue>> {
        // handle is always required; we no longer do any call forwarding to feeder_gateway as was
        // done before local pending support for calls, never for estimate_fee.
        let handle = self
            .call_handle
            .as_ref()
            .ok_or_else(|| internal_server_error("Unsupported configuration"))?;

        let (when, pending_update) = self.base_block_and_pending_for_call(block_id).await?;

        Ok(handle.call(request, when, pending_update).await?)
    }

    /// Get the latest local block's number.
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
                .map(|number| number.0)
                .ok_or_else(|| Error::from(ErrorCode::NoBlocks))
        });

        jh.await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            .and_then(|x| x)
    }

    /// Get the latest local block's hash and number.
    pub async fn block_hash_and_number(&self) -> RpcResult<BlockHashAndNumber> {
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

            StarknetBlocksTable::get_latest_hash_and_number(&tx)
                .context("Reading latest block number from database")
                .map_err(internal_server_error)?
                .map(|(hash, number)| BlockHashAndNumber { hash, number })
                .ok_or_else(|| Error::from(ErrorCode::NoBlocks))
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

    /// Returns the current pending transactions.
    pub async fn pending_transactions(&self) -> RpcResult<Vec<Transaction>> {
        match self.pending_data()?.block().await {
            Some(block) => {
                let tx = block.transactions.iter().map(Transaction::from).collect();
                Ok(tx)
            }
            None => {
                // Get transactions from `latest` instead.
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

                    let tx = StarknetTransactionsTable::get_transactions_for_latest_block(&db_tx)
                        .map_err(internal_server_error)?
                        .into_iter()
                        .map(Transaction::from)
                        .collect();

                    Ok(tx)
                });

                jh.await
                    .context("Database read panic or shutting down")
                    .map_err(internal_server_error)
                    .and_then(|x| x)
            }
        }
    }

    /// Returns the contract's latest nonce.
    ///
    /// Not currently supported correctly as nonce's aren't implemented yet. In the mean time
    /// returns "0x0" until starknet reaches 0.10 at which point it will return an error instead.
    pub async fn get_nonce(&self, contract: ContractAddress) -> RpcResult<ContractNonce> {
        // Check that contract actually exists..
        let storage = self.storage.clone();
        let span = tracing::Span::current();
        let jh = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut db = storage
                .connection()
                .context("Opening database connection")?;
            let tx = db.transaction().context("Creating database transaction")?;

            let exists = crate::storage::ContractsTable::exists(&tx, contract)
                .context("Reading contract from database")?;

            anyhow::Result::<_, anyhow::Error>::Ok(exists)
        });
        let exists = jh
            .await
            .context("Database read panic or shutting down")
            .and_then(|x| x)
            .map_err(internal_server_error)?;

        if !exists {
            return Err(Error::from(ErrorCode::ContractNotFound));
        }

        // Check the latest known starknet version, and return "0" if its < 0.10.0
        let version = { self.sync_state.version.read().await.clone() };
        match version {
            // This field was only populated from version 0.9 onwards, so earlier versions don't exist.
            // This property has no confirmed specification, so we are hesistant to alaways parse it as semver.
            Some(version) if version.starts_with("0.9.") => Ok(ContractNonce(StarkHash::ZERO)),
            Some(_) => Err(internal_server_error(
                "Not supported for StarkNet versions from 0.10.0 onwards",
            )),
            None => {
                // The `latest` sync status has not been set which means we are still waiting for our
                // first `sync` latest poll to complete.
                Err(internal_server_error(
                    "Waiting to connect to StarkNet gateway, please try again later",
                ))
            }
        }
    }

    /// Returns an object about the sync status, or false if the node is not synching.
    pub async fn syncing(&self) -> RpcResult<Syncing> {
        // Scoped so I don't have to think too hard about mutex guard drop semantics.
        let value = { self.sync_state.status.read().await.clone() };
        Ok(value)
    }

    /// Append's pending events to `dst` based on the filter requirements and returns
    /// true if this was the last pending data i.e. `is_last_page`.
    async fn append_pending_events(
        &self,
        dst: &mut Vec<EmittedEvent>,
        skip: usize,
        amount: usize,
        address: Option<ContractAddress>,
        keys: std::collections::HashSet<crate::core::EventKey>,
    ) -> bool {
        let pending_block = match self.pending_data.as_ref() {
            Some(data) => match data.block().await {
                Some(block) => block,
                None => return true,
            },
            None => return true,
        };

        let original_len = dst.len();

        let pending_events = pending_block
            .transaction_receipts
            .iter()
            .flat_map(|receipt| {
                receipt
                    .events
                    .iter()
                    .zip(std::iter::repeat(receipt.transaction_hash))
            })
            .filter(|(event, _)| match address {
                Some(address) => event.from_address == address,
                None => true,
            })
            .filter(|(event, _)| {
                if keys.is_empty() {
                    return true;
                }

                for ek in &event.keys {
                    if keys.contains(ek) {
                        return true;
                    }
                }
                false
            })
            .skip(skip)
            // We need to take an extra event to determine is_last_page.
            .take(amount + 1)
            .map(|(event, tx_hash)| crate::rpc::types::reply::EmittedEvent {
                data: event.data.clone(),
                keys: event.keys.clone(),
                from_address: event.from_address,
                block_hash: None,
                block_number: None,
                transaction_hash: tx_hash,
            });

        dst.extend(pending_events);
        let is_last_page = dst.len() <= (original_len + amount);
        if !is_last_page {
            dst.pop();
        }

        is_last_page
    }

    /// Returns events matching the specified filter
    pub async fn get_events(&self, request: EventFilter) -> RpcResult<GetEventsResult> {
        // The [Block::Pending] in ranges makes things quite complicated. This implementation splits
        // the ranges into the following buckets:
        //
        // 1. pending     :     pending -> query pending only
        // 2. pending     : non-pending -> return empty result
        // 3. non-pending : non-pending -> query db only
        // 4. non-pending :     pending -> query db and potentially append pending events
        //
        // The database query for 3 and 4 is combined into one step.
        //
        // 4 requires some additional logic to handle some edge cases:
        //  a) Query database
        //  b) if full page           -> return page
        //  c) else if partially full -> append events from start of pending
        //  d) else (page is empty):
        //      i) query database for event count
        //     ii) query pending data using count for paging into pending events

        use BlockId::*;

        let storage = self.storage.clone();

        // Handle the trivial (1) and (2) cases.
        match (request.from_block, request.to_block) {
            (Some(Pending), non_pending) if non_pending != Some(Pending) => {
                return Ok(GetEventsResult {
                    events: Vec::new(),
                    // Or should this always be zero? Hard to say.. its a dumb request.
                    page_number: request.page_number,
                    is_last_page: true,
                });
            }
            (Some(Pending), Some(Pending)) => {
                let mut events = Vec::new();
                let is_last_page = self
                    .append_pending_events(
                        &mut events,
                        request.page_number * request.page_size,
                        request.page_size,
                        request.address,
                        request.keys.into_iter().collect(),
                    )
                    .await;
                return Ok(GetEventsResult {
                    events,
                    page_number: request.page_number,
                    is_last_page,
                });
            }
            _ => {}
        }

        let keys = request.keys.clone();
        // blocking task to perform database event query and optionally, the event count
        // required for (4d).
        let span = tracing::Span::current();
        let db_events = tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut connection = storage
                .connection()
                .context("Opening database connection")
                .map_err(internal_server_error)?;

            let transaction = connection
                .transaction()
                .context("Creating database transaction")
                .map_err(internal_server_error)?;

            // Maps a BlockId to a block number which can be used by the events query.
            fn map_to_number(
                tx: &rusqlite::Transaction<'_>,
                block: Option<BlockId>,
            ) -> RpcResult<Option<StarknetBlockNumber>> {
                match block {
                    Some(Hash(hash)) => {
                        let number = StarknetBlocksTable::get_number(tx, hash)
                            .map_err(internal_server_error)?
                            .ok_or_else(|| Error::from(ErrorCode::InvalidBlockId))?;

                        Ok(Some(number))
                    }
                    Some(Number(number)) => Ok(Some(number)),
                    Some(Pending) | Some(Latest) | None => Ok(None),
                }
            }

            let from_block = map_to_number(&transaction, request.from_block)?;
            let to_block = map_to_number(&transaction, request.to_block)?;

            let filter = crate::storage::StarknetEventFilter {
                from_block,
                to_block,
                contract_address: request.address,
                keys: keys.clone(),
                page_size: request.page_size,
                page_number: request.page_number,
            };
            // We don't add context here, because [StarknetEventsTable::get_events] adds its
            // own context to the errors. This way we get meaningful error information
            // for errors related to query parameters.
            let page = StarknetEventsTable::get_events(&transaction, &filter).map_err(|e| {
                if let Some(e) = e.downcast_ref::<EventFilterError>() {
                    Error::from(*e)
                } else {
                    internal_server_error(e)
                }
            })?;

            // Additional information is required if we need to append pending events.
            // More specifically, we need some database event count in order to page through
            // the pending events properly.
            let event_count = if request.to_block == Some(Pending) && page.events.is_empty() {
                let count = StarknetEventsTable::event_count(
                    &transaction,
                    from_block,
                    to_block,
                    request.address,
                    keys,
                )
                .map_err(internal_server_error)?;

                Some(count)
            } else {
                None
            };

            Ok((
                GetEventsResult {
                    events: page.events.into_iter().map(|e| e.into()).collect(),
                    page_number: filter.page_number,
                    is_last_page: page.is_last_page,
                },
                event_count,
            ))
        });

        let (mut events, count) = db_events
            .await
            .context("Database read panic or shutting down")
            .map_err(internal_server_error)
            // flatten is unstable
            .and_then(|x| x)?;

        // Append pending data if required.
        if matches!(request.to_block, Some(Pending)) && events.events.len() < request.page_size {
            let keys = request
                .keys
                .into_iter()
                .collect::<std::collections::HashSet<_>>();

            let amount = request.page_size - events.events.len();
            let skip = match count {
                Some(count) => request.page_number * request.page_size - count,
                None => 0,
            };
            events.is_last_page = self
                .append_pending_events(&mut events.events, skip, amount, request.address, keys)
                .await;
        }

        Ok(events)
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

    /// Estimate fee on a starknet transaction locally.
    pub async fn estimate_fee(&self, request: Call, block_id: BlockId) -> RpcResult<FeeEstimate> {
        use crate::cairo::ext_py::GasPriceSource;

        let handle = self
            .call_handle
            .as_ref()
            .ok_or_else(|| internal_server_error("Unsupported configuration"))?;

        // discussed during estimateFee work: when user is requesting using block_hash use the
        // gasPrice from the starknet_blocks::gas_price column, otherwise (tags) get the latest
        // eth_gasPrice.
        //
        // the fact that [`Self::base_block_and_pending_for_call`] transforms pending cases to use
        // actual parent blocks by hash is an internal transformation we do for correctness,
        // unrelated to this consideration.
        let gas_price = if matches!(block_id, BlockId::Pending | BlockId::Latest) {
            let gas_price = match self.shared_gas_price.as_ref() {
                Some(cached) => cached.get().await,
                None => None,
            };

            let gas_price = gas_price
                .ok_or_else(|| internal_server_error("Current eth_gasPrice is unavailable"))?;

            GasPriceSource::Current(gas_price)
        } else {
            GasPriceSource::PastBlock
        };

        let (when, pending_update) = self.base_block_and_pending_for_call(block_id).await?;

        Ok(handle
            .estimate_fee(request, when, gas_price, pending_update)
            .await?)
    }

    /// Transforms the request to call or estimate fee at some point in time to the type expected
    /// by [`crate::cairo::ext_py`] with the optional, latest pending data.
    ///
    /// The procedure is shared between call and estimate fee.
    async fn base_block_and_pending_for_call(
        &self,
        at_block: BlockId,
    ) -> Result<
        (
            BlockHashNumberOrLatest,
            Option<Arc<sequencer::reply::StateUpdate>>,
        ),
        anyhow::Error,
    > {
        use crate::cairo::ext_py::Pending;

        match BlockHashNumberOrLatest::try_from(at_block) {
            Ok(when) => Ok((when, None)),
            Err(Pending) => {
                // we must have pending_data configured for pending requests, otherwise we fail
                // fast.
                let pending = self.pending_data()?;

                // call on this particular parent block hash; if it's not found at query time over
                // at python, it should fall back to latest and **disregard** the pending data.
                let pending_on_top_of_a_block = pending
                    .state_update_on_parent_block()
                    .await
                    .map(|(parent_block, data)| (parent_block.into(), Some(data)));

                // if there is no pending data available, just execute on whatever latest. this is
                // the "intent" of the pending functinality other rpc methods should follow as
                // well, that "pending" is just an emphemeral view of the latest, when it's not
                // available one is supposed to use latest (for example: testnet).
                Ok(pending_on_top_of_a_block.unwrap_or((BlockHashNumberOrLatest::Latest, None)))
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
/// The `gasPrice` is used for [`RpcApi::estimate_fee`] when user requests for [`BlockId::Latest`] or
/// [`BlockId::Pending`].
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
