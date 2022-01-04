//! Implementation of JSON-RPC endpoints.
use crate::{
    rpc::types::{
        relaxed,
        reply::{Block, Code, ErrorCode, Syncing, Transaction},
        BlockHashOrTag, BlockNumberOrTag,
    },
    sequencer::{
        reply, reply::starknet::Error as SeqError, reply::starknet::ErrorCode as SeqErrorCode,
        request::Call, Client,
    },
};
use jsonrpsee::types::error::{CallError, Error};
use reqwest::Url;
use std::convert::{From, TryInto};
use web3::types::H256;

/// Helper function for creating invalid transaction hash call error.
///
/// Unfortunately invalid transaction hash has the same error code as
/// invalid block hash, so `ErrorCode::InvalidTransactionHash.into()`
/// cannot be used.
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

impl RpcApi {
    async fn get_raw_block_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Block, Error> {
        // TODO get this from storage
        let block = match block_hash {
            BlockHashOrTag::Tag(_) => self.0.latest_block().await?,
            BlockHashOrTag::Hash(hash) => self.0.block(hash).await.map_err(|e| -> Error {
                match e.downcast_ref::<SeqError>() {
                    Some(starknet_e) => match starknet_e.code {
                        SeqErrorCode::OutOfRangeBlockHash | SeqErrorCode::BlockNotFound => {
                            ErrorCode::InvalidBlockHash.into()
                        }
                        _ => e.into(),
                    },
                    None => e.into(),
                }
            })?,
        };
        Ok(block)
    }

    pub async fn get_block_by_hash(&self, block_hash: BlockHashOrTag) -> Result<Block, Error> {
        let block = self.get_raw_block_by_hash(block_hash).await?;
        Ok(block.into())
    }

    async fn get_raw_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::Block, Error> {
        let block = match block_number {
            BlockNumberOrTag::Tag(_) => self.0.latest_block().await?,
            BlockNumberOrTag::Number(number) => {
                self.0.block_by_number(number).await.map_err(|e| -> Error {
                    match e.downcast_ref::<SeqError>() {
                        Some(starknet_e)
                            if starknet_e.code == SeqErrorCode::MalformedRequest
                                && starknet_e
                                    .message
                                    .contains("Block ID should be in the range") =>
                        {
                            ErrorCode::InvalidBlockNumber.into()
                        }
                        Some(_) | None => e.into(),
                    }
                })
            }?,
        };
        Ok(block)
    }

    pub async fn get_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<Block, Error> {
        let block = self.get_raw_block_by_number(block_number).await?;
        Ok(block.into())
    }

    pub async fn get_state_update_by_hash(&self, block_hash: BlockHashOrTag) -> Result<(), Error> {
        // TODO get this from storage or directly from L1
        match block_hash {
            BlockHashOrTag::Tag(_) => todo!("Implement L1 state diff retrieval."),
            BlockHashOrTag::Hash(_) => todo!(
                "Implement L1 state diff retrieval, determine the type of hash required here."
            ),
        }
    }

    pub async fn get_storage_at(
        &self,
        contract_address: relaxed::H256,
        key: relaxed::H256,
        block_hash: BlockHashOrTag,
    ) -> Result<relaxed::H256, Error> {
        let block_hash = match block_hash {
            BlockHashOrTag::Tag(_) => None,
            BlockHashOrTag::Hash(hash) => Some(hash),
        };
        let key: H256 = *key;
        let key: [u8; 32] = key.into();
        let storage = self
            .0
            .storage(*contract_address, key.into(), block_hash)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<SeqError>() {
                    Some(starknet_e) => match starknet_e.code {
                        SeqErrorCode::OutOfRangeContractAddress
                        | SeqErrorCode::UninitializedContract => ErrorCode::ContractNotFound.into(),
                        SeqErrorCode::OutOfRangeStorageKey => ErrorCode::InvalidStorageKey.into(),
                        SeqErrorCode::OutOfRangeBlockHash | SeqErrorCode::BlockNotFound => {
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

    pub async fn get_transaction_by_hash(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<Transaction, Error> {
        // TODO get this from storage
        let txn = self
            .0
            .transaction(*transaction_hash)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<SeqError>() {
                    Some(starknet_e) => match starknet_e.code {
                        SeqErrorCode::OutOfRangeTransactionHash => invalid_transaction_hash(),
                        _ => e.into(),
                    },
                    None => e.into(),
                }
            })?;
        if txn.status == reply::transaction::Status::NotReceived {
            return Err(invalid_transaction_hash());
        }
        Ok(txn.into())
    }

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

    pub async fn get_transaction_receipt(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<reply::TransactionStatus, Error> {
        let status = self.0.transaction_status(*transaction_hash).await?;
        Ok(status)
    }

    pub async fn get_code(&self, contract_address: relaxed::H256) -> Result<Code, Error> {
        let code = self
            .0
            .code(*contract_address, None)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<SeqError>() {
                    Some(starknet_e) => match starknet_e.code {
                        SeqErrorCode::OutOfRangeContractAddress
                        | SeqErrorCode::UninitializedContract => {
                            // TODO check me
                            ErrorCode::ContractNotFound.into()
                        }
                        _ => e.into(),
                    },
                    None => e.into(),
                }
            })?;
        Ok(code)
    }

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

    pub async fn call(
        &self,
        request: Call,
        block_hash: BlockHashOrTag,
    ) -> Result<Vec<relaxed::H256>, Error> {
        let block_hash = match block_hash {
            BlockHashOrTag::Tag(_) => None,
            BlockHashOrTag::Hash(hash) => Some(hash),
        };
        let call = self
            .0
            .call(request, block_hash)
            .await
            .map_err(|e| -> Error {
                match e.downcast_ref::<SeqError>() {
                    Some(starknet_e) => match starknet_e.code {
                        SeqErrorCode::EntryPointNotFound => {
                            // TODO check me
                            ErrorCode::InvalidMessageSelector.into()
                        }
                        SeqErrorCode::OutOfRangeContractAddress
                        | SeqErrorCode::UninitializedContract => {
                            // TODO check me
                            ErrorCode::ContractNotFound.into()
                        }
                        SeqErrorCode::TransactionFailed => {
                            // TODO check me
                            ErrorCode::InvalidCallData.into()
                        }
                        SeqErrorCode::OutOfRangeBlockHash | SeqErrorCode::BlockNotFound => {
                            // TODO consult Starkware
                            ErrorCode::InvalidBlockHash.into()
                        }
                        _ => e.into(),
                    },
                    None => e.into(),
                }
            })?;

        Ok(call.into())
    }

    pub async fn block_number(&self) -> Result<u64, Error> {
        let block = self.0.latest_block().await?;
        Ok(block.block_number)
    }

    pub async fn chain_id(&self) -> Result<relaxed::H256, Error> {
        todo!("Figure out where to take it from.")
    }

    pub async fn pending_transactions(&self) -> Result<Vec<Transaction>, Error> {
        todo!("Figure out where to take them from.")
    }

    pub async fn protocol_version(&self) -> Result<relaxed::H256, Error> {
        todo!("Figure out where to take it from.")
    }

    pub async fn syncing(&self) -> Result<Syncing, Error> {
        todo!("Figure out where to take it from.")
    }
}
