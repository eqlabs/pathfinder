//! Implementation of JSON-RPC endpoints.
use crate::{
    rpc::{
        rpc_trait::RpcApiServer,
        types::{relaxed, BlockHashOrTag, BlockNumberOrTag, Syncing},
    },
    sequencer::{reply, request::Call, Client},
};
use jsonrpsee::types::{
    async_trait,
    error::{CallError, Error},
};
use reqwest::Url;
use std::convert::{From, TryInto};
use web3::types::{H256, U256};

/// Implements JSON-RPC endpoints.
///
/// __TODO__ directly calls [sequencer::Client](crate::sequencer::Client) until storage is implemented.
pub struct RpcImpl(Client);

impl Default for RpcImpl {
    fn default() -> Self {
        let module = Client::new(Url::parse("https://alpha3.starknet.io/").expect("Valid URL."));
        Self(module)
    }
}

#[async_trait]
impl RpcApiServer for RpcImpl {
    async fn get_block_by_hash(&self, block_hash: BlockHashOrTag) -> Result<reply::Block, Error> {
        // TODO get this from storage
        // TODO how do we calculate block_hash
        let block = match block_hash {
            BlockHashOrTag::Tag(_) => self.0.latest_block().await,
            BlockHashOrTag::Hash(_) => todo!("Determine the type of hash required here."),
        }?;
        Ok(block)
    }

    async fn get_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::Block, Error> {
        let block = match block_number {
            BlockNumberOrTag::Tag(_) => self.0.latest_block().await,
            BlockNumberOrTag::Number(number) => self.0.block(number).await,
        }?;
        Ok(block)
    }

    async fn get_state_update_by_hash(&self, block_hash: BlockHashOrTag) -> Result<(), Error> {
        // TODO get this from storage or directly from L1
        // TODO how do we calculate block_hash
        match block_hash {
            BlockHashOrTag::Tag(_) => todo!("Implement L1 state diff retrieval."),
            BlockHashOrTag::Hash(_) => todo!(
                "Implement L1 state diff retrieval, determine the type of hash required here."
            ),
        }
    }

    async fn get_storage_at(
        &self,
        contract_address: relaxed::H256,
        key: relaxed::H256,
        block_hash: BlockHashOrTag,
    ) -> Result<relaxed::H256, Error> {
        let block_id = match block_hash {
            BlockHashOrTag::Tag(_) => None,
            BlockHashOrTag::Hash(_) => todo!("Determine the type of hash required here."),
        };
        let key: H256 = *key;
        let key: [u8; 32] = key.into();
        let storage = self
            .0
            .storage(*contract_address, key.into(), block_id)
            .await?;
        let x: [u8; 32] = storage.into();
        Ok(H256::from(x).into())
    }

    async fn get_storage_at_by_block_number(
        &self,
        contract_address: relaxed::H256,
        key: relaxed::H256,
        block_number: BlockNumberOrTag,
    ) -> Result<relaxed::H256, Error> {
        let block_id = match block_number {
            BlockNumberOrTag::Tag(_) => None,
            BlockNumberOrTag::Number(number) => Some(number),
        };
        let key: H256 = *key;
        let key: [u8; 32] = key.into();
        let storage = self
            .0
            .storage(*contract_address, key.into(), block_id)
            .await?;
        let x: [u8; 32] = storage.into();
        Ok(H256::from(x).into())
    }

    async fn get_transaction_by_hash(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<reply::Transaction, Error> {
        // TODO get this from storage
        let txn = self.0.transaction(*transaction_hash).await?;
        Ok(txn)
    }

    async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: BlockHashOrTag,
        index: u64,
    ) -> Result<reply::transaction::Transaction, Error> {
        // TODO get this from storage
        // TODO how do we calculate block_hash
        let block = self.get_block_by_hash(block_hash).await?;
        let index: usize = index
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        if index >= block.transactions.len() {
            return Err(Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                "transaction index {} not found",
                index
            ))));
        }
        Ok(block.transactions[index].clone())
    }

    async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: BlockNumberOrTag,
        index: u64,
    ) -> Result<reply::transaction::Transaction, Error> {
        // TODO get this from storage
        let block = self.get_block_by_number(block_number).await?;
        let index: usize = index
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;

        if index >= block.transactions.len() {
            return Err(Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                "transaction index {} not found",
                index
            ))));
        }
        Ok(block.transactions[index].clone())
    }

    async fn get_transaction_receipt(
        &self,
        transaction_hash: relaxed::H256,
    ) -> Result<reply::TransactionStatus, Error> {
        let status = self.0.transaction_status(*transaction_hash).await?;
        Ok(status)
    }

    async fn get_code(&self, contract_address: relaxed::H256) -> Result<reply::Code, Error> {
        let code = self.0.code(*contract_address, None).await?;
        Ok(code)
    }

    async fn get_block_transaction_count_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<u64, Error> {
        // TODO get this from storage
        // TODO how do we calculate block_hash
        let block = match block_hash {
            BlockHashOrTag::Tag(_) => self.0.latest_block().await,
            BlockHashOrTag::Hash(_) => todo!("Determine the type of hash required here."),
        }?;
        let len: u64 = block
            .transactions
            .len()
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;
        Ok(len)
    }

    async fn get_block_transaction_count_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<u64, Error> {
        // TODO get this from storage
        let block = match block_number {
            BlockNumberOrTag::Tag(_) => self.0.latest_block().await,
            BlockNumberOrTag::Number(number) => self.0.block(number).await,
        }?;
        let len: u64 = block
            .transactions
            .len()
            .try_into()
            .map_err(|e| Error::Call(CallError::InvalidParams(anyhow::Error::new(e))))?;
        Ok(len)
    }

    async fn call(&self, request: Call, block_hash: BlockHashOrTag) -> Result<reply::Call, Error> {
        let block_id = match block_hash {
            BlockHashOrTag::Tag(_) => None,
            BlockHashOrTag::Hash(_) => todo!("Determine the type of hash required here."),
        };
        let call = self.0.call(request, block_id).await?;
        Ok(call)
    }

    async fn block_number(&self) -> Result<U256, Error> {
        let block = self.0.latest_block().await?;
        Ok(block.block_id)
    }

    async fn chain_id(&self) -> Result<relaxed::H256, Error> {
        todo!("Figure out where to take it from.")
    }

    async fn pending_transactions(&self) -> Result<(), Error> {
        todo!("Figure out where to take them from.")
    }

    async fn protocol_version(&self) -> Result<relaxed::H256, Error> {
        todo!("Figure out where to take it from.")
    }

    async fn syncing(&self) -> Result<Syncing, Error> {
        todo!("Figure out where to take it from.")
    }
}
