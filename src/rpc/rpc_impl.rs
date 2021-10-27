//! Implementation of JSON-RPC endpoints.
use crate::{
    rpc::rpc_trait::RpcApiServer,
    sequencer::{reply, request, Client},
};
use jsonrpsee::types::{
    async_trait,
    error::{CallError, Error},
};
use reqwest::Url;
use web3::types::{H256, U256};

/// Special tag values used in the RPC API.
mod tags {
    pub const LATEST: &str = "latest";
    pub const EARLIEST: &str = "earliest";
}

/// Implements JSON-RPC endpoints.
///
/// __TODO__ directly calls [sequencer::Client](crate::sequencer::Client) until storage is implemented.
pub struct RpcImpl(Client);

impl RpcImpl {
    /// Constructs a sequencer client for the __alpha2__ network.
    pub fn new() -> Self {
        let module = Client::new(Url::parse("https://alpha2.starknet.io/").expect("Valid URL."));
        Self(module)
    }
}

#[async_trait]
impl RpcApiServer for RpcImpl {
    async fn block_number(&self) -> Result<U256, Error> {
        // TODO get this from storage
        let block = self.0.latest_block().await?;
        Ok(block.block_id)
    }

    async fn get_block_by_hash(&self, block_hash: String) -> Result<reply::Block, Error> {
        // TODO get this from storage
        // TODO how do we calculate block_hash
        let block = match block_hash.as_str() {
            tags::LATEST => self.0.latest_block().await,
            tags::EARLIEST => self.0.block(U256::zero()).await,
            _ => todo!("Determine the type of hash required here."),
        }?;
        Ok(block)
    }

    async fn get_block_by_number(&self, block_number: String) -> Result<reply::Block, Error> {
        // TODO get this from storage
        // TODO earliest, latest, block_number
        let block = match block_number.as_str() {
            tags::LATEST => self.0.latest_block().await,
            tags::EARLIEST => self.0.block(U256::zero()).await,
            _ => {
                self.0
                    .block(
                        U256::from_str_radix(block_number.as_str(), 16)
                            .map_err(anyhow::Error::new)?,
                    )
                    .await
            }
        }?;
        Ok(block)
    }

    async fn get_transaction_by_hash(
        &self,
        _transaction_hash: String,
    ) -> Result<reply::Transaction, Error> {
        // TODO get this from storage
        // TODO how do we calculate transaction_hash
        todo!("Determine the type of hash required here.");
    }

    async fn get_transaction_by_number(
        &self,
        transaction_number: String,
    ) -> Result<reply::Transaction, Error> {
        // TODO get this from storage
        // TODO how do we calculate transaction_hash
        let txn = self
            .0
            .transaction(
                U256::from_str_radix(transaction_number.as_str(), 16)
                    .map_err(anyhow::Error::new)?,
            )
            .await?;
        Ok(txn)
    }

    async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: String,
        transaction_index: u32,
    ) -> Result<reply::transaction::Transaction, Error> {
        // TODO get this from storage
        // TODO how do we calculate block_hash
        let block = self.get_block_by_hash(block_hash).await?;
        let mut keys: Vec<&U256> = block.transactions.keys().collect();
        keys.sort();
        let key = keys
            .into_iter()
            .nth(transaction_index as usize)
            .ok_or_else(|| {
                Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                    "transaction index {} not found",
                    transaction_index
                )))
            })?;

        let txn = block.transactions.get(key).ok_or_else(|| {
            Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                "transaction key {} not found",
                key
            )))
        })?;
        Ok(txn.clone())
    }

    async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: String,
        transaction_index: u32,
    ) -> Result<reply::transaction::Transaction, Error> {
        // TODO get this from storage
        // TODO earliest, latest, block_number
        let block = self.get_block_by_number(block_number).await?;
        let mut keys: Vec<&U256> = block.transactions.keys().collect();
        keys.sort();
        let key = keys
            .into_iter()
            .nth(transaction_index as usize)
            .ok_or_else(|| {
                Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                    "transaction index {} not found",
                    transaction_index
                )))
            })?;

        let txn = block.transactions.get(key).ok_or_else(|| {
            Error::Call(CallError::InvalidParams(anyhow::anyhow!(
                "transaction key {} not found",
                key
            )))
        })?;
        Ok(txn.clone())
    }

    async fn get_storage(&self, contract_address: H256, key: U256) -> Result<H256, Error> {
        // TODO get this from storage
        // TODO calculate key
        let storage = self.0.storage(contract_address, key, None).await?;
        let x: [u8; 32] = storage.into();
        Ok(H256::from(x))
    }

    async fn get_code(&self, contract_address: H256) -> Result<reply::Code, Error> {
        // TODO get this from storage
        let storage = self.0.code(contract_address, None).await?;
        Ok(storage)
    }

    async fn call(
        &self,
        contract_address: H256,
        call_data: Vec<U256>,
        entry_point: H256,
    ) -> Result<reply::Call, Error> {
        // TODO calculate entry point?
        let call = self
            .0
            .call(
                request::Call {
                    calldata: call_data,
                    contract_address,
                    entry_point_selector: entry_point,
                },
                None,
            )
            .await?;
        Ok(call)
    }
}
