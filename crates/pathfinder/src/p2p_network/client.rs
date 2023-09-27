//! Sync related data retrieval from other peers
//!
//! This is a temporary wrapper around proper p2p sync|propagation api that fits into
//! current sequential sync logic and will be removed when __proper__ sync algo is
//! integrated. What it does is just split methods between a "proxy" node
//! that syncs from the gateway and propagates new headers and a
//! "proper" p2p node which only syncs via p2p.

use lru::LruCache;
use p2p::HeadRx;
use pathfinder_common::{
    BlockHash, BlockId, BlockNumber, CallParam, CasmHash, ClassHash, ContractAddress,
    ContractAddressSalt, Fee, StateUpdate, TransactionHash, TransactionNonce,
    TransactionSignatureElem, TransactionVersion,
};
use starknet_gateway_client::{GatewayApi, GossipApi};
use starknet_gateway_types::reply;
use starknet_gateway_types::request::add_transaction::ContractDefinition;
use starknet_gateway_types::{error::SequencerError, reply::Block};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub mod v0;
pub mod v1;

/// Hybrid, as it uses either p2p or the gateway depending on role and api call
#[derive(Clone, Debug)]
pub enum HybridClient {
    /// Syncs from the feeder gateway, propagates new headers via p2p/gossipsub
    /// Proxies blockchain data to non propagating nodes via p2p
    GatewayProxy {
        p2p_client: p2p::SyncClient,
        sequencer: starknet_gateway_client::Client,
    },
    /// Syncs from p2p network, does not propagate
    NonPropagatingP2P {
        p2p_client: p2p::SyncClient,
        sequencer: starknet_gateway_client::Client,
        head_rx: HeadRx,
        /// We need to cache the last two fetched blocks via p2p otherwise sync logic will
        /// produce a false reorg from genesis when we loose connection to other p2p nodes.
        /// This was we can stay at the same height while we are disconnected.
        block_lru: BlockLru,
    },
}

#[derive(Clone, Debug)]
pub struct BlockLru {
    inner: Arc<Mutex<LruCache<BlockNumber, Block>>>,
}

impl Default for BlockLru {
    fn default() -> Self {
        Self {
            // We only need 2 blocks: the last one and its parent
            inner: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(2).unwrap()))),
        }
    }
}

impl BlockLru {
    fn get(&self, number: BlockNumber) -> Option<Block> {
        let mut locked_inner = self.inner.lock().unwrap();
        locked_inner.get(&number).cloned()
    }

    fn clear_if_reorg(&self, header: &p2p_proto_v0::common::BlockHeader) {
        if let Some(parent_number) = header.number.checked_sub(1) {
            let mut locked_inner = self.inner.lock().unwrap();
            if let Some(parent) = locked_inner.get(&BlockNumber::new_or_panic(parent_number)) {
                // If there's a reorg, purge the cache or we'll be stuck
                //
                // There's a risk we'll falsely reorg to genesis if all other peers get disconnected
                // just after the cache is purged
                // TODO: consider increasing the cache and just purging the last block
                if parent.block_hash.0 != header.parent_hash {
                    locked_inner.clear();
                }
            }
        }
    }

    fn insert(&self, block: Block) {
        let mut locked_inner = self.inner.lock().unwrap();
        locked_inner.put(block.block_number, block);
    }
}

impl HybridClient {
    pub fn new(
        i_am_proxy: bool,
        p2p_client: p2p::SyncClient,
        sequencer: starknet_gateway_client::Client,
        head_rx: HeadRx,
    ) -> Self {
        if i_am_proxy {
            Self::GatewayProxy {
                p2p_client,
                sequencer,
            }
        } else {
            Self::NonPropagatingP2P {
                p2p_client,
                sequencer,
                head_rx,
                block_lru: Default::default(),
            }
        }
    }

    fn as_sequencer(&self) -> &starknet_gateway_client::Client {
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer,
            HybridClient::NonPropagatingP2P { sequencer, .. } => sequencer,
        }
    }
}

/// A hacky temporary way to wrap p2p related errors
mod error {
    use starknet_gateway_types::error::{
        KnownStarknetErrorCode, SequencerError, StarknetError, StarknetErrorCode,
    };

    pub fn block_not_found(message: impl ToString) -> SequencerError {
        SequencerError::StarknetError(StarknetError {
            code: StarknetErrorCode::Known(KnownStarknetErrorCode::BlockNotFound),
            message: message.to_string(),
        })
    }

    pub fn class_not_found(message: impl ToString) -> SequencerError {
        SequencerError::StarknetError(StarknetError {
            code: StarknetErrorCode::Known(KnownStarknetErrorCode::UndeclaredClass),
            message: message.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl GatewayApi for HybridClient {
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        use error::block_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.block(block).await,
            HybridClient::NonPropagatingP2P {
                p2p_client,
                block_lru,
                ..
            } => match block {
                BlockId::Number(n) => {
                    if let Some(block) = block_lru.get(n) {
                        tracing::trace!(number=%n, "HybridClient: using cached block");
                        return Ok(block.into());
                    }

                    let mut headers = p2p_client.block_headers(n, 1).await.ok_or_else(|| {
                        block_not_found(format!("No peers with headers for block {n}"))
                    })?;

                    if headers.len() != 1 {
                        return Err(block_not_found(format!(
                            "Headers len for block {n} is {}, expected 1",
                            headers.len()
                        )));
                    }

                    let header = headers.swap_remove(0);

                    block_lru.clear_if_reorg(&header);

                    let mut bodies = p2p_client
                        .block_bodies(BlockHash(header.hash), 1)
                        .await
                        .ok_or_else(|| {
                            block_not_found(format!("No peers with bodies for block {n}"))
                        })?;

                    if bodies.len() != 1 {
                        return Err(block_not_found(format!(
                            "Bodies len for block {n} is {}, expected 1",
                            headers.len()
                        )));
                    }

                    let body = bodies.swap_remove(0);
                    let (transactions, transaction_receipts) =
                        v0::conv::body::try_from_p2p(body).map_err(block_not_found)?;
                    let header = v0::conv::header::try_from_p2p(header).map_err(block_not_found)?;

                    let block = reply::Block {
                        block_hash: header.hash,
                        block_number: header.number,
                        gas_price: Some(header.gas_price),
                        parent_block_hash: header.parent_hash,
                        sequencer_address: Some(header.sequencer_address),
                        state_commitment: header.state_commitment,
                        // FIXME
                        status: starknet_gateway_types::reply::Status::AcceptedOnL2,
                        timestamp: header.timestamp,
                        transaction_receipts,
                        transactions,
                        starknet_version: header.starknet_version,
                    };

                    block_lru.insert(block.clone());
                    tracing::trace!(number=%n, "HybridClient: updating cached block");

                    Ok(block.into())
                }
                BlockId::Latest => {
                    unreachable!("GatewayApi.head() is used in sync and sync status instead")
                }
                BlockId::Hash(_) => unreachable!("not used in sync"),
                BlockId::Pending => {
                    unreachable!("pending should be disabled when p2p is enabled")
                }
            },
        }
    }

    async fn block_without_retry(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingBlock, SequencerError> {
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => {
                sequencer.block_without_retry(block).await
            }
            HybridClient::NonPropagatingP2P { .. } => {
                unreachable!("used for gas price and not in sync")
            }
        }
    }

    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        use error::class_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => {
                sequencer.class_by_hash(class_hash).await
            }
            HybridClient::NonPropagatingP2P { p2p_client, .. } => {
                let classes = p2p_client
                    .contract_classes(vec![class_hash])
                    .await
                    .ok_or_else(|| class_not_found(format!("No peers with class {class_hash}")))?;
                let mut classes = classes.classes;

                if classes.len() != 1 {
                    return Err(class_not_found(format!(
                        "Classes len is {}, expected 1",
                        classes.len()
                    )));
                }

                let p2p_proto_v0::common::RawClass { class } = classes.swap_remove(0);

                let class = zstd::decode_all(class.as_slice())
                    .map_err(|_| class_not_found("zstd failed"))?;

                Ok(class.into())
            }
        }
    }

    async fn pending_class_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        use error::class_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => {
                sequencer.pending_class_by_hash(class_hash).await
            }
            HybridClient::NonPropagatingP2P { p2p_client, .. } => {
                let classes = p2p_client
                    .contract_classes(vec![class_hash])
                    .await
                    .ok_or_else(|| class_not_found(format!("No peers with class {class_hash}")))?;
                let mut classes = classes.classes;

                if classes.len() != 1 {
                    return Err(class_not_found(format!(
                        "Classes len is {}, expected 1",
                        classes.len()
                    )));
                }

                let p2p_proto_v0::common::RawClass { class } = classes.swap_remove(0);

                let class = zstd::decode_all(class.as_slice())
                    .map_err(|_| class_not_found("zstd failed"))?;

                Ok(class.into())
            }
        }
    }

    async fn transaction(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        self.as_sequencer().transaction(transaction_hash).await
    }

    async fn state_update(&self, block: BlockId) -> Result<StateUpdate, SequencerError> {
        use error::block_not_found;

        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.state_update(block).await,
            HybridClient::NonPropagatingP2P { p2p_client, .. } => match block {
                BlockId::Hash(hash) => {
                    let mut state_updates =
                        p2p_client.state_updates(hash, 1).await.ok_or_else(|| {
                            block_not_found(format!("No peers with state update for block {hash}"))
                        })?;

                    if state_updates.len() != 1 {
                        return Err(block_not_found(format!(
                            "State updates len is {}, expected 1",
                            state_updates.len()
                        )));
                    }

                    let state_update = state_updates.swap_remove(0);

                    let state_update = v0::conv::state_update::try_from_p2p(state_update)
                        .map_err(block_not_found)?;

                    if state_update.block_hash == hash {
                        Ok(state_update.into())
                    } else {
                        Err(block_not_found("Block hash mismatch"))
                    }
                }
                _ => unreachable!("not used in sync"),
            },
        }
    }

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        self.as_sequencer().eth_contract_addresses().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_invoke_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address: ContractAddress,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        self.as_sequencer()
            .add_invoke_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_address,
                calldata,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_declare_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        compiled_class_hash: Option<CasmHash>,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
        self.as_sequencer()
            .add_declare_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_definition,
                sender_address,
                compiled_class_hash,
                token,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_deploy_account(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address_salt: ContractAddressSalt,
        class_hash: ClassHash,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError> {
        self.as_sequencer()
            .add_deploy_account(
                version,
                max_fee,
                signature,
                nonce,
                contract_address_salt,
                class_hash,
                calldata,
            )
            .await
    }

    /// This is a **temporary** measure to keep the sync logic unchanged
    ///
    /// TODO remove me when sync is changed to use the high level (ie. peer unaware) p2p API
    async fn head(&self) -> Result<(BlockNumber, BlockHash), SequencerError> {
        match self {
            HybridClient::GatewayProxy { sequencer, .. } => sequencer.head().await,
            HybridClient::NonPropagatingP2P { head_rx, .. } => {
                let head = *head_rx.borrow();
                tracing::trace!(?head, "HybridClient::head");
                head.ok_or(error::block_not_found(
                    "Haven't received any gossiped head yet",
                ))
            }
        }
    }
}

#[async_trait::async_trait]
impl GossipApi for HybridClient {
    async fn propagate_head(&self, block_number: BlockNumber, block_hash: BlockHash) {
        match self {
            HybridClient::GatewayProxy { p2p_client, .. } => {
                match p2p_client
                    .propagate_new_header(p2p_proto_v0::common::BlockHeader {
                        hash: block_hash.0,
                        number: block_number.get(),
                        ..Default::default()
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "Propagating block header failed"),
                }
            }
            HybridClient::NonPropagatingP2P { .. } => {
                // This is why it's called non-propagating
            }
        }
    }
}
